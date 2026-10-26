//! Profile lifecycle from the SOC (contract §6).
//!
//! ```text
//! draft (observe) ──publish──► SOC review / lock / sign (commission)
//!        SOC offer ──fetch──► verify (commission trust, anti-rollback) ──► STAGED (not enforced)
//!   SOC approval artefact ──approve (operator, explicit)──► re-verify ──► INSTALLED at agentd's
//!                                                         profile_path; restart agentd to enforce
//! ```
//!
//! * **Never auto-enforce.** `fetch` only stages: it never touches agentd's
//!   profile. Only `approve`, run by the operator with an approval
//!   artefact signed by a SOC fleet key, installs a profile, and agentd
//!   enforces it only after its next start (where it verifies it again).
//! * The staged profile is verified with exactly agentd's trust inputs
//!   (`sensor.profile_trust`: trusted keys, trust roots and floor,
//!   revocation list and policy, platform / unit expectations) and against
//!   agentd's anti-rollback state file (read-only: agentd writes it when it
//!   accepts the profile). A draft offer is refused (the SOC distributes
//!   only locked, signed profiles; drafts never leave observe mode).
//! * The approval names the exact profile digest, version, platform, robot
//!   and workspace, has an expiry, and is single-use on the unit.
//! * Install is re-verified immediately before writing (the trust inputs
//!   may have changed since staging); the previous profile and `.sig` are
//!   kept under `profile/backup-<ms>/`. The `.sig` is written first, then
//!   the profile: a crash in between leaves a pair that does not verify,
//!   which agentd refuses (observe-only) — fail closed, and re-running
//!   `approve` with the same artefact completes the install.

use robodr_commission::trust::{evaluate_profile_trust, sig_path_for, TrustInputs};
use std::path::{Path, PathBuf};

use crate::client::{self, SocTransport};
use crate::fsx;
use crate::keys::{self, SocKeys};
use crate::state::{Ctx, StagedMeta};
use crate::wire::{self, Approval, Envelope, Offer};

const STAGED: &str = "staged.json";
const STAGED_META: &str = "staged-meta.json";
const APPROVALS_USED: &str = "approvals-used.json";
const INSTALL_INTENT: &str = "install-intent.json";
const MAX_PROFILE_BYTES: u64 = 8 * 1024 * 1024;

fn trust_inputs<'a>(ctx: &'a Ctx) -> TrustInputs<'a> {
    TrustInputs {
        trusted_keys: ctx.facts.trusted_keys.as_deref(),
        trust_roots: ctx.facts.trust_roots.as_deref(),
        revocation_list: ctx.facts.revocation_list.as_deref(),
        revocation_policy: ctx.facts.revocation_policy,
        expect_platform: ctx.facts.expect_platform.as_deref(),
        expect_unit_id: ctx.facts.expect_unit_id.as_deref(),
        state_file: ctx.facts.state_file.as_deref(),
        allow_rollback: None,
        chain: None,
    }
}

/// Verify the profile at `path` (its `.sig` next to it) as agentd would.
fn verify(ctx: &Ctx, path: &Path) -> Result<StagedMeta, String> {
    let raw =
        String::from_utf8(fsx::read_capped(path, MAX_PROFILE_BYTES).map_err(|e| e.to_string())?)
            .map_err(|_| "profile is not UTF-8")?;
    let ev = evaluate_profile_trust(path, &raw, &trust_inputs(ctx));
    let acc = ev.result.map_err(|e| format!("profile refused: {e}"))?;
    let v = &acc.verified;
    if !v.profile.locked {
        return Err(
            "profile refused: it is a draft (observe-only); the SOC distributes locked, signed \
             profiles only"
                .into(),
        );
    }
    let m = v
        .profile
        .metadata
        .as_ref()
        .ok_or("profile refused: locked without metadata")?;
    if let Some(u) = &m.unit_id {
        if let Ok(en) = ctx.enrollment() {
            if *u != en.robot_id {
                return Err(format!(
                    "profile refused: it is for unit {u:?}, this unit is {:?}",
                    en.robot_id
                ));
            }
        }
    }
    Ok(StagedMeta {
        digest: v.digest.clone(),
        profile_version: m.profile_version,
        platform: m.platform.clone(),
        unit_id: m.unit_id.clone(),
        signed_by: v.signed_by.clone(),
        staged_at_ms: ctx.now(),
    })
}

fn journal(ctx: &Ctx, note: serde_json::Value) -> Result<(), String> {
    let en = ctx.enrollment()?;
    let mut j = ctx.journal(&en.robot_id)?;
    j.note(&note)?;
    j.close()
}

/// Send a draft profile (from `robodr-commission learn`) to the SOC for
/// review. Refuses a locked profile (that direction is the SOC's).
pub fn publish_draft(ctx: &Ctx, t: &mut dyn SocTransport, path: &Path) -> Result<String, String> {
    let bytes = fsx::read_capped(path, MAX_PROFILE_BYTES)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "draft is not UTF-8")?;
    let p = robodr_commission::parse_profile_text(text).map_err(|e| format!("draft: {e}"))?;
    if p.locked {
        return Err("only drafts (locked: false) are published for review".into());
    }
    ctx.enrollment()?;
    let auth = keys::load("uplink", &ctx.cfg.uplink_key)?;
    let body = client::exchange(
        t,
        "POST",
        wire::PATH_PROFILE_DRAFTS,
        &bytes,
        Some((&auth.signing, ctx.now())),
    )
    .map_err(|e| e.to_string())?;
    #[derive(serde::Deserialize)]
    struct R {
        digest: String,
        status: String,
    }
    let r: R = serde_json::from_slice(&body).map_err(|e| format!("SOC answer: {e}"))?;
    let d = wire::digest(&bytes);
    if r.digest != d || r.status != "received" {
        return Err("the SOC acknowledged other bytes than the draft sent".into());
    }
    journal(
        ctx,
        serde_json::json!({"kind": crate::journal::K_PROFILE, "step": "draft_published", "digest": d}),
    )?;
    Ok(d)
}

/// Fetch the SOC's current profile offer and stage it.
pub fn fetch(ctx: &Ctx, t: &mut dyn SocTransport) -> Result<StagedMeta, String> {
    ctx.enrollment()?;
    let auth = keys::load("uplink", &ctx.cfg.uplink_key)?;
    let body = client::exchange(
        t,
        "GET",
        wire::PATH_PROFILE_CURRENT,
        b"",
        Some((&auth.signing, ctx.now())),
    )
    .map_err(|e| e.to_string())?;
    let (_, profile, sig) = Offer::parse(&body).map_err(|e| format!("offer: {e}"))?;
    stage(ctx, &profile, &sig)
}

/// Verify `profile` + `sig` with agentd's trust inputs and stage them (the
/// air-gapped path gives the two files directly).
pub fn stage(ctx: &Ctx, profile: &[u8], sig: &[u8]) -> Result<StagedMeta, String> {
    ctx.enrollment()?;
    let dir = ctx.profile_dir()?;
    let staged = dir.join(STAGED);
    fsx::write_atomic(&sig_path_for(&staged), sig).map_err(|e| e.to_string())?;
    fsx::write_atomic(&staged, profile).map_err(|e| e.to_string())?;
    let meta = match verify(ctx, &staged) {
        Ok(m) => m,
        Err(e) => {
            let _ = std::fs::remove_file(&staged);
            let _ = std::fs::remove_file(sig_path_for(&staged));
            let _ = std::fs::remove_file(dir.join(STAGED_META));
            journal(
                ctx,
                serde_json::json!({"kind": crate::journal::K_REFUSED, "step": "profile_stage",
                                   "digest": wire::digest(profile), "reason": e}),
            )?;
            return Err(e);
        }
    };
    crate::state::store_json(&dir.join(STAGED_META), &meta)?;
    journal(
        ctx,
        serde_json::json!({"kind": crate::journal::K_PROFILE, "step": "staged",
                           "digest": meta.digest, "profile_version": meta.profile_version,
                           "platform": meta.platform, "signed_by": meta.signed_by}),
    )?;
    Ok(meta)
}

/// The staged profile, if any.
pub fn staged(ctx: &Ctx) -> Result<Option<StagedMeta>, String> {
    crate::state::load_json(&ctx.path("profile").join(STAGED_META))
}

/// Fetch the approval artefact for the staged profile from the SOC.
pub fn fetch_approval(ctx: &Ctx, t: &mut dyn SocTransport) -> Result<Vec<u8>, String> {
    let meta = staged(ctx)?.ok_or("no staged profile (robodr-enroll profile fetch)")?;
    let hex = meta.digest.trim_start_matches("sha256:");
    let auth = keys::load("uplink", &ctx.cfg.uplink_key)?;
    client::exchange(
        t,
        "GET",
        &format!("{}/{hex}", wire::PATH_PROFILE_APPROVALS),
        b"",
        Some((&auth.signing, ctx.now())),
    )
    .map_err(|e| e.to_string())
}

/// What [`approve`] installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub meta: StagedMeta,
    pub approval_id: String,
    pub approved_by: Vec<String>,
    pub path: PathBuf,
    pub backup: Option<PathBuf>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    approval_id: String,
    digest: String,
}

/// Verify the approval artefact and install the staged profile as agentd's
/// profile (see the module docs).
pub fn approve(ctx: &Ctx, approval: &[u8]) -> Result<Installed, String> {
    let en = ctx.enrollment()?;
    let target = ctx
        .facts
        .profile_path
        .clone()
        .ok_or("agentd has no sensor.profile_path: nowhere to install the profile")?;
    let meta = staged(ctx)?.ok_or("no staged profile (robodr-enroll profile fetch)")?;
    let o = Envelope::parse(approval, wire::T_APPROVAL).map_err(|e| format!("approval: {e}"))?;
    SocKeys::load(&ctx.cfg.soc_keys)?
        .verify(&o)
        .map_err(|e| format!("approval: {e}"))?;
    let a = Approval::parse(&o.payload).map_err(|e| format!("approval: {e}"))?;
    let refuse = |why: String| -> Result<Installed, String> {
        let _ = journal(
            ctx,
            serde_json::json!({"kind": crate::journal::K_REFUSED, "step": "profile_approve",
                               "approval_id": a.approval_id, "reason": why}),
        );
        Err(format!("approval refused: {why}"))
    };
    if a.workspace != en.workspace || a.robot_id != en.robot_id {
        return refuse(format!(
            "it is for robot {:?} in workspace {:?}, this unit is {:?} in {:?}",
            a.robot_id, a.workspace, en.robot_id, en.workspace
        ));
    }
    if a.profile_digest != meta.digest
        || a.profile_version != meta.profile_version
        || a.platform != meta.platform
    {
        return refuse(format!(
            "it approves {} (version {}, platform {}), the staged profile is {} (version {}, \
             platform {})",
            a.profile_digest,
            a.profile_version,
            a.platform,
            meta.digest,
            meta.profile_version,
            meta.platform
        ));
    }
    let now = ctx.now();
    if now > a.expires_at_ms {
        return refuse(format!(
            "it expired at {} ms (now {now} ms)",
            a.expires_at_ms
        ));
    }
    if now.saturating_add(wire::MAX_SKEW_MS) < a.issued_at_ms {
        return refuse("it is issued in the future: fix the unit's clock".into());
    }
    // Single use; an interrupted install of the same approval may resume.
    let intent: Option<Intent> = ctx.load(INSTALL_INTENT)?;
    let resuming = intent
        .as_ref()
        .is_some_and(|i| i.approval_id == a.approval_id && i.digest == a.profile_digest);
    if !resuming && ctx.used(APPROVALS_USED, &a.approval_id)? {
        return refuse(format!(
            "approval {} was already used on this unit",
            a.approval_id
        ));
    }
    // Re-verify now (trust inputs may have changed since staging).
    let dir = ctx.profile_dir()?;
    let staged_path = dir.join(STAGED);
    let again = match verify(ctx, &staged_path) {
        Ok(m) => m,
        Err(e) => return refuse(e),
    };
    if again.digest != meta.digest {
        return refuse("the staged files changed since staging".into());
    }
    ctx.store(
        INSTALL_INTENT,
        &Intent {
            approval_id: a.approval_id.clone(),
            digest: a.profile_digest.clone(),
        },
    )?;
    ctx.mark_used(APPROVALS_USED, &a.approval_id)?;
    // Back up the active pair.
    let target_sig = sig_path_for(&target);
    let mut backup = None;
    if !resuming {
        if let Some(cur) =
            fsx::read_optional(&target, MAX_PROFILE_BYTES).map_err(|e| e.to_string())?
        {
            let b = dir.join(format!("backup-{now}"));
            fsx::ensure_private_dir(&b).map_err(|e| e.to_string())?;
            fsx::write_atomic(&b.join("profile.json"), &cur).map_err(|e| e.to_string())?;
            if let Some(s) =
                fsx::read_optional(&target_sig, 64 * 1024).map_err(|e| e.to_string())?
            {
                fsx::write_atomic(&b.join("profile.json.sig"), &s).map_err(|e| e.to_string())?;
            }
            backup = Some(b);
        }
    }
    let profile = fsx::read_capped(&staged_path, MAX_PROFILE_BYTES).map_err(|e| e.to_string())?;
    let sig =
        fsx::read_capped(&sig_path_for(&staged_path), 64 * 1024).map_err(|e| e.to_string())?;
    crate::install::install_public(&target_sig, &sig)?;
    crate::install::install_public(&target, &profile)?;
    journal(
        ctx,
        serde_json::json!({"kind": crate::journal::K_PROFILE, "step": "installed",
                           "digest": meta.digest, "profile_version": meta.profile_version,
                           "approval_id": a.approval_id, "approved_by": a.approved_by,
                           "approval_signed_by": o.signers(), "path": target.display().to_string()}),
    )?;
    ctx.remove(INSTALL_INTENT)?;
    let _ = std::fs::remove_file(dir.join(STAGED_META));
    let _ = std::fs::remove_file(&staged_path);
    let _ = std::fs::remove_file(sig_path_for(&staged_path));
    Ok(Installed {
        meta,
        approval_id: a.approval_id,
        approved_by: a.approved_by,
        path: target,
        backup,
    })
}
