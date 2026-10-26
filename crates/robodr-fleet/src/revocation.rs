//! Revocation list distribution (contract §4.1): fetch the root-signed
//! `robodr-profile-revocations/v2` list for this unit's platform from the
//! SOC, verify it with robodr-commission's own code against agentd's trust
//! roots, refuse a rollback, and install it where agentd reads it.
//!
//! Anti-rollback: the list's `serial` must not be lower than the highest of
//! (a) the last list this tool installed for the platform, (b) the list
//! currently installed (if it verifies), (c) the `revocation_serial` in
//! agentd's profile anti-rollback state file; an equal serial must carry
//! the same content (digest), otherwise it is equivocation and refused.

use robodr_commission::trust::{
    evaluate_profile_trust, load_state, load_trust_roots, RevocationList, TrustInputs,
};
use std::path::Path;

use crate::client::{self, SocTransport};
use crate::fsx;
use crate::state::{Ctx, RevocationMark};
use crate::wire;

const MARKS: &str = "revocations-state.json";
const MAX_LIST_BYTES: u64 = robodr_commission::trust::MAX_REVOCATION_BYTES;

/// What [`install`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub serial: u64,
    pub digest: String,
    /// The same list was already installed (nothing written).
    pub unchanged: bool,
    /// With this list, agentd would refuse the active profile (reason).
    pub active_profile_refused: Option<String>,
}

/// The platform this unit's lists are for: agentd's `expect_platform`, else
/// the active profile's `metadata.platform`.
pub fn platform(ctx: &Ctx) -> Result<String, String> {
    if let Some(p) = &ctx.facts.expect_platform {
        return Ok(p.clone());
    }
    if let Some(pp) = &ctx.facts.profile_path {
        if let Ok(Some(b)) = fsx::read_optional(pp, 8 * 1024 * 1024) {
            if let Ok(t) = String::from_utf8(b) {
                if let Ok(p) = robodr_commission::parse_profile_text(&t) {
                    if let Some(m) = p.metadata {
                        return Ok(m.platform);
                    }
                }
            }
        }
    }
    Err(
        "cannot tell this unit's platform: set sensor.profile_trust.expect_platform in agentd's \
         configuration or pass --platform"
            .into(),
    )
}

/// Fetch the list for `platform` and [`install`] it.
pub fn fetch(ctx: &Ctx, t: &mut dyn SocTransport, platform: &str) -> Result<Installed, String> {
    if !wire::is_label(platform) {
        return Err("platform must be [A-Za-z0-9._-]{1,64}".into());
    }
    ctx.enrollment()?;
    let auth = crate::keys::load("uplink", &ctx.cfg.uplink_key)?;
    let body = client::exchange(
        t,
        "GET",
        &format!("{}/{platform}", wire::PATH_REVOCATIONS),
        b"",
        Some((&auth.signing, ctx.now())),
    )
    .map_err(|e| e.to_string())?;
    install(ctx, &body, platform)
}

fn installed_mark(
    path: &Path,
    roots: &robodr_commission::trust::TrustRoots,
) -> Option<(u64, String)> {
    let b = fsx::read_optional(path, MAX_LIST_BYTES).ok()??;
    let l = RevocationList::parse(std::str::from_utf8(&b).ok()?).ok()?;
    l.verify(roots).ok()?;
    Some((l.serial, l.digest()))
}

/// Verify `bytes` as the list for `platform` and install it at agentd's
/// `revocation_list` path.
pub fn install(ctx: &Ctx, bytes: &[u8], platform: &str) -> Result<Installed, String> {
    let roots_path = ctx.facts.trust_roots.as_deref().ok_or(
        "agentd has no sensor.profile_trust.trust_roots: a revocation list cannot be \
         authenticated on this unit",
    )?;
    let target =
        ctx.facts.revocation_list.as_deref().ok_or(
            "agentd has no sensor.profile_trust.revocation_list path to install the list to",
        )?;
    if bytes.len() as u64 > MAX_LIST_BYTES {
        return Err("revocation list too large".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "revocation list is not UTF-8")?;
    let roots = load_trust_roots(roots_path).map_err(|e| e.to_string())?;
    let list = RevocationList::parse(text).map_err(|e| e.to_string())?;
    list.verify(&roots).map_err(|e| e.to_string())?;
    if list.platform != platform {
        return Err(format!(
            "the list is for platform {:?}, this unit is {platform:?}",
            list.platform
        ));
    }
    let digest = list.digest();
    // Anti-rollback floor.
    let mut marks: Vec<RevocationMark> = ctx.load(MARKS)?.unwrap_or_default();
    let mut floor: Vec<(u64, String, &str)> = Vec::new();
    if let Some(m) = marks.iter().find(|m| m.platform == platform) {
        floor.push((
            m.serial,
            m.digest.clone(),
            "last list installed by robodr-enroll",
        ));
    }
    if let Some((s, d)) = installed_mark(target, &roots) {
        floor.push((s, d, "list currently installed"));
    }
    if let Some(sf) = &ctx.facts.state_file {
        if let Ok(Some(st)) = load_state(sf) {
            if let (Some(s), Some(d)) = (st.revocation_serial, st.revocation_digest) {
                floor.push((s, d, "agentd's accepted state"));
            }
        }
    }
    let mut unchanged = false;
    for (s, d, what) in &floor {
        if list.serial < *s {
            return Err(format!(
                "rollback refused: list serial {} is older than serial {s} ({what})",
                list.serial
            ));
        }
        if list.serial == *s {
            if *d != digest {
                return Err(format!(
                    "equivocation refused: serial {s} with other content than the {what}"
                ));
            }
            unchanged = true;
        }
    }
    // What agentd would decide for the active profile with this list.
    let active_profile_refused = match &ctx.facts.profile_path {
        Some(pp) if pp.exists() => {
            let staged = ctx.path("revocations-candidate.json");
            fsx::write_atomic(&staged, bytes).map_err(|e| e.to_string())?;
            let raw = String::from_utf8(
                fsx::read_capped(pp, 8 * 1024 * 1024).map_err(|e| e.to_string())?,
            )
            .unwrap_or_default();
            let inp = TrustInputs {
                trusted_keys: ctx.facts.trusted_keys.as_deref(),
                trust_roots: Some(roots_path),
                revocation_list: Some(&staged),
                revocation_policy: ctx.facts.revocation_policy,
                expect_platform: ctx.facts.expect_platform.as_deref(),
                expect_unit_id: ctx.facts.expect_unit_id.as_deref(),
                state_file: None,
                allow_rollback: None,
                chain: None,
            };
            let r = evaluate_profile_trust(pp, &raw, &inp).result.err();
            let _ = std::fs::remove_file(&staged);
            r.map(|e| e.to_string())
        }
        _ => None,
    };
    if !(unchanged && target.exists()) {
        crate::install::install_public(target, bytes)?;
    }
    marks.retain(|m| m.platform != platform);
    marks.push(RevocationMark {
        platform: platform.into(),
        serial: list.serial,
        digest: digest.clone(),
    });
    ctx.store(MARKS, &marks)?;
    let en = ctx.enrollment()?;
    let mut j = ctx.journal(&en.robot_id)?;
    j.note(&serde_json::json!({
        "kind": crate::journal::K_REVOCATIONS,
        "platform": platform,
        "serial": list.serial,
        "digest": digest,
        "signed_by": list.signature.key_id,
        "unchanged": unchanged,
        "active_profile_refused": active_profile_refused,
    }))?;
    j.close()?;
    Ok(Installed {
        serial: list.serial,
        digest,
        unchanged,
        active_profile_refused,
    })
}
