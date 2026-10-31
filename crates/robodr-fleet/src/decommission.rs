//! Decommissioning (contract §5.6): the unit asks the SOC, in a request
//! signed by its three registered keys, to retire every key it holds and
//! close its registration; the SOC's signed answer is the receipt.
//!
//! ```text
//! (none) ──prepare──► prepared ──(SOC: answer "decommissioned")──► done
//!           request stored          │ journal note + seal (black-box key)
//!           byte-exact              │ uplink and finding secret keys shredded
//!   abort: only while never sent    │ enrollment.json removed
//!                                   └ decommission.json kept: the receipt
//! ```
//!
//! * **Signed both ways**: the request is signed by the `uplink`,
//!   `finding` and `blackbox` keys the SOC has registered for the unit (in
//!   that order: proof that the unit itself, holding every key, asks), names
//!   those keys and the fleet journal head it follows; the answer is signed
//!   by a configured SOC fleet key and must repeat every field. Request and
//!   answer together are the decommission receipt
//!   (`robodr-fleet-decommission-receipt/v1`, [`receipt`]), which the
//!   operator archives with the site's records.
//! * **Online or as files** (air-gapped): `robodr-enroll decommission`
//!   sends the request; `--request-out FILE` writes it for vetted media and
//!   `--answer FILE` completes with the SOC's answer. Nothing else differs.
//! * **A sent request is never abandoned locally**: once it may have
//!   reached the SOC (submitted or written out) the SOC may have retired
//!   the keys already, so [`abort`] refuses; the stored request is resent
//!   unchanged (the SOC answers with its stored answer, §5.6) and the
//!   decommission completes.
//! * **Crash safety**: the request is stored before it is sent; the answer
//!   is stored before any key is shredded; re-running the command after a
//!   crash finishes it. The journal notes are not exactly-once: a crash
//!   between storing the request and its `prepared` note leaves the
//!   journal without that note (the re-run returns the stored request;
//!   the final `decommissioned` note still carries the request digest),
//!   and a crash right after the final note is sealed writes that note a
//!   second time on the re-run.
//! * **A black-box key rotated in place** (`robodr-blackbox rotate`,
//!   `docs/OPERATIONS.md` 4.3) is not known to the SOC: the fleet API does
//!   not rotate the black-box role, so the SOC still has the enrollment
//!   black-box key registered. The request is then signed with that
//!   registered key, found by its fingerprint among the retired keys in
//!   `<key directory>/retired/` (where the rotation procedure keeps it on
//!   an enrolled unit); without it the request is refused here, before
//!   anything is sent, with the way out.
//! * **What is destroyed here, and what is not**: the uplink and finding
//!   secret keys (retired at the SOC: they authenticate nothing any more)
//!   are shredded. The black-box key is **kept**: it signs the final journal
//!   note, and agentd's black box may still have to be exported and
//!   verified; it is destroyed with the rest of the unit's data in the
//!   sanitisation step of the procedure (`docs/DECOMMISSION.md`).
//!   [`fsx::shred`] is best effort on flash media (wear levelling): media
//!   sanitisation (NIST SP 800-88) is still required.

use robodr_blackbox::crypto::to_hex;
use serde::{Deserialize, Serialize};

use crate::client::{self, SocTransport};
use crate::fsx;
use crate::keys::{self, SocKeys};
use crate::state::Ctx;
use crate::wire::{self, DecommissionAnswer, DecommissionRequest, Envelope, KeyRef};

/// The decommission journal and, once done, the receipt.
pub const STATE_FILE: &str = "decommission.json";
pub const STATE_FORMAT: &str = "robodr-fleet-decommission/v1";
pub const RECEIPT_FORMAT: &str = "robodr-fleet-decommission-receipt/v1";

/// Phase of a decommission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// The request is built and stored; no verified answer yet.
    Prepared,
    /// The SOC's answer is verified and stored; local clean-up may be
    /// unfinished.
    Answered,
    /// Clean-up done: keys shredded, enrollment removed.
    Done,
}

/// `decommission.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decommission {
    pub format: String,
    pub decommission_id: String,
    pub workspace: String,
    pub robot_id: String,
    pub site: Option<String>,
    pub reason: String,
    pub keys: Vec<KeyRef>,
    pub phase: Phase,
    /// The exact request envelope (resent byte-identical).
    pub request: String,
    pub request_digest: String,
    /// The request may have reached the SOC (set before the first submit
    /// and before `--request-out` writes it).
    pub sent: bool,
    /// The exact, verified answer envelope.
    pub answer: Option<String>,
    /// The SOC fleet key that signed the answer.
    pub soc_key_id: Option<String>,
    /// SOC time of the decommission (from the answer).
    pub decommissioned_at_ms: Option<u64>,
    pub created_at_ms: u64,
}

/// What [`receipt`] returns: the signed request and the signed answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub format: String,
    pub decommission_id: String,
    pub workspace: String,
    pub robot_id: String,
    pub site: Option<String>,
    pub reason: String,
    pub keys: Vec<KeyRef>,
    pub soc_key_id: String,
    pub decommissioned_at_ms: u64,
    /// The request envelope, verbatim (signed by the unit's three keys).
    pub request: String,
    /// The answer envelope, verbatim (signed by the SOC fleet key).
    pub answer: String,
}

/// The decommission in progress or done on this unit, if any.
pub fn current(ctx: &Ctx) -> Result<Option<Decommission>, String> {
    ctx.load::<Decommission>(STATE_FILE)
}

fn check_reason(reason: &str) -> Result<(), String> {
    if wire::DECOMMISSION_REASONS.contains(&reason) {
        Ok(())
    } else {
        Err(format!(
            "--reason must be one of {:?}",
            wire::DECOMMISSION_REASONS
        ))
    }
}

/// Build (or return the unfinished) decommission request. Refused while
/// an enrollment or a key rotation is unfinished, and when the key files
/// do not hold the keys the SOC has registered. The `prepared` journal note
/// is written after the request is stored, only by the call that builds
/// it (see "Crash safety" in the module docs).
pub fn prepare(ctx: &Ctx, reason: &str) -> Result<Decommission, String> {
    check_reason(reason)?;
    if let Some(d) = current(ctx)? {
        if d.phase != Phase::Done {
            if d.reason != reason {
                return Err(format!(
                    "decommission {} (reason {}) is unfinished; complete it first",
                    d.decommission_id, d.reason
                ));
            }
            return Ok(d);
        }
        return Err(format!(
            "this unit was decommissioned ({} at {} ms); nothing to do. To commission it \
             again, sanitise it and start from new keys and an empty fleet state directory \
             (docs/DECOMMISSION.md, \"Re-commissioning\")",
            d.decommission_id,
            d.decommissioned_at_ms.unwrap_or(0)
        ));
    }
    let en = ctx.enrollment()?;
    if ctx
        .load::<crate::state::PendingEnroll>("enroll-pending.json")?
        .is_some()
    {
        return Err("an enrollment request is pending; finish it first".into());
    }
    for role in wire::ROTATABLE {
        if let Some(r) = crate::rotate::current(ctx, role)? {
            return Err(format!(
                "rotation {} of the {role} key is unfinished: finish it (robodr-enroll rotate \
                 --role {role} [--finish]) or cancel it (--cancel / --abort) before \
                 decommissioning",
                r.rotation_id
            ));
        }
    }
    let mut role_keys = Vec::new();
    for role in wire::ROLES {
        let path = ctx.cfg.role_key_path(role)?;
        let k = keys::load(role, path)?;
        let registered = en
            .key(role)
            .ok_or_else(|| format!("enrollment has no {role} key"))?;
        if registered.fingerprint != k.fingerprint() && role == "blackbox" {
            // Rotated in place (OPERATIONS 4.3): sign with the registered,
            // retired key if the unit kept it.
            match keys::find_retired(role, path, &registered.fingerprint)? {
                Some(old) => {
                    role_keys.push(old);
                    continue;
                }
                None => {
                    return Err(format!(
                        "{} holds black-box key {} but the SOC has {} registered as this \
                         unit's black-box key (the key was rotated in place with \
                         robodr-blackbox rotate; the fleet API does not rotate it). The \
                         decommission request must be signed by the registered key: put \
                         the retired secret key file back in {}/retired/ (0600 root) and \
                         run this again (docs/OPERATIONS.md 4.3, docs/DECOMMISSION.md \
                         step 4). If it was destroyed, the SOC operator has to retire this \
                         unit's registration on the SOC side; the SOC would refuse this \
                         request (409 stale_key)",
                        path.display(),
                        k.key_id(),
                        registered.key_id,
                        path.parent().unwrap_or(std::path::Path::new("/")).display()
                    ));
                }
            }
        }
        if registered.fingerprint != k.fingerprint() {
            return Err(format!(
                "{} holds key {} but the SOC has {} registered as this unit's {role} key; \
                 the SOC would refuse the request (409 stale_key)",
                path.display(),
                k.key_id(),
                registered.key_id
            ));
        }
        role_keys.push(k);
    }
    let journal_head = {
        let j = ctx.journal(&en.robot_id)?;
        let h = j.head_hex();
        j.close()?;
        h
    };
    let mut rid = [0u8; 16];
    robodr_blackbox::crypto::fill_random(&mut rid).map_err(|e| e.to_string())?;
    let req = DecommissionRequest {
        format: wire::DECOMMISSION_REQUEST_FORMAT.into(),
        decommission_id: format!("rfd1-{}", to_hex(&rid)),
        workspace: en.workspace.clone(),
        robot_id: en.robot_id.clone(),
        reason: reason.into(),
        keys: role_keys.iter().map(keys::RoleKey::reference).collect(),
        journal_head,
        created_at_ms: ctx.now(),
    };
    let payload = wire::payload_bytes(&req)?;
    let signers: Vec<&robodr_blackbox::Ed25519SigningKey> =
        role_keys.iter().map(|k| &k.signing).collect();
    let env = Envelope::sign(wire::T_DECOMMISSION_REQUEST, &payload, &signers);
    let d = Decommission {
        format: STATE_FORMAT.into(),
        decommission_id: req.decommission_id.clone(),
        workspace: req.workspace.clone(),
        robot_id: req.robot_id.clone(),
        site: en.site.clone(),
        reason: req.reason.clone(),
        keys: req.keys.clone(),
        phase: Phase::Prepared,
        request: env.to_text()?,
        request_digest: wire::digest(&payload),
        sent: false,
        answer: None,
        soc_key_id: None,
        decommissioned_at_ms: None,
        created_at_ms: req.created_at_ms,
    };
    ctx.store(STATE_FILE, &d)?;
    let mut j = ctx.journal(&en.robot_id)?;
    j.note(&serde_json::json!({
        "kind": crate::journal::K_DECOMMISSION,
        "phase": "prepared",
        "decommission_id": d.decommission_id,
        "reason": d.reason,
        "request_digest": d.request_digest,
        "keys": d.keys,
    }))?;
    j.close()?;
    Ok(d)
}

/// Record that the request may reach the SOC; returns the decommission.
pub fn mark_sent(ctx: &Ctx) -> Result<Decommission, String> {
    let mut d = current(ctx)?.ok_or("no decommission in progress")?;
    if !d.sent {
        d.sent = true;
        ctx.store(STATE_FILE, &d)?;
    }
    Ok(d)
}

/// The request envelope for the air-gapped flow (marks it sent).
pub fn request_out(ctx: &Ctx) -> Result<Vec<u8>, String> {
    let d = mark_sent(ctx)?;
    if d.phase != Phase::Prepared {
        return Err("the SOC already answered this decommission".into());
    }
    Ok(d.request.into_bytes())
}

/// Send the stored request (authenticated by the uplink key it retires)
/// and complete with the answer.
pub fn submit(ctx: &Ctx, t: &mut dyn SocTransport) -> Result<Decommission, String> {
    let d = current(ctx)?.ok_or("no decommission in progress")?;
    if d.phase != Phase::Prepared {
        return complete(ctx);
    }
    let d = mark_sent(ctx)?;
    let auth = keys::load("uplink", &ctx.cfg.uplink_key)?;
    let ans = client::exchange(
        t,
        "POST",
        wire::PATH_DECOMMISSION,
        d.request.as_bytes(),
        Some((&auth.signing, ctx.now())),
    )
    .map_err(|e| e.to_string())?;
    accept(ctx, &ans)
}

/// Verify the SOC's answer (online or from a file), store it, and complete.
pub fn accept(ctx: &Ctx, answer: &[u8]) -> Result<Decommission, String> {
    let mut d = current(ctx)?.ok_or("no decommission in progress on this unit")?;
    if d.phase != Phase::Prepared {
        if d.answer.as_deref().map(str::as_bytes) == Some(answer) {
            return complete(ctx);
        }
        return Err("this decommission was already answered with another answer".into());
    }
    let o =
        Envelope::parse(answer, wire::T_DECOMMISSION_ANSWER).map_err(|e| format!("answer: {e}"))?;
    let signer = SocKeys::load(&ctx.cfg.soc_keys)?
        .verify(&o)
        .map_err(|e| format!("answer: {e}"))?;
    let a = DecommissionAnswer::parse(&o.payload).map_err(|e| format!("answer: {e}"))?;
    if a.decommission_id != d.decommission_id
        || a.request_digest != d.request_digest
        || a.workspace != d.workspace
        || a.robot_id != d.robot_id
        || a.reason != d.reason
        || a.keys != d.keys
    {
        return Err(
            "answer does not match this decommission (another request, robot or key set)".into(),
        );
    }
    d.phase = Phase::Answered;
    d.sent = true;
    d.answer =
        Some(String::from_utf8(answer.to_vec()).map_err(|_| "answer: not UTF-8".to_string())?);
    d.soc_key_id = Some(signer);
    d.decommissioned_at_ms = Some(a.at_ms);
    ctx.store(STATE_FILE, &d)?;
    complete(ctx)
}

/// Finish an answered decommission (idempotent): journal note and seal
/// (signed by the black-box key), shred the uplink and finding secret keys
/// (and any `.next` / `retired/` leftovers of them), remove the enrollment.
pub fn complete(ctx: &Ctx) -> Result<Decommission, String> {
    let mut d = current(ctx)?.ok_or("no decommission in progress")?;
    match d.phase {
        Phase::Prepared => return Err("the SOC has not answered this decommission yet".into()),
        Phase::Done => return Ok(d),
        Phase::Answered => {}
    }
    let answer = d
        .answer
        .clone()
        .ok_or("answered decommission without answer")?;
    let answer_digest = Envelope::parse(answer.as_bytes(), wire::T_DECOMMISSION_ANSWER)
        .map_err(|e| format!("stored answer: {e}"))?
        .payload_digest();
    // The journal note comes first: it is signed by the black-box key and
    // names the receipt. A re-run after the note is marked
    // (`journal_noted`) does not write it again; a crash after the seal
    // and before the mark is stored writes it a second time (same content:
    // at least once, at most twice).
    if !journal_noted(ctx, &d)? {
        let mut j = ctx.journal(&d.robot_id)?;
        j.note(&serde_json::json!({
            "kind": crate::journal::K_DECOMMISSION,
            "phase": "decommissioned",
            "decommission_id": d.decommission_id,
            "reason": d.reason,
            "request_digest": d.request_digest,
            "answer_digest": answer_digest,
            "soc_key_id": d.soc_key_id,
            "decommissioned_at_ms": d.decommissioned_at_ms,
            "keys": d.keys,
        }))?;
        j.seal()?;
        j.close()?;
        ctx.store(NOTED_FILE, &d.decommission_id)?;
    }
    for role in wire::ROTATABLE {
        let path = ctx.cfg.role_key_path(role)?.to_path_buf();
        for p in [path.clone(), fsx::with_suffix(&path, ".next")] {
            fsx::shred(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        }
        if let Some(k) = d.keys.iter().find(|k| k.role == role) {
            let r = crate::rotate::retired_path(&path, role, &k.key_id);
            fsx::shred(&r).map_err(|e| format!("{}: {e}", r.display()))?;
        }
    }
    ctx.remove("enrollment.json")?;
    ctx.remove(NOTED_FILE)?;
    d.phase = Phase::Done;
    ctx.store(STATE_FILE, &d)?;
    Ok(d)
}

/// Marks that the final journal note of a decommission is written.
const NOTED_FILE: &str = "decommission-noted.json";

fn journal_noted(ctx: &Ctx, d: &Decommission) -> Result<bool, String> {
    Ok(ctx.load::<String>(NOTED_FILE)?.as_deref() == Some(d.decommission_id.as_str()))
}

/// Abandon a decommission whose request never left the unit.
pub fn abort(ctx: &Ctx) -> Result<(), String> {
    let d = current(ctx)?.ok_or("no decommission in progress")?;
    if d.phase != Phase::Prepared {
        return Err("the SOC already answered: the decommission is completed, not aborted".into());
    }
    if d.sent {
        return Err(format!(
            "decommission request {} may have reached the SOC (it was sent or written out), \
             and the SOC may have retired the unit's keys already: it is not abandoned \
             locally; resend it (robodr-enroll decommission; the SOC answers with its stored \
             answer) or complete it with the answer file (--answer FILE)",
            d.decommission_id
        ));
    }
    let mut j = ctx.journal(&d.robot_id)?;
    j.note(&serde_json::json!({
        "kind": crate::journal::K_DECOMMISSION,
        "phase": "aborted",
        "decommission_id": d.decommission_id,
    }))?;
    j.close()?;
    ctx.remove(STATE_FILE)
}

/// The receipt of a finished (or answered) decommission.
pub fn receipt(d: &Decommission) -> Result<Receipt, String> {
    let (Some(answer), Some(soc_key_id), Some(at)) =
        (&d.answer, &d.soc_key_id, d.decommissioned_at_ms)
    else {
        return Err("the SOC has not answered this decommission yet".into());
    };
    Ok(Receipt {
        format: RECEIPT_FORMAT.into(),
        decommission_id: d.decommission_id.clone(),
        workspace: d.workspace.clone(),
        robot_id: d.robot_id.clone(),
        site: d.site.clone(),
        reason: d.reason.clone(),
        keys: d.keys.clone(),
        soc_key_id: soc_key_id.clone(),
        decommissioned_at_ms: at,
        request: d.request.clone(),
        answer: answer.clone(),
    })
}

/// [`receipt`] as pretty JSON with a final newline (the `--receipt-out`
/// file).
pub fn receipt_bytes(d: &Decommission) -> Result<Vec<u8>, String> {
    let mut s = serde_json::to_string_pretty(&receipt(d)?).map_err(|e| e.to_string())?;
    s.push('\n');
    Ok(s.into_bytes())
}
