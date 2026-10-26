//! Key rotation with overlap (contract §5).
//!
//! ```text
//! prepared ──(SOC: rotate answer "overlap")──► registered ──(local swap)──► swapped
//!    │ new key at <key>.next, request              both keys valid at the SOC   │
//!    │ stored byte-exact in rotation-<role>.json        │                       │
//!    ├─ abort: shred .next (never sent)                 │   (SOC: retire answer "retired")
//!    └─ sent: cancel at the SOC (signed by the old key) ┘   old key shredded, rotation done
//!       (SOC: cancel answer "cancelled") -> shred .next, rotation done
//! ```
//!
//! * The **old key stays valid until the SOC confirms**: it signs the
//!   rotate request (with the new key: proof of possession of both), stays
//!   the active key file until the SOC has registered the new one, and is
//!   kept in `<keydir>/retired/` after the swap until the SOC answers the
//!   retire request (signed by the new key). Only then is it shredded.
//! * **Atomic swap**: the new key is written next to the active one
//!   (`<key>.next`, exclusive create, 0600) and `rename(2)`d over it; a
//!   reader sees the old key or the new one, never a partial file.
//! * **A sent request is never abandoned locally**: `sent` is persisted
//!   before the first submit (and before `--request-out` writes the file);
//!   from then on the SOC may hold the rotation (an answer can be lost), so
//!   [`abort`] refuses and the rotation is either resent (the SOC answers
//!   with its stored answer) or cancelled at the SOC ([`cancel_request`],
//!   signed by the old key), which also closes it there.
//! * **Crash safety**: every phase is in the rotation journal
//!   (`rotation-<role>.json`) before the next step, requests are stored
//!   byte-exact and resent unchanged (the SOC answers a repeated
//!   `rotation_id` with its stored answer), and every step is idempotent;
//!   re-running `robodr-enroll rotate --role R` resumes. [`Crash`] names the
//!   points the tests interrupt.
//! * **Fleet journal continuity**: each phase is a journal note, and the
//!   swap writes the `key_handover` note signed by both keys over the
//!   journal head it follows (`journal` module docs), then seals.
//! * Services read their key at start (systemd `LoadCredential=`): after
//!   the swap, restart the service (`robodr-uplink` for `uplink`,
//!   `robodr-agentd` for `finding`), and finish only once it runs with the
//!   new key — for `finding`, also once the findings signed with the old key
//!   have been delivered (the SOC verifies them with the old key until it is
//!   retired).

use robodr_blackbox::crypto::to_hex;
use robodr_blackbox::KeyFile;
use std::path::{Path, PathBuf};

use crate::client::{self, SocTransport};
use crate::fsx;
use crate::keys::{self, SocKeys};
use crate::state::{Ctx, Enrollment, Phase, Rotation, ROTATION_FORMAT};
use crate::wire::{self, CancelRequest, Envelope, KeyAnswer, RetireRequest, RotateRequest};

/// Points where the crash tests interrupt a rotation (no-op in production).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Crash {
    /// The new key file exists, the rotation journal does not.
    AfterNewKey,
    /// The journal (phase `prepared`) is stored; nothing sent.
    AfterPrepared,
    /// The old key is copied to `retired/`; the active file is still old.
    AfterRetiredCopy,
    /// The new key is the active file; `.pub` and journal not updated.
    AfterRename,
    /// The handover note is written; the phase is still `registered`.
    AfterHandover,
    /// The old key is shredded; the rotation journal still exists.
    AfterShred,
}

/// The production hook: never interrupts.
pub fn no_crash(_: Crash) -> Result<(), String> {
    Ok(())
}

fn journal_name(role: &str) -> String {
    format!("rotation-{role}.json")
}

fn check_role(role: &str) -> Result<(), String> {
    if wire::ROTATABLE.contains(&role) {
        Ok(())
    } else {
        Err(format!(
            "--role must be one of {:?} (the black-box key is not rotated by robodr-enroll: \
             agentd's chain would need the old key to verify; see OPERATIONS 8.6)",
            wire::ROTATABLE
        ))
    }
}

/// `<keydir>/retired/<role>-<old key hex>.key`.
pub fn retired_path(key: &Path, role: &str, old_key_id: &str) -> PathBuf {
    let dir = key.parent().unwrap_or(Path::new("/")).join("retired");
    let hex = old_key_id.strip_prefix("ed25519:").unwrap_or(old_key_id);
    dir.join(format!("{role}-{hex}.key"))
}

/// The unfinished rotation of `role`, if any.
pub fn current(ctx: &Ctx, role: &str) -> Result<Option<Rotation>, String> {
    check_role(role)?;
    ctx.load::<Rotation>(&journal_name(role))
}

/// Start a rotation of `role` (or return the unfinished one): generate the
/// new key at `<key>.next` and build the rotate request.
pub fn prepare(
    ctx: &Ctx,
    role: &str,
    crash: &dyn Fn(Crash) -> Result<(), String>,
) -> Result<Rotation, String> {
    check_role(role)?;
    if let Some(r) = current(ctx, role)? {
        return Ok(r);
    }
    let en = ctx.enrollment()?;
    let path = ctx.cfg.key_path(role).expect("role checked").to_path_buf();
    let old = keys::load(role, &path)?;
    let registered = en
        .key(role)
        .ok_or_else(|| format!("enrollment has no {role} key"))?;
    if registered.fingerprint != old.fingerprint() {
        return Err(format!(
            "{} holds key {} but the SOC has {} registered as this unit's {role} key; \
             refusing to rotate a key the SOC does not know",
            path.display(),
            old.key_id(),
            registered.key_id
        ));
    }
    let next = fsx::with_suffix(&path, ".next");
    // An orphan from a crash before the journal was written: it was never
    // sent anywhere.
    if std::fs::symlink_metadata(&next).is_ok() {
        fsx::shred(&next).map_err(|e| format!("{}: {e}", next.display()))?;
    }
    fsx::check_parent_private(&path).map_err(|e| e.to_string())?;
    let kf = KeyFile::generate_ed25519(None).map_err(|e| e.to_string())?;
    kf.write_new(&next)
        .map_err(|e| format!("{}: {e}", next.display()))?;
    let new = keys::load(role, &next)?;
    crash(Crash::AfterNewKey)?;
    let mut rid = [0u8; 16];
    robodr_blackbox::crypto::fill_random(&mut rid).map_err(|e| e.to_string())?;
    let req = RotateRequest {
        format: wire::ROTATE_REQUEST_FORMAT.into(),
        rotation_id: format!("rfr1-{}", to_hex(&rid)),
        workspace: en.workspace.clone(),
        robot_id: en.robot_id.clone(),
        role: role.into(),
        old_key_id: old.key_id(),
        old_fingerprint: old.fingerprint(),
        new_key_id: new.key_id(),
        new_public_hex: to_hex(&new.public()),
        new_fingerprint: new.fingerprint(),
        created_at_ms: ctx.now(),
    };
    let payload = wire::payload_bytes(&req);
    let env = Envelope::sign(
        wire::T_ROTATE_REQUEST,
        &payload,
        &[&old.signing, &new.signing],
    );
    let rot = Rotation {
        format: ROTATION_FORMAT.into(),
        rotation_id: req.rotation_id.clone(),
        role: role.into(),
        workspace: en.workspace.clone(),
        robot_id: en.robot_id.clone(),
        phase: Phase::Prepared,
        old_key_id: req.old_key_id.clone(),
        old_fingerprint: req.old_fingerprint.clone(),
        new_key_id: req.new_key_id.clone(),
        new_fingerprint: req.new_fingerprint.clone(),
        request: String::from_utf8(env.to_bytes()).expect("UTF-8"),
        request_digest: wire::digest(&payload),
        sent: false,
        cancel_request: None,
        retire_request: None,
        started_at_ms: req.created_at_ms,
    };
    ctx.store(&journal_name(role), &rot)?;
    crash(Crash::AfterPrepared)?;
    note(ctx, &en, &rot, "prepared", None)?;
    Ok(rot)
}

fn note(
    ctx: &Ctx,
    en: &Enrollment,
    rot: &Rotation,
    phase: &str,
    extra: Option<serde_json::Value>,
) -> Result<(), String> {
    let mut j = ctx.journal(&en.robot_id)?;
    let mut n = serde_json::json!({
        "kind": crate::journal::K_ROTATION,
        "phase": phase,
        "rotation_id": rot.rotation_id,
        "role": rot.role,
        "old_key_id": rot.old_key_id,
        "old_fingerprint": rot.old_fingerprint,
        "new_key_id": rot.new_key_id,
        "new_fingerprint": rot.new_fingerprint,
    });
    if let (Some(serde_json::Value::Object(x)), Some(m)) = (extra, n.as_object_mut()) {
        m.extend(x);
    }
    j.note(&n)?;
    j.close()
}

/// The uplink key that authenticates this unit's requests now.
fn uplink_auth(ctx: &Ctx) -> Result<keys::RoleKey, String> {
    keys::load("uplink", &ctx.cfg.uplink_key)
}

/// Record that the rotate request may reach the SOC (before it is sent or
/// written out); returns the rotation.
pub fn mark_sent(ctx: &Ctx, role: &str) -> Result<Rotation, String> {
    let mut rot = current(ctx, role)?.ok_or("no rotation in progress")?;
    if !rot.sent {
        rot.sent = true;
        ctx.store(&journal_name(role), &rot)?;
    }
    Ok(rot)
}

/// The rotate request envelope for the air-gapped flow (marks it sent).
pub fn request_out(ctx: &Ctx, role: &str) -> Result<Vec<u8>, String> {
    Ok(mark_sent(ctx, role)?.request.into_bytes())
}

/// Send the stored rotate request and register the answer.
pub fn submit_rotate(ctx: &Ctx, t: &mut dyn SocTransport, role: &str) -> Result<Rotation, String> {
    let rot = current(ctx, role)?.ok_or("no rotation in progress")?;
    if rot.phase != Phase::Prepared {
        return Ok(rot);
    }
    if rot.cancel_request.is_some() {
        return Err(cancelling(role));
    }
    let rot = mark_sent(ctx, role)?;
    let auth = uplink_auth(ctx)?;
    let ans = client::exchange(
        t,
        "POST",
        wire::PATH_ROTATE,
        rot.request.as_bytes(),
        Some((&auth.signing, ctx.now())),
    )
    .map_err(|e| e.to_string())?;
    register(ctx, role, &ans)
}

fn check_key_answer(
    ctx: &Ctx,
    rot: &Rotation,
    bytes: &[u8],
    kind: &str,
    format: &str,
    status: &str,
    digest: &str,
) -> Result<KeyAnswer, String> {
    let o = Envelope::parse(bytes, kind).map_err(|e| format!("answer: {e}"))?;
    SocKeys::load(&ctx.cfg.soc_keys)?
        .verify(&o)
        .map_err(|e| format!("answer: {e}"))?;
    let a = KeyAnswer::parse(&o.payload, format, status).map_err(|e| format!("answer: {e}"))?;
    if a.rotation_id != rot.rotation_id
        || a.request_digest != digest
        || a.workspace != rot.workspace
        || a.robot_id != rot.robot_id
        || a.role != rot.role
        || a.old_key_id != rot.old_key_id
        || a.new_key_id != rot.new_key_id
    {
        return Err(
            "answer does not match this rotation (another rotation, robot or request)".into(),
        );
    }
    Ok(a)
}

/// Register the SOC's rotate answer (online or from a file).
pub fn register(ctx: &Ctx, role: &str, answer: &[u8]) -> Result<Rotation, String> {
    let mut rot = current(ctx, role)?.ok_or("no rotation in progress")?;
    if rot.phase != Phase::Prepared {
        return Ok(rot);
    }
    let a = check_key_answer(
        ctx,
        &rot,
        answer,
        wire::T_ROTATE_ANSWER,
        wire::ROTATE_ANSWER_FORMAT,
        "overlap",
        &rot.request_digest,
    )?;
    rot.phase = Phase::Registered;
    ctx.store(&journal_name(role), &rot)?;
    let en = ctx.enrollment()?;
    note(
        ctx,
        &en,
        &rot,
        "registered",
        Some(serde_json::json!({ "registered_at_ms": a.at_ms })),
    )?;
    Ok(rot)
}

/// Swap the key files: the old key to `retired/`, `<key>.next` over the
/// active file, `.pub` rewritten, the handover note written.
pub fn swap(
    ctx: &Ctx,
    role: &str,
    crash: &dyn Fn(Crash) -> Result<(), String>,
) -> Result<Rotation, String> {
    let mut rot = current(ctx, role)?.ok_or("no rotation in progress")?;
    match rot.phase {
        Phase::Prepared => {
            return Err(
                "the SOC has not confirmed the new key yet (overlap not open): submit the \
                 rotate request first"
                    .into(),
            )
        }
        Phase::Swapped => return Ok(rot),
        Phase::Registered if rot.cancel_request.is_some() => return Err(cancelling(role)),
        Phase::Registered => {}
    }
    let path = ctx.cfg.key_path(role).expect("role").to_path_buf();
    let next = fsx::with_suffix(&path, ".next");
    let retired = retired_path(&path, role, &rot.old_key_id);
    fsx::ensure_private_dir(retired.parent().expect("has parent"))
        .map_err(|e| format!("{}: {e}", retired.display()))?;
    let active = keys::load(role, &path)?;
    if active.fingerprint() == rot.old_fingerprint {
        // (a) keep the old key until the SOC retires it.
        match keys::load(role, &retired) {
            Ok(k) if k.fingerprint() == rot.old_fingerprint => {}
            Ok(_) => {
                return Err(format!(
                    "{} holds another key; refusing to overwrite it",
                    retired.display()
                ))
            }
            Err(_) => {
                if std::fs::symlink_metadata(&retired).is_ok() {
                    fsx::shred(&retired).map_err(|e| e.to_string())?;
                }
                let kf = KeyFile::load_secret(&path).map_err(|e| e.to_string())?;
                kf.write_new(&retired)
                    .map_err(|e| format!("{}: {e}", retired.display()))?;
            }
        }
        crash(Crash::AfterRetiredCopy)?;
        // (b) atomic swap.
        let nk = keys::load(role, &next)?;
        if nk.fingerprint() != rot.new_fingerprint {
            return Err(format!(
                "{} does not hold the registered new key {}",
                next.display(),
                rot.new_key_id
            ));
        }
        fsx::rename_durable(&next, &path).map_err(|e| format!("swap {}: {e}", path.display()))?;
        crash(Crash::AfterRename)?;
    } else if active.fingerprint() != rot.new_fingerprint {
        return Err(format!(
            "{} holds neither the old nor the new key of rotation {}; refusing",
            path.display(),
            rot.rotation_id
        ));
    }
    // (c) the public half.
    let kf = KeyFile::load_secret(&path).map_err(|e| e.to_string())?;
    keys::write_public(&kf, &path)?;
    // (d) handover note, signed by both keys over the journal head.
    let old = keys::load(role, &retired)?;
    let new = keys::load(role, &path)?;
    let en = ctx.enrollment()?;
    let mut j = ctx.journal(&en.robot_id)?;
    let head = j.head_hex();
    let stmt = wire::handover_message(
        &rot.rotation_id,
        role,
        &rot.old_fingerprint,
        &rot.new_fingerprint,
        &head,
    );
    j.note(&serde_json::json!({
        "kind": crate::journal::K_HANDOVER,
        "rotation_id": rot.rotation_id,
        "role": role,
        "old_key_id": rot.old_key_id,
        "old_fingerprint": rot.old_fingerprint,
        "new_key_id": rot.new_key_id,
        "new_fingerprint": rot.new_fingerprint,
        "journal_head": head,
        "old_sig": to_hex(&old.signing.sign_message(&stmt)),
        "new_sig": to_hex(&new.signing.sign_message(&stmt)),
    }))?;
    j.seal()?;
    j.close()?;
    crash(Crash::AfterHandover)?;
    rot.phase = Phase::Swapped;
    ctx.store(&journal_name(role), &rot)?;
    Ok(rot)
}

/// Build (once) and return the retire request envelope.
pub fn retire_request(ctx: &Ctx, role: &str) -> Result<Vec<u8>, String> {
    let mut rot = current(ctx, role)?.ok_or("no rotation in progress")?;
    if rot.phase != Phase::Swapped {
        return Err("the new key is not active yet: finish the swap first".into());
    }
    if let Some(r) = &rot.retire_request {
        return Ok(r.as_bytes().to_vec());
    }
    let new = keys::load(role, ctx.cfg.key_path(role).expect("role"))?;
    if new.fingerprint() != rot.new_fingerprint {
        return Err("the active key file is not the rotation's new key".into());
    }
    let req = RetireRequest {
        format: wire::RETIRE_REQUEST_FORMAT.into(),
        rotation_id: rot.rotation_id.clone(),
        workspace: rot.workspace.clone(),
        robot_id: rot.robot_id.clone(),
        role: role.into(),
        old_key_id: rot.old_key_id.clone(),
        new_key_id: rot.new_key_id.clone(),
        created_at_ms: ctx.now(),
    };
    let env = Envelope::sign(
        wire::T_RETIRE_REQUEST,
        &wire::payload_bytes(&req),
        &[&new.signing],
    );
    let text = String::from_utf8(env.to_bytes()).expect("UTF-8");
    rot.retire_request = Some(text.clone());
    ctx.store(&journal_name(role), &rot)?;
    Ok(text.into_bytes())
}

/// Send the retire request and finish with the answer.
pub fn submit_retire(
    ctx: &Ctx,
    t: &mut dyn SocTransport,
    role: &str,
    crash: &dyn Fn(Crash) -> Result<(), String>,
) -> Result<Enrollment, String> {
    let body = retire_request(ctx, role)?;
    let auth = uplink_auth(ctx)?;
    let ans = client::exchange(
        t,
        "POST",
        wire::PATH_RETIRE,
        &body,
        Some((&auth.signing, ctx.now())),
    )
    .map_err(|e| e.to_string())?;
    finish(ctx, role, &ans, crash)
}

/// Verify the retire answer, shred the old key and close the rotation.
pub fn finish(
    ctx: &Ctx,
    role: &str,
    answer: &[u8],
    crash: &dyn Fn(Crash) -> Result<(), String>,
) -> Result<Enrollment, String> {
    let rot = current(ctx, role)?.ok_or("no rotation in progress")?;
    let req = rot
        .retire_request
        .as_deref()
        .ok_or("no retire request was built for this rotation")?;
    let o = Envelope::parse(req.as_bytes(), wire::T_RETIRE_REQUEST).map_err(|e| e.to_string())?;
    let a = check_key_answer(
        ctx,
        &rot,
        answer,
        wire::T_RETIRE_ANSWER,
        wire::RETIRE_ANSWER_FORMAT,
        "retired",
        &o.payload_digest(),
    )?;
    let path = ctx.cfg.key_path(role).expect("role").to_path_buf();
    let retired = retired_path(&path, role, &rot.old_key_id);
    fsx::shred(&retired).map_err(|e| format!("{}: {e}", retired.display()))?;
    crash(Crash::AfterShred)?;
    let mut en = ctx.enrollment()?;
    for k in &mut en.keys {
        if k.role == role {
            k.key_id = rot.new_key_id.clone();
            k.fingerprint = rot.new_fingerprint.clone();
        }
    }
    ctx.store("enrollment.json", &en)?;
    note(
        ctx,
        &en,
        &rot,
        "retired",
        Some(serde_json::json!({ "retired_at_ms": a.at_ms })),
    )?;
    ctx.remove(&journal_name(role))?;
    Ok(en)
}

fn cancelling(role: &str) -> String {
    format!(
        "a cancel request was built for this rotation: finish the cancellation \
         (robodr-enroll rotate --role {role} --cancel)"
    )
}

/// Abandon a rotation whose request never left the unit (phase `prepared`,
/// not sent): the new key never became valid anywhere, so it is shredded.
/// A sent request may have reached the SOC (a lost answer): it is resent
/// or cancelled at the SOC ([`cancel_request`]), never abandoned locally.
/// A registered rotation is finished or cancelled.
pub fn abort(ctx: &Ctx, role: &str) -> Result<(), String> {
    let rot = current(ctx, role)?.ok_or("no rotation in progress")?;
    if rot.phase != Phase::Prepared {
        return Err(format!(
            "the SOC already registered the new key; a registered rotation is finished \
             (robodr-enroll rotate --role {role}, then --finish) or cancelled at the SOC \
             (robodr-enroll rotate --role {role} --cancel), not aborted"
        ));
    }
    if rot.sent {
        return Err(format!(
            "the rotate request {} may have reached the SOC (it was sent or written out), so \
             it is not abandoned locally: resend it (robodr-enroll rotate --role {role}; the SOC \
             answers with its stored answer) or cancel it at the SOC (robodr-enroll rotate \
             --role {role} --cancel)",
            rot.rotation_id
        ));
    }
    let path = ctx.cfg.key_path(role).expect("role");
    fsx::shred(&fsx::with_suffix(path, ".next")).map_err(|e| e.to_string())?;
    let en = ctx.enrollment()?;
    note(ctx, &en, &rot, "aborted", None)?;
    ctx.remove(&journal_name(role))
}

/// Build (once) and return the cancel request envelope (§5.5): signed by
/// the old key, which must still be the active key file (before the swap).
pub fn cancel_request(ctx: &Ctx, role: &str) -> Result<Vec<u8>, String> {
    let mut rot = current(ctx, role)?.ok_or("no rotation in progress")?;
    if let Some(r) = &rot.cancel_request {
        return Ok(r.as_bytes().to_vec());
    }
    if rot.phase == Phase::Swapped {
        return Err(format!(
            "the new key is already the active key: finish the rotation \
             (robodr-enroll rotate --role {role} --finish)"
        ));
    }
    let path = ctx.cfg.key_path(role).expect("role");
    let old = keys::load(role, path)?;
    if old.fingerprint() != rot.old_fingerprint {
        return Err(format!(
            "{} no longer holds the rotation's old key (the swap has begun): finish the \
             rotation (robodr-enroll rotate --role {role}) instead",
            path.display()
        ));
    }
    let req = CancelRequest {
        format: wire::CANCEL_REQUEST_FORMAT.into(),
        rotation_id: rot.rotation_id.clone(),
        request_digest: rot.request_digest.clone(),
        workspace: rot.workspace.clone(),
        robot_id: rot.robot_id.clone(),
        role: role.into(),
        old_key_id: rot.old_key_id.clone(),
        new_key_id: rot.new_key_id.clone(),
        created_at_ms: ctx.now(),
    };
    let env = Envelope::sign(
        wire::T_CANCEL_REQUEST,
        &wire::payload_bytes(&req),
        &[&old.signing],
    );
    let text = String::from_utf8(env.to_bytes()).expect("UTF-8");
    rot.cancel_request = Some(text.clone());
    ctx.store(&journal_name(role), &rot)?;
    Ok(text.into_bytes())
}

/// Send the cancel request and close the rotation with the answer.
pub fn submit_cancel(ctx: &Ctx, t: &mut dyn SocTransport, role: &str) -> Result<(), String> {
    let body = cancel_request(ctx, role)?;
    let auth = uplink_auth(ctx)?;
    let ans = client::exchange(
        t,
        "POST",
        wire::PATH_CANCEL,
        &body,
        Some((&auth.signing, ctx.now())),
    )
    .map_err(|e| e.to_string())?;
    cancelled(ctx, role, &ans)
}

/// Verify the SOC's cancel answer, shred the new key and close the
/// rotation (the old key stays the active one).
pub fn cancelled(ctx: &Ctx, role: &str, answer: &[u8]) -> Result<(), String> {
    let rot = current(ctx, role)?.ok_or("no rotation in progress")?;
    let req = rot
        .cancel_request
        .as_deref()
        .ok_or("no cancel request was built for this rotation")?;
    let o = Envelope::parse(req.as_bytes(), wire::T_CANCEL_REQUEST).map_err(|e| e.to_string())?;
    let a = check_key_answer(
        ctx,
        &rot,
        answer,
        wire::T_CANCEL_ANSWER,
        wire::CANCEL_ANSWER_FORMAT,
        "cancelled",
        &o.payload_digest(),
    )?;
    let path = ctx.cfg.key_path(role).expect("role").to_path_buf();
    let active = keys::load(role, &path)?;
    if active.fingerprint() != rot.old_fingerprint {
        return Err(format!(
            "{} does not hold the old key {}; refusing to shred anything",
            path.display(),
            rot.old_key_id
        ));
    }
    fsx::shred(&fsx::with_suffix(&path, ".next")).map_err(|e| e.to_string())?;
    // A copy of the (still active) old key from an interrupted swap.
    let retired = retired_path(&path, role, &rot.old_key_id);
    fsx::shred(&retired).map_err(|e| format!("{}: {e}", retired.display()))?;
    let en = ctx.enrollment()?;
    note(
        ctx,
        &en,
        &rot,
        "cancelled",
        Some(serde_json::json!({ "cancelled_at_ms": a.at_ms })),
    )?;
    ctx.remove(&journal_name(role))
}
