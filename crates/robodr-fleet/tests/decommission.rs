//! Decommissioning (contract §5.6) against the reference SOC
//! (`tests/common/soc.rs`): online and air-gapped, a lost answer, the
//! refusals on both sides, the receipt, what is shredded and what is kept,
//! and re-enrollment of a decommissioned unit.

mod common;

use common::soc::{Direct, Down};
use common::*;
use robodr_blackbox::record::{scan_frames, ScanItem};
use robodr_blackbox::verify::{read_segments, verify_dir, VerifyOptions};
use robodr_blackbox::KeyFile;
use robodr_fleet::decommission::{self, Phase};
use robodr_fleet::wire::{self, Envelope};
use robodr_fleet::{enroll, rotate};
use std::cell::RefCell;

fn enrolled(tag: &str) -> (Unit, RefCell<common::soc::Soc>) {
    let u = Unit::new(tag);
    let soc = new_soc();
    let t = soc
        .borrow_mut()
        .issue_token("tok-1", ROBOT, Some(SITE), 3_600_000, [0x33; 32]);
    let ctx = u.ctx();
    enroll::prepare(&ctx, &t, &Default::default()).unwrap();
    enroll::submit(&ctx, &mut Direct { soc: &soc }).unwrap();
    (u, soc)
}

fn kinds(u: &Unit) -> Vec<serde_json::Value> {
    let dir = u.cfg.state_dir.join("journal");
    let kf = KeyFile::load_secret(&u.cfg.blackbox_key).unwrap();
    let v = kf.verifier().unwrap();
    let report = verify_dir(&dir, v.as_ref(), &VerifyOptions::default()).unwrap();
    assert!(report.is_intact(), "{:?}", report.findings);
    let mut out = Vec::new();
    for s in read_segments(&dir).unwrap() {
        for it in scan_frames(&s.bytes).items {
            if let ScanItem::Record(r) = it {
                if let Some(j) = r.record.payload_json::<serde_json::Value>() {
                    if j["kind"] == journal_kind() {
                        out.push(j);
                    }
                }
            }
        }
    }
    out
}

fn journal_kind() -> &'static str {
    robodr_fleet::journal::K_DECOMMISSION
}

fn active_keys(soc: &RefCell<common::soc::Soc>) -> usize {
    soc.borrow()
        .keys
        .values()
        .filter(|k| k.robot == ROBOT && k.retired_at.is_none())
        .count()
}

#[test]
fn online_decommission_retires_every_key_and_leaves_a_signed_receipt() {
    let (u, soc) = enrolled("decom-online");
    let ctx = u.ctx();
    let en = ctx.enrollment().unwrap();
    assert_eq!(active_keys(&soc), 3);
    let d = decommission::prepare(&ctx, "end_of_life").unwrap();
    assert_eq!(d.phase, Phase::Prepared);
    assert!(!d.sent);
    assert_eq!(d.keys, en.keys);
    let d = decommission::submit(&ctx, &mut Direct { soc: &soc }).unwrap();
    assert_eq!(d.phase, Phase::Done);

    // SOC: every key retired; the old uplink key authenticates nothing else.
    assert_eq!(active_keys(&soc), 0);
    // Unit: uplink and finding secrets shredded, black-box key kept (the
    // journal and agentd's black box still verify with it), public halves
    // kept, enrollment removed.
    assert!(!u.cfg.uplink_key.exists());
    assert!(!u.cfg.finding_key.exists());
    assert!(u.cfg.blackbox_key.exists());
    assert!(robodr_blackbox::keys::public_key_path(&u.cfg.uplink_key).exists());
    assert!(ctx
        .load::<robodr_fleet::state::Enrollment>("enrollment.json")
        .unwrap()
        .is_none());

    // The receipt: the request verifies under the three registered keys in
    // role order, the answer under the SOC fleet key.
    let r = decommission::receipt(&d).unwrap();
    assert_eq!(r.format, decommission::RECEIPT_FORMAT);
    let req = Envelope::parse(r.request.as_bytes(), wire::T_DECOMMISSION_REQUEST).unwrap();
    let ids: Vec<&str> = en.keys.iter().map(|k| k.key_id.as_str()).collect();
    assert_eq!(req.signers(), ids);
    let ans = Envelope::parse(r.answer.as_bytes(), wire::T_DECOMMISSION_ANSWER).unwrap();
    ans.verify_by(&key_id(&soc_key()), &soc_key().public_key())
        .unwrap();
    let a = wire::DecommissionAnswer::parse(&ans.payload).unwrap();
    assert_eq!(a.request_digest, req.payload_digest());
    assert_eq!(a.keys, en.keys);
    let p = wire::DecommissionRequest::parse(&req.payload).unwrap();
    assert!(wire::is_journal_head(&p.journal_head));
    assert_ne!(
        p.journal_head, "genesis",
        "enrollment wrote journal records"
    );

    // Journal: prepared, then decommissioned (signed by the black-box key).
    let notes = kinds(&u);
    let phases: Vec<&str> = notes.iter().filter_map(|n| n["phase"].as_str()).collect();
    assert_eq!(phases, ["prepared", "decommissioned"]);
    assert_eq!(notes[1]["answer_digest"], ans.payload_digest());

    // Idempotent: completing again changes nothing; a second decommission
    // of a decommissioned unit is refused.
    assert_eq!(decommission::complete(&ctx).unwrap().phase, Phase::Done);
    assert!(decommission::prepare(&ctx, "end_of_life")
        .unwrap_err()
        .contains("was decommissioned"));
    // Other lifecycle commands now find no enrollment.
    assert!(rotate::prepare(&ctx, "uplink", &rotate::no_crash).is_err());
}

#[test]
fn air_gapped_decommission_with_files() {
    let (u, soc) = enrolled("decom-files");
    let ctx = u.ctx();
    decommission::prepare(&ctx, "transfer").unwrap();
    let req = decommission::request_out(&ctx).unwrap();
    assert!(decommission::current(&ctx).unwrap().unwrap().sent);
    // Written out: it may reach the SOC, so it is not abandoned locally.
    assert!(decommission::abort(&ctx)
        .unwrap_err()
        .contains("may have reached the SOC"));
    // The SOC imports the file (authenticated by the unit's uplink key at
    // the import: the SOC's file import runs §5.6 processing on it).
    let up = robodr_fleet::keys::load("uplink", &u.cfg.uplink_key).unwrap();
    let full = format!("{}{}", common::soc::BASE, wire::PATH_DECOMMISSION);
    let mut h: Vec<(String, String)> = vec![("Content-Type".into(), "application/json".into())];
    for (k, v) in robodr_fleet::client::auth_headers("POST", &full, &req, &up.signing, T0) {
        h.push((k.into(), v));
    }
    let r = soc
        .borrow_mut()
        .handle("POST", wire::PATH_DECOMMISSION, &h, &req);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    // A tampered answer is refused and nothing is shredded.
    let mut bad = Envelope::parse(&r.body, wire::T_DECOMMISSION_ANSWER)
        .unwrap()
        .envelope;
    bad.payload = robodr_fleet::b64::encode(
        &String::from_utf8(robodr_fleet::b64::decode(&bad.payload).unwrap())
            .unwrap()
            .replace("transfer", "repair")
            .into_bytes(),
    );
    assert!(decommission::accept(&ctx, &bad.to_bytes().unwrap()).is_err());
    assert!(u.cfg.uplink_key.exists());
    let d = decommission::accept(&ctx, &r.body).unwrap();
    assert_eq!(d.phase, Phase::Done);
    assert_eq!(d.reason, "transfer");
    assert!(!u.cfg.uplink_key.exists());
    // The same answer file again: completes (idempotent); another refuses.
    decommission::accept(&ctx, &r.body).unwrap();
    assert!(decommission::accept(&ctx, b"{}").is_err());
}

#[test]
fn a_lost_answer_is_fetched_by_resending_the_stored_request() {
    let (u, soc) = enrolled("decom-lost");
    let ctx = u.ctx();
    decommission::prepare(&ctx, "end_of_life").unwrap();
    // Network down: the request stays, marked sent.
    let e = decommission::submit(&ctx, &mut Down).unwrap_err();
    assert!(e.starts_with("SOC not reached"), "{e}");
    let d = decommission::current(&ctx).unwrap().unwrap();
    assert!(d.sent);
    assert_eq!(d.phase, Phase::Prepared);
    assert!(u.cfg.uplink_key.exists());
    // The SOC processes it but the answer is lost: simulate by sending the
    // stored request directly, then resend through the unit. The SOC
    // answers the resend (authenticated by the uplink key the first one
    // retired) with its stored answer.
    let up = robodr_fleet::keys::load("uplink", &u.cfg.uplink_key).unwrap();
    let full = format!("{}{}", common::soc::BASE, wire::PATH_DECOMMISSION);
    let mut h: Vec<(String, String)> = vec![("Content-Type".into(), "application/json".into())];
    for (k, v) in
        robodr_fleet::client::auth_headers("POST", &full, d.request.as_bytes(), &up.signing, T0)
    {
        h.push((k.into(), v));
    }
    let first = soc
        .borrow_mut()
        .handle("POST", wire::PATH_DECOMMISSION, &h, d.request.as_bytes());
    assert_eq!(first.status, 200);
    assert_eq!(active_keys(&soc), 0);
    let d = decommission::submit(&ctx, &mut Direct { soc: &soc }).unwrap();
    assert_eq!(d.phase, Phase::Done);
    assert_eq!(
        d.answer.as_deref().map(str::as_bytes),
        Some(&first.body[..])
    );
}

#[test]
fn unfinished_rotation_and_mismatched_keys_are_refused_before_anything_is_sent() {
    let (u, soc) = enrolled("decom-refusals");
    let ctx = u.ctx();
    assert!(decommission::prepare(&ctx, "scrapped")
        .unwrap_err()
        .contains("--reason"));
    rotate::prepare(&ctx, "finding", &rotate::no_crash).unwrap();
    let e = decommission::prepare(&ctx, "end_of_life").unwrap_err();
    assert!(e.contains("rotation"), "{e}");
    rotate::abort(&ctx, "finding").unwrap();
    // A key file that is not the registered key: refused locally (the SOC
    // would answer 409 stale_key).
    let fk = u.cfg.finding_key.clone();
    std::fs::remove_file(&fk).unwrap();
    robodr_fleet::keys::generate("finding", &fk).unwrap();
    let e = decommission::prepare(&ctx, "end_of_life").unwrap_err();
    assert!(e.contains("stale_key"), "{e}");
    assert!(decommission::current(&ctx).unwrap().is_none());
    assert_eq!(active_keys(&soc), 3);
}

#[test]
fn soc_refuses_a_decommission_during_an_open_rotation_and_answers_from_its_own_key() {
    let (u, soc) = enrolled("decom-soc-rotation");
    let ctx = u.ctx();
    let d = decommission::prepare(&ctx, "repair").unwrap();
    // A rotation opened at the SOC after the request was built (another
    // operator, another tool): the SOC refuses with 409.
    rotate::prepare(&ctx, "finding", &rotate::no_crash).unwrap();
    rotate::submit_rotate(&ctx, &mut Direct { soc: &soc }, "finding").unwrap();
    let e = decommission::submit(&ctx, &mut Direct { soc: &soc }).unwrap_err();
    assert!(e.contains("409 rotation_in_progress"), "{e}");
    assert_eq!(active_keys(&soc), 4);
    assert!(u.cfg.uplink_key.exists());
    // An answer signed by a key that is not a configured SOC fleet key
    // (here the approval key) is refused.
    let a = wire::DecommissionAnswer {
        format: wire::DECOMMISSION_ANSWER_FORMAT.into(),
        decommission_id: d.decommission_id.clone(),
        request_digest: d.request_digest.clone(),
        workspace: d.workspace.clone(),
        robot_id: d.robot_id.clone(),
        reason: d.reason.clone(),
        keys: d.keys.clone(),
        status: "decommissioned".into(),
        at_ms: T0,
    };
    let forged = Envelope::sign(
        wire::T_DECOMMISSION_ANSWER,
        &wire::payload_bytes(&a).unwrap(),
        &[&approval_key()],
    );
    let e = decommission::accept(&ctx, &forged.to_bytes().unwrap()).unwrap_err();
    assert!(e.contains("answer"), "{e}");
    assert!(u.cfg.uplink_key.exists());
    // The same payload signed by the SOC fleet key is accepted.
    let real = Envelope::sign(
        wire::T_DECOMMISSION_ANSWER,
        &wire::payload_bytes(&a).unwrap(),
        &[&soc_key()],
    );
    // ... but an answer to another request (digest) is not.
    let mut other = a.clone();
    other.request_digest = format!("sha256:{}", "0".repeat(64));
    let other = Envelope::sign(
        wire::T_DECOMMISSION_ANSWER,
        &wire::payload_bytes(&other).unwrap(),
        &[&soc_key()],
    );
    assert!(decommission::accept(&ctx, &other.to_bytes().unwrap())
        .unwrap_err()
        .contains("does not match"));
    decommission::accept(&ctx, &real.to_bytes().unwrap()).unwrap();
}

#[test]
fn abort_before_sending_and_reenrollment_after_decommission() {
    let (u, soc) = enrolled("decom-reenroll");
    let ctx = u.ctx();
    decommission::prepare(&ctx, "end_of_life").unwrap();
    decommission::abort(&ctx).unwrap();
    assert!(decommission::current(&ctx).unwrap().is_none());
    assert_eq!(active_keys(&soc), 3);
    decommission::prepare(&ctx, "end_of_life").unwrap();
    decommission::submit(&ctx, &mut Direct { soc: &soc }).unwrap();
    assert_eq!(active_keys(&soc), 0);
    // No second decommission. Re-commissioning starts from new keys and an
    // empty fleet state directory: the unit refuses to enroll on the
    // decommissioned state directory, even with --reuse-existing-keys.
    assert!(decommission::prepare(&ctx, "transfer")
        .unwrap_err()
        .contains("Re-commissioning"));
    let t = soc
        .borrow_mut()
        .issue_token("tok-2", ROBOT, Some(SITE), 3_600_000, [0x44; 32]);
    let err = enroll::prepare(&ctx, &t, &Default::default()).unwrap_err();
    assert!(err.contains("was decommissioned"), "{err}");
    let err = enroll::prepare(
        &ctx,
        &t,
        &enroll::EnrollOptions {
            reuse_existing_keys: true,
        },
    )
    .unwrap_err();
    assert!(err.contains("was decommissioned"), "{err}");
    // The SOC side refuses too: it never registers a key id twice (§4), so
    // the kept black-box key cannot be enrolled again even on a fresh state
    // directory.
    std::fs::remove_file(ctx.path(decommission::STATE_FILE)).unwrap();
    enroll::prepare(
        &ctx,
        &t,
        &enroll::EnrollOptions {
            reuse_existing_keys: true,
        },
    )
    .unwrap();
    let e = enroll::submit(&ctx, &mut Direct { soc: &soc }).unwrap_err();
    assert!(e.contains("409 key_conflict"), "{e}");
    assert_eq!(active_keys(&soc), 0);
}

#[test]
fn enrollment_on_a_decommissioned_state_dir_is_refused_even_with_fresh_keys() {
    let (u, soc) = enrolled("decom-fresh-keys");
    let ctx = u.ctx();
    decommission::prepare(&ctx, "end_of_life").unwrap();
    decommission::submit(&ctx, &mut Direct { soc: &soc }).unwrap();
    // The operator moves the kept black-box key away (the uplink and
    // finding keys are shredded already), so enrollment would generate
    // three fresh keys the SOC has never seen.
    std::fs::remove_file(&u.cfg.blackbox_key).unwrap();
    let t = soc
        .borrow_mut()
        .issue_token("tok-3", ROBOT, Some(SITE), 3_600_000, [0x55; 32]);
    let err = enroll::prepare(&ctx, &t, &Default::default()).unwrap_err();
    assert!(err.contains("was decommissioned"), "{err}");
    assert!(err.contains("Re-commissioning"), "{err}");
    // Nothing was generated or stored for the refused enrollment.
    assert!(!u.cfg.blackbox_key.exists());
    assert_eq!(
        decommission::current(&ctx).unwrap().map(|d| d.phase),
        Some(Phase::Done)
    );
}

/// What `docs/OPERATIONS.md` 4.3 does to a unit's black-box key: a new key,
/// the old one moved to `retired/`, and, when `rotate_journal`, the fleet
/// journal rotated in place onto the new key the way `robodr-blackbox
/// rotate` does (`Recorder::rotate_key`). Returns the retired key's path
/// and a copy of its `.pub` where agentd's `blackbox.previous_keys` points.
fn rotate_blackbox_in_place(
    u: &Unit,
    rotate_journal: bool,
) -> (std::path::PathBuf, std::path::PathBuf) {
    use robodr_blackbox::keys::public_key_path;
    use robodr_blackbox::{Recorder, RecorderConfig, SystemClock, TimeSource};
    use std::os::unix::fs::PermissionsExt;
    let active = u.cfg.blackbox_key.clone();
    let keys_dir = active.parent().unwrap().to_path_buf();
    let next = keys_dir.join("agentd-blackbox-next.key");
    robodr_fleet::keys::generate("blackbox", &next).unwrap();
    if rotate_journal {
        let old = KeyFile::load_secret(&active).unwrap().signer().unwrap();
        let new = KeyFile::load_secret(&next).unwrap().signer().unwrap();
        let cfg = RecorderConfig::new(u.cfg.state_dir.join("journal"), ROBOT, "test-boot");
        let mut rec =
            Recorder::open(cfg, old, Box::new(SystemClock::new(TimeSource::Rtc))).unwrap();
        rec.rotate_key(new, None, "scheduled rotation").unwrap();
        rec.close().unwrap();
    }
    let retired = keys_dir.join("retired");
    std::fs::create_dir_all(&retired).unwrap();
    std::fs::set_permissions(&retired, std::fs::Permissions::from_mode(0o700)).unwrap();
    let old_key = retired.join("agentd-blackbox-old.key");
    std::fs::rename(&active, &old_key).unwrap();
    std::fs::rename(public_key_path(&active), public_key_path(&old_key)).unwrap();
    std::fs::rename(&next, &active).unwrap();
    std::fs::rename(public_key_path(&next), public_key_path(&active)).unwrap();
    let prev = u.root.join("etc/blackbox-previous.pub");
    std::fs::copy(public_key_path(&old_key), &prev).unwrap();
    std::fs::set_permissions(&prev, std::fs::Permissions::from_mode(0o644)).unwrap();
    (old_key, prev)
}

#[test]
fn black_box_key_rotated_in_place_still_decommissions_with_the_retired_registered_key() {
    let (mut u, soc) = enrolled("decom-bb-rotated");
    let registered = u.ctx().enrollment().unwrap().keys;
    let (_, prev) = rotate_blackbox_in_place(&u, true);

    // Without the retired .pub the rotated journal's older records do not
    // authenticate: refused, nothing reset.
    let e = decommission::prepare(&u.ctx(), "end_of_life").unwrap_err();
    assert!(e.contains("fleet journal"), "{e}");

    // agentd's blackbox.previous_keys names the retired .pub; the fleet
    // tool reads it from agentd's configuration.
    u.facts.blackbox_previous_keys = vec![prev.clone()];
    let ctx = u.ctx();
    // Other fleet commands work again (they need the journal).
    rotate::prepare(&ctx, "finding", &rotate::no_crash).unwrap();
    rotate::abort(&ctx, "finding").unwrap();
    // The request is signed by the keys the SOC has registered (the
    // black-box one is the retired key); the SOC accepts it.
    let d = decommission::prepare(&ctx, "end_of_life").unwrap();
    assert_eq!(d.keys, registered);
    let d = decommission::submit(&ctx, &mut Direct { soc: &soc }).unwrap();
    assert_eq!(d.phase, Phase::Done);
    assert_eq!(active_keys(&soc), 0);
    // The journal verifies with both keys: the rotation, then the final
    // notes signed by the new key.
    let mut ring = robodr_blackbox::Keyring::new();
    ring.load_public_file(&prev).unwrap();
    ring.load_public_file(&robodr_blackbox::keys::public_key_path(&u.cfg.blackbox_key))
        .unwrap();
    let report = verify_dir(
        &u.cfg.state_dir.join("journal"),
        &ring,
        &VerifyOptions::default(),
    )
    .unwrap();
    assert!(report.is_intact(), "{:?}", report.findings);
}

#[test]
fn black_box_key_rotated_without_the_journal_or_without_the_retired_key_is_refused_clearly() {
    // The journal not rotated: the error names the command that fixes it.
    let (mut u, _soc) = enrolled("decom-bb-journal");
    let (_, prev) = rotate_blackbox_in_place(&u, false);
    u.facts.blackbox_previous_keys = vec![prev];
    let e = decommission::prepare(&u.ctx(), "end_of_life").unwrap_err();
    assert!(e.contains("robodr-blackbox rotate"), "{e}");
    assert!(e.contains("OPERATIONS.md 4.3"), "{e}");

    // The journal rotated but the retired secret destroyed: refused before
    // anything is sent, naming the way out.
    let (mut u, soc) = enrolled("decom-bb-destroyed");
    let (old_key, prev) = rotate_blackbox_in_place(&u, true);
    std::fs::remove_file(&old_key).unwrap();
    u.facts.blackbox_previous_keys = vec![prev];
    let ctx = u.ctx();
    let e = decommission::prepare(&ctx, "end_of_life").unwrap_err();
    assert!(e.contains("retired secret key"), "{e}");
    assert!(e.contains("stale_key"), "{e}");
    assert!(decommission::current(&ctx).unwrap().is_none());
    assert_eq!(active_keys(&soc), 3);
}
