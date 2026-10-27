//! Fleet lifecycle against the reference SOC (`tests/common/soc.rs`), in
//! memory: enrollment (online and air-gapped), token replay / expiry /
//! workspace / robot binding, tampering, key rotation with every crash
//! point, revocation lists, profile staging and approval, ring info.

mod common;

use common::soc::{Direct, Down};
use common::*;
use robodr_blackbox::record::{scan_frames, ScanItem};
use robodr_blackbox::verify::{read_segments, verify_dir, VerifyOptions};
use robodr_blackbox::{Ed25519SigningKey, KeyFile};
use robodr_commission::trust::{evaluate_profile_trust, sig_path_for, TrustInputs};
use robodr_fleet::rotate::{self, Crash};
use robodr_fleet::state::Phase;
use robodr_fleet::wire::{self, Envelope};
use robodr_fleet::{enroll, profile, revocation, ring};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn token(soc: &std::cell::RefCell<common::soc::Soc>, id: &str) -> String {
    soc.borrow_mut()
        .issue_token(id, ROBOT, Some(SITE), 3_600_000, [0x33; 32])
}

fn enrolled(tag: &str) -> (Unit, std::cell::RefCell<common::soc::Soc>) {
    let u = Unit::new(tag);
    let soc = new_soc();
    let t = token(&soc, "tok-1");
    let ctx = u.ctx();
    enroll::prepare(&ctx, &t, &Default::default()).unwrap();
    enroll::submit(&ctx, &mut Direct { soc: &soc }).unwrap();
    (u, soc)
}

fn mode(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

/// Every fleet note in the journal, verified with the black-box key.
fn journal_notes(u: &Unit) -> Vec<serde_json::Value> {
    let dir = u.cfg.state_dir.join("journal");
    let kf = KeyFile::load_secret(&u.cfg.blackbox_key).unwrap();
    let v = kf.verifier().unwrap();
    let report = verify_dir(&dir, v.as_ref(), &VerifyOptions::default()).unwrap();
    assert!(
        report.is_intact(),
        "fleet journal not intact: {:?}",
        report.findings
    );
    let mut out = Vec::new();
    for s in read_segments(&dir).unwrap() {
        for it in scan_frames(&s.bytes).items {
            if let ScanItem::Record(r) = it {
                if let Some(j) = r.record.payload_json::<serde_json::Value>() {
                    if j["kind"]
                        .as_str()
                        .is_some_and(|k| k.starts_with("robodr.fleet."))
                    {
                        out.push(j);
                    }
                }
            }
        }
    }
    out
}

// ------------------------------------------------------------- enroll --

#[test]
fn enroll_online_generates_root_only_keys_and_registers_them() {
    let (u, soc) = enrolled("enroll-ok");
    for role in wire::ROLES {
        let p = u.cfg.key_path(role).unwrap();
        assert_eq!(mode(p), 0o600, "{role} key mode");
        let pubp = robodr_blackbox::keys::public_key_path(p);
        assert_eq!(mode(&pubp), 0o644);
        let k = robodr_fleet::keys::load(role, p).unwrap();
        let rec = &soc.borrow().keys[&k.key_id()];
        assert_eq!((rec.robot.as_str(), rec.role.as_str()), (ROBOT, role));
        assert!(rec.retired_at.is_none());
    }
    let ctx = u.ctx();
    let e = ctx.enrollment().unwrap();
    assert_eq!(
        (e.workspace.as_str(), e.robot_id.as_str()),
        (WORKSPACE, ROBOT)
    );
    assert_eq!(e.site.as_deref(), Some(SITE));
    assert!(!u.cfg.state_dir.join("enroll-pending.json").exists());
    assert_eq!(mode(&u.cfg.state_dir), 0o700);
    let notes = journal_notes(&u);
    let kinds: Vec<&str> = notes.iter().map(|n| n["kind"].as_str().unwrap()).collect();
    assert_eq!(
        kinds,
        ["robodr.fleet.enroll_requested", "robodr.fleet.enrolled"]
    );
    // Enrolling again is refused.
    let t2 = token(&soc, "tok-2");
    let err = enroll::prepare(&ctx, &t2, &Default::default()).unwrap_err();
    assert!(err.contains("already enrolled"), "{err}");
}

#[test]
fn request_carries_the_mac_not_the_token_secret() {
    let u = Unit::new("mac");
    let soc = new_soc();
    let t = token(&soc, "tok-1");
    let ctx = u.ctx();
    let p = enroll::prepare(&ctx, &t, &Default::default()).unwrap();
    let nonce_hex = robodr_blackbox::crypto::to_hex(&[0x33; 32]);
    assert!(!p.pending.envelope.contains(&nonce_hex));
    assert!(!p.pending.envelope.contains("rdet1."));
    let o = Envelope::parse(p.pending.envelope.as_bytes(), wire::T_ENROLL_REQUEST).unwrap();
    o.verify_mac(&[0x33; 32]).unwrap();
    assert!(o.verify_mac(&[0x34; 32]).is_err());
}

#[test]
fn token_replay_is_refused_locally_and_by_the_soc() {
    let u = Unit::new("replay");
    let soc = new_soc();
    let t = token(&soc, "tok-1");
    {
        let ctx = u.ctx();
        enroll::prepare(&ctx, &t, &Default::default()).unwrap();
        enroll::submit(&ctx, &mut Direct { soc: &soc }).unwrap();
    }
    // Another unit (other keys) presents the same token: the SOC refuses.
    let u2 = Unit::new("replay2");
    let ctx2 = u2.ctx();
    enroll::prepare(&ctx2, &t, &Default::default()).unwrap();
    let err = enroll::submit(&ctx2, &mut Direct { soc: &soc }).unwrap_err();
    assert!(err.contains("409 token_used"), "{err}");
    assert!(ctx2.enrollment().is_err());
    // Resubmitting the same request (lost answer) gets the stored answer.
    let u3 = Unit::new("replay3");
    let soc3 = new_soc();
    let t3 = token(&soc3, "tok-9");
    let ctx3 = u3.ctx();
    enroll::prepare(&ctx3, &t3, &Default::default()).unwrap();
    let pending = ctx3
        .load::<robodr_fleet::state::PendingEnroll>("enroll-pending.json")
        .unwrap()
        .unwrap();
    let h = vec![("Content-Type".to_string(), "application/json".to_string())];
    let a1 = soc3
        .borrow_mut()
        .handle("POST", wire::PATH_ENROLL, &h, pending.envelope.as_bytes());
    let a2 = soc3
        .borrow_mut()
        .handle("POST", wire::PATH_ENROLL, &h, pending.envelope.as_bytes());
    assert_eq!((a1.status, a2.status), (200, 200));
    assert_eq!(a1.body, a2.body);
    // The local guard: a token used on this unit is refused before keys.
    let u4 = Unit::new("replay4");
    let soc4 = new_soc();
    let t4 = token(&soc4, "tok-4");
    let ctx4 = u4.ctx();
    ctx4.mark_used("tokens-used.json", "tok-4").unwrap();
    let err = enroll::prepare(&ctx4, &t4, &Default::default()).unwrap_err();
    assert!(err.contains("already used"), "{err}");
    assert!(!u4.cfg.uplink_key.exists());
}

#[test]
fn expired_token_is_refused_by_the_robot_and_by_the_soc() {
    let u = Unit::new("expired");
    let soc = new_soc();
    let t = token(&soc, "tok-1");
    u.now.set(T0 + 3_600_001);
    let ctx = u.ctx();
    let err = enroll::prepare(&ctx, &t, &Default::default()).unwrap_err();
    assert!(err.contains("expired"), "{err}");
    assert!(
        !u.cfg.uplink_key.exists(),
        "no key generated for an expired token"
    );
    drop(ctx);
    // Robot clock fine, SOC imports the (air-gapped) request too late.
    u.now.set(T0 + 1000);
    let ctx = u.ctx();
    enroll::prepare(&ctx, &t, &Default::default()).unwrap();
    soc.borrow_mut().now_ms = T0 + 3_600_001;
    let err = enroll::submit(&ctx, &mut Direct { soc: &soc }).unwrap_err();
    assert!(err.contains("410 token_expired"), "{err}");
    // A token from the future (robot clock far behind) is refused.
    let u2 = Unit::new("future");
    u2.now.set(T0 - wire::MAX_SKEW_MS - 1);
    let err = enroll::prepare(&u2.ctx(), &t, &Default::default()).unwrap_err();
    assert!(err.contains("future"), "{err}");
}

#[test]
fn wrong_workspace_robot_or_site_is_refused() {
    let soc = new_soc();
    let other_ws = soc.borrow_mut().issue_token_for(
        "tok-w",
        "ws-other",
        ROBOT,
        Some(SITE),
        3_600_000,
        [1; 32],
    );
    let u = Unit::new("ws");
    let err = enroll::prepare(&u.ctx(), &other_ws, &Default::default()).unwrap_err();
    assert!(err.contains("workspace"), "{err}");
    let other_robot =
        soc.borrow_mut()
            .issue_token("tok-r", "ugv-999", Some(SITE), 3_600_000, [2; 32]);
    let err = enroll::prepare(&u.ctx(), &other_robot, &Default::default()).unwrap_err();
    assert!(err.contains("robot"), "{err}");
    let other_site =
        soc.borrow_mut()
            .issue_token("tok-s", ROBOT, Some("lab-2"), 3_600_000, [3; 32]);
    let err = enroll::prepare(&u.ctx(), &other_site, &Default::default()).unwrap_err();
    assert!(err.contains("site"), "{err}");
    assert!(!u.cfg.uplink_key.exists());
}

#[test]
fn tampered_or_foreign_tokens_are_refused() {
    let u = Unit::new("tamper-token");
    let soc = new_soc();
    let t = token(&soc, "tok-1");
    // Flip one payload character (still base64url).
    let mut b = t.clone().into_bytes();
    let i = "rdet1.".len() + 10;
    b[i] = if b[i] == b'A' { b'B' } else { b'A' };
    let bad = String::from_utf8(b).unwrap();
    assert!(enroll::prepare(&u.ctx(), &bad, &Default::default()).is_err());
    // Signed by a key that is not a configured SOC key.
    let mut rogue = common::soc::Soc::new(
        Ed25519SigningKey::from_seed_with_derived_id(&[0x77; 32]),
        Ed25519SigningKey::from_seed_with_derived_id(&[0x78; 32]),
        WORKSPACE,
        T0,
    );
    let rt = rogue.issue_token("tok-x", ROBOT, Some(SITE), 3_600_000, [4; 32]);
    let err = enroll::prepare(&u.ctx(), &rt, &Default::default()).unwrap_err();
    assert!(err.contains("not a configured SOC fleet key"), "{err}");
    assert!(!u.cfg.uplink_key.exists());
}

#[test]
fn air_gapped_enrollment_with_files() {
    let u = Unit::new("airgap");
    let soc = new_soc();
    let t = token(&soc, "tok-1");
    let ctx = u.ctx();
    let p = enroll::prepare(&ctx, &t, &Default::default()).unwrap();
    // The request file goes to the SOC on media; the answer comes back.
    let req_file = u.root.join("media-request.json");
    std::fs::write(&req_file, &p.pending.envelope).unwrap();
    let h = vec![("Content-Type".to_string(), "application/json".to_string())];
    let ans = soc.borrow_mut().handle(
        "POST",
        wire::PATH_ENROLL,
        &h,
        &std::fs::read(&req_file).unwrap(),
    );
    assert_eq!(ans.status, 200);
    // A tampered answer is refused, the request stays pending.
    let mut bad = ans.body.clone();
    let n = bad.len() - 20;
    bad[n] = if bad[n] == b'0' { b'1' } else { b'0' };
    assert!(enroll::accept(&ctx, &bad).is_err());
    assert!(ctx.enrollment().is_err());
    // An answer to another request (another unit's) is refused.
    let u2 = Unit::new("airgap2");
    let soc2 = new_soc();
    let t2 = token(&soc2, "tok-1");
    let ctx2 = u2.ctx();
    let p2 = enroll::prepare(&ctx2, &t2, &Default::default()).unwrap();
    let other = soc2.borrow_mut().handle(
        "POST",
        wire::PATH_ENROLL,
        &h,
        p2.pending.envelope.as_bytes(),
    );
    let err = enroll::accept(&ctx, &other.body).unwrap_err();
    assert!(
        err.contains("another request") || err.contains("does not match"),
        "{err}"
    );
    // The genuine answer completes enrollment.
    enroll::accept(&ctx, &ans.body).unwrap();
    assert_eq!(ctx.enrollment().unwrap().robot_id, ROBOT);
    // Re-running prepare after a crash (before accept) resumes the pending
    // request unchanged.
    let u3 = Unit::new("airgap3");
    let soc3 = new_soc();
    let t3 = token(&soc3, "tok-1");
    let ctx3 = u3.ctx();
    let a = enroll::prepare(&ctx3, &t3, &Default::default()).unwrap();
    let b = enroll::prepare(&ctx3, &t3, &Default::default()).unwrap();
    assert!(b.resumed);
    assert_eq!(a.pending, b.pending);
}

#[test]
fn soc_unreachable_keeps_the_request_pending() {
    let u = Unit::new("down");
    let soc = new_soc();
    let t = token(&soc, "tok-1");
    let ctx = u.ctx();
    enroll::prepare(&ctx, &t, &Default::default()).unwrap();
    let err = enroll::submit(&ctx, &mut Down).unwrap_err();
    assert!(err.starts_with("SOC not reached"), "{err}");
    enroll::submit(&ctx, &mut Direct { soc: &soc }).unwrap();
}

#[test]
fn existing_keys_need_explicit_reuse() {
    let u = Unit::new("reuse");
    let soc = new_soc();
    let t = token(&soc, "tok-1");
    let bb = KeyFile::generate_ed25519(None).unwrap();
    bb.write_new(&u.cfg.blackbox_key).unwrap();
    let ctx = u.ctx();
    let err = enroll::prepare(&ctx, &t, &Default::default()).unwrap_err();
    assert!(err.contains("--reuse-existing-keys"), "{err}");
    let p = enroll::prepare(
        &ctx,
        &t,
        &enroll::EnrollOptions {
            reuse_existing_keys: true,
        },
    )
    .unwrap();
    assert!(p.key_origin.contains(&("blackbox".to_string(), "reused")));
    assert_eq!(p.pending.keys[2].key_id, bb.key_id);
    // A crash after generating some keys: the retry adopts its own keys.
    let u2 = Unit::new("reuse2");
    let soc2 = new_soc();
    let t2 = token(&soc2, "tok-1");
    let ctx2 = u2.ctx();
    std::fs::set_permissions(
        u2.root.join("etc/keys"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    // Make the finding key generation fail (directory unwritable for the
    // finding key path: point it at a missing directory).
    drop(ctx2);
    let mut cfg = u2.cfg.clone();
    cfg.finding_key = u2.root.join("missing-dir/finding.key");
    let ctxf = robodr_fleet::state::Ctx::open(cfg, u2.facts.clone(), Box::new(|| T0)).unwrap();
    assert!(enroll::prepare(&ctxf, &t2, &Default::default()).is_err());
    drop(ctxf);
    assert!(u2.cfg.uplink_key.exists());
    let ctx2 = u2.ctx();
    let p = enroll::prepare(&ctx2, &t2, &Default::default()).unwrap();
    assert!(p.key_origin.iter().all(|(_, o)| *o == "generated"));
}

// ------------------------------------------------------------- rotate --

fn full_rotation(u: &Unit, soc: &std::cell::RefCell<common::soc::Soc>, role: &str) {
    let ctx = u.ctx();
    rotate::prepare(&ctx, role, &rotate::no_crash).unwrap();
    rotate::submit_rotate(&ctx, &mut Direct { soc }, role).unwrap();
    rotate::swap(&ctx, role, &rotate::no_crash).unwrap();
    rotate::submit_retire(&ctx, &mut Direct { soc }, role, &rotate::no_crash).unwrap();
}

#[test]
fn rotation_keeps_the_old_key_valid_until_the_soc_confirms() {
    for role in wire::ROTATABLE {
        let (u, soc) = enrolled(&format!("rot-{role}"));
        let path = u.cfg.key_path(role).unwrap().to_path_buf();
        let old = robodr_fleet::keys::load(role, &path).unwrap();
        let ctx = u.ctx();
        let rot = rotate::prepare(&ctx, role, &rotate::no_crash).unwrap();
        // Prepared: the active file is still the old key; the SOC knows
        // nothing yet.
        assert_eq!(
            robodr_fleet::keys::load(role, &path).unwrap().key_id(),
            old.key_id()
        );
        assert_eq!(soc.borrow().active_key(ROBOT, role).len(), 1);
        // Swap before the SOC confirmed: refused.
        assert!(rotate::swap(&ctx, role, &rotate::no_crash).is_err());
        rotate::submit_rotate(&ctx, &mut Direct { soc: &soc }, role).unwrap();
        // Overlap: both keys active at the SOC.
        assert_eq!(soc.borrow().active_key(ROBOT, role).len(), 2);
        let rot2 = rotate::swap(&ctx, role, &rotate::no_crash).unwrap();
        assert_eq!(rot2.phase, Phase::Swapped);
        let active = robodr_fleet::keys::load(role, &path).unwrap();
        assert_eq!(active.key_id(), rot.new_key_id);
        assert_eq!(mode(&path), 0o600);
        let retired = rotate::retired_path(&path, role, &rot.old_key_id);
        assert_eq!(
            robodr_fleet::keys::load(role, &retired).unwrap().key_id(),
            old.key_id()
        );
        // The old key is still valid at the SOC until retire.
        assert!(soc.borrow().keys[&old.key_id()].retired_at.is_none());
        let en = rotate::submit_retire(&ctx, &mut Direct { soc: &soc }, role, &rotate::no_crash)
            .unwrap();
        assert!(soc.borrow().keys[&old.key_id()].retired_at.is_some());
        assert_eq!(soc.borrow().active_key(ROBOT, role), vec![&rot.new_key_id]);
        assert!(!retired.exists(), "old key shredded");
        assert_eq!(en.key(role).unwrap().key_id, rot.new_key_id);
        assert!(rotate::current(&ctx, role).unwrap().is_none());
        // .pub matches the active key.
        let pubk = KeyFile::load_public(&robodr_blackbox::keys::public_key_path(&path)).unwrap();
        assert_eq!(pubk.key_id, rot.new_key_id);
        drop(ctx);
        // The handover note is signed by both keys over the journal head.
        let notes = journal_notes(&u);
        let h = notes
            .iter()
            .find(|n| n["kind"] == "robodr.fleet.key_handover")
            .expect("handover note");
        let stmt = wire::handover_message(
            h["rotation_id"].as_str().unwrap(),
            role,
            h["old_fingerprint"].as_str().unwrap(),
            h["new_fingerprint"].as_str().unwrap(),
            h["journal_head"].as_str().unwrap(),
        );
        assert!(wire::verify_hex(
            &old.public(),
            &stmt,
            h["old_sig"].as_str().unwrap()
        ));
        assert!(wire::verify_hex(
            &active.public(),
            &stmt,
            h["new_sig"].as_str().unwrap()
        ));
        let phases: Vec<&str> = notes
            .iter()
            .filter(|n| n["kind"] == "robodr.fleet.key_rotation")
            .map(|n| n["phase"].as_str().unwrap())
            .collect();
        assert_eq!(phases, ["prepared", "registered", "retired"]);
        // A second rotation works from the new key.
        full_rotation(&u, &soc, role);
        assert_eq!(soc.borrow().active_key(ROBOT, role).len(), 1);
    }
}

#[test]
fn rotation_survives_every_crash_point() {
    let points = [
        Crash::AfterNewKey,
        Crash::AfterPrepared,
        Crash::AfterRetiredCopy,
        Crash::AfterRename,
        Crash::AfterHandover,
        Crash::AfterShred,
    ];
    for role in wire::ROTATABLE {
        for point in points {
            let (u, soc) = enrolled(&format!("crash-{role}-{point:?}"));
            let path = u.cfg.key_path(role).unwrap().to_path_buf();
            let old_id = robodr_fleet::keys::load(role, &path).unwrap().key_id();
            let crash = move |c: Crash| {
                if c == point {
                    Err(format!("simulated crash at {c:?}"))
                } else {
                    Ok(())
                }
            };
            // First run: dies at `point` (drop = process exit).
            {
                let ctx = u.ctx();
                let r = (|| -> Result<(), String> {
                    rotate::prepare(&ctx, role, &crash)?;
                    rotate::submit_rotate(&ctx, &mut Direct { soc: &soc }, role)?;
                    rotate::swap(&ctx, role, &crash)?;
                    rotate::submit_retire(&ctx, &mut Direct { soc: &soc }, role, &crash)?;
                    Ok(())
                })();
                assert!(r.unwrap_err().contains("simulated crash"));
            }
            // The active key file always holds a whole key the SOC accepts.
            let active = robodr_fleet::keys::load(role, &path).unwrap();
            assert!(
                soc.borrow()
                    .keys
                    .get(&active.key_id())
                    .is_some_and(|k| k.retired_at.is_none()),
                "{role}/{point:?}: active key not valid at the SOC"
            );
            // Second run resumes and finishes.
            {
                let ctx = u.ctx();
                rotate::prepare(&ctx, role, &rotate::no_crash).unwrap();
                rotate::submit_rotate(&ctx, &mut Direct { soc: &soc }, role).unwrap();
                rotate::swap(&ctx, role, &rotate::no_crash).unwrap();
                let en =
                    rotate::submit_retire(&ctx, &mut Direct { soc: &soc }, role, &rotate::no_crash)
                        .unwrap();
                let now = robodr_fleet::keys::load(role, &path).unwrap();
                assert_ne!(now.key_id(), old_id, "{role}/{point:?}");
                assert_eq!(en.key(role).unwrap().key_id, now.key_id());
                assert_eq!(soc.borrow().active_key(ROBOT, role), vec![&now.key_id()]);
                assert!(!fsx_exists(&robodr_fleet::fsx::with_suffix(&path, ".next")));
                assert!(!rotate::retired_path(&path, role, &old_id).exists());
                // Exactly one rotation registered at the SOC.
                assert_eq!(soc.borrow().rotations.len(), 1, "{role}/{point:?}");
            }
            journal_notes(&u);
        }
    }
}

fn fsx_exists(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok()
}

#[test]
fn rotation_abort_and_refusals() {
    let (u, soc) = enrolled("rot-abort");
    let ctx = u.ctx();
    let rot = rotate::prepare(&ctx, "uplink", &rotate::no_crash).unwrap();
    rotate::abort(&ctx, "uplink").unwrap();
    assert!(!fsx_exists(&robodr_fleet::fsx::with_suffix(
        &u.cfg.uplink_key,
        ".next"
    )));
    assert!(rotate::current(&ctx, "uplink").unwrap().is_none());
    assert!(!soc.borrow().keys.contains_key(&rot.new_key_id));
    // The black-box key is not rotated by this tool.
    assert!(rotate::prepare(&ctx, "blackbox", &rotate::no_crash).is_err());
    // A key file the SOC does not know is not rotated.
    std::fs::remove_file(&u.cfg.finding_key).unwrap();
    KeyFile::generate_ed25519(None)
        .unwrap()
        .write_new(&u.cfg.finding_key)
        .unwrap();
    let err = rotate::prepare(&ctx, "finding", &rotate::no_crash).unwrap_err();
    assert!(err.contains("does not know"), "{err}");
    // A forged rotate answer (not SOC-signed) is refused.
    let rot = rotate::prepare(&ctx, "uplink", &rotate::no_crash).unwrap();
    let mut rogue = common::soc::Soc::new(
        Ed25519SigningKey::from_seed_with_derived_id(&[0x77; 32]),
        Ed25519SigningKey::from_seed_with_derived_id(&[0x78; 32]),
        WORKSPACE,
        T0,
    );
    // The rogue SOC knows the robot's uplink key (copy the registry).
    rogue.keys = soc.borrow().keys.clone();
    let rogue = std::cell::RefCell::new(rogue);
    let err = rotate::submit_rotate(&ctx, &mut Direct { soc: &rogue }, "uplink").unwrap_err();
    assert!(
        err.contains("SOC key") || err.contains("signature"),
        "{err}"
    );
    assert_eq!(
        rotate::current(&ctx, "uplink").unwrap().unwrap().phase,
        Phase::Prepared
    );
    // An answer for another rotation is refused.
    let other = soc.borrow().rotations.get(&rot.rotation_id).cloned();
    assert!(other.is_none());
}

// -------------------------------------------------------- revocations --

#[test]
fn revocation_list_install_and_anti_rollback() {
    let (u, soc) = enrolled("rev");
    let ctx = u.ctx();
    soc.borrow_mut()
        .revocations
        .insert(PLATFORM.into(), revocation_list(2, &[], &root_key()));
    let r = revocation::fetch(&ctx, &mut Direct { soc: &soc }, PLATFORM).unwrap();
    assert_eq!((r.serial, r.unchanged), (2, false));
    let target = u.etc("revocations.json");
    assert_eq!(mode(&target), 0o644);
    // Same list again: unchanged.
    assert!(
        revocation::fetch(&ctx, &mut Direct { soc: &soc }, PLATFORM)
            .unwrap()
            .unchanged
    );
    // Older serial: rollback refused, installed file untouched.
    let before = std::fs::read(&target).unwrap();
    let err =
        revocation::install(&ctx, &revocation_list(1, &[], &root_key()), PLATFORM).unwrap_err();
    assert!(err.contains("rollback"), "{err}");
    // Same serial, other content: equivocation.
    let other = revocation_list(2, &[format!("sha256:{}", "c".repeat(64))], &root_key());
    let err = revocation::install(&ctx, &other, PLATFORM).unwrap_err();
    assert!(err.contains("equivocation"), "{err}");
    // Not signed by a trust root (signed by the profile key).
    let err =
        revocation::install(&ctx, &revocation_list(5, &[], &profile_key()), PLATFORM).unwrap_err();
    assert!(!err.is_empty());
    // Tampered.
    let mut t = revocation_list(6, &[], &root_key());
    let s = String::from_utf8(t.clone())
        .unwrap()
        .replace("\"serial\": 6", "\"serial\": 7");
    t = s.into_bytes();
    assert!(revocation::install(&ctx, &t, PLATFORM).is_err());
    // Another platform.
    assert!(revocation::install(&ctx, &revocation_list(9, &[], &root_key()), "other-x").is_err());
    assert_eq!(std::fs::read(&target).unwrap(), before);
    // Rollback floor survives the state file being deleted: the installed
    // list is a witness too.
    std::fs::remove_file(u.cfg.state_dir.join("revocations-state.json")).unwrap();
    assert!(revocation::install(&ctx, &revocation_list(1, &[], &root_key()), PLATFORM).is_err());
    // A list revoking the active profile installs, with a warning.
    let (p, s) = signed_profile(3, None);
    std::fs::write(u.etc("profile.json"), &p).unwrap();
    std::fs::write(sig_path_for(&u.etc("profile.json")), &s).unwrap();
    let r = revocation::install(
        &ctx,
        &revocation_list(10, &[wire::digest(&p)], &root_key()),
        PLATFORM,
    )
    .unwrap();
    assert!(r.active_profile_refused.is_some());
}

// ------------------------------------------------------------ profile --

fn agentd_accepts(u: &Unit) -> Result<(), String> {
    let pp = u.etc("profile.json");
    let raw = std::fs::read_to_string(&pp).unwrap();
    let f = &u.facts;
    let inp = TrustInputs {
        trusted_keys: f.trusted_keys.as_deref(),
        trust_roots: f.trust_roots.as_deref(),
        revocation_list: f.revocation_list.as_deref(),
        revocation_policy: f.revocation_policy,
        expect_platform: f.expect_platform.as_deref(),
        expect_unit_id: f.expect_unit_id.as_deref(),
        state_file: f.state_file.as_deref(),
        allow_rollback: None,
        chain: None,
    };
    evaluate_profile_trust(&pp, &raw, &inp)
        .result
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[test]
fn profile_is_staged_never_enforced_without_approval() {
    let (u, soc) = enrolled("prof");
    let ctx = u.ctx();
    let (p, s) = signed_profile(4, Some(ROBOT));
    soc.borrow_mut().offer(ROBOT, 4, &p, &s);
    let m = profile::fetch(&ctx, &mut Direct { soc: &soc }).unwrap();
    assert_eq!(m.digest, wire::digest(&p));
    // Staged only: agentd's profile does not exist.
    assert!(!u.etc("profile.json").exists());
    // Approval checks.
    let digest = m.digest.clone();
    let wrong_digest = soc.borrow_mut().approval(
        "ap-1",
        ROBOT,
        PLATFORM,
        &format!("sha256:{}", "d".repeat(64)),
        4,
        &["op-a", "op-b"],
        600_000,
    );
    assert!(profile::approve(&ctx, &wrong_digest)
        .unwrap_err()
        .contains("approves"));
    let wrong_robot =
        soc.borrow_mut()
            .approval("ap-2", "ugv-999", PLATFORM, &digest, 4, &["op-a"], 600_000);
    assert!(profile::approve(&ctx, &wrong_robot)
        .unwrap_err()
        .contains("robot"));
    let wrong_version =
        soc.borrow_mut()
            .approval("ap-3", ROBOT, PLATFORM, &digest, 5, &["op-a"], 600_000);
    assert!(profile::approve(&ctx, &wrong_version).is_err());
    let expired = soc
        .borrow_mut()
        .approval("ap-4", ROBOT, PLATFORM, &digest, 4, &["op-a"], 1);
    u.now.set(T0 + 10);
    assert!(profile::approve(&ctx, &expired)
        .unwrap_err()
        .contains("expired"));
    u.now.set(T0);
    let mut rogue = common::soc::Soc::new(
        Ed25519SigningKey::from_seed_with_derived_id(&[0x77; 32]),
        Ed25519SigningKey::from_seed_with_derived_id(&[0x78; 32]),
        WORKSPACE,
        T0,
    );
    let forged = rogue.approval("ap-5", ROBOT, PLATFORM, &digest, 4, &["op-a"], 600_000);
    assert!(profile::approve(&ctx, &forged).is_err());
    assert!(
        !u.etc("profile.json").exists(),
        "nothing installed by a refused approval"
    );
    // The genuine approval installs; agentd's own check accepts the result.
    let good = soc.borrow_mut().approval(
        "ap-6",
        ROBOT,
        PLATFORM,
        &digest,
        4,
        &["op-a", "op-b"],
        600_000,
    );
    let i = profile::approve(&ctx, &good).unwrap();
    assert_eq!(std::fs::read(&i.path).unwrap(), p);
    assert_eq!(std::fs::read(sig_path_for(&i.path)).unwrap(), s);
    agentd_accepts(&u).unwrap();
    assert!(profile::staged(&ctx).unwrap().is_none());
    // Replay of the approval: refused (nothing staged, and single use).
    soc.borrow_mut().offer(ROBOT, 4, &p, &s);
    profile::fetch(&ctx, &mut Direct { soc: &soc }).unwrap();
    assert!(profile::approve(&ctx, &good)
        .unwrap_err()
        .contains("already used"));
    let notes = journal_notes(&u);
    assert!(notes
        .iter()
        .any(|n| n["step"] == "installed" && n["approval_id"] == "ap-6"));
}

#[test]
fn tampered_draft_foreign_and_rolled_back_profiles_are_not_staged() {
    let (u, soc) = enrolled("prof-bad");
    let ctx = u.ctx();
    // Tampered profile bytes (signature no longer matches).
    let (p, s) = signed_profile(4, None);
    let mut t = p.clone();
    let n = t.iter().position(|&b| b == b'/').unwrap();
    t[n + 1] = b'x';
    let err = profile::stage(&ctx, &t, &s).unwrap_err();
    assert!(err.contains("refused"), "{err}");
    assert!(profile::staged(&ctx).unwrap().is_none());
    // A draft is never staged.
    let err = profile::stage(&ctx, &draft_profile(), b"").unwrap_err();
    assert!(err.contains("draft") || err.contains("refused"), "{err}");
    // For another unit.
    let (p2, s2) = signed_profile(4, Some("ugv-999"));
    assert!(profile::stage(&ctx, &p2, &s2).is_err());
    // Signed by an unknown key.
    let rogue = Ed25519SigningKey::from_seed_with_derived_id(&[0x66; 32]);
    let s3 = robodr_commission::trust::ProfileSignature::create(&p, &rogue)
        .unwrap()
        .to_text();
    assert!(profile::stage(&ctx, &p, s3.as_bytes()).is_err());
    // Anti-rollback: agentd accepted version 7; version 4 is refused.
    let st = robodr_commission::trust::AcceptedState {
        format: robodr_commission::trust::STATE_FORMAT.into(),
        model: "ugv-test".into(),
        platform: PLATFORM.into(),
        unit_id: None,
        profile_version: 7,
        digest: format!("sha256:{}", "e".repeat(64)),
        revocation_serial: None,
        revocation_digest: None,
        trust_floor: None,
    };
    robodr_commission::trust::store_state(u.facts.state_file.as_ref().unwrap(), &st).unwrap();
    let err = profile::stage(&ctx, &p, &s).unwrap_err();
    assert!(
        err.to_lowercase().contains("rollback") || err.contains("version"),
        "{err}"
    );
    // Revoked profile.
    std::fs::remove_file(u.facts.state_file.as_ref().unwrap()).unwrap();
    soc.borrow_mut().revocations.insert(
        PLATFORM.into(),
        revocation_list(3, &[wire::digest(&p)], &root_key()),
    );
    revocation::fetch(&ctx, &mut Direct { soc: &soc }, PLATFORM).unwrap();
    assert!(profile::stage(&ctx, &p, &s).is_err());
    let notes = journal_notes(&u);
    assert!(notes.iter().any(|n| n["kind"] == "robodr.fleet.refused"));
}

#[test]
fn draft_publish() {
    let (u, soc) = enrolled("draft");
    let ctx = u.ctx();
    let f = u.root.join("draft.json");
    std::fs::write(&f, draft_profile()).unwrap();
    let d = profile::publish_draft(&ctx, &mut Direct { soc: &soc }, &f).unwrap();
    assert_eq!(soc.borrow().drafts.len(), 1);
    assert_eq!(d, wire::digest(&draft_profile()));
    let (p, _) = signed_profile(1, None);
    std::fs::write(&f, p).unwrap();
    assert!(profile::publish_draft(&ctx, &mut Direct { soc: &soc }, &f).is_err());
}

// --------------------------------------------------------------- ring --

#[test]
fn ring_info_is_verified_and_anti_rollback() {
    let (u, soc) = enrolled("ring");
    let ctx = u.ctx();
    soc.borrow_mut().ring(ROBOT, 3, 1, Some("9.9.9"));
    let s = ring::fetch(&ctx, &mut Direct { soc: &soc }).unwrap();
    assert_eq!(
        (s.info.ring, s.info.serial, s.update_available, s.stale),
        (1, 3, true, false)
    );
    let old = soc.borrow_mut().ring(ROBOT, 2, 0, None);
    assert!(ring::accept(&ctx, &old).unwrap_err().contains("rollback"));
    let equiv = soc.borrow_mut().ring(ROBOT, 3, 2, None);
    assert!(ring::accept(&ctx, &equiv)
        .unwrap_err()
        .contains("equivocation"));
    let other = soc.borrow_mut().ring("ugv-999", 9, 0, None);
    assert!(ring::accept(&ctx, &other).is_err());
    u.now.set(T0 + 2 * 86_400_000);
    let same = soc
        .borrow_mut()
        .ring(ROBOT, 4, 1, Some(env!("CARGO_PKG_VERSION")));
    let s = ring::accept(&ctx, &same).unwrap();
    assert!(!s.update_available);
    assert!(s.stale);
}

// ------------------------------------------------------ request auth --

#[test]
fn soc_refuses_unauthenticated_and_stale_requests() {
    let (u, soc) = enrolled("auth");
    let k = robodr_fleet::keys::load("uplink", &u.cfg.uplink_key).unwrap();
    let full = format!("{}{}", common::soc::BASE, wire::PATH_RING);
    let mut h: Vec<(String, String)> =
        robodr_fleet::client::auth_headers("GET", &full, b"", &k.signing, T0)
            .into_iter()
            .map(|(a, b)| (a.to_string(), b))
            .collect();
    soc.borrow_mut().ring(ROBOT, 1, 0, None);
    assert_eq!(
        soc.borrow_mut()
            .handle("GET", wire::PATH_RING, &h, b"")
            .status,
        200
    );
    soc.borrow_mut().now_ms = T0 + wire::MAX_SKEW_MS + 1;
    assert_eq!(
        soc.borrow_mut()
            .handle("GET", wire::PATH_RING, &h, b"")
            .status,
        401
    );
    soc.borrow_mut().now_ms = T0;
    // Signed for another path.
    assert_eq!(
        soc.borrow_mut()
            .handle("GET", wire::PATH_PROFILE_CURRENT, &h, b"")
            .status,
        401
    );
    // A finding key is not a request key.
    let f = robodr_fleet::keys::load("finding", &u.cfg.finding_key).unwrap();
    let hf: Vec<(String, String)> =
        robodr_fleet::client::auth_headers("GET", &full, b"", &f.signing, T0)
            .into_iter()
            .map(|(a, b)| (a.to_string(), b))
            .collect();
    assert_eq!(
        soc.borrow_mut()
            .handle("GET", wire::PATH_RING, &hf, b"")
            .status,
        401
    );
    h.push(("X-RoboDR-Timestamp".into(), T0.to_string()));
    assert_eq!(
        soc.borrow_mut()
            .handle("GET", wire::PATH_RING, &h, b"")
            .status,
        400
    );
    let _ = key_id(&soc_key());
}

// ------------------------------------------- review regression tests --

/// Delivers the request to the SOC, then loses the answer (connection
/// reset after the SOC processed it).
struct LoseAnswer<'a> {
    soc: &'a std::cell::RefCell<common::soc::Soc>,
}

impl robodr_fleet::client::SocTransport for LoseAnswer<'_> {
    fn send(
        &mut self,
        method: &str,
        target: &str,
        headers: Vec<(&'static str, String)>,
        body: &[u8],
    ) -> Result<robodr_fleet::client::HttpResponse, robodr_fleet::client::TransportError> {
        Direct { soc: self.soc }.send(method, target, headers, body)?;
        Err(robodr_fleet::client::TransportError(
            "connection reset by peer".into(),
        ))
    }

    fn base_path(&self) -> String {
        common::soc::BASE.into()
    }
}

#[test]
fn rotation_whose_answer_was_lost_is_not_aborted_locally() {
    use robodr_fleet::client::SocTransport as _;
    let (u, soc) = enrolled("rot-lost");
    let ctx = u.ctx();
    rotate::prepare(&ctx, "uplink", &rotate::no_crash).unwrap();
    let err = rotate::submit_rotate(&ctx, &mut LoseAnswer { soc: &soc }, "uplink").unwrap_err();
    assert!(err.starts_with("SOC not reached"), "{err}");
    // The SOC registered the new key: a local abort would leave the
    // rotation open at the SOC forever (409 rotation_in_progress).
    let err = rotate::abort(&ctx, "uplink").unwrap_err();
    assert!(err.contains("may have reached the SOC"), "{err}");
    assert!(robodr_fleet::fsx::with_suffix(&u.cfg.uplink_key, ".next").exists());
    // Resending gets the stored answer.
    let r = rotate::submit_rotate(&ctx, &mut Direct { soc: &soc }, "uplink").unwrap();
    assert_eq!(r.phase, Phase::Registered);
    let _ = Direct { soc: &soc }.base_path();
}

#[test]
fn enrollment_request_proves_possession_of_every_key() {
    let u = Unit::new("pop");
    let soc = new_soc();
    let t = token(&soc, "tok-1");
    let ctx = u.ctx();
    let p = enroll::prepare(&ctx, &t, &Default::default()).unwrap();
    let o = Envelope::parse(p.pending.envelope.as_bytes(), wire::T_ENROLL_REQUEST).unwrap();
    let keys: Vec<robodr_fleet::keys::RoleKey> = wire::ROLES
        .iter()
        .map(|r| robodr_fleet::keys::load(r, u.cfg.key_path(r).unwrap()).unwrap())
        .collect();
    let ids: Vec<String> = keys.iter().map(|k| k.key_id()).collect();
    assert_eq!(o.signers(), ids, "signed by uplink, finding, blackbox");
    for k in &keys {
        o.verify_by(&k.key_id(), &k.public()).unwrap();
    }
    // The SOC refuses a request signed by the uplink key alone.
    let mut e = o.envelope.clone();
    e.sigs.truncate(1);
    let h = vec![("Content-Type".to_string(), "application/json".to_string())];
    let r = soc
        .borrow_mut()
        .handle("POST", wire::PATH_ENROLL, &h, &e.to_bytes().unwrap());
    assert_eq!(r.status, 401);
    assert!(String::from_utf8_lossy(&r.body).contains("bad_signature"));
}

fn authed_headers(
    method: &str,
    target: &str,
    body: &[u8],
    k: &robodr_fleet::keys::RoleKey,
    now: u64,
) -> Vec<(String, String)> {
    let mut h = vec![("Content-Type".to_string(), "application/json".to_string())];
    for (a, b) in robodr_fleet::client::auth_headers(
        method,
        &format!("{}{target}", common::soc::BASE),
        body,
        &k.signing,
        now,
    ) {
        h.push((a.to_string(), b));
    }
    h
}

#[test]
fn soc_takes_rotate_auth_from_the_old_uplink_key_and_retire_auth_from_the_new() {
    let (u, soc) = enrolled("rot-auth");
    let ctx = u.ctx();
    let rot = rotate::prepare(&ctx, "uplink", &rotate::no_crash).unwrap();
    rotate::submit_rotate(&ctx, &mut Direct { soc: &soc }, "uplink").unwrap();
    // Overlap: both uplink keys are active. The rotate request (a replay)
    // authenticated by the NEW key is refused: rotate is the old key's.
    let next = robodr_fleet::fsx::with_suffix(&u.cfg.uplink_key, ".next");
    let new = robodr_fleet::keys::load("uplink", &next).unwrap();
    let h = authed_headers("POST", wire::PATH_ROTATE, rot.request.as_bytes(), &new, T0);
    let r = soc
        .borrow_mut()
        .handle("POST", wire::PATH_ROTATE, &h, rot.request.as_bytes());
    assert_eq!(r.status, 401, "{}", String::from_utf8_lossy(&r.body));
    rotate::swap(&ctx, "uplink", &rotate::no_crash).unwrap();
    // Retire authenticated by the OLD key: refused (retire is the new key's).
    let body = rotate::retire_request(&ctx, "uplink").unwrap();
    let old = robodr_fleet::keys::load(
        "uplink",
        &rotate::retired_path(&u.cfg.uplink_key, "uplink", &rot.old_key_id),
    )
    .unwrap();
    let h = authed_headers("POST", wire::PATH_RETIRE, &body, &old, T0);
    let r = soc
        .borrow_mut()
        .handle("POST", wire::PATH_RETIRE, &h, &body);
    assert_eq!(r.status, 401, "{}", String::from_utf8_lossy(&r.body));
    assert!(soc.borrow().keys[&rot.old_key_id].retired_at.is_none());
    rotate::submit_retire(&ctx, &mut Direct { soc: &soc }, "uplink", &rotate::no_crash).unwrap();
}

#[test]
fn revocation_reinstall_compares_the_installed_file() {
    let (u, soc) = enrolled("rev-reinstall");
    let ctx = u.ctx();
    let list = revocation_list(2, &[], &root_key());
    soc.borrow_mut()
        .revocations
        .insert(PLATFORM.into(), list.clone());
    revocation::fetch(&ctx, &mut Direct { soc: &soc }, PLATFORM).unwrap();
    let target = u.etc("revocations.json");
    // The installed file is damaged or replaced: the same list is
    // installed again, not skipped as "already installed".
    std::fs::write(&target, b"{\"damaged\": true}").unwrap();
    let r = revocation::fetch(&ctx, &mut Direct { soc: &soc }, PLATFORM).unwrap();
    assert!(!r.unchanged, "the installed file was not the list");
    assert_eq!(std::fs::read(&target).unwrap(), list);
    // Intact: nothing written.
    assert!(
        revocation::fetch(&ctx, &mut Direct { soc: &soc }, PLATFORM)
            .unwrap()
            .unchanged
    );
}

#[test]
fn files_for_agentd_are_not_installed_into_a_shared_directory() {
    let (u, soc) = enrolled("shared-dir");
    let pubdir = u.root.join("pub");
    std::fs::create_dir_all(&pubdir).unwrap();
    std::fs::set_permissions(&pubdir, std::fs::Permissions::from_mode(0o777)).unwrap();
    let mut facts = u.facts.clone();
    facts.revocation_list = Some(pubdir.join("revocations.json"));
    let ctx = robodr_fleet::state::Ctx::open(u.cfg.clone(), facts, Box::new(|| T0)).unwrap();
    soc.borrow_mut()
        .revocations
        .insert(PLATFORM.into(), revocation_list(2, &[], &root_key()));
    let err = revocation::fetch(&ctx, &mut Direct { soc: &soc }, PLATFORM).unwrap_err();
    assert!(err.contains("writable by group or others"), "{err}");
    assert!(!pubdir.join("revocations.json").exists());
}

#[test]
fn soc_key_file_must_be_root_owned_in_a_private_directory() {
    let (u, soc) = enrolled("soc-key-dir");
    soc.borrow_mut().ring(ROBOT, 1, 0, None);
    let shared = u.root.join("shared");
    std::fs::create_dir_all(&shared).unwrap();
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o775)).unwrap();
    let k = shared.join("fleet-soc.pub");
    write_public_key(&k, &soc_key());
    let mut cfg = u.cfg.clone();
    cfg.soc_keys = vec![k.clone()];
    {
        let ctx =
            robodr_fleet::state::Ctx::open(cfg.clone(), u.facts.clone(), Box::new(|| T0)).unwrap();
        let err = ring::fetch(&ctx, &mut Direct { soc: &soc }).unwrap_err();
        assert!(err.contains("writable by group or others"), "{err}");
    }
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).unwrap();
    if robodr_blackbox::keys::effective_uid() == 0 {
        // Owned by another user: refused.
        std::os::unix::fs::chown(&k, Some(4242), Some(4242)).unwrap();
        let ctx =
            robodr_fleet::state::Ctx::open(cfg.clone(), u.facts.clone(), Box::new(|| T0)).unwrap();
        let err = ring::fetch(&ctx, &mut Direct { soc: &soc }).unwrap_err();
        assert!(err.contains("owned by root"), "{err}");
        std::os::unix::fs::chown(&k, Some(0), Some(0)).unwrap();
    }
    let ctx = robodr_fleet::state::Ctx::open(cfg, u.facts.clone(), Box::new(|| T0)).unwrap();
    ring::fetch(&ctx, &mut Direct { soc: &soc }).unwrap();
}

#[test]
fn ring_info_issued_in_the_future_is_refused() {
    let (u, soc) = enrolled("ring-future");
    let ctx = u.ctx();
    soc.borrow_mut().now_ms = T0 + wire::MAX_SKEW_MS + 1;
    let r = soc.borrow_mut().ring(ROBOT, 1, 0, None);
    let err = ring::accept(&ctx, &r).unwrap_err();
    assert!(err.contains("future"), "{err}");
    soc.borrow_mut().now_ms = T0 + wire::MAX_SKEW_MS;
    let r = soc.borrow_mut().ring(ROBOT, 1, 0, None);
    ring::accept(&ctx, &r).unwrap();
}

#[test]
fn a_sent_rotation_is_cancelled_at_the_soc_and_a_new_one_can_start() {
    let (u, soc) = enrolled("rot-cancel");
    let ctx = u.ctx();
    let old_id = robodr_fleet::keys::load("uplink", &u.cfg.uplink_key)
        .unwrap()
        .key_id();
    // (a) The SOC registered the rotation, the answer was lost.
    let rot = rotate::prepare(&ctx, "uplink", &rotate::no_crash).unwrap();
    assert!(rotate::submit_rotate(&ctx, &mut LoseAnswer { soc: &soc }, "uplink").is_err());
    assert!(soc.borrow().keys.contains_key(&rot.new_key_id));
    rotate::submit_cancel(&ctx, &mut Direct { soc: &soc }, "uplink").unwrap();
    assert!(rotate::current(&ctx, "uplink").unwrap().is_none());
    assert!(!robodr_fleet::fsx::with_suffix(&u.cfg.uplink_key, ".next").exists());
    assert!(soc.borrow().keys[&rot.new_key_id].retired_at.is_some());
    assert_eq!(
        robodr_fleet::keys::load("uplink", &u.cfg.uplink_key)
            .unwrap()
            .key_id(),
        old_id,
        "the old key stays active"
    );
    assert_eq!(soc.borrow().active_key(ROBOT, "uplink"), vec![&old_id]);
    // (b) A request that never reached the SOC (network down) is sent as
    // far as the unit knows: cancelled at the SOC too, which records it.
    let rot2 = rotate::prepare(&ctx, "uplink", &rotate::no_crash).unwrap();
    assert!(rotate::submit_rotate(&ctx, &mut Down, "uplink").is_err());
    assert!(rotate::abort(&ctx, "uplink").is_err());
    rotate::submit_cancel(&ctx, &mut Direct { soc: &soc }, "uplink").unwrap();
    // The late rotate request is refused by the SOC.
    let up = robodr_fleet::keys::load("uplink", &u.cfg.uplink_key).unwrap();
    let h = authed_headers("POST", wire::PATH_ROTATE, rot2.request.as_bytes(), &up, T0);
    let r = soc
        .borrow_mut()
        .handle("POST", wire::PATH_ROTATE, &h, rot2.request.as_bytes());
    assert_eq!(r.status, 409);
    assert!(String::from_utf8_lossy(&r.body).contains("rotation_cancelled"));
    // (c) The air-gapped request file counts as sent.
    let ctx2 = &ctx;
    rotate::prepare(ctx2, "finding", &rotate::no_crash).unwrap();
    rotate::request_out(ctx2, "finding").unwrap();
    assert!(rotate::abort(ctx2, "finding").is_err());
    rotate::submit_cancel(ctx2, &mut Direct { soc: &soc }, "finding").unwrap();
    // A new rotation runs to the end (nothing is left "in progress").
    drop(ctx);
    full_rotation(&u, &soc, "uplink");
    full_rotation(&u, &soc, "finding");
    let notes = journal_notes(&u);
    assert_eq!(
        notes.iter().filter(|n| n["phase"] == "cancelled").count(),
        3
    );
}

#[test]
fn approvals_are_accepted_from_the_approval_key_only() {
    let (u, soc) = enrolled("approval-key");
    let ctx = u.ctx();
    let (p, s) = signed_profile(4, Some(ROBOT));
    soc.borrow_mut().offer(ROBOT, 4, &p, &s);
    let m = profile::fetch(&ctx, &mut Direct { soc: &soc }).unwrap();
    // Signed by the online fleet key (a valid SOC key for answers): refused.
    let a = wire::Approval {
        format: wire::APPROVAL_FORMAT.into(),
        approval_id: "ap-f".into(),
        workspace: WORKSPACE.into(),
        robot_id: ROBOT.into(),
        platform: PLATFORM.into(),
        profile_digest: m.digest.clone(),
        profile_version: 4,
        transition: "enforce".into(),
        approved_by: vec!["op-a".into()],
        issued_at_ms: T0,
        expires_at_ms: T0 + 600_000,
    };
    let by_fleet_key = Envelope::sign(
        wire::T_APPROVAL,
        &wire::payload_bytes(&a).unwrap(),
        &[&soc_key()],
    )
    .to_bytes()
    .unwrap();
    let err = profile::approve(&ctx, &by_fleet_key).unwrap_err();
    assert!(err.contains("approval key"), "{err}");
    assert!(!u.etc("profile.json").exists());
    drop(ctx);
    // The fleet key configured as an approval key too: refused.
    let mut cfg = u.cfg.clone();
    let dup = u.etc("fleet-soc-copy.pub");
    write_public_key(&dup, &soc_key());
    cfg.approval_keys = vec![dup];
    let ctx = robodr_fleet::state::Ctx::open(cfg, u.facts.clone(), Box::new(|| T0)).unwrap();
    let err = profile::approve(&ctx, &by_fleet_key).unwrap_err();
    assert!(
        err.contains("both as a fleet key and as an approval key"),
        "{err}"
    );
    drop(ctx);
    let ctx = u.ctx();
    let good = soc
        .borrow_mut()
        .approval("ap-g", ROBOT, PLATFORM, &m.digest, 4, &["op-a"], 600_000);
    profile::approve(&ctx, &good).unwrap();
    assert_eq!(std::fs::read(u.etc("profile.json")).unwrap(), p);
}

#[test]
fn ring_minimum_version_reaches_ring_env() {
    let (u, soc) = enrolled("ring-min");
    let ctx = u.ctx();
    soc.borrow_mut()
        .ring_with_min(ROBOT, 1, 0, Some("0.2.0"), Some("0.1.5"));
    let s = ring::fetch(&ctx, &mut Direct { soc: &soc }).unwrap();
    assert_eq!(s.info.min_version.as_deref(), Some("0.1.5"));
    let env = std::fs::read_to_string(u.cfg.state_dir.join("ring.env")).unwrap();
    assert!(env.lines().any(|l| l == "min_version=0.1.5"), "{env}");
    assert!(env.lines().any(|l| l == "target_version=0.2.0"), "{env}");
}
