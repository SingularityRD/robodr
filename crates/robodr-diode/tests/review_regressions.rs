//! Regression tests for the rev4/diode security review. Each test is the
//! review's proof of concept (ported to the Ed25519 key layout where keys
//! matter) asserting the **fixed** behaviour.

mod common;

use common::*;
use robodr_blackbox::{
    Ed25519SigningKey, FsyncPolicy, HmacSha256Key, KeyFile, Recorder, RecorderConfig,
    SteppingClock, TimeSource,
};
use robodr_diode::manifest::{batch_dir_name, FINDINGS_FILE, MAX_BATCH_SEQ};
use robodr_diode::pack::{DEFAULT_MAX_BATCH_BYTES, MAX_BATCH_BYTES};
use robodr_diode::unpack::{
    DEFAULT_MAX_IMPORT_BATCH_BYTES, QUARANTINE_ENTRY, REASON_FILE, RECORDS_FILE,
};
use robodr_diode::{ImportReport, Importer, Keyring, PackConfig, Packer};
use robodr_events::graph::Endpoint;
use robodr_events::{Deviation, RobotEvent, Severity};
use robodr_ocsf::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const ED_SEED: [u8; 32] = [0x29; 32];
const ED_KEY_ID: &str = "diode-ugv-007-ed";
const OTHER: &str = "ugv-999";
const DAY_MS: u64 = 24 * 3600 * 1000;

fn codes(r: &ImportReport) -> Vec<String> {
    r.quarantined
        .iter()
        .map(|q| reason_code(&q.reason))
        .collect()
}

fn ed_signer() -> Box<Ed25519SigningKey> {
    Box::new(Ed25519SigningKey::from_seed(ED_KEY_ID, &ED_SEED).unwrap())
}

/// The SOC keyring: only the unit's Ed25519 public key.
fn ed_ring() -> Keyring {
    let kf = KeyFile::ed25519_from_seed(&ED_SEED, Some(ED_KEY_ID))
        .unwrap()
        .to_public()
        .unwrap();
    let mut k = Keyring::new();
    k.add(UNIT, kf.verifier().unwrap()).unwrap();
    k
}

fn ed_packer(site: &Site) -> Packer {
    Packer::open(
        &site.outbox,
        &site.pack_state,
        PackConfig::new(UNIT),
        ed_signer(),
    )
    .unwrap()
}

/// A valid finding whose `entity_context.robot.id` is `robot`.
fn finding_for(robot: &str, i: u64) -> FindingEnvelope {
    let mut c = ctx();
    c.robot.id = robot.into();
    let dev = Deviation::new(
        "robot.ros2.unknown_writer_topic",
        Severity::High,
        format!("writer on rt/t{i}"),
    );
    FindingBuilder::from_deviation(&dev, &c)
        .event(&RobotEvent::Ros2WriterDiscovered(Endpoint {
            guid_prefix: "0102030405060708090a0b0c".into(),
            topic: format!("rt/t{i}"),
            type_name: "std_msgs::msg::dds_::String_".into(),
        }))
        .seen(T0 + i, T0 + i)
        .build()
        .unwrap()
}

/// A black-box bundle whose chain identity names `device`.
fn bundle_for(device: &str) -> Vec<u8> {
    let d = TempDir::new("rr-bb");
    let mut cfg = RecorderConfig::new(d.path().join("bb"), device, "boot-x");
    cfg.fsync = FsyncPolicy::SealsOnly;
    let mut rec = Recorder::open(
        cfg,
        Box::new(HmacSha256Key::new(BB_KEY_ID, &BB_KEY).unwrap()),
        Box::new(SteppingClock::new(1_000_000, 1_000, TimeSource::Gps)),
    )
    .unwrap();
    rec.append_note(&serde_json::json!({"n": 1}), false)
        .unwrap();
    rec.export_pending(None).unwrap().unwrap().to_bytes()
}

fn bb_key() -> Box<HmacSha256Key> {
    Box::new(HmacSha256Key::new(BB_KEY_ID, &BB_KEY).unwrap())
}

fn reason_json(q: &robodr_diode::unpack::QuarantinedBatch) -> serde_json::Value {
    let dir = q.moved_to.parent().unwrap();
    serde_json::from_slice(&fs::read(dir.join(REASON_FILE)).unwrap()).unwrap()
}

fn mtime_ms(p: &Path) -> u64 {
    fs::symlink_metadata(p)
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

// ---------------------------------------------------------------- F1

/// F1 (fixed): a unit's diode key can no longer emit findings attributed to
/// another robot; an explicit per-unit allow-list re-enables it.
#[test]
fn f1_findings_for_other_robot_are_quarantined_unless_allowed() {
    let site = Site::new("rr-f1");
    ed_packer(&site)
        .pack(&[finding_for(UNIT, 0), finding_for(OTHER, 1)], &[], NOW)
        .unwrap();
    site.transfer_all();
    let mut imp = Importer::open(site.import_cfg(), ed_ring()).unwrap();
    let r = imp.run(NOW).unwrap();
    assert!(r.accepted.is_empty(), "{r:?}");
    assert_eq!(codes(&r), vec!["robot_not_allowed"]);
    let rf = reason_json(&r.quarantined[0]);
    assert_eq!(rf["reason"]["line"], 2);
    assert_eq!(rf["reason"]["robot_id"], OTHER);
    assert_eq!(rf["reason"]["unit_id"], UNIT);
    assert!(imp.state().units.is_empty());
    assert!(fs::read_dir(site.high.join("out"))
        .unwrap()
        .next()
        .is_none());

    // The operator allows ugv-007 to report on ugv-999 (e.g. a console):
    // an intact re-send is now accepted, with the robot id preserved.
    let site = Site::new("rr-f1-allowed");
    ed_packer(&site)
        .pack(&[finding_for(OTHER, 1)], &[], NOW)
        .unwrap();
    site.transfer_all();
    let mut ring = ed_ring();
    ring.allow_robot(UNIT, OTHER).unwrap();
    let r = Importer::open(site.import_cfg(), ring)
        .unwrap()
        .run(NOW)
        .unwrap();
    assert_eq!(r.accepted.len(), 1, "{r:?}");
    let recs = read_lines(&r.accepted[0].output.join(RECORDS_FILE));
    let v: serde_json::Value = serde_json::from_str(recs[0]["value"].as_str().unwrap()).unwrap();
    assert_eq!(v["entity_context"]["robot"]["id"], OTHER);
    assert_eq!(recs[0]["diode"]["unit_id"], UNIT);

    // The allow-list is per unit: allowing it for another unit does not help.
    let site = Site::new("rr-f1-other-unit");
    ed_packer(&site)
        .pack(&[finding_for(OTHER, 1)], &[], NOW)
        .unwrap();
    site.transfer_all();
    let mut ring = ed_ring();
    ring.allow_robot("ugv-008", OTHER).unwrap();
    let r = Importer::open(site.import_cfg(), ring)
        .unwrap()
        .run(NOW)
        .unwrap();
    assert_eq!(codes(&r), vec!["robot_not_allowed"]);
}

/// F1b (fixed): a bundle whose chain names another device is quarantined,
/// even when it is signed by a black-box key the importer trusts.
#[test]
fn f1b_bundle_device_must_belong_to_the_unit() {
    let site = Site::new("rr-f1b");
    ed_packer(&site)
        .pack(&[], &[bundle_for(OTHER)], NOW)
        .unwrap();
    site.transfer_all();
    let mut imp = Importer::open(site.import_cfg(), ed_ring()).unwrap();
    imp.add_bundle_verifier(UNIT, bb_key()).unwrap();
    let r = imp.run(NOW).unwrap();
    assert!(r.accepted.is_empty(), "{r:?}");
    assert_eq!(codes(&r), vec!["bundle_device_not_allowed"]);
    let rf = reason_json(&r.quarantined[0]);
    assert_eq!(rf["reason"]["device_id"], OTHER);

    // Allowed explicitly: accepted and verified.
    let site = Site::new("rr-f1b-allowed");
    ed_packer(&site)
        .pack(&[], &[bundle_for(OTHER)], NOW)
        .unwrap();
    site.transfer_all();
    let mut ring = ed_ring();
    ring.allow_robot(UNIT, OTHER).unwrap();
    let mut imp = Importer::open(site.import_cfg(), ring).unwrap();
    imp.add_bundle_verifier(UNIT, bb_key()).unwrap();
    let r = imp.run(NOW).unwrap();
    assert_eq!(r.accepted.len(), 1, "{r:?}");
    assert_eq!(r.accepted[0].bundles_verified, 1);
}

/// F1b (fixed): bundle verifiers are bound to a unit. A bundle signed with a
/// key registered for another unit is quarantined, not counted as verified
/// evidence of this unit.
#[test]
fn f1b_bundle_key_must_be_bound_to_the_unit() {
    let site = Site::new("rr-f1b-key");
    ed_packer(&site)
        .pack(&[], &[bundle_for(UNIT)], NOW)
        .unwrap();
    site.transfer_all();
    let mut imp = Importer::open(site.import_cfg(), ed_ring()).unwrap();
    imp.add_bundle_verifier("ugv-008", bb_key()).unwrap();
    let r = imp.run(NOW).unwrap();
    assert_eq!(codes(&r), vec!["bundle_key_unit_mismatch"]);
    let rf = reason_json(&r.quarantined[0]);
    assert_eq!(rf["reason"]["key_unit"], "ugv-008");
    assert_eq!(rf["reason"]["unit_id"], UNIT);
    drop(imp);

    // The same key cannot be registered for two units.
    let mut imp = Importer::open(site.import_cfg(), ed_ring()).unwrap();
    imp.add_bundle_verifier(UNIT, bb_key()).unwrap();
    assert!(imp.add_bundle_verifier("ugv-008", bb_key()).is_err());
}

// ---------------------------------------------------------------- F2

/// F2 (fixed): after the documented recovery for packer-state loss, the new
/// batch 1 is emitted under its own output directory instead of being
/// reported accepted while the stale `out/<batch>/` is reused.
#[test]
fn f2_stale_out_dir_does_not_swallow_a_new_batch() {
    let site = Site::new("rr-f2");
    let old = site.packer().pack(&[finding(1)], &[], NOW).unwrap();
    site.transfer_all();
    let r1 = site.importer().run(NOW).unwrap();
    assert_eq!(r1.accepted.len(), 1);
    let out = r1.accepted[0].output.clone();
    assert_eq!(out, site.high.join("out").join(&old[0].name));
    let old_records = fs::read(out.join(RECORDS_FILE)).unwrap();

    // Low side loses its state; outbox already drained.
    fs::remove_file(&site.pack_state).unwrap();
    fs::remove_dir_all(site.outbox.join(&old[0].name)).unwrap();
    let new = site.packer().pack(&[finding(2)], &[], NOW).unwrap();
    assert_eq!(new[0].name, old[0].name);
    assert_ne!(new[0].batch_hash, old[0].batch_hash);
    site.transfer_all();

    // Operator resets the unit entry, as the README recommends.
    let sp = site.high.join("state.json");
    let mut st: serde_json::Value = serde_json::from_slice(&fs::read(&sp).unwrap()).unwrap();
    st["units"].as_object_mut().unwrap().remove(UNIT);
    fs::write(&sp, serde_json::to_vec(&st).unwrap()).unwrap();

    let mut imp = site.importer();
    let r2 = imp.run(NOW).unwrap();
    assert_eq!(r2.accepted.len(), 1, "{r2:?}");
    let a = &r2.accepted[0];
    assert_eq!(a.batch_hash, new[0].batch_hash);
    // Emitted under a distinct, hash-suffixed name, with the NEW findings.
    let expected =
        site.high
            .join("out")
            .join(format!("{}.{}", new[0].name, &new[0].batch_hash[..16]));
    assert_eq!(a.output, expected);
    let recs = fs::read_to_string(a.output.join(RECORDS_FILE)).unwrap();
    assert!(recs.contains(&finding(2).finding_id), "{recs}");
    assert!(!recs.contains(&finding(1).finding_id));
    // The old output is untouched.
    assert_eq!(fs::read(out.join(RECORDS_FILE)).unwrap(), old_records);
    assert_eq!(imp.state().units[UNIT].last_hash, new[0].batch_hash);
}

/// F2: the crash-recovery path still works: an `out/<batch>/` holding the
/// same signed manifest is reused, not duplicated.
#[test]
fn f2_same_batch_output_is_reused_after_crash() {
    let site = Site::new("rr-f2-crash");
    let b = site.packer().pack(&findings(2), &[], NOW).unwrap();
    site.transfer_all();
    // Keep a copy of the inbox entry, import, then simulate a crash after
    // emit but before the state was written / the batch was moved.
    let keep = site.tmp.path().join("keep");
    copy_dir(&site.inbox().join(&b[0].name), &keep);
    let r = site.importer().run(NOW).unwrap();
    assert_eq!(r.accepted.len(), 1);
    fs::remove_file(site.high.join("state.json")).unwrap();
    copy_dir(&keep, &site.inbox().join(&b[0].name));

    let r = site.importer().run(NOW).unwrap();
    assert_eq!(r.accepted.len(), 1, "{r:?}");
    assert_eq!(r.accepted[0].output, site.high.join("out").join(&b[0].name));
    let outs: Vec<_> = fs::read_dir(site.high.join("out")).unwrap().collect();
    assert_eq!(outs.len(), 1, "no second output directory");
}

// ---------------------------------------------------------------- F3

/// F3 (fixed): any number of earlier quarantine occupants of a name cannot
/// wedge the importer; the legitimate batch is imported in the same run.
#[test]
fn f3_quarantine_names_cannot_be_exhausted() {
    let site = Site::new("rr-f3");
    let legit = one_batch_name(&site);
    let q = site.high.join("quarantine");
    fs::create_dir_all(&q).unwrap();
    fs::write(q.join("junk"), b"").unwrap();
    for i in 1..10_000 {
        fs::write(q.join(format!("junk.{i}")), b"").unwrap();
    }
    for round in 0..3 {
        fs::write(site.inbox().join("junk"), b"x").unwrap();
        let mut imp = site.importer();
        let r = imp.run(NOW).unwrap();
        assert!(r.errors.is_empty(), "{r:?}");
        assert_eq!(codes(&r), vec!["not_a_directory"], "round {round}");
        assert_eq!(fs::read(&r.quarantined[0].moved_to).unwrap(), b"x");
        if round == 0 {
            assert_eq!(r.accepted.len(), 1);
            assert_eq!(r.accepted[0].name, legit);
        }
        assert!(site.inbox_entries().is_empty());
    }
}

/// F3 (fixed): an I/O failure on one entry is reported per entry; other
/// entries (here another unit's batch) are still imported in the same run.
#[test]
fn f3_per_entry_io_error_does_not_abort_the_run() {
    let site = Site::new("rr-f3-io");
    let a = one_batch_name(&site);
    // A second unit, packing into the same outbox.
    let b_state = site.tmp.path().join("low/pack-state-b.json");
    let b_key = || Box::new(HmacSha256Key::new("diode-ugv-008", &[8; 32]).unwrap());
    let mut pb = Packer::open(&site.outbox, &b_state, PackConfig::new("ugv-008"), b_key()).unwrap();
    let mut c = ctx();
    c.robot.id = "ugv-008".into();
    let dev = Deviation::new("robot.ros2.unknown_writer_topic", Severity::High, "w");
    let fb = FindingBuilder::from_deviation(&dev, &c)
        .event(&RobotEvent::Ros2WriterDiscovered(Endpoint {
            guid_prefix: "0102030405060708090a0b0c".into(),
            topic: "rt/b".into(),
            type_name: "std_msgs::msg::dds_::String_".into(),
        }))
        .seen(T0, T0)
        .build()
        .unwrap();
    let b = pb.pack(&[fb], &[], NOW).unwrap();
    site.transfer(&b[0].name);
    let mut ring = keyring();
    ring.add("ugv-008", b_key()).unwrap();

    // Sabotage the emit of unit A's batch: its staging path is a file.
    fs::create_dir_all(site.high.join("out")).unwrap();
    fs::write(site.high.join("out").join(format!(".tmp-{a}")), b"").unwrap();
    let mut imp = Importer::open(site.import_cfg(), ring).unwrap();
    let r = imp.run(NOW).unwrap();
    assert_eq!(r.errors.len(), 1, "{r:?}");
    assert_eq!(r.errors[0].name, a);
    assert!(!r.is_clean());
    assert_eq!(r.accepted.len(), 1, "{r:?}");
    assert_eq!(r.accepted[0].unit_id, "ugv-008");
    assert!(!imp.state().units.contains_key(UNIT));
    assert!(site.inbox().join(&a).exists(), "left for the next run");

    // Fixed: the next run imports it.
    fs::remove_file(site.high.join("out").join(format!(".tmp-{a}"))).unwrap();
    let r = imp.run(NOW).unwrap();
    assert!(r.is_clean(), "{r:?}");
    assert_eq!(r.accepted.len(), 1);
}

/// Unreadable entries (permissions) are quarantined or reported, never
/// abort the run. (As root, permission bits do not deny reads; the test
/// then only checks the run completes.)
#[test]
fn unreadable_entry_does_not_abort_the_run() {
    let site = Site::new("rr-perm");
    let name = one_batch_name(&site);
    let f = site.inbox().join(&name).join(FINDINGS_FILE);
    fs::set_permissions(&f, fs::Permissions::from_mode(0o000)).unwrap();
    let denied = fs::File::open(&f).is_err();
    let r = site.importer().run(NOW).unwrap();
    if denied {
        assert_eq!(codes(&r), vec!["unreadable"], "{r:?}");
    } else {
        assert_eq!(r.accepted.len(), 1, "{r:?}");
    }

    // A whole unreadable directory next to a good batch: the good batch is
    // imported; the bad entry is quarantined or reported, never fatal.
    let site = Site::new("rr-perm-dir");
    let name = one_batch_name(&site);
    let bad = site.inbox().join("rdd_ugv-007_0000000000000009");
    fs::create_dir(&bad).unwrap();
    fs::write(bad.join("MANIFEST.json"), b"{}").unwrap();
    fs::set_permissions(&bad, fs::Permissions::from_mode(0o000)).unwrap();
    let r = site.importer().run(NOW).unwrap();
    let _ = fs::set_permissions(&bad, fs::Permissions::from_mode(0o700));
    assert_eq!(r.accepted.len(), 1, "{r:?}");
    assert_eq!(r.accepted[0].name, name);
    assert_eq!(r.quarantined.len() + r.errors.len(), 1, "{r:?}");
    for q in &r.quarantined {
        // Denied: `unreadable`; as root: the unsigned junk's own reason.
        let code = reason_code(&q.reason);
        assert!(
            ["unreadable", "missing_signature"].contains(&code.as_str()),
            "{code}"
        );
        let _ = fs::set_permissions(&q.moved_to, fs::Permissions::from_mode(0o700));
    }
}

// ---------------------------------------------------------------- F4

/// F4 (fixed): each quarantined entry gets its own directory; an inbox entry
/// named like a reason file can neither impersonate one nor block a later
/// reason write.
#[test]
fn f4_reason_files_have_their_own_namespace() {
    let site = Site::new("rr-f4");
    let forged = br#"{"format":"robodr-diode/1","entry":"rdd_ugv-007_0000000000000001","quarantined_at_ms":1,"reason":{"code":"duplicate"}}"#;
    fs::write(site.inbox().join("x.reason.json"), forged).unwrap();
    let r = site.importer().run(NOW).unwrap();
    let q = &r.quarantined[0];
    let qdir = site.high.join("quarantine").join("x.reason.json");
    assert_eq!(q.moved_to, qdir.join(QUARANTINE_ENTRY));
    assert_eq!(fs::read(&q.moved_to).unwrap(), forged);
    let rf: serde_json::Value =
        serde_json::from_slice(&fs::read(qdir.join(REASON_FILE)).unwrap()).unwrap();
    assert_eq!(rf["reason"]["code"], "not_a_directory");
    assert_eq!(rf["entry"], "x.reason.json");

    let site = Site::new("rr-f4b");
    fs::create_dir(site.inbox().join("y.reason.json")).unwrap();
    site.importer().run(NOW).unwrap();
    let legit = one_batch_name(&site);
    fs::write(site.inbox().join("y"), b"z").unwrap();
    // A second "y" in the same run, and entries named like our layout.
    fs::create_dir(site.inbox().join(REASON_FILE)).unwrap();
    fs::write(site.inbox().join(QUARANTINE_ENTRY), b"e").unwrap();
    let r = site.importer().run(NOW).unwrap();
    assert!(r.errors.is_empty(), "{r:?}");
    assert_eq!(r.accepted.len(), 1);
    assert_eq!(r.accepted[0].name, legit);
    assert_eq!(r.quarantined.len(), 3);
    for q in &r.quarantined {
        assert!(q.moved_to.ends_with(QUARANTINE_ENTRY));
        assert!(q.moved_to.parent().unwrap().join(REASON_FILE).is_file());
    }
    assert!(site.inbox_entries().is_empty());
}

// ---------------------------------------------------------------- notes

#[test]
fn packer_limit_never_exceeds_importer_default() {
    assert_eq!(MAX_BATCH_BYTES, DEFAULT_MAX_IMPORT_BATCH_BYTES);
    const { assert!(DEFAULT_MAX_BATCH_BYTES <= DEFAULT_MAX_IMPORT_BATCH_BYTES) };
    let site = Site::new("rr-limits");
    let mut cfg = PackConfig::new(UNIT);
    cfg.max_batch_bytes = MAX_BATCH_BYTES + 1;
    assert!(Packer::open(&site.outbox, &site.pack_state, cfg, signer()).is_err());
    let mut cfg = PackConfig::new(UNIT);
    cfg.max_batch_bytes = MAX_BATCH_BYTES;
    assert!(Packer::open(&site.outbox, &site.pack_state, cfg, signer()).is_ok());
}

#[test]
fn accepted_gap_is_bounded_and_seq_cannot_reach_u64_max() {
    // A far-future batch (re-signed by the key holder) with an operator
    // acceptance beyond the bound is refused, not accepted.
    let site = Site::new("rr-gap");
    let name = one_batch_name(&site);
    let far = 1_000_000u64;
    let new_name = batch_dir_name(UNIT, far);
    fs::rename(site.inbox().join(&name), site.inbox().join(&new_name)).unwrap();
    resign(&site.inbox().join(&new_name), |m| {
        m["batch_seq"] = far.into();
        m["prev_batch_hash"] = "ab".repeat(32).into();
    });
    let mut cfg = site.import_cfg();
    cfg.accept_gaps.push((UNIT.into(), far));
    cfg.max_accept_gap = 1000;
    let mut imp = Importer::open(cfg.clone(), keyring()).unwrap();
    let r = imp.run(NOW).unwrap();
    assert_eq!(codes(&r), vec!["gap_too_large"], "{r:?}");
    assert!(imp.state().units.is_empty());

    // Within the bound it is accepted and recorded.
    let site = Site::new("rr-gap-ok");
    let name = one_batch_name(&site);
    let new_name = batch_dir_name(UNIT, 1001);
    fs::rename(site.inbox().join(&name), site.inbox().join(&new_name)).unwrap();
    resign(&site.inbox().join(&new_name), |m| {
        m["batch_seq"] = 1001.into();
        m["prev_batch_hash"] = "ab".repeat(32).into();
    });
    let mut cfg = site.import_cfg();
    cfg.accept_gaps.push((UNIT.into(), 1001));
    cfg.max_accept_gap = 1000;
    let r = Importer::open(cfg, keyring()).unwrap().run(NOW).unwrap();
    assert_eq!(r.accepted[0].gap_accepted, Some((1, 1000)));

    // u64::MAX (or anything past the 16-digit name space) is malformed.
    let site = Site::new("rr-seq-max");
    let name = one_batch_name(&site);
    let new_name = format!("rdd_{UNIT}_{}", u64::MAX);
    fs::rename(site.inbox().join(&name), site.inbox().join(&new_name)).unwrap();
    resign(&site.inbox().join(&new_name), |m| {
        m["batch_seq"] = u64::MAX.into();
        m["prev_batch_hash"] = "ab".repeat(32).into();
    });
    let mut cfg = site.import_cfg();
    cfg.accept_gaps.push((UNIT.into(), u64::MAX));
    cfg.max_accept_gap = u64::MAX;
    let r = Importer::open(cfg, keyring()).unwrap().run(NOW).unwrap();
    assert_eq!(codes(&r), vec!["manifest_invalid"], "{r:?}");
    const { assert!(MAX_BATCH_SEQ < u64::MAX / 2) };
}

#[test]
fn held_batches_and_stale_dot_entries_expire() {
    let site = Site::new("rr-expire");
    let mut cfg = PackConfig::new(UNIT);
    cfg.max_findings_per_batch = 1;
    let b = site.packer_cfg(cfg).pack(&findings(2), &[], NOW).unwrap();
    site.transfer(&b[1].name); // gap at 1
    fs::create_dir(site.inbox().join(".incoming")).unwrap();
    let held_at = mtime_ms(&site.inbox().join(&b[1].name));
    let dot_at = mtime_ms(&site.inbox().join(".incoming"));

    // Young: held / in transit, reported.
    let r = site.importer().run(held_at.max(dot_at) + 1000).unwrap();
    assert_eq!(r.held.len(), 1);
    assert_eq!(r.in_transit, vec![".incoming".to_string()]);
    assert!(r.quarantined.is_empty());

    // After the in-transit limit but before the held limit.
    let now = dot_at + DAY_MS + 1;
    let r = site.importer().run(now).unwrap();
    assert_eq!(codes(&r), vec!["stale_in_transit"]);
    assert_eq!(r.held.len(), 1);
    assert!(r.held[0].age_ms > 0);

    // After the held limit: quarantined with a reason.
    let now = held_at + 31 * DAY_MS;
    let r = site.importer().run(now).unwrap();
    assert_eq!(codes(&r), vec!["held_expired"], "{r:?}");
    let rf = reason_json(&r.quarantined[0]);
    assert_eq!(rf["reason"]["seq"], 2);
    assert_eq!(rf["reason"]["expected_seq"], 1);
    assert!(site.inbox_entries().is_empty());

    // Disabled expiry: held forever.
    let site = Site::new("rr-expire-off");
    let mut cfg = PackConfig::new(UNIT);
    cfg.max_findings_per_batch = 1;
    let b = site.packer_cfg(cfg).pack(&findings(2), &[], NOW).unwrap();
    site.transfer(&b[1].name);
    let mut icfg = site.import_cfg();
    icfg.held_max_age_ms = None;
    icfg.in_transit_max_age_ms = None;
    let r = Importer::open(icfg, keyring())
        .unwrap()
        .run(u64::MAX)
        .unwrap();
    assert_eq!(r.held.len(), 1);
    assert!(r.quarantined.is_empty());
}

#[test]
fn findings_are_streamed_with_bounded_lines() {
    // A line longer than one finding may be is rejected without buffering
    // the whole file as a line.
    let site = Site::new("rr-long-line");
    let name = one_batch_name(&site);
    let dir = site.inbox().join(&name);
    let mut long = vec![b'x'; MAX_FINDING_BYTES_PLUS];
    long.push(b'\n');
    replace_file_resigned(&dir, FINDINGS_FILE, &long);
    let r = site.importer().run(NOW).unwrap();
    assert_eq!(codes(&r), vec!["findings_format"], "{r:?}");
    assert!(r.quarantined[0].reason.to_string().contains("longer than"));

    // Many findings spanning several read chunks round-trip exactly.
    let site = Site::new("rr-stream");
    let fs_in = findings(300);
    let b = site.packer().pack(&fs_in, &[], NOW).unwrap();
    assert_eq!(b.len(), 1);
    assert!(b[0].data_bytes > 3 * 64 * 1024, "{}", b[0].data_bytes);
    site.transfer_all();
    let r = site.importer().run(NOW).unwrap();
    assert!(r.is_clean(), "{r:?}");
    let recs = read_lines(&r.accepted[0].output.join(RECORDS_FILE));
    assert_eq!(recs.len(), 300);
    for (i, (rec, f)) in recs.iter().zip(&fs_in).enumerate() {
        assert_eq!(rec["diode"]["line"], i + 1);
        assert_eq!(rec["value"].as_str().unwrap(), to_json(f).unwrap());
    }

    // A corrupted (unsigned) byte in a middle line is a hash mismatch, not a
    // line-level verdict on unauthenticated content.
    let site = Site::new("rr-stream-tamper");
    let name = one_batch_name(&site);
    let p = site.inbox().join(&name).join(FINDINGS_FILE);
    let mut bytes = fs::read(&p).unwrap();
    bytes[10] = b'#';
    fs::write(&p, bytes).unwrap();
    let r = site.importer().run(NOW).unwrap();
    assert_eq!(codes(&r), vec!["hash_mismatch"]);
}

const MAX_FINDING_BYTES_PLUS: usize = robodr_ocsf::validate::MAX_FINDING_BYTES + 1;

fn one_batch_name(site: &Site) -> String {
    let b = site.packer().pack(&[finding(1)], &[], NOW).unwrap();
    site.transfer_all();
    assert_eq!(b[0].name, batch_dir_name(UNIT, b[0].seq));
    b[0].name.clone()
}
