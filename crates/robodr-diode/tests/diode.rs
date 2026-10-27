//! End-to-end tests: pack on the low side, "diode" copy, import on the high side.

mod common;

use common::*;
use robodr_blackbox::HmacSha256Key;
use robodr_diode::manifest::{
    batch_dir_name, FINDINGS_FILE, MANIFEST_FILE, MAX_MANIFEST_BYTES, SIGNATURE_FILE,
};
use robodr_diode::pack::MIN_BATCH_BYTES;
use robodr_diode::unpack::{QUARANTINE_ENTRY, REASON_FILE, RECORDS_FILE};
use robodr_diode::{ImportReport, Importer, Keyring, PackConfig, PackError, Packer};
use std::fs;
use std::os::unix::fs::symlink;

fn codes(r: &ImportReport) -> Vec<String> {
    r.quarantined
        .iter()
        .map(|q| reason_code(&q.reason))
        .collect()
}

fn one_batch(site: &Site, n: u64) -> String {
    let mut p = site.packer();
    let b = p.pack(&findings(n), &[], NOW).unwrap();
    assert_eq!(b.len(), 1);
    site.transfer(&b[0].name);
    b[0].name.clone()
}

/// Assert a single quarantine with `code`, nothing accepted, state untouched.
fn expect_quarantine(site: &Site, code: &str) -> ImportReport {
    let mut imp = site.importer();
    let r = imp.run(NOW).unwrap();
    assert!(r.accepted.is_empty(), "{r:?}");
    assert_eq!(codes(&r), vec![code.to_string()], "{r:?}");
    assert!(imp.state().units.is_empty());
    let q = &r.quarantined[0];
    assert!(fs::symlink_metadata(&q.moved_to).is_ok());
    assert_eq!(q.moved_to.file_name().unwrap(), QUARANTINE_ENTRY);
    let qdir = q.moved_to.parent().unwrap();
    assert_eq!(qdir.parent().unwrap(), site.high.join("quarantine"));
    let rf: serde_json::Value =
        serde_json::from_slice(&fs::read(qdir.join(REASON_FILE)).unwrap()).unwrap();
    assert_eq!(rf["reason"]["code"], code);
    assert!(site.inbox_entries().is_empty());
    r
}

#[test]
fn round_trip_findings_and_bundle() {
    let site = Site::new("rt");
    let fs_in = findings(5);
    let bb = bundle(4);
    let mut p = site.packer();
    let pubd = p.pack(&fs_in, std::slice::from_ref(&bb), NOW).unwrap();
    assert_eq!(pubd.len(), 1);
    assert_eq!(pubd[0].seq, 1);
    assert_eq!(pubd[0].finding_count, 5);
    assert_eq!(pubd[0].bundle_count, 1);
    assert_eq!(p.state().next_seq, 2);
    site.transfer_all();

    let mut cfg = site.import_cfg();
    cfg.partitions = Some(12);
    let mut imp = Importer::open(cfg, keyring()).unwrap();
    imp.add_bundle_verifier(
        UNIT,
        Box::new(HmacSha256Key::new(BB_KEY_ID, &BB_KEY).unwrap()),
    )
    .unwrap();
    let r = imp.run(NOW).unwrap();
    assert!(r.is_clean(), "{r:?}");
    assert_eq!(r.accepted.len(), 1);
    let a = &r.accepted[0];
    assert_eq!(
        (a.seq, a.findings, a.bundles, a.bundles_verified),
        (1, 5, 1, 1)
    );
    assert_eq!(a.batch_hash, pubd[0].batch_hash);

    let recs = read_lines(&a.output.join(RECORDS_FILE));
    assert_eq!(recs.len(), 5);
    for (rec, env) in recs.iter().zip(&fs_in) {
        let expected = robodr_ocsf::record(env, Some(12)).unwrap();
        assert_eq!(rec["topic"], robodr_ocsf::DEFAULT_TOPIC);
        assert_eq!(rec["key"], expected.key.as_str());
        assert_eq!(rec["value"], expected.value.as_str());
        assert_eq!(rec["partition"], expected.partition.unwrap());
        assert_eq!(
            rec["headers"].as_array().unwrap().len(),
            expected.headers.len()
        );
        assert_eq!(rec["headers"][6][1], env.ocsf.metadata.uid.as_str());
        assert_eq!(rec["diode"]["unit_id"], UNIT);
        robodr_ocsf::parse_and_validate(rec["value"].as_str().unwrap()).unwrap();
    }
    assert_eq!(fs::read(a.output.join("bundle-0001.rbbx")).unwrap(), bb);
    assert!(a.output.join(MANIFEST_FILE).exists());
    assert!(a.output.join(SIGNATURE_FILE).exists());
    assert!(site.inbox_entries().is_empty());
    assert!(site.high.join("processed").join(&a.name).is_dir());
    let st = &imp.state().units[UNIT];
    assert_eq!(
        (st.last_seq, st.last_hash.as_str()),
        (1, a.batch_hash.as_str())
    );

    // State survives a restart; a second run with an empty inbox is a no-op.
    // (One importer per state file: the first must be closed first.)
    let before = imp.state().clone();
    drop(imp);
    let mut again = site.importer();
    assert_eq!(again.state(), &before);
    let r2 = again.run(NOW).unwrap();
    assert!(r2.accepted.is_empty() && r2.is_clean());
}

#[test]
fn batches_are_split_chained_and_size_bounded() {
    let site = Site::new("split");
    let mut cfg = PackConfig::new(UNIT);
    cfg.max_findings_per_batch = 2;
    let mut p = site.packer_cfg(cfg);
    let pubd = p.pack(&findings(5), &[], NOW).unwrap();
    assert_eq!(
        pubd.iter().map(|b| b.finding_count).collect::<Vec<_>>(),
        vec![2, 2, 1]
    );
    assert_eq!(
        pubd.iter().map(|b| b.seq).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    // Next pack continues the chain.
    let more = p.pack(&findings(1), &[], NOW).unwrap();
    assert_eq!(more[0].seq, 4);
    let m: robodr_diode::Manifest =
        serde_json::from_slice(&fs::read(more[0].path.join(MANIFEST_FILE)).unwrap()).unwrap();
    assert_eq!(
        m.prev_batch_hash.as_deref(),
        Some(pubd[2].batch_hash.as_str())
    );

    // Byte bound: every batch's data stays under the limit.
    let site2 = Site::new("bytes");
    let mut cfg = PackConfig::new(UNIT);
    cfg.max_batch_bytes = MIN_BATCH_BYTES;
    let mut p2 = site2.packer_cfg(cfg);
    let many = findings(60);
    let pubd2 = p2.pack(&many, &[bundle(2)], NOW).unwrap();
    assert!(pubd2.len() > 1);
    assert!(pubd2.iter().all(|b| b.data_bytes <= MIN_BATCH_BYTES));
    assert_eq!(pubd2.iter().map(|b| b.finding_count).sum::<u64>(), 60);

    site.transfer_all();
    site2.transfer_all();
    let r = site.importer().run(NOW).unwrap();
    assert_eq!(r.accepted.len(), 4);
    assert!(r.is_clean());
    let r2 = site2.importer().run(NOW).unwrap();
    assert_eq!(r2.accepted.len(), pubd2.len());
    assert!(r2.is_clean());
}

#[test]
fn tampered_data_file_is_quarantined_and_intact_resend_accepted() {
    let site = Site::new("tamper-file");
    let name = one_batch(&site, 3);
    let f = site.inbox().join(&name).join(FINDINGS_FILE);
    let mut b = fs::read(&f).unwrap();
    let i = b.len() / 2;
    b[i] ^= 0x01;
    fs::write(&f, &b).unwrap();
    expect_quarantine(&site, "hash_mismatch");
    assert!(!site.high.join("out").join(&name).exists());

    // Forward-error recovery: the same batch re-sent intact is accepted.
    site.transfer(&name);
    let r = site.importer().run(NOW).unwrap();
    assert_eq!(r.accepted.len(), 1);
    assert!(r.is_clean());
}

#[test]
fn tampered_manifest_or_signature_is_rejected() {
    let site = Site::new("tamper-manifest");
    let name = one_batch(&site, 2);
    let m = site.inbox().join(&name).join(MANIFEST_FILE);
    let s = fs::read_to_string(&m).unwrap();
    fs::write(
        &m,
        s.replace("\"finding_count\": 2", "\"finding_count\": 1"),
    )
    .unwrap();
    expect_quarantine(&site, "bad_signature");

    site.transfer(&name);
    fs::write(site.inbox().join(&name).join(SIGNATURE_FILE), b"{not json").unwrap();
    let site_r = site.importer().run(NOW).unwrap();
    assert_eq!(codes(&site_r), vec!["signature_file_invalid"]);

    site.transfer(&name);
    fs::write(
        site.inbox().join(&name).join(SIGNATURE_FILE),
        vec![b' '; 5000],
    )
    .unwrap();
    assert_eq!(
        codes(&site.importer().run(NOW).unwrap()),
        vec!["signature_file_invalid"]
    );
}

#[test]
fn wrong_key_unknown_key_and_wrong_unit() {
    // Same key id, different secret.
    let site = Site::new("wrong-key");
    let mut p = Packer::open(
        &site.outbox,
        &site.pack_state,
        PackConfig::new(UNIT),
        Box::new(HmacSha256Key::new(KEY_ID, &[9; 32]).unwrap()),
    )
    .unwrap();
    p.pack(&findings(1), &[], NOW).unwrap();
    site.transfer_all();
    expect_quarantine(&site, "bad_signature");

    // Unknown key id.
    let site = Site::new("unknown-key");
    let mut p = Packer::open(
        &site.outbox,
        &site.pack_state,
        PackConfig::new(UNIT),
        Box::new(HmacSha256Key::new("other-key", &KEY).unwrap()),
    )
    .unwrap();
    p.pack(&findings(1), &[], NOW).unwrap();
    site.transfer_all();
    expect_quarantine(&site, "unknown_key");

    // Valid key, but it belongs to another unit.
    let site = Site::new("wrong-unit");
    one_batch(&site, 1);
    let mut ring = Keyring::new();
    ring.add("ugv-008", signer()).unwrap();
    let mut imp = Importer::open(site.import_cfg(), ring).unwrap();
    let r = imp.run(NOW).unwrap();
    assert_eq!(codes(&r), vec!["unit_key_mismatch"]);
}

#[test]
fn gap_is_held_then_filled_in_any_order() {
    let site = Site::new("gap");
    let mut cfg = PackConfig::new(UNIT);
    cfg.max_findings_per_batch = 1;
    let pubd = site.packer_cfg(cfg).pack(&findings(4), &[], NOW).unwrap();
    let n: Vec<String> = pubd.iter().map(|b| b.name.clone()).collect();

    // Batches 1 and 3 arrive: 1 accepted, 3 held (gap at 2).
    site.transfer(&n[0]);
    site.transfer(&n[2]);
    let r = site.importer().run(NOW).unwrap();
    assert_eq!(r.accepted.len(), 1);
    assert_eq!(r.held.len(), 1);
    assert_eq!((r.held[0].seq, r.held[0].expected_seq), (3, 2));
    assert!(!r.is_clean());
    assert_eq!(site.inbox_entries(), vec![n[2].clone()]);

    // Batch 4 arrives before 2 (reordering): still held.
    site.transfer(&n[3]);
    let r = site.importer().run(NOW).unwrap();
    assert!(r.accepted.is_empty());
    assert_eq!(r.held.len(), 2);

    // Batch 2 arrives: 2, 3, 4 accepted in sequence order in one run.
    site.transfer(&n[1]);
    let r = site.importer().run(NOW).unwrap();
    assert_eq!(
        r.accepted.iter().map(|a| a.seq).collect::<Vec<_>>(),
        vec![2, 3, 4]
    );
    assert!(r.is_clean());
}

#[test]
fn first_contact_must_start_at_one_unless_gap_accepted() {
    let site = Site::new("first");
    let mut cfg = PackConfig::new(UNIT);
    cfg.max_findings_per_batch = 1;
    let pubd = site.packer_cfg(cfg).pack(&findings(3), &[], NOW).unwrap();
    site.transfer(&pubd[2].name);
    let r = site.importer().run(NOW).unwrap();
    assert_eq!((r.held[0].seq, r.held[0].expected_seq), (3, 1));

    // Operator explicitly accepts the gap: recorded in the state.
    let mut cfg = site.import_cfg();
    cfg.accept_gaps.push((UNIT.into(), 3));
    let mut imp = Importer::open(cfg, keyring()).unwrap();
    let r = imp.run(NOW).unwrap();
    assert_eq!(r.accepted[0].gap_accepted, Some((1, 2)));
    assert_eq!(imp.state().units[UNIT].accepted_gaps, vec![(1, 2)]);
    drop(imp);

    // A skipped batch arriving later cannot be slotted in: replay.
    site.transfer(&pubd[1].name);
    let r = site.importer().run(NOW).unwrap();
    assert_eq!(codes(&r), vec!["replay"]);
}

#[test]
fn duplicate_resend_is_idempotent() {
    let site = Site::new("dup");
    let mut cfg = PackConfig::new(UNIT);
    cfg.max_findings_per_batch = 1;
    let pubd = site.packer_cfg(cfg).pack(&findings(2), &[], NOW).unwrap();
    site.transfer_all();
    let r = site.importer().run(NOW).unwrap();
    assert_eq!(r.accepted.len(), 2);
    let out = site.high.join("out").join(&pubd[0].name).join(RECORDS_FILE);
    let before = fs::read(&out).unwrap();

    // The whole outbox is replayed (e.g. the diode re-sends everything).
    site.transfer_all();
    let mut imp = site.importer();
    let st = imp.state().clone();
    let r = imp.run(NOW).unwrap();
    assert!(r.accepted.is_empty());
    assert_eq!(r.duplicates.len(), 2);
    assert!(r.is_clean());
    assert_eq!(imp.state(), &st);
    assert_eq!(fs::read(&out).unwrap(), before);
    assert!(site.inbox_entries().is_empty());
}

#[test]
fn conflicting_batch_for_used_seq_is_quarantined() {
    // The packer lost its state and restarts at seq 1 with other content.
    let site = Site::new("conflict");
    one_batch(&site, 1);
    assert_eq!(site.importer().run(NOW).unwrap().accepted.len(), 1);
    let name = batch_dir_name(UNIT, 1);
    fs::remove_dir_all(site.outbox.join(&name)).unwrap();
    fs::remove_file(&site.pack_state).unwrap();
    site.packer().pack(&[finding(99)], &[], NOW).unwrap();
    site.transfer(&name);
    let r = site.importer().run(NOW).unwrap();
    assert_eq!(codes(&r), vec!["conflict"]);
}

#[test]
fn chain_break_is_quarantined() {
    let site = Site::new("chain");
    one_batch(&site, 1);
    assert_eq!(site.importer().run(NOW).unwrap().accepted.len(), 1);
    // Forge a packer state whose chain head is not batch 1's hash.
    fs::write(
        &site.pack_state,
        serde_json::json!({
            "format": "robodr-diode-pack-state/1",
            "unit_id": UNIT,
            "next_seq": 2,
            "last_batch_hash": "ab".repeat(32),
        })
        .to_string(),
    )
    .unwrap();
    let b = site.packer().pack(&findings(1), &[], NOW).unwrap();
    site.transfer(&b[0].name);
    let r = site.importer().run(NOW).unwrap();
    assert_eq!(codes(&r), vec!["chain_break"]);
}

#[test]
fn truncated_or_incomplete_batches() {
    let site = Site::new("trunc");
    let name = one_batch(&site, 3);
    let f = site.inbox().join(&name).join(FINDINGS_FILE);
    let b = fs::read(&f).unwrap();
    fs::write(&f, &b[..b.len() - 100]).unwrap();
    expect_quarantine(&site, "size_mismatch");

    site.transfer(&name);
    fs::write(
        site.inbox().join(&name).join(FINDINGS_FILE),
        [&b[..], b"x"].concat(),
    )
    .unwrap();
    expect_quarantine(&site, "size_mismatch");

    site.transfer(&name);
    fs::remove_file(site.inbox().join(&name).join(FINDINGS_FILE)).unwrap();
    expect_quarantine(&site, "missing_file");

    site.transfer(&name);
    fs::remove_file(site.inbox().join(&name).join(MANIFEST_FILE)).unwrap();
    expect_quarantine(&site, "missing_manifest");

    site.transfer(&name);
    fs::remove_file(site.inbox().join(&name).join(SIGNATURE_FILE)).unwrap();
    expect_quarantine(&site, "missing_signature");

    // The intact batch still goes through afterwards.
    site.transfer(&name);
    assert_eq!(site.importer().run(NOW).unwrap().accepted.len(), 1);
}

#[test]
fn huge_manifest_is_rejected_before_reading() {
    let site = Site::new("huge");
    let name = one_batch(&site, 1);
    fs::write(
        site.inbox().join(&name).join(MANIFEST_FILE),
        vec![b' '; MAX_MANIFEST_BYTES + 1],
    )
    .unwrap();
    let r = expect_quarantine(&site, "manifest_too_large");
    assert!(r.quarantined[0].reason.to_string().contains("131073"));

    // A validly signed manifest with an absurd declared size is refused too.
    site.transfer(&name);
    resign(&site.inbox().join(&name), |m| {
        m["files"][0]["size"] = (u64::MAX / 2).into()
    });
    expect_quarantine(&site, "batch_too_large");
}

#[test]
fn path_traversal_in_manifest_names_is_rejected() {
    for evil in [
        "../evil.jsonl",
        "../../etc/passwd",
        "/etc/passwd",
        "sub/findings.jsonl",
        "findings.jsonl/..",
        "..",
        ".hidden",
        "findings.jsonl\u{0}",
        "Findings.jsonl",
    ] {
        let site = Site::new("traversal");
        let name = one_batch(&site, 1);
        // Plant the target the traversal would reach, to prove it is not read.
        fs::write(site.inbox().join("evil.jsonl"), b"x").unwrap();
        let dir = site.inbox().join(&name);
        resign(&dir, |m| m["files"][0]["name"] = evil.into());
        let mut imp = site.importer();
        let r = imp.run(NOW).unwrap();
        assert!(r.accepted.is_empty(), "{evil:?}: {r:?}");
        // The stray file is quarantined as not-a-directory; the batch for
        // its unsafe name.
        let q = r
            .quarantined
            .iter()
            .find(|q| q.name == name)
            .unwrap_or_else(|| panic!("{evil:?}: {r:?}"));
        assert_eq!(reason_code(&q.reason), "manifest_invalid", "{evil:?}");
        assert!(imp.state().units.is_empty());
        assert!(fs::read_dir(site.high.join("out"))
            .unwrap()
            .next()
            .is_none());
    }
}

#[test]
fn symlinks_in_inbox_are_refused() {
    // A symlinked batch directory.
    let site = Site::new("sym-dir");
    let name = one_batch(&site, 1);
    let real = site.tmp.path().join("elsewhere");
    fs::rename(site.inbox().join(&name), &real).unwrap();
    symlink(&real, site.inbox().join(&name)).unwrap();
    expect_quarantine(&site, "symlink");
    assert!(real.join(MANIFEST_FILE).exists(), "target untouched");

    // A data file that is a symlink (to an identical copy).
    let site = Site::new("sym-file");
    let name = one_batch(&site, 1);
    let dir = site.inbox().join(&name);
    let copy = site.tmp.path().join("copy.jsonl");
    fs::rename(dir.join(FINDINGS_FILE), &copy).unwrap();
    symlink(&copy, dir.join(FINDINGS_FILE)).unwrap();
    expect_quarantine(&site, "not_regular_file");

    // Symlinked manifest.
    let site = Site::new("sym-manifest");
    let name = one_batch(&site, 1);
    let dir = site.inbox().join(&name);
    let copy = site.tmp.path().join("m.json");
    fs::rename(dir.join(MANIFEST_FILE), &copy).unwrap();
    symlink(&copy, dir.join(MANIFEST_FILE)).unwrap();
    expect_quarantine(&site, "not_regular_file");

    // The inbox itself must not be a symlink.
    let site = Site::new("sym-inbox");
    let real = site.tmp.path().join("real-inbox");
    fs::rename(site.inbox(), &real).unwrap();
    symlink(&real, site.inbox()).unwrap();
    assert!(Importer::open(site.import_cfg(), keyring()).is_err());
}

#[test]
fn symlinks_in_outbox_are_refused() {
    let site = Site::new("sym-outbox");
    let real = site.tmp.path().join("real-outbox");
    fs::rename(&site.outbox, &real).unwrap();
    symlink(&real, &site.outbox).unwrap();
    assert!(Packer::open(
        &site.outbox,
        &site.pack_state,
        PackConfig::new(UNIT),
        signer()
    )
    .is_err());

    // A planted temp-dir symlink is never written through.
    let site = Site::new("sym-tmp");
    let target = site.tmp.path().join("target");
    fs::create_dir(&target).unwrap();
    symlink(
        &target,
        site.outbox
            .join(format!(".tmp-{}", batch_dir_name(UNIT, 1))),
    )
    .unwrap();
    assert!(Packer::open(
        &site.outbox,
        &site.pack_state,
        PackConfig::new(UNIT),
        signer()
    )
    .is_err());
    assert!(fs::read_dir(&target).unwrap().next().is_none());

    // A planted symlink at the final batch name: packing fails, nothing written.
    let site = Site::new("sym-final");
    let target = site.tmp.path().join("target");
    fs::create_dir(&target).unwrap();
    symlink(&target, site.outbox.join(batch_dir_name(UNIT, 1))).unwrap();
    let mut p = site.packer();
    assert!(p.pack(&findings(1), &[], NOW).is_err());
    assert!(fs::read_dir(&target).unwrap().next().is_none());
    assert_eq!(p.state().next_seq, 1);
}

#[test]
fn unexpected_entries_and_names() {
    // Extra file in a batch.
    let site = Site::new("extra");
    let name = one_batch(&site, 1);
    fs::write(site.inbox().join(&name).join("payload.sh"), b"#!/bin/sh").unwrap();
    expect_quarantine(&site, "unexpected_file");

    // Renamed batch directory.
    let site = Site::new("rename");
    let name = one_batch(&site, 1);
    fs::rename(
        site.inbox().join(&name),
        site.inbox().join(batch_dir_name(UNIT, 9)),
    )
    .unwrap();
    expect_quarantine(&site, "name_mismatch");

    // Stray file; dot-entries are left alone as in transit.
    let site = Site::new("stray");
    fs::write(site.inbox().join("notes.txt"), b"x").unwrap();
    fs::create_dir(site.inbox().join(".partial")).unwrap();
    let r = site.importer().run(NOW).unwrap();
    assert_eq!(codes(&r), vec!["not_a_directory"]);
    assert_eq!(r.in_transit, vec![".partial".to_string()]);
    assert_eq!(site.inbox_entries(), vec![".partial".to_string()]);
}

#[test]
fn invalid_finding_in_signed_batch_is_quarantined() {
    let site = Site::new("invalid");
    let name = one_batch(&site, 2);
    let dir = site.inbox().join(&name);
    let text = fs::read_to_string(dir.join(FINDINGS_FILE)).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    // A hostile bidi override in a trusted field: rejected by the validator.
    lines[1] = lines[1].replacen("\"title\":\"", "\"title\":\"\u{202e}", 1);
    let content = format!("{}\n", lines.join("\n"));
    replace_file_resigned(&dir, FINDINGS_FILE, content.as_bytes());
    let r = expect_quarantine(&site, "invalid_finding");
    match &r.quarantined[0].reason {
        robodr_diode::QuarantineReason::InvalidFinding { line, errors } => {
            assert_eq!(*line, 2);
            assert!(!errors.is_empty());
        }
        other => panic!("{other:?}"),
    }

    // Count, framing and time range must match the signed manifest.
    let site = Site::new("count");
    let name = one_batch(&site, 2);
    let dir = site.inbox().join(&name);
    resign(&dir, |m| m["finding_count"] = 3.into());
    expect_quarantine(&site, "count_mismatch");

    let site = Site::new("framing");
    let name = one_batch(&site, 2);
    let dir = site.inbox().join(&name);
    let text = fs::read_to_string(dir.join(FINDINGS_FILE)).unwrap();
    replace_file_resigned(&dir, FINDINGS_FILE, text.trim_end().as_bytes());
    expect_quarantine(&site, "findings_format");

    let site = Site::new("times");
    let name = one_batch(&site, 2);
    resign(&site.inbox().join(&name), |m| {
        m["last_time"] = (T0 + 50).into()
    });
    expect_quarantine(&site, "time_range_mismatch");

    let site = Site::new("unknown-field");
    let name = one_batch(&site, 1);
    resign(&site.inbox().join(&name), |m| m["extra"] = 1.into());
    expect_quarantine(&site, "manifest_invalid");
}

#[test]
fn bundles_are_parsed_and_optionally_verified() {
    let site = Site::new("bundle-bad");
    site.packer().pack(&[], &[bundle(2)], NOW).unwrap();
    site.transfer_all();
    let name = batch_dir_name(UNIT, 1);
    replace_file_resigned(
        &site.inbox().join(&name),
        "bundle-0001.rbbx",
        b"RBBXBND1junk",
    );
    expect_quarantine(&site, "bad_bundle");

    // A bundle verifier with the wrong secret flags tampering.
    let site = Site::new("bundle-verify");
    site.packer().pack(&[], &[bundle(2)], NOW).unwrap();
    site.transfer_all();
    let mut imp = site.importer();
    imp.add_bundle_verifier(
        UNIT,
        Box::new(HmacSha256Key::new(BB_KEY_ID, &[1; 32]).unwrap()),
    )
    .unwrap();
    let r = imp.run(NOW).unwrap();
    assert_eq!(codes(&r), vec!["bundle_verify_failed"]);

    // Without a matching verifier, bundles are only parsed (and reported so).
    let site = Site::new("bundle-unverified");
    site.packer()
        .pack(&[], &[bundle(2), bundle(3)], NOW)
        .unwrap();
    site.transfer_all();
    let r = site.importer().run(NOW).unwrap();
    assert_eq!(
        (r.accepted[0].bundles, r.accepted[0].bundles_verified),
        (2, 0)
    );
    assert_eq!(r.accepted[0].findings, 0);
}

#[test]
fn packer_rejects_bad_input_before_writing() {
    let site = Site::new("bad-input");
    let mut p = site.packer();
    let good = robodr_ocsf::to_json(&finding(1)).unwrap();
    let err = p.pack_lines(&[&good, "{\"x\":1}"], &[], NOW).unwrap_err();
    assert!(
        matches!(err, PackError::InvalidFinding { index: 1, .. }),
        "{err}"
    );
    let err = p.pack(&findings(1), &[b"nope".to_vec()], NOW).unwrap_err();
    assert!(
        matches!(err, PackError::BadBundle { index: 0, .. }),
        "{err}"
    );
    assert!(p.pack(&findings(1), &[], 0).is_err(), "unset clock");
    let mut bad = finding(1);
    bad.title = "\u{202e}x".into();
    assert!(matches!(
        p.pack(&[bad], &[], NOW),
        Err(PackError::InvalidFinding { index: 0, .. })
    ));
    assert!(p.pack(&[], &[], NOW).unwrap().is_empty());
    assert!(site.outbox_batches().is_empty());
    assert_eq!(p.state().next_seq, 1);
    assert!(!site.pack_state.exists());
    drop(p);

    // Oversized bundle.
    let mut cfg = PackConfig::new(UNIT);
    cfg.max_batch_bytes = MIN_BATCH_BYTES;
    let mut p = site.packer_cfg(cfg);
    let huge = bundle(2000);
    assert!(huge.len() as u64 > MIN_BATCH_BYTES);
    assert!(matches!(
        p.pack(&[], &[huge], NOW),
        Err(PackError::BundleTooLarge { .. })
    ));
    drop(p);

    // Bad configs (refused as configuration errors, not by the lock).
    for (unit, bytes, n) in [
        ("a/b", MIN_BATCH_BYTES, 1),
        (UNIT, 10, 1),
        (UNIT, MIN_BATCH_BYTES, 0),
    ] {
        let mut cfg = PackConfig::new(unit);
        cfg.max_batch_bytes = bytes;
        cfg.max_findings_per_batch = n;
        assert!(matches!(
            Packer::open(&site.outbox, &site.pack_state, cfg, signer()),
            Err(PackError::Config(_))
        ));
    }
}

#[test]
fn packer_state_is_bound_to_unit_and_validated() {
    let site = Site::new("state");
    one_batch(&site, 1);
    assert!(Packer::open(
        &site.outbox,
        &site.pack_state,
        PackConfig::new("ugv-008"),
        signer()
    )
    .is_err());
    fs::write(&site.pack_state, b"{garbage").unwrap();
    assert!(Packer::open(
        &site.outbox,
        &site.pack_state,
        PackConfig::new(UNIT),
        signer()
    )
    .is_err());
}

#[test]
fn packer_recovers_after_crash_between_commit_and_rename() {
    let site = Site::new("crash");
    let b = site.packer().pack(&findings(2), &[], NOW).unwrap();
    let name = &b[0].name;
    // Simulate: state committed, rename not done.
    fs::rename(
        site.outbox.join(name),
        site.outbox.join(format!(".tmp-{name}")),
    )
    .unwrap();
    // And an uncommitted staging dir for the next seq.
    let stale = site
        .outbox
        .join(format!(".tmp-{}", batch_dir_name(UNIT, 2)));
    fs::create_dir(&stale).unwrap();
    fs::write(stale.join(FINDINGS_FILE), b"partial").unwrap();

    let mut p = site.packer();
    assert_eq!(site.outbox_batches(), vec![name.clone()]);
    assert!(!stale.exists());
    let b2 = p.pack(&findings(1), &[], NOW).unwrap();
    assert_eq!(b2[0].seq, 2);
    site.transfer_all();
    let r = site.importer().run(NOW).unwrap();
    assert_eq!(r.accepted.len(), 2);
    assert!(r.is_clean());
}

#[test]
fn importer_rejects_bad_layouts() {
    let site = Site::new("layout");
    let mut cfg = site.import_cfg();
    cfg.quarantine_dir = site.inbox().join("q");
    assert!(Importer::open(cfg, keyring()).is_err());
    let mut cfg = site.import_cfg();
    cfg.out_dir = site.inbox();
    assert!(Importer::open(cfg, keyring()).is_err());
    let mut cfg = site.import_cfg();
    cfg.state_path = site.inbox().join("state.json");
    assert!(Importer::open(cfg, keyring()).is_err());
    assert!(Importer::open(site.import_cfg(), Keyring::new()).is_err());
    fs::write(site.high.join("state.json"), b"[]").unwrap();
    assert!(Importer::open(site.import_cfg(), keyring()).is_err());
}

#[test]
fn hostile_inbox_never_panics() {
    // Assorted junk: deep dirs, binary manifests, empty files, many entries.
    let site = Site::new("junk");
    let inbox = site.inbox();
    for i in 0..20u8 {
        let d = inbox.join(format!("rdd_x_{i:016}"));
        fs::create_dir(&d).unwrap();
        fs::write(d.join(SIGNATURE_FILE), [i; 64]).unwrap();
        fs::write(d.join(MANIFEST_FILE), vec![i; i as usize * 13]).unwrap();
    }
    fs::create_dir_all(inbox.join("deep/a/b/c")).unwrap();
    fs::create_dir(inbox.join("empty")).unwrap();
    let r = site.importer().run(NOW).unwrap();
    assert!(r.accepted.is_empty());
    assert_eq!(r.quarantined.len(), 22);
    assert!(site.inbox_entries().is_empty());
}

#[test]
fn packer_exposes_its_configuration_read_only() {
    let site = Site::new("config-accessor");
    let mut cfg = PackConfig::new(UNIT);
    cfg.max_findings_per_batch = 7;
    let p = Packer::open(
        &site.outbox,
        &site.pack_state,
        cfg.clone(),
        Box::new(HmacSha256Key::new(KEY_ID, &KEY).unwrap()),
    )
    .unwrap();
    let got = p.config();
    assert_eq!(got.unit_id, UNIT);
    assert_eq!(got.max_findings_per_batch, 7);
    assert_eq!(got.max_batch_bytes, cfg.max_batch_bytes);
    assert_eq!(got.parity_shards, cfg.parity_shards);
    assert_eq!(got.shard_size, cfg.shard_size);
}
