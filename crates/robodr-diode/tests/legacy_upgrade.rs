//! Upgrade path (review finding M5): contract 1.x diode batches still in
//! flight when the SOC side is upgraded to contract 2.x must not stall the
//! unit's batch chain.
//!
//! * A 1.x batch whose findings are valid 1.3 findings is accepted: each
//!   finding is upgraded to contract 2.0 (batch-signed, not per-finding
//!   signed, so nothing signed changes), and the chain moves on.
//! * A 1.x batch that is authentic, chain-linked and intact but whose
//!   findings cannot be upgraded is quarantined (`legacy_not_convertible`)
//!   *and the chain advances over it*: re-sending it cannot help, and
//!   batch N+1 must not be held as a gap.
//! * A damaged 1.x batch is quarantined without advancing (a re-send can
//!   repair it), like any other damaged batch.

mod common;

use common::*;
use robodr_diode::manifest::{batch_hash, FileKind, Manifest, MANIFEST_FILE};
use robodr_diode::PackConfig;
use robodr_events::{Deviation, Severity};
use robodr_ocsf::*;
use std::fs;
use std::path::Path;

/// Relabel a 2.x finding line as contract `version` (1.x constants).
fn to_v1(line: &str, version: &str) -> String {
    line.replacen(
        &format!("\"contract_version\":\"{CONTRACT_VERSION}\""),
        &format!("\"contract_version\":\"{version}\""),
        1,
    )
    .replacen(
        &format!("\"data_source\":\"{DEFAULT_DATA_SOURCE}\""),
        &format!("\"data_source\":\"{}\"", legacy_v1::DATA_SOURCE),
        1,
    )
    .replacen(
        &format!("\"log_name\":\"{DEFAULT_TOPIC}\""),
        &format!("\"log_name\":\"{}\"", legacy_v1::TOPIC),
        1,
    )
}

fn manifest(dir: &Path) -> Manifest {
    serde_json::from_slice(&fs::read(dir.join(MANIFEST_FILE)).unwrap()).unwrap()
}

/// Turn a published (2.x) batch into what a 1.x producer published: every
/// findings line rewritten by `f`, manifest `contract_version` set and
/// re-signed with the unit's key; `prev` overrides `prev_batch_hash`.
fn make_legacy(dir: &Path, version: &str, prev: Option<String>, f: impl Fn(&str) -> String) {
    let m = manifest(dir);
    for file in m.files.iter().filter(|x| x.kind == FileKind::Findings) {
        let text = fs::read_to_string(dir.join(&file.name)).unwrap();
        let out: String = text.lines().map(|l| format!("{}\n", f(l))).collect();
        replace_file_resigned(dir, &file.name, out.as_bytes());
    }
    let version = version.to_string();
    resign(dir, move |v| {
        v["contract_version"] = version.into();
        if let Some(p) = prev {
            v["prev_batch_hash"] = p.into();
        }
    });
}

/// Re-link batch `dir` to the (rewritten) batch `prev_dir`.
fn relink(dir: &Path, prev_dir: &Path) {
    let h = batch_hash(&fs::read(prev_dir.join(MANIFEST_FILE)).unwrap());
    resign(dir, move |v| v["prev_batch_hash"] = h.into());
}

fn no_parity() -> PackConfig {
    let mut c = PackConfig::new(UNIT);
    c.parity_shards = 0;
    c
}

/// Two batches: 1 (to be made legacy) and 2 (2.x), chained.
fn two_batches(site: &Site, first: Vec<FindingEnvelope>) -> (String, String) {
    let mut p = site.packer_cfg(no_parity());
    let b1 = p.pack(&first, &[], NOW).unwrap().remove(0).name;
    let b2 = p.pack(&findings(2), &[], NOW).unwrap().remove(0).name;
    (b1, b2)
}

#[test]
fn legacy_1_3_batch_is_upgraded_and_the_chain_continues() {
    let site = Site::new("legacy-ok");
    let (b1, b2) = two_batches(&site, findings(3));
    let originals: Vec<String> = fs::read_to_string(
        site.outbox
            .join(&b1)
            .join(&manifest(&site.outbox.join(&b1)).files[0].name),
    )
    .unwrap()
    .lines()
    .map(str::to_string)
    .collect();
    make_legacy(&site.outbox.join(&b1), "1.3.0", None, |l| to_v1(l, "1.3.0"));
    relink(&site.outbox.join(&b2), &site.outbox.join(&b1));
    site.transfer_all();
    let r = site.importer().run(NOW).unwrap();
    assert!(r.quarantined.is_empty(), "{:?}", r.quarantined);
    assert!(r.held.is_empty(), "{:?}", r.held);
    assert_eq!(r.accepted.len(), 2);
    let recs = read_lines(&r.accepted[0].output.join("records.jsonl"));
    assert_eq!(recs.len(), 3);
    for (rec, orig) in recs.iter().zip(&originals) {
        let v: FindingEnvelope = serde_json::from_str(rec["value"].as_str().unwrap()).unwrap();
        let o: FindingEnvelope = serde_json::from_str(orig).unwrap();
        // Upgraded to 2.0 (the 1.3 catalog is the 2.0 catalog) with the
        // default labels; identity unchanged.
        assert_eq!(v.contract_version, "2.0.0");
        assert_eq!(v.data_source, DEFAULT_DATA_SOURCE);
        assert_eq!(v.ocsf.metadata.log_name, DEFAULT_TOPIC);
        assert_eq!(v.finding_id, o.finding_id);
        assert_eq!(v.ocsf.metadata.uid, o.ocsf.metadata.uid);
        assert_eq!(rec["topic"], DEFAULT_TOPIC);
        assert!(rec["headers"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!(["robodr-contract-version", "2.0.0"])));
    }
}

/// A valid contract 1.2 finding that is not a valid 2.0 finding: a rule
/// that only gained a catalog entry in 1.3, carrying the generic entry.
fn v1_2_line(line: &str) -> String {
    let rule = "robot.safety_state.unmapped_value";
    let new = rule_info(rule);
    let old = rule_info_for_contract(rule, "1.2.0");
    to_v1(line, "1.2.0")
        .replace(new.title, old.title)
        .replace(new.desc, old.desc)
        .replace(
            &format!("\"{}\"", new.data_source),
            &format!("\"{}\"", old.data_source),
        )
}

fn unmapped_findings() -> Vec<FindingEnvelope> {
    let dev = Deviation::new("robot.safety_state.unmapped_value", Severity::Medium, "x");
    vec![FindingBuilder::from_deviation(&dev, &ctx())
        .seen(T0, T0)
        .build()
        .unwrap()]
}

#[test]
fn unconvertible_legacy_batch_is_quarantined_and_the_chain_advances() {
    let site = Site::new("legacy-skip");
    let (b1, b2) = two_batches(&site, unmapped_findings());
    make_legacy(&site.outbox.join(&b1), "1.2.0", None, v1_2_line);
    // The 1.2 line is a valid 1.x finding.
    let m = manifest(&site.outbox.join(&b1));
    let line = fs::read_to_string(site.outbox.join(&b1).join(&m.files[0].name)).unwrap();
    let env = parse_and_validate(line.trim_end()).expect("valid 1.2 finding");
    assert_eq!(env.contract_version, "1.2.0");
    relink(&site.outbox.join(&b2), &site.outbox.join(&b1));
    site.transfer_all();
    let r = site.importer().run(NOW).unwrap();
    assert_eq!(r.quarantined.len(), 1, "{:?}", r.quarantined);
    assert_eq!(r.quarantined[0].name, b1);
    assert_eq!(
        reason_code(&r.quarantined[0].reason),
        "legacy_not_convertible"
    );
    // Batch 2 is not held behind it.
    assert!(r.held.is_empty(), "{:?}", r.held);
    assert_eq!(r.accepted.len(), 1);
    assert_eq!(r.accepted[0].name, b2);
    // A replay of batch 1 is a duplicate of the skipped batch (its hash is
    // in the chain), not a fresh batch.
    site.transfer(&b1);
    let r = site.importer().run(NOW).unwrap();
    assert!(r.accepted.is_empty() && r.quarantined.is_empty(), "{r:?}");
}

#[test]
fn damaged_legacy_batch_does_not_advance_the_chain() {
    let site = Site::new("legacy-damaged");
    let (b1, b2) = two_batches(&site, unmapped_findings());
    make_legacy(&site.outbox.join(&b1), "1.2.0", None, v1_2_line);
    relink(&site.outbox.join(&b2), &site.outbox.join(&b1));
    site.transfer_all();
    // Damage batch 1 in transit (after signing).
    let m = manifest(&site.inbox().join(&b1));
    let p = site.inbox().join(&b1).join(&m.files[0].name);
    let mut bytes = fs::read(&p).unwrap();
    bytes[10] ^= 1;
    fs::write(&p, bytes).unwrap();
    let r = site.importer().run(NOW).unwrap();
    assert_eq!(r.quarantined.len(), 1);
    assert_ne!(
        reason_code(&r.quarantined[0].reason),
        "legacy_not_convertible"
    );
    // Batch 2 waits for a good copy of batch 1.
    assert_eq!(r.held.len(), 1, "{r:?}");
    assert!(r.accepted.is_empty());
}

#[test]
fn legacy_batch_out_of_order_or_unlinked_is_judged_like_any_batch() {
    let site = Site::new("legacy-chain");
    let (b1, b2) = two_batches(&site, unmapped_findings());
    // Batch 1 legacy but linked to a wrong predecessor... it is batch 1, so
    // it must have none; give it one: invalid manifest, no advance.
    make_legacy(
        &site.outbox.join(&b1),
        "1.2.0",
        Some("ab".repeat(32)),
        v1_2_line,
    );
    relink(&site.outbox.join(&b2), &site.outbox.join(&b1));
    site.transfer_all();
    let r = site.importer().run(NOW).unwrap();
    assert_eq!(r.quarantined.len(), 1);
    assert_ne!(
        reason_code(&r.quarantined[0].reason),
        "legacy_not_convertible"
    );
    assert_eq!(r.held.len(), 1, "batch 2 still waits: {r:?}");
}
