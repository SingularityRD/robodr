//! Upgrade path (review finding M5): contract 1.x records still in an
//! agentd spool when the exporter / publisher are upgraded.
//!
//! * Unsigned 1.3 records are upgraded to contract 2.0 (same identity) and
//!   exported / published.
//! * Signed 1.x records cannot be upgraded (the signature covers the exact
//!   value bytes): they are kept — moved to `rejected/` by the spool
//!   exporter, written to the dead-letter file by the publisher — with the
//!   explicit reason "legacy 1.x signed record: re-sign required".

mod common;

use common::*;
use robodr_agent::FindingOutput;
use robodr_agentd::spool::Spool;
use robodr_blackbox::Ed25519SigningKey;
use robodr_diode::{ImportConfig, Importer, Keyring, PackConfig, Packer};
use robodr_export::kafka::{Producer, ProducerConfig};
use robodr_export::{ExportConfig, Exporter, PublishConfig, Publisher, Source};
use robodr_ocsf::{legacy_v1, FindingEnvelope, CONTRACT_VERSION, DEFAULT_DATA_SOURCE};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

const SEED: [u8; 32] = [0x21; 32];
const KEY_ID: &str = "diode-ugv-007";
const SIGNED_REASON: &str = "legacy 1.x signed record: re-sign required";

fn finding_signer() -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed("finding-ugv-007", &[0x33; 32]).unwrap()
}

/// A spool record (as `FindingOutput`) for finding `i`, relabelled as
/// contract 1.3 the way a 1.3 agentd wrote it; `signed` adds a detached
/// finding signature header (1.2+).
fn legacy_output(i: u64, signed: bool) -> FindingOutput {
    let env = finding(i);
    let mut rec = robodr_ocsf::record(&env, Some(12)).unwrap();
    rec.value = rec
        .value
        .replacen(
            &format!("\"contract_version\":\"{CONTRACT_VERSION}\""),
            "\"contract_version\":\"1.3.0\"",
            1,
        )
        .replacen(
            &format!("\"data_source\":\"{DEFAULT_DATA_SOURCE}\""),
            &format!("\"data_source\":\"{}\"", legacy_v1::DATA_SOURCE),
            1,
        )
        .replacen(
            &format!("\"log_name\":\"{TOPIC}\""),
            &format!("\"log_name\":\"{}\"", legacy_v1::TOPIC),
            1,
        );
    let legacy = robodr_ocsf::parse_and_validate(&rec.value).expect("valid 1.3 finding");
    assert_eq!(legacy.contract_version, "1.3.0");
    if signed {
        robodr_ocsf::sign_record(&mut rec, &finding_signer()).unwrap();
    }
    let sig = rec
        .headers
        .iter()
        .find(|(k, _)| *k == robodr_ocsf::SIG_HEADER)
        .cloned();
    let mut headers: Vec<(String, String)> = robodr_ocsf::headers(&legacy)
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    if let Some((k, v)) = sig {
        headers.push((k.to_string(), v));
    }
    FindingOutput {
        topic: legacy_v1::TOPIC.into(),
        key: rec.key,
        partition: rec.partition,
        value: rec.value,
        headers,
    }
}

fn current_output(i: u64) -> FindingOutput {
    let rec = robodr_ocsf::record(&finding(i), Some(12)).unwrap();
    FindingOutput {
        topic: rec.topic,
        key: rec.key,
        partition: rec.partition,
        value: rec.value,
        headers: rec
            .headers
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    }
}

struct Site {
    _tmp: TempDir,
    spool: PathBuf,
    outbox: PathBuf,
    root: PathBuf,
}

impl Site {
    fn new(tag: &str, outputs: &[FindingOutput]) -> Self {
        let tmp = TempDir::new(tag);
        let root = tmp.path().to_path_buf();
        let s = Self {
            spool: root.join("spool"),
            outbox: root.join("outbox"),
            root,
            _tmp: tmp,
        };
        fs::create_dir_all(&s.outbox).unwrap();
        let mut sp = Spool::open(&s.spool, 1 << 30, 1_000_000).unwrap();
        for o in outputs {
            sp.write(o, false).unwrap();
        }
        s
    }

    fn exporter(&self) -> Exporter {
        let packer = Packer::open(
            &self.outbox,
            self.root.join("pack-state.json"),
            PackConfig::new(UNIT),
            Box::new(Ed25519SigningKey::from_seed(KEY_ID, &SEED).unwrap()),
        )
        .unwrap();
        Exporter::open(
            ExportConfig::new(&self.spool, self.root.join("export-state.json")),
            packer,
        )
        .unwrap()
    }

    fn import(&self) -> Vec<serde_json::Value> {
        let high = self.root.join("high");
        fs::create_dir_all(high.join("inbox")).unwrap();
        for b in names(&self.outbox) {
            let to = high.join("inbox").join(&b);
            fs::create_dir_all(&to).unwrap();
            for f in fs::read_dir(self.outbox.join(&b)).unwrap() {
                let f = f.unwrap();
                fs::copy(f.path(), to.join(f.file_name())).unwrap();
            }
        }
        let mut k = Keyring::new();
        let pk = robodr_blackbox::KeyFile::ed25519_from_seed(&SEED, Some(KEY_ID))
            .unwrap()
            .to_public()
            .unwrap()
            .ed25519_verifying_key()
            .unwrap();
        k.add(UNIT, Box::new(pk)).unwrap();
        let rep = Importer::open(ImportConfig::under(&high), k)
            .unwrap()
            .run(NOW)
            .unwrap();
        assert!(rep.is_clean(), "{rep:?}");
        let mut out = Vec::new();
        for b in names(&high.join("out")) {
            let t = fs::read_to_string(high.join("out").join(&b).join("records.jsonl")).unwrap();
            out.extend(t.lines().map(|l| serde_json::from_str(l).unwrap()));
        }
        out
    }
}

fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .map(|rd| {
            rd.map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

fn value(rec: &serde_json::Value) -> FindingEnvelope {
    serde_json::from_str(rec["value"].as_str().unwrap()).unwrap()
}

#[test]
fn spool_exporter_upgrades_unsigned_legacy_records() {
    let site = Site::new(
        "x-legacy",
        &[
            legacy_output(0, false),
            legacy_output(1, false),
            current_output(2),
        ],
    );
    let rep = site.exporter().run_once(NOW).unwrap();
    assert!(rep.rejected.is_empty(), "{:?}", rep.rejected);
    assert_eq!(rep.exported, 3);
    let recs = site.import();
    assert_eq!(recs.len(), 3);
    for (i, r) in recs.iter().enumerate() {
        let v = value(r);
        assert_eq!(v.finding_id, finding(i as u64).finding_id, "identity kept");
        assert_eq!(v.data_source, DEFAULT_DATA_SOURCE);
        assert_eq!(v.ocsf.metadata.log_name, TOPIC);
        let want = if i < 2 { "2.0.0" } else { CONTRACT_VERSION };
        assert_eq!(v.contract_version, want);
    }
}

#[test]
fn spool_exporter_keeps_signed_legacy_records_with_a_clear_reason() {
    let site = Site::new("x-signed", &[legacy_output(0, true), current_output(1)]);
    let rep = site.exporter().run_once(NOW).unwrap();
    assert_eq!(rep.exported, 1);
    assert_eq!(rep.rejected.len(), 1, "{:?}", rep.rejected);
    assert!(
        rep.rejected[0].reason.contains(SIGNED_REASON),
        "{}",
        rep.rejected[0].reason
    );
    // Kept, with the reason beside it.
    let rej = names(&site.spool.join("rejected"));
    assert_eq!(rej.len(), 2, "{rej:?}");
    let why = fs::read_to_string(site.spool.join("rejected").join(&rej[1])).unwrap();
    assert!(why.contains(SIGNED_REASON), "{why}");
}

fn producer(c: &Cluster) -> Producer {
    let mut p = ProducerConfig::new(c.bootstrap());
    p.retry_backoff = Duration::from_millis(5);
    Producer::new(p).unwrap()
}

#[test]
fn publisher_upgrades_unsigned_legacy_records_and_keeps_signed_ones() {
    let site = Site::new(
        "p-legacy",
        &[
            legacy_output(0, false),
            legacy_output(1, true),
            current_output(2),
        ],
    );
    let c = Cluster::start(1, 2);
    let mut cfg = PublishConfig::new(Source::Spool(site.spool.clone()), site.root.join("soc"));
    cfg.upgrade_data_source = "site-a.robodr".into();
    let mut p = Publisher::open(cfg, producer(&c)).unwrap();
    let rep = p.run_once().unwrap();
    assert_eq!(rep.published, 2, "{rep:?}");
    assert_eq!(rep.legacy_upgraded, 1);
    assert_eq!(rep.dead_lettered, 1);
    let dl = fs::read_to_string(site.root.join("soc/dead-letter.jsonl")).unwrap();
    assert!(dl.contains(SIGNED_REASON), "{dl}");
    // The upgraded record went out as contract 2.0 with its own headers.
    let recs = c.all_records();
    let up = recs
        .iter()
        .map(|(_, r)| String::from_utf8(r.value.clone().unwrap()).unwrap())
        .map(|v| robodr_ocsf::parse_and_validate(&v).unwrap())
        .find(|v| v.finding_id == finding(0).finding_id)
        .expect("upgraded legacy record published");
    assert_eq!(up.contract_version, "2.0.0");
    assert_eq!(up.data_source, "site-a.robodr");
    assert_eq!(up.ocsf.metadata.log_name, TOPIC);
    let rec = recs
        .iter()
        .find(|(_, r)| r.key.as_deref() == Some(finding(0).finding_id.as_bytes()))
        .unwrap();
    assert_eq!(
        header(&rec.1, "robodr-contract-version").as_deref(),
        Some("2.0.0")
    );
    assert_eq!(
        header(&rec.1, "data-source").as_deref(),
        Some("site-a.robodr")
    );
}
