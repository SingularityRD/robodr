//! End to end: agentd spool -> robodr-spool-export -> diode packer ->
//! (transfer) -> diode importer -> robodr-kafka-publish -> fake Kafka.
//! Plus the crash-recovery cases of both exporters.

mod common;

use common::*;
use robodr_agent::FindingOutput;
use robodr_agentd::spool::Spool;
use robodr_blackbox::Ed25519SigningKey;
use robodr_diode::{ImportConfig, Importer, Keyring, PackConfig, Packer};
use robodr_export::kafka::{Producer, ProducerConfig};
use robodr_export::spool_export::FailPoint;
use robodr_export::{ExportConfig, ExportError, Exporter, PublishConfig, Publisher, Source};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

const SEED: [u8; 32] = [0x21; 32];
const KEY_ID: &str = "diode-ugv-007";
const PARTITIONS: usize = 4;

fn signer() -> Box<Ed25519SigningKey> {
    Box::new(Ed25519SigningKey::from_seed(KEY_ID, &SEED).unwrap())
}

fn keyring() -> Keyring {
    let mut k = Keyring::new();
    let pk = robodr_blackbox::KeyFile::ed25519_from_seed(&SEED, Some(KEY_ID))
        .unwrap()
        .to_public()
        .unwrap()
        .ed25519_verifying_key()
        .unwrap();
    k.add(UNIT, Box::new(pk)).unwrap();
    k
}

struct Robot {
    _tmp: TempDir,
    spool: PathBuf,
    outbox: PathBuf,
    pack_state: PathBuf,
    export_state: PathBuf,
    high: PathBuf,
    soc_state: PathBuf,
}

impl Robot {
    fn new(tag: &str) -> Self {
        let tmp = TempDir::new(tag);
        let p = tmp.path().to_path_buf();
        let r = Self {
            spool: p.join("spool"),
            outbox: p.join("outbox"),
            pack_state: p.join("pack-state.json"),
            export_state: p.join("export-state.json"),
            high: p.join("high"),
            soc_state: p.join("soc-state"),
            _tmp: tmp,
        };
        fs::create_dir_all(&r.outbox).unwrap();
        fs::create_dir_all(r.high.join("inbox")).unwrap();
        r
    }

    /// Spool `n` findings the way agentd does.
    fn spool_findings(&self, from: u64, n: u64) {
        let mut s = Spool::open(&self.spool, 1 << 30, 1_000_000).unwrap();
        for i in from..from + n {
            let rec = robodr_ocsf::record(&finding(i), Some(12)).unwrap();
            let out = FindingOutput {
                topic: rec.topic.to_string(),
                key: rec.key,
                partition: rec.partition,
                value: rec.value,
                headers: rec
                    .headers
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v))
                    .collect(),
            };
            s.write(&out, robodr_agentd::SpoolClass::Normal).unwrap();
        }
    }

    fn packer(&self, cfg: PackConfig) -> Packer {
        Packer::open(&self.outbox, &self.pack_state, cfg, signer()).unwrap()
    }

    fn export_cfg(&self) -> ExportConfig {
        ExportConfig::new(&self.spool, &self.export_state)
    }

    fn exporter(&self, fail: Option<FailPoint>) -> Exporter {
        let mut c = self.export_cfg();
        c.fail_point = fail;
        Exporter::open(c, self.packer(PackConfig::new(UNIT))).unwrap()
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

    fn ready(&self) -> Vec<String> {
        Self::names(&self.spool.join("ready"))
    }
    fn acked(&self) -> Vec<String> {
        Self::names(&self.spool.join("acked"))
    }
    fn outbox_batches(&self) -> Vec<String> {
        Self::names(&self.outbox)
    }

    /// The diode: copy every published batch into the inbox, then import.
    fn transfer_and_import(&self) -> robodr_diode::ImportReport {
        for b in self.outbox_batches() {
            if b.starts_with('.') {
                continue;
            }
            let to = self.high.join("inbox").join(&b);
            if self.high.join("processed").join(&b).exists() || to.exists() {
                continue;
            }
            fs::create_dir_all(&to).unwrap();
            for f in fs::read_dir(self.outbox.join(&b)).unwrap() {
                let f = f.unwrap();
                fs::copy(f.path(), to.join(f.file_name())).unwrap();
            }
        }
        let mut cfg = ImportConfig::under(&self.high);
        cfg.partitions = Some(12);
        let mut imp = Importer::open(cfg, keyring()).unwrap();
        imp.run(NOW).unwrap()
    }

    /// Finding ids found in the importer output, in order.
    fn imported_keys(&self) -> Vec<String> {
        let mut keys = Vec::new();
        for b in Self::names(&self.high.join("out")) {
            let p = self.high.join("out").join(&b).join("records.jsonl");
            let Ok(text) = fs::read_to_string(p) else {
                continue;
            };
            for l in text.lines() {
                let v: serde_json::Value = serde_json::from_str(l).unwrap();
                keys.push(v["key"].as_str().unwrap().to_string());
            }
        }
        keys
    }
}

fn key_of(i: u64) -> String {
    finding(i).finding_id
}

fn producer(c: &Cluster) -> Producer {
    let mut p = ProducerConfig::new(c.bootstrap());
    p.allow_plaintext = true;
    p.retry_backoff = Duration::from_millis(5);
    Producer::new(p).unwrap()
}

#[test]
fn spool_to_kafka_end_to_end() {
    let r = Robot::new("e2e");
    r.spool_findings(0, 25);
    let mut x = r.exporter(None);
    let rep = x.run_once(NOW).unwrap();
    assert_eq!(rep.exported, 25);
    assert_eq!(rep.batches.len(), 1);
    assert!(r.ready().is_empty(), "everything acked");
    assert_eq!(r.acked().len(), 25);
    // Idempotent: nothing more to do.
    assert_eq!(x.run_once(NOW).unwrap().exported, 0);
    drop(x);

    let imp = r.transfer_and_import();
    assert_eq!(imp.accepted.len(), 1, "{imp:?}");
    let keys = r.imported_keys();
    assert_eq!(keys, (0..25).map(key_of).collect::<Vec<_>>());

    let c = Cluster::start(1, PARTITIONS);
    let mut cfg = PublishConfig::new(Source::DiodeOut(r.high.join("out")), &r.soc_state);
    cfg.chunk_records = 7;
    let mut p = Publisher::open(cfg, producer(&c)).unwrap();
    let rep = p.run_once().unwrap();
    assert_eq!(rep.published, 25);
    assert_eq!(rep.dead_lettered, 0);
    assert_eq!(rep.batches_done.len(), 1);
    // The importer computed partitions for 12, the topic has 4: recomputed.
    assert_eq!(
        rep.partition_overridden,
        25 * u64::from(robodr_ocsf::partition_for(UNIT, 12) != robodr_ocsf::partition_for(UNIT, 4))
    );
    let want_p = robodr_ocsf::partition_for(UNIT, PARTITIONS as u32).unwrap() as i32;
    let all = c.all_records();
    assert_eq!(all.len(), 25);
    for (i, (part, rec)) in all.iter().enumerate() {
        assert_eq!(*part, want_p, "all findings of one robot on one partition");
        let env = finding(i as u64);
        assert_eq!(
            rec.key.as_deref(),
            Some(env.finding_id.as_bytes()),
            "order kept"
        );
        let want = robodr_ocsf::record(&env, None).unwrap();
        assert_eq!(rec.value.as_deref(), Some(want.value.as_bytes()));
        let hs: Vec<(String, String)> = rec
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), String::from_utf8(v.clone().unwrap()).unwrap()))
            .collect();
        let want_h: Vec<(String, String)> = want
            .headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect();
        assert_eq!(hs, want_h, "contract headers in contract order");
    }
    // Restart: nothing re-sent.
    drop(p);
    let mut p = Publisher::open(
        PublishConfig::new(Source::DiodeOut(r.high.join("out")), &r.soc_state),
        producer(&c),
    )
    .unwrap();
    assert_eq!(p.run_once().unwrap().published, 0);
    assert_eq!(c.total(), 25);
    assert_eq!(p.progress().published_total, 25);

    // More findings later: a second batch, chained.
    r.spool_findings(25, 5);
    let rep = r.exporter(None).run_once(NOW + 1).unwrap();
    assert_eq!(rep.batches[0].seq, 2);
    assert_eq!(r.transfer_and_import().accepted.len(), 1);
    assert_eq!(p.run_once().unwrap().published, 5);
    assert_eq!(c.total(), 30);
}

/// The task's key case: crash after the batch is published, before the
/// spool records are renamed into acked/.
#[test]
fn crash_between_pack_and_ack_neither_loses_nor_duplicates() {
    let r = Robot::new("crash-pack-ack");
    r.spool_findings(0, 10);
    let mut x = r.exporter(Some(FailPoint::AfterPack));
    let e = x.run_once(NOW).unwrap_err();
    assert!(
        matches!(e, ExportError::Injected(FailPoint::AfterPack)),
        "{e}"
    );
    // A further run on the same (poisoned) exporter refuses.
    assert!(x.run_once(NOW).is_err());
    drop(x);
    assert_eq!(r.ready().len(), 10, "nothing acked yet");
    assert_eq!(r.outbox_batches().len(), 1, "batch published");

    let mut x = r.exporter(None);
    let rep = x.run_once(NOW).unwrap();
    assert_eq!(rep.recovered.as_deref(), Some("acked"));
    assert_eq!(rep.exported, 0, "no re-pack");
    assert!(r.ready().is_empty());
    assert_eq!(r.acked().len(), 10);
    assert_eq!(r.outbox_batches().len(), 1, "no second batch");
    r.transfer_and_import();
    assert_eq!(r.imported_keys(), (0..10).map(key_of).collect::<Vec<_>>());
}

/// Crash inside the packer, after its commit and before its rename: the
/// packer finishes the batch on open, then the exporter acknowledges.
#[test]
fn crash_between_packer_commit_and_rename() {
    let r = Robot::new("crash-commit-rename");
    r.spool_findings(0, 4);
    let mut x = r.exporter(Some(FailPoint::AfterPack));
    assert!(x.run_once(NOW).is_err());
    drop(x);
    // Rewind the outbox to "committed but not renamed".
    let b = r.outbox_batches().pop().unwrap();
    fs::rename(r.outbox.join(&b), r.outbox.join(format!(".tmp-{b}"))).unwrap();
    let mut x = r.exporter(None);
    let rep = x.run_once(NOW).unwrap();
    assert_eq!(rep.recovered.as_deref(), Some("acked"));
    assert_eq!(r.outbox_batches(), vec![b]);
    assert_eq!(r.acked().len(), 4);
    r.transfer_and_import();
    assert_eq!(r.imported_keys().len(), 4);
}

#[test]
fn crash_before_commit_repacks_under_the_same_sequence() {
    let r = Robot::new("crash-intent");
    r.spool_findings(0, 3);
    let mut x = r.exporter(Some(FailPoint::AfterIntent));
    assert!(x.run_once(NOW).is_err());
    drop(x);
    assert!(r.outbox_batches().is_empty());
    let mut x = r.exporter(None);
    let rep = x.run_once(NOW).unwrap();
    assert_eq!(rep.recovered.as_deref(), Some("dropped"));
    assert_eq!(rep.batches.len(), 1);
    assert_eq!(rep.batches[0].seq, 1);
    assert_eq!(r.acked().len(), 3);
}

#[test]
fn crash_in_the_middle_of_acknowledging() {
    let r = Robot::new("crash-mid-ack");
    r.spool_findings(0, 5);
    let mut x = r.exporter(Some(FailPoint::AfterFirstAck));
    assert!(x.run_once(NOW).is_err());
    drop(x);
    assert_eq!(r.acked().len(), 1);
    assert_eq!(r.ready().len(), 4);
    let mut x = r.exporter(None);
    let rep = x.run_once(NOW).unwrap();
    assert_eq!(rep.recovered.as_deref(), Some("acked"));
    assert_eq!(rep.exported, 0);
    assert_eq!(r.acked().len(), 5);
    assert_eq!(r.outbox_batches().len(), 1);
}

#[test]
fn bad_spool_records_are_moved_aside_never_deleted() {
    let r = Robot::new("reject");
    r.spool_findings(0, 2);
    let ready = r.spool.join("ready");
    fs::write(ready.join("00000000000000000100.json"), b"{not json").unwrap();
    // Valid JSON, wrong seq.
    let good = fs::read(ready.join("00000000000000000001.json")).unwrap();
    fs::write(ready.join("00000000000000000101.json"), &good).unwrap();
    // A tampered finding: valid record shape, invalid value.
    let mut v: serde_json::Value = serde_json::from_slice(&good).unwrap();
    v["seq"] = 102.into();
    v["value"] = "{\"contract_version\":\"1.1.0\"}".into();
    fs::write(ready.join("00000000000000000102.json"), v.to_string()).unwrap();
    // Not a record name: ignored, untouched.
    fs::write(ready.join("notes.txt"), b"x").unwrap();
    let mut x = r.exporter(None);
    let rep = x.run_once(NOW).unwrap();
    assert_eq!(rep.exported, 2);
    assert_eq!(rep.rejected.len(), 3, "{:?}", rep.rejected);
    assert_eq!(r.ready(), vec!["notes.txt".to_string()]);
    let rej = Robot::names(&r.spool.join("rejected"));
    assert_eq!(rej.len(), 6, "{rej:?}"); // 3 records + 3 reasons
    assert!(rej.contains(&"00000000000000000100.json.reason.json".to_string()));
}

#[test]
fn large_spool_is_split_into_single_batch_steps() {
    let r = Robot::new("split");
    r.spool_findings(0, 23);
    let mut cfg = r.export_cfg();
    cfg.max_findings_per_batch = 10;
    let mut pc = PackConfig::new(UNIT);
    pc.max_findings_per_batch = 10;
    let mut x = Exporter::open(cfg, r.packer(pc)).unwrap();
    let rep = x.run_once(NOW).unwrap();
    assert_eq!(rep.exported, 23);
    let seqs: Vec<u64> = rep.batches.iter().map(|b| b.seq).collect();
    assert_eq!(seqs, vec![1, 2, 3]);
    r.transfer_and_import();
    assert_eq!(r.imported_keys(), (0..23).map(key_of).collect::<Vec<_>>());
}

#[test]
fn mismatched_planner_limits_are_reported() {
    let r = Robot::new("mismatch");
    r.spool_findings(0, 5);
    let mut pc = PackConfig::new(UNIT);
    pc.max_findings_per_batch = 2; // exporter thinks 10 000
                                   // `Exporter::open` itself compares the planner limits with the packer's
                                   // own configuration and refuses before touching the spool.
    let e = Exporter::open(r.export_cfg(), r.packer(pc.clone()))
        .err()
        .expect("mismatched limits are refused");
    assert!(matches!(e, ExportError::Config(_)), "{e}");
    assert!(e.to_string().contains("max_findings_per_batch"), "{e}");
    assert!(r.acked().is_empty());
    assert!(r.outbox_batches().is_empty());
    // Matching limits open and export everything.
    let mut cfg = r.export_cfg();
    cfg.max_findings_per_batch = 2;
    let mut x = Exporter::open(cfg, r.packer(pc)).unwrap();
    assert_eq!(x.run_once(NOW).unwrap().exported, 5);
    assert_eq!(r.acked().len(), 5);
    assert_eq!(r.outbox_batches().len(), 3);
}

fn producer_with(c: &Cluster, idempotence: bool) -> Producer {
    let mut p = ProducerConfig::new(c.bootstrap());
    p.allow_plaintext = true;
    p.retry_backoff = Duration::from_millis(5);
    p.idempotence = idempotence;
    Producer::new(p).unwrap()
}

/// A crash after Kafka acknowledged chunk 2 but before its progress was
/// saved. Idempotent (the default): the restarted publisher re-sends the
/// chunk with its journal and the broker drops the copy: exactly once.
/// Without idempotence: that one chunk is duplicated.
#[test]
fn publisher_crash_after_send_is_deduplicated_by_the_broker() {
    for idempotence in [true, false] {
        let r = Robot::new(if idempotence {
            "pub-crash-idem"
        } else {
            "pub-crash"
        });
        r.spool_findings(0, 10);
        r.exporter(None).run_once(NOW).unwrap();
        r.transfer_and_import();
        let c = Cluster::start(1, 2);
        let out = r.high.join("out");
        let mut cfg = PublishConfig::new(Source::DiodeOut(out.clone()), &r.soc_state);
        cfg.chunk_records = 3;
        cfg.fail_after_send = Some(2);
        let mut p = Publisher::open(cfg, producer_with(&c, idempotence)).unwrap();
        assert!(p.run_once().is_err());
        drop(p);
        assert_eq!(c.total(), 6, "two chunks acknowledged by Kafka");
        let mut cfg = PublishConfig::new(Source::DiodeOut(out), &r.soc_state);
        cfg.chunk_records = 3;
        let mut p = Publisher::open(cfg, producer_with(&c, idempotence)).unwrap();
        let batch = Robot::names(&r.high.join("out")).pop().unwrap();
        assert_eq!(p.progress().lines_committed(&batch), 3);
        assert_eq!(p.progress().producer.is_some(), idempotence);
        let rep = p.run_once().unwrap();
        assert_eq!(rep.resumed_after, 3);
        assert_eq!(rep.published, 7);
        let mut keys: Vec<Vec<u8>> = c
            .all_records()
            .into_iter()
            .map(|(_, r)| r.key.unwrap())
            .collect();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), 10, "every finding delivered");
        if idempotence {
            assert_eq!(c.total(), 10, "exactly once");
            assert!(c.state.lock().unwrap().duplicates >= 1);
            assert_eq!(
                c.init_pid_requests(),
                1,
                "producer id kept across the restart"
            );
            let pp = p.progress().producer.clone().unwrap();
            assert!(pp.chunk.is_none(), "journal cleared with the commit");
        } else {
            // 10 findings, chunk 2 (lines 4-6) sent twice.
            assert_eq!(c.total(), 13);
            assert!(p.progress().producer.is_none());
        }
    }
}

#[test]
fn publisher_dead_letters_bad_records_and_continues() {
    let r = Robot::new("pub-dead");
    r.spool_findings(0, 4);
    r.exporter(None).run_once(NOW).unwrap();
    r.transfer_and_import();
    let out = r.high.join("out");
    let b = Robot::names(&out).pop().unwrap();
    let path = out.join(&b).join("records.jsonl");
    let text = fs::read_to_string(&path).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    // A header that disagrees with the value (severity downgraded).
    lines[1] = lines[1].replace("[\"severity\",\"high\"]", "[\"severity\",\"low\"]");
    assert!(lines[1].contains("\"low\""));
    // Garbage, an overlong line and a wrong topic.
    lines.insert(2, "not json".into());
    lines.insert(3, "x".repeat(2 * 1024 * 1024));
    // (Only the record's topic: its value still names the default topic.)
    let wrong = lines[0].replacen(
        &format!("\"topic\":\"{TOPIC}\""),
        "\"topic\":\"other.topic\"",
        1,
    );
    assert_ne!(wrong, lines[0]);
    lines.push(wrong);
    // A finding whose producer was configured with another topic: it is
    // published to this publisher's topic and counted, not refused.
    let mut f = finding(99);
    f.ocsf.metadata.log_name = "site-b.findings".into();
    let rec = robodr_ocsf::record(&f, None).unwrap();
    lines.push(
        serde_json::json!({
            "topic": rec.topic, "partition": null, "key": rec.key,
            "headers": rec.headers, "value": rec.value,
        })
        .to_string(),
    );
    fs::write(&path, lines.join("\n") + "\n").unwrap();

    let c = Cluster::start(1, 1);
    let mut p = Publisher::open(
        PublishConfig::new(Source::DiodeOut(out), &r.soc_state),
        producer(&c),
    )
    .unwrap();
    let rep = p.run_once().unwrap();
    assert_eq!(rep.published, 4);
    assert_eq!(rep.topic_overridden, 1);
    assert_eq!(rep.dead_lettered, 4);
    let dl = fs::read_to_string(r.soc_state.join("dead-letter.jsonl")).unwrap();
    assert_eq!(dl.lines().count(), 4);
    assert!(dl.contains("headers disagree"));
    assert!(dl.contains("longer than"));
    assert!(dl.contains("not the one the value names"));
}

#[test]
fn publisher_from_a_connected_site_spool() {
    let r = Robot::new("pub-spool");
    r.spool_findings(0, 9);
    fs::write(r.spool.join("ready/00000000000000000050.json"), b"junk").unwrap();
    let c = Cluster::start(1, 3);
    let mut cfg = PublishConfig::new(Source::Spool(r.spool.clone()), &r.soc_state);
    cfg.chunk_records = 4;
    let mut p = Publisher::open(cfg, producer(&c)).unwrap();
    let rep = p.run_once().unwrap();
    assert_eq!(rep.published, 9);
    assert_eq!(rep.dead_lettered, 1);
    assert!(r.ready().is_empty());
    assert_eq!(r.acked().len(), 9);
    assert_eq!(Robot::names(&r.spool.join("rejected")).len(), 1);
    assert_eq!(c.total(), 9);
    assert_eq!(p.run_once().unwrap().published, 0);
}

#[test]
fn publisher_stops_on_fatal_kafka_error_without_committing() {
    let r = Robot::new("pub-fatal");
    r.spool_findings(0, 3);
    r.exporter(None).run_once(NOW).unwrap();
    r.transfer_and_import();
    let c = Cluster::start(1, 1);
    c.script([Action::Error(29)]);
    let out = r.high.join("out");
    let mut p = Publisher::open(
        PublishConfig::new(Source::DiodeOut(out.clone()), &r.soc_state),
        producer(&c),
    )
    .unwrap();
    assert!(p.run_once().is_err());
    assert!(p.progress().in_flight.is_empty());
    assert!(fs::read_dir(r.soc_state.join("done"))
        .unwrap()
        .next()
        .is_none());
    // Fixed (ACL granted): the same publisher goes on.
    assert_eq!(p.run_once().unwrap().published, 3);
}

/// Per-finding signatures (contract §2a) on the connected path: the
/// `robodr-finding-sig` header agentd spools is published verbatim (last
/// header, value bytes unchanged) and verifies at the consumer; a malformed
/// or misplaced signature header is dead-lettered, never forwarded.
#[test]
fn publisher_carries_finding_signatures_from_a_spool() {
    const FSEED: [u8; 32] = [0x42; 32];
    const FKEY: &str = "finding:ugv-007:1";
    let r = Robot::new("pub-sig");
    let fsigner = Ed25519SigningKey::from_seed(FKEY, &FSEED).unwrap();
    let mut s = Spool::open(&r.spool, 1 << 30, 1_000_000).unwrap();
    let out = |rec: robodr_ocsf::Record| FindingOutput {
        topic: rec.topic.to_string(),
        key: rec.key,
        partition: rec.partition,
        value: rec.value,
        headers: rec
            .headers
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    };
    for i in 0..3 {
        let mut rec = robodr_ocsf::record(&finding(i), Some(12)).unwrap();
        robodr_ocsf::sign_record(&mut rec, &fsigner).unwrap();
        s.write(&out(rec), robodr_agentd::SpoolClass::Normal)
            .unwrap();
    }
    // Signature header moved first: refused.
    let mut rec = robodr_ocsf::record(&finding(3), Some(12)).unwrap();
    robodr_ocsf::sign_record(&mut rec, &fsigner).unwrap();
    let mut o = out(rec);
    let sig = o.headers.pop().unwrap();
    o.headers.insert(0, sig);
    s.write(&o, robodr_agentd::SpoolClass::Normal).unwrap();
    // Malformed signature header: refused.
    let rec = robodr_ocsf::record(&finding(4), Some(12)).unwrap();
    let mut o = out(rec);
    o.headers
        .push((robodr_ocsf::SIG_HEADER.into(), "{\"alg\":\"hmac\"}".into()));
    s.write(&o, robodr_agentd::SpoolClass::Normal).unwrap();
    drop(s);

    let c = Cluster::start(1, 3);
    let cfg = PublishConfig::new(Source::Spool(r.spool.clone()), &r.soc_state);
    let mut p = Publisher::open(cfg, producer(&c)).unwrap();
    let rep = p.run_once().unwrap();
    assert_eq!(rep.published, 3);
    assert_eq!(rep.dead_lettered, 2);

    let pk = robodr_blackbox::KeyFile::ed25519_from_seed(&FSEED, Some(FKEY))
        .unwrap()
        .to_public()
        .unwrap()
        .ed25519_verifying_key()
        .unwrap();
    let mut keys: std::collections::BTreeMap<String, Box<dyn robodr_blackbox::Verifier>> =
        std::collections::BTreeMap::new();
    keys.insert(UNIT.into(), Box::new(pk));
    let recs = c.all_records();
    assert_eq!(recs.len(), 3);
    for (_, d) in recs {
        let value = String::from_utf8(d.value.clone().unwrap()).unwrap();
        let last = d.headers.last().unwrap();
        assert_eq!(last.0, robodr_ocsf::SIG_HEADER);
        let sig = header(&d, robodr_ocsf::SIG_HEADER);
        let v = robodr_ocsf::parse_and_validate_signed(
            &value,
            sig.as_deref(),
            &keys,
            robodr_ocsf::SignaturePolicy::Strict,
        )
        .unwrap();
        assert!(matches!(
            v.signature,
            robodr_ocsf::SignatureStatus::Verified { .. }
        ));
    }
}
