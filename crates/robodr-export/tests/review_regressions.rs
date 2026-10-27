//! Regression tests for the rev5/export review findings. The review's PoCs
//! (which passed while the bugs existed) are ported here asserting the
//! fixed behaviour.

mod common;

use common::*;
use robodr_agent::FindingOutput;
use robodr_agentd::spool::Spool;
use robodr_blackbox::Ed25519SigningKey;
use robodr_diode::{PackConfig, Packer};
use robodr_export::kafka::{Outcome, ProduceError, ProduceRecord};
use robodr_export::spool_export::ExportError;
use robodr_export::{ExportConfig, Exporter, PublishConfig, Publisher, Sink, Source};
use std::fs;
use std::path::{Path, PathBuf};

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

fn spool_findings(spool: &Path, from: u64, n: u64) {
    let mut s = Spool::open(spool, 1 << 30, 1_000_000).unwrap();
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

fn signer() -> Box<Ed25519SigningKey> {
    Box::new(Ed25519SigningKey::from_seed("k", &[7; 32]).unwrap())
}

const MAX_SEQ: u64 = 9_999_999_999_999_999;

/// A robot whose packer is one batch away from sequence exhaustion, so the
/// second batch of a split `pack` fails after the first was committed.
struct SplitFixture {
    _tmp: TempDir,
    spool: PathBuf,
    outbox: PathBuf,
    pack_state: PathBuf,
    export_state: PathBuf,
}

impl SplitFixture {
    fn new(tag: &str) -> Self {
        let tmp = TempDir::new(tag);
        let spool = tmp.path().join("spool");
        let outbox = tmp.path().join("outbox");
        let pack_state = tmp.path().join("pack-state.json");
        let export_state = tmp.path().join("export-state.json");
        fs::create_dir_all(&outbox).unwrap();
        spool_findings(&spool, 0, 3);
        fs::write(
            &pack_state,
            format!(
                "{{\"format\":\"robodr-diode-pack-state/1\",\"unit_id\":\"{UNIT}\",\
                 \"next_seq\":{MAX_SEQ},\"last_batch_hash\":\"{}\"}}",
                "ab".repeat(32)
            ),
        )
        .unwrap();
        Self {
            _tmp: tmp,
            spool,
            outbox,
            pack_state,
            export_state,
        }
    }

    fn packer(&self, pc: &PackConfig) -> Packer {
        Packer::open(&self.outbox, &self.pack_state, pc.clone(), signer()).unwrap()
    }

    /// Run the unchecked exporter (limits 10 000 vs the packer's 2; only
    /// possible through the test-only `fault-injection` feature, since
    /// `Exporter::open` refuses mismatched limits): the split's second batch
    /// fails. Returns the published batch name.
    fn fail_split(&self, pc: &PackConfig) -> String {
        assert!(Exporter::open(
            ExportConfig::new(&self.spool, &self.export_state),
            self.packer(pc),
        )
        .is_err());
        let mut x = Exporter::open_unchecked_for_fault_injection(
            ExportConfig::new(&self.spool, &self.export_state),
            self.packer(pc),
        )
        .unwrap();
        assert!(x.run_once(NOW).is_err(), "second batch of the split fails");
        drop(x);
        let batches: Vec<String> = names(&self.outbox)
            .into_iter()
            .filter(|n| !n.starts_with('.'))
            .collect();
        assert_eq!(batches.len(), 1);
        batches[0].clone()
    }

    /// Re-open (what the binary does after an error) and return the
    /// recovery verdict.
    fn reopen(&self, pc: &PackConfig) -> Option<String> {
        // Recovery runs under the checked open with matching limits.
        let x = Exporter::open(
            ExportConfig::for_packer(&self.spool, &self.export_state, pc),
            self.packer(pc),
        )
        .unwrap();
        x.recovered().map(str::to_string)
    }

    fn ready(&self) -> Vec<String> {
        names(&self.spool.join("ready"))
    }

    fn acked(&self) -> Vec<String> {
        names(&self.spool.join("acked"))
    }
}

fn split_pack_config() -> PackConfig {
    let mut pc = PackConfig::new(UNIT);
    pc.max_findings_per_batch = 2;
    pc
}

/// Finding 1 (was PoC A): the packer splits the exporter's step and the
/// second batch fails. Recovery must acknowledge only the two records that
/// are in the committed batch; the third stays in `ready/`.
#[test]
fn split_pack_failure_acks_only_packed_records() {
    let f = SplitFixture::new("reg-split");
    let pc = split_pack_config();
    let batch = f.fail_split(&pc);
    let packed = fs::read_to_string(f.outbox.join(&batch).join("findings.jsonl"))
        .unwrap()
        .lines()
        .count();
    assert_eq!(packed, 2, "only two findings reached the outbox");
    assert_eq!(f.reopen(&pc).as_deref(), Some("partial"));
    assert_eq!(f.acked().len(), 2, "exactly the packed records are acked");
    assert_eq!(
        f.ready(),
        vec!["00000000000000000003.json".to_string()],
        "the unpacked record is kept for the next batch"
    );
    let st: serde_json::Value =
        serde_json::from_slice(&fs::read(&f.export_state).unwrap()).unwrap();
    assert!(st["pending"].is_null(), "intent resolved");
    assert_eq!(st["exported"], 2);
}

/// Same, after the transfer agent took the batch out of the outbox: the
/// proof comes from the packer archive.
#[test]
fn split_pack_failure_proof_from_archive_after_transfer() {
    let f = SplitFixture::new("reg-split-archive");
    let pc = split_pack_config();
    let batch = f.fail_split(&pc);
    fs::remove_dir_all(f.outbox.join(&batch)).unwrap();
    assert_eq!(f.reopen(&pc).as_deref(), Some("partial"));
    assert_eq!(f.acked().len(), 2);
    assert_eq!(f.ready().len(), 1);
}

/// No copy anywhere (archive disabled, batch transferred): nothing can be
/// proven, so nothing is acknowledged (duplicates later, never loss).
#[test]
fn split_pack_failure_without_any_copy_keeps_everything() {
    let f = SplitFixture::new("reg-split-nocopy");
    let mut pc = split_pack_config();
    pc.archive_keep = 0;
    let batch = f.fail_split(&pc);
    fs::remove_dir_all(f.outbox.join(&batch)).unwrap();
    f.reopen(&pc);
    assert!(f.acked().is_empty());
    assert_eq!(f.ready().len(), 3);
}

/// A tampered/partial findings file does not count as proof.
#[test]
fn split_pack_failure_ignores_a_corrupt_batch_copy() {
    let f = SplitFixture::new("reg-split-corrupt");
    let mut pc = split_pack_config();
    pc.archive_keep = 0;
    let batch = f.fail_split(&pc);
    let path = f.outbox.join(&batch).join("findings.jsonl");
    let text = fs::read_to_string(&path).unwrap();
    // Keep only the first line: size/hash no longer match the manifest.
    let first = text.lines().next().unwrap().to_string() + "\n";
    fs::remove_file(&path).unwrap();
    fs::write(&path, first).unwrap();
    f.reopen(&pc);
    assert!(f.acked().is_empty());
    assert_eq!(f.ready().len(), 3);
}

/// Finding 1, first half: `open_checked` refuses limits that differ from
/// the packer's, before touching anything.
#[test]
fn open_checked_refuses_mismatched_limits() {
    let f = SplitFixture::new("reg-checked");
    let pc = split_pack_config();
    let e = Exporter::open_checked(
        ExportConfig::new(&f.spool, &f.export_state),
        &pc,
        f.packer(&pc),
    )
    .err()
    .unwrap();
    assert!(
        matches!(&e, ExportError::Config(m) if m.contains("max_findings_per_batch")),
        "{e}"
    );
    let mut parity = PackConfig::new(UNIT);
    parity.parity_shards = 2;
    let e = ExportConfig::new(&f.spool, &f.export_state)
        .check_against(&parity)
        .unwrap_err();
    assert!(e.to_string().contains("parity_shards"), "{e}");
    // Matching limits (derived from the packer config) are accepted.
    let ok = Exporter::open_checked(
        ExportConfig::for_packer(&f.spool, &f.export_state, &pc),
        &pc,
        f.packer(&pc),
    );
    assert!(ok.is_ok());
    assert_eq!(f.ready().len(), 3, "nothing touched");
}

#[test]
fn open_checked_refuses_another_units_packer() {
    let f = SplitFixture::new("reg-checked-unit");
    let pc = PackConfig::new(UNIT);
    let other = PackConfig::new("ugv-999");
    let e = Exporter::open_checked(
        ExportConfig::for_packer(&f.spool, &f.export_state, &other),
        &other,
        f.packer(&pc),
    )
    .err()
    .unwrap();
    assert!(matches!(e, ExportError::Config(_)), "{e}");
}

/// With `open_checked` and parity, the exporter's planner accounts for the
/// parity bytes, so the packer never splits a step.
#[test]
fn parity_aware_planner_never_splits() {
    let tmp = TempDir::new("reg-parity");
    let spool = tmp.path().join("spool");
    let outbox = tmp.path().join("outbox");
    fs::create_dir_all(&outbox).unwrap();
    spool_findings(&spool, 0, 150);
    let mut pc = PackConfig::new(UNIT);
    pc.parity_shards = 2;
    pc.shard_size = 512;
    // Smallest limit that holds a maximal finding plus its parity; with
    // parity a batch takes ~3x its data, so the data cap is ~66 KB.
    pc.max_batch_bytes = 200_000;
    let packer = Packer::open(&outbox, tmp.path().join("ps.json"), pc.clone(), signer()).unwrap();
    let cfg = ExportConfig::for_packer(&spool, tmp.path().join("es.json"), &pc);
    let mut x = Exporter::open_checked(cfg, &pc, packer).unwrap();
    let rep = x.run_once(NOW).unwrap();
    assert_eq!(rep.exported, 150);
    assert!(rep.batches.len() > 1, "limits force several steps");
    assert!(rep
        .batches
        .iter()
        .all(|b| b.data_bytes * 3 <= 200_000 + 4096));
    assert!(rep.batches.iter().all(|b| b.parity_files == 2));
    assert!(names(&spool.join("ready")).is_empty());
}

/// Counting sink: records every key it is asked to send.
struct CountSink {
    sent: Vec<Vec<u8>>,
    fail_after: Option<usize>,
}

impl Sink for CountSink {
    fn partition_count(&mut self, _: &str) -> Result<u32, ProduceError> {
        Ok(4)
    }
    fn send(
        &mut self,
        _: &str,
        records: &[(i32, ProduceRecord)],
    ) -> Result<Vec<Outcome>, ProduceError> {
        if let Some(n) = self.fail_after {
            if self.sent.len() >= n {
                return Err(ProduceError::Timeout("simulated outage".into()));
            }
        }
        let mut out = Vec::new();
        for (p, r) in records {
            self.sent.push(r.key.clone().unwrap());
            out.push(Outcome::Delivered {
                partition: *p,
                offset: 0,
            });
        }
        Ok(out)
    }
}

fn sink(fail_after: Option<usize>) -> CountSink {
    CountSink {
        sent: vec![],
        fail_after,
    }
}

fn write_batch(out: &Path, name: &str, robot: &str, n: u64) {
    let d = out.join(name);
    fs::create_dir_all(&d).unwrap();
    let mut s = String::new();
    for i in 0..n {
        let rec = robodr_ocsf::record(&finding_for(robot, i), Some(4)).unwrap();
        let line = serde_json::json!({
            "topic": rec.topic, "partition": rec.partition, "key": rec.key,
            "headers": rec.headers, "value": rec.value,
        });
        s.push_str(&line.to_string());
        s.push('\n');
    }
    fs::write(d.join("records.jsonl"), s).unwrap();
}

const UGV_BATCH: &str = "rdd_ugv-007_0000000000000001";
const AAA_BATCH: &str = "rdd_aaa-001_0000000000000001";

/// Finding 2 (was PoC B): a batch imported between a mid-batch stop and the
/// resume, whose name sorts first, no longer resets the stopped batch's
/// offset: it resumes after its last committed chunk.
#[test]
fn publisher_resumes_after_interleaved_import() {
    let tmp = TempDir::new("reg-resume");
    let out = tmp.path().join("out");
    let state = tmp.path().join("state");
    write_batch(&out, UGV_BATCH, UNIT, 10);
    let mut cfg = PublishConfig::new(Source::DiodeOut(out.clone()), &state);
    cfg.chunk_records = 2;
    let mut p = Publisher::open(cfg.clone(), sink(Some(8))).unwrap();
    assert!(p.run_once().is_err());
    assert_eq!(p.progress().lines_committed(UGV_BATCH), 8);
    drop(p);
    write_batch(&out, AAA_BATCH, "aaa-001", 1);
    let mut p = Publisher::open(cfg.clone(), sink(None)).unwrap();
    let rep = p.run_once().unwrap();
    assert_eq!(rep.resumed_after, 8);
    assert_eq!(p.sink().sent.len(), 1 + 2, "aaa + the last ugv chunk only");
    assert_eq!(rep.batches_done, vec![AAA_BATCH, UGV_BATCH]);
    assert!(p.progress().in_flight.is_empty(), "pruned when done");
    // A further run sends nothing.
    drop(p);
    let mut p = Publisher::open(cfg, sink(None)).unwrap();
    assert_eq!(p.run_once().unwrap().published, 0);
    assert!(p.sink().sent.is_empty());
}

/// Two batches interrupted at different points both keep their offsets.
#[test]
fn publisher_keeps_offsets_of_several_interrupted_batches() {
    let tmp = TempDir::new("reg-multi");
    let out = tmp.path().join("out");
    let state = tmp.path().join("state");
    write_batch(&out, UGV_BATCH, UNIT, 6);
    let mut cfg = PublishConfig::new(Source::DiodeOut(out.clone()), &state);
    cfg.chunk_records = 2;
    let mut p = Publisher::open(cfg.clone(), sink(Some(4))).unwrap();
    assert!(p.run_once().is_err());
    drop(p);
    // aaa sorts first: it is interrupted after one chunk.
    write_batch(&out, AAA_BATCH, "aaa-001", 6);
    let mut p = Publisher::open(cfg.clone(), sink(Some(2))).unwrap();
    assert!(p.run_once().is_err());
    assert_eq!(p.progress().lines_committed(AAA_BATCH), 2);
    assert_eq!(p.progress().lines_committed(UGV_BATCH), 4);
    drop(p);
    let mut p = Publisher::open(cfg, sink(None)).unwrap();
    let rep = p.run_once().unwrap();
    assert_eq!(rep.resumed_after, 2 + 4);
    assert_eq!(p.sink().sent.len(), 4 + 2);
}

/// Offsets of batches that disappeared from out/ are pruned.
#[test]
fn publisher_prunes_offsets_of_vanished_batches() {
    let tmp = TempDir::new("reg-prune");
    let out = tmp.path().join("out");
    let state = tmp.path().join("state");
    write_batch(&out, UGV_BATCH, UNIT, 4);
    let mut cfg = PublishConfig::new(Source::DiodeOut(out.clone()), &state);
    cfg.chunk_records = 2;
    let mut p = Publisher::open(cfg.clone(), sink(Some(2))).unwrap();
    assert!(p.run_once().is_err());
    drop(p);
    fs::remove_dir_all(out.join(UGV_BATCH)).unwrap();
    let mut p = Publisher::open(cfg, sink(None)).unwrap();
    p.run_once().unwrap();
    assert!(p.progress().in_flight.is_empty());
    let saved = fs::read_to_string(state.join("progress.json")).unwrap();
    assert!(!saved.contains(UGV_BATCH), "{saved}");
}

/// A version-1 progress file is migrated into the per-batch map.
#[test]
fn publisher_migrates_v1_progress() {
    let tmp = TempDir::new("reg-v1");
    let out = tmp.path().join("out");
    let state = tmp.path().join("state");
    write_batch(&out, UGV_BATCH, UNIT, 5);
    fs::create_dir_all(&state).unwrap();
    fs::write(
        state.join("progress.json"),
        format!(
            "{{\"format\":\"robodr-kafka-publish-state/1\",\"batch\":\"{UGV_BATCH}\",\
             \"lines_committed\":3,\"published_total\":3,\"dead_lettered_total\":0}}"
        ),
    )
    .unwrap();
    let mut p = Publisher::open(
        PublishConfig::new(Source::DiodeOut(out), &state),
        sink(None),
    )
    .unwrap();
    assert_eq!(p.progress().lines_committed(UGV_BATCH), 3);
    let rep = p.run_once().unwrap();
    assert_eq!(rep.resumed_after, 3);
    assert_eq!(p.sink().sent.len(), 2);
    assert_eq!(p.progress().published_total, 5);
}

/// Note (dead letters): a chunk whose progress was not saved before a crash
/// is processed again; its dead-lettered records are appended only once.
#[test]
fn dead_letters_are_not_duplicated_after_a_crash() {
    let tmp = TempDir::new("reg-dead");
    let out = tmp.path().join("out");
    let state = tmp.path().join("state");
    write_batch(&out, UGV_BATCH, UNIT, 3);
    let path = out.join(UGV_BATCH).join("records.jsonl");
    let mut text = fs::read_to_string(&path).unwrap();
    text.insert_str(0, "not json\n");
    fs::write(&path, text).unwrap();
    let mut cfg = PublishConfig::new(Source::DiodeOut(out), &state);
    cfg.fail_after_send = Some(1); // crash after the chunk, before progress
    let mut p = Publisher::open(cfg.clone(), sink(None)).unwrap();
    assert!(p.run_once().is_err());
    drop(p);
    let dl = state.join("dead-letter.jsonl");
    assert_eq!(fs::read_to_string(&dl).unwrap().lines().count(), 1);
    cfg.fail_after_send = None;
    let mut p = Publisher::open(cfg, sink(None)).unwrap();
    let rep = p.run_once().unwrap();
    assert_eq!(rep.dead_lettered, 1);
    assert_eq!(p.sink().sent.len(), 3);
    assert_eq!(
        fs::read_to_string(&dl).unwrap().lines().count(),
        1,
        "deduplicated on (batch, line)"
    );
}

/// Not a bug: independent byte-level check of RecordBatch v2 against the
/// protocol spec (hand-assembled expected bytes, CRC-32C over attributes..end).
#[test]
fn verify_record_batch_v2_layout_by_hand() {
    let r = ProduceRecord {
        key: Some(b"k".to_vec()),
        value: Some(b"v".to_vec()),
        headers: vec![("h".into(), b"x".to_vec())],
        timestamp_ms: 0x0102_0304_0506,
    };
    let b = robodr_export::kafka::encode_batch(&[r]).unwrap();
    let mut want = Vec::new();
    want.extend_from_slice(&0i64.to_be_bytes()); // baseOffset
    want.extend_from_slice(&62i32.to_be_bytes()); // batchLength = 74 - 12
    want.extend_from_slice(&(-1i32).to_be_bytes()); // partitionLeaderEpoch
    want.push(2); // magic
    want.extend_from_slice(&[0; 4]); // crc placeholder
    let crc_from = want.len();
    want.extend_from_slice(&0i16.to_be_bytes()); // attributes
    want.extend_from_slice(&0i32.to_be_bytes()); // lastOffsetDelta
    want.extend_from_slice(&0x0102_0304_0506i64.to_be_bytes()); // firstTimestamp
    want.extend_from_slice(&0x0102_0304_0506i64.to_be_bytes()); // maxTimestamp
    want.extend_from_slice(&(-1i64).to_be_bytes()); // producerId
    want.extend_from_slice(&(-1i16).to_be_bytes()); // producerEpoch
    want.extend_from_slice(&(-1i32).to_be_bytes()); // baseSequence
    want.extend_from_slice(&1i32.to_be_bytes()); // records count
                                                 // length=12 (zigzag 24), attr, tsDelta 0, offDelta 0, key, value, 1 header
    want.extend_from_slice(&[
        0x18, 0, 0, 0, 0x02, b'k', 0x02, b'v', 0x02, 0x02, b'h', 0x02, b'x',
    ]);
    let crc = robodr_export::crc32c::crc32c(&want[crc_from..]);
    want[17..21].copy_from_slice(&crc.to_be_bytes());
    assert_eq!(b, want);
}
