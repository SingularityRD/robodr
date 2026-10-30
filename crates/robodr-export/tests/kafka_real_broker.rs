//! The std-only producer and `robodr-kafka-publish` against a **real**
//! Apache Kafka broker.
//!
//! Every test is `#[ignore]`d and additionally needs
//! `ROBODR_KAFKA_BROKER=host:port` (a single-node cluster); without it an
//! ignored run prints "skipped" and passes. `scripts/kafka-it.sh` starts a
//! broker in docker, creates the topics below, runs these tests and tears
//! the broker down:
//!
//! | topic | partitions | config |
//! | --- | --- | --- |
//! | `robodr.findings` | 12 | defaults |
//! | `robodr-it-small` | 1 | `max.message.bytes=4096` |
//! | `robodr-it-denied` | 1 | ACL: DENY `User:ANONYMOUS` WRITE |
//!
//! Optional: `ROBODR_KAFKA_SASL_BROKER` (a SASL_PLAINTEXT/PLAIN listener:
//! this client does not speak PLAIN, it must fail cleanly) and
//! `ROBODR_KAFKA_RESTART_CMD` (a shell command restarting the broker, run
//! mid-stream).
//!
//! TLS / SASL (`scripts/kafka-tls-it.sh`, a native broker whose
//! certificate is `fixtures/tls/server.pem`): `ROBODR_KAFKA_TLS_PKI` (the
//! fixtures directory) with `ROBODR_KAFKA_TLS_BROKER` (SSL),
//! `ROBODR_KAFKA_MTLS_BROKER` (SSL, client certificate required) and
//! `ROBODR_KAFKA_SCRAM_BROKER` (SASL_SSL, SCRAM-SHA-256/512;
//! `ROBODR_KAFKA_SCRAM_USER` / `_PASSWORD`, `_REAUTH_MS` the listener's
//! `connections.max.reauth.ms`).
//!
//! What is read back is read with a minimal Fetch v4 consumer below (test
//! only); each fetched RecordBatch goes through
//! [`robodr_export::kafka::decode_batches`], which re-checks its CRC-32C
//! as stored and served by the broker.

mod common;

use common::*;
use robodr_agent::FindingOutput;
use robodr_agentd::spool::Spool;
use robodr_blackbox::Ed25519SigningKey;
use robodr_diode::{ImportConfig, Importer, Keyring, PackConfig, Packer};
use robodr_export::kafka::batch::DecodedRecord;
use robodr_export::kafka::proto;
use robodr_export::kafka::wire::{Reader, Writer};
use robodr_export::kafka::{
    decode_batches, Outcome, ProduceError, ProduceRecord, Producer, ProducerConfig,
};
use robodr_export::{ExportConfig, Exporter, PublishConfig, Publisher, Source};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PUBLISH: &str = env!("CARGO_BIN_EXE_robodr-kafka-publish");
const PARTITIONS: u32 = 12;
const SMALL_TOPIC: &str = "robodr-it-small";
const DENIED_TOPIC: &str = "robodr-it-denied";
const FSEED: [u8; 32] = [0x42; 32];
const FKEY: &str = "finding:ugv-007:1";
const DSEED: [u8; 32] = [0x21; 32];
const DKEY: &str = "diode-ugv-007";

fn broker() -> Option<String> {
    match std::env::var("ROBODR_KAFKA_BROKER") {
        Ok(b) if !b.is_empty() => Some(b),
        _ => {
            eprintln!("skipped: ROBODR_KAFKA_BROKER is not set (see scripts/kafka-it.sh)");
            None
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// A finding index base unique to this run (so repeated runs against the
/// same broker produce distinct finding ids).
fn run_base() -> u64 {
    static BASE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *BASE.get_or_init(|| (now_ms() / 1000 % 1_000_000) * 10_000)
}

fn producer_cfg(b: &str) -> ProducerConfig {
    let mut p = ProducerConfig::new(vec![b.to_string()]);
    p.allow_plaintext = true;
    p.retry_backoff = Duration::from_millis(50);
    p.retry_backoff_max = Duration::from_millis(1000);
    p
}

// ------------------------------------------------------- Fetch v4 consumer

/// One record as stored by the broker.
#[derive(Debug, Clone)]
struct Fetched {
    partition: i32,
    offset: i64,
    producer_id: i64,
    rec: DecodedRecord,
}

impl Fetched {
    fn key(&self) -> String {
        String::from_utf8(self.rec.key.clone().unwrap()).unwrap()
    }
    fn value(&self) -> String {
        String::from_utf8(self.rec.value.clone().unwrap()).unwrap()
    }
    fn headers(&self) -> Vec<(String, String)> {
        self.rec
            .headers
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    String::from_utf8(v.clone().expect("header value")).unwrap(),
                )
            })
            .collect()
    }
}

/// Connects per use when needed: the script's broker closes connections
/// idle for 10 s, longer than some publishes take.
struct Consumer {
    addr: String,
    s: Option<TcpStream>,
    corr: i32,
}

impl Consumer {
    fn connect(addr: &str) -> Self {
        Self {
            addr: addr.to_string(),
            s: None,
            corr: 0,
        }
    }

    fn exchange(&mut self, api: i16, v: i16, body: &[u8]) -> Vec<u8> {
        for attempt in 0..2 {
            match self.try_exchange(api, v, body) {
                Ok(b) => return b,
                Err(e) if attempt == 0 => {
                    eprintln!("consumer: {e}, reconnecting");
                    self.s = None;
                }
                Err(e) => panic!("consumer: {e}"),
            }
        }
        unreachable!()
    }

    fn try_exchange(&mut self, api: i16, v: i16, body: &[u8]) -> std::io::Result<Vec<u8>> {
        if self.s.is_none() {
            let s = TcpStream::connect(&self.addr)?;
            s.set_read_timeout(Some(Duration::from_secs(30)))?;
            self.s = Some(s);
        }
        let s = self.s.as_mut().expect("connected");
        self.corr += 1;
        let f = proto::frame_request(api, v, self.corr, "robodr-it-consumer", body).unwrap();
        s.write_all(&f)?;
        let mut len = [0u8; 4];
        s.read_exact(&mut len)?;
        let mut b = vec![0u8; i32::from_be_bytes(len) as usize];
        s.read_exact(&mut b)?;
        assert_eq!(i32::from_be_bytes([b[0], b[1], b[2], b[3]]), self.corr);
        Ok(b.split_off(4))
    }

    /// Fetch v4 of one partition from `offset`: (high watermark, records).
    /// Leadership errors (right after a broker restart) are waited out.
    fn fetch(&mut self, topic: &str, partition: i32, offset: i64) -> (i64, Vec<Fetched>) {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            match self.try_fetch(topic, partition, offset) {
                Ok(r) => return r,
                Err(e @ (5 | 6 | 3)) if Instant::now() < deadline => {
                    eprintln!("fetch {topic}/{partition}: error {e}, retrying");
                    std::thread::sleep(Duration::from_millis(500));
                }
                Err(e) => panic!("fetch {topic}/{partition}: error {e}"),
            }
        }
    }

    fn try_fetch(
        &mut self,
        topic: &str,
        partition: i32,
        offset: i64,
    ) -> Result<(i64, Vec<Fetched>), i16> {
        let mut w = Writer::new();
        w.i32(-1).i32(200).i32(1).i32(64 << 20).i8(0);
        w.try_array_len(1).unwrap();
        w.try_string(topic).unwrap();
        w.try_array_len(1).unwrap();
        w.i32(partition).i64(offset).i32(16 << 20);
        let body = self.exchange(1, 4, &w.buf);
        let mut r = Reader::new(&body);
        let _throttle = r.i32().unwrap();
        assert_eq!(r.i32().unwrap(), 1);
        assert_eq!(r.string().unwrap(), topic);
        assert_eq!(r.i32().unwrap(), 1);
        assert_eq!(r.i32().unwrap(), partition);
        let err = r.i16().unwrap();
        if err != 0 {
            return Err(err);
        }
        let hwm = r.i64().unwrap();
        let _lso = r.i64().unwrap();
        let aborted = r.i32().unwrap();
        if aborted > 0 {
            r.take(aborted as usize * 16).unwrap();
        }
        let records = r.nullable_bytes().unwrap().unwrap_or_default();
        let mut out = Vec::new();
        let mut pos = 0;
        // Whole batches only (the last one may be cut by the size limit).
        while records.len() - pos >= 12 {
            let len = i32::from_be_bytes(records[pos + 8..pos + 12].try_into().unwrap()) as usize;
            if records.len() - pos < 12 + len {
                break;
            }
            let one = &records[pos..pos + 12 + len];
            pos += 12 + len;
            // CRC-32C, lengths, magic 2, no compression: checked here.
            for b in decode_batches(one).expect("broker-stored batch decodes, CRC valid") {
                for rec in b.records {
                    let off = b.base_offset + i64::from(rec.offset_delta);
                    if off >= offset {
                        out.push(Fetched {
                            partition,
                            offset: off,
                            producer_id: b.producer_id,
                            rec,
                        });
                    }
                }
            }
        }
        Ok((hwm, out))
    }

    /// High watermarks of every partition (a fetch at offset 0 with a
    /// 1-byte partition limit returns the watermark cheaply; the log start
    /// is 0 on the test broker).
    fn marks(&mut self, topic: &str, partitions: u32) -> Vec<i64> {
        (0..partitions as i32)
            .map(|p| self.fetch_limited(topic, p))
            .collect()
    }

    fn fetch_limited(&mut self, topic: &str, partition: i32) -> i64 {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            match self.try_fetch_limited(topic, partition) {
                Ok(h) => return h,
                Err(e @ (5 | 6 | 3)) if Instant::now() < deadline => {
                    eprintln!("watermark {topic}/{partition}: error {e}, retrying");
                    std::thread::sleep(Duration::from_millis(500));
                }
                Err(e) => panic!("watermark {topic}/{partition}: error {e}"),
            }
        }
    }

    fn try_fetch_limited(&mut self, topic: &str, partition: i32) -> Result<i64, i16> {
        let mut w = Writer::new();
        w.i32(-1).i32(0).i32(0).i32(1).i8(0);
        w.try_array_len(1).unwrap();
        w.try_string(topic).unwrap();
        w.try_array_len(1).unwrap();
        w.i32(partition).i64(0).i32(1);
        let body = self.exchange(1, 4, &w.buf);
        let mut r = Reader::new(&body);
        let _ = r.i32().unwrap();
        let _ = r.i32().unwrap();
        let _ = r.string().unwrap();
        let _ = r.i32().unwrap();
        let _ = r.i32().unwrap();
        let err = r.i16().unwrap();
        if err != 0 {
            return Err(err);
        }
        Ok(r.i64().unwrap())
    }

    /// Everything appended since `marks`, waiting until the watermarks stop
    /// moving.
    fn since(&mut self, topic: &str, marks: &[i64]) -> Vec<Fetched> {
        let mut out = Vec::new();
        for (p, &from) in marks.iter().enumerate() {
            let p = p as i32;
            let mut at = from;
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                let (hwm, recs) = self.fetch(topic, p, at);
                if let Some(last) = recs.last() {
                    at = last.offset + 1;
                }
                out.extend(recs);
                if at >= hwm {
                    break;
                }
                assert!(Instant::now() < deadline, "fetch {topic}/{p} stuck at {at}");
            }
        }
        out
    }
}

// ------------------------------------------------------------- fixtures

const ROBOTS: [&str; 3] = ["ugv-007", "ugv-008", "uav-101"];

fn finding_signer() -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed(FKEY, &FSEED).unwrap()
}

fn verifying_keys() -> BTreeMap<String, Box<dyn robodr_blackbox::Verifier>> {
    let pk = robodr_blackbox::KeyFile::ed25519_from_seed(&FSEED, Some(FKEY))
        .unwrap()
        .to_public()
        .unwrap()
        .ed25519_verifying_key()
        .unwrap();
    let mut keys: BTreeMap<String, Box<dyn robodr_blackbox::Verifier>> = BTreeMap::new();
    for r in ROBOTS {
        keys.insert(r.into(), Box::new(pk.clone()));
    }
    keys
}

fn output(rec: robodr_ocsf::Record) -> FindingOutput {
    FindingOutput {
        topic: rec.topic.to_string(),
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

/// Spool `n` findings, round-robin over [`ROBOTS`], signed if `sign`; the
/// expected record of each (partition for [`PARTITIONS`]) keyed by id.
fn spool(
    dir: &Path,
    from: u64,
    n: u64,
    sign: bool,
    robots: &[&str],
) -> BTreeMap<String, robodr_ocsf::Record> {
    let mut s = Spool::open(dir, 1 << 34, 10_000_000).unwrap();
    let signer = finding_signer();
    let mut want = BTreeMap::new();
    for i in from..from + n {
        let robot = robots[(i % robots.len() as u64) as usize];
        let env = finding_for(robot, run_base() + i);
        // The agent computes the partition for whatever count it was told
        // (here 7): the publisher must override it with the topic's count.
        let mut rec = robodr_ocsf::record(&env, Some(7)).unwrap();
        if sign {
            robodr_ocsf::sign_record(&mut rec, &signer).unwrap();
        }
        let mut expect = rec.clone();
        expect.partition = robodr_ocsf::record(&env, Some(PARTITIONS))
            .unwrap()
            .partition;
        s.write(&output(rec), robodr_agentd::SpoolClass::Normal)
            .unwrap();
        want.insert(expect.key.clone(), expect);
    }
    want
}

fn count(dir: &Path) -> usize {
    fs::read_dir(dir).map(|d| d.count()).unwrap_or(0)
}

/// Every expected record present exactly `times(key)` times, with the
/// documented partition, key, value bytes, headers (contract order,
/// signature last and verifying), CreateTime ~ publish time, a producer id
/// (>= 0, idempotent; -1 only with idempotence off) and per-partition
/// offsets strictly increasing.
fn check(
    got: &[Fetched],
    want: &BTreeMap<String, robodr_ocsf::Record>,
    times: impl Fn(&str) -> usize,
    t_start: u64,
) {
    let mut by_key: HashMap<String, Vec<&Fetched>> = HashMap::new();
    for f in got {
        by_key.entry(f.key()).or_default().push(f);
    }
    // One mode per check: all idempotent, or all without a producer id.
    let modes: std::collections::BTreeSet<bool> = got.iter().map(|f| f.producer_id >= 0).collect();
    assert!(modes.len() <= 1, "mixed producer ids");
    let unexpected: Vec<&String> = by_key.keys().filter(|k| !want.contains_key(*k)).collect();
    assert!(unexpected.is_empty(), "unexpected keys: {unexpected:?}");
    let keys = verifying_keys();
    for (k, w) in want {
        let fs = by_key.get(k).map(Vec::as_slice).unwrap_or(&[]);
        assert_eq!(fs.len(), times(k), "copies of {k}");
        for f in fs {
            assert_eq!(Some(f.partition as u32), w.partition, "partition of {k}");
            assert_eq!(f.value(), w.value, "value bytes of {k}");
            let wh: Vec<(String, String)> = w
                .headers
                .iter()
                .map(|(a, b)| (a.to_string(), b.clone()))
                .collect();
            assert_eq!(f.headers(), wh, "headers of {k}");
            assert!(f.producer_id >= -1, "producer id of {k}");
            let ts = f.rec.timestamp_ms as u64;
            assert!(
                ts + 1000 >= t_start && ts <= now_ms() + 1000,
                "CreateTime {ts} of {k} not the publish time"
            );
            if w.headers.iter().any(|(h, _)| *h == robodr_ocsf::SIG_HEADER) {
                let sig = f
                    .headers()
                    .last()
                    .filter(|(h, _)| h == robodr_ocsf::SIG_HEADER)
                    .map(|(_, v)| v.clone());
                let v = robodr_ocsf::parse_and_validate_signed(
                    &f.value(),
                    sig.as_deref(),
                    &keys,
                    robodr_ocsf::SignaturePolicy::Strict,
                )
                .unwrap_or_else(|e| panic!("signature of {k}: {e:?}"));
                assert!(matches!(
                    v.signature,
                    robodr_ocsf::SignatureStatus::Verified { .. }
                ));
            }
        }
    }
    let mut last: HashMap<i32, i64> = HashMap::new();
    for f in got {
        if let Some(prev) = last.insert(f.partition, f.offset) {
            assert!(f.offset > prev, "offsets of partition {}", f.partition);
        }
    }
}

struct KillOnDrop(std::process::Child);

impl KillOnDrop {
    fn stop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        self.stop();
    }
}

// ----------------------------------------------------------------- tests

/// The binary, `--spool` source: 300 signed findings of three robots in
/// chunks of 40, each delivered exactly once with the documented
/// partition/key/headers; the spool is fully acknowledged; a second run
/// sends nothing.
#[test]
#[ignore = "needs a Kafka broker: ROBODR_KAFKA_BROKER (scripts/kafka-it.sh)"]
fn real_cli_spool_signed_exactly_once() {
    let Some(b) = broker() else { return };
    let t = TempDir::new("real-cli");
    let sp = t.path().join("spool");
    let want = spool(&sp, 0, 300, true, &ROBOTS);
    let mut c = Consumer::connect(&b);
    let marks = c.marks(TOPIC, PARTITIONS);
    let t0 = now_ms();
    for _ in 0..2 {
        let o = Command::new(PUBLISH)
            .args([
                "--bootstrap",
                &b,
                "--allow-plaintext",
                "--once",
                "--chunk",
                "40",
            ])
            .args(["--spool".as_ref(), sp.as_os_str()])
            .args(["--state-dir".as_ref(), t.path().join("soc").as_os_str()])
            .output()
            .unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    }
    let got = c.since(TOPIC, &marks);
    assert_eq!(got.len(), 300);
    check(&got, &want, |_| 1, t0);
    assert_eq!(count(&sp.join("ready")), 0);
    assert_eq!(count(&sp.join("acked")), 300);
    assert_eq!(count(&sp.join("rejected")), 0);
    let prog: serde_json::Value =
        serde_json::from_slice(&fs::read(t.path().join("soc/progress.json")).unwrap()).unwrap();
    assert_eq!(prog["published_total"], 300);
    // Every partition the robots hash to got records.
    let used: std::collections::BTreeSet<i32> = got.iter().map(|f| f.partition).collect();
    let expect: std::collections::BTreeSet<i32> =
        want.values().map(|r| r.partition.unwrap() as i32).collect();
    assert_eq!(used, expect);
}

/// Robot side to SOC side through the diode: agentd spool -> exporter ->
/// packer -> (copy) -> importer -> publisher -> Kafka, exactly once.
#[test]
#[ignore = "needs a Kafka broker: ROBODR_KAFKA_BROKER (scripts/kafka-it.sh)"]
fn real_diode_path_exactly_once() {
    let Some(b) = broker() else { return };
    let t = TempDir::new("real-diode");
    let sp = t.path().join("spool");
    let outbox = t.path().join("outbox");
    let high = t.path().join("high");
    fs::create_dir_all(&outbox).unwrap();
    fs::create_dir_all(high.join("inbox")).unwrap();
    let want = spool(&sp, 1000, 120, false, &[UNIT]);
    let signer = Box::new(Ed25519SigningKey::from_seed(DKEY, &DSEED).unwrap());
    let packer = Packer::open(
        &outbox,
        t.path().join("pack.json"),
        PackConfig::new(UNIT),
        signer,
    )
    .unwrap();
    let mut x =
        Exporter::open(ExportConfig::new(&sp, t.path().join("export.json")), packer).unwrap();
    assert_eq!(x.run_once(NOW).unwrap().exported, 120);
    drop(x);
    for e in fs::read_dir(&outbox).unwrap() {
        let e = e.unwrap();
        let name = e.file_name();
        if name.to_string_lossy().starts_with('.') {
            continue;
        }
        let to = high.join("inbox").join(&name);
        fs::create_dir_all(&to).unwrap();
        for f in fs::read_dir(e.path()).unwrap() {
            let f = f.unwrap();
            fs::copy(f.path(), to.join(f.file_name())).unwrap();
        }
    }
    let mut ring = Keyring::new();
    let pk = robodr_blackbox::KeyFile::ed25519_from_seed(&DSEED, Some(DKEY))
        .unwrap()
        .to_public()
        .unwrap()
        .ed25519_verifying_key()
        .unwrap();
    ring.add(UNIT, Box::new(pk)).unwrap();
    let mut ic = ImportConfig::under(&high);
    ic.partitions = Some(7);
    let imp = Importer::open(ic, ring).unwrap().run(NOW).unwrap();
    assert_eq!(imp.accepted.len(), 1, "{imp:?}");

    let mut c = Consumer::connect(&b);
    let marks = c.marks(TOPIC, PARTITIONS);
    let t0 = now_ms();
    let mut cfg = PublishConfig::new(Source::DiodeOut(high.join("out")), t.path().join("soc"));
    cfg.chunk_records = 25;
    let mut p = Publisher::open(cfg, Producer::new(producer_cfg(&b)).unwrap()).unwrap();
    let rep = p.run_once().unwrap();
    assert_eq!(rep.published, 120);
    assert_eq!(rep.batches_done.len(), 1);
    assert_eq!(p.run_once().unwrap().published, 0, "done marker honoured");
    let got = c.since(TOPIC, &marks);
    check(&got, &want, |_| 1, t0);
}

/// A crash after Kafka acknowledged chunk 2 but before it was committed:
/// the restarted publisher re-sends exactly that chunk, nothing is lost.
/// Idempotent (the default): the broker drops the copy, every record once.
/// With idempotence off: that chunk is in the topic twice.
#[test]
#[ignore = "needs a Kafka broker: ROBODR_KAFKA_BROKER (scripts/kafka-it.sh)"]
fn real_resume_after_crash_is_deduplicated() {
    let Some(b) = broker() else { return };
    for idempotence in [true, false] {
        resume_after_crash(&b, idempotence);
    }
}

fn resume_after_crash(b: &str, idempotence: bool) {
    let t = TempDir::new(if idempotence {
        "real-resume-idem"
    } else {
        "real-resume"
    });
    let sp = t.path().join("spool");
    let want = spool(&sp, 2000, 100, true, &ROBOTS);
    let mut c = Consumer::connect(b);
    let marks = c.marks(TOPIC, PARTITIONS);
    let t0 = now_ms();
    let mut pcfg = producer_cfg(b);
    pcfg.idempotence = idempotence;
    let mut cfg = PublishConfig::new(Source::Spool(sp.clone()), t.path().join("soc"));
    cfg.chunk_records = 25;
    cfg.fail_after_send = Some(2);
    let mut p = Publisher::open(cfg.clone(), Producer::new(pcfg.clone()).unwrap()).unwrap();
    assert!(p.run_once().is_err(), "injected crash");
    drop(p);
    assert_eq!(count(&sp.join("acked")), 25, "chunk 1 committed");
    // Chunk 2 = the spool's records 26..=50 (seq order = key order of the
    // second chunk as read from ready/).
    let mut ready: Vec<String> = fs::read_dir(sp.join("ready"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    ready.sort();
    let dup: std::collections::HashSet<String> = ready[..25]
        .iter()
        .map(|f| {
            let v: serde_json::Value =
                serde_json::from_slice(&fs::read(sp.join("ready").join(f)).unwrap()).unwrap();
            v["key"].as_str().unwrap().to_string()
        })
        .collect();
    cfg.fail_after_send = None;
    let mut p = Publisher::open(cfg, Producer::new(pcfg.clone()).unwrap()).unwrap();
    assert_eq!(p.run_once().unwrap().published, 75);
    assert_eq!(count(&sp.join("ready")), 0);
    assert_eq!(count(&sp.join("acked")), 100);
    let got = c.since(TOPIC, &marks);
    if idempotence {
        assert_eq!(got.len(), 100, "the broker dropped the re-sent chunk");
        check(&got, &want, |_| 1, t0);
    } else {
        assert_eq!(got.len(), 125);
        check(&got, &want, |k| if dup.contains(k) { 2 } else { 1 }, t0);
    }
}

/// 5 000 findings in chunks of 1 000 (requests split under
/// `max_request_bytes`), exactly once.
#[test]
#[ignore = "needs a Kafka broker: ROBODR_KAFKA_BROKER (scripts/kafka-it.sh)"]
fn real_large_backlog() {
    let Some(b) = broker() else { return };
    let t = TempDir::new("real-large");
    let sp = t.path().join("spool");
    let want = spool(&sp, 10_000, 5_000, true, &ROBOTS);
    let mut c = Consumer::connect(&b);
    let marks = c.marks(TOPIC, PARTITIONS);
    let t0 = now_ms();
    let mut cfg = PublishConfig::new(Source::Spool(sp.clone()), t.path().join("soc"));
    cfg.chunk_records = 1000;
    let mut p = Publisher::open(cfg, Producer::new(producer_cfg(&b)).unwrap()).unwrap();
    let rep = p.run_once().unwrap();
    assert_eq!(rep.published, 5_000);
    let st = p.sink().stats();
    assert!(st.requests >= 5, "{st:?}");
    let got = c.since(TOPIC, &marks);
    assert_eq!(got.len(), 5_000);
    check(&got, &want, |_| 1, t0);
}

fn plain(i: usize, size: usize) -> ProduceRecord {
    ProduceRecord {
        key: Some(format!("k-{}-{i}", run_base()).into_bytes()),
        value: Some(format!("{i:06}{}", "x".repeat(size)).into_bytes()),
        headers: vec![("robot-id".into(), b"ugv-007".to_vec())],
        timestamp_ms: now_ms() as i64,
    }
}

/// A record above the topic's `max.message.bytes` is rejected
/// (MESSAGE_TOO_LARGE / RECORD_LIST_TOO_LARGE) and isolated; the records
/// around it are delivered, in order.
#[test]
#[ignore = "needs a Kafka broker: ROBODR_KAFKA_BROKER (scripts/kafka-it.sh)"]
fn real_oversize_record_isolated() {
    let Some(b) = broker() else { return };
    let mut p = Producer::new(producer_cfg(&b)).unwrap();
    assert_eq!(p.partition_count(SMALL_TOPIC).unwrap(), 1);
    let mut c = Consumer::connect(&b);
    let marks = c.marks(SMALL_TOPIC, 1);
    // 12 x ~1 KB: fits per record, not in one 4 KiB batch; #5 is 8 KB.
    let input: Vec<(i32, ProduceRecord)> = (0..12)
        .map(|i| (0, plain(i, if i == 5 { 8000 } else { 1000 })))
        .collect();
    let out = p.send(SMALL_TOPIC, &input).unwrap();
    eprintln!("oversize: {:?}", p.stats());
    for (i, o) in out.iter().enumerate() {
        if i == 5 {
            assert!(
                matches!(o, Outcome::Rejected { code: 10 | 18, .. }),
                "{i}: {o:?}"
            );
        } else {
            assert!(matches!(o, Outcome::Delivered { .. }), "{i}: {o:?}");
        }
    }
    let got = c.since(SMALL_TOPIC, &marks);
    let order: Vec<usize> = got
        .iter()
        .map(|f| f.value()[..6].parse().unwrap())
        .collect();
    assert_eq!(order, vec![0, 1, 2, 3, 4, 6, 7, 8, 9, 10, 11]);
    // Delivered offsets are the broker's.
    for (f, o) in got.iter().zip(
        out.iter()
            .filter(|o| matches!(o, Outcome::Delivered { .. })),
    ) {
        assert_eq!(
            o,
            &Outcome::Delivered {
                partition: 0,
                offset: f.offset
            }
        );
    }
}

/// A topic that does not exist: the publisher fails (no auto-creation),
/// commits nothing, and says why.
#[test]
#[ignore = "needs a Kafka broker: ROBODR_KAFKA_BROKER (scripts/kafka-it.sh)"]
fn real_unknown_topic_commits_nothing() {
    let Some(b) = broker() else { return };
    let t = TempDir::new("real-unknown");
    let sp = t.path().join("spool");
    spool(&sp, 3000, 3, false, &ROBOTS);
    let started = Instant::now();
    let o = Command::new(PUBLISH)
        .args([
            "--bootstrap",
            &b,
            "--allow-plaintext",
            "--once",
            "--retries",
            "3",
        ])
        .args(["--topic", "robodr-it-does-not-exist"])
        .args(["--spool".as_ref(), sp.as_os_str()])
        .args(["--state-dir".as_ref(), t.path().join("soc").as_os_str()])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("UNKNOWN_TOPIC_OR_PARTITION"), "{err}");
    assert!(started.elapsed() < Duration::from_secs(30));
    assert_eq!(count(&sp.join("ready")), 3);
    assert_eq!(count(&sp.join("acked")), 0);
    let mut cfg = producer_cfg(&b);
    cfg.retries = 1;
    let mut p = Producer::new(cfg).unwrap();
    let e = p.partition_count("robodr-it-does-not-exist").unwrap_err();
    assert!(matches!(e, ProduceError::RetriesExhausted(_)), "{e}");
    assert!(e.to_string().contains("UNKNOWN_TOPIC_OR_PARTITION"), "{e}");
}

/// An ACL denying WRITE: a fatal TOPIC_AUTHORIZATION_FAILED, not retried.
#[test]
#[ignore = "needs a Kafka broker: ROBODR_KAFKA_BROKER (scripts/kafka-it.sh)"]
fn real_authorization_failure_is_fatal() {
    let Some(b) = broker() else { return };
    let mut p = Producer::new(producer_cfg(&b)).unwrap();
    let started = Instant::now();
    let e = p.send(DENIED_TOPIC, &[(0, plain(0, 10))]).unwrap_err();
    assert!(matches!(e, ProduceError::Fatal { code: 29, .. }), "{e}");
    assert!(started.elapsed() < Duration::from_secs(10), "not retried");
}

/// Without SASL configured, against a SASL_PLAINTEXT listener the client
/// must fail in bounded time with an error naming the cause, never hang or
/// panic.
#[test]
#[ignore = "needs a Kafka broker: ROBODR_KAFKA_SASL_BROKER (scripts/kafka-it.sh)"]
fn real_sasl_listener_fails_cleanly() {
    let Some(sasl) = std::env::var("ROBODR_KAFKA_SASL_BROKER")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        eprintln!("skipped: ROBODR_KAFKA_SASL_BROKER is not set");
        return;
    };
    let mut cfg = producer_cfg(&sasl);
    cfg.retries = 2;
    let mut p = Producer::new(cfg).unwrap();
    let started = Instant::now();
    let e = p.partition_count(TOPIC).unwrap_err();
    eprintln!("SASL listener: {e}");
    assert!(started.elapsed() < Duration::from_secs(30));
    assert!(e.to_string().contains("SASL"), "{e}");
}

/// The broker is restarted while a backlog is being published (the
/// binary's own loop: errors are retried): nothing is lost, and every
/// duplicate is a re-send of an unacknowledged request.
#[test]
#[ignore = "needs a Kafka broker: ROBODR_KAFKA_BROKER + ROBODR_KAFKA_RESTART_CMD"]
fn real_broker_restart_mid_stream() {
    let Some(b) = broker() else { return };
    let Some(cmd) = std::env::var("ROBODR_KAFKA_RESTART_CMD")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        eprintln!("skipped: ROBODR_KAFKA_RESTART_CMD is not set");
        return;
    };
    let t = TempDir::new("real-restart");
    let sp = t.path().join("spool");
    let want = spool(&sp, 20_000, 3_000, true, &ROBOTS);
    let mut c = Consumer::connect(&b);
    let marks = c.marks(TOPIC, PARTITIONS);
    drop(c);
    let t0 = now_ms();
    let child = Command::new(PUBLISH)
        .args([
            "--bootstrap",
            &b,
            "--allow-plaintext",
            "--chunk",
            "20",
            "--interval-ms",
            "200",
        ])
        .args(["--delivery-timeout-ms", "180000", "--retries", "30"])
        .args(["--spool".as_ref(), sp.as_os_str()])
        .args(["--state-dir".as_ref(), t.path().join("soc").as_os_str()])
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    // Killed on every exit path (a panic must not leave it running).
    let mut child = KillOnDrop(child);
    // Restart once some, but not all, records are acknowledged.
    let deadline = Instant::now() + Duration::from_secs(60);
    while count(&sp.join("acked")) < 200 {
        assert!(Instant::now() < deadline, "publisher made no progress");
        std::thread::sleep(Duration::from_millis(20));
    }
    let acked_before = count(&sp.join("acked"));
    let st = Command::new("sh").args(["-c", &cmd]).status().unwrap();
    assert!(st.success(), "restart command failed");
    let deadline = Instant::now() + Duration::from_secs(240);
    while count(&sp.join("ready")) > 0 {
        assert!(
            Instant::now() < deadline,
            "backlog not drained after restart"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    child.stop();
    assert!(acked_before < 3_000, "restart happened mid-stream");
    assert_eq!(count(&sp.join("acked")), 3_000);
    let mut c = Consumer::connect(&b);
    let got = c.since(TOPIC, &marks);
    let mut n: HashMap<String, usize> = HashMap::new();
    for f in &got {
        *n.entry(f.key()).or_default() += 1;
    }
    let dups = got.len() - n.len();
    eprintln!("restart: {} records, {dups} duplicates", got.len());
    check(&got, &want, |k| n.get(k).copied().unwrap_or(0).max(1), t0);
    // At-least-once, bounded: a duplicate only comes from requests in
    // flight around the restart (one chunk = at most 20 records each).
    assert!(dups <= 100, "{dups} duplicates");
}

/// Plain TCP (allowed explicitly) to a TLS listener: the broker answers the
/// plaintext ApiVersions with a TLS alert; the error must say so (and the
/// client never retries in TLS on its own).
#[test]
#[ignore = "needs a Kafka broker: ROBODR_KAFKA_TLS_BROKER (scripts/kafka-it.sh)"]
fn real_tls_listener_fails_cleanly() {
    let Some(tls) = std::env::var("ROBODR_KAFKA_TLS_BROKER")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        eprintln!("skipped: ROBODR_KAFKA_TLS_BROKER is not set");
        return;
    };
    let mut cfg = producer_cfg(&tls);
    cfg.retries = 2;
    let mut p = Producer::new(cfg).unwrap();
    let started = Instant::now();
    let e = p.partition_count(TOPIC).unwrap_err();
    eprintln!("TLS listener: {e}");
    assert!(started.elapsed() < Duration::from_secs(30));
    assert!(e.to_string().contains("TLS record"), "{e}");
}

/// Contract §4 partitioning against the Java client: `scripts/kafka-it.sh`
/// produces one record per robot id (key = robot id) to the 12-partition
/// topic `robodr-it-murmur` with `kafka-console-producer`, i.e. the Java
/// client's `toPositive(murmur2(key)) % 12`. Our `partition_for` must put
/// every robot id where Java did.
#[test]
#[ignore = "needs a Kafka broker: ROBODR_KAFKA_BROKER (scripts/kafka-it.sh)"]
fn real_partitioner_matches_java_client() {
    let Some(b) = broker() else { return };
    let mut c = Consumer::connect(&b);
    let got = c.since("robodr-it-murmur", &[0; 12]);
    assert!(
        got.len() >= 100,
        "{} keyed records (run the script)",
        got.len()
    );
    for f in &got {
        let robot = f.key();
        assert_eq!(
            robodr_ocsf::partition_for(&robot, 12),
            Some(f.partition as u32),
            "robot id {robot:?}"
        );
    }
}

/// The broker closes connections idle for `connections.max.idle.ms`
/// (`ROBODR_KAFKA_IDLE_MS`, set low by the script). With the client's idle
/// limit above the broker's, the next send hits the closed connection,
/// reconnects and delivers exactly once; below it, the client reconnects
/// up front without any error or retry.
#[test]
#[ignore = "needs a Kafka broker: ROBODR_KAFKA_BROKER + ROBODR_KAFKA_IDLE_MS"]
fn real_idle_connection_closed_by_broker() {
    let Some(b) = broker() else { return };
    let Some(idle) = std::env::var("ROBODR_KAFKA_IDLE_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    else {
        eprintln!("skipped: ROBODR_KAFKA_IDLE_MS is not set");
        return;
    };
    let mut c = Consumer::connect(&b);
    let marks = c.marks(SMALL_TOPIC, 1);
    drop(c);
    let mut stale = Producer::new(producer_cfg(&b)).unwrap();
    let mut cf = producer_cfg(&b);
    cf.connections_max_idle = Duration::from_millis(idle / 2);
    let mut fresh = Producer::new(cf).unwrap();
    for (i, p) in [&mut stale, &mut fresh].into_iter().enumerate() {
        assert!(matches!(
            p.send(SMALL_TOPIC, &[(0, plain(2 * i, 10))]).unwrap()[0],
            Outcome::Delivered { .. }
        ));
    }
    // Idle connections are reaped on the broker's next check after the
    // limit; wait comfortably past it.
    std::thread::sleep(Duration::from_millis(idle * 2 + 5_000));
    for (i, p) in [&mut stale, &mut fresh].into_iter().enumerate() {
        assert!(matches!(
            p.send(SMALL_TOPIC, &[(0, plain(2 * i + 1, 10))]).unwrap()[0],
            Outcome::Delivered { .. }
        ));
    }
    eprintln!("idle: stale {:?}, fresh {:?}", stale.stats(), fresh.stats());
    assert!(stale.stats().io_errors >= 1, "the broker closed it");
    assert_eq!(fresh.stats().io_errors, 0);
    assert_eq!(fresh.stats().retries, 0);
    let mut c = Consumer::connect(&b);
    let got = c.since(SMALL_TOPIC, &marks);
    let mut order: Vec<usize> = got
        .iter()
        .map(|f| f.value()[..6].parse().unwrap())
        .collect();
    order.sort();
    assert_eq!(
        order,
        vec![0, 1, 2, 3],
        "exactly once across the reconnects"
    );
}

/// A produce quota (`producer_byte_rate` 64 KiB/s) on client id
/// `robodr-it-throttled` (set by the script): the broker throttles; every
/// record still arrives exactly once and no request times out.
#[test]
#[ignore = "needs a Kafka broker: ROBODR_KAFKA_BROKER + ROBODR_KAFKA_QUOTA=1"]
fn real_quota_throttling() {
    let Some(b) = broker() else { return };
    if std::env::var("ROBODR_KAFKA_QUOTA").ok().as_deref() != Some("1") {
        eprintln!("skipped: ROBODR_KAFKA_QUOTA is not set");
        return;
    }
    let t = TempDir::new("real-quota");
    let sp = t.path().join("spool");
    let want = spool(&sp, 40_000, 300, true, &ROBOTS);
    let mut c = Consumer::connect(&b);
    let marks = c.marks(TOPIC, PARTITIONS);
    let t0 = now_ms();
    let mut pc = producer_cfg(&b);
    pc.client_id = "robodr-it-throttled".into();
    let mut cfg = PublishConfig::new(Source::Spool(sp.clone()), t.path().join("soc"));
    // Small chunks: each request's throttle (~2.5 s) stays below the
    // script broker's 10 s connections.max.idle.ms, which also expires a
    // connection muted for throttling.
    cfg.chunk_records = 25;
    let mut p = Publisher::open(cfg, Producer::new(pc).unwrap()).unwrap();
    let started = Instant::now();
    assert_eq!(p.run_once().unwrap().published, 300);
    let st = p.sink().stats();
    eprintln!("quota: {:?} in {:?}", st, started.elapsed());
    assert_eq!(st.io_errors, 0, "no request timed out: {st:?}");
    // ~1.9 MB at 64 KiB/s: the broker must actually have throttled.
    assert!(started.elapsed() >= Duration::from_secs(5), "not throttled");
    let got = c.since(TOPIC, &marks);
    check(&got, &want, |_| 1, t0);
}

// ------------------------------------------------------- TLS / SASL / mTLS

fn env(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => {
            eprintln!("skipped: {name} is not set (see scripts/kafka-tls-it.sh)");
            None
        }
    }
}

/// A private copy of the PKI (keys 0600) and a TLS client from it.
struct Pki(TempDir);

impl Pki {
    fn new() -> Option<Self> {
        use std::os::unix::fs::PermissionsExt;
        let src = std::path::PathBuf::from(env("ROBODR_KAFKA_TLS_PKI")?);
        let d = TempDir::new("real-pki");
        for n in [
            "ca.pem",
            "other-ca.pem",
            "client.pem",
            "client.key",
            "other-client.pem",
            "other-client.key",
        ] {
            fs::copy(src.join(n), d.path().join(n)).unwrap();
            let mode = if n.ends_with(".key") { 0o600 } else { 0o644 };
            fs::set_permissions(d.path().join(n), fs::Permissions::from_mode(mode)).unwrap();
        }
        Some(Pki(d))
    }

    fn client(
        &self,
        ca: &str,
        cert: Option<&str>,
        name: Option<&str>,
    ) -> robodr_blackbox::tls::ClientTls {
        let p = |n: &str| self.0.path().join(n);
        robodr_blackbox::tls::load_client(&robodr_blackbox::tls::ClientTlsFiles {
            ca_file: p(ca),
            cert_chain: cert.map(|c| p(&format!("{c}.pem"))),
            key_file: cert.map(|c| p(&format!("{c}.key"))),
            server_name: name.map(str::to_string),
            spki_sha256: vec![],
        })
        .unwrap()
    }
}

fn tls_cfg(b: &str, t: robodr_blackbox::tls::ClientTls) -> ProducerConfig {
    let mut p = producer_cfg(b);
    p.allow_plaintext = false;
    p.tls = Some(t);
    p.retries = 2;
    p
}

/// Send `n` records over `cfg` and read them back over the plain listener.
fn deliver_and_read_back(cfg: ProducerConfig, n: usize, tag: &str) -> Producer {
    let b = broker().expect("ROBODR_KAFKA_BROKER");
    let mut c = Consumer::connect(&b);
    let marks = c.marks(TOPIC, PARTITIONS);
    let mut p = Producer::new(cfg).unwrap();
    let recs: Vec<(i32, ProduceRecord)> = (0..n)
        .map(|i| {
            let mut r = plain(i, 10);
            r.key = Some(format!("{tag}-{}-{i}", run_base()).into_bytes());
            ((i % PARTITIONS as usize) as i32, r)
        })
        .collect();
    let out = p.send(TOPIC, &recs).unwrap();
    assert!(
        out.iter().all(|o| matches!(o, Outcome::Delivered { .. })),
        "{out:?}"
    );
    let got = c.since(TOPIC, &marks);
    let mine = got
        .iter()
        .filter(|f| f.key().starts_with(&format!("{tag}-{}-", run_base())))
        .count();
    assert_eq!(mine, n, "read back over the plain listener");
    p
}

#[test]
#[ignore = "needs a Kafka TLS listener: scripts/kafka-tls-it.sh"]
fn real_tls_round_trip_and_refusals() {
    let (Some(pki), Some(tls)) = (Pki::new(), env("ROBODR_KAFKA_TLS_BROKER")) else {
        return;
    };
    if broker().is_none() {
        return;
    }
    deliver_and_read_back(tls_cfg(&tls, pki.client("ca.pem", None, None)), 24, "tls");
    // The advertised `localhost` listeners are verified too (metadata
    // routes every partition's leader through them).
    for (what, t) in [
        ("unrelated CA", pki.client("other-ca.pem", None, None)),
        (
            "wrong name",
            pki.client("ca.pem", None, Some("wrong.example")),
        ),
    ] {
        let mut p = Producer::new(tls_cfg(&tls, t)).unwrap();
        let e = p.partition_count(TOPIC).unwrap_err().to_string();
        eprintln!("{what}: {e}");
        assert!(e.contains("certificate"), "{what}: {e}");
    }
}

#[test]
#[ignore = "needs a Kafka mTLS listener: scripts/kafka-tls-it.sh"]
fn real_mtls_round_trip_and_refusals() {
    let (Some(pki), Some(mtls)) = (Pki::new(), env("ROBODR_KAFKA_MTLS_BROKER")) else {
        return;
    };
    if broker().is_none() {
        return;
    }
    deliver_and_read_back(
        tls_cfg(&mtls, pki.client("ca.pem", Some("client"), None)),
        12,
        "mtls",
    );
    for (what, cert) in [
        ("no client certificate", None),
        ("foreign client", Some("other-client")),
    ] {
        let mut p = Producer::new(tls_cfg(&mtls, pki.client("ca.pem", cert, None))).unwrap();
        let e = p.partition_count(TOPIC).unwrap_err().to_string();
        eprintln!("{what}: {e}");
    }
}

#[test]
#[ignore = "needs a Kafka SASL_SSL SCRAM listener: scripts/kafka-tls-it.sh"]
fn real_scram_over_tls() {
    use robodr_export::kafka::sasl::{Mechanism, SaslConfig};
    let (Some(pki), Some(scram), Some(user), Some(pw)) = (
        Pki::new(),
        env("ROBODR_KAFKA_SCRAM_BROKER"),
        env("ROBODR_KAFKA_SCRAM_USER"),
        env("ROBODR_KAFKA_SCRAM_PASSWORD"),
    ) else {
        return;
    };
    if broker().is_none() {
        return;
    }
    let cfg = |m: Mechanism, pw: &str| {
        let mut c = tls_cfg(&scram, pki.client("ca.pem", None, None));
        c.sasl = Some(SaslConfig::new(m, &user, pw).unwrap());
        c
    };
    for (m, tag) in [
        (Mechanism::ScramSha256, "scram256"),
        (Mechanism::ScramSha512, "scram512"),
    ] {
        deliver_and_read_back(cfg(m, &pw), 12, tag);
    }
    // Wrong password: fatal, not retried.
    let started = Instant::now();
    let mut p = Producer::new(cfg(Mechanism::ScramSha512, "not-the-password")).unwrap();
    let e = p.partition_count(TOPIC).unwrap_err();
    eprintln!("wrong password: {e}");
    assert!(matches!(e, ProduceError::Fatal { code: 58, .. }), "{e}");
    assert!(started.elapsed() < Duration::from_secs(10));
    // The listener's connections.max.reauth.ms: the producer reconnects
    // (a fresh authentication) before the broker would cut the session.
    if let Some(ms) = std::env::var("ROBODR_KAFKA_SCRAM_REAUTH_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        let mut p = deliver_and_read_back(cfg(Mechanism::ScramSha256, &pw), 2, "reauth1");
        let before = p.stats();
        std::thread::sleep(Duration::from_millis(ms + 500));
        let out = p.send(TOPIC, &[(0, plain(1, 10))]).unwrap();
        assert!(matches!(out[0], Outcome::Delivered { .. }), "{out:?}");
        let after = p.stats();
        eprintln!("reauth: {before:?} -> {after:?}");
        assert!(after.connects > before.connects);
        assert_eq!(after.io_errors, before.io_errors, "no failed request");
    }
}
