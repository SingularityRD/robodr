#![allow(dead_code)]

use robodr_blackbox::record::{scan_frames, Record, ScanItem};
use robodr_blackbox::verify::{read_segments, verify_segments};
use robodr_blackbox::*;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Unique temp dir removed on drop.
pub struct TestDir(pub PathBuf);

impl TestDir {
    pub fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!(
            "robodr-bb-{tag}-{}-{nanos}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).unwrap();
        TestDir(p)
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
    pub fn sub(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub const KEY: [u8; 32] = [0x42; 32];
pub const KEY_ID: &str = "unit-key";

pub fn signer() -> Box<dyn Signer> {
    Box::new(HmacSha256Key::new(KEY_ID, &KEY).unwrap())
}

pub fn verifier() -> HmacSha256Key {
    HmacSha256Key::new(KEY_ID, &KEY).unwrap()
}

pub fn clock() -> Box<dyn Clock> {
    Box::new(SteppingClock::new(1_000_000, 1_000, TimeSource::Gps))
}

pub fn cfg(dir: &Path, mode: RetentionMode) -> RecorderConfig {
    let mut c = RecorderConfig::new(dir, "ugv-01", "boot-a");
    c.mode = mode;
    c.max_segment_bytes = 4096;
    c.fsync = FsyncPolicy::SealsOnly;
    c.seal_every_records = 0;
    c
}

pub fn big() -> RetentionMode {
    RetentionMode::Cyclic { max_segments: 1000 }
}

pub fn open(c: RecorderConfig) -> Recorder {
    Recorder::open(c, signer(), clock()).unwrap()
}

pub fn note(i: u64) -> serde_json::Value {
    serde_json::json!({ "i": i, "msg": "evidence note with some padding to fill segments" })
}

pub fn recorded(o: AppendOutcome) -> u64 {
    match o {
        AppendOutcome::Recorded { seq, .. } => seq,
        AppendOutcome::Refused(r) => panic!("refused: {r:?}"),
    }
}

/// A closed multi-segment log with `n` notes.
pub fn build_log(dir: &Path, n: u64) -> Checkpoint {
    let mut r = open(cfg(dir, big()));
    for i in 0..n {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    r.close().unwrap()
}

pub fn segs(dir: &Path) -> Vec<SegmentData> {
    read_segments(dir).unwrap()
}

pub fn write_segs(dir: &Path, segs: &[SegmentData]) {
    for s in segs {
        std::fs::write(dir.join(&s.name), &s.bytes).unwrap();
    }
}

/// `(offset, len, record)` of every decodable frame.
pub fn frames(bytes: &[u8]) -> Vec<(usize, usize, Record)> {
    scan_frames(bytes)
        .items
        .into_iter()
        .filter_map(|i| match i {
            ScanItem::Record(r) => Some((r.offset as usize, r.frame_len as usize, r.record)),
            ScanItem::Malformed { .. } => None,
        })
        .collect()
}

pub fn verify(segs: &[SegmentData]) -> Report {
    verify_segments(segs, &verifier(), &VerifyOptions::default())
}

pub fn verify_with(segs: &[SegmentData], opts: &VerifyOptions) -> Report {
    verify_segments(segs, &verifier(), opts)
}

pub fn tamper_kinds(r: &Report) -> Vec<FindingKind> {
    r.tamper().map(|f| f.kind.clone()).collect()
}

pub fn has(r: &Report, pred: impl Fn(&FindingKind) -> bool) -> bool {
    r.findings.iter().any(|f| pred(&f.kind))
}

pub fn dump(r: &Report) -> String {
    r.findings
        .iter()
        .map(|f| f.to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

/// All records (in order) of a directory.
pub fn all_records(dir: &Path) -> Vec<Record> {
    segs(dir)
        .iter()
        .flat_map(|s| frames(&s.bytes).into_iter().map(|(_, _, r)| r))
        .collect()
}

/// Deterministic xorshift64*.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}
