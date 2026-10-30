//! Review O2 (T84): `GET .../evidence` (the inventory) indexed the black box
//! by reading each segment whole and decoding every record into a second
//! in-memory copy, so agentd's RSS rose by about twice a segment per call.
//! The index now streams frames: its peak heap is the per-record metadata
//! plus one frame, independent of the segment size.
//!
//! This binary holds one test only: the counting allocator is global.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use robodr_agentd::control::evidence::{index, inventory, DirSource, SegmentSource};
use robodr_blackbox::{
    Ed25519SigningKey, Recorder, RecorderConfig, RetentionMode, SystemClock, TimeSource,
};

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards to the system allocator unchanged; only counts.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        // SAFETY: same contract as the caller's.
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            let now = LIVE.fetch_add(l.size(), Ordering::SeqCst) + l.size();
            PEAK.fetch_max(now, Ordering::SeqCst);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(p, l) };
        LIVE.fetch_sub(l.size(), Ordering::SeqCst);
    }
}

#[global_allocator]
static A: Counting = Counting;

const SEGMENT: u64 = 4 * 1024 * 1024;

/// The same directory, read whole (the pre-O2 path).
struct Whole(DirSource);

impl SegmentSource for Whole {
    fn list(&self) -> std::io::Result<Vec<u64>> {
        self.0.list()
    }
    fn read(&self, idx: u64) -> std::io::Result<Option<Vec<u8>>> {
        self.0.read(idx)
    }
}

#[test]
fn inventory_heap_does_not_scale_with_segment_size() {
    let dir = std::env::temp_dir().join(format!("robodr-o2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let bb = dir.join("bb");
    let mut c = RecorderConfig::new(&bb, "ugv-o2", "boot");
    c.max_segment_bytes = SEGMENT;
    c.mode = RetentionMode::Cyclic { max_segments: 4 };
    let key = Ed25519SigningKey::from_seed("bb", &[5; 32]).unwrap();
    let mut r = Recorder::open(
        c,
        Box::new(key),
        Box::new(SystemClock::new(TimeSource::Unknown)),
    )
    .unwrap();
    // Two closed segments and a large open one (the case the soak
    // measured), of 2 KiB notes.
    let pad = "x".repeat(2048);
    let mut n = 0u64;
    while r.segments().len() < 3 {
        r.append_note(&serde_json::json!({"i": n, "pad": pad}), false)
            .unwrap();
        n += 1;
    }
    for _ in 0..1000 {
        r.append_note(&serde_json::json!({"i": n, "pad": pad}), false)
            .unwrap();
        n += 1;
    }
    r.mark_head().unwrap();
    let src = DirSource(bb.clone());

    let base = LIVE.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    let ix = index(&src).unwrap();
    let v = inventory(&ix, "ugv-o2");
    let peak = PEAK.load(Ordering::SeqCst) - base;

    assert_eq!(
        ix.records.len() as u64,
        v["retained"]["records"].as_u64().unwrap()
    );
    assert!(ix.records.len() > 4000, "{}", ix.records.len());
    // Before the fix: at least one whole segment (4 MiB) plus a decoded
    // copy of its records (about as much again); now the metadata of the
    // records (72 bytes each) and one read buffer.
    assert!(
        peak < (SEGMENT / 2) as usize,
        "indexing {} records peaked at {peak} heap bytes",
        ix.records.len()
    );

    // The streamed index is the one the whole-segment scan gives, and the
    // whole-segment scan (what every segment used to cost) is what this
    // test would have measured before the fix.
    let base = LIVE.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    let whole = index(&Whole(src)).unwrap();
    let whole_peak = PEAK.load(Ordering::SeqCst) - base;
    assert!(whole_peak > SEGMENT as usize, "{whole_peak}");
    eprintln!("streamed peak {peak} B, whole-segment peak {whole_peak} B");
    assert_eq!(whole.records, ix.records);
    assert_eq!(whole.keys, ix.keys);
    assert_eq!(whole.segment_bytes, ix.segment_bytes);
    drop(r);
    std::fs::remove_dir_all(&dir).unwrap();
}
