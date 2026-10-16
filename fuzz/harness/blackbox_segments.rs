//! Harness: black-box evidence parsing and verification (`robodr-blackbox`).
//!
//! The input is a recorder directory flattened into one byte string: parts
//! separated by [`SPLIT`]; a part starting with `{` is the directory's
//! `checkpoint.json`, every other part is a segment file (`seg-<idx>.rbb`
//! in order). The harness then
//!
//! 1. scans every segment (`record::scan_frames`) and checks that the scan
//!    is a faithful partition: items are in order, non-overlapping and in
//!    bounds, and every decoded record re-encodes to exactly the bytes it
//!    was decoded from (the decoder is strict/canonical);
//! 2. decodes the whole input as one frame body (`Record::decode_body`),
//!    with the same re-encoding invariant;
//! 3. verifies the segments in memory (`verify::verify_segments`) and, via
//!    a private temp directory, from disk (`verify::verify_dir`), which must
//!    not fail with an I/O error on a directory the harness wrote itself;
//! 4. parses the whole input as an export bundle (`Bundle::from_bytes`,
//!    which must round-trip through `to_bytes`) and verifies it, and as the
//!    JSON control files (checkpoint, cursor, ack).
//!
//! Hostile evidence must yield findings, never a panic.
#![allow(dead_code)]

use std::path::PathBuf;

use robodr_blackbox::record::{scan_frames, ScanItem, FRAME_HEADER_LEN};
use robodr_blackbox::store::{segment_file_name, CHECKPOINT_FILE};
use robodr_blackbox::verify::{verify_dir, verify_segments, SegmentData, VerifyOptions};
use robodr_blackbox::{Ack, Anchor, Bundle, Checkpoint, HmacSha256Key, Record, SignedCursor};

/// Separator between flattened directory entries.
pub const SPLIT: &[u8] = b"\n--RBX-SPLIT--\n";
/// Key id and key of the seed corpus chains.
pub const KEY_ID: &str = "fuzz-key";
pub const KEY: [u8; 32] = [0x42; 32];

pub fn verifier() -> HmacSha256Key {
    HmacSha256Key::new(KEY_ID, &KEY).expect("valid fuzz key")
}

/// Split the flattened input into (segments, checkpoint text).
pub fn split(data: &[u8]) -> (Vec<Vec<u8>>, Option<Vec<u8>>) {
    let mut parts = Vec::new();
    let mut rest = data;
    while let Some(i) = rest.windows(SPLIT.len()).position(|w| w == SPLIT) {
        parts.push(rest[..i].to_vec());
        rest = &rest[i + SPLIT.len()..];
    }
    parts.push(rest.to_vec());
    let mut segs = Vec::new();
    let mut ckpt = None;
    for p in parts {
        if p.first() == Some(&b'{') {
            ckpt = Some(p);
        } else {
            segs.push(p);
        }
    }
    (segs, ckpt)
}

/// Inverse of [`split`] (seed generation).
pub fn join(segments: &[Vec<u8>], checkpoint: Option<&[u8]>) -> Vec<u8> {
    let mut v = Vec::new();
    for (i, s) in segments.iter().enumerate() {
        if i > 0 {
            v.extend_from_slice(SPLIT);
        }
        v.extend_from_slice(s);
    }
    if let Some(c) = checkpoint {
        v.extend_from_slice(SPLIT);
        v.extend_from_slice(c);
    }
    v
}

fn check_scan(seg: &[u8]) {
    let scan = scan_frames(seg);
    let mut pos = 0u64;
    for item in &scan.items {
        match item {
            ScanItem::Record(r) => {
                assert_eq!(r.offset, pos, "scan gap/overlap at {pos}");
                let end = r.offset + r.frame_len;
                assert!(end <= seg.len() as u64, "record past end of segment");
                let bytes = &seg[r.offset as usize..end as usize];
                assert_eq!(
                    r.record.encode_frame(),
                    bytes,
                    "record at {} does not re-encode to its bytes",
                    r.offset
                );
                pos = end;
            }
            ScanItem::Malformed { offset, len, .. } => {
                assert_eq!(*offset, pos, "scan gap/overlap at {pos}");
                assert!(*len > 0, "empty malformed region");
                pos = offset + len;
                assert!(pos <= seg.len() as u64, "malformed region past end");
            }
        }
    }
    match scan.tail {
        Some(t) => {
            assert_eq!(t.offset, pos, "tail does not follow the last item");
            assert_eq!(
                t.offset + t.len,
                seg.len() as u64,
                "tail does not reach EOF"
            );
        }
        None => assert_eq!(pos, seg.len() as u64, "scan does not cover the segment"),
    }
}

fn scratch_path() -> PathBuf {
    let t = format!("{:?}", std::thread::current().id());
    let t: String = t.chars().filter(char::is_ascii_digit).collect();
    std::env::temp_dir().join(format!("robodr-fuzz-bb-{}-{t}", std::process::id()))
}

/// Remove this thread's scratch directory (call after a run).
pub fn cleanup() {
    let _ = std::fs::remove_dir_all(scratch_path());
}

/// This thread's scratch directory, emptied (not re-created: directory
/// creation dominates the run time on some filesystems).
fn fresh_dir() -> PathBuf {
    let dir = scratch_path();
    match std::fs::read_dir(&dir) {
        Ok(entries) => {
            for e in entries.flatten() {
                std::fs::remove_file(e.path()).expect("clear fuzz temp dir");
            }
        }
        Err(_) => std::fs::create_dir_all(&dir).expect("create fuzz temp dir"),
    }
    dir
}

pub fn run(data: &[u8]) {
    let verifier = verifier();
    let (segs, ckpt) = split(data);

    // 1. Segment scans.
    for s in &segs {
        check_scan(s);
    }

    // 2. One frame body.
    if let Ok(r) = Record::decode_body(data) {
        assert_eq!(
            &r.encode_frame()[FRAME_HEADER_LEN..],
            data,
            "non-canonical body"
        );
    }

    // 3. Verification, in memory and from disk.
    let seg_data: Vec<SegmentData> = segs
        .iter()
        .enumerate()
        .map(|(i, b)| SegmentData {
            name: segment_file_name(i as u64),
            bytes: b.clone(),
        })
        .collect();
    let opts = VerifyOptions {
        checkpoint: ckpt
            .as_deref()
            .and_then(|c| std::str::from_utf8(c).ok())
            .and_then(Checkpoint::from_json),
        ..VerifyOptions::default()
    };
    let mem = verify_segments(&seg_data, &verifier, &opts);
    let _ = mem.is_clean();

    let dir = fresh_dir();
    for s in &seg_data {
        std::fs::write(dir.join(&s.name), &s.bytes).expect("write segment");
    }
    if let Some(c) = &ckpt {
        std::fs::write(dir.join(CHECKPOINT_FILE), c).expect("write checkpoint");
    }
    let disk = verify_dir(&dir, &verifier, &VerifyOptions::default())
        .expect("verify_dir on a harness-written directory must not fail");
    if ckpt.is_none() || opts.checkpoint.is_some() {
        // Same inputs (an unparseable checkpoint.json adds a finding on
        // disk only), same verdict.
        assert_eq!(mem.is_intact(), disk.is_intact(), "disk/memory disagree");
        assert_eq!(mem.is_clean(), disk.is_clean(), "disk/memory disagree");
    }

    // 4. Export bundle and JSON control files.
    if let Ok(b) = Bundle::from_bytes(data) {
        let again = Bundle::from_bytes(&b.to_bytes()).expect("bundle round trip");
        assert_eq!(again, b, "bundle round trip changed it");
        let _ = b.verify(&verifier, None, None).is_clean();
        let _ = b.records();
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = Checkpoint::from_json(text);
        let _ = Anchor::from_json(text);
        if let Some(c) = SignedCursor::from_json(text) {
            assert_eq!(
                SignedCursor::from_json(&c.to_json()),
                Some(c),
                "cursor round trip"
            );
        }
        let _ = Ack::from_json(text).map(|a| a.verify(&verifier));
    }
}
