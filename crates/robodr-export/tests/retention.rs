//! Retention of `robodr-kafka-publish`'s `done/` markers and rotated
//! dead-letter files: bounded, and never deleting a marker whose batch is
//! still in `out/` or a dead letter whose record may be processed again.

mod common;

use common::*;
use robodr_export::deadletter::{self, Rotation, MIN_ROTATION_BYTES};
use robodr_export::kafka::{Outcome, ProduceError, ProduceRecord};
use robodr_export::retention::Retention;
use robodr_export::{PublishConfig, Publisher, Sink, Source};
use std::fs;
use std::path::Path;

/// Delivers everything.
struct OkSink;

impl Sink for OkSink {
    fn partition_count(&mut self, _: &str) -> Result<u32, ProduceError> {
        Ok(4)
    }
    fn send(
        &mut self,
        _: &str,
        records: &[(i32, ProduceRecord)],
    ) -> Result<Vec<Outcome>, ProduceError> {
        Ok(records
            .iter()
            .map(|(p, _)| Outcome::Delivered {
                partition: *p,
                offset: 0,
            })
            .collect())
    }
}

/// A diode batch: one oversized garbage line (a ~70 KB dead letter, so
/// every dead letter rotates the file) and `n` good records.
fn write_batch(out: &Path, name: &str, n: u64) {
    let d = out.join(name);
    fs::create_dir_all(&d).unwrap();
    let mut s = format!("not json {}\n", "x".repeat(70_000));
    for i in 0..n {
        let rec = robodr_ocsf::record(&finding_for(UNIT, i), Some(4)).unwrap();
        let line = serde_json::json!({
            "topic": rec.topic, "partition": rec.partition, "key": rec.key,
            "headers": rec.headers, "value": rec.value,
        });
        s.push_str(&line.to_string());
        s.push('\n');
    }
    fs::write(d.join("records.jsonl"), s).unwrap();
}

fn dl_files(state: &Path) -> Vec<String> {
    deadletter::files(state, "dead-letter.jsonl")
        .unwrap()
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect()
}

#[test]
fn publisher_prunes_markers_and_dead_letters_it_no_longer_needs() {
    let tmp = TempDir::new("ret-publish");
    let out = tmp.path().join("out");
    let state = tmp.path().join("state");
    for b in ["rdd_a_1", "rdd_a_2", "rdd_a_3"] {
        write_batch(&out, b, 2);
    }
    let mut cfg = PublishConfig::new(Source::DiodeOut(out.clone()), &state);
    cfg.dead_letter_rotation = Some(Rotation {
        max_bytes: MIN_ROTATION_BYTES,
        keep: 1,
    });
    cfg.done_retention = Retention {
        max_count: Some(0),
        ..Default::default()
    };
    let mut p = Publisher::open(cfg.clone(), OkSink).unwrap();
    let rep = p.run_once().unwrap();
    assert_eq!((rep.published, rep.dead_lettered), (6, 3));
    // Every marker is over the bound, but each batch is still in out/:
    // deleting a marker would publish its batch again.
    assert_eq!((rep.pruned_done.removed, rep.pruned_done.held), (0, 3));
    // Three dead letters, one per file; past keep = 1 the oldest goes
    // (its batch is done: the entry protects nothing).
    assert_eq!(rep.pruned_dead_letters.removed, 1, "{rep:?}");
    assert_eq!(
        dl_files(&state),
        ["dead-letter.jsonl.1", "dead-letter.jsonl"]
    );
    for b in ["rdd_a_1", "rdd_a_2", "rdd_a_3"] {
        assert!(state.join("done").join(b).exists());
    }

    // The importer's output of two batches is cleaned up: their markers
    // go, the third stays.
    fs::remove_dir_all(out.join("rdd_a_1")).unwrap();
    fs::remove_dir_all(out.join("rdd_a_2")).unwrap();
    let rep = p.run_once().unwrap();
    assert_eq!(rep.published, 0, "nothing republished");
    assert_eq!((rep.pruned_done.removed, rep.pruned_done.held), (2, 1));
    assert!(state.join("done").join("rdd_a_3").exists());
    drop(p);

    // A rotated file whose entry belongs to a batch that is in out/ and not
    // done is held (the batch's records may be processed again). Here: an
    // entry for "rdd_b_9", present in out/ (as a file, so it is not
    // published by this run) without a done marker.
    fs::write(out.join("rdd_b_9"), b"").unwrap();
    let line = serde_json::json!({"source": "rdd_b_9", "position": 1});
    fs::write(state.join("dead-letter.jsonl.7"), format!("{line}\n")).unwrap();
    let mut p = Publisher::open(cfg.clone(), OkSink).unwrap();
    let rep = p.run_once().unwrap();
    assert_eq!(rep.pruned_dead_letters.held, 1, "{rep:?}");
    assert!(state.join("dead-letter.jsonl.7").exists());
    // Once the batch is done (marker), it goes.
    fs::write(state.join("done").join("rdd_b_9"), b"").unwrap();
    let rep = p.run_once().unwrap();
    assert_eq!(rep.pruned_dead_letters.held, 0, "{rep:?}");
    assert!(!state.join("dead-letter.jsonl.7").exists());
    // ... and the marker itself stays while rdd_b_9 is in out/.
    assert!(state.join("done").join("rdd_b_9").exists());
}

#[test]
fn spool_dead_letters_are_held_while_the_file_is_in_ready() {
    let tmp = TempDir::new("ret-spool");
    let spool = tmp.path().join("spool");
    let state = tmp.path().join("state");
    for d in ["ready", "acked"] {
        fs::create_dir_all(spool.join(d)).unwrap();
    }
    let mut cfg = PublishConfig::new(Source::Spool(spool.clone()), &state);
    cfg.dead_letter_retention = Retention {
        max_count: Some(0),
        ..Default::default()
    };
    cfg.dead_letter_rotation = None;
    fs::create_dir_all(&state).unwrap();
    // An entry whose spool file is still in ready/ (a directory, so this
    // run does not process it) and one whose file left ready/.
    let root = spool.display().to_string();
    let held = serde_json::json!({"source": root, "position": 9});
    let gone = serde_json::json!({"source": root, "position": 8});
    fs::create_dir(spool.join("ready").join(format!("{:020}.json", 9))).unwrap();
    fs::write(state.join("dead-letter.jsonl.2"), format!("{held}\n")).unwrap();
    fs::write(state.join("dead-letter.jsonl.1"), format!("{gone}\n")).unwrap();
    let mut p = Publisher::open(cfg, OkSink).unwrap();
    let rep = p.run_once().unwrap();
    assert_eq!(
        (
            rep.pruned_dead_letters.removed,
            rep.pruned_dead_letters.held
        ),
        (1, 1)
    );
    assert_eq!(dl_files(&state), ["dead-letter.jsonl.2"]);
}

#[test]
fn bad_rotation_is_refused() {
    let tmp = TempDir::new("ret-bad");
    let mut cfg = PublishConfig::new(Source::DiodeOut(tmp.path().join("out")), tmp.path());
    cfg.dead_letter_rotation = Some(Rotation {
        max_bytes: 10,
        keep: 1,
    });
    assert!(Publisher::open(cfg, OkSink).is_err());
}
