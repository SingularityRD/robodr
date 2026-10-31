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
    // (its batch is done: the entry protects nothing), counted and logged.
    assert_eq!(rep.pruned_dead_letters.removed, 1, "{rep:?}");
    assert_eq!(rep.pruned_dead_letters.removed_entries, 1, "{rep:?}");
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

/// Review finding: the publisher rotated by default, and pruning deleted
/// rotated files whose entries could be the only copy of Kafka-refused
/// findings. Rotation is now opt-in: by default nothing is ever deleted,
/// whatever the batches' state.
#[test]
fn publisher_keeps_every_dead_letter_by_default() {
    let tmp = TempDir::new("ret-default");
    let out = tmp.path().join("out");
    let state = tmp.path().join("state");
    for b in ["rdd_a_1", "rdd_a_2", "rdd_a_3"] {
        write_batch(&out, b, 1);
    }
    let cfg = PublishConfig::new(Source::DiodeOut(out.clone()), &state);
    assert_eq!(cfg.dead_letter_rotation, None, "rotation is opt-in");
    let mut p = Publisher::open(cfg, OkSink).unwrap();
    let rep = p.run_once().unwrap();
    assert_eq!(rep.dead_lettered, 3);
    // The batches are done and even gone from out/: their entries protect
    // nothing for deduplication, yet nothing is deleted.
    for b in ["rdd_a_1", "rdd_a_2", "rdd_a_3"] {
        fs::remove_dir_all(out.join(b)).unwrap();
    }
    for _ in 0..2 {
        let rep = p.run_once().unwrap();
        assert_eq!(rep.pruned_dead_letters, Default::default());
    }
    assert_eq!(dl_files(&state), ["dead-letter.jsonl"]);
    let dl = fs::read_to_string(state.join("dead-letter.jsonl")).unwrap();
    assert_eq!(dl.lines().count(), 3);
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

/// T83: with `out_retention` (opt-in; this publisher the sole consumer of
/// `out/`), the importer's batch directories the publisher has finished
/// are deleted; nothing is published again, the `done/` markers stay
/// (their own retention follows once the batch has left `out/`), and the
/// report carries the state's sizes (measured at most once per
/// `usage_interval`). By default `out/` is never touched.
#[test]
fn publisher_prunes_finished_out_batches_only_when_asked() {
    let tmp = TempDir::new("ret-out");
    let out = tmp.path().join("out");
    let state = tmp.path().join("state");
    for b in ["rdd_a_1", "rdd_a_2", "rdd_a_3"] {
        write_batch(&out, b, 2);
    }
    let cfg = PublishConfig::new(Source::DiodeOut(out.clone()), &state);
    assert!(cfg.out_retention.is_unbounded(), "opt-in");
    let mut p = Publisher::open(cfg.clone(), OkSink).unwrap();
    let rep = p.run_once().unwrap();
    assert_eq!(rep.published, 6);
    assert_eq!(rep.pruned_out, Default::default());
    let u = rep.state_usage.expect("measured on the first run");
    let o = u.diode_out.expect("diode source");
    assert_eq!(o.entries, 3);
    assert!(o.bytes > 3 * 70_000, "{o:?}");
    assert_eq!(u.done_markers.entries, 3);
    assert_eq!(u.spool_rejected, None);
    assert_eq!(u.reinject, None);
    // Within the interval: not measured again.
    assert_eq!(p.run_once().unwrap().state_usage, None);
    assert_eq!(fs::read_dir(&out).unwrap().count(), 3, "default: kept");
    drop(p);

    let mut cfg = cfg;
    cfg.out_retention = Retention {
        max_count: Some(1),
        ..Default::default()
    };
    cfg.usage_interval = std::time::Duration::ZERO;
    // The count bound keeps one (the newest by done/ marker) and deletes
    // two.
    let mut p = Publisher::open(cfg.clone(), OkSink).unwrap();
    let rep = p.run_once().unwrap();
    assert_eq!(rep.published, 0, "nothing republished");
    assert_eq!(rep.pruned_out.removed, 2, "{rep:?}");
    assert!(rep.pruned_out.removed_bytes > 2 * 70_000);
    // Two payloads gone; the directories stay as tombstones (with the
    // manifest copy the importer writes; none in this test), so the
    // importer never re-emits a different batch under a finished name.
    let with_records = ["rdd_a_1", "rdd_a_2", "rdd_a_3"]
        .iter()
        .filter(|b| out.join(b).join("records.jsonl").exists())
        .count();
    assert_eq!(with_records, 1);
    for b in ["rdd_a_1", "rdd_a_2", "rdd_a_3"] {
        assert!(out.join(b).is_dir(), "tombstone");
        assert!(state.join("done").join(b).exists(), "markers stay");
    }
    let u = rep.state_usage.unwrap();
    let o = u.diode_out.unwrap();
    assert_eq!(o.entries, 3);
    assert!(o.bytes < 100_000, "{o:?}");
    let rep = p.run_once().unwrap();
    assert_eq!(rep.published, 0);
    assert_eq!(rep.pruned_out.removed, 0, "tombstones are not pruned again");
}

/// T83: with a spool source, `rejected_retention` bounds `<spool>/rejected/`
/// like `robodr-spool-export` does (default: kept). A record moved there
/// by the publisher has no reason file (its reason is in the dead-letter
/// file): it is dated by the first pass that sees it.
#[test]
fn publisher_prunes_spool_rejected_only_when_asked() {
    let tmp = TempDir::new("ret-rej");
    let spool = tmp.path().join("spool");
    let state = tmp.path().join("state");
    for d in ["ready", "acked"] {
        fs::create_dir_all(spool.join(d)).unwrap();
    }
    fs::write(
        spool.join("ready").join(format!("{:020}.json", 1)),
        b"garbage",
    )
    .unwrap();
    let cfg = PublishConfig::new(Source::Spool(spool.clone()), &state);
    let mut p = Publisher::open(cfg.clone(), OkSink).unwrap();
    let rep = p.run_once().unwrap();
    assert_eq!(rep.dead_lettered, 1);
    assert_eq!(rep.pruned_rejected, Default::default());
    let u = rep.state_usage.unwrap();
    assert_eq!(u.spool_rejected.map(|x| x.entries), Some(1));
    assert_eq!(u.diode_out, None);
    assert!(spool
        .join("rejected")
        .join(format!("{:020}.json", 1))
        .exists());
    drop(p);
    let mut cfg = cfg;
    cfg.rejected_retention = Retention::max_age(std::time::Duration::from_secs(3600));
    let mut p = Publisher::open(cfg.clone(), OkSink).unwrap();
    // Dated now: not old yet.
    let rep = p.run_once().unwrap();
    assert_eq!(rep.pruned_rejected.removed, 0);
    let why = spool
        .join("rejected")
        .join(format!("{:020}.json.reason.json", 1));
    assert!(why.exists());
    assert!(fs::read_to_string(&why)
        .unwrap()
        .contains("dead-letter file"));
    drop(p);
    cfg.rejected_retention = Retention {
        max_count: Some(0),
        ..Default::default()
    };
    let rep = Publisher::open(cfg, OkSink).unwrap().run_once().unwrap();
    assert_eq!(rep.pruned_rejected.removed, 1);
    assert_eq!(fs::read_dir(spool.join("rejected")).unwrap().count(), 0);
}

/// Review finding (WP16): measuring the state's usage is monitoring. A
/// measurement that fails (here `<spool>/rejected` is not a directory)
/// is reported in the run's report and never fails the run (it used to
/// stop `robodr-kafka-publish`).
#[test]
fn a_failed_usage_measurement_does_not_fail_the_run() {
    let tmp = TempDir::new("ret-usage-err");
    let spool = tmp.path().join("spool");
    let state = tmp.path().join("state");
    for d in ["ready", "acked"] {
        fs::create_dir_all(spool.join(d)).unwrap();
    }
    let cfg = PublishConfig::new(Source::Spool(spool.clone()), &state);
    let mut p = Publisher::open(cfg, OkSink).unwrap();
    // Broken after open (which creates it).
    fs::remove_dir_all(spool.join("rejected")).unwrap();
    fs::write(spool.join("rejected"), b"not a directory").unwrap();
    let rep = p
        .run_once()
        .expect("measurement errors do not fail the run");
    assert_eq!(rep.state_usage, None);
    let e = rep.state_usage_error.expect("reported");
    assert!(e.contains("rejected"), "{e}");
    // Within the interval: not measured (nor reported) again.
    let rep = p.run_once().unwrap();
    assert_eq!((rep.state_usage, rep.state_usage_error), (None, None));
}

/// Review finding (WP16): `--out-max-*` where this tool may not delete an
/// `out/` batch's payload (the importer's files, no write permission on
/// its directory) does not stop publishing: the failure is reported with
/// the batch's path and what to do, and the other batches are pruned.
#[test]
fn out_pruning_that_fails_does_not_stop_publishing() {
    let tmp = TempDir::new("ret-out-err");
    let out = tmp.path().join("out");
    let state = tmp.path().join("state");
    for b in ["rdd_a_1", "rdd_a_2"] {
        write_batch(&out, b, 1);
    }
    let mut cfg = PublishConfig::new(Source::DiodeOut(out.clone()), &state);
    let first = Publisher::open(cfg.clone(), OkSink)
        .unwrap()
        .run_once()
        .unwrap();
    assert_eq!(first.published, 2);
    let stuck = out.join("rdd_a_1");
    let Some(_guard) = undeletable(&stuck, &stuck.join("records.jsonl")) else {
        eprintln!("skipped: cannot make a file undeletable here");
        return;
    };
    write_batch(&out, "rdd_a_3", 1);
    cfg.out_retention = Retention {
        max_count: Some(0),
        ..Default::default()
    };
    let mut p = Publisher::open(cfg, OkSink).unwrap();
    let rep = p.run_once().expect("pruning errors do not stop publishing");
    assert_eq!(rep.published, 1, "the new batch is published");
    assert_eq!(rep.batches_done, ["rdd_a_3"]);
    let e = rep.out_prune_error.clone().expect("reported");
    assert!(e.contains("rdd_a_1") && e.contains("--out-max"), "{e}");
    assert!(stuck.join("records.jsonl").exists());
    assert_eq!(rep.pruned_out.removed, 2, "the others are pruned: {rep:?}");
    assert!(!out.join("rdd_a_2").join("records.jsonl").exists());
    assert!(!out.join("rdd_a_3").join("records.jsonl").exists());
    // Every pass reports it while it lasts.
    assert!(p.run_once().unwrap().out_prune_error.is_some());
}
