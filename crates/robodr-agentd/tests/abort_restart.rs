//! S10 (R9, `panic = "abort"`): the release profile aborts on any panic, and
//! systemd's watchdog (`WatchdogSec=`, default `WatchdogSignal=SIGABRT`)
//! aborts a hung main loop. Either way the process dies on SIGABRT with no
//! unwinding, no destructors and no black-box seal, and systemd restarts it
//! (`Restart=on-failure`, `RestartSec=5s`; see
//! `packaging/systemd/robodr-agentd.service` and docs/OPERATIONS.md).
//!
//! This test does what systemd does, with the real binary: start the
//! daemon, let it record a finding, kill it with SIGABRT, check what an
//! abort leaves behind, start it again on the same state and check it comes
//! back cleanly: it starts, keeps recording, chains onto the aborted run's
//! evidence (the whole black box still verifies end to end against the
//! final checkpoint), keeps the first run's findings in the spool, and stops
//! gracefully afterwards.
//!
//! The write-burst variant (review I2) aborts the daemon while the black box
//! appends at a high rate (a stream of distinct rogue participants on
//! stdin), so the abort lands between or inside appends. If the abort left
//! no torn frame (`write(2)` of a whole frame is usually completed by the
//! kernel even for a killed process) the test leaves the prefix of a frame
//! at the end of the live segment, which is what a crash inside a write
//! produces. The restart must quarantine exactly that torn tail as
//! crash-plausible damage, chain onto the last whole record, and the black
//! box must verify end to end with every spooled finding's evidence.

mod common;

use std::io::{Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use common::pcap::robot_profile;
use common::*;
use robodr_blackbox::record::{scan_frames, RecordKind, RecoveryPayload, ScanItem};
use robodr_blackbox::verify::read_segments;

const BIN: &str = env!("CARGO_BIN_EXE_robodr-agentd");
const SIGABRT: i32 = 6;

/// Send `sig` to `child` with the system `kill(1)` (no FFI in this test).
fn signal(child: &Child, sig: &str) {
    let st = Command::new("kill")
        .arg(format!("-{sig}"))
        .arg(child.id().to_string())
        .status()
        .expect("run kill(1)");
    assert!(st.success(), "kill -{sig} failed: {st:?}");
}

fn wait_exit(child: &mut Child, what: &str) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(st) = child.try_wait().unwrap() {
            return st;
        }
        assert!(Instant::now() < deadline, "daemon did not exit ({what})");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn start(cfg: &std::path::Path) -> Child {
    Command::new(BIN)
        .arg("--config")
        .arg(cfg)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn rogue(guid_prefix: &str) -> String {
    format!(
        "{{\"kind\":\"ros2_participant_discovered\",\"guid_prefix\":\"{guid_prefix}\",\
         \"src_ip\":\"192.168.50.66\",\"locators\":[]}}"
    )
}

fn unknown_participants(s: &Setup) -> usize {
    rules(&spooled(&s.spool))
        .iter()
        .filter(|r| *r == "robot.ros2.unknown_participant")
        .count()
}

#[test]
fn agentd_restarts_cleanly_after_an_abort() {
    let s = setup("abort-restart", &robot_profile(true));
    let cfg = s.config(
        serde_json::json!({}),
        serde_json::json!([{"kind": "stdin"}]),
        serde_json::json!({}),
    );
    let path = s.write_config(&cfg);

    // Run 1: record one finding, then abort.
    let mut child = start(&path);
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "{}", rogue("eeeeeeeeeeeeeeeeeeeeeeee")).unwrap();
    stdin.flush().unwrap();
    wait_for(20, "first finding in spool", || {
        (unknown_participants(&s) == 1).then_some(())
    });
    wait_for(20, "first status.json", || status(&s.spool));
    signal(&child, "ABRT");
    let exit = wait_exit(&mut child, "SIGABRT");
    drop(stdin);
    assert_eq!(exit.signal(), Some(SIGABRT), "{exit:?}");
    assert!(!exit.success());
    // What an abort leaves behind: no stop note, no seal, a status file that
    // still says "running" (consumers detect the stale status by its
    // monotonic timestamp, see notify.rs), and the finding in the spool.
    assert_eq!(notes_with(&s.blackbox, "robodr.agentd_stop"), 0);
    assert_eq!(status(&s.spool).unwrap()["running"], true);
    assert_eq!(unknown_participants(&s), 1);

    // Run 2 (what Restart=on-failure does): same configuration and state.
    let mut child = start(&path);
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "{}", rogue("dddddddddddddddddddddddd")).unwrap();
    stdin.flush().unwrap();
    wait_for(20, "second finding in spool", || {
        (unknown_participants(&s) == 2).then_some(())
    });
    signal(&child, "TERM");
    let exit = wait_exit(&mut child, "SIGTERM after restart");
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    drop(stdin);
    assert!(exit.success(), "{exit:?}\n{err}");
    assert!(err.contains("black box sealed"), "{err}");

    // Both runs' evidence, one verified chain: the sealed checkpoint of run 2
    // covers the records of the aborted run 1.
    assert_eq!(notes_with(&s.blackbox, "robodr.agentd_start"), 2);
    assert_eq!(notes_with(&s.blackbox, "robodr.agentd_stop"), 1);
    let cp = std::fs::read_to_string(s.spool.join("checkpoint.json")).unwrap();
    let cp = robodr_blackbox::Checkpoint::from_json(&cp).unwrap();
    let found = spooled(&s.spool);
    assert_eq!(unknown_participants(&s), 2);
    assert_verified(&s.blackbox, Some(cp), &found);
    assert_eq!(status(&s.spool).unwrap()["running"], false);
    let _ = std::fs::remove_dir_all(&s.dir);
}

/// Every `Recovery` payload in the black box.
fn recoveries(dir: &std::path::Path) -> Vec<RecoveryPayload> {
    records(dir)
        .iter()
        .filter(|r| r.kind == RecordKind::Recovery)
        .map(|r| serde_json::from_slice(&r.payload).unwrap())
        .collect()
}

#[test]
fn agentd_restarts_cleanly_after_an_abort_during_a_write_burst() {
    let s = setup("abort-burst", &robot_profile(true));
    let cfg = s.config(
        serde_json::json!({}),
        serde_json::json!([{"kind": "stdin"}]),
        serde_json::json!({}),
    );
    let path = s.write_config(&cfg);

    // Run 1: a writer thread streams distinct rogue participants as fast as
    // the daemon reads them, until the pipe breaks at the abort.
    let mut child = start(&path);
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        let mut sent = 0u64;
        for i in 0u64.. {
            if writeln!(stdin, "{}", rogue(&format!("{i:024x}"))).is_err() {
                break;
            }
            sent += 1;
        }
        sent
    });
    wait_for(60, "black box appending at a high rate", || {
        let n = read_segments(&s.blackbox)
            .map(|segs| segs.iter().map(|g| g.bytes.len()).sum::<usize>())
            .unwrap_or(0);
        (n >= 512 * 1024).then_some(())
    });
    signal(&child, "ABRT");
    let exit = wait_exit(&mut child, "SIGABRT during the burst");
    let sent = writer.join().unwrap();
    assert_eq!(exit.signal(), Some(SIGABRT), "{exit:?}");
    assert!(sent > 0);
    assert_eq!(notes_with(&s.blackbox, "robodr.agentd_stop"), 0);
    let spooled_1 = unknown_participants(&s);
    assert!(spooled_1 > 0);

    // The live segment's tail: torn by the abort itself, or made torn here.
    let segs = read_segments(&s.blackbox).unwrap();
    let live = segs.last().unwrap();
    let live_path = s.blackbox.join(&live.name);
    let scan = scan_frames(&live.bytes);
    eprintln!(
        "burst: {sent} lines sent, {} records in {} segments, abort left a torn tail: {}",
        records(&s.blackbox).len(),
        segs.len(),
        scan.tail.is_some()
    );
    let torn_len = match scan.tail {
        Some(t) => t.len,
        None => {
            let last = scan
                .items
                .iter()
                .rev()
                .find_map(|it| match it {
                    ScanItem::Record(r) => Some(r.record.encode_frame()),
                    _ => None,
                })
                .expect("live segment holds records");
            let prefix = &last[..last.len() / 2];
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&live_path)
                .unwrap();
            f.write_all(prefix).unwrap();
            f.sync_all().unwrap();
            prefix.len() as u64
        }
    };
    let head_before = records(&s.blackbox).iter().map(|r| r.seq).max().unwrap();
    assert!(recoveries(&s.blackbox).is_empty());

    // Run 2: same configuration and state.
    let mut child = start(&path);
    let mut stdin = child.stdin.take().unwrap();
    wait_for(20, "second start note", || {
        (notes_with(&s.blackbox, "robodr.agentd_start") == 2).then_some(())
    });
    writeln!(stdin, "{}", rogue("dddddddddddddddddddddddd")).unwrap();
    stdin.flush().unwrap();
    wait_for(20, "evidence of run 2", || {
        (notes_with(&s.blackbox, "dddddddddddddddddddddddd") > 0).then_some(())
    });
    signal(&child, "TERM");
    let exit = wait_exit(&mut child, "SIGTERM after restart");
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    drop(stdin);
    assert!(exit.success(), "{exit:?}\n{err}");
    assert!(err.contains("black box sealed"), "{err}");

    // Torn-tail handling: exactly the torn bytes were quarantined, as a
    // crash (no record lost), and the chain continued after the last whole
    // record (no seq reused, nothing beyond it reported as truncation).
    let rec = recoveries(&s.blackbox);
    assert_eq!(rec.len(), 1, "{rec:#?}");
    let rp = &rec[0];
    assert_eq!(rp.discarded_bytes, torn_len, "{rp:#?}");
    assert_eq!(rp.discarded_records, 0, "{rp:#?}");
    assert!(rp.crash_plausible, "{rp:#?}");
    let q = rp.quarantine_file.as_deref().expect("torn bytes preserved");
    assert_eq!(
        std::fs::metadata(s.blackbox.join(q)).unwrap().len(),
        torn_len
    );
    let all = records(&s.blackbox);
    assert!(!all.iter().any(|r| r.kind == RecordKind::TruncationDetected));
    let mut seqs: Vec<u64> = all.iter().map(|r| r.seq).collect();
    let n = seqs.len();
    seqs.sort_unstable();
    seqs.dedup();
    assert_eq!(seqs.len(), n, "a seq was reused");
    assert!(all.iter().any(|r| r.seq == head_before + 1));

    // One verified chain over both runs, every finding's evidence resolves.
    let cp = std::fs::read_to_string(s.spool.join("checkpoint.json")).unwrap();
    let cp = robodr_blackbox::Checkpoint::from_json(&cp).unwrap();
    let found = spooled(&s.spool);
    assert!(unknown_participants(&s) >= spooled_1);
    assert_verified(&s.blackbox, Some(cp), &found);
    assert_eq!(status(&s.spool).unwrap()["running"], false);
    let _ = std::fs::remove_dir_all(&s.dir);
}
