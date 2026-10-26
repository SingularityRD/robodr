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

mod common;

use std::io::{Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use common::pcap::robot_profile;
use common::*;

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
