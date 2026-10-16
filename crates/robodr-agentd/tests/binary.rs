//! The real `robodr-agentd` binary: argument / configuration errors, and a
//! graceful shutdown on SIGTERM / SIGINT that leaves a sealed, verified
//! black box and the findings in the spool.

mod common;

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::pcap::robot_profile;
use common::*;

const BIN: &str = env!("CARGO_BIN_EXE_robodr-agentd");

extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

#[test]
fn usage_and_config_errors_exit_2() {
    let out = Command::new(BIN).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = Command::new(BIN).arg("--help").output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("--config"));
    let out = Command::new(BIN)
        .args(["--config", "/a", "--config", "/b"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = Command::new(BIN).arg("--key-hex").output().unwrap();
    assert_eq!(out.status.code(), Some(2), "no keys on argv");

    let s = setup("bin-cfg", &robot_profile(true));
    let cfg = s.config(
        serde_json::json!({}),
        serde_json::json!([{"kind": "stdin"}]),
        serde_json::json!({}),
    );
    let path = s.write_config(&cfg);
    let out = Command::new(BIN)
        .args(["--config"])
        .arg(&path)
        .arg("--check-config")
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("configuration OK"));

    // A group/world-readable key file is refused before anything starts.
    std::fs::set_permissions(&s.key, std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = Command::new(BIN)
        .arg("--config")
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("chmod 600"), "{err}");
    assert!(!s.blackbox.exists(), "nothing started");

    // Unknown key in the config.
    std::fs::set_permissions(&s.key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut bad = cfg.clone();
    bad["daemon"]["tick_msec"] = serde_json::json!(5);
    let path = s.write_config(&bad);
    let out = Command::new(BIN)
        .arg("--config")
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("tick_msec"));
}

fn graceful_stop(sig: i32, tag: &str) {
    let s = setup(tag, &robot_profile(true));
    let cfg = s.config(
        serde_json::json!({}),
        serde_json::json!([{"kind": "stdin"}]),
        serde_json::json!({}),
    );
    let path = s.write_config(&cfg);
    let mut child = Command::new(BIN)
        .arg("--config")
        .arg(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    // A rogue participant: one High finding.
    writeln!(
        stdin,
        "{{\"kind\":\"ros2_participant_discovered\",\"guid_prefix\":\"eeeeeeeeeeeeeeeeeeeeeeee\",\"src_ip\":\"192.168.50.66\",\"locators\":[]}}"
    )
    .unwrap();
    stdin.flush().unwrap();
    wait_for(20, "finding in spool", || {
        let r = rules(&spooled(&s.spool));
        r.iter()
            .any(|x| x == "robot.ros2.unknown_participant")
            .then_some(())
    });
    // stdin stays open: the daemon must stop on the signal alone.
    let pid = i32::try_from(child.id()).unwrap();
    // SAFETY: plain kill(2) on our own child.
    assert_eq!(unsafe { kill(pid, sig) }, 0);
    let deadline = Instant::now() + Duration::from_secs(20);
    let exit = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st;
        }
        assert!(
            Instant::now() < deadline,
            "daemon did not stop on signal {sig}"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut err = String::new();
    use std::io::Read;
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    assert!(exit.success(), "{exit:?}\n{err}");
    assert!(err.contains("stopping (Requested)"), "{err}");
    assert!(err.contains("black box sealed"), "{err}");
    drop(stdin);

    // Sealed: the spool's checkpoint copy verifies the chain end to end.
    let cp = std::fs::read_to_string(s.spool.join("checkpoint.json")).unwrap();
    let cp = robodr_blackbox::Checkpoint::from_json(&cp).unwrap();
    let found = spooled(&s.spool);
    assert_verified(&s.blackbox, Some(cp), &found);
    assert_eq!(notes_with(&s.blackbox, "robodr.agentd_stop"), 1);
    let st = status(&s.spool).unwrap();
    assert_eq!(st["running"], false);
}

#[test]
fn sigterm_stops_gracefully_with_a_sealed_black_box() {
    graceful_stop(15, "sigterm");
}

#[test]
fn sigint_stops_gracefully_with_a_sealed_black_box() {
    graceful_stop(2, "sigint");
}
