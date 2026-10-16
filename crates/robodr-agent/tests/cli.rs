//! `robodr-replay` binary, end to end, on the shipped example scenarios.

mod common;

use std::path::Path;
use std::process::{Command, Output};

use common::*;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_robodr-replay"))
}

fn run_demo(dir: &Path, extra: &[&str]) -> Output {
    let ex = examples();
    let mut c = bin();
    c.arg("--events")
        .arg(ex.join("rogue-ugv.jsonl"))
        .arg("--profile")
        .arg(ex.join("ugv-demo.profile.json"))
        .arg("--policy")
        .arg(ex.join("policy-oem-validated.json"))
        .arg("--blackbox")
        .arg(dir)
        .args(["--key-hex", &key_hex(), "--robot-id", ROBOT])
        .args(["--safety-state", "moving_slow", "--firewall"])
        .args(extra);
    c.output().unwrap()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn demo_run_writes_valid_findings_and_verifies() {
    let dir = tmpdir("cli-run");
    let out = run_demo(&dir, &["--log-plans"]);
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(0), "{err}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 5, "{stdout}");
    for l in &lines {
        robodr_ocsf::parse_and_validate(l).unwrap();
    }
    assert!(
        err.contains("VERIFIED: evidence chain intact end to end"),
        "{err}"
    );
    assert!(err.contains("CLEAN"), "{err}");
    assert!(err.contains("[executor:dry-run replay]"), "{err}");
    assert!(err.contains("awaiting human approval"), "{err}");

    // Same run, findings to a file; then the standalone verifier.
    let dir2 = tmpdir("cli-run2");
    let findings = dir2.with_extension("jsonl");
    let out = run_demo(&dir2, &["--out", findings.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(
        std::fs::read_to_string(&findings).unwrap(),
        stdout,
        "deterministic"
    );
    let v = bin()
        .args(["verify", "--blackbox"])
        .arg(&dir2)
        .args(["--key-hex", &key_hex(), "--robot-id", ROBOT, "--findings"])
        .arg(&findings)
        .output()
        .unwrap();
    assert_eq!(v.status.code(), Some(0), "{}", stderr(&v));
    assert!(stderr(&v).contains("17/17"), "{}", stderr(&v));

    // Tamper: flip a byte in the middle of the segment => exit 1.
    let seg = dir2.join(robodr_blackbox::store::segment_file_name(0));
    let mut bytes = std::fs::read(&seg).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x80;
    std::fs::write(&seg, &bytes).unwrap();
    let v = bin()
        .args(["verify", "--blackbox"])
        .arg(&dir2)
        .args(["--key-hex", &key_hex(), "--findings"])
        .arg(&findings)
        .output()
        .unwrap();
    assert_eq!(v.status.code(), Some(1), "{}", stderr(&v));
    assert!(stderr(&v).contains("TAMPERED"), "{}", stderr(&v));

    for d in [&dir, &dir2] {
        std::fs::remove_dir_all(d).unwrap();
    }
    std::fs::remove_file(&findings).unwrap();
}

#[test]
fn motion_demo_reports_injected_telemetry() {
    let dir = tmpdir("cli-motion");
    let ex = examples();
    let out = bin()
        .arg("--events")
        .arg(ex.join("motion-injection.jsonl"))
        .arg("--profile")
        .arg(ex.join("ugv-demo.profile.json"))
        .arg("--policy")
        .arg(ex.join("policy-oem-validated.json"))
        .arg("--blackbox")
        .arg(&dir)
        .args(["--key-hex", &key_hex(), "--robot-id", ROBOT])
        .args(["--safety-state", "moving_slow", "--step-ms", "20"])
        .args([
            "--monitor",
            "--feedback-source",
            "/odom=wheel_odometry",
            "--firewall",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "{stdout}");
    let f = robodr_ocsf::parse_and_validate(lines[0]).unwrap();
    assert_eq!(f.entity_context.rule_id, "robot.motion.feedback_divergence");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn observe_mode_demo_with_the_unvalidated_example_policy() {
    // The repository's example policy is not OEM-validated: observe only.
    let dir = tmpdir("cli-observe");
    let ex = examples();
    let outcomes = dir.with_extension("outcomes.jsonl");
    let policy =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/response-policy.example.json");
    let out = bin()
        .arg("--events")
        .arg(ex.join("rogue-ugv.jsonl"))
        .arg("--profile")
        .arg(ex.join("ugv-demo.profile.json"))
        .arg("--policy")
        .arg(policy)
        .arg("--blackbox")
        .arg(&dir)
        .args(["--key-hex", &key_hex(), "--robot-id", ROBOT, "--firewall"])
        .arg("--outcomes")
        .arg(&outcomes)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let text = std::fs::read_to_string(&outcomes).unwrap();
    assert!(!text.is_empty());
    for l in text.lines() {
        let v: serde_json::Value = serde_json::from_str(l).unwrap();
        assert_eq!(v["disposition"], "observe_only");
        assert_eq!(
            v["plan"]["actions"],
            serde_json::json!([{"step": "record"}])
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_file(&outcomes).unwrap();
}

#[test]
fn usage_and_input_errors_exit_2() {
    let dir = tmpdir("cli-err");
    // No args.
    assert_eq!(bin().output().unwrap().status.code(), Some(2));
    // Help.
    assert_eq!(bin().arg("--help").output().unwrap().status.code(), Some(0));
    // Unknown option / bad enum / short key / bad hex / zero step.
    for extra in [
        vec!["--bogus", "1"],
        vec!["--safety-state", "flying"],
        vec!["--step-ms", "0"],
        vec!["--feedback-source", "/odom"],
        vec!["--partitions", "-1"],
    ] {
        let out = run_demo(&dir, &extra);
        assert_eq!(out.status.code(), Some(2), "{extra:?}: {}", stderr(&out));
    }
    let short = bin()
        .args([
            "--events",
            "x",
            "--profile",
            "x",
            "--policy",
            "x",
            "--blackbox",
        ])
        .arg(&dir)
        .args(["--key-hex", "abcd", "--robot-id", ROBOT])
        .output()
        .unwrap();
    assert_eq!(short.status.code(), Some(2));
    // Missing events file.
    let ex = examples();
    let missing = bin()
        .args(["--events", "/nonexistent/x.jsonl", "--profile"])
        .arg(ex.join("ugv-demo.profile.json"))
        .arg("--policy")
        .arg(ex.join("policy-oem-validated.json"))
        .arg("--blackbox")
        .arg(dir.join("bb-missing"))
        .args(["--key-hex", &key_hex(), "--robot-id", ROBOT])
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(2), "{}", stderr(&missing));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn malformed_input_aborts_but_the_black_box_stays_verifiable() {
    let dir = tmpdir("cli-bad");
    let events = dir.join("bad.jsonl");
    let rogue = std::fs::read_to_string(examples().join("rogue-ugv.jsonl")).unwrap();
    std::fs::write(&events, format!("{rogue}{{\"kind\":\"nope\"}}\n")).unwrap();
    let bb = dir.join("bb");
    let ex = examples();
    let out = bin()
        .arg("--events")
        .arg(&events)
        .arg("--profile")
        .arg(ex.join("ugv-demo.profile.json"))
        .arg("--policy")
        .arg(ex.join("policy-oem-validated.json"))
        .arg("--blackbox")
        .arg(&bb)
        .args(["--key-hex", &key_hex(), "--robot-id", ROBOT])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("not a RobotEvent"),
        "{}",
        stderr(&out)
    );
    let v = bin()
        .args(["verify", "--blackbox"])
        .arg(&bb)
        .args(["--key-hex", &key_hex()])
        .output()
        .unwrap();
    assert_eq!(v.status.code(), Some(0), "{}", stderr(&v));
    std::fs::remove_dir_all(&dir).unwrap();
}
