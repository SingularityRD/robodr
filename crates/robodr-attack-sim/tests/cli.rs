//! The `robodr-attack-sim` binary: guard refusals, pcap output, scoring.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_robodr-attack-sim"))
        .args(args)
        .output()
        .unwrap()
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("robodr-attack-sim-cli-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d.join(name)
}

fn fixture(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/captures/ros2-jazzy")
        .join(name)
        .display()
        .to_string()
}

#[test]
fn live_send_is_refused_without_every_guard() {
    let cases: &[(&[&str], &str)] = &[
        (
            &[
                "send",
                "--scenario",
                "lowcmd-torque",
                "--target",
                "127.0.0.1",
                "--allow",
                "127.0.0.1/32",
            ],
            "--i-understand",
        ),
        (
            &[
                "send",
                "--scenario",
                "lowcmd-torque",
                "--target",
                "127.0.0.1",
                "--i-understand",
            ],
            "not in any --allow",
        ),
        (
            &[
                "send",
                "--scenario",
                "lowcmd-torque",
                "--target",
                "8.8.8.8",
                "--allow",
                "8.8.8.0/24",
                "--i-understand",
            ],
            "not a private",
        ),
        (
            &[
                "send",
                "--scenario",
                "lowcmd-torque",
                "--target",
                "10.1.2.3",
                "--allow",
                "0.0.0.0/0",
                "--i-understand",
            ],
            "wider than /16",
        ),
    ];
    for (args, needle) in cases {
        let o = bin(args);
        assert_eq!(o.status.code(), Some(2), "{args:?}");
        let err = String::from_utf8_lossy(&o.stderr);
        assert!(err.contains(needle), "{args:?}: {err}");
        assert!(o.stdout.is_empty(), "{args:?} sent something");
    }
}

#[test]
fn live_send_to_an_allowed_loopback_target() {
    let o = bin(&[
        "send",
        "--scenario",
        "lowcmd-torque",
        "--count",
        "3",
        "--target",
        "127.0.0.1",
        "--allow",
        "127.0.0.0/24",
        "--i-understand",
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["sent"], 3);
    assert!(v["first_send_unix_ms"].as_u64().unwrap() > 1_700_000_000_000);
}

#[test]
fn pcap_writes_every_scenario_and_score_reports_missing_rules() {
    let out = tmp("all.pcap");
    let o = bin(&[
        "pcap",
        "--scenario",
        "all",
        "--carrier",
        &fixture("fastrtps_baseline.pcap"),
        "--out",
        out.to_str().unwrap(),
        "--count",
        "200",
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["scenarios"].as_array().unwrap().len(), 5);
    let frames = robodr_attack_sim::read_capture(&out).unwrap();
    assert_eq!(frames.len() as u64, v["frames"].as_u64().unwrap());
    assert!(frames.windows(2).all(|w| w[0].ts <= w[1].ts));

    let nd = tmp("findings.ndjson");
    std::fs::write(
        &nd,
        "{\"entity_context\":{\"rule_id\":\"robot.ros2.unknown_participant\"}}\n",
    )
    .unwrap();
    let o = bin(&[
        "score",
        "--scenario",
        "rogue-participant",
        "--findings",
        nd.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(0));
    let o = bin(&[
        "score",
        "--scenario",
        "rogue-participant,guid-spray",
        "--findings",
        nd.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(1));
    let o = bin(&["pcap", "--scenario", "nope"]);
    assert_eq!(o.status.code(), Some(2));
}

/// demo/scripts/check-score.sh, which makes demo/run.sh fail on a scenario
/// regression: its verdict is `score`'s exit status (SCORE.rc, written by
/// demo/scripts/robot.sh), not the report's layout.
#[test]
fn demo_check_score_fails_the_run_on_a_missed_scenario() {
    let nd = tmp("check-score.ndjson");
    std::fs::write(
        &nd,
        "{\"entity_context\":{\"rule_id\":\"robot.ros2.unknown_participant\"}}\n",
    )
    .unwrap();
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../demo/scripts/check-score.sh");
    let check = |report: &Path| {
        Command::new("sh")
            .arg(&script)
            .arg(report)
            .output()
            .unwrap()
    };
    for (scenarios, want) in [
        ("rogue-participant", Some(0)),
        ("rogue-participant,guid-spray", Some(1)),
    ] {
        let o = bin(&[
            "score",
            "--scenario",
            scenarios,
            "--findings",
            nd.to_str().unwrap(),
        ]);
        let report = tmp(&format!("score-{scenarios}.json"));
        std::fs::write(&report, &o.stdout).unwrap();
        let rc = report.with_extension("rc");
        std::fs::write(&rc, format!("{}\n", o.status.code().unwrap())).unwrap();
        let c = check(&report);
        let e = String::from_utf8_lossy(&c.stderr);
        assert_eq!(c.status.code(), want, "{scenarios}: {e}");
        if want == Some(1) {
            assert!(e.contains("FAILED (exit 1; guid-spray)"), "{e}");
        }
        // The same report re-serialised compactly: same verdict, same names.
        let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
        std::fs::write(&report, v.to_string()).unwrap();
        let c = check(&report);
        let e = String::from_utf8_lossy(&c.stderr);
        assert_eq!(c.status.code(), want, "compact {scenarios}: {e}");
        if want == Some(1) {
            assert!(e.contains("guid-spray"), "{e}");
        }
        // Without the exit status there is no verdict: fail.
        std::fs::remove_file(&rc).unwrap();
        assert_eq!(check(&report).status.code(), Some(1), "{scenarios}");
    }
    let empty = tmp("score-empty.json");
    std::fs::write(&empty, "").unwrap();
    std::fs::write(empty.with_extension("rc"), "0\n").unwrap();
    assert_eq!(check(&empty).status.code(), Some(1));
}
