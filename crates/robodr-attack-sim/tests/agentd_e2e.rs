//! Every scenario through the real daemon: the rule ids
//! [`Scenario::expected`] promises are what `robodr-agentd` reports.
//!
//! Profile learned from the real Fast DDS baseline capture
//! (`fixtures/captures/ros2-jazzy/fastrtps_baseline.pcap`), the scenario
//! merged into the same capture, replayed through `robodr_agentd::run`,
//! findings read from the spool (validated) and scored with
//! [`robodr_attack_sim::score`]. The clean carrier is checked too: none of
//! a scenario's expected ids may appear without the attack.

use robodr_attack_sim::{generate, read_capture, score, write_capture, Params, Scenario};
use robodr_commission::{LearnConfig, Learner, PcapSource};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const ROBOT: &str = "ugv-007";
const KEY: [u8; 32] = [0x42; 32];
const LEGACY_PC: &str = "10.77.10.21";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/captures/ros2-jazzy")
        .join(name)
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("robodr-attack-sim-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn profile_key() -> robodr_blackbox::Ed25519SigningKey {
    robodr_blackbox::Ed25519SigningKey::from_seed("attack-sim-test", &[0x24; 32]).unwrap()
}

/// Learn, lock (signed) and write the lab profile + trust file.
fn write_profile(dir: &Path) {
    let mut l = Learner::new(LearnConfig {
        model: "lab-ugv".into(),
        ..LearnConfig::default()
    })
    .unwrap();
    l.ingest(&mut PcapSource::open(&fixture("fastrtps_baseline.pcap")).unwrap())
        .unwrap();
    let mut p = l.finish().profile;
    p.locked = true;
    p.metadata = Some(robodr_events::profile::ProfileMetadata {
        schema_version: robodr_events::profile::PROFILE_SCHEMA_VERSION,
        profile_version: 1,
        platform: "ugv-lab".into(),
        unit_id: Some(ROBOT.into()),
        locked_by: "Test Operator".into(),
        locked_at: 1_790_000_000,
        parent_digest: None,
        attestation: None,
    });
    let text = robodr_commission::sealed_text(&p).unwrap();
    let path = dir.join("profile.json");
    let sig = robodr_commission::ProfileSignature::create(text.as_bytes(), &profile_key()).unwrap();
    std::fs::write(robodr_commission::sig_path_for(&path), sig.to_text()).unwrap();
    std::fs::write(&path, text).unwrap();
    std::fs::write(
        dir.join("profile-trust.json"),
        robodr_commission::trust::trust_keys_text(&[profile_key().verifying_key()]),
    )
    .unwrap();
}

/// Replay `pcap` through the daemon; the spool directory.
fn run_daemon(tag: &str, pcap: &Path) -> PathBuf {
    let dir = tmpdir(tag);
    write_profile(&dir);
    let policy = dir.join("policy.json");
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../robodr-agent/examples/policy-oem-validated.json"),
        &policy,
    )
    .unwrap();
    let key = dir.join("blackbox.key");
    std::fs::write(&key, robodr_blackbox::crypto::to_hex(&KEY)).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let spool = dir.join("spool");
    let cfg = serde_json::json!({
        "robot": {"id": ROBOT, "site": "lab"},
        "sensor": {
            "profile_path": dir.join("profile.json"),
            "listen_spdp": false,
            "profile_trust": {
                "trusted_keys": dir.join("profile-trust.json"),
                "state_file": dir.join("profile-state.json"),
            },
            "capture": {"enabled": true, "pcap_replay": pcap},
            "motion": {"feedback_topics": ["/odom"]},
            "unitree_legacy": {"enabled": true, "command_senders": [LEGACY_PC]},
        },
        "firewall": {
            "max_angular": {"/cmd_vel": 1.0},
            "allow": {"/cmd_vel": ["identity:teleop_twist"]},
        },
        "motion_monitor": {"feedback_sources": {"/odom": "wheel_odometry"}},
        "policy_path": policy,
        "blackbox": {"dir": dir.join("blackbox"), "key_file": key, "key_id": "test-key",
                     "boot_id": "test-boot", "allow_hmac": true},
        "spool": {"dir": spool},
        "event_inputs": [],
        "context": {"safety_state": "moving_slow"},
        "daemon": {"tick_ms": 50, "heartbeat_ms": 200, "silence_ms": 60000, "lag_ms": 5000,
                   "health_report_ms": 0, "exit_when_inputs_end": true},
    });
    let cfg_path = dir.join("agentd.json");
    std::fs::write(&cfg_path, serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();
    let r = robodr_agentd::load(&cfg_path).unwrap();
    let mut log = Vec::new();
    let sum = robodr_agentd::run(&r, &|| false, &mut log).unwrap();
    assert_eq!(
        sum.reason,
        robodr_agentd::StopReason::InputsEnded,
        "{}",
        String::from_utf8_lossy(&log)
    );
    // Every spooled finding is a valid contract message.
    for sub in ["ready", "acked"] {
        if let Ok(rd) = std::fs::read_dir(spool.join(sub)) {
            for e in rd {
                let rec: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(e.unwrap().path()).unwrap()).unwrap();
                robodr_ocsf::parse_and_validate(rec["value"].as_str().unwrap()).unwrap();
            }
        }
    }
    spool
}

fn carrier() -> Vec<robodr_attack_sim::Frame> {
    read_capture(&fixture("fastrtps_baseline.pcap")).unwrap()
}

fn params() -> Params {
    Params {
        count: 600,
        ..Params::default()
    }
}

#[test]
fn the_clean_carrier_raises_no_expected_rule() {
    let dir = tmpdir("clean-pcap");
    let pcap = dir.join("clean.pcap");
    write_capture(&pcap, &carrier()).unwrap();
    let spool = run_daemon("clean", &pcap);
    let (seen, bad) = score::load(&spool).unwrap();
    assert_eq!(bad, 0);
    for s in Scenario::ALL {
        for r in s.expected() {
            assert!(
                !seen.iter().any(|x| x.rule_id == *r),
                "{s}: {r} without the attack: {:?}",
                seen.iter().map(|x| &x.rule_id).collect::<Vec<_>>()
            );
        }
    }
}

#[test]
fn every_scenario_produces_its_expected_findings() {
    let base = carrier();
    let mut failures = Vec::new();
    for s in Scenario::ALL {
        let dir = tmpdir(&format!("{s}-pcap"));
        let pcap = dir.join("attack.pcap");
        let frames = generate(s, &base, &params()).unwrap();
        write_capture(&pcap, &frames).unwrap();
        let spool = run_daemon(s.name(), &pcap);
        let (seen, bad) = score::load(&spool).unwrap();
        assert_eq!(bad, 0);
        let r = score::report(&[s], &seen, None);
        eprintln!("{s}: {}", r);
        if r["pass"] != true {
            failures.push(format!("{s}: {r:#}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
