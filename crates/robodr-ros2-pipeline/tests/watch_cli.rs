//! `robodr-ros2-watch` driven through `std::process::Command` on generated
//! pcaps.

mod common;

use std::path::Path;
use std::process::{Command, Output};

use common::*;
use serde_json::Value;

fn watch(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_robodr-ros2-watch"))
        .args(args)
        .output()
        .expect("run robodr-ros2-watch")
}

fn lines(out: &Output) -> Vec<Value> {
    String::from_utf8(out.stdout.clone())
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad JSON line {l:?}: {e}")))
        .collect()
}

/// A locked profile is written sealed, versioned and signed, exactly as
/// `robodr-commission lock --sign-key` writes it (the sensor refuses to
/// enforce anything else); the matching trust file is `trust_of(path)`.
fn write_profile(path: &Path, locked: bool) {
    let p = robot_profile(locked);
    if locked {
        write_signed(path, p);
    } else {
        write(path, serde_json::to_string_pretty(&p).unwrap().as_bytes());
    }
}

/// Stamp metadata on a locked profile, seal, sign, write profile + .sig +
/// trust file.
fn write_signed(path: &Path, mut p: robodr_events::profile::Profile) {
    p.metadata = Some(robodr_events::profile::ProfileMetadata {
        schema_version: robodr_events::profile::PROFILE_SCHEMA_VERSION,
        profile_version: 1,
        platform: "ugv-lab".into(),
        unit_id: None,
        locked_by: "test".into(),
        locked_at: 1_790_000_000,
        parent_digest: None,
        attestation: None,
    });
    let text = robodr_commission::sealed_text(&p).unwrap();
    write(path, text.as_bytes());
    let key = robodr_blackbox::Ed25519SigningKey::from_seed("lab", &[1; 32]).unwrap();
    let sig = robodr_commission::ProfileSignature::create(text.as_bytes(), &key).unwrap();
    write(
        &robodr_commission::sig_path_for(path),
        sig.to_text().as_bytes(),
    );
    write(
        &trust_of(path),
        robodr_commission::trust::trust_keys_text(&[key.verifying_key()]).as_bytes(),
    );
}

fn trust_of(path: &Path) -> std::path::PathBuf {
    path.with_extension("trust.json")
}

#[test]
fn pcap_run_prints_expected_json_lines() {
    let dir = temp_dir("cli-locked");
    let (pcap_path, prof) = (dir.join("lab.pcap"), dir.join("profile.json"));
    write(&pcap_path, &pcap(&scenario_frames(4)));
    write_profile(&prof, true);
    let trust = trust_of(&prof);
    let out = watch(&[
        "--profile",
        prof.to_str().unwrap(),
        "--pcap",
        pcap_path.to_str().unwrap(),
        "--stats",
        "--trusted-keys",
        trust.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{out:?}");
    let l = lines(&out);
    assert_eq!(l.len(), 2, "{l:#?}");
    assert_eq!(l[0]["rule"], "robot.ros2.unknown_participant");
    assert_eq!(l[0]["severity"], "high");
    assert_eq!(l[0]["src_ip"], "192.168.50.66");
    assert_eq!(l[1]["rule"], "robot.ros2.unauthorized_motion_writer");
    assert_eq!(l[1]["severity"], "critical");
    for x in &l {
        assert_eq!(x["mode"], "enforce");
        assert_eq!(x["observe_only"], false);
        assert_eq!(x["profile_model"], "ugv-lab");
        assert_eq!(x["profile_status"], "enforcing");
    }
    let stderr = String::from_utf8(out.stderr).unwrap();
    let stats: Value = serde_json::from_str(stderr.lines().last().unwrap()).unwrap();
    assert_eq!(stats["pipeline"]["findings"], 2);
    assert_eq!(stats["pipeline"]["duplicates"], 4);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn unlocked_and_invalid_profiles_are_observe_only() {
    let dir = temp_dir("cli-observe");
    let pcap_path = dir.join("lab.pcap");
    write(&pcap_path, &pcap(&scenario_frames(1)));

    let unlocked = dir.join("unlocked.json");
    write_profile(&unlocked, false);
    let out = watch(&[
        "--profile",
        unlocked.to_str().unwrap(),
        "--pcap",
        pcap_path.to_str().unwrap(),
    ]);
    assert!(out.status.success());
    let l = lines(&out);
    assert_eq!(l.len(), 2);
    assert!(l.iter().all(|x| x["observe_only"] == true));
    assert!(String::from_utf8_lossy(&out.stderr).contains("NOT locked"));

    let invalid = dir.join("invalid.json");
    write(
        &invalid,
        br#"{"model": "ugv-lab", "locked": true, "participants": ["NOT-HEX"],
             "motion_envelopes": {"/cmd_vel": {"max_linear_speed": -2.0}}}"#,
    );
    let out = watch(&[
        "--profile",
        invalid.to_str().unwrap(),
        "--pcap",
        pcap_path.to_str().unwrap(),
    ]);
    assert!(out.status.success());
    let l = lines(&out);
    assert_eq!(l[0]["rule"], "robot.ros2.profile_refused");
    assert_eq!(l[0]["src_ip"], "local");
    assert!(l.iter().all(|x| x["observe_only"] == true));
    assert!(l.iter().all(|x| x["profile_status"] == "refused"));
    assert!(l
        .iter()
        .any(|x| x["rule"] == "robot.ros2.unauthorized_motion_writer"));
    assert!(String::from_utf8_lossy(&out.stderr).contains("REFUSED"));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn errors_and_usage_exit_codes() {
    let dir = temp_dir("cli-errors");
    let prof = dir.join("profile.json");
    write_profile(&prof, true);
    let p = prof.to_str().unwrap();

    // Usage error.
    let out = watch(&["--profile", p]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("USAGE"));
    // Help / version.
    let out = watch(&["--help"]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("--pcap"));
    assert!(watch(&["--version"]).status.success());
    // Missing capture file.
    let out = watch(&["--profile", p, "--pcap", "/nonexistent/lab.pcap"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    // Missing profile.
    let out = watch(&["--profile", "/nonexistent/p.json", "--pcap", "/x"]);
    assert_eq!(out.status.code(), Some(1));
    // Truncated capture: findings printed, then exit 1.
    let mut bytes = pcap(&scenario_frames(1));
    bytes.truncate(bytes.len() - 7);
    let t = dir.join("truncated.pcap");
    write(&t, &bytes);
    let trust = trust_of(&prof);
    let out = watch(&[
        "--profile",
        p,
        "--pcap",
        t.to_str().unwrap(),
        "--trusted-keys",
        trust.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(lines(&out).len(), 2);
    assert!(String::from_utf8_lossy(&out.stderr).contains("capture ended with an error"));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn rtps_fixture_pcap_with_empty_profile() {
    let dir = temp_dir("cli-fixtures");
    let mut frames = Vec::new();
    let mut bins: Vec<_> = std::fs::read_dir(rtps_fixtures_dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "bin"))
        .collect();
    bins.sort();
    for b in bins {
        frames.push(frame(ROGUE_IP, ROBOT_IP, 7410, &std::fs::read(b).unwrap()));
    }
    let pcap_path = dir.join("fixtures.pcap");
    write(&pcap_path, &pcap(&frames));
    let prof = dir.join("empty.json");
    let empty = robodr_events::profile::Profile {
        model: "empty".into(),
        locked: true,
        ..Default::default()
    };
    write_signed(&prof, empty);
    let trust = trust_of(&prof);
    let out = watch(&[
        "--profile",
        prof.to_str().unwrap(),
        "--pcap",
        pcap_path.to_str().unwrap(),
        "--domain",
        "0",
        "--trusted-keys",
        trust.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{out:?}");
    let l = lines(&out);
    // 4 participants + 5 writers + 1 reader (see tests/rtps_fixtures.rs),
    // plus, at the end of the replay, the two participants whose SEDP is in
    // the fixtures but whose SPDP is not (big-endian `rt/scan` and the
    // service-request participant): "never announced", Medium.
    assert_eq!(l.len(), 12, "{l:#?}");
    let unannounced: Vec<_> = l
        .iter()
        .filter(|x| x["rule"] == "robot.ros2.endpoint_unannounced_participant")
        .collect();
    assert_eq!(unannounced.len(), 2, "{l:#?}");
    assert!(unannounced.iter().all(|x| x["severity"] == "medium"));
    assert!(l
        .iter()
        .all(|x| x["rule"] != "robot.ros2.endpoint_source_mismatch"));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn locked_profile_without_trust_or_signature_is_refused() {
    let dir = temp_dir("cli-untrusted");
    let (pcap_path, prof) = (dir.join("lab.pcap"), dir.join("profile.json"));
    write(&pcap_path, &pcap(&scenario_frames(1)));
    write_profile(&prof, true);
    let trust = trust_of(&prof);
    let state = dir.join("state.json");
    // No --trusted-keys: observe-only, profile_refused first.
    let out = watch(&[
        "--profile",
        prof.to_str().unwrap(),
        "--pcap",
        pcap_path.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{out:?}");
    let l = lines(&out);
    assert_eq!(l[0]["rule"], "robot.ros2.profile_refused");
    assert!(l.iter().all(|x| x["observe_only"] == true));
    assert!(String::from_utf8_lossy(&out.stderr).contains("trusted_keys is not set"));
    // Trusted, with state: enforcing, state written.
    let args = |extra: &[&str]| {
        let mut a = vec![
            "--profile",
            prof.to_str().unwrap(),
            "--pcap",
            pcap_path.to_str().unwrap(),
            "--trusted-keys",
            trust.to_str().unwrap(),
            "--profile-state",
            state.to_str().unwrap(),
        ];
        a.extend_from_slice(extra);
        watch(&a)
    };
    let out = args(&[]);
    assert!(
        lines(&out).iter().all(|x| x["mode"] == "enforce"),
        "{out:?}"
    );
    assert!(state.exists());
    // Signature removed: refused.
    std::fs::remove_file(robodr_commission::sig_path_for(&prof)).unwrap();
    let out = args(&[]);
    let l = lines(&out);
    assert_eq!(l[0]["rule"], "robot.ros2.profile_refused");
    assert!(
        l[0]["detail"].as_str().unwrap().contains("signature"),
        "{l:?}"
    );
    // Bad flag values are usage errors.
    assert_eq!(args(&["--allow-rollback", "v1"]).status.code(), Some(2));
    assert_eq!(args(&["--expect-platform", "a b"]).status.code(), Some(2));
    std::fs::remove_dir_all(&dir).ok();
}

/// T91: `--check-config` validates pulsar.toml offline, reports typos the
/// daemon would only log, evaluates the profile's trust without writing the
/// anti-rollback state, and is read-only.
#[test]
fn check_config_validates_pulsar_toml_offline() {
    let dir = temp_dir("cli-check-config");
    let prof = dir.join("profile.json");
    write_profile(&prof, true);
    let trust = trust_of(&prof);
    let state = dir.join("state.json");
    let cfg = dir.join("pulsar.toml");
    let section = |extra: &str| {
        format!(
            "[pulsar]\n\n[module.robodr-sensor-ros2]\nenabled = true\nprofile_path = {:?}\n\
             [module.robodr-sensor-ros2.capture]\nenabled = false\n\
             [module.robodr-sensor-ros2.profile_trust]\ntrusted_keys = {:?}\nstate_file = {:?}\n{extra}",
            prof.to_str().unwrap(),
            trust.to_str().unwrap(),
            state.to_str().unwrap(),
        )
    };
    let check = |text: &str, extra: &[&str]| {
        write(&cfg, text.as_bytes());
        let mut a = vec!["--check-config", cfg.to_str().unwrap()];
        a.extend_from_slice(extra);
        watch(&a)
    };

    // Signed, trusted, locked: valid, would enforce, state NOT written
    // (one warning: no revocation list).
    let out = check(&section(""), &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{out:?}");
    assert!(stdout.contains("would be ENFORCED"), "{stdout}");
    assert!(stdout.contains("configuration OK"), "{stdout}");
    assert!(!state.exists(), "the check must not write the state file");

    // Typo in a key: still valid (the daemon ignores it), warned; --strict fails.
    let typo = section("expect_platfrom = \"ugv-lab\"\n");
    let out = check(&typo, &[]);
    assert!(out.status.success(), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("`profile_trust.expect_platfrom`"));
    assert_eq!(check(&typo, &["--strict"]).status.code(), Some(1));

    // Out-of-range value: invalid.
    let out = check(
        &section("").replace("enabled = false", "enabled = true\nqueue_capacity = 0"),
        &[],
    );
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("queue_capacity"));

    // Signature removed: the profile would be refused -> warning, --strict fails.
    std::fs::remove_file(robodr_commission::sig_path_for(&prof)).unwrap();
    let out = check(&section(""), &[]);
    assert!(out.status.success(), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("REFUSED for enforcement"));
    assert_eq!(check(&section(""), &["--strict"]).status.code(), Some(1));

    // Syntax error, missing file: invalid.
    assert_eq!(
        check("[module.robodr-sensor-ros2\n", &[]).status.code(),
        Some(1)
    );
    let out = watch(&["--check-config", dir.join("absent.toml").to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));

    // Usage: a run flag next to --check-config, or no value.
    let out = watch(&["--check-config", cfg.to_str().unwrap(), "--pcap", "x.pcap"]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert_eq!(watch(&["--check-config"]).status.code(), Some(2));
    std::fs::remove_dir_all(&dir).ok();
}

/// The shipped example section has only known keys and valid syntax (the
/// files it names are absent on a build host, so it is not otherwise OK).
#[test]
fn check_config_shipped_example_has_no_unknown_keys() {
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/robodr.toml.example");
    let out = watch(&["--check-config", example.to_str().unwrap()]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("unknown key"), "{stderr}");
    assert!(!stderr.contains("TOML syntax error"), "{stderr}");
    assert!(stderr.contains("profile_path"), "{stderr}");
}
