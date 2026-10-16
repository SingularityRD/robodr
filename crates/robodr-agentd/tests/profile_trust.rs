//! agentd and profile trust: signature required to enforce, anti-rollback
//! state written only when the daemon starts (not by `--check-config` /
//! `resolve`), version label from the signed metadata, removed
//! `robot.profile_version`.

mod common;

use common::pcap::{robot_profile, scenario_frames};
use common::*;
use robodr_ocsf::Mode;
use robodr_ros2_pipeline::{Pipeline, ProfileStatus};

fn run_capture(
    s: &Setup,
) -> (
    Vec<(robodr_agentd::SpoolRecord, robodr_ocsf::FindingEnvelope)>,
    String,
) {
    let pcap = s.pcap(&scenario_frames(2));
    let cfg = s.config(
        serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}}),
        serde_json::json!([]),
        serde_json::json!({"exit_when_inputs_end": true}),
    );
    let mut log = Vec::new();
    let sum = robodr_agentd::run(&s.resolve(&cfg), &|| false, &mut log).unwrap();
    let found = spooled(&s.spool);
    assert_verified(&s.blackbox, Some(sum.finished.checkpoint), &found);
    (found, String::from_utf8(log).unwrap())
}

#[test]
fn signed_profile_enforces_with_its_version_and_persists_state_at_start() {
    let mut prof = robot_profile(true);
    prof.metadata = Some(metadata(7));
    let s = setup("trust-ok", &prof);
    let state = s.dir.join("profile-state.json");
    // resolve (what --check-config does) decides but writes nothing.
    let cfg = s.config(
        serde_json::json!({}),
        serde_json::json!([{"kind": "stdin"}]),
        serde_json::json!({}),
    );
    let r = s.resolve(&cfg);
    assert!(r.profile.file_check.is_ok(), "{:?}", r.profile.file_check);
    assert!(r.profile_state_commit.is_some());
    assert!(!state.exists());

    let (found, _) = run_capture(&s);
    assert!(!found.is_empty());
    for (_, e) in &found {
        assert_eq!(e.entity_context.mode, Mode::Enforce);
        assert_eq!(e.entity_context.profile.version, "7");
    }
    let st = robodr_commission::trust::load_state(&state)
        .unwrap()
        .unwrap();
    assert_eq!(st.profile_version, 7);
}

#[test]
fn unsigned_or_rolled_back_profile_runs_observe_only_with_a_finding() {
    let s = setup("trust-unsigned", &robot_profile(true));
    std::fs::remove_file(robodr_commission::sig_path_for(&s.profile)).unwrap();
    let (found, log) = run_capture(&s);
    let r = rules(&found);
    assert_eq!(r[0], "robot.ros2.profile_refused", "{r:?}");
    assert!(log.contains("no signature file"), "{log}");
    for (_, e) in &found {
        assert_eq!(e.entity_context.mode, Mode::Observe);
        assert_eq!(e.entity_context.profile.version, "untrusted");
    }
    assert!(!s.dir.join("profile-state.json").exists());

    // Anti-rollback: v3 accepted, then v2 offered.
    let mut v3 = robot_profile(true);
    v3.metadata = Some(metadata(3));
    let s = setup("trust-rollback", &v3);
    let _ = run_capture(&s);
    let mut v2 = robot_profile(true);
    v2.metadata = Some(metadata(2));
    write_profile(&s.profile, &v2);
    std::fs::remove_dir_all(&s.spool).unwrap();
    std::fs::remove_dir_all(&s.blackbox).unwrap();
    let (found, log) = run_capture(&s);
    assert_eq!(rules(&found)[0], "robot.ros2.profile_refused");
    assert!(log.contains("rollback refused"), "{log}");
    assert!(found
        .iter()
        .all(|(_, e)| e.entity_context.mode == Mode::Observe));
    let st = robodr_commission::trust::load_state(&s.dir.join("profile-state.json"))
        .unwrap()
        .unwrap();
    assert_eq!(
        st.profile_version, 3,
        "a refused profile never moves the state"
    );

    // The operator names v2's digest: accepted, state lowered.
    let digest = robodr_commission::file_digest(&std::fs::read(&s.profile).unwrap());
    let pcap = s.pcap(&scenario_frames(1));
    let mut cfg = s.config(
        serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}}),
        serde_json::json!([]),
        serde_json::json!({"exit_when_inputs_end": true}),
    );
    cfg["sensor"]["profile_trust"]["allow_rollback"] = digest.into();
    std::fs::remove_dir_all(&s.spool).unwrap();
    std::fs::remove_dir_all(&s.blackbox).unwrap();
    let r = s.resolve(&cfg);
    assert!(r
        .warnings
        .iter()
        .any(|w| w.contains("allow_rollback is set")));
    robodr_agentd::run(&r, &|| false, &mut Vec::new()).unwrap();
    let st = robodr_commission::trust::load_state(&s.dir.join("profile-state.json"))
        .unwrap()
        .unwrap();
    assert_eq!(st.profile_version, 2);
}

#[test]
fn trust_config_errors_and_removed_profile_version() {
    let s = setup("trust-cfg", &robot_profile(true));
    let base = s.config(
        serde_json::json!({}),
        serde_json::json!([{"kind": "stdin"}]),
        serde_json::json!({}),
    );
    let load = |cfg: &serde_json::Value| robodr_agentd::load(&s.write_config(cfg));

    let mut c = base.clone();
    c["robot"]["profile_version"] = "v3".into();
    let e = load(&c).unwrap_err();
    assert!(e.contains("robot.profile_version was removed"), "{e}");

    let mut c = base.clone();
    c["sensor"]["profile_trust"]["trusted_key"] = "/x".into();
    assert!(load(&c).unwrap_err().contains("unknown key"));

    let mut c = base.clone();
    c["sensor"]["profile_trust"]["trusted_keys"] = "relative.json".into();
    assert!(load(&c).unwrap_err().contains("absolute"));

    let mut c = base.clone();
    c["sensor"]["profile_trust"]["allow_rollback"] = "3".into();
    assert!(load(&c).unwrap_err().contains("allow_rollback"));

    // No profile_trust at all: loads, warns, refuses the locked profile.
    let mut c = base.clone();
    c["sensor"].as_object_mut().unwrap().remove("profile_trust");
    let r = load(&c).unwrap();
    assert!(r.warnings.iter().any(|w| w.contains("observe-only")));
    let p = Pipeline::from_loaded(r.profile.clone(), r.sensor.pipeline.clone());
    assert!(matches!(p.status(), ProfileStatus::FileRejected(_)));

    // Wrong platform expectation.
    let mut c = base.clone();
    c["sensor"]["profile_trust"]["expect_platform"] = "drone".into();
    let r = load(&c).unwrap();
    let p = Pipeline::from_loaded(r.profile.clone(), r.sensor.pipeline.clone());
    assert!(matches!(p.status(), ProfileStatus::FileRejected(w) if w.contains("platform")));
    // Matching unit expectation is fine.
    let mut c = base.clone();
    c["sensor"]["profile_trust"]["expect_unit_id"] = ROBOT.into();
    let r = load(&c).unwrap();
    assert!(r.profile.file_check.is_ok());
}
