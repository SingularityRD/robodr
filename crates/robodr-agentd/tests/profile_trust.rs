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

#[test]
fn deleted_state_file_is_detected_through_the_black_box() {
    // v3 accepted: state written and the acceptance recorded in the black
    // box (start note + heartbeats).
    let mut v3 = robot_profile(true);
    v3.metadata = Some(metadata(3));
    let s = setup("trust-chain", &v3);
    let _ = run_capture(&s);
    let state = s.dir.join("profile-state.json");
    let accepted = robodr_commission::trust::load_state(&state)
        .unwrap()
        .unwrap();
    let notes: Vec<_> = records(&s.blackbox)
        .iter()
        .filter_map(|r| robodr_commission::trust::accepted_from_note(&r.payload))
        .collect();
    assert!(!notes.is_empty());
    assert!(notes.iter().all(|n| *n == accepted));

    // Root deletes the state file and installs the older v2 (still validly
    // signed). The black box is kept.
    std::fs::remove_file(&state).unwrap();
    let mut v2 = robot_profile(true);
    v2.metadata = Some(metadata(2));
    write_profile(&s.profile, &v2);
    std::fs::remove_dir_all(&s.spool).unwrap();
    let cfg = s.config(
        serde_json::json!({}),
        serde_json::json!([{"kind": "stdin"}]),
        serde_json::json!({}),
    );
    // --check-config already sees it.
    let r = s.resolve(&cfg);
    assert!(r.profile_alarm.is_some());
    assert!(r.profile.file_check.is_err());
    assert!(r
        .warnings
        .iter()
        .any(|w| w.starts_with("CRITICAL") && w.contains("missing")));
    let (found, log) = run_capture(&s);
    let rs = rules(&found);
    assert!(
        rs.contains(&"robot.ros2.profile_refused".to_string()),
        "{rs:?}"
    );
    let tamper: Vec<_> = found
        .iter()
        .filter(|(_, e)| e.entity_context.rule_id == "robot.ros2.profile_state_tampered")
        .collect();
    assert_eq!(tamper.len(), 1, "{rs:?}");
    assert_eq!(tamper[0].1.severity, robodr_events::Severity::Critical);
    assert_eq!(tamper[0].1.entity_context.mode, Mode::Observe);
    assert!(
        log.contains("rollback refused") && log.contains("CRITICAL"),
        "{log}"
    );
    assert!(found
        .iter()
        .all(|(_, e)| e.entity_context.mode == Mode::Observe));
    assert!(!state.exists(), "a refused profile never writes the state");

    // v3 back: enforced again, the alarm is reported once more and the
    // state is restored from the black-box record; the next start is quiet.
    write_profile(&s.profile, &v3);
    std::fs::remove_dir_all(&s.spool).unwrap();
    let (found, _) = run_capture(&s);
    assert!(rules(&found).contains(&"robot.ros2.profile_state_tampered".to_string()));
    assert_eq!(
        robodr_commission::trust::load_state(&state).unwrap(),
        Some(accepted)
    );
    std::fs::remove_dir_all(&s.spool).unwrap();
    let r = s.resolve(&cfg);
    assert!(r.profile_alarm.is_none() && r.profile.file_check.is_ok());
    let (found, _) = run_capture(&s);
    assert!(!rules(&found).contains(&"robot.ros2.profile_state_tampered".to_string()));
}

#[test]
fn revocation_list_and_config_keys() {
    let mut v1 = robot_profile(true);
    v1.metadata = Some(metadata(1));
    let s = setup("trust-revoke", &v1);
    let root = robodr_blackbox::Ed25519SigningKey::from_seed("root", &[0x77; 32]).unwrap();
    let roots = s.dir.join("roots.json");
    std::fs::write(
        &roots,
        robodr_commission::trust::trust_roots_text(&[root.verifying_key()]),
    )
    .unwrap();
    // With trust roots the trust file must be root-signed (this
    // hand-written profile carries no operator attestation: the root-signed
    // trust file opts out of requiring one).
    let tf = robodr_commission::trust::trust_file_text_with(
        &[profile_key().verifying_key()],
        &robodr_commission::trust::TrustFileOptions {
            require_attestation: Some(false),
            ..Default::default()
        },
    );
    let tpath = s.dir.join("profile-trust.json");
    std::fs::write(&tpath, &tf).unwrap();
    std::fs::write(
        robodr_commission::sig_path_for(&tpath),
        robodr_commission::ProfileSignature::create_for(
            robodr_commission::trust::SigKind::TrustFile,
            tf.as_bytes(),
            &root,
        )
        .unwrap()
        .to_text(),
    )
    .unwrap();
    let revs = s.dir.join("revocations.json");
    let digest = robodr_commission::file_digest(&std::fs::read(&s.profile).unwrap());
    let list = robodr_commission::trust::RevocationList::create(
        1,
        1_790_000_000,
        "ugv-lab",
        [digest],
        [],
        &root,
    )
    .unwrap();
    std::fs::write(&revs, list.to_text()).unwrap();
    let mut cfg = s.config(
        serde_json::json!({}),
        serde_json::json!([{"kind": "stdin"}]),
        serde_json::json!({}),
    );
    cfg["sensor"]["profile_trust"]["trust_roots"] = roots.to_str().unwrap().into();
    cfg["sensor"]["profile_trust"]["revocation_list"] = revs.to_str().unwrap().into();
    cfg["sensor"]["profile_trust"]["revocation_policy"] = "required".into();
    let r = s.resolve(&cfg);
    let p = Pipeline::from_loaded(r.profile.clone(), r.sensor.pipeline.clone());
    assert!(matches!(p.status(), ProfileStatus::FileRejected(w) if w.contains("revoked")));
    // The trust file without its root signature: refused (roots configured).
    let sig = std::fs::read(robodr_commission::sig_path_for(&tpath)).unwrap();
    std::fs::remove_file(robodr_commission::sig_path_for(&tpath)).unwrap();
    let r = s.resolve(&cfg);
    assert!(
        matches!(&r.profile.file_check, Err(e) if e.to_string().contains("must be signed")),
        "{:?}",
        r.profile.file_check
    );
    std::fs::write(robodr_commission::sig_path_for(&tpath), sig).unwrap();
    // Required but missing.
    std::fs::remove_file(&revs).unwrap();
    let r = s.resolve(&cfg);
    assert!(r.profile.file_check.is_err());
    // Bad policy value / list without roots: configuration errors.
    let load = |c: &serde_json::Value| robodr_agentd::load(&s.write_config(c));
    let mut c = cfg.clone();
    c["sensor"]["profile_trust"]["revocation_policy"] = "sometimes".into();
    assert!(load(&c).is_err());
    let mut c = cfg.clone();
    c["sensor"]["profile_trust"]
        .as_object_mut()
        .unwrap()
        .remove("trust_roots");
    assert!(load(&c).unwrap_err().contains("trust_roots"));
}

/// T12: `oem_validated` counts only for the policy file the trusted locked
/// profile binds. An edited (or unbound) policy that still claims it is
/// treated as not validated and reported once at start.
#[test]
fn unbound_or_edited_policy_is_not_oem_validated() {
    let mut prof = robot_profile(true);
    prof.metadata = Some(metadata(4));
    let s = setup("trust-policy", &prof);
    let cfg = s.config(
        serde_json::json!({}),
        serde_json::json!([{"kind": "stdin"}]),
        serde_json::json!({}),
    );
    // The setup binds exactly the installed policy: honoured.
    let r = s.resolve(&cfg);
    assert!(r.policy.oem_validated);
    assert!(r.config_unattested.is_empty(), "{:?}", r.config_unattested);

    // One byte added to the policy file: not the commissioned one.
    let mut t = std::fs::read_to_string(&s.policy).unwrap();
    t.push('\n');
    std::fs::write(&s.policy, &t).unwrap();
    let r = s.resolve(&cfg);
    assert!(!r.policy.oem_validated);
    assert_eq!(r.config_unattested.len(), 1, "{:?}", r.config_unattested);
    assert!(
        r.config_unattested[0].contains("edited, replaced or rolled back"),
        "{:?}",
        r.config_unattested
    );

    // At start: one observe-only High finding.
    let (found, log) = run_capture(&s);
    let hits = found
        .iter()
        .filter(|(_, e)| e.entity_context.rule_id == "robot.agent.config_unattested")
        .count();
    assert_eq!(hits, 1, "{log}");
    assert!(log.contains("treated as NOT OEM-validated"), "{log}");

    // A profile that binds another policy: same outcome.
    let mut prof = robot_profile(true);
    prof.metadata = Some(metadata(5));
    prof.bound_config.insert(
        "response_policy".into(),
        format!("sha256:{}", "0".repeat(64)),
    );
    write_profile(&s.profile, &prof);
    std::fs::copy(demo_policy_path(), &s.policy).unwrap();
    let r = s.resolve(&cfg);
    assert!(!r.policy.oem_validated);
}
