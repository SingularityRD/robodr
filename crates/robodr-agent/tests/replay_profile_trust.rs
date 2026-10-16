//! `robodr-replay` and profile trust: the demo profile is enforced only
//! with its trust file, the version in findings comes from the signed
//! metadata, `--profile-version` is gone, and anti-rollback is opt-in.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::*;
use robodr_agent::replay::{self, ReplayOptions};
use robodr_responder::SafetyState;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_robodr-replay"))
}

fn args(bb: &Path, profile: &Path, trust: Option<&Path>, extra: &[&str]) -> Output {
    let ex = examples();
    let mut c = bin();
    c.arg("--events")
        .arg(ex.join("rogue-ugv.jsonl"))
        .arg("--profile")
        .arg(profile)
        .arg("--policy")
        .arg(ex.join("policy-oem-validated.json"))
        .arg("--blackbox")
        .arg(bb)
        .args(["--key-file", &key_arg(), "--robot-id", ROBOT])
        .args(["--safety-state", "moving_slow"]);
    if let Some(t) = trust {
        c.arg("--trusted-keys").arg(t);
    }
    c.args(extra).output().unwrap()
}

fn findings(o: &Output) -> Vec<serde_json::Value> {
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn mode_of(f: &serde_json::Value) -> String {
    let env = robodr_ocsf::parse_and_validate(&f.to_string()).unwrap();
    format!("{:?}", env.entity_context.mode)
}

fn demo() -> (PathBuf, PathBuf) {
    let ex = examples();
    (
        ex.join("ugv-demo.profile.json"),
        ex.join("ugv-demo.trust.json"),
    )
}

#[test]
fn trusted_demo_profile_enforces_with_signed_version() {
    let dir = tmpdir("rpt-ok");
    let (profile, trust) = demo();
    let o = args(&dir.join("bb"), &profile, Some(&trust), &[]);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("profile: version 1"), "{err}");
    let f = findings(&o);
    assert!(!f.is_empty());
    for x in &f {
        let env = robodr_ocsf::parse_and_validate(&x.to_string()).unwrap();
        assert_eq!(env.entity_context.profile.version, "1");
        assert_eq!(env.entity_context.mode, robodr_ocsf::Mode::Enforce);
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn untrusted_profile_is_observe_only_with_a_refusal_finding() {
    let dir = tmpdir("rpt-untrusted");
    let (profile, _) = demo();
    // No trust file.
    let o = args(&dir.join("bb1"), &profile, None, &[]);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(String::from_utf8_lossy(&o.stderr).contains("NOT enforced"));
    let f = findings(&o);
    let first = robodr_ocsf::parse_and_validate(&f[0].to_string()).unwrap();
    assert_eq!(first.entity_context.rule_id, "robot.ros2.profile_refused");
    assert!(f.iter().all(|x| mode_of(x) == "Observe"));
    assert!(f.iter().all(|x| {
        robodr_ocsf::parse_and_validate(&x.to_string())
            .unwrap()
            .entity_context
            .profile
            .version
            == "untrusted"
    }));

    // Wrong key in the trust file.
    let other = dir.join("other-trust.json");
    let k = robodr_blackbox::Ed25519SigningKey::from_seed("robodr-demo", &[9; 32]).unwrap();
    std::fs::write(
        &other,
        robodr_commission::trust::trust_keys_text(&[k.verifying_key()]),
    )
    .unwrap();
    let o = args(&dir.join("bb2"), &profile, Some(&other), &[]);
    assert_eq!(o.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&o.stderr).contains("does not verify"));

    // Tampered copy (one space) next to the original signature.
    let copy = dir.join("p.json");
    let text = std::fs::read_to_string(&profile).unwrap();
    std::fs::write(
        &copy,
        text.replacen("\"locked\": true", "\"locked\":  true", 1),
    )
    .unwrap();
    std::fs::copy(
        examples().join("ugv-demo.profile.json.sig"),
        dir.join("p.json.sig"),
    )
    .unwrap();
    let (_, trust) = demo();
    let o = args(&dir.join("bb3"), &copy, Some(&trust), &[]);
    assert_eq!(o.status.code(), Some(0));
    let f = findings(&o);
    let first = robodr_ocsf::parse_and_validate(&f[0].to_string()).unwrap();
    assert_eq!(first.entity_context.rule_id, "robot.ros2.profile_refused");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn removed_and_invalid_flags() {
    let dir = tmpdir("rpt-flags");
    let (profile, trust) = demo();
    let bb = dir.join("bb");
    let o = args(&bb, &profile, Some(&trust), &["--profile-version", "v3"]);
    assert_eq!(o.status.code(), Some(2));
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("--profile-version was removed"), "{err}");
    let o = args(
        &bb,
        &profile,
        Some(&trust),
        &["--allow-profile-rollback", "1"],
    );
    assert_eq!(o.status.code(), Some(2));
    assert!(!bb.exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

fn opts(bb: &Path, profile: &Path) -> ReplayOptions {
    let ex = examples();
    let mut o = ReplayOptions::new(
        ex.join("rogue-ugv.jsonl"),
        profile,
        ex.join("policy-oem-validated.json"),
        bb,
        KEY.to_vec(),
        ROBOT,
    );
    o.safety = SafetyState::MovingSlow;
    o.trusted_keys = Some(ex.join("ugv-demo.trust.json"));
    o
}

#[test]
fn opt_in_anti_rollback_state() {
    let dir = tmpdir("rpt-state");
    let (profile, _) = demo();
    let state = dir.join("state.json");
    // A state that already accepted version 5: the demo (version 1) is a
    // rollback.
    let st = robodr_commission::AcceptedState {
        format: robodr_commission::trust::STATE_FORMAT.into(),
        model: "ugv-demo-x1".into(),
        platform: "ugv-demo".into(),
        unit_id: None,
        profile_version: 5,
        digest: format!("sha256:{}", "0".repeat(64)),
    };
    std::fs::write(&state, robodr_commission::to_json(&st).unwrap()).unwrap();
    let mut o = opts(&dir.join("bb1"), &profile);
    o.profile_state = Some(state.clone());
    let mut out = Vec::new();
    let sum = replay::run(&o, &mut out, None, None).unwrap();
    assert!(sum
        .profile_refused
        .as_deref()
        .unwrap()
        .contains("rollback refused"));
    assert_eq!(sum.profile_version, "untrusted");
    // Named by digest: accepted, state lowered to 1.
    let digest = robodr_commission::file_digest(&std::fs::read(&profile).unwrap());
    let mut o = opts(&dir.join("bb2"), &profile);
    o.profile_state = Some(state.clone());
    o.allow_profile_rollback = Some(digest);
    let sum = replay::run(&o, &mut Vec::new(), None, None).unwrap();
    assert!(sum.profile_refused.is_none());
    assert_eq!(sum.profile_version, "1");
    let st = robodr_commission::trust::load_state(&state)
        .unwrap()
        .unwrap();
    assert_eq!(st.profile_version, 1);
    // Without the state option nothing is checked or written.
    let o = opts(&dir.join("bb3"), &profile);
    assert!(replay::run(&o, &mut Vec::new(), None, None)
        .unwrap()
        .profile_refused
        .is_none());
    // A hand-written draft is still observed (no trust needed).
    let draft = dir.join("draft.json");
    std::fs::write(&draft, r#"{"model":"ugv-demo-x1","locked":false}"#).unwrap();
    let sum = replay::run(&opts(&dir.join("bb4"), &draft), &mut Vec::new(), None, None).unwrap();
    assert!(sum.profile_refused.is_none());
    assert_eq!(sum.profile_version, "draft");
    // Garbage is still an error.
    std::fs::write(&draft, r#"{"model":"m","lockd":true}"#).unwrap();
    assert!(replay::run(&opts(&dir.join("bb5"), &draft), &mut Vec::new(), None, None).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}
