//! T12: with `commissioning` configured, the executor honours the response
//! policy's `oem_validated` and its adapters' `oem_validated` only for the
//! files the signed locked profile binds, and verifies that itself
//! (`config::load_commissioned`, used at start and before every order).

use std::path::{Path, PathBuf};

use robodr_blackbox::Ed25519SigningKey;
use robodr_commission::trust::bound::{bytes_digest, digest_for_role};
use robodr_commission::trust::{sig_path_for, trust_keys_text, ProfileSignature};
use robodr_events::profile::{Envelope, Profile, ProfileMetadata, PROFILE_SCHEMA_VERSION};
use robodr_executor::config::load_commissioned;
use serde_json::Value;

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "robodr-executor-commissioning-{}-{tag}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed("oem", &[5; 32]).unwrap()
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config")
}

fn policy_text() -> String {
    std::fs::read_to_string(root().join("response-policy.example.json"))
        .unwrap()
        .replace("\"oem_validated\": false", "\"oem_validated\": true")
}

/// executor.motion.example.json with its paths in `d`, every adapter
/// validated, and (optionally) a `commissioning` section.
fn config_text(d: &Path, commissioning: bool) -> String {
    let mut v: Value = serde_json::from_str(
        &std::fs::read_to_string(root().join("executor.motion.example.json")).unwrap(),
    )
    .unwrap();
    v["policy_path"] = d.join("policy.json").to_str().unwrap().into();
    for (_, a) in v["motion"].as_object_mut().unwrap().iter_mut() {
        if let Some(o) = a.as_object_mut() {
            if o.contains_key("oem_validated") {
                o.insert("oem_validated".into(), true.into());
            }
        }
    }
    if commissioning {
        v["commissioning"] = serde_json::json!({
            "profile_path": d.join("profile.json"),
            "trusted_keys": d.join("trust.json"),
        });
    }
    serde_json::to_string_pretty(&v).unwrap()
}

/// A signed locked profile binding `binds`.
fn write_profile(d: &Path, binds: &[(&str, String)]) {
    let mut p = Profile {
        model: "ugv".into(),
        locked: true,
        ..Default::default()
    };
    p.participants.insert("a".repeat(24));
    p.writer_topics.insert("/cmd_vel".into());
    p.motion_envelopes.insert(
        "/cmd_vel".into(),
        Envelope {
            max_linear_speed: Some(1.0),
            ..Default::default()
        },
    );
    p.metadata = Some(ProfileMetadata {
        schema_version: PROFILE_SCHEMA_VERSION,
        profile_version: 1,
        platform: "ugv".into(),
        unit_id: None,
        locked_by: "alice".into(),
        locked_at: 1_790_000_000,
        parent_digest: None,
        attestation: None,
    });
    for (r, dg) in binds {
        p.bound_config.insert((*r).into(), dg.clone());
    }
    let text = robodr_commission::sealed_text(&p).unwrap();
    let path = d.join("profile.json");
    std::fs::write(&path, &text).unwrap();
    let sig = ProfileSignature::create(text.as_bytes(), &key()).unwrap();
    std::fs::write(sig_path_for(&path), sig.to_text()).unwrap();
}

fn setup(tag: &str, commissioning: bool) -> (PathBuf, PathBuf) {
    let d = tmpdir(tag);
    std::fs::write(d.join("policy.json"), policy_text()).unwrap();
    std::fs::write(
        d.join("trust.json"),
        trust_keys_text(&[key().verifying_key()]),
    )
    .unwrap();
    let cfg = d.join("executor.json");
    std::fs::write(&cfg, config_text(&d, commissioning)).unwrap();
    (d, cfg)
}

fn validated_adapters(r: &robodr_executor::config::Resolved) -> bool {
    r.config.motion.as_ref().unwrap().any_validated()
}

#[test]
fn bound_files_keep_their_flags() {
    let (d, cfg) = setup("bound", true);
    let text = std::fs::read_to_string(&cfg).unwrap();
    write_profile(
        &d,
        &[
            ("response_policy", bytes_digest(policy_text().as_bytes())),
            (
                "executor_motion",
                digest_for_role("executor_motion", &text).unwrap(),
            ),
        ],
    );
    let (r, p, notes) = load_commissioned(&cfg).unwrap();
    assert!(p.oem_validated, "{notes:?}");
    assert!(validated_adapters(&r), "{notes:?}");
    assert!(notes.is_empty(), "{notes:?}");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn edited_or_unbound_files_lose_their_flags() {
    let (d, cfg) = setup("edited", true);
    let text = std::fs::read_to_string(&cfg).unwrap();
    write_profile(
        &d,
        &[
            ("response_policy", bytes_digest(policy_text().as_bytes())),
            (
                "executor_motion",
                digest_for_role("executor_motion", &text).unwrap(),
            ),
        ],
    );
    // A site edit of the policy after commissioning (one byte).
    std::fs::write(d.join("policy.json"), format!("{} ", policy_text())).unwrap();
    let (r, p, notes) = load_commissioned(&cfg).unwrap();
    assert!(!p.oem_validated, "{notes:?}");
    assert!(
        validated_adapters(&r),
        "the motion section is still the bound one"
    );
    assert!(
        notes.iter().any(|n| n.contains("response policy")),
        "{notes:?}"
    );

    // A motion section edited (an adapter's settings changed): every
    // adapter loses its flag; the network section may change freely.
    std::fs::write(d.join("policy.json"), policy_text()).unwrap();
    let mut v: Value = serde_json::from_str(&text).unwrap();
    v["network"]["management"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({"cidr": "10.20.0.7", "proto": "tcp", "port": 22}));
    std::fs::write(&cfg, serde_json::to_string(&v).unwrap()).unwrap();
    let (r, p, _) = load_commissioned(&cfg).unwrap();
    assert!(p.oem_validated && validated_adapters(&r));
    v["motion"]["safe_pause_ttl_s"] = 7.into();
    std::fs::write(&cfg, serde_json::to_string(&v).unwrap()).unwrap();
    let (r, p, notes) = load_commissioned(&cfg).unwrap();
    assert!(p.oem_validated);
    assert!(!validated_adapters(&r), "{notes:?}");

    // A forged profile (signature no longer matches): nothing holds.
    let pp = d.join("profile.json");
    let t = std::fs::read_to_string(&pp)
        .unwrap()
        .replacen("\"ugv\"", "\"ugw\"", 1);
    std::fs::write(&pp, t).unwrap();
    let (r, p, notes) = load_commissioned(&cfg).unwrap();
    assert!(!p.oem_validated && !validated_adapters(&r), "{notes:?}");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn without_commissioning_the_flags_are_reported_unsigned() {
    let (d, cfg) = setup("legacy", false);
    let (r, p, notes) = load_commissioned(&cfg).unwrap();
    assert!(p.oem_validated && validated_adapters(&r));
    assert!(notes.iter().any(|n| n.contains("UNSIGNED")), "{notes:?}");
    let _ = std::fs::remove_dir_all(&d);
}
