//! The demo profile in `examples/` is a real locked artifact: sealed, with
//! metadata, and signed by the **demo** profile key, whose public half is
//! `examples/ugv-demo.trust.json`. Ed25519 is deterministic, so the files
//! are reproducible from the published demo seed below; this test checks
//! they match. To rewrite them after an intended change run
//! `ROBODR_REGEN_EXAMPLES=1 cargo test -p robodr-agent --test demo_profile`.
//!
//! The demo seed is public: the demo key must never be trusted on a real
//! unit.

use std::path::{Path, PathBuf};

use robodr_blackbox::Ed25519SigningKey;
use robodr_commission::trust::{trust_keys_text, ProfileSignature};
use robodr_events::profile::{Envelope, Profile, ProfileMetadata, PROFILE_SCHEMA_VERSION};

/// SHA-256 of this label is the demo seed (public, for examples only).
const DEMO_SEED_LABEL: &str = "robodr-demo-profile-signing-key (PUBLIC, never trust in the field)";

fn ex(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join(name)
}

fn demo_key() -> Ed25519SigningKey {
    let seed = robodr_blackbox::crypto::sha256(DEMO_SEED_LABEL.as_bytes());
    Ed25519SigningKey::from_seed("robodr-demo", &seed).unwrap()
}

fn demo_profile() -> Profile {
    let mut p = Profile {
        model: "ugv-demo-x1".into(),
        locked: true,
        metadata: Some(ProfileMetadata {
            schema_version: PROFILE_SCHEMA_VERSION,
            profile_version: 1,
            platform: "ugv-demo".into(),
            unit_id: None,
            locked_by: "RoboDR demo (synthetic)".into(),
            locked_at: 1_767_225_600,
            parent_digest: None,
        }),
        ..Default::default()
    };
    for g in [
        "01103f5a8c2e000000000101",
        "01103f5a8c2e000000000102",
        "01103f5a8c2e000000000103",
    ] {
        p.participants.insert(g.into());
    }
    for t in ["/cmd_vel", "/odom", "/tf", "/scan"] {
        p.writer_topics.insert(t.into());
    }
    p.motion_envelopes.insert(
        "/cmd_vel".into(),
        Envelope {
            max_linear_speed: Some(0.5),
            max_joint_speed: None,
            ..Default::default()
        },
    );
    p
}

#[test]
fn demo_profile_is_sealed_signed_and_reproducible() {
    let text = robodr_commission::sealed_text(&demo_profile()).unwrap();
    let sig = ProfileSignature::create(text.as_bytes(), &demo_key())
        .unwrap()
        .to_text();
    let trust = trust_keys_text(&[demo_key().verifying_key()]);
    let files = [
        (ex("ugv-demo.profile.json"), text),
        (ex("ugv-demo.profile.json.sig"), sig),
        (ex("ugv-demo.trust.json"), trust),
    ];
    if std::env::var_os("ROBODR_REGEN_EXAMPLES").is_some() {
        for (p, c) in &files {
            std::fs::write(p, c).unwrap();
        }
    }
    for (p, c) in &files {
        let on_disk = std::fs::read_to_string(p).unwrap_or_default();
        assert_eq!(
            &on_disk,
            c,
            "{} is stale; regenerate with ROBODR_REGEN_EXAMPLES=1",
            p.display()
        );
    }
    // And it verifies through the loader the replay uses.
    let policy = robodr_commission::TrustPolicy {
        anchors: Some(robodr_commission::load_trust_keys(&ex("ugv-demo.trust.json")).unwrap()),
        ..Default::default()
    };
    let v = robodr_commission::verify_profile_file(&ex("ugv-demo.profile.json"), &policy)
        .unwrap()
        .unwrap();
    assert_eq!(v.version(), Some(1));
}
