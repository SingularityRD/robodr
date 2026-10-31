//! Sales-readiness T11: the Motion Firewall configuration (the envelope:
//! joint limits, allowed sources) was read as plain JSON, outside the
//! profile's signature chain: whoever could write `firewall.json` could
//! widen every limit and the gateway enforced the widened envelope. In
//! enforce mode it now needs `<firewall>.sig` (`robodr-commission
//! sign-firewall`), by the key that signed the locked profile, over the
//! profile's digest and the file's bytes.

use std::path::{Path, PathBuf};

use robodr_blackbox::Ed25519SigningKey;
use robodr_commission::trust::{
    file_digest, firewall_signed_bytes, sig_path_for, trust_keys_text, ProfileSignature, SigKind,
};
use robodr_events::profile::{ProfileMetadata, PROFILE_SCHEMA_VERSION};
use robodr_firewall_gw::config::GatewayMode;
use robodr_firewall_gw::runtime::load_with_provenance;
use robodr_firewall_gw::testkit::*;
use robodr_firewall_gw::GatewayConfig;

fn key(id: &str, seed: u8) -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed(id, &[seed; 32]).unwrap()
}

struct Site {
    cfg: GatewayConfig,
    profile_digest: String,
    firewall: PathBuf,
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("robodr-gw-fwsig-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A locked, signed G1 profile, its trust file and the G1 example
/// firewall configuration (unsigned).
fn site(dir: &Path) -> Site {
    let mut p = profile(Fixture::G1);
    p.metadata = Some(ProfileMetadata {
        schema_version: PROFILE_SCHEMA_VERSION,
        profile_version: 3,
        platform: "unitree-g1".into(),
        unit_id: None,
        locked_by: "op".into(),
        locked_at: 1_790_000_000,
        parent_digest: None,
        attestation: None,
    });
    let text = robodr_commission::sealed_text(&p).unwrap();
    let ppath = dir.join("profile.json");
    std::fs::write(&ppath, &text).unwrap();
    let sig = ProfileSignature::create(text.as_bytes(), &key("oem", 3)).unwrap();
    std::fs::write(sig_path_for(&ppath), sig.to_text()).unwrap();
    let trust = dir.join("trust.json");
    std::fs::write(&trust, trust_keys_text(&[key("oem", 3).verifying_key()])).unwrap();
    let fw = dir.join("firewall.json");
    std::fs::copy(config_dir().join("firewall.unitree-g1.example.json"), &fw).unwrap();
    let mut cfg = gateway_config(Fixture::G1);
    cfg.mode = GatewayMode::Enforce;
    cfg.profile = ppath;
    cfg.firewall = fw.clone();
    cfg.profile_trust.trusted_keys = Some(trust);
    Site {
        cfg,
        profile_digest: file_digest(text.as_bytes()),
        firewall: fw,
    }
}

fn sign(s: &Site, profile_digest: &str, k: &Ed25519SigningKey) {
    let text = std::fs::read(&s.firewall).unwrap();
    let sig = ProfileSignature::create_for(
        SigKind::FirewallConfig,
        &firewall_signed_bytes(profile_digest, &text),
        k,
    )
    .unwrap();
    std::fs::write(sig_path_for(&s.firewall), sig.to_text()).unwrap();
}

#[test]
fn enforce_needs_the_envelope_signed_for_the_profile() {
    let dir = tmpdir("enforce");
    let s = site(&dir);
    // Unsigned: refused, with the command that fixes it.
    let e = load_with_provenance(&s.cfg).map(|_| ()).unwrap_err();
    assert!(e.contains("unsigned") && e.contains("sign-firewall"), "{e}");

    // Signed for this profile by its key: accepted, digests recorded.
    sign(&s, &s.profile_digest, &key("oem", 3));
    let (_, _, _, prov) = load_with_provenance(&s.cfg).unwrap();
    assert_eq!(
        prov.profile_sha256.as_deref(),
        Some(s.profile_digest.as_str())
    );
    let fw_text = std::fs::read(&s.firewall).unwrap();
    assert_eq!(prov.firewall_sha256, Some(file_digest(&fw_text)));

    // Attack: the envelope widened after signing.
    let widened = String::from_utf8(fw_text.clone())
        .unwrap()
        .replace("\"max_dq_step\": 0.15", "\"max_dq_step\": 3.0");
    assert_ne!(widened.as_bytes(), &fw_text[..], "fixture has max_dq_step");
    std::fs::write(&s.firewall, &widened).unwrap();
    let e = load_with_provenance(&s.cfg).map(|_| ()).unwrap_err();
    assert!(e.contains("digest") || e.contains("signature"), "{e}");
    std::fs::write(&s.firewall, &fw_text).unwrap();

    // Attack: a valid signature made for another profile (an older one).
    sign(&s, &format!("sha256:{}", "0".repeat(64)), &key("oem", 3));
    assert!(load_with_provenance(&s.cfg).is_err());

    // Attack: signed by a key that did not sign the profile.
    sign(&s, &s.profile_digest, &key("rogue", 9));
    let e = load_with_provenance(&s.cfg).map(|_| ()).unwrap_err();
    assert!(e.contains("rogue"), "{e}");

    // Observe mode starts without one, with a note.
    std::fs::remove_file(sig_path_for(&s.firewall)).unwrap();
    let mut obs = s.cfg.clone();
    obs.mode = GatewayMode::Observe;
    let (_, _, notes, _) = load_with_provenance(&obs).unwrap();
    assert!(
        notes
            .iter()
            .any(|n| n.contains("enforce mode would refuse")),
        "{notes:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
