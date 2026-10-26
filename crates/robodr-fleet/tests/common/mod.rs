//! A test unit: a temporary root with the key directory, the fleet state
//! directory, an agentd configuration, profile trust files, a SOC fleet
//! key, and a controllable clock.
#![allow(dead_code)]

pub mod soc;

use robodr_blackbox::{Ed25519SigningKey, KeyFile, Signer};
use robodr_commission::trust::{
    sig_path_for, trust_file_text_with, trust_roots_text, ProfileSignature, RevocationList,
    SigKind, TrustFileOptions,
};
use robodr_events::profile::{Profile, ProfileMetadata, PROFILE_SCHEMA_VERSION};
use robodr_fleet::config::{AgentdFacts, Config};
use robodr_fleet::state::Ctx;
use std::cell::{Cell, RefCell};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};

pub const WORKSPACE: &str = "ws-test-0001";
pub const ROBOT: &str = "ugv-001";
pub const SITE: &str = "lab-1";
pub const PLATFORM: &str = "ugv-x1";
pub const T0: u64 = 1_790_000_000_000;

pub fn soc_key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed_with_derived_id(&[0x50; 32])
}
pub fn profile_key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed_with_derived_id(&[0x51; 32])
}
pub fn root_key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed_with_derived_id(&[0x52; 32])
}

pub fn tmpdir(tag: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "robodr-fleet-{}-{}-{tag}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

pub fn write_mode(p: &Path, bytes: &[u8], mode: u32) {
    std::fs::write(p, bytes).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

pub fn write_public_key(p: &Path, k: &Ed25519SigningKey) {
    let kf = KeyFile::ed25519_public(&k.public_key(), None).unwrap();
    write_mode(p, kf.to_json().as_bytes(), 0o644);
}

pub struct Unit {
    pub root: PathBuf,
    pub cfg: Config,
    pub facts: AgentdFacts,
    pub now: Rc<Cell<u64>>,
}

impl Unit {
    /// A unit with agentd configured for `ROBOT` at `SITE`, profile trust
    /// (profile key, trust roots, revocation list path, state file).
    pub fn new(tag: &str) -> Self {
        let root = tmpdir(tag);
        let etc = root.join("etc");
        let keys = etc.join("keys");
        std::fs::create_dir_all(&keys).unwrap();
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&etc, std::fs::Permissions::from_mode(0o755)).unwrap();
        write_public_key(&etc.join("fleet-soc.pub"), &soc_key());
        // Trust roots + root-signed trust file (attestation not required).
        write_mode(
            &etc.join("trust-roots.json"),
            trust_roots_text(&[root_key().verifying_key()]).as_bytes(),
            0o644,
        );
        let trust = trust_file_text_with(
            &[profile_key().verifying_key()],
            &TrustFileOptions {
                require_attestation: Some(false),
                ..Default::default()
            },
        );
        let tp = etc.join("profile-trust.json");
        write_mode(&tp, trust.as_bytes(), 0o644);
        let tsig = ProfileSignature::create_for(SigKind::TrustFile, trust.as_bytes(), &root_key())
            .unwrap();
        write_mode(&sig_path_for(&tp), tsig.to_text().as_bytes(), 0o644);
        let state = root.join("var/profile-state");
        std::fs::create_dir_all(&state).unwrap();
        let agentd = serde_json::json!({
            "robot": {"id": ROBOT, "site": SITE},
            "sensor": {
                "profile_path": etc.join("profile.json"),
                "profile_trust": {
                    "trusted_keys": tp,
                    "trust_roots": etc.join("trust-roots.json"),
                    "revocation_list": etc.join("revocations.json"),
                    "state_file": state.join("agentd.json"),
                    "expect_platform": PLATFORM,
                }
            }
        });
        let ap = etc.join("agentd.json");
        write_mode(&ap, agentd.to_string().as_bytes(), 0o644);
        let cfg = Config {
            state_dir: root.join("var/fleet"),
            agentd_config: Some(ap.clone()),
            soc_url: None,
            ca_bundle: etc.join("soc-ca.pem"),
            spki_sha256: Vec::new(),
            soc_keys: vec![etc.join("fleet-soc.pub")],
            workspace: Some(WORKSPACE.into()),
            uplink_key: keys.join("uplink.key"),
            finding_key: keys.join("agentd-finding.key"),
            blackbox_key: keys.join("agentd-blackbox.key"),
        };
        let facts = AgentdFacts::load(Some(&ap)).unwrap();
        Self {
            root,
            cfg,
            facts,
            now: Rc::new(Cell::new(T0)),
        }
    }

    pub fn ctx(&self) -> Ctx {
        let now = self.now.clone();
        Ctx::open(
            self.cfg.clone(),
            self.facts.clone(),
            Box::new(move || now.get()),
        )
        .unwrap()
    }

    pub fn etc(&self, name: &str) -> PathBuf {
        self.root.join("etc").join(name)
    }

    /// Write the fleet config file and return its path (CLI tests).
    pub fn config_file(&self, soc_url: Option<&str>) -> PathBuf {
        let p = self.etc("fleet.json");
        let j = serde_json::json!({
            "format": "robodr-fleet-config/v1",
            "state_dir": self.cfg.state_dir,
            "agentd_config": self.cfg.agentd_config,
            "soc": {"url": soc_url, "ca_bundle": self.cfg.ca_bundle, "keys": self.cfg.soc_keys},
            "workspace": self.cfg.workspace,
            "keys": {"uplink": self.cfg.uplink_key, "finding": self.cfg.finding_key,
                     "blackbox": self.cfg.blackbox_key},
        });
        write_mode(&p, j.to_string().as_bytes(), 0o644);
        p
    }
}

pub fn new_soc() -> RefCell<soc::Soc> {
    RefCell::new(soc::Soc::new(soc_key(), WORKSPACE, T0))
}

/// A locked profile of `version` for `PLATFORM`, signed by the profile key:
/// (profile bytes, sig bytes).
pub fn signed_profile(version: u64, unit: Option<&str>) -> (Vec<u8>, Vec<u8>) {
    let mut p = Profile {
        model: "ugv-test".into(),
        locked: true,
        ..Default::default()
    };
    p.participants.insert("01103f5a8c2e000000000101".into());
    p.writer_topics.insert("/cmd_vel".into());
    p.metadata = Some(ProfileMetadata {
        schema_version: PROFILE_SCHEMA_VERSION,
        profile_version: version,
        platform: PLATFORM.into(),
        unit_id: unit.map(str::to_string),
        locked_by: "op-a".into(),
        locked_at: 1_790_000_000,
        parent_digest: None,
        attestation: None,
    });
    let text = robodr_commission::sealed_text(&p).unwrap();
    let sig = ProfileSignature::create(text.as_bytes(), &profile_key()).unwrap();
    (text.into_bytes(), sig.to_text().into_bytes())
}

/// A draft profile text.
pub fn draft_profile() -> Vec<u8> {
    let mut p = Profile {
        model: "ugv-test".into(),
        ..Default::default()
    };
    p.writer_topics.insert("/cmd_vel".into());
    robodr_commission::to_json(&p).unwrap().into_bytes()
}

/// A root-signed revocation list.
pub fn revocation_list(serial: u64, digests: &[String], signer: &dyn Signer) -> Vec<u8> {
    RevocationList::create(
        serial,
        1_790_000_000,
        PLATFORM,
        digests.to_vec(),
        Vec::new(),
        signer,
    )
    .unwrap()
    .to_text()
    .into_bytes()
}

pub fn key_id(k: &Ed25519SigningKey) -> String {
    k.key_id().to_string()
}
