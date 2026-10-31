//! Demo SOC configuration: which robots are registered and which public
//! keys may authenticate batches (`uplink`) or sign findings (`finding`).
//!
//! ```json
//! {"robots": [{"id": "ugv-007", "site": "lab", "require_finding_signature": true}],
//!  "keys": [{"role": "uplink", "robot": "ugv-007", "pub": "/demo/keys/uplink.key.pub"},
//!           {"role": "finding", "robot": "ugv-007", "pub": "/demo/keys/finding.key.pub"}]}
//! ```
//!
//! Key files are RoboDR public key files (`robodr-blackbox keygen` writes
//! `<key>.pub`); the key id is the one in the file.

use crate::ingest::{Registry, Role};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RobotEntry {
    id: String,
    #[serde(default)]
    site: Option<String>,
    #[serde(default = "yes")]
    require_finding_signature: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyEntry {
    role: String,
    robot: String,
    #[serde(rename = "pub")]
    public: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    robots: Vec<RobotEntry>,
    keys: Vec<KeyEntry>,
}

/// The registry described by the config file at `path`.
pub fn load(path: &Path) -> Result<Registry, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let f: File = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut reg = Registry::default();
    for r in &f.robots {
        reg = reg.robot_at(&r.id, r.require_finding_signature, r.site.as_deref());
    }
    for k in &f.keys {
        let role = match k.role.as_str() {
            "uplink" => Role::Uplink,
            "finding" => Role::Finding,
            other => return Err(format!("key role {other:?} (uplink or finding)")),
        };
        if !reg.robots.contains_key(&k.robot) {
            return Err(format!("key for unregistered robot {:?}", k.robot));
        }
        let files = robodr_blackbox::keys::load_key_files(&k.public)
            .map_err(|e| format!("{}: {e}", k.public.display()))?;
        let [kf] = files.as_slice() else {
            return Err(format!("{}: expected one key", k.public.display()));
        };
        if !kf.is_public() {
            return Err(format!(
                "{}: a secret key file; give the SOC the .pub file only",
                k.public.display()
            ));
        }
        let public = kf
            .public_key()
            .ok_or_else(|| format!("{}: not an Ed25519 public key", k.public.display()))?;
        if reg.keys.contains_key(&kf.key_id) {
            return Err(format!("duplicate key id {}", kf.key_id));
        }
        reg = reg.key(&kf.key_id, role, Some(&k.robot), public);
    }
    Ok(reg)
}
