//! The robot's role keys: generated on the unit, written root-only, never
//! sent anywhere but as public halves.
//!
//! Format: robodr-blackbox's key file (`robodr-blackbox-key/v2`, Ed25519,
//! derived key id `ed25519:<16 hex>`), the one format agentd, robodr-uplink
//! and robodr-commission read. The secret file is created exclusively with
//! mode 0600 (`KeyFile::write_new`, never following a symlink) in a
//! directory that must not be writable by group or others; the public half
//! goes next to it as `<key>.pub` (0644).

use robodr_blackbox::keys::public_key_path;
use robodr_blackbox::sign_ed25519::PUBLIC_KEY_LEN;
use robodr_blackbox::{Ed25519SigningKey, KeyFile};
use std::path::Path;

use crate::fsx;
use crate::wire::{self, KeyEntry, KeyRef};

/// A loaded Ed25519 role key.
pub struct RoleKey {
    pub role: String,
    pub signing: Ed25519SigningKey,
}

impl RoleKey {
    pub fn key_id(&self) -> String {
        robodr_blackbox::Signer::key_id(&self.signing).to_string()
    }

    pub fn public(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.signing.public_key()
    }

    pub fn fingerprint(&self) -> String {
        wire::fingerprint(&self.public())
    }

    pub fn entry(&self) -> KeyEntry {
        KeyEntry {
            role: self.role.clone(),
            key_id: self.key_id(),
            public_hex: robodr_blackbox::crypto::to_hex(&self.public()),
            fingerprint: self.fingerprint(),
        }
    }

    pub fn reference(&self) -> KeyRef {
        KeyRef {
            role: self.role.clone(),
            key_id: self.key_id(),
            fingerprint: self.fingerprint(),
        }
    }
}

/// Load the Ed25519 secret key file at `path` (blackbox checks: regular
/// file, no symlink, owner root or this user, no group/other access).
pub fn load(role: &str, path: &Path) -> Result<RoleKey, String> {
    let kf = KeyFile::load_secret(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let signing = kf
        .ed25519_signing_key()
        .map_err(|e| format!("{}: {e} (fleet keys are Ed25519)", path.display()))?;
    let derived = robodr_blackbox::sign_ed25519::derive_key_id(&signing.public_key());
    if robodr_blackbox::Signer::key_id(&signing) != derived {
        return Err(format!(
            "{}: key id {:?} is not the derived id {derived:?}; the ingest and fleet APIs \
             identify keys by the derived id (regenerate with robodr-blackbox keygen)",
            path.display(),
            robodr_blackbox::Signer::key_id(&signing)
        ));
    }
    Ok(RoleKey {
        role: role.into(),
        signing,
    })
}

/// Generate a fresh key into `path` (exclusive create, 0600) and its
/// `.pub` (replaced atomically). The directory must exist and be private.
pub fn generate(role: &str, path: &Path) -> Result<RoleKey, String> {
    fsx::check_parent_private(path).map_err(|e| e.to_string())?;
    let kf = KeyFile::generate_ed25519(None).map_err(|e| e.to_string())?;
    kf.write_new(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    write_public(&kf, path)?;
    load(role, path)
}

/// (Re)write `<path>.pub` for the secret key file `kf` stored at `path`.
pub fn write_public(kf: &KeyFile, path: &Path) -> Result<(), String> {
    let public = kf.to_public().map_err(|e| e.to_string())?;
    let pubp = public_key_path(path);
    robodr_commission::write_file_atomic(&pubp, public.to_json().as_bytes(), true)
        .map_err(|e| format!("{}: {e}", pubp.display()))?;
    // write_file_atomic creates 0600; a public key is world-readable.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&pubp, std::fs::Permissions::from_mode(0o644))
        .map_err(|e| format!("{}: {e}", pubp.display()))
}

/// Load a SOC fleet public key file (`kind: public`, Ed25519, not group- or
/// other-writable, no symlink).
pub fn load_soc_key(path: &Path) -> Result<(String, [u8; PUBLIC_KEY_LEN]), String> {
    use std::os::unix::fs::PermissionsExt;
    let md = std::fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if md.file_type().is_symlink() || md.permissions().mode() & 0o022 != 0 {
        return Err(format!(
            "{}: SOC key file must not be a symlink or writable by group/others",
            path.display()
        ));
    }
    let kf = KeyFile::load_public(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let pk = kf
        .public_key()
        .ok_or_else(|| format!("{}: not an Ed25519 public key", path.display()))?;
    let id = robodr_blackbox::sign_ed25519::derive_key_id(&pk);
    if kf.key_id != id {
        return Err(format!(
            "{}: key id {:?} is not the derived id {id:?}",
            path.display(),
            kf.key_id
        ));
    }
    Ok((id, pk))
}

/// The configured SOC keys, by key id.
pub struct SocKeys(pub Vec<(String, [u8; PUBLIC_KEY_LEN])>);

impl SocKeys {
    pub fn load(paths: &[std::path::PathBuf]) -> Result<Self, String> {
        if paths.is_empty() {
            return Err(
                "no SOC fleet key configured (fleet.json soc.keys or --soc-key): SOC-signed \
                 documents cannot be authenticated"
                    .into(),
            );
        }
        let mut v: Vec<(String, [u8; PUBLIC_KEY_LEN])> = Vec::new();
        for p in paths {
            let k = load_soc_key(p)?;
            if !v.iter().any(|(id, _)| *id == k.0) {
                v.push(k);
            }
        }
        Ok(Self(v))
    }

    pub fn get(&self, key_id: &str) -> Option<&[u8; PUBLIC_KEY_LEN]> {
        self.0.iter().find(|(id, _)| id == key_id).map(|(_, k)| k)
    }

    /// Verify an envelope signed by (at least) one configured SOC key.
    pub fn verify(&self, o: &wire::Opened) -> Result<String, String> {
        let mut last = String::from("signed by no configured SOC key");
        for id in o.signers() {
            if let Some(pk) = self.get(id) {
                match o.verify_by(id, pk) {
                    Ok(()) => return Ok(id.to_string()),
                    Err(e) => last = e.to_string(),
                }
            }
        }
        Err(last)
    }
}
