//! Sealed RPKs on the unit (Sprint 13c, `docs/SECURE-DELIVERY.md` §7.3,
//! §7.4), through `robodr-seal`:
//!
//! * the deployment's `wrapped_keys` entry for **this** unit is kept in the
//!   store next to the RPK (`store/wraps/<digest>`, ciphertext only);
//! * at staging, the content key is unwrapped by the unit's UWK (in the
//!   TPM, under the signed PCR policy, the policy floor and the erase
//!   epoch; or, without a TPM, by the X25519 key on the runtime volume),
//!   checked against the manifest's key commitment, and used only to open
//!   chunks straight into the **runtime volume** (`seal.runtime_root`),
//!   which must be a mounted dm-crypt mapping ([`check_volume`]). The key
//!   is wiped when staging ends; nothing derived from it is stored;
//! * a TPM that refuses the policy (changed boot measurements, revoked
//!   policy) or an erased unit is `robot.seal.unseal_failed`; a wrap that
//!   does not authenticate is a refusal like any other delivery check.

use crate::config::{SealCfg, VolumeCheck};
use robodr_pkg::rpk::{Kind, Manifest};
use robodr_seal::chunk::ContentKey;
use robodr_seal::unit::Unit;
use robodr_seal::{ErrorKind, SealError};
use std::path::Path;

/// Directory of a kind inside the runtime volume.
pub fn kind_dir(kind: Kind) -> &'static str {
    match kind {
        Kind::Model => "model",
        Kind::Config => "config",
        _ => "files",
    }
}

/// Whether a manifest is installed into the runtime volume: every sealed
/// RPK, and every `model` (§4.2: models only ever go there).
pub fn in_volume(m: &Manifest) -> bool {
    m.is_sealed() || m.kind == Kind::Model
}

/// The device (`major:minor`) mounted exactly at `mount_point`, from
/// `/proc/self/mountinfo` text.
pub fn mounted_device(mountinfo: &str, mount_point: &Path) -> Option<String> {
    let ms = robodr_seal::mounts::parse(mountinfo);
    robodr_seal::mounts::at(&ms, mount_point).map(|m| m.dev.clone())
}

/// Check that `runtime_root` is a mounted dm-crypt mapping (or nothing,
/// with [`VolumeCheck::Unchecked`]).
pub fn check_volume(cfg: &SealCfg) -> Result<(), String> {
    match cfg.volume_check {
        VolumeCheck::Unchecked => Ok(()),
        VolumeCheck::DmCrypt => robodr_seal::mounts::check_mounted_dm_crypt(&cfg.runtime_root),
    }
}

/// The unit's sealing, from the configuration.
#[derive(Debug, Clone)]
pub struct Sealing {
    pub cfg: SealCfg,
    pub unit_id: String,
}

impl Sealing {
    pub fn new(cfg: &SealCfg, unit_id: &str) -> Self {
        Self {
            cfg: cfg.clone(),
            unit_id: unit_id.into(),
        }
    }

    /// Open the unit's seal directory (with its TPM, if configured).
    pub fn unit(&self) -> Result<Unit, SealError> {
        let tpm = match &self.cfg.tpm {
            Some(t) => Some(robodr_seal::tpm::Tpm::new(
                t.tpm_config()
                    .map_err(|e| SealError::new(ErrorKind::Invalid, e))?,
                Box::new(robodr_seal::cmd::System),
            )?),
            None => None,
        };
        let u = Unit::open(&self.cfg.seal_dir, tpm)?;
        if u.record().unit != self.unit_id {
            return Err(SealError::new(
                ErrorKind::Invalid,
                format!(
                    "the seal directory is enrolled as {}, this unit is {}",
                    u.record().unit,
                    self.unit_id
                ),
            ));
        }
        Ok(u)
    }

    /// The content key of sealed RPK `digest` from this unit's `wrap`.
    pub fn content_key(
        &self,
        m: &Manifest,
        digest: &str,
        wrap: &[u8],
    ) -> Result<ContentKey, SealError> {
        let seal = m
            .seal
            .as_ref()
            .ok_or_else(|| SealError::new(ErrorKind::Invalid, "not a sealed RPK"))?;
        self.unit()?.unwrap_content_key(wrap, digest, seal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mountinfo() {
        let mi = "22 1 253:0 / / rw - ext4 /dev/mapper/root rw\n\
                  40 22 253:3 / /run/robodr\\040sealed rw - ext4 /dev/mapper/sealed rw\n\
                  41 22 8:1 / /boot rw - ext4 /dev/sda1 rw\n";
        assert_eq!(
            mounted_device(mi, Path::new("/run/robodr sealed")).as_deref(),
            Some("253:3")
        );
        assert_eq!(
            mounted_device(mi, Path::new("/boot")).as_deref(),
            Some("8:1")
        );
        assert_eq!(mounted_device(mi, Path::new("/run/robodr")), None);
        // A directory that is not a mount point fails the dm-crypt check.
        let cfg = SealCfg {
            seal_dir: "/var/lib/robodr-seal".into(),
            runtime_root: "/nonexistent-robodr-runtime".into(),
            volume_check: VolumeCheck::DmCrypt,
            tpm: None,
            device: None,
            mapper_name: None,
            stop_units: Vec::new(),
        };
        assert!(check_volume(&cfg).is_err());
        let ok = SealCfg {
            volume_check: VolumeCheck::Unchecked,
            ..cfg
        };
        assert!(check_volume(&ok).is_ok());
    }
}
