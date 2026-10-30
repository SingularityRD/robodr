//! The sealed runtime volume (`docs/SECURE-DELIVERY.md` §7.4, §7.7):
//! LUKS2 through `cryptsetup`, and the Clevis/Tang binding through
//! `clevis` for units without a TPM.
//!
//! * **TPM units.** The volume has one keyslot whose passphrase is a random
//!   256-bit key. That key is stored only **wrapped to the unit's UWK**
//!   (`volume.wrap` in the seal directory, context
//!   [`crate::wrap::WrapContext::Volume`]), so opening the volume needs the
//!   same TPM policy as every content key: the signed PCR policy, the
//!   policy floor and the erase epoch. Erase kills it with them.
//! * **Units without a TPM.** The volume key is **never stored on the
//!   unit**: the only keyslot is a Clevis `tang` binding (optionally an
//!   `sss` threshold with an operator passphrase), so the volume opens
//!   only while the site's Tang server is reachable. The initial random key
//!   is used to bind and then its keyslot is killed. The unit's X25519 UWK
//!   lives *inside* the volume.
//!
//! Keys reach `cryptsetup` on stdin (`--key-file -`), never on the command
//! line or in a file. The PBKDF is PBKDF2 with a low iteration count: the
//! passphrases are uniformly random 256-bit keys, so stretching adds
//! nothing (Argon2's memory cost would only slow every boot). Opening a
//! mapping needs device-mapper (`dm-crypt`); formatting, binding, checking
//! a key (`--test-passphrase`) and erasing work on an image file without
//! it, which is how the tests run where device-mapper is not available.

use crate::cmd::{tool, Output, Runner};
use crate::{invalid, ErrorKind, SealError};
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

/// Mapper name pattern: `[a-z0-9][a-z0-9_-]{0,31}`.
pub fn is_mapper_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'-'))
}

/// `cryptsetup` / `clevis` front end.
#[derive(Debug)]
pub struct Luks {
    pub sbin: PathBuf,
    pub bin: PathBuf,
    pub timeout: Duration,
    runner: Box<dyn Runner>,
}

fn dev(p: &Path) -> Result<String, SealError> {
    if !p.is_absolute() {
        return Err(invalid(format!("{}: device must be absolute", p.display())));
    }
    Ok(p.display().to_string())
}

impl Luks {
    /// `sbin` holds `cryptsetup`, `bin` holds `clevis`.
    pub fn new(sbin: PathBuf, bin: PathBuf, timeout: Duration, runner: Box<dyn Runner>) -> Self {
        Self {
            sbin,
            bin,
            timeout,
            runner,
        }
    }

    /// The system default locations.
    pub fn system() -> Self {
        Self::new(
            PathBuf::from("/usr/sbin"),
            PathBuf::from("/usr/bin"),
            Duration::from_secs(60),
            Box::new(crate::cmd::System),
        )
    }

    fn cryptsetup(&self, args: &[String], stdin: Option<&[u8]>) -> Result<Output, SealError> {
        self.runner.run(
            &tool(&self.sbin, "cryptsetup")?,
            args,
            &[],
            stdin,
            self.timeout,
        )
    }

    fn clevis(&self, args: &[String], stdin: Option<&[u8]>) -> Result<Output, SealError> {
        self.runner
            .run(&tool(&self.bin, "clevis")?, args, &[], stdin, self.timeout)
    }

    fn must(o: Output, what: &str) -> Result<Output, SealError> {
        if o.ok() {
            Ok(o)
        } else {
            Err(SealError::new(
                ErrorKind::Unavailable,
                format!("{what}: {}", o.error_line()),
            ))
        }
    }

    /// Create a LUKS2 volume on `device` whose one keyslot is `key`.
    pub fn format(&self, device: &Path, key: &[u8], label: &str) -> Result<(), SealError> {
        let o = self.cryptsetup(
            &[
                "luksFormat".into(),
                "--type".into(),
                "luks2".into(),
                "--batch-mode".into(),
                "--pbkdf".into(),
                "pbkdf2".into(),
                "--pbkdf-force-iterations".into(),
                "1000".into(),
                "--label".into(),
                label.into(),
                "--key-file".into(),
                "-".into(),
                dev(device)?,
            ],
            Some(key),
        )?;
        Self::must(o, "cryptsetup luksFormat").map(|_| ())
    }

    /// Whether `key` opens a keyslot of `device` (no mapping is made).
    pub fn test_key(&self, device: &Path, key: &[u8]) -> Result<bool, SealError> {
        let o = self.cryptsetup(
            &[
                "open".into(),
                "--test-passphrase".into(),
                "--key-file".into(),
                "-".into(),
                dev(device)?,
            ],
            Some(key),
        )?;
        Ok(o.ok())
    }

    /// Whether `device` has a LUKS2 header.
    pub fn is_luks2(&self, device: &Path) -> Result<bool, SealError> {
        let o = self.cryptsetup(
            &[
                "isLuks".into(),
                "--type".into(),
                "luks2".into(),
                dev(device)?,
            ],
            None,
        )?;
        Ok(o.ok())
    }

    /// Open `device` as `/dev/mapper/<name>` (needs device-mapper).
    pub fn open(&self, device: &Path, name: &str, key: &[u8]) -> Result<(), SealError> {
        if !is_mapper_name(name) {
            return Err(invalid("bad mapper name"));
        }
        let o = self.cryptsetup(
            &[
                "open".into(),
                "--type".into(),
                "luks2".into(),
                "--key-file".into(),
                "-".into(),
                dev(device)?,
                name.into(),
            ],
            Some(key),
        )?;
        Self::must(o, "cryptsetup open").map(|_| ())
    }

    pub fn close(&self, name: &str) -> Result<(), SealError> {
        if !is_mapper_name(name) {
            return Err(invalid("bad mapper name"));
        }
        let o = self.cryptsetup(&["close".into(), name.into()], None)?;
        Self::must(o, "cryptsetup close").map(|_| ())
    }

    /// Wipe every keyslot of `device` (`cryptsetup erase`): the volume key
    /// is unrecoverable afterwards, whatever passphrase or Tang binding
    /// existed.
    pub fn erase(&self, device: &Path) -> Result<(), SealError> {
        let o = self.cryptsetup(&["erase".into(), "--batch-mode".into(), dev(device)?], None)?;
        Self::must(o, "cryptsetup erase").map(|_| ())
    }

    /// Kill keyslot `slot` (batch mode: no passphrase asked).
    pub fn kill_slot(&self, device: &Path, slot: u8) -> Result<(), SealError> {
        let o = self.cryptsetup(
            &[
                "luksKillSlot".into(),
                "--batch-mode".into(),
                dev(device)?,
                slot.to_string(),
            ],
            None,
        )?;
        Self::must(o, "cryptsetup luksKillSlot").map(|_| ())
    }

    /// The Clevis `tang` pin configuration (`url` and the server's key
    /// thumbprint `thp`, pinned so the first contact is not trust on first
    /// use).
    pub fn tang_config(url: &str, thp: &str) -> Result<String, SealError> {
        if !(url.starts_with("http://") || url.starts_with("https://"))
            || url.len() > 256
            || !url
                .bytes()
                .all(|b| b.is_ascii_graphic() && !matches!(b, b'"' | b'\\'))
        {
            return Err(invalid("bad Tang URL"));
        }
        if thp.is_empty()
            || thp.len() > 128
            || !thp
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err(invalid("bad Tang thumbprint"));
        }
        Ok(format!("{{\"url\":\"{url}\",\"thp\":\"{thp}\"}}"))
    }

    /// Format `device` for a unit without a TPM: a random key, a Tang
    /// binding, then the random key's keyslot killed. Afterwards nothing on
    /// the unit opens the volume without the Tang server.
    pub fn format_tang(&self, device: &Path, url: &str, thp: &str) -> Result<(), SealError> {
        let cfg = Self::tang_config(url, thp)?;
        let key = crate::random32()?;
        self.format(device, &key[..], "robodr-sealed")?;
        let o = self.clevis(
            &[
                "luks".into(),
                "bind".into(),
                "-y".into(),
                "-k".into(),
                "-".into(),
                "-d".into(),
                dev(device)?,
                "tang".into(),
                cfg,
            ],
            Some(&key[..]),
        )?;
        Self::must(o, "clevis luks bind")?;
        self.kill_slot(device, 0)?;
        if self.test_key(device, &key[..])? {
            return Err(SealError::new(
                ErrorKind::Unavailable,
                "the bootstrap keyslot survived luksKillSlot",
            ));
        }
        Ok(())
    }

    /// The passphrase of a Clevis-bound keyslot, recovered through the Tang
    /// server (fails when it is unreachable).
    pub fn tang_pass(&self, device: &Path, slot: u8) -> Result<Zeroizing<Vec<u8>>, SealError> {
        let o = self.clevis(
            &[
                "luks".into(),
                "pass".into(),
                "-d".into(),
                dev(device)?,
                "-s".into(),
                slot.to_string(),
            ],
            None,
        )?;
        if !o.ok() {
            return Err(SealError::new(
                ErrorKind::Unavailable,
                format!(
                    "the volume key could not be recovered (Tang server unreachable?): {}",
                    o.error_line()
                ),
            ));
        }
        Ok(o.stdout)
    }

    /// Open a Clevis-bound volume (needs device-mapper).
    pub fn open_tang(&self, device: &Path, name: &str, slot: u8) -> Result<(), SealError> {
        let k = self.tang_pass(device, slot)?;
        self.open(device, name, &k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_config() {
        assert!(is_mapper_name("robodr-sealed"));
        assert!(!is_mapper_name("../x"));
        assert!(!is_mapper_name(""));
        assert!(Luks::tang_config("http://10.0.0.1:7500", "abc_DEF-1").is_ok());
        assert!(Luks::tang_config("ftp://x", "a").is_err());
        assert!(Luks::tang_config("http://x\"}", "a").is_err());
        assert!(Luks::tang_config("http://x", "a b").is_err());
        assert!(dev(Path::new("rel.img")).is_err());
    }
}
