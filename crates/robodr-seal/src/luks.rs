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
use serde::{Deserialize, Serialize};
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

/// A systemd unit name: `[A-Za-z0-9:_.@\\-]{1,255}` with a type suffix.
pub fn is_unit_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && !s.starts_with('-')
        && s.bytes().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, b':' | b'_' | b'.' | b'@' | b'-' | b'\\')
        })
        && s.rsplit_once('.').is_some_and(|(n, t)| {
            !n.is_empty() && matches!(t, "service" | "scope" | "socket" | "target" | "mount")
        })
}

/// What [`Luks::lockdown`] did to the open runtime volume at erase. A
/// crypto-erase destroys keys; the plaintext of a volume that is still
/// open stays readable through its mount (and the kernel keeps its volume
/// key) until it is closed or the unit powers off.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lockdown {
    /// Units stopped (`systemctl stop`).
    pub stopped_units: Vec<String>,
    /// The runtime root was unmounted.
    pub unmounted: bool,
    /// The mapping was closed (`cryptsetup close`): the kernel dropped the
    /// volume key.
    pub closed: bool,
    /// Not closable (busy): suspended instead (`cryptsetup luksSuspend`):
    /// the kernel wiped the volume key and blocks all I/O; pages already
    /// cached stay in memory until power-off.
    pub suspended: bool,
    /// What failed.
    pub notes: Vec<String>,
}

impl Lockdown {
    /// Whether the volume's key is out of the kernel.
    pub fn volume_locked(&self) -> bool {
        self.closed || self.suspended
    }
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

    fn bin_tool(&self, name: &str, args: &[String]) -> Result<Output, SealError> {
        self.runner
            .run(&tool(&self.bin, name)?, args, &[], None, self.timeout)
    }

    /// Lock the open runtime volume down at erase: stop `units` (they hold
    /// files open), unmount `mount`, close mapping `mapper`, or, if it
    /// cannot be closed, suspend it. Best effort, every failure noted;
    /// never fails.
    pub fn lockdown(
        &self,
        units: &[String],
        mount: Option<&Path>,
        mapper: Option<&str>,
    ) -> Lockdown {
        let mut l = Lockdown::default();
        for u in units {
            if !is_unit_name(u) {
                l.notes.push(format!("{u:?}: not a unit name, not stopped"));
                continue;
            }
            match self.bin_tool("systemctl", &["stop".into(), "--".into(), u.clone()]) {
                Ok(o) if o.ok() => l.stopped_units.push(u.clone()),
                Ok(o) => l
                    .notes
                    .push(format!("systemctl stop {u}: {}", o.error_line())),
                Err(e) => l.notes.push(format!("systemctl stop {u}: {e}")),
            }
        }
        if let Some(m) = mount {
            match dev(m).and_then(|m| self.bin_tool("umount", &["--".into(), m])) {
                Ok(o) if o.ok() => l.unmounted = true,
                Ok(o) => l
                    .notes
                    .push(format!("umount {}: {}", m.display(), o.error_line())),
                Err(e) => l.notes.push(format!("umount {}: {e}", m.display())),
            }
        }
        if let Some(n) = mapper {
            if !is_mapper_name(n) {
                l.notes.push(format!("{n:?}: not a mapper name"));
                return l;
            }
            if mount.is_none() || l.unmounted {
                match self.close(n) {
                    Ok(()) => l.closed = true,
                    Err(e) => l.notes.push(e.detail),
                }
            }
            if !l.closed {
                match self.cryptsetup(&["luksSuspend".into(), n.into()], None) {
                    Ok(o) if o.ok() => l.suspended = true,
                    Ok(o) => l
                        .notes
                        .push(format!("cryptsetup luksSuspend: {}", o.error_line())),
                    Err(e) => l.notes.push(format!("cryptsetup luksSuspend: {e}")),
                }
            }
        }
        l
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
        assert!(is_unit_name("robot-planner.service"));
        assert!(is_unit_name("model-runner@1.service"));
        assert!(!is_unit_name("--now.service"));
        assert!(!is_unit_name("planner"));
        assert!(!is_unit_name("a b.service"));
    }

    /// Records every call; fails the programs (and arguments) listed.
    #[derive(Debug)]
    struct Script {
        fail: Vec<&'static str>,
        calls: Calls,
    }

    type Calls = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

    impl Runner for Script {
        fn run(
            &self,
            program: &Path,
            args: &[String],
            _env: &[(&str, &str)],
            _stdin: Option<&[u8]>,
            _timeout: Duration,
        ) -> Result<Output, SealError> {
            let line = format!(
                "{} {}",
                program.file_name().unwrap().to_str().unwrap(),
                args.join(" ")
            );
            let failed = self.fail.iter().any(|f| line.starts_with(f));
            self.calls.lock().unwrap().push(line);
            Ok(Output {
                status: Some(if failed { 32 } else { 0 }),
                stdout: Zeroizing::new(Vec::new()),
                stderr: Zeroizing::new(if failed { b"busy".to_vec() } else { Vec::new() }),
            })
        }
    }

    fn luks(fail: Vec<&'static str>) -> (Luks, Calls) {
        let calls = Calls::default();
        let l = Luks::new(
            "/usr/sbin".into(),
            "/usr/bin".into(),
            Duration::from_secs(1),
            Box::new(Script {
                fail,
                calls: calls.clone(),
            }),
        );
        (l, calls)
    }

    fn calls(c: &Calls) -> Vec<String> {
        c.lock().unwrap().clone()
    }

    #[test]
    fn lockdown_stops_unmounts_and_closes() {
        let (l, c) = luks(vec![]);
        let units = vec!["planner.service".to_string()];
        let r = l.lockdown(
            &units,
            Some(Path::new("/run/robodr-sealed")),
            Some("robodr-sealed"),
        );
        assert_eq!(r.stopped_units, units);
        assert!(r.unmounted && r.closed && !r.suspended, "{r:?}");
        assert!(r.volume_locked() && r.notes.is_empty());
        assert_eq!(
            calls(&c),
            [
                "systemctl stop -- planner.service",
                "umount -- /run/robodr-sealed",
                "cryptsetup close robodr-sealed"
            ]
        );
    }

    #[test]
    fn a_busy_volume_is_suspended_and_said_so() {
        let (l, c) = luks(vec!["umount", "systemctl"]);
        let units = vec!["planner.service".to_string()];
        let r = l.lockdown(
            &units,
            Some(Path::new("/run/robodr-sealed")),
            Some("robodr-sealed"),
        );
        assert!(r.stopped_units.is_empty() && !r.unmounted && !r.closed);
        assert!(r.suspended && r.volume_locked());
        assert_eq!(r.notes.len(), 2, "{:?}", r.notes);
        let c = calls(&c);
        assert!(
            !c.iter().any(|x| x.starts_with("cryptsetup close")),
            "{c:?}"
        );
        assert!(c
            .iter()
            .any(|x| x == "cryptsetup luksSuspend robodr-sealed"));
        // Nothing works at all: still open, and noted.
        let (l, _) = luks(vec!["umount", "cryptsetup"]);
        let r = l.lockdown(
            &[],
            Some(Path::new("/run/robodr-sealed")),
            Some("robodr-sealed"),
        );
        assert!(!r.volume_locked());
        assert_eq!(r.notes.len(), 2, "{:?}", r.notes);
    }
}
