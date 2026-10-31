//! The agent's own executable (T52) and the check of its replacement.
//!
//! When the agent installs RoboDR's own `.deb`, dpkg renames the new
//! `robodr-deliverd` over the running one. The agent keeps running the old
//! code until its pass is done and then exits 3 (`run`,
//! [`crate::cli::EXIT_RESTART`]); the unit starts the new binary.
//!
//! Before that pass commits, the health gate also runs the **new** binary
//! once: `<path> self-check --config <file>` ([`SelfCheck`]), as root,
//! inside the same unit sandbox, bounded by [`SELF_CHECK_TIMEOUT`]. It
//! loads the configuration, the state file the old binary wrote and the
//! black-box and finding keys, the inputs `run` needs before it reports
//! READY. A binary that cannot start (wrong architecture, missing
//! library, a state or configuration it cannot read) fails the gate, and
//! the old binary, still running, rolls the package back. A new binary
//! that passes `self-check` but fails later in `run` is **not** rolled
//! back automatically: systemd restarts it (`Restart=on-failure`) until its
//! start limit, and then an operator acts (`docs/OPERATIONS.md` 11.4).

use crate::runner::{self, Limits};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Longest `self-check` of a replaced binary.
pub const SELF_CHECK_TIMEOUT: Duration = Duration::from_secs(60);

/// The executable this process was started from, as path, device and
/// inode taken at start (T52). dpkg replaces a file by renaming a new one
/// over it, so after an upgrade the path names another inode (or nothing)
/// while this process still runs the old one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnBinary {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

impl OwnBinary {
    /// Of this process (`/proc/self/exe`). `None`: not knowable (already
    /// replaced before the start, or no `/proc`): never reports a change.
    pub fn of_self() -> Option<Self> {
        Self::of(Path::new("/proc/self/exe"))
    }

    /// Of the executable `link` resolves to (`/proc/<pid>/exe`, or any
    /// path in tests).
    pub fn of(link: &Path) -> Option<Self> {
        use std::os::unix::fs::MetadataExt;
        let path = std::fs::canonicalize(link).ok()?;
        // The kernel marks an unlinked executable " (deleted)".
        if path.to_string_lossy().ends_with(" (deleted)") {
            return None;
        }
        let m = std::fs::metadata(link).ok()?;
        let p = std::fs::metadata(&path).ok()?;
        if (m.dev(), m.ino()) != (p.dev(), p.ino()) {
            return None;
        }
        Some(Self {
            path,
            dev: m.dev(),
            ino: m.ino(),
        })
    }

    /// The path the executable was started from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The path now names another file, or none.
    pub fn replaced(&self) -> bool {
        use std::os::unix::fs::MetadataExt;
        match std::fs::metadata(&self.path) {
            Ok(m) => (m.dev(), m.ino()) != (self.dev, self.ino),
            Err(e) => e.kind() == std::io::ErrorKind::NotFound,
        }
    }
}

/// Run the replacement of the agent's own binary once before a deb
/// install that replaced it commits (see the module documentation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfCheck {
    pub exe: OwnBinary,
    /// The configuration file the agent was started with.
    pub config: PathBuf,
}

impl SelfCheck {
    /// The check's name in the health report.
    pub const LABEL: &'static str = "robodr-deliverd self-check";

    /// `None`: the binary was not replaced (nothing to check). Otherwise
    /// whether `<path> self-check --config <config>` exited 0 in time, and
    /// a one-line summary. A path that names nothing now fails.
    pub fn judge(&self) -> Option<(bool, String)> {
        if !self.exe.replaced() {
            return None;
        }
        let r = runner::run(
            &[
                self.exe.path.to_string_lossy().into_owned(),
                "self-check".into(),
                "--config".into(),
                self.config.to_string_lossy().into_owned(),
            ],
            None,
            Limits {
                timeout: SELF_CHECK_TIMEOUT,
                max_output: 4096,
            },
        );
        Some((r.success(), r.summary()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn script(p: &Path, body: &str) {
        let tmp = p.with_extension("new");
        std::fs::write(&tmp, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::rename(&tmp, p).unwrap();
    }

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("robodr-own-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn an_unreplaced_binary_is_not_run() {
        let d = dir("same");
        let exe = d.join("deliverd");
        script(&exe, &format!("touch {}/ran\nexit 1", d.display()));
        let c = SelfCheck {
            exe: OwnBinary::of(&exe).unwrap(),
            config: d.join("cfg.json"),
        };
        assert_eq!(c.judge(), None);
        assert!(!d.join("ran").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_replaced_binary_is_run_with_self_check_and_its_exit_status_counts() {
        let d = dir("replaced");
        let exe = d.join("deliverd");
        script(&exe, "exit 0");
        let c = SelfCheck {
            exe: OwnBinary::of(&exe).unwrap(),
            config: d.join("cfg.json"),
        };
        script(&exe, &format!("echo \"$@\" >{}/args\nexit 0", d.display()));
        let (ok, why) = c.judge().unwrap();
        assert!(ok, "{why}");
        assert_eq!(
            std::fs::read_to_string(d.join("args")).unwrap(),
            format!("self-check --config {}\n", d.join("cfg.json").display())
        );
        script(&exe, "echo broken >&2\nexit 1");
        let (ok, why) = c.judge().unwrap();
        assert!(!ok);
        assert!(why.contains("exit 1") && why.contains("broken"), "{why}");
        std::fs::remove_file(&exe).unwrap();
        let (ok, why) = c.judge().unwrap();
        assert!(!ok, "{why}");
        let _ = std::fs::remove_dir_all(&d);
    }
}
