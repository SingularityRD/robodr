//! The agent's own executable (T52) and the check of its replacement.
//!
//! When the agent installs RoboDR's own `.deb`, dpkg renames the new
//! `robodr-deliverd` over the running one. The agent keeps running the old
//! code until its pass is done and then exits 3 (`run`,
//! [`crate::cli::EXIT_RESTART`]); the unit starts the new binary.
//!
//! Before that pass commits, the health gate also runs the **new** binary
//! once: `<path> self-check --config <file>` ([`SelfCheck`],
//! [`crate::engine::Engine::self_check`]), as root, inside the same unit
//! sandbox, bounded by [`SELF_CHECK_TIMEOUT`]. Read only, it checks what
//! the start needs: the keys, the journal's segments, the state file the
//! old binary wrote (and that it is this unit's), a start the high-water
//! record would not lock, the NV counter's TPM settings and the trust
//! anchor. A binary that cannot start (wrong architecture, missing
//! library, a state, record or configuration it cannot read) fails the
//! gate, and the old binary, still running, rolls the package back. The
//! gate runs only when the switch being judged replaced the binary (a
//! [`Mark`] taken right before it). If the rollback cannot restore the
//! binary (the security floor blocks it), `run` does not exit into it
//! ([`SelfCheck::replacement_failed`]).
//!
//! Not covered: a new binary that passes `self-check` but fails later in
//! `run` is **not** rolled back automatically: systemd restarts it
//! (`Restart=on-failure`) until its start limit, and then an operator acts
//! (`docs/OPERATIONS.md` 11.4). Nor is an agent killed between the switch
//! and the end of the gate: the next start runs the new binary, which
//! judges the resumed gate without a self-check of itself. When
//! `/proc/self/exe` does not resolve, the check is skipped and the journal
//! says so (`robodr.deliver.self_check_unavailable`).

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

/// The file a path names at one moment (device and inode); `None` inside
/// [`Mark`]: none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileId {
    dev: u64,
    ino: u64,
}

fn file_id(p: &Path) -> Option<FileId> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(p).ok().map(|m| FileId {
        dev: m.dev(),
        ino: m.ino(),
    })
}

/// What the agent's own path named right before a switch
/// ([`SelfCheck::mark`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mark(Option<FileId>);

/// Run the replacement of the agent's own binary once before a deb
/// install that replaced it commits (see the module documentation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfCheck {
    pub exe: OwnBinary,
    /// The configuration file the agent was started with.
    pub config: PathBuf,
    /// The file that failed the last check, while it may still be at the
    /// path (a rollback that did not restore the binary).
    failed: Option<FileId>,
}

impl SelfCheck {
    /// The check's name in the health report.
    pub const LABEL: &'static str = "robodr-deliverd self-check";

    /// The check of a replacement of `exe`, started with `config`.
    pub fn new(exe: OwnBinary, config: PathBuf) -> Self {
        Self {
            exe,
            config,
            failed: None,
        }
    }

    /// What the path names now; taken right before a deb switch so
    /// [`Self::judge`] can tell whether that switch replaced the binary.
    pub fn mark(&self) -> Mark {
        Mark(file_id(&self.exe.path))
    }

    /// `None`: nothing to check, because the binary was not replaced
    /// since this process started, or `before` (the [`Self::mark`] taken
    /// right before the switch being judged) shows that this switch did
    /// not replace it. Without a mark (a switch resumed after a restart)
    /// any replacement since the start counts. Otherwise whether
    /// `<path> self-check --config <config>` exited 0 in time, and a
    /// one-line summary. A path that names nothing now fails.
    pub fn judge(&mut self, before: Option<Mark>) -> Option<(bool, String)> {
        if !self.exe.replaced() {
            return None;
        }
        let now = file_id(&self.exe.path);
        if before.is_some_and(|m| m.0 == now) {
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
        let ok = r.success();
        self.failed = if ok { None } else { now };
        Some((ok, r.summary()))
    }

    /// The file at the path is the one that failed the last check (its
    /// install was not rolled back, e.g. the rollback was blocked by a
    /// security floor): `run` stays on the old code instead of exiting
    /// into a binary that cannot start.
    pub fn replacement_failed(&self) -> bool {
        self.failed.is_some() && file_id(&self.exe.path) == self.failed
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
        let mut c = SelfCheck::new(OwnBinary::of(&exe).unwrap(), d.join("cfg.json"));
        assert_eq!(c.judge(None), None);
        assert!(!d.join("ran").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_replaced_binary_is_run_with_self_check_and_its_exit_status_counts() {
        let d = dir("replaced");
        let exe = d.join("deliverd");
        script(&exe, "exit 0");
        let mut c = SelfCheck::new(OwnBinary::of(&exe).unwrap(), d.join("cfg.json"));
        script(&exe, &format!("echo \"$@\" >{}/args\nexit 0", d.display()));
        let (ok, why) = c.judge(None).unwrap();
        assert!(ok, "{why}");
        assert_eq!(
            std::fs::read_to_string(d.join("args")).unwrap(),
            format!("self-check --config {}\n", d.join("cfg.json").display())
        );
        script(&exe, "echo broken >&2\nexit 1");
        let (ok, why) = c.judge(None).unwrap();
        assert!(!ok);
        assert!(why.contains("exit 1") && why.contains("broken"), "{why}");
        std::fs::remove_file(&exe).unwrap();
        let (ok, why) = c.judge(None).unwrap();
        assert!(!ok, "{why}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// WP14: a switch that did not replace the binary (its mark is what
    /// the path still names) is not checked, even though the binary was
    /// replaced earlier (an operator, or an earlier install): the deb being
    /// judged is not blamed for it.
    #[test]
    fn a_switch_that_did_not_replace_the_binary_is_not_checked() {
        let d = dir("mark");
        let exe = d.join("deliverd");
        script(&exe, "exit 0");
        let mut c = SelfCheck::new(OwnBinary::of(&exe).unwrap(), d.join("cfg.json"));
        // The running process keeps its executable's inode in use.
        let _running = std::fs::File::open(&exe).unwrap();
        // Replaced by something that cannot start, before the switch.
        script(&exe, &format!("touch {}/ran\nexit 1", d.display()));
        let before = c.mark();
        assert_eq!(c.judge(Some(before)), None);
        assert!(!d.join("ran").exists());
        // The switch replaced it: checked.
        let before = c.mark();
        script(&exe, &format!("touch {}/ran\nexit 1", d.display()));
        let (ok, _) = c.judge(Some(before)).unwrap();
        assert!(!ok);
        assert!(d.join("ran").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// WP14: the file that failed the check is remembered while it stays
    /// at the path (a rollback the floor blocked); a later file at the path
    /// (a rollback, or a newer install) is not that file.
    #[test]
    fn a_failed_replacement_is_known_while_it_stays_at_the_path() {
        let d = dir("failed");
        let exe = d.join("deliverd");
        script(&exe, "exit 0");
        let mut c = SelfCheck::new(OwnBinary::of(&exe).unwrap(), d.join("cfg.json"));
        let _running = std::fs::File::open(&exe).unwrap();
        assert!(!c.replacement_failed());
        script(&exe, "exit 1");
        assert!(!c.judge(None).unwrap().0);
        assert!(c.replacement_failed());
        // Rolled back (dpkg renames the old version over it).
        script(&exe, "exit 0");
        assert!(!c.replacement_failed());
        script(&exe, "exit 1");
        assert!(!c.judge(None).unwrap().0);
        assert!(c.replacement_failed());
        // A newer install that passes.
        script(&exe, "exit 0");
        assert!(c.judge(None).unwrap().0);
        assert!(!c.replacement_failed());
        let _ = std::fs::remove_dir_all(&d);
    }
}
