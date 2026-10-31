//! Support bundle (`robodr-support-bundle`, sales-readiness T69).
//!
//! Collects what RoboDR support needs to diagnose a unit, and nothing that
//! could hurt the customer if the bundle leaked:
//!
//! * **collected:** OS and kernel, RoboDR package and binary hashes
//!   (`dpkg --verify` / `rpm -V`), the state of every `robodr*` unit and its
//!   unit files with drop-ins (`systemctl cat`, redacted), the journal of the
//!   `robodr*` units and the kernel (bounded, redacted), the status files of
//!   the daemons, file counts and sizes of the spool / black box / outbox
//!   (never names or content), the nftables ruleset, network interfaces, the
//!   configuration files directly in `/etc/robodr` (redacted), this host's
//!   preflight and current metrics;
//! * **never collected:** anything under [`FORBIDDEN`]: keys
//!   (`/etc/robodr/keys`, `/etc/robodr-depot/keys`, `/run/credentials`),
//!   evidence (`/var/lib/robodr/blackbox`), findings (spool records),
//!   control-plane state and evidence exports, diode batches, fleet and
//!   delivery state, archives, release packages. Files are read only from
//!   explicit paths, a symlink is never followed, and every path is checked
//!   against that list;
//! * **checked before it is written:** every file of the finished bundle is
//!   scanned for secret key material ([`redact::secret_markers`]); a hit
//!   deletes the bundle and fails (fail closed).
//!
//! Layout: `robodr-support-<host>-<UTC>/` with `manifest.json`
//! (`robodr-support-bundle/1`: every file with its size, SHA-256, source and
//! whether it was redacted; every item that could not be collected and
//! why; the never-collected list) and `SHA256SUMS` (`sha256sum -c`), packed
//! as `<dir>.tar.gz` (mode 0600) when `tar` is available.

use crate::exec::{Host, Runner};
use crate::redact;
use crate::{rooted, sha256_hex};
use serde::Serialize;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Paths (and everything below them) the bundle never reads.
pub const FORBIDDEN: &[&str] = &[
    "/etc/robodr/keys",
    "/etc/robodr/kafka",
    "/etc/robodr-depot/keys",
    "/etc/robodr-anchor-receiver",
    "/run/credentials",
    "/var/lib/robodr/blackbox",
    "/var/lib/robodr/spool/agentd/ready",
    "/var/lib/robodr/spool/agentd/acked",
    "/var/lib/robodr/spool/agentd/rejected",
    "/var/lib/robodr/spool/pulsard",
    "/var/lib/robodr/control-plane",
    "/var/lib/robodr/export/diode",
    "/var/lib/robodr/commission",
    "/var/lib/robodr/archive",
    "/var/lib/robodr/fleet",
    "/var/lib/robodr/deliverd",
    "/var/lib/robodr/deliverd-media",
    "/var/lib/robodr/depot",
    "/var/lib/robodr/releases",
    "/var/lib/robodr/executor",
];

/// The logical path `p` is (under) a forbidden one. `p` must be absolute
/// and free of `.` / `..` components (anything else is forbidden too).
pub fn forbidden(p: &str) -> bool {
    if !p.starts_with('/') || p.split('/').any(|c| c == ".." || c == ".") {
        return true;
    }
    FORBIDDEN
        .iter()
        .any(|f| p == *f || p.strip_prefix(f).is_some_and(|r| r.starts_with('/')))
}

/// Status files of the daemons.
const STATUS_FILES: &[&str] = &[
    "/var/lib/robodr/spool/agentd/status.json",
    "/var/lib/robodr/export/uplink/uplink-status.json",
    "/var/lib/robodr/export/kafka-publish/status.json",
    "/var/lib/robodr/export/spool-export/state.json",
];

/// Directories summarised by count and size only.
const SUMMARISED: &[&str] = &[
    "/var/lib/robodr/blackbox",
    "/var/lib/robodr/spool/agentd/ready",
    "/var/lib/robodr/spool/agentd/acked",
    "/var/lib/robodr/spool/agentd/rejected",
    "/var/lib/robodr/spool/pulsard",
    "/var/lib/robodr/export/diode",
    "/var/lib/robodr/releases",
];

/// Settings.
#[derive(Debug, Clone)]
pub struct Options {
    /// Root of the host's file system (`/`; tests use a temporary tree).
    pub root: PathBuf,
    /// Where the bundle is written.
    pub out_dir: PathBuf,
    /// Journal window (`journalctl --since`), e.g. `-48h`.
    pub since: String,
    pub journal_lines: u64,
    pub journal: bool,
    /// Pack into `.tar.gz` (and remove the directory).
    pub tar: bool,
    pub now: SystemTime,
}

/// One file of the bundle.
#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    /// The command or file it came from.
    pub source: String,
    pub redacted: bool,
}

/// Something that was not collected.
#[derive(Debug, Clone, Serialize)]
pub struct Skipped {
    pub item: String,
    pub reason: String,
}

#[derive(Serialize)]
struct Manifest<'a> {
    format: &'static str,
    created_utc: String,
    host: &'a str,
    robodr_ops_version: &'static str,
    files: &'a [Entry],
    skipped: &'a [Skipped],
    never_collected: &'static [&'static str],
}

/// How collected text is treated.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Redact {
    /// Command output with no settings in it (counts, states).
    None,
    /// Line-based ([`redact::redact_text`]).
    Text,
    /// Structural if it parses as JSON, else line-based.
    Json,
}

struct Builder<'a> {
    opts: &'a Options,
    runner: &'a dyn Runner,
    dir: PathBuf,
    files: Vec<Entry>,
    skipped: Vec<Skipped>,
}

/// The bundle that was written: the archive (or directory) and the
/// manifest's file count.
#[derive(Debug, Clone)]
pub struct Written {
    pub path: PathBuf,
    pub sha256: Option<String>,
    pub files: usize,
    pub skipped: usize,
}

fn host_name(root: &Path) -> String {
    let h = std::fs::read_to_string(rooted(root, "/proc/sys/kernel/hostname")).unwrap_or_default();
    let h: String = h
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    if h.is_empty() {
        "unknown".into()
    } else {
        h
    }
}

impl Builder<'_> {
    fn write(
        &mut self,
        rel: &str,
        bytes: &[u8],
        source: &str,
        redacted: bool,
    ) -> Result<(), String> {
        let p = self.dir.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&p)
            .map_err(|e| format!("{}: {e}", p.display()))?;
        f.write_all(bytes)
            .and_then(|()| f.sync_all())
            .map_err(|e| format!("{}: {e}", p.display()))?;
        self.files.push(Entry {
            path: rel.to_string(),
            bytes: bytes.len() as u64,
            sha256: sha256_hex(bytes),
            source: source.to_string(),
            redacted,
        });
        Ok(())
    }

    fn skip(&mut self, item: &str, reason: impl Into<String>) {
        self.skipped.push(Skipped {
            item: item.to_string(),
            reason: reason.into(),
        });
    }

    fn redacted(text: &[u8], how: Redact) -> (Vec<u8>, bool) {
        let t = String::from_utf8_lossy(text);
        match how {
            Redact::None => (text.to_vec(), false),
            Redact::Text => (redact::redact_text(&t).into_bytes(), true),
            Redact::Json => match redact::redact_json(&t) {
                Some(j) => (j.into_bytes(), true),
                None => (redact::redact_text(&t).into_bytes(), true),
            },
        }
    }

    /// Run a command into `rel`.
    fn cmd(&mut self, rel: &str, prog: &str, args: &[&str], how: Redact) -> Result<(), String> {
        let source = format!("{prog} {}", args.join(" "));
        match self.runner.run(prog, args) {
            Err(e) => {
                self.skip(&source, format!("not run: {e}"));
                Ok(())
            }
            Ok(o) => {
                let mut body = o.stdout.clone();
                if !o.stderr.is_empty() {
                    body.extend_from_slice(b"\n--- stderr ---\n");
                    body.extend_from_slice(&o.stderr);
                }
                let mut trailer = format!("\n--- exit: {:?}", o.code);
                if o.timed_out {
                    trailer.push_str(", killed after the timeout");
                }
                if o.truncated {
                    trailer.push_str(", output truncated");
                }
                trailer.push_str(" ---\n");
                body.extend_from_slice(trailer.as_bytes());
                let (b, r) = Self::redacted(&body, how);
                self.write(rel, &b, &source, r)
            }
        }
    }

    /// Copy one file (by logical path) into `rel`: regular files only,
    /// never through a symlink, never a forbidden path, at most 4 MiB.
    fn file(&mut self, rel: &str, logical: &str, how: Redact) -> Result<(), String> {
        if forbidden(logical) {
            self.skip(logical, "never collected (keys, credentials or evidence)");
            return Ok(());
        }
        let p = rooted(&self.opts.root, logical);
        match std::fs::symlink_metadata(&p) {
            Err(_) => {
                self.skip(logical, "absent");
                Ok(())
            }
            Ok(md) if !md.file_type().is_file() => {
                self.skip(logical, "not a regular file (symlinks are not followed)");
                Ok(())
            }
            Ok(md) if md.len() > 4 << 20 => {
                self.skip(logical, format!("{} bytes, larger than 4 MiB", md.len()));
                Ok(())
            }
            Ok(_) => match std::fs::read(&p) {
                Ok(b) => {
                    let (b, r) = Self::redacted(&b, how);
                    self.write(rel, &b, logical, r)
                }
                Err(e) => {
                    self.skip(logical, format!("unreadable: {e}"));
                    Ok(())
                }
            },
        }
    }
}

/// Count and total size of the regular files under `dir` (no symlinks
/// followed, depth <= 4). Names are not kept.
fn summarise(dir: &Path, depth: u32) -> (u64, u64) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return (0, 0);
    };
    let (mut n, mut bytes) = (0u64, 0u64);
    for e in rd.filter_map(Result::ok) {
        let Ok(md) = std::fs::symlink_metadata(e.path()) else {
            continue;
        };
        if md.file_type().is_file() {
            n += 1;
            bytes = bytes.saturating_add(md.len());
        } else if md.is_dir() && depth < 4 {
            let (a, b) = summarise(&e.path(), depth + 1);
            n += a;
            bytes = bytes.saturating_add(b);
        }
    }
    (n, bytes)
}

/// Collect the bundle.
pub fn collect(opts: &Options, runner: &dyn Runner) -> Result<Written, String> {
    let host = host_name(&opts.root);
    let now = crate::time::unix_secs(opts.now);
    let name = format!("robodr-support-{host}-{}", crate::time::compact(now));
    let dir = opts.out_dir.join(&name);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut b = Builder {
        opts,
        runner,
        dir: dir.clone(),
        files: Vec::new(),
        skipped: Vec::new(),
    };
    let res = fill(&mut b, &host, now);
    let res = res.and_then(|()| scan(&b));
    if let Err(e) = res {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(e);
    }
    let (files, skipped) = (b.files.len(), b.skipped.len());
    if !opts.tar {
        return Ok(Written {
            path: dir,
            sha256: None,
            files,
            skipped,
        });
    }
    let archive = opts.out_dir.join(format!("{name}.tar.gz"));
    match pack(&opts.out_dir, &name, &archive, now) {
        Ok(()) => {
            let _ = std::fs::remove_dir_all(&dir);
            let sum = std::fs::read(&archive).ok().map(|x| sha256_hex(&x));
            Ok(Written {
                path: archive,
                sha256: sum,
                files,
                skipped,
            })
        }
        Err(e) => {
            let _ = std::fs::remove_file(&archive);
            eprintln!("robodr-support-bundle: not packed ({e}); the bundle is the directory");
            Ok(Written {
                path: dir,
                sha256: None,
                files,
                skipped,
            })
        }
    }
}

fn fill(b: &mut Builder<'_>, host: &str, now: u64) -> Result<(), String> {
    // System.
    // /etc/os-release is usually a symlink (never followed) to this one.
    let os_release = if rooted(&b.opts.root, "/usr/lib/os-release").is_file() {
        "/usr/lib/os-release"
    } else {
        "/etc/os-release"
    };
    b.file("system/os-release", os_release, Redact::None)?;
    b.file("system/kernel-version", "/proc/version", Redact::None)?;
    b.file("system/uptime", "/proc/uptime", Redact::None)?;
    b.file("system/meminfo", "/proc/meminfo", Redact::None)?;
    b.cmd(
        "system/df.txt",
        "df",
        &["-Pk", "/", "/var/lib/robodr"],
        Redact::None,
    )?;
    b.cmd("system/ip-addr.txt", "ip", &["-br", "addr"], Redact::None)?;
    b.cmd(
        "system/timedatectl.txt",
        "timedatectl",
        &["show"],
        Redact::None,
    )?;
    // Packages and binaries.
    b.cmd(
        "packages/dpkg.txt",
        "dpkg-query",
        &[
            "-W",
            "-f=${binary:Package} ${Version} ${db:Status-Abbrev}\n",
            "robodr*",
        ],
        Redact::None,
    )?;
    b.cmd(
        "packages/dpkg-verify.txt",
        "dpkg",
        &["--verify", "robodr", "robodr-focal"],
        Redact::None,
    )?;
    b.cmd("packages/rpm.txt", "rpm", &["-q", "robodr"], Redact::None)?;
    b.cmd(
        "packages/rpm-verify.txt",
        "rpm",
        &["-V", "robodr"],
        Redact::None,
    )?;
    let mut sums = String::new();
    for d in ["/usr/bin", "/usr/sbin"] {
        let Ok(rd) = std::fs::read_dir(rooted(&b.opts.root, d)) else {
            continue;
        };
        let mut names: Vec<String> = rd
            .filter_map(Result::ok)
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.starts_with("robodr-"))
            .collect();
        names.sort();
        for n in names {
            let p = rooted(&b.opts.root, &format!("{d}/{n}"));
            if std::fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_file()) {
                if let Ok(x) = std::fs::read(&p) {
                    sums.push_str(&format!("{}  {d}/{n}\n", sha256_hex(&x)));
                }
            }
        }
    }
    b.write(
        "packages/binaries.sha256",
        sums.as_bytes(),
        "sha256 of /usr/{bin,sbin}/robodr-*",
        false,
    )?;
    // Units and journal.
    b.cmd(
        "units/list-units.txt",
        "systemctl",
        &["list-units", "--all", "--no-pager", "--plain", "robodr*"],
        Redact::None,
    )?;
    b.cmd(
        "units/list-unit-files.txt",
        "systemctl",
        &["list-unit-files", "--no-pager", "robodr*"],
        Redact::None,
    )?;
    b.cmd(
        "units/show.txt",
        "systemctl",
        &[
            "show",
            "--no-pager",
            "-p",
            "Id,ActiveState,SubState,Result,NRestarts,ExecMainStatus,ExecMainStartTimestamp,\
             MemoryCurrent,MemoryPeak,CPUUsageNSec,TasksCurrent,UnitFileState",
            "robodr*",
        ],
        Redact::None,
    )?;
    b.cmd(
        "units/cat.txt",
        "systemctl",
        &["cat", "--no-pager", "robodr*"],
        Redact::Text,
    )?;
    if b.opts.journal {
        let since = format!("--since={}", b.opts.since);
        let lines = format!("--lines={}", b.opts.journal_lines);
        b.cmd(
            "journal/robodr.txt",
            "journalctl",
            &[
                "--no-pager",
                "-o",
                "short-iso-precise",
                &since,
                &lines,
                "-u",
                "robodr*",
            ],
            Redact::Text,
        )?;
        b.cmd(
            "journal/kernel.txt",
            "journalctl",
            &[
                "--no-pager",
                "-o",
                "short-iso-precise",
                "-k",
                &since,
                "--lines=5000",
            ],
            Redact::Text,
        )?;
    } else {
        b.skip("journal", "--no-journal");
    }
    // Network policy.
    b.cmd(
        "network/nft-ruleset.txt",
        "nft",
        &["list", "ruleset"],
        Redact::Text,
    )?;
    // Daemon status files.
    for s in STATUS_FILES {
        let rel = format!("status{s}");
        b.file(&rel, s, Redact::Json)?;
    }
    // Spool / evidence / outbox sizes (never names or content).
    let mut sizes =
        String::from("# directory  regular_files  bytes (names and content are never collected)\n");
    for d in SUMMARISED {
        let p = rooted(&b.opts.root, d);
        if p.is_dir() {
            let (n, by) = summarise(&p, 0);
            sizes.push_str(&format!("{d}  {n}  {by}\n"));
        } else {
            sizes.push_str(&format!("{d}  absent\n"));
        }
    }
    b.write(
        "state/sizes.txt",
        sizes.as_bytes(),
        "file counts and sizes",
        false,
    )?;
    // Configuration directly in /etc/robodr (redacted; not keys/, not kafka/).
    let etc = rooted(&b.opts.root, "/etc/robodr");
    if let Ok(rd) = std::fs::read_dir(&etc) {
        let mut names: Vec<String> = rd
            .filter_map(Result::ok)
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| {
                [".json", ".toml", ".env", ".conf"]
                    .iter()
                    .any(|s| n.ends_with(s))
            })
            .collect();
        names.sort();
        for n in names {
            let logical = format!("/etc/robodr/{n}");
            let how = if n.ends_with(".json") {
                Redact::Json
            } else {
                Redact::Text
            };
            b.file(&format!("config/{n}"), &logical, how)?;
        }
    } else {
        b.skip("/etc/robodr", "absent or unreadable");
    }
    // This host's preflight and metrics.
    let probe = crate::preflight::Probe {
        root: b.opts.root.clone(),
        runner: b.runner,
        now: b.opts.now,
    };
    let popts = crate::preflight::Options {
        variant: crate::preflight::detect_variant(&b.opts.root),
        ..Default::default()
    };
    let checks = crate::preflight::run(&probe, &popts);
    let pj = serde_json::to_vec_pretty(&checks).map_err(|e| e.to_string())?;
    b.write("preflight.json", &pj, "robodr-setup preflight", false)?;
    let read_json = |p: &str| -> Option<Result<serde_json::Value, String>> {
        let path = rooted(&b.opts.root, p);
        path.exists().then(|| {
            std::fs::read(&path)
                .map_err(|e| e.to_string())
                .and_then(|x| serde_json::from_slice(&x).map_err(|e| e.to_string()))
        })
    };
    let inputs = crate::metrics::Inputs {
        agentd: read_json(crate::metrics::AGENTD_STATUS),
        uplink: read_json(crate::metrics::UPLINK_STATUS),
        units: Some(
            b.runner
                .stdout("systemctl", &crate::metrics::units_show_args())
                .ok_or_else(|| "systemctl show failed".to_string()),
        ),
        now_mono_ms: robodr_agentd::notify::monotonic_ms(),
        boot_id: std::fs::read_to_string(rooted(&b.opts.root, "/proc/sys/kernel/random/boot_id"))
            .unwrap_or_default()
            .trim()
            .to_string(),
        now_wall_ms: now.saturating_mul(1000),
    };
    let m = crate::metrics::render(&inputs);
    b.write("metrics.prom", m.as_bytes(), "robodr-metrics", false)?;
    // Manifest, then the checksums of everything (manifest included).
    let manifest = Manifest {
        format: "robodr-support-bundle/1",
        created_utc: crate::time::rfc3339(now),
        host,
        robodr_ops_version: env!("CARGO_PKG_VERSION"),
        files: &b.files,
        skipped: &b.skipped,
        never_collected: FORBIDDEN,
    };
    let mj = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
    b.write("manifest.json", &mj, "robodr-support-bundle", false)?;
    let mut sums = String::new();
    for e in &b.files {
        sums.push_str(&format!("{}  {}\n", e.sha256, e.path));
    }
    let p = b.dir.join("SHA256SUMS");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&p)
        .map_err(|e| format!("{}: {e}", p.display()))?;
    f.write_all(sums.as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("{}: {e}", p.display()))
}

/// Fail closed on secret key material anywhere in the bundle.
fn scan(b: &Builder<'_>) -> Result<(), String> {
    let mut hits = Vec::new();
    for e in &b.files {
        let x = std::fs::read(b.dir.join(&e.path)).map_err(|err| format!("{}: {err}", e.path))?;
        let m = redact::secret_markers(&x);
        if !m.is_empty() {
            hits.push(format!("{} ({})", e.path, m.join(", ")));
        }
    }
    if hits.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "secret key material found after redaction in {}; the bundle was deleted, nothing \
             was written. Report this to RoboDR support without the bundle.",
            hits.join("; ")
        ))
    }
}

/// `tar -czf` the bundle directory (owner 0:0, sorted, fixed mtime) into
/// `archive`, created 0600 beforehand so it is never world-readable.
fn pack(parent: &Path, name: &str, archive: &Path, now: u64) -> Result<(), String> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(archive)
        .map_err(|e| format!("{}: {e}", archive.display()))?;
    let parent_s = parent.to_string_lossy().into_owned();
    let archive_s = archive.to_string_lossy().into_owned();
    let mtime = format!("--mtime=@{now}");
    let o = Host::default()
        .run(
            "tar",
            &[
                "--sort=name",
                "--owner=0",
                "--group=0",
                "--numeric-owner",
                &mtime,
                "-czf",
                &archive_s,
                "-C",
                &parent_s,
                name,
            ],
        )
        .map_err(|e| format!("tar: {e}"))?;
    if !o.ok() {
        return Err(format!(
            "tar exited {:?}: {}",
            o.code,
            String::from_utf8_lossy(&o.stderr).trim()
        ));
    }
    let md = std::fs::metadata(archive).map_err(|e| e.to_string())?;
    if md.mode() & 0o077 != 0 {
        return Err(format!(
            "{}: mode {:04o}",
            archive.display(),
            md.mode() & 0o7777
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forbidden_paths() {
        for p in [
            "/etc/robodr/keys",
            "/etc/robodr/keys/agentd-blackbox.key",
            "/var/lib/robodr/blackbox/agentd/seg-1",
            "/run/credentials/robodr-agentd.service/blackbox.key",
            "/etc/robodr/../robodr/keys/x",
            "relative/path",
        ] {
            assert!(forbidden(p), "{p}");
        }
        for p in [
            "/etc/robodr/agentd.json",
            "/etc/robodr/keysmith.json",
            "/var/lib/robodr/spool/agentd/status.json",
        ] {
            assert!(!forbidden(p), "{p}");
        }
    }
}
