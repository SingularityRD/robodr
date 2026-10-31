//! Host preflight (`robodr-setup preflight`, sales-readiness T68).
//!
//! Each check reads the host (files under a root, `/` in production) and,
//! where no file says it, runs a command through an [`exec::Runner`]. A
//! check is `ok`, `warn` (RoboDR runs, but something is reduced: e.g. no
//! BTF, so no `robodr-pulsard`), `fail` (a RoboDR unit cannot run, or would
//! run wrongly: systemd too old, the wall clock before the release was
//! built, the state disk nearly full, a key directory others can read) or
//! `skip` (not applicable to this package variant). Any `fail` makes the
//! preflight fail (exit 1).
//!
//! | id | ok | warn | fail |
//! |---|---|---|---|
//! | `kernel.btf` | `/sys/kernel/btf/vmlinux`, or an external BTF stamped for the running kernel | no BTF (no `robodr-pulsard`) | external BTF stamped for another kernel |
//! | `bpffs` | `/sys/fs/bpf` is a `bpf` mount | not mounted (`robodr-pulsard` refuses to start) | |
//! | `nf_tables` | loaded, built in, a module of the running kernel, or `nft list tables` works | none (executor / gateway cannot enforce) | |
//! | `systemd` | PID 1 is systemd >= 247 (245 for `robodr-focal`) | | older, or not PID 1 |
//! | `glibc` | >= the package's `libc6` floor | | older |
//! | `clock` | after the build date and NTP-synchronised | not synchronised / unknown | before the build date |
//! | `disk` | free >= 2 x minimum on the state disk | free < 2 x minimum | free < minimum |
//! | `keys.dir` | `/etc/robodr/keys` root-owned 0700 | missing (created by the package) | group/other access, not root's, or a symlink |

use crate::exec::Runner;
use crate::rooted;
use serde::Serialize;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Outcome of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Ok,
    Skip,
    Warn,
    Fail,
}

impl Level {
    pub fn tag(self) -> &'static str {
        match self {
            Level::Ok => "  OK  ",
            Level::Skip => " SKIP ",
            Level::Warn => " WARN ",
            Level::Fail => " FAIL ",
        }
    }
}

/// One check's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    pub id: &'static str,
    pub level: Level,
    pub detail: String,
}

fn check(id: &'static str, level: Level, detail: impl Into<String>) -> Check {
    Check {
        id,
        level,
        detail: detail.into(),
    }
}

/// Which package the host runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Variant {
    /// `robodr` (glibc, systemd >= 247, with `robodr-pulsard`).
    Standard,
    /// `robodr-focal` (static, systemd 245, no `robodr-pulsard`).
    Focal,
}

/// The variant installed under `root`: `robodr-focal` ships
/// `/usr/lib/robodr/robodr-load-credential` and nothing else does.
pub fn detect_variant(root: &Path) -> Variant {
    if rooted(root, "/usr/lib/robodr/robodr-load-credential").exists() {
        Variant::Focal
    } else {
        Variant::Standard
    }
}

/// Settings of a preflight run.
#[derive(Debug, Clone)]
pub struct Options {
    pub variant: Variant,
    /// RoboDR's state directory (`/var/lib/robodr`); its file system is the
    /// one checked for free space.
    pub state_dir: String,
    /// Minimum free space on it, MiB.
    pub min_free_mib: u64,
    /// Unix time this release was built (`SOURCE_DATE_EPOCH`); a wall clock
    /// before it is wrong.
    pub build_epoch: u64,
}

/// The build time compiled in (`SOURCE_DATE_EPOCH` of the release build),
/// or 2026-01-01 for a development build without it.
pub fn build_epoch() -> u64 {
    option_env!("SOURCE_DATE_EPOCH")
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(1_767_225_600)
}

impl Default for Options {
    fn default() -> Self {
        Self {
            variant: Variant::Standard,
            state_dir: "/var/lib/robodr".into(),
            min_free_mib: 2048,
            build_epoch: build_epoch(),
        }
    }
}

/// The host under test.
pub struct Probe<'a> {
    pub root: PathBuf,
    pub runner: &'a dyn Runner,
    pub now: SystemTime,
}

impl Probe<'_> {
    fn path(&self, p: &str) -> PathBuf {
        rooted(&self.root, p)
    }

    fn read(&self, p: &str) -> Option<String> {
        std::fs::read_to_string(self.path(p)).ok()
    }

    fn kernel_release(&self) -> Option<String> {
        self.read("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }
}

/// Run every check.
pub fn run(p: &Probe<'_>, o: &Options) -> Vec<Check> {
    vec![
        btf(p, o),
        bpffs(p, o),
        nf_tables(p),
        systemd(p, o),
        glibc(p, o),
        clock(p, o),
        disk(p, o),
        keys_dir(p),
    ]
}

/// The worst level of `checks` (`Ok` for none).
pub fn worst(checks: &[Check]) -> Level {
    checks.iter().map(|c| c.level).max().unwrap_or(Level::Ok)
}

fn btf(p: &Probe<'_>, o: &Options) -> Check {
    const ID: &str = "kernel.btf";
    if o.variant == Variant::Focal {
        return check(ID, Level::Skip, "robodr-focal has no robodr-pulsard");
    }
    if p.path("/sys/kernel/btf/vmlinux").is_file() {
        return check(ID, Level::Ok, "kernel BTF at /sys/kernel/btf/vmlinux");
    }
    let ext = p.path("/etc/robodr/btf/vmlinux");
    if ext.is_file() {
        let stamp = p.read("/etc/robodr/btf/vmlinux.kernel");
        let release = p.kernel_release();
        let stamped = stamp
            .as_deref()
            .and_then(|s| s.lines().next())
            .map(str::trim);
        return match (stamped, release.as_deref()) {
            (Some(s), Some(r)) if s == r => check(
                ID,
                Level::Ok,
                format!(
                    "external BTF /etc/robodr/btf/vmlinux stamped for {r} \
                     (robodr-btf-check verifies its hash and build at start)"
                ),
            ),
            (Some(s), r) => check(
                ID,
                Level::Fail,
                format!(
                    "external BTF /etc/robodr/btf/vmlinux was generated for kernel {s}, \
                     this is {}: regenerate it (docs/UNITREE.md 3.2.1); robodr-pulsard \
                     refuses to start",
                    r.unwrap_or("unknown")
                ),
            ),
            (None, _) => check(
                ID,
                Level::Fail,
                "external BTF /etc/robodr/btf/vmlinux without its stamp vmlinux.kernel \
                 (docs/UNITREE.md 3.2.1); robodr-pulsard refuses to start",
            ),
        };
    }
    check(
        ID,
        Level::Warn,
        "no BTF (/sys/kernel/btf/vmlinux missing): robodr-pulsard cannot run, so there is \
         no host behaviour detection; network detection (robodr-agentd) is unaffected. \
         Generate an external BTF (docs/UNITREE.md 3.2.1) or use a BTF kernel",
    )
}

fn bpffs(p: &Probe<'_>, o: &Options) -> Check {
    const ID: &str = "bpffs";
    if o.variant == Variant::Focal {
        return check(ID, Level::Skip, "robodr-focal has no robodr-pulsard");
    }
    let mounted = p
        .read("/proc/self/mounts")
        .map(|m| {
            m.lines().any(|l| {
                let mut f = l.split_whitespace();
                let (_, mp, ty) = (f.next(), f.next(), f.next());
                mp == Some("/sys/fs/bpf") && ty == Some("bpf")
            })
        })
        .unwrap_or(false);
    if mounted {
        check(ID, Level::Ok, "bpf file system mounted at /sys/fs/bpf")
    } else {
        check(
            ID,
            Level::Warn,
            "/sys/fs/bpf is not a bpf mount: robodr-pulsard will not start \
             (AssertPathIsMountPoint=); systemd mounts it at boot on a standard kernel",
        )
    }
}

fn nf_tables(p: &Probe<'_>) -> Check {
    const ID: &str = "nf_tables";
    if p.path("/sys/module/nf_tables").is_dir() {
        return check(ID, Level::Ok, "nf_tables loaded");
    }
    // Built in without a /sys/module entry, and no module tree (a minimal
    // or container kernel): ask the kernel (needs CAP_NET_ADMIN; changes
    // nothing).
    if p.runner
        .run("nft", &["list", "tables"])
        .is_ok_and(|o| o.ok())
    {
        return check(ID, Level::Ok, "nf_tables usable (nft list tables)");
    }
    let Some(rel) = p.kernel_release() else {
        return check(
            ID,
            Level::Warn,
            "kernel release unknown: cannot tell whether nf_tables is available",
        );
    };
    let listed = |file: &str| {
        p.read(&format!("/lib/modules/{rel}/{file}"))
            .map(|t| {
                t.lines().any(|l| {
                    let name = l.split(':').next().unwrap_or_default();
                    name.rsplit('/')
                        .next()
                        .is_some_and(|b| b == "nf_tables.ko" || b.starts_with("nf_tables.ko."))
                })
            })
            .unwrap_or(false)
    };
    if listed("modules.builtin") {
        check(ID, Level::Ok, "nf_tables built into the kernel")
    } else if listed("modules.dep") {
        check(
            ID,
            Level::Ok,
            "nf_tables available as a module (loaded on first use)",
        )
    } else {
        check(
            ID,
            Level::Warn,
            "no nf_tables in the running kernel: robodr-executor and robodr-firewall-gw \
             cannot enforce (detection is unaffected)",
        )
    }
}

/// `systemd 255 (255.4-1ubuntu8)` -> 255.
fn systemd_version(text: &str) -> Option<u32> {
    let line = text.lines().next()?;
    let mut f = line.split_whitespace();
    if f.next()? != "systemd" {
        return None;
    }
    f.next()?.parse().ok()
}

fn systemd(p: &Probe<'_>, o: &Options) -> Check {
    const ID: &str = "systemd";
    let min = match o.variant {
        Variant::Standard => 247,
        Variant::Focal => 245,
    };
    let pid1 = p
        .read("/proc/1/comm")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if pid1 != "systemd" {
        return check(
            ID,
            Level::Fail,
            format!(
                "PID 1 is {:?}, not systemd: RoboDR's units (sandboxing, credentials, \
                 watchdog) need systemd",
                pid1
            ),
        );
    }
    match p
        .runner
        .stdout("systemctl", &["--version"])
        .as_deref()
        .and_then(systemd_version)
    {
        Some(v) if v >= min => check(ID, Level::Ok, format!("systemd {v} (>= {min})")),
        Some(v) => check(
            ID,
            Level::Fail,
            format!(
                "systemd {v} is older than {min}{}",
                if o.variant == Variant::Standard {
                    ": use the robodr-focal package (systemd 245) on this host"
                } else {
                    ""
                }
            ),
        ),
        None => check(
            ID,
            Level::Fail,
            "cannot read the systemd version (systemctl)",
        ),
    }
}

/// `2.39` -> (2, 39).
fn version_pair(s: &str) -> Option<(u32, u32)> {
    let mut it = s.trim().split('.');
    let a = it.next()?.parse().ok()?;
    let b = it
        .next()?
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .ok()?;
    Some((a, b))
}

/// The `libc6 (>= X)` floor of the installed `robodr` package.
fn package_glibc_floor(p: &Probe<'_>) -> Option<(u32, u32)> {
    let deps = p
        .runner
        .stdout("dpkg-query", &["-W", "-f=${Depends}", "robodr"])?;
    deps.split(',').find_map(|d| {
        let d = d.trim();
        let v = d.strip_prefix("libc6 (>=")?.trim().strip_suffix(')')?;
        // Debian revision / epoch-free upstream part: 2.39-0ubuntu1 -> 2.39.
        version_pair(v.split('-').next().unwrap_or(v))
    })
}

fn glibc(p: &Probe<'_>, o: &Options) -> Check {
    const ID: &str = "glibc";
    if o.variant == Variant::Focal {
        return check(ID, Level::Skip, "robodr-focal binaries are static");
    }
    // The oldest supported userland (Ubuntu 22.04), raised to what the
    // installed package declares.
    let (floor, from) = match package_glibc_floor(p) {
        Some(f) => (f, "the robodr package's libc6 dependency"),
        None => ((2, 35), "the oldest supported userland"),
    };
    let have = p
        .runner
        .stdout("getconf", &["GNU_LIBC_VERSION"])
        .and_then(|s| s.trim().strip_prefix("glibc ").and_then(version_pair));
    match have {
        Some(v) if v >= floor => check(
            ID,
            Level::Ok,
            format!("glibc {}.{} (>= {}.{}, {from})", v.0, v.1, floor.0, floor.1),
        ),
        Some(v) => check(
            ID,
            Level::Fail,
            format!(
                "glibc {}.{} is older than {}.{} ({from}): use the robodr-focal package",
                v.0, v.1, floor.0, floor.1
            ),
        ),
        None => check(
            ID,
            Level::Fail,
            "cannot read the glibc version (getconf GNU_LIBC_VERSION)",
        ),
    }
}

fn clock(p: &Probe<'_>, o: &Options) -> Check {
    const ID: &str = "clock";
    let now = crate::time::unix_secs(p.now);
    if now < o.build_epoch {
        return check(
            ID,
            Level::Fail,
            format!(
                "the wall clock ({}) is before this release was built ({}): evidence and \
                 finding timestamps would be wrong and certificates may not verify; set the \
                 clock (RTC battery, NTP) before starting RoboDR",
                crate::time::rfc3339(now),
                crate::time::rfc3339(o.build_epoch)
            ),
        );
    }
    match p
        .runner
        .stdout("timedatectl", &["show", "-p", "NTPSynchronized", "--value"])
        .map(|s| s.trim().to_string())
        .as_deref()
    {
        Some("yes") => check(
            ID,
            Level::Ok,
            format!("{}, NTP-synchronised", crate::time::rfc3339(now)),
        ),
        Some(_) => check(
            ID,
            Level::Warn,
            format!(
                "{}, not NTP-synchronised: evidence timestamps drift (air-gapped site: \
                 provide a site NTP source, or record the offset at commissioning)",
                crate::time::rfc3339(now)
            ),
        ),
        None => check(
            ID,
            Level::Warn,
            format!(
                "{}; synchronisation unknown (timedatectl unavailable)",
                crate::time::rfc3339(now)
            ),
        ),
    }
}

/// The nearest existing directory at or above `state_dir` under the root.
fn existing_ancestor(p: &Probe<'_>, state_dir: &str) -> PathBuf {
    let mut d = p.path(state_dir);
    while !d.is_dir() {
        match d.parent() {
            Some(up) if up != d => d = up.to_path_buf(),
            _ => break,
        }
    }
    d
}

/// Available KiB from `df -Pk` output (second line, fourth field).
fn df_avail_kib(text: &str) -> Option<u64> {
    text.lines().nth(1)?.split_whitespace().nth(3)?.parse().ok()
}

fn disk(p: &Probe<'_>, o: &Options) -> Check {
    const ID: &str = "disk";
    let dir = existing_ancestor(p, &o.state_dir);
    let dir_s = dir.to_string_lossy().into_owned();
    let Some(kib) = p
        .runner
        .stdout("df", &["-Pk", &dir_s])
        .as_deref()
        .and_then(df_avail_kib)
    else {
        return check(
            ID,
            Level::Fail,
            format!("cannot read free space of {dir_s} (df)"),
        );
    };
    let mib = kib / 1024;
    let detail = format!(
        "{mib} MiB free on the file system of {} (minimum {} MiB: black box, spool, \
         releases kept for rollback)",
        o.state_dir, o.min_free_mib
    );
    if mib < o.min_free_mib {
        check(ID, Level::Fail, detail)
    } else if mib < o.min_free_mib.saturating_mul(2) {
        check(ID, Level::Warn, detail)
    } else {
        check(ID, Level::Ok, detail)
    }
}

fn keys_dir(p: &Probe<'_>) -> Check {
    const ID: &str = "keys.dir";
    let path = p.path("/etc/robodr/keys");
    let md =
        match std::fs::symlink_metadata(&path) {
            Ok(md) => md,
            Err(_) => return check(
                ID,
                Level::Warn,
                "/etc/robodr/keys missing (the package's systemd-tmpfiles creates it 0700 root)",
            ),
        };
    if !md.is_dir() {
        return check(
            ID,
            Level::Fail,
            "/etc/robodr/keys is not a directory (a symlink is refused)",
        );
    }
    let mode = md.mode() & 0o7777;
    if md.uid() != 0 && md.uid() != robodr_blackbox::keys::effective_uid() {
        return check(
            ID,
            Level::Fail,
            format!("/etc/robodr/keys is owned by uid {}, not root", md.uid()),
        );
    }
    if mode & 0o077 != 0 {
        return check(
            ID,
            Level::Fail,
            format!(
                "/etc/robodr/keys has mode {mode:04o}: group/other can reach the secret keys \
                 (want 0700; systemd-tmpfiles --create resets it)"
            ),
        );
    }
    check(ID, Level::Ok, format!("/etc/robodr/keys mode {mode:04o}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsers() {
        assert_eq!(
            systemd_version("systemd 255 (255.4-1ubuntu8)\n+PAM"),
            Some(255)
        );
        assert_eq!(systemd_version("nope 1"), None);
        assert_eq!(version_pair("2.39"), Some((2, 39)));
        assert_eq!(version_pair("2.35-0ubuntu3"), Some((2, 35)));
        assert_eq!(
            df_avail_kib("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda 100 50 4096 50% /\n"),
            Some(4096)
        );
    }
}
