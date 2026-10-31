//! Operational early warnings and the periodic health record
//! (sales-readiness T5, T6, T7, T40, T41; findings contract 2.5, §3g).
//!
//! | Issue | Rule | Severity | Raised |
//! |---|---|---|---|
//! | periodic record | [`rules::HEALTH`] | Low | every `health_record_ms` (`entity_context.agent_health`) |
//! | certificate / CRL expiry close | [`rules::CREDENTIAL_EXPIRING`] | Medium (≤ `credential_warn_days`), High (≤ `credential_critical_days` or expired) | per credential on each escalation, then at most once a day |
//! | kernel clock unsynchronised | [`rules::CLOCK_UNSYNCED`] | Medium | once per episode, after `clock_unsynced_grace_ms` |
//! | wall clock jumped against monotonic | [`rules::CLOCK_JUMP`] | High | on a new jump, at most every `health_report_ms` |
//! | filesystem nearly full | [`rules::DISK_LOW`] | Medium (< `disk_warn_percent` free), High (< `disk_critical_percent`) | per filesystem on each escalation |
//! | executor does not answer | [`rules::EXECUTOR_UNREACHABLE`] | High | once per outage, after `executor_unreachable_ms` |
//! | gateway / executor still on the binaries from before an upgrade | [`rules::RESTART_PENDING`] | Medium | once the pending-restart file is `restart_pending_grace_ms` old, again when its units change, then at most once a day |
//!
//! Every evaluator here is a pure function of its inputs (times are
//! milliseconds: daemon time for durations, Unix time for expiry), so it is
//! unit-tested without a clock, a disk or a kernel. The two probes
//! ([`fs_space`], [`kernel_clock`]) are thin `statvfs(3)` / `adjtimex(2)`
//! wrappers; `adjtimex` with `modes = 0` only reads and needs no
//! capability, but a seccomp filter can refuse it: the shipped systemd
//! unit's `ProtectClock=yes` / `@clock` filter does. Then the clock state
//! falls back to systemd-timesyncd's marker file ([`clock_health`]), the
//! health record carries `clock.adjtimex_errno`, and `clock_unsynced`
//! cannot be raised.
//!
//! Like every self-health finding these are observe-only: a full disk or
//! a lost clock never causes a response by itself.

use std::collections::BTreeMap;
use std::path::Path;

use robodr_events::{Deviation, Severity};
use robodr_ocsf::{CredentialExpiry, DiskHealth};
use serde::{Deserialize, Serialize};

/// Rule ids (findings contract 2.5).
pub mod rules {
    pub const HEALTH: &str = robodr_ocsf::AGENT_HEALTH_RULE;
    pub const CREDENTIAL_EXPIRING: &str = "robot.agent.credential_expiring";
    pub const CLOCK_UNSYNCED: &str = "robot.agent.clock_unsynced";
    pub const CLOCK_JUMP: &str = "robot.agent.clock_jump";
    pub const DISK_LOW: &str = "robot.agent.disk_low";
    pub const EXECUTOR_UNREACHABLE: &str = "robot.agent.executor_unreachable";
    pub const RESTART_PENDING: &str = "robot.agent.restart_pending";
}

/// The file the package's maintainer scripts write the gated units into
/// when an upgrade leaves them on the previous binaries
/// (`packaging/deb/postinst`, `packaging/rpm/post`: `mark_pending_restart`);
/// `install-bundle.sh` removes it once they are restarted.
pub const PENDING_RESTART_FILE: &str = "/var/lib/robodr/pending-restart";

/// The units a package upgrade never restarts by itself (T9): only these
/// names in [`PENDING_RESTART_FILE`] count (`install-bundle.sh` ignores
/// any other line too).
pub const GATED_UNITS: &[&str] = &["robodr-executor.service", "robodr-firewall-gw.service"];

/// At most this much of the pending-restart file is read.
const PENDING_RESTART_MAX_BYTES: u64 = 4096;

const DAY_MS: u64 = 86_400_000;

/// `daemon.self_health`: the health record and the early-warning
/// thresholds.
///
/// ```json
/// "daemon": { "self_health": { "health_record_ms": 60000,
///   "credential_warn_days": 14, "credential_critical_days": 3,
///   "clock_unsynced_grace_ms": 300000, "disk_warn_percent": 10,
///   "disk_critical_percent": 3, "executor_unreachable_ms": 30000,
///   "restart_pending_grace_ms": 900000 } }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SelfHealthSection {
    /// Period of the `robot.agent.health` record, 1 000 ..= 3 600 000 ms
    /// (default 60 000). 0 switches the record off (the early warnings
    /// stay on): only for replay and tests, a SOC then cannot tell a
    /// silent robot from a quiet one.
    pub health_record_ms: u64,
    /// Medium at this many days before a certificate / CRL expires
    /// (1 ..= 365, default 14).
    pub credential_warn_days: u64,
    /// High at this many days (0 ..= `credential_warn_days`, default 3).
    pub credential_critical_days: u64,
    /// The kernel must report the clock unsynchronised this long before
    /// `robot.agent.clock_unsynced` (0 ..= 86 400 000 ms, default 300 000:
    /// a booting robot gets five minutes to lock).
    pub clock_unsynced_grace_ms: u64,
    /// Medium below this percentage of free space (1 ..= 50, default 10).
    pub disk_warn_percent: u8,
    /// High below this percentage (0 ..= `disk_warn_percent`, default 3).
    pub disk_critical_percent: u8,
    /// The executor must fail to answer this long before
    /// `robot.agent.executor_unreachable` (1 000 ..= 3 600 000 ms, default
    /// 30 000).
    pub executor_unreachable_ms: u64,
    /// The pending-restart file must be this old before
    /// `robot.agent.restart_pending` (0 ..= 86 400 000 ms, default 900 000:
    /// an install whose safety gate is open restarts the two within
    /// seconds and removes the file).
    pub restart_pending_grace_ms: u64,
    /// Where the maintainer scripts record the units left on the previous
    /// binaries (default [`PENDING_RESTART_FILE`]; another path only for
    /// tests or a relocated install root).
    pub restart_pending_file: std::path::PathBuf,
}

impl Default for SelfHealthSection {
    fn default() -> Self {
        Self {
            health_record_ms: 60_000,
            credential_warn_days: 14,
            credential_critical_days: 3,
            clock_unsynced_grace_ms: 300_000,
            disk_warn_percent: 10,
            disk_critical_percent: 3,
            executor_unreachable_ms: 30_000,
            restart_pending_grace_ms: 900_000,
            restart_pending_file: PENDING_RESTART_FILE.into(),
        }
    }
}

impl SelfHealthSection {
    pub fn validate(&self) -> Result<(), String> {
        let bad = |what: &str, lo: u64, hi: u64, v: u64| {
            Err(format!(
                "daemon.self_health.{what} must be {lo}..={hi}, got {v}"
            ))
        };
        if self.health_record_ms != 0 && !(1_000..=3_600_000).contains(&self.health_record_ms) {
            return bad("health_record_ms", 1_000, 3_600_000, self.health_record_ms);
        }
        if !(1..=365).contains(&self.credential_warn_days) {
            return bad("credential_warn_days", 1, 365, self.credential_warn_days);
        }
        if self.credential_critical_days > self.credential_warn_days {
            return bad(
                "credential_critical_days",
                0,
                self.credential_warn_days,
                self.credential_critical_days,
            );
        }
        if self.clock_unsynced_grace_ms > 86_400_000 {
            return bad(
                "clock_unsynced_grace_ms",
                0,
                86_400_000,
                self.clock_unsynced_grace_ms,
            );
        }
        if !(1..=50).contains(&self.disk_warn_percent) {
            return bad("disk_warn_percent", 1, 50, self.disk_warn_percent.into());
        }
        if self.disk_critical_percent > self.disk_warn_percent {
            return bad(
                "disk_critical_percent",
                0,
                self.disk_warn_percent.into(),
                self.disk_critical_percent.into(),
            );
        }
        if !(1_000..=3_600_000).contains(&self.executor_unreachable_ms) {
            return bad(
                "executor_unreachable_ms",
                1_000,
                3_600_000,
                self.executor_unreachable_ms,
            );
        }
        if self.restart_pending_grace_ms > 86_400_000 {
            return bad(
                "restart_pending_grace_ms",
                0,
                86_400_000,
                self.restart_pending_grace_ms,
            );
        }
        if !self.restart_pending_file.is_absolute() {
            return Err(format!(
                "daemon.self_health.restart_pending_file must be an absolute path, got {}",
                self.restart_pending_file.display()
            ));
        }
        Ok(())
    }
}

/// How close to trouble something is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Ok,
    Warn,
    Critical,
}

impl Level {
    fn severity(self) -> Severity {
        match self {
            Level::Critical => Severity::High,
            _ => Severity::Medium,
        }
    }
}

/// Whole days from `now_ms` to `expires_ms` (Unix ms), rounded down
/// (negative once expired).
pub fn days_to_expiry(expires_ms: u64, now_ms: u64) -> i64 {
    CredentialExpiry::days_between(expires_ms, now_ms)
}

/// A credential's expiry from its Unix-seconds date (`notAfter`,
/// `nextUpdate`) at `now_ms` (Unix ms). Dates before 1970 read as 0.
pub fn credential(name: &str, expires_s: i64, now_ms: u64) -> CredentialExpiry {
    CredentialExpiry::at(name, expires_s, now_ms)
}

/// The kernel's view of the wall clock (`adjtimex(2)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct KernelClock {
    /// `false`: `STA_UNSYNC` set or the call returned `TIME_ERROR`.
    pub synchronized: bool,
    /// `maxerror` (µs).
    pub max_error_us: u64,
}

/// Why [`kernel_clock`] has no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockProbeError {
    /// `adjtimex(2)` failed with this `errno` (`EPERM` under the shipped
    /// unit: its `ProtectClock=yes` / `@clock` system-call filter refuses
    /// the call even read-only).
    Errno(u32),
    /// No `adjtimex(2)` on this platform.
    Unsupported,
}

/// systemd-timesyncd touches this file each time it synchronises the clock
/// (`systemd-timesyncd.service(8)`).
pub const TIMESYNC_MARKER: &str = "/run/systemd/timesync/synchronized";

/// A marker touched at most this long ago (twice timesyncd's default
/// longest poll interval, `PollIntervalMaxSec=2048`) reads as synchronised
/// when `adjtimex(2)` is refused. An older marker proves nothing either
/// way (timesyncd may have stopped, or polls less often): unknown.
pub const TIMESYNC_FRESH_MS: u64 = 4_096_000;

/// The clock part of the health record from the `adjtimex(2)` probe, the
/// age of [`TIMESYNC_MARKER`] (`None`: no such file) and the agent's
/// wall-clock jump count. `adjtimex` wins; a fresh marker only ever says
/// "synchronised" (an absent or old one is not evidence of the opposite:
/// the site may run chrony), so it never raises `clock_unsynced`.
pub fn clock_health(
    kernel: Result<KernelClock, ClockProbeError>,
    timesync_age_ms: Option<u64>,
    wall_jumps: u64,
) -> robodr_ocsf::ClockHealth {
    use robodr_ocsf::{ClockHealth, ClockSource};
    let mut h = ClockHealth {
        timesync_age_ms,
        wall_jumps,
        ..ClockHealth::default()
    };
    match kernel {
        Ok(k) => {
            h.synchronized = Some(k.synchronized);
            h.max_error_ms = Some(k.max_error_us / 1000);
            h.source = Some(ClockSource::Adjtimex);
        }
        Err(e) => {
            if let ClockProbeError::Errno(n) = e {
                h.adjtimex_errno = Some(n);
            }
            if timesync_age_ms.is_some_and(|a| a <= TIMESYNC_FRESH_MS) {
                h.synchronized = Some(true);
                h.source = Some(ClockSource::Timesyncd);
            }
        }
    }
    h
}

/// Reachability of a component fed by one or more inputs (`(ended,
/// last_rx_ms)` each, daemon time): an input is reachable when heard
/// within `silence_ms`, unknown before `silence_ms` has passed without a
/// word, unreachable otherwise or once ended. Several inputs report the
/// worst one, with that input's age, so a dead input is never hidden by a
/// live one and the state and `last_ok_age_ms` describe the same input.
pub fn inputs_reachability(
    inputs: impl IntoIterator<Item = (bool, Option<u64>)>,
    now_ms: u64,
    silence_ms: u64,
) -> (robodr_ocsf::ReachState, Option<u64>) {
    use robodr_ocsf::ReachState;
    let rank = |s: ReachState| match s {
        ReachState::Unreachable => 3,
        ReachState::Unknown => 2,
        ReachState::Reachable => 1,
        ReachState::NotConfigured => 0,
    };
    let mut worst = (ReachState::NotConfigured, None);
    for (ended, last_rx) in inputs {
        let state = match last_rx {
            _ if ended => ReachState::Unreachable,
            None if now_ms < silence_ms => ReachState::Unknown,
            None => ReachState::Unreachable,
            Some(t) if now_ms.saturating_sub(t) < silence_ms => ReachState::Reachable,
            Some(_) => ReachState::Unreachable,
        };
        if rank(state) > rank(worst.0) {
            worst = (state, last_rx.map(|t| now_ms.saturating_sub(t)));
        }
    }
    worst
}

/// Milliseconds from `path`'s modification time to `wall_ms` (Unix ms);
/// 0 for a time in the future, `None` if it cannot be read.
pub fn file_age_ms(path: &Path, wall_ms: u64) -> Option<u64> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    let at = modified.duration_since(std::time::UNIX_EPOCH).ok()?;
    let at_ms = u64::try_from(at.as_millis()).unwrap_or(u64::MAX);
    Some(wall_ms.saturating_sub(at_ms))
}

/// What the pending-restart file says (`status.json`
/// `self_health.pending_restart`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PendingRestart {
    /// The gated units it names, sorted, each once; empty when the file
    /// could not be read (`read_error`).
    pub units: Vec<String>,
    /// Milliseconds since the file was last written (`None`: unknown).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_ms: Option<u64>,
    /// Why the file exists but could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_error: Option<String>,
}

/// The pending-restart file at `path` at Unix time `wall_ms`: `None` when
/// there is none, or it names no gated unit (nothing to restart). A file
/// that exists but cannot be read still counts (its units unknown): the
/// gated units may well run the previous binaries.
pub fn pending_restart(path: &Path, wall_ms: u64) -> Option<PendingRestart> {
    use std::io::Read;
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            return Some(PendingRestart {
                units: Vec::new(),
                age_ms: None,
                read_error: Some(e.to_string()),
            })
        }
    };
    let age_ms = file_age_ms(path, wall_ms);
    if !meta.is_file() {
        return Some(PendingRestart {
            units: Vec::new(),
            age_ms,
            read_error: Some("not a regular file".into()),
        });
    }
    let mut text = Vec::new();
    let read = std::fs::File::open(path).and_then(|f| {
        f.take(PENDING_RESTART_MAX_BYTES)
            .read_to_end(&mut text)
            .map(|_| ())
    });
    if let Err(e) = read {
        return Some(PendingRestart {
            units: Vec::new(),
            age_ms,
            read_error: Some(e.to_string()),
        });
    }
    let text = String::from_utf8_lossy(&text);
    let mut units: Vec<String> = GATED_UNITS
        .iter()
        .filter(|u| text.lines().any(|l| l.trim() == **u))
        .map(|u| (*u).to_string())
        .collect();
    units.sort();
    (!units.is_empty()).then_some(PendingRestart {
        units,
        age_ms,
        read_error: None,
    })
}

/// A problem worth a finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warning {
    CredentialExpiring {
        name: String,
        days: i64,
        level: Level,
    },
    ClockUnsynced {
        for_ms: u64,
        max_error_us: u64,
    },
    ClockJump {
        jumps: u64,
        new: u64,
    },
    DiskLow {
        name: String,
        free_bytes: u64,
        total_bytes: u64,
        level: Level,
    },
    ExecutorUnreachable {
        for_ms: u64,
        error: Option<String>,
    },
    RestartPending(PendingRestart),
}

impl Warning {
    /// The deviation (observe-only once the agent stamps it).
    pub fn deviation(&self) -> Deviation {
        match self {
            Warning::CredentialExpiring { name, days, level } => Deviation::new(
                rules::CREDENTIAL_EXPIRING,
                level.severity(),
                if *days < 0 {
                    format!(
                        "{name} expired {} day(s) ago: renew it (the control plane refuses \
                         clients it can no longer vouch for)",
                        days.unsigned_abs()
                    )
                } else {
                    format!("{name} expires in {days} day(s): renew it before it does")
                },
            ),
            Warning::ClockUnsynced {
                for_ms,
                max_error_us,
            } => Deviation::new(
                rules::CLOCK_UNSYNCED,
                Severity::Medium,
                format!(
                    "the kernel has reported the wall clock unsynchronised for {} s (maximum \
                     error {} ms): check chrony / NTS / PTP; finding and evidence times may be \
                     wrong",
                    for_ms / 1000,
                    max_error_us / 1000
                ),
            ),
            Warning::ClockJump { jumps, new } => Deviation::new(
                rules::CLOCK_JUMP,
                Severity::High,
                format!(
                    "the wall clock jumped against the monotonic clock {new} time(s) ({jumps} \
                     since start; each one is a robodr.agent_fault note in the black box): a \
                     time step, an RTC reset or a spoofed time source"
                ),
            ),
            Warning::DiskLow {
                name,
                free_bytes,
                total_bytes,
                level,
            } => Deviation::new(
                rules::DISK_LOW,
                level.severity(),
                format!(
                    "the {name} filesystem has {free_bytes} of {total_bytes} bytes free ({}%): \
                     free space before recording stops",
                    percent(*free_bytes, *total_bytes)
                ),
            ),
            Warning::ExecutorUnreachable { for_ms, error } => Deviation::new(
                rules::EXECUTOR_UNREACHABLE,
                Severity::High,
                format!(
                    "robodr-executor has not answered for {} s{}: containment actions cannot be \
                     applied, verified or reverted until it does",
                    for_ms / 1000,
                    error
                        .as_deref()
                        .map(|e| format!(" (last error: {e})"))
                        .unwrap_or_default()
                ),
            ),
            Warning::RestartPending(p) => Deviation::new(
                rules::RESTART_PENDING,
                Severity::Medium,
                format!(
                    "{} still run the binaries from before the last package upgrade{}{}: \
                     the installed release and its security floor are not what runs. Restart \
                     them through the safety gate when the robot is idle or in its safe state: \
                     install-bundle.sh restart-pending (OPERATIONS.md 7)",
                    if p.units.is_empty() {
                        "the gated units (robodr-firewall-gw, robodr-executor) may".to_string()
                    } else {
                        p.units.join(" and ")
                    },
                    p.age_ms
                        .map(|a| format!(" (pending for {} s)", a / 1000))
                        .unwrap_or_default(),
                    p.read_error
                        .as_deref()
                        .map(|e| format!(" ({PENDING_RESTART_FILE} unreadable: {e})"))
                        .unwrap_or_default()
                ),
            ),
        }
    }
}

fn percent(free: u64, total: u64) -> u64 {
    if total == 0 {
        return 0;
    }
    u64::try_from(u128::from(free) * 100 / u128::from(total)).unwrap_or(100)
}

/// Level of a filesystem with `free` of `total` bytes.
pub fn disk_level(free: u64, total: u64, cfg: &SelfHealthSection) -> Level {
    if total == 0 {
        return Level::Ok; // not a real filesystem (or unreadable): nothing to say
    }
    // free/total < pct/100  <=>  free*100 < pct*total (exact, no rounding).
    let below = |pct: u8| u128::from(free) * 100 < u128::from(pct) * u128::from(total);
    if below(cfg.disk_critical_percent) {
        Level::Critical
    } else if below(cfg.disk_warn_percent) {
        Level::Warn
    } else {
        Level::Ok
    }
}

/// Stateful evaluator of the early warnings (one per daemon).
#[derive(Debug, Clone)]
pub struct Warnings {
    cfg: SelfHealthSection,
    report_ms: u64,
    /// Per credential: level last reported and when (daemon ms).
    creds: BTreeMap<String, (Level, u64)>,
    disks: BTreeMap<String, Level>,
    unsynced_since: Option<u64>,
    unsynced_reported: bool,
    jumps_reported: u64,
    jump_reported_at: Option<u64>,
    executor_reported: bool,
    /// The units last reported pending and when (daemon ms).
    restart_reported: Option<(Vec<String>, u64)>,
}

impl Warnings {
    /// `report_ms`: `daemon.health_report_ms` (rate limit of clock jumps).
    pub fn new(cfg: SelfHealthSection, report_ms: u64) -> Self {
        Self {
            cfg,
            report_ms,
            creds: BTreeMap::new(),
            disks: BTreeMap::new(),
            unsynced_since: None,
            unsynced_reported: false,
            jumps_reported: 0,
            jump_reported_at: None,
            executor_reported: false,
            restart_reported: None,
        }
    }

    pub fn config(&self) -> &SelfHealthSection {
        &self.cfg
    }

    fn credential_level(&self, days: i64) -> Level {
        let crit = i64::try_from(self.cfg.credential_critical_days).unwrap_or(i64::MAX);
        let warn = i64::try_from(self.cfg.credential_warn_days).unwrap_or(i64::MAX);
        if days <= crit {
            Level::Critical
        } else if days <= warn {
            Level::Warn
        } else {
            Level::Ok
        }
    }

    /// Credentials at daemon time `now_ms`: a finding when one gets worse
    /// (ok -> warn -> critical), and again once a day while it stays
    /// below `credential_warn_days`. Renewing it re-arms.
    pub fn credentials(&mut self, now_ms: u64, creds: &[CredentialExpiry]) -> Vec<Warning> {
        let mut out = Vec::new();
        for c in creds {
            let level = self.credential_level(c.days_to_expiry);
            let prev = self.creds.get(&c.name).copied();
            let due = match prev {
                _ if level == Level::Ok => false,
                None => true,
                Some((l, _)) if level > l => true,
                Some((_, at)) => now_ms.saturating_sub(at) >= DAY_MS,
            };
            if level == Level::Ok {
                self.creds.remove(&c.name);
            } else if due {
                self.creds.insert(c.name.clone(), (level, now_ms));
                out.push(Warning::CredentialExpiring {
                    name: c.name.clone(),
                    days: c.days_to_expiry,
                    level,
                });
            }
        }
        out
    }

    /// The kernel clock (`None`: not known here, including when
    /// `adjtimex(2)` is refused) and the agent's count of wall-clock jumps
    /// at daemon time `now_ms`.
    pub fn clock(
        &mut self,
        now_ms: u64,
        kernel: Option<KernelClock>,
        wall_jumps: u64,
    ) -> Vec<Warning> {
        let mut out = Vec::new();
        match kernel {
            Some(k) if !k.synchronized => {
                let since = *self.unsynced_since.get_or_insert(now_ms);
                let for_ms = now_ms.saturating_sub(since);
                if !self.unsynced_reported && for_ms >= self.cfg.clock_unsynced_grace_ms {
                    self.unsynced_reported = true;
                    out.push(Warning::ClockUnsynced {
                        for_ms,
                        max_error_us: k.max_error_us,
                    });
                }
            }
            _ => {
                self.unsynced_since = None;
                self.unsynced_reported = false;
            }
        }
        if wall_jumps > self.jumps_reported
            && self
                .jump_reported_at
                .is_none_or(|t| now_ms.saturating_sub(t) >= self.report_ms)
        {
            out.push(Warning::ClockJump {
                jumps: wall_jumps,
                new: wall_jumps - self.jumps_reported,
            });
            self.jumps_reported = wall_jumps;
            self.jump_reported_at = Some(now_ms);
        }
        out
    }

    /// Filesystems: a finding when one gets worse; getting better re-arms.
    pub fn disks(&mut self, disks: &[DiskHealth]) -> Vec<Warning> {
        let mut out = Vec::new();
        for d in disks {
            let level = disk_level(d.free_bytes, d.total_bytes, &self.cfg);
            let prev = self.disks.get(&d.name).copied().unwrap_or(Level::Ok);
            if level > prev {
                out.push(Warning::DiskLow {
                    name: d.name.clone(),
                    free_bytes: d.free_bytes,
                    total_bytes: d.total_bytes,
                    level,
                });
            }
            self.disks.insert(d.name.clone(), level);
        }
        out
    }

    /// The executor link: `unreachable_for_ms` = how long it has not
    /// answered (`None`: it answers, or is off).
    pub fn executor(
        &mut self,
        unreachable_for_ms: Option<u64>,
        error: Option<&str>,
    ) -> Vec<Warning> {
        match unreachable_for_ms {
            Some(for_ms) if for_ms >= self.cfg.executor_unreachable_ms => {
                if self.executor_reported {
                    return Vec::new();
                }
                self.executor_reported = true;
                vec![Warning::ExecutorUnreachable {
                    for_ms,
                    error: error.map(str::to_string),
                }]
            }
            Some(_) => Vec::new(),
            None => {
                self.executor_reported = false;
                Vec::new()
            }
        }
    }
}

impl Warnings {
    /// The pending-restart file at daemon time `now_ms` (`None`: none):
    /// a finding once it is `restart_pending_grace_ms` old (its age
    /// unknown counts as old), again when the units it names change, then
    /// once a day while it stays. Its removal re-arms.
    pub fn restart_pending(
        &mut self,
        now_ms: u64,
        pending: Option<&PendingRestart>,
    ) -> Vec<Warning> {
        let Some(p) = pending else {
            self.restart_reported = None;
            return Vec::new();
        };
        if p.age_ms
            .is_some_and(|a| a < self.cfg.restart_pending_grace_ms)
        {
            return Vec::new();
        }
        let due = match &self.restart_reported {
            None => true,
            Some((units, _)) if *units != p.units => true,
            Some((_, at)) => now_ms.saturating_sub(*at) >= DAY_MS,
        };
        if !due {
            return Vec::new();
        }
        self.restart_reported = Some((p.units.clone(), now_ms));
        vec![Warning::RestartPending(p.clone())]
    }
}

/// Free and total bytes (for an unprivileged writer) of the filesystem
/// holding `dir` (`statvfs(3)`; `None` where unavailable).
#[allow(unsafe_code)]
pub fn fs_space(dir: &Path) -> Option<(u64, u64)> {
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    {
        use std::os::unix::ffi::OsStrExt;
        extern "C" {
            fn statvfs(path: *const std::ffi::c_char, buf: *mut u64) -> std::ffi::c_int;
        }
        let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
        // Larger than `struct statvfs` on every 64-bit Linux libc (glibc,
        // musl: 112 bytes); its first fields are f_bsize, f_frsize,
        // f_blocks, f_bfree, f_bavail, all 64-bit here.
        let mut buf = [0u64; 32];
        // SAFETY: `c` is a NUL-terminated path that outlives the call;
        // `buf` is a writable, 8-byte aligned buffer larger than the
        // struct the call fills.
        let rc = unsafe { statvfs(c.as_ptr(), buf.as_mut_ptr()) };
        if rc != 0 {
            return None;
        }
        let [_, frsize, blocks, _, bavail, ..] = buf;
        Some((frsize.saturating_mul(bavail), frsize.saturating_mul(blocks)))
    }
    #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
    {
        let _ = dir;
        None
    }
}

/// The kernel clock discipline (`adjtimex(2)` with `modes = 0`: read
/// only, no capability needed). A seccomp filter can still refuse it: the
/// shipped systemd unit's `ProtectClock=yes` and `@clock` filter do, so
/// under that unit this returns `Err(Errno(EPERM))`.
#[allow(unsafe_code)]
pub fn kernel_clock() -> Result<KernelClock, ClockProbeError> {
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    {
        extern "C" {
            fn adjtimex(buf: *mut i64) -> std::ffi::c_int;
        }
        /// `TIME_ERROR` (clock not synchronised).
        const TIME_ERROR: std::ffi::c_int = 5;
        /// `STA_UNSYNC` in `status`.
        const STA_UNSYNC: i64 = 0x0040;
        // `struct timex` is 208 bytes on 64-bit Linux (glibc and musl):
        // `modes` (int, padded to 8), offset, freq, maxerror, esterror
        // (long each), `status` (int). Zeroed: `modes = 0` reads only.
        let mut buf = [0i64; 32];
        // SAFETY: `buf` is a writable, 8-byte aligned, zeroed buffer
        // larger than `struct timex`; with `modes = 0` the call only
        // fills it.
        let rc = unsafe { adjtimex(buf.as_mut_ptr()) };
        if rc < 0 {
            let errno = std::io::Error::last_os_error()
                .raw_os_error()
                .and_then(|e| u32::try_from(e).ok())
                .unwrap_or(0);
            return Err(ClockProbeError::Errno(errno));
        }
        let [_, _, _, maxerror, _, status_word, ..] = buf;
        // `status` is the low 32 bits of its 8-byte slot (little endian:
        // x86_64, aarch64; on a big-endian target the high bits).
        let status = if cfg!(target_endian = "little") {
            status_word & 0xffff_ffff
        } else {
            (status_word >> 32) & 0xffff_ffff
        };
        Ok(KernelClock {
            synchronized: rc != TIME_ERROR && status & STA_UNSYNC == 0,
            max_error_us: u64::try_from(maxerror).unwrap_or(0),
        })
    }
    #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
    {
        Err(ClockProbeError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w() -> Warnings {
        Warnings::new(SelfHealthSection::default(), 10_000)
    }

    fn cred(name: &str, days: i64) -> CredentialExpiry {
        CredentialExpiry {
            name: name.into(),
            expires_ms: 0,
            days_to_expiry: days,
        }
    }

    #[test]
    fn defaults_validate_and_bad_values_are_refused() {
        assert!(SelfHealthSection::default().validate().is_ok());
        for bad in [
            SelfHealthSection {
                health_record_ms: 500,
                ..Default::default()
            },
            SelfHealthSection {
                credential_critical_days: 20,
                ..Default::default()
            },
            SelfHealthSection {
                disk_warn_percent: 0,
                ..Default::default()
            },
            SelfHealthSection {
                disk_critical_percent: 11,
                ..Default::default()
            },
            SelfHealthSection {
                executor_unreachable_ms: 10,
                ..Default::default()
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
        let off = SelfHealthSection {
            health_record_ms: 0,
            ..Default::default()
        };
        assert!(off.validate().is_ok());
        for bad in [
            SelfHealthSection {
                restart_pending_grace_ms: 86_400_001,
                ..Default::default()
            },
            SelfHealthSection {
                restart_pending_file: "pending-restart".into(),
                ..Default::default()
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
    }

    fn pending(units: &[&str], age_ms: Option<u64>) -> PendingRestart {
        PendingRestart {
            units: units.iter().map(|u| (*u).to_string()).collect(),
            age_ms,
            read_error: None,
        }
    }

    /// WP8a (Phase 2 review, medium): units left on the previous binaries
    /// by an upgrade reach the SOC, after the grace, again when the set
    /// changes, daily while they stay; the file's removal re-arms.
    #[test]
    fn restart_pending_is_reported_after_the_grace_and_rearms() {
        let mut w = w();
        let gw = "robodr-firewall-gw.service";
        let ex = "robodr-executor.service";
        assert!(w.restart_pending(0, None).is_empty());
        // Younger than the grace (an install restarting them right now).
        assert!(w
            .restart_pending(1_000, Some(&pending(&[gw], Some(60_000))))
            .is_empty());
        let f = w.restart_pending(2_000, Some(&pending(&[gw], Some(900_000))));
        assert_eq!(f.len(), 1);
        let d = f[0].deviation();
        assert_eq!(d.rule_str(), rules::RESTART_PENDING);
        assert_eq!(d.severity, Severity::Medium);
        assert!(d.detail.contains(gw) && d.detail.contains("restart-pending"));
        // Not again while unchanged, within a day.
        assert!(w
            .restart_pending(60_000, Some(&pending(&[gw], Some(960_000))))
            .is_empty());
        // The set grew: again.
        assert_eq!(
            w.restart_pending(61_000, Some(&pending(&[ex, gw], Some(1_000_000))))
                .len(),
            1
        );
        // A day later: again.
        assert_eq!(
            w.restart_pending(61_000 + DAY_MS, Some(&pending(&[ex, gw], None)))
                .len(),
            1
        );
        // Restarted (file gone), then a new upgrade: reported anew.
        assert!(w.restart_pending(DAY_MS * 2, None).is_empty());
        assert_eq!(
            w.restart_pending(DAY_MS * 2 + 1, Some(&pending(&[ex], None)))
                .len(),
            1
        );
        // Unreadable: the units are unknown, still reported.
        let mut w2 = super::Warnings::new(SelfHealthSection::default(), 10_000);
        let p = PendingRestart {
            units: Vec::new(),
            age_ms: None,
            read_error: Some("Permission denied".into()),
        };
        let f = w2.restart_pending(0, Some(&p));
        assert_eq!(f.len(), 1);
        assert!(f[0].deviation().detail.contains("unreadable"));
    }

    #[test]
    fn pending_restart_file_reads_only_gated_units() {
        let d = std::env::temp_dir().join(format!("robodr-pr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("pending-restart");
        assert_eq!(pending_restart(&f, 0), None);
        std::fs::write(&f, "robodr-agentd.service\n").unwrap();
        assert_eq!(
            pending_restart(&f, 0),
            None,
            "no gated unit: nothing pending"
        );
        std::fs::write(
            &f,
            "robodr-firewall-gw.service\nrobodr-executor.service\nrobodr-firewall-gw.service\n",
        )
        .unwrap();
        let p = pending_restart(&f, u64::MAX).unwrap();
        assert_eq!(
            p.units,
            ["robodr-executor.service", "robodr-firewall-gw.service"]
        );
        assert!(p.age_ms.is_some() && p.read_error.is_none());
        std::fs::remove_file(&f).unwrap();
        std::fs::create_dir(&f).unwrap();
        let p = pending_restart(&f, 0).unwrap();
        assert!(p.units.is_empty() && p.read_error.is_some());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn days_round_down_and_go_negative() {
        let now = 1_800_000_000_000;
        assert_eq!(days_to_expiry(now + DAY_MS * 14, now), 14);
        assert_eq!(days_to_expiry(now + DAY_MS * 14 - 1, now), 13);
        assert_eq!(days_to_expiry(now, now), 0);
        assert_eq!(days_to_expiry(now - 1, now), -1);
        assert_eq!(days_to_expiry(0, u64::MAX), -213_503_982_335);
        let c = credential("x", 1_800_000_000 + 3 * 86_400, now);
        assert_eq!((c.expires_ms, c.days_to_expiry), (now + 3 * DAY_MS, 3));
        assert_eq!(credential("x", -5, now).expires_ms, 0);
    }

    /// T6: Medium at 14 days, High at 3 days (and expired), once per
    /// escalation, then daily; renewal re-arms.
    #[test]
    fn credential_expiry_escalates_and_repeats_daily() {
        let mut w = w();
        assert!(w.credentials(0, &[cred("cert", 30)]).is_empty());
        let r = w.credentials(1, &[cred("cert", 13)]);
        assert_eq!(
            r,
            vec![Warning::CredentialExpiring {
                name: "cert".into(),
                days: 13,
                level: Level::Warn
            }]
        );
        assert_eq!(r[0].deviation().severity, Severity::Medium);
        assert!(
            w.credentials(2, &[cred("cert", 12)]).is_empty(),
            "same level"
        );
        let r = w.credentials(3, &[cred("cert", 2)]);
        assert_eq!(r[0].deviation().severity, Severity::High);
        assert!(w.credentials(4, &[cred("cert", 2)]).is_empty());
        let r = w.credentials(3 + DAY_MS, &[cred("cert", 1)]);
        assert_eq!(r.len(), 1, "daily reminder");
        let r = w.credentials(3 + 2 * DAY_MS, &[cred("cert", -1)]);
        assert!(r[0].deviation().detail.contains("expired 1 day(s) ago"));
        // Renewed: quiet, and a later approach warns again.
        assert!(w.credentials(5 * DAY_MS, &[cred("cert", 365)]).is_empty());
        assert_eq!(w.credentials(6 * DAY_MS, &[cred("cert", 10)]).len(), 1);
        // Exactly the configured day counts.
        let mut w = Warnings::new(SelfHealthSection::default(), 10_000);
        assert!(w.credentials(0, &[cred("a", 15)]).is_empty());
        let level = |r: Vec<Warning>| match r.first() {
            Some(Warning::CredentialExpiring { level, .. }) => *level,
            _ => Level::Ok,
        };
        assert_eq!(level(w.credentials(0, &[cred("b", 14)])), Level::Warn);
        assert_eq!(level(w.credentials(0, &[cred("c", 4)])), Level::Warn);
        assert_eq!(level(w.credentials(0, &[cred("d", 3)])), Level::Critical);
    }

    /// T7: unsynchronised only after the grace period, once per episode;
    /// wall jumps are reported as they come, rate-limited.
    #[test]
    fn clock_unsynced_after_grace_and_jumps() {
        let mut w = w();
        let unsync = Some(KernelClock {
            synchronized: false,
            max_error_us: 16_000_000,
        });
        let sync = Some(KernelClock {
            synchronized: true,
            max_error_us: 5_000,
        });
        assert!(w.clock(0, unsync, 0).is_empty());
        assert!(w.clock(299_999, unsync, 0).is_empty());
        let r = w.clock(300_000, unsync, 0);
        assert_eq!(
            r,
            vec![Warning::ClockUnsynced {
                for_ms: 300_000,
                max_error_us: 16_000_000
            }]
        );
        assert!(r[0].deviation().detail.contains("16000 ms"));
        assert!(w.clock(900_000, unsync, 0).is_empty(), "once per episode");
        assert!(w.clock(900_001, sync, 0).is_empty());
        assert!(w.clock(900_002, unsync, 0).is_empty(), "grace again");
        assert_eq!(w.clock(1_200_002, unsync, 0).len(), 1);
        // Unknown platform: nothing.
        let mut w2 = Warnings::new(SelfHealthSection::default(), 10_000);
        assert!(w2.clock(10_000_000, None, 0).is_empty());

        let r = w2.clock(10_000_000, None, 1);
        assert_eq!(r, vec![Warning::ClockJump { jumps: 1, new: 1 }]);
        assert_eq!(r[0].deviation().severity, Severity::High);
        assert!(w2.clock(10_000_001, None, 3).is_empty(), "rate-limited");
        assert_eq!(
            w2.clock(10_010_001, None, 3),
            vec![Warning::ClockJump { jumps: 3, new: 2 }]
        );
        assert!(w2.clock(10_100_000, None, 3).is_empty());
    }

    /// T40: Medium below 10 % free, High below 3 %, per escalation.
    #[test]
    fn disk_low_escalates_and_rearms() {
        let mut w = w();
        let d = |free: u64| {
            vec![DiskHealth {
                name: "spool".into(),
                free_bytes: free,
                total_bytes: 1000,
            }]
        };
        assert!(w.disks(&d(100)).is_empty(), "exactly 10 % is not below");
        let r = w.disks(&d(99));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].deviation().severity, Severity::Medium);
        assert!(r[0]
            .deviation()
            .detail
            .contains("99 of 1000 bytes free (9%)"));
        assert!(w.disks(&d(50)).is_empty());
        let r = w.disks(&d(29));
        assert_eq!(r[0].deviation().severity, Severity::High);
        assert!(w.disks(&d(10)).is_empty());
        assert!(w.disks(&d(500)).is_empty());
        assert_eq!(w.disks(&d(20)).len(), 1, "re-armed");
        // An unreadable / zero-size filesystem says nothing.
        assert!(w
            .disks(&[DiskHealth {
                name: "x".into(),
                free_bytes: 0,
                total_bytes: 0
            }])
            .is_empty());
        // Huge filesystems do not overflow.
        assert_eq!(
            disk_level(u64::MAX / 20, u64::MAX, &SelfHealthSection::default()),
            Level::Warn
        );
    }

    /// T41: once per outage after the threshold; recovery re-arms.
    #[test]
    fn executor_unreachable_once_per_outage() {
        let mut w = w();
        assert!(w.executor(None, None).is_empty());
        assert!(w.executor(Some(29_999), Some("refused")).is_empty());
        let r = w.executor(Some(30_000), Some("connection refused"));
        assert_eq!(r.len(), 1);
        let d = r[0].deviation();
        assert_eq!(d.rule_str(), rules::EXECUTOR_UNREACHABLE);
        assert_eq!(d.severity, Severity::High);
        assert!(d.detail.contains("30 s (last error: connection refused)"));
        assert!(w.executor(Some(90_000), None).is_empty());
        assert!(w.executor(None, None).is_empty());
        assert_eq!(w.executor(Some(31_000), None).len(), 1);
    }

    #[test]
    fn rule_ids_are_catalogued_in_contract_2_5() {
        for r in [
            rules::HEALTH,
            rules::CREDENTIAL_EXPIRING,
            rules::CLOCK_UNSYNCED,
            rules::CLOCK_JUMP,
            rules::DISK_LOW,
            rules::EXECUTOR_UNREACHABLE,
            rules::RESTART_PENDING,
        ] {
            assert!(robodr_ocsf::builder::rule_known(r), "{r}");
            assert_eq!(robodr_ocsf::rule_info(r).data_source, "robodr_agent");
        }
    }

    #[test]
    fn probes_read_this_machine() {
        let (free, total) = fs_space(Path::new("/")).expect("statvfs /");
        assert!(total > 0 && free <= total);
        assert!(fs_space(Path::new("/nonexistent/robodr")).is_none());
        // adjtimex(2) with modes = 0 works unprivileged on Linux (outside a
        // seccomp filter: the test runner has none).
        let k = kernel_clock().expect("adjtimex");
        assert!(k.max_error_us <= 16_000_000 || !k.synchronized);
        let dir = std::env::temp_dir().join(format!("robodr-selfcheck-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let marker = dir.join("synchronized");
        std::fs::write(&marker, b"").expect("marker");
        let now_ms = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("after 1970")
                .as_millis(),
        )
        .expect("ms");
        let age = file_age_ms(&marker, now_ms + 5_000).expect("age");
        assert!((5_000..60_000).contains(&age), "{age}");
        assert_eq!(file_age_ms(&marker, 0), Some(0), "future mtime reads 0");
        assert_eq!(file_age_ms(&dir.join("absent"), now_ms), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Several inputs of one component: the worst one is reported, with
    /// its own age (before: the last input's state and the first one's
    /// age, so a dead input could hide behind a live one).
    #[test]
    fn reachability_reports_the_worst_input_with_its_age() {
        use robodr_ocsf::ReachState as R;
        let silence = 1_000;
        let now = 10_000;
        assert_eq!(
            inputs_reachability([], now, silence),
            (R::NotConfigured, None)
        );
        let live = (false, Some(9_900));
        let dead = (false, Some(2_000));
        let ended = (true, Some(9_950));
        for set in [vec![dead, live], vec![live, dead]] {
            assert_eq!(
                inputs_reachability(set, now, silence),
                (R::Unreachable, Some(8_000))
            );
        }
        assert_eq!(
            inputs_reachability([live, ended], now, silence),
            (R::Unreachable, Some(50))
        );
        assert_eq!(
            inputs_reachability([live, (false, Some(9_990))], now, silence),
            (R::Reachable, Some(100))
        );
        // Not heard yet: unknown during the first silence window.
        assert_eq!(
            inputs_reachability([(false, None), (false, Some(500))], 800, silence),
            (R::Unknown, None)
        );
        assert_eq!(
            inputs_reachability([(false, None)], now, silence),
            (R::Unreachable, None)
        );
    }

    /// Under the shipped unit `adjtimex(2)` fails with EPERM (seccomp
    /// `@clock`): the record must say so instead of looking like a platform
    /// without a clock probe, and a fresh timesyncd marker still reports
    /// the clock synchronised.
    #[test]
    fn clock_probe_refused_is_reported_and_timesyncd_fallback() {
        use robodr_ocsf::{ClockHealth, ClockSource};
        let eperm = Err(ClockProbeError::Errno(1));
        assert_eq!(
            clock_health(eperm, None, 2),
            ClockHealth {
                adjtimex_errno: Some(1),
                wall_jumps: 2,
                ..ClockHealth::default()
            }
        );
        let fresh = clock_health(eperm, Some(TIMESYNC_FRESH_MS), 0);
        assert_eq!(fresh.synchronized, Some(true));
        assert_eq!(fresh.source, Some(ClockSource::Timesyncd));
        assert_eq!(fresh.max_error_ms, None);
        assert_eq!(fresh.adjtimex_errno, Some(1));
        // A stale marker is not evidence either way.
        let stale = clock_health(eperm, Some(TIMESYNC_FRESH_MS + 1), 0);
        assert_eq!((stale.synchronized, stale.source), (None, None));
        assert_eq!(stale.timesync_age_ms, Some(TIMESYNC_FRESH_MS + 1));
        // No adjtimex on the platform: no errno.
        let none = clock_health(Err(ClockProbeError::Unsupported), None, 0);
        assert_eq!(none, ClockHealth::default());
        // adjtimex wins over the marker, unsynchronised included.
        let k = KernelClock {
            synchronized: false,
            max_error_us: 16_000_000,
        };
        let h = clock_health(Ok(k), Some(10), 0);
        assert_eq!(h.synchronized, Some(false));
        assert_eq!(h.max_error_ms, Some(16_000));
        assert_eq!(h.source, Some(ClockSource::Adjtimex));
        assert_eq!(h.adjtimex_errno, None);
        let json = serde_json::to_value(clock_health(eperm, None, 0)).expect("json");
        assert_eq!(
            json,
            serde_json::json!({"adjtimex_errno": 1, "wall_jumps": 0})
        );
    }
}
