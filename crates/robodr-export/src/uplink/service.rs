//! The long-running `robodr-uplink` loop: runs [`Uplink::run_once`] every
//! interval, backs off after failures, and makes a blocked queue visible.
//!
//! # Backoff between runs
//!
//! After a failed run the next one waits `backoff_delay` (exponential from
//! the poll interval, equal jitter) with a cap that depends on the failure:
//!
//! * **transient** ([`UplinkError::is_transient`]: network, `408`, `429`,
//!   `5xx` with the run's attempts exhausted): up to
//!   [`ServiceConfig::transient_backoff_max`] (default 60 s);
//! * **anything else** (`400`, `401`, `409`, `415`, a single-line `413`, a
//!   `200` that does not account for the batch, a local state or I/O
//!   error): up to [`ServiceConfig::refused_backoff_max`] (default 15 min).
//!   These need a fix somewhere (registration, clock, a server or producer
//!   bug); retrying every minute only floods the SOC's audit log (every
//!   `401` is logged there, contract §4 step 2): about 1440 entries a day
//!   at a 60 s cap, under 200 at 15 min.
//!
//! and **never less than the server's `Retry-After`** of the last attempt
//! ([`UplinkError::retry_after`], honoured up to 24 h, contract §7).
//!
//! # Observability
//!
//! The batch in flight blocks every later record (delivery is in order), so
//! a batch the server keeps refusing stops the whole queue. That must never
//! be silent:
//!
//! * `<state>/uplink-status.json` ([`STATUS_FILE`], atomically replaced
//!   after every run, mode 0640 so the service's group can read it): state (`ok`, `retrying`, `blocked`), last success,
//!   last delivery, last error (kind, HTTP status, server code, message),
//!   `stuck_since_ms` (start of the current failure streak, kept across
//!   restarts while the same batch is pending), the pending batch id, its
//!   line count and failed runs, the backlog, the next attempt time, the
//!   delivery totals and `credentials` (each CRL's `nextUpdate` with
//!   `days_to_expiry`; a log line once a day from
//!   [`CREDENTIAL_WARN_DAYS`] before it);
//! * `sd_notify` `STATUS=` (shown by `systemctl status robodr-uplink`; the
//!   units set `NotifyAccess=main`);
//! * a log line per failed run;
//! * optionally ([`ServiceConfig::exit_when_stuck_after`]) exit with
//!   [`EXIT_STUCK`] once failures have lasted that long in this process, so
//!   the unit enters `failed` / restarts visibly (off by default: a fixed
//!   registration then needs no restart to resume).

use super::http::Transport;
use super::{backoff_delay, RetryPolicy, Uplink, UplinkError, UplinkReport};
use crate::fsutil;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Status file in the state directory.
pub const STATUS_FILE: &str = "uplink-status.json";
/// Mode of [`STATUS_FILE`]: group-readable, so `robodr-agentd` (group
/// `robodr` in the shipped units, like this service's `Group=`) can read the
/// connectivity it carries.
pub const STATUS_FILE_MODE: u32 = 0o640;
pub const STATUS_FORMAT: &str = "robodr-uplink-status/1";
/// Exit code when failures lasted [`ServiceConfig::exit_when_stuck_after`].
pub const EXIT_STUCK: u8 = 3;

/// Loop settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceConfig {
    /// Poll interval after a successful run (and first backoff step).
    pub interval: Duration,
    /// Backoff cap after transient failures.
    pub transient_backoff_max: Duration,
    /// Backoff cap after refusals and other non-transient failures.
    pub refused_backoff_max: Duration,
    /// Exit with [`EXIT_STUCK`] once failures have lasted this long in this
    /// process (`None`: never).
    pub exit_when_stuck_after: Option<Duration>,
    /// One run, then exit (0 ok, 1 failed).
    pub once: bool,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(2),
            transient_backoff_max: Duration::from_secs(60),
            refused_backoff_max: Duration::from_secs(900),
            exit_when_stuck_after: None,
            once: false,
        }
    }
}

/// The last failure, as the status file shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusError {
    pub at_ms: u64,
    /// [`UplinkError::kind`].
    pub kind: String,
    /// HTTP status of a refusal.
    pub status: Option<u16>,
    /// Server code of a refusal.
    pub code: Option<String>,
    pub message: String,
    /// The server's `Retry-After` (seconds, as honoured).
    pub retry_after_s: Option<u64>,
}

/// Records not yet acknowledged.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Backlog {
    /// Spool input: records in `ready/`.
    pub spool_ready: Option<u64>,
    /// Diode input: batch directories not finished.
    pub diode_batches: Option<u64>,
    /// Re-injected generations not finished.
    pub reinject_generations: u64,
}

/// What a run leaves for the status file ([`Uplink::snapshot`]).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub pending_batch_id: Option<String>,
    pub pending_source: Option<String>,
    pub pending_lines: u64,
    pub backlog: Backlog,
    pub sent_lines_total: u64,
    pub accepted_total: u64,
    pub rejected_total: u64,
    pub dead_lettered_total: u64,
    /// What the state occupies on disk (`done/`, dead letters, `out/` or
    /// `rejected/`, re-injection generations), measured at most every
    /// [`super::UplinkConfig::usage_interval`] (the last good
    /// measurement; `measured_at_ms` says when).
    #[serde(default)]
    pub state_usage: Option<crate::retention::StateUsage>,
    /// The last measurement failed (monitoring only; retried after the
    /// interval).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_usage_error: Option<String>,
    /// The last pruning of `out/` (`--out-max-*`) failed, with the path and
    /// what to do; delivery goes on, that payload stays.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub out_prune_error: Option<String>,
}

/// `<state>/uplink-status.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub format: String,
    /// `ok`, `retrying` (transient failures) or `blocked` (refused or
    /// otherwise failing until something is fixed).
    pub state: String,
    pub updated_at_ms: u64,
    pub pid: u32,
    /// End of the last run that completed.
    pub last_success_at_ms: Option<u64>,
    /// End of the last run that acknowledged at least one batch.
    pub last_delivery_at_ms: Option<u64>,
    pub last_error: Option<StatusError>,
    /// Failed runs in a row (this process).
    pub consecutive_failures: u64,
    /// Start of the current failure streak (kept across restarts while the
    /// same batch is pending); `None` when the last run succeeded.
    pub stuck_since_ms: Option<u64>,
    /// Failed runs while the current pending batch was pending (kept across
    /// restarts).
    pub pending_failed_runs: u64,
    pub next_attempt_at_ms: Option<u64>,
    pub dead_letter_malformed: u64,
    /// Spool files quarantined as unreadable (I/O error) by this process.
    #[serde(default)]
    pub quarantined_unreadable: u64,
    /// Expiry of the credentials the uplink depends on, as of the last
    /// run: each CRL in use (`--crl-file`) as `crl:<issuer>` with its
    /// `nextUpdate` (past it every connection is refused). Empty without
    /// CRLs.
    #[serde(default)]
    pub credentials: Vec<robodr_ocsf::CredentialExpiry>,
    #[serde(flatten)]
    pub snapshot: Snapshot,
}

impl Status {
    fn new(now: u64) -> Self {
        Self {
            format: STATUS_FORMAT.into(),
            state: "starting".into(),
            updated_at_ms: now,
            pid: std::process::id(),
            last_success_at_ms: None,
            last_delivery_at_ms: None,
            last_error: None,
            consecutive_failures: 0,
            stuck_since_ms: None,
            pending_failed_runs: 0,
            next_attempt_at_ms: None,
            dead_letter_malformed: 0,
            quarantined_unreadable: 0,
            credentials: Vec::new(),
            snapshot: Snapshot::default(),
        }
    }

    /// The previous status (to carry the failure streak across a restart),
    /// or a fresh one.
    pub fn load_or_new(state_dir: &Path, now: u64) -> Self {
        let prev = fsutil::read_capped(&state_dir.join(STATUS_FILE), 1024 * 1024)
            .ok()
            .and_then(|b| serde_json::from_slice::<Status>(&b).ok())
            .filter(|s| s.format == STATUS_FORMAT);
        let mut s = Self::new(now);
        if let Some(p) = prev {
            s.last_success_at_ms = p.last_success_at_ms;
            s.last_delivery_at_ms = p.last_delivery_at_ms;
            s.last_error = p.last_error;
            s.stuck_since_ms = p.stuck_since_ms;
            s.pending_failed_runs = p.pending_failed_runs;
            s.snapshot = p.snapshot;
        }
        s
    }

    fn apply_snapshot(&mut self, snap: Snapshot) {
        if snap.pending_batch_id != self.snapshot.pending_batch_id {
            self.pending_failed_runs = 0;
        }
        self.snapshot = snap;
    }

    /// A one-line summary for `sd_notify` `STATUS=` and logs.
    pub fn summary(&self, now: u64) -> String {
        let backlog = match (
            self.snapshot.backlog.spool_ready,
            self.snapshot.backlog.diode_batches,
        ) {
            (Some(n), _) => format!("{n} spool record(s)"),
            (None, Some(n)) => format!("{n} diode batch(es)"),
            (None, None) => "unknown".into(),
        };
        let next = self
            .next_attempt_at_ms
            .map(|t| format!("; next attempt in {} s", t.saturating_sub(now) / 1000))
            .unwrap_or_default();
        match (&self.last_error, self.state.as_str()) {
            (Some(e), "retrying" | "blocked") => {
                let since = self
                    .stuck_since_ms
                    .map(|t| format!(" for {} s", now.saturating_sub(t) / 1000))
                    .unwrap_or_default();
                let what = match (e.status, &e.code) {
                    (Some(st), Some(c)) if !c.is_empty() => format!("HTTP {st} {c}"),
                    (Some(st), _) => format!("HTTP {st}"),
                    _ => e.kind.clone(),
                };
                let batch = self
                    .snapshot
                    .pending_batch_id
                    .as_deref()
                    .map(|b| format!("; batch {b}"))
                    .unwrap_or_default();
                format!(
                    "{}{since}: {what}{batch}; backlog {backlog}{next}",
                    self.state
                )
            }
            _ => format!("{}: backlog {backlog}{next}", self.state),
        }
    }
}

/// Side effects of the loop (replaced in tests).
pub struct Env<'a> {
    /// Wall clock, ms since the epoch.
    pub now_ms: Box<dyn FnMut() -> u64 + 'a>,
    pub sleep: Box<dyn FnMut(Duration) + 'a>,
    pub rng: Box<dyn FnMut() -> u64 + 'a>,
    /// `sd_notify` message (`STATUS=...`).
    pub notify: Box<dyn FnMut(&str) + 'a>,
    pub log: Box<dyn FnMut(&str) + 'a>,
    /// A run's report (non-empty ones).
    pub report: Box<dyn FnMut(&UplinkReport) + 'a>,
    /// Checked after each sleep: `true` ends the loop with exit code 0
    /// (tests).
    pub stop: Box<dyn FnMut() -> bool + 'a>,
    /// The credentials' expiry at a wall-clock time ([`Status::credentials`]).
    pub credentials: Box<dyn FnMut(u64) -> Vec<robodr_ocsf::CredentialExpiry> + 'a>,
}

/// The expiry of each CRL in use (`crl:<issuer>`, its `nextUpdate`) at
/// `now_ms`; a CRL without `nextUpdate` has none.
pub fn crl_credentials(
    s: &robodr_blackbox::crl::CrlStatus,
    now_ms: u64,
) -> Vec<robodr_ocsf::CredentialExpiry> {
    s.in_use
        .iter()
        .filter_map(|u| {
            u.next_update.map(|nu| {
                robodr_ocsf::CredentialExpiry::at(&format!("crl:{}", u.issuer), nu, now_ms)
            })
        })
        .collect()
}

/// A credential this close to expiry (whole days) is logged once a day
/// (the same default as agentd's `credential_warn_days`).
pub const CREDENTIAL_WARN_DAYS: i64 = 14;

/// Log each credential within [`CREDENTIAL_WARN_DAYS`] once per day count
/// (`logged`: the day count last logged per name).
fn warn_expiring(
    creds: &[robodr_ocsf::CredentialExpiry],
    logged: &mut std::collections::BTreeMap<String, i64>,
    log: &mut dyn FnMut(&str),
) {
    for c in creds {
        if c.days_to_expiry > CREDENTIAL_WARN_DAYS {
            logged.remove(&c.name);
            continue;
        }
        if logged.get(&c.name) == Some(&c.days_to_expiry) {
            continue;
        }
        logged.insert(c.name.clone(), c.days_to_expiry);
        log(&if c.days_to_expiry < 0 {
            format!(
                "{} expired {} day(s) ago: install a fresh one (every connection is refused)",
                c.name,
                c.days_to_expiry.unsigned_abs()
            )
        } else {
            format!(
                "{} expires in {} day(s): install a fresh one before then",
                c.name, c.days_to_expiry
            )
        });
    }
}

/// The wait after `failures` failed runs in a row ending with `e`.
pub fn failure_delay(cfg: &ServiceConfig, failures: u32, e: &UplinkError, rand: u64) -> Duration {
    let cap = if e.is_transient() {
        cfg.transient_backoff_max
    } else {
        cfg.refused_backoff_max
    };
    let p = RetryPolicy {
        max_attempts: u32::MAX,
        base: cfg.interval,
        max: cap.max(cfg.interval),
    };
    let d = backoff_delay(&p, failures, rand);
    match e.retry_after() {
        Some(ra) => d.max(ra),
        None => d,
    }
}

fn write_status(state_dir: &Path, st: &Status, log: &mut dyn FnMut(&str), warned: &mut bool) {
    let res = serde_json::to_vec_pretty(st)
        .map_err(|e| std::io::Error::other(e.to_string()))
        .and_then(|b| {
            fsutil::atomic_write_mode(&state_dir.join(STATUS_FILE), &b, STATUS_FILE_MODE)
        });
    match res {
        Ok(()) => *warned = false,
        Err(e) if !*warned => {
            log(&format!("cannot write {STATUS_FILE}: {e}"));
            *warned = true;
        }
        Err(_) => {}
    }
}

/// Run the loop. `open` builds a fresh [`Uplink`] for each run (state is
/// re-read from disk after a failure); the caller holds the state
/// directory's lock for the whole loop. Returns the exit code.
pub fn run<T: Transport>(
    cfg: &ServiceConfig,
    state_dir: &Path,
    mut open: impl FnMut() -> Result<Uplink<T>, UplinkError>,
    env: &mut Env<'_>,
) -> u8 {
    let state_dir: PathBuf = state_dir.to_path_buf();
    let mut status = Status::load_or_new(&state_dir, (env.now_ms)());
    let mut failures: u32 = 0;
    let mut streak_start: Option<u64> = None;
    let mut warned = false;
    let mut cred_logged = std::collections::BTreeMap::new();
    // Carried from one run's Uplink to the next (usage measured at most
    // once per interval, a lasting pruning error logged once).
    let mut upkeep = super::Upkeep::default();
    loop {
        let (result, snap) = match open() {
            Ok(u) => {
                let mut u = u.with_upkeep(std::mem::take(&mut upkeep));
                let r = u.run_once();
                let snap = u.snapshot();
                upkeep = u.take_upkeep();
                if let Err(e) = &snap {
                    (env.log)(&format!("cannot update the status snapshot: {e}"));
                }
                (r, snap.ok())
            }
            Err(e) => (Err(e), None),
        };
        let now = (env.now_ms)();
        status.updated_at_ms = now;
        status.credentials = (env.credentials)(now);
        warn_expiring(&status.credentials, &mut cred_logged, &mut *env.log);
        if let Some(s) = snap {
            status.apply_snapshot(s);
        }
        let delay = match &result {
            Ok(rep) => {
                failures = 0;
                streak_start = None;
                status.state = "ok".into();
                status.consecutive_failures = 0;
                status.stuck_since_ms = None;
                status.pending_failed_runs = 0;
                status.last_success_at_ms = Some(now);
                if rep.batches > 0 {
                    status.last_delivery_at_ms = Some(now);
                }
                if rep.dead_letter_malformed > 0 {
                    status.dead_letter_malformed = rep.dead_letter_malformed;
                }
                status.quarantined_unreadable += rep.quarantined_unreadable;
                if !rep.is_empty() {
                    (env.report)(rep);
                }
                cfg.interval
            }
            Err(e) => {
                failures = failures.saturating_add(1);
                streak_start.get_or_insert(now);
                status.state = if e.is_transient() {
                    "retrying"
                } else {
                    "blocked"
                }
                .into();
                status.consecutive_failures = u64::from(failures);
                status.stuck_since_ms.get_or_insert(now);
                status.pending_failed_runs += 1;
                status.last_error = Some(StatusError {
                    at_ms: now,
                    kind: e.kind().into(),
                    status: e.refusal().map(|(s, _)| s),
                    code: e.refusal().map(|(_, c)| c.to_string()),
                    message: e.to_string(),
                    retry_after_s: e.retry_after().map(|d| d.as_secs()),
                });
                (env.log)(&e.to_string());
                failure_delay(cfg, failures, e, (env.rng)())
            }
        };
        if cfg.once {
            status.next_attempt_at_ms = None;
            write_status(&state_dir, &status, &mut *env.log, &mut warned);
            (env.notify)(&format!("STATUS={}", status.summary(now)));
            return if result.is_ok() { 0 } else { 1 };
        }
        status.next_attempt_at_ms = Some(now.saturating_add(delay.as_millis() as u64));
        write_status(&state_dir, &status, &mut *env.log, &mut warned);
        let summary = status.summary(now);
        (env.notify)(&format!("STATUS={summary}"));
        if result.is_err() {
            (env.log)(&summary);
        }
        if let (Some(limit), Some(start)) = (cfg.exit_when_stuck_after, streak_start) {
            if now.saturating_sub(start) >= limit.as_millis() as u64 {
                (env.log)(&format!(
                    "failing for {} s (--exit-when-stuck-s {}): exiting with status {EXIT_STUCK}",
                    now.saturating_sub(start) / 1000,
                    limit.as_secs()
                ));
                return EXIT_STUCK;
            }
        }
        (env.sleep)(delay);
        if (env.stop)() {
            return 0;
        }
    }
}
