//! Decision summaries for agentd's signed black box (sales-readiness T19,
//! GAP-24): per-sample verdicts stay in the gateway (status file, events
//! file), but what the gateway enforced and how it decided is recorded
//! where it cannot be rewritten afterwards. Over the findings feed
//! (`crate::feed`, agentd's `gateway_feed` socket: a local unix socket whose
//! peer agentd checks by uid) the gateway writes one line
//!
//! ```json
//! {"format":"robodr-gateway-summary/v1","event":"interval","mode":"enforce",
//!  "on_gateway_down":"fail_closed","config_sha256":"sha256:...",
//!  "firewall_sha256":"sha256:...","profile_sha256":"sha256:...",
//!  "interval_ms":60000,"counters":{"packets":...},"firewall_faults":0,
//!  "restriction":null}
//! ```
//!
//! at start (`event: start`, counters zero), every [`INTERVAL`]
//! (`interval`, the counters since the previous line) and at a clean stop
//! (`stop`). agentd appends each as a black-box note (signed and chained
//! like every record; start and stop as critical notes). The digests are
//! those of the configuration, firewall and profile files as the gateway
//! read them at start (`None` when not known, e.g. in tests).
//!
//! Only housekeeping writes here, never the decision path.

use std::time::{Duration, Instant};

use serde::Serialize;

use crate::config::{GatewayMode, OnGatewayDown};
use crate::gateway::{Gateway, GatewayStats};

/// The line's format tag.
pub const FORMAT: &str = "robodr-gateway-summary/v1";
/// Interval between two `interval` lines.
pub const INTERVAL: Duration = Duration::from_secs(60);

/// Digests of the files the gateway started from (`sha256:<hex>`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Provenance {
    pub config_sha256: Option<String>,
    pub firewall_sha256: Option<String>,
    pub profile_sha256: Option<String>,
}

/// The decision counters of one summary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub packets: u64,
    pub accepted: u64,
    pub modified: u64,
    pub dropped: u64,
    pub samples: u64,
    pub passed: u64,
    pub limited: u64,
    pub substituted: u64,
    pub suppressed: u64,
    pub late: u64,
    pub undecidable: u64,
}

impl Counters {
    fn of(s: &GatewayStats) -> Self {
        Counters {
            packets: s.packets,
            accepted: s.accepted,
            modified: s.modified,
            dropped: s.dropped,
            samples: s.samples,
            passed: s.passed,
            limited: s.limited,
            substituted: s.substituted,
            suppressed: s.suppressed,
            late: s.late,
            undecidable: s.undecidable,
        }
    }

    fn since(self, earlier: Self) -> Self {
        Counters {
            packets: self.packets.saturating_sub(earlier.packets),
            accepted: self.accepted.saturating_sub(earlier.accepted),
            modified: self.modified.saturating_sub(earlier.modified),
            dropped: self.dropped.saturating_sub(earlier.dropped),
            samples: self.samples.saturating_sub(earlier.samples),
            passed: self.passed.saturating_sub(earlier.passed),
            limited: self.limited.saturating_sub(earlier.limited),
            substituted: self.substituted.saturating_sub(earlier.substituted),
            suppressed: self.suppressed.saturating_sub(earlier.suppressed),
            late: self.late.saturating_sub(earlier.late),
            undecidable: self.undecidable.saturating_sub(earlier.undecidable),
        }
    }
}

/// What a summary line says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    Start,
    Interval,
    Stop,
}

#[derive(Debug, Clone, Serialize)]
struct Line<'a> {
    format: &'static str,
    event: Event,
    mode: &'static str,
    on_gateway_down: &'static str,
    config_sha256: Option<&'a str>,
    firewall_sha256: Option<&'a str>,
    profile_sha256: Option<&'a str>,
    interval_ms: u64,
    counters: Counters,
    firewall_faults: u64,
    restriction: Option<&'a str>,
}

/// Builds the lines (module docs).
#[derive(Debug, Clone)]
pub struct Summarizer {
    on_gateway_down: OnGatewayDown,
    last: Counters,
    last_faults: u64,
    last_at: Instant,
    /// Lines built.
    pub lines: u64,
}

impl Summarizer {
    pub fn new(on_gateway_down: OnGatewayDown, now: Instant) -> Self {
        Summarizer {
            on_gateway_down,
            last: Counters::default(),
            last_faults: 0,
            last_at: now,
            lines: 0,
        }
    }

    /// The `interval` line when [`INTERVAL`] has passed since the last one.
    pub fn due(&mut self, gw: &Gateway, now: Instant) -> Option<String> {
        (now.saturating_duration_since(self.last_at) >= INTERVAL)
            .then(|| self.line(Event::Interval, gw, now))
            .flatten()
    }

    /// A line of `event` with the counters since the previous line.
    pub fn line(&mut self, event: Event, gw: &Gateway, now: Instant) -> Option<String> {
        let c = Counters::of(&gw.stats);
        let faults = gw.firewall().stats().faults;
        let p = &gw.provenance;
        let line = Line {
            format: FORMAT,
            event,
            mode: match gw.mode() {
                GatewayMode::Enforce => "enforce",
                GatewayMode::Observe => "observe",
            },
            on_gateway_down: match self.on_gateway_down {
                OnGatewayDown::FailClosed => "fail_closed",
                OnGatewayDown::Bypass => "bypass",
            },
            config_sha256: p.config_sha256.as_deref(),
            firewall_sha256: p.firewall_sha256.as_deref(),
            profile_sha256: p.profile_sha256.as_deref(),
            interval_ms: u64::try_from(now.saturating_duration_since(self.last_at).as_millis())
                .unwrap_or(u64::MAX),
            counters: c.since(self.last),
            firewall_faults: faults.saturating_sub(self.last_faults),
            restriction: gw.restriction().map(|r| r.id.as_str()),
        };
        let text = serde_json::to_string(&line).ok()?;
        self.last = c;
        self.last_faults = faults;
        self.last_at = now;
        self.lines = self.lines.saturating_add(1);
        Some(text)
    }
}
