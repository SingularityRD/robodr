//! Discovery-flood aggregation (red team F1).
//!
//! # The problem
//!
//! Every new GUID prefix on the bus is a distinct, true finding
//! (`robot.ros2.unknown_participant`, and usually
//! `robot.ros2.identity_instances_exceeded`), each with its own finding id.
//! The pipeline's dedup and rate limiter cannot bound that (each one is
//! different; see `robodr_ros2_pipeline::pipeline`, "Known limits":
//! "Downstream consumers should aggregate"). The red team sprayed 3000 SPDP
//! announcements with random prefixes: about 5000 spool records, each a
//! separate SOC case; about 10 000 fill the default 64 MiB spool, after
//! which every new finding, legitimate ones included, was in the black box
//! only.
//!
//! # What this module does
//!
//! agentd passes every pipeline finding through [`FloodGuard::admit`]
//! before the agent. Only the per-participant discovery rules
//! ([`FOLDABLE_RULES`]) below Critical take part; everything else, and
//! every Critical finding, always goes through one by one.
//!
//! - Per source IP, the first [`PER_SOURCE`] foldable findings of a window
//!   ([`WINDOW`], 60 s) are reported one by one, and at most
//!   [`PER_WINDOW`] of all sources together.
//! - Past either threshold the source is **flooding**: its foldable
//!   findings are folded into one aggregate per source, reported as
//!   [`FLOOD_RULE`] (`robot.ros2.discovery_flood`, the most severe folded
//!   severity, at least Medium) with the folded count per rule, first and
//!   last seen (wall clock) and up to [`MAX_SAMPLES`] sample GUID prefixes.
//!   The aggregate is reported when its count reaches 1, 2, 4, 8, ... and
//!   once more when the flood ends (a full window without a folded finding
//!   from the source) or agentd stops: O(log n) records for n folded
//!   findings. Its subject is the source IP, so every report has the same
//!   finding id: one SOC case, updated (`count`, `last_seen_time`).
//! - While a source's flood is open, all its foldable findings are folded
//!   (a slow spray cannot leak [`PER_SOURCE`] findings a minute).
//! - A source that passed its own share gets its own aggregate (at most
//!   [`MAX_KEYS`] of them); a source folded only because all sources
//!   together passed [`PER_WINDOW`] (a spoofed-source spray: a new address
//!   per packet), or one beyond [`MAX_KEYS`], goes to one shared "many
//!   sources" aggregate (no source IP). The per-window counters track at
//!   most [`MAX_SOURCES`] sources (more count as flooding).
//! - **Every folded finding is still recorded** in the black box as the
//!   same deviation record the agent writes for a reported one
//!   (`robodr_agent::Agent::record_deviation`), and still feeds the
//!   correlation engine. Only the response plan, the finding and the
//!   spool record are replaced by the aggregate.
//!
//! # Limits (be honest)
//!
//! - A genuine unknown participant announced from a flooding source (or,
//!   past [`PER_WINDOW`], from any source) is folded too: it is named only
//!   if it is among the samples, and no per-participant response is
//!   planned for it. It is in the black box, and a rogue that publishes on
//!   a motion topic still raises its Critical finding, which is never
//!   folded. The spool keeps a share for Critical findings
//!   (`crate::spool`, "Critical findings first").
//! - Source addresses are not authenticated: an attacker can make a
//!   legitimate host's address look like a flooding source for its own
//!   (non-Critical) discovery findings.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use robodr_events::{Deviation, Severity};
use serde::Serialize;

/// The aggregate's rule id.
pub const FLOOD_RULE: &str = "robot.ros2.discovery_flood";

/// Rules folded during a flood: one finding per participant (GUID prefix)
/// each.
pub const FOLDABLE_RULES: &[&str] = &[
    "robot.ros2.unknown_participant",
    "robot.ros2.identity_instances_exceeded",
    "robot.ros2.participant_source_mismatch",
    "robot.ros2.endpoint_unannounced_participant",
    "robot.ros2.participant_removed",
];

/// Counting window, and how long a flood must be quiet to end.
pub const WINDOW: Duration = Duration::from_secs(60);
/// Foldable findings of one source reported one by one per window.
pub const PER_SOURCE: u32 = 8;
/// Foldable findings of all sources reported one by one per window.
pub const PER_WINDOW: u32 = 32;
/// Sources counted per window (beyond: treated as flooding).
pub const MAX_SOURCES: usize = 1024;
/// Sources with their own aggregate (beyond: the "many sources" one).
pub const MAX_KEYS: usize = 32;
/// Sample GUID prefixes named per aggregate.
pub const MAX_SAMPLES: usize = 8;

/// Counters (in agentd's status).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct FloodStats {
    /// Findings folded into an aggregate (recorded, not reported alone).
    pub folded: u64,
    /// Aggregate reports made.
    pub reports: u64,
    /// Floods (aggregates) opened.
    pub floods: u64,
}

/// An aggregate report: hand it to the agent like a pipeline finding.
#[derive(Debug, Clone, PartialEq)]
pub struct FloodReport {
    /// The flooding source, `None` for the "many sources" aggregate.
    pub src_ip: Option<String>,
    pub deviation: Deviation,
}

/// What to do with one finding.
#[derive(Debug, Clone, PartialEq)]
pub enum Admit {
    /// Report it as usual.
    Pass,
    /// Record it only; report the aggregate, if any.
    Fold(Option<FloodReport>),
}

#[derive(Debug, Clone)]
struct Agg {
    folded: u64,
    reported_at: u64,
    by_rule: BTreeMap<&'static str, u64>,
    severity: Severity,
    first_wall_ms: u64,
    last_wall_ms: u64,
    last_ns: u64,
    samples: Vec<String>,
}

/// See the module docs. Pure: time is passed in (agentd's detection
/// clock, `mono_ns`; wall clock for the report text, `wall_ms`).
#[derive(Debug, Default)]
pub struct FloodGuard {
    window_start: Option<u64>,
    per_source: HashMap<String, u32>,
    passed: u32,
    /// Open floods; key `None` = many sources.
    aggs: BTreeMap<Option<String>, Agg>,
    stats: FloodStats,
}

fn window_ns() -> u64 {
    u64::try_from(WINDOW.as_nanos()).unwrap_or(u64::MAX)
}

/// The first GUID prefix (24 lower-case hex digits) in `detail`.
fn guid_in(detail: &str) -> Option<String> {
    let b = detail.as_bytes();
    let hex = |c: u8| c.is_ascii_digit() || (b'a'..=b'f').contains(&c);
    let mut i = 0;
    while i < b.len() {
        if b.get(i).copied().is_some_and(hex) {
            let start = i;
            while b.get(i).copied().is_some_and(hex) {
                i += 1;
            }
            if i - start == 24 {
                return detail.get(start..i).map(str::to_owned);
            }
        } else {
            i += 1;
        }
    }
    None
}

impl FloodGuard {
    pub fn stats(&self) -> FloodStats {
        self.stats
    }

    /// Open floods (aggregates not yet closed).
    pub fn open(&self) -> usize {
        self.aggs.len()
    }

    /// Decide for one pipeline finding.
    pub fn admit(&mut self, dev: &Deviation, src_ip: &str, mono_ns: u64, wall_ms: u64) -> Admit {
        let Some(rule) = FOLDABLE_RULES
            .iter()
            .copied()
            .find(|r| *r == dev.rule_str())
        else {
            return Admit::Pass;
        };
        if dev.severity >= Severity::Critical {
            return Admit::Pass;
        }
        if self
            .window_start
            .is_none_or(|s| mono_ns >= s.saturating_add(window_ns()) || mono_ns < s)
        {
            self.window_start = Some(mono_ns);
            self.per_source.clear();
            self.passed = 0;
        }
        let own = Some(src_ip.to_owned());
        let flooding = self.aggs.contains_key(&own);
        let count = self.per_source.get(src_ip).copied();
        let room = count.is_some() || self.per_source.len() < MAX_SOURCES;
        if !flooding && room && count.unwrap_or(0) < PER_SOURCE && self.passed < PER_WINDOW {
            *self.per_source.entry(src_ip.to_owned()).or_insert(0) += 1;
            self.passed += 1;
            return Admit::Pass;
        }
        // A source gets its own aggregate once it passed its own share; a
        // fresh source folded only by the all-sources cap (a spoofed-source
        // spray) goes to the "many sources" one.
        let own_flood = count.is_some_and(|c| c >= PER_SOURCE) && self.aggs.len() < MAX_KEYS;
        let key = if flooding || own_flood { own } else { None };
        self.stats.folded += 1;
        let opened = !self.aggs.contains_key(&key);
        let a = self.aggs.entry(key.clone()).or_insert_with(|| Agg {
            folded: 0,
            reported_at: 0,
            by_rule: BTreeMap::new(),
            severity: Severity::Medium,
            first_wall_ms: wall_ms,
            last_wall_ms: wall_ms,
            last_ns: mono_ns,
            samples: Vec::new(),
        });
        if opened {
            self.stats.floods += 1;
        }
        a.folded += 1;
        *a.by_rule.entry(rule).or_insert(0) += 1;
        a.severity = a.severity.max(dev.severity);
        a.first_wall_ms = a.first_wall_ms.min(wall_ms);
        a.last_wall_ms = a.last_wall_ms.max(wall_ms);
        a.last_ns = mono_ns;
        if a.samples.len() < MAX_SAMPLES {
            if let Some(g) = guid_in(&dev.detail) {
                if !a.samples.contains(&g) {
                    a.samples.push(g);
                }
            }
        }
        let report = a.folded.is_power_of_two().then(|| {
            a.reported_at = a.folded;
            report(key.as_deref(), a, false)
        });
        if report.is_some() {
            self.stats.reports += 1;
        }
        Admit::Fold(report)
    }

    /// Close the floods quiet for a full [`WINDOW`]; report those with
    /// findings folded since their last report.
    pub fn tick(&mut self, mono_ns: u64) -> Vec<FloodReport> {
        let quiet: Vec<Option<String>> = self
            .aggs
            .iter()
            .filter(|(_, a)| {
                mono_ns >= a.last_ns.saturating_add(window_ns()) || mono_ns < a.last_ns
            })
            .map(|(k, _)| k.clone())
            .collect();
        let mut out = Vec::new();
        for k in quiet {
            if let Some(a) = self.aggs.remove(&k) {
                if a.folded > a.reported_at {
                    out.push(report(k.as_deref(), &a, true));
                }
            }
        }
        self.stats.reports += out.len() as u64;
        out
    }

    /// Close every flood (agentd stops).
    pub fn flush(&mut self) -> Vec<FloodReport> {
        let mut out = Vec::new();
        for (k, a) in std::mem::take(&mut self.aggs) {
            if a.folded > a.reported_at {
                out.push(report(k.as_deref(), &a, true));
            }
        }
        self.stats.reports += out.len() as u64;
        out
    }
}

fn utc(ms: u64) -> String {
    robodr_ocsf::builder::rfc3339_ms(ms)
}

fn report(src: Option<&str>, a: &Agg, closing: bool) -> FloodReport {
    let rules = a
        .by_rule
        .iter()
        .map(|(r, n)| format!("{} x{n}", r.strip_prefix("robot.ros2.").unwrap_or(r)))
        .collect::<Vec<_>>()
        .join(", ");
    let from = match src {
        Some(ip) => format!("from {ip}"),
        None => format!("from more than {MAX_KEYS} source addresses"),
    };
    let detail = format!(
        "discovery flood {from}: {} per-participant findings folded into this one: {rules}; \
         first seen {}, last seen {}; sample GUID prefixes: {}; {}every folded finding is \
         recorded in the black box",
        a.folded,
        utc(a.first_wall_ms),
        utc(a.last_wall_ms),
        if a.samples.is_empty() {
            "none".to_string()
        } else {
            a.samples.join(", ")
        },
        if closing { "flood ended; " } else { "" },
    );
    FloodReport {
        src_ip: src.map(str::to_owned),
        deviation: Deviation::new(FLOOD_RULE, a.severity.max(Severity::Medium), detail),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000_000;

    fn unknown(i: u32) -> Deviation {
        Deviation::new(
            "robot.ros2.unknown_participant",
            Severity::High,
            format!("unknown DDS participant d1d1d1d1d1d1d1d1{i:08x} from 10.0.0.9 joined"),
        )
    }

    fn folded(a: &Admit) -> bool {
        matches!(a, Admit::Fold(_))
    }

    #[test]
    fn one_source_passes_its_share_then_folds_with_log_reports() {
        let mut g = FloodGuard::default();
        let mut passed = 0;
        let mut reports = Vec::new();
        for i in 0..1000u32 {
            match g.admit(
                &unknown(i),
                "10.0.0.9",
                u64::from(i) * 1_000_000,
                1_000 + u64::from(i),
            ) {
                Admit::Pass => passed += 1,
                Admit::Fold(r) => reports.extend(r),
            }
        }
        assert_eq!(passed, PER_SOURCE);
        // 992 folded: reports at 1, 2, 4, ..., 512.
        assert_eq!(reports.len(), 10);
        assert!(reports
            .iter()
            .all(|r| r.src_ip.as_deref() == Some("10.0.0.9")));
        let last = &reports[9].deviation;
        assert_eq!(last.rule_str(), FLOOD_RULE);
        assert_eq!(last.severity, Severity::High);
        assert!(
            last.detail.contains("512 per-participant"),
            "{}",
            last.detail
        );
        assert!(last.detail.contains("unknown_participant x512"));
        assert!(
            last.detail.contains("d1d1d1d1d1d1d1d100000008"),
            "{}",
            last.detail
        );
        // Quiet for a window: one closing report with the full count.
        assert!(g.tick(2 * S).is_empty(), "still within the window");
        let close = g.tick(100 * S);
        assert_eq!(close.len(), 1);
        assert!(close[0].deviation.detail.contains("992 per-participant"));
        assert!(close[0].deviation.detail.contains("flood ended"));
        assert_eq!(g.open(), 0);
        assert_eq!(g.stats().folded, 992);
    }

    #[test]
    fn critical_and_other_rules_are_never_folded() {
        let mut g = FloodGuard::default();
        for i in 0..100u32 {
            g.admit(&unknown(i), "10.0.0.9", 0, 0);
        }
        let crit = Deviation::new(
            "robot.ros2.unauthorized_motion_writer",
            Severity::Critical,
            "x",
        );
        assert_eq!(g.admit(&crit, "10.0.0.9", 1, 0), Admit::Pass);
        let crit_mismatch = Deviation::new(
            "robot.ros2.participant_source_mismatch",
            Severity::Critical,
            "contested",
        );
        assert_eq!(g.admit(&crit_mismatch, "10.0.0.9", 1, 0), Admit::Pass);
        let other = Deviation::new("robot.ros2.unknown_writer_topic", Severity::High, "y");
        assert_eq!(g.admit(&other, "10.0.0.9", 1, 0), Admit::Pass);
    }

    #[test]
    fn another_source_still_passes_and_a_spoofed_spray_is_bounded() {
        let mut g = FloodGuard::default();
        for i in 0..100u32 {
            g.admit(&unknown(i), "10.0.0.9", 0, 0);
        }
        // A genuine unknown participant elsewhere is reported alone.
        assert_eq!(g.admit(&unknown(7777), "10.0.0.66", 1, 0), Admit::Pass);
        // A spray from a new source address per packet: at most PER_WINDOW
        // pass in a window, the rest fold into at most MAX_KEYS + 1
        // aggregates.
        let mut g = FloodGuard::default();
        let mut passed = 0;
        let mut reports = 0;
        for i in 0..10_000u32 {
            let ip = format!("10.{}.{}.{}", i >> 16, (i >> 8) & 255, i & 255);
            match g.admit(&unknown(i), &ip, u64::from(i), 0) {
                Admit::Pass => passed += 1,
                Admit::Fold(r) => reports += usize::from(r.is_some()),
            }
        }
        assert_eq!(passed, PER_WINDOW);
        assert!(g.open() <= MAX_KEYS + 1, "{}", g.open());
        assert!(reports <= 16, "{reports}");
        assert_eq!(g.open(), 1, "one many-sources aggregate");
        let many = g.flush();
        assert_eq!(many.len(), 1);
        assert!(many[0].src_ip.is_none());
        assert!(many[0].deviation.detail.contains("9968 per-participant"));
    }

    #[test]
    fn an_open_flood_folds_a_slow_spray_too() {
        let mut g = FloodGuard::default();
        for i in 0..20u32 {
            g.admit(&unknown(i), "10.0.0.9", 0, 0);
        }
        // Next window, one a second: still folded while the flood is open.
        for i in 0..30u64 {
            let a = g.admit(&unknown(100 + i as u32), "10.0.0.9", (61 + i) * S, 0);
            assert!(folded(&a), "{i}");
        }
        // After a quiet window it ends; a new burst passes its share again.
        g.tick(200 * S);
        assert_eq!(g.open(), 0);
        assert_eq!(g.admit(&unknown(999), "10.0.0.9", 201 * S, 0), Admit::Pass);
    }

    #[test]
    fn guid_extraction() {
        assert_eq!(
            guid_in("participant 010ff3a00100c38500000000 from 10.77.10.66").as_deref(),
            Some("010ff3a00100c38500000000")
        );
        assert_eq!(guid_in("no prefix 0123 here"), None);
        assert_eq!(guid_in("too long 010ff3a00100c3850000000000"), None);
    }
}
