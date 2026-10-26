//! Discovery-flood aggregation (red team F1, and the review of its fix:
//! H3, H4, L9, L10).
//!
//! # The problem
//!
//! Every new GUID prefix on the bus is a distinct, true finding
//! (`robot.ros2.unknown_participant`, often
//! `robot.ros2.identity_instances_exceeded`, and one more per endpoint it
//! announces, e.g. a Critical `robot.ros2.unauthorized_motion_writer` for a
//! `cmd_vel` writer), each with its own finding id. The pipeline's dedup
//! and rate limiter cannot bound that (each one is different; see
//! `robodr_ros2_pipeline::pipeline`, "Known limits": "Downstream consumers
//! should aggregate"). The red team sprayed 3000 SPDP announcements with
//! random prefixes: about 5000 spool records, each a separate SOC case;
//! about 10 000 fill the default 64 MiB spool, after which every new
//! finding, legitimate ones included, was in the black box only.
//!
//! # What this module does
//!
//! agentd passes every pipeline finding through [`FloodGuard::admit`]
//! before the agent. A finding takes part when it is about **one
//! participant**: the pipeline names its GUID prefix as structured data
//! (`robodr_ros2_pipeline::Finding::participant`: every per-participant and
//! per-endpoint discovery rule, Critical ones included). Everything else
//! always goes through one by one, and so does every finding about one of
//! the robot's **own** participants (profiled or pinned: an impersonation
//! such as `participant_source_mismatch` on a pinned prefix, or a forged
//! dispose, is never folded).
//!
//! Findings are counted per source IP and per **class** (Critical, and
//! below Critical) in a window ([`WINDOW`], 60 s):
//!
//! - A source's first [`PER_SOURCE`] findings of a class in a window are
//!   reported one by one. While fewer than [`PER_WINDOW`] findings of all
//!   sources passed in the window, a newly seen source gets that share; a
//!   source first seen after that gets [`FRESH_PER_SOURCE`] (so a spray from
//!   many addresses is bounded, but a genuine rogue's first finding is still
//!   reported by name). **Only a source past its own share is folded**: a
//!   busy bus never hides another source's findings.
//! - Past its share a source is **flooding**: its findings of that class are
//!   folded into one aggregate per (source, class), reported as
//!   [`FLOOD_RULE`] (`robot.ros2.discovery_flood`): **Critical** for the
//!   Critical class, else the most severe folded severity (at least
//!   Medium). It carries the folded count per rule, first and last seen
//!   (wall clock) and up to [`MAX_SAMPLES`] sample GUID prefixes, taken from
//!   the structured prefixes only (never parsed from the detail, which
//!   carries attacker-chosen names). The aggregate is reported when its
//!   count reaches 1, 2, 4, 8, ... and once more when the flood ends (a full
//!   window without a folded finding from the source) or agentd stops:
//!   O(log n) records for n folded findings.
//! - Each flood **episode** is its own finding: its subject is the source IP
//!   plus a synthetic node name `discovery_flood/<class>/<episode start>`
//!   ([`FloodReport::episode`]), so every report of one episode updates one
//!   SOC case, and a later flood (after the first ended) opens a new case
//!   instead of reopening one the SOC may have closed.
//! - At most [`MAX_KEYS`] sources have their own aggregate, and at most
//!   [`MAX_SOURCES`] sources are counted per window. A flooding source
//!   beyond [`MAX_KEYS`], or any source beyond [`MAX_SOURCES`] (a
//!   spoofed-source spray: hundreds of addresses in a minute), goes to one
//!   "many sources" aggregate per class, which names up to [`MAX_SAMPLES`]
//!   sample source addresses as well.
//! - **Every folded finding is still recorded** in the black box as the
//!   same deviation record the agent writes for a reported one
//!   (`robodr_agent::Agent::record_deviation`), and still feeds the
//!   correlation engine. Only the response plan, the finding and the spool
//!   record are replaced by the aggregate (which itself goes through the
//!   response planner, keyed by its source).
//!
//! # Limits (be honest)
//!
//! - A genuine participant announced from a source that is already
//!   flooding (or beyond [`MAX_SOURCES`] in a window) is folded: it is named
//!   only if it is among the samples, and no per-participant response is
//!   planned for it. It is in the black box. The Critical class is folded
//!   too, past its own share per source: a rogue that hides among a
//!   sprayer's motion writers *from the sprayer's own address* is reported
//!   through the Critical aggregate, not by name.
//! - Source addresses are not authenticated: an attacker can make a
//!   legitimate host's address look like a flooding source for its own
//!   (unprotected) discovery findings. A spoofed-source spray still costs at
//!   most `PER_WINDOW + MAX_SOURCES * FRESH_PER_SOURCE` individual findings
//!   per class and window, plus the aggregates.
//! - The counters and open aggregates are in memory: after a restart a
//!   flood starts a new episode (the folded findings are in the black box).

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use robodr_events::{Deviation, Severity};
use serde::Serialize;

/// The aggregate's rule id.
pub const FLOOD_RULE: &str = "robot.ros2.discovery_flood";

/// Counting window, and how long a flood must be quiet to end.
pub const WINDOW: Duration = Duration::from_secs(60);
/// Findings of one class a source reports one by one per window.
pub const PER_SOURCE: u32 = 8;
/// Findings of all sources after which a newly seen source gets only
/// [`FRESH_PER_SOURCE`].
pub const PER_WINDOW: u32 = 32;
/// The share of a source first seen after [`PER_WINDOW`] findings passed.
pub const FRESH_PER_SOURCE: u32 = 1;
/// Sources counted per window (beyond: the "many sources" aggregate).
pub const MAX_SOURCES: usize = 128;
/// Sources with their own aggregate (beyond: the "many sources" one).
pub const MAX_KEYS: usize = 32;
/// Sample GUID prefixes (and, for "many sources", source addresses) named
/// per aggregate.
pub const MAX_SAMPLES: usize = 4;
/// The finding detail's cap (`robodr_ocsf` `caps::DETAIL`): the aggregate's
/// text is built to fit, never cut.
pub const MAX_DETAIL: usize = 400;

/// Counters (in agentd's status).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct FloodStats {
    /// Findings folded into an aggregate (recorded, not reported alone).
    pub folded: u64,
    /// Aggregate reports made.
    pub reports: u64,
    /// Floods (aggregates, i.e. episodes) opened.
    pub floods: u64,
    /// Findings never folded because they are about one of the robot's own
    /// (profiled or pinned) participants.
    pub protected_passed: u64,
}

/// An aggregate report: hand it to the agent like a pipeline finding.
#[derive(Debug, Clone, PartialEq)]
pub struct FloodReport {
    /// The flooding source, `None` for the "many sources" aggregate.
    pub src_ip: Option<String>,
    /// The episode's synthetic subject node,
    /// `discovery_flood/<critical|other>/<episode start, RFC 3339 ms>`:
    /// one finding id per episode.
    pub episode: String,
    pub deviation: Deviation,
}

/// What to do with one finding.
#[derive(Debug, Clone, PartialEq)]
pub enum Admit {
    /// Report it as usual.
    Pass,
    /// Record it only; report these aggregates (a closing report of a
    /// previous episode, and / or this one's), if any.
    Fold(Vec<FloodReport>),
}

/// One finding as [`FloodGuard::admit`] sees it.
#[derive(Debug, Clone, Copy)]
pub struct Item<'a> {
    pub deviation: &'a Deviation,
    pub src_ip: &'a str,
    /// The structured GUID prefix it is about (`None`: not a
    /// per-participant finding, never folded).
    pub participant: Option<&'a [u8; 12]>,
    /// The participant is one of the robot's own (profiled or pinned):
    /// never folded.
    pub protected: bool,
}

type Key = (Option<String>, bool);

#[derive(Debug, Clone)]
struct Agg {
    folded: u64,
    reported_at: u64,
    by_rule: BTreeMap<String, u64>,
    severity: Severity,
    first_wall_ms: u64,
    last_wall_ms: u64,
    last_ns: u64,
    samples: Vec<[u8; 12]>,
    sources: Vec<String>,
    episode: String,
}

#[derive(Debug, Clone, Copy, Default)]
struct Count {
    other: u32,
    critical: u32,
    share: u32,
}

/// See the module docs. Pure: time is passed in (agentd's detection
/// clock, `mono_ns`; wall clock for the report text, `wall_ms`).
#[derive(Debug, Default)]
pub struct FloodGuard {
    window_start: Option<u64>,
    per_source: HashMap<String, Count>,
    passed: u32,
    /// Open floods: (source, Critical class); source `None` = many sources.
    aggs: BTreeMap<Key, Agg>,
    /// Closing reports of ended episodes not handed out yet (next tick).
    closed: Vec<FloodReport>,
    stats: FloodStats,
}

fn window_ns() -> u64 {
    u64::try_from(WINDOW.as_nanos()).unwrap_or(u64::MAX)
}

fn quiet(a: &Agg, mono_ns: u64) -> bool {
    mono_ns >= a.last_ns.saturating_add(window_ns()) || mono_ns < a.last_ns
}

fn hex(p: &[u8; 12]) -> String {
    p.iter().map(|b| format!("{b:02x}")).collect()
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
    pub fn admit(&mut self, it: Item<'_>, mono_ns: u64, wall_ms: u64) -> Admit {
        let Some(participant) = it.participant else {
            return Admit::Pass;
        };
        if it.protected {
            self.stats.protected_passed += 1;
            return Admit::Pass;
        }
        let critical = it.deviation.severity >= Severity::Critical;
        if self
            .window_start
            .is_none_or(|s| mono_ns >= s.saturating_add(window_ns()) || mono_ns < s)
        {
            self.window_start = Some(mono_ns);
            self.per_source.clear();
            self.passed = 0;
        }
        let mut reports = Vec::new();
        let own: Key = (Some(it.src_ip.to_owned()), critical);
        // An episode quiet for a full window has ended: close it first.
        if self.aggs.get(&own).is_some_and(|a| quiet(a, mono_ns)) {
            if let Some(a) = self.aggs.remove(&own) {
                if a.folded > a.reported_at {
                    reports.push(report(&own, &a, true));
                }
            }
        }
        let flooding = self.aggs.contains_key(&own);
        let tracked = self.per_source.contains_key(it.src_ip);
        if !tracked && self.per_source.len() < MAX_SOURCES {
            let share = if self.passed < PER_WINDOW {
                PER_SOURCE
            } else {
                FRESH_PER_SOURCE
            };
            self.per_source.insert(
                it.src_ip.to_owned(),
                Count {
                    share,
                    ..Count::default()
                },
            );
        }
        let key: Key = match self.per_source.get_mut(it.src_ip) {
            Some(c) if !flooding => {
                let n = if critical {
                    &mut c.critical
                } else {
                    &mut c.other
                };
                if *n < c.share {
                    *n += 1;
                    self.passed = self.passed.saturating_add(1);
                    // A closing report of an ended episode: handed out at
                    // the next tick.
                    self.stats.reports += reports.len() as u64;
                    self.closed.extend(reports);
                    return Admit::Pass;
                }
                // Past its own share: its own aggregate (bounded).
                let open_own = self.aggs.keys().filter(|k| k.0.is_some()).count();
                if open_own < MAX_KEYS {
                    own
                } else {
                    (None, critical)
                }
            }
            Some(_) => own,
            // Beyond MAX_SOURCES in this window.
            None => (None, critical),
        };
        if key.0.is_none() && self.aggs.get(&key).is_some_and(|a| quiet(a, mono_ns)) {
            if let Some(a) = self.aggs.remove(&key) {
                if a.folded > a.reported_at {
                    reports.push(report(&key, &a, true));
                }
            }
        }
        self.stats.folded += 1;
        let opened = !self.aggs.contains_key(&key);
        let a = self.aggs.entry(key.clone()).or_insert_with(|| Agg {
            folded: 0,
            reported_at: 0,
            by_rule: BTreeMap::new(),
            severity: if critical {
                Severity::Critical
            } else {
                Severity::Medium
            },
            first_wall_ms: wall_ms,
            last_wall_ms: wall_ms,
            last_ns: mono_ns,
            samples: Vec::new(),
            sources: Vec::new(),
            episode: format!(
                "discovery_flood/{}/{}",
                if critical { "critical" } else { "other" },
                utc(wall_ms)
            ),
        });
        if opened {
            self.stats.floods += 1;
        }
        a.folded += 1;
        let rule = it.deviation.rule_str();
        let rule = rule.strip_prefix("robot.ros2.").unwrap_or(rule);
        if a.by_rule.len() < 16 || a.by_rule.contains_key(rule) {
            *a.by_rule.entry(rule.to_owned()).or_insert(0) += 1;
        }
        a.severity = a.severity.max(it.deviation.severity);
        a.first_wall_ms = a.first_wall_ms.min(wall_ms);
        a.last_wall_ms = a.last_wall_ms.max(wall_ms);
        a.last_ns = mono_ns;
        if a.samples.len() < MAX_SAMPLES && !a.samples.contains(participant) {
            a.samples.push(*participant);
        }
        if key.0.is_none()
            && a.sources.len() < MAX_SAMPLES
            && !a.sources.iter().any(|s| s == it.src_ip)
        {
            a.sources.push(it.src_ip.to_owned());
        }
        if a.folded.is_power_of_two() {
            a.reported_at = a.folded;
            reports.push(report(&key, a, false));
        }
        self.stats.reports += reports.len() as u64;
        Admit::Fold(reports)
    }

    /// Close the floods quiet for a full [`WINDOW`]; report those with
    /// findings folded since their last report.
    pub fn tick(&mut self, mono_ns: u64) -> Vec<FloodReport> {
        let quiet_keys: Vec<Key> = self
            .aggs
            .iter()
            .filter(|(_, a)| quiet(a, mono_ns))
            .map(|(k, _)| k.clone())
            .collect();
        let mut out = std::mem::take(&mut self.closed);
        let mut n = 0;
        for k in quiet_keys {
            if let Some(a) = self.aggs.remove(&k) {
                if a.folded > a.reported_at {
                    out.push(report(&k, &a, true));
                    n += 1;
                }
            }
        }
        self.stats.reports += n;
        out
    }

    /// Close every flood (agentd stops).
    pub fn flush(&mut self) -> Vec<FloodReport> {
        let mut out = std::mem::take(&mut self.closed);
        for (k, a) in std::mem::take(&mut self.aggs) {
            if a.folded > a.reported_at {
                out.push(report(&k, &a, true));
                self.stats.reports += 1;
            }
        }
        out
    }
}

fn utc(ms: u64) -> String {
    robodr_ocsf::builder::rfc3339_ms(ms)
}

/// The aggregate's detail, built to fit [`MAX_DETAIL`]: samples are dropped
/// (last first) before anything else, then the per-rule list is shortened;
/// the closing sentence is always there.
fn report(key: &Key, a: &Agg, closing: bool) -> FloodReport {
    let severity = if key.1 {
        Severity::Critical
    } else {
        a.severity.max(Severity::Medium)
    };
    let from = match &key.0 {
        Some(ip) => format!("from {ip}"),
        None => format!(
            "from many source addresses (sample sources: {})",
            a.sources.join(", ")
        ),
    };
    let tail = format!(
        "{}every folded finding is recorded in the black box",
        if closing { "flood ended; " } else { "" }
    );
    let all_rules: Vec<String> = a.by_rule.iter().map(|(r, n)| format!("{r} x{n}")).collect();
    let compose = |rules: &[String], samples: &[[u8; 12]]| {
        format!(
            "{}discovery flood {from}: {} per-participant findings folded into this one: {}; \
             first seen {}, last seen {}; sample GUID prefixes: {}; {tail}",
            if key.1 { "Critical " } else { "" },
            a.folded,
            rules.join(", "),
            utc(a.first_wall_ms),
            utc(a.last_wall_ms),
            if samples.is_empty() {
                "none".to_string()
            } else {
                samples.iter().map(hex).collect::<Vec<_>>().join(", ")
            },
        )
    };
    let fits = |d: &String| d.chars().count() <= MAX_DETAIL;
    let mut detail = None;
    // Fewer samples first, then fewer rules named.
    'outer: for keep_rules in (1..=all_rules.len().max(1)).rev() {
        let mut rules: Vec<String> = all_rules.iter().take(keep_rules).cloned().collect();
        if keep_rules < all_rules.len() {
            rules.push(format!("+{} more rules", all_rules.len() - keep_rules));
        }
        for n in (0..=a.samples.len()).rev() {
            let d = compose(&rules, &a.samples[..n]);
            if fits(&d) {
                detail = Some(d);
                break 'outer;
            }
        }
    }
    let detail = detail.unwrap_or_else(|| {
        format!(
            "discovery flood: {} per-participant findings folded; {tail}",
            a.folded
        )
    });
    FloodReport {
        src_ip: key.0.clone(),
        episode: a.episode.clone(),
        deviation: Deviation::new(FLOOD_RULE, severity, detail),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000_000;

    fn g(i: u32) -> [u8; 12] {
        let mut p = [0xd1; 12];
        p[8..].copy_from_slice(&i.to_be_bytes());
        p
    }

    fn unknown(i: u32) -> Deviation {
        Deviation::new(
            "robot.ros2.unknown_participant",
            Severity::High,
            format!(
                "unknown DDS participant {} from 10.0.0.9 joined",
                hex(&g(i))
            ),
        )
    }

    fn writer(i: u32) -> Deviation {
        Deviation::new(
            "robot.ros2.unauthorized_motion_writer",
            Severity::Critical,
            format!("writer on rt/cmd_vel of {}", hex(&g(i))),
        )
    }

    fn admit(f: &mut FloodGuard, d: &Deviation, ip: &str, p: [u8; 12], ns: u64) -> Admit {
        f.admit(
            Item {
                deviation: d,
                src_ip: ip,
                participant: Some(&p),
                protected: false,
            },
            ns,
            1_000 + ns / 1_000_000,
        )
    }

    fn reports(a: Admit) -> Vec<FloodReport> {
        match a {
            Admit::Pass => Vec::new(),
            Admit::Fold(r) => r,
        }
    }

    #[test]
    fn one_source_passes_its_share_then_folds_with_log_reports() {
        let mut f = FloodGuard::default();
        let mut passed = 0;
        let mut out = Vec::new();
        for i in 0..1000u32 {
            match admit(
                &mut f,
                &unknown(i),
                "10.0.0.9",
                g(i),
                u64::from(i) * 1_000_000,
            ) {
                Admit::Pass => passed += 1,
                Admit::Fold(r) => out.extend(r),
            }
        }
        assert_eq!(passed, PER_SOURCE);
        assert_eq!(out.len(), 10, "reports at 1, 2, 4, ..., 512");
        let last = &out[9];
        assert_eq!(last.src_ip.as_deref(), Some("10.0.0.9"));
        assert_eq!(last.deviation.rule_str(), FLOOD_RULE);
        assert_eq!(last.deviation.severity, Severity::High);
        let d = &last.deviation.detail;
        assert!(d.contains("512 per-participant") && d.contains("unknown_participant x512"));
        assert!(d.contains(&hex(&g(8))), "{d}");
        assert!(d.chars().count() <= MAX_DETAIL);
        assert!(out.iter().all(|r| r.episode == out[0].episode));
        assert!(f.tick(2 * S).is_empty(), "still within the window");
        let close = f.tick(100 * S);
        assert_eq!(close.len(), 1);
        assert!(close[0].deviation.detail.contains("992 per-participant"));
        assert!(close[0].deviation.detail.contains("flood ended"));
        assert_eq!(f.open(), 0);
        assert_eq!(f.stats().folded, 992);
    }

    /// Review H3: Critical per-participant findings are aggregated per
    /// source too (the first ones one by one), into a Critical aggregate;
    /// another source's Critical finding is never folded into it.
    #[test]
    fn critical_findings_are_aggregated_per_source() {
        let mut f = FloodGuard::default();
        let mut passed = 0;
        let mut out = Vec::new();
        for i in 0..600u32 {
            match admit(&mut f, &writer(i), "10.0.0.9", g(i), u64::from(i)) {
                Admit::Pass => passed += 1,
                Admit::Fold(r) => out.extend(r),
            }
        }
        assert_eq!(passed, PER_SOURCE);
        assert!(out
            .iter()
            .all(|r| r.deviation.severity == Severity::Critical));
        assert!(out.len() <= 10);
        assert!(out[0].episode.starts_with("discovery_flood/critical/"));
        // Its High findings have their own share and aggregate.
        assert_eq!(
            admit(&mut f, &unknown(1), "10.0.0.9", g(1), 700),
            Admit::Pass
        );
        // The genuine rogue elsewhere: reported by itself.
        assert_eq!(
            admit(&mut f, &writer(7777), "10.0.0.66", g(7777), 701),
            Admit::Pass
        );
    }

    /// Review H4: not-per-participant and protected findings always pass;
    /// a source under its own share is never folded because others used
    /// up a global budget.
    #[test]
    fn other_protected_and_unflooded_findings_are_never_folded() {
        let mut f = FloodGuard::default();
        for i in 0..100u32 {
            admit(&mut f, &unknown(i), "10.0.0.9", g(i), 0);
        }
        let other = Deviation::new("robot.motion.uncommanded_motion", Severity::High, "y");
        let it = Item {
            deviation: &other,
            src_ip: "10.0.0.9",
            participant: None,
            protected: false,
        };
        assert_eq!(f.admit(it, 1, 0), Admit::Pass);
        let pinned = Deviation::new(
            "robot.ros2.participant_source_mismatch",
            Severity::High,
            "pinned prefix from a wrong address",
        );
        let it = Item {
            deviation: &pinned,
            src_ip: "10.0.0.9",
            participant: Some(&[0xaa; 12]),
            protected: true,
        };
        assert_eq!(f.admit(it, 1, 0), Admit::Pass);
        assert_eq!(f.stats().protected_passed, 1);

        // The reviewer's low-rate PoC: 4 sources use up the global budget,
        // 8 more each send one; a genuine rogue later is still reported.
        let mut f = FloodGuard::default();
        let mut n = 0;
        for s in 0..4 {
            for _ in 0..8 {
                assert_eq!(
                    admit(&mut f, &unknown(n), &format!("10.1.0.{s}"), g(n), 1),
                    Admit::Pass
                );
                n += 1;
            }
        }
        for s in 0..8 {
            assert_eq!(
                admit(&mut f, &unknown(n), &format!("10.2.0.{s}"), g(n), 2),
                Admit::Pass
            );
            n += 1;
        }
        assert_eq!(
            admit(&mut f, &unknown(9999), "10.0.0.66", g(9999), 3),
            Admit::Pass
        );
        // Its second finding folds into its own aggregate, which names it.
        let r = reports(admit(&mut f, &unknown(9998), "10.0.0.66", g(9998), 4));
        assert_eq!(r[0].src_ip.as_deref(), Some("10.0.0.66"));
        assert!(r[0].deviation.detail.contains(&hex(&g(9998))));
        assert!(!r[0].deviation.detail.contains("more than"));
    }

    #[test]
    fn a_spoofed_source_spray_is_bounded_and_names_sample_sources() {
        let mut f = FloodGuard::default();
        let mut passed = 0u32;
        let mut out = Vec::new();
        for i in 0..10_000u32 {
            let ip = format!("10.{}.{}.{}", i >> 16, (i >> 8) & 255, i & 255);
            match admit(&mut f, &unknown(i), &ip, g(i), u64::from(i)) {
                Admit::Pass => passed += 1,
                Admit::Fold(r) => out.extend(r),
            }
        }
        assert!(
            passed <= PER_WINDOW + MAX_SOURCES as u32 * FRESH_PER_SOURCE,
            "{passed}"
        );
        assert!(out.len() <= 16, "{}", out.len());
        assert_eq!(f.open(), 1, "one many-sources aggregate");
        let many = f.flush();
        assert!(many[0].src_ip.is_none());
        let d = &many[0].deviation.detail;
        assert!(d.contains("sample sources: 10."), "{d}");
        assert!(d.chars().count() <= MAX_DETAIL, "{d}");
    }

    /// Review L10: a flood after the previous one ended is a new episode
    /// (a new finding id downstream), and the old one gets its closing
    /// report.
    #[test]
    fn each_episode_has_its_own_subject() {
        let mut f = FloodGuard::default();
        let mut first = Vec::new();
        for i in 0..20u32 {
            first.extend(reports(admit(
                &mut f,
                &unknown(i),
                "10.0.0.9",
                g(i),
                u64::from(i),
            )));
        }
        let mut second = Vec::new();
        for i in 20..40u32 {
            second.extend(reports(admit(
                &mut f,
                &unknown(i),
                "10.0.0.9",
                g(i),
                600 * S + u64::from(i),
            )));
        }
        second.extend(f.tick(600 * S + 100));
        let e1 = &first[0].episode;
        assert!(first.iter().all(|r| &r.episode == e1));
        assert!(second
            .iter()
            .any(|r| &r.episode == e1 && r.deviation.detail.contains("flood ended")));
        assert!(second.iter().any(|r| &r.episode != e1));
    }

    /// Review L9: samples are the structured prefixes; the text always fits
    /// and keeps its closing sentence, however many rules were folded.
    #[test]
    fn detail_fits_and_samples_are_structured() {
        let mut f = FloodGuard::default();
        let mut last = None;
        for i in 0..200u32 {
            let d = Deviation::new(
                format!("robot.ros2.some_long_rule_name_number_{}", i % 12),
                Severity::High,
                format!(
                    "writer on rt/{} attributed to {}",
                    "a".repeat(24),
                    hex(&g(i))
                ),
            );
            if let Admit::Fold(r) = admit(&mut f, &d, "10.0.0.9", g(i), u64::from(i)) {
                last = r.into_iter().last().or(last);
            }
        }
        let d = last.unwrap().deviation.detail;
        assert!(d.chars().count() <= MAX_DETAIL, "{}", d.len());
        assert!(
            d.ends_with("every folded finding is recorded in the black box"),
            "{d}"
        );
        assert!(!d.contains(&"a".repeat(24)), "{d}");
    }
}
