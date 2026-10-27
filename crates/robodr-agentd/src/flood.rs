//! Discovery-flood aggregation (red team F1, and the reviews of its fix:
//! H3, H4, L9, L10; R2-1, R2-2).
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
//! finding, legitimate ones included, was in the black box only. The same
//! holds for endpoint announcements *attributed to* one of the robot's own
//! participants with distinct topics (review R2-1): one Critical
//! `endpoint_source_mismatch` and one High `unknown_writer_topic` per
//! attacker datagram.
//!
//! # What this module does
//!
//! agentd passes every pipeline finding through [`FloodGuard::admit`]
//! before the agent. A finding takes part when it is about **one
//! participant**: the pipeline names its GUID prefix as structured data
//! (`robodr_ros2_pipeline::Finding::participant`: every per-participant and
//! per-endpoint discovery rule, Critical ones included). Everything else
//! always goes through one by one.
//!
//! Findings about one of the robot's **own** participants (profiled or
//! pinned: an impersonation such as `participant_source_mismatch` on a
//! pinned prefix, a forged dispose, an endpoint attributed to it from a
//! foreign host) are never hidden, but they are bounded (review R2-1): the
//! first [`PROTECTED_PER_KEY`] High or Critical ones per (participant,
//! source, rule) and window are reported one by one, at most
//! [`PROTECTED_PER_PREFIX`] per participant and window; the rest is
//! folded into a **Critical** aggregate per (source, participant) whose
//! text names the participant as its subject ("about the robot's own
//! participant <prefix>"), never as a sample GUID prefix. A new rule from
//! the same source passes again. Findings below High about them (a
//! legitimate participant leaving reports one Low `discovery_removal` per
//! endpoint) have far larger budgets ([`PROTECTED_LOW_PER_KEY`],
//! [`PROTECTED_LOW_PER_PREFIX`]) and an aggregate of their own severity.
//!
//! The other findings are counted per source IP and per **class**
//! (Critical, and below Critical) in a window ([`WINDOW`], 60 s):
//!
//! - A source's first [`PER_SOURCE`] findings of a class in a window are
//!   reported one by one. While fewer than [`PER_WINDOW`] findings of all
//!   sources passed in the window, a newly seen source gets that share; a
//!   source first seen after that gets [`FRESH_PER_SOURCE`] (so a spray from
//!   many addresses is bounded, but a genuine rogue's first finding is still
//!   reported by name). **Only a source past its own share is folded**: a
//!   busy bus never hides another source's findings.
//! - At most [`MAX_SOURCES`] (128) sources are counted per window. A
//!   **Critical** finding from a source beyond them is still reported by
//!   name, up to [`FRESH_CRITICAL`] (128) per window (review R2-2: 128
//!   spoofed SPDPs used to push a genuine rogue's motion writer into the
//!   sourceless aggregate). Exhausting that budget takes the 128 sources
//!   plus 128 more Critical findings, i.e. an SPDP and a motion writer
//!   each from yet another address: about 384 datagrams a minute (6.4
//!   packets/s) sustained.
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
//!   (`discovery_flood/protected-<class>/<prefix>/<episode start>` for a
//!   protected participant's; [`FloodReport::episode`]), so every report of one
//!   episode updates one SOC case, and a later flood (after the first
//!   ended) opens a new case instead of reopening one the SOC may have
//!   closed.
//! - At most [`MAX_KEYS`] sources have their own aggregate. A flooding
//!   source beyond [`MAX_KEYS`], or a below-Critical finding from a source
//!   beyond [`MAX_SOURCES`] (or a Critical one past [`FRESH_CRITICAL`]),
//!   goes to one "many sources" aggregate per class (per protected
//!   participant for theirs). It names the **latest** [`MAX_SAMPLES`]
//!   source addresses and GUID prefixes (motion writers kept over the
//!   others), so a seeded aggregate cannot hide the newest one.
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
//!   flooding (or, below Critical, beyond [`MAX_SOURCES`] in a window) is
//!   folded: it is named only if it is among the samples, and no
//!   per-participant response is planned for it. It is in the black box.
//!   The Critical class is folded too, past its own share per source: a
//!   rogue that hides among a sprayer's motion writers *from the sprayer's
//!   own address* is reported through the Critical aggregate, not by name.
//! - Source addresses are not authenticated: an attacker can make a
//!   legitimate host's address look like a flooding source for its own
//!   (unprotected) discovery findings. A spoofed-source spray still costs at
//!   most `PER_WINDOW + MAX_SOURCES * FRESH_PER_SOURCE + FRESH_CRITICAL`
//!   individual findings per class and window (plus
//!   `PROTECTED_PER_PREFIX` per protected participant), plus the
//!   aggregates. One that sustains more than about 6 packets/s of spoofed
//!   SPDP and motion writers can push a genuine rogue's Critical finding
//!   into the "many sources" aggregate; it is named there only while it
//!   is among the latest samples (and always in the black box).
//! - The counters and open aggregates are in memory: after a restart a
//!   flood starts a new episode (the folded findings are in the black box).
//! - The catalog title of `robot.ros2.discovery_flood` ("Discovery flood:
//!   unknown participants aggregated") is frozen and mirrored by the SOC;
//!   the aggregate also covers Critical per-endpoint findings and findings
//!   about the robot's own participants (the detail says which).

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
/// Sources counted per window (beyond: the "many sources" aggregate, or,
/// for a Critical finding, [`FRESH_CRITICAL`]).
pub const MAX_SOURCES: usize = 128;
/// Critical findings from sources beyond [`MAX_SOURCES`] reported one by
/// one per window (review R2-2): a spoofed-source spray that fills the
/// source table must send this many more Critical findings (an SPDP and a
/// motion writer each: about 6 packets/s sustained, with the 128 sources)
/// before a genuine rogue's Critical finding is folded.
pub const FRESH_CRITICAL: u32 = 128;
/// High or Critical findings about one of the robot's own participants
/// (profiled or pinned) reported one by one per (participant, source,
/// rule) and window (review R2-1).
pub const PROTECTED_PER_KEY: u32 = 4;
/// High or Critical findings about one protected participant reported one
/// by one per window, every source and rule together.
pub const PROTECTED_PER_PREFIX: u32 = 64;
/// The same for findings below High about a protected participant (a
/// legitimate participant leaving reports one `discovery_removal` per
/// endpoint): far larger, they never use the spool's Critical share.
pub const PROTECTED_LOW_PER_KEY: u32 = 256;
pub const PROTECTED_LOW_PER_PREFIX: u32 = 1024;
/// (protected participant, source, rule) counters per window.
pub const MAX_PROTECTED_KEYS: usize = 512;
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
    /// Findings about one of the robot's own (profiled or pinned)
    /// participants reported one by one (within [`PROTECTED_PER_KEY`] /
    /// [`PROTECTED_PER_PREFIX`]).
    pub protected_passed: u64,
    /// Findings about one of the robot's own participants folded into a
    /// Critical aggregate that names it.
    pub protected_folded: u64,
    /// Critical findings from sources beyond [`MAX_SOURCES`] reported one by
    /// one ([`FRESH_CRITICAL`]).
    pub fresh_critical_passed: u64,
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
    /// counted per (participant, source, rule), folded only into an
    /// aggregate that names it (module docs).
    pub protected: bool,
}

/// (source, Critical class, protected participant): source `None` = many
/// sources; for a protected participant the class is "High or above",
/// and its aggregate is Critical.
type Key = (Option<String>, bool, Option<[u8; 12]>);

#[derive(Debug, Clone)]
struct Agg {
    folded: u64,
    reported_at: u64,
    by_rule: BTreeMap<String, u64>,
    severity: Severity,
    first_wall_ms: u64,
    last_wall_ms: u64,
    last_ns: u64,
    /// Sample prefixes / sources, each with "a motion writer": the first
    /// ones of a per-source aggregate, the **latest** ones of a "many
    /// sources" aggregate (motion writers kept first; review R2-2).
    samples: Vec<([u8; 12], bool)>,
    sources: Vec<(String, bool)>,
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
    /// Critical findings passed by name from sources beyond MAX_SOURCES.
    fresh_critical: u32,
    /// Per window: (protected participant, source, rule, High or above)
    /// -> passed.
    protected_keys: HashMap<([u8; 12], String, String, bool), u32>,
    /// Per window: (protected participant, High or above) -> passed.
    protected_prefix: HashMap<([u8; 12], bool), u32>,
    /// Open floods ([`Key`]).
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

/// Note a sample: the first [`MAX_SAMPLES`] (`latest == false`), or the
/// latest ones, motion writers kept over the others (`latest == true`).
fn note_sample<T: PartialEq + Clone>(v: &mut Vec<(T, bool)>, x: &T, motion: bool, latest: bool) {
    if let Some(i) = v.iter().position(|(y, _)| y == x) {
        if latest {
            let (y, m) = v.remove(i);
            v.push((y, m || motion));
        } else {
            v[i].1 |= motion;
        }
        return;
    }
    if v.len() < MAX_SAMPLES {
        v.push((x.clone(), motion));
        return;
    }
    if !latest {
        return;
    }
    let victim = v
        .iter()
        .position(|(_, m)| !*m)
        .or(if motion { Some(0) } else { None });
    if let Some(i) = victim {
        v.remove(i);
        v.push((x.clone(), motion));
    }
}

/// A finding that names a writer able to command motion.
fn is_motion(d: &Deviation) -> bool {
    d.rule_str() == "robot.ros2.unauthorized_motion_writer"
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
        if self
            .window_start
            .is_none_or(|s| mono_ns >= s.saturating_add(window_ns()) || mono_ns < s)
        {
            self.window_start = Some(mono_ns);
            self.per_source.clear();
            self.passed = 0;
            self.fresh_critical = 0;
            self.protected_keys.clear();
            self.protected_prefix.clear();
        }
        if it.protected {
            return self.admit_protected(it, participant, mono_ns, wall_ms);
        }
        let critical = it.deviation.severity >= Severity::Critical;
        let mut reports = Vec::new();
        let own: Key = (Some(it.src_ip.to_owned()), critical, None);
        // An episode quiet for a full window has ended: close it first.
        self.close_if_quiet(&own, mono_ns, &mut reports);
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
                    return self.pass(reports);
                }
                // Past its own share: its own aggregate (bounded).
                if self.open_own() < MAX_KEYS {
                    own
                } else {
                    (None, critical, None)
                }
            }
            Some(_) => own,
            // Beyond MAX_SOURCES in this window (review R2-2): a Critical
            // finding from a source not seen yet still passes by name,
            // within its own per-window budget.
            None if critical && self.fresh_critical < FRESH_CRITICAL => {
                self.fresh_critical += 1;
                self.passed = self.passed.saturating_add(1);
                self.stats.fresh_critical_passed += 1;
                return self.pass(reports);
            }
            None => (None, critical, None),
        };
        self.fold(key, it, participant, mono_ns, wall_ms, reports)
    }

    /// A finding about one of the robot's own participants (review R2-1):
    /// the first [`PROTECTED_PER_KEY`] High or Critical ones per
    /// (participant, source, rule) and window, at most
    /// [`PROTECTED_PER_PREFIX`] per participant, are reported one by one
    /// (below High: [`PROTECTED_LOW_PER_KEY`], [`PROTECTED_LOW_PER_PREFIX`]);
    /// the rest is folded into an aggregate per (source, participant,
    /// class) that names the participant: **Critical** for the High and
    /// Critical ones.
    fn admit_protected(
        &mut self,
        it: Item<'_>,
        participant: &[u8; 12],
        mono_ns: u64,
        wall_ms: u64,
    ) -> Admit {
        let high = it.deviation.severity >= Severity::High;
        let (per_key, per_prefix) = if high {
            (PROTECTED_PER_KEY, PROTECTED_PER_PREFIX)
        } else {
            (PROTECTED_LOW_PER_KEY, PROTECTED_LOW_PER_PREFIX)
        };
        let mut reports = Vec::new();
        let own: Key = (Some(it.src_ip.to_owned()), high, Some(*participant));
        self.close_if_quiet(&own, mono_ns, &mut reports);
        let k = (
            *participant,
            it.src_ip.to_owned(),
            it.deviation.rule_str().to_owned(),
            high,
        );
        let n = self.protected_keys.get(&k).copied();
        let total = self
            .protected_prefix
            .get(&(*participant, high))
            .copied()
            .unwrap_or(0);
        let room = n.is_some() || self.protected_keys.len() < MAX_PROTECTED_KEYS;
        if room && n.unwrap_or(0) < per_key && total < per_prefix {
            *self.protected_keys.entry(k).or_insert(0) += 1;
            *self
                .protected_prefix
                .entry((*participant, high))
                .or_insert(0) += 1;
            self.stats.protected_passed += 1;
            return self.pass(reports);
        }
        self.stats.protected_folded += 1;
        let key = if self.aggs.contains_key(&own) || self.open_own() < MAX_KEYS {
            own
        } else {
            (None, high, Some(*participant))
        };
        self.fold(key, it, participant, mono_ns, wall_ms, reports)
    }

    /// Open aggregates with a source of their own.
    fn open_own(&self) -> usize {
        self.aggs.keys().filter(|k| k.0.is_some()).count()
    }

    /// Close `key`'s episode if it was quiet for a full window.
    fn close_if_quiet(&mut self, key: &Key, mono_ns: u64, reports: &mut Vec<FloodReport>) {
        if self.aggs.get(key).is_some_and(|a| quiet(a, mono_ns)) {
            if let Some(a) = self.aggs.remove(key) {
                if a.folded > a.reported_at {
                    reports.push(report(key, &a, true));
                }
            }
        }
    }

    /// Report the finding; a closing report of an ended episode is handed
    /// out at the next tick.
    fn pass(&mut self, reports: Vec<FloodReport>) -> Admit {
        self.stats.reports += reports.len() as u64;
        self.closed.extend(reports);
        Admit::Pass
    }

    fn fold(
        &mut self,
        key: Key,
        it: Item<'_>,
        participant: &[u8; 12],
        mono_ns: u64,
        wall_ms: u64,
        mut reports: Vec<FloodReport>,
    ) -> Admit {
        let critical = key.1;
        if key.0.is_none() {
            self.close_if_quiet(&key, mono_ns, &mut reports);
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
            episode: match &key.2 {
                Some(p) => format!(
                    "discovery_flood/protected-{}/{}/{}",
                    if critical { "critical" } else { "other" },
                    hex(p),
                    utc(wall_ms)
                ),
                None => format!(
                    "discovery_flood/{}/{}",
                    if critical { "critical" } else { "other" },
                    utc(wall_ms)
                ),
            },
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
        let motion = is_motion(it.deviation);
        let many = key.0.is_none();
        // A protected aggregate names its participant, never as a sample.
        if key.2.is_none() {
            note_sample(&mut a.samples, participant, motion, many);
        }
        if many {
            note_sample(&mut a.sources, &it.src_ip.to_owned(), motion, true);
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

/// The aggregate's detail, built to fit [`MAX_DETAIL`]: sample prefixes are
/// dropped first (the last of a per-source aggregate, the oldest of a "many
/// sources" one), then sample sources (oldest first), then the per-rule
/// list is shortened; the subject (source, protected participant) and the
/// closing sentence are always there.
fn report(key: &Key, a: &Agg, closing: bool) -> FloodReport {
    let severity = if key.1 {
        Severity::Critical
    } else {
        a.severity.max(Severity::Medium)
    };
    let srcs: Vec<&str> = a.sources.iter().map(|(s, _)| s.as_str()).collect();
    let from = |n: usize| match &key.0 {
        Some(ip) => format!("from {ip}"),
        None if n == 0 => "from many source addresses".to_string(),
        // The latest ones first.
        None => format!(
            "from many source addresses (latest sample sources: {})",
            srcs[srcs.len() - n..]
                .iter()
                .rev()
                .copied()
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };
    // Review R2-1: the robot's own participant is named as the subject,
    // never as a sample GUID prefix (a SOC must not quarantine it for this).
    let about = match &key.2 {
        Some(p) => format!(
            " about the robot's own participant {} (profiled or pinned)",
            hex(p)
        ),
        None => String::new(),
    };
    let samples: Vec<[u8; 12]> = a.samples.iter().map(|(p, _)| *p).collect();
    let tail = format!(
        "{}every folded finding is recorded in the black box",
        if closing { "flood ended; " } else { "" }
    );
    let all_rules: Vec<String> = a.by_rule.iter().map(|(r, n)| format!("{r} x{n}")).collect();
    let compose = |rules: &[String], samples: &[[u8; 12]], n_src: usize| {
        let sampled = if key.2.is_some() {
            String::new()
        } else if samples.is_empty() {
            "sample GUID prefixes: none; ".to_string()
        } else {
            format!(
                "{}sample GUID prefixes: {}; ",
                if key.0.is_none() { "latest " } else { "" },
                // The latest ones first (a "many sources" aggregate).
                if key.0.is_none() {
                    samples.iter().rev().map(hex).collect::<Vec<_>>().join(", ")
                } else {
                    samples.iter().map(hex).collect::<Vec<_>>().join(", ")
                }
            )
        };
        format!(
            "{}discovery flood {}{about}: {} per-participant findings folded into this one: \
             {}; first seen {}, last seen {}; {sampled}{tail}",
            if key.1 { "Critical " } else { "" },
            from(n_src),
            a.folded,
            rules.join(", "),
            utc(a.first_wall_ms),
            utc(a.last_wall_ms),
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
        for n_src in (0..=srcs.len()).rev() {
            for n in (0..=samples.len()).rev() {
                // Keep the latest samples of a "many sources" aggregate.
                let kept = if key.0.is_none() {
                    &samples[samples.len() - n..]
                } else {
                    &samples[..n]
                };
                let d = compose(&rules, kept, n_src);
                if fits(&d) {
                    detail = Some(d);
                    break 'outer;
                }
            }
        }
    }
    let detail = detail.unwrap_or_else(|| {
        format!(
            "discovery flood{about}: {} per-participant findings folded; {tail}",
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

    fn protected(f: &mut FloodGuard, d: &Deviation, ip: &str, p: [u8; 12], ns: u64) -> Admit {
        f.admit(
            Item {
                deviation: d,
                src_ip: ip,
                participant: Some(&p),
                protected: true,
            },
            ns,
            1_000 + ns / 1_000_000,
        )
    }

    /// Review R2-1: findings about a protected participant were never
    /// folded (one Critical and one High per attacker datagram). The first
    /// few per (participant, source, rule) pass; the rest is one Critical
    /// aggregate per source that names the participant (never as a
    /// sample); a new rule from the same source still passes.
    #[test]
    fn protected_findings_are_bounded_and_name_the_participant() {
        let legit = [0xaa; 12];
        let mut f = FloodGuard::default();
        let mut passed = 0;
        let mut out = Vec::new();
        for i in 0..1000u32 {
            let ip = format!("10.5.0.{}", i % 5);
            let d = Deviation::new(
                "robot.ros2.endpoint_source_mismatch",
                Severity::High,
                format!("writer on rt/x{i}"),
            );
            match protected(&mut f, &d, &ip, legit, u64::from(i)) {
                Admit::Pass => passed += 1,
                Admit::Fold(r) => out.extend(r),
            }
        }
        assert_eq!(passed, 5 * PROTECTED_PER_KEY);
        assert!(out.len() <= 5 * 9, "{}", out.len());
        for r in &out {
            assert_eq!(r.deviation.severity, Severity::Critical);
            let d = &r.deviation.detail;
            assert!(
                d.contains(&format!("robot's own participant {}", hex(&legit))),
                "{d}"
            );
            assert!(!d.contains("sample GUID prefixes"), "{d}");
            assert!(r
                .episode
                .starts_with("discovery_flood/protected-critical/aaaa"));
        }
        let d = Deviation::new(
            "robot.ros2.participant_source_mismatch",
            Severity::Critical,
            "x",
        );
        assert_eq!(protected(&mut f, &d, "10.5.0.1", legit, 2000), Admit::Pass);
        // The legitimate participant leaving: one Low finding per endpoint.
        for i in 0..200u32 {
            let d = Deviation::new(
                "robot.rtps.discovery_removal",
                Severity::Low,
                format!("writer {i} disposed"),
            );
            assert_eq!(protected(&mut f, &d, "10.5.0.9", legit, 3000), Admit::Pass);
        }
        // Many sources: bounded per participant too.
        let mut f = FloodGuard::default();
        let mut passed = 0u32;
        for i in 0..5000u32 {
            let ip = format!("10.6.{}.{}", i >> 8, i & 255);
            let d = Deviation::new(
                "robot.ros2.endpoint_source_mismatch",
                Severity::Critical,
                "x",
            );
            if protected(&mut f, &d, &ip, legit, u64::from(i)) == Admit::Pass {
                passed += 1;
            }
        }
        assert_eq!(passed, PROTECTED_PER_PREFIX);
        let fl = f.flush();
        assert!(fl.iter().all(|r| r.deviation.detail.contains(&hex(&legit))));
        assert!(fl.iter().any(|r| r.src_ip.is_none()
            && r.deviation
                .detail
                .contains("latest sample sources: 10.6.19.")));
    }

    /// Review R2-2: with the source table full (128 spoofed sources), a
    /// Critical finding from a new source still passes by name; the "many
    /// sources" aggregate keeps the latest samples, motion writers first.
    #[test]
    fn a_full_source_table_does_not_fold_a_new_sources_critical_finding() {
        let mut f = FloodGuard::default();
        for i in 0..MAX_SOURCES as u32 {
            admit(&mut f, &unknown(i), &format!("10.60.0.{i}"), g(i), 1);
        }
        for i in 0..4u32 {
            let ip = format!("10.61.0.{i}");
            admit(&mut f, &unknown(500 + i), &ip, g(500 + i), 2);
            assert_eq!(
                admit(&mut f, &writer(500 + i), &ip, g(500 + i), 2),
                Admit::Pass
            );
        }
        assert_eq!(
            admit(&mut f, &writer(7777), "10.0.0.66", g(7777), 3),
            Admit::Pass
        );
        // The budget is bounded; beyond it, the latest are named.
        for i in 0..(FRESH_CRITICAL + 50) {
            admit(
                &mut f,
                &writer(1000 + i),
                &format!("10.62.{}.{}", i >> 8, i & 255),
                g(1000 + i),
                4,
            );
        }
        assert_eq!(f.stats().fresh_critical_passed, u64::from(FRESH_CRITICAL));
        reports(admit(&mut f, &unknown(9000), "10.0.0.67", g(9000), 5));
        assert!(matches!(
            admit(&mut f, &writer(9001), "10.0.0.68", g(9001), 5),
            Admit::Fold(_)
        ));
        let fl = f.flush();
        let crit = fl
            .iter()
            .find(|r| r.src_ip.is_none() && r.deviation.severity == Severity::Critical)
            .unwrap();
        let d = &crit.deviation.detail;
        assert!(d.contains("10.0.0.68") && d.contains(&hex(&g(9001))), "{d}");
    }
}
