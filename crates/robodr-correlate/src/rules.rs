//! Declarative correlation rules (JSON) and their load-time validation.
//!
//! ```json
//! { "version": 1,
//!   "rules": [ {
//!     "id": "robot.correlate.credential_theft",
//!     "title": "SROS 2 key read, then an unknown participant joined",
//!     "severity": "critical",
//!     "window_secs": 600,
//!     "group_by": null,
//!     "pattern": { "kind": "sequence", "steps": [
//!         { "rules": ["RoboDR: SROS 2 enclave private key read by a process outside the ROS stack"],
//!           "domain": "host" },
//!         { "rules": ["robot.ros2.unknown_participant"] } ] } } ] }
//! ```
//!
//! Pattern kinds:
//!
//! * `sequence` — `steps[0]`, then `steps[1]`, ... (arrival order), all
//!   within `window_secs` of the first step, in the same group.
//! * `co_occurrence` — every slot in `all_of` matched (each `count` times,
//!   default 1) within `window_secs`, in any order. With slot `domain`s this
//!   expresses "host-side and network-side evidence together".
//! * `threshold` — `count` signals matching `match` within `window_secs`.
//! * `distinct_sources` — signals matching `match` from `count` distinct
//!   values of entity kind `distinct_by` within `window_secs`.
//!
//! `group_by` (an [`EntityKind`] or `null`) partitions state: with `"ip"`,
//! only signals carrying the *same* IP entity are combined; `null` combines
//! everything the engine sees (one robot = one group).
//!
//! Output severity: `max(severity, max contributing severity raised by
//! escalate_by levels)`, saturating at Critical. A correlated finding never
//! has a lower severity than any of its inputs and can never exceed
//! Critical (the type has nothing above it).
//!
//! Validation is strict (unknown fields, non-finite or non-positive
//! windows, oversize counts, duplicate ids, self-referencing ids are
//! errors) and every problem is reported at once. Rule ids outside the
//! [`crate::catalog`] are warnings: a deployment may add its own Pulsar
//! rules, but a typo silently disables a correlation, so it is surfaced.

use std::collections::BTreeSet;

use robodr_events::Severity;
use serde::{Deserialize, Serialize};

use crate::catalog;
use crate::signal::{Domain, EntityKind};

/// Required prefix of every correlation rule id. Signals with this prefix
/// are ignored on input, so a correlated finding cannot feed back.
pub const RULE_ID_PREFIX: &str = "robot.correlate.";
/// Largest accepted rule file.
pub const MAX_JSON_BYTES: usize = 1 << 20;
/// Most rules in one set.
pub const MAX_RULES: usize = 64;
/// Most steps in a sequence / slots in a co-occurrence.
pub const MAX_STEPS: usize = 8;
/// Largest `count` anywhere.
pub const MAX_COUNT: u32 = 64;
/// Most signals one rule may need to fire (bounds per-group memory).
pub const MAX_REQUIRED_SIGNALS: u32 = 64;
/// Longest window / cooldown (one day).
pub const MAX_WINDOW_SECS: f64 = 86_400.0;
/// Most ids + prefixes in one matcher.
pub const MAX_IDS_PER_MATCHER: usize = 64;
/// Longest id / prefix / title string.
pub const MAX_ID_LEN: usize = 256;
/// Longest description.
pub const MAX_DESCRIPTION_LEN: usize = 4096;
/// Highest `escalate_by`.
pub const MAX_ESCALATE_BY: u8 = 3;

/// A whole rule file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleFile {
    /// Schema version; must be 1.
    pub version: u32,
    pub rules: Vec<RuleSpec>,
}

/// One correlation rule as written in JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    /// `robot.correlate.<name>`; becomes the finding's (deviation's) rule id.
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    /// Minimum output severity.
    pub severity: Severity,
    /// Output is at least the highest input severity raised by this many
    /// levels (0..=3, saturating at Critical).
    #[serde(default)]
    pub escalate_by: u8,
    pub window_secs: f64,
    /// After firing, the same group cannot fire this rule again for this
    /// long. Default: `window_secs`.
    #[serde(default)]
    pub cooldown_secs: Option<f64>,
    /// Partition key; `null` = the whole unit.
    #[serde(default)]
    pub group_by: Option<EntityKind>,
    pub pattern: PatternSpec,
}

/// See the module docs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PatternSpec {
    Sequence(SequenceSpec),
    CoOccurrence(CoOccurrenceSpec),
    Threshold(ThresholdSpec),
    DistinctSources(DistinctSpec),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SequenceSpec {
    pub steps: Vec<MatcherSpec>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoOccurrenceSpec {
    pub all_of: Vec<MatcherSpec>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdSpec {
    #[serde(rename = "match")]
    pub matcher: MatcherSpec,
    pub count: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DistinctSpec {
    #[serde(rename = "match")]
    pub matcher: MatcherSpec,
    pub distinct_by: EntityKind,
    pub count: u32,
}

/// Which signals a step / slot accepts. A signal matches when its rule id
/// is in `rules` or starts with one of `prefixes` (if either list is
/// non-empty), its domain equals `domain` (if set) and its severity is at
/// least `min_severity` (if set).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatcherSpec {
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default)]
    pub prefixes: Vec<String>,
    #[serde(default)]
    pub domain: Option<Domain>,
    #[serde(default)]
    pub min_severity: Option<Severity>,
    /// Only in `co_occurrence` slots: how many matching signals the slot
    /// needs. Default 1.
    #[serde(default)]
    pub count: Option<u32>,
}

/// A validated, compiled matcher.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Matcher {
    pub exact: BTreeSet<String>,
    pub prefixes: Vec<String>,
    pub domain: Option<Domain>,
    pub min_severity: Option<Severity>,
    /// Signals this slot needs (1 except in co-occurrence / threshold).
    pub count: usize,
}

impl Matcher {
    pub(crate) fn matches(&self, rule: &str, domain: Domain, severity: Severity) -> bool {
        if let Some(d) = self.domain {
            if d != domain {
                return false;
            }
        }
        if let Some(min) = self.min_severity {
            if severity < min {
                return false;
            }
        }
        if self.exact.is_empty() && self.prefixes.is_empty() {
            return true;
        }
        self.exact.contains(rule) || self.prefixes.iter().any(|p| rule.starts_with(p.as_str()))
    }
}

/// A validated, compiled pattern.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Pattern {
    Sequence(Vec<Matcher>),
    /// Co-occurrence and threshold (a threshold is one slot of `count`).
    Slots(Vec<Matcher>),
    Distinct {
        matcher: Matcher,
        by: EntityKind,
        count: usize,
    },
}

/// A validated, compiled rule.
#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub(crate) id: String,
    pub(crate) title: String,
    pub(crate) description: String,
    pub(crate) severity: Severity,
    pub(crate) escalate_by: u8,
    pub(crate) window_ns: u64,
    pub(crate) cooldown_ns: u64,
    pub(crate) group_by: Option<EntityKind>,
    pub(crate) pattern: Pattern,
}

impl Rule {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn title(&self) -> &str {
        &self.title
    }
    pub fn description(&self) -> &str {
        &self.description
    }
    pub fn window_ns(&self) -> u64 {
        self.window_ns
    }
    pub fn group_by(&self) -> Option<EntityKind> {
        self.group_by
    }

    /// Output severity for contributors whose highest severity is `max_in`.
    pub fn output_severity(&self, max_in: Severity) -> Severity {
        self.severity.max(bump(max_in, self.escalate_by))
    }

    /// Does any matcher of this rule accept the signal (ignoring entities)?
    pub(crate) fn any_matcher(&self, rule: &str, domain: Domain, sev: Severity) -> bool {
        match &self.pattern {
            Pattern::Sequence(ms) | Pattern::Slots(ms) => {
                ms.iter().any(|m| m.matches(rule, domain, sev))
            }
            Pattern::Distinct { matcher, .. } => matcher.matches(rule, domain, sev),
        }
    }
}

/// `s` raised by `levels`, saturating at Critical.
pub fn bump(s: Severity, levels: u8) -> Severity {
    let mut s = s;
    for _ in 0..levels {
        s = match s {
            Severity::Low => Severity::Medium,
            Severity::Medium => Severity::High,
            Severity::High | Severity::Critical => Severity::Critical,
        };
    }
    s
}

/// A validated rule set, ready for [`crate::Correlator::new`].
#[derive(Debug, Clone, PartialEq)]
pub struct RuleSet {
    pub(crate) rules: Vec<Rule>,
}

/// Why a rule file was refused: every problem found, one per entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleError {
    pub problems: Vec<String>,
}

impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid correlation rules: {}", self.problems.join("; "))
    }
}

impl std::error::Error for RuleError {}

/// The default rule set shipped with RoboDR (`rules/default.json` in this
/// crate).
pub const DEFAULT_RULES_JSON: &str = include_str!("../rules/default.json");

impl RuleSet {
    /// Parse and validate a rule file. Returns the set and the warnings
    /// (unknown rule ids, prefixes that match no known id, domain hints that
    /// contradict an id).
    pub fn from_json(json: &str) -> Result<(RuleSet, Vec<String>), RuleError> {
        if json.len() > MAX_JSON_BYTES {
            return Err(RuleError {
                problems: vec![format!(
                    "rule file is {} bytes (max {MAX_JSON_BYTES})",
                    json.len()
                )],
            });
        }
        let file: RuleFile = serde_json::from_str(json).map_err(|e| RuleError {
            problems: vec![format!("parse error: {e}")],
        })?;
        RuleSet::from_file(&file)
    }

    /// Validate an already parsed rule file.
    pub fn from_file(file: &RuleFile) -> Result<(RuleSet, Vec<String>), RuleError> {
        let mut problems = Vec::new();
        let mut warnings = Vec::new();
        if file.version != 1 {
            problems.push(format!("unsupported version {} (expected 1)", file.version));
        }
        if file.rules.len() > MAX_RULES {
            problems.push(format!("{} rules (max {MAX_RULES})", file.rules.len()));
        }
        let mut ids = BTreeSet::new();
        let mut rules = Vec::new();
        for (i, spec) in file.rules.iter().enumerate() {
            let ctx = format!("rule[{i}] {:?}", truncate_for_msg(&spec.id));
            if !ids.insert(spec.id.clone()) {
                problems.push(format!("{ctx}: duplicate id"));
            }
            if let Some(r) = compile_rule(spec, &ctx, &mut problems, &mut warnings) {
                rules.push(r);
            }
        }
        if problems.is_empty() {
            Ok((RuleSet { rules }, warnings))
        } else {
            Err(RuleError { problems })
        }
    }

    /// The shipped default rules. They are validated by the test suite, so
    /// this cannot fail in a released build; if it ever did, an empty set
    /// is returned (correlation off, every input still reported on its own)
    /// rather than panicking.
    pub fn default_rules() -> RuleSet {
        RuleSet::from_json(DEFAULT_RULES_JSON)
            .map(|(r, _)| r)
            .unwrap_or_else(|_| RuleSet { rules: Vec::new() })
    }

    /// An empty set (correlation disabled).
    pub fn empty() -> RuleSet {
        RuleSet { rules: Vec::new() }
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

fn truncate_for_msg(s: &str) -> String {
    let mut t: String = s.chars().take(80).collect();
    if t.len() < s.len() {
        t.push('…');
    }
    t
}

fn valid_rule_id(id: &str) -> bool {
    id.len() > RULE_ID_PREFIX.len()
        && id.len() <= MAX_ID_LEN
        && id.starts_with(RULE_ID_PREFIX)
        && !id.ends_with('.')
        && !id.contains("..")
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.')
}

fn secs_to_ns(
    secs: f64,
    what: &str,
    allow_zero: bool,
    ctx: &str,
    problems: &mut Vec<String>,
) -> Option<u64> {
    if !secs.is_finite() {
        problems.push(format!("{ctx}: {what} is not finite"));
        return None;
    }
    if secs < 0.0 || (!allow_zero && secs == 0.0) {
        problems.push(format!(
            "{ctx}: {what} must be {}",
            if allow_zero { ">= 0" } else { "> 0" }
        ));
        return None;
    }
    if secs > MAX_WINDOW_SECS {
        problems.push(format!("{ctx}: {what} {secs} > {MAX_WINDOW_SECS}"));
        return None;
    }
    // secs <= 86400, so the product is < 2^47: exact enough and in range.
    let ns = (secs * 1e9).round() as u64;
    if !allow_zero && ns == 0 {
        problems.push(format!("{ctx}: {what} rounds to 0 ns"));
        return None;
    }
    Some(ns)
}

fn compile_rule(
    spec: &RuleSpec,
    ctx: &str,
    problems: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Option<Rule> {
    let before = problems.len();
    if !valid_rule_id(&spec.id) {
        problems.push(format!(
            "{ctx}: id must be {RULE_ID_PREFIX}<name> with [a-z0-9_.] only (max {MAX_ID_LEN} bytes)"
        ));
    }
    if spec.title.trim().is_empty()
        || spec.title.len() > MAX_ID_LEN
        || spec.title.chars().any(char::is_control)
    {
        problems.push(format!(
            "{ctx}: title must be non-empty, <= {MAX_ID_LEN} bytes, no control characters"
        ));
    }
    if spec.description.len() > MAX_DESCRIPTION_LEN {
        problems.push(format!(
            "{ctx}: description longer than {MAX_DESCRIPTION_LEN} bytes"
        ));
    }
    if spec.escalate_by > MAX_ESCALATE_BY {
        problems.push(format!(
            "{ctx}: escalate_by {} > {MAX_ESCALATE_BY}",
            spec.escalate_by
        ));
    }
    let window_ns = secs_to_ns(spec.window_secs, "window_secs", false, ctx, problems);
    let cooldown_ns = match spec.cooldown_secs {
        Some(c) => secs_to_ns(c, "cooldown_secs", true, ctx, problems),
        None => window_ns,
    };

    let required: u64;
    let pattern = match &spec.pattern {
        PatternSpec::Sequence(s) => {
            if s.steps.len() < 2 || s.steps.len() > MAX_STEPS {
                problems.push(format!(
                    "{ctx}: sequence needs 2..={MAX_STEPS} steps, has {}",
                    s.steps.len()
                ));
            }
            let ms: Vec<Matcher> = s
                .steps
                .iter()
                .enumerate()
                .filter_map(|(i, m)| {
                    compile_matcher(m, &format!("{ctx} step[{i}]"), false, problems, warnings)
                })
                .collect();
            required = s.steps.len() as u64;
            Pattern::Sequence(ms)
        }
        PatternSpec::CoOccurrence(c) => {
            if c.all_of.len() < 2 || c.all_of.len() > MAX_STEPS {
                problems.push(format!(
                    "{ctx}: co_occurrence needs 2..={MAX_STEPS} slots, has {}",
                    c.all_of.len()
                ));
            }
            let ms: Vec<Matcher> = c
                .all_of
                .iter()
                .enumerate()
                .filter_map(|(i, m)| {
                    compile_matcher(m, &format!("{ctx} all_of[{i}]"), true, problems, warnings)
                })
                .collect();
            required = ms.iter().map(|m| m.count as u64).sum();
            Pattern::Slots(ms)
        }
        PatternSpec::Threshold(t) => {
            if t.count < 2 || t.count > MAX_COUNT {
                problems.push(format!(
                    "{ctx}: threshold count must be 2..={MAX_COUNT}, is {}",
                    t.count
                ));
            }
            let m = compile_matcher(
                &t.matcher,
                &format!("{ctx} match"),
                false,
                problems,
                warnings,
            );
            required = u64::from(t.count);
            match m {
                Some(mut m) => {
                    m.count = t.count.clamp(1, MAX_COUNT) as usize;
                    Pattern::Slots(vec![m])
                }
                None => Pattern::Slots(Vec::new()),
            }
        }
        PatternSpec::DistinctSources(d) => {
            if d.count < 2 || d.count > MAX_COUNT {
                problems.push(format!(
                    "{ctx}: distinct_sources count must be 2..={MAX_COUNT}, is {}",
                    d.count
                ));
            }
            if spec.group_by == Some(d.distinct_by) {
                problems.push(format!(
                    "{ctx}: distinct_by equals group_by ({}): a group only ever has one value",
                    d.distinct_by.as_str()
                ));
            }
            let m = compile_matcher(
                &d.matcher,
                &format!("{ctx} match"),
                false,
                problems,
                warnings,
            );
            required = u64::from(d.count);
            Pattern::Distinct {
                matcher: m.unwrap_or_else(|| Matcher {
                    exact: BTreeSet::new(),
                    prefixes: Vec::new(),
                    domain: None,
                    min_severity: None,
                    count: 1,
                }),
                by: d.distinct_by,
                count: d.count.clamp(1, MAX_COUNT) as usize,
            }
        }
    };
    if required > u64::from(MAX_REQUIRED_SIGNALS) {
        problems.push(format!(
            "{ctx}: needs {required} signals to fire (max {MAX_REQUIRED_SIGNALS})"
        ));
    }
    if problems.len() != before {
        return None;
    }
    Some(Rule {
        id: spec.id.clone(),
        title: spec.title.clone(),
        description: spec.description.clone(),
        severity: spec.severity,
        escalate_by: spec.escalate_by,
        window_ns: window_ns?,
        cooldown_ns: cooldown_ns?,
        group_by: spec.group_by,
        pattern,
    })
}

fn compile_matcher(
    m: &MatcherSpec,
    ctx: &str,
    count_allowed: bool,
    problems: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Option<Matcher> {
    let before = problems.len();
    if m.rules.is_empty() && m.prefixes.is_empty() && m.domain.is_none() {
        problems.push(format!(
            "{ctx}: matcher needs at least one of rules, prefixes, domain"
        ));
    }
    if m.rules.len() + m.prefixes.len() > MAX_IDS_PER_MATCHER {
        problems.push(format!(
            "{ctx}: more than {MAX_IDS_PER_MATCHER} rules + prefixes"
        ));
    }
    let count = match m.count {
        None => 1,
        Some(c) if !count_allowed => {
            problems.push(format!(
                "{ctx}: count ({c}) is only allowed in co_occurrence slots"
            ));
            1
        }
        Some(c) if c == 0 || c > MAX_COUNT => {
            problems.push(format!("{ctx}: count must be 1..={MAX_COUNT}, is {c}"));
            1
        }
        Some(c) => c as usize,
    };
    for r in &m.rules {
        if r.is_empty() || r.len() > MAX_ID_LEN || r.chars().any(char::is_control) {
            problems.push(format!(
                "{ctx}: rule id {:?} empty, too long or has control characters",
                truncate_for_msg(r)
            ));
            continue;
        }
        if r.starts_with(RULE_ID_PREFIX) {
            problems.push(format!(
                "{ctx}: {r:?} is a correlation output; correlations cannot consume their own findings"
            ));
            continue;
        }
        if !catalog::is_known(r) {
            warnings.push(format!(
                "{ctx}: rule id {r:?} is not in the RoboDR catalog (custom rule or typo?)"
            ));
        }
        if let Some(d) = m.domain {
            let inferred = Domain::infer(r);
            if inferred != d {
                warnings.push(format!(
                    "{ctx}: {r:?} looks like a {inferred:?} rule but the matcher requires domain {d:?}; the producer must set the domain explicitly"
                ));
            }
        }
    }
    for p in &m.prefixes {
        if p.is_empty() || p.len() > MAX_ID_LEN || p.chars().any(char::is_control) {
            problems.push(format!(
                "{ctx}: prefix {:?} empty, too long or has control characters",
                truncate_for_msg(p)
            ));
            continue;
        }
        if !catalog::prefix_matches_known(p) {
            warnings.push(format!(
                "{ctx}: prefix {p:?} matches no rule id in the RoboDR catalog"
            ));
        }
    }
    if problems.len() != before {
        return None;
    }
    Some(Matcher {
        exact: m.rules.iter().cloned().collect(),
        prefixes: m.prefixes.clone(),
        domain: m.domain,
        min_severity: m.min_severity,
        count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(rule: &str) -> String {
        format!(r#"{{"version":1,"rules":[{rule}]}}"#)
    }

    const SEQ: &str = r#"{"id":"robot.correlate.t","title":"T","severity":"high","window_secs":10,
        "pattern":{"kind":"sequence","steps":[{"rules":["robot.ros2.unknown_participant"]},
        {"rules":["robot.ros2.unauthorized_motion_writer"]}]}}"#;

    #[test]
    fn defaults_load_without_warnings() {
        let (set, warnings) = RuleSet::from_json(DEFAULT_RULES_JSON).expect("defaults valid");
        assert!(warnings.is_empty(), "{warnings:?}");
        assert!(set.len() >= 3);
        assert_eq!(RuleSet::default_rules(), set);
    }

    #[test]
    fn minimal_rule_loads() {
        let (set, w) = RuleSet::from_json(&one(SEQ)).unwrap();
        assert!(w.is_empty());
        assert_eq!(set.rules()[0].window_ns(), 10_000_000_000);
        assert_eq!(set.rules()[0].cooldown_ns, 10_000_000_000);
    }

    fn err_of(json: &str) -> String {
        RuleSet::from_json(json).unwrap_err().to_string()
    }

    #[test]
    fn bad_windows_rejected() {
        for w in ["0", "-1", "1e300", "86401", "1e-12"] {
            let j = one(&SEQ.replace(r#""window_secs":10"#, &format!(r#""window_secs":{w}"#)));
            let e = err_of(&j);
            assert!(e.contains("window_secs"), "{w}: {e}");
        }
        // NaN / Infinity are not valid JSON numbers at all.
        let j = one(&SEQ.replace(r#""window_secs":10"#, r#""window_secs":NaN"#));
        assert!(err_of(&j).contains("parse error"));
        let j = one(&SEQ.replace(
            r#""window_secs":10"#,
            r#""window_secs":10,"cooldown_secs":-1"#,
        ));
        assert!(err_of(&j).contains("cooldown_secs"));
        let j = one(&SEQ.replace(
            r#""window_secs":10"#,
            r#""window_secs":10,"cooldown_secs":0"#,
        ));
        assert!(RuleSet::from_json(&j).is_ok());
    }

    #[test]
    fn non_finite_via_struct_rejected() {
        let mut f: RuleFile = serde_json::from_str(&one(SEQ)).unwrap();
        for v in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            f.rules[0].window_secs = v;
            let e = RuleSet::from_file(&f).unwrap_err().to_string();
            assert!(e.contains("not finite"), "{e}");
        }
        f.rules[0].window_secs = 1.0;
        f.rules[0].cooldown_secs = Some(f64::NAN);
        assert!(RuleSet::from_file(&f).is_err());
    }

    #[test]
    fn structural_errors_all_reported() {
        let j = format!(
            r#"{{"version":2,"rules":[{},{}]}}"#,
            SEQ.replace("robot.correlate.t", "Robot.Bad"),
            SEQ.replace("robot.correlate.t", "Robot.Bad")
        );
        let e = RuleSet::from_json(&j).unwrap_err();
        assert!(e.problems.iter().any(|p| p.contains("version")));
        assert!(e.problems.iter().any(|p| p.contains("duplicate")));
        assert!(
            e.problems
                .iter()
                .filter(|p| p.contains("id must be"))
                .count()
                == 2
        );
    }

    #[test]
    fn unknown_fields_and_kinds_rejected() {
        assert!(
            err_of(&one(&SEQ.replace(r#""title":"T""#, r#""title":"T","x":1"#))).contains("parse")
        );
        assert!(err_of(&one(&SEQ.replace("sequence", "telepathy"))).contains("parse"));
        assert!(err_of(r#"{"version":1}"#).contains("parse"));
        assert!(err_of("").contains("parse"));
        assert!(err_of(&"[".repeat(10_000)).contains("parse"));
    }

    #[test]
    fn oversize_file_rejected() {
        let big = " ".repeat(MAX_JSON_BYTES + 1);
        assert!(err_of(&big).contains("bytes"));
    }

    #[test]
    fn self_reference_rejected_and_unknown_warned() {
        let j = one(&SEQ.replace("robot.ros2.unknown_participant", "robot.correlate.t"));
        assert!(err_of(&j).contains("correlation output"));
        let j = one(&SEQ.replace(
            "robot.ros2.unknown_participant",
            "robot.ros2.unknown_participnat",
        ));
        let (_, w) = RuleSet::from_json(&j).unwrap();
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("not in the RoboDR catalog"));
        let j = one(&SEQ.replace(
            r#"{"rules":["robot.ros2.unknown_participant"]}"#,
            r#"{"prefixes":["robot.nothing."]}"#,
        ));
        let (_, w) = RuleSet::from_json(&j).unwrap();
        assert!(w[0].contains("matches no rule id"));
        let j = one(&SEQ.replace(
            r#"{"rules":["robot.ros2.unknown_participant"]}"#,
            r#"{"rules":["robot.ros2.unknown_participant"],"domain":"host"}"#,
        ));
        let (_, w) = RuleSet::from_json(&j).unwrap();
        assert!(w[0].contains("domain"));
    }

    #[test]
    fn matcher_shape_errors() {
        let empty = one(&SEQ.replace(r#"{"rules":["robot.ros2.unknown_participant"]}"#, "{}"));
        assert!(err_of(&empty).contains("at least one of"));
        let empty_id = one(&SEQ.replace("robot.ros2.unknown_participant", ""));
        assert!(err_of(&empty_id).contains("empty"));
        let count_in_seq = one(&SEQ.replace(
            r#"{"rules":["robot.ros2.unknown_participant"]}"#,
            r#"{"rules":["robot.ros2.unknown_participant"],"count":2}"#,
        ));
        assert!(err_of(&count_in_seq).contains("only allowed"));
        let one_step = one(
            r#"{"id":"robot.correlate.t","title":"T","severity":"high","window_secs":1,
            "pattern":{"kind":"sequence","steps":[{"domain":"host"}]}}"#,
        );
        assert!(err_of(&one_step).contains("2..="));
    }

    #[test]
    fn counts_bounded() {
        let t = |n: u32| {
            one(&format!(
                r#"{{"id":"robot.correlate.t","title":"T","severity":"high","window_secs":1,
                "pattern":{{"kind":"threshold","match":{{"domain":"network"}},"count":{n}}}}}"#
            ))
        };
        assert!(RuleSet::from_json(&t(2)).is_ok());
        assert!(RuleSet::from_json(&t(64)).is_ok());
        assert!(RuleSet::from_json(&t(1)).is_err());
        assert!(RuleSet::from_json(&t(65)).is_err());
        let co = one(
            r#"{"id":"robot.correlate.t","title":"T","severity":"high","window_secs":1,
            "pattern":{"kind":"co_occurrence","all_of":[{"domain":"host","count":40},{"domain":"network","count":40}]}}"#,
        );
        assert!(err_of(&co).contains("needs 80 signals"));
        let d = one(
            r#"{"id":"robot.correlate.t","title":"T","severity":"high","window_secs":1,"group_by":"ip",
            "pattern":{"kind":"distinct_sources","match":{"domain":"network"},"distinct_by":"ip","count":3}}"#,
        );
        assert!(err_of(&d).contains("distinct_by equals group_by"));
    }

    #[test]
    fn severity_bump_saturates() {
        assert_eq!(bump(Severity::Low, 0), Severity::Low);
        assert_eq!(bump(Severity::Low, 1), Severity::Medium);
        assert_eq!(bump(Severity::Medium, 3), Severity::Critical);
        assert_eq!(bump(Severity::Critical, 3), Severity::Critical);
        let j = one(&SEQ.replace(
            r#""severity":"high""#,
            r#""severity":"low","escalate_by":4"#,
        ));
        assert!(err_of(&j).contains("escalate_by"));
    }

    #[test]
    fn matcher_semantics() {
        let m = Matcher {
            exact: ["a.b".to_string()].into_iter().collect(),
            prefixes: vec!["c.".into()],
            domain: Some(Domain::Network),
            min_severity: Some(Severity::Medium),
            count: 1,
        };
        assert!(m.matches("a.b", Domain::Network, Severity::Medium));
        assert!(m.matches("c.x", Domain::Network, Severity::Critical));
        assert!(!m.matches("a.b", Domain::Host, Severity::High));
        assert!(!m.matches("a.b", Domain::Network, Severity::Low));
        assert!(!m.matches("a.bc", Domain::Network, Severity::High));
        let any_host = Matcher {
            exact: BTreeSet::new(),
            prefixes: vec![],
            domain: Some(Domain::Host),
            min_severity: None,
            count: 1,
        };
        assert!(any_host.matches("whatever", Domain::Host, Severity::Low));
    }
}
