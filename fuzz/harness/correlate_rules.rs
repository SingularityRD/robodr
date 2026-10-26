//! Harness: correlation rule JSON (`robodr_correlate::RuleSet::from_json`)
//! and the engine driven by those rules.
//!
//! Input: `rules JSON \0 signal bytes`. The JSON is parsed and validated;
//! when it is rejected, the shipped default rules drive the engine instead,
//! so mutations of the signal bytes still reach it. Signal bytes are 4-byte
//! records `dt rule sev_mode entity`: time advances by `dt` (scaled, with
//! occasional regressions), `rule` picks from a vocabulary made of every
//! string in the rule file (ids, prefixes, titles) plus a fixed list of
//! real deviation / Pulsar rule names, `sev_mode` sets severity, observe
//! mode and the domain, `entity` adds up to two entities from small pools.
//!
//! Invariants beyond "no panic":
//!
//! * an accepted file survives serialise -> parse -> validate with the same
//!   rule count; every accepted rule id
//!   carries `robot.correlate.`, its window is in `(0, 1 day]`, and its
//!   output severity is never below its input severity;
//! * every correlated finding: rule from the set, window equal to the rule's,
//!   at least two contributors with strictly increasing `seq` ending at the
//!   current signal, contributors within the window, severity >= every
//!   contributor's, observe-only iff a contributor was, no contributor is a
//!   correlated finding itself, bounded entities, the group entity on every
//!   contributor;
//! * group tables stay within `max_groups_per_rule`; counters add up.
//!
//! Shared via `#[path]` with `crates/robodr-correlate/tests/fuzz_smoke.rs`.
#![allow(dead_code)]

use robodr_correlate::{
    CorrelatedFinding, Correlator, Domain, EntityKind, Limits, RuleFile, RuleSet, Signal,
    RULE_ID_PREFIX,
};
use robodr_events::{Mode, Severity};

const S: u64 = 1_000_000_000;
const MAX_SIGNALS: usize = 512;

const VOCAB: &[&str] = &[
    "robot.ros2.unknown_participant",
    "robot.ros2.unauthorized_motion_writer",
    "robot.ros2.participant_source_mismatch",
    "robot.capture.ip_fragment_refused",
    "robot.rtps.discovery_fragment_rejected",
    "robot.motion.uncommanded_motion",
    "robot.firewall.rejected_unknown_source",
    "robot.correlate.coordinated_intrusion",
    "RoboDR: Interactive shell started on robot controller",
    "RoboDR: SROS 2 enclave private key read by a process outside the ROS stack",
    "Some other Pulsar rule",
    "",
];

const SEVS: [Severity; 4] = [
    Severity::Low,
    Severity::Medium,
    Severity::High,
    Severity::Critical,
];

fn strings_of(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(a) => a.iter().for_each(|x| strings_of(x, out)),
        serde_json::Value::Object(o) => o.values().for_each(|x| strings_of(x, out)),
        _ => {}
    }
}

pub fn run(data: &[u8]) {
    let _ = run_counting(data);
}

/// [`run`], returning `(rules accepted, findings produced)` (seed checks).
pub fn run_counting(data: &[u8]) -> (bool, u64) {
    let (json, sigs) = match data.iter().position(|&b| b == 0) {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, &[][..]),
    };
    let mut vocab: Vec<String> = VOCAB.iter().map(|s| s.to_string()).collect();
    let mut rules = None;
    if let Ok(text) = std::str::from_utf8(json) {
        let first = RuleSet::from_json(text);
        if let Ok(file) = serde_json::from_str::<RuleFile>(text) {
            if let Ok(v) = serde_json::to_value(&file) {
                strings_of(&v, &mut vocab);
            }
        }
        if let Ok((set, _warnings)) = first {
            check_set(&set);
            let file: RuleFile = serde_json::from_str(text).expect("accepted file parses");
            let again = serde_json::to_string(&file).expect("serialises");
            let (set2, _) = RuleSet::from_json(&again).expect("round trip validates");
            assert_eq!(set.len(), set2.len());
            rules = Some(set);
        }
    }
    vocab.truncate(256);
    let accepted = rules.is_some();
    let rules = rules.unwrap_or_else(RuleSet::default_rules);
    let limits = Limits {
        max_groups_per_rule: 1 + sigs.first().map_or(0, |&b| usize::from(b % 8)),
        ..Limits::default()
    };
    (accepted, drive(rules, limits, sigs, &vocab))
}

fn check_set(set: &RuleSet) {
    assert!(set.len() <= robodr_correlate::rules::MAX_RULES);
    for r in set.rules() {
        assert!(r.id().starts_with(RULE_ID_PREFIX), "{}", r.id());
        assert!(
            r.window_ns() > 0 && r.window_ns() <= 86_400 * S,
            "{}",
            r.window_ns()
        );
        for s in SEVS {
            assert!(r.output_severity(s) >= s);
        }
    }
}

fn drive(rules: RuleSet, limits: Limits, sigs: &[u8], vocab: &[String]) -> u64 {
    let mut c = Correlator::new(rules, limits);
    let windows: Vec<(String, u64)> = c
        .rules()
        .iter()
        .map(|r| (r.id().to_string(), r.window_ns()))
        .collect();
    let mut t: u64 = 1_000 * S;
    let mut found_total = 0u64;
    let mut n = 0u64;
    for rec in sigs.chunks_exact(4).take(MAX_SIGNALS) {
        let (dt, ri, sm, en) = (rec[0], rec[1], rec[2], rec[3]);
        t = match dt {
            0xff => t.saturating_sub(30 * S),
            0xfe => u64::MAX - S,
            0xfd => 0,
            d => t.saturating_add(u64::from(d) * S / 4),
        };
        let rule = &vocab[usize::from(ri) % vocab.len()];
        let sev = SEVS[usize::from(sm & 3)];
        let mut s = Signal::new(t, rule.clone(), sev);
        if sm & 4 != 0 {
            s = s.with_mode(Mode::Observe);
        }
        if sm & 8 != 0 {
            s = Signal::host(t, rule.clone(), sev).with_mode(s.mode);
        }
        if sm & 16 != 0 {
            s.domain = Domain::Network;
        }
        for (i, kind) in [EntityKind::Ip, EntityKind::Participant]
            .into_iter()
            .enumerate()
        {
            let bits = (en >> (i * 4)) & 0x0f;
            if bits != 0 {
                s = s.with_entity(kind, format!("{}-{}", kind.as_str(), bits % 5));
            }
        }
        if en == 0xff {
            s = s.with_entity(EntityKind::Process, "é".repeat(300));
        }
        n += 1;
        let found = c.observe(&s);
        let now = c.now();
        for f in &found {
            check_finding(f, &windows, now, n);
        }
        found_total += found.len() as u64;
        for (id, _) in &windows {
            assert!(c.groups_of(id) <= limits.max_groups_per_rule.max(1));
        }
        if n.is_multiple_of(64) {
            c.tick(t);
        }
        for notice in c.take_notices() {
            assert!(notice.rule.starts_with(RULE_ID_PREFIX));
        }
    }
    assert_eq!(c.stats().signals, n);
    assert_eq!(c.stats().findings, found_total);
    found_total
}

fn check_finding(f: &CorrelatedFinding, windows: &[(String, u64)], now: Option<u64>, seq: u64) {
    assert!(f.rule.starts_with(RULE_ID_PREFIX));
    let window = windows
        .iter()
        .find(|(id, _)| *id == f.rule)
        .expect("finding of a rule in the set")
        .1;
    assert_eq!(f.window_ns, window);
    assert_eq!(Some(f.at_ns), now);
    assert!(f.contributors.len() >= 2, "{f:?}");
    let seqs: Vec<u64> = f.contributors.iter().map(|c| c.seq).collect();
    assert!(seqs.windows(2).all(|w| w[0] < w[1]), "{seqs:?}");
    assert_eq!(seqs.last().copied(), Some(seq));
    let min = f.contributors.iter().map(|c| c.at_ns).min().unwrap_or(0);
    let max = f.contributors.iter().map(|c| c.at_ns).max().unwrap_or(0);
    assert!(max - min <= window, "{f:?}");
    assert_eq!(max, f.at_ns);
    let max_sev = f
        .contributors
        .iter()
        .map(|c| c.severity)
        .max()
        .unwrap_or(Severity::Low);
    assert!(f.severity >= max_sev);
    let observe = f.contributors.iter().any(|c| c.mode == Mode::Observe);
    assert_eq!(f.mode == Mode::Observe, observe);
    for c in &f.contributors {
        assert!(!c.rule.starts_with(RULE_ID_PREFIX));
        assert!(c.entities.len() <= 8);
        assert!(c.entities.iter().all(|e| e.value.len() <= 256));
        assert!(c.at_ns >= c.t_ns);
    }
    if let Some(g) = &f.group {
        for c in &f.contributors {
            assert!(c.entities.contains(g));
        }
    }
}
