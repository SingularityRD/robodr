//! Engine semantics on small custom rule sets.

use robodr_correlate::{Correlator, EntityKind, Limits, RuleSet, Signal};
use robodr_events::Severity;

const S: u64 = 1_000_000_000;

fn engine(pattern: &str, window: f64, group_by: &str) -> Correlator {
    let json = format!(
        r#"{{"version":1,"rules":[{{"id":"robot.correlate.t","title":"T","severity":"low",
        "window_secs":{window},"cooldown_secs":0,"group_by":{group_by},"pattern":{pattern}}}]}}"#
    );
    let (set, _) = RuleSet::from_json(&json).unwrap();
    Correlator::new(set, Limits::default())
}

fn sig(t: u64, rule: &str) -> Signal {
    Signal::new(t, rule, Severity::Low)
}

#[test]
fn one_signal_never_fills_two_steps() {
    let mut c = engine(
        r#"{"kind":"sequence","steps":[{"prefixes":["robot.ros2."]},{"prefixes":["robot.ros2."]}]}"#,
        10.0,
        "null",
    );
    assert!(c.observe(&sig(0, "robot.ros2.unknown_reader")).is_empty());
    let f = c.observe(&sig(S, "robot.ros2.unknown_reader"));
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].contributors.len(), 2);
    // Cooldown 0: the state was consumed, the next one starts afresh.
    assert!(c
        .observe(&sig(2 * S, "robot.ros2.unknown_reader"))
        .is_empty());
}

#[test]
fn sequence_keeps_latest_start() {
    // A, A, B, C: the window is measured from the *latest* usable A.
    let mut c = engine(
        r#"{"kind":"sequence","steps":[{"rules":["robot.a"]},{"rules":["robot.b"]},{"rules":["robot.c"]}]}"#,
        10.0,
        "null",
    );
    c.observe(&sig(0, "robot.a"));
    c.observe(&sig(8 * S, "robot.a"));
    c.observe(&sig(9 * S, "robot.b"));
    let f = c.observe(&sig(17 * S, "robot.c"));
    assert_eq!(f.len(), 1);
    let ts: Vec<u64> = f[0].contributors.iter().map(|x| x.t_ns).collect();
    assert_eq!(ts, [8 * S, 9 * S, 17 * S]);
}

#[test]
fn sequence_steps_out_of_order_do_not_fire() {
    let mut c = engine(
        r#"{"kind":"sequence","steps":[{"rules":["robot.a"]},{"rules":["robot.b"]},{"rules":["robot.c"]}]}"#,
        10.0,
        "null",
    );
    for r in ["robot.c", "robot.b", "robot.a", "robot.c"] {
        assert!(c.observe(&sig(S, r)).is_empty());
    }
    assert_eq!(c.observe(&sig(S, "robot.b")).len(), 0);
    assert_eq!(c.observe(&sig(S, "robot.c")).len(), 1);
}

#[test]
fn co_occurrence_signal_counts_once() {
    // Both slots accept the same rule: one signal fills one slot only.
    let mut c = engine(
        r#"{"kind":"co_occurrence","all_of":[{"rules":["robot.a"]},{"rules":["robot.a","robot.b"]}]}"#,
        10.0,
        "null",
    );
    assert!(c.observe(&sig(0, "robot.a")).is_empty());
    let f = c.observe(&sig(S, "robot.a"));
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].contributors.len(), 2);
}

#[test]
fn distinct_sources_refresh_and_expiry() {
    let mut c = engine(
        r#"{"kind":"distinct_sources","match":{"rules":["robot.a"]},"distinct_by":"ip","count":3}"#,
        10.0,
        "null",
    );
    let s = |t, ip: &str| sig(t, "robot.a").with_entity(EntityKind::Ip, ip);
    c.observe(&s(0, "1"));
    c.observe(&s(5 * S, "2"));
    c.observe(&s(9 * S, "1")); // refreshes "1"
    let f = c.observe(&s(12 * S, "3")); // "1" (9 s) and "2" (5 s) still live
    assert_eq!(f.len(), 1);
    let mut c = engine(
        r#"{"kind":"distinct_sources","match":{"rules":["robot.a"]},"distinct_by":"ip","count":3}"#,
        10.0,
        "null",
    );
    c.observe(&s(0, "1"));
    c.observe(&s(5 * S, "2"));
    assert!(c.observe(&s(11 * S, "3")).is_empty(), "\"1\" expired");
}

#[test]
fn signal_in_several_groups() {
    let mut c = engine(
        r#"{"kind":"threshold","match":{"rules":["robot.a"]},"count":2}"#,
        10.0,
        "\"ip\"",
    );
    let both = sig(0, "robot.a")
        .with_entity(EntityKind::Ip, "1")
        .with_entity(EntityKind::Ip, "2");
    c.observe(&both);
    let f = c.observe(&both.clone());
    assert_eq!(f.len(), 2, "one finding per group");
    assert_eq!(f[0].group.as_ref().unwrap().value, "1");
    assert_eq!(f[1].group.as_ref().unwrap().value, "2");
}

#[test]
fn zero_group_cap_is_treated_as_one() {
    let (set, _) = RuleSet::from_json(robodr_correlate::DEFAULT_RULES_JSON).unwrap();
    let mut c = Correlator::new(
        set,
        Limits {
            max_groups_per_rule: 0,
            max_entities_per_signal: 0,
            max_value_len: 0,
            protected_reserve_pct: 0,
        },
    );
    assert_eq!(c.limits().max_groups_per_rule, 1);
    let s = Signal::new(0, "robot.ros2.unknown_participant", Severity::High)
        .with_entity(EntityKind::Ip, "1.2.3.4");
    c.observe(&s);
    assert_eq!(c.stats().entities_dropped, 1);
}
