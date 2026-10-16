//! Stateful responder: escalation timing and boundaries, hold and
//! de-escalation (quiet period, acknowledge), e-stop clearing of the motion
//! guard and rate-limit memory, rate-limit fairness across sources, and a
//! clock that goes backwards (or jumps to the end of time).

mod common;

use common::*;
use robodr_events::{Mode, Severity};
use robodr_responder::escalation::{MAX_REISSUE_KEYS, MAX_SOURCES, MAX_SOURCE_KEY_LEN};
use robodr_responder::*;

const WINDOW: u64 = 10_000;
const QUIET: u64 = 60_000;
const REISSUE: u64 = 2_000;
const SPACING: u64 = 2_500; // > REISSUE, so repeats are never rate limited

/// UGV policy with fast, explicit escalation tuning.
fn esc_policy() -> ResponsePolicy {
    let mut p = validated(PlatformFamily::Ugv);
    p.auto_max_step = Step::SafePause;
    p.escalation = EscalationPolicy {
        window_ms: WINDOW,
        threshold: 3,
        max_escalation_steps: 2,
        ceiling: Step::SafePause,
        quiet_period_ms: QUIET,
        min_reissue_interval_ms: REISSUE,
    };
    p.validate().unwrap();
    p
}

fn responder() -> Responder {
    Responder::new(esc_policy()).unwrap()
}

fn c() -> OperationalContext {
    ctx(PlatformFamily::Ugv)
}

/// Medium in MovingSlow: matrix cell Record, so every rung is escalation.
fn med(r: &mut Responder, src: &str, t: u64) -> ResponsePlan {
    let d = dev("robot.test.med", Severity::Medium, Mode::Enforce);
    let p = r.plan(&d, src, SafetyState::MovingSlow, &c(), t);
    universal_invariants(&p, &d, SafetyState::MovingSlow, &c(), r.policy()).unwrap();
    p
}

fn high(r: &mut Responder, rule: &str, src: &str, state: SafetyState, t: u64) -> ResponsePlan {
    let d = dev(rule, Severity::High, Mode::Enforce);
    let p = r.plan(&d, src, state, &c(), t);
    universal_invariants(&p, &d, state, &c(), r.policy()).unwrap();
    p
}

// ---------------------------------------------------------------- escalation

#[test]
fn threshold_hits_inside_the_window_escalate_one_rung_at_a_time() {
    let mut r = responder();
    let steps: Vec<Step> = (0..9)
        .map(|k| med(&mut r, "a", k * SPACING).max_step)
        .collect();
    use Step::*;
    assert_eq!(
        steps,
        vec![
            Record,
            Record,
            Restrict, // 3rd hit: +1
            Restrict,
            Restrict,
            LimitMotion, // 6th hit: +2
            LimitMotion,
            LimitMotion,
            LimitMotion, // capped at max_escalation_steps = 2
        ]
    );
    assert_eq!(r.escalation_level("a"), 2);
    // Another source is untouched.
    assert_eq!(r.escalation_level("b"), 0);
    assert_eq!(med(&mut r, "b", 9 * SPACING).max_step, Record);
}

#[test]
fn window_boundary_is_exclusive() {
    // Hits at 0, 5000, WINDOW-1: all inside => escalates.
    let mut r = responder();
    med(&mut r, "a", 0);
    med(&mut r, "a", 5_000);
    assert_eq!(med(&mut r, "a", WINDOW - 1).max_step, Step::Restrict);
    assert_eq!(r.escalation_level("a"), 1);

    // Hits at 0, 5000, WINDOW: the first has aged out => no escalation.
    let mut r = responder();
    med(&mut r, "a", 0);
    med(&mut r, "a", 5_000);
    assert_eq!(med(&mut r, "a", WINDOW).max_step, Step::Record);
    assert_eq!(r.escalation_level("a"), 0);
}

#[test]
fn hits_spaced_wider_than_the_window_never_escalate() {
    let mut r = responder();
    for k in 0..50 {
        let p = med(&mut r, "slow-drip", k * (WINDOW / 2 + 1));
        assert_eq!(p.max_step, Step::Record, "k={k}");
    }
    assert_eq!(r.escalation_level("slow-drip"), 0);
}

#[test]
fn escalation_is_bounded_by_the_ceiling_and_rule_cap() {
    let mut p = esc_policy();
    p.escalation.ceiling = Step::Restrict;
    let mut r = Responder::new(p).unwrap();
    for k in 0..30 {
        let q = med(&mut r, "a", k * SPACING);
        assert!(q.max_step <= Step::Restrict, "k={k}");
    }
    // A Critical in MovingFast is already RequestSafeState by matrix: the
    // ceiling never lowers a matrix decision.
    let d = dev("x", Severity::Critical, Mode::Enforce);
    let q = r.plan(&d, "a", SafetyState::MovingFast, &c(), 1_000_000);
    assert_eq!(q.max_step, Step::RequestSafeState);
    assert!(q.requires_human_approval);
}

// ------------------------------------------------------- hold & de-escalation

fn escalate_to_limit(r: &mut Responder, src: &str) -> u64 {
    for k in 0..6 {
        med(r, src, k * SPACING);
    }
    assert_eq!(r.escalation_level(src), 2);
    5 * SPACING
}

#[test]
fn hold_keeps_the_earned_step_for_lower_severities() {
    let mut r = responder();
    let t = escalate_to_limit(&mut r, "a");
    let d = dev("robot.test.low", Severity::Low, Mode::Enforce);
    let p = r.plan(&d, "a", SafetyState::MovingSlow, &c(), t + SPACING);
    assert_eq!(p.max_step, Step::LimitMotion);
    assert!(p
        .rationale
        .contains(|x| matches!(x, Reason::Held { .. } | Reason::Escalated { .. })));
}

#[test]
fn quiet_period_resets_exactly_at_the_boundary() {
    let mut r = responder();
    let last = escalate_to_limit(&mut r, "a");
    // Observe-mode probes read the state without changing it.
    let probe = |r: &mut Responder, t| {
        let d = dev("robot.test.low", Severity::Low, Mode::Observe);
        let p = r.plan(&d, "a", SafetyState::MovingSlow, &c(), t);
        assert!(p.observe_only && is_record_only(&p));
        p.would_have.unwrap().max_step
    };
    assert_eq!(probe(&mut r, last + QUIET - 1), Step::LimitMotion);
    assert_eq!(probe(&mut r, last + QUIET), Step::Record);
    // The probes did not refresh last_seen: an enforce plan at the boundary
    // starts from scratch.
    let p = med(&mut r, "a", last + QUIET);
    assert_eq!(p.max_step, Step::Record);
    assert_eq!(r.escalation_level("a"), 0);
}

#[test]
fn activity_inside_the_quiet_period_keeps_the_hold() {
    let mut r = responder();
    let mut t = escalate_to_limit(&mut r, "a");
    // One deviation every QUIET-1 ms for a long time: never de-escalates.
    for _ in 0..20 {
        t += QUIET - 1;
        assert_eq!(med(&mut r, "a", t).max_step, Step::LimitMotion);
    }
}

#[test]
fn acknowledge_one_source_resets_only_that_source() {
    let mut r = responder();
    let t = escalate_to_limit(&mut r, "a");
    for k in 0..3 {
        med(&mut r, "b", k * SPACING);
    }
    assert_eq!(r.escalation_level("b"), 1);
    assert!(r.acknowledge(Some("a"), t));
    assert_eq!(r.escalation_level("a"), 0);
    assert_eq!(r.escalation_level("b"), 1);
    assert_eq!(med(&mut r, "a", t + SPACING).max_step, Step::Record);
    assert_eq!(med(&mut r, "b", t + SPACING).max_step, Step::Restrict);
}

#[test]
fn acknowledge_return_values() {
    let mut r = responder();
    assert!(!r.acknowledge(None, 0), "nothing to reset");
    assert!(!r.acknowledge(Some("never-seen"), 0));
    med(&mut r, "a", 1);
    assert!(r.acknowledge(Some("a"), 2), "tracked source");
    assert!(
        r.acknowledge(None, 3),
        "source still tracked (reset, not removed)"
    );
    assert!(!r.acknowledge(None, 4), "second global ack is a no-op");
    assert_eq!(r.tracked_sources(), 0);
    assert_eq!(r.rate_limit_entries(), 0);
}

#[test]
fn acknowledge_clears_the_rate_limit_for_that_source() {
    let mut r = responder();
    let s = SafetyState::MovingFast;
    assert!(is_eligible(&high(&mut r, "rule", "a", s, 0)));
    assert!(high(&mut r, "rule", "a", s, 100).suppressed);
    r.acknowledge(Some("a"), 200);
    let p = high(&mut r, "rule", "a", s, 300);
    assert!(!p.suppressed && is_eligible(&p) && has_limit(&p));
}

// ------------------------------------------------------------ e-stop clearing

#[test]
fn estop_is_record_only_for_an_escalated_source_and_the_hold_survives() {
    let mut r = responder();
    let t = escalate_to_limit(&mut r, "a");
    for state in [SafetyState::EStopActive, SafetyState::SafeStateActive] {
        for sev in SEVERITIES {
            let d = dev("robot.test.x", sev, Mode::Enforce);
            let p = r.plan(&d, "a", state, &c(), t + 1);
            assert!(is_record_only(&p), "{state:?} {sev:?}");
            assert!(p
                .rationale
                .contains(|x| *x == Reason::SafetySystemHasAuthority));
            universal_invariants(&p, &d, state, &c(), r.policy()).unwrap();
        }
    }
    // E-stop released (operator restart): the source's hold is still there
    // until an operator acknowledges it.
    assert_eq!(
        med(&mut r, "a", t + 2 * SPACING).max_step,
        Step::LimitMotion
    );
    r.acknowledge(Some("a"), t + 3 * SPACING);
    assert_eq!(med(&mut r, "a", t + 4 * SPACING).max_step, Step::Record);
}

#[test]
fn estop_clears_the_motion_guard_and_lowers_rate_limit_memory() {
    let mut r = responder();
    let s = SafetyState::MovingFast;
    let a = high(&mut r, "rule", "A", s, 0);
    assert!(is_eligible(&a) && has_limit(&a));
    // B, same severity and step within the guard: motion part dropped,
    // Restrict kept, not suppressed.
    let b = high(&mut r, "rule", "B", s, 100);
    assert!(!b.suppressed && has_restrict(&b) && !has_limit(&b));
    assert!(b
        .rationale
        .contains(|x| matches!(x, Reason::MotionAlreadyRequested { .. })));
    // Platform takes its safe state.
    let e = high(&mut r, "rule", "C", SafetyState::EStopActive, 200);
    assert!(is_record_only(&e));
    // After restart, both A and B get their motion request again (the old
    // one is no longer in force), neither is suppressed.
    let a2 = high(&mut r, "rule", "A", s, 300);
    assert!(!a2.suppressed && has_limit(&a2), "{a2:#?}");
    let b2 = high(&mut r, "rule", "B", s, 400);
    // A re-established the guard at 300; B's Restrict is still there.
    assert!(!b2.suppressed && has_restrict(&b2), "{b2:#?}");
}

#[test]
fn global_acknowledge_clears_the_motion_guard() {
    let mut r = responder();
    let s = SafetyState::MovingFast;
    high(&mut r, "rule", "A", s, 0);
    assert!(!has_limit(&high(&mut r, "rule", "B", s, 10)));
    assert!(r.acknowledge(None, 20));
    assert!(has_limit(&high(&mut r, "rule", "B", s, 30)));
}

#[test]
fn motion_guard_never_outlives_its_window() {
    let mut r = responder();
    let s = SafetyState::MovingFast;
    high(&mut r, "rule", "A", s, 0);
    assert!(!has_limit(&high(&mut r, "rule", "B", s, REISSUE - 1)));
    assert!(has_limit(&high(&mut r, "rule", "C", s, 2 * REISSUE)));
}

// ------------------------------------------------------ rate-limit fairness

#[test]
fn same_source_and_rule_is_rate_limited_until_the_interval_elapses() {
    let mut r = responder();
    let s = SafetyState::MovingFast;
    assert!(is_eligible(&high(&mut r, "rule", "a", s, 0)));
    let q = high(&mut r, "rule", "a", s, REISSUE - 1);
    assert!(q.suppressed && is_record_only(&q));
    assert!(q.rationale.contains(|x| *x
        == Reason::RateLimited {
            since_ms: REISSUE - 1
        }));
    // A different rule from the same source is not suppressed.
    assert!(!high(&mut r, "other-rule", "a", s, REISSUE - 1).suppressed);
    // After the interval it is issued again.
    assert!(!high(&mut r, "rule", "a", s, REISSUE).suppressed);
}

#[test]
fn attacker_flooding_a_rule_cannot_suppress_another_sources_response() {
    let mut r = responder();
    let s = SafetyState::MovingFast;
    let mut t = 0;
    for round in 0..200u64 {
        // Attacker: same rule, every ms, a few times per round.
        for _ in 0..5 {
            high(&mut r, "robot.shared.rule", "attacker", s, t);
            t += 1;
        }
        // Legit source, same rule and severity, fresh after each interval.
        if round % 50 == 0 {
            let p = high(&mut r, "robot.shared.rule", "legit", s, t);
            assert!(!p.suppressed, "round {round}: {p:#?}");
            assert!(has_restrict(&p), "round {round}");
            assert_eq!(p.source, "legit");
            t += REISSUE; // let the legit entry expire
        }
    }
}

#[test]
fn approval_pending_decoys_from_fresh_keys_never_suppress_or_downgrade() {
    let mut r = responder();
    let crit = dev("robot.decoy", Severity::Critical, Mode::Enforce);
    for k in 0..500u64 {
        let p = r.plan(
            &crit,
            &format!("decoy-{k}"),
            SafetyState::MovingFast,
            &c(),
            k * 3,
        );
        assert!(p.requires_human_approval);
    }
    let p = high(&mut r, "robot.real", "real", SafetyState::MovingFast, 1_500);
    assert!(
        is_eligible(&p) && has_limit(&p) && has_restrict(&p),
        "{p:#?}"
    );
}

#[test]
fn fresh_key_flood_is_bounded_and_keeps_real_offenders_state() {
    let mut r = responder();
    // A real offender escalates first.
    escalate_to_limit(&mut r, "real");
    let t0 = 5 * SPACING + 1;
    for k in 0..10_000u64 {
        let p = high(
            &mut r,
            "flood",
            &format!("f{k}"),
            SafetyState::MovingFast,
            t0 + k,
        );
        assert!(!p.observe_only);
    }
    assert!(r.tracked_sources() <= MAX_SOURCES);
    assert!(r.rate_limit_entries() <= MAX_REISSUE_KEYS);
    // The real offender was not evicted.
    assert_eq!(r.escalation_level("real"), 2);
    // A new real source after the table filled still gets an automatic
    // response (never pushed into approval by the shared overflow bucket).
    let p = high(
        &mut r,
        "robot.new",
        "late-real",
        SafetyState::MovingSlow,
        t0 + 20_000,
    );
    assert!(is_eligible(&p) && has_restrict(&p), "{p:#?}");
}

#[test]
fn long_keys_sharing_a_prefix_are_distinct_sources() {
    let mut r = responder();
    let prefix = "p".repeat(MAX_SOURCE_KEY_LEN * 2);
    let legit = format!("{prefix}/legit");
    let evil = format!("{prefix}/evil");
    let s = SafetyState::MovingFast;
    for t in 0..50 {
        high(&mut r, "rule", &evil, s, t);
    }
    let p = high(&mut r, "rule", &legit, s, 60);
    assert!(!p.suppressed, "{p:#?}");
    assert!(has_restrict(&p));
    // The plan carries the plain truncated key.
    assert_eq!(p.source.len(), MAX_SOURCE_KEY_LEN);
    // Multi-byte chars at the cut never panic.
    let emoji = "💥".repeat(200);
    let q = high(&mut r, "rule", &emoji, s, 70);
    assert!(q.source.len() <= MAX_SOURCE_KEY_LEN);
    assert!(emoji.starts_with(&q.source));
}

#[test]
fn overflow_key_literal_is_not_a_backdoor() {
    let mut r = responder();
    let p = high(
        &mut r,
        "rule",
        robodr_responder::escalation::OVERFLOW_SOURCE,
        SafetyState::MovingSlow,
        0,
    );
    assert!(is_eligible(&p));
    let q = high(&mut r, "rule", "someone-else", SafetyState::MovingSlow, 1);
    assert!(!q.suppressed);
}

#[test]
fn observe_mode_deviations_change_no_state() {
    let mut r = responder();
    for k in 0..100u64 {
        let d = dev("rule", Severity::Critical, Mode::Observe);
        let p = r.plan(&d, &format!("s{k}"), SafetyState::MovingFast, &c(), k);
        assert!(p.observe_only && is_record_only(&p));
    }
    assert_eq!(r.tracked_sources(), 0);
    assert_eq!(r.rate_limit_entries(), 0);
    // And they never suppress a later enforce plan.
    assert!(is_eligible(&high(
        &mut r,
        "rule",
        "s0",
        SafetyState::MovingFast,
        200
    )));
}

// ------------------------------------------------------------- clock handling

#[test]
fn clock_going_backwards_counts_as_no_time_elapsed() {
    // No escalation in this test, so only the rate limit is observed.
    let mut pol = esc_policy();
    pol.escalation.threshold = 64;
    let mut r = Responder::new(pol).unwrap();
    let s = SafetyState::MovingFast;
    assert!(is_eligible(&high(&mut r, "rule", "a", s, 100_000)));
    // Back in time: the rate limit still holds (no wrap-around, no reset).
    let q = high(&mut r, "rule", "a", s, 50_000);
    assert!(q.suppressed);
    assert!(q
        .rationale
        .contains(|x| *x == Reason::RateLimited { since_ms: 0 }));
    let q = high(&mut r, "rule", "a", s, 0);
    assert!(q.suppressed);
    // The interval is measured from the latest time seen.
    assert!(!high(&mut r, "rule", "a", s, 100_000 + REISSUE).suppressed);
}

#[test]
fn backwards_timestamps_cannot_evade_escalation() {
    let mut r = responder();
    med(&mut r, "a", 1_000_000);
    // An attacker replaying "old" timestamps: they count at the current time.
    med(&mut r, "a", 0);
    let p = med(&mut r, "a", 3);
    assert_eq!(p.max_step, Step::Restrict);
    assert_eq!(r.escalation_level("a"), 1);
}

#[test]
fn backwards_timestamps_cannot_trigger_de_escalation() {
    let mut r = responder();
    let t = escalate_to_limit(&mut r, "a");
    for back in [0, 1, t / 2, t] {
        let p = med(&mut r, "a", back);
        // Either the held step again, or rate limited because it is still
        // in force: never a lower step.
        assert!(p.max_step == Step::LimitMotion || p.suppressed, "{p:#?}");
        assert_eq!(r.escalation_level("a"), 2);
    }
    assert_eq!(med(&mut r, "a", t + REISSUE).max_step, Step::LimitMotion);
}

#[test]
fn extreme_timestamps_never_panic() {
    let mut r = responder();
    for t in [u64::MAX, 0, u64::MAX - 1, 1, u64::MAX] {
        for state in SafetyState::ALL {
            let d = dev("rule", Severity::Critical, Mode::Enforce);
            let p = r.plan(&d, "a", state, &c(), t);
            universal_invariants(&p, &d, state, &c(), r.policy()).unwrap();
        }
        r.acknowledge(Some("a"), t);
    }
}

/// A forward jump to the end of time freezes the responder's clock (it never
/// goes back). Documented behaviour: no time elapses afterwards, so holds
/// never expire and the same (source, rule) stays rate limited — fail-active
/// (the earlier request is still in force) — until an operator acknowledges.
#[test]
fn clock_frozen_at_the_end_of_time_fails_active_until_acknowledged() {
    let mut r = responder();
    let s = SafetyState::MovingFast;
    assert!(is_eligible(&high(&mut r, "rule", "a", s, u64::MAX)));
    assert!(high(&mut r, "rule", "a", s, 5).suppressed);
    // Other sources still get their own response.
    assert!(has_restrict(&high(&mut r, "rule", "b", s, 6)));
    assert!(r.acknowledge(None, 7));
    assert!(is_eligible(&high(&mut r, "rule", "a", s, 8)));
}

/// A large forward jump is indistinguishable from a quiet period and
/// de-escalates (documented in the crate; the agent's TimeGuard does not
/// detect a monotonic forward jump either).
#[test]
fn forward_jump_past_the_quiet_period_de_escalates() {
    let mut r = responder();
    let t = escalate_to_limit(&mut r, "a");
    assert_eq!(med(&mut r, "a", t + QUIET).max_step, Step::Record);
}
