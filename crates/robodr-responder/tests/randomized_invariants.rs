//! Property-style tests: random (but seeded, std-only xorshift) policies and
//! long random sequences of deviations, safety states, contexts, clock
//! steps (including backwards and huge jumps), hostile source keys and
//! operator acknowledgements. After every plan the invariants are checked;
//! every sequence is replayed on a second responder and must give identical
//! plans.

mod common;

use std::collections::HashSet;

use common::*;
use robodr_events::{Deviation, Mode};
use robodr_responder::escalation::{MAX_REISSUE_KEYS, MAX_SOURCES, OVERFLOW_SOURCE};
use robodr_responder::*;

const SEEDS: u64 = 48;
const OPS_PER_SEED: usize = 1_500;

fn random_policy(rng: &mut XorShift) -> ResponsePolicy {
    let platform = *rng.pick(&PlatformFamily::ALL);
    let mut p = ResponsePolicy::conservative_default(platform);
    p.oem_validated = !rng.chance(1, 8);
    p.morphology = *rng.pick(&Morphology::ALL);
    let row = |rng: &mut XorShift| SeverityRow {
        low: *rng.pick(&Step::ALL),
        medium: *rng.pick(&Step::ALL),
        high: *rng.pick(&Step::ALL),
        critical: *rng.pick(&Step::ALL),
    };
    p.matrix.idle = row(rng);
    p.matrix.moving_slow = row(rng);
    p.matrix.moving_fast = row(rng);
    p.matrix.collaborative_human_nearby = row(rng);
    p.matrix.unknown = row(rng);
    p.auto_max_step = *rng.pick(&Step::ALL);
    if p.morphology.is_unspecified() && (p.oem_validated || platform == PlatformFamily::Other) {
        p.morphology = stable(platform);
    }
    p.allow_terminate_when_idle = rng.chance(1, 2) && !p.morphology.needs_active_balance();
    p.limit_motion_factor = (rng.below(1000) + 1) as f64 / 1000.0;
    p.min_motion_factor = (rng.below(451) + 50) as f64 / 1000.0;
    if p.morphology.needs_active_balance() {
        p.limit_motion_factor = p.limit_motion_factor.max(p.min_motion_factor);
    }
    if p.morphology.falls_when_de_energised() && rng.chance(1, 2) {
        p.fall_safe_restrict = vec![RestrictTarget::Network];
    }
    let mut targets: Vec<RestrictTarget> = RestrictTarget::ALL
        .into_iter()
        .filter(|_| rng.chance(1, 2))
        .collect();
    if targets.is_empty() {
        targets.push(RestrictTarget::Process);
    }
    p.default_restrict = targets;
    let valid: Vec<SafeBehaviour> = SafeBehaviour::ALL
        .into_iter()
        .filter(|b| b.allowed_for(platform))
        .collect();
    p.safe_pause = *rng.pick(&valid);
    p.safe_state = *rng.pick(&valid);
    let lo = *rng.pick(&Step::ALL);
    let hi = *rng.pick(&Step::ALL);
    p.rule_overrides = vec![RuleOverride {
        rule: "rule.override".into(),
        min_step: lo.min(hi),
        max_step: lo.max(hi),
        restrict: rng.chance(1, 2).then(|| vec![RestrictTarget::Process]),
    }];
    let window = 1 + rng.below(20_000);
    let quiet = window + rng.below(100_000);
    p.escalation = EscalationPolicy {
        window_ms: window,
        threshold: 2 + rng.below(4) as u32,
        max_escalation_steps: rng.below(3) as u8,
        ceiling: *rng.pick(&Step::ALL),
        quiet_period_ms: quiet,
        min_reissue_interval_ms: rng.below(quiet.min(10_000) + 1),
    };
    p.validate().expect("generated policy must be valid");
    p
}

#[derive(Debug, Clone)]
enum Op {
    Plan {
        dev: Deviation,
        source: String,
        state: SafetyState,
        ctx: OperationalContext,
        t: u64,
    },
    Ack {
        source: Option<String>,
        t: u64,
    },
}

fn random_ops(rng: &mut XorShift, policy: &ResponsePolicy) -> Vec<Op> {
    let long_a = format!("{}A", "L".repeat(300));
    let long_b = format!("{}B", "L".repeat(300));
    let fixed: Vec<String> = vec![
        "a".into(),
        "b".into(),
        "c".into(),
        long_a,
        long_b,
        "ü".repeat(100),
        OVERFLOW_SOURCE.into(),
        String::new(),
    ];
    let rules = ["rule.a", "rule.b", "rule.override", ""];
    let mut ops = Vec::with_capacity(OPS_PER_SEED);
    let mut t: u64 = rng.below(1_000);
    let mut fresh = 0u64;
    for _ in 0..OPS_PER_SEED {
        // Clock: mostly small forward steps, sometimes backwards, sometimes
        // a big jump, rarely the end of time.
        t = match rng.below(100) {
            0..=79 => t.saturating_add(rng.below(1_500)),
            80..=91 => t.saturating_sub(rng.below(60_000)),
            92..=98 => t.saturating_add(rng.below(400_000)),
            _ => u64::MAX - rng.below(3),
        };
        let source = if rng.chance(1, 5) {
            fresh += 1;
            format!("fresh-{fresh}")
        } else {
            rng.pick(&fixed).clone()
        };
        if rng.chance(1, 40) {
            let source = (!rng.chance(1, 4)).then_some(source);
            ops.push(Op::Ack { source, t });
            continue;
        }
        let sev = *rng.pick(&SEVERITIES);
        let mode = if rng.chance(1, 7) {
            Mode::Observe
        } else {
            Mode::Enforce
        };
        let platform = if rng.chance(1, 20) {
            *rng.pick(&PlatformFamily::ALL)
        } else {
            policy.platform
        };
        let ctxs = all_contexts(platform);
        // Mostly the nominal context so enforcement paths are exercised.
        let mut ctx = if rng.chance(1, 2) {
            ctx(platform)
        } else {
            *rng.pick(&ctxs)
        };
        // Mostly the policy's own morphology, sometimes a mismatch.
        if !rng.chance(1, 20) {
            ctx.morphology = policy.morphology;
        }
        ops.push(Op::Plan {
            dev: dev(rng.pick(&rules), sev, mode),
            source,
            state: *rng.pick(&SafetyState::ALL),
            ctx,
            t,
        });
    }
    ops
}

/// Highest step any plan from this policy may reach: the highest matrix
/// cell outside the safety-system states (clamped by the override), or the
/// escalation ceiling.
fn policy_bound(p: &ResponsePolicy) -> Step {
    let mut m = p.escalation.ceiling;
    for s in SafetyState::ALL {
        for sev in SEVERITIES {
            let cell = p.matrix.get(sev, s);
            m = m.max(cell);
            if let Some(o) = p.override_for("rule.override") {
                m = m.max(cell.clamp(o.min_step, o.max_step));
            }
        }
    }
    m
}

fn run(policy: &ResponsePolicy, ops: &[Op], seed: u64) -> Vec<Option<ResponsePlan>> {
    let mut r = Responder::new(policy.clone()).unwrap();
    let bound = policy_bound(policy);
    // (source, rule) pairs that got an auto-executable plan since their
    // last acknowledgement: the only ones that may ever be suppressed.
    let mut issued: HashSet<(String, String)> = HashSet::new();
    let mut out = Vec::with_capacity(ops.len());
    for (i, op) in ops.iter().enumerate() {
        match op {
            Op::Ack { source, t } => {
                r.acknowledge(source.as_deref(), *t);
                match source {
                    Some(s) => issued.retain(|(src, _)| src != s),
                    None => issued.clear(),
                }
                out.push(None);
            }
            Op::Plan {
                dev,
                source,
                state,
                ctx,
                t,
            } => {
                let p = r.plan(dev, source, *state, ctx, *t);
                let tag = format!("seed {seed} op {i}: {op:?}");
                universal_invariants(&p, dev, *state, ctx, policy)
                    .unwrap_or_else(|e| panic!("{tag}: {e}\n{p:#?}"));
                assert!(p.max_step <= bound, "{tag}: above policy bound {bound:?}");
                if let Some(w) = &p.would_have {
                    assert!(w.max_step <= bound, "{tag}");
                }
                let key = (source.clone(), dev.rule.to_string());
                if p.suppressed {
                    assert!(
                        issued.contains(&key),
                        "{tag}: suppressed without an earlier auto plan for the same (source, rule)"
                    );
                    assert!(p
                        .rationale
                        .contains(|x| matches!(x, Reason::RateLimited { .. })));
                }
                if is_eligible(&p) {
                    issued.insert(key);
                }
                // Restrict is never dropped by the motion guard.
                if p.rationale
                    .contains(|x| matches!(x, Reason::MotionAlreadyRequested { .. }))
                {
                    assert!(has_restrict(&p), "{tag}");
                    assert!(!p.suppressed, "{tag}");
                }
                assert!(r.escalation_level(source) <= policy.escalation.max_escalation_steps);
                assert!(r.tracked_sources() <= MAX_SOURCES);
                assert!(r.rate_limit_entries() <= MAX_REISSUE_KEYS);
                out.push(Some(p));
            }
        }
    }
    out
}

#[test]
fn random_sequences_hold_every_invariant_and_are_deterministic() {
    let mut eligible = 0usize;
    let mut suppressed = 0usize;
    let mut guarded = 0usize;
    for seed in 0..SEEDS {
        let mut rng = XorShift::new(seed);
        let policy = random_policy(&mut rng);
        let ops = random_ops(&mut rng, &policy);
        let a = run(&policy, &ops, seed);
        let b = run(&policy, &ops, seed);
        assert_eq!(a, b, "seed {seed}: same input, different plans");
        for p in a.iter().flatten() {
            eligible += usize::from(is_eligible(p));
            suppressed += usize::from(p.suppressed);
            guarded += usize::from(
                p.rationale
                    .contains(|x| matches!(x, Reason::MotionAlreadyRequested { .. })),
            );
        }
    }
    // The generator must actually reach the interesting paths.
    assert!(eligible > 1_000, "eligible {eligible}");
    assert!(suppressed > 50, "suppressed {suppressed}");
    assert!(guarded > 10, "guarded {guarded}");
}

#[test]
fn random_sequences_under_estop_never_act() {
    // Same generator, but the safety system is engaged throughout: every
    // plan is Record only, whatever the escalation state says.
    for seed in 100..100 + SEEDS / 2 {
        let mut rng = XorShift::new(seed);
        let policy = random_policy(&mut rng);
        let mut r = Responder::new(policy.clone()).unwrap();
        for op in random_ops(&mut rng, &policy) {
            if let Op::Plan {
                dev,
                source,
                ctx,
                t,
                ..
            } = op
            {
                let state = if rng.chance(1, 2) {
                    SafetyState::EStopActive
                } else {
                    SafetyState::SafeStateActive
                };
                let p = r.plan(&dev, &source, state, &ctx, t);
                assert!(is_record_only(&p), "seed {seed}: {p:#?}");
                if let Some(w) = &p.would_have {
                    assert!(is_record_only(w));
                }
            }
        }
    }
}

#[test]
fn random_policies_round_trip_through_json() {
    for seed in 0..200 {
        let mut rng = XorShift::new(seed);
        let p = random_policy(&mut rng);
        let back = ResponsePolicy::from_json(&p.to_json()).unwrap();
        assert_eq!(back, p, "seed {seed}");
    }
}

/// Replace a random node at most `depth` levels down with `with`.
fn mutate(v: &mut serde_json::Value, depth: u64, rng: &mut XorShift, with: serde_json::Value) {
    if depth > 0 {
        match v {
            serde_json::Value::Object(m) if !m.is_empty() => {
                let i = rng.below(m.len() as u64) as usize;
                let child = m.values_mut().nth(i).expect("index in range");
                return mutate(child, depth - 1, rng, with);
            }
            serde_json::Value::Array(a) if !a.is_empty() => {
                let i = rng.below(a.len() as u64) as usize;
                return mutate(&mut a[i], depth - 1, rng, with);
            }
            _ => {}
        }
    }
    *v = with;
}

#[test]
fn random_json_mutations_of_a_policy_never_panic() {
    let base: serde_json::Value =
        serde_json::from_str(&validated(PlatformFamily::Ugv).to_json()).unwrap();
    let junk = [
        serde_json::json!(null),
        serde_json::json!(-1),
        serde_json::json!(1e308),
        serde_json::json!("kill"),
        serde_json::json!("request_safe_state"),
        serde_json::json!([]),
        serde_json::json!({}),
        serde_json::json!(u64::MAX),
        serde_json::json!(true),
    ];
    let mut rng = XorShift::new(7);
    for _ in 0..2_000 {
        let mut v = base.clone();
        // Walk to a random node and replace it.
        let depth = rng.below(4);
        let replacement = rng.pick(&junk).clone();
        mutate(&mut v, depth, &mut rng, replacement);
        if let Ok(p) = ResponsePolicy::from_json(&v.to_string()) {
            // Anything accepted is valid and keeps the e-stop rows Record.
            p.validate().unwrap();
            for sev in SEVERITIES {
                assert_eq!(p.matrix.get(sev, SafetyState::EStopActive), Step::Record);
                assert_eq!(
                    p.matrix.get(sev, SafetyState::SafeStateActive),
                    Step::Record
                );
            }
        }
    }
    // Truncations of the JSON text, byte by byte.
    let text = validated(PlatformFamily::Drone).to_json();
    for cut in 0..text.len() {
        if text.is_char_boundary(cut) {
            assert!(ResponsePolicy::from_json(&text[..cut]).is_err());
        }
    }
}

#[test]
fn severity_is_monotone_for_a_fresh_source() {
    // For every random policy and context, a higher severity never yields a
    // lower enforcement step than a lower severity would on a fresh source,
    // unless the matrix itself says so (it is OEM data). With the default
    // matrix it must hold everywhere.
    for platform in PlatformFamily::ALL {
        let policy = validated(platform);
        for c in all_contexts(platform) {
            for state in SafetyState::ALL {
                let mut last = Step::Record;
                for sev in SEVERITIES {
                    let d = Deviation::new("r", sev, "x");
                    let p = plan_stateless(&policy, &d, "s", state, &c);
                    let enforce = p.would_have.as_deref().unwrap_or(&p);
                    assert!(enforce.max_step >= last, "{platform:?} {state:?} {sev:?}");
                    last = enforce.max_step;
                }
            }
        }
    }
}
