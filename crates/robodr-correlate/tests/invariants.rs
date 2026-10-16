//! Randomized ("fuzz-ish") invariants and determinism. A fixed-seed
//! xorshift generator keeps runs reproducible without extra dependencies.

use std::collections::BTreeSet;

use robodr_correlate::{
    CorrelatedFinding, Correlator, EntityKind, Limits, RuleSet, Signal, Stats, RULE_ID_PREFIX,
};
use robodr_events::{Mode, Severity};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len() as u64) as usize]
    }
}

const S: u64 = 1_000_000_000;

const VOCAB: &[&str] = &[
    "robot.ros2.unknown_participant",
    "robot.ros2.unauthorized_motion_writer",
    "robot.ros2.participant_source_mismatch",
    "robot.ros2.endpoint_source_mismatch",
    "robot.capture.ip_fragment_refused",
    "robot.rtps.discovery_fragment_rejected",
    "robot.rtps.discovery_not_inspected",
    "robot.motion.uncommanded_motion",
    "robot.firewall.rejected_unknown_source",
    "robot.agent.input_silent",
    "robot.correlate.coordinated_intrusion",
    "robot.unrelated.noise",
    "RoboDR: Interactive shell started on robot controller",
    "RoboDR: SROS 2 enclave private key read by a process outside the ROS stack",
    "RoboDR: Debian package installed on robot controller",
    "RoboDR: Attempt to stop the Pulsar or RoboDR service",
    "Some other Pulsar rule",
];

const SEVS: &[Severity] = &[
    Severity::Low,
    Severity::Medium,
    Severity::High,
    Severity::Critical,
];

fn random_signals(seed: u64, n: usize) -> Vec<Signal> {
    let mut r = Rng(seed | 1);
    let mut t: u64 = r.below(1000) * S;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        // Mostly forward in small steps; sometimes backwards; rarely a jump.
        match r.below(100) {
            0..=79 => t = t.saturating_add(r.below(5 * S)),
            80..=94 => t = t.saturating_sub(r.below(30 * S)),
            95..=98 => t = t.saturating_add(r.below(700 * S)),
            _ => {
                t = if r.below(2) == 0 {
                    0
                } else {
                    u64::MAX - r.below(S)
                }
            }
        }
        let rule = *r.pick(VOCAB);
        let mut s = Signal::new(t, rule, *r.pick(SEVS));
        if !rule.starts_with("robot.") {
            s = Signal::host(t, rule, s.severity);
        }
        if r.below(4) == 0 {
            s = s.with_mode(Mode::Observe);
        }
        for _ in 0..r.below(4) {
            let kind = *r.pick(&[
                EntityKind::Ip,
                EntityKind::Process,
                EntityKind::Participant,
                EntityKind::Unit,
            ]);
            // Small pools so groups collide; occasionally a huge value.
            let v = if r.below(50) == 0 {
                "é".repeat(400)
            } else {
                format!("{}-{}", kind.as_str(), r.below(12))
            };
            s = s.with_entity(kind, v);
        }
        if r.below(3) == 0 {
            s = s.with_evidence_ref(format!("bb:{}", r.below(1_000_000)));
        }
        out.push(s);
    }
    out
}

fn run(sigs: &[Signal], limits: Limits) -> (Vec<CorrelatedFinding>, Stats) {
    let mut c = Correlator::new(RuleSet::default_rules(), limits);
    let windows: Vec<(String, u64)> = c
        .rules()
        .iter()
        .map(|r| (r.id().to_string(), r.window_ns()))
        .collect();
    let mut all = Vec::new();
    for (i, s) in sigs.iter().enumerate() {
        let found = c.observe(s);
        let now = c.now();
        for f in &found {
            check_finding(f, &windows, now, i as u64 + 1);
        }
        for (id, _) in &windows {
            assert!(c.groups_of(id) <= limits.max_groups_per_rule.max(1));
        }
        all.extend(found);
        if i % 97 == 0 {
            c.tick(s.t_ns);
        }
    }
    (all, *c.stats())
}

fn check_finding(f: &CorrelatedFinding, windows: &[(String, u64)], now: Option<u64>, seq: u64) {
    assert!(f.rule.starts_with(RULE_ID_PREFIX));
    let window = windows.iter().find(|(id, _)| *id == f.rule).unwrap().1;
    assert_eq!(f.window_ns, window);
    assert_eq!(Some(f.at_ns), now);
    assert!(f.contributors.len() >= 2, "{f:?}");
    let seqs: Vec<u64> = f.contributors.iter().map(|c| c.seq).collect();
    assert!(
        seqs.windows(2).all(|w| w[0] < w[1]),
        "sorted, unique: {seqs:?}"
    );
    assert_eq!(
        *seqs.last().unwrap(),
        seq,
        "the current signal completes it"
    );
    let min = f.contributors.iter().map(|c| c.at_ns).min().unwrap();
    let max = f.contributors.iter().map(|c| c.at_ns).max().unwrap();
    assert!(max - min <= window, "{f:?}");
    assert_eq!(max, f.at_ns);
    let max_sev = f.contributors.iter().map(|c| c.severity).max().unwrap();
    assert!(f.severity >= max_sev);
    let observe = f.contributors.iter().any(|c| c.mode == Mode::Observe);
    assert_eq!(f.mode == Mode::Observe, observe);
    for c in &f.contributors {
        assert!(!c.rule.starts_with(RULE_ID_PREFIX));
        assert!(c.entities.len() <= 8);
        assert!(c.entities.iter().all(|e| e.value.len() <= 256));
        assert!(
            c.at_ns >= c.t_ns,
            "processing time never before the signal time"
        );
    }
    if let Some(g) = &f.group {
        for c in &f.contributors {
            assert!(
                c.entities.contains(g),
                "every contributor carries the group entity"
            );
        }
    }
    let d = f.to_deviation();
    assert_eq!(d.rule_str(), f.rule);
    assert_eq!(d.mode, f.mode);
}

#[test]
fn randomized_invariants_hold() {
    for seed in 1..=24u64 {
        let sigs = random_signals(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15), 3000);
        for cap in [1usize, 3, 256] {
            let limits = Limits {
                max_groups_per_rule: cap,
                ..Limits::default()
            };
            let (f, st) = run(&sigs, limits);
            assert_eq!(st.signals, sigs.len() as u64);
            assert_eq!(st.findings, f.len() as u64);
        }
    }
}

#[test]
fn randomized_runs_produce_findings() {
    // Guard against a vacuous fuzz test: the vocabulary does trigger rules.
    let mut total = 0;
    let mut rules = BTreeSet::new();
    for seed in 1..=40u64 {
        let (f, _) = run(&random_signals(seed, 3000), Limits::default());
        total += f.len();
        rules.extend(f.into_iter().map(|x| x.rule));
    }
    assert!(total > 50, "{total}");
    assert!(rules.len() >= 5, "{rules:?}");
}

#[test]
fn deterministic() {
    for seed in [7u64, 99, 12345] {
        let sigs = random_signals(seed, 4000);
        let limits = Limits {
            max_groups_per_rule: 5,
            ..Limits::default()
        };
        let a = run(&sigs, limits);
        let b = run(&sigs, limits);
        assert_eq!(a.0, b.0);
        assert_eq!(a.1, b.1);
        // Serialized output is byte-identical too.
        assert_eq!(
            serde_json::to_string(&a.0).unwrap(),
            serde_json::to_string(&b.0).unwrap()
        );
    }
}

#[test]
fn entity_order_does_not_matter() {
    let sigs = random_signals(4242, 3000);
    let reversed: Vec<Signal> = sigs
        .iter()
        .cloned()
        .map(|mut s| {
            s.entities.reverse();
            s
        })
        .collect();
    // Only valid while no signal exceeds the entity cap (which keeps the
    // *first* entities): the generator attaches at most 3.
    let a = run(&sigs, Limits::default());
    let b = run(&reversed, Limits::default());
    assert_eq!(a.0, b.0);
}

#[test]
fn signals_roundtrip_through_json() {
    for s in random_signals(5, 200) {
        let j = serde_json::to_string(&s).unwrap();
        let back: Signal = serde_json::from_str(&j).unwrap();
        assert_eq!(back, s);
    }
}

#[test]
fn hostile_rule_files_never_panic() {
    let base = robodr_correlate::DEFAULT_RULES_JSON.as_bytes();
    let mut r = Rng(0xDEAD_BEEF);
    for _ in 0..3000 {
        let mut b = base.to_vec();
        for _ in 0..(1 + r.below(8)) {
            let i = r.below(b.len() as u64) as usize;
            match r.below(3) {
                0 => b[i] = r.below(256) as u8,
                1 => {
                    b.remove(i);
                }
                _ => b.insert(i, *r.pick(b"{}[]\",:0-9e.")),
            }
        }
        if let Ok(s) = std::str::from_utf8(&b) {
            if let Ok((set, _)) = RuleSet::from_json(s) {
                // Whatever survived validation must run.
                let mut c = Correlator::new(set, Limits::default());
                for sig in random_signals(r.next(), 50) {
                    c.observe(&sig);
                }
            }
        }
    }
}
