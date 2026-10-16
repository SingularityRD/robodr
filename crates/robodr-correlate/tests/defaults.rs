//! Behaviour of the shipped default rules: each fires on its pattern and
//! not on near misses; window edges; entity separation; cooldown; clock
//! regression; eviction fairness.

use robodr_correlate::{
    CorrelatedFinding, Correlator, Domain, EntityKind, Limits, RuleSet, Signal,
};
use robodr_events::{Mode, Severity};

const S: u64 = 1_000_000_000;

const PARTICIPANT: &str = "robot.ros2.unknown_participant";
const MOTION_WRITER: &str = "robot.ros2.unauthorized_motion_writer";
const SHELL: &str = "RoboDR: Interactive shell started on robot controller";
const PKG: &str = "RoboDR: Debian package installed on robot controller";
const KEY_READ: &str = "RoboDR: SROS 2 enclave private key read by a process outside the ROS stack";
const STOP_SVC: &str = "RoboDR: Attempt to stop the Pulsar or RoboDR service";
const REFUSED: &str = "robot.capture.ip_fragment_refused";
const FRAG_REJECTED: &str = "robot.rtps.discovery_fragment_rejected";
const NOT_INSPECTED: &str = "robot.rtps.discovery_not_inspected";
const SRC_MISMATCH: &str = "robot.ros2.participant_source_mismatch";
const UNCOMMANDED: &str = "robot.motion.uncommanded_motion";

fn net(t: u64, rule: &str, sev: Severity) -> Signal {
    Signal::new(t, rule, sev)
}

fn net_ip(t: u64, rule: &str, sev: Severity, ip: &str) -> Signal {
    Signal::new(t, rule, sev).with_entity(EntityKind::Ip, ip)
}

fn host(t: u64, rule: &str, sev: Severity) -> Signal {
    Signal::host(t, rule, sev).with_entity(EntityKind::Process, "4242:/usr/bin/bash")
}

fn feed(c: &mut Correlator, sigs: &[Signal]) -> Vec<CorrelatedFinding> {
    sigs.iter().flat_map(|s| c.observe(s)).collect()
}

fn ids(f: &[CorrelatedFinding]) -> Vec<&str> {
    f.iter().map(|x| x.rule.as_str()).collect()
}

fn defaults() -> Correlator {
    Correlator::with_defaults()
}

// ---------------------------------------------------------------- coordinated intrusion

fn intrusion(t0: u64, host_at: u64) -> Vec<Signal> {
    vec![
        net(t0, PARTICIPANT, Severity::High).with_evidence_ref("bb:1"),
        net(t0 + 10 * S, MOTION_WRITER, Severity::Critical).with_evidence_ref("bb:2"),
        host(host_at, SHELL, Severity::Medium).with_evidence_ref("bb:3"),
    ]
}

#[test]
fn coordinated_intrusion_fires_with_cited_evidence() {
    let mut c = defaults();
    let f = feed(&mut c, &intrusion(0, 59 * S));
    assert_eq!(ids(&f), ["robot.correlate.coordinated_intrusion"]);
    let f = &f[0];
    assert_eq!(f.severity, Severity::Critical);
    assert_eq!(f.mode, Mode::Enforce);
    assert_eq!(f.at_ns, 59 * S);
    assert_eq!(f.group, None);
    let seqs: Vec<u64> = f.contributors.iter().map(|x| x.seq).collect();
    assert_eq!(seqs, [1, 2, 3]);
    let refs: Vec<_> = f
        .contributors
        .iter()
        .map(|x| x.evidence_ref.as_deref().unwrap())
        .collect();
    assert_eq!(refs, ["bb:1", "bb:2", "bb:3"]);
    let ts: Vec<u64> = f.contributors.iter().map(|x| x.t_ns).collect();
    assert_eq!(ts, [0, 10 * S, 59 * S]);
    assert_eq!(f.contributors[2].domain, Domain::Host);
    assert!(f.detail.contains(PARTICIPANT) && f.detail.contains(SHELL));
    let d = f.to_deviation();
    assert_eq!(d.rule_str(), "robot.correlate.coordinated_intrusion");
    assert_eq!(d.severity, Severity::Critical);
    assert_eq!(d.mode, Mode::Enforce);
}

#[test]
fn coordinated_intrusion_window_edge() {
    let mut c = defaults();
    assert_eq!(
        feed(&mut c, &intrusion(0, 60 * S)).len(),
        1,
        "exactly 60 s fires"
    );
    let mut c = defaults();
    assert!(
        feed(&mut c, &intrusion(0, 60 * S + 1)).is_empty(),
        "60 s + 1 ns does not"
    );
}

#[test]
fn coordinated_intrusion_any_order() {
    let mut c = defaults();
    let s = [
        host(0, SHELL, Severity::Medium),
        net(5 * S, MOTION_WRITER, Severity::Critical),
        net(6 * S, PARTICIPANT, Severity::High),
    ];
    assert_eq!(
        ids(&feed(&mut c, &s)),
        ["robot.correlate.coordinated_intrusion"]
    );
}

#[test]
fn coordinated_intrusion_needs_all_three_sides() {
    let mut c = defaults();
    let s = [
        net(0, PARTICIPANT, Severity::High),
        net(S, MOTION_WRITER, Severity::Critical),
        // A host signal, but not a process anomaly.
        host(2 * S, PKG, Severity::Low),
        // A process anomaly reported with the wrong domain (as if network).
        Signal::new(3 * S, SHELL, Severity::Medium).with_domain(Domain::Network),
    ];
    assert!(feed(&mut c, &s).is_empty());
    // Two network signals alone, many times over: still nothing.
    let mut c = defaults();
    for i in 0..20 {
        assert!(c
            .observe(&net(i * S, PARTICIPANT, Severity::High))
            .is_empty());
        assert!(c
            .observe(&net(i * S, MOTION_WRITER, Severity::Critical))
            .is_empty());
    }
}

#[test]
fn observe_input_makes_observe_output() {
    let mut c = defaults();
    let mut s = intrusion(0, 30 * S);
    s[0] = s[0].clone().with_mode(Mode::Observe);
    let f = feed(&mut c, &s);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].mode, Mode::Observe);
    assert_eq!(f[0].to_deviation().mode, Mode::Observe);
}

#[test]
fn cooldown_suppresses_then_releases() {
    let mut c = defaults();
    assert_eq!(feed(&mut c, &intrusion(0, 20 * S)).len(), 1);
    // Same pattern again inside the 60 s cooldown: suppressed.
    assert!(feed(&mut c, &intrusion(21 * S, 40 * S)).is_empty());
    assert!(c.stats().suppressed_cooldown >= 3);
    // After the cooldown, a fresh complete pattern fires again. (The third
    // shell from the same process also completes the per-process threshold.)
    let f = feed(&mut c, &intrusion(81 * S, 100 * S));
    assert_eq!(
        ids(&f),
        [
            "robot.correlate.coordinated_intrusion",
            "robot.correlate.host_process_persistence"
        ]
    );
    assert_eq!(c.stats().findings, 3);
}

// ---------------------------------------------------------------- sensor evasion

#[test]
fn sensor_evasion_needs_three_refusals_and_uninspected_discovery() {
    let mut c = defaults();
    let s = [
        net(0, REFUSED, Severity::Medium),
        net(10 * S, FRAG_REJECTED, Severity::Medium),
        net(20 * S, NOT_INSPECTED, Severity::Medium),
    ];
    assert!(feed(&mut c, &s).is_empty(), "two refusals are not enough");
    let f = c.observe(&net(30 * S, REFUSED, Severity::Medium));
    assert_eq!(ids(&f), ["robot.correlate.sensor_evasion"]);
    assert_eq!(f[0].severity, Severity::High);
    assert_eq!(f[0].contributors.len(), 4);
}

#[test]
fn sensor_evasion_refusals_alone_or_spread_out_do_not_fire() {
    let mut c = defaults();
    for i in 0..50 {
        assert!(c.observe(&net(i * S, REFUSED, Severity::Medium)).is_empty());
    }
    let mut c = defaults();
    let s = [
        net(0, REFUSED, Severity::Medium),
        net(70 * S, REFUSED, Severity::Medium),
        net(130 * S, REFUSED, Severity::Medium), // the first one expired (121 s)
        net(131 * S, NOT_INSPECTED, Severity::Medium),
    ];
    assert!(feed(&mut c, &s).is_empty());
    // One more refusal inside the window completes it.
    assert_eq!(c.observe(&net(132 * S, REFUSED, Severity::Medium)).len(), 1);
}

// ---------------------------------------------------------------- credential theft

#[test]
fn credential_theft_sequence_and_edges() {
    let mut c = defaults();
    let s = [
        host(0, KEY_READ, Severity::High),
        net(600 * S, PARTICIPANT, Severity::High),
    ];
    let f = feed(&mut c, &s);
    assert_eq!(ids(&f), ["robot.correlate.credential_theft"]);
    assert_eq!(f[0].severity, Severity::Critical);
    assert_eq!(f[0].contributors[0].rule, KEY_READ);
    assert_eq!(f[0].contributors[1].rule, PARTICIPANT);

    let mut c = defaults();
    let s = [
        host(0, KEY_READ, Severity::High),
        net(600 * S + 1, PARTICIPANT, Severity::High),
    ];
    assert!(feed(&mut c, &s).is_empty(), "outside the window");

    let mut c = defaults();
    let s = [
        net(0, PARTICIPANT, Severity::High),
        host(S, KEY_READ, Severity::High),
    ];
    assert!(feed(&mut c, &s).is_empty(), "wrong order");
}

#[test]
fn trojaned_package_then_key_read_then_participant() {
    let mut c = defaults();
    let s = [
        host(0, PKG, Severity::Low),
        host(60 * S, KEY_READ, Severity::High),
    ];
    let f = feed(&mut c, &s);
    assert_eq!(ids(&f), ["robot.correlate.trojaned_package_key_access"]);
    assert_eq!(f[0].severity, Severity::Critical);
    // The key read also opened a credential-theft sequence.
    let f = c.observe(&net(120 * S, PARTICIPANT, Severity::High));
    assert_eq!(ids(&f), ["robot.correlate.credential_theft"]);
}

// ---------------------------------------------------------------- spoofed source (per IP)

#[test]
fn spoofed_motion_source_is_per_ip() {
    let mut c = defaults();
    let a = "10.0.0.66";
    let b = "10.0.0.77";
    assert!(c
        .observe(&net_ip(0, SRC_MISMATCH, Severity::High, a))
        .is_empty());
    // The motion writer comes from another address: no correlation.
    assert!(c
        .observe(&net_ip(S, MOTION_WRITER, Severity::Critical, b))
        .is_empty());
    assert!(c.has_group("robot.correlate.spoofed_motion_source", a));
    assert!(!c.has_group("robot.correlate.spoofed_motion_source", b));
    let f = c.observe(&net_ip(2 * S, MOTION_WRITER, Severity::Critical, a));
    assert_eq!(ids(&f), ["robot.correlate.spoofed_motion_source"]);
    let g = f[0].group.as_ref().unwrap();
    assert_eq!((g.kind, g.value.as_str()), (EntityKind::Ip, a));
    for x in &f[0].contributors {
        assert!(x
            .entities
            .iter()
            .any(|e| e.kind == EntityKind::Ip && e.value == a));
    }
    // A signal without an IP entity cannot join an IP-grouped rule.
    let before = c.stats().missing_group_entity;
    c.observe(&net(3 * S, SRC_MISMATCH, Severity::High));
    assert_eq!(c.stats().missing_group_entity, before + 1);
}

// ---------------------------------------------------------------- motion hijack

#[test]
fn motion_hijack_sequence() {
    let mut c = defaults();
    let s = [
        net(0, MOTION_WRITER, Severity::Critical),
        Signal::new(30 * S, UNCOMMANDED, Severity::High),
    ];
    assert_eq!(ids(&feed(&mut c, &s)), ["robot.correlate.motion_hijack"]);
    let mut c = defaults();
    let s = [
        Signal::new(0, UNCOMMANDED, Severity::High),
        net(S, MOTION_WRITER, Severity::Critical),
    ];
    assert!(feed(&mut c, &s).is_empty());
    let mut c = defaults();
    let s = [
        net(0, MOTION_WRITER, Severity::Critical),
        Signal::new(30 * S + 1, UNCOMMANDED, Severity::High),
    ];
    assert!(feed(&mut c, &s).is_empty());
}

// ---------------------------------------------------------------- defense tampering

#[test]
fn defense_tampering_is_observe_only() {
    let mut c = defaults();
    let s = [
        host(0, STOP_SVC, Severity::High),
        Signal::new(5 * S, "robot.agent.input_silent", Severity::Medium).with_mode(Mode::Observe),
    ];
    let f = feed(&mut c, &s);
    assert_eq!(ids(&f), ["robot.correlate.defense_tampering"]);
    assert_eq!(f[0].mode, Mode::Observe);
    assert_eq!(f[0].severity, Severity::High);
    let mut c = defaults();
    assert!(feed(&mut c, &s[..1]).is_empty());
}

// ---------------------------------------------------------------- discovery flood

#[test]
fn discovery_flood_counts_distinct_ips() {
    let mut c = defaults();
    // Many announcements from 7 addresses: not a flood by this rule.
    for i in 0..70u64 {
        let ip = format!("10.1.0.{}", i % 7);
        assert!(c
            .observe(&net_ip(i * S / 10, PARTICIPANT, Severity::High, &ip))
            .is_empty());
    }
    let f = c.observe(&net_ip(
        7 * S + 1,
        PARTICIPANT,
        Severity::High,
        "10.1.0.200",
    ));
    assert_eq!(ids(&f), ["robot.correlate.discovery_flood"]);
    assert_eq!(f[0].contributors.len(), 8);
    assert_eq!(f[0].severity, Severity::High);
}

// ---------------------------------------------------------------- host process persistence

#[test]
fn host_process_threshold_escalates_per_process() {
    let mut c = defaults();
    let p =
        |t, pid: &str| Signal::host(t, SHELL, Severity::High).with_entity(EntityKind::Process, pid);
    assert!(c.observe(&p(0, "1:/bin/a")).is_empty());
    assert!(c.observe(&p(S, "2:/bin/b")).is_empty());
    assert!(c.observe(&p(2 * S, "3:/bin/c")).is_empty());
    assert!(c.observe(&p(3 * S, "1:/bin/a")).is_empty());
    let f = c.observe(&p(4 * S, "1:/bin/a"));
    assert_eq!(ids(&f), ["robot.correlate.host_process_persistence"]);
    assert_eq!(f[0].severity, Severity::Critical, "High escalated by one");
    // Low inputs: max(medium floor, Low+1) = Medium.
    let mut c = defaults();
    let low = |t| Signal::host(t, PKG, Severity::Low).with_entity(EntityKind::Process, "9:/x");
    let f = feed(&mut c, &[low(0), low(S), low(2 * S)]);
    assert_eq!(ids(&f), ["robot.correlate.host_process_persistence"]);
    assert_eq!(f[0].severity, Severity::Medium);
}

// ---------------------------------------------------------------- time

#[test]
fn clock_regression_is_clamped_and_cited() {
    let mut c = defaults();
    let s = [
        net(100 * S, PARTICIPANT, Severity::High),
        net(50 * S, MOTION_WRITER, Severity::Critical), // clock went back
        host(101 * S, SHELL, Severity::Medium),
    ];
    let f = feed(&mut c, &s);
    assert_eq!(f.len(), 1);
    assert_eq!(c.stats().clock_regressions, 1);
    let w = &f[0].contributors[1];
    assert_eq!((w.t_ns, w.at_ns), (50 * S, 100 * S));
    assert_eq!(c.now(), Some(101 * S));
}

#[test]
fn regression_cannot_extend_a_window() {
    // A step 2 arriving with an old timestamp is still processed at `now`.
    let mut c = defaults();
    c.observe(&host(0, KEY_READ, Severity::High));
    c.tick(700 * S);
    assert!(c
        .observe(&net(10 * S, PARTICIPANT, Severity::High))
        .is_empty());
    assert_eq!(c.stats().clock_regressions, 1);
}

#[test]
fn tick_expires_state() {
    let mut c = defaults();
    c.observe(&host(0, KEY_READ, Severity::High));
    c.observe(&net_ip(0, SRC_MISMATCH, Severity::High, "10.0.0.1"));
    assert!(c.pending_groups() >= 2);
    c.tick(30 * S + 1);
    assert!(!c.has_group("robot.correlate.spoofed_motion_source", "10.0.0.1"));
    assert!(c.has_group("robot.correlate.credential_theft", ""));
    c.tick(601 * S);
    assert_eq!(c.pending_groups(), 0);
    assert!(c.stats().groups_expired >= 2);
}

#[test]
fn correlation_outputs_are_not_inputs() {
    let mut c = defaults();
    let f = c.observe(&Signal::new(
        0,
        "robot.correlate.coordinated_intrusion",
        Severity::Critical,
    ));
    assert!(f.is_empty());
    assert_eq!(c.stats().ignored_correlation_inputs, 1);
    assert_eq!(c.pending_groups(), 0);
}

// ---------------------------------------------------------------- bounds & fairness

fn persistence_only() -> RuleSet {
    let json = robodr_correlate::DEFAULT_RULES_JSON;
    let mut file: robodr_correlate::RuleFile = serde_json::from_str(json).unwrap();
    file.rules.retain(|r| {
        r.id == "robot.correlate.host_process_persistence"
            || r.id == "robot.correlate.spoofed_motion_source"
    });
    RuleSet::from_file(&file).unwrap().0
}

fn proc_sig(t: u64, pid: &str) -> Signal {
    Signal::host(t, SHELL, Severity::Medium).with_entity(EntityKind::Process, pid)
}

#[test]
fn flood_cannot_evict_multi_signal_state() {
    let cap = 16;
    let mut c = Correlator::new(
        persistence_only(),
        Limits {
            max_groups_per_rule: cap,
            ..Limits::default()
        },
    );
    let rule = "robot.correlate.host_process_persistence";
    // The legitimate (victim) process has two of three signals.
    c.observe(&proc_sig(0, "victim"));
    c.observe(&proc_sig(S, "victim"));
    // An attacker floods 10x the table with fresh processes.
    for i in 0..(10 * cap) {
        c.observe(&proc_sig(2 * S + i as u64, &format!("flood-{i}")));
        assert!(c.groups_of(rule) <= cap);
    }
    assert!(c.has_group(rule, "victim"));
    assert!(c.stats().groups_evicted >= (9 * cap) as u64);
    let f = c.observe(&proc_sig(3 * S, "victim"));
    assert_eq!(ids(&f), [rule]);
    assert_eq!(f[0].contributors.len(), 3);
}

#[test]
fn flood_on_one_rule_does_not_touch_another() {
    let cap = 8;
    let mut c = Correlator::new(
        persistence_only(),
        Limits {
            max_groups_per_rule: cap,
            ..Limits::default()
        },
    );
    c.observe(&proc_sig(0, "victim"));
    for i in 0..100 {
        c.observe(&net_ip(
            S + i,
            SRC_MISMATCH,
            Severity::High,
            &format!("10.9.0.{i}"),
        ));
    }
    assert!(c.has_group("robot.correlate.host_process_persistence", "victim"));
    assert_eq!(c.groups_of("robot.correlate.spoofed_motion_source"), cap);
}

#[test]
fn full_table_of_progressed_groups_refuses_newcomers() {
    let cap = 4;
    let mut c = Correlator::new(
        persistence_only(),
        Limits {
            max_groups_per_rule: cap,
            // Every slot usable by these (unprotected, Medium) groups.
            protected_reserve_pct: 0,
            ..Limits::default()
        },
    );
    let rule = "robot.correlate.host_process_persistence";
    for i in 0..cap {
        c.observe(&proc_sig(0, &format!("p{i}")));
        c.observe(&proc_sig(0, &format!("p{i}")));
    }
    for i in 0..50 {
        c.observe(&proc_sig(S, &format!("new{i}")));
    }
    assert_eq!(c.stats().groups_refused, 50);
    assert_eq!(c.stats().groups_evicted, 0);
    assert!(!c.has_group(rule, "new0"));
    // The held groups still complete.
    for i in 0..cap {
        assert_eq!(c.observe(&proc_sig(2 * S, &format!("p{i}"))).len(), 1);
    }
    // After their state is gone, newcomers get in again.
    c.tick(2 * S + 300 * S + 1);
    assert_eq!(c.groups_of(rule), 0);
    c.observe(&proc_sig(400 * S, "late"));
    assert!(c.has_group(rule, "late"));
}

#[test]
fn single_signal_state_is_lru_evicted_and_counted() {
    let cap = 4;
    let mut c = Correlator::new(
        persistence_only(),
        Limits {
            max_groups_per_rule: cap,
            ..Limits::default()
        },
    );
    let rule = "robot.correlate.spoofed_motion_source";
    for i in 0..cap {
        c.observe(&net_ip(
            i as u64,
            SRC_MISMATCH,
            Severity::High,
            &format!("ip{i}"),
        ));
    }
    // Touch ip0 so it is no longer the least recently used.
    c.observe(&net_ip(10, SRC_MISMATCH, Severity::High, "ip0"));
    c.observe(&net_ip(11, SRC_MISMATCH, Severity::High, "ipX"));
    assert_eq!(c.stats().groups_evicted, 1);
    assert!(c.has_group(rule, "ip0"));
    assert!(!c.has_group(rule, "ip1"), "least recently used evicted");
    assert!(c.has_group(rule, "ipX"));
}

#[test]
fn entity_flood_in_one_signal_is_bounded() {
    let mut c = Correlator::new(persistence_only(), Limits::default());
    let mut s = Signal::new(0, SRC_MISMATCH, Severity::High);
    for i in 0..1000 {
        s = s.with_entity(EntityKind::Ip, format!("10.2.{}.{}", i / 256, i % 256));
    }
    s = s.with_entity(EntityKind::Ip, "x".repeat(100_000));
    c.observe(&s);
    assert_eq!(c.groups_of("robot.correlate.spoofed_motion_source"), 8);
    assert_eq!(c.stats().entities_dropped, 1001 - 8);
}

#[test]
fn custom_rules_from_json() {
    let json = r#"{"version":1,"rules":[{"id":"robot.correlate.custom","title":"Custom",
        "severity":"low","window_secs":0.5,"group_by":"participant",
        "pattern":{"kind":"threshold","match":{"prefixes":["robot.ros2.unknown_"]},"count":2}}]}"#;
    let (set, w) = RuleSet::from_json(json).unwrap();
    assert!(w.is_empty());
    let mut c = Correlator::new(set, Limits::default());
    let p = |t, g: &str| {
        Signal::new(t, "robot.ros2.unknown_reader", Severity::Medium)
            .with_entity(EntityKind::Participant, g)
    };
    assert!(c.observe(&p(0, "01.0f")).is_empty());
    assert!(c.observe(&p(1, "02.0f")).is_empty());
    let f = c.observe(&p(S / 2, "01.0f"));
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].severity, Severity::Medium, "never below an input");
    assert!(
        c.observe(&p(S, "02.0f")).is_empty(),
        "02.0f's first signal has expired"
    );
}

// ---- review finding 5: protected pending state under a fresh-IP flood ----

const SPOOFED: &str = "robot.correlate.spoofed_motion_source";
const ENDPOINT_MISMATCH: &str = "robot.ros2.endpoint_source_mismatch";

/// Port of the review PoC F5 with the shipped rules and default limits: a
/// step-0 signal for A, then 256 step-0 signals from fresh IPs. A low /
/// medium-severity flood can no longer evict A's High step 0 (tier 1), and
/// the sequence still fires.
#[test]
fn low_severity_flood_cannot_evict_severe_pending_sequence() {
    let a = "192.168.50.66";
    let mut c = Correlator::with_defaults();
    c.observe(&net_ip(1, SRC_MISMATCH, Severity::High, a));
    for i in 0..1024u32 {
        let ip = format!("10.{}.{}.1", i / 256, i % 256);
        c.observe(&net_ip(2, ENDPOINT_MISMATCH, Severity::Medium, &ip));
        assert!(c.groups_of(SPOOFED) <= 256);
    }
    assert!(c.has_group(SPOOFED, a));
    // The unprotected flood was confined to its share of the table.
    let reserve = Limits::default().protected_reserve();
    assert_eq!(c.groups_of(SPOOFED), 256 - reserve + 1);
    assert!(c.evictions_of(SPOOFED) > 0);
    let f = c.observe(&net_ip(3, MOTION_WRITER, Severity::Critical, a));
    assert!(ids(&f).contains(&SPOOFED), "{f:?}");
}

/// A group whose entity is known (a robot IP / profiled participant) cannot
/// be evicted by a flood of unknown entities, even a High / Critical one.
#[test]
fn known_entity_survives_a_severe_flood() {
    let a = "192.168.50.10";
    let mut c = Correlator::with_defaults();
    c.set_known_entities(EntityKind::Ip, [a]);
    assert!(c.is_known(EntityKind::Ip, a));
    c.observe(&net_ip(1, SRC_MISMATCH, Severity::Low, a));
    for i in 0..1024u32 {
        let ip = format!("10.{}.{}.1", i / 256, i % 256);
        c.observe(&net_ip(2, ENDPOINT_MISMATCH, Severity::Critical, &ip));
    }
    assert!(c.has_group(SPOOFED, a));
    let f = c.observe(&net_ip(3, MOTION_WRITER, Severity::High, a));
    assert!(ids(&f).contains(&SPOOFED), "{f:?}");
}

/// The PoC exactly (same-tier flood: High mismatches from fresh IPs against
/// an unknown IP). Eviction can still happen, but no longer silently: it is
/// counted per rule and an observe-only notice names the rule and cites the
/// lost evidence, once per rule window.
#[test]
fn same_tier_eviction_is_reported_per_rule() {
    let a = "192.168.50.66";
    let mut c = Correlator::with_defaults();
    c.observe(&net_ip(1, SRC_MISMATCH, Severity::High, a));
    for i in 0..300u32 {
        let ip = format!("10.{}.{}.1", i / 256, i % 256);
        c.observe(&net_ip(2, ENDPOINT_MISMATCH, Severity::High, &ip));
    }
    assert!(!c.has_group(SPOOFED, a));
    assert_eq!(c.evictions_of(SPOOFED), 300 - 255);
    assert_eq!(c.evictions_of("robot.correlate.no_such_rule"), 0);
    let n = c.take_notices();
    assert_eq!(n.len(), 1, "rate-limited to one per rule window: {n:?}");
    assert!(c.take_notices().is_empty(), "taken");
    let n = &n[0];
    assert_eq!(n.rule, robodr_correlate::EVICTED_RULE_ID);
    assert_eq!(n.mode, robodr_events::Mode::Observe);
    assert_eq!(n.severity, Severity::Medium);
    assert!(n.detail.contains(SPOOFED), "{}", n.detail);
    assert_eq!(n.group.as_ref().unwrap().value, a);
    assert_eq!(n.contributors.len(), 1);
    assert_eq!(n.contributors[0].rule, SRC_MISMATCH);
    assert_eq!(c.stats().eviction_notices, 1);
    assert!(c.stats().eviction_notices_suppressed >= 1);
    // The notice is observe-only as a deviation too.
    assert_eq!(n.to_deviation().mode, robodr_events::Mode::Observe);
    // After a rule window, a new eviction is reported again.
    c.observe(&net_ip(40 * S, SRC_MISMATCH, Severity::High, "10.200.0.1"));
    c.tick(40 * S);
    for i in 0..300u32 {
        let ip = format!("10.{}.{}.2", 100 + i / 256, i % 256);
        c.observe(&net_ip(41 * S, ENDPOINT_MISMATCH, Severity::High, &ip));
    }
    assert_eq!(c.take_notices().len(), 1);
}

/// Unprotected newcomers never displace protected groups, even when the
/// table is full; protected newcomers displace unprotected ones first.
#[test]
fn tiers_order_eviction() {
    let cap = 8;
    let mut c = Correlator::new(
        RuleSet::default_rules(),
        Limits {
            max_groups_per_rule: cap,
            ..Limits::default()
        },
    );
    assert_eq!(c.limits().protected_reserve(), 2);
    // Fill with protected (High) groups.
    for i in 0..cap {
        c.observe(&net_ip(1, SRC_MISMATCH, Severity::High, &format!("h{i}")));
    }
    assert_eq!(c.groups_of(SPOOFED), cap);
    // Low newcomers are refused, nothing evicted.
    let refused = c.stats().groups_refused;
    c.observe(&net_ip(2, SRC_MISMATCH, Severity::Low, "low"));
    assert!(!c.has_group(SPOOFED, "low"));
    assert!(c.stats().groups_refused > refused);
    // Known newcomer: evicts the least recently used severe group.
    c.set_known_entities(EntityKind::Ip, ["k"]);
    c.observe(&net_ip(3, SRC_MISMATCH, Severity::Low, "k"));
    assert!(c.has_group(SPOOFED, "k"));
    assert!(!c.has_group(SPOOFED, "h0"));
    // Unknown, unprotected groups go first.
    let mut c = Correlator::new(
        RuleSet::default_rules(),
        Limits {
            max_groups_per_rule: cap,
            ..Limits::default()
        },
    );
    for i in 0..(cap - 2) {
        c.observe(&net_ip(1, SRC_MISMATCH, Severity::Low, &format!("l{i}")));
    }
    // The unprotected share is full: a 7th low group evicts a low one.
    c.observe(&net_ip(1, SRC_MISMATCH, Severity::Low, "l-new"));
    assert_eq!(c.groups_of(SPOOFED), cap - 2);
    assert!(!c.has_group(SPOOFED, "l0"));
    for i in 0..2 {
        c.observe(&net_ip(2, SRC_MISMATCH, Severity::High, &format!("h{i}")));
    }
    assert_eq!(c.groups_of(SPOOFED), cap);
    // A further severe group evicts an unprotected one, not a severe one.
    c.observe(&net_ip(3, SRC_MISMATCH, Severity::Critical, "h2"));
    assert!(c.has_group(SPOOFED, "h0") && c.has_group(SPOOFED, "h1"));
    assert!(c.has_group(SPOOFED, "h2"));
    assert_eq!(c.groups_of(SPOOFED), cap);
}

#[test]
fn known_entity_sets_are_bounded_and_replaceable() {
    let mut c = Correlator::with_defaults();
    c.set_known_entities(
        EntityKind::Participant,
        (0..robodr_correlate::MAX_KNOWN_ENTITIES + 10).map(|i| format!("p{i}")),
    );
    assert_eq!(c.stats().known_entities_dropped, 10);
    assert!(c.is_known(EntityKind::Participant, "p0"));
    assert!(!c.is_known(EntityKind::Ip, "p0"));
    c.set_known_entities(EntityKind::Participant, Vec::<String>::new());
    assert!(!c.is_known(EntityKind::Participant, "p0"));
    // Reserve arithmetic never leaves zero unprotected slots.
    for (cap, pct) in [(1usize, 100u8), (2, 255), (4, 25), (0, 50)] {
        let l = Limits {
            max_groups_per_rule: cap,
            protected_reserve_pct: pct,
            ..Limits::default()
        };
        assert!(l.protected_reserve() < cap.max(1), "{cap} {pct}");
    }
}
