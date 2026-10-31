//! `Agent::report_health` (findings contract 2.5, sales-readiness T5): the
//! daemon's periodic health record becomes an observe-only, validated
//! `robot.agent.health` finding carrying `entity_context.agent_health`, and
//! the record never leaks into another finding.

mod common;

use common::*;
use robodr_agent::*;
use robodr_events::{Deviation, Mode, Severity};
use robodr_ocsf::{
    parse_and_validate, AgentHealth, BlackBoxHealth, ClockHealth, HealthCounters, HealthLabel,
    Subject, AGENT_HEALTH_RULE,
};
use robodr_responder::{ResponseAction, SafetyState};

fn record(seq: u64) -> AgentHealth {
    AgentHealth {
        state: HealthLabel::Ok,
        reasons: vec![],
        interval_ms: 60_000,
        uptime_ms: seq * 60_000,
        seq,
        versions: vec![],
        inputs: vec![],
        counters: HealthCounters::default(),
        blackbox: BlackBoxHealth::default(),
        reachability: vec![],
        credentials: vec![],
        clock: ClockHealth::default(),
        disks: vec![],
    }
}

fn subject() -> Subject {
    Subject {
        node: Some("robodr-agentd".into()),
        ..Subject::default()
    }
}

#[test]
fn health_record_is_an_observe_only_finding_with_its_record() {
    let dir = tmpdir("health-record");
    let mut a = build(config(&dir, demo_profile(true), validated_policy()));
    let dev = Deviation::new(AGENT_HEALTH_RULE, Severity::Low, "health record");
    let o = a.report_health(
        at(1_000_000),
        "agentd:health",
        subject(),
        dev.clone(),
        record(1),
        SafetyState::Idle,
    );
    let f = o.finding.as_ref().expect("finding");
    let env = parse_and_validate(&f.value).expect("valid");
    assert_eq!(env.entity_context.agent_health, Some(record(1)));
    assert_eq!(env.entity_context.mode, robodr_ocsf::Mode::Observe);
    assert_eq!(o.deviation.mode, Mode::Observe);
    assert!(o
        .plan
        .actions
        .iter()
        .all(|x| matches!(x, ResponseAction::Record)));
    // The second record is an Update of the same finding.
    let o2 = a.report_health(
        at(61_000_000),
        "agentd:health",
        subject(),
        dev,
        record(2),
        SafetyState::Idle,
    );
    let env2 = parse_and_validate(&o2.finding.unwrap().value).unwrap();
    assert_eq!(env2.finding_id, env.finding_id);
    assert_eq!(env2.ocsf.count, 2);
    assert_eq!(env2.entity_context.agent_health.unwrap().seq, 2);

    // The record never travels with another finding.
    let other = a.handle_external(
        at(62_000_000),
        Detector::SelfHealth,
        "agentd",
        subject(),
        Deviation::new("robot.agent.input_silent", Severity::High, "x"),
        SafetyState::Idle,
    );
    let env3 = parse_and_validate(&other.finding.unwrap().value).unwrap();
    assert_eq!(env3.entity_context.agent_health, None);

    // A record handed with another rule id is dropped (the finding builds).
    let wrong = a.report_health(
        at(63_000_000),
        "agentd",
        subject(),
        Deviation::new("robot.agent.pipeline_lag", Severity::Medium, "x"),
        record(3),
        SafetyState::Idle,
    );
    let env4 = parse_and_validate(&wrong.finding.unwrap().value).unwrap();
    assert_eq!(env4.entity_context.agent_health, None);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The contract version agentd states in the record's `versions[]` is the
/// one the agent's findings carry, including under a producer cap.
#[test]
fn contract_version_follows_the_producer_cap() {
    let dir = tmpdir("health-contract-version");
    let a = build(config(&dir, demo_profile(true), validated_policy()));
    assert_eq!(a.contract_version(), robodr_ocsf::CONTRACT_VERSION);
    drop(a);
    let _ = std::fs::remove_dir_all(&dir);
    let dir = tmpdir("health-contract-version-capped");
    let mut cfg = config(&dir, demo_profile(true), validated_policy());
    cfg.max_contract_minor = Some(4);
    let mut capped = build(cfg);
    assert_eq!(capped.contract_version(), "2.4.0");
    let o = capped.handle_external(
        at(1_000_000),
        Detector::SelfHealth,
        "agentd",
        subject(),
        Deviation::new("robot.agent.input_silent", Severity::High, "x"),
        SafetyState::Idle,
    );
    let env = parse_and_validate(&o.finding.unwrap().value).unwrap();
    assert_eq!(env.contract_version, capped.contract_version());
    let _ = std::fs::remove_dir_all(&dir);
}
