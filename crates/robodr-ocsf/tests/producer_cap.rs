//! Producer cap (sales-readiness T38): a robot whose SOC still validates
//! an older contract minor is configured with `max_contract_minor`, and
//! every finding it builds is one that minor's validator accepts.

mod common;

use robodr_events::{Deviation, Severity};
use robodr_ocsf::{
    finding_uid, parse_and_validate, rule_info, rule_info_for_contract, to_json, FindingBuilder,
    FindingEnvelope, RobotContext, Subject, AGENT_HEALTH_RULE, CONTRACT_MINOR, CONTRACT_VERSION,
    HOST_RULES, HOST_THREAT_FALLBACK,
};

fn ctx(cap: Option<u64>) -> RobotContext {
    let mut c = common::ctx();
    c.max_contract_minor = cap;
    c
}

fn build(c: &RobotContext, rule: &str) -> FindingEnvelope {
    let dev = Deviation::new(rule.to_string(), Severity::Medium, "detail");
    let mut b = FindingBuilder::from_deviation(&dev, c).seen(common::T0, common::T0);
    if rule == AGENT_HEALTH_RULE {
        b = b.agent_health(common::health::sample());
    }
    let env = b.build().unwrap_or_else(|e| panic!("{rule}: {e:?}"));
    // What goes on the wire parses and validates under its own minor.
    parse_and_validate(&to_json(&env).unwrap()).unwrap_or_else(|e| panic!("{rule}: {e:?}"));
    env
}

#[test]
fn contract_minor_matches_contract_version() {
    assert_eq!(CONTRACT_VERSION, format!("2.{CONTRACT_MINOR}.0"));
    for cap in [None, Some(CONTRACT_MINOR), Some(CONTRACT_MINOR + 7)] {
        let c = ctx(cap);
        assert_eq!(c.contract_minor(), CONTRACT_MINOR);
        assert_eq!(c.contract_version(), CONTRACT_VERSION);
        assert_eq!(
            build(&c, "robot.agent.disk_low").contract_version,
            CONTRACT_VERSION
        );
    }
}

/// Capped at 2.4, a 2.5-only id is built with the generic entry, as a 2.4
/// producer would have; the rule id stays.
#[test]
fn capped_new_id_gets_the_older_minors_generic_entry() {
    let env = build(&ctx(Some(4)), "robot.agent.disk_low");
    assert_eq!(env.contract_version, "2.4.0");
    assert_eq!(env.entity_context.rule_id, "robot.agent.disk_low");
    let generic = rule_info("robot.__none__.none");
    assert_eq!(env.title, generic.title);
    assert_eq!(env.ocsf.finding_info.data_sources, [generic.data_source]);
    assert_eq!(
        rule_info_for_contract("robot.agent.disk_low", "2.4.0"),
        generic
    );
    // Uncapped it carries its 2.5 entry, which a 2.4 validator refuses
    // (the reviewer's failure case).
    let now = build(&ctx(None), "robot.agent.disk_low");
    assert_ne!(now.title, generic.title);
    let mut as_24 = serde_json::to_value(&now).unwrap();
    as_24["contract_version"] = "2.4.0".into();
    assert!(parse_and_validate(&as_24.to_string()).is_err());
    // An id both minors catalogue is unchanged but for the version.
    let old = build(&ctx(Some(4)), "robot.ros2.unknown_participant");
    let cur = build(&ctx(None), "robot.ros2.unknown_participant");
    assert_eq!(
        (old.title.as_str(), old.finding_id.as_str()),
        (cur.title.as_str(), cur.finding_id.as_str())
    );
    // Lower caps use their own catalogs (robot.seal.* is 2.3).
    let seal = build(&ctx(Some(2)), "robot.seal.unseal_failed");
    assert_eq!(seal.contract_version, "2.2.0");
    assert_eq!(seal.title, generic.title);
}

/// Below 2.5 a per-rule host id goes out as the 2.4 fallback id, with the
/// 2.4 finding identity.
#[test]
fn capped_host_rule_uses_the_fallback_id() {
    let (_, per_rule) = HOST_RULES[0];
    let env = build(&ctx(Some(4)), per_rule);
    assert_eq!(env.entity_context.rule_id, HOST_THREAT_FALLBACK);
    assert_eq!(env.ocsf.finding_info.analytic.uid, HOST_THREAT_FALLBACK);
    assert_eq!(
        env.finding_id,
        finding_uid(
            &common::ctx().robot.id,
            HOST_THREAT_FALLBACK,
            &Subject::default()
        )
    );
    assert_eq!(env.title, rule_info(HOST_THREAT_FALLBACK).title);
    let dev = Deviation::new(per_rule.to_string(), Severity::High, "d");
    let c = ctx(Some(4));
    assert_eq!(
        FindingBuilder::from_deviation(&dev, &c).finding_uid(),
        env.finding_id,
        "the uid the agent dedups on matches the wire"
    );
    // Uncapped: its own id.
    assert_eq!(build(&ctx(None), per_rule).entity_context.rule_id, per_rule);
    // A deployment's own Pulsar rule already uses the fallback.
    assert_eq!(
        build(&ctx(Some(4)), HOST_THREAT_FALLBACK)
            .entity_context
            .rule_id,
        HOST_THREAT_FALLBACK
    );
}

/// Below 2.5 the health record is left out: a 2.4 validator refuses
/// `agent_health`. The finding itself still goes out (generic entry).
#[test]
fn capped_health_finding_has_no_record() {
    let env = build(&ctx(Some(4)), AGENT_HEALTH_RULE);
    assert!(env.entity_context.agent_health.is_none());
    assert!(!to_json(&env).unwrap().contains("agent_health"));
    let now = build(&ctx(None), AGENT_HEALTH_RULE);
    assert!(now.entity_context.agent_health.is_some());
}
