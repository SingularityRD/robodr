//! Rule-catalog versioning (review finding M6): a catalog entry is a contract
//! minor, and the validator applies the catalog of the message's own minor.
//!
//! * 1.0 - 1.2: the base catalog;
//! * 1.3 and 2.0: base + the 1.3 entries, exactly as released in 1.3
//!   (reference: `git show c64744d:crates/robodr-ocsf/src/builder.rs`; 2.0
//!   did not change the catalog);
//! * 2.1: + the low-level joint-frame firewall ids, the robot API /
//!   control-handover motion ids, the Unitree legacy UDP sender ids, the
//!   motion command type id and the discovery-flood aggregate;
//! * 2.2: + the secure-delivery ids of `robodr-deliverd` (`robot.deliver.*`,
//!   data source `robodr_delivery`, `docs/SECURE-DELIVERY.md` §9);
//! * 2.3: + the in-path gateway ids of `robodr-firewall-gw`
//!   (`robot.gateway.*`, data source `ros2_motion_commands`, Sprint 8) and
//!   the sealing ids (`robot.seal.*`, data source `robodr_delivery`,
//!   `docs/SECURE-DELIVERY.md` §7, §9, Sprint 13c), the site depot ids
//!   (`robot.depot.*`) and `robot.seal.erase_deferred` (Sprints 14a / 14b,
//!   data source `robodr_delivery`).

mod common;

use robodr_events::{Deviation, Severity};
use robodr_ocsf::{rule_info, rule_info_for_contract, FindingBuilder, CONTRACT_VERSION};

/// Ids whose catalog entry was added after contract 2.0.0 (2.1).
const IDS_2_1: &[&str] = &[
    "robot.motion.api_id_out_of_range",
    "robot.motion.control_handover",
    "robot.unitree.legacy_unknown_sender",
    "robot.unitree.legacy_sender_flood",
    "robot.unitree.legacy_sender_mac_mismatch",
    "robot.unitree.legacy_port_rtps",
    "robot.motion.command_type_mismatch",
    "robot.ros2.discovery_flood",
    "robot.firewall.joint_position_out_of_envelope",
    "robot.firewall.joint_velocity_out_of_envelope",
    "robot.firewall.joint_torque_out_of_envelope",
    "robot.firewall.joint_gain_out_of_envelope",
    "robot.firewall.disabled_motor_energised",
    "robot.firewall.crc_invalid",
    "robot.firewall.joint_rate_violation",
    "robot.firewall.joint_gain_below_minimum",
    "robot.firewall.joint_step_out_of_envelope",
    "robot.firewall.joint_pd_torque_out_of_envelope",
    "robot.firewall.joint_mode_inconsistent",
    "robot.firewall.joint_mode_pin_mismatch",
    "robot.firewall.joint_limp_frame",
    "robot.firewall.joint_hold_exceeded",
];

/// Ids whose catalog entry was added after contract 2.1.0 (2.2).
const IDS_2_2: &[&str] = &[
    "robot.deliver.installed",
    "robot.deliver.deferred_safety",
    "robot.deliver.health_failed",
    "robot.deliver.rollback_blocked_floor",
    "robot.deliver.refused",
    "robot.deliver.stale",
    "robot.deliver.chain_gap",
];

/// A sample of 1.3 entries (wave 6 and wave 7) that must stay as they were.
const IDS_1_3: &[&str] = &[
    "robot.correlate.coordinated_intrusion",
    "robot.safety_state.writer_overflow",
    "robot.agent.evidence_truncated",
    "robot.host.pulsar_threat",
    "robot.firewall.rejected_stale",
    "robot.motion.uncommanded_motion",
];

fn generic() -> robodr_ocsf::RuleInfo {
    rule_info("robot.nope.nothing")
}

fn build(rule: &str) -> String {
    let dev = Deviation::new(rule.to_string(), Severity::High, "detail");
    let env = FindingBuilder::from_deviation(&dev, &common::ctx())
        .seen(common::T0, common::T0)
        .build()
        .unwrap();
    robodr_ocsf::to_json(&env).unwrap()
}

/// Replace the JSON array value of `"key":[...]` (no nested arrays) by `[]`.
fn empty_array(json: &str, key: &str) -> String {
    let start = json.find(&format!("\"{key}\":[")).expect(key) + key.len() + 4;
    let end = start + json[start..].find(']').unwrap();
    format!("{}{}", &json[..start], &json[end..])
}

/// What a 2.0.0 producer emitted for `id`: the generic entry (generic
/// title, description and data source, no techniques).
fn as_2_0(json: &str, id: &str) -> String {
    let new = rule_info(id);
    let old = rule_info_for_contract(id, "2.0.0");
    assert!(old.techniques.is_empty());
    let out = json
        .replace(new.title, old.title)
        .replace(new.desc, old.desc)
        .replace(
            &format!("\"{}\"", new.data_source),
            &format!("\"{}\"", old.data_source),
        )
        .replace(
            &format!("\"contract_version\":\"{CONTRACT_VERSION}\""),
            "\"contract_version\":\"2.0.0\"",
        );
    empty_array(&empty_array(&out, "mitre_predictions"), "attacks")
}

/// Ids whose catalog entry was added after contract 2.2.0 by the in-path
/// gateway (2.3).
const IDS_2_3_GATEWAY: &[&str] = &[
    "robot.gateway.trajectory_rejected",
    "robot.gateway.trajectory_time_scaled",
    "robot.gateway.undecodable_command",
    "robot.gateway.fragmented_command",
    "robot.gateway.writer_binding_conflict",
    "robot.gateway.sequence_jump",
    "robot.gateway.port_bypass_risk",
    "robot.gateway.restriction_changed",
    "robot.gateway.findings_dropped",
];

#[test]
fn entries_added_after_2_2_are_not_in_2_2_or_earlier() {
    let g = generic();
    for id in IDS_2_3_GATEWAY {
        let full = rule_info(id);
        assert_ne!(full, g, "{id} has its own entry in the current catalog");
        assert_eq!(full.data_source, "ros2_motion_commands", "{id}");
        for v in ["1.0.0", "1.3.0", "2.0.0", "2.1.0", "2.2.0", "2.2.9"] {
            assert_eq!(rule_info_for_contract(id, v), g, "{id} @ {v}");
        }
        for v in ["2.3.0", "2.3.5", "2.9.0"] {
            assert_eq!(rule_info_for_contract(id, v), full, "{id} @ {v}");
        }
        assert_eq!(rule_info_for_contract(id, "x"), full);
    }
    for id in IDS_2_1.iter().chain(IDS_2_2) {
        assert_eq!(
            rule_info_for_contract(id, "2.3.0"),
            rule_info_for_contract(id, "2.2.0")
        );
    }
}

#[test]
fn a_2_2_message_validates_with_its_own_catalog() {
    for id in IDS_2_3_GATEWAY {
        let v23 = build(id);
        robodr_ocsf::parse_and_validate(&v23).unwrap_or_else(|e| panic!("{id}: {e:?}"));
        let new = rule_info(id);
        let old = rule_info_for_contract(id, "2.2.0");
        assert!(old.techniques.is_empty() && new.techniques.is_empty());
        let v22 = v23
            .replace(new.title, old.title)
            .replace(new.desc, old.desc)
            .replace(
                &format!("\"{}\"", new.data_source),
                &format!("\"{}\"", old.data_source),
            )
            .replace(
                &format!("\"contract_version\":\"{CONTRACT_VERSION}\""),
                "\"contract_version\":\"2.2.0\"",
            );
        assert_ne!(v22, v23);
        robodr_ocsf::parse_and_validate(&v22).unwrap_or_else(|e| panic!("{id} 2.2: {e:?}"));
        let up = v22.replace(
            "\"contract_version\":\"2.2.0\"",
            &format!("\"contract_version\":\"{CONTRACT_VERSION}\""),
        );
        assert!(robodr_ocsf::parse_and_validate(&up).is_err(), "{id}");
        let down = v23.replace(
            &format!("\"contract_version\":\"{CONTRACT_VERSION}\""),
            "\"contract_version\":\"2.2.0\"",
        );
        assert!(robodr_ocsf::parse_and_validate(&down).is_err(), "{id}");
    }
}

#[test]
fn current_contract_is_2_5() {
    assert_eq!(CONTRACT_VERSION, "2.5.0");
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/contracts/robodr-finding.schema.json"
    ))
    .unwrap();
    assert_eq!(
        schema["$id"],
        "https://schemas.singularityrd.com/robodr/findings/2.5.0"
    );
}

/// The 2.4 entries (gap 1 / S5: agentd's state integrity, the executor's
/// failed reverts and journal resets).
const IDS_2_4: &[&str] = &[
    "robot.agent.control_plane_state_untrusted",
    "robot.agent.executor_revert_failed",
    "robot.agent.executor_journal_reset",
];

#[test]
fn entries_added_in_2_4_are_not_in_2_3_or_earlier() {
    let g = generic();
    for id in IDS_2_4 {
        let full = rule_info(id);
        assert_ne!(full, g, "{id} has its own entry in the current catalog");
        assert_eq!(full.data_source, "robodr_agent", "{id}");
        assert!(full.techniques.is_empty(), "{id}");
        for v in ["1.3.0", "2.0.0", "2.2.0", "2.3.0", "2.3.9"] {
            assert_eq!(rule_info_for_contract(id, v), g, "{id} @ {v}");
        }
        for v in ["2.4.0", "2.4.1", "2.5.0", "2.9.0"] {
            assert_eq!(rule_info_for_contract(id, v), full, "{id} @ {v}");
        }
        // A 2.4 finding validates; relabelled as 2.3 it does not (its
        // catalog constants are the 2.4 ones).
        let v24 = build(id);
        robodr_ocsf::parse_and_validate(&v24).unwrap_or_else(|e| panic!("{id}: {e:?}"));
        let down = v24.replace(
            &format!("\"contract_version\":\"{CONTRACT_VERSION}\""),
            "\"contract_version\":\"2.3.0\"",
        );
        assert!(robodr_ocsf::parse_and_validate(&down).is_err(), "{id}");
    }
    for id in IDS_2_3_GATEWAY {
        assert_eq!(
            rule_info_for_contract(id, "2.4.0"),
            rule_info_for_contract(id, "2.3.0")
        );
    }
}

#[test]
fn entries_added_after_2_0_are_not_in_1_3_or_2_0() {
    let g = generic();
    for id in IDS_2_1 {
        let full = rule_info(id);
        assert_ne!(full, g, "{id} has its own entry in the current catalog");
        for v in ["1.0.0", "1.2.0", "1.3.0", "1.9.0", "2.0.0", "2.0.7"] {
            assert_eq!(rule_info_for_contract(id, v), g, "{id} @ {v}");
        }
        for v in ["2.1.0", "2.1.3", "2.2.0", "2.4.0"] {
            assert_eq!(rule_info_for_contract(id, v), full, "{id} @ {v}");
        }
        // Malformed versions get the current (strictest) catalog.
        assert_eq!(rule_info_for_contract(id, "x"), full);
    }
}

#[test]
fn entries_added_after_2_1_are_not_in_2_1_or_earlier() {
    let g = generic();
    for id in IDS_2_2 {
        let full = rule_info(id);
        assert_ne!(full, g, "{id} has its own entry in the current catalog");
        assert_eq!(full.data_source, "robodr_delivery", "{id}");
        for v in ["1.0.0", "1.3.0", "2.0.0", "2.1.0", "2.1.9"] {
            assert_eq!(rule_info_for_contract(id, v), g, "{id} @ {v}");
        }
        for v in ["2.2.0", "2.2.5", "2.9.0"] {
            assert_eq!(rule_info_for_contract(id, v), full, "{id} @ {v}");
        }
        assert_eq!(rule_info_for_contract(id, "x"), full);
    }
    // The 2.1 entries are unchanged in 2.2.
    for id in IDS_2_1 {
        assert_eq!(
            rule_info_for_contract(id, "2.2.0"),
            rule_info_for_contract(id, "2.1.0")
        );
    }
}

/// What a 2.1.0 producer emitted for `id`: the generic entry.
fn as_2_1(json: &str, id: &str) -> String {
    let new = rule_info(id);
    let old = rule_info_for_contract(id, "2.1.0");
    assert!(old.techniques.is_empty() && new.techniques.is_empty());
    json.replace(new.title, old.title)
        .replace(new.desc, old.desc)
        .replace(
            &format!("\"{}\"", new.data_source),
            &format!("\"{}\"", old.data_source),
        )
        .replace(
            &format!("\"contract_version\":\"{CONTRACT_VERSION}\""),
            "\"contract_version\":\"2.1.0\"",
        )
}

#[test]
fn a_2_1_message_validates_with_its_own_catalog() {
    for id in IDS_2_2 {
        let v22 = build(id);
        robodr_ocsf::parse_and_validate(&v22).unwrap_or_else(|e| panic!("{id}: {e:?}"));
        let v21 = as_2_1(&v22, id);
        assert_ne!(v21, v22);
        robodr_ocsf::parse_and_validate(&v21).unwrap_or_else(|e| panic!("{id} 2.1: {e:?}"));
        let up = v21.replace(
            "\"contract_version\":\"2.1.0\"",
            &format!("\"contract_version\":\"{CONTRACT_VERSION}\""),
        );
        assert!(robodr_ocsf::parse_and_validate(&up).is_err(), "{id}");
        let down = v22.replace(
            &format!("\"contract_version\":\"{CONTRACT_VERSION}\""),
            "\"contract_version\":\"2.1.0\"",
        );
        assert!(robodr_ocsf::parse_and_validate(&down).is_err(), "{id}");
    }
}

#[test]
fn the_1_3_entries_are_the_same_in_1_3_2_0_and_2_1() {
    for id in IDS_1_3 {
        let full = rule_info(id);
        assert_ne!(full, generic(), "{id}");
        for v in ["1.3.0", "2.0.0", "2.1.0", "2.2.0"] {
            assert_eq!(rule_info_for_contract(id, v), full, "{id} @ {v}");
        }
    }
}

#[test]
fn a_2_0_message_validates_with_its_own_catalog() {
    for id in [
        "robot.firewall.joint_limp_frame",
        "robot.motion.control_handover",
        "robot.firewall.joint_rate_violation",
    ] {
        let v21 = build(id);
        robodr_ocsf::parse_and_validate(&v21).unwrap_or_else(|e| panic!("{id}: {e:?}"));
        let v20 = as_2_0(&v21, id);
        assert_ne!(v20, v21);
        robodr_ocsf::parse_and_validate(&v20).unwrap_or_else(|e| panic!("{id} 2.0: {e:?}"));
        // The 2.0 form relabelled 2.1 is rejected (generic entry, new minor).
        let up = v20.replace(
            "\"contract_version\":\"2.0.0\"",
            &format!("\"contract_version\":\"{CONTRACT_VERSION}\""),
        );
        assert!(robodr_ocsf::parse_and_validate(&up).is_err(), "{id}");
        // The 2.1 form relabelled 2.0 is rejected (new entry, old minor).
        let down = v21.replace(
            &format!("\"contract_version\":\"{CONTRACT_VERSION}\""),
            "\"contract_version\":\"2.0.0\"",
        );
        assert!(robodr_ocsf::parse_and_validate(&down).is_err(), "{id}");
    }
}

/// Sealing ids whose catalog entry was added after contract 2.2.0 (2.3).
const IDS_2_3_SEAL: &[&str] = &[
    "robot.seal.unseal_failed",
    "robot.seal.lease_expired",
    "robot.seal.erased",
    "robot.seal.tamper",
];

/// Depot and executed-erase ids added in 2.3 (Sprints 14a / 14b).
const IDS_2_3_DEPOT: &[&str] = &[
    "robot.depot.import_refused",
    "robot.depot.enrolment_refused",
    "robot.depot.unit_enrolled",
    "robot.depot.rollout_halted",
    "robot.depot.locked",
    "robot.seal.erase_deferred",
];

#[test]
fn seal_entries_added_after_2_2_are_not_in_2_2_or_earlier() {
    let g = generic();
    for id in IDS_2_3_SEAL.iter().chain(IDS_2_3_DEPOT) {
        let full = rule_info(id);
        assert_ne!(full, g, "{id} has its own entry in the current catalog");
        assert_eq!(full.data_source, "robodr_delivery", "{id}");
        for v in ["1.0.0", "1.3.0", "2.0.0", "2.1.0", "2.2.0", "2.2.9"] {
            assert_eq!(rule_info_for_contract(id, v), g, "{id} @ {v}");
        }
        for v in ["2.3.0", "2.3.4", "2.9.0"] {
            assert_eq!(rule_info_for_contract(id, v), full, "{id} @ {v}");
        }
        assert_eq!(rule_info_for_contract(id, "x"), full);
    }
}

/// What a 2.2.0 producer emitted for a sealing id: the generic entry.
fn seal_as_2_2(json: &str, id: &str) -> String {
    let new = rule_info(id);
    let old = rule_info_for_contract(id, "2.2.0");
    assert!(old.techniques.is_empty() && new.techniques.is_empty());
    json.replace(new.title, old.title)
        .replace(new.desc, old.desc)
        .replace(
            &format!("\"{}\"", new.data_source),
            &format!("\"{}\"", old.data_source),
        )
        .replace(
            &format!("\"contract_version\":\"{CONTRACT_VERSION}\""),
            "\"contract_version\":\"2.2.0\"",
        )
}

#[test]
fn a_2_2_seal_message_validates_with_its_own_catalog() {
    for id in IDS_2_3_SEAL.iter().chain(IDS_2_3_DEPOT) {
        let v23 = build(id);
        robodr_ocsf::parse_and_validate(&v23).unwrap_or_else(|e| panic!("{id}: {e:?}"));
        let v22 = seal_as_2_2(&v23, id);
        assert_ne!(v22, v23);
        robodr_ocsf::parse_and_validate(&v22).unwrap_or_else(|e| panic!("{id} 2.2: {e:?}"));
        let up = v22.replace(
            "\"contract_version\":\"2.2.0\"",
            &format!("\"contract_version\":\"{CONTRACT_VERSION}\""),
        );
        assert!(robodr_ocsf::parse_and_validate(&up).is_err(), "{id}");
        let down = v23.replace(
            &format!("\"contract_version\":\"{CONTRACT_VERSION}\""),
            "\"contract_version\":\"2.2.0\"",
        );
        assert!(robodr_ocsf::parse_and_validate(&down).is_err(), "{id}");
    }
}

/// Unitree WebRTC ids whose catalog entry was added after contract 2.2.0
/// (2.3, `catalog_2_3_unitree`).
const IDS_2_3_UNITREE: &[&str] = &[
    "robot.unitree.webrtc_unknown_controller",
    "robot.unitree.webrtc_new_peer",
    "robot.unitree.webrtc_controller_mac_mismatch",
    "robot.unitree.webrtc_session_in_denied_window",
    "robot.unitree.webrtc_concurrent_sessions",
    "robot.unitree.webrtc_relayed_session",
    "robot.unitree.webrtc_media_without_signalling",
];

#[test]
fn unitree_entries_added_after_2_2_are_not_in_2_2_or_earlier() {
    let g = generic();
    for id in IDS_2_3_UNITREE {
        let full = rule_info(id);
        assert_ne!(full, g, "{id} has its own entry in the current catalog");
        assert_eq!(full.data_source, "ros2_motion_commands", "{id}");
        for v in ["1.0.0", "1.3.0", "2.0.0", "2.1.0", "2.2.0", "2.2.9"] {
            assert_eq!(rule_info_for_contract(id, v), g, "{id} @ {v}");
        }
        for v in ["2.3.0", "2.3.4", "2.9.0"] {
            assert_eq!(rule_info_for_contract(id, v), full, "{id} @ {v}");
        }
        assert_eq!(rule_info_for_contract(id, "x"), full);
        // Not shadowing another 2.3 block.
        assert!(
            !IDS_2_3_SEAL.contains(id)
                && !IDS_2_3_GATEWAY.contains(id)
                && !IDS_2_3_DEPOT.contains(id)
        );
    }
}

#[test]
fn a_2_2_unitree_message_validates_with_its_own_catalog() {
    for id in IDS_2_3_UNITREE {
        let v23 = build(id);
        robodr_ocsf::parse_and_validate(&v23).unwrap_or_else(|e| panic!("{id}: {e:?}"));
        let v22 = seal_as_2_2(&v23, id);
        assert_ne!(v22, v23);
        robodr_ocsf::parse_and_validate(&v22).unwrap_or_else(|e| panic!("{id} 2.2: {e:?}"));
        let up = v22.replace(
            "\"contract_version\":\"2.2.0\"",
            &format!("\"contract_version\":\"{CONTRACT_VERSION}\""),
        );
        assert!(robodr_ocsf::parse_and_validate(&up).is_err(), "{id}");
    }
}

/// The 2.5 agent entries (sales-readiness WP2: T5 health record, T6
/// credential expiry, T7 clock, T40 disk, T41 executor reachability; WP3:
/// T81 control-plane fencing, connections refused or cut before
/// authentication; WP4 T15 black-box retention pressure and unexported
/// drops; an id reserved for T13 self-test).
const IDS_2_5_AGENT: &[&str] = &[
    "robot.agent.health",
    "robot.agent.credential_expiring",
    "robot.agent.clock_unsynced",
    "robot.agent.clock_jump",
    "robot.agent.disk_low",
    "robot.agent.executor_unreachable",
    "robot.agent.restart_pending",
    "robot.agent.executor_pause_overridden",
    "robot.agent.config_unattested",
    "robot.agent.evidence_retention_pressure",
    "robot.agent.evidence_unexported_dropped",
    "robot.agent.control_plane_request_fenced",
    "robot.agent.control_plane_saturated",
    "robot.agent.control_plane_replay_unavailable",
    "robot.agent.selftest",
];

/// The 2.5 discovery entries (WP7: DDS transports the capture cannot
/// inspect, SROS 2 keystore identities).
const IDS_2_5_GRAPH: &[&str] = &[
    "robot.capture.unsupported_transport",
    "robot.ros2.untrusted_security_identity",
];

#[test]
fn entries_added_in_2_5_are_not_in_2_4_or_earlier() {
    let g = generic();
    let host: Vec<&str> = robodr_ocsf::HOST_RULES.iter().map(|(_, id)| *id).collect();
    let all = IDS_2_5_AGENT
        .iter()
        .map(|id| (*id, "robodr_agent"))
        .chain(std::iter::once((
            "robot.gateway.overload",
            "ros2_motion_commands",
        )))
        .chain(IDS_2_5_GRAPH.iter().map(|id| (*id, "ros2_dds_discovery")))
        .chain(host.iter().map(|id| (*id, "host_runtime")));
    let mut n = 0;
    for (id, source) in all {
        n += 1;
        let full = rule_info(id);
        assert_ne!(full, g, "{id} has its own entry in the current catalog");
        assert!(robodr_ocsf::builder::rule_known(id), "{id}");
        assert_eq!(full.data_source, source, "{id}");
        assert!(full.techniques.is_empty(), "{id}");
        for v in ["1.3.0", "2.0.0", "2.3.0", "2.4.0", "2.4.9"] {
            assert_eq!(rule_info_for_contract(id, v), g, "{id} @ {v}");
        }
        for v in ["2.5.0", "2.5.1", "2.9.0"] {
            assert_eq!(rule_info_for_contract(id, v), full, "{id} @ {v}");
        }
        if id == robodr_ocsf::AGENT_HEALTH_RULE {
            continue; // needs its record: tests/agent_health.rs
        }
        let v25 = build(id);
        robodr_ocsf::parse_and_validate(&v25).unwrap_or_else(|e| panic!("{id}: {e:?}"));
        let down = v25.replace(
            &format!("\"contract_version\":\"{CONTRACT_VERSION}\""),
            "\"contract_version\":\"2.4.0\"",
        );
        assert!(robodr_ocsf::parse_and_validate(&down).is_err(), "{id}");
    }
    assert_eq!(
        n,
        IDS_2_5_AGENT.len() + 1 + IDS_2_5_GRAPH.len() + host.len()
    );
    // Everything older is unchanged in 2.5, the fallback host id included.
    for id in IDS_2_4.iter().chain(IDS_1_3).chain(IDS_2_2) {
        assert_eq!(
            rule_info_for_contract(id, "2.5.0"),
            rule_info_for_contract(id, "2.4.0"),
            "{id}"
        );
    }
}
