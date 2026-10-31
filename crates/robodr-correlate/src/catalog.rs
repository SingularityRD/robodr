//! The signal vocabulary the correlation rules are validated against.
//!
//! Two sources, both kept in sync with the rest of the repository by the
//! `catalog_drift` integration test:
//!
//! * [`NETWORK_AND_AGENT_RULES`]: the `robot.*` deviation rule ids raised by
//!   the in-repo detectors (`robodr-events` profile, `robodr-ros2-pipeline`,
//!   `robodr-firewall`, `robodr-motion`, `robodr-agentd` self-health). The
//!   test checks each one still appears as a string literal in some other
//!   crate's `src/`.
//! * [`PULSAR_RULES`]: the `name` of every rule in `rules/robodr/*.toml`, i.e.
//!   what Pulsar's rule engine puts in a threat for a host-side detection.
//!   The test checks the two lists are equal in both directions, so a new
//!   host rule cannot be added without the catalog noticing.
//!
//! An id outside the catalog is *allowed* in a correlation rule (a
//! deployment may add its own Pulsar rules); [`crate::RuleSet::from_json`]
//! reports it as a warning, because a typo there silently disables a rule.

/// `robot.*` rule ids produced by RoboDR's own detectors.
pub const NETWORK_AND_AGENT_RULES: &[&str] = &[
    // robodr-events profile
    "robot.ros2.unknown_participant",
    "robot.ros2.unauthorized_motion_writer",
    "robot.ros2.unknown_writer_topic",
    "robot.ros2.unknown_service",
    "robot.ros2.unknown_action",
    "robot.dds.unknown_raw_writer",
    "robot.ros2.unknown_reader",
    "robot.ros2.unknown_reader_topic",
    "robot.motion.non_finite_command",
    "robot.motion.unprofiled_channel",
    "robot.profile.invalid_envelope",
    "robot.motion.linear_over_envelope",
    "robot.motion.joint_over_envelope",
    "robot.motion.control_handover",
    "robot.motion.angular_over_envelope",
    // robodr-ros2-pipeline
    "robot.ros2.profile_refused",
    "robot.ros2.profile_state_tampered",
    "robot.ros2.participant_removed",
    "robot.rtps.malformed_discovery",
    "robot.rtps.fragmented_discovery",
    "robot.rtps.discovery_fragment_rejected",
    "robot.rtps.discovery_fragment_conflict",
    "robot.rtps.discovery_fragment_evicted",
    "robot.rtps.discovery_removal",
    "robot.capture.malformed_frames",
    "robot.capture.ip_fragment_conflict",
    "robot.capture.ip_reassembly_dropped",
    "robot.capture.ip_reassembly_evicted",
    "robot.capture.ip_fragment_refused",
    "robot.capture.ip_fragment_duplicate_conflict",
    "robot.capture.bad_checksum",
    "robot.capture.not_udp",
    "robot.capture.unsupported_middleware",
    "robot.capture.unsupported_transport",
    "robot.ros2.ambiguous_discovery",
    "robot.rtps.discovery_not_inspected",
    "robot.sensor.findings_capped",
    "robot.ros2.endpoint_source_mismatch",
    "robot.ros2.endpoint_unannounced_participant",
    "robot.ros2.participant_source_mismatch",
    "robot.ros2.identity_instances_exceeded",
    "robot.ros2.untrusted_security_identity",
    "robot.motion.undecodable_sample",
    "robot.motion.unattributed_sample",
    "robot.motion.sample_source_mismatch",
    "robot.motion.unverifiable_command",
    "robot.motion.decode_anomaly",
    "robot.motion.api_id_out_of_range",
    "robot.unitree.legacy_unknown_sender",
    "robot.unitree.legacy_sender_flood",
    "robot.unitree.legacy_sender_mac_mismatch",
    "robot.unitree.legacy_port_rtps",
    "robot.motion.command_type_mismatch",
    // robodr-firewall
    "robot.firewall.rejected_clock_regression",
    "robot.firewall.rejected_unknown_channel",
    "robot.firewall.rejected_unknown_source",
    "robot.firewall.rejected_unauthorized_source",
    "robot.firewall.rejected_rate_limited",
    "robot.firewall.rejected_kind_mismatch",
    "robot.firewall.rejected_non_finite",
    "robot.firewall.rejected_future_timestamp",
    "robot.firewall.rejected_stale",
    "robot.firewall.rejected_out_of_order",
    "robot.firewall.rejected_over_hard_limit",
    "robot.firewall.internal_fault",
    "robot.firewall.limited_speed",
    "robot.firewall.limited_acceleration",
    "robot.firewall.limited_jerk",
    "robot.firewall.events_dropped",
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
    // robodr-motion consistency monitor
    "robot.motion.feedback_divergence",
    "robot.motion.uncommanded_motion",
    "robot.motion.frozen_feedback",
    "robot.motion.cross_sensor_disagreement",
    "robot.motion.invalid_feedback",
    "robot.motion.multiple_feedback_publishers",
    "robot.motion.inconsistent_feedback_stream",
    // robodr-agentd discovery-flood aggregation (red team F1)
    "robot.ros2.discovery_flood",
    // robodr-deliverd (secure delivery, Sprint 13b): spooled directly by the
    // delivery agent, not through agentd's correlator; listed so rule files
    // may name them and the drift test sees them.
    "robot.deliver.installed",
    "robot.deliver.deferred_safety",
    "robot.deliver.health_failed",
    "robot.deliver.rollback_blocked_floor",
    "robot.deliver.refused",
    "robot.deliver.stale",
    "robot.deliver.chain_gap",
    // robodr-deliverd sealing (captured-unit protection, Sprint 13c,
    // contract 2.3): spooled directly by the delivery agent as above.
    "robot.seal.unseal_failed",
    "robot.seal.lease_expired",
    "robot.seal.erased",
    "robot.seal.tamper",
    // Go2 WebRTC sessions (robodr-ros2-pipeline::webrtc via the in-path
    // gateway's `webrtc` section and agentd's gateway feed; contract 2.3).
    "robot.unitree.webrtc_unknown_controller",
    "robot.unitree.webrtc_new_peer",
    "robot.unitree.webrtc_controller_mac_mismatch",
    "robot.unitree.webrtc_session_in_denied_window",
    "robot.unitree.webrtc_concurrent_sessions",
    "robot.unitree.webrtc_relayed_session",
    "robot.unitree.webrtc_media_without_signalling",
    // Sprints 14a / 14b (contract 2.3): the executed erase's deferral
    // (robodr-deliverd) and the site depot's own findings (robodr-depot),
    // spooled directly like the delivery agent's.
    "robot.seal.erase_deferred",
    "robot.depot.import_refused",
    "robot.depot.enrolment_refused",
    "robot.depot.unit_enrolled",
    "robot.depot.rollout_halted",
    "robot.depot.locked",
    // robodr-firewall-gw in-path gateway (Sprint 8, contract 2.3): fed to
    // agentd through its `gateway_feed` socket and correlated like any input.
    "robot.gateway.trajectory_rejected",
    "robot.gateway.trajectory_time_scaled",
    "robot.gateway.undecodable_command",
    "robot.gateway.fragmented_command",
    "robot.gateway.writer_binding_conflict",
    "robot.gateway.sequence_jump",
    "robot.gateway.port_bypass_risk",
    "robot.gateway.restriction_changed",
    "robot.gateway.findings_dropped",
    // robodr-agentd self-health (always observe-only downstream)
    "robot.agent.input_silent",
    "robot.agent.input_ended",
    "robot.agent.queue_overflow",
    "robot.agent.input_malformed",
    "robot.agent.pipeline_lag",
    "robot.agent.spool_full",
    "robot.agent.evidence_degraded",
    "robot.agent.evidence_quarantined",
    "robot.agent.evidence_truncated",
    // robodr-agentd control-plane API (observe-only self-health)
    "robot.agent.control_plane_unauthenticated",
    "robot.agent.control_plane_invalid",
    "robot.agent.control_plane_state_untrusted",
    // robodr-agentd executor link (failed revert, executor journal reset)
    "robot.agent.executor_revert_failed",
    "robot.agent.executor_journal_reset",
    "robot.agent.executor_pause_overridden",
    // robodr-agentd early warnings (contract 2.5, `selfcheck`). The
    // periodic `robot.agent.health` record is never fed to the engine.
    "robot.agent.credential_expiring",
    "robot.agent.clock_unsynced",
    "robot.agent.clock_jump",
    "robot.agent.disk_low",
    "robot.agent.executor_unreachable",
    // robodr-agentd: gated units an upgrade left on the previous binaries
    "robot.agent.restart_pending",
    // Contract 2.5 ids reserved for their producers (control-plane replay
    // fence, field self-test, in-path gateway overload).
    "robot.agent.control_plane_request_fenced",
    "robot.agent.selftest",
    "robot.gateway.overload",
    // robodr-agentd commissioning: a safety configuration file (response
    // policy, firewall joint config) not bound to the trusted locked profile
    "robot.agent.config_unattested",
    // robodr-agentd live safety-state feed
    "robot.safety_state.untrusted_source",
    "robot.safety_state.undecodable_sample",
    "robot.safety_state.unmapped_value",
    "robot.safety_state.writer_overflow",
];

/// Names of the host-side Pulsar rules in `rules/robodr/*.toml`.
pub const PULSAR_RULES: &[&str] = &[
    // kernel_modules.toml
    "RoboDR: Kernel module file written outside the package manager",
    "RoboDR: Kernel module autoload configuration changed",
    "RoboDR: Kernel module file or autoload configuration moved into place outside the package manager",
    "RoboDR: Kernel module file or autoload configuration linked into place outside the package manager",
    // radio_provisioning.toml
    "RoboDR: Bluetooth tooling executed on robot controller",
    "RoboDR: Wi-Fi configuration tooling executed on robot controller",
    "RoboDR: Wireless network configuration modified",
    "RoboDR: Wireless network configuration moved into or out of place",
    "RoboDR: Link created in a wireless network configuration directory",
    // ros2_stack.toml
    "RoboDR: Interactive shell started on robot controller",
    "RoboDR: Login shell started on robot controller",
    "RoboDR: ROS 2 process connects outside the robot's networks",
    "RoboDR: ROS 2 install tree written outside the package manager",
    "RoboDR: File created or moved into the ROS 2 install tree outside the package manager",
    "RoboDR: Link created inside the ROS 2 install tree outside the package manager",
    "RoboDR: Shell or netcat-style tool opened a network connection",
    // runtime_hooking.toml
    "RoboDR: ROS 2 process loaded a library from outside the allowlisted library paths",
    "RoboDR: ROS 2 process mapped an ELF from outside the allowlisted paths",
    "RoboDR: ELF opened from a world-writable or user cache directory",
    "RoboDR: ROS 2 process loaded /etc/ld.so.preload",
    "RoboDR: Unexpected ROS 2 middleware (RMW) library loaded",
    "RoboDR: Shared library opened from a temporary directory",
    "RoboDR: Program executed from a temporary directory",
    "RoboDR: Shared library written into a system library path outside the package manager",
    "RoboDR: File moved into a system library path or linker configuration outside the package manager",
    "RoboDR: Link created in a system library path or linker configuration outside the package manager",
    "RoboDR: Existing file in a system library path opened for writing outside the package manager",
    "RoboDR: Dynamic linker search path changed",
    "RoboDR: Process memory written through /proc",
    "RoboDR: Debugger or tracer started on robot controller",
    "RoboDR: Program executed from a file descriptor or /proc path",
    "RoboDR: Program executed through a non-canonical path",
    "RoboDR: ROS 2 process imported Python code from outside the allowlisted paths",
    "RoboDR: Interpreter one-liner executed",
    "RoboDR: Interactive or stdin-fed Python interpreter started",
    "RoboDR: Pseudo-terminal wrapper executed on robot controller",
    "RoboDR: Package manager loaded a library from outside the system library paths",
    "RoboDR: Package manager mapped an ELF from outside the system paths",
    // self_protection.toml
    "RoboDR: RoboDR or Pulsar protected file written",
    "RoboDR: RoboDR or Pulsar protected file deleted",
    "RoboDR: RoboDR or Pulsar protected file or directory renamed",
    "RoboDR: File or device node created in a RoboDR or Pulsar protected path",
    "RoboDR: Link created in or to a RoboDR or Pulsar protected path",
    "RoboDR: Directory created in a RoboDR or Pulsar protected path",
    "RoboDR: RoboDR or Pulsar protected directory deleted",
    "RoboDR: Attempt to stop the Pulsar or RoboDR service",
    // sros2_keystore.toml
    "RoboDR: SROS 2 enclave private key read by a process outside the ROS stack",
    "RoboDR: SROS 2 CA private key accessed on robot",
    "RoboDR: SROS 2 keystore file written",
    "RoboDR: SROS 2 keystore file renamed or replaced",
    "RoboDR: Link created to an SROS 2 private key",
    "RoboDR: Link created inside an SROS 2 enclave directory",
    "RoboDR: SROS 2 security files loaded from outside the commissioned keystore",
    // supply_chain.toml
    "RoboDR: Debian package installed on robot controller",
    "RoboDR: Debian package maintainer script executed",
    "RoboDR: Debian package database changed",
    "RoboDR: Python package installed on robot controller",
    "RoboDR: Python package installed with uv, pipx, poetry or conda/mamba",
    "RoboDR: Node.js package installed with npm, npx, pnpm or yarn",
    "RoboDR: File created in the system or ROS Python environment outside the package manager",
    "RoboDR: File moved into the system or ROS Python environment outside the package manager",
    "RoboDR: Link created in the system or ROS Python environment outside the package manager",
    // unitree.toml
    "RoboDR: Unitree Wi-Fi provisioning script executed",
    "RoboDR: Unitree Wi-Fi provisioning script opened",
    "RoboDR: Bluetooth daemon or Wi-Fi provisioning script opened an IP connection",
    "RoboDR: Bluetooth pairing keys or configuration modified outside bluetoothd",
    "RoboDR: Bluetooth pairing keys or configuration moved into place outside bluetoothd",
    "RoboDR: Service or autostart entry written outside the package manager",
    "RoboDR: Service or autostart entry moved into place outside the package manager",
    "RoboDR: Service enabled, masked or linked outside the package manager",
    "RoboDR: Boot, network or udev hook written outside the package manager",
    "RoboDR: Boot, network or udev hook moved into place outside the package manager",
    "RoboDR: Boot, network or udev hook linked outside the package manager",
    "RoboDR: Shell startup or login environment file modified",
    "RoboDR: Shell startup or login environment file moved into place",
    "RoboDR: Shell startup or login environment file linked",
    "RoboDR: Unitree robot process connects outside the allowlisted destinations",
    "RoboDR: Program in a user-writable directory connects to a public address",
    "RoboDR: Reverse tunnel client executed on robot",
    "RoboDR: SSH reverse or dynamic tunnel with bundled options",
    "RoboDR: Remote-access overlay VPN started on robot",
    "RoboDR: Unitree DDS configuration modified",
    "RoboDR: Unitree DDS configuration moved into place",
    "RoboDR: Unitree SDK or Cyclone DDS library modified outside the package manager",
    "RoboDR: Unitree SDK or Cyclone DDS library moved into place outside the package manager",
    "RoboDR: Unitree SDK or Cyclone DDS library linked outside the package manager",
];

/// Is `id` a known signal id (either list)?
pub fn is_known(id: &str) -> bool {
    NETWORK_AND_AGENT_RULES.contains(&id) || PULSAR_RULES.contains(&id)
}

/// Does `prefix` match at least one known signal id?
pub fn prefix_matches_known(prefix: &str) -> bool {
    NETWORK_AND_AGENT_RULES
        .iter()
        .chain(PULSAR_RULES.iter())
        .any(|id| id.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn no_duplicates() {
        let mut seen = BTreeSet::new();
        for id in NETWORK_AND_AGENT_RULES.iter().chain(PULSAR_RULES.iter()) {
            assert!(seen.insert(*id), "duplicate catalog id {id}");
        }
    }

    #[test]
    fn shapes() {
        for id in NETWORK_AND_AGENT_RULES {
            assert!(id.starts_with("robot."), "{id}");
            assert!(!id.starts_with("robot.correlate."), "{id}");
        }
        for id in PULSAR_RULES {
            assert!(id.starts_with("RoboDR: "), "{id}");
        }
        assert!(is_known("robot.ros2.unknown_participant"));
        assert!(!is_known("robot.ros2.unknown_participan"));
        assert!(prefix_matches_known("robot.capture."));
        assert!(prefix_matches_known("RoboDR: SROS 2 "));
        assert!(!prefix_matches_known("robot.nope."));
    }
}
