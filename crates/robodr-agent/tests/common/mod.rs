#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use robodr_agent::*;
use robodr_blackbox::record::{scan_frames, ScanItem};
use robodr_blackbox::verify::read_segments;
use robodr_blackbox::{HmacSha256Key, Record, RecorderConfig};
use robodr_events::profile::Profile;
use robodr_events::RobotEvent;
use robodr_ocsf::{BlackBoxRef, PlatformFamily as OcsfPlatform, RobotInfo};
use robodr_responder::{
    Connectivity, ControlMode, MissionPhase, OperationalContext, ResponsePolicy,
};

pub const KEY: [u8; 32] = [0x42; 32];
pub const MS: u64 = 1_000_000;
/// 2026-01-01T00:00:00Z in ns.
pub const START_NS: u64 = 1_767_225_600_000 * MS;
pub const ROBOT: &str = "ugv-007";
pub const LEGIT: &str = "01103f5a8c2e000000000101";
pub const LEGIT_WRITER: &str = "01103f5a8c2e00000000010100000103";
pub const ROGUE: &str = "0f0f0f0f0f0f0f0f0f0f0f0f";

pub fn examples() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("examples")
}

pub fn key_hex() -> String {
    "42".repeat(32)
}

/// A fresh, empty directory under the system temp dir.
pub fn tmpdir(tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "robodr-agent-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

pub fn demo_profile(locked: bool) -> Profile {
    let text = std::fs::read_to_string(examples().join("ugv-demo.profile.json")).unwrap();
    let mut p: Profile = serde_json::from_str(&text).unwrap();
    p.locked = locked;
    p
}

pub fn validated_policy() -> ResponsePolicy {
    let text = std::fs::read_to_string(examples().join("policy-oem-validated.json")).unwrap();
    let p = ResponsePolicy::from_json(&text).unwrap();
    assert!(p.oem_validated);
    p
}

pub fn context() -> OperationalContext {
    OperationalContext {
        platform: robodr_responder::PlatformFamily::Ugv,
        phase: MissionPhase::Transit,
        connectivity: Connectivity::Connected,
        control: ControlMode::Autonomous,
        operator_present: true,
        profile_locked: true,
    }
}

pub fn config(dir: &Path, profile: Profile, policy: ResponsePolicy) -> AgentConfig {
    let robot = RobotInfo {
        id: ROBOT.into(),
        model: profile.model.clone(),
        platform_family: OcsfPlatform::LinuxRos2,
        site: "test-site".into(),
        firmware: None,
    };
    AgentConfig::new(
        robot,
        profile,
        policy,
        context(),
        RecorderConfig::new(dir, ROBOT, "boot-1"),
    )
}

pub fn signer() -> Box<HmacSha256Key> {
    Box::new(HmacSha256Key::new("test-key", &KEY).unwrap())
}

pub fn verifier() -> HmacSha256Key {
    HmacSha256Key::new("test-key", &KEY).unwrap()
}

pub fn clock() -> Box<ReplayClock> {
    Box::new(ReplayClock::new(START_NS, 0, 20 * MS, TimeSource::Unknown))
}

pub fn build(cfg: AgentConfig) -> Agent {
    Agent::new(cfg, signer(), clock()).unwrap()
}

/// Event time `t_ns` after start.
pub fn at(t_ns: u64) -> Timestamp {
    Timestamp {
        wall_ns: START_NS + t_ns,
        mono_ns: t_ns,
        source: TimeSource::Unknown,
    }
}

pub fn ev(json: &str) -> RobotEvent {
    serde_json::from_str(json).unwrap()
}

pub fn rogue_participant() -> RobotEvent {
    ev(&format!(
        r#"{{"kind":"ros2_participant_discovered","guid_prefix":"{ROGUE}","src_ip":"10.42.0.66","locators":[]}}"#
    ))
}

pub fn rogue_cmd_vel_writer() -> RobotEvent {
    ev(&format!(
        r#"{{"kind":"ros2_writer_discovered","guid_prefix":"{ROGUE}","topic":"rt/cmd_vel","type_name":"geometry_msgs::msg::dds_::Twist_"}}"#
    ))
}

pub fn cmd(source: &str, v: f64) -> RobotEvent {
    RobotEvent::MotionCommand(robodr_events::MotionCommand {
        channel: "/cmd_vel".into(),
        source_guid: Some(source.into()),
        linear_speed: Some(v),
        joint_speed: None,
    })
}

/// Every decodable record in the black box, keyed by (segment, seq).
pub fn records(dir: &Path) -> Vec<((u64, u64), Record)> {
    let mut out = Vec::new();
    for seg in read_segments(dir).unwrap() {
        let idx = robodr_blackbox::store::parse_segment_file_name(&seg.name).unwrap();
        for item in scan_frames(&seg.bytes).items {
            if let ScanItem::Record(r) = item {
                out.push(((idx, r.record.seq), r.record));
            }
        }
    }
    out
}

pub fn record_at(dir: &Path, r: &BlackBoxRef) -> Record {
    records(dir)
        .into_iter()
        .find(|(k, _)| *k == (r.segment, r.seq))
        .map(|(_, rec)| rec)
        .unwrap_or_else(|| panic!("no record for {r:?}"))
}
