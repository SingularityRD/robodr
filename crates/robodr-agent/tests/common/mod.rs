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

/// An Ed25519 secret key file (seed [`KEY`], key id derived from the
/// public key) with its public file `<path>.pub`, mode 0600, created once
/// per test process. `robodr-replay` takes keys only from such a file
/// (`--key-file`); legacy HMAC key files need `--allow-hmac`.
pub fn key_file() -> PathBuf {
    static PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    PATH.get_or_init(|| {
        let p = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("robodr-replay-test-{}.key", std::process::id()));
        let pubp = robodr_blackbox::keys::public_key_path(&p);
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(&pubp);
        let kf = robodr_blackbox::KeyFile::ed25519_from_seed(&KEY, None).unwrap();
        kf.write_new(&p).unwrap();
        kf.to_public().unwrap().write_new(&pubp).unwrap();
        p
    })
    .clone()
}

/// A legacy HMAC key file holding [`KEY`] (for the `--allow-hmac` path).
pub fn hmac_key_file() -> PathBuf {
    static PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    PATH.get_or_init(|| {
        let p = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "robodr-replay-test-hmac-{}.key",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);
        robodr_blackbox::KeyFile::hmac_from_secret(&KEY, None)
            .unwrap()
            .write_new(&p)
            .unwrap();
        p
    })
    .clone()
}

/// [`key_file`] as an argument string.
pub fn key_arg() -> String {
    key_file().to_string_lossy().into_owned()
}

/// Write `text` to a new file with mode `mode` (for hand-made key files).
pub fn write_mode(path: &Path, text: &str, mode: u32) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let _ = std::fs::remove_file(path);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .unwrap();
    f.write_all(text.as_bytes()).unwrap();
}

/// A key file's JSON text with the given fields.
pub fn key_json(algorithm: &str, key_id: &str, secret_hex: &str) -> String {
    format!(
        r#"{{"format":"robodr-blackbox-key/v1","algorithm":"{algorithm}","key_id":"{key_id}","secret_hex":"{secret_hex}"}}"#
    )
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

/// The OEM angular bound (rad/s) the tests configure for the demo's Twist
/// channel (the profile envelope has none; the firewall requires one).
pub const DEMO_MAX_ANGULAR: f64 = 1.0;

pub fn demo_angular() -> std::collections::BTreeMap<String, f64> {
    std::collections::BTreeMap::from([("/cmd_vel".to_string(), DEMO_MAX_ANGULAR)])
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
        morphology: robodr_responder::Morphology::WheeledMobile,
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
        angular_speed: None,
        ..Default::default()
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
