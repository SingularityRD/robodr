//! The daemon's single configuration file (JSON) and its validation.
//!
//! One file ties everything together; every path in it must be absolute (the
//! daemon's working directory is not defined) and unknown keys are refused at
//! every level, so a typo cannot silently fall back to a default.
//!
//! ```json
//! {
//!   "robot":   { "id": "ugv-007", "site": "lab", "profile_version": "v3" },
//!   "sensor":  { "profile_path": "/etc/robodr/profile.json", "listen_spdp": false,
//!                "capture": { "enabled": true, "interfaces": ["eth0"] } },
//!   "policy_path": "/etc/robodr/policy.json",
//!   "blackbox": { "dir": "/var/lib/robodr/blackbox", "key_file": "/etc/robodr/blackbox.key" },
//!   "spool":    { "dir": "/var/spool/robodr/findings", "max_bytes": 67108864 },
//!   "event_inputs": [ { "kind": "unix_socket", "path": "/run/robodr/events.sock" } ],
//!   "context":  { "safety_state": "unknown", "control": "autonomous" },
//!   "firewall": { "max_angular": { "/cmd_vel": 1.0 } },
//!   "daemon":   { "tick_ms": 1000, "heartbeat_ms": 10000, "silence_ms": 30000 }
//! }
//! ```
//!
//! * `sensor` is exactly the `[module.robodr-sensor-ros2]` section the Pulsar
//!   sensor reads ([`robodr_ros2_pipeline::Config`]), in JSON form, validated
//!   by the same [`robodr_ros2_pipeline::Config::validate`]. Its profile is
//!   the profile of the whole daemon (pipeline and agent). Unlike Pulsar,
//!   which only warns, unknown keys are refused here ([`SENSOR_KEYS`]).
//!   `listen_spdp` defaults to `true` there; set it to `false` when capture
//!   is enabled (capture sees SPDP too).
//! * The black-box key is read from `blackbox.key_file`, never from the
//!   command line: either a `robodr-blackbox-key/v1` JSON key file (as
//!   written by `robodr-blackbox keygen`; HMAC-SHA256 only, its `key_id` is
//!   used) or bare hex (>= 32 bytes; legacy 0.1.0-alpha.1 format). The file
//!   must be a regular file (not a symlink), owned by the daemon's effective
//!   user or root, and not accessible by group or others (`chmod 600`); see
//!   [`read_key_file`]. A `blackbox.key_id` that contradicts the key file's
//!   own id is a configuration error.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use robodr_motion::{FeedbackSource, MonitorConfig};
use robodr_responder::{Connectivity, ControlMode, MissionPhase, ResponsePolicy, SafetyState};
use robodr_ros2_pipeline::config::Settings;
use robodr_ros2_pipeline::{load_profile, LoadedProfile};
use serde::Deserialize;

/// Max size of the daemon config, the policy and a monitor config file.
pub const MAX_CONFIG_BYTES: u64 = 4 << 20;
/// Max size of the key file (a JSON key file or a hex key plus whitespace).
pub const MAX_KEY_FILE_BYTES: u64 = 4096;
/// Most event inputs.
pub const MAX_EVENT_INPUTS: usize = 8;
/// Most concurrent connections on one unix-socket event input.
pub const MAX_SOCKET_CONNECTIONS: usize = 64;

/// The keys of the `sensor` section (`robodr_ros2_pipeline::Config`), its
/// `capture` and its `binding` sub-tables. `Config` ignores unknown keys (it
/// is shared with Pulsar, which only warns); the daemon refuses them.
/// Keep in sync with `robodr-ros2-pipeline/src/config.rs`.
pub const SENSOR_KEYS: &[&str] = &[
    "profile_path",
    "domain_id",
    "spdp_port",
    "spdp_group",
    "interface",
    "listen_spdp",
    "dedup_capacity",
    "report_anomalies",
    "report_fragmentation",
    "max_findings_per_datagram",
    "rate_limit_burst",
    "rate_limit_interval_ms",
    "capture",
    "binding",
];
/// Keys of `sensor.capture`.
pub const SENSOR_CAPTURE_KEYS: &[&str] = &[
    "enabled",
    "interfaces",
    "pcap_replay",
    "domain_ids",
    "read_timeout_ms",
    "queue_capacity",
];
/// Keys of `sensor.binding` (`participant_ips` is a free-form map).
pub const SENSOR_BINDING_KEYS: &[&str] = &[
    "enabled",
    "hold_ms",
    "max_participants",
    "discovery_server",
    "participant_ips",
];

/// The configuration file as written.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    pub robot: RobotSection,
    /// The ROS 2 sensor section (see the module docs).
    pub sensor: serde_json::Value,
    pub policy_path: PathBuf,
    pub blackbox: BlackboxSection,
    pub spool: SpoolSection,
    #[serde(default)]
    pub event_inputs: Vec<EventInputConfig>,
    #[serde(default)]
    pub context: ContextSection,
    /// Motion Firewall decision core on `MotionCommand` events (JSONL inputs).
    #[serde(default)]
    pub firewall: Option<FirewallSection>,
    /// Motion/feedback consistency monitor on JSONL events.
    #[serde(default)]
    pub motion_monitor: Option<MonitorSection>,
    #[serde(default)]
    pub daemon: DaemonSection,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RobotSection {
    /// `[A-Za-z0-9._-]{1,64}`; also the black-box device id.
    pub id: String,
    pub site: String,
    /// Robot model for findings; default: the profile's model.
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default = "default_profile_version")]
    pub profile_version: String,
    /// Kafka partition count of `robot-edr.findings`, if known.
    #[serde(default)]
    pub kafka_partitions: Option<u32>,
}

fn default_profile_version() -> String {
    "unversioned".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlackboxSection {
    pub dir: PathBuf,
    /// HMAC key file: `robodr-blackbox-key/v1` JSON or hex (see
    /// [`read_key_file`]).
    pub key_file: PathBuf,
    /// Key id. Default: the key file's `key_id` (JSON key file), else
    /// derived from the key. Must equal the JSON key file's id if both are
    /// given.
    #[serde(default)]
    pub key_id: Option<String>,
    /// Boot id; default: `/proc/sys/kernel/random/boot_id`.
    #[serde(default)]
    pub boot_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpoolSection {
    pub dir: PathBuf,
    /// Bound on `ready/` + `acked/` bytes (default 64 MiB, min 64 KiB).
    #[serde(default = "default_spool_bytes")]
    pub max_bytes: u64,
    /// Bound on `ready/` + `acked/` files (default 10000).
    #[serde(default = "default_spool_files")]
    pub max_files: u64,
}

fn default_spool_bytes() -> u64 {
    64 << 20
}
fn default_spool_files() -> u64 {
    10_000
}

/// A source of JSON Lines `RobotEvent`s (one event per line, the format of
/// `robodr-replay` / `robodr-commission`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EventInputConfig {
    /// Standard input. EOF ends the input.
    Stdin,
    /// A unix stream socket the daemon creates (mode 0600). Each connection
    /// sends JSON lines; the input never ends on its own.
    UnixSocket {
        path: PathBuf,
        #[serde(default = "default_connections")]
        max_connections: usize,
    },
}

fn default_connections() -> usize {
    4
}

/// Platform context. The daemon has no live safety-state feed yet: the
/// configured value is used for every plan (default `unknown`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextSection {
    #[serde(default = "default_safety")]
    pub safety_state: SafetyState,
    #[serde(default = "default_control")]
    pub control: ControlMode,
    #[serde(default = "default_phase")]
    pub phase: MissionPhase,
    #[serde(default = "default_connectivity")]
    pub connectivity: Connectivity,
    #[serde(default = "default_true")]
    pub operator_present: bool,
}

fn default_safety() -> SafetyState {
    SafetyState::Unknown
}
fn default_control() -> ControlMode {
    ControlMode::Autonomous
}
fn default_phase() -> MissionPhase {
    MissionPhase::Unknown
}
fn default_connectivity() -> Connectivity {
    Connectivity::Connected
}
fn default_true() -> bool {
    true
}

impl Default for ContextSection {
    fn default() -> Self {
        Self {
            safety_state: default_safety(),
            control: default_control(),
            phase: default_phase(),
            connectivity: default_connectivity(),
            operator_present: true,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallSection {
    /// Per Twist channel: the OEM's yaw-rate bound (rad/s). Required for
    /// every profiled Twist channel (see `robodr_agent::FirewallSettings`).
    #[serde(default)]
    pub max_angular: BTreeMap<String, f64>,
    /// Per channel: allowed writer GUIDs (default: every profiled participant).
    #[serde(default)]
    pub allow: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MonitorSection {
    /// `robodr_motion::MonitorConfig` JSON (strict); default: UGV defaults
    /// correlating the profile's motion channels.
    #[serde(default)]
    pub config_path: Option<PathBuf>,
    /// Feedback channel -> provenance.
    #[serde(default)]
    pub feedback_sources: BTreeMap<String, FeedbackSource>,
}

/// Loop timing, queue bound and self-health thresholds (milliseconds).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DaemonSection {
    /// Bound of the input -> pipeline queue (shared by all inputs). A full
    /// queue drops the newest item and counts it (see `health`).
    pub queue_capacity: usize,
    /// Housekeeping period: `Pipeline::tick`, capture health, self-health,
    /// status file, spool pruning. 1000 ms = the 1 Hz the pipeline expects.
    pub tick_ms: u64,
    /// Heartbeat note in the black box every this many ms.
    pub heartbeat_ms: u64,
    /// An input that delivered nothing for this long is "silent".
    pub silence_ms: u64,
    /// An item that waited longer than this in the queue (or a late tick)
    /// means the pipeline lags.
    pub lag_ms: u64,
    /// Minimum interval between two findings about the same recurring
    /// counter (queue drops, malformed input, spool trouble).
    pub health_report_ms: u64,
    /// Stop once every input has ended (pcap replay, stdin EOF) and the
    /// queue is drained. Off for a live daemon: an input that ends is then a
    /// health finding and the daemon keeps running ("unknown" state).
    pub exit_when_inputs_end: bool,
}

impl Default for DaemonSection {
    fn default() -> Self {
        Self {
            queue_capacity: 4096,
            tick_ms: 1000,
            heartbeat_ms: 10_000,
            silence_ms: 30_000,
            lag_ms: 2_000,
            health_report_ms: 10_000,
            exit_when_inputs_end: false,
        }
    }
}

/// A validated configuration with every referenced file loaded.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub config: DaemonConfig,
    /// The validated sensor section.
    pub sensor: Settings,
    /// The profile as loaded (with its commissioning file check).
    pub profile: LoadedProfile,
    pub policy: ResponsePolicy,
    pub monitor: Option<MonitorConfig>,
    /// Black-box key bytes (never printed by `Debug`).
    pub key: KeyBytes,
    /// Effective key id: `blackbox.key_id`, else the JSON key file's id,
    /// else `None` (derived from the key).
    pub key_id: Option<String>,
    pub boot_id: String,
    /// Non-fatal warnings to log at start.
    pub warnings: Vec<String>,
}

impl std::fmt::Debug for KeyBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyBytes(<{} bytes>)", self.0.len())
    }
}

/// Key material wrapper that does not print its bytes.
#[derive(Clone)]
pub struct KeyBytes(pub Vec<u8>);

/// Read a size-capped UTF-8 file.
pub fn read_capped(path: &Path, max: u64) -> Result<String, String> {
    let f = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut s = String::new();
    f.take(max + 1)
        .read_to_string(&mut s)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if s.len() as u64 > max {
        return Err(format!("{}: larger than {max} bytes", path.display()));
    }
    Ok(s)
}

/// Parse the configuration text (no file access).
pub fn parse(text: &str) -> Result<DaemonConfig, String> {
    serde_json::from_str(text).map_err(|e| format!("config: {e}"))
}

/// Read and fully resolve the configuration at `path`.
pub fn load(path: &Path) -> Result<Resolved, String> {
    let text = read_capped(path, MAX_CONFIG_BYTES)?;
    resolve(parse(&text)?)
}

fn require_abs(what: &str, p: &Path) -> Result<(), String> {
    if p.as_os_str().is_empty() || !p.is_absolute() {
        return Err(format!(
            "{what} must be an absolute path, got {:?}",
            p.display().to_string()
        ));
    }
    Ok(())
}

/// Refuse keys `allowed` does not list in a JSON object.
fn check_keys(what: &str, v: &serde_json::Value, allowed: &[&str]) -> Result<(), String> {
    let Some(obj) = v.as_object() else {
        return Err(format!("{what} must be an object"));
    };
    let unknown: Vec<&str> = obj
        .keys()
        .map(String::as_str)
        .filter(|k| !allowed.contains(k))
        .collect();
    if unknown.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{what}: unknown key(s): {}",
            robodr_ros2_pipeline::sanitize(&unknown.join(", "))
        ))
    }
}

/// Strictly parse and validate the `sensor` section.
pub fn sensor_settings(v: &serde_json::Value) -> Result<(Settings, Vec<String>), String> {
    check_keys("sensor", v, SENSOR_KEYS)?;
    if let Some(c) = v.get("capture") {
        check_keys("sensor.capture", c, SENSOR_CAPTURE_KEYS)?;
    }
    if let Some(b) = v.get("binding") {
        check_keys("sensor.binding", b, SENSOR_BINDING_KEYS)?;
    }
    let cfg: robodr_ros2_pipeline::Config =
        serde_json::from_value(v.clone()).map_err(|e| format!("sensor: {e}"))?;
    if let Some(p) = &cfg.capture.pcap_replay {
        require_abs("sensor.capture.pcap_replay", p)?;
    }
    cfg.validate().map_err(|e| format!("sensor: {e}"))
}

/// Validate the daemon section's numbers.
pub fn validate_daemon(d: &DaemonSection) -> Result<(), String> {
    let range = |what: &str, v: u64, lo: u64, hi: u64| {
        if (lo..=hi).contains(&v) {
            Ok(())
        } else {
            Err(format!("daemon.{what} = {v}: must be {lo}..={hi}"))
        }
    };
    range("queue_capacity", d.queue_capacity as u64, 1, 1 << 20)?;
    range("tick_ms", d.tick_ms, 10, 60_000)?;
    range("heartbeat_ms", d.heartbeat_ms, d.tick_ms, 3_600_000)?;
    range("silence_ms", d.silence_ms, d.tick_ms, 86_400_000)?;
    range("lag_ms", d.lag_ms, 10, 3_600_000)?;
    range("health_report_ms", d.health_report_ms, 0, 86_400_000)?;
    Ok(())
}

/// Validate a parsed configuration and load every file it names.
pub fn resolve(config: DaemonConfig) -> Result<Resolved, String> {
    let mut warnings = Vec::new();
    if !robodr_ocsf::validate::is_valid_robot_id(&config.robot.id) {
        return Err(format!(
            "robot.id {:?} must match [A-Za-z0-9._-]{{1,64}}",
            robodr_ros2_pipeline::sanitize(&config.robot.id)
        ));
    }
    require_abs("policy_path", &config.policy_path)?;
    require_abs("blackbox.dir", &config.blackbox.dir)?;
    require_abs("blackbox.key_file", &config.blackbox.key_file)?;
    require_abs("spool.dir", &config.spool.dir)?;
    if config.spool.max_bytes < 64 * 1024 {
        return Err("spool.max_bytes must be >= 65536".into());
    }
    if config.spool.max_files == 0 {
        return Err("spool.max_files must be >= 1".into());
    }
    if config.spool.dir == config.blackbox.dir
        || config.spool.dir.starts_with(&config.blackbox.dir)
        || config.blackbox.dir.starts_with(&config.spool.dir)
    {
        return Err("spool.dir and blackbox.dir must not contain each other".into());
    }
    validate_daemon(&config.daemon)?;
    if config.event_inputs.len() > MAX_EVENT_INPUTS {
        return Err(format!("at most {MAX_EVENT_INPUTS} event_inputs"));
    }
    let mut stdin_seen = false;
    let mut socket_paths: Vec<&Path> = Vec::new();
    for i in &config.event_inputs {
        match i {
            EventInputConfig::Stdin => {
                if std::mem::replace(&mut stdin_seen, true) {
                    return Err("event_inputs: stdin listed twice".into());
                }
            }
            EventInputConfig::UnixSocket {
                path,
                max_connections,
            } => {
                require_abs("event_inputs[].path", path)?;
                if !(1..=MAX_SOCKET_CONNECTIONS).contains(max_connections) {
                    return Err(format!(
                        "event_inputs[].max_connections must be 1..={MAX_SOCKET_CONNECTIONS}"
                    ));
                }
                if socket_paths.contains(&path.as_path()) {
                    return Err("event_inputs: a socket path is listed twice".into());
                }
                socket_paths.push(path);
            }
        }
    }

    let (sensor, mut w) = sensor_settings(&config.sensor)?;
    warnings.append(&mut w);
    if !sensor.has_builtin_source() && config.event_inputs.is_empty() {
        return Err(
            "no input configured: enable sensor.capture, sensor.listen_spdp or add event_inputs"
                .into(),
        );
    }
    let profile = load_profile(&sensor.profile_path)?;
    let policy_text = read_capped(&config.policy_path, MAX_CONFIG_BYTES)?;
    let policy = ResponsePolicy::from_json(&policy_text)
        .map_err(|e| format!("{}: {e}", config.policy_path.display()))?;
    if !policy.oem_validated {
        warnings.push(
            "response policy is not OEM-validated: every plan is observe-only (Record)".into(),
        );
    }
    let monitor = match &config.motion_monitor {
        None => None,
        Some(m) => Some(match &m.config_path {
            Some(p) => {
                require_abs("motion_monitor.config_path", p)?;
                let text = read_capped(p, MAX_CONFIG_BYTES)?;
                robodr_agent::strict_from_str::<MonitorConfig>(&text)
                    .map_err(|e| format!("{}: not a monitor config: {e}", p.display()))?
            }
            None => {
                let mut mc = MonitorConfig::ugv(profile.profile.model.clone());
                mc.command_channels = profile.profile.motion_envelopes.keys().cloned().collect();
                mc
            }
        }),
    };
    if let Some(fw) = &config.firewall {
        for (ch, v) in &fw.max_angular {
            if !v.is_finite() || *v < 0.0 {
                return Err(format!(
                    "firewall.max_angular {:?}: must be finite and >= 0",
                    robodr_ros2_pipeline::sanitize(ch)
                ));
            }
        }
    }
    let (key, file_key_id) = read_key_material(&config.blackbox.key_file)?;
    let key_id = match (&config.blackbox.key_id, file_key_id) {
        (Some(cfg), Some(file)) if *cfg != file => {
            return Err(format!(
                "blackbox.key_id {:?} contradicts the key file's key_id {:?}",
                robodr_ros2_pipeline::sanitize(cfg),
                robodr_ros2_pipeline::sanitize(&file)
            ))
        }
        (Some(cfg), _) => Some(cfg.clone()),
        (None, file) => file,
    };
    let boot_id = match &config.blackbox.boot_id {
        Some(b) => b.clone(),
        None => read_boot_id(),
    };
    Ok(Resolved {
        config,
        sensor,
        profile,
        policy,
        monitor,
        key,
        key_id,
        boot_id,
        warnings,
    })
}

/// This boot's id, or `unknown-boot` when it cannot be read.
pub fn read_boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s.len() <= 64 && !s.chars().any(char::is_control))
        .unwrap_or_else(|| "unknown-boot".into())
}

extern "C" {
    fn geteuid() -> u32;
}

/// The effective uid of this process.
pub fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no arguments, cannot fail and touches no memory.
    unsafe { geteuid() }
}

/// [`read_key_material`] without the key id.
pub fn read_key_file(path: &Path) -> Result<KeyBytes, String> {
    read_key_material(path).map(|(k, _)| k)
}

/// Read the black-box HMAC key from `path`: a `robodr-blackbox-key/v1` JSON
/// key file (HMAC-SHA256 only; returns its key id too) or bare hex
/// (returns no key id). Refuses a file that is a
/// symlink or not a regular file, is readable or writable by group or
/// others, is not owned by the effective user (or root), or is larger than
/// [`MAX_KEY_FILE_BYTES`]. The file is opened once and the checks run on
/// the opened file (`fstat`), compared against the path's `lstat`, so it
/// cannot be swapped between check and read.
pub fn read_key_material(path: &Path) -> Result<(KeyBytes, Option<String>), String> {
    let shown = path.display();
    let lmeta = std::fs::symlink_metadata(path).map_err(|e| format!("key file {shown}: {e}"))?;
    if !lmeta.file_type().is_file() {
        return Err(format!(
            "key file {shown}: not a regular file (symlinks are refused)"
        ));
    }
    let f = File::open(path).map_err(|e| format!("key file {shown}: {e}"))?;
    let meta = f.metadata().map_err(|e| format!("key file {shown}: {e}"))?;
    if meta.ino() != lmeta.ino() || meta.dev() != lmeta.dev() {
        return Err(format!("key file {shown}: changed while being opened"));
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!(
            "key file {shown}: mode {mode:03o} lets group/others access it; chmod 600"
        ));
    }
    let euid = effective_uid();
    if meta.uid() != euid && meta.uid() != 0 {
        return Err(format!(
            "key file {shown}: owned by uid {}, not by the daemon's uid {euid} or root",
            meta.uid()
        ));
    }
    if meta.len() > MAX_KEY_FILE_BYTES {
        return Err(format!(
            "key file {shown}: larger than {MAX_KEY_FILE_BYTES} bytes"
        ));
    }
    let mut text = String::new();
    f.take(MAX_KEY_FILE_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| format!("key file {shown}: {e}"))?;
    if text.trim_start().starts_with('{') {
        // The permission checks above already ran on this descriptor;
        // `from_json` only parses (strict, unknown fields refused).
        let parsed = robodr_blackbox::KeyFile::from_json(&text);
        wipe_text(&mut text);
        let kf = parsed.map_err(|e| format!("key file {shown}: {e}"))?;
        kf.hmac().map_err(|e| format!("key file {shown}: {e}"))?;
        return Ok((KeyBytes(kf.secret().to_vec()), Some(kf.key_id.clone())));
    }
    let key = robodr_blackbox::crypto::from_hex(text.trim());
    wipe_text(&mut text);
    let key = key.ok_or_else(|| format!("key file {shown}: not valid hex"))?;
    if key.len() < 32 {
        return Err(format!(
            "key file {shown}: key is {} bytes, at least 32 needed",
            key.len()
        ));
    }
    Ok((KeyBytes(key), None))
}

/// Best-effort overwrite of a string that held key material.
fn wipe_text(s: &mut String) {
    let n = s.len();
    s.clear();
    s.extend(std::iter::repeat_n('0', n));
    s.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp(tag: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("robodr-agentd-cfg-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write_mode(p: &Path, text: &str, mode: u32) {
        let mut f = File::create(p).unwrap();
        f.write_all(text.as_bytes()).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn key_file_checks() {
        let d = tmp("key");
        let good = d.join("good.key");
        write_mode(&good, &format!("{}\n", "ab".repeat(32)), 0o600);
        assert_eq!(read_key_file(&good).unwrap().0, vec![0xab; 32]);
        assert_eq!(
            format!("{:?}", read_key_file(&good).unwrap()),
            "KeyBytes(<32 bytes>)"
        );

        let open = d.join("open.key");
        write_mode(&open, &"ab".repeat(32), 0o644);
        assert!(read_key_file(&open).unwrap_err().contains("chmod 600"));
        let grp = d.join("grp.key");
        write_mode(&grp, &"ab".repeat(32), 0o620);
        assert!(read_key_file(&grp).is_err());

        let short = d.join("short.key");
        write_mode(&short, &"ab".repeat(8), 0o600);
        assert!(read_key_file(&short).unwrap_err().contains("at least 32"));
        let bad = d.join("bad.key");
        write_mode(&bad, "zz not hex", 0o400);
        assert!(read_key_file(&bad).unwrap_err().contains("hex"));
        let big = d.join("big.key");
        write_mode(&big, &"a".repeat(5000), 0o600);
        assert!(read_key_file(&big).unwrap_err().contains("larger"));

        // robodr-blackbox-key/v1 JSON (as `robodr-blackbox keygen` writes).
        let json = d.join("json.key");
        let kf =
            robodr_blackbox::KeyFile::hmac_from_secret(&[0xcd; 32], Some("ugv-07-bb")).unwrap();
        kf.write_new(&json).unwrap();
        let (k, id) = read_key_material(&json).unwrap();
        assert_eq!(k.0, vec![0xcd; 32]);
        assert_eq!(id.as_deref(), Some("ugv-07-bb"));
        assert_eq!(read_key_material(&good).unwrap().1, None);
        let json_open = d.join("json-open.key");
        write_mode(&json_open, &kf.to_json(), 0o644);
        assert!(read_key_file(&json_open).unwrap_err().contains("chmod 600"));
        let ed = d.join("ed.key");
        write_mode(&ed, &kf.to_json().replace("hmac-sha256", "ed25519"), 0o600);
        assert!(read_key_file(&ed).unwrap_err().contains("unsupported"));
        let junk = d.join("junk.key");
        write_mode(&junk, "{\"format\":\"x\"}", 0o600);
        assert!(read_key_file(&junk).unwrap_err().contains("malformed"));

        let link = d.join("link.key");
        std::os::unix::fs::symlink(&good, &link).unwrap();
        assert!(read_key_file(&link).unwrap_err().contains("symlink"));
        assert!(read_key_file(&d).unwrap_err().contains("regular file"));
        assert!(read_key_file(&d.join("missing")).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// `config/agentd.example.json` (shipped as an example and matching
    /// `packaging/systemd/robodr-agentd.service`) parses strictly, its
    /// sections validate, and it uses the unit's paths.
    #[test]
    fn shipped_example_config_parses() {
        let text = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/agentd.example.json"),
        )
        .unwrap();
        let c = parse(&text).unwrap();
        sensor_settings(&c.sensor).unwrap();
        validate_daemon(&c.daemon).unwrap();
        assert_eq!(
            c.blackbox.key_file,
            Path::new("/run/credentials/robodr-agentd.service/blackbox.key")
        );
        assert_eq!(c.blackbox.dir, Path::new("/var/lib/robodr/blackbox/agentd"));
        assert_eq!(c.spool.dir, Path::new("/var/lib/robodr/spool/agentd"));
        let unit = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../packaging/systemd/robodr-agentd.service"),
        )
        .unwrap();
        assert!(unit.contains("ExecStart=/usr/sbin/robodr-agentd --config /etc/robodr/agentd.json"));
        assert!(unit.contains("LoadCredential=blackbox.key:"));
        assert!(unit.contains(
            "ReadWritePaths=/var/lib/robodr/blackbox/agentd /var/lib/robodr/spool/agentd"
        ));
        assert!(unit.contains("RuntimeDirectory=robodr-agentd"));
    }

    #[test]
    fn sensor_section_is_strict() {
        let ok = serde_json::json!({
            "profile_path": "/etc/robodr/profile.json",
            "listen_spdp": false,
            "capture": {"enabled": true, "pcap_replay": "/x.pcap"},
            "binding": {"hold_ms": 0}
        });
        let (s, _) = sensor_settings(&ok).unwrap();
        assert!(s.capture.is_some() && s.spdp.is_none());
        for (bad, needle) in [
            (
                serde_json::json!({"profile_path": "/p", "listen_spdp": false, "typo": 1}),
                "typo",
            ),
            (
                serde_json::json!({"profile_path": "/p", "capture": {"enabeld": true}}),
                "enabeld",
            ),
            (
                serde_json::json!({"profile_path": "/p", "binding": {"hold": 1}}),
                "hold",
            ),
            (
                serde_json::json!({"profile_path": "/p", "capture": {"enabled": true, "pcap_replay": "rel.pcap"}}),
                "absolute",
            ),
            (
                serde_json::json!({"profile_path": "relative.json"}),
                "absolute",
            ),
            (serde_json::json!([1]), "object"),
            (
                serde_json::json!({"profile_path": "/p", "domain_id": 999}),
                "domain",
            ),
        ] {
            let e = sensor_settings(&bad).unwrap_err();
            assert!(e.contains(needle), "{e}");
        }
    }

    #[test]
    fn daemon_section_ranges() {
        assert!(validate_daemon(&DaemonSection::default()).is_ok());
        for d in [
            DaemonSection {
                queue_capacity: 0,
                ..Default::default()
            },
            DaemonSection {
                tick_ms: 1,
                ..Default::default()
            },
            DaemonSection {
                heartbeat_ms: 10,
                ..Default::default()
            },
            DaemonSection {
                silence_ms: 0,
                ..Default::default()
            },
            DaemonSection {
                lag_ms: u64::MAX,
                ..Default::default()
            },
        ] {
            assert!(validate_daemon(&d).is_err(), "{d:?}");
        }
    }

    #[test]
    fn config_parse_is_strict() {
        let base = r#"{"robot":{"id":"r1","site":"s"},"sensor":{},"policy_path":"/p",
            "blackbox":{"dir":"/b","key_file":"/k"},"spool":{"dir":"/s"}}"#;
        let c = parse(base).unwrap();
        assert_eq!(c.daemon, DaemonSection::default());
        assert_eq!(c.context.safety_state, SafetyState::Unknown);
        assert!(c.event_inputs.is_empty());
        for bad in [
            base.replace(r#""site":"s""#, r#""site":"s","x":1"#),
            base.replace(r#""spool":{"dir":"/s"}"#, r#""spool":{"dir":"/s"},"extra":1"#),
            base.replace(
                r#""spool":{"dir":"/s"}"#,
                r#""spool":{"dir":"/s"},"event_inputs":[{"kind":"tcp"}]"#,
            ),
            base.replace(
                r#""spool":{"dir":"/s"}"#,
                r#""spool":{"dir":"/s"},"event_inputs":[{"kind":"unix_socket","path":"/x","bogus":1}]"#,
            ),
            base.replace(
                r#""spool":{"dir":"/s"}"#,
                r#""spool":{"dir":"/s"},"daemon":{"tick":5}"#,
            ),
            base.replace(
                r#""spool":{"dir":"/s"}"#,
                r#""spool":{"dir":"/s"},"context":{"safety_state":"flying"}"#,
            ),
            "not json".to_string(),
            "{}".to_string(),
        ] {
            assert!(parse(&bad).is_err(), "{bad}");
        }
        let c = parse(&base.replace(
            r#""spool":{"dir":"/s"}"#,
            r#""spool":{"dir":"/s"},"event_inputs":[{"kind":"stdin"},{"kind":"unix_socket","path":"/run/x.sock"}]"#,
        ))
        .unwrap();
        assert_eq!(c.event_inputs[0], EventInputConfig::Stdin);
        assert!(matches!(
            c.event_inputs[1],
            EventInputConfig::UnixSocket {
                max_connections: 4,
                ..
            }
        ));
    }

    #[test]
    fn example_config_parses_and_its_sensor_section_validates() {
        let text = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/agentd.example.json"),
        )
        .unwrap();
        let c = parse(&text).unwrap();
        validate_daemon(&c.daemon).unwrap();
        let (s, _) = sensor_settings(&c.sensor).unwrap();
        assert!(s.capture.is_some() && s.spdp.is_none());
        assert_eq!(c.event_inputs.len(), 1);
        assert_eq!(c.firewall.unwrap().max_angular["/cmd_vel"], 1.0);
    }

    #[test]
    fn resolve_refuses_relative_and_overlapping_paths() {
        let base = |bb: &str, spool: &str| {
            parse(&format!(
                r#"{{"robot":{{"id":"r1","site":"s"}},"sensor":{{"profile_path":"/nonexistent/p.json","listen_spdp":false}},
                "policy_path":"/nonexistent/policy.json","blackbox":{{"dir":"{bb}","key_file":"/k"}},
                "spool":{{"dir":"{spool}"}},"event_inputs":[{{"kind":"stdin"}}]}}"#
            ))
            .unwrap()
        };
        assert!(resolve(base("rel", "/s")).unwrap_err().contains("absolute"));
        assert!(resolve(base("/var/x", "/var/x/spool"))
            .unwrap_err()
            .contains("contain"));
        // Everything valid up to the missing profile file.
        assert!(resolve(base("/var/bb", "/var/spool"))
            .unwrap_err()
            .contains("profile"));
        let mut c = base("/var/bb", "/var/spool");
        c.robot.id = "bad id\n".into();
        assert!(resolve(c).unwrap_err().contains("robot.id"));
        let mut c = base("/var/bb", "/var/spool");
        c.event_inputs = vec![EventInputConfig::Stdin, EventInputConfig::Stdin];
        assert!(resolve(c).unwrap_err().contains("twice"));
        let mut c = base("/var/bb", "/var/spool");
        c.event_inputs.clear();
        assert!(resolve(c).unwrap_err().contains("no input"));
    }
}
