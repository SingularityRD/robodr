//! The daemon's single configuration file (JSON) and its validation.
//!
//! One file ties everything together; every path in it must be absolute (the
//! daemon's working directory is not defined) and unknown keys are refused at
//! every level, so a typo cannot silently fall back to a default.
//!
//! ```json
//! {
//!   "robot":   { "id": "ugv-007", "site": "lab" },
//!   "sensor":  { "profile_path": "/etc/robodr/profile.json", "listen_spdp": false,
//!                "capture": { "enabled": true, "interfaces": ["eth0"] },
//!                "profile_trust": { "trusted_keys": "/etc/robodr/profile-trust.json",
//!                                   "state_file": "/var/lib/robodr/profile-state/agentd.json" } },
//!   "policy_path": "/etc/robodr/policy.json",
//!   "blackbox": { "dir": "/var/lib/robodr/blackbox", "key_file": "/etc/robodr/blackbox.key" },
//!   "spool":    { "dir": "/var/spool/robodr/findings", "max_bytes": 67108864 },
//!   "event_inputs": [ { "kind": "unix_socket", "path": "/run/robodr/events.sock" } ],
//!   "context":  { "safety_state": "unknown", "control": "autonomous" },
//!   "safety_feed": { "stale_after_ms": 1000,
//!                    "topics": [ { "topic": "/estop", "type": "std_msgs/msg/Bool",
//!                                  "values": { "true": "estop_active", "false": "none" },
//!                                  "writers": [ "0110a2b3c4d5e6f701000000" ] } ] },
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
//! * `sensor.motion` (keys [`SENSOR_MOTION_KEYS`]) configures the live
//!   motion decode path: user DATA on the profile's motion channels and on
//!   `feedback_topics` is decoded into `MotionCommand` / `MotionFeedback`
//!   and fed to the agent. The keys of `motion_monitor.feedback_sources`
//!   that are ROS topic names are added to `feedback_topics`.
//! * `sensor.profile_trust` ([`robodr_ros2_pipeline::ProfileTrustConfig`],
//!   keys [`SENSOR_TRUST_KEYS`]) decides whether a locked profile is
//!   enforced: it must carry a valid detached signature (`<profile>.sig`)
//!   from a key in `trusted_keys`, and with `state_file` its
//!   `profile_version` must not be lower than the last accepted one unless
//!   `allow_rollback` names its exact digest. Otherwise the daemon runs
//!   observe-only and reports `robot.ros2.profile_refused`. The rollback
//!   decision is made by [`resolve`] (so `--check-config` reports it) but
//!   the state file is only written when the daemon starts
//!   ([`Resolved::profile_state_commit`]). With `trust_roots`, a
//!   root-signed `min_profile_version` in the trust file and a signed
//!   revocation list (`revocation_list`, `revocation_policy`) apply too.
//!   With `state_file`, the newest accepted-profile record of the black box
//!   (`blackbox.dir`, verified with the black-box key; see
//!   [`crate::profile_chain`]) is the second witness: a state file missing
//!   or behind it is [`Resolved::profile_alarm`] (reported as a Critical,
//!   observe-only finding at start, also by `--check-config`) and the record
//!   is the rollback baseline.
//! * `robot.profile_version` was **removed**: the version reported in
//!   findings is the signed profile's `metadata.profile_version`. A config
//!   that still sets it is refused with a message saying so.
//! * The black-box key is read from `blackbox.key_file`, never from the
//!   command line: either a `robodr-blackbox` **secret** key file (as
//!   written by `robodr-blackbox keygen`: Ed25519 by default, format v2, or
//!   a legacy HMAC-SHA256 v1 file; its `key_id` is used) or bare hex
//!   (>= 32 bytes HMAC; legacy 0.1.0-alpha.1 format). A public key file
//!   (`.pub`) is refused: the recorder needs the secret. HMAC keys load
//!   with a start-up warning (symmetric: every verifier can forge). The file
//!   must be a regular file (not a symlink), owned by the daemon's effective
//!   user or root, and not accessible by group or others (`chmod 600`); see
//!   [`read_key_file`]. A `blackbox.key_id` that contradicts the key file's
//!   own id is a configuration error.
//! * `spool.dir` and `blackbox.dir` must not be equal or contain each
//!   other, and `sensor.profile_trust.state_file` must not be inside either.
//!   The check ([`check_daemon_dirs`]) runs on resolved paths
//!   ([`resolve_path`]: symlinks of the existing part followed, `.` / `..`
//!   folded) here, and again on canonical paths in the daemon after the
//!   directories exist, so neither `..` nor a symlink can alias them.
//! * `safety_feed` (optional, [`crate::safety::SafetyFeedSection`]) replaces
//!   the static `context.safety_state` with a live feed read from the bus
//!   and / or a local socket; see [`crate::safety`]. With a feed,
//!   `context.safety_state` must be left `unknown` (it would be ignored),
//!   and the feed's socket path must differ from every event socket.
//! * `correlation` (optional, [`CorrelationSection`]; on by default):
//!   `{"enabled": true, "rules_path": null, "include_default_rules": true}`.
//!   The shipped `robodr-correlate` rules plus an optional rule file,
//!   validated as one set ([`correlation_rules`]); a file that does not load
//!   refuses the configuration (never a partial set). See the daemon docs.
//! * `finding_signing` (optional, [`FindingSigningSection`]):
//!   `{"key_file": "/etc/robodr/finding.key"}`, a dedicated Ed25519 key
//!   (not the black-box key, not HMAC, not inside the spool or black-box
//!   directory; same file checks as the black-box key, see [`finding_key`]).
//!   Every finding then carries the contract §2a `robodr-finding-sig` header.
//! * `host_threats` (optional, [`crate::host::HostThreatsSection`]):
//!   `{"socket_path": "/run/robodr-agentd/host-threats.sock"}`, the socket
//!   the `robodr-threat-forward` Pulsar module writes Pulsar threats to (see
//!   [`crate::host`]). Its path must differ from every other socket input.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use robodr_commission::trust::{AcceptedState, RollbackDecision, StateAlarm};
use robodr_motion::{FeedbackSource, MonitorConfig};
use robodr_responder::{Connectivity, ControlMode, MissionPhase, ResponsePolicy, SafetyState};
use robodr_ros2_pipeline::config::Settings;
use robodr_ros2_pipeline::profile_trust::load_profile_checked;
use robodr_ros2_pipeline::{LoadedProfile, StateCommit};
use serde::Deserialize;

/// Max size of the daemon config, the policy and a monitor config file.
pub const MAX_CONFIG_BYTES: u64 = 4 << 20;
/// Max size of the key file (a JSON key file or a hex key plus whitespace).
pub const MAX_KEY_FILE_BYTES: u64 = 4096;
/// Most event inputs.
pub const MAX_EVENT_INPUTS: usize = 8;
/// Most concurrent connections on one unix-socket event input.
pub const MAX_SOCKET_CONNECTIONS: usize = 64;
/// Largest `daemon.queue_capacity` (items).
pub const MAX_QUEUE_CAPACITY: usize = 65_536;
/// Bounds of `daemon.queue_bytes`.
pub const MIN_QUEUE_BYTES: usize = 1 << 20;
pub const MAX_QUEUE_BYTES: usize = 256 << 20;

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
    "motion",
    "profile_trust",
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
/// Keys of `sensor.profile_trust`.
pub const SENSOR_TRUST_KEYS: &[&str] = &[
    "trusted_keys",
    "state_file",
    "allow_rollback",
    "expect_platform",
    "expect_unit_id",
    "trust_roots",
    "revocation_list",
    "revocation_policy",
];
/// Keys of `sensor.binding` (`participant_ips` is a free-form map).
pub const SENSOR_BINDING_KEYS: &[&str] = &[
    "enabled",
    "hold_ms",
    "max_participants",
    "discovery_server",
    "participant_ips",
];

/// Keys of `sensor.motion` (the live motion decode path).
pub const SENSOR_MOTION_KEYS: &[&str] = &[
    "enabled",
    "feedback_topics",
    "evaluate_commands",
    "max_writers",
    "max_samples_per_datagram",
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
    /// Live safety-state feed (see [`crate::safety`]); `None` = the static
    /// `context.safety_state`.
    #[serde(default)]
    pub safety_feed: Option<crate::safety::SafetyFeedSection>,
    /// Weak-signal correlation over every finding (see [`CorrelationSection`]).
    #[serde(default)]
    pub correlation: CorrelationSection,
    /// Dedicated per-finding signing key (contract §2a); `None` = findings
    /// are emitted unsigned.
    #[serde(default)]
    pub finding_signing: Option<FindingSigningSection>,
    /// Pulsar threats from `robodr-threat-forward` (see [`crate::host`]);
    /// `None` = no host-side signals.
    #[serde(default)]
    pub host_threats: Option<crate::host::HostThreatsSection>,
}

/// `correlation`: the `robodr-correlate` engine over every finding the
/// daemon reports. On by default with the shipped rule set.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationSection {
    /// `false` turns correlation off (every finding is still reported on
    /// its own).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Additional rules (`robodr-correlate` JSON rule file, version 1). Each
    /// id must be unique across the shipped and the added rules.
    #[serde(default)]
    pub rules_path: Option<PathBuf>,
    /// `false` = use only `rules_path` (the shipped rules are dropped).
    #[serde(default = "default_true")]
    pub include_default_rules: bool,
}

impl Default for CorrelationSection {
    fn default() -> Self {
        Self {
            enabled: true,
            rules_path: None,
            include_default_rules: true,
        }
    }
}

/// `finding_signing`: sign every finding record with a dedicated Ed25519
/// key (`robodr-blackbox keygen` secret key file, same permission rules as
/// the black-box key). The signature travels in the `robodr-finding-sig`
/// header of the spooled Kafka record (contract §2a).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingSigningSection {
    pub key_file: PathBuf,
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
    /// Removed (the version comes from the signed profile's metadata).
    /// Still parsed so that an old config gets a clear error from
    /// [`resolve`] instead of a generic "unknown field".
    #[serde(default)]
    pub profile_version: Option<serde_json::Value>,
    /// Kafka partition count of `robot-edr.findings`, if known.
    #[serde(default)]
    pub kafka_partitions: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlackboxSection {
    pub dir: PathBuf,
    /// Secret key file: `robodr-blackbox` JSON key file (Ed25519 or HMAC)
    /// or legacy hex HMAC (see [`read_key`]).
    pub key_file: PathBuf,
    /// Key id. Default: the key file's `key_id` (JSON key file), else
    /// derived from the key. Must equal the JSON key file's id if both are
    /// given.
    #[serde(default)]
    pub key_id: Option<String>,
    /// Boot id; default: `/proc/sys/kernel/random/boot_id`.
    #[serde(default)]
    pub boot_id: Option<String>,
    /// External home for the black box's high-water mark
    /// (`robodr_blackbox::HeadAnchor`). Without one (the default) the
    /// daemon logs a warning at start and reports `"anchored": false` in
    /// its status: a cut of the newest records combined with a rollback of
    /// `head.json`, or a wiped store, is then not detectable on the unit.
    /// A deployment against an attacker with write access needs the
    /// `tpm_nv_counter` or the `remote` kind.
    #[serde(default)]
    pub head_anchor: Option<HeadAnchorConfig>,
}

/// `blackbox.head_anchor`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HeadAnchorConfig {
    /// `robodr_blackbox::FileHeadAnchor` at `path` (absolute; outside
    /// `blackbox.dir` and `spool.dir`). Only as strong as the storage the
    /// file lives on: useful on a separately mounted, write-restricted or
    /// off-unit replicated filesystem, worthless on the log's own.
    File { path: PathBuf },
    /// `robodr_blackbox::TpmNvCounterAnchor`: a TPM 2.0 NV counter
    /// (provisioned with `robodr-blackbox tpm-anchor-init`) plus a sidecar
    /// file signed with the black-box key. Rollback and truncation become
    /// detectable on the unit; see `docs/OPERATIONS.md`.
    TpmNvCounter {
        /// NV index handle, `"0x01500020"` form.
        nv_index: String,
        /// Sidecar file (absolute; outside `blackbox.dir` and `spool.dir`;
        /// its directory must exist).
        sidecar_path: PathBuf,
        /// `TPM2TOOLS_TCTI`; default `device:/dev/tpmrm0`.
        #[serde(default)]
        tcti: Option<String>,
        /// Directory of the `tpm2_*` binaries (absolute); default `/usr/bin`.
        #[serde(default)]
        tools_dir: Option<PathBuf>,
        /// The index's authorization value (absolute file); default empty.
        #[serde(default)]
        auth_file: Option<PathBuf>,
        /// At most one counter increment per this interval (NV endurance);
        /// default 60000, max 86400000. 0 = every mark.
        #[serde(default)]
        min_increment_interval_ms: Option<u64>,
        /// Bound on one tool invocation; default 2000, 100..=30000.
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    /// `robodr_blackbox::RemoteHeadAnchor`: marks go to a
    /// `robodr-anchor-receiver` off the unit (unit id = `robot.id`), which
    /// is queried at open with a nonce and answers signed. Needs an Ed25519
    /// black-box key and a reverse channel to the receiver; see
    /// `docs/OPERATIONS.md`.
    Remote {
        /// Receiver `host:port` (an IP literal avoids DNS at open).
        address: String,
        /// The receiver's Ed25519 public key file (absolute; outside
        /// `blackbox.dir` and `spool.dir`).
        receiver_public_key: PathBuf,
        /// Bound on connect, write and read each; default 2000,
        /// 100..=30000.
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
}

impl HeadAnchorConfig {
    /// Short name for logs and status.
    pub fn kind(&self) -> &'static str {
        match self {
            HeadAnchorConfig::File { .. } => "file",
            HeadAnchorConfig::TpmNvCounter { .. } => "tpm_nv_counter",
            HeadAnchorConfig::Remote { .. } => "remote",
        }
    }

    /// The client settings and the receiver's verifying key of a `remote`
    /// anchor for unit `unit` (validated, the key file loaded; no network).
    /// `None` for other kinds.
    pub fn remote_config(
        &self,
        unit: &str,
    ) -> Option<
        Result<
            (
                robodr_blackbox::RemoteAnchorConfig,
                robodr_blackbox::Ed25519VerifyingKey,
            ),
            String,
        >,
    > {
        let HeadAnchorConfig::Remote {
            address,
            receiver_public_key,
            timeout_ms,
        } = self
        else {
            return None;
        };
        Some((|| {
            use robodr_blackbox::remote_anchor as ra;
            ra::check_address(address).map_err(|e| format!("blackbox.head_anchor.address: {e}"))?;
            require_abs(
                "blackbox.head_anchor.receiver_public_key",
                receiver_public_key,
            )?;
            let key = robodr_blackbox::KeyFile::load_public(receiver_public_key)
                .and_then(|k| k.ed25519_verifying_key())
                .map_err(|e| {
                    format!(
                        "blackbox.head_anchor.receiver_public_key {}: {e}",
                        sanitize_path(&receiver_public_key.display().to_string())
                    )
                })?;
            let mut c = robodr_blackbox::RemoteAnchorConfig::new(address.clone(), unit);
            match *timeout_ms {
                Some(ms) if !(100..=30_000).contains(&ms) => {
                    return Err("blackbox.head_anchor.timeout_ms must be 100..=30000".into())
                }
                Some(ms) => c.timeout = std::time::Duration::from_millis(ms),
                None => {}
            }
            Ok((c, key))
        })())
    }

    /// The anchor settings of a `tpm_nv_counter` (validated; does not touch
    /// the TPM). `None` for other kinds.
    pub fn tpm_config(&self) -> Option<Result<robodr_blackbox::TpmAnchorConfig, String>> {
        let HeadAnchorConfig::TpmNvCounter {
            nv_index,
            sidecar_path,
            tcti,
            tools_dir,
            auth_file,
            min_increment_interval_ms,
            timeout_ms,
        } = self
        else {
            return None;
        };
        Some((|| {
            use robodr_blackbox::tpm_anchor as t;
            let index = t::parse_nv_index(nv_index)
                .map_err(|e| format!("blackbox.head_anchor.nv_index: {e}"))?;
            require_abs("blackbox.head_anchor.sidecar_path", sidecar_path)?;
            let mut c = robodr_blackbox::TpmAnchorConfig::new(index, sidecar_path);
            if let Some(d) = tools_dir {
                require_abs("blackbox.head_anchor.tools_dir", d)?;
                c.tools_dir = d.clone();
            }
            if let Some(f) = auth_file {
                require_abs("blackbox.head_anchor.auth_file", f)?;
                c.auth_file = Some(f.clone());
            }
            if let Some(x) = tcti {
                c.tcti = x.clone();
            }
            match *min_increment_interval_ms {
                Some(ms) if ms > 86_400_000 => {
                    return Err(
                        "blackbox.head_anchor.min_increment_interval_ms must be <= 86400000".into(),
                    )
                }
                Some(ms) => c.min_increment_interval = std::time::Duration::from_millis(ms),
                None => {}
            }
            match *timeout_ms {
                Some(ms) if !(100..=30_000).contains(&ms) => {
                    return Err("blackbox.head_anchor.timeout_ms must be 100..=30000".into())
                }
                Some(ms) => c.timeout = std::time::Duration::from_millis(ms),
                None => {}
            }
            t::Tpm2Tools::new(&c.tools_dir, &c.tcti, c.timeout)
                .map_err(|e| format!("blackbox.head_anchor: {e}"))?;
            Ok(c)
        })())
    }
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

/// Platform context. Without a `safety_feed`, the configured
/// `safety_state` is used for every plan (default `unknown`); with one, the
/// feed decides and this must stay `unknown`.
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
    /// Bound of the input -> pipeline queue in items (shared by all
    /// inputs), 1..=[`MAX_QUEUE_CAPACITY`]. A full queue drops the newest
    /// item and counts it (see `health`).
    pub queue_capacity: usize,
    /// Bound of the same queue in bytes (payloads + per-item overhead),
    /// [`MIN_QUEUE_BYTES`]..=[`MAX_QUEUE_BYTES`], default
    /// [`crate::input::DEFAULT_QUEUE_BYTES`]. Whichever bound is hit first
    /// drops the item.
    pub queue_bytes: usize,
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
            queue_bytes: crate::input::DEFAULT_QUEUE_BYTES,
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
    /// The profile as loaded (with its commissioning file and trust check).
    pub profile: LoadedProfile,
    /// The anti-rollback state write that accepting the profile implies
    /// (written by the daemon at start, never by `--check-config`).
    pub profile_state_commit: Option<StateCommit>,
    /// The state file is missing or behind the black box's record.
    pub profile_alarm: Option<StateAlarm>,
    /// The accepted locked profile to record in the black box at start
    /// (and in every heartbeat) once enforcing.
    pub profile_accepted: Option<AcceptedState>,
    /// Key that signed the accepted profile.
    pub profile_signed_by: Option<String>,
    /// Anti-rollback decision for the accepted profile.
    pub profile_decision: Option<RollbackDecision>,
    pub policy: ResponsePolicy,
    pub monitor: Option<MonitorConfig>,
    /// Black-box key bytes: the HMAC key or the Ed25519 seed (never
    /// printed by `Debug`).
    pub key: KeyBytes,
    /// Algorithm of `key`: `"ed25519"` or `"hmac-sha256"`.
    pub key_algorithm: String,
    /// Effective key id: `blackbox.key_id`, else the JSON key file's id,
    /// else `None` (derived from the key).
    pub key_id: Option<String>,
    pub boot_id: String,
    /// The validated live safety-state feed, if configured.
    pub safety_feed: Option<crate::safety::FeedSpec>,
    /// The correlation rules (`None` = correlation disabled).
    pub correlation: Option<robodr_correlate::RuleSet>,
    /// The dedicated finding-signing key: Ed25519 seed and key id.
    pub finding_key: Option<(KeyBytes, String)>,
    /// The validated host-threat socket, if configured.
    pub host_threats: Option<crate::host::HostThreatsSpec>,
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

/// Lexically fold `.` and `..` (`..` at the root stays at the root).
fn normalize_lexically(p: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// The path `p` will name once created: the longest existing ancestor is
/// canonicalised (symlinks followed, `..` resolved by the kernel), the
/// missing rest is folded lexically (correct once it is created as plain
/// directories, which is what the daemon does). `p` must be absolute.
pub fn resolve_path(p: &Path) -> PathBuf {
    let mut existing = p.to_path_buf();
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(c) = std::fs::canonicalize(&existing) {
            let mut out = c;
            for r in rest.iter().rev() {
                out.push(r);
            }
            return normalize_lexically(&out);
        }
        match (existing.file_name(), existing.parent()) {
            (Some(name), Some(parent)) => {
                rest.push(name.to_os_string());
                existing = parent.to_path_buf();
            }
            // `..` / `.` as the last component, or the root: fold it all.
            _ => return normalize_lexically(p),
        }
    }
}

/// Check the directories the daemon writes, after mapping each through
/// `resolve` ([`resolve_path`] at configuration time, `canonicalize` once
/// they exist): `spool.dir` and `blackbox.dir` must not be equal or contain
/// each other, and the profile-state file must not live in (or under)
/// either of them (the exporter would ship or prune it, the recorder owns
/// its directory). A state directory that *contains* them is allowed (e.g.
/// `/var/lib/robodr`).
pub fn check_daemon_dirs(
    config: &DaemonConfig,
    state_file: Option<&Path>,
    resolve: impl Fn(&Path) -> Result<PathBuf, String>,
) -> Result<(), String> {
    let spool = resolve(&config.spool.dir)?;
    let blackbox = resolve(&config.blackbox.dir)?;
    let shown = |a: &Path, b: &Path| {
        format!(
            "({} vs {}, after resolving symlinks and ..)",
            a.display(),
            b.display()
        )
    };
    if spool.starts_with(&blackbox) || blackbox.starts_with(&spool) {
        return Err(format!(
            "spool.dir and blackbox.dir must not contain each other {}",
            shown(&spool, &blackbox)
        ));
    }
    if let Some(dir) = state_file.and_then(Path::parent) {
        let state = resolve(dir)?;
        for (what, d) in [("spool.dir", &spool), ("blackbox.dir", &blackbox)] {
            if state.starts_with(d) {
                return Err(format!(
                    "sensor.profile_trust.state_file must not be inside {what} {}",
                    shown(&state, d)
                ));
            }
        }
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
    if let Some(m) = v.get("motion") {
        check_keys("sensor.motion", m, SENSOR_MOTION_KEYS)?;
    }
    if let Some(t) = v.get("profile_trust") {
        check_keys("sensor.profile_trust", t, SENSOR_TRUST_KEYS)?;
    }
    let cfg: robodr_ros2_pipeline::Config =
        serde_json::from_value(v.clone()).map_err(|e| format!("sensor: {e}"))?;
    if let Some(p) = &cfg.capture.pcap_replay {
        require_abs("sensor.capture.pcap_replay", p)?;
    }
    cfg.validate().map_err(|e| format!("sensor: {e}"))
}

use crate::safety::is_ros_topic;

/// Validate the daemon section's numbers.
pub fn validate_daemon(d: &DaemonSection) -> Result<(), String> {
    let range = |what: &str, v: u64, lo: u64, hi: u64| {
        if (lo..=hi).contains(&v) {
            Ok(())
        } else {
            Err(format!("daemon.{what} = {v}: must be {lo}..={hi}"))
        }
    };
    range(
        "queue_capacity",
        d.queue_capacity as u64,
        1,
        MAX_QUEUE_CAPACITY as u64,
    )?;
    range(
        "queue_bytes",
        d.queue_bytes as u64,
        MIN_QUEUE_BYTES as u64,
        MAX_QUEUE_BYTES as u64,
    )?;
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
    if config.robot.profile_version.is_some() {
        return Err(
            "robot.profile_version was removed: the profile version is taken from the \
                    signed profile's metadata (`robodr-commission lock --profile-version`); \
                    delete the key"
                .into(),
        );
    }
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
    check_daemon_dirs(&config, None, |p| Ok(resolve_path(p)))?;
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

    let (mut sensor, mut w) = sensor_settings(&config.sensor)?;
    warnings.append(&mut w);
    check_daemon_dirs(&config, sensor.profile_trust.state_file.as_deref(), |p| {
        Ok(resolve_path(p))
    })?;
    // The motion monitor's feedback channels are decoded from the bus too
    // (in addition to `sensor.motion.feedback_topics`).
    if let Some(m) = &config.motion_monitor {
        for ch in m.feedback_sources.keys() {
            if is_ros_topic(ch) {
                sensor.pipeline.motion.feedback_topics.insert(ch.clone());
            } else {
                warnings.push(format!(
                    "motion_monitor.feedback_sources {:?} is not a ROS topic name: it is not \
                     decoded from the bus (JSONL events only)",
                    robodr_ros2_pipeline::sanitize(ch)
                ));
            }
        }
    }
    if !sensor.has_builtin_source() && config.event_inputs.is_empty() {
        return Err(
            "no input configured: enable sensor.capture, sensor.listen_spdp or add event_inputs"
                .into(),
        );
    }
    warnings.extend(sensor.profile_trust.warnings());
    let policy_text = read_capped(&config.policy_path, MAX_CONFIG_BYTES)?;
    let policy = ResponsePolicy::from_json(&policy_text)
        .map_err(|e| format!("{}: {e}", config.policy_path.display()))?;
    if !policy.oem_validated {
        warnings.push(
            "response policy is not OEM-validated: every plan is observe-only (Record)".into(),
        );
    }
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
    let KeyMaterial {
        key,
        key_id: file_key_id,
        algorithm: key_algorithm,
    } = read_key(&config.blackbox.key_file)?;
    if key_algorithm == robodr_blackbox::sign::HMAC_SHA256 {
        warnings.push(
            "black-box key is hmac-sha256, the symmetric placeholder: whoever verifies the \
             evidence can also forge it; generate an ed25519 key (robodr-blackbox keygen)"
                .into(),
        );
    }
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
    // The black box's newest accepted-profile record (only consulted with
    // anti-rollback state).
    let chain = if sensor.profile_trust.state_file.is_some() {
        let signer = signer_for(&key_algorithm, &key, key_id.as_deref())
            .map_err(|e| format!("black-box key: {e}"))?;
        match crate::profile_chain::latest_accepted(&config.blackbox.dir, signer.as_ref()) {
            Ok(scan) => {
                if scan.unverified > 0 {
                    warnings.push(format!(
                        "black box: {} accepted-profile record(s) do not verify under the \
                         current key (another key, or tampered); ignored",
                        scan.unverified
                    ));
                }
                for s in &scan.skipped {
                    warnings.push(format!("black box segment skipped: {}", sanitize_path(s)));
                }
                // A replayed or rewritten accepted-profile record: the
                // baseline ignores it, the operator must hear of it.
                for a in scan.alarms() {
                    warnings.push(format!("CRITICAL: {}", robodr_ros2_pipeline::sanitize(&a)));
                }
                scan.latest
            }
            Err(e) => {
                warnings.push(format!(
                    "black box not readable for the profile anti-rollback record: {}; only the \
                     state file is used",
                    sanitize_path(&e)
                ));
                None
            }
        }
    } else {
        None
    };
    let t = load_profile_checked(&sensor.profile_path, &sensor.profile_trust, chain.as_ref())?;
    if let Some(a) = &t.alarm {
        warnings.push(format!("CRITICAL: {a}"));
    }
    let safety_feed = match &config.safety_feed {
        None => None,
        Some(f) => {
            if config.context.safety_state != SafetyState::Unknown {
                return Err(
                    "context.safety_state is static configuration and cannot be combined with \
                     safety_feed (the feed decides; leave it unknown)"
                        .into(),
                );
            }
            let (spec, mut w) = f.resolve(&t.loaded.profile)?;
            if let Some(sock) = &spec.socket {
                let clash = config.event_inputs.iter().any(|i| {
                    matches!(i, EventInputConfig::UnixSocket { path, .. } if *path == sock.path)
                });
                if clash {
                    return Err(
                        "safety_feed.socket.path is also an event_inputs socket path".into(),
                    );
                }
            }
            if !spec.topics.is_empty() && sensor.capture.is_none() {
                w.push(
                    "safety_feed.topics are read from captured user DATA, but sensor.capture is \
                     off: those sources will stay unknown"
                        .into(),
                );
            }
            if !spec.topics.is_empty() && !sensor.pipeline.binding.enabled {
                w.push(
                    "safety_feed.topics trust a sample only from an IP bound to its participant, \
                     but sensor.binding is disabled: every topic source will stay unknown"
                        .into(),
                );
            }
            warnings.append(&mut w);
            Some(spec)
        }
    };
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
                let mut mc = MonitorConfig::ugv(t.loaded.profile.model.clone());
                mc.command_channels = t.loaded.profile.motion_envelopes.keys().cloned().collect();
                mc
            }
        }),
    };
    let correlation = correlation_rules(&config.correlation, &mut warnings)?;
    let host_threats = match &config.host_threats {
        None => None,
        Some(h) => {
            let spec = h.resolve()?;
            let clash = config.event_inputs.iter().any(
                |i| matches!(i, EventInputConfig::UnixSocket { path, .. } if *path == spec.path),
            ) || safety_feed
                .as_ref()
                .and_then(|f| f.socket.as_ref())
                .is_some_and(|s| s.path == spec.path);
            if clash {
                return Err(
                    "host_threats.socket_path is also an event_inputs or safety_feed socket path"
                        .into(),
                );
            }
            for (what, d) in [
                ("spool.dir", &config.spool.dir),
                ("blackbox.dir", &config.blackbox.dir),
            ] {
                if resolve_path(&spec.path).starts_with(resolve_path(d)) {
                    return Err(format!(
                        "host_threats.socket_path must not be inside {what}"
                    ));
                }
            }
            if correlation.is_none() {
                warnings.push(
                    "host_threats is configured but correlation is disabled: host threats are                      reported as findings only"
                        .into(),
                );
            }
            Some(spec)
        }
    };
    let finding_key = match &config.finding_signing {
        None => None,
        Some(fs) => {
            require_abs("finding_signing.key_file", &fs.key_file)?;
            // The exporter ships the spool; the recorder owns its directory.
            let k = resolve_path(&fs.key_file);
            for (what, d) in [
                ("spool.dir", &config.spool.dir),
                ("blackbox.dir", &config.blackbox.dir),
            ] {
                if k.starts_with(resolve_path(d)) {
                    return Err(format!(
                        "finding_signing.key_file must not be inside {what}"
                    ));
                }
            }
            Some(finding_key(&fs.key_file, &key, key_id.as_deref())?)
        }
    };
    match &config.blackbox.head_anchor {
        None => warnings.push(
            "blackbox.head_anchor is not configured: the black box is not anchored; a cut of \
             its newest records plus a rolled-back head.json, or a wiped store, cannot be \
             detected on the unit (deployment needs a TPM NV counter or a remote anchor)"
                .into(),
        ),
        Some(HeadAnchorConfig::File { path }) => {
            require_abs("blackbox.head_anchor.path", path)?;
            let p = resolve_path(path);
            for (what, d) in [
                ("spool.dir", &config.spool.dir),
                ("blackbox.dir", &config.blackbox.dir),
            ] {
                if p.starts_with(resolve_path(d)) {
                    return Err(format!(
                        "blackbox.head_anchor.path must not be inside {what} (an anchor next \
                         to the log adds nothing)"
                    ));
                }
            }
            warnings.push(format!(
                "blackbox.head_anchor is a file ({}): only as tamper-resistant as the storage \
                 it lives on; deployment needs a TPM NV counter or a remote anchor",
                sanitize_path(&path.display().to_string())
            ));
        }
        Some(a @ HeadAnchorConfig::TpmNvCounter { .. }) => {
            let tc = a
                .tpm_config()
                .unwrap_or_else(|| Err("not a TPM anchor".into()))?;
            // The sidecar is signed and the counter exposes an older copy,
            // but a wiped log directory must not take the sidecar with it.
            let p = resolve_path(&tc.sidecar);
            let mut inside = vec![("blackbox.head_anchor.sidecar_path", p)];
            if let Some(f) = &tc.auth_file {
                inside.push(("blackbox.head_anchor.auth_file", resolve_path(f)));
            }
            for (field, p) in inside {
                for (what, d) in [
                    ("spool.dir", &config.spool.dir),
                    ("blackbox.dir", &config.blackbox.dir),
                ] {
                    if p.starts_with(resolve_path(d)) {
                        return Err(format!("{field} must not be inside {what}"));
                    }
                }
            }
        }
        Some(
            a @ HeadAnchorConfig::Remote {
                receiver_public_key,
                ..
            },
        ) => {
            // The receiver checks marks with the unit's *public* key.
            if key_algorithm != robodr_blackbox::sign_ed25519::ED25519 {
                return Err(format!(
                    "blackbox.head_anchor kind remote needs an ed25519 black-box key (the \
                     receiver verifies marks with its public half), got {key_algorithm}"
                ));
            }
            let p = resolve_path(receiver_public_key);
            for (what, d) in [
                ("spool.dir", &config.spool.dir),
                ("blackbox.dir", &config.blackbox.dir),
            ] {
                if p.starts_with(resolve_path(d)) {
                    return Err(format!(
                        "blackbox.head_anchor.receiver_public_key must not be inside {what}"
                    ));
                }
            }
            a.remote_config(&config.robot.id)
                .unwrap_or_else(|| Err("not a remote anchor".into()))?;
        }
    }
    Ok(Resolved {
        config,
        sensor,
        profile: t.loaded,
        profile_state_commit: t.commit,
        profile_alarm: t.alarm,
        profile_accepted: t.accepted,
        profile_signed_by: t.signed_by,
        profile_decision: t.decision,
        policy,
        monitor,
        key,
        key_algorithm,
        key_id,
        boot_id,
        safety_feed,
        correlation,
        finding_key,
        host_threats,
        warnings,
    })
}

/// Build the correlation rule set from the `correlation` section: the
/// shipped rules and / or `rules_path`, validated as one set (unique ids,
/// at most `robodr_correlate` limits). A rule file that does not load
/// refuses the configuration (never a partial set).
pub fn correlation_rules(
    c: &CorrelationSection,
    warnings: &mut Vec<String>,
) -> Result<Option<robodr_correlate::RuleSet>, String> {
    use robodr_correlate::{RuleFile, RuleSet, DEFAULT_RULES_JSON};
    if !c.enabled {
        if c.rules_path.is_some() {
            warnings.push("correlation.rules_path is ignored: correlation is disabled".into());
        }
        return Ok(None);
    }
    let mut file = RuleFile {
        version: 1,
        rules: Vec::new(),
    };
    if c.include_default_rules {
        let d: RuleFile = serde_json::from_str(DEFAULT_RULES_JSON)
            .map_err(|e| format!("shipped correlation rules: {e}"))?;
        file.rules.extend(d.rules);
    }
    if let Some(p) = &c.rules_path {
        require_abs("correlation.rules_path", p)?;
        let text = read_capped(p, MAX_CONFIG_BYTES)?;
        // Validate the file on its own first (size, version, strict parse).
        RuleSet::from_json(&text).map_err(|e| format!("{}: {e}", p.display()))?;
        let extra: RuleFile =
            serde_json::from_str(&text).map_err(|e| format!("{}: {e}", p.display()))?;
        file.rules.extend(extra.rules);
    }
    if file.rules.is_empty() {
        return Err(
            "correlation: no rules (include_default_rules is false and no rules_path);              set enabled = false to turn correlation off"
                .into(),
        );
    }
    let (set, w) = RuleSet::from_file(&file).map_err(|e| format!("correlation rules: {e}"))?;
    warnings.extend(w.into_iter().map(|w| format!("correlation rules: {w}")));
    Ok(Some(set))
}

/// Load the dedicated finding-signing key: an Ed25519 `robodr-blackbox`
/// secret key file (same file checks as [`read_key`]) with a key id. Refused
/// if it is HMAC (a symmetric key lets every verifier forge findings), has
/// no key id, or is the black-box key itself (by bytes or key id: findings
/// and evidence must not share a key).
pub fn finding_key(
    path: &Path,
    blackbox_key: &KeyBytes,
    blackbox_key_id: Option<&str>,
) -> Result<(KeyBytes, String), String> {
    require_abs("finding_signing.key_file", path)?;
    let m = read_key(path)?;
    if m.algorithm != robodr_blackbox::sign_ed25519::ED25519 {
        return Err(format!(
            "finding_signing.key_file {}: must be an ed25519 key (got {}); generate one with \
             `robodr-blackbox keygen`",
            path.display(),
            robodr_ros2_pipeline::sanitize(&m.algorithm)
        ));
    }
    let Some(id) = m.key_id else {
        return Err(format!(
            "finding_signing.key_file {}: no key_id",
            path.display()
        ));
    };
    if m.key.0 == blackbox_key.0 || blackbox_key_id == Some(id.as_str()) {
        return Err(
            "finding_signing.key_file is the black-box key: use a dedicated finding key".into(),
        );
    }
    // Probe: the key must produce a valid finding signature.
    let signer = signer_for(&m.algorithm, &m.key, Some(&id))?;
    robodr_ocsf::sign_value("", signer.as_ref()).map_err(|e| format!("finding key: {e}"))?;
    Ok((m.key, id))
}

fn sanitize_path(s: &str) -> String {
    robodr_ros2_pipeline::sanitize(s)
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

/// A loaded black-box signing key.
#[derive(Debug, Clone)]
pub struct KeyMaterial {
    /// HMAC key or Ed25519 seed.
    pub key: KeyBytes,
    /// The JSON key file's id (`None` for legacy bare hex).
    pub key_id: Option<String>,
    /// `"ed25519"` or `"hmac-sha256"`.
    pub algorithm: String,
}

/// [`read_key`] without the algorithm (key bytes and key id).
pub fn read_key_material(path: &Path) -> Result<(KeyBytes, Option<String>), String> {
    read_key(path).map(|m| (m.key, m.key_id))
}

/// Read the black-box signing key from `path`: a `robodr-blackbox` JSON
/// secret key file (Ed25519 v2 or HMAC-SHA256 v1/v2; returns its key id
/// too) or bare hex HMAC (returns no key id). Refuses a file that is a
/// symlink or not a regular file, is readable or writable by group or
/// others, is not owned by the effective user (or root), or is larger than
/// [`MAX_KEY_FILE_BYTES`]; and refuses a public key file (it cannot sign).
/// The file is opened once and the checks run on the opened file (`fstat`),
/// compared against the path's `lstat`, so it cannot be swapped between
/// check and read.
pub fn read_key(path: &Path) -> Result<KeyMaterial, String> {
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
        // Refuses public key files and unknown algorithms; re-checks lengths.
        kf.signer().map_err(|e| format!("key file {shown}: {e}"))?;
        return Ok(KeyMaterial {
            key: KeyBytes(kf.secret().to_vec()),
            key_id: Some(kf.key_id.clone()),
            algorithm: kf.algorithm.clone(),
        });
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
    Ok(KeyMaterial {
        key: KeyBytes(key),
        key_id: None,
        algorithm: robodr_blackbox::sign::HMAC_SHA256.into(),
    })
}

/// The recorder signer for a resolved key (Ed25519 seed or HMAC key).
pub fn signer_for(
    algorithm: &str,
    key: &KeyBytes,
    key_id: Option<&str>,
) -> Result<Box<dyn robodr_blackbox::Signer>, String> {
    match algorithm {
        robodr_blackbox::sign_ed25519::ED25519 => {
            let seed: &[u8; 32] = key
                .0
                .as_slice()
                .try_into()
                .map_err(|_| "ed25519 seed must be 32 bytes".to_string())?;
            robodr_blackbox::KeyFile::ed25519_from_seed(seed, key_id)
                .and_then(|k| k.signer())
                .map_err(|e| e.to_string())
        }
        robodr_blackbox::sign::HMAC_SHA256 => match key_id {
            Some(id) => robodr_blackbox::HmacSha256Key::new(id, &key.0),
            None => robodr_blackbox::HmacSha256Key::with_derived_id(&key.0),
        }
        .map(|k| Box::new(k) as Box<dyn robodr_blackbox::Signer>)
        .map_err(|e| e.to_string()),
        a => Err(format!("unsupported key algorithm {a:?}")),
    }
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
        assert_eq!(read_key(&json).unwrap().algorithm, "hmac-sha256");
        assert_eq!(read_key(&good).unwrap().algorithm, "hmac-sha256");
        // Ed25519 secret key file (keygen's default): accepted, seed + id.
        let ed = d.join("ed.key");
        let ekf =
            robodr_blackbox::KeyFile::ed25519_from_seed(&[0x11; 32], Some("ugv-07-ed")).unwrap();
        ekf.write_new(&ed).unwrap();
        let m = read_key(&ed).unwrap();
        assert_eq!(
            (m.algorithm.as_str(), m.key_id.as_deref()),
            ("ed25519", Some("ugv-07-ed"))
        );
        assert_eq!(m.key.0, vec![0x11; 32]);
        let signer = signer_for(&m.algorithm, &m.key, m.key_id.as_deref()).unwrap();
        assert_eq!(signer.algorithm(), "ed25519");
        assert_eq!(signer.key_id(), "ugv-07-ed");
        let sig = signer.sign(b"m").unwrap();
        assert!(ekf
            .to_public()
            .unwrap()
            .verifier()
            .unwrap()
            .verify(b"m", &sig));
        // ...but its public half cannot sign, and loose modes are refused.
        let edpub = d.join("ed.key.pub");
        ekf.to_public().unwrap().write_new(&edpub).unwrap();
        std::fs::set_permissions(&edpub, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_key(&edpub).unwrap_err().contains("public key file"));
        let ed_open = d.join("ed-open.key");
        write_mode(&ed_open, &ekf.to_json(), 0o640);
        assert!(read_key(&ed_open).unwrap_err().contains("chmod 600"));
        // Unknown algorithms (parsed from v1) cannot sign.
        let odd = d.join("odd.key");
        write_mode(
            &odd,
            &kf.to_json().replace("hmac-sha256", "tpm-ecdsa"),
            0o600,
        );
        assert!(read_key_file(&odd).unwrap_err().contains("unsupported"));
        assert!(signer_for("tpm-ecdsa", &m.key, None).is_err());
        assert!(signer_for("ed25519", &KeyBytes(vec![1; 31]), None).is_err());
        assert_eq!(
            signer_for("hmac-sha256", &KeyBytes(vec![1; 32]), None)
                .unwrap()
                .algorithm(),
            "hmac-sha256"
        );
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

    /// `config/agentd.example.json` and `config/agentd.full.example.json`
    /// (shipped as examples and matching
    /// `packaging/systemd/robodr-agentd.service`) parse strictly, their
    /// sections validate, and they use the unit's paths.
    #[test]
    fn shipped_example_configs_parse() {
        shipped_example_config("agentd.example.json", false);
        shipped_example_config("agentd.full.example.json", true);
    }

    /// The base example names only files a commissioned robot has with the
    /// shipped unit (profile, profile trust file, response policy, black-box
    /// key credential) plus directories / sockets the unit creates, so it
    /// passes `--check-config` when copied verbatim. Everything needing an
    /// extra file or an extra drop-in (trust roots, revocation list, the
    /// finding-signing key credential) is only in the full example.
    #[test]
    fn base_example_needs_no_optional_files() {
        let text = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/agentd.example.json"),
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        let mut paths = Vec::new();
        // Values of file / directory keys (ROS topic names also start with
        // '/', so go by key).
        fn walk(key: &str, v: &serde_json::Value, out: &mut Vec<String>) {
            const PATH_KEYS: &[&str] = &[
                "path",
                "profile_path",
                "policy_path",
                "key_file",
                "dir",
                "trusted_keys",
                "state_file",
                "trust_roots",
                "revocation_list",
                "pcap_replay",
                "rules_file",
            ];
            match v {
                serde_json::Value::String(s) if PATH_KEYS.contains(&key) => out.push(s.clone()),
                serde_json::Value::Array(a) => a.iter().for_each(|x| walk(key, x, out)),
                serde_json::Value::Object(m) => m.iter().for_each(|(k, x)| walk(k, x, out)),
                _ => {}
            }
        }
        walk("", &v, &mut paths);
        assert!(paths.len() >= 6, "{paths:?}");
        let allowed = [
            "/etc/robodr/profile.json",
            "/etc/robodr/profile-trust.json",
            "/etc/robodr/response-policy.json",
            "/run/credentials/robodr-agentd.service/blackbox.key",
        ];
        let created = ["/var/lib/robodr/", "/run/robodr-agentd/"];
        for p in &paths {
            assert!(
                allowed.contains(&p.as_str()) || created.iter().any(|d| p.starts_with(d)),
                "base example names {p}, which a default install does not have"
            );
        }
        let c = parse(&text).unwrap();
        assert!(c.finding_signing.is_none());
        let (s, _) = sensor_settings(&c.sensor).unwrap();
        assert!(s.profile_trust.trust_roots.is_none());
        assert!(s.profile_trust.revocation_list.is_none());
    }

    fn shipped_example_config(file: &str, full: bool) {
        let text = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../config")
                .join(file),
        )
        .unwrap();
        let c = parse(&text).unwrap();
        let (s, _) = sensor_settings(&c.sensor).unwrap();
        assert!(s.profile_trust.trusted_keys.is_some() && s.profile_trust.state_file.is_some());
        assert!(c.robot.profile_version.is_none());
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
        // Every directory the daemon writes is in ReadWritePaths= (exact
        // entries), the anti-rollback state included: a state file the unit
        // cannot write makes the daemon run observe-only.
        let rw: Vec<&str> = unit
            .lines()
            .filter_map(|l| l.strip_prefix("ReadWritePaths="))
            .flat_map(str::split_whitespace)
            .collect();
        let state = s.profile_trust.state_file.as_deref().unwrap();
        assert_eq!(
            state,
            Path::new("/var/lib/robodr/profile-state/agentd.json")
        );
        for dir in [
            c.blackbox.dir.as_path(),
            c.spool.dir.as_path(),
            state.parent().unwrap(),
        ] {
            assert!(
                rw.iter().any(|p| Path::new(p) == dir),
                "{dir:?} not in ReadWritePaths= {rw:?}"
            );
        }
        assert!(unit.contains("RuntimeDirectory=robodr-agentd"));
        // The daemon sends READY=1 / WATCHDOG=1 (crate::notify), so the unit
        // is Type=notify with a watchdog well above the 1 s ping.
        let value = |k: &str| {
            unit.lines()
                .filter_map(|l| l.strip_prefix(k))
                .next_back()
                .map(str::trim)
        };
        assert_eq!(value("Type="), Some("notify"));
        let wd = value("WatchdogSec=").expect("WatchdogSec=");
        let secs: u64 = wd.trim_end_matches('s').parse().unwrap();
        assert!(secs >= 10 * crate::daemon::WATCHDOG_PING.as_secs(), "{wd}");
        // Never shield agentd from the OOM killer at the motion stack's
        // expense; cap it instead.
        let oom: i32 = value("OOMScoreAdjust=").unwrap().parse().unwrap();
        assert!(oom >= 0, "OOMScoreAdjust={oom}");
        assert!(value("MemoryMax=").is_some());
        // ... and tmpfiles.d creates the state directory for User=robodr.
        let tmpfiles = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/tmpfiles.d/robodr.conf"),
        )
        .unwrap();
        assert!(
            tmpfiles.lines().any(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                f.len() >= 5
                    && f[0] == "d"
                    && Path::new(f[1]) == state.parent().unwrap()
                    && f[3] == "robodr"
            }),
            "tmpfiles.d does not create {:?} for robodr",
            state.parent()
        );
        // Wave-6 keys: revocation / trust roots (full example only), safety
        // feed on the unit's runtime directory, correlation, and (full
        // example only) the finding key through the shipped drop-in's
        // credential.
        assert_eq!(s.profile_trust.trust_roots.is_some(), full, "{file}");
        assert_eq!(s.profile_trust.revocation_list.is_some(), full, "{file}");
        let feed = c.safety_feed.as_ref().expect("safety_feed");
        let sock = feed.socket.as_ref().expect("safety_feed.socket");
        assert!(sock.path.starts_with("/run/robodr-agentd/"), "{sock:?}");
        assert_eq!(c.context.safety_state, SafetyState::Unknown);
        assert!(c.correlation.enabled && c.correlation.include_default_rules);
        let mut w = Vec::new();
        let rules = correlation_rules(&c.correlation, &mut w).unwrap().unwrap();
        assert_eq!(
            rules.len(),
            robodr_correlate::RuleSet::default_rules().len()
        );
        assert!(w.is_empty(), "{w:?}");
        if !full {
            assert!(c.finding_signing.is_none(), "{file}");
            return;
        }
        let fk = &c
            .finding_signing
            .as_ref()
            .expect("finding_signing")
            .key_file;
        assert_eq!(
            fk,
            Path::new("/run/credentials/robodr-agentd.service/finding.key")
        );
        let dropin =
            std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(
                "../../packaging/systemd/robodr-agentd.service.d/20-finding-key.conf.example",
            ))
            .unwrap();
        assert!(dropin
            .lines()
            .any(|l| l.starts_with("LoadCredential=finding.key:/etc/robodr/keys/")));
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
        assert!(s.profile_trust.trusted_keys.is_some() && s.profile_trust.state_file.is_some());
        assert!(c.robot.profile_version.is_none());
        assert_eq!(c.event_inputs.len(), 1);
        assert_eq!(c.firewall.unwrap().max_angular["/cmd_vel"], 1.0);
        let mut p = robodr_events::profile::Profile::default();
        for t in ["/estop", "/robot_mode", "/odom"] {
            p.writer_topics.insert(t.into());
        }
        p.participants.insert("0110a2b3c4d5e6f701000000".into());
        let (feed, warnings) = c.safety_feed.unwrap().resolve(&p).unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(feed.topics.len(), 3);
        assert!(feed.socket.is_some());
        assert_eq!(c.context.safety_state, SafetyState::Unknown);
        assert!(s.profile_trust.trust_roots.is_some() && s.profile_trust.revocation_list.is_some());
        assert!(c.correlation.enabled && c.correlation.rules_path.is_some());
        assert!(c.finding_signing.is_some());
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
        // Everything valid up to the missing policy file (read before the
        // key and the profile: the profile's trust check needs the
        // black-box key to read the anti-rollback record).
        assert!(resolve(base("/var/bb", "/var/spool"))
            .unwrap_err()
            .contains("policy"));
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

    #[test]
    fn queue_bounds_are_capped() {
        let d = DaemonSection::default();
        assert_eq!(d.queue_bytes, 32 << 20);
        for (bad, needle) in [
            (
                DaemonSection {
                    queue_capacity: MAX_QUEUE_CAPACITY + 1,
                    ..d.clone()
                },
                "queue_capacity",
            ),
            (
                DaemonSection {
                    queue_bytes: MIN_QUEUE_BYTES - 1,
                    ..d.clone()
                },
                "queue_bytes",
            ),
            (
                DaemonSection {
                    queue_bytes: MAX_QUEUE_BYTES + 1,
                    ..d.clone()
                },
                "queue_bytes",
            ),
        ] {
            assert!(validate_daemon(&bad).unwrap_err().contains(needle));
        }
        let ok = DaemonSection {
            queue_capacity: MAX_QUEUE_CAPACITY,
            queue_bytes: MAX_QUEUE_BYTES,
            ..d
        };
        validate_daemon(&ok).unwrap();
    }

    #[test]
    fn resolve_path_folds_dotdot_and_follows_symlinks() {
        let d = std::env::temp_dir().join(format!("robodr-agentd-rp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("real")).unwrap();
        let d = std::fs::canonicalize(&d).unwrap();
        std::os::unix::fs::symlink(d.join("real"), d.join("link")).unwrap();
        assert_eq!(resolve_path(&d.join("x/../bb")), d.join("bb"));
        assert_eq!(resolve_path(&d.join("x/./y/../../bb/")), d.join("bb"));
        assert_eq!(resolve_path(&d.join("link/spool")), d.join("real/spool"));
        assert_eq!(resolve_path(&d.join("link/../real")), d.join("real"));
        assert_eq!(resolve_path(Path::new("/../..")), Path::new("/"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn daemon_dirs_must_not_alias() {
        let d = std::env::temp_dir().join(format!("robodr-agentd-dirs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("bb")).unwrap();
        let d = std::fs::canonicalize(&d).unwrap();
        std::os::unix::fs::symlink(d.join("bb"), d.join("alias")).unwrap();
        let text = |bb: &Path, spool: &Path| {
            format!(
                r#"{{"robot":{{"id":"r1","site":"s"}},"sensor":{{}},"policy_path":"/p",
                "blackbox":{{"dir":{bb:?},"key_file":"/k"}},"spool":{{"dir":{spool:?}}}}}"#
            )
        };
        let res = |p: &Path| Ok(resolve_path(p));
        let bb = d.join("bb");
        let ok = parse(&text(&bb, &d.join("spool"))).unwrap();
        check_daemon_dirs(&ok, None, res).unwrap();
        // The state directory may contain both (/var/lib/robodr) ...
        check_daemon_dirs(&ok, Some(&d.join("state.json")), res).unwrap();
        // ... but the state file may not live in either.
        for st in [bb.join("state.json"), d.join("alias/sub/state.json")] {
            let e = check_daemon_dirs(&ok, Some(&st), res).unwrap_err();
            assert!(
                e.contains("state_file") && e.contains("blackbox.dir"),
                "{e}"
            );
        }
        let e = check_daemon_dirs(&ok, Some(&d.join("spool/s.json")), res).unwrap_err();
        assert!(e.contains("spool.dir"), "{e}");
        for spool in [
            d.join("x/../bb"),
            d.join("alias"),
            d.join("alias/spool"),
            d.join("bb/./spool"),
        ] {
            let c = parse(&text(&bb, &spool)).unwrap();
            let e = check_daemon_dirs(&c, None, res).unwrap_err();
            assert!(e.contains("must not contain"), "{spool:?}: {e}");
        }
        // The blackbox inside the spool, through a symlink, too.
        std::fs::create_dir_all(d.join("sp")).unwrap();
        std::os::unix::fs::symlink(d.join("sp"), d.join("sp-link")).unwrap();
        let c = parse(&text(&d.join("sp-link/bb"), &d.join("sp"))).unwrap();
        assert!(check_daemon_dirs(&c, None, res).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
