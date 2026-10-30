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
//!   (`.pub`) is refused: the recorder needs the secret. **Legacy HMAC keys
//!   (JSON or bare hex) are refused** unless `blackbox.allow_hmac: true`
//!   (then they load with a start-up warning: symmetric, every verifier
//!   can forge); migrate with `robodr-blackbox rotate`. The file
//!   must be a regular file (not a symlink), owned by the daemon's effective
//!   user or root, and not accessible by group or others (`chmod 600`); see
//!   [`read_key_file`]. A `blackbox.key_id` that contradicts the key file's
//!   own id is a configuration error.
//! * `blackbox.previous_keys` (optional, at most [`MAX_PREVIOUS_KEY_FILES`]
//!   absolute paths): the black box's **retired** keys after an in-place
//!   key rotation (`robodr-blackbox rotate`), as Ed25519 **public** key
//!   files or keyring files (a legacy HMAC key, the secret itself, only
//!   with `allow_hmac`; an Ed25519 secret is refused: the `.pub` suffices).
//!   They authenticate the records signed before the rotation each time
//!   the black box is opened (`robodr_blackbox::Recorder::open_with_keys`),
//!   the TPM anchor's sidecar written before it, and the accepted-profile
//!   records of [`crate::profile_chain`]. Each key must have another id
//!   than the current key, ids are unique, and a key bound to a device
//!   (`device_id`) must be bound to `robot.id`. Without a key that signed
//!   a retained record the daemon refuses to start (fail closed) and says
//!   which setting is missing; see [`previous_keys`].
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
//! * `gateway_feed` (optional, [`crate::gateway_feed::GatewayFeedSection`]):
//!   the same keys, the socket the in-path gateway `robodr-firewall-gw`
//!   writes its findings to (`findings_socket` there; see
//!   [`crate::gateway_feed`]). `allowed_uids` names the gateway's uid.
//! * `findings` (optional, [`FindingsSection`]): `{"topic":
//!   "robodr.findings", "data_source": "robodr"}` (the defaults), the
//!   deployment labels every finding carries (`ocsf.metadata.log_name`, the
//!   spooled record's topic, the envelope `data_source`). The response
//!   policy (`policy_path`) carries the robot's `morphology` (a humanoid
//!   never gets an executable safe pause / safe state; see
//!   `robodr-responder`).
//! * `control_plane` (optional, [`crate::control::ControlPlaneSection`]; off
//!   when absent): the SOC action-request and evidence API
//!   (`robodr-control-plane/v2`), `listen_tcp` (loopback, or any address
//!   with `tls`: mutual TLS) and / or `unix_socket`, `state_dir` (private
//!   persistent state), `soc_keys` (Ed25519 public key files, not
//!   group/other-writable, not this robot's own keys), optional `evidence`.
//!   Needs `finding_signing` (answers are signed). Requests are judged and
//!   recorded, never executed; see [`crate::control`].

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
/// Most `blackbox.previous_keys` files.
pub const MAX_PREVIOUS_KEY_FILES: usize = 16;
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
    "unitree_legacy",
];
/// Keys of `sensor.unitree_legacy` (Unitree legacy UDP, Go1 generation).
pub const SENSOR_LEGACY_KEYS: &[&str] = &["enabled", "ports", "command_senders", "robot_addresses"];
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
    /// The in-path gateway's findings feed (see [`crate::gateway_feed`]);
    /// `None` = gateway findings stay in the gateway's events file.
    #[serde(default)]
    pub gateway_feed: Option<crate::gateway_feed::GatewayFeedSection>,
    /// The control-plane action API (see [`crate::control`]); `None` (the
    /// default) = no listener.
    #[serde(default)]
    pub control_plane: Option<crate::control::ControlPlaneSection>,
    /// Findings topic and `data_source` (see [`FindingsSection`]).
    #[serde(default)]
    pub findings: FindingsSection,
    /// executor v1: the link to `robodr-executor` (see
    /// [`crate::executor_link`]); absent or `enabled: false` (the default)
    /// = nothing is executed.
    #[serde(default)]
    pub executor: Option<crate::executor_link::ExecutorSection>,
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
    /// Kafka partition count of the findings topic, if known.
    #[serde(default)]
    pub kafka_partitions: Option<u32>,
    /// The robot's Unitree model (`robodr_cdr::UnitreeModel` name: `Go2`,
    /// `Go2-W`, `B2`, `B2-W`, `A2`, `AS2`, `H1`, `H1-2`, `H2`, `G1`, `R1`,
    /// `Go1`, ...; case, `-` and `_` ignored). Optional. When set, Unitree
    /// API requests are interpreted with the model's API tables
    /// (model-specific ids are classified instead of `Unknown`), and the
    /// configuration is checked for consistency with it (see
    /// [`check_robot_model`]).
    #[serde(default)]
    pub robot_model: Option<String>,
}

fn default_findings_topic() -> String {
    robodr_ocsf::DEFAULT_TOPIC.into()
}
fn default_data_source() -> String {
    robodr_ocsf::DEFAULT_DATA_SOURCE.into()
}

/// `findings` (optional): the deployment labels of the findings this robot
/// emits (`robodr.findings` contract 2.x). Both default to the contract
/// defaults, so a config without the section is unchanged.
///
/// ```json
/// "findings": { "topic": "robodr.findings", "data_source": "robodr" }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingsSection {
    /// Topic named in every finding (`ocsf.metadata.log_name`) and in its
    /// spooled record; `[A-Za-z0-9._-]{1,249}`.
    #[serde(default = "default_findings_topic")]
    pub topic: String,
    /// Envelope `data_source` (with `external_id` the SOC's dedup key);
    /// `[a-z0-9][a-z0-9._-]{0,63}`.
    #[serde(default = "default_data_source")]
    pub data_source: String,
}

impl Default for FindingsSection {
    fn default() -> Self {
        Self {
            topic: default_findings_topic(),
            data_source: default_data_source(),
        }
    }
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
    /// Retired black-box keys after a key rotation (public key or keyring
    /// files); see the module docs and [`previous_keys`].
    #[serde(default)]
    pub previous_keys: Vec<PathBuf>,
    /// Accept a legacy HMAC-SHA256 black-box key (`key_file` or in
    /// `previous_keys`). Off by default: HMAC is symmetric, so whoever can
    /// verify the evidence can also forge it.
    #[serde(default)]
    pub allow_hmac: bool,
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
        /// Bound on connect, TLS handshake, write and read each; default
        /// 2000, 100..=30000.
        #[serde(default)]
        timeout_ms: Option<u64>,
        /// TLS to the receiver (required unless `allow_plaintext`).
        #[serde(default)]
        tls: Option<AnchorTlsConfig>,
        /// Plain TCP to the receiver (lab / private link only; marks and
        /// answers stay Ed25519-signed). Default `false`: without `tls`
        /// the configuration is refused.
        #[serde(default)]
        allow_plaintext: bool,
    },
}

/// `blackbox.head_anchor.tls` (kind `remote`): see
/// `robodr_blackbox::tls`. The receiver's certificate is always verified
/// (chain to `ca_file`, validity, `serverAuth`, the address's host or
/// `server_name`); `server_spki_sha256` pins add to that; `cert_chain` +
/// `key_file` present a client certificate (mutual TLS).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorTlsConfig {
    pub ca_file: PathBuf,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub server_spki_sha256: Vec<String>,
    #[serde(default)]
    pub cert_chain: Option<PathBuf>,
    #[serde(default)]
    pub key_file: Option<PathBuf>,
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
            tls,
            allow_plaintext,
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
            match (tls, *allow_plaintext) {
                (Some(_), true) => {
                    return Err(
                        "blackbox.head_anchor: tls and allow_plaintext are both set: remove one"
                            .into(),
                    )
                }
                (None, false) => {
                    return Err(
                        "blackbox.head_anchor kind remote: set tls (the receiver's CA file; \
                         plain TCP needs an explicit \"allow_plaintext\": true, lab or \
                         private link only)"
                            .into(),
                    )
                }
                (None, true) => c.allow_plaintext = true,
                (Some(t), false) => {
                    for (f, p) in [
                        ("ca_file", Some(&t.ca_file)),
                        ("cert_chain", t.cert_chain.as_ref()),
                        ("key_file", t.key_file.as_ref()),
                    ] {
                        if let Some(p) = p {
                            require_abs(&format!("blackbox.head_anchor.tls.{f}"), p)?;
                        }
                    }
                    let files = robodr_blackbox::tls::ClientTlsFiles {
                        ca_file: t.ca_file.clone(),
                        cert_chain: t.cert_chain.clone(),
                        key_file: t.key_file.clone(),
                        server_name: t.server_name.clone(),
                        spki_sha256: t.server_spki_sha256.clone(),
                    };
                    let loaded = robodr_blackbox::tls::load_client(&files).map_err(|e| {
                        format!(
                            "blackbox.head_anchor.tls: {}",
                            robodr_ros2_pipeline::sanitize(&e)
                        )
                    })?;
                    // The name verified must be a valid TLS name.
                    loaded
                        .name_for(robodr_blackbox::tls::host_of(address))
                        .map_err(|e| format!("blackbox.head_anchor: {e}"))?;
                    c.tls = Some(loaded);
                }
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
    /// Optional unix socket (created 0600) on which the daemon serves its
    /// current status (the bytes of `status.json`) to every connection,
    /// e.g. `/run/robodr-agentd/status.sock`. `robodr-deliverd` reads the
    /// robot's safety state here and checks the peer with `SO_PEERCRED`
    /// (review H1): unlike `status.json` in the spool, which the
    /// exporters' user can replace, only this process can serve it.
    #[serde(default)]
    pub status_socket: Option<PathBuf>,
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
    /// A Motion Firewall JSON file (`robodr_firewall::FirewallConfig`, e.g.
    /// `config/firewall.unitree-g1.example.json`) whose `joint_channels`
    /// (low-level joint frames, Unitree `LowCmd`) and `platform`
    /// (morphology, substitutes) are used. Its `channels` must be empty:
    /// twist channels come from the profile and `max_angular` / `allow`.
    /// Checked as written (a humanoid's unsafe substitutes are refused) and
    /// then run **recording-only** like every firewall verdict of the
    /// daemon.
    #[serde(default)]
    pub joint_config: Option<PathBuf>,
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
    /// `blackbox.previous_keys`, loaded (`None` when none are configured).
    pub previous_keys: Option<robodr_blackbox::PreviousKeys>,
    pub boot_id: String,
    /// The validated live safety-state feed, if configured.
    pub safety_feed: Option<crate::safety::FeedSpec>,
    /// The correlation rules (`None` = correlation disabled).
    pub correlation: Option<robodr_correlate::RuleSet>,
    /// The dedicated finding-signing key: Ed25519 seed and key id.
    pub finding_key: Option<(KeyBytes, String)>,
    /// The validated host-threat socket, if configured.
    pub host_threats: Option<crate::host::HostThreatsSpec>,
    /// The validated gateway feed socket, if configured.
    pub gateway_feed: Option<crate::host::HostThreatsSpec>,
    /// The validated control-plane API (listeners, SOC keys), if configured.
    pub control_plane: Option<crate::control::ControlPlaneSpec>,
    /// executor v1: the enabled executor link (`None` = off).
    pub executor: Option<crate::executor_link::ExecutorSpec>,
    /// `firewall.joint_config`, parsed (its `platform` and
    /// `joint_channels`).
    pub firewall_joint: Option<robodr_firewall::FirewallConfig>,
    /// `robot.robot_model`, resolved.
    pub robot_model: Option<robodr_cdr::UnitreeModel>,
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
    if let Some(l) = v.get("unitree_legacy") {
        check_keys("sensor.unitree_legacy", l, SENSOR_LEGACY_KEYS)?;
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
    if !robodr_ocsf::validate::is_valid_topic(&config.findings.topic) {
        return Err(format!(
            "findings.topic {:?} must match [A-Za-z0-9._-]{{1,249}}",
            robodr_ros2_pipeline::sanitize(&config.findings.topic)
        ));
    }
    if !robodr_ocsf::validate::is_valid_data_source(&config.findings.data_source) {
        return Err(format!(
            "findings.data_source {:?} must match [a-z0-9][a-z0-9._-]{{0,63}}",
            robodr_ros2_pipeline::sanitize(&config.findings.data_source)
        ));
    }
    require_abs("policy_path", &config.policy_path)?;
    require_abs("blackbox.dir", &config.blackbox.dir)?;
    require_abs("blackbox.key_file", &config.blackbox.key_file)?;
    require_abs("spool.dir", &config.spool.dir)?;
    if config.spool.max_bytes < 64 * 1024 {
        return Err("spool.max_bytes must be >= 65536".into());
    }
    // Review L10: a spool below 8 files would have no share kept for
    // Critical findings (max_files / 8 == 0).
    if config.spool.max_files < crate::spool::CRITICAL_RESERVE_DIVISOR {
        return Err(format!(
            "spool.max_files must be >= {} (1/{} of it is kept for Critical findings)",
            crate::spool::CRITICAL_RESERVE_DIVISOR,
            crate::spool::CRITICAL_RESERVE_DIVISOR
        ));
    }
    check_daemon_dirs(&config, None, |p| Ok(resolve_path(p)))?;
    validate_daemon(&config.daemon)?;
    if config.event_inputs.len() > MAX_EVENT_INPUTS {
        return Err(format!("at most {MAX_EVENT_INPUTS} event_inputs"));
    }
    let mut stdin_seen = false;
    let mut socket_paths: Vec<&Path> = Vec::new();
    if let Some(p) = &config.spool.status_socket {
        require_abs("spool.status_socket", p)?;
        if p.file_name().is_none() || p.parent().is_none() {
            return Err("spool.status_socket must name a file in a directory".into());
        }
        for (what, d) in [
            ("spool.dir", &config.spool.dir),
            ("blackbox.dir", &config.blackbox.dir),
        ] {
            if resolve_path(p).starts_with(resolve_path(d)) {
                return Err(format!("spool.status_socket must not be inside {what}"));
            }
        }
        socket_paths.push(p);
    }
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
                    return Err(
                        "event_inputs: a socket path is listed twice (or is spool.status_socket)"
                            .into(),
                    );
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
    let robot_model = match &config.robot.robot_model {
        None => None,
        Some(name) => Some(robodr_cdr::UnitreeModel::from_name(name).ok_or_else(|| {
            format!(
                "robot.robot_model {:?} is not a known Unitree model (one of: {})",
                robodr_ros2_pipeline::sanitize(name),
                robodr_cdr::UnitreeModel::ALL
                    .iter()
                    .map(|m| m.info().name)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?),
    };
    sensor.pipeline.motion.robot_model = robot_model;
    let firewall_joint = match config
        .firewall
        .as_ref()
        .and_then(|f| f.joint_config.as_ref())
    {
        None => None,
        Some(p) => {
            require_abs("firewall.joint_config", p)?;
            let text = read_capped(p, MAX_CONFIG_BYTES)?;
            let fc = robodr_firewall::FirewallConfig::from_json(&text)
                .map_err(|e| format!("{}: {e}", p.display()))?;
            if !fc.channels.is_empty() {
                return Err(format!(
                    "{}: firewall.joint_config may only define joint_channels and platform; \
                     twist channels come from the profile (firewall.max_angular / allow)",
                    p.display()
                ));
            }
            if fc.joint_channels.is_empty() {
                return Err(format!(
                    "{}: firewall.joint_config defines no joint_channels",
                    p.display()
                ));
            }
            Some(fc)
        }
    };
    check_robot_model(
        robot_model,
        &policy,
        firewall_joint.as_ref(),
        &sensor,
        &mut warnings,
    )?;
    let KeyMaterial {
        key,
        key_id: file_key_id,
        algorithm: key_algorithm,
    } = read_key(&config.blackbox.key_file)?;
    if key_algorithm == robodr_blackbox::sign::HMAC_SHA256 {
        if !config.blackbox.allow_hmac {
            return Err(format!(
                "blackbox.key_file {}: legacy hmac-sha256 key refused (symmetric: whoever \
                 verifies the evidence can also forge it); migrate to ed25519 \
                 (robodr-blackbox keygen + robodr-blackbox rotate --allow-hmac, OPERATIONS \
                 4.3), or set blackbox.allow_hmac: true to accept it knowingly",
                config.blackbox.key_file.display()
            ));
        }
        warnings.push(
            "black-box key is hmac-sha256, the symmetric placeholder (allowed by \
             blackbox.allow_hmac): whoever verifies the evidence can also forge it; migrate to \
             ed25519 (robodr-blackbox rotate, OPERATIONS 4.3)"
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
    let previous = previous_keys(
        &config.blackbox,
        &config.robot.id,
        key_id.as_deref(),
        &mut warnings,
    )?;
    let boot_id = match &config.blackbox.boot_id {
        Some(b) => b.clone(),
        None => read_boot_id(),
    };
    // The black box's newest accepted-profile record (only consulted with
    // anti-rollback state).
    let chain = if sensor.profile_trust.state_file.is_some() {
        let signer = signer_for(&key_algorithm, &key, key_id.as_deref())
            .map_err(|e| format!("black-box key: {e}"))?;
        match crate::profile_chain::latest_accepted(
            &config.blackbox.dir,
            signer.as_ref(),
            previous.as_ref(),
        ) {
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
    if let (Some(fc), Some(fw)) = (&firewall_joint, &config.firewall) {
        check_joint_firewall(fc, fw, &t.loaded.profile, &mut warnings)?;
    }
    check_profile_channels(
        robot_model,
        &t.loaded.profile,
        config.firewall.as_ref(),
        firewall_joint.as_ref(),
        &mut warnings,
    )?;
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
    let gateway_feed = match &config.gateway_feed {
        None => None,
        Some(g) => {
            let spec = g.resolve()?;
            let clash = config.event_inputs.iter().any(
                |i| matches!(i, EventInputConfig::UnixSocket { path, .. } if *path == spec.path),
            ) || safety_feed
                .as_ref()
                .and_then(|f| f.socket.as_ref())
                .is_some_and(|s| s.path == spec.path)
                || host_threats.as_ref().is_some_and(|h| h.path == spec.path);
            if clash {
                return Err(
                    "gateway_feed.socket_path is also an event_inputs, safety_feed or \
                            host_threats socket path"
                        .into(),
                );
            }
            for (what, d) in [
                ("spool.dir", &config.spool.dir),
                ("blackbox.dir", &config.blackbox.dir),
            ] {
                if resolve_path(&spec.path).starts_with(resolve_path(d)) {
                    return Err(format!(
                        "gateway_feed.socket_path must not be inside {what}"
                    ));
                }
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
    let control_plane = match &config.control_plane {
        None => None,
        Some(c) => {
            let mut own: Vec<&str> = Vec::new();
            own.extend(key_id.as_deref());
            own.extend(finding_key.as_ref().map(|(_, id)| id.as_str()));
            let spec = c.resolve(&config.robot.id, &own)?;
            if let Some(p) = &spec.unix {
                let clash =
                    config.event_inputs.iter().any(
                        |i| matches!(i, EventInputConfig::UnixSocket { path, .. } if path == p),
                    ) || safety_feed
                        .as_ref()
                        .and_then(|f| f.socket.as_ref())
                        .is_some_and(|s| s.path == *p)
                        || host_threats.as_ref().is_some_and(|h| h.path == *p);
                if clash {
                    return Err(
                        "control_plane.unix_socket is also an event_inputs, safety_feed or \
                         host_threats socket path"
                            .into(),
                    );
                }
            }
            for p in c.paths() {
                for (what, d) in [
                    ("spool.dir", &config.spool.dir),
                    ("blackbox.dir", &config.blackbox.dir),
                ] {
                    if resolve_path(p).starts_with(resolve_path(d))
                        || (p == c.state_dir && resolve_path(d).starts_with(resolve_path(p)))
                    {
                        return Err(format!(
                            "control_plane: {} must not be inside (or contain) {what}",
                            sanitize_path(&p.display().to_string())
                        ));
                    }
                }
            }
            if finding_key.is_none() {
                return Err(
                    "control_plane needs finding_signing: in robodr-control-plane/v2 every \
                     answer to an authenticated request (and every evidence manifest) is signed \
                     with the finding key"
                        .into(),
                );
            }
            if !policy.oem_validated {
                warnings.push(
                    "control_plane: the response policy is not OEM-validated, so every action \
                     request is refused (observe_mode)"
                        .into(),
                );
            }
            if spec.tcp.is_some_and(|a| !a.ip().is_loopback()) && spec.tls.is_some() {
                warnings.push(format!(
                    "control_plane.listen_tcp {} is reachable off the robot (mutual TLS): the \
                     unit's IPAddressDeny=any needs an IPAddressAllow= drop-in for the SOC \
                     network (packaging/systemd/robodr-agentd.service.d/30-control-plane.conf.example)",
                    spec.tcp.map(|a| a.to_string()).unwrap_or_default()
                ));
            }
            Some(spec)
        }
    };
    // --- executor v1 -------------------------------------------------------
    let executor = match &config.executor {
        None => None,
        Some(e) => {
            let spec = e.resolve()?;
            if let Some(x) = &spec {
                if !policy.oem_validated {
                    warnings.push(
                        "executor: the response policy is not OEM-validated, so the executor \
                         refuses every action (observe_mode)"
                            .into(),
                    );
                }
                if control_plane.is_none() && !x.planner_orders {
                    warnings.push(
                        "executor: enabled, but without control_plane and with planner_orders \
                         false nothing is ever handed to it"
                            .into(),
                    );
                }
            }
            spec
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
    if let Some(p) = &config.spool.status_socket {
        let clash = safety_feed
            .as_ref()
            .and_then(|f| f.socket.as_ref())
            .is_some_and(|s| s.path == *p)
            || host_threats.as_ref().is_some_and(|h| h.path == *p)
            || control_plane
                .as_ref()
                .and_then(|c| c.unix.as_ref())
                .is_some_and(|u| u == p);
        if clash {
            return Err(
                "spool.status_socket is also a safety_feed, host_threats or control_plane socket \
                 path"
                    .into(),
            );
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
        previous_keys: previous,
        boot_id,
        safety_feed,
        correlation,
        finding_key,
        host_threats,
        gateway_feed,
        control_plane,
        executor,
        firewall_joint,
        robot_model,
        warnings,
    })
}

/// The responder morphology a firewall platform morphology means.
fn firewall_morphology(m: robodr_firewall::Morphology) -> robodr_responder::Morphology {
    use robodr_firewall::Morphology as F;
    use robodr_responder::Morphology as R;
    match m {
        F::Humanoid => R::Humanoid,
        F::Quadruped => R::Quadruped,
        F::Wheeled => R::WheeledMobile,
        F::Arm => R::Arm,
        F::Other => R::Other,
    }
}

/// Consistency of `robot.robot_model` with the rest of the configuration.
///
/// * **Morphology (fail closed).** A humanoid model (G1, H1, H1-2, H2, R1)
///   needs a response policy whose `morphology` is `humanoid` (or left
///   unspecified, which the responder treats as humanoid) and, with a
///   joint firewall, a `humanoid` firewall platform: anything else would
///   allow a de-energising response (safe pause, damping substitute) that
///   makes the robot fall, so it is a configuration error. A legged
///   quadruped (Go2, Go2-W, B2, B2-W, A2, AS2, Go1, ...) balances actively
///   too: a policy or firewall morphology other than `quadruped` /
///   `humanoid` / unspecified is an error; `humanoid` is accepted (more
///   conservative) with a warning.
/// * **Low-level layout.** A joint firewall channel `/lowcmd`, `/arm_sdk`
///   or `/user_lowcmd` must have as many motor slots as the model's
///   low-level message (`unitree_go` 20, `unitree_hg` 35).
/// * **Legacy UDP.** `sensor.unitree_legacy` on a DDS-generation model (or
///   a legacy model without it) is a warning.
/// * **Without a model (fail closed).** A joint firewall channel with 35
///   motor slots is a `unitree_hg` low-level message, and every `unitree_hg`
///   model is a humanoid (`robodr_cdr::unitree::model`): the firewall
///   platform must then be `humanoid` and the policy `humanoid` or
///   unspecified, model or not.
pub fn check_robot_model(
    model: Option<robodr_cdr::UnitreeModel>,
    policy: &ResponsePolicy,
    joint: Option<&robodr_firewall::FirewallConfig>,
    sensor: &Settings,
    warnings: &mut Vec<String>,
) -> Result<(), String> {
    use robodr_cdr::unitree::{Generation, Morphology as M};
    use robodr_responder::Morphology as R;
    let fw_morph = joint.map(|j| firewall_morphology(j.platform.morphology));
    if let Some(fm) = fw_morph {
        let pm = policy.morphology;
        if pm != R::Unspecified && fm != pm {
            return Err(format!(
                "firewall.joint_config platform morphology {fm:?} contradicts the response \
                 policy's morphology {pm:?}"
            ));
        }
    }
    if let Some(j) = joint {
        let hg = robodr_cdr::unitree::MOTOR_SLOTS_HG;
        if let Some((ch, _)) = j.joint_channels.iter().find(|(_, s)| s.motors.len() == hg) {
            let pm = policy.morphology;
            let fm = fw_morph.unwrap_or(R::Unspecified);
            if fm != R::Humanoid || !matches!(pm, R::Humanoid | R::Unspecified) {
                return Err(format!(
                    "firewall.joint_config channel {ch:?} has {hg} motor slots, the unitree_hg \
                     low-level layout, and every unitree_hg robot is a humanoid (falls when \
                     de-energised); the firewall platform morphology is {fm:?} and the response \
                     policy's {pm:?}: set both to humanoid"
                ));
            }
        }
    }
    let Some(model) = model else {
        return Ok(());
    };
    let info = model.info();
    let name = info.name;
    let checks = [
        ("response policy", Some(policy.morphology)),
        ("firewall.joint_config platform", fw_morph),
    ];
    for (what, m) in checks {
        let Some(m) = m else { continue };
        match (info.morphology, m) {
            (_, R::Unspecified) => {}
            (M::Humanoid, R::Humanoid) => {}
            (M::Humanoid, other) => {
                return Err(format!(
                    "robot.robot_model {name} is a humanoid, but the {what} morphology is \
                     {other:?}: a humanoid falls when de-energised; set morphology humanoid"
                ))
            }
            (M::Quadruped | M::WheeledQuadruped, R::Quadruped) => {}
            (M::Quadruped | M::WheeledQuadruped, R::Humanoid) => warnings.push(format!(
                "robot.robot_model {name} is a legged quadruped, but the {what} morphology is \
                 humanoid (more conservative than needed)"
            )),
            (M::Quadruped | M::WheeledQuadruped, other) => {
                return Err(format!(
                    "robot.robot_model {name} is a legged quadruped (it balances actively), but \
                     the {what} morphology is {other:?}; set morphology quadruped"
                ))
            }
        }
    }
    if let (Some(j), Some(slots)) = (joint, info.lowcmd_motor_slots()) {
        for (ch, spec) in &j.joint_channels {
            let low = matches!(ch.as_str(), "/lowcmd" | "/arm_sdk" | "/user_lowcmd");
            if low && info.generation == Generation::Sdk2Dds && spec.motors.len() != slots {
                return Err(format!(
                    "firewall.joint_config channel {ch:?} has {} motor slots, but the \
                     {name}'s low-level message has {slots}",
                    spec.motors.len()
                ));
            }
        }
    }
    let legacy = sensor.pipeline.legacy.enabled;
    match (info.generation, legacy) {
        (Generation::Sdk2Dds, true) => warnings.push(format!(
            "sensor.unitree_legacy is enabled, but robot.robot_model {name} speaks DDS \
             (unitree_sdk2), not the legacy UDP protocol"
        )),
        (Generation::LegacyUdp, false) => warnings.push(format!(
            "robot.robot_model {name} speaks the legacy UDP protocol (unitree_legged_sdk); \
             enable sensor.unitree_legacy to inspect its commands"
        )),
        _ => {}
    }
    Ok(())
}

/// Unitree channels whose meaning depends on the robot model (low-level
/// joint commands, robot API requests).
fn model_dependent_channel(ch: &str) -> bool {
    matches!(ch, "/lowcmd" | "/arm_sdk" | "/user_lowcmd") || ch.starts_with("/api/")
}

/// The profile's channels against the model and the firewall (needs the
/// loaded profile, so it runs after [`check_robot_model`]):
///
/// * a profile with Unitree low-level or API channels and no
///   `robot.robot_model` is a warning (API ids and slot layouts are then
///   interpreted without the model);
/// * a joint firewall channel whose profile-recorded type
///   (`motion_types`) is a Unitree `LowCmd_` must have that layout's slot
///   count (`unitree_go` 20, `unitree_hg` 35), whatever its name, and the
///   layout must be the model's;
/// * a legacy UDP channel (`/unitree_legacy/...`) is refused as a joint
///   firewall channel: legacy frames carry no writer identity the firewall
///   could authorise, so every frame would be rejected as an unknown
///   source before its joints were checked (the sensor still evaluates
///   them against the profile envelope and checks the sender address);
/// * with a `firewall` section, every twist / joint-velocity channel must
///   have a kind the firewall can tell ([`robodr_agent::channel_kind`]).
pub fn check_profile_channels(
    model: Option<robodr_cdr::UnitreeModel>,
    profile: &robodr_events::profile::Profile,
    firewall: Option<&FirewallSection>,
    joint: Option<&robodr_firewall::FirewallConfig>,
    warnings: &mut Vec<String>,
) -> Result<(), String> {
    use robodr_cdr::unitree::{IdlFamily, MOTOR_SLOTS_GO, MOTOR_SLOTS_HG};
    use robodr_cdr::MessageKind;
    if model.is_none() {
        let mut chans: Vec<&str> = profile
            .motion_envelopes
            .keys()
            .chain(profile.writer_topics.iter())
            .map(String::as_str)
            .filter(|c| model_dependent_channel(c))
            .collect();
        // Low-level channels first, then the API services.
        chans.sort_unstable_by_key(|c| (c.starts_with("/api/"), *c));
        chans.dedup();
        if !chans.is_empty() {
            let shown: Vec<&str> = chans.iter().take(6).copied().collect();
            warnings.push(format!(
                "the profile has Unitree channels ({}{}) but robot.robot_model is not set: API \
                 call ids and low-level layouts are interpreted without the model, and the \
                 morphology is only checked from the slot counts; set robot.robot_model",
                shown.join(", "),
                if chans.len() > shown.len() {
                    ", ..."
                } else {
                    ""
                }
            ));
        }
    }
    if let Some(j) = joint {
        for (ch, spec) in &j.joint_channels {
            if ch.starts_with(robodr_cdr::unitree_legacy::channels::PREFIX) {
                return Err(format!(
                    "firewall.joint_config channel {ch:?} is a Unitree legacy UDP channel: \
                     legacy frames carry no writer identity the joint firewall could \
                     authorise (the sender is a UDP address), so every frame would be rejected \
                     as an unknown source before its joints were checked; leave it out of \
                     joint_config (the sensor still checks the sender against \
                     unitree_legacy.command_senders and the frame against the profile envelope)"
                ));
            }
            let Some(t) = profile.motion_types.get(ch) else {
                continue;
            };
            let layout = match MessageKind::from_type_name(t) {
                Some(MessageKind::UnitreeGoLowCmd) => (IdlFamily::Go, MOTOR_SLOTS_GO),
                Some(MessageKind::UnitreeHgLowCmd) => (IdlFamily::Hg, MOTOR_SLOTS_HG),
                _ => continue,
            };
            if spec.motors.len() != layout.1 {
                return Err(format!(
                    "firewall.joint_config channel {ch:?} has {} motor slots, but the profile \
                     records its type as {t} ({} motor slots)",
                    spec.motors.len(),
                    layout.1
                ));
            }
            if let Some(m) = model {
                let info = m.info();
                // A2 / AS2: the inferred family counts too (a profile
                // that learned another layout on such a robot is a model
                // alias or a wrong model, never silently accepted).
                if info.lowcmd_idl().is_some_and(|idl| idl != layout.0) {
                    return Err(format!(
                        "firewall.joint_config channel {ch:?}: the profile records its type as \
                         {t}, which is not the low-level layout of robot.robot_model {}{}",
                        info.name,
                        if info.lowcmd_inferred() {
                            " (inferred: the SDK publishes no low-level type for this model; \
                             confirm the type on the robot and report it)"
                        } else {
                            ""
                        }
                    ));
                }
            }
        }
    }
    if firewall.is_some() {
        let legacy: Vec<&String> = profile
            .motion_envelopes
            .keys()
            .filter(|c| c.starts_with(robodr_cdr::unitree_legacy::channels::PREFIX))
            .collect();
        if !legacy.is_empty() {
            warnings.push(format!(
                "firewall: the profile's Unitree legacy channels ({}) carry no writer identity, \
                 so the firewall records every legacy command as from an unknown source; the \
                 sensor's sender check (unitree_legacy.command_senders) is what authorises them",
                legacy
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        for (ch, env) in &profile.motion_envelopes {
            if joint.is_some_and(|j| j.joint_channels.contains_key(ch)) {
                continue;
            }
            let (_, w) = robodr_agent::channel_kind(profile, ch, env)?;
            warnings.extend(w);
        }
    }
    Ok(())
}

/// Check `firewall.joint_config` against the profile as the daemon will
/// run it, **with the platform as written** (so a humanoid configured with
/// a damping / fail-open substitute is refused even though the daemon only
/// records verdicts: the same file must be safe for the in-path gateway).
fn check_joint_firewall(
    fc: &robodr_firewall::FirewallConfig,
    fw: &FirewallSection,
    profile: &robodr_events::profile::Profile,
    warnings: &mut Vec<String>,
) -> Result<(), String> {
    if profile.validate().is_err() {
        // The daemon disables the firewall for an invalid profile.
        return Ok(());
    }
    // The joint part on its own: the twist part (max_angular for every twist
    // channel) is checked when the daemon starts, as without a joint file.
    for ch in fw.max_angular.keys() {
        if fc.joint_channels.contains_key(ch) {
            return Err(format!(
                "firewall.max_angular names {ch:?}, a low-level joint channel of \
                 firewall.joint_config"
            ));
        }
    }
    let mut joint_profile = profile.clone();
    joint_profile.retain_motion_channels(|k| fc.joint_channels.contains_key(k));
    for ch in fc.joint_channels.keys() {
        if !profile.motion_envelopes.contains_key(ch) {
            return Err(format!(
                "firewall.joint_config channel {ch:?} is not a profiled motion channel \
                 (motion_envelopes)"
            ));
        }
        if ch == "/arm_sdk" {
            warnings.push(
                "firewall.joint_config channel \"/arm_sdk\": the arm SDK sends mode 0 on every \
                 slot and still moves the arms; the joint firewall rejects a mode-0 slot with \
                 gains (joint_mode_inconsistent), so every arm-SDK frame becomes a would-have \
                 rejection. Leave \"/arm_sdk\" out of firewall.joint_config: the profile \
                 envelope still checks torque, kp and position step on every slot of every \
                 arm-SDK frame (robot.motion.joint_over_envelope)"
                    .into(),
            );
        }
    }
    robodr_firewall::Policy::compile_with_joints(
        &joint_profile,
        fc.platform,
        &BTreeMap::new(),
        &fc.joint_channels,
    )
    .map_err(|e| format!("firewall.joint_config: {e}"))?;
    Ok(())
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

/// The effective uid of this process (the one FFI declaration lives in
/// `robodr_blackbox::keys`; agentd itself needs no `unsafe` for it).
pub fn effective_uid() -> u32 {
    robodr_blackbox::keys::effective_uid()
}

/// Load and check `blackbox.previous_keys` (see the module docs): absolute
/// paths, at most [`MAX_PREVIOUS_KEY_FILES`], each a public key or keyring
/// file (`robodr_blackbox::keys::load_key_files`: a file with a secret
/// must pass the 0600 / owner rule); an Ed25519 secret is refused (its
/// `.pub` suffices), an HMAC key needs `allow_hmac`; ids distinct and not
/// the current key's; device bindings must name `robot_id`. `None` when
/// the list is empty.
pub fn previous_keys(
    bb: &BlackboxSection,
    robot_id: &str,
    current_key_id: Option<&str>,
    warnings: &mut Vec<String>,
) -> Result<Option<robodr_blackbox::PreviousKeys>, String> {
    if bb.previous_keys.is_empty() {
        return Ok(None);
    }
    if bb.previous_keys.len() > MAX_PREVIOUS_KEY_FILES {
        return Err(format!(
            "blackbox.previous_keys: at most {MAX_PREVIOUS_KEY_FILES} files"
        ));
    }
    let mut all = Vec::new();
    for p in &bb.previous_keys {
        require_abs("blackbox.previous_keys[]", p)?;
        let shown = p.display();
        if resolve_path(p) == resolve_path(&bb.key_file) {
            return Err(format!(
                "blackbox.previous_keys {shown} is blackbox.key_file: list the retired keys only"
            ));
        }
        let keys = robodr_blackbox::keys::load_key_files(p)
            .map_err(|e| format!("blackbox.previous_keys {shown}: {e}"))?;
        for k in keys {
            let id = robodr_ros2_pipeline::sanitize(&k.key_id);
            k.check_hmac_policy(bb.allow_hmac).map_err(|e| {
                format!("blackbox.previous_keys {shown}: {e} (blackbox.allow_hmac)")
            })?;
            if !k.is_symmetric() && !k.is_public() {
                return Err(format!(
                    "blackbox.previous_keys {shown}: key {id:?} is a secret key file; a retired \
                     ed25519 key is listed by its public file (robodr-blackbox export-pub)"
                ));
            }
            if Some(k.key_id.as_str()) == current_key_id {
                return Err(format!(
                    "blackbox.previous_keys {shown}: key {id:?} is the current black-box key"
                ));
            }
            if let Some(d) = k.device_id.as_deref() {
                if d != robot_id {
                    return Err(format!(
                        "blackbox.previous_keys {shown}: key {id:?} is bound to device {:?}, \
                         not robot.id {robot_id:?}",
                        robodr_ros2_pipeline::sanitize(d)
                    ));
                }
            }
            if k.is_symmetric() {
                warnings.push(format!(
                    "blackbox.previous_keys: {id} is a legacy hmac-sha256 key (allowed by \
                     blackbox.allow_hmac): whoever holds it can forge the records it signed"
                ));
            }
            all.push(k);
        }
    }
    robodr_blackbox::PreviousKeys::from_key_files(&all, bb.allow_hmac)
        .map(Some)
        .map_err(|e| format!("blackbox.previous_keys: {e}"))
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
        // ... and tmpfiles.d creates the state directory for agentd's own
        // user (review H1: not the exporters' robodr).
        assert_eq!(value("User="), Some("robodr-agentd"));
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
                    && f[3] == "robodr-agentd"
            }),
            "tmpfiles.d does not create {:?} for robodr-agentd",
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
        // The control plane (full example): its state directory is writable
        // through the shipped drop-in and created private by tmpfiles.d, and
        // its TLS key arrives as that drop-in's credential.
        let cp = c.control_plane.as_ref().expect("control_plane");
        let cpdrop =
            std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(
                "../../packaging/systemd/robodr-agentd.service.d/30-control-plane.conf.example",
            ))
            .unwrap();
        let rw: Vec<&str> = cpdrop
            .lines()
            .filter_map(|l| l.strip_prefix("ReadWritePaths="))
            .flat_map(str::split_whitespace)
            .collect();
        assert!(rw.iter().any(|p| Path::new(p) == cp.state_dir), "{rw:?}");
        assert!(
            tmpfiles.lines().any(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                f.len() >= 5
                    && f[0] == "d"
                    && Path::new(f[1]) == cp.state_dir
                    && f[2] == "0700"
                    && f[3] == "robodr-agentd"
            }),
            "tmpfiles.d does not create {:?} 0700 for robodr-agentd",
            cp.state_dir
        );
        let tls = cp.tls.as_ref().expect("tls");
        let cred = tls
            .key_file
            .strip_prefix("/run/credentials/robodr-agentd.service/")
            .expect("the TLS key is a credential")
            .to_str()
            .unwrap();
        assert!(cpdrop
            .lines()
            .any(|l| l.starts_with(&format!("LoadCredential={cred}:/etc/robodr/keys/"))));
        assert!(cpdrop.lines().any(|l| l.starts_with("IPAddressAllow=")));
        assert!(cp.evidence.is_some());
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
    fn findings_section_defaults_and_validation() {
        let base = r#"{"robot":{"id":"r1","site":"s"},"sensor":{},"policy_path":"/p",
            "blackbox":{"dir":"/b","key_file":"/k"},"spool":{"dir":"/s"}}"#;
        let c = parse(base).unwrap();
        assert_eq!(c.findings, FindingsSection::default());
        assert_eq!(c.findings.topic, "robodr.findings");
        assert_eq!(c.findings.data_source, "robodr");
        let with = |f: &str| {
            base.replace(
                r#""spool":{"dir":"/s"}"#,
                &format!(r#""spool":{{"dir":"/s"}},"findings":{f}"#),
            )
        };
        let c = parse(&with(r#"{"topic":"site-b.findings"}"#)).unwrap();
        assert_eq!(c.findings.topic, "site-b.findings");
        assert_eq!(c.findings.data_source, "robodr");
        assert!(parse(&with(r#"{"topc":"x"}"#)).is_err(), "unknown key");
        for (bad, what) in [
            (r#"{"topic":"a b"}"#, "findings.topic"),
            (r#"{"topic":""}"#, "findings.topic"),
            (r#"{"data_source":"RoboDR"}"#, "findings.data_source"),
            (r#"{"data_source":"kafka:x"}"#, "findings.data_source"),
        ] {
            let e = resolve(parse(&with(bad)).unwrap()).err().unwrap();
            assert!(e.contains(what), "{bad}: {e}");
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
