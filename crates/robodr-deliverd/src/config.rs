//! The agent's configuration (`robodr-deliverd-config/1`, JSON, unknown
//! members refused). Everything that decides *what* may be installed comes
//! from signed documents; the configuration says **who this unit is**
//! (enrolment: unit id, site, pinned roots, ring for production rings,
//! architecture, platform) and **where** things go.
//!
//! ```json
//! {
//!   "format": "robodr-deliverd-config/1",
//!   "unit": {"id": "ugv-07", "site": "site-a", "model": "ugv-x1",
//!            "platform": "ugv-x1", "arch": "arm64"},
//!   "trust": {"roots": ["sha256:...", "sha256:...", "sha256:..."], "clock": "trusted"}
//! }
//! ```
//!
//! Every other member has the default documented on its field (the paths
//! of `packaging/README.md`). Paths must be absolute and normalised (no
//! `.` / `..` / empty component); the install roots, the state directory
//! and the media directory must not contain one another.

use robodr_pkg::common::{is_fingerprint, is_label};
use robodr_pkg::deployment::is_ring;
use robodr_pkg::rpk::Arch;
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

/// `format` of the configuration.
pub const CONFIG_FORMAT: &str = "robodr-deliverd-config/1";
/// Largest configuration file read.
pub const MAX_CONFIG_BYTES: usize = 256 * 1024;
/// Usernames a probe may never run as, whatever the configuration says:
/// root and the RoboDR service users (they hold keys and sockets).
pub const ALWAYS_DENIED_USERS: [&str; 3] = ["root", "robodr", "robodr-exec"];

/// Who this unit is (enrolment).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unit {
    /// Unit id: the deployment's `targets.units` entry and the trust
    /// file's `rings` entry for this unit; also the findings' robot id.
    pub id: String,
    /// Site label: must equal the trust file's `site` (pinned).
    pub site: String,
    /// Robot model label (findings).
    pub model: String,
    /// RPK `platform` this unit takes.
    pub platform: String,
    /// `amd64` or `arm64` (an RPK must be this or `all`).
    pub arch: Arch,
    /// Hardware id matched against an RPK's non-empty `hw_compat`.
    #[serde(default)]
    pub hw: Option<String>,
    /// The production ring (`ring-<n>`) given at enrolment, used only when
    /// the trust file assigns this unit to no ring. `lab` and `canary`
    /// are never taken from here: only the root-signed trust file can put
    /// a unit into them.
    #[serde(default)]
    pub ring: Option<String>,
    /// Depot groups this unit belongs to (enrolment). A deployment may name
    /// the unit through one of them only for a production ring.
    #[serde(default)]
    pub groups: Vec<String>,
}

/// How the unit judges expiry (`docs/SECURE-DELIVERY.md` §10, 13b
/// requirement 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockTrust {
    /// The system clock is trusted (GPS / PTP disciplined, or an RTC set
    /// at commissioning): expiry of the trust file and of deployments is
    /// judged on it.
    Trusted,
    /// The system clock is not trusted. Time is the newest depot-signed
    /// time seen (`deployment.created_at` of an accepted deployment, never
    /// beyond the root-signed trust file's `expires_at`), kept monotonic in
    /// the state file: a trust file expired "by the depot's clock" and an
    /// expired newest deployment become staleness findings.
    Untrusted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustCfg {
    /// The delivery roots' public-key fingerprints, pinned out of band.
    pub roots: Vec<String>,
    pub clock: ClockTrust,
}

fn d_state_dir() -> PathBuf {
    "/var/lib/robodr/deliverd".into()
}
fn d_media_dir() -> PathBuf {
    "/var/lib/robodr/deliverd-media".into()
}
fn d_files_root() -> PathBuf {
    "/opt/robodr-delivered".into()
}
fn d_config_root() -> PathBuf {
    "/etc/robodr-delivered".into()
}
fn d_rules_active() -> PathBuf {
    "/etc/robodr-delivered-rules".into()
}
fn d_dpkg() -> PathBuf {
    "/usr/bin/dpkg".into()
}
fn d_dpkg_deb() -> PathBuf {
    "/usr/bin/dpkg-deb".into()
}
fn d_dpkg_query() -> PathBuf {
    "/usr/bin/dpkg-query".into()
}
fn d_keep() -> u32 {
    2
}
fn d_dpkg_timeout() -> u32 {
    900
}

/// Install roots and tools.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallCfg {
    /// `files`: `<files_root>/<name>/<serial>/`, `current` symlink.
    #[serde(default = "d_files_root")]
    pub files_root: PathBuf,
    /// `config`: `<config_root>/<name>/<serial>/`, `current` symlink. The
    /// only place a `config` RPK can write.
    #[serde(default = "d_config_root")]
    pub config_root: PathBuf,
    /// `robodr-rules`: `<rules_active>/<name>` is a symlink to the active
    /// version (kept under the state directory), so a rules loader that
    /// reads `<rules_active>/**/*.toml` sees exactly one version per
    /// package. Point Pulsar's `rules_path` (or a symlink below it) here.
    #[serde(default = "d_rules_active")]
    pub rules_active: PathBuf,
    /// Run after a rules switch (and after a rules rollback), e.g.
    /// `["/usr/bin/systemctl", "try-restart", "robodr-pulsard.service"]`;
    /// a failure fails the health gate. `null`: nothing is reloaded.
    #[serde(default)]
    pub rules_reload: Option<Vec<String>>,
    /// Extra validator for rules versions (argv; the version directory is
    /// appended), e.g. the full DSL check of `scripts/validate_rules.py`.
    #[serde(default)]
    pub rules_validator: Option<Vec<String>>,
    #[serde(default = "d_dpkg")]
    pub dpkg: PathBuf,
    #[serde(default = "d_dpkg_deb")]
    pub dpkg_deb: PathBuf,
    #[serde(default = "d_dpkg_query")]
    pub dpkg_query: PathBuf,
    /// `dpkg --root=DIR` (its own dpkg database under DIR); tests and lab
    /// images only. `null`: the host's dpkg database.
    #[serde(default)]
    pub dpkg_root: Option<PathBuf>,
    /// Longest `dpkg -i`, seconds.
    #[serde(default = "d_dpkg_timeout")]
    pub dpkg_timeout_s: u32,
    /// Versions kept per package besides the installed one (rollback
    /// targets), 1..=8.
    #[serde(default = "d_keep")]
    pub keep_versions: u32,
}

impl Default for InstallCfg {
    fn default() -> Self {
        Self {
            files_root: d_files_root(),
            config_root: d_config_root(),
            rules_active: d_rules_active(),
            rules_reload: None,
            rules_validator: None,
            dpkg: d_dpkg(),
            dpkg_deb: d_dpkg_deb(),
            dpkg_query: d_dpkg_query(),
            dpkg_root: None,
            dpkg_timeout_s: d_dpkg_timeout(),
            keep_versions: d_keep(),
        }
    }
}

fn d_passwd() -> PathBuf {
    "/etc/passwd".into()
}
fn d_uid_min() -> u32 {
    100
}
fn d_uid_max() -> u32 {
    59_999
}
fn d_systemctl() -> PathBuf {
    "/usr/bin/systemctl".into()
}
fn d_true() -> bool {
    true
}
fn d_max_output() -> u32 {
    64 * 1024
}
fn d_service_timeout() -> u32 {
    30
}

/// Health gate settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCfg {
    /// The user database probe users are resolved in (`name:x:uid:gid:...`).
    #[serde(default = "d_passwd")]
    pub passwd: PathBuf,
    /// Probe UIDs must lie in `probe_uid_min..=probe_uid_max` (min >= 1).
    #[serde(default = "d_uid_min")]
    pub probe_uid_min: u32,
    #[serde(default = "d_uid_max")]
    pub probe_uid_max: u32,
    /// More usernames a probe may never run as (besides
    /// [`ALWAYS_DENIED_USERS`]).
    #[serde(default)]
    pub deny_users: Vec<String>,
    #[serde(default = "d_systemctl")]
    pub systemctl: PathBuf,
    /// Fixed check (§6.2): agentd's health must be `ok` after a switch.
    #[serde(default = "d_true")]
    pub require_agentd_ok: bool,
    /// Bytes of stdout + stderr kept per probe (the rest is read and
    /// discarded), 1 KiB..=1 MiB.
    #[serde(default = "d_max_output")]
    pub max_output_bytes: u32,
    /// Timeout of `systemctl is-active`, seconds (1..=300).
    #[serde(default = "d_service_timeout")]
    pub service_timeout_s: u32,
}

impl Default for HealthCfg {
    fn default() -> Self {
        Self {
            passwd: d_passwd(),
            probe_uid_min: d_uid_min(),
            probe_uid_max: d_uid_max(),
            deny_users: Vec::new(),
            systemctl: d_systemctl(),
            require_agentd_ok: true,
            max_output_bytes: d_max_output(),
            service_timeout_s: d_service_timeout(),
        }
    }
}

fn d_status() -> PathBuf {
    "/var/lib/robodr/spool/agentd/status.json".into()
}
fn d_boot_id() -> PathBuf {
    "/proc/sys/kernel/random/boot_id".into()
}

/// Where the live safety state is read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyCfg {
    /// agentd's `status.json` (its live `safety_feed` view).
    #[serde(default = "d_status")]
    pub agentd_status: PathBuf,
    #[serde(default = "d_boot_id")]
    pub boot_id: PathBuf,
}

impl Default for SafetyCfg {
    fn default() -> Self {
        Self {
            agentd_status: d_status(),
            boot_id: d_boot_id(),
        }
    }
}

fn d_bb_dir() -> PathBuf {
    "/var/lib/robodr/blackbox/deliverd".into()
}
fn d_bb_key() -> PathBuf {
    "/run/credentials/robodr-deliverd.service/blackbox.key".into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlackboxCfg {
    /// A black-box chain of its own (the recorder is single-writer).
    #[serde(default = "d_bb_dir")]
    pub dir: PathBuf,
    /// The unit's black-box signing key (`robodr-blackbox` secret key file).
    #[serde(default = "d_bb_key")]
    pub key: PathBuf,
}

impl Default for BlackboxCfg {
    fn default() -> Self {
        Self {
            dir: d_bb_dir(),
            key: d_bb_key(),
        }
    }
}

fn d_spool() -> PathBuf {
    "/var/lib/robodr/spool/agentd".into()
}
fn d_data_source() -> String {
    robodr_ocsf::DEFAULT_DATA_SOURCE.into()
}
fn d_topic() -> String {
    robodr_ocsf::DEFAULT_TOPIC.into()
}
fn d_max_ready() -> u64 {
    10_000
}
fn d_grace() -> u64 {
    86_400
}
fn d_deferral_medium() -> u32 {
    10
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingsCfg {
    /// agentd's findings spool (`robodr.spool/v1`); the agent adds its
    /// records with no-replace links, so both producers share it.
    #[serde(default = "d_spool")]
    pub spool: PathBuf,
    #[serde(default = "d_data_source")]
    pub data_source: String,
    #[serde(default = "d_topic")]
    pub topic: String,
    /// No record is written while `ready/` holds this many files.
    #[serde(default = "d_max_ready")]
    pub max_ready_files: u64,
    /// `robot.deliver.stale` turns High this long after the newest
    /// deployment expired, seconds.
    #[serde(default = "d_grace")]
    pub stale_grace_s: u64,
    /// `robot.deliver.deferred_safety` turns Medium after this many
    /// deferrals of one item.
    #[serde(default = "d_deferral_medium")]
    pub deferral_medium_after: u32,
    /// Optional finding signing key (`robodr-finding-sig`), as agentd's.
    #[serde(default)]
    pub finding_key: Option<PathBuf>,
}

impl Default for FindingsCfg {
    fn default() -> Self {
        Self {
            spool: d_spool(),
            data_source: d_data_source(),
            topic: d_topic(),
            max_ready_files: d_max_ready(),
            stale_grace_s: d_grace(),
            deferral_medium_after: d_deferral_medium(),
            finding_key: None,
        }
    }
}

fn d_interval() -> u64 {
    5_000
}

/// The whole configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub format: String,
    pub unit: Unit,
    pub trust: TrustCfg,
    /// State file, trust anchor, content-addressed store, imported packs
    /// (root only, 0700).
    #[serde(default = "d_state_dir")]
    pub state_dir: PathBuf,
    /// Where media packs are put (copied or mounted) for the agent:
    /// **untrusted**, read only through the verified-copy import.
    #[serde(default = "d_media_dir")]
    pub media_dir: PathBuf,
    #[serde(default)]
    pub install: InstallCfg,
    #[serde(default)]
    pub health: HealthCfg,
    #[serde(default)]
    pub safety: SafetyCfg,
    #[serde(default)]
    pub blackbox: BlackboxCfg,
    #[serde(default)]
    pub findings: FindingsCfg,
    /// Loop interval of `run`, milliseconds (100..=3_600_000).
    #[serde(default = "d_interval")]
    pub interval_ms: u64,
}

/// A normalised absolute path: starts with `/`, no `.`, `..` or empty
/// component, valid UTF-8, at most 4096 bytes, not `/` itself.
pub fn is_clean_abs(p: &Path) -> bool {
    let Some(s) = p.to_str() else { return false };
    if !s.starts_with('/') || s.len() > 4096 || s == "/" || s.ends_with('/') || s.contains("//") {
        return false;
    }
    p.components()
        .skip(1)
        .all(|c| matches!(c, Component::Normal(_)))
        && !s
            .split('/')
            .skip(1)
            .any(|c| c == "." || c == ".." || c.is_empty())
}

fn check_argv(what: &str, argv: &[String]) -> Result<(), String> {
    if argv.is_empty() || argv.len() > 32 {
        return Err(format!("{what}: 1..=32 arguments"));
    }
    if !is_clean_abs(Path::new(&argv[0])) {
        return Err(format!("{what}: the program must be an absolute path"));
    }
    if argv.iter().any(|a| a.len() > 1024 || a.contains('\0')) {
        return Err(format!("{what}: argument too long or with NUL"));
    }
    Ok(())
}

/// `a` contains `b` (or is it).
fn contains(a: &Path, b: &Path) -> bool {
    b.starts_with(a)
}

impl Config {
    /// Parse and validate configuration bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(format!(
                "configuration larger than {MAX_CONFIG_BYTES} bytes"
            ));
        }
        let c: Config = serde_json::from_slice(bytes).map_err(|e| {
            format!(
                "not a {CONFIG_FORMAT} document: {}",
                robodr_pkg::common::trunc(&e.to_string())
            )
        })?;
        c.validate()?;
        Ok(c)
    }

    /// Load and validate a configuration file (no symlink).
    pub fn load(path: &Path) -> Result<Self, String> {
        let b = robodr_release::fsio::read_capped(path, MAX_CONFIG_BYTES)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        Self::parse(&b)
    }

    /// Every rule of the module docs.
    pub fn validate(&self) -> Result<(), String> {
        if self.format != CONFIG_FORMAT {
            return Err(format!("format must be {CONFIG_FORMAT}"));
        }
        let u = &self.unit;
        for (what, v) in [
            ("unit.id", &u.id),
            ("unit.site", &u.site),
            ("unit.model", &u.model),
            ("unit.platform", &u.platform),
        ] {
            if !is_label(v) {
                return Err(format!("{what}: not a label ([a-z0-9][a-z0-9._-]{{0,63}})"));
            }
        }
        if u.arch == Arch::All {
            return Err("unit.arch must be amd64 or arm64".into());
        }
        if u.hw.as_deref().is_some_and(|h| !is_label(h)) {
            return Err("unit.hw: not a label".into());
        }
        if let Some(r) = &u.ring {
            if !is_ring(r) || !robodr_pkg::deployment::is_prod_ring(r) {
                return Err(
                    "unit.ring: only a production ring (ring-<1..99>); lab and canary come from \
                     the root-signed trust file alone"
                        .into(),
                );
            }
        }
        if u.groups.len() > 64 || !u.groups.iter().all(|g| is_label(g)) {
            return Err("unit.groups: at most 64 labels".into());
        }
        let t = &self.trust;
        if t.roots.is_empty() || t.roots.len() > 32 || !t.roots.iter().all(|r| is_fingerprint(r)) {
            return Err("trust.roots: 1..=32 sha256:<64 hex> fingerprints".into());
        }
        let mut sorted = t.roots.clone();
        sorted.sort();
        sorted.dedup();
        if sorted.len() != t.roots.len() {
            return Err("trust.roots: a fingerprint is listed twice".into());
        }
        let i = &self.install;
        let h = &self.health;
        let mut paths: Vec<(&str, &Path)> = vec![
            ("state_dir", &self.state_dir),
            ("media_dir", &self.media_dir),
            ("install.files_root", &i.files_root),
            ("install.config_root", &i.config_root),
            ("install.rules_active", &i.rules_active),
            ("install.dpkg", &i.dpkg),
            ("install.dpkg_deb", &i.dpkg_deb),
            ("install.dpkg_query", &i.dpkg_query),
            ("health.passwd", &h.passwd),
            ("health.systemctl", &h.systemctl),
            ("safety.agentd_status", &self.safety.agentd_status),
            ("safety.boot_id", &self.safety.boot_id),
            ("blackbox.dir", &self.blackbox.dir),
            ("blackbox.key", &self.blackbox.key),
            ("findings.spool", &self.findings.spool),
        ];
        if let Some(r) = &i.dpkg_root {
            paths.push(("install.dpkg_root", r));
        }
        if let Some(k) = &self.findings.finding_key {
            paths.push(("findings.finding_key", k));
        }
        for (what, p) in &paths {
            if !is_clean_abs(p) {
                return Err(format!("{what}: must be a normalised absolute path"));
            }
        }
        // The trees the agent writes must be disjoint: a config RPK must
        // never land in the state directory (anchor, floors), a files RPK
        // never in the config root, the media (untrusted) never overlap
        // anything it trusts.
        let trees: [(&str, &Path); 7] = [
            ("state_dir", &self.state_dir),
            ("media_dir", &self.media_dir),
            ("install.files_root", &i.files_root),
            ("install.config_root", &i.config_root),
            ("install.rules_active", &i.rules_active),
            ("blackbox.dir", &self.blackbox.dir),
            ("findings.spool", &self.findings.spool),
        ];
        for (a, pa) in &trees {
            for (b, pb) in &trees {
                if a != b && contains(pa, pb) {
                    return Err(format!("{b} must not be inside {a} (or equal to it)"));
                }
            }
        }
        if let Some(a) = &i.rules_reload {
            check_argv("install.rules_reload", a)?;
        }
        if let Some(a) = &i.rules_validator {
            check_argv("install.rules_validator", a)?;
        }
        if !(1..=8).contains(&i.keep_versions) {
            return Err("install.keep_versions: 1..=8".into());
        }
        if !(10..=7200).contains(&i.dpkg_timeout_s) {
            return Err("install.dpkg_timeout_s: 10..=7200".into());
        }
        if h.probe_uid_min == 0 || h.probe_uid_min > h.probe_uid_max {
            return Err("health: need 1 <= probe_uid_min <= probe_uid_max".into());
        }
        if h.deny_users.len() > 64 || h.deny_users.iter().any(|n| n.is_empty() || n.len() > 32) {
            return Err("health.deny_users: at most 64 names".into());
        }
        if !(1024..=1024 * 1024).contains(&h.max_output_bytes) {
            return Err("health.max_output_bytes: 1024..=1048576".into());
        }
        if !(1..=300).contains(&h.service_timeout_s) {
            return Err("health.service_timeout_s: 1..=300".into());
        }
        let f = &self.findings;
        if !robodr_ocsf::validate::is_valid_data_source(&f.data_source) {
            return Err("findings.data_source: not a valid data source label".into());
        }
        if !robodr_ocsf::validate::is_valid_topic(&f.topic) {
            return Err("findings.topic: not a valid topic".into());
        }
        if f.max_ready_files == 0 || f.deferral_medium_after == 0 {
            return Err("findings: max_ready_files and deferral_medium_after must be >= 1".into());
        }
        if !(100..=3_600_000).contains(&self.interval_ms) {
            return Err("interval_ms: 100..=3600000".into());
        }
        Ok(())
    }

    /// The trust anchor (`ANCHOR.json` + `.sig`) in the state directory.
    pub fn anchor_path(&self) -> PathBuf {
        self.state_dir.join("trust-anchor.json")
    }

    /// The state file.
    pub fn state_path(&self) -> PathBuf {
        self.state_dir.join("state.json")
    }

    /// Whether `user` may never run a probe.
    pub fn is_denied_user(&self, user: &str) -> bool {
        ALWAYS_DENIED_USERS.contains(&user) || self.health.deny_users.iter().any(|u| u == user)
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub fn minimal() -> serde_json::Value {
        serde_json::json!({
            "format": CONFIG_FORMAT,
            "unit": {"id": "ugv-07", "site": "site-a", "model": "ugv-x1",
                     "platform": "ugv-x1", "arch": "arm64"},
            "trust": {"roots": [format!("sha256:{}", "ab".repeat(32))], "clock": "trusted"}
        })
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::minimal;
    use super::*;

    fn parse(v: &serde_json::Value) -> Result<Config, String> {
        Config::parse(&serde_json::to_vec(v).unwrap())
    }

    #[test]
    fn minimal_config_gets_the_documented_defaults() {
        let c = parse(&minimal()).unwrap();
        assert_eq!(c.state_dir, Path::new("/var/lib/robodr/deliverd"));
        assert_eq!(c.install.config_root, Path::new("/etc/robodr-delivered"));
        assert_eq!(c.findings.spool, Path::new("/var/lib/robodr/spool/agentd"));
        assert!(c.health.require_agentd_ok);
        assert!(c.is_denied_user("root"));
        assert!(c.is_denied_user("robodr"));
        assert!(!c.is_denied_user("probe"));
    }

    #[test]
    fn hostile_configurations_are_refused() {
        type M = fn(&mut serde_json::Value);
        let cases: Vec<(&str, M)> = vec![
            ("unknown member", |v| v["extra"] = 1.into()),
            ("unknown unit member", |v| v["unit"]["x"] = 1.into()),
            ("format", |v| v["format"] = "x".into()),
            ("unit id", |v| v["unit"]["id"] = "../x".into()),
            ("arch all", |v| v["unit"]["arch"] = "all".into()),
            ("lab ring from config", |v| v["unit"]["ring"] = "lab".into()),
            ("canary ring from config", |v| {
                v["unit"]["ring"] = "canary".into()
            }),
            ("bad ring", |v| v["unit"]["ring"] = "ring-0".into()),
            ("no roots", |v| v["trust"]["roots"] = serde_json::json!([])),
            ("bad root", |v| {
                v["trust"]["roots"] = serde_json::json!(["ab"])
            }),
            ("dup root", |v| {
                let r = v["trust"]["roots"][0].clone();
                v["trust"]["roots"] = serde_json::json!([r.clone(), r]);
            }),
            ("relative state", |v| v["state_dir"] = "var/lib/x".into()),
            ("dotdot", |v| v["state_dir"] = "/var/lib/../x".into()),
            ("root dir", |v| {
                v["install"] = serde_json::json!({"files_root": "/"})
            }),
            (
                "config root inside state",
                |v| {
                    v["install"] =
                        serde_json::json!({"config_root": "/var/lib/robodr/deliverd/etc"})
                },
            ),
            ("state inside config root", |v| {
                v["state_dir"] = "/etc/robodr-delivered/state".into()
            }),
            ("media inside files", |v| {
                v["media_dir"] = "/opt/robodr-delivered/media".into()
            }),
            (
                "same roots",
                |v| v["install"] = serde_json::json!({"files_root": "/x", "config_root": "/x"}),
            ),
            (
                "relative reload",
                |v| v["install"] = serde_json::json!({"rules_reload": ["systemctl", "restart"]}),
            ),
            ("uid min 0", |v| {
                v["health"] = serde_json::json!({"probe_uid_min": 0})
            }),
            (
                "uid min > max",
                |v| v["health"] = serde_json::json!({"probe_uid_min": 10, "probe_uid_max": 5}),
            ),
            ("keep 0", |v| {
                v["install"] = serde_json::json!({"keep_versions": 0})
            }),
            ("interval", |v| v["interval_ms"] = 1.into()),
            ("topic", |v| {
                v["findings"] = serde_json::json!({"topic": "a b"})
            }),
        ];
        for (what, m) in cases {
            let mut v = minimal();
            m(&mut v);
            assert!(parse(&v).is_err(), "{what} accepted");
        }
        assert!(Config::parse(&vec![b' '; MAX_CONFIG_BYTES + 1]).is_err());
    }

    #[test]
    fn clean_paths() {
        for ok in ["/a", "/a/b.c", "/var/lib/robodr"] {
            assert!(is_clean_abs(Path::new(ok)), "{ok}");
        }
        for bad in ["", "/", "a", "/a/", "/a//b", "/a/./b", "/a/../b", "./a"] {
            assert!(!is_clean_abs(Path::new(bad)), "{bad}");
        }
    }
}

#[cfg(test)]
mod example_tests {
    use super::*;

    /// The shipped example (config/deliverd.example.json) parses and is the
    /// documented defaults plus its unit section.
    #[test]
    fn the_example_configuration_is_valid_and_spells_out_the_defaults() {
        let c = Config::parse(include_bytes!("../../../config/deliverd.example.json")).unwrap();
        // Everything but the unit, the roots and the rules reload command
        // is the default.
        let minimal = serde_json::json!({
            "format": CONFIG_FORMAT, "unit": c.unit, "trust": c.trust,
            "install": {"rules_reload": c.install.rules_reload}
        });
        assert_eq!(
            Config::parse(&serde_json::to_vec(&minimal).unwrap()).unwrap(),
            c
        );
    }
}
