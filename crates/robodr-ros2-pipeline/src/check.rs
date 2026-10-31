//! `robodr-ros2-watch --check-config <pulsar.toml>`: offline validation of
//! the sensor's `[module.robodr-sensor-ros2]` section, before the Pulsar
//! daemon is (re)started with it (SALES-READINESS T91).
//!
//! What it does, in the order the daemon does it:
//!
//! 1. reads the file (at most [`MAX_CONFIG_BYTES`]) and parses it as TOML
//!    (a syntax error stops Pulsar from starting at all);
//! 2. takes `[module.robodr-sensor-ros2]`: `enabled` is Pulsar's own key and
//!    must be a boolean; the rest is deserialised into [`Config`] exactly as
//!    `pulsar_core::pdk::ModuleConfig::parse` does (same `serde_ignored`
//!    pass), so a key the daemon would ignore with a log warning (a typo such
//!    as `bindng`, `hold_msec`) is reported here as a warning too;
//! 3. runs [`Config::validate`] (ranges, absolute paths, port overlap, ...);
//! 4. lists `/dev/shm` **of the host running the check** for DDS
//!    shared-memory segments (Fast DDS SHM, data sharing, iceoryx): their
//!    traffic is invisible to the capture (a warning when segments are
//!    found, a summary line otherwise; see `robodr_capture::shm`). Run the
//!    check on the robot for this to mean anything;
//! 5. reads the profile and evaluates its trust (signature, metadata,
//!    revocation, anti-rollback decision against the current state file)
//!    with [`load_profile_deferred`], **without writing** the state file,
//!    and reports whether the daemon would enforce it.
//!
//! Read-only: nothing is written, no socket is opened, nothing is captured.
//! The default-route lookup for an absent `capture.interfaces` reads this
//! host's `/proc/net/route`, so run the check on the robot (or list the
//! interfaces explicitly).
//!
//! Outcome: errors make the configuration invalid (exit 1); warnings do not,
//! unless `--strict` is given. Limits that hold for every deployment (the
//! capture cannot see shared-memory transports; what an SROS 2 governance
//! leaves visible) are summary lines starting with `note:`, not warnings,
//! so a correct configuration can pass `--strict`. A profile the daemon would refuse to enforce
//! (it then runs observe-only and raises `robot.ros2.profile_refused`) is a
//! warning, as in `robodr-agentd --check-config`, and an error under
//! `--strict`.
//!
//! Every echoed value (file text, key names, paths) is sanitised: the file
//! may be attacker-supplied in a support case.

use std::io::Read;
use std::path::Path;

use crate::config::{CaptureInput, Config};
use crate::pipeline::{Pipeline, ProfileStatus};
use crate::profile_trust::load_profile_deferred;
use crate::sanitize::sanitize;

/// Pulsar's module name of the RoboDR ROS 2 sensor
/// (`robodr_sensor_ros2::MODULE_NAME`; that crate depends on Pulsar, this
/// one does not).
pub const SENSOR_MODULE: &str = "robodr-sensor-ros2";

/// Modules `robodr-pulsard` registers besides the sensor. A
/// `[module.robodr-*]` section with any other name is almost certainly a
/// typo (Pulsar only warns "no such module is loaded").
pub const OTHER_ROBODR_MODULES: &[&str] = &["robodr-threat-forward"];

/// Largest configuration file read (a real `pulsar.toml` is a few KiB).
pub const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// Result of a check.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CheckReport {
    /// The configuration is invalid (the daemon would refuse to start the
    /// module, or Pulsar would not start).
    pub errors: Vec<String>,
    /// Accepted, but probably not what the operator meant.
    pub warnings: Vec<String>,
    /// What the daemon would run with (one line per item), when valid.
    pub summary: Vec<String>,
}

impl CheckReport {
    /// Valid: no error, and with `strict` no warning either.
    pub fn ok(&self, strict: bool) -> bool {
        self.errors.is_empty() && (!strict || self.warnings.is_empty())
    }
}

/// Check the file at `path` (see the module docs).
pub fn check_config_file(path: &Path) -> CheckReport {
    match read_bounded(path) {
        Ok(text) => {
            let mut r = check_config_text(&text, crate::config::system_default_route_interface);
            shm_scan_lines(
                robodr_capture::shm::scan_dir(Path::new(robodr_capture::shm::DEV_SHM)),
                &mut r,
            );
            r
        }
        Err(e) => CheckReport {
            errors: vec![format!(
                "{}: {}",
                sanitize(&path.display().to_string()),
                sanitize(&e)
            )],
            ..CheckReport::default()
        },
    }
}

/// Report a `/dev/shm` scan of the host running the check, which is the
/// robot only when the check runs there: a warning only when segments are
/// found, a `note:` summary line otherwise (both outcomes say nothing about
/// the robot when the check runs elsewhere).
fn shm_scan_lines(scan: std::io::Result<robodr_capture::shm::ShmScan>, r: &mut CheckReport) {
    match scan {
        Ok(scan) => match shm_warning(&scan) {
            Some(w) => r.warnings.push(w),
            None => r.summary.push(format!(
                "note: no DDS shared-memory segment in {} of the host running this check \
                 (meaningful only on the robot)",
                robodr_capture::shm::DEV_SHM
            )),
        },
        Err(e) => r.summary.push(format!(
            "note: cannot list {}: {} (DDS shared-memory use on the host running this check \
             not checked)",
            robodr_capture::shm::DEV_SHM,
            sanitize(&e.to_string())
        )),
    }
}

/// The warning for DDS shared-memory segments found in `/dev/shm` of the
/// host running the check, if any: DDS traffic between that host's
/// participants over them is never captured.
pub fn shm_warning(scan: &robodr_capture::shm::ShmScan) -> Option<String> {
    (!scan.is_empty()).then(|| {
        format!(
            "{} of the host running this check holds DDS shared-memory segments ({}{}): if \
             this is the robot, DDS traffic between its processes goes over shared memory and \
             is invisible to the capture; commission the robot with UDP-only transports \
             (docs/DDS-TRANSPORTS.md)",
            robodr_capture::shm::DEV_SHM,
            scan.summary(),
            if scan.truncated {
                ", listing truncated"
            } else {
                ""
            }
        )
    })
}

fn read_bounded(path: &Path) -> Result<String, String> {
    // Stat before opening: opening a FIFO blocks until a writer appears.
    let meta = std::fs::metadata(path).map_err(|e| format!("cannot open: {e}"))?;
    if !meta.is_file() {
        return Err("not a regular file".into());
    }
    let f = std::fs::File::open(path).map_err(|e| format!("cannot open: {e}"))?;
    // Again on the opened file (the path may have changed in between).
    let meta = f.metadata().map_err(|e| format!("cannot stat: {e}"))?;
    if !meta.is_file() {
        return Err("not a regular file".into());
    }
    let mut buf = Vec::new();
    f.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("cannot read: {e}"))?;
    if buf.len() as u64 > MAX_CONFIG_BYTES {
        return Err(format!("larger than {MAX_CONFIG_BYTES} bytes"));
    }
    String::from_utf8(buf).map_err(|_| "not valid UTF-8 (TOML must be UTF-8)".to_string())
}

/// Check configuration text. `default_iface` is the default-route lookup
/// used when `capture.interfaces` is absent (injectable for tests).
pub fn check_config_text(
    text: &str,
    default_iface: impl FnOnce() -> Option<String>,
) -> CheckReport {
    let mut r = CheckReport::default();
    let root: toml::Table = match toml::from_str(text) {
        Ok(t) => t,
        Err(e) => {
            r.errors
                .push(format!("TOML syntax error: {}", sanitize(&e.to_string())));
            return r;
        }
    };
    let modules = match root.get("module") {
        None => None,
        Some(toml::Value::Table(t)) => Some(t),
        Some(_) => {
            r.errors
                .push("`module` must be a table of [module.<name>] sections".into());
            return r;
        }
    };
    if let Some(modules) = modules {
        for name in modules.keys() {
            if name.starts_with("robodr")
                && name != SENSOR_MODULE
                && !OTHER_ROBODR_MODULES.contains(&name.as_str())
            {
                r.warnings.push(format!(
                    "[module.{}] is not a RoboDR module (typo of [module.{SENSOR_MODULE}]?): \
                     Pulsar ignores it",
                    sanitize(name)
                ));
            }
        }
    }
    let Some(section) = modules.and_then(|m| m.get(SENSOR_MODULE)) else {
        r.warnings.push(format!(
            "no [module.{SENSOR_MODULE}] section: the sensor is disabled (its default) and the \
             robot's DDS traffic is not watched"
        ));
        return r;
    };
    let Some(section) = section.as_table() else {
        r.errors
            .push(format!("[module.{SENSOR_MODULE}] must be a table"));
        return r;
    };
    let mut section = section.clone();
    match section.remove("enabled") {
        Some(toml::Value::Boolean(true)) => {}
        Some(toml::Value::Boolean(false)) | None => r.warnings.push(format!(
            "[module.{SENSOR_MODULE}] enabled is not true: the sensor is not started"
        )),
        Some(_) => {
            r.errors.push(format!(
                "[module.{SENSOR_MODULE}] enabled must be a boolean (Pulsar refuses the file)"
            ));
            return r;
        }
    }

    let mut ignored = Vec::new();
    let cfg: Config = match serde_ignored::deserialize(toml::Value::Table(section), |p| {
        ignored.push(p.to_string())
    }) {
        Ok(c) => c,
        Err(e) => {
            r.errors.push(format!(
                "[module.{SENSOR_MODULE}]: {}",
                sanitize(&e.to_string())
            ));
            return r;
        }
    };
    for key in ignored {
        r.warnings.push(format!(
            "unknown key `{}` in [module.{SENSOR_MODULE}]: ignored by the daemon (typo?)",
            sanitize(&key)
        ));
    }

    let (settings, warnings) = match cfg.validate_with(default_iface) {
        Ok(v) => v,
        Err(e) => {
            r.errors.push(sanitize(&e));
            return r;
        }
    };
    r.warnings.extend(warnings.iter().map(|w| sanitize(w)));
    r.warnings.extend(
        settings
            .profile_trust
            .warnings()
            .iter()
            .map(|w| sanitize(w)),
    );

    r.summary.push(format!(
        "domain_id {}; SPDP socket {}",
        settings.domain_id,
        match &settings.spdp {
            Some(s) => format!("{}:{} on {}", s.group, s.port, s.interface),
            None => "off".into(),
        }
    ));
    match &settings.capture {
        None => r.summary.push("passive capture off".into()),
        Some(c) => {
            match &c.input {
                CaptureInput::Live { interfaces } if interfaces.is_empty() => {
                    r.summary.push(format!(
                        "passive capture on every interface, domains {:?}",
                        c.domain_ids
                    ));
                }
                CaptureInput::Live { interfaces } => r.summary.push(format!(
                    "passive capture on {}, domains {:?}",
                    sanitize(&interfaces.join(",")),
                    c.domain_ids
                )),
                CaptureInput::Replay { path } => {
                    r.warnings.push(format!(
                        "capture.pcap_replay is set ({}): LAB ONLY, the robot's live traffic \
                         is NOT watched by the capture",
                        sanitize(&path.display().to_string())
                    ));
                    let shown = sanitize(&path.display().to_string());
                    // Stat first: opening a FIFO would block the check.
                    match std::fs::metadata(path) {
                        Err(e) => r.errors.push(format!(
                            "capture.pcap_replay {shown}: cannot open: {}",
                            sanitize(&e.to_string())
                        )),
                        Ok(m) if !m.is_file() => r.warnings.push(format!(
                            "capture.pcap_replay {shown} is not a regular file: not opened by \
                             the check"
                        )),
                        Ok(_) => {
                            if let Err(e) = std::fs::File::open(path) {
                                r.errors.push(format!(
                                    "capture.pcap_replay {shown}: cannot open: {}",
                                    sanitize(&e.to_string())
                                ));
                            }
                        }
                    }
                }
            }
            // A fact about every capture, not about this configuration:
            // a summary note, so `--strict` can pass.
            r.summary.push(
                "note: shared-memory DDS transports (Fast DDS SHM, Cyclone iceoryx, Connext \
                 SHM) are invisible to the capture: commission the robot with them off \
                 (docs/DDS-TRANSPORTS.md)"
                    .into(),
            );
        }
    }
    if !settings.has_builtin_source() {
        r.warnings.push(
            "listen_spdp = false and capture.enabled = false: the sensor has no datagram source"
                .into(),
        );
    }

    if let Some(policy) = &settings.pipeline.sros2 {
        r.summary.push(format!(
            "SROS 2 keystore: {} grant(s); DDS-Security identities are checked against it",
            policy.grants.len()
        ));
        r.summary.extend(policy.publish_summary());
        // What the governance leaves visible follows from a correct
        // (secured) deployment: summary notes, not warnings.
        r.summary.extend(
            policy
                .visibility()
                .into_iter()
                .map(|v| format!("note: {}", sanitize(&v))),
        );
    }

    // Profile + trust, without writing the anti-rollback state.
    match load_profile_deferred(&settings.profile_path, &settings.profile_trust) {
        Err(e) => r.errors.push(format!(
            "profile_path {}: {}",
            sanitize(&settings.profile_path.display().to_string()),
            sanitize(&e)
        )),
        Ok((loaded, commit)) => {
            let pipeline = Pipeline::from_loaded(loaded, settings.pipeline.clone());
            let model = sanitize(&pipeline.profile().model);
            match pipeline.status() {
                ProfileStatus::Enforcing => {
                    r.summary
                        .push(format!("profile '{model}' would be ENFORCED"));
                    if commit.is_some() {
                        r.summary.push(
                            "the daemon would record this profile version in the \
                             anti-rollback state file at start (not written by the check)"
                                .into(),
                        );
                    }
                }
                _ => {
                    if let Some(msg) = pipeline.status_message() {
                        r.warnings.push(msg);
                    }
                    r.summary.push(format!(
                        "profile '{model}' would run {}",
                        pipeline.status().as_str()
                    ));
                }
            }
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth0() -> Option<String> {
        Some("eth0".into())
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "robodr-checkcfg-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn unlocked_profile(dir: &Path) -> std::path::PathBuf {
        let mut p = robodr_events::profile::Profile {
            model: "lab-bot".into(),
            ..Default::default()
        };
        p.writer_topics.insert("/cmd_vel".into());
        let path = dir.join("profile.json");
        std::fs::write(&path, serde_json::to_string_pretty(&p).unwrap()).unwrap();
        path
    }

    fn section(profile: &Path, extra: &str) -> String {
        format!(
            "[module.robodr-sensor-ros2]\nenabled = true\nprofile_path = {:?}\n{extra}",
            profile.display().to_string()
        )
    }

    #[test]
    fn valid_unlocked_profile_is_ok_with_observe_warning() {
        let d = tmpdir("ok");
        let p = unlocked_profile(&d);
        let r = check_config_text(&section(&p, ""), eth0);
        assert!(r.errors.is_empty(), "{r:?}");
        assert!(r.ok(false));
        assert!(!r.ok(true), "observe-only is a warning: --strict fails");
        assert!(r.warnings.iter().any(|w| w.contains("NOT locked")), "{r:?}");
        assert!(r.summary.iter().any(|s| s.contains("observing")), "{r:?}");
    }

    #[test]
    fn syntax_error_is_reported() {
        let r = check_config_text("[module.robodr-sensor-ros2\nenabled = true\n", eth0);
        assert!(!r.ok(false));
        assert!(r.errors[0].contains("TOML syntax error"), "{r:?}");
    }

    #[test]
    fn unknown_keys_are_warned_like_pulsar_does() {
        let d = tmpdir("unknown");
        let p = unlocked_profile(&d);
        let text = section(
            &p,
            "hold_msec = 5\n[module.robodr-sensor-ros2.bindng]\nenabled = false\n",
        );
        let r = check_config_text(&text, eth0);
        assert!(r.errors.is_empty(), "{r:?}");
        assert!(
            r.warnings.iter().any(|w| w.contains("`hold_msec`")),
            "{r:?}"
        );
        assert!(r.warnings.iter().any(|w| w.contains("`bindng`")), "{r:?}");
    }

    #[test]
    fn out_of_range_value_is_an_error() {
        let d = tmpdir("range");
        let p = unlocked_profile(&d);
        let r = check_config_text(&section(&p, "domain_id = 233\n"), eth0);
        assert!(
            r.errors.iter().any(|e| e.contains("domain_id 233")),
            "{r:?}"
        );
    }

    #[test]
    fn wrong_type_is_an_error() {
        let d = tmpdir("type");
        let p = unlocked_profile(&d);
        let r = check_config_text(&section(&p, "dedup_capacity = \"many\"\n"), eth0);
        assert!(!r.errors.is_empty(), "{r:?}");
    }

    #[test]
    fn non_bool_enabled_is_an_error_and_false_a_warning() {
        let r = check_config_text("[module.robodr-sensor-ros2]\nenabled = \"yes\"\n", eth0);
        assert!(r.errors.iter().any(|e| e.contains("boolean")), "{r:?}");
        let d = tmpdir("disabled");
        let p = unlocked_profile(&d);
        let r = check_config_text(
            &section(&p, "").replace("enabled = true", "enabled = false"),
            eth0,
        );
        assert!(r.errors.is_empty(), "{r:?}");
        assert!(
            r.warnings.iter().any(|w| w.contains("not started")),
            "{r:?}"
        );
    }

    #[test]
    fn missing_section_and_module_typo_are_warned() {
        let r = check_config_text("[module.robodr-sensor-ros]\nenabled = true\n", eth0);
        assert!(r.errors.is_empty());
        assert!(
            r.warnings.iter().any(|w| w.contains("not a RoboDR module")),
            "{r:?}"
        );
        assert!(r
            .warnings
            .iter()
            .any(|w| w.contains("no [module.robodr-sensor-ros2]")));
        let r = check_config_text(
            "[module.robodr-threat-forward]\nenabled = true\n[module.robodr-sensor-ros2]\n\
             enabled = true\nprofile_path = \"/nonexistent/robodr/p.json\"\n",
            eth0,
        );
        assert!(
            !r.warnings.iter().any(|w| w.contains("not a RoboDR module")),
            "{r:?}"
        );
    }

    #[test]
    fn missing_profile_is_an_error() {
        let r = check_config_text(
            "[module.robodr-sensor-ros2]\nenabled = true\n\
             profile_path = \"/nonexistent/robodr/profile.json\"\n",
            eth0,
        );
        assert!(r.errors.iter().any(|e| e.contains("profile_path")), "{r:?}");
    }

    #[test]
    fn hostile_text_is_sanitised() {
        let r = check_config_text(
            "[module.robodr-sensor-ros2]\nenabled = true\n\"evil\\u001b[2Jkey\" = 1\n\
             profile_path = \"/nonexistent/x.json\"\n",
            eth0,
        );
        for line in r.errors.iter().chain(&r.warnings) {
            assert!(!line.contains('\u{1b}'), "{line:?}");
        }
    }

    #[test]
    fn capture_on_notes_shared_memory_and_replay_is_checked() {
        let d = tmpdir("cap");
        let p = unlocked_profile(&d);
        let r = check_config_text(
            &section(&p, "[module.robodr-sensor-ros2.capture]\nenabled = true\n"),
            eth0,
        );
        assert!(r.errors.is_empty(), "{r:?}");
        assert!(
            r.summary.iter().any(|s| s.contains("shared-memory")),
            "{r:?}"
        );
        assert!(r.summary.iter().any(|s| s.contains("lo,eth0")), "{r:?}");
        let r = check_config_text(
            &section(
                &p,
                "[module.robodr-sensor-ros2.capture]\nenabled = true\n\
                 pcap_replay = \"/nonexistent/robodr/x.pcapng\"\n",
            ),
            eth0,
        );
        assert!(r.errors.iter().any(|e| e.contains("pcap_replay")), "{r:?}");
        assert!(r.warnings.iter().any(|w| w.contains("LAB ONLY")), "{r:?}");
    }

    #[test]
    fn shared_memory_segments_on_this_host_are_warned() {
        let s = robodr_capture::shm::scan_names(["fastrtps_port7411", "fastrtps_port7411_el"]);
        let w = shm_warning(&s).unwrap();
        assert!(w.contains("Fast DDS shared-memory transport (1)"), "{w}");
        assert!(shm_warning(&robodr_capture::shm::scan_names(["x"])).is_none());
    }

    /// Review (phase 3): the "no segment" line of the `/dev/shm` scan was
    /// the only static summary line without the `note:` prefix.
    #[test]
    fn shm_scan_outcomes_are_a_warning_or_a_note() {
        let mut r = CheckReport::default();
        shm_scan_lines(Ok(robodr_capture::shm::scan_names(["x"])), &mut r);
        assert!(r.warnings.is_empty(), "{r:?}");
        assert_eq!(r.summary.len(), 1);
        assert!(
            r.summary[0].starts_with("note: no DDS shared-memory"),
            "{r:?}"
        );

        let mut r = CheckReport::default();
        shm_scan_lines(Err(std::io::Error::other("denied")), &mut r);
        assert!(r.warnings.is_empty(), "{r:?}");
        assert!(r.summary[0].starts_with("note: cannot list"), "{r:?}");

        let mut r = CheckReport::default();
        shm_scan_lines(
            Ok(robodr_capture::shm::scan_names(["fastrtps_port7411"])),
            &mut r,
        );
        assert_eq!(r.warnings.len(), 1, "{r:?}");
        assert!(r.summary.is_empty(), "{r:?}");
        assert!(!r.ok(true));
    }

    #[test]
    fn sros2_keystore_is_loaded_and_summarised() {
        let d = tmpdir("sros2");
        let p = unlocked_profile(&d);
        let ks = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/captures/ros2-humble/sros2");
        let r = check_config_text(
            &section(
                &p,
                &format!("sros2_keystore = {:?}\n", ks.display().to_string()),
            ),
            eth0,
        );
        assert!(r.errors.is_empty(), "{r:?}");
        assert!(r.summary.iter().any(|s| s.contains("2 grant(s)")), "{r:?}");
        assert!(r.summary.iter().any(|s| s.contains("no topic")), "{r:?}");
        let r = check_config_text(
            &section(&p, "sros2_keystore = \"relative/enclaves\"\n"),
            eth0,
        );
        assert!(r.errors.iter().any(|e| e.contains("absolute")), "{r:?}");
        let r = check_config_text(
            &section(&p, "sros2_keystore = \"/nonexistent/enclaves\"\n"),
            eth0,
        );
        assert!(
            r.errors.iter().any(|e| e.contains("sros2_keystore")),
            "{r:?}"
        );
    }

    /// Review finding (WP7, medium): with the capture enabled, a static
    /// shared-memory note was a warning, so `--strict` failed on every
    /// configuration with passive capture, whatever the operator did; the
    /// SROS 2 visibility statements did the same for every keystore.
    #[test]
    fn static_notes_do_not_fail_strict() {
        let d = tmpdir("strictnotes");
        let p = unlocked_profile(&d);
        let ks = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/captures/ros2-humble/sros2");
        let r = check_config_text(
            &section(
                &p,
                &format!(
                    "sros2_keystore = {:?}\n[module.robodr-sensor-ros2.capture]\nenabled = true\n",
                    ks.display().to_string()
                ),
            ),
            eth0,
        );
        assert!(r.errors.is_empty(), "{r:?}");
        let static_notes: Vec<&String> = r
            .warnings
            .iter()
            .filter(|w| w.contains("shared-memory") || w.contains("SROS 2 governance"))
            .collect();
        assert!(static_notes.is_empty(), "{static_notes:?}");
        assert!(
            r.summary.iter().any(|s| s.contains("shared-memory")),
            "{r:?}"
        );
        assert!(r.summary.iter().any(|s| s.contains("no topic")), "{r:?}");
    }

    /// Review finding (WP7, low): the file was opened before the regular
    /// file check, so a FIFO made `--check-config` block for ever.
    #[test]
    fn fifo_is_refused_without_blocking() {
        let d = tmpdir("fifo");
        let f = d.join("pulsar.toml");
        let made = std::process::Command::new("mkfifo")
            .arg(&f)
            .status()
            .is_ok_and(|s| s.success());
        if !made {
            eprintln!("mkfifo unavailable: skipped");
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let path = f.clone();
        std::thread::spawn(move || {
            let _ = tx.send(check_config_file(&path));
        });
        let r = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("check_config_file blocked on a FIFO");
        assert!(
            r.errors.iter().any(|e| e.contains("not a regular file")),
            "{r:?}"
        );
        // pcap_replay pointing at a FIFO: not opened by the check either.
        let p = unlocked_profile(&d);
        let cfg = d.join("replay.toml");
        std::fs::write(
            &cfg,
            section(
                &p,
                &format!(
                    "[module.robodr-sensor-ros2.capture]\nenabled = true\npcap_replay = {:?}\n",
                    f.display().to_string()
                ),
            ),
        )
        .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(check_config_file(&cfg));
        });
        let r = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("check_config_file blocked on a pcap_replay FIFO");
        assert!(r.errors.is_empty(), "{r:?}");
        assert!(
            r.warnings.iter().any(|w| w.contains("not a regular file")),
            "{r:?}"
        );
    }

    #[test]
    fn oversized_file_is_refused() {
        let d = tmpdir("big");
        let f = d.join("pulsar.toml");
        std::fs::write(&f, vec![b'#'; (MAX_CONFIG_BYTES + 1) as usize]).unwrap();
        let r = check_config_file(&f);
        assert!(r.errors.iter().any(|e| e.contains("larger than")), "{r:?}");
    }
}
