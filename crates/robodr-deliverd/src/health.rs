//! The health gate (`docs/SECURE-DELIVERY.md` §6.2): the RPK's declared
//! checks plus the fixed one (agentd healthy), judged right after a switch.
//!
//! | check | how |
//! |---|---|
//! | `service_active` | `systemctl is-active --quiet -- <unit>` (argv, bounded) |
//! | `file_present` | the path is a regular file (symlinks followed: `current/...`) |
//! | `probe` | the argv run without a shell as the probe user's UID, bounded in time and output ([`crate::runner`]) |
//! | `ros2_node` | not evaluable on the unit in 13b: an RPK declaring it is refused before anything is installed |
//! | agentd `ok` | `status.json` fresh and `state: ok` (config `health.require_agentd_ok`) |
//!
//! A check that cannot run (missing program, user that resolves
//! differently than at staging, escaped process holding the pipe) fails.

use crate::config::Config;
use crate::runner::{self, Limits, RunAs};
use crate::state::Ver;
use robodr_pkg::rpk::HealthCheck;
use serde::Serialize;
use std::time::Duration;

/// Result of one check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckResult {
    pub check: String,
    pub passed: bool,
    pub detail: String,
}

/// Result of the gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub passed: bool,
    pub checks: Vec<CheckResult>,
}

impl Report {
    /// The first failure, for findings.
    pub fn first_failure(&self) -> String {
        self.checks
            .iter()
            .find(|c| !c.passed)
            .map(|c| format!("{}: {}", c.check, c.detail))
            .unwrap_or_default()
    }
}

/// Whether the unit can evaluate `h` (13b: everything but `ros2_node`).
pub fn supported(h: &HealthCheck) -> bool {
    !matches!(h, HealthCheck::Ros2Node { .. })
}

fn label(h: &HealthCheck) -> String {
    match h {
        HealthCheck::ServiceActive { unit } => format!("service_active {unit}"),
        HealthCheck::FilePresent { path } => format!("file_present {path}"),
        HealthCheck::Ros2Node { node } => format!("ros2_node {node}"),
        HealthCheck::Probe { argv, user, .. } => {
            format!(
                "probe {} as {user}",
                argv.first().map(String::as_str).unwrap_or("")
            )
        }
    }
}

/// Run every check of `checks` for version `v` (its staged probe users).
pub fn run(cfg: &Config, checks: &[HealthCheck], v: &Ver) -> Report {
    let mut out = Vec::new();
    for h in checks {
        let (passed, detail) = match h {
            HealthCheck::ServiceActive { unit } => {
                let r = runner::run(
                    &[
                        cfg.health.systemctl.to_string_lossy().into_owned(),
                        "is-active".into(),
                        "--quiet".into(),
                        "--".into(),
                        unit.clone(),
                    ],
                    None,
                    Limits {
                        timeout: Duration::from_secs(u64::from(cfg.health.service_timeout_s)),
                        max_output: 4096,
                    },
                );
                (r.success(), r.summary())
            }
            HealthCheck::FilePresent { path } => match std::fs::metadata(path) {
                Ok(m) if m.is_file() => (true, "present".into()),
                Ok(_) => (false, "not a regular file".into()),
                Err(e) => (false, robodr_pkg::common::trunc(&e.to_string())),
            },
            HealthCheck::Ros2Node { .. } => (false, "ros2_node checks are not evaluable".into()),
            HealthCheck::Probe {
                argv,
                user,
                timeout_s,
            } => probe(cfg, argv, user, *timeout_s, v),
        };
        out.push(CheckResult {
            check: label(h),
            passed,
            detail,
        });
    }
    if cfg.health.require_agentd_ok {
        let o = crate::safety::observe(&cfg.safety);
        let ok = o.why.is_none() && o.agentd_health.as_deref() == Some("ok");
        out.push(CheckResult {
            check: "agentd ok".into(),
            passed: ok,
            detail: match (&o.why, &o.agentd_health) {
                (Some(w), _) => w.clone(),
                (None, Some(h)) => format!("agentd health {h}"),
                (None, None) => "agentd health unknown".into(),
            },
        });
    }
    Report {
        passed: out.iter().all(|c| c.passed),
        checks: out,
    }
}

fn probe(cfg: &Config, argv: &[String], user: &str, timeout_s: u32, v: &Ver) -> (bool, String) {
    let Some(&[uid, gid]) = v.probe_users.get(user) else {
        return (
            false,
            format!("probe user {user} was not resolved at staging"),
        );
    };
    match crate::users::resolve(cfg, user) {
        Ok(ids) if ids.uid == uid && ids.gid == gid => {}
        Ok(ids) => {
            return (
                false,
                format!(
                    "probe user {user} now resolves to {}:{}, at staging {uid}:{gid}",
                    ids.uid, ids.gid
                ),
            )
        }
        Err(e) => return (false, e),
    }
    let r = runner::run(
        argv,
        Some(RunAs { uid, gid }),
        Limits {
            timeout: Duration::from_secs(u64::from(timeout_s)),
            max_output: cfg.health.max_output_bytes as usize,
        },
    );
    (r.success(), r.summary())
}
