//! The safety-state gate (`docs/SECURE-DELIVERY.md` §6.3): installs and
//! rollbacks that change anything on the robot run only while the robot's
//! **live** safety state is `idle` or `safe_state_active`.
//!
//! The state is the one agentd grades every response plan by: the
//! combined view of its `safety_feed` (ROS 2 topics and / or the safety
//! socket a PLC gateway writes), which agentd writes into `status.json`
//! every housekeeping tick. This module reads that file and takes its
//! `safety_state` only if **all** hold, otherwise the state is
//! `unknown` (and the install is deferred):
//!
//! * agentd is running (`running: true`) on this boot (`boot_id`);
//! * the status is fresh by `CLOCK_MONOTONIC` (`updated_mono_ms` at most
//!   `stale_after_ms` old, the latter capped at [`MAX_STALE_MS`]) — the
//!   same rule as `robodr_agentd::effective_state`;
//! * agentd has a **live feed** (`safety_feed` present): a state that is
//!   only agentd's static configuration (`context.safety_state`) says
//!   nothing about whether the robot is moving now.
//!
//! The feed itself goes to `unknown` when its sources go stale, so a dead
//! PLC gateway defers installs too.
//!
//! # Only from agentd (review H1)
//!
//! The status is taken only from **agentd itself**, never from a file a
//! network-facing service could write. agentd runs as its own system user
//! (`robodr-agentd`), distinct from the exporters (`robodr-kafka-publish`,
//! `robodr-uplink`, `robodr-spool-export` run as `robodr`), and serves its
//! status on a unix socket (`spool.status_socket`,
//! `/run/robodr-agentd/status.sock`). [`observe`]:
//!
//! * **socket** (the shipped configuration): connects and checks the peer
//!   with `SO_PEERCRED`: the process that bound and serves it must run as
//!   `safety.agentd_user` (resolved in `safety.passwd`, files only) or
//!   root;
//! * **regular file** (tests, lab setups): opened without following a
//!   symlink relative to its directory's descriptor; the file and its
//!   directory must be owned by that user or root and writable by nobody
//!   else (no group or other write bit), so no other user can have put
//!   or replaced it;
//! * anything else, or a check that fails (another uid, unknown agentd
//!   user and a non-root writer, a group-writable spool), is `unknown`:
//!   the install is deferred.
//!
//! agentd's own safety input (`safety_feed.socket`, the PLC gateway) is
//! protected the same way on agentd's side: socket mode and group, and an
//! `SO_PEERCRED` check against the configured feeders
//! (`robodr_agentd::safety`).

use crate::config::SafetyCfg;
use robodr_responder::SafetyState;
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::time::Duration;

/// Largest `status.json` read.
pub const MAX_STATUS_BYTES: usize = 1024 * 1024;
/// A status claiming a longer freshness window than this is treated as
/// this (10 minutes).
pub const MAX_STALE_MS: u64 = 600_000;

/// What the gate saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub state: SafetyState,
    /// Why the state is `unknown` when it is not agentd's reading.
    pub why: Option<String>,
    /// agentd's own health (`ok` / `degraded` / `unknown`) when fresh.
    pub agentd_health: Option<String>,
}

impl Observed {
    /// Installs may switch now.
    pub fn allows_install(&self) -> bool {
        matches!(self.state, SafetyState::Idle | SafetyState::SafeStateActive)
    }

    fn unknown(why: impl Into<String>) -> Self {
        Self {
            state: SafetyState::Unknown,
            why: Some(why.into()),
            agentd_health: None,
        }
    }
}

/// The configuration / serde name of a state.
pub fn state_name(s: SafetyState) -> &'static str {
    match s {
        SafetyState::Idle => "idle",
        SafetyState::MovingSlow => "moving_slow",
        SafetyState::MovingFast => "moving_fast",
        SafetyState::CollaborativeHumanNearby => "collaborative_human_nearby",
        SafetyState::EStopActive => "estop_active",
        SafetyState::SafeStateActive => "safe_state_active",
        SafetyState::Unknown => "unknown",
    }
}

/// agentd's heartbeat: the status is agentd's, says it is running on
/// this boot and is fresh by `CLOCK_MONOTONIC`. Returns the parsed status,
/// or why not. (The first half of [`judge`]; `robodr-deliverd
/// safety-state` reports it as `agentd_fresh`, and the post-install
/// health check of `install-bundle.sh` waits for it.)
pub fn heartbeat(
    status: &[u8],
    now_mono_ms: u64,
    boot_id: &str,
) -> Result<serde_json::Value, String> {
    if status.len() > MAX_STATUS_BYTES {
        return Err("agentd status too large".into());
    }
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(status) else {
        return Err("agentd status is not JSON".into());
    };
    let s = |k: &str| v.get(k).and_then(serde_json::Value::as_str);
    let n = |k: &str| v.get(k).and_then(serde_json::Value::as_u64);
    if s("kind") != Some("robodr.agentd_status") {
        return Err("not an agentd status".into());
    }
    if v.get("running").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err("agentd is not running".into());
    }
    if boot_id.is_empty() || s("boot_id") != Some(boot_id) {
        return Err("agentd status is from another boot".into());
    }
    let (Some(at), Some(stale)) = (n("updated_mono_ms"), n("stale_after_ms")) else {
        return Err("agentd status has no freshness fields".into());
    };
    if at > now_mono_ms || now_mono_ms - at > stale.min(MAX_STALE_MS) {
        return Err("agentd status is stale".into());
    }
    Ok(v)
}

/// Judge `status.json` bytes read at `now_mono_ms` on boot `boot_id`.
pub fn judge(status: &[u8], now_mono_ms: u64, boot_id: &str) -> Observed {
    let v = match heartbeat(status, now_mono_ms, boot_id) {
        Ok(v) => v,
        Err(why) => return Observed::unknown(why),
    };
    if v.get("safety_feed").is_none_or(|f| f.is_null()) {
        return Observed::unknown(
            "agentd has no live safety feed (a configured static state is not a reading)",
        );
    }
    let raw_state = v.get("safety_state").cloned().unwrap_or_default();
    let Ok(state) = serde_json::from_value::<SafetyState>(raw_state) else {
        return Observed::unknown("agentd status has no valid safety_state");
    };
    Observed {
        state,
        why: None,
        agentd_health: v
            .get("state")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
    }
}

/// The boot id of this boot (trimmed), or empty.
pub fn boot_id(path: &Path) -> String {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s.len() <= 64 && !s.chars().any(char::is_control))
        .unwrap_or_default()
}

/// The uids agentd's status is accepted from: root and `agentd_user`.
pub fn trusted_uids(cfg: &SafetyCfg) -> Vec<u32> {
    let mut v = vec![0];
    let db = robodr_release::fsio::read_capped(&cfg.passwd, crate::users::MAX_PASSWD_BYTES)
        .ok()
        .and_then(|b| String::from_utf8(b).ok());
    if let Some(ids) = db.and_then(|t| crate::users::lookup(&t, &cfg.agentd_user).ok()) {
        if ids.uid != 0 {
            v.push(ids.uid);
        }
    }
    v
}

/// How long a status read may take (connect, read).
pub const STATUS_TIMEOUT: Duration = Duration::from_secs(2);

fn bounded(mut r: impl Read) -> Result<Vec<u8>, String> {
    let mut b = Vec::new();
    r.by_ref()
        .take(MAX_STATUS_BYTES as u64 + 1)
        .read_to_end(&mut b)
        .map_err(|e| format!("agentd status unreadable: {e}"))?;
    if b.len() > MAX_STATUS_BYTES {
        return Err("agentd status too large".into());
    }
    Ok(b)
}

fn writer_ok(md: &std::fs::Metadata, trusted: &[u32]) -> bool {
    trusted.contains(&md.uid()) && md.mode() & 0o022 == 0
}

/// Read agentd's status bytes from `path` (socket or file), accepted only
/// from a writer in `trusted` (see the module docs).
pub fn read_status(path: &Path, trusted: &[u32]) -> Result<Vec<u8>, String> {
    let md = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err("no agentd status (agentd not running?)".into())
        }
        Err(e) => return Err(format!("agentd status unreadable: {e}")),
    };
    if md.file_type().is_socket() {
        let s = std::os::unix::net::UnixStream::connect(path)
            .map_err(|e| format!("agentd status socket: {e}"))?;
        s.set_read_timeout(Some(STATUS_TIMEOUT))
            .map_err(|e| format!("agentd status socket: {e}"))?;
        let uid = robodr_agentd::host::peer_uid(&s)
            .map_err(|e| format!("agentd status socket: peer credentials unreadable: {e}"))?;
        if !trusted.contains(&uid) {
            return Err(format!(
                "agentd status socket is served by uid {uid}, not by agentd's user or root \
                 (accepted: {trusted:?})"
            ));
        }
        return bounded(s);
    }
    if !md.file_type().is_file() {
        return Err("agentd status is neither a socket nor a regular file".into());
    }
    let (Some(dir), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str())) else {
        return Err("agentd status: bad path".into());
    };
    let d = crate::fdio::open_dir(dir).map_err(|e| format!("agentd status directory: {e}"))?;
    let dmd = d
        .metadata()
        .map_err(|e| format!("agentd status directory: {e}"))?;
    if !writer_ok(&dmd, trusted) {
        return Err(format!(
            "agentd status directory {} (uid {}, mode {:o}) can be written by others than \
             agentd's user or root",
            dir.display(),
            dmd.uid(),
            dmd.mode() & 0o7777
        ));
    }
    let f = crate::fdio::open_read_at(&d, name).map_err(|e| format!("agentd status: {e}"))?;
    let fmd = f.metadata().map_err(|e| format!("agentd status: {e}"))?;
    if !fmd.is_file() || !writer_ok(&fmd, trusted) {
        return Err(format!(
            "agentd status (uid {}, mode {:o}) was not written by agentd's user or root",
            fmd.uid(),
            fmd.mode() & 0o7777
        ));
    }
    bounded(f)
}

/// Read agentd's status now: the gate's view and whether agentd's
/// heartbeat is fresh (`Err(why)` if not), from one read.
pub fn observe_with_heartbeat(cfg: &SafetyCfg) -> (Observed, Result<(), String>) {
    let bytes = match read_status(&cfg.agentd_status, &trusted_uids(cfg)) {
        Ok(b) => b,
        Err(why) => return (Observed::unknown(why.clone()), Err(why)),
    };
    let now = robodr_agentd::notify::monotonic_ms();
    let boot = boot_id(&cfg.boot_id);
    let hb = heartbeat(&bytes, now, &boot).map(|_| ());
    (judge(&bytes, now, &boot), hb)
}

/// Read agentd's status now.
pub fn observe(cfg: &SafetyCfg) -> Observed {
    let bytes = match read_status(&cfg.agentd_status, &trusted_uids(cfg)) {
        Ok(b) => b,
        Err(why) => return Observed::unknown(why),
    };
    judge(
        &bytes,
        robodr_agentd::notify::monotonic_ms(),
        &boot_id(&cfg.boot_id),
    )
}

#[cfg(test)]
pub(crate) mod test_support {
    /// A fresh agentd status claiming `state`, as agentd writes it.
    pub fn status(state: &str, mono: u64, boot: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "safety_state": state,
            "safety_feed": {"state": state, "sources": [], "stats": {}},
            "kind": "robodr.agentd_status",
            "robot_id": "ugv-07",
            "updated_mono_ms": mono,
            "boot_id": boot,
            "stale_after_ms": 4000,
            "running": true,
            "state": "ok"
        }))
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::status;
    use super::*;

    #[test]
    fn the_status_is_taken_only_from_agentd_or_root() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("deliverd-safety-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let me = crate::users::effective_uid().unwrap();
        let f = d.join("status.json");
        std::fs::write(&f, b"{}").unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(read_status(&f, &[me]).unwrap(), b"{}");
        assert!(read_status(&f, &[me + 1]).is_err(), "another owner");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert!(read_status(&f, &[me]).is_err(), "group-writable file");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(read_status(&f, &[me]).is_err(), "group-writable directory");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        let l = d.join("link.json");
        std::os::unix::fs::symlink(&f, &l).unwrap();
        assert!(read_status(&l, &[me]).is_err(), "symlink");
        // A socket: the serving process's uid decides.
        let sp = d.join("status.sock");
        let srv = std::os::unix::net::UnixListener::bind(&sp).unwrap();
        let t = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut c, _) = srv.accept().unwrap();
                let _ = std::io::Write::write_all(&mut c, b"{\"x\":1}");
            }
        });
        assert_eq!(read_status(&sp, &[me]).unwrap(), b"{\"x\":1}");
        assert!(read_status(&sp, &[me + 1])
            .unwrap_err()
            .contains("served by uid"));
        t.join().unwrap();
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn only_idle_and_safe_state_allow_installs() {
        for (s, ok) in [
            ("idle", true),
            ("safe_state_active", true),
            ("moving_slow", false),
            ("moving_fast", false),
            ("collaborative_human_nearby", false),
            ("estop_active", false),
            ("unknown", false),
        ] {
            let o = judge(&status(s, 1000, "b"), 1500, "b");
            assert_eq!(state_name(o.state), s);
            assert_eq!(o.allows_install(), ok, "{s}");
        }
    }

    #[test]
    fn anything_doubtful_is_unknown() {
        let base: serde_json::Value = serde_json::from_slice(&status("idle", 5000, "b")).unwrap();
        assert_eq!(
            judge(&serde_json::to_vec(&base).unwrap(), 5500, "b").state,
            SafetyState::Idle
        );
        type M = fn(&mut serde_json::Value);
        let cases: Vec<(&str, u64, M)> = vec![
            ("not running", 5500, |v| v["running"] = false.into()),
            ("other boot", 5500, |v| v["boot_id"] = "a".into()),
            ("stale", 5500, |v| v["updated_mono_ms"] = 100.into()),
            ("future", 5500, |v| v["updated_mono_ms"] = 99_999.into()),
            ("no feed", 5500, |v| {
                v.as_object_mut().unwrap().remove("safety_feed");
            }),
            ("null feed", 5500, |v| {
                v["safety_feed"] = serde_json::Value::Null
            }),
            ("bad state", 5500, |v| v["safety_state"] = "parked".into()),
            ("no freshness", 5500, |v| {
                v.as_object_mut().unwrap().remove("stale_after_ms");
            }),
            ("huge window is capped", MAX_STALE_MS + 1, |v| {
                v["stale_after_ms"] = u64::MAX.into();
                v["updated_mono_ms"] = 0.into();
            }),
            ("wrong kind", 5500, |v| v["kind"] = "x".into()),
        ];
        for (what, now, m) in cases {
            let mut v = base.clone();
            m(&mut v);
            let o = judge(&serde_json::to_vec(&v).unwrap(), now, "b");
            assert_eq!(o.state, SafetyState::Unknown, "{what}");
            assert!(o.why.is_some(), "{what}");
            assert!(!o.allows_install());
        }
        assert_eq!(judge(b"{", 1, "b").state, SafetyState::Unknown);
        assert_eq!(
            judge(&vec![b' '; MAX_STATUS_BYTES + 1], 1, "b").state,
            SafetyState::Unknown
        );
        assert_eq!(
            judge(&status("idle", 1, ""), 1, "").state,
            SafetyState::Unknown
        );
    }
}
