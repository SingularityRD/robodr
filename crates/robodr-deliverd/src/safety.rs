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
//! PLC gateway defers installs too. Trust: `status.json` is written by the
//! `robodr` user; whoever controls that user can claim `idle` to agentd's
//! responder and to this gate alike (documented in OPERATIONS.md).

use crate::config::SafetyCfg;
use robodr_responder::SafetyState;
use std::path::Path;

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

/// Judge `status.json` bytes read at `now_mono_ms` on boot `boot_id`.
pub fn judge(status: &[u8], now_mono_ms: u64, boot_id: &str) -> Observed {
    if status.len() > MAX_STATUS_BYTES {
        return Observed::unknown("agentd status too large");
    }
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(status) else {
        return Observed::unknown("agentd status is not JSON");
    };
    if v["kind"].as_str() != Some("robodr.agentd_status") {
        return Observed::unknown("not an agentd status");
    }
    if v["running"].as_bool() != Some(true) {
        return Observed::unknown("agentd is not running");
    }
    if boot_id.is_empty() || v["boot_id"].as_str() != Some(boot_id) {
        return Observed::unknown("agentd status is from another boot");
    }
    let (Some(at), Some(stale)) = (v["updated_mono_ms"].as_u64(), v["stale_after_ms"].as_u64())
    else {
        return Observed::unknown("agentd status has no freshness fields");
    };
    if at > now_mono_ms || now_mono_ms - at > stale.min(MAX_STALE_MS) {
        return Observed::unknown("agentd status is stale");
    }
    if v.get("safety_feed").is_none_or(|f| f.is_null()) {
        return Observed::unknown(
            "agentd has no live safety feed (a configured static state is not a reading)",
        );
    }
    let Ok(state) = serde_json::from_value::<SafetyState>(v["safety_state"].clone()) else {
        return Observed::unknown("agentd status has no valid safety_state");
    };
    Observed {
        state,
        why: None,
        agentd_health: v["state"].as_str().map(str::to_string),
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

/// Read agentd's status now.
pub fn observe(cfg: &SafetyCfg) -> Observed {
    let bytes = match crate::fsx::read_optional(&cfg.agentd_status, MAX_STATUS_BYTES) {
        Ok(Some(b)) => b,
        Ok(None) => return Observed::unknown("no agentd status (agentd not running?)"),
        Err(e) => return Observed::unknown(format!("agentd status unreadable: {e}")),
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
