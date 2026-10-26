//! Harness: the configuration and the state file of `robodr-deliverd`
//! (`robodr_deliverd::config::Config::parse`,
//! `robodr_deliverd::state::State::parse`).
//!
//! Input: one selector byte (even: configuration, odd: state) and the
//! document bytes. Invariants beyond "no panic":
//!
//! * an accepted document re-serialises to bytes that parse to the same
//!   value (no state the agent writes is one it would refuse to read);
//! * an accepted configuration's paths are normalised absolute paths and
//!   its install roots, state and media directories are disjoint;
//! * on an accepted state, `raise_floor` never lowers a floor.
//!
//! Shared via `#[path]` with `crates/robodr-deliverd/tests/fuzz_smoke.rs`.
#![allow(dead_code)]

use robodr_deliverd::config::{is_clean_abs, Config};
use robodr_deliverd::state::State;

pub fn run(data: &[u8]) {
    let Some((&sel, doc)) = data.split_first() else {
        return;
    };
    if sel % 2 == 0 {
        if let Ok(c) = Config::parse(doc) {
            let again = serde_json::to_vec(&c).expect("serialise config");
            let c2 = Config::parse(&again).expect("an accepted config re-parses");
            assert_eq!(c, c2);
            for p in [
                &c.state_dir,
                &c.media_dir,
                &c.install.files_root,
                &c.install.config_root,
            ] {
                assert!(is_clean_abs(p));
            }
            assert!(!c.state_dir.starts_with(&c.install.config_root));
            assert!(!c.install.config_root.starts_with(&c.state_dir));
            assert!(!c.media_dir.starts_with(&c.state_dir));
            assert!(c.is_denied_user("root"));
        }
    } else if let Ok(mut s) = State::parse(doc) {
        let again = serde_json::to_vec(&s).expect("serialise state");
        let s2 = State::parse(&again).expect("an accepted state re-parses");
        assert_eq!(s, s2);
        let names: Vec<String> = s.floors.keys().cloned().collect();
        for n in names {
            let before = s.floor(&n);
            s.raise_floor(&n, before.saturating_sub(1));
            assert_eq!(s.floor(&n), before);
            s.raise_floor(&n, before.saturating_add(1));
            assert!(s.floor(&n) > before || before == u64::MAX);
        }
    }
}

fn config_seed() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "format": "robodr-deliverd-config/1",
        "unit": {"id": "ugv-07", "site": "site-a", "model": "ugv-x1", "platform": "ugv-x1",
                 "arch": "arm64", "hw": "rev-b", "ring": "ring-1", "groups": ["north"]},
        "trust": {"roots": [format!("sha256:{}", "ab".repeat(32)), format!("sha256:{}", "cd".repeat(32))],
                  "clock": "untrusted"},
        "state_dir": "/var/lib/robodr/deliverd",
        "media_dir": "/var/lib/robodr/deliverd-media",
        "install": {"files_root": "/opt/robodr-delivered", "config_root": "/etc/robodr-delivered",
                    "rules_active": "/etc/robodr-delivered-rules",
                    "rules_reload": ["/usr/bin/systemctl", "try-restart", "robodr-pulsard.service"],
                    "rules_validator": null, "dpkg_root": null, "keep_versions": 2},
        "health": {"probe_uid_min": 1000, "probe_uid_max": 59999, "deny_users": ["operator"]},
        "findings": {"stale_grace_s": 3600, "deferral_medium_after": 5},
        "interval_ms": 5000
    }))
    .expect("seed")
}

fn state_seed() -> Vec<u8> {
    let ver = |s: u64, d: &str| {
        serde_json::json!({"serial": s, "digest": d.repeat(32), "kind": "files",
        "deb": null, "probe_users": {"probe": [1500, 1500]}})
    };
    serde_json::to_vec(&serde_json::json!({
        "format": "robodr-deliverd-state/1",
        "site": "site-a",
        "unit": "ugv-07",
        "time_floor": 1_790_000_000u64,
        "last_deployment": {"seq": 3, "digest": "cd".repeat(32), "expires_at": 1_792_000_000u64},
        "chains": [{"format": "robodr-bundle-chain/1", "site": "site-a", "programme": "ugv-x1",
                    "bundle_seq": 2, "bundle_hash": "ef".repeat(32), "trust_version": 1,
                    "trust_digest": "01".repeat(32)}],
        "floors": {"nav-stack": 2},
        "installed": {"nav-stack": {"ver": ver(2, "aa"), "healthy": true}},
        "kept": {"nav-stack": [ver(1, "bb")]},
        "deployment": {"id": "dep-0003", "seq": 3, "digest": "cd".repeat(32), "pack": "3-cdcdcdcdcdcdcdcd",
                       "ring": "ring-1", "expires_at": 1_792_000_000u64,
                       "maintenance_window": {"days": ["mon"], "start_minute": 60, "duration_minutes": 120},
                       "items": [{"name": "nav-stack", "serial": 3, "digest": "dd".repeat(32),
                                  "status": "pending", "deferrals": 2,
                                  "last_deferral": "safety_state:moving_slow", "ver": ver(3, "dd")}]},
        "txn": {"name": "nav-stack", "from": ver(2, "aa"), "to": ver(3, "dd"), "phase": "health", "failure": null},
        "stale": null,
        "seen_media": {"pack-0003": "cd".repeat(32)}
    }))
    .expect("seed")
}

/// The seed corpus (file name, bytes).
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    let mut c = vec![0u8];
    c.extend(config_seed());
    let mut s = vec![1u8];
    s.extend(state_seed());
    vec![("seed-config.bin", c), ("seed-state.bin", s)]
}
