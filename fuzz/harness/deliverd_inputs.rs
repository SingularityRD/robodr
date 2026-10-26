//! Harness: the untrusted inputs `robodr-deliverd` reads besides the signed
//! formats (those are `pkg_*`): agentd's `status.json` (the safety-state
//! gate, `robodr_deliverd::safety::judge`), the passwd-format user database
//! (`users::lookup`), recorded safety reports (`replay::parse` /
//! `replay::schedule`) and delivered Pulsar rule files
//! (`rules::check_file`).
//!
//! Input: one selector byte (`% 4`: status, passwd, recording, rules) and
//! the bytes. Invariants beyond "no panic":
//!
//! * the gate allows an install only for `idle` / `safe_state_active` read
//!   from a fresh status of this boot with a live feed; a reason is given
//!   exactly when the state is not agentd's reading (then `unknown`);
//! * an accepted user has the canonical decimal UID / GID of its line;
//! * a schedule is non-decreasing in time and bounded;
//! * accepted rules have 1..=MAX_RULES entries.
//!
//! Shared via `#[path]` with `crates/robodr-deliverd/tests/fuzz_smoke.rs`.
#![allow(dead_code)]

use robodr_deliverd::{replay, rules, safety, users};
use robodr_responder::SafetyState;

pub const NOW_MONO: u64 = 50_000;
pub const BOOT: &str = "fuzz-boot";

pub fn run(data: &[u8]) {
    let Some((&sel, doc)) = data.split_first() else {
        return;
    };
    match sel % 4 {
        0 => {
            let o = safety::judge(doc, NOW_MONO, BOOT);
            if o.allows_install() {
                assert!(o.why.is_none());
                assert!(matches!(
                    o.state,
                    SafetyState::Idle | SafetyState::SafeStateActive
                ));
                let v: serde_json::Value = serde_json::from_slice(doc).expect("json");
                assert_eq!(v["running"], true);
                assert_eq!(v["boot_id"], BOOT);
                assert!(v.get("safety_feed").is_some_and(|f| !f.is_null()));
            }
            if o.why.is_some() {
                assert_eq!(o.state, SafetyState::Unknown);
            }
        }
        1 => {
            if let Ok(text) = std::str::from_utf8(doc) {
                if let Ok(ids) = users::lookup(text, "probe") {
                    let (u, g) = (ids.uid.to_string(), ids.gid.to_string());
                    let n = text
                        .lines()
                        .filter(|l| {
                            let f: Vec<&str> = l.split(':').collect();
                            f.len() == 7 && f[0] == "probe" && f[2] == u && f[3] == g
                        })
                        .count();
                    assert_eq!(n, 1, "exactly one canonical line for the accepted user");
                }
            }
        }
        2 => {
            if let Ok(r) = replay::parse(doc) {
                assert!(!r.is_empty() && r.len() <= replay::MAX_RECORDS);
                if let Ok(s) = replay::schedule(&r, 50, 1000) {
                    assert!(s.windows(2).all(|w| w[0].0 <= w[1].0));
                    assert!(s.len() <= replay::MAX_SENDS);
                    assert!(s.len() >= r.len());
                }
            }
        }
        _ => {
            let mut names = std::collections::BTreeSet::new();
            if let Ok(n) = rules::check_file("fuzz.toml", doc, &mut names) {
                assert!((1..=rules::MAX_RULES).contains(&n));
                assert_eq!(names.len(), n);
            }
        }
    }
}

/// The seed corpus (file name, bytes).
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    let status = serde_json::to_vec(&serde_json::json!({
        "safety_state": "idle",
        "safety_feed": {"state": "idle", "sources": [{"name": "socket", "claim": "idle", "age_ms": 120}],
                        "stats": {"reports": 10}},
        "kind": "robodr.agentd_status", "robot_id": "ugv-07", "wall_ms": 1_790_000_000_000u64,
        "uptime_ms": 40_000, "updated_mono_ms": NOW_MONO - 200, "boot_id": BOOT,
        "stale_after_ms": 4000, "running": true, "state": "ok"
    }))
    .expect("seed");
    let mut moving = status.clone();
    let s = String::from_utf8(moving)
        .expect("utf8")
        .replace("\"idle\"", "\"moving_slow\"");
    moving = s.into_bytes();
    let passwd =
        b"root:x:0:0:root:/root:/bin/bash\nprobe:x:1500:1500::/nonexistent:/usr/sbin/nologin\n"
            .to_vec();
    let rec =
        b"{\"at_ms\":0,\"state\":\"moving_slow\"}\n{\"at_ms\":3000,\"state\":\"idle\"}\n".to_vec();
    let rules_toml = b"[[rules]]\nname = \"r\"\ntype = \"Exec\"\ncondition = 'payload.filename ENDS_WITH \"/nc\"'\ncategory = \"execution\"\nseverity = \"low\"\ndescription = \"d\"\n".to_vec();
    let tag = |t: u8, b: Vec<u8>| {
        let mut v = vec![t];
        v.extend(b);
        v
    };
    vec![
        ("seed-status-idle.bin", tag(0, status)),
        ("seed-status-moving.bin", tag(4, moving)),
        ("seed-passwd.bin", tag(1, passwd)),
        ("seed-replay.bin", tag(2, rec)),
        ("seed-rules.bin", tag(3, rules_toml)),
    ]
}
