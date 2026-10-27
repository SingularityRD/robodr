//! The two binaries: exit codes, help, enrolment (`init-anchor`), one pass
//! (`once`), `status`, and the replay helper's `--check`.

mod common;

use common::*;
use std::process::Command;

fn deliverd(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_robodr-deliverd"))
        .args(args)
        .output()
        .unwrap()
}

fn replay(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_robodr-safety-replay"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn version_help_and_usage_errors() {
    let o = deliverd(&["--version"]);
    assert_eq!(o.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&o.stdout).starts_with("robodr-deliverd "));
    assert_eq!(deliverd(&["--help"]).status.code(), Some(0));
    assert_eq!(deliverd(&["-h"]).status.code(), Some(0));
    // Help next to anything else is a usage error, never success.
    assert_eq!(
        deliverd(&["once", "--config", "/x", "-h"]).status.code(),
        Some(2)
    );
    assert_eq!(deliverd(&[]).status.code(), Some(2));
    assert_eq!(deliverd(&["install"]).status.code(), Some(2));
    assert_eq!(deliverd(&["once"]).status.code(), Some(2));
    assert_eq!(
        deliverd(&["once", "--config", "/nonexistent.json"])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(deliverd(&["once", "--confi", "/x"]).status.code(), Some(2));
    assert_eq!(replay(&["--version"]).status.code(), Some(0));
    assert_eq!(replay(&["--help"]).status.code(), Some(0));
    assert_eq!(replay(&["--file"]).status.code(), Some(2));
}

#[test]
fn enrol_check_run_once_and_status() {
    let u = Unit::new("bin");
    // A unit configuration file, without the anchor Unit::new created.
    std::fs::remove_file(u.cfg.anchor_path()).unwrap();
    std::fs::remove_file(robodr_release::ops::sig_path(&u.cfg.anchor_path())).unwrap();
    let cfgp = u.dir().join("deliverd.json");
    std::fs::write(&cfgp, serde_json::to_vec_pretty(&u.cfg).unwrap()).unwrap();
    let c = cfgp.to_str().unwrap();
    let o = deliverd(&["check-config", "--config", c]);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    // A config with an unknown member is a usage error.
    let bad = u.dir().join("bad.json");
    let mut v = serde_json::to_value(&u.cfg).unwrap();
    v["surprise"] = 1.into();
    std::fs::write(&bad, serde_json::to_vec(&v).unwrap()).unwrap();
    assert_eq!(
        deliverd(&["check-config", "--config", bad.to_str().unwrap()])
            .status
            .code(),
        Some(2)
    );
    // The binary runs on the system clock: a trust file and a deployment
    // valid now.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut tf = trust_file(&u.keys);
    tf.issued_at = now - 3600;
    tf.expires_at = now + 90 * 86400;
    write_trust(&u.trust_path, &tf, &u.keys);
    // Before enrolment a pack is not imported (no anchor).
    let r = u.rpk(&files_spec(&u, "nav-stack", 1, true), &[("ok", b"v1")]);
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    let mut d = deployment(1, "ring-1", &[UNIT], &[r]);
    d.created_at = now - 60;
    d.not_before = now - 60;
    d.expires_at = now + 30 * 86400;
    pack(
        &u.cfg.media_dir,
        "p1",
        &u.trust_path,
        &d,
        &depot_and_ops(&u.keys),
        &[b],
    );
    u.safety("idle");
    let o = deliverd(&["once", "--config", c]);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert!(v["imported"].as_array().unwrap().is_empty(), "{v}");
    // Enrolment: the anchor from a trust file under the pinned roots. A
    // trust file of another site is refused.
    let mut tb = trust_file(&u.keys);
    tb.site = "site-b".into();
    let tbp = u.dir().join("b.json");
    write_trust(&tbp, &tb, &u.keys);
    assert_eq!(
        deliverd(&[
            "init-anchor",
            "--config",
            c,
            "--trust",
            tbp.to_str().unwrap()
        ])
        .status
        .code(),
        Some(1)
    );
    let o = deliverd(&[
        "init-anchor",
        "--config",
        c,
        "--trust",
        u.trust_path.to_str().unwrap(),
    ]);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["unit_ring"], "ring-1");
    // Never re-created.
    assert_eq!(
        deliverd(&[
            "init-anchor",
            "--config",
            c,
            "--trust",
            u.trust_path.to_str().unwrap()
        ])
        .status
        .code(),
        Some(1)
    );
    // Now the pass imports and installs (one switch per pass).
    let o = deliverd(&["once", "--config", c]);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["installed"], serde_json::json!(["nav-stack 1"]), "{v}");
    let o = deliverd(&["status", "--config", c]);
    assert_eq!(o.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["installed"]["nav-stack"]["ver"]["serial"], 1);
    assert_eq!(v["floors"]["nav-stack"], 1);
}

#[test]
fn replay_check_parses_without_sending() {
    let t = Tmp::new("replay-check");
    let f = t.path().join("r.jsonl");
    std::fs::write(
        &f,
        "{\"at_ms\":0,\"state\":\"moving_slow\"}\n{\"at_ms\":1000,\"state\":\"idle\"}\n",
    )
    .unwrap();
    let o = replay(&[
        "--check",
        "--file",
        f.to_str().unwrap(),
        "--repeat-ms",
        "100",
    ]);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(
        String::from_utf8_lossy(&o.stdout).contains("2 records, 11 lines"),
        "{}",
        String::from_utf8_lossy(&o.stdout)
    );
    std::fs::write(&f, "{\"at_ms\":0,\"state\":\"flying\"}\n").unwrap();
    assert_eq!(
        replay(&["--check", "--file", f.to_str().unwrap()])
            .status
            .code(),
        Some(1)
    );
    // No socket: an error, not a hang.
    std::fs::write(&f, "{\"at_ms\":0,\"state\":\"idle\"}\n").unwrap();
    let o = replay(&[
        "--file",
        f.to_str().unwrap(),
        "--socket",
        t.path().join("none.sock").to_str().unwrap(),
        "--connect-timeout-ms",
        "200",
    ]);
    assert_eq!(o.status.code(), Some(1));
}
