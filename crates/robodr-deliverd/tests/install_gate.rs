//! The two commands `packaging/install-bundle.sh` relies on (WP8a, T9 and
//! T51): `safety-state` (the package-upgrade restart gate and the
//! post-install heartbeat) and `verify-minisign` (the built-in release
//! signature verifier).

mod common;

use common::*;
use std::process::{Command, Output};

fn deliverd(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_robodr-deliverd"))
        .args(args)
        .output()
        .unwrap()
}

/// Whether install-bundle.sh's heartbeat expression (healthy_now: the
/// `grep -Eq '...agentd_fresh...'` line, taken from the script itself)
/// matches `stdout`.
fn heartbeat_grep(stdout: &[u8]) -> bool {
    let script = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/install-bundle.sh"),
    )
    .unwrap();
    let line = script
        .lines()
        .find(|l| l.contains("grep -Eq '\"agentd_fresh\""))
        .expect("install-bundle.sh: the agentd_fresh grep line");
    let a = line.find("-Eq '").unwrap() + 5;
    let b = a + line[a..].find('\'').unwrap();
    let mut c = Command::new("grep")
        .args(["-Eq", &line[a..b]])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    c.stdin.take().unwrap().write_all(stdout).unwrap();
    c.wait().unwrap().success()
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout)
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&o.stderr)))
}

#[test]
fn safety_state_opens_only_for_idle_or_safe_state_from_a_fresh_agentd() {
    let u = Unit::new("gate");
    let cfgp = u.dir().join("deliverd.json");
    std::fs::write(&cfgp, serde_json::to_vec_pretty(&u.cfg).unwrap()).unwrap();
    let c = cfgp.to_str().unwrap();
    for (state, open) in [
        ("idle", true),
        ("safe_state_active", true),
        ("moving_slow", false),
        ("moving_fast", false),
        ("collaborative_human_nearby", false),
        ("estop_active", false),
        ("unknown", false),
    ] {
        u.safety(state);
        let o = deliverd(&["safety-state", "--config", c]);
        let v = json(&o);
        assert_eq!(
            o.status.code(),
            Some(if open { 0 } else { 1 }),
            "{state}: {v}"
        );
        assert_eq!(v["safety_state"], state);
        assert_eq!(v["allows_restart"], open);
        assert_eq!(v["agentd_fresh"], true, "{v}");
        // install-bundle.sh reads the heartbeat from this output with a
        // grep expression, not a JSON parser: it must match the real text.
        assert!(heartbeat_grep(&o.stdout), "{state}: {v}");
    }
    // agentd gone: closed, and no heartbeat.
    std::fs::remove_file(&u.cfg.safety.agentd_status).unwrap();
    let o = deliverd(&["safety-state", "--config", c]);
    let v = json(&o);
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(v["safety_state"], "unknown");
    assert_eq!(v["agentd_fresh"], false);
    assert!(!heartbeat_grep(&o.stdout), "{v}");
    // A status written by agentd but without a live feed: fresh heartbeat,
    // gate closed (a configured static state is not a reading).
    let st = serde_json::json!({
        "safety_state": "idle", "kind": "robodr.agentd_status",
        "updated_mono_ms": robodr_agentd::notify::monotonic_ms(),
        "boot_id": BOOT, "stale_after_ms": 600_000, "running": true, "state": "ok"
    });
    std::fs::write(&u.cfg.safety.agentd_status, st.to_string()).unwrap();
    let o = deliverd(&["safety-state", "--config", c]);
    let v = json(&o);
    assert_eq!(o.status.code(), Some(1), "{v}");
    assert_eq!(v["agentd_fresh"], true, "{v}");
    assert!(
        v["why"].as_str().unwrap().contains("no live safety feed"),
        "{v}"
    );
    // Usage errors.
    assert_eq!(
        deliverd(&["safety-state", "--config", "/nonexistent.json"])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        deliverd(&["safety-state", "--x", "y"]).status.code(),
        Some(2)
    );
}

/// Without a configuration the shipped defaults are used: in a test
/// environment there is no agentd socket, so the gate is closed.
#[test]
fn safety_state_defaults_to_closed_without_agentd() {
    let o = deliverd(&["safety-state"]);
    if std::path::Path::new("/run/robodr-agentd/status.sock").exists() {
        return;
    }
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(json(&o)["allows_restart"], false);
}

#[test]
fn verify_minisign_self_test_and_real_signatures() {
    let o = deliverd(&["verify-minisign", "--self-test"]);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    assert_eq!(
        deliverd(&["verify-minisign", "--self-test", "--file", "/x"])
            .status
            .code(),
        Some(1)
    );
    assert_eq!(deliverd(&["verify-minisign"]).status.code(), Some(1));
    let have = Command::new("minisign")
        .arg("-v")
        .output()
        .is_ok_and(|o| o.status.success());
    if !have {
        eprintln!("SKIPPED the real-signature half: no minisign");
        return;
    }
    let d = std::env::temp_dir().join(format!("deliverd-minisign-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let ms = |args: &[&str]| {
        let o = Command::new("minisign")
            .args(args)
            .current_dir(&d)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(o.status.success(), "{o:?}");
    };
    ms(&["-G", "-W", "-p", "k.pub", "-s", "k.sec"]);
    ms(&["-G", "-W", "-p", "o.pub", "-s", "o.sec"]);
    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(d.join("robodr-1.tar.gz"), &data).unwrap();
    ms(&[
        "-S",
        "-s",
        "k.sec",
        "-m",
        "robodr-1.tar.gz",
        "-t",
        "robodr 1 robodr-1.tar.gz",
    ]);
    let p = |n: &str| d.join(n).to_str().unwrap().to_string();
    let o = deliverd(&[
        "verify-minisign",
        "--pubkey",
        &p("k.pub"),
        "--file",
        &p("robodr-1.tar.gz"),
    ]);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    assert_eq!(
        String::from_utf8_lossy(&o.stdout).trim(),
        "robodr 1 robodr-1.tar.gz"
    );
    // Another key, other bytes, a symlinked file, a missing signature.
    let o = deliverd(&[
        "verify-minisign",
        "--pubkey",
        &p("o.pub"),
        "--file",
        &p("robodr-1.tar.gz"),
    ]);
    assert_eq!(o.status.code(), Some(1));
    std::os::unix::fs::symlink(d.join("robodr-1.tar.gz"), d.join("l.tar.gz")).unwrap();
    std::fs::copy(
        d.join("robodr-1.tar.gz.minisig"),
        d.join("l.tar.gz.minisig"),
    )
    .unwrap();
    let o = deliverd(&[
        "verify-minisign",
        "--pubkey",
        &p("k.pub"),
        "--file",
        &p("l.tar.gz"),
    ]);
    assert_eq!(
        o.status.code(),
        Some(1),
        "a symlink is not verified through"
    );
    let mut other = data.clone();
    other[1000] ^= 1;
    std::fs::write(d.join("robodr-1.tar.gz"), &other).unwrap();
    let o = deliverd(&[
        "verify-minisign",
        "--pubkey",
        &p("k.pub"),
        "--file",
        &p("robodr-1.tar.gz"),
    ]);
    assert_eq!(o.status.code(), Some(1));
    std::fs::write(d.join("x"), b"x").unwrap();
    let o = deliverd(&[
        "verify-minisign",
        "--pubkey",
        &p("k.pub"),
        "--file",
        &p("x"),
    ]);
    assert_eq!(o.status.code(), Some(1));
    let _ = std::fs::remove_dir_all(&d);
}
