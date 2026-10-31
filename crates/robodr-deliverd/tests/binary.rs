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
    std::fs::remove_file(robodr_release::ops::anchor_chain_path(&u.cfg.anchor_path())).unwrap();
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

/// Start a copy of the agent binary at `exe` (retrying ETXTBSY: another
/// test may fork while the copy's descriptor is still open).
fn spawn_copy(exe: &std::path::Path, args: &[&str]) -> std::process::Child {
    for _ in 0..50 {
        match Command::new(exe)
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            Ok(c) => return c,
            Err(e) if e.raw_os_error() == Some(26) => {
                std::thread::sleep(std::time::Duration::from_millis(100))
            }
            Err(e) => panic!("{}: {e}", exe.display()),
        }
    }
    panic!("{}: text file busy", exe.display());
}

fn wait_exit(c: &mut std::process::Child, secs: u64) -> Option<std::process::ExitStatus> {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    while std::time::Instant::now() < until {
        if let Some(st) = c.try_wait().unwrap() {
            return Some(st);
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    None
}

/// T52: RoboDR's own package upgraded by this agent replaces its binary
/// while it runs (the postinst leaves the restart to it: restarting the
/// unit from inside its own dpkg run would kill dpkg). `run` notices
/// between passes and exits 3, which the unit restarts on
/// (RestartForceExitStatus=3); without a replacement it runs until
/// SIGTERM and exits 0.
#[test]
fn run_exits_3_after_its_own_binary_is_replaced() {
    let u = Unit::new("bin-replaced");
    let cfgp = u.dir().join("deliverd.json");
    std::fs::write(&cfgp, serde_json::to_vec_pretty(&u.cfg).unwrap()).unwrap();
    let c = cfgp.to_str().unwrap();
    let exe = u.dir().join("robodr-deliverd");
    std::fs::copy(env!("CARGO_BIN_EXE_robodr-deliverd"), &exe).unwrap();

    // Not replaced: runs until SIGTERM, then exits 0.
    let mut child = spawn_copy(&exe, &["run", "--config", c]);
    std::thread::sleep(std::time::Duration::from_millis(1500));
    assert!(child.try_wait().unwrap().is_none(), "run stopped by itself");
    let pid = child.id().to_string();
    assert!(Command::new("kill")
        .args(["-TERM", &pid])
        .status()
        .unwrap()
        .success());
    let st = wait_exit(&mut child, 30).expect("run ignored SIGTERM");
    assert_eq!(st.code(), Some(0), "{st:?}");

    // Replaced as dpkg does it (a new file renamed over the path).
    let mut child = spawn_copy(&exe, &["run", "--config", c]);
    std::thread::sleep(std::time::Duration::from_millis(1500));
    assert!(child.try_wait().unwrap().is_none(), "run stopped by itself");
    let new = u.dir().join("robodr-deliverd.dpkg-new");
    std::fs::copy(env!("CARGO_BIN_EXE_robodr-deliverd"), &new).unwrap();
    std::fs::rename(&new, &exe).unwrap();
    let Some(st) = wait_exit(&mut child, 30) else {
        let _ = child.kill();
        panic!("run kept running on a replaced binary");
    };
    let mut err = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut err).unwrap();
    assert_eq!(st.code(), Some(3), "{st:?} {err}");
    assert!(err.contains("replaced on disk"), "{err}");
}

/// `self-check` (run by the old agent on a binary that replaced it, before
/// that install commits): exit 0 when the configuration, the state file
/// and the keys load; 1 when one of them does not; nothing is written.
#[test]
fn self_check_loads_what_run_needs_without_writing() {
    let u = Unit::new("bin-self-check");
    let cfgp = u.dir().join("deliverd.json");
    std::fs::write(&cfgp, serde_json::to_vec_pretty(&u.cfg).unwrap()).unwrap();
    let c = cfgp.to_str().unwrap();
    let o = deliverd(&["self-check", "--config", c]);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(String::from_utf8_lossy(&o.stdout).contains("self-check ok"));
    // Read only: no journal opened, no state written.
    assert!(!u.cfg.state_path().exists());
    assert!(u.cfg.blackbox.dir.read_dir().unwrap().next().is_none());

    // A state file it cannot parse.
    std::fs::write(u.cfg.state_path(), b"{not json").unwrap();
    let o = deliverd(&["self-check", "--config", c]);
    assert_eq!(o.status.code(), Some(1));
    std::fs::remove_file(u.cfg.state_path()).unwrap();

    // The black-box key unreadable.
    std::fs::remove_file(&u.cfg.blackbox.key).unwrap();
    let o = deliverd(&["self-check", "--config", c]);
    assert_eq!(o.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("black-box key"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
}

/// WP14 (MEDIUM #3, narrowed): `self-check` refuses what would stop
/// `Engine::open` or lock the start, not only an unparsable state or key:
/// a state file of another unit, a missing or older high-water record
/// next to a journal with records, and a trust anchor that does not load.
/// After a real start and stop it passes, and it still writes nothing.
#[test]
fn self_check_refuses_what_would_stop_or_lock_the_start() {
    let u = Unit::new("bin-self-check-open");
    let cfgp = u.dir().join("deliverd.json");
    std::fs::write(&cfgp, serde_json::to_vec_pretty(&u.cfg).unwrap()).unwrap();
    let c = cfgp.to_str().unwrap();
    u.open().close().unwrap();
    let check = || {
        let o = deliverd(&["self-check", "--config", c]);
        (
            o.status.code(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        )
    };
    let (code, err) = check();
    assert_eq!(code, Some(0), "{err}");
    let listing = |d: &std::path::Path| -> Vec<(std::ffi::OsString, u64)> {
        let mut v: Vec<_> = std::fs::read_dir(d)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (e.file_name(), e.metadata().unwrap().len())
            })
            .collect();
        v.sort();
        v
    };
    let bb = listing(&u.cfg.blackbox.dir);
    let st = std::fs::read(u.cfg.state_path()).unwrap();
    let (code, _) = check();
    assert_eq!(code, Some(0));
    assert_eq!(listing(&u.cfg.blackbox.dir), bb);
    assert_eq!(std::fs::read(u.cfg.state_path()).unwrap(), st);

    // A state file of another unit: Engine::open refuses it.
    let mut v: serde_json::Value = serde_json::from_slice(&st).unwrap();
    v["unit"] = "another-unit".into();
    std::fs::write(u.cfg.state_path(), serde_json::to_vec(&v).unwrap()).unwrap();
    let (code, err) = check();
    assert_eq!(code, Some(1), "{err}");
    assert!(err.contains("state of unit another-unit"), "{err}");
    std::fs::write(u.cfg.state_path(), &st).unwrap();

    // The high-water record gone while the journal has records: the start
    // would be locked.
    let hw = robodr_deliverd::highwater::path(&u.cfg.blackbox.dir);
    let hw_bytes = std::fs::read(&hw).unwrap();
    std::fs::remove_file(&hw).unwrap();
    let (code, err) = check();
    assert_eq!(code, Some(1), "{err}");
    assert!(err.contains("the start would be locked"), "{err}");
    std::fs::write(&hw, &hw_bytes).unwrap();
    assert_eq!(check().0, Some(0));

    // A damaged mirror of the anchor record: the record is what counts,
    // and self-check does not repair the mirror (it writes nothing).
    let anchor = u.cfg.anchor_path();
    let a = std::fs::read(&anchor).unwrap();
    std::fs::write(&anchor, b"{}").unwrap();
    let (code, err) = check();
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(std::fs::read(&anchor).unwrap(), b"{}");
    std::fs::write(&anchor, &a).unwrap();
    // An anchor record that does not load.
    let chain = robodr_release::ops::anchor_chain_path(&anchor);
    let ch = std::fs::read(&chain).unwrap();
    std::fs::write(&chain, b"{}").unwrap();
    let (code, err) = check();
    assert_eq!(code, Some(1), "{err}");
    assert!(err.contains("trust anchor"), "{err}");
    std::fs::write(&chain, &ch).unwrap();
    assert_eq!(check().0, Some(0));
}
