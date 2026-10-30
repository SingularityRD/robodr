//! The two binaries, run as processes.

mod common;

use common::*;
use robodr_agent::FindingOutput;
use robodr_agentd::spool::Spool;
use robodr_blackbox::KeyFile;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

const EXPORT: &str = env!("CARGO_BIN_EXE_robodr-spool-export");
const PUBLISH: &str = env!("CARGO_BIN_EXE_robodr-kafka-publish");

#[test]
fn usage_errors_exit_2() {
    for bin in [EXPORT, PUBLISH] {
        let o = Command::new(bin).arg("--bogus").output().unwrap();
        assert_eq!(o.status.code(), Some(2), "{bin}");
        assert!(String::from_utf8_lossy(&o.stderr).contains("usage"));
        let o = Command::new(bin).output().unwrap();
        assert_eq!(o.status.code(), Some(2), "{bin}");
    }
    let o = Command::new(PUBLISH)
        .args([
            "--bootstrap",
            "x:1",
            "--allow-plaintext",
            "--state-dir",
            "/tmp/x",
        ])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("--diode-out"));
}

#[test]
fn export_then_publish_spool_once() {
    let t = TempDir::new("cli");
    let spool = t.path().join("spool");
    let mut s = Spool::open(&spool, 1 << 30, 1000).unwrap();
    for i in 0..3 {
        let rec = robodr_ocsf::record(&finding(i), None).unwrap();
        s.write(
            &FindingOutput {
                topic: rec.topic,
                key: rec.key,
                partition: rec.partition,
                value: rec.value,
                headers: rec
                    .headers
                    .into_iter()
                    .map(|(k, v)| (k.into(), v))
                    .collect(),
            },
            robodr_agentd::SpoolClass::Normal,
        )
        .unwrap();
    }
    drop(s);
    let key = t.path().join("diode.key");
    let kf = KeyFile::ed25519_from_seed(&[9; 32], Some("diode-ugv-007")).unwrap();
    fs::write(&key, kf.to_json()).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let outbox = t.path().join("outbox");
    fs::create_dir_all(&outbox).unwrap();
    let o = Command::new(EXPORT)
        .args(["--spool".as_ref(), spool.as_os_str()])
        .args(["--outbox".as_ref(), outbox.as_os_str()])
        .args(["--state".as_ref(), t.path().join("x.json").as_os_str()])
        .args(["--pack-state".as_ref(), t.path().join("p.json").as_os_str()])
        .args(["--unit", UNIT, "--once"])
        .args(["--key-file".as_ref(), key.as_os_str()])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let report: serde_json::Value =
        serde_json::from_slice(o.stdout.split(|b| *b == b'\n').next().unwrap()).unwrap();
    assert_eq!(report["exported"], 3);
    assert_eq!(fs::read_dir(spool.join("acked")).unwrap().count(), 3);

    // Publishing the (now acked) spool finds nothing; put records back in
    // ready/ to publish them as a connected site would.
    for e in fs::read_dir(spool.join("acked")).unwrap() {
        let e = e.unwrap();
        fs::rename(e.path(), spool.join("ready").join(e.file_name())).unwrap();
    }
    let c = Cluster::start(1, 2);
    let o = Command::new(PUBLISH)
        .args([
            "--bootstrap",
            &c.bootstrap()[0],
            "--allow-plaintext",
            "--once",
        ])
        .args(["--spool".as_ref(), spool.as_os_str()])
        .args(["--state-dir".as_ref(), t.path().join("soc").as_os_str()])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(c.total(), 3);

    // Unreachable broker with --once: runtime failure, exit 1, nothing acked.
    let first = fs::read_dir(spool.join("acked"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    fs::rename(first.path(), spool.join("ready").join(first.file_name())).unwrap();
    let o = Command::new(PUBLISH)
        .args([
            "--bootstrap",
            "127.0.0.1:1",
            "--allow-plaintext",
            "--once",
            "--retries",
            "1",
        ])
        .args(["--spool".as_ref(), spool.as_os_str()])
        .args(["--state-dir".as_ref(), t.path().join("soc2").as_os_str()])
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(fs::read_dir(spool.join("ready")).unwrap().count(), 1);
}

/// `--version` prints `<name> <version>` and `--help` the usage, both on
/// stdout with exit 0 (the release .deb smoke test runs both on every
/// shipped binary); misuse of either stays a usage error (exit 2).
#[test]
fn version_and_help_exit_0() {
    for (name, exe) in [
        (
            "robodr-spool-export",
            env!("CARGO_BIN_EXE_robodr-spool-export"),
        ),
        (
            "robodr-kafka-publish",
            env!("CARGO_BIN_EXE_robodr-kafka-publish"),
        ),
    ] {
        let o = std::process::Command::new(exe)
            .arg("--version")
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(0), "{name} --version");
        assert_eq!(
            String::from_utf8_lossy(&o.stdout),
            format!("{name} {}\n", env!("CARGO_PKG_VERSION")),
            "{name} --version"
        );
        let o = std::process::Command::new(exe)
            .arg("--help")
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(0), "{name} --help");
        assert!(
            String::from_utf8_lossy(&o.stdout).contains(name),
            "{name} --help prints the usage on stdout"
        );
        for bad in [&["--version", "--bogus"][..], &["--bogus"][..]] {
            let o = std::process::Command::new(exe).args(bad).output().unwrap();
            assert_eq!(o.status.code(), Some(2), "{name} {bad:?}");
            assert!(o.stdout.is_empty(), "{name} {bad:?}");
        }
    }
}
