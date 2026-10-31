//! robodr-support-bundle: what is collected, what never is (keys,
//! credentials, evidence, findings), redaction, the manifest and
//! checksums, and the fail-closed scan.

mod common;

use common::*;
use robodr_ops::bundle::{collect, Options};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

const SECRET_SEED: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

/// A unit with keys, evidence, findings and secrets in its configuration.
fn unit(t: &Tmp) {
    t.put("/proc/sys/kernel/hostname", "robot-7\n");
    t.put("/proc/1/comm", "systemd\n");
    t.put("/etc/os-release", "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\n");
    mkdir_mode(&t.path("/etc/robodr/keys"), 0o700);
    let k = robodr_blackbox::KeyFile::generate("ed25519", None).unwrap();
    k.write_new(&t.path("/etc/robodr/keys/agentd-blackbox.key"))
        .unwrap();
    t.put(
        "/run/credentials/robodr-agentd.service/blackbox.key",
        &k.to_json(),
    );
    t.put(
        "/etc/robodr/kafka/client.key",
        "-----BEGIN PRIVATE KEY-----\nMIIkafka\n-----END PRIVATE KEY-----\n",
    );
    t.put(
        "/var/lib/robodr/blackbox/agentd/seg-000001.rbb",
        "EVIDENCE-RECORD-BYTES",
    );
    t.put(
        "/var/lib/robodr/spool/agentd/ready/rf1-1.json",
        "{\"finding\":\"FINDING-CONTENT\"}",
    );
    t.put(
        "/var/lib/robodr/spool/agentd/status.json",
        &std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/agentd-status.json"),
        )
        .unwrap(),
    );
    t.put("/var/lib/robodr/control-plane/agentd/journal", "CP-STATE");
    t.put(
        "/etc/robodr/agentd.json",
        "{\"robot\":{\"id\":\"robot-7\"},\"blackbox\":{\"key_file\":\"/run/credentials/robodr-agentd.service/blackbox.key\"},\
         \"control_plane\":{\"token\":\"tok-SECRET-1\"}}",
    );
    t.put(
        "/etc/robodr/kafka-publish.env",
        "ROBODR_KAFKA_BROKERS=b1:9093\nROBODR_KAFKA_SASL_PASSWORD=pw-SECRET-2\n",
    );
    t.put(
        "/etc/robodr/pulsar.toml",
        "[pulsar]\napi_token = \"tok-SECRET-3\"\nbtf_path = \"/etc/robodr/btf/vmlinux\"\n",
    );
    // A symlink in /etc/robodr pointing at a key: never followed.
    std::os::unix::fs::symlink(
        t.path("/etc/robodr/keys/agentd-blackbox.key"),
        t.path("/etc/robodr/sneaky.json"),
    )
    .unwrap();
}

fn runner() -> Fake {
    Fake::default()
        .with("systemctl --version", 0, "systemd 255\n")
        .with(
            "systemctl cat --no-pager robodr*",
            0,
            "# /usr/lib/systemd/system/robodr-uplink.service\n[Service]\nEnvironment=ROBODR_UPLINK_URL=https://soc \"ROBODR_UPLINK_TOKEN=tok-SECRET-4\"\n",
        )
        .with(
            "journalctl",
            0,
            "2026-10-31T00:00:00+0000 robot-7 robodr-uplink[9]: auth token: tok-SECRET-5\n\
             2026-10-31T00:00:01+0000 robot-7 robodr-agentd[8]: started\n",
        )
        .with("nft list ruleset", 0, "table inet robodr {\n}\n")
}

fn opts(t: &Tmp, out: &Path, tar: bool) -> Options {
    Options {
        root: t.0.clone(),
        out_dir: out.to_path_buf(),
        since: "-48h".into(),
        journal_lines: 100,
        journal: true,
        tar,
        now: UNIX_EPOCH + Duration::from_secs(1_793_408_003),
    }
}

fn all_bytes(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(all_bytes(&p));
        } else {
            out.push((p.clone(), std::fs::read(&p).unwrap()));
        }
    }
    out
}

#[test]
fn collects_diagnostics_but_never_keys_evidence_or_secrets() {
    let t = Tmp::new("bundle");
    unit(&t);
    let out = Tmp::new("bundle-out");
    let w = collect(&opts(&t, &out.0, false), &runner()).unwrap();
    assert!(
        w.path.ends_with("robodr-support-robot-7-20261031T005323Z"),
        "{:?}",
        w.path
    );
    assert_eq!(mode(&w.path), 0o700);
    let files = all_bytes(&w.path);
    let names: Vec<String> = files
        .iter()
        .map(|(p, _)| {
            p.strip_prefix(&w.path)
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    for want in [
        "manifest.json",
        "SHA256SUMS",
        "preflight.json",
        "metrics.prom",
        "units/cat.txt",
        "journal/robodr.txt",
        "network/nft-ruleset.txt",
        "status/var/lib/robodr/spool/agentd/status.json",
        "config/agentd.json",
        "config/kafka-publish.env",
        "config/pulsar.toml",
        "state/sizes.txt",
        "system/os-release",
    ] {
        assert!(names.iter().any(|n| n == want), "{want} missing: {names:?}");
    }
    assert!(!names.iter().any(|n| n.contains("sneaky")), "{names:?}");
    let k =
        robodr_blackbox::KeyFile::load(&t.path("/etc/robodr/keys/agentd-blackbox.key")).unwrap();
    let seed_hex = robodr_ops::hex(k.secret());
    for (p, b) in &files {
        assert_eq!(mode(p), 0o600, "{p:?}");
        let s = String::from_utf8_lossy(b);
        for forbidden in [
            "EVIDENCE-RECORD-BYTES",
            "FINDING-CONTENT",
            "CP-STATE",
            "MIIkafka",
            "tok-SECRET-1",
            "pw-SECRET-2",
            "tok-SECRET-3",
            "tok-SECRET-4",
            "tok-SECRET-5",
            seed_hex.as_str(),
            SECRET_SEED,
        ] {
            assert!(
                !s.contains(forbidden),
                "{forbidden} leaked into {p:?}:\n{s}"
            );
        }
        assert!(robodr_ops::redact::secret_markers(b).is_empty(), "{p:?}");
    }
    // Useful, non-secret content survives redaction.
    let cfg = std::fs::read_to_string(w.path.join("config/agentd.json")).unwrap();
    assert!(
        cfg.contains("/run/credentials/robodr-agentd.service/blackbox.key"),
        "{cfg}"
    );
    let env = std::fs::read_to_string(w.path.join("config/kafka-publish.env")).unwrap();
    assert!(env.contains("ROBODR_KAFKA_BROKERS=b1:9093"), "{env}");
    let sizes = std::fs::read_to_string(w.path.join("state/sizes.txt")).unwrap();
    assert!(sizes.contains("/var/lib/robodr/blackbox  1  21"), "{sizes}");
    assert!(!sizes.contains("seg-000001"), "{sizes}");
    // The manifest lists every file with its digest; SHA256SUMS verifies.
    let m: serde_json::Value =
        serde_json::from_slice(&std::fs::read(w.path.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(m["format"], "robodr-support-bundle/1");
    let listed = m["files"].as_array().unwrap();
    for e in listed {
        let b = std::fs::read(w.path.join(e["path"].as_str().unwrap())).unwrap();
        assert_eq!(e["sha256"], robodr_ops::sha256_hex(&b));
    }
    assert!(m["never_collected"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x == "/etc/robodr/keys"));
    assert!(m["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["item"] == "/etc/robodr/sneaky.json"));
    let o = std::process::Command::new("sha256sum")
        .args(["-c", "--quiet", "SHA256SUMS"])
        .current_dir(&w.path)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stdout));
}

#[test]
fn secret_material_that_survives_redaction_aborts_the_bundle() {
    let t = Tmp::new("bundle-abort");
    unit(&t);
    // Key material that redaction does not see (a JSON object *key* is
    // never rewritten): the final scan must catch it.
    t.put(
        "/var/lib/robodr/export/uplink/uplink-status.json",
        "{\"x\":{\"-----BEGIN OPENSSH PRIVATE KEY-----\":1}}",
    );
    let r = runner();
    let out = Tmp::new("bundle-abort-out");
    let e = collect(&opts(&t, &out.0, false), &r).unwrap_err();
    assert!(e.contains("secret key material"), "{e}");
    assert!(e.contains("uplink-status.json"), "{e}");
    // Nothing is left behind.
    assert_eq!(std::fs::read_dir(&out.0).unwrap().count(), 0);
}

#[test]
fn packed_bundle_is_private_and_reproducible_in_layout() {
    let t = Tmp::new("bundle-tar");
    unit(&t);
    let out = Tmp::new("bundle-tar-out");
    let w = collect(&opts(&t, &out.0, true), &runner()).unwrap();
    assert!(
        w.path.to_string_lossy().ends_with(".tar.gz"),
        "{:?}",
        w.path
    );
    assert_eq!(mode(&w.path), 0o600);
    assert!(w.sha256.is_some());
    // The directory is gone; only the archive remains.
    assert_eq!(std::fs::read_dir(&out.0).unwrap().count(), 1);
    let o = std::process::Command::new("tar")
        .arg("-tzvf")
        .arg(&w.path)
        .output()
        .unwrap();
    let list = String::from_utf8_lossy(&o.stdout);
    assert!(list.contains("manifest.json"), "{list}");
    assert!(list.lines().all(|l| l.contains("0/0")), "{list}");
}

#[test]
fn cli_refuses_bad_arguments() {
    let bin = env!("CARGO_BIN_EXE_robodr-support-bundle");
    for bad in [
        vec!["--out-dir", "relative"],
        vec!["--since", "--output=/etc/x"],
        vec!["--since", "$(id)"],
        vec!["--frob"],
        vec!["positional"],
    ] {
        let o = std::process::Command::new(bin).args(&bad).output().unwrap();
        assert_eq!(o.status.code(), Some(2), "{bad:?}");
    }
}
