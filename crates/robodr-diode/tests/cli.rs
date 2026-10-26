//! The two binaries end to end.

mod common;

use common::*;
use robodr_blackbox::KeyFile;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[test]
fn pack_and_unpack_binaries() {
    let site = Site::new("cli");
    // Low side: the unit's secret key. High side: only its public key.
    let keys = site.tmp.path().join("keys");
    fs::create_dir(&keys).unwrap();
    let key_file = keys.join("ugv-007.key");
    let kf = KeyFile::generate_ed25519(Some(KEY_ID)).unwrap();
    kf.write_new(&key_file).unwrap();
    let soc = site.tmp.path().join("soc-keys");
    fs::create_dir(&soc).unwrap();
    kf.to_public()
        .unwrap()
        .write_new(&soc.join("ugv-007.pub"))
        .unwrap();
    set_mode(&soc.join("ugv-007.pub"), 0o664);
    let keyring = soc.join("keyring");
    fs::write(
        &keyring,
        format!("# unit public-key-file\n{UNIT} ugv-007.pub\n"),
    )
    .unwrap();

    let input = site.tmp.path().join("findings.jsonl");
    let lines: Vec<String> = findings(3)
        .iter()
        .map(|f| robodr_ocsf::to_json(f).unwrap())
        .collect();
    fs::write(&input, format!("{}\n\n", lines.join("\n"))).unwrap();
    let bb = site.tmp.path().join("b.rbbx");
    fs::write(&bb, bundle(2)).unwrap();

    let pack = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_robodr-diode-pack"))
            .args(["--outbox", site.outbox.to_str().unwrap()])
            .args(["--state", site.pack_state.to_str().unwrap()])
            .args(["--unit", UNIT, "--key-id", KEY_ID])
            .args(["--key-file", key_file.to_str().unwrap()])
            .args(["--now-ms", &NOW.to_string()])
            .args(extra)
            .output()
            .unwrap()
    };
    let out = pack(&[
        "--findings",
        input.to_str().unwrap(),
        "--bundle",
        bb.to_str().unwrap(),
        "--max-findings",
        "2",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let published: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(published.as_array().unwrap().len(), 2);

    // Invalid input: nothing written, line reported.
    let bad = site.tmp.path().join("bad.jsonl");
    fs::write(&bad, format!("{}\n{{\"x\":1}}\n", lines[0])).unwrap();
    let out = pack(&["--findings", bad.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("bad.jsonl:2"));
    assert_eq!(site.outbox_batches().len(), 2);
    assert_eq!(pack(&["--bogus", "1"]).status.code(), Some(2));

    site.transfer_all();
    let unpack = || {
        let h = &site.high;
        Command::new(env!("CARGO_BIN_EXE_robodr-diode-unpack"))
            .args(["--inbox", h.join("inbox").to_str().unwrap()])
            .args(["--out", h.join("out").to_str().unwrap()])
            .args(["--quarantine", h.join("quarantine").to_str().unwrap()])
            .args(["--processed", h.join("processed").to_str().unwrap()])
            .args(["--state", h.join("state.json").to_str().unwrap()])
            .args(["--keyring", keyring.to_str().unwrap()])
            .args(["--partitions", "12"])
            .output()
            .unwrap()
    };
    let out = unpack();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rep: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rep["accepted"].as_array().unwrap().len(), 2);
    assert!(!String::from_utf8_lossy(&out.stderr).contains("warning"));

    // A tampered re-send: exit code 3 and a quarantine entry.
    site.transfer_all();
    let name = site.outbox_batches()[0].clone();
    let f = site.inbox().join(&name).join("findings.jsonl");
    let mut b = fs::read(&f).unwrap();
    b[10] ^= 1;
    fs::write(&f, b).unwrap();
    let out = unpack();
    assert_eq!(
        out.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let rep: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rep["quarantined"][0]["reason"]["code"], "hash_mismatch");
    assert_eq!(rep["duplicates"].as_array().unwrap().len(), 1);
}

/// An argument that is not valid UTF-8 is a usage error (exit 2), never a
/// panic.
#[test]
fn non_utf8_argument_is_a_usage_error() {
    use std::os::unix::ffi::OsStrExt;
    for bin in [
        env!("CARGO_BIN_EXE_robodr-diode-pack"),
        env!("CARGO_BIN_EXE_robodr-diode-unpack"),
    ] {
        let o = Command::new(bin)
            .args(["--state"])
            .arg(std::ffi::OsStr::from_bytes(b"/tmp/\xff"))
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&o.stderr);
        assert_eq!(o.status.code(), Some(2), "{bin}: {err}");
        assert!(err.contains("not valid UTF-8"), "{bin}: {err}");
    }
}

fn set_mode(p: &Path, m: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(m)).unwrap();
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Paths and helpers for the key-handling CLI tests.
struct Keys {
    site: Site,
    input: PathBuf,
}

impl Keys {
    fn new(tag: &str) -> Self {
        let site = Site::new(tag);
        let input = site.tmp.path().join("findings.jsonl");
        let lines: Vec<String> = findings(2)
            .iter()
            .map(|f| robodr_ocsf::to_json(f).unwrap())
            .collect();
        fs::write(&input, lines.join("\n")).unwrap();
        Self { site, input }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.site.tmp.path().join(name)
    }

    fn pack(&self, key: &Path, extra: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_robodr-diode-pack"))
            .args(["--outbox", self.site.outbox.to_str().unwrap()])
            .args(["--state", self.site.pack_state.to_str().unwrap()])
            .args(["--unit", UNIT])
            .args(["--key-file", key.to_str().unwrap()])
            .args(["--findings", self.input.to_str().unwrap()])
            .args(["--now-ms", &NOW.to_string()])
            .args(extra)
            .output()
            .unwrap()
    }

    fn unpack(&self, ring: &Path, extra: &[&str]) -> Output {
        let h = &self.site.high;
        Command::new(env!("CARGO_BIN_EXE_robodr-diode-unpack"))
            .args(["--inbox", h.join("inbox").to_str().unwrap()])
            .args(["--out", h.join("out").to_str().unwrap()])
            .args(["--quarantine", h.join("quarantine").to_str().unwrap()])
            .args(["--processed", h.join("processed").to_str().unwrap()])
            .args(["--state", h.join("state.json").to_str().unwrap()])
            .args(["--keyring", ring.to_str().unwrap()])
            .args(extra)
            .output()
            .unwrap()
    }

    fn ring(&self, name: &str, body: &str) -> PathBuf {
        let p = self.path(name);
        fs::write(&p, body).unwrap();
        p
    }
}

#[test]
fn packer_key_must_be_a_private_secret_key_file() {
    let k = Keys::new("cli-pack-keys");
    let sk = k.path("unit.key");
    let kf = KeyFile::generate_ed25519(Some(KEY_ID)).unwrap();
    kf.write_new(&sk).unwrap();

    // Loose permissions: refused (no longer just a warning), nothing written.
    for m in [0o640, 0o604, 0o644] {
        set_mode(&sk, m);
        let o = k.pack(&sk, &[]);
        assert_eq!(o.status.code(), Some(1), "{m:o}: {}", err(&o));
        assert!(err(&o).contains("chmod 600"), "{}", err(&o));
        assert!(k.site.outbox_batches().is_empty());
    }
    set_mode(&sk, 0o600);

    // The public key cannot sign.
    let pk = k.path("unit.pub");
    kf.to_public().unwrap().write_new(&pk).unwrap();
    let o = k.pack(&pk, &[]);
    assert_eq!(o.status.code(), Some(1));
    assert!(err(&o).contains("public key file"), "{}", err(&o));

    // A legacy bare-hex key file is not a key file any more.
    let hex = k.path("legacy.hex");
    fs::write(&hex, "07".repeat(32)).unwrap();
    set_mode(&hex, 0o600);
    let o = k.pack(&hex, &[]);
    assert_eq!(o.status.code(), Some(1));
    assert!(err(&o).contains("malformed"), "{}", err(&o));

    // --key-id must agree with the file.
    let o = k.pack(&sk, &["--key-id", "something-else"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(err(&o).contains("contradicts"), "{}", err(&o));
    let o = k.pack(&sk, &["--key-id", KEY_ID]);
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(k.site.outbox_batches().len(), 1);
    // A value-less switch given a value is a usage error.
    assert_eq!(k.pack(&sk, &["--allow-hmac", "yes"]).status.code(), Some(2));
}

#[test]
fn hmac_needs_allow_hmac_on_both_sides() {
    let k = Keys::new("cli-hmac");
    let hk = k.path("hmac.key");
    KeyFile::hmac_from_secret(&KEY, Some(KEY_ID))
        .unwrap()
        .write_new(&hk)
        .unwrap();
    let o = k.pack(&hk, &[]);
    assert_eq!(o.status.code(), Some(1));
    assert!(err(&o).contains("--allow-hmac"), "{}", err(&o));
    assert!(k.site.outbox_batches().is_empty());
    let o = k.pack(&hk, &["--allow-hmac"]);
    assert!(o.status.success(), "{}", err(&o));
    assert!(err(&o).contains("warning"), "{}", err(&o));
    k.site.transfer_all();

    let ring = k.ring("ring", &format!("{UNIT} {}\n", hk.display()));
    let o = k.unpack(&ring, &[]);
    assert_eq!(o.status.code(), Some(1));
    assert!(err(&o).contains("--allow-hmac"), "{}", err(&o));
    // Even with --allow-hmac, an HMAC secret with loose permissions is refused.
    set_mode(&hk, 0o640);
    let o = k.unpack(&ring, &["--allow-hmac"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(err(&o).contains("chmod 600"), "{}", err(&o));
    set_mode(&hk, 0o600);
    let o = k.unpack(&ring, &["--allow-hmac"]);
    assert!(o.status.success(), "{}", err(&o));
    assert!(err(&o).contains("warning"), "{}", err(&o));
    let rep: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(rep["accepted"].as_array().unwrap().len(), 1);
}

#[test]
fn importer_holds_public_keys_only() {
    let k = Keys::new("cli-pub-only");
    let sk = k.path("unit.key");
    let kf = KeyFile::generate_ed25519(None).unwrap();
    kf.write_new(&sk).unwrap();
    let pk = k.path("unit.pub");
    kf.to_public().unwrap().write_new(&pk).unwrap();
    assert!(k.pack(&sk, &[]).status.success());
    k.site.transfer_all();

    // The unit's SECRET in the SOC keyring: refused (even mode 0600, even
    // with --allow-hmac, which is about HMAC only).
    let ring = k.ring("secret.ring", &format!("{UNIT} {}\n", sk.display()));
    for extra in [&[][..], &["--allow-hmac"][..]] {
        let o = k.unpack(&ring, extra);
        assert_eq!(o.status.code(), Some(1), "{}", err(&o));
        assert!(err(&o).contains("export-pub"), "{}", err(&o));
    }
    // As a bundle key too.
    let pring = k.ring("pub.ring", &format!("{UNIT} unit.pub\n"));
    let bk = format!("{UNIT}:{}", sk.display());
    let o = k.unpack(&pring, &["--bundle-key", &bk]);
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));

    // Three-column form: the key id must match the file.
    let bad = k.ring("bad.ring", &format!("{UNIT} not-the-id unit.pub\n"));
    let o = k.unpack(&bad, &[]);
    assert_eq!(o.status.code(), Some(1));
    assert!(err(&o).contains("contradicts"), "{}", err(&o));
    let bad = k.ring("bad2.ring", &format!("{UNIT}\n"));
    assert_eq!(k.unpack(&bad, &[]).status.code(), Some(1));

    // The public key, world-readable: accepted.
    set_mode(&pk, 0o644);
    let three = k.ring("three.ring", &format!("{UNIT} {} unit.pub\n", kf.key_id));
    let bk = format!("{UNIT}:{}", pk.display());
    let o = k.unpack(&three, &["--bundle-key", &bk]);
    assert!(o.status.success(), "{}", err(&o));
    let rep: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(rep["accepted"].as_array().unwrap().len(), 1);
}

#[test]
fn wrong_unit_key_is_quarantined_by_the_binary() {
    let k = Keys::new("cli-wrong-unit");
    let sk = k.path("unit.key");
    let kf = KeyFile::generate_ed25519(None).unwrap();
    kf.write_new(&sk).unwrap();
    kf.to_public()
        .unwrap()
        .write_new(&k.path("unit.pub"))
        .unwrap();
    let other = KeyFile::generate_ed25519(None).unwrap();
    other
        .to_public()
        .unwrap()
        .write_new(&k.path("other.pub"))
        .unwrap();
    assert!(k.pack(&sk, &[]).status.success());

    // The SOC lists our key for another unit, and another key for us.
    k.site.transfer_all();
    let ring = k.ring("ring", &format!("ugv-008 unit.pub\n{UNIT} other.pub\n"));
    let o = k.unpack(&ring, &[]);
    assert_eq!(o.status.code(), Some(3), "{}", err(&o));
    let rep: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(rep["quarantined"][0]["reason"]["code"], "unit_key_mismatch");
    assert!(rep["accepted"].as_array().unwrap().is_empty());
}

#[test]
fn keyring_robots_directive_and_unit_bound_bundle_keys() {
    let k = Keys::new("cli-robots");
    let sk = k.path("unit.key");
    let kf = KeyFile::generate_ed25519(None).unwrap();
    kf.write_new(&sk).unwrap();
    kf.to_public()
        .unwrap()
        .write_new(&k.path("unit.pub"))
        .unwrap();
    assert!(k.pack(&sk, &[]).status.success());
    k.site.transfer_all();

    // Malformed directives are configuration errors.
    for body in [
        format!("{UNIT} unit.pub\nrobots:\n"),
        format!("{UNIT} unit.pub\nrobots: {UNIT}\n"),
        format!("{UNIT} unit.pub\nrobots: {UNIT} a/b\n"),
    ] {
        let ring = k.ring("bad.ring", &body);
        let o = k.unpack(&ring, &[]);
        assert_eq!(o.status.code(), Some(1), "{body}: {}", err(&o));
    }
    // A bundle key must name its unit.
    let ring = k.ring(
        "ok.ring",
        &format!(
            "# console may report on two robots\n{UNIT} unit.pub\nrobots: {UNIT} ugv-100 ugv-101\n"
        ),
    );
    let pk = k.path("unit.pub");
    let o = k.unpack(&ring, &["--bundle-key", pk.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    assert!(err(&o).contains("<unit>:<key-file>"), "{}", err(&o));

    let bk = format!("{UNIT}:{}", pk.display());
    let o = k.unpack(&ring, &["--bundle-key", &bk, "--held-max-age-s", "0"]);
    assert!(o.status.success(), "{}", err(&o));
    let rep: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(rep["accepted"].as_array().unwrap().len(), 1);
    assert_eq!(rep["errors"].as_array().unwrap().len(), 0);
}

/// `--version` prints `<name> <version>` and `--help` the usage, both on
/// stdout with exit 0 (the release .deb smoke test runs both on every
/// shipped binary); misuse of either stays a usage error (exit 2).
#[test]
fn version_and_help_exit_0() {
    for (name, exe) in [
        ("robodr-diode-pack", env!("CARGO_BIN_EXE_robodr-diode-pack")),
        (
            "robodr-diode-unpack",
            env!("CARGO_BIN_EXE_robodr-diode-unpack"),
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
