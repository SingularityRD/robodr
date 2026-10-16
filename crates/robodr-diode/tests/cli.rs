//! The two binaries end to end.

mod common;

use common::*;
use std::fs;
use std::process::Command;

#[test]
fn pack_and_unpack_binaries() {
    let site = Site::new("cli");
    let keys = site.tmp.path().join("keys");
    fs::create_dir(&keys).unwrap();
    let key_file = keys.join("ugv-007.key");
    fs::write(&key_file, format!("{}\n", "07".repeat(32))).unwrap();
    let keyring = keys.join("keyring");
    fs::write(
        &keyring,
        format!("# unit key-id key-file\n{UNIT} {KEY_ID} ugv-007.key\n"),
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
