//! Robot-side key protection (SALES-READINESS T66): every private key is
//! classified (TPM-sealed systemd credential or the file fallback), the
//! fallback is flagged in `status.json`, and `key_protection.require:
//! "tpm2"` refuses to start on a key that is not TPM-sealed.
//!
//! `swtpm_sealed_credentials` (with `ROBODR_SWTPM=1`; needs swtpm,
//! systemd-creds >= 250 with TPM2 support and libtss2-tcti-swtpm) seals the
//! real key with `systemd-creds encrypt --with-key=tpm2` against a
//! software TPM, decrypts it back the way `LoadCredentialEncrypted=` does,
//! and runs the real binary's `--check-config` on the result.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::pcap::robot_profile;
use common::*;

const BIN: &str = env!("CARGO_BIN_EXE_robodr-agentd");

/// A systemd credential header (binary form) for `id`.
fn header(id: &str) -> Vec<u8> {
    let mut v = robodr_blackbox::crypto::from_hex(id).unwrap();
    for n in [32u32, 1, 12, 16] {
        v.extend_from_slice(&n.to_le_bytes());
    }
    v.extend_from_slice(&[0x11; 64]);
    v
}
const TPM2: &str = "0c7cc07b117645919c4b0bea08bc20fe";
const HOST: &str = "5a1c6a86df9d4096b1d5a65e0862f19a";

/// Move the fixture's key into `<dir>/creds/blackbox.key` (the "systemd
/// credentials directory") and return (creds, encrypted) dirs.
fn credential_layout(s: &Setup) -> (PathBuf, PathBuf) {
    let creds = s.dir.join("creds");
    let enc = s.dir.join("enc");
    std::fs::create_dir_all(&creds).unwrap();
    std::fs::create_dir_all(&enc).unwrap();
    std::fs::copy(&s.key, creds.join("blackbox.key")).unwrap();
    std::fs::set_permissions(
        creds.join("blackbox.key"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    (creds, enc)
}

fn with_credential(s: &Setup, creds: &Path, enc: &Path, require: &str) -> serde_json::Value {
    let mut cfg = s.config(
        serde_json::json!({}),
        serde_json::json!([{"kind": "stdin"}]),
        serde_json::json!({}),
    );
    cfg["blackbox"]["key_file"] = serde_json::json!(creds.join("blackbox.key"));
    cfg["key_protection"] = serde_json::json!({
        "require": require,
        "credentials_dir": creds,
        "encrypted_dir": enc,
    });
    cfg
}

#[test]
fn a_plain_key_file_is_the_flagged_fallback_in_status_json() {
    let s = setup("keyprot-file", &robot_profile(true));
    let cfg = s.config(
        serde_json::json!({}),
        serde_json::json!([{"kind": "stdin"}]),
        serde_json::json!({}),
    );
    let r = s.resolve(&cfg);
    assert!(r.key_protection.fallback);
    assert!(!r.key_protection.all_tpm2);
    assert_eq!(r.key_protection.keys.len(), 1);
    assert_eq!(r.key_protection.keys[0].role, "blackbox");
    assert_eq!(r.key_protection.keys[0].protection, "file");

    // The running daemon reports it.
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    let h = std::thread::spawn(move || {
        let mut log = Vec::new();
        robodr_agentd::run(&r, &|| s2.load(Ordering::SeqCst), &mut log).map(|_| ())
    });
    let st = wait_for(10, "status.json", || status(&s.spool));
    stop.store(true, Ordering::SeqCst);
    h.join().unwrap().unwrap();
    let kp = &st["key_protection"];
    assert_eq!(kp["require"], "none", "{kp}");
    assert_eq!(kp["fallback"], true, "{kp}");
    assert_eq!(kp["all_tpm2"], false, "{kp}");
    assert_eq!(kp["keys"][0]["role"], "blackbox");
    assert_eq!(kp["keys"][0]["protection"], "file");
    assert_eq!(kp["keys"][0]["fallback"], true);
    assert_eq!(kp["keys"][0]["path"], s.key.display().to_string());

    // --check-config names the fallback too.
    let out = Command::new(BIN)
        .arg("--config")
        .arg(s.write_config(&cfg))
        .arg("--check-config")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("key blackbox: file (not TPM-sealed"), "{err}");
}

#[test]
fn require_tpm2_refuses_every_weaker_key() {
    let s = setup("keyprot-require", &robot_profile(true));
    let (creds, enc) = credential_layout(&s);

    // A plain key file.
    let mut cfg = s.config(
        serde_json::json!({}),
        serde_json::json!([{"kind": "stdin"}]),
        serde_json::json!({}),
    );
    cfg["key_protection"] = serde_json::json!({"require": "tpm2"});
    let e = robodr_agentd::load(&s.write_config(&cfg)).unwrap_err();
    assert!(
        e.contains("not TPM-sealed") && e.contains("blackbox"),
        "{e}"
    );

    // A credential loaded from a plain file (no sealed source).
    let cfg = with_credential(&s, &creds, &enc, "tpm2");
    let e = robodr_agentd::load(&s.write_config(&cfg)).unwrap_err();
    assert!(e.contains("plain-credential"), "{e}");

    // Sealed with the host key only: a disk copy decrypts it.
    std::fs::write(enc.join("blackbox.key"), header(HOST)).unwrap();
    let e = robodr_agentd::load(&s.write_config(&cfg)).unwrap_err();
    assert!(e.contains("blackbox") && e.contains(": host)"), "{e}");

    // The binary refuses to start (exit 2) and starts nothing.
    let out = Command::new(BIN)
        .arg("--config")
        .arg(s.write_config(&cfg))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(!s.blackbox.exists());

    // TPM2-sealed: accepted, reported as such.
    std::fs::write(enc.join("blackbox.key"), header(TPM2)).unwrap();
    let r = robodr_agentd::load(&s.write_config(&cfg)).unwrap();
    assert!(r.key_protection.all_tpm2);
    assert!(!r.key_protection.fallback);
    assert_eq!(r.key_protection.keys[0].protection, "tpm2");

    // Review finding (WP15): the same layout, but systemd says this
    // service's credentials are elsewhere ($CREDENTIALS_DIRECTORY): the
    // configured directory is just a directory, refused under tpm2.
    let out = Command::new(BIN)
        .arg("--config")
        .arg(s.write_config(&cfg))
        .arg("--check-config")
        .env("CREDENTIALS_DIRECTORY", s.dir.join("elsewhere"))
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(err.contains("blackbox") && err.contains(": file)"), "{err}");
    // ... and accepted when it is the configured one.
    let out = Command::new(BIN)
        .arg("--config")
        .arg(s.write_config(&cfg))
        .arg("--check-config")
        .env("CREDENTIALS_DIRECTORY", &creds)
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(err.contains("key blackbox: tpm2"), "{err}");

    // A second key that is a plain file breaks the requirement again.
    let fk = s.dir.join("finding.key");
    robodr_blackbox::KeyFile::ed25519_from_seed(&[3; 32], Some("finding-1"))
        .unwrap()
        .write_new(&fk)
        .unwrap();
    let mut cfg2 = cfg.clone();
    cfg2["finding_signing"] = serde_json::json!({"key_file": fk});
    let e = robodr_agentd::load(&s.write_config(&cfg2)).unwrap_err();
    assert!(
        e.contains("finding_signing") && e.contains(": file)"),
        "{e}"
    );
    // Report-only: the same layout loads, the fallback flagged.
    cfg2["key_protection"]["require"] = serde_json::json!("none");
    let r = robodr_agentd::load(&s.write_config(&cfg2)).unwrap();
    assert!(r.key_protection.fallback);
    assert!(!r.key_protection.all_tpm2);
}

#[test]
fn key_protection_section_is_strict() {
    let s = setup("keyprot-strict", &robot_profile(true));
    let mut cfg = s.config(
        serde_json::json!({}),
        serde_json::json!([{"kind": "stdin"}]),
        serde_json::json!({}),
    );
    for bad in [
        serde_json::json!({"require": "yes"}),
        serde_json::json!({"require": "tpm2", "fallback": true}),
        serde_json::json!({"encrypted_dir": "relative/dir"}),
    ] {
        cfg["key_protection"] = bad.clone();
        assert!(robodr_agentd::load(&s.write_config(&cfg)).is_err(), "{bad}");
    }
}

// ------------------------------------------------------------- swtpm --

struct Swtpm {
    child: std::process::Child,
    port: u16,
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_swtpm(state: &Path, n: u16) -> Swtpm {
    let port: u16 = 30_000 + (std::process::id() % 2_000) as u16 * 4 + 2 * n;
    let child = Command::new("swtpm")
        .args(["socket", "--tpm2"])
        .args(["--server", &format!("type=tcp,port={port}")])
        .args(["--ctrl", &format!("type=tcp,port={}", port + 1)])
        .args(["--tpmstate", &format!("dir={}", state.display())])
        .args(["--flags", "not-need-init,startup-clear"])
        .spawn()
        .expect("swtpm (apt install swtpm)");
    let t0 = std::time::Instant::now();
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "swtpm did not start"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    Swtpm { child, port }
}

fn creds(args: &[&str]) -> std::process::Output {
    Command::new("systemd-creds").args(args).output().unwrap()
}

#[test]
fn swtpm_sealed_credentials() {
    if std::env::var("ROBODR_SWTPM").as_deref() != Ok("1") {
        eprintln!("skipped: set ROBODR_SWTPM=1 (needs swtpm and systemd-creds)");
        return;
    }
    let s = setup("keyprot-swtpm", &robot_profile(true));
    let state = s.dir.join("swtpm-state");
    std::fs::create_dir_all(&state).unwrap();
    let tpm = start_swtpm(&state, 0);
    let dev = format!("--tpm2-device=swtpm:host=127.0.0.1,port={}", tpm.port);
    let (cred_dir, enc) = credential_layout(&s);
    let sealed = enc.join("blackbox.key");
    let plain = s.key.to_str().unwrap();

    // Seal the black-box key to the (software) TPM, as the operator does.
    let o = creds(&[
        "encrypt",
        "--with-key=tpm2",
        &dev,
        "--name=blackbox.key",
        plain,
        sealed.to_str().unwrap(),
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    // What LoadCredentialEncrypted= does at service start: decrypt with the
    // TPM into the credentials directory.
    let loaded = cred_dir.join("blackbox.key");
    std::fs::remove_file(&loaded).unwrap();
    let o = creds(&[
        "decrypt",
        &dev,
        "--name=blackbox.key",
        sealed.to_str().unwrap(),
        loaded.to_str().unwrap(),
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    std::fs::set_permissions(&loaded, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        std::fs::read(&loaded).unwrap(),
        std::fs::read(&s.key).unwrap()
    );

    let cfg = with_credential(&s, &cred_dir, &enc, "tpm2");
    let out = Command::new(BIN)
        .arg("--config")
        .arg(s.write_config(&cfg))
        .arg("--check-config")
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(err.contains("key blackbox: tpm2"), "{err}");

    // Another TPM cannot open it: a fresh swtpm (new storage seed).
    drop(tpm);
    let state2 = s.dir.join("swtpm-state-2");
    std::fs::create_dir_all(&state2).unwrap();
    let other = start_swtpm(&state2, 1);
    let dev2 = format!("--tpm2-device=swtpm:host=127.0.0.1,port={}", other.port);
    let stolen = s.dir.join("stolen.key");
    let o = creds(&[
        "decrypt",
        &dev2,
        "--name=blackbox.key",
        sealed.to_str().unwrap(),
        stolen.to_str().unwrap(),
    ]);
    assert!(!o.status.success(), "decrypted on another TPM");

    // Sealed with the null key (tpm2-absent): refused by require tpm2.
    std::fs::remove_file(&sealed).unwrap();
    let o = creds(&[
        "encrypt",
        "--with-key=tpm2-absent",
        "--name=blackbox.key",
        plain,
        sealed.to_str().unwrap(),
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let out = Command::new(BIN)
        .arg("--config")
        .arg(s.write_config(&cfg))
        .arg("--check-config")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains(": null)"));
}
