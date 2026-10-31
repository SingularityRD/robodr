//! T36: every `robodr-commission --sign-key` takes a `robodr-signer/v1`
//! signer file, so the profile signing key can stay in a PKCS#11 token or
//! HSM. The external signer here is `openssl pkeyutl` over the key (a
//! stand-in token); the PKCS#11 adapter itself is tested against SoftHSM
//! in crates/robodr-signer/tests/external.rs. Skipped (with a message)
//! without `openssl`; on CI (`CI` or `ROBODR_REQUIRE_SIGNER_TESTS=1` set)
//! a missing `openssl` fails instead.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use robodr_blackbox::crypto::to_hex;
use robodr_blackbox::KeyFile;

const BIN: &str = env!("CARGO_BIN_EXE_robodr-commission");

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(common::with_operator_signature(args))
        .output()
        .expect("run binary")
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Under the target dir: the signer command's directories must pass the
/// trusted-path rule, which a world-writable /tmp never does.
struct Dir(PathBuf);
impl Dir {
    fn new(tag: &str) -> Self {
        let p = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("commission-extsig-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        Dir(p)
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn have_openssl() -> bool {
    let ok = Command::new("openssl")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        skip("needs openssl (Ed25519 pkeyutl)");
    }
    ok
}

/// A prerequisite of these tests is missing. Off CI that is a skip (with a
/// message); on CI (`CI` set, as GitHub Actions does, or
/// `ROBODR_REQUIRE_SIGNER_TESTS=1`) it fails the test, so a runner without
/// `openssl` or with an untrusted checkout path cannot report green
/// without having run them.
fn skip(why: &str) {
    let on = |n: &str| std::env::var(n).is_ok_and(|v| !v.is_empty() && v != "0" && v != "false");
    assert!(
        !(on("CI") || on("ROBODR_REQUIRE_SIGNER_TESTS")),
        "required on CI, but {why}"
    );
    eprintln!("skipped: {why}");
}

/// A stand-in token holding `held`'s seed, and a signer file pinned to
/// `pinned`'s public key under `key_id`.
fn token(dir: &Path, name: &str, held: &Path, pinned: &Path, key_id: &str) -> PathBuf {
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(KeyFile::load_secret(held).unwrap().secret());
    let der_path = dir.join(format!("{name}.der"));
    fs::write(&der_path, &der).unwrap();
    fs::set_permissions(&der_path, fs::Permissions::from_mode(0o600)).unwrap();
    let script = dir.join(format!("{name}.sh"));
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nt=$(mktemp) || exit 1\ncat > \"$t\"\n\
             openssl pkeyutl -sign -rawin -keyform DER -inkey {} -in \"$t\"\nrc=$?\n\
             rm -f \"$t\"\nexit $rc\n",
            der_path.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    let public = KeyFile::load_secret(pinned).unwrap().public_key().unwrap();
    let f = dir.join(format!("{name}.signer.json"));
    fs::write(
        &f,
        serde_json::json!({
            "format": "robodr-signer/v1",
            "backend": "external",
            "key_id": key_id,
            "public_key_hex": to_hex(&public),
            "command": [script],
        })
        .to_string(),
    )
    .unwrap();
    fs::set_permissions(&f, fs::Permissions::from_mode(0o644)).unwrap();
    f
}

fn keygen(dir: &Path, name: &str) -> (PathBuf, PathBuf) {
    let key = dir.join(format!("{name}.key"));
    let trust = dir.join(format!("{name}.trust.json"));
    let o = run(&[
        "keygen",
        "--out",
        s(&key),
        "--trust-out",
        s(&trust),
        "--key-id",
        name,
    ]);
    assert!(o.status.success(), "{}", err(&o));
    (key, trust)
}

/// Learn the clean example and confirm its sign-off.
fn draft(dir: &Path) -> (PathBuf, PathBuf) {
    let p = dir.join("draft.json");
    let ex = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/clean-run.jsonl");
    let o = run(&[
        "learn",
        "--events",
        s(&ex),
        "--model",
        "ugv-demo-synthetic",
        "--out",
        s(&p),
        "--quiet",
    ]);
    assert!(o.status.success(), "{}", err(&o));
    let so = PathBuf::from(format!("{}.signoff.json", p.display()));
    let mut v: serde_json::Value = serde_json::from_str(&fs::read_to_string(&so).unwrap()).unwrap();
    v["operator"] = "Test Operator".into();
    for i in v["items"].as_array_mut().unwrap() {
        i["confirmed"] = true.into();
    }
    fs::write(&so, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    (p, so)
}

fn lock(p: &Path, so: &Path, out: &Path, key: &Path) -> Output {
    run(&[
        "lock",
        "--in",
        s(p),
        "--signoff",
        s(so),
        "--out",
        s(out),
        "--platform",
        "ugv-x1",
        "--profile-version",
        "3",
        "--locked-at",
        "1790000000",
        "--sign-key",
        s(key),
    ])
}

#[test]
fn a_profile_signed_by_a_token_verifies_and_a_wrong_token_signs_nothing() {
    if !have_openssl() {
        return;
    }
    let d = Dir::new("lock");
    let (key, trust) = keygen(&d.0, "oem-a");
    let (other, _) = keygen(&d.0, "oem-b");
    let (p, so) = draft(&d.0);

    // A token holding oem-b's key, pinned to oem-a: refused, nothing written.
    let wrong = token(&d.0, "wrong", &other, &key, "oem-a");
    let bad = d.0.join("bad.json");
    let o = lock(&p, &so, &bad, &wrong);
    assert!(!o.status.success());
    assert!(err(&o).contains("does not verify"), "{}", err(&o));
    assert!(!bad.exists() && !d.0.join("bad.json.sig").exists());

    // The token holding oem-a's key: the profile verifies under the trust
    // file keygen wrote for the key file.
    let good = token(&d.0, "good", &key, &key, "oem-a");
    let locked = d.0.join("locked.json");
    let o = lock(&p, &so, &locked, &good);
    assert!(o.status.success(), "{}", err(&o));
    let o = run(&[
        "verify-profile",
        "--profile",
        s(&locked),
        "--trusted-keys",
        s(&trust),
        "--json",
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stdout));
    let r: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(r["trusted"], true);
    assert_eq!(r["signed_by"], "oem-a");

    // `sign` (re-sign an existing profile) takes the signer file too.
    let o = run(&[
        "sign",
        "--profile",
        s(&locked),
        "--sign-key",
        s(&good),
        "--force",
    ]);
    assert!(o.status.success(), "{}", err(&o));
}
