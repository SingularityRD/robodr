//! T36: `robodr-release sign --key` takes a `robodr-signer/v1` signer
//! file, so a release or root key can stay in a PKCS#11 token or HSM. The
//! external signer here is `openssl pkeyutl` over a PEM of the key (a
//! stand-in token); the PKCS#11 adapter itself is tested against SoftHSM
//! in crates/robodr-signer/tests/external.rs. Skipped (with a message)
//! without `openssl`; on CI (`CI` or `ROBODR_REQUIRE_SIGNER_TESTS=1` set)
//! a missing `openssl` fails instead.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use robodr_blackbox::crypto::to_hex;
use robodr_blackbox::KeyFile;
use robodr_pkg::common::to_canonical;
use robodr_pkg::trust::{Programme, Quorum, TrustFile, TrustKey, TRUST_FORMAT};
use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_robodr-release");
const NOW: &str = "1790000000";

fn run(args: &[&str]) -> (i32, Value, String) {
    let o = Command::new(BIN).args(args).output().unwrap();
    let v = serde_json::from_slice(&o.stdout).unwrap_or(Value::Null);
    (
        o.status.code().unwrap_or(-1),
        v,
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// Under the target dir: the signer command's directories must pass the
/// trusted-path rule, which a world-writable /tmp never does.
struct Dir(PathBuf);
impl Dir {
    fn new(tag: &str) -> Self {
        let p = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("release-extsig-{tag}-{}", std::process::id()));
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

/// A stand-in token holding `key_file`'s seed, and a signer file pinned to
/// `pinned`'s public key under `key_id`.
fn token(dir: &Path, name: &str, key_file: &Path, pinned: &Path, key_id: &str) -> PathBuf {
    let seed = KeyFile::load_secret(key_file).unwrap().secret().to_vec();
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(&seed);
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

#[test]
fn a_root_quorum_with_one_key_in_a_token() {
    if !have_openssl() {
        return;
    }
    let d = Dir::new("quorum");
    let keys = d.0.join("keys");
    fs::create_dir_all(&keys).unwrap();
    fs::set_permissions(&keys, fs::Permissions::from_mode(0o755)).unwrap();
    let mut pins = Vec::new();
    for r in ["root-1", "root-2", "rel-a", "rel-b", "op-1", "op-2"] {
        let (c, v, e) = run(&[
            "keygen",
            "--out",
            s(&keys.join(format!("{r}.key"))),
            "--key-id",
            r,
        ]);
        assert_eq!(c, 0, "{e}");
        if r.starts_with("root") {
            pins.push(v["fingerprint"].as_str().unwrap().to_string());
        }
    }
    let tk = |id: &str| {
        let k = KeyFile::load_public(&keys.join(format!("{id}.key.pub"))).unwrap();
        TrustKey::new(id, &k.public_key().unwrap())
    };
    let t = TrustFile {
        format: TRUST_FORMAT.into(),
        site: "site-a".into(),
        version: 1,
        issued_at: 1_790_000_000,
        expires_at: 1_790_000_000 + 90 * 86400,
        programmes: vec![Programme {
            name: "ugv-x1".into(),
            release_keys: vec!["rel-a".into(), "rel-b".into()],
            packages: vec!["nav-stack".into()],
        }],
        quorum: Quorum {
            root: 2,
            release: 2,
            operator_prod: 2,
            operator_lab: 1,
        },
        roots: vec![tk("root-1"), tk("root-2")],
        release_keys: vec![tk("rel-a"), tk("rel-b")],
        depot_keys: vec![],
        operator_keys: vec![tk("op-1"), tk("op-2")],
        rings: vec![],
        revoked_keys: vec![],
        revoked_rpks: vec![],
        revoked_serials: vec![],
        floors: vec![],
        entry_keys: vec![],
        depot_wrap_keys: vec![],
        ek_ca_certs: vec![],
    };
    let trust = d.0.join("trust.json");
    fs::write(&trust, to_canonical(&t).unwrap()).unwrap();
    let verify = |pins: &[String]| {
        let mut v = vec![
            "verify",
            "trust",
            "--trust",
            s(&trust),
            "--site",
            "site-a",
            "--no-trust-anchor",
            "--now",
            NOW,
        ];
        for p in pins {
            v.extend(["--root", p.as_str()]);
        }
        run(&v)
    };

    // root-1 signs from its key file.
    let (c, v, e) = run(&[
        "sign",
        "--key",
        s(&keys.join("root-1.key")),
        "--target",
        s(&trust),
    ]);
    assert_eq!(c, 0, "{e}");
    assert_eq!(v["backend"], "file");

    // A "token" holding rel-a's key but pinned to root-2's public key (the
    // wrong slot): refused before anything is written.
    let sig_before = fs::read(d.0.join("trust.json.sig")).unwrap();
    let wrong = token(
        &d.0,
        "wrong",
        &keys.join("rel-a.key"),
        &keys.join("root-2.key"),
        "root-2",
    );
    let (c, _, e) = run(&["sign", "--key", s(&wrong), "--target", s(&trust)]);
    assert_eq!(c, 1);
    assert!(e.contains("does not verify"), "{e}");
    assert_eq!(fs::read(d.0.join("trust.json.sig")).unwrap(), sig_before);
    assert_eq!(verify(&pins).0, 1, "still one root signature");

    // root-2 signs from its token: the quorum is met.
    let good = token(
        &d.0,
        "good",
        &keys.join("root-2.key"),
        &keys.join("root-2.key"),
        "root-2",
    );
    let (c, v, e) = run(&["sign", "--key", s(&good), "--target", s(&trust)]);
    assert_eq!(c, 0, "{e}");
    assert_eq!(v["backend"], "external");
    assert_eq!(v["key_id"], "root-2");
    assert_eq!(v["fingerprint"], pins[1].as_str());
    let (c, _, e) = verify(&pins);
    assert_eq!(c, 0, "{e}");
}
