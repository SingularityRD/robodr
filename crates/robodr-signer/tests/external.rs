//! The external signer protocol end to end: real commands, the pinned-key
//! check, hostile and broken signers, the trust checks on the signer file
//! and its command, and (with `ROBODR_PKCS11=1`, needs SoftHSM 2 and OpenSC
//! `pkcs11-tool`) the shipped PKCS#11 adapter against a SoftHSM token.
//!
//! The well-behaved fake signer is `openssl pkeyutl -sign -rawin` with an
//! Ed25519 key built from a known seed; tests that need it are skipped
//! (with a message) on a host without `openssl`.

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use robodr_blackbox::crypto::to_hex;
use robodr_blackbox::sign_ed25519::{public_key_from_seed, verify};
use robodr_blackbox::{KeyFile, Signer};
use robodr_signer::{load, Backend};

const SEED: [u8; 32] = [5; 32];
const OTHER_SEED: [u8; 32] = [6; 32];

struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Self {
        let p = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("robodr-signer-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        Dir(p)
    }
    fn path(&self, f: &str) -> PathBuf {
        self.0.join(f)
    }
    /// An executable script, mode 0755.
    fn script(&self, name: &str, body: &str) -> PathBuf {
        let p = self.path(name);
        fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        p
    }
    /// A signer file (mode 0644) for `command`, pinned to `seed`'s key.
    fn signer_file(&self, name: &str, seed: &[u8; 32], command: &[&str], extra: &str) -> PathBuf {
        let p = self.path(name);
        let cmd = serde_json::to_string(command).unwrap();
        fs::write(
            &p,
            format!(
                r#"{{"format":"robodr-signer/v1","backend":"external","key_id":"rel-1",
                   "public_key_hex":"{}","command":{cmd}{extra}}}"#,
                to_hex(&public_key_from_seed(seed))
            ),
        )
        .unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        p
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The test tree's ancestors must pass the trusted-path rule for any
/// external signer test to run here (they do on a normal checkout).
fn trusted_tree(d: &Dir) -> bool {
    let probe = d.script("probe", "exit 0");
    match robodr_signer::external::check_trusted_executable(&probe) {
        Ok(_) => true,
        Err(e) => {
            eprintln!("skipped: the test directory is not a trusted path here ({e})");
            false
        }
    }
}

fn have_openssl() -> bool {
    let ok = Command::new("openssl")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        eprintln!("skipped: needs openssl (Ed25519 pkeyutl)");
    }
    ok
}

/// A PKCS#8 PEM Ed25519 key for `seed`, and an openssl-backed signer
/// script over it.
fn openssl_signer(d: &Dir, name: &str, seed: &[u8; 32]) -> PathBuf {
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(seed);
    let b64 = Command::new("base64")
        .arg("-w0")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            use std::io::Write;
            c.stdin.take().unwrap().write_all(&der)?;
            c.wait_with_output()
        })
        .unwrap();
    let pem = d.path(&format!("{name}.pem"));
    fs::write(
        &pem,
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            String::from_utf8(b64.stdout).unwrap()
        ),
    )
    .unwrap();
    fs::set_permissions(&pem, fs::Permissions::from_mode(0o600)).unwrap();
    d.script(
        name,
        &format!(
            "t=$(mktemp) || exit 1\ncat > \"$t\"\n\
             openssl pkeyutl -sign -rawin -inkey {} -in \"$t\"\nrc=$?\nrm -f \"$t\"\nexit $rc",
            pem.display()
        ),
    )
}

#[test]
fn an_external_signer_signs_and_the_signature_is_checked() {
    let d = Dir::new("good");
    if !trusted_tree(&d) || !have_openssl() {
        return;
    }
    let cmd = openssl_signer(&d, "sign.sh", &SEED);
    let f = d.signer_file("signer.json", &SEED, &[cmd.to_str().unwrap()], "");
    let s = load(&f).unwrap();
    assert_eq!(s.backend(), Backend::External);
    assert_eq!(s.key_id(), "rel-1");
    assert_eq!(s.public_key(), public_key_from_seed(&SEED));
    // A large message goes through the pipe intact.
    let msg = vec![0x5a; 3 * 1024 * 1024 + 17];
    let sig = s.sign(&msg).unwrap();
    assert!(verify(&s.public_key(), &msg, &sig));
    assert_eq!(s.verify_own(&msg, &sig), Some(true));

    // The CLI check does the same.
    let o = Command::new(env!("CARGO_BIN_EXE_robodr-signer"))
        .args(["check", "--key", f.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["backend"], "external");
    assert_eq!(v["signature_verified"], true);
}

#[test]
fn a_signer_holding_another_key_is_refused() {
    let d = Dir::new("wrongkey");
    if !trusted_tree(&d) || !have_openssl() {
        return;
    }
    // The token holds OTHER_SEED, the file pins SEED: wrong token / slot.
    let cmd = openssl_signer(&d, "sign.sh", &OTHER_SEED);
    let f = d.signer_file("signer.json", &SEED, &[cmd.to_str().unwrap()], "");
    let e = load(&f).unwrap().sign(b"doc").unwrap_err().to_string();
    assert!(e.contains("does not verify"), "{e}");
}

#[test]
fn broken_and_hostile_signers_are_refused() {
    let d = Dir::new("hostile");
    if !trusted_tree(&d) {
        return;
    }
    let sig_hex = to_hex(&[1u8; 64]);
    for (name, body, want) in [
        (
            "fail.sh",
            "echo token locked >&2; exit 3".to_string(),
            "failed",
        ),
        (
            "garbage.sh",
            "echo 'signature: none'".to_string(),
            "neither 64 raw bytes",
        ),
        // A well-formed but forged signature: caught by the pinned key.
        (
            "forged.sh",
            format!("cat >/dev/null; echo {sig_hex}"),
            "does not verify",
        ),
        (
            "flood.sh",
            "head -c 100000 /dev/zero".to_string(),
            "more than 4096",
        ),
        ("empty.sh", "exit 0".to_string(), "neither 64 raw bytes"),
    ] {
        let cmd = d.script(name, &body);
        let f = d.signer_file(&format!("{name}.json"), &SEED, &[cmd.to_str().unwrap()], "");
        let e = load(&f).unwrap().sign(b"doc").unwrap_err().to_string();
        assert!(e.contains(want), "{name}: {e}");
    }
}

#[test]
fn a_hanging_signer_is_killed_at_the_deadline() {
    let d = Dir::new("hang");
    if !trusted_tree(&d) {
        return;
    }
    let cmd = d.script("hang.sh", "exec sleep 30");
    let f = d.signer_file(
        "s.json",
        &SEED,
        &[cmd.to_str().unwrap()],
        r#","timeout_ms":300"#,
    );
    let t = Instant::now();
    let e = load(&f).unwrap().sign(b"doc").unwrap_err().to_string();
    assert!(e.contains("no answer within 300 ms"), "{e}");
    assert!(t.elapsed() < Duration::from_secs(10));

    // Exits at once but leaves a background process holding stdout.
    let cmd = d.script("bg.sh", "sleep 30 &\nexit 0");
    let f = d.signer_file(
        "bg.json",
        &SEED,
        &[cmd.to_str().unwrap()],
        r#","timeout_ms":300"#,
    );
    let t = Instant::now();
    let e = load(&f).unwrap().sign(b"doc").unwrap_err().to_string();
    assert!(e.contains("stdout stayed open"), "{e}");
    assert!(t.elapsed() < Duration::from_secs(10));
}

#[test]
fn the_environment_is_cleared_but_for_the_protocol_and_pass_env() {
    let d = Dir::new("env");
    if !trusted_tree(&d) || !have_openssl() {
        return;
    }
    let inner = openssl_signer(&d, "inner.sh", &SEED);
    // Fails unless exactly the expected environment is present.
    let body = format!(
        "[ \"$ROBODR_SIGNER_PROTOCOL\" = 1 ] || exit 11\n\
         [ \"$ROBODR_SIGNER_KEY_ID\" = rel-1 ] || exit 12\n\
         [ \"$ROBODR_SIGNER_ALGORITHM\" = ed25519 ] || exit 13\n\
         [ \"$PATH\" = {} ] || exit 14\n\
         [ -z \"${{ROBODR_TEST_SECRET:-}}\" ] || exit 15\n\
         [ \"${{ROBODR_TEST_PIN:-}}\" = 4321 ] || exit 16\n\
         exec {}",
        robodr_signer::external::SAFE_PATH,
        inner.display()
    );
    let cmd = d.script("env.sh", &body);
    let f = d.signer_file(
        "s.json",
        &SEED,
        &[cmd.to_str().unwrap()],
        r#","pass_env":["ROBODR_TEST_PIN"]"#,
    );
    // Run in a child process so the variables do not leak into other
    // tests: this test binary re-executes itself with the env set.
    if std::env::var_os("ROBODR_SIGNER_ENV_CHILD").is_none() {
        let o = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "the_environment_is_cleared_but_for_the_protocol_and_pass_env",
                "--nocapture",
            ])
            .env("ROBODR_SIGNER_ENV_CHILD", "1")
            .env("ROBODR_TEST_SECRET", "leak")
            .env("ROBODR_TEST_PIN", "4321")
            .output()
            .unwrap();
        assert!(
            o.status.success(),
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        return;
    }
    let s = load(&f).unwrap();
    assert!(s.sign(b"doc").is_ok());
}

#[test]
fn the_signer_file_and_its_command_must_be_trusted_paths() {
    let d = Dir::new("trust");
    if !trusted_tree(&d) {
        return;
    }
    let cmd = d.script("ok.sh", "exit 1");
    let c = cmd.to_str().unwrap();

    // Group-writable signer file.
    let f = d.signer_file("gw.json", &SEED, &[c], "");
    fs::set_permissions(&f, fs::Permissions::from_mode(0o664)).unwrap();
    let e = load(&f).unwrap_err();
    assert!(e.contains("group- or other-writable"), "{e}");

    // A symlinked signer file.
    let real = d.signer_file("real.json", &SEED, &[c], "");
    let link = d.path("link.json");
    symlink(&real, &link).unwrap();
    let e = load(&link).unwrap_err();
    assert!(e.contains("regular"), "{e}");

    // An other-writable command.
    let w = d.script("w.sh", "exit 1");
    fs::set_permissions(&w, fs::Permissions::from_mode(0o757)).unwrap();
    let f = d.signer_file("w.json", &SEED, &[w.to_str().unwrap()], "");
    assert!(load(&f).unwrap_err().contains("writable"));

    // A command in a group-writable directory.
    let sub = d.path("gwdir");
    fs::create_dir(&sub).unwrap();
    fs::set_permissions(&sub, fs::Permissions::from_mode(0o775)).unwrap();
    let inner = sub.join("s.sh");
    fs::write(&inner, "#!/bin/sh\nexit 1\n").unwrap();
    fs::set_permissions(&inner, fs::Permissions::from_mode(0o755)).unwrap();
    let f = d.signer_file("gwdir.json", &SEED, &[inner.to_str().unwrap()], "");
    let e = load(&f).unwrap_err();
    assert!(e.contains("directory") && e.contains("writable"), "{e}");

    // A command that is not executable, a relative command.
    let ne = d.path("noexec.sh");
    fs::write(&ne, "#!/bin/sh\n").unwrap();
    fs::set_permissions(&ne, fs::Permissions::from_mode(0o644)).unwrap();
    let f = d.signer_file("ne.json", &SEED, &[ne.to_str().unwrap()], "");
    assert!(load(&f).unwrap_err().contains("executable"));
    let f = d.signer_file("rel.json", &SEED, &["sign.sh"], "");
    assert!(load(&f).unwrap_err().contains("absolute"));

    // The command is checked again at signing time: made writable after
    // loading, it is refused.
    let late = d.script("late.sh", "exit 1");
    let f = d.signer_file("late.json", &SEED, &[late.to_str().unwrap()], "");
    let s = load(&f).unwrap();
    fs::set_permissions(&late, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(s.sign(b"x").unwrap_err().to_string().contains("writable"));
}

#[test]
fn key_files_still_load_and_non_signing_keys_are_refused() {
    let d = Dir::new("keyfiles");
    let kf = KeyFile::ed25519_from_seed(&SEED, Some("op-1")).unwrap();
    let p = d.path("op.key");
    kf.write_new(&p).unwrap();
    let s = load(&p).unwrap();
    assert_eq!(s.backend(), Backend::File);
    assert_eq!(s.key_id(), "op-1");
    assert_eq!(s.public_key(), public_key_from_seed(&SEED));
    let sig = s.sign(b"m").unwrap();
    assert!(verify(&s.public_key(), b"m", &sig));

    // The public half cannot sign.
    let pubp = d.path("op.key.pub");
    kf.to_public().unwrap().write_new(&pubp).unwrap();
    assert!(load(&pubp).is_err());
    // HMAC keys cannot sign documents.
    let h = d.path("h.key");
    KeyFile::generate_hmac(Some("h"))
        .unwrap()
        .write_new(&h)
        .unwrap();
    assert!(load(&h).unwrap_err().contains("cannot sign"));
    // A secret key file readable by others is refused (blackbox rule).
    let loose = d.path("loose.key");
    KeyFile::ed25519_from_seed(&SEED, Some("l"))
        .unwrap()
        .write_new(&loose)
        .unwrap();
    fs::set_permissions(&loose, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(load(&loose).is_err());
    // Some other JSON is neither.
    let other = d.path("other.json");
    fs::write(&other, r#"{"format":"something-else"}"#).unwrap();
    assert!(load(&other).unwrap_err().contains("neither"));
}

// ------------------------------------------------------------ PKCS#11 --

const SOFTHSM_MODULES: &[&str] = &[
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib64/pkcs11/libsofthsm2.so",
];

fn adapter() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("adapters/robodr-signer-pkcs11")
}

/// Run a command, panicking with its output on failure.
fn run(c: &mut Command) -> Vec<u8> {
    let o = c.output().unwrap();
    assert!(
        o.status.success(),
        "{c:?}: {}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    o.stdout
}

#[test]
fn pkcs11_adapter_against_softhsm() {
    if std::env::var_os("ROBODR_PKCS11").is_none() {
        eprintln!("skipped: set ROBODR_PKCS11=1 (needs softhsm2 and opensc's pkcs11-tool)");
        return;
    }
    let module = SOFTHSM_MODULES
        .iter()
        .find(|m| Path::new(m).exists())
        .expect("libsofthsm2.so (apt install softhsm2)");
    let d = Dir::new("pkcs11");
    assert!(
        trusted_tree(&d),
        "ROBODR_PKCS11=1 needs a trusted test tree"
    );
    let conf = d.path("softhsm2.conf");
    fs::create_dir(d.path("tokens")).unwrap();
    fs::write(
        &conf,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
            d.path("tokens").display()
        ),
    )
    .unwrap();
    let env = |c: &mut Command| {
        c.env("SOFTHSM2_CONF", &conf);
    };
    let mut c = Command::new("softhsm2-util");
    c.args([
        "--init-token",
        "--free",
        "--label",
        "robodr-test",
        "--so-pin",
        "1234",
        "--pin",
        "4321",
    ]);
    env(&mut c);
    run(&mut c);
    let mut c = Command::new("pkcs11-tool");
    c.args([
        "--module",
        module,
        "--token-label",
        "robodr-test",
        "--login",
        "--pin",
        "4321",
    ])
    .args([
        "--keypairgen",
        "--key-type",
        "EC:edwards25519",
        "--id",
        "a1",
        "--label",
        "rel",
    ]);
    env(&mut c);
    run(&mut c);

    // The adapter writes the signer file, pinning the token's public key.
    let mut c = Command::new(adapter());
    c.args([
        "signer-file",
        "--module",
        module,
        "--token-label",
        "robodr-test",
        "--id",
        "a1",
    ])
    .args(["--key-id", "rel-hsm", "--pin-env", "ROBODR_TEST_P11_PIN"])
    .args(["--adapter", adapter().to_str().unwrap()]);
    env(&mut c);
    let text = String::from_utf8(run(&mut c)).unwrap();
    // SoftHSM finds its token store through SOFTHSM2_CONF: pass it too.
    let text = text.replace(
        r#""pass_env": ["ROBODR_TEST_P11_PIN"]"#,
        r#""pass_env": ["ROBODR_TEST_P11_PIN", "SOFTHSM2_CONF"]"#,
    );
    let f = d.path("signer.json");
    fs::write(&f, &text).unwrap();
    fs::set_permissions(&f, fs::Permissions::from_mode(0o644)).unwrap();

    // Sign in a child process that has the PIN and SOFTHSM2_CONF.
    let o = Command::new(env!("CARGO_BIN_EXE_robodr-signer"))
        .args(["check", "--key", f.to_str().unwrap()])
        .env("SOFTHSM2_CONF", &conf)
        .env("ROBODR_TEST_P11_PIN", "4321")
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["backend"], "external");
    assert_eq!(v["key_id"], "rel-hsm");
    assert_eq!(v["signature_verified"], true);

    // A wrong PIN is an error, not a signature.
    let o = Command::new(env!("CARGO_BIN_EXE_robodr-signer"))
        .args(["check", "--key", f.to_str().unwrap()])
        .env("SOFTHSM2_CONF", &conf)
        .env("ROBODR_TEST_P11_PIN", "0000")
        .output()
        .unwrap();
    assert!(!o.status.success());

    // A second key on the token, the file still pinned to the first:
    // pointing the command at it is caught by the pinned-key check.
    let mut c = Command::new("pkcs11-tool");
    c.args([
        "--module",
        module,
        "--token-label",
        "robodr-test",
        "--login",
        "--pin",
        "4321",
    ])
    .args([
        "--keypairgen",
        "--key-type",
        "EC:edwards25519",
        "--id",
        "b2",
        "--label",
        "other",
    ]);
    env(&mut c);
    run(&mut c);
    let swapped = d.path("swapped.json");
    fs::write(&swapped, text.replace(r#""--id", "a1""#, r#""--id", "b2""#)).unwrap();
    fs::set_permissions(&swapped, fs::Permissions::from_mode(0o644)).unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_robodr-signer"))
        .args(["check", "--key", swapped.to_str().unwrap()])
        .env("SOFTHSM2_CONF", &conf)
        .env("ROBODR_TEST_P11_PIN", "4321")
        .output()
        .unwrap();
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("does not verify"));
}
