//! The `robodr-blackbox` binary: keygen, verify (with keyrings), inspect.
mod common;
use common::*;
use robodr_blackbox::keys::{self, KeyFile, KEYRING_FORMAT};
use robodr_blackbox::store::segment_file_name;
use robodr_blackbox::*;
use std::path::Path;
use std::process::{Command, Output};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_robodr-blackbox"))
}

fn run(args: &[&str]) -> Output {
    bin().args(args).output().unwrap()
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn keygen_writes_a_private_key_and_never_overwrites() {
    let d = TestDir::new("cli-keygen");
    let k = d.sub("unit.key");
    let o = run(&["keygen", "--out", s(&k), "--key-id", "ugv-01-2026"]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(String::from_utf8_lossy(&o.stdout).trim(), "ugv-01-2026");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(&k).unwrap().permissions().mode() & 0o777;
        assert_eq!(m, 0o600);
    }
    let kf = KeyFile::load(&k).unwrap();
    assert_eq!(kf.key_id, "ugv-01-2026");
    assert!(!text(&o).contains(&robodr_blackbox::crypto::to_hex(kf.secret())));
    let before = std::fs::read(&k).unwrap();
    let o = run(&["keygen", "--out", s(&k)]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert_eq!(std::fs::read(&k).unwrap(), before);
    #[cfg(unix)]
    {
        let link = d.sub("link.key");
        std::os::unix::fs::symlink(d.sub("target.key"), &link).unwrap();
        let o = run(&["keygen", "--out", s(&link)]);
        assert_eq!(o.status.code(), Some(2));
        assert!(!d.sub("target.key").exists());
    }
    // Derived key id when none is given (ed25519 by default).
    let o = run(&["keygen", "--out", s(&d.sub("b.key"))]);
    assert!(String::from_utf8_lossy(&o.stdout).starts_with("ed25519:"));
    let o = run(&[
        "keygen",
        "--alg",
        "hmac",
        "--allow-hmac",
        "--out",
        s(&d.sub("c.key")),
    ]);
    assert!(String::from_utf8_lossy(&o.stdout).starts_with("hmac-sha256:"));
    assert_eq!(run(&["keygen"]).status.code(), Some(2));
    assert_eq!(run(&["frobnicate"]).status.code(), Some(2));
}

/// A log written with a key loaded from a key file made by `keygen`.
fn log_with_key_file(d: &TestDir) -> (std::path::PathBuf, std::path::PathBuf) {
    let k = d.sub("unit.key");
    assert!(run(&["keygen", "--out", s(&k)]).status.success());
    let key = KeyFile::load(&k).unwrap().signer().unwrap();
    let dir = d.sub("log");
    let mut c = cfg(&dir, big());
    c.device_id = "ugv-01".into();
    let mut r = Recorder::open(c, key, clock()).unwrap();
    for i in 0..20 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    r.close().unwrap();
    (k, dir)
}

#[test]
fn verify_exit_codes_and_permission_check() {
    let d = TestDir::new("cli-verify");
    let (k, dir) = log_with_key_file(&d);
    let o = run(&["verify", s(&dir), "--keyring", s(&k)]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("INTACT, CLEAN"));
    let o = run(&["verify", s(&dir), "--keyring", s(&k), "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert!(v["findings"].is_array());
    let o = run(&["verify", s(&dir), "--keyring", s(&k), "--device", "other"]);
    assert_eq!(o.status.code(), Some(1));

    // Group-readable key file: refused before anything is verified.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o640)).unwrap();
        let o = run(&["verify", s(&dir), "--keyring", s(&k)]);
        assert_eq!(o.status.code(), Some(2));
        assert!(text(&o).contains("chmod 600"), "{}", text(&o));
        std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    // Wrong key: verification fails.
    let other = d.sub("other.key");
    assert!(run(&["keygen", "--out", s(&other)]).status.success());
    let o = run(&["verify", s(&dir), "--keyring", s(&other)]);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(text(&o).contains("TAMPER"));

    // Tampered record: verification fails.
    let seg = dir.join(segment_file_name(0));
    let mut b = std::fs::read(&seg).unwrap();
    let (o5, _, _) = frames(&b)[5];
    b[o5 + 80] ^= 1;
    std::fs::write(&seg, &b).unwrap();
    let o = run(&["verify", s(&dir), "--keyring", s(&k)]);
    assert_eq!(o.status.code(), Some(1));

    // Usage errors.
    assert_eq!(run(&["verify", s(&dir)]).status.code(), Some(2));
    assert_eq!(run(&["verify", "--keyring", s(&k)]).status.code(), Some(2));
    assert_eq!(
        run(&["verify", s(&d.sub("nope")), "--keyring", s(&k)])
            .status
            .code(),
        Some(2)
    );
}

#[test]
fn verify_with_external_checkpoint_and_strict() {
    let d = TestDir::new("cli-cp");
    let (k, dir) = log_with_key_file(&d);
    let cp = d.sub("cp.json");
    std::fs::copy(dir.join("checkpoint.json"), &cp).unwrap();
    // Truncate the log below the checkpoint (whole frames).
    let last = robodr_blackbox::store::list_segments(&dir).unwrap();
    let seg = last.last().unwrap().1.clone();
    let b = std::fs::read(&seg).unwrap();
    let fr = frames(&b);
    std::fs::write(&seg, &b[..fr[fr.len() - 3].0]).unwrap();
    std::fs::remove_file(dir.join("checkpoint.json")).unwrap();
    // The local high-water mark (head.json) still exposes it ...
    let o = run(&["verify", s(&dir), "--keyring", s(&k)]);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    // ... without any local mark the shortened log looks fine ...
    std::fs::remove_file(dir.join("head.json")).unwrap();
    assert!(run(&["verify", s(&dir), "--keyring", s(&k)])
        .status
        .success());
    // ... the off-unit checkpoint exposes it.
    let o = run(&[
        "verify",
        s(&dir),
        "--keyring",
        s(&k),
        "--checkpoint",
        s(&cp),
    ]);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(text(&o).contains("checkpoint"));
    std::fs::write(&cp, "not a checkpoint").unwrap();
    let o = run(&[
        "verify",
        s(&dir),
        "--keyring",
        s(&k),
        "--checkpoint",
        s(&cp),
    ]);
    assert_eq!(o.status.code(), Some(2));

    // A torn tail is a warning: fine by default, a failure with --strict.
    let mut b = std::fs::read(&seg).unwrap();
    b.extend_from_slice(b"RBF1\x00\x00");
    std::fs::write(&seg, &b).unwrap();
    let o = run(&["verify", s(&dir), "--keyring", s(&k)]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("WITH WARNINGS"));
    let o = run(&["verify", s(&dir), "--keyring", s(&k), "--strict"]);
    assert_eq!(o.status.code(), Some(1));
}

#[test]
fn verify_across_a_rotation_with_a_keyring_file() {
    let d = TestDir::new("cli-rot");
    let ka = KeyFile::generate_hmac(Some("a")).unwrap();
    let kb = KeyFile::generate_hmac(Some("b")).unwrap();
    let dir = d.sub("log");
    let mut r = Recorder::open(cfg(&dir, big()), Box::new(ka.hmac().unwrap()), clock()).unwrap();
    recorded(r.append_note(&note(0), false).unwrap());
    r.rotate_key(Box::new(kb.hmac().unwrap()), None, "t")
        .unwrap();
    recorded(r.append_note(&note(1), false).unwrap());
    r.close().unwrap();
    let pa = d.sub("a.key");
    let pb = d.sub("b.key");
    ka.write_new(&pa).unwrap();
    kb.write_new(&pb).unwrap();
    // Legacy HMAC keys are refused without the explicit opt-in ...
    let o = run(&["verify", s(&dir), "--keyring", s(&pa), "--keyring", s(&pb)]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains("legacy hmac-sha256"), "{}", text(&o));
    // ... two key files with it ...
    let o = run(&[
        "verify",
        s(&dir),
        "--keyring",
        s(&pa),
        "--keyring",
        s(&pb),
        "--allow-hmac",
    ]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("signing key rotated a -> b"));
    // ... or one keyring file.
    let ring = d.sub("ring.json");
    let json = format!(
        "{{\"format\":\"{KEYRING_FORMAT}\",\"keys\":[{},{}]}}",
        ka.to_json().trim(),
        kb.to_json().trim()
    );
    {
        use std::io::Write;
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        o.open(&ring).unwrap().write_all(json.as_bytes()).unwrap();
    }
    assert!(
        run(&["verify", "--allow-hmac", s(&dir), "--keyring", s(&ring)])
            .status
            .success()
    );
    // One key alone fails.
    assert_eq!(
        run(&["verify", "--allow-hmac", s(&dir), "--keyring", s(&pa)])
            .status
            .code(),
        Some(1)
    );
    // The same key twice is ambiguous: refused.
    assert_eq!(
        run(&[
            "verify",
            "--allow-hmac",
            s(&dir),
            "--keyring",
            s(&pa),
            "--keyring",
            s(&ring)
        ])
        .status
        .code(),
        Some(2)
    );
}

#[test]
fn inspect_lists_frames_without_verdict() {
    let d = TestDir::new("cli-inspect");
    let (_, dir) = log_with_key_file(&d);
    let o = run(&["inspect", s(&dir)]);
    assert!(o.status.success(), "{}", text(&o));
    let t = text(&o);
    assert!(t.contains("seq 0 genesis") && t.contains("note"), "{t}");
    assert!(t.contains("signatures not checked"));
    let o = run(&["inspect", s(&dir), "--json", "--limit", "3"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["frames"].as_array().unwrap().len(), 3);
    assert_eq!(v["signatures_checked"], false);
    assert!(v["checkpoint"]["seq"].is_u64());
    let o = run(&["inspect", s(&dir.join(segment_file_name(0)))]);
    assert!(o.status.success());
    // Noise never panics.
    let junk = d.sub("junk.rbb");
    std::fs::write(&junk, b"RBF1\xff\xff\xff\xffgarbage").unwrap();
    assert!(run(&["inspect", s(&junk)]).status.success());
    assert_eq!(run(&["inspect"]).status.code(), Some(2));
    assert_eq!(
        run(&["inspect", s(&dir), "--limit", "x"]).status.code(),
        Some(2)
    );
}

/// An argument that is not valid UTF-8 is a usage error (exit 2), never a
/// panic.
#[test]
fn non_utf8_argument_is_a_usage_error() {
    use std::os::unix::ffi::OsStrExt;
    for args in [vec![&b"\xff"[..]], vec![b"verify", b"/tmp/\xc0"]] {
        let o = bin()
            .args(args.iter().map(|a| std::ffi::OsStr::from_bytes(a)))
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(2), "{}", text(&o));
        assert!(!text(&o).contains("panicked"), "{}", text(&o));
    }
}

fn mode_of(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

fn set_mode(p: &Path, m: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
}

#[test]
fn keygen_ed25519_writes_a_secret_and_a_public_file() {
    let d = TestDir::new("cli-keygen-ed");
    let k = d.sub("unit.key");
    let o = run(&[
        "keygen",
        "--alg",
        "ed25519",
        "--out",
        s(&k),
        "--key-id",
        "ugv-02",
    ]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(String::from_utf8_lossy(&o.stdout).trim(), "ugv-02");
    let pubp = d.sub("unit.key.pub");
    assert_eq!(mode_of(&k), 0o600);
    assert_eq!(mode_of(&pubp), 0o644);
    let sk = KeyFile::load(&k).unwrap();
    let pk = KeyFile::load(&pubp).unwrap();
    assert_eq!(sk.algorithm, "ed25519");
    assert!(!sk.is_public() && pk.is_public());
    assert_eq!(sk.public_key(), pk.public_key());
    assert_eq!(pk.key_id, "ugv-02");
    // The seed is in neither stdout/stderr nor the public file.
    let seed = robodr_blackbox::crypto::to_hex(sk.secret());
    assert!(!text(&o).contains(&seed));
    assert!(!std::fs::read_to_string(&pubp).unwrap().contains(&seed));
    assert!(!text(&o).contains("warning"));

    // If the public target exists, nothing at all is written.
    let k2 = d.sub("two.key");
    std::fs::write(d.sub("two.key.pub"), "x").unwrap();
    let o = run(&["keygen", "--out", s(&k2)]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(!k2.exists());
    // Explicit --pub-out.
    let k3 = d.sub("three.key");
    let p3 = d.sub("pubs-three");
    let o = run(&["keygen", "--out", s(&k3), "--pub-out", s(&p3)]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(KeyFile::load_public(&p3).is_ok());
    assert!(!d.sub("three.key.pub").exists());
    // Same path twice, unknown algorithm, --pub-out with hmac.
    let k4 = d.sub("four.key");
    assert_eq!(
        run(&["keygen", "--out", s(&k4), "--pub-out", s(&k4)])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        run(&["keygen", "--out", s(&k4), "--alg", "rsa"])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        run(&[
            "keygen",
            "--out",
            s(&k4),
            "--alg",
            "hmac",
            "--pub-out",
            s(&p3)
        ])
        .status
        .code(),
        Some(2)
    );
    assert!(!k4.exists());
}

#[test]
fn keygen_hmac_is_legacy_and_warns() {
    let d = TestDir::new("cli-keygen-hmac");
    let k = d.sub("h.key");
    // Refused by default: nothing is written.
    let o = run(&["keygen", "--alg", "hmac", "--out", s(&k)]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains("--allow-hmac"), "{}", text(&o));
    assert!(!k.exists());
    let o = run(&["keygen", "--alg", "hmac", "--allow-hmac", "--out", s(&k)]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(String::from_utf8_lossy(&o.stderr).contains("symmetric"));
    assert!(!d.sub("h.key.pub").exists());
    let kf = KeyFile::load(&k).unwrap();
    assert!(kf.is_symmetric());
    assert!(std::fs::read_to_string(&k)
        .unwrap()
        .contains("robodr-blackbox-key/v1"));
    // HMAC has no public half.
    let o = run(&["export-pub", s(&k)]);
    assert_eq!(o.status.code(), Some(2));
    assert!(text(&o).contains("no public key"), "{}", text(&o));
}

#[test]
fn export_pub_matches_keygen_and_checks_permissions() {
    let d = TestDir::new("cli-export");
    let k = d.sub("e.key");
    assert!(run(&["keygen", "--out", s(&k)]).status.success());
    let o = run(&["export-pub", s(&k)]);
    assert!(o.status.success(), "{}", text(&o));
    let printed = String::from_utf8_lossy(&o.stdout).to_string();
    assert_eq!(
        printed,
        std::fs::read_to_string(d.sub("e.key.pub")).unwrap()
    );
    assert!(!printed.contains("secret_hex"));
    let out = d.sub("copy.pub");
    let o = run(&["export-pub", s(&k), "--out", s(&out)]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(std::fs::read_to_string(&out).unwrap(), printed);
    assert_eq!(mode_of(&out), 0o644);
    // Never overwrites.
    assert_eq!(
        run(&["export-pub", s(&k), "--out", s(&out)]).status.code(),
        Some(2)
    );
    // Exporting from a public file re-emits it.
    let o = run(&["export-pub", s(&out)]);
    assert_eq!(String::from_utf8_lossy(&o.stdout), printed);
    // A secret readable by others is refused.
    set_mode(&k, 0o644);
    let o = run(&["export-pub", s(&k)]);
    assert_eq!(o.status.code(), Some(2));
    assert!(text(&o).contains("chmod 600"), "{}", text(&o));
    assert_eq!(run(&["export-pub"]).status.code(), Some(2));
}

#[test]
fn verify_with_only_the_public_key() {
    let d = TestDir::new("cli-pub-verify");
    let (k, dir) = log_with_key_file(&d);
    let pubp = d.sub("unit.key.pub");
    // World-readable public key: fine.
    set_mode(&pubp, 0o644);
    let o = run(&["verify", s(&dir), "--keyring", s(&pubp)]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("INTACT, CLEAN"));
    assert!(text(&o).contains("ed25519"));
    assert!(!text(&o).contains("warning"));
    // Another unit's public key: tamper verdict.
    let other = d.sub("other.key");
    assert!(run(&["keygen", "--out", s(&other)]).status.success());
    let o = run(&[
        "verify",
        s(&dir),
        "--keyring",
        &format!("{}.pub", s(&other)),
    ]);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    // The secret, world-readable: refused.
    set_mode(&k, 0o604);
    let o = run(&["verify", s(&dir), "--keyring", s(&k)]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
}

#[test]
fn keygen_device_binding_and_verify_refuses_other_units_keys() {
    let d = TestDir::new("cli-bind");
    let k = d.sub("unit.key");
    let o = run(&["keygen", "--out", s(&k), "--device", "ugv-01"]);
    assert!(o.status.success(), "{}", text(&o));
    let pubk = KeyFile::load(&keys::public_key_path(&k)).unwrap();
    assert_eq!(pubk.device_id.as_deref(), Some("ugv-01"));
    assert_eq!(
        KeyFile::load(&k).unwrap().device_id.as_deref(),
        Some("ugv-01")
    );
    for bad in [
        &["--device", "has space"][..],
        &["--device", "a", "--device", "b"],
    ] {
        let mut args = vec!["keygen", "--out"];
        let p = d.sub("bad.key");
        args.push(s(&p));
        args.extend_from_slice(bad);
        assert_eq!(run(&args).status.code(), Some(2));
        assert!(!p.exists());
    }

    // A log of ugv-01 signed by that key verifies with its public file...
    let dir = d.sub("log");
    let mut c = cfg(&dir, big());
    c.device_id = "ugv-01".into();
    let signer = KeyFile::load(&k).unwrap().signer().unwrap();
    let mut r = Recorder::open(c, signer, clock()).unwrap();
    recorded(r.append_note(&note(0), false).unwrap());
    r.close().unwrap();
    let pp = keys::public_key_path(&k);
    let o = run(&["verify", s(&dir), "--keyring", s(&pp)]);
    assert!(o.status.success(), "{}", text(&o));
    // ... but the same key bound to another unit is refused.
    let other_pub = d.sub("other.pub");
    pubk.with_device_id(Some("ugv-02"))
        .unwrap()
        .write_new(&other_pub)
        .unwrap();
    let o = run(&["verify", s(&dir), "--keyring", s(&other_pub)]);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
}

#[test]
fn verify_mixing_hmac_and_ed25519_needs_an_explicit_flag() {
    let d = TestDir::new("cli-mixed");
    let ka = KeyFile::generate_hmac(Some("a")).unwrap();
    let kb = KeyFile::generate_ed25519(Some("b")).unwrap();
    let dir = d.sub("log");
    let mut r = Recorder::open(cfg(&dir, big()), Box::new(ka.hmac().unwrap()), clock()).unwrap();
    recorded(r.append_note(&note(0), false).unwrap());
    r.rotate_key(kb.signer().unwrap(), None, "move to ed25519")
        .unwrap();
    recorded(r.append_note(&note(1), false).unwrap());
    r.close().unwrap();
    let (pa, pb) = (d.sub("a.key"), d.sub("b.pub"));
    ka.write_new(&pa).unwrap();
    kb.to_public().unwrap().write_new(&pb).unwrap();
    let o = run(&[
        "verify",
        "--allow-hmac",
        s(&dir),
        "--keyring",
        s(&pa),
        "--keyring",
        s(&pb),
    ]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains("mixed algorithms"), "{}", text(&o));
    let o = run(&[
        "verify",
        "--allow-hmac",
        s(&dir),
        "--keyring",
        s(&pa),
        "--keyring",
        s(&pb),
        "--allow-mixed-algorithms",
    ]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("INTACT, CLEAN"), "{}", text(&o));
}

/// `verify BUNDLE`: an `RBBXBND1` export bundle (as the control-plane
/// evidence API ships one) verifies with the unit's public key file; a
/// flipped byte, another device or a wrong key fail; directory-only
/// options are usage errors.
#[test]
fn verify_an_export_bundle_file() {
    let d = TestDir::new("cli-verify-bundle");
    let k = d.sub("unit.key");
    assert!(run(&["keygen", "--out", s(&k)]).status.success());
    let key = KeyFile::load(&k).unwrap().signer().unwrap();
    let dir = d.sub("log");
    let mut c = cfg(&dir, big());
    c.device_id = "ugv-01".into();
    let mut r = Recorder::open(c, key, clock()).unwrap();
    for i in 0..20 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let b = r.export_pending(None).unwrap().unwrap();
    r.mark_exported(&b).unwrap();
    for i in 20..30 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    // A bundle that starts mid-chain (with an anchor).
    let b2 = r.export_pending(None).unwrap().unwrap();
    assert!(b2.anchor.is_some());
    r.close().unwrap();
    let pubk = d.sub("unit.key.pub");
    for (name, bundle) in [("b1.rbbx", &b), ("b2.rbbx", &b2)] {
        let f = d.sub(name);
        std::fs::write(&f, bundle.to_bytes()).unwrap();
        let o = run(&["verify", s(&f), "--keyring", s(&pubk), "--device", "ugv-01"]);
        assert!(o.status.success(), "{name}: {}", text(&o));
        assert!(text(&o).contains("RESULT: INTACT"), "{}", text(&o));
        let o = run(&["verify", s(&f), "--keyring", s(&pubk), "--json"]);
        let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
        assert!(v["verified_records"].as_u64().unwrap() > 0);
        let o = run(&["verify", s(&f), "--keyring", s(&pubk), "--device", "other"]);
        assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    }
    let f = d.sub("b2.rbbx");
    // The signing key named explicitly (as the manifest does).
    let id = KeyFile::load(&pubk).unwrap().key_id.clone();
    let o = run(&["verify", s(&f), "--keyring", s(&pubk), "--signing-key", &id]);
    assert!(o.status.success(), "{}", text(&o));
    let o = run(&[
        "verify",
        s(&f),
        "--keyring",
        s(&pubk),
        "--signing-key",
        "nope",
    ]);
    assert_eq!(o.status.code(), Some(2));
    // A flipped byte in a frame.
    let mut bytes = std::fs::read(&f).unwrap();
    let n = bytes.len();
    bytes[n - 100] ^= 1;
    let t = d.sub("t.rbbx");
    std::fs::write(&t, &bytes).unwrap();
    let o = run(&["verify", s(&t), "--keyring", s(&pubk)]);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    // Not a bundle; a checkpoint option on a bundle.
    let junk = d.sub("junk.rbbx");
    std::fs::write(&junk, b"RBBXBND1 not really").unwrap();
    assert_eq!(
        run(&["verify", s(&junk), "--keyring", s(&pubk)])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        run(&[
            "verify",
            s(&f),
            "--keyring",
            s(&pubk),
            "--checkpoint",
            s(&junk)
        ])
        .status
        .code(),
        Some(2)
    );
    // Another key: tamper.
    let other = d.sub("other.key");
    assert!(run(&["keygen", "--out", s(&other)]).status.success());
    let o = run(&["verify", s(&f), "--keyring", s(&d.sub("other.key.pub"))]);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
}

/// `--version` prints `<name> <version>` and `--help` the usage, both on
/// stdout with exit 0 (the release .deb smoke test runs both on every
/// shipped binary); misuse of either stays a usage error (exit 2).
#[test]
fn version_and_help_exit_0() {
    for (name, exe) in [
        ("robodr-blackbox", env!("CARGO_BIN_EXE_robodr-blackbox")),
        (
            "robodr-anchor-receiver",
            env!("CARGO_BIN_EXE_robodr-anchor-receiver"),
        ),
    ] {
        let o = std::process::Command::new(exe)
            .arg("--version")
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(0), "{name} --version");
        assert_eq!(
            String::from_utf8_lossy(&o.stdout),
            // Names the build (commit, SOURCE_DATE_EPOCH, target), not only the version.
            format!(
                "{}\n",
                robodr_buildinfo::version_line(name, env!("CARGO_PKG_VERSION"))
            ),
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

/// Write `k` (secret) and its public half next to it; returns both paths.
fn write_pair(d: &TestDir, name: &str, k: &KeyFile) -> (std::path::PathBuf, std::path::PathBuf) {
    let sk = d.sub(&format!("{name}.key"));
    let pk = d.sub(&format!("{name}.key.pub"));
    k.write_new(&sk).unwrap();
    if !k.is_symmetric() {
        k.to_public().unwrap().write_new(&pk).unwrap();
    }
    (sk, pk)
}

fn rotate_args<'a>(dir: &'a Path, old: &'a Path, new: &'a Path) -> Vec<&'a str> {
    vec![
        "rotate",
        s(dir),
        "--old-key",
        s(old),
        "--new-key",
        s(new),
        "--device",
        "ugv-01",
        "--boot-id",
        "boot-rot",
    ]
}

/// `rotate`: a log signed with key A, rotated in place to key B, continues
/// with B and verifies with both public keys; the writer reopens it only
/// with A as a previous key (without it: refused, naming the remedy); a
/// second rotation B -> C needs A in `--previous-keys`; re-running is a
/// no-op.
#[test]
fn rotate_continues_the_chain_under_the_new_key() {
    let d = TestDir::new("cli-rotate");
    let ka = KeyFile::generate_ed25519(Some("bb-a")).unwrap();
    let kb = KeyFile::generate_ed25519(Some("bb-b")).unwrap();
    let kc = KeyFile::generate_ed25519(Some("bb-c")).unwrap();
    let (sa, pa) = write_pair(&d, "a", &ka);
    let (sb, pb) = write_pair(&d, "b", &kb);
    let (_, pc) = write_pair(&d, "c", &kc);
    let sc = d.sub("c.key");
    let dir = d.sub("log");
    let mut r = Recorder::open(cfg(&dir, big()), ka.signer().unwrap(), clock()).unwrap();
    for i in 0..5 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let chain = r.chain_id();
    r.close().unwrap();

    let o = run(&rotate_args(&dir, &sa, &sb));
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(String::from_utf8_lossy(&o.stdout).trim(), "bb-b");
    assert!(text(&o).contains("previous_keys"), "{}", text(&o));
    // Idempotent: the log is keyed bb-b now.
    let o = run(&rotate_args(&dir, &sa, &sb));
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("already rotated"), "{}", text(&o));

    // The writer with B alone fails closed ...
    let e = Recorder::open(cfg(&dir, big()), kb.signer().unwrap(), clock()).unwrap_err();
    assert!(e.to_string().contains("previous key"), "{e}");
    // ... with A as a previous key it continues the same chain.
    let prev = PreviousKeys::from_key_files(&[KeyFile::load(&pa).unwrap()], false).unwrap();
    let mut r = Recorder::open_with_keys(
        cfg(&dir, big()),
        kb.signer().unwrap(),
        None,
        Some(Box::new(prev)),
        clock(),
    )
    .unwrap();
    assert_eq!(r.chain_id(), chain);
    assert_eq!(r.key_id(), "bb-b");
    recorded(r.append_note(&note(99), false).unwrap());
    r.close().unwrap();

    // Verifiers need both public keys.
    let o = run(&["verify", s(&dir), "--keyring", s(&pa), "--keyring", s(&pb)]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(
        text(&o).contains("signing key rotated bb-a -> bb-b"),
        "{}",
        text(&o)
    );
    assert_eq!(
        run(&["verify", s(&dir), "--keyring", s(&pb)]).status.code(),
        Some(1)
    );

    // Second rotation: the records of A need A as a previous key.
    let o = run(&rotate_args(&dir, &sb, &sc));
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains("--previous-keys"), "{}", text(&o));
    let mut args = rotate_args(&dir, &sb, &sc);
    args.extend(["--previous-keys", s(&pa), "--reason", "scheduled"]);
    let o = run(&args);
    assert!(o.status.success(), "{}", text(&o));
    let o = run(&[
        "verify",
        s(&dir),
        "--keyring",
        s(&pa),
        "--keyring",
        s(&pb),
        "--keyring",
        s(&pc),
    ]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("bb-b -> bb-c"), "{}", text(&o));
}

/// `rotate` refusals: legacy HMAC old key without `--allow-hmac` (with it:
/// the migration to ed25519 works), an HMAC target, the same key id, the
/// wrong old key, a missing log.
#[test]
fn rotate_refusals_and_the_hmac_migration() {
    let d = TestDir::new("cli-rotate-refuse");
    let kh = KeyFile::generate_hmac(Some("bb-h")).unwrap();
    let ke = KeyFile::generate_ed25519(Some("bb-e")).unwrap();
    let kh2 = KeyFile::generate_hmac(Some("bb-h2")).unwrap();
    let (sh, _) = write_pair(&d, "h", &kh);
    let (se, pe) = write_pair(&d, "e", &ke);
    let (sh2, _) = write_pair(&d, "h2", &kh2);
    let dir = d.sub("log");
    let mut r = Recorder::open(cfg(&dir, big()), kh.signer().unwrap(), clock()).unwrap();
    recorded(r.append_note(&note(0), false).unwrap());
    r.close().unwrap();

    let nolog = d.sub("nolog");
    let o = run(&rotate_args(&nolog, &sh, &se));
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    let o = run(&rotate_args(&dir, &sh, &se));
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains("--allow-hmac"), "{}", text(&o));
    let mut a = rotate_args(&dir, &sh, &sh2);
    a.push("--allow-hmac");
    let o = run(&a);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains("must be ed25519"), "{}", text(&o));
    assert_eq!(run(&rotate_args(&dir, &se, &se)).status.code(), Some(2));
    // Wrong old key: the log is keyed bb-h.
    let ke2 = KeyFile::generate_ed25519(Some("bb-e2")).unwrap();
    let (se2, _) = write_pair(&d, "e2", &ke2);
    let o = run(&rotate_args(&dir, &se2, &se));
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains("--old-key must be"), "{}", text(&o));

    // The migration off HMAC, explicitly allowed.
    let mut a = rotate_args(&dir, &sh, &se);
    a.push("--allow-hmac");
    let o = run(&a);
    assert!(o.status.success(), "{}", text(&o));
    let o = run(&[
        "verify",
        s(&dir),
        "--keyring",
        s(&sh),
        "--keyring",
        s(&pe),
        "--allow-hmac",
        "--allow-mixed-algorithms",
    ]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("bb-h -> bb-e"), "{}", text(&o));
}

/// `rotate --previous-keys` gets robodr-agentd's `previous_keys` checks: a
/// secret key file (the retired signing key left on disk), a key bound to
/// another unit, or a group-writable trust file is refused; a public file
/// of this unit works. `--tpm-sidecar` names a sidecar to re-sign (none
/// here: reported, not an error).
#[test]
fn rotate_previous_keys_get_the_agentd_checks() {
    let d = TestDir::new("cli-rotate-prev");
    let ka = KeyFile::generate_ed25519(Some("bb-a")).unwrap();
    let kb = KeyFile::generate_ed25519(Some("bb-b")).unwrap();
    let kc = KeyFile::generate_ed25519(Some("bb-c")).unwrap();
    let mut kf = KeyFile::generate_ed25519(Some("bb-f")).unwrap();
    kf.device_id = Some("ugv-99".into());
    let (sa, pa) = write_pair(&d, "a", &ka);
    let (sb, _) = write_pair(&d, "b", &kb);
    let (sc, _) = write_pair(&d, "c", &kc);
    let (_, pf) = write_pair(&d, "f", &kf);
    let dir = d.sub("log");
    let mut r = Recorder::open(cfg(&dir, big()), ka.signer().unwrap(), clock()).unwrap();
    recorded(r.append_note(&note(0), false).unwrap());
    r.close().unwrap();
    assert!(run(&rotate_args(&dir, &sa, &sb)).status.success());

    let attempt = |prev: &Path| {
        let mut a = rotate_args(&dir, &sb, &sc);
        a.extend(["--previous-keys", s(prev)]);
        run(&a)
    };
    let o = attempt(&sa);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains("secret key file"), "{}", text(&o));
    let mut a = rotate_args(&dir, &sb, &sc);
    a.extend(["--previous-keys", s(&pa), "--previous-keys", s(&pf)]);
    let o = run(&a);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains("bound to device"), "{}", text(&o));
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&pa, std::fs::Permissions::from_mode(0o664)).unwrap();
        let o = attempt(&pa);
        assert_eq!(o.status.code(), Some(2), "{}", text(&o));
        assert!(text(&o).contains("trust anchor"), "{}", text(&o));
        std::fs::set_permissions(&pa, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let sidecar = d.sub("tpm-sidecar.json");
    let mut a = rotate_args(&dir, &sb, &sc);
    a.extend(["--previous-keys", s(&pa), "--tpm-sidecar", s(&sidecar)]);
    let o = run(&a);
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("no TPM anchor sidecar"), "{}", text(&o));
}

/// T15: `export-pending` writes bundles that `verify` accepts, advances the
/// cursor, and on a second run has nothing to do; a wrong device is a
/// usage error and writes nothing.
#[test]
fn export_pending_writes_verifiable_bundles_and_advances_the_cursor() {
    let d = TestDir::new("cli-export-pending");
    let (k, dir) = log_with_key_file(&d);
    let out = d.sub("outbox");
    std::fs::create_dir(&out).unwrap();
    let o = run(&[
        "export-pending",
        s(&dir),
        "--key",
        s(&k),
        "--device",
        "other-unit",
        "--out-dir",
        s(&out),
    ]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(!dir.join(robodr_blackbox::store::CURSOR_FILE).exists());
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0);
    let o = run(&[
        "export-pending",
        s(&dir),
        "--key",
        s(&k),
        "--device",
        "ugv-01",
        "--out-dir",
        s(&out),
        "--max-records",
        "8",
    ]);
    assert!(o.status.success(), "{}", text(&o));
    let mut bundles: Vec<_> = std::fs::read_dir(&out)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    bundles.sort();
    assert!(bundles.len() >= 3, "{}", text(&o));
    for b in &bundles {
        let v = run(&["verify", s(b), "--keyring", s(&k), "--device", "ugv-01"]);
        assert!(v.status.success(), "{}", text(&v));
    }
    assert!(dir.join(robodr_blackbox::store::CURSOR_FILE).exists());
    let o = run(&[
        "export-pending",
        s(&dir),
        "--key",
        s(&k),
        "--device",
        "ugv-01",
        "--out-dir",
        s(&out),
    ]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("nothing pending"), "{}", text(&o));
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), bundles.len());
    // The recorder accepts the cursor the CLI wrote.
    let key = KeyFile::load(&k).unwrap().signer().unwrap();
    let mut c = cfg(&dir, big());
    c.device_id = "ugv-01".into();
    let r = Recorder::open(c, key, clock()).unwrap();
    assert!(r.export_cursor().is_some());
}

fn export_args<'a>(dir: &'a Path, k: &'a Path, out: &'a Path) -> Vec<&'a str> {
    vec![
        "export-pending",
        s(dir),
        "--key",
        s(k),
        "--device",
        "ugv-01",
        "--out-dir",
        s(out),
    ]
}

/// Review (WP4): `export-pending` streams the segments, so its memory is
/// bounded by `--max-bytes` and one frame, not by the segment size
/// (`blackbox.retention.segment_bytes` accepts 256 MiB; the service has
/// `MemoryMax=320M`). A 60 MiB segment exported under a 96 MiB
/// address-space limit.
#[cfg(target_os = "linux")]
#[test]
fn export_pending_memory_does_not_grow_with_the_segment() {
    let d = TestDir::new("cli-export-mem");
    let k = d.sub("unit.key");
    assert!(run(&["keygen", "--out", s(&k)]).status.success());
    let key = KeyFile::load(&k).unwrap().signer().unwrap();
    let dir = d.sub("log");
    let mut c = cfg(&dir, big());
    c.device_id = "ugv-01".into();
    c.max_segment_bytes = 256 * 1024 * 1024;
    let mut r = Recorder::open(c, key, clock()).unwrap();
    let pad = "x".repeat(60 * 1024);
    for i in 0..1000u64 {
        recorded(
            r.append_note(&serde_json::json!({ "i": i, "pad": pad }), false)
                .unwrap(),
        );
    }
    r.close().unwrap();
    let biggest = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().metadata().unwrap().len())
        .max()
        .unwrap();
    assert!(biggest > 55 * 1024 * 1024, "{biggest}");
    let out = d.sub("outbox");
    std::fs::create_dir(&out).unwrap();
    let mut args = export_args(&dir, &k, &out);
    args.extend(["--max-bytes", "4194304"]);
    let o = Command::new("sh")
        .arg("-c")
        .arg("ulimit -v 98304 && exec \"$@\"")
        .arg("sh")
        .arg(env!("CARGO_BIN_EXE_robodr-blackbox"))
        .args(&args)
        .output()
        .unwrap();
    assert!(o.status.success(), "{:?}: {}", o.status, text(&o));
    assert!(text(&o).contains("exported seq"), "{}", text(&o));
    let o = run(&args);
    assert!(text(&o).contains("nothing pending"), "{}", text(&o));
}

/// Review (WP4): the timer's failure signal. Records dropped before they
/// were exported: the CLI still writes the bundle of what is there, says
/// so, and exits 1.
#[test]
fn export_pending_gap_writes_the_bundle_and_exits_1() {
    let d = TestDir::new("cli-export-gap");
    let k = d.sub("unit.key");
    assert!(run(&["keygen", "--out", s(&k)]).status.success());
    let key = KeyFile::load(&k).unwrap().signer().unwrap();
    let dir = d.sub("log");
    let mut c = cfg(&dir, RetentionMode::Cyclic { max_segments: 2 });
    c.device_id = "ugv-01".into();
    let mut r = Recorder::open(c, key, clock()).unwrap();
    for i in 0..400 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    assert!(r.unexported_drops() > 0);
    r.close().unwrap();
    let out = d.sub("outbox");
    std::fs::create_dir(&out).unwrap();
    let o = run(&export_args(&dir, &k, &out));
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(
        text(&o).contains("EVIDENCE LOST BEFORE EXPORT: records 0..="),
        "{}",
        text(&o)
    );
    let bundles: Vec<_> = std::fs::read_dir(&out)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(bundles.len(), 1, "{}", text(&o));
    let v = run(&[
        "verify",
        s(&bundles[0]),
        "--keyring",
        s(&k),
        "--device",
        "ugv-01",
    ]);
    assert!(v.status.code().is_some(), "{}", text(&v));
    assert!(dir.join(robodr_blackbox::store::CURSOR_FILE).exists());
}

/// Review (WP4): after `robodr-blackbox rotate`, an exporter still holding
/// the old key (the timer's credential not yet replaced) is refused before
/// it writes anything: it would re-export everything and overwrite the
/// cursor the rotation re-signed with one the recorder ignores. The
/// cursor-ignored warning names the likely cause.
#[test]
fn export_pending_with_a_superseded_key_is_refused() {
    let d = TestDir::new("cli-export-stale-key");
    let (k_old, dir) = log_with_key_file(&d);
    let out = d.sub("outbox");
    std::fs::create_dir(&out).unwrap();
    // Export once, then rotate.
    let o = run(&export_args(&dir, &k_old, &out));
    assert!(o.status.success(), "{}", text(&o));
    let k_new = d.sub("unit-2.key");
    assert!(run(&[
        "keygen",
        "--out",
        s(&k_new),
        "--key-id",
        "ugv-01-bb-2",
        "--device",
        "ugv-01"
    ])
    .status
    .success());
    let o = run(&rotate_args(&dir, &k_old, &k_new));
    assert!(o.status.success(), "{}", text(&o));
    let cursor = std::fs::read(dir.join(robodr_blackbox::store::CURSOR_FILE)).unwrap();
    let before = std::fs::read_dir(&out).unwrap().count();
    let o = run(&export_args(&dir, &k_old, &out));
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains("rotat"), "{}", text(&o));
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), before);
    assert_eq!(
        std::fs::read(dir.join(robodr_blackbox::store::CURSOR_FILE)).unwrap(),
        cursor,
        "the re-signed cursor is untouched"
    );
    // With the new key (and the old public key for the records before the
    // rotation) the export continues from the cursor.
    let mut a = export_args(&dir, &k_new, &out);
    let pub_old = format!("{}.pub", s(&k_old));
    a.extend(["--previous-keys", &pub_old]);
    let o = run(&a);
    assert!(o.status.success(), "{}", text(&o));
    assert!(!text(&o).contains("cursor ignored"), "{}", text(&o));
}
