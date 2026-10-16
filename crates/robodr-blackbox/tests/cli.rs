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
    let o = run(&["keygen", "--alg", "hmac", "--out", s(&d.sub("c.key"))]);
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
    // Two key files ...
    let o = run(&["verify", s(&dir), "--keyring", s(&pa), "--keyring", s(&pb)]);
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
    assert!(run(&["verify", s(&dir), "--keyring", s(&ring)])
        .status
        .success());
    // One key alone fails.
    assert_eq!(
        run(&["verify", s(&dir), "--keyring", s(&pa)]).status.code(),
        Some(1)
    );
    // The same key twice is ambiguous: refused.
    assert_eq!(
        run(&[
            "verify",
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
    let o = run(&["keygen", "--alg", "hmac", "--out", s(&k)]);
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
    let o = run(&["verify", s(&dir), "--keyring", s(&pa), "--keyring", s(&pb)]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains("mixed algorithms"), "{}", text(&o));
    let o = run(&[
        "verify",
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
