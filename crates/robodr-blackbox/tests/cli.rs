//! The `robodr-blackbox` binary: keygen, verify (with keyrings), inspect.
mod common;
use common::*;
use robodr_blackbox::keys::{KeyFile, KEYRING_FORMAT};
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
    // Derived key id when none is given.
    let o = run(&["keygen", "--out", s(&d.sub("b.key"))]);
    assert!(String::from_utf8_lossy(&o.stdout).starts_with("hmac-sha256:"));
    assert_eq!(run(&["keygen"]).status.code(), Some(2));
    assert_eq!(run(&["frobnicate"]).status.code(), Some(2));
}

/// A log written with a key loaded from a key file made by `keygen`.
fn log_with_key_file(d: &TestDir) -> (std::path::PathBuf, std::path::PathBuf) {
    let k = d.sub("unit.key");
    assert!(run(&["keygen", "--out", s(&k)]).status.success());
    let key = KeyFile::load(&k).unwrap().hmac().unwrap();
    let dir = d.sub("log");
    let mut c = cfg(&dir, big());
    c.device_id = "ugv-01".into();
    let mut r = Recorder::open(c, Box::new(key), clock()).unwrap();
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
    // Without the checkpoint the shortened log looks fine ...
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
