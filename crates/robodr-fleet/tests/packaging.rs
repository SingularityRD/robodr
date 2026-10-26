//! Update and rollback (GA-ROADMAP Sprint 9): `packaging/install-bundle.sh`
//! install -> upgrade -> rollback against the **real dpkg** of this host
//! (in a separate dpkg root, `ROBODR_ROOT`, with stub packages), the
//! black-box format gate on rollback and downgrade, ring information, and
//! the real `build-deb.sh` / `make-bundle.sh` output carrying
//! `robodr-enroll`, its man page and the formats file.
//!
//! The dpkg tests need root (dpkg extracts files as root:root). As non-root
//! they are reported and skipped, unless `ROBODR_REQUIRE_DPKG_TEST=1`, which
//! makes that a failure (CI runs them with sudo).

use robodr_blackbox::record::{FORMAT_VERSION, FRAME_MAGIC};
use robodr_blackbox::{HmacSha256Key, Recorder, RecorderConfig, SteppingClock, TimeSource};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A temporary directory, removed when dropped (also when a test fails).
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!(
            "robodr-fleet-pkg-{}-{}-{tag}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Self(d)
    }
}

impl std::ops::Deref for TempDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn sh(cmd: &mut Command) -> Output {
    cmd.output().unwrap()
}

fn ok(o: &Output) -> String {
    let t = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(o.status.success(), "failed: {t}");
    t
}

fn is_root() -> bool {
    robodr_blackbox::keys::effective_uid() == 0
}

fn have(tool: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {tool}")])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Whether the dpkg tests can run here (see the module docs).
fn dpkg_available(test: &str) -> bool {
    let ok = is_root() && have("dpkg") && have("dpkg-deb");
    if !ok {
        assert!(
            std::env::var("ROBODR_REQUIRE_DPKG_TEST").as_deref() != Ok("1"),
            "{test}: needs root and dpkg (ROBODR_REQUIRE_DPKG_TEST=1)"
        );
        eprintln!("SKIPPED {test}: needs root and dpkg");
    }
    ok
}

#[test]
fn formats_file_matches_the_black_box_code() {
    let text = std::fs::read_to_string(repo().join("packaging/formats")).unwrap();
    let current = format!(
        "{}:{}",
        std::str::from_utf8(&FRAME_MAGIC).unwrap(),
        FORMAT_VERSION
    );
    let get = |k: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{k}=")))
            .unwrap_or_else(|| panic!("{k} missing"))
            .to_string()
    };
    assert_eq!(get("blackbox_write"), current, "packaging/formats is stale");
    assert!(
        get("blackbox_read").split(',').any(|f| f == current),
        "this release must read what it writes"
    );
}

/// A stub `robodr` package: `formats` = Some((write, read)) or None (a
/// legacy release without the file).
fn stub_deb(dir: &Path, version: &str, formats: Option<(&str, &str)>) -> PathBuf {
    stub_deb_marked(dir, version, formats, "genuine")
}

/// [`stub_deb`] whose `usr/lib/robodr/stub-version` also names `marker`
/// (another package of the same name and version: a "genuine" one goes to
/// `dir`, any other to `dir/<marker>/`).
fn stub_deb_marked(
    dir: &Path,
    version: &str,
    formats: Option<(&str, &str)>,
    marker: &str,
) -> PathBuf {
    let out = if marker == "genuine" {
        dir.to_path_buf()
    } else {
        dir.join(marker)
    };
    let st = out.join(format!("stage-{version}"));
    std::fs::create_dir_all(st.join("DEBIAN")).unwrap();
    std::fs::create_dir_all(st.join("usr/lib/robodr")).unwrap();
    std::fs::write(
        st.join("DEBIAN/control"),
        format!(
            "Package: robodr\nVersion: {version}\nArchitecture: all\nMaintainer: test <t@invalid>\n\
             Description: stub robodr package for the install-bundle test\n"
        ),
    )
    .unwrap();
    std::fs::write(
        st.join("usr/lib/robodr/stub-version"),
        format!("{version} {marker}"),
    )
    .unwrap();
    if let Some((w, r)) = formats {
        std::fs::create_dir_all(st.join("usr/share/robodr")).unwrap();
        std::fs::write(
            st.join("usr/share/robodr/formats"),
            format!("blackbox_write={w}\nblackbox_read={r}\n"),
        )
        .unwrap();
    }
    let deb = out.join(format!("robodr_{version}_all.deb"));
    ok(&sh(Command::new("dpkg-deb")
        .args(["--root-owner-group", "-Zxz", "--build"])
        .arg(&st)
        .arg(&deb)));
    deb
}

/// An extracted bundle directory around `deb` (as make-bundle.sh lays it out).
fn bundle(dir: &Path, deb: &Path) -> PathBuf {
    let name = format!("bundle-{}", deb.file_name().unwrap().to_string_lossy());
    bundle_named(dir, deb, &name, None)
}

/// A bundle directory `dir/name` around `deb`, with a `security-floor`
/// file when `floor` is given.
fn bundle_named(dir: &Path, deb: &Path, name: &str, floor: Option<&str>) -> PathBuf {
    let b = dir.join(name);
    std::fs::create_dir_all(&b).unwrap();
    std::fs::copy(deb, b.join(deb.file_name().unwrap())).unwrap();
    let s = b.join("install-bundle.sh");
    std::fs::copy(repo().join("packaging/install-bundle.sh"), &s).unwrap();
    std::fs::set_permissions(&s, std::fs::Permissions::from_mode(0o755)).unwrap();
    if let Some(f) = floor {
        std::fs::write(b.join("security-floor"), format!("min_version={f}\n")).unwrap();
    }
    resum(&b);
    b
}

/// Rewrite a bundle directory's `SHA256SUMS` over its current files.
fn resum(b: &Path) {
    let _ = std::fs::remove_file(b.join("SHA256SUMS"));
    ok(&sh(Command::new("sh").current_dir(b).args([
        "-c",
        "find . -type f -printf '%P\\n' | LC_ALL=C sort | xargs sha256sum > ../SHA256SUMS.tmp && mv ../SHA256SUMS.tmp SHA256SUMS",
    ])));
}

fn run_bundle(root: &Path, b: &Path, args: &[&str]) -> Output {
    Command::new("sh")
        .arg(b.join("install-bundle.sh"))
        .args(args)
        .env("ROBODR_ROOT", root)
        .env("ROBODR_ALLOW_UNSIGNED", "1")
        .output()
        .unwrap()
}

fn installed(root: &Path) -> String {
    let o = sh(Command::new("dpkg-query")
        .arg(format!(
            "--admindir={}",
            root.join("var/lib/dpkg").display()
        ))
        .args(["-W", "-f", "${Version}", "robodr"]));
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn dpkg_root(dir: &Path) -> PathBuf {
    let root = dir.join("root");
    for d in [
        "var/lib/dpkg/info",
        "var/lib/dpkg/updates",
        "var/lib/dpkg/triggers",
    ] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    std::fs::write(root.join("var/lib/dpkg/status"), "").unwrap();
    std::fs::write(root.join("var/lib/dpkg/available"), "").unwrap();
    root
}

/// A real black box written by the current recorder.
fn record_black_box(dir: &Path) {
    let key = [0x42u8; 32];
    let mut rec = Recorder::open(
        RecorderConfig::new(dir, "ugv-001", "boot-a"),
        Box::new(HmacSha256Key::new("k", &key).unwrap()),
        Box::new(SteppingClock::new(1, 1_000, TimeSource::Rtc)),
    )
    .unwrap();
    rec.append_note(&serde_json::json!({"kind": "test", "n": 1}), true)
        .unwrap();
    rec.close().unwrap();
}

fn black_box_verifies(dir: &Path) -> bool {
    let v = HmacSha256Key::new("k", &[0x42u8; 32]).unwrap();
    robodr_blackbox::verify::verify_dir(dir, &v, &Default::default())
        .unwrap()
        .is_intact()
}

#[test]
fn install_upgrade_rollback_with_real_dpkg_and_the_format_gate() {
    if !dpkg_available("install_upgrade_rollback") {
        return;
    }
    let dir = TempDir::new("dpkg");
    let root = dpkg_root(&dir);
    // v1: a legacy release (no formats file); v2: the current one; v3: a
    // future release that writes black-box format 2 and reads 1 and 2.
    let (v1, v2, v3) = ("0.1.0~alpha.1-1", "0.1.0-1", "0.2.0-1");
    let b1 = bundle(&dir, &stub_deb(&dir, v1, None));
    let b2 = bundle(&dir, &stub_deb(&dir, v2, Some(("RBF1:1", "RBF1:1"))));
    let b3 = bundle(&dir, &stub_deb(&dir, v3, Some(("RBF1:2", "RBF1:1,RBF1:2"))));

    // Unsigned install refused without the lab override.
    let o = Command::new("sh")
        .arg(b1.join("install-bundle.sh"))
        .arg("install")
        .env("ROBODR_ROOT", &root)
        .env_remove("ROBODR_ALLOW_UNSIGNED")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));

    // Install v1; the agent writes its black box.
    ok(&run_bundle(&root, &b1, &["install"]));
    assert_eq!(installed(&root), v1);
    let bb = root.join("var/lib/robodr/blackbox/agentd");
    std::fs::create_dir_all(bb.parent().unwrap()).unwrap();
    record_black_box(&bb);

    // Upgrade to v2 (reads RBF1:1).
    let t = ok(&run_bundle(&root, &b2, &["install"]));
    assert!(t.contains("black-box formats OK for 0.1.0-1"), "{t}");
    assert_eq!(installed(&root), v2);
    assert!(root
        .join("var/lib/robodr/releases")
        .join(v2)
        .join("formats")
        .exists());
    // Ring information is printed, information only.
    let fleet = root.join("var/lib/robodr/fleet");
    std::fs::create_dir_all(&fleet).unwrap();
    std::fs::write(
        fleet.join("ring.env"),
        "# x\nserial=3\nring=1\ntarget_version=0.2.0\nbundle_sha256=\nexpires_at_ms=1\nstale=false\n",
    )
    .unwrap();
    let t = ok(&run_bundle(&root, &b2, &["ring"]));
    assert!(t.contains("ring 1, target 0.2.0"), "{t}");

    // Roll back to the legacy v1: it reads RBF1:1, the black box is RBF1:1.
    let t = ok(&run_bundle(&root, &b2, &["rollback", v1]));
    assert!(t.contains("black-box formats OK"), "{t}");
    assert_eq!(installed(&root), v1);
    assert!(
        black_box_verifies(&bb),
        "the black box survives the rollback"
    );

    // Upgrade to v3, which writes format 2 (simulated: a new segment whose
    // first frame carries record format version 2).
    let t = ok(&run_bundle(&root, &b3, &["install"]));
    assert!(t.contains("information only"), "{t}");
    assert_eq!(installed(&root), v3);
    let mut seg = FRAME_MAGIC.to_vec();
    seg.extend_from_slice(&64u32.to_be_bytes());
    seg.push(2);
    seg.extend_from_slice(&[0u8; 63]);
    std::fs::write(bb.join("seg-0000000000000009.rbb"), &seg).unwrap();

    // Rolling back across the format change is refused, by name.
    for v in [v2, v1] {
        let o = run_bundle(&root, &b3, &["rollback", v]);
        let e = String::from_utf8_lossy(&o.stderr).into_owned();
        assert_eq!(o.status.code(), Some(1), "{e}");
        assert!(
            e.contains("REFUSED") && e.contains("RBF1:2") && e.contains("seg-0000000000000009.rbb"),
            "{e}"
        );
        assert_eq!(
            installed(&root),
            v3,
            "nothing installed by a refused rollback"
        );
    }
    // `install` of the older bundle is a downgrade: refused as such ...
    let o = run_bundle(&root, &b2, &["install"]);
    let e = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(o.status.code(), Some(1), "{e}");
    assert!(e.contains("downgrade"), "{e}");
    assert_eq!(installed(&root), v3);
    // ... and, made deliberate, still refused by the format gate.
    let o = run_bundle(&root, &b2, &["install", "--allow-downgrade"]);
    let e = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(o.status.code(), Some(1), "{e}");
    assert!(e.contains("REFUSED") && e.contains("RBF1:2"), "{e}");
    assert_eq!(installed(&root), v3);
    // `list` shows what each kept release reads.
    let t = ok(&run_bundle(&root, &b3, &["list"]));
    assert!(
        t.contains(&format!("{v1}  black-box formats read: RBF1:1")),
        "{t}"
    );
    assert!(
        t.contains(&format!("{v3}  black-box formats read: RBF1:1 RBF1:2")),
        "{t}"
    );

    // After the chain is archived (moved aside), the rollback proceeds.
    let archive = root.join("var/lib/robodr/archive");
    std::fs::create_dir_all(&archive).unwrap();
    std::fs::rename(&bb, archive.join("blackbox-agentd")).unwrap();
    ok(&run_bundle(&root, &b3, &["rollback", v2]));
    assert_eq!(installed(&root), v2);

    // A tampered kept release is refused.
    let kept = root
        .join("var/lib/robodr/releases")
        .join(v3)
        .join(format!("robodr_{v3}_all.deb"));
    let mut b = std::fs::read(&kept).unwrap();
    let n = b.len() - 1;
    b[n] ^= 1;
    std::fs::write(&kept, b).unwrap();
    let o = run_bundle(&root, &b3, &["rollback", v3]);
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr).contains("fails its checksums"));
    assert_eq!(installed(&root), v2);
}

#[test]
fn build_deb_and_make_bundle_carry_robodr_enroll() {
    if !have("dpkg-deb") || !have("readelf") {
        assert!(std::env::var("ROBODR_REQUIRE_DPKG_TEST").as_deref() != Ok("1"));
        eprintln!("SKIPPED build_deb: needs dpkg-deb and readelf");
        return;
    }
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => {
            eprintln!("SKIPPED build_deb: arch {other}");
            return;
        }
    };
    let dir = TempDir::new("build-deb");
    let bins = dir.join("bin");
    std::fs::create_dir_all(&bins).unwrap();
    // Stub ELF binaries of the host architecture (the package layout is
    // under test, not the programs).
    let elf = PathBuf::from("/bin/true");
    for b in [
        "robodr-commission",
        "robodr-replay",
        "robodr-ros2-watch",
        "robodr-enroll",
    ] {
        std::fs::copy(&elf, bins.join(b)).unwrap();
        std::fs::set_permissions(bins.join(b), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let out = dir.join("dist");
    let o = Command::new("bash")
        .arg(repo().join("packaging/build-deb.sh"))
        .args(["--bin-dir"])
        .arg(&bins)
        .args(["--arch", arch, "--out"])
        .arg(&out)
        .env("ROBODR_DEB_REQUIRE", "robodr-enroll")
        .env("SOURCE_DATE_EPOCH", "1790000000")
        .output()
        .unwrap();
    ok(&o);
    let deb = PathBuf::from(String::from_utf8_lossy(&o.stdout).trim());
    let list = ok(&sh(Command::new("dpkg-deb").arg("-c").arg(&deb)));
    for want in [
        "./usr/sbin/robodr-enroll",
        "./usr/share/robodr/formats",
        "./usr/share/man/man8/robodr-enroll.8.gz",
        "./usr/share/doc/robodr/examples/fleet.example.json",
        "./usr/lib/robodr/install-bundle.sh",
    ] {
        assert!(list.contains(want), "{want} missing from the .deb:\n{list}");
    }
    let tmpf = ok(&sh(Command::new("sh").arg("-c").arg(format!(
        "dpkg-deb --fsys-tarfile {} | tar -xOf - ./usr/lib/tmpfiles.d/robodr.conf",
        deb.display()
    ))));
    assert!(tmpf.contains("/var/lib/robodr/fleet             0700 root   root"));
    // The offline bundle around it verifies.
    let o = Command::new("bash")
        .arg(repo().join("packaging/make-bundle.sh"))
        .args(["--deb"])
        .arg(&deb)
        .args(["--out"])
        .arg(&out)
        .env("SOURCE_DATE_EPOCH", "1790000000")
        .output()
        .unwrap();
    let t = ok(&o);
    let tarball = PathBuf::from(t.lines().last().unwrap().trim());
    let x = dir.join("x");
    std::fs::create_dir_all(&x).unwrap();
    ok(&sh(Command::new("tar")
        .arg("-xzf")
        .arg(&tarball)
        .arg("-C")
        .arg(&x)));
    let bdir = std::fs::read_dir(&x)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let t = ok(&sh(Command::new("sh")
        .arg(bdir.join("install-bundle.sh"))
        .arg("verify")));
    assert!(t.contains("checksums OK"), "{t}");
    let floor = std::fs::read_to_string(bdir.join("security-floor")).unwrap();
    assert!(
        floor.lines().any(|l| l.starts_with("min_version=")),
        "{floor}"
    );
}

// ------------------------------------------------- signed installation --

fn run_bundle_with(
    root: &Path,
    script: &Path,
    args: &[&str],
    unsigned: bool,
    tmp: &Path,
) -> Output {
    let mut c = Command::new("sh");
    c.arg(script)
        .args(args)
        .env("ROBODR_ROOT", root)
        .env("TMPDIR", tmp);
    if unsigned {
        c.env("ROBODR_ALLOW_UNSIGNED", "1");
    } else {
        c.env_remove("ROBODR_ALLOW_UNSIGNED");
    }
    c.output().unwrap()
}

fn stderr(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

/// Whether minisign is here too (the signed-install tests).
fn minisign_available(test: &str) -> bool {
    if !dpkg_available(test) {
        return false;
    }
    if !have("minisign") {
        assert!(
            std::env::var("ROBODR_REQUIRE_DPKG_TEST").as_deref() != Ok("1"),
            "{test}: needs minisign (ROBODR_REQUIRE_DPKG_TEST=1)"
        );
        eprintln!("SKIPPED {test}: needs minisign");
        return false;
    }
    true
}

/// A test release key pair (minisign, no password): (public, secret).
fn release_key(dir: &Path, name: &str) -> (PathBuf, PathBuf) {
    let (p, s) = (
        dir.join(format!("{name}.pub")),
        dir.join(format!("{name}.sec")),
    );
    ok(&sh(Command::new("minisign")
        .args(["-G", "-W", "-p"])
        .arg(&p)
        .arg("-s")
        .arg(&s)
        .stdin(std::process::Stdio::null())));
    (p, s)
}

fn minisign(secret: &Path, file: &Path) {
    ok(&sh(Command::new("minisign")
        .arg("-S")
        .arg("-s")
        .arg(secret)
        .arg("-m")
        .arg(file)
        .stdin(std::process::Stdio::null())));
}

/// The offline tarball of the bundle directory `b` (in `out`), signed.
fn signed_tarball(out: &Path, b: &Path, secret: &Path) -> PathBuf {
    std::fs::create_dir_all(out).unwrap();
    let name = b.file_name().unwrap().to_string_lossy().into_owned();
    let t = out.join(format!("{name}-offline.tar.gz"));
    ok(&sh(Command::new("tar")
        .arg("-C")
        .arg(b.parent().unwrap())
        .arg("-czf")
        .arg(&t)
        .arg(&name)));
    minisign(secret, &t);
    t
}

fn stub_marker(root: &Path) -> String {
    std::fs::read_to_string(root.join("usr/lib/robodr/stub-version")).unwrap_or_default()
}

fn is_empty_dir(d: &Path) -> bool {
    std::fs::read_dir(d).unwrap().next().is_none()
}

#[test]
fn signed_install_takes_the_signed_tarball_not_the_extracted_directory() {
    if !minisign_available("signed_install") {
        return;
    }
    let dir = TempDir::new("signed");
    let root = dpkg_root(&dir);
    let tmp = dir.join("tmp");
    std::fs::create_dir_all(&tmp).unwrap();
    let (public, secret) = release_key(&dir, "release");
    let v = "0.1.0-1";
    let f = Some(("RBF1:1", "RBF1:1"));
    let genuine = bundle_named(&dir, &stub_deb(&dir, v, f), "robodr-0.1.0-all", None);
    let rel = dir.join("rel");
    let t = signed_tarball(&rel, &genuine, &secret);
    let (pk, tb) = (public.to_str().unwrap(), t.to_str().unwrap());

    // The extracted directory is modified after extraction: another .deb
    // of the same name, SHA256SUMS rewritten to match. The tarball and its
    // signature are genuine.
    let evil = stub_deb_marked(&dir, v, f, "evil");
    std::fs::copy(&evil, genuine.join(evil.file_name().unwrap())).unwrap();
    resum(&genuine);
    let script = genuine.join("install-bundle.sh");
    for cmd in ["install", "verify"] {
        let o = run_bundle_with(
            &root,
            &script,
            &[cmd, "--pubkey", pk, "--tarball", tb],
            false,
            &tmp,
        );
        let e = stderr(&o);
        assert_eq!(o.status.code(), Some(1), "{cmd}: {e}");
        assert!(e.contains("differs from the signed tarball"), "{cmd}: {e}");
        assert_eq!(installed(&root), "", "{cmd}: nothing installed");
        assert!(
            is_empty_dir(&tmp),
            "{cmd}: private staging directory removed"
        );
    }
    // A file smuggled in next to an otherwise genuine copy: refused too.
    let copy = dir.join("copy");
    ok(&sh(Command::new("tar").arg("-xzf").arg(&t).arg("-C").arg(
        {
            std::fs::create_dir_all(&copy).unwrap();
            &copy
        },
    )));
    let extracted = copy.join("robodr-0.1.0-all");
    std::fs::write(extracted.join("postinst-extra.sh"), "#!/bin/sh\n").unwrap();
    let o = run_bundle_with(
        &root,
        &extracted.join("install-bundle.sh"),
        &["install", "--pubkey", pk, "--tarball", tb],
        false,
        &tmp,
    );
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert_eq!(installed(&root), "");

    // A tampered tarball: its signature fails.
    let bad = rel.join("tampered.tar.gz");
    let mut b = std::fs::read(&t).unwrap();
    let n = b.len() / 2;
    b[n] ^= 1;
    std::fs::write(&bad, &b).unwrap();
    std::fs::copy(
        t.with_extension("gz.minisig"),
        rel.join("tampered.tar.gz.minisig"),
    )
    .unwrap();
    let o = run_bundle_with(
        &root,
        &script,
        &[
            "install",
            "--pubkey",
            pk,
            "--tarball",
            bad.to_str().unwrap(),
        ],
        false,
        &tmp,
    );
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(stderr(&o).contains("SIGNATURE CHECK FAILED"));
    assert_eq!(installed(&root), "");

    // The release's signed SHA256SUMS next to the tarball is checked too:
    // a tarball it does not list (or lists with another hash) is refused.
    let sums = rel.join("SHA256SUMS");
    std::fs::write(
        &sums,
        format!(
            "{}  {}\n",
            "0".repeat(64),
            t.file_name().unwrap().to_string_lossy()
        ),
    )
    .unwrap();
    minisign(&secret, &sums);
    let trusted = dir.join("trusted");
    std::fs::create_dir_all(&trusted).unwrap();
    let tscript = trusted.join("install-bundle.sh");
    std::fs::copy(repo().join("packaging/install-bundle.sh"), &tscript).unwrap();
    let o = run_bundle_with(
        &root,
        &tscript,
        &["install", "--pubkey", pk, "--tarball", tb],
        false,
        &tmp,
    );
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(stderr(&o).contains("SHA256SUMS"), "{}", stderr(&o));
    // A SHA256SUMS whose signature fails: refused.
    let h = ok(&sh(Command::new("sha256sum").arg(&t)));
    let line = format!(
        "{}  {}\n",
        h.split_whitespace().next().unwrap(),
        t.file_name().unwrap().to_string_lossy()
    );
    std::fs::write(&sums, &line).unwrap();
    let o = run_bundle_with(
        &root,
        &tscript,
        &["install", "--pubkey", pk, "--tarball", tb],
        false,
        &tmp,
    );
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("SIGNATURE CHECK FAILED"),
        "{}",
        stderr(&o)
    );
    minisign(&secret, &sums);

    // A trusted copy of the script, outside any bundle, installs exactly
    // the signed content (from a private staging directory it removes).
    let t2 = ok(&run_bundle_with(
        &root,
        &tscript,
        &["install", "--pubkey", pk, "--tarball", tb],
        false,
        &tmp,
    ));
    assert!(t2.contains("signature OK"), "{t2}");
    assert_eq!(installed(&root), v);
    assert_eq!(stub_marker(&root), format!("{v} genuine"));
    assert!(is_empty_dir(&tmp), "private staging directory removed");
    // So does the genuine extracted directory.
    let o = run_bundle_with(
        &root,
        &copy.join("robodr-0.1.0-all/install-bundle.sh"),
        &["verify", "--pubkey", pk, "--tarball", tb],
        false,
        &tmp,
    );
    assert_eq!(
        o.status.code(),
        Some(1),
        "the copy still has the smuggled file"
    );
    std::fs::remove_file(extracted.join("postinst-extra.sh")).unwrap();
    ok(&run_bundle_with(
        &root,
        &extracted.join("install-bundle.sh"),
        &["verify", "--pubkey", pk, "--tarball", tb],
        false,
        &tmp,
    ));
}

#[test]
fn downgrade_needs_allow_downgrade_and_never_passes_the_security_floor() {
    if !dpkg_available("downgrade_floor") {
        return;
    }
    let dir = TempDir::new("floor");
    let root = dpkg_root(&dir);
    let tmp = dir.join("tmp");
    std::fs::create_dir_all(&tmp).unwrap();
    let f = Some(("RBF1:1", "RBF1:1"));
    let (v1, v2, v3, v4) = ("0.1.0-1", "0.2.0-1", "0.3.0-1", "0.4.0-1");
    let b1 = bundle(&dir, &stub_deb(&dir, v1, f));
    let b2 = bundle(&dir, &stub_deb(&dir, v2, f));
    let b3 = bundle_named(&dir, &stub_deb(&dir, v3, f), "b3", Some("0.2.0-1"));
    let b4 = bundle_named(&dir, &stub_deb(&dir, v4, f), "b4", Some("0.1.0-1"));
    let run = |b: &Path, args: &[&str]| {
        run_bundle_with(&root, &b.join("install-bundle.sh"), args, true, &tmp)
    };
    ok(&run(&b2, &["install"]));
    // An older release through `install`: a downgrade, refused.
    let o = run(&b1, &["install"]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(stderr(&o).contains("downgrade"), "{}", stderr(&o));
    assert_eq!(installed(&root), v2);
    // Deliberately.
    ok(&run(&b1, &["install", "--allow-downgrade"]));
    assert_eq!(installed(&root), v1);
    ok(&run(&b2, &["install"]));
    // v3's bundle carries the security floor 0.2.0-1: recorded.
    let t = ok(&run(&b3, &["install"]));
    assert!(t.contains("security floor"), "{t}");
    let floor = root.join("var/lib/robodr/releases/security-floor");
    assert!(std::fs::read_to_string(&floor)
        .unwrap()
        .contains("min_version=0.2.0-1"));
    // Below the floor: refused, by rollback and by install, no override.
    for args in [vec!["rollback", v1], vec!["install", "--allow-downgrade"]] {
        let b = if args[0] == "rollback" { &b3 } else { &b1 };
        let o = run(b, &args);
        assert_eq!(o.status.code(), Some(1), "{args:?}: {}", stderr(&o));
        assert!(
            stderr(&o).contains("security floor"),
            "{args:?}: {}",
            stderr(&o)
        );
        assert_eq!(installed(&root), v3);
    }
    // At the floor: allowed.
    ok(&run(&b3, &["rollback", v2]));
    assert_eq!(installed(&root), v2);
    // The SOC's (verified) ring information raises the floor.
    let fleet = root.join("var/lib/robodr/fleet");
    std::fs::create_dir_all(&fleet).unwrap();
    std::fs::write(
        fleet.join("ring.env"),
        "serial=4\nring=1\ntarget_version=0.3.0\nmin_version=0.3.0\nbundle_sha256=\nexpires_at_ms=1\nstale=false\n",
    )
    .unwrap();
    let o = run(&b3, &["rollback", v2]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(stderr(&o).contains("security floor"), "{}", stderr(&o));
    ok(&run(&b3, &["install"]));
    assert_eq!(installed(&root), v3);
    // Monotonic: neither a bundle with a lower floor nor the ring
    // information going away lowers it.
    std::fs::remove_file(fleet.join("ring.env")).unwrap();
    ok(&run(&b4, &["install"]));
    assert!(std::fs::read_to_string(&floor)
        .unwrap()
        .contains("min_version=0.3.0"));
    let o = run(&b4, &["rollback", v2]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert_eq!(installed(&root), v4);
}

#[test]
fn unknown_frames_do_not_block_and_unreadable_segments_are_accepted_by_name() {
    if !dpkg_available("unknown_frames") {
        return;
    }
    let dir = TempDir::new("frames");
    let root = dpkg_root(&dir);
    let tmp = dir.join("tmp");
    std::fs::create_dir_all(&tmp).unwrap();
    let f = Some(("RBF1:1", "RBF1:1"));
    let b1 = bundle(&dir, &stub_deb(&dir, "0.1.0-1", f));
    let b2 = bundle(&dir, &stub_deb(&dir, "0.2.0-1", f));
    let run = |b: &Path, args: &[&str]| {
        run_bundle_with(&root, &b.join("install-bundle.sh"), args, true, &tmp)
    };
    ok(&run(&b1, &["install"]));
    let bb = root.join("var/lib/robodr/blackbox/agentd");
    std::fs::create_dir_all(bb.parent().unwrap()).unwrap();
    record_black_box(&bb);
    // A segment file that does not start with a RoboDR frame (damaged, or
    // not RoboDR's): reported as such, and it blocks nothing.
    let junk = bb.join("seg-0000000000000005.rbb");
    std::fs::write(&junk, b"GARBAGE: not a black-box frame at all").unwrap();
    let t = ok(&run(&b2, &["install"]));
    assert!(t.contains("not a RoboDR black-box frame"), "{t}");
    assert!(!t.contains("newer release"), "{t}");
    assert_eq!(installed(&root), "0.2.0-1");
    // A recognised format the release cannot read: refused by name ...
    let mut seg = FRAME_MAGIC.to_vec();
    seg.extend_from_slice(&64u32.to_be_bytes());
    seg.push(2);
    seg.extend_from_slice(&[0u8; 63]);
    let newer = bb.join("seg-0000000000000009.rbb");
    std::fs::write(&newer, &seg).unwrap();
    let o = run(&b2, &["install"]);
    let e = stderr(&o);
    assert_eq!(o.status.code(), Some(1), "{e}");
    assert!(
        e.contains("REFUSED") && e.contains("RBF1:2") && e.contains("newer release"),
        "{e}"
    );
    // ... unless the operator accepts exactly that segment.
    let o = run(
        &b2,
        &["install", "--accept-unreadable", junk.to_str().unwrap()],
    );
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    let t = ok(&run(
        &b2,
        &["install", "--accept-unreadable", newer.to_str().unwrap()],
    ));
    assert!(t.contains("accepted"), "{t}");
}

#[test]
fn rollback_version_and_blackbox_dirs_are_neither_paths_nor_patterns() {
    if !dpkg_available("rollback_paths") {
        return;
    }
    let dir = TempDir::new("paths");
    let root = dpkg_root(&dir);
    let tmp = dir.join("tmp");
    std::fs::create_dir_all(&tmp).unwrap();
    let f = Some(("RBF1:1", "RBF1:1"));
    let b1 = bundle(&dir, &stub_deb(&dir, "0.1.0-1", f));
    let run =
        |args: &[&str]| run_bundle_with(&root, &b1.join("install-bundle.sh"), args, true, &tmp);
    ok(&run(&["install"]));
    // A "release" outside the kept releases, reachable by a relative path.
    let evil = root.join("var/lib/robodr/evil");
    std::fs::create_dir_all(&evil).unwrap();
    let d = stub_deb_marked(&dir, "6.6.6-1", f, "evil");
    std::fs::copy(&d, evil.join(d.file_name().unwrap())).unwrap();
    resum(&evil);
    for v in ["../evil", "../evil/", "*", "0.1.0-1/../../evil", ""] {
        let o = run(&["rollback", v]);
        assert_eq!(o.status.code(), Some(2), "{v:?}: {}", stderr(&o));
        assert_eq!(installed(&root), "0.1.0-1", "{v:?}");
    }
    // --blackbox-dir is a directory, never a pattern: `bbx*` is refused
    // (it is not expanded to bbx1, whose segment would be judged).
    let bbx1 = dir.join("bbx1");
    std::fs::create_dir_all(&bbx1).unwrap();
    let mut seg = FRAME_MAGIC.to_vec();
    seg.extend_from_slice(&64u32.to_be_bytes());
    seg.push(2);
    seg.extend_from_slice(&[0u8; 63]);
    std::fs::write(bbx1.join("seg-0000000000000001.rbb"), &seg).unwrap();
    let pattern = format!("{}/bbx*", dir.display());
    let o = run(&["install", "--blackbox-dir", &pattern]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(!stderr(&o).contains("bbx1"), "{}", stderr(&o));
    ok(&run(&[
        "install",
        "--blackbox-dir",
        dir.join("no-such-dir").to_str().unwrap(),
    ]));
    let o = run(&["install", "--blackbox-dir", bbx1.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
}
