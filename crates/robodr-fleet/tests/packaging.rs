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

fn tmpdir(tag: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "robodr-pkg-{}-{}-{tag}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
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
    let st = dir.join(format!("stage-{version}"));
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
    std::fs::write(st.join("usr/lib/robodr/stub-version"), version).unwrap();
    if let Some((w, r)) = formats {
        std::fs::create_dir_all(st.join("usr/share/robodr")).unwrap();
        std::fs::write(
            st.join("usr/share/robodr/formats"),
            format!("blackbox_write={w}\nblackbox_read={r}\n"),
        )
        .unwrap();
    }
    let deb = dir.join(format!("robodr_{version}_all.deb"));
    ok(&sh(Command::new("dpkg-deb")
        .args(["--root-owner-group", "-Zxz", "--build"])
        .arg(&st)
        .arg(&deb)));
    deb
}

/// An extracted bundle directory around `deb` (as make-bundle.sh lays it out).
fn bundle(dir: &Path, deb: &Path) -> PathBuf {
    let b = dir.join(format!(
        "bundle-{}",
        deb.file_name().unwrap().to_string_lossy()
    ));
    std::fs::create_dir_all(&b).unwrap();
    std::fs::copy(deb, b.join(deb.file_name().unwrap())).unwrap();
    let s = b.join("install-bundle.sh");
    std::fs::copy(repo().join("packaging/install-bundle.sh"), &s).unwrap();
    std::fs::set_permissions(&s, std::fs::Permissions::from_mode(0o755)).unwrap();
    ok(&sh(Command::new("sh").current_dir(&b).args([
        "-c",
        "find . -type f -printf '%P\\n' | LC_ALL=C sort | xargs sha256sum > ../SHA256SUMS.tmp && mv ../SHA256SUMS.tmp SHA256SUMS",
    ])));
    b
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
    let dir = tmpdir("dpkg");
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
    // A downgrade through `install` of the older bundle is refused too.
    let o = run_bundle(&root, &b2, &["install"]);
    assert_eq!(o.status.code(), Some(1));
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
    let _ = std::fs::remove_dir_all(&dir);
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
    let dir = tmpdir("build-deb");
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
    let _ = std::fs::remove_dir_all(&dir);
}
