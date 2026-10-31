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
    stub_deb_pkg(dir, "robodr", version, formats, marker, None)
}

/// [`stub_deb_marked`] of package `pkg` (robodr or robodr-focal; the two
/// conflict and replace each other, as the real ones) with an optional
/// postinst script.
fn stub_deb_pkg(
    dir: &Path,
    pkg: &str,
    version: &str,
    formats: Option<(&str, &str)>,
    marker: &str,
    postinst: Option<&str>,
) -> PathBuf {
    let out = if marker == "genuine" {
        dir.to_path_buf()
    } else {
        dir.join(marker)
    };
    let st = out.join(format!("stage-{pkg}-{version}"));
    std::fs::create_dir_all(st.join("DEBIAN")).unwrap();
    std::fs::create_dir_all(st.join("usr/lib/robodr")).unwrap();
    let other = if pkg == "robodr" {
        "robodr-focal"
    } else {
        "robodr"
    };
    std::fs::write(
        st.join("DEBIAN/control"),
        format!(
            "Package: {pkg}\nVersion: {version}\nArchitecture: all\nMaintainer: test <t@invalid>\n\
             Conflicts: {other}\nReplaces: {other}\n\
             Description: stub robodr package for the install-bundle test\n"
        ),
    )
    .unwrap();
    if let Some(script) = postinst {
        let f = st.join("DEBIAN/postinst");
        std::fs::write(&f, script).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
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
    let deb = out.join(format!("{pkg}_{version}_all.deb"));
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
        // Always required too (crates/robodr-ops).
        "robodr-setup",
        "robodr-support-bundle",
        "robodr-metrics",
        "robodr-enroll",
        "robodr-uplink",
        "robodr-executor",
        "robodr-firewall-gw",
        "robodr-deliverd",
        "robodr-depot",
        // The replay helper is a test tool: built, never packaged.
        "robodr-safety-replay",
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
        .env(
            "ROBODR_DEB_REQUIRE",
            "robodr-enroll robodr-uplink robodr-executor robodr-firewall-gw robodr-deliverd robodr-depot",
        )
        .env("SOURCE_DATE_EPOCH", "1790000000")
        .output()
        .unwrap();
    ok(&o);
    let deb = PathBuf::from(String::from_utf8_lossy(&o.stdout).trim());
    // The operator tools are always required: a tree without one is refused.
    let partial = dir.join("bin-partial");
    std::fs::create_dir_all(&partial).unwrap();
    for e in std::fs::read_dir(&bins).unwrap() {
        let e = e.unwrap();
        if e.file_name() != "robodr-metrics" {
            std::fs::copy(e.path(), partial.join(e.file_name())).unwrap();
        }
    }
    let o = Command::new("bash")
        .arg(repo().join("packaging/build-deb.sh"))
        .args(["--bin-dir"])
        .arg(&partial)
        .args(["--arch", arch, "--out"])
        .arg(dir.join("partial-out"))
        .env("SOURCE_DATE_EPOCH", "1790000000")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(stderr(&o).contains("required binary"), "{}", stderr(&o));
    // A release build (ROBODR_RELEASE=1) refuses the development
    // placeholder maintainer, and an unset one.
    for m in [
        None,
        Some("RoboDR maintainers <robodr-maintainers@invalid>"),
        // Control characters would inject fields into DEBIAN/control or
        // the spec (review: newline in the name).
        Some("RoboDR\nX-Injected: yes <release@robodr.dev>"),
        Some("RoboDR\rRelease <release@robodr.dev>"),
        Some("RoboDR\tRelease <release@robodr.dev>"),
    ] {
        let mut c = Command::new("bash");
        c.arg(repo().join("packaging/build-deb.sh"))
            .args(["--bin-dir"])
            .arg(&bins)
            .args(["--arch", arch, "--out"])
            .arg(dir.join("release"))
            .env("ROBODR_RELEASE", "1")
            .env("SOURCE_DATE_EPOCH", "1790000000");
        match m {
            Some(v) => c.env("DEB_MAINTAINER", v),
            None => c.env_remove("DEB_MAINTAINER"),
        };
        let o = c.output().unwrap();
        assert_eq!(o.status.code(), Some(2), "{m:?}: {}", stderr(&o));
        assert!(stderr(&o).contains("ROBODR_RELEASE=1"), "{}", stderr(&o));
    }
    let list = ok(&sh(Command::new("dpkg-deb").arg("-c").arg(&deb)));
    for want in [
        "./usr/sbin/robodr-enroll",
        "./usr/share/robodr/formats",
        "./usr/share/man/man8/robodr-enroll.8.gz",
        "./usr/share/doc/robodr/examples/fleet.example.json",
        "./usr/lib/robodr/install-bundle.sh",
        // Third-party notices and the eBPF source offer (S12).
        "./usr/share/doc/robodr/THIRD_PARTY_NOTICES",
        "./usr/share/doc/robodr/GPL-2.0-SOURCE-OFFER",
        // The other units and tools of the package sit next to it.
        "./usr/bin/robodr-uplink",
        "./usr/lib/systemd/system/robodr-uplink.service",
        "./usr/sbin/robodr-executor",
        "./usr/lib/systemd/system/robodr-executor.service",
        "./usr/sbin/robodr-firewall-gw",
        "./usr/lib/systemd/system/robodr-firewall-gw.service",
        "./usr/lib/systemd/system/robodr-firewall-gw-rules.service",
        "./usr/share/doc/robodr/contracts/robodr.control-plane.md",
        "./usr/share/doc/robodr/contracts/robodr.fleet-api.md",
        // The delivery agent (Sprint 13b), its unit, man page, example
        // configuration and design document.
        "./usr/sbin/robodr-deliverd",
        "./usr/lib/systemd/system/robodr-deliverd.service",
        "./usr/share/man/man8/robodr-deliverd.8.gz",
        "./usr/share/doc/robodr/examples/deliverd.example.json",
        "./usr/share/doc/robodr/SECURE-DELIVERY.md",
        "./usr/share/doc/robodr/examples/robodr-deliverd.service.d/50-depot-lan.conf.example",
        // The site depot (Sprint 14a): tool, unit, man page, examples.
        "./usr/sbin/robodr-depot",
        "./usr/lib/systemd/system/robodr-depot.service",
        "./usr/share/man/man8/robodr-depot.8.gz",
        "./usr/share/doc/robodr/examples/depot.example.json",
        "./usr/share/doc/robodr/examples/robodr-depot.service.d/50-tpm-anchor.conf.example",
        // Operator tools, their man pages and examples (T68-T70, T87).
        "./usr/sbin/robodr-setup",
        "./usr/sbin/robodr-support-bundle",
        "./usr/bin/robodr-metrics",
        "./usr/share/man/man8/robodr-setup.8.gz",
        "./usr/share/man/man8/robodr-support-bundle.8.gz",
        "./usr/share/man/man1/robodr-metrics.1.gz",
        "./usr/share/man/man8/robodr-executor.8.gz",
        "./usr/share/man/man8/robodr-firewall-gw.8.gz",
        "./usr/share/doc/robodr/examples/metrics/robodr-alerts.example.yml",
        "./usr/share/doc/robodr/examples/modules-load.d/robodr.conf.example",
        // Customer documentation and demo data (T49).
        "./usr/share/doc/robodr/customer/quick-start.md",
        "./usr/share/doc/robodr/customer/known-limitations.md",
        "./usr/share/doc/robodr/demo/fastrtps_rogue_cmd_vel.pcap",
        "./usr/share/doc/robodr/demo/SHA256SUMS",
    ] {
        assert!(list.contains(want), "{want} missing from the .deb:\n{list}");
    }
    assert!(
        !list.contains("robodr-safety-replay"),
        "the replay helper must not ship:\n{list}"
    );
    assert!(
        !list.contains("-draft.md"),
        "draft customer documents must not ship:\n{list}"
    );
    let tmpf = ok(&sh(Command::new("sh").arg("-c").arg(format!(
        "dpkg-deb --fsys-tarfile {} | tar -xOf - ./usr/lib/tmpfiles.d/robodr.conf",
        deb.display()
    ))));
    assert!(tmpf.contains("/var/lib/robodr/fleet             0700 root   root"));
    assert!(tmpf.contains("/var/lib/robodr/deliverd          0700 root   root"));
    assert!(tmpf.contains("/var/lib/robodr/blackbox/deliverd 0750 root   robodr"));
    assert!(tmpf.contains("/var/lib/robodr/depot             0700 robodr-depot robodr-depot"));
    assert!(tmpf.contains("/etc/robodr-depot/keys            0700 robodr-depot robodr-depot"));
    let sysu = ok(&sh(Command::new("sh").arg("-c").arg(format!(
        "dpkg-deb --fsys-tarfile {} | tar -xOf - ./usr/lib/sysusers.d/robodr.conf",
        deb.display()
    ))));
    assert!(
        sysu.lines().any(|l| l.starts_with("u      robodr-depot ")),
        "{sysu}"
    );
    // One user per network-facing service (review: a shared uid let each
    // read the others' credentials), owning its own state.
    for (u, d) in [
        ("robodr-spool", "/var/lib/robodr/export/diode"),
        ("robodr-kafka", "/var/lib/robodr/export/kafka-publish"),
        ("robodr-uplink", "/var/lib/robodr/export/uplink"),
        ("robodr-gw", ""),
    ] {
        assert!(
            sysu.lines().any(|l| l.starts_with(&format!("u      {u} "))),
            "{u}: {sysu}"
        );
        if !d.is_empty() {
            assert!(
                tmpf.lines()
                    .any(|l| l.split_whitespace().collect::<Vec<_>>()[..]
                        .starts_with(&["d", d, "0750", u, "robodr"])),
                "{d}: {tmpf}"
            );
        }
    }
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
    // b3 writes format 2 (and reads 1 and 2).
    let b3 = bundle(
        &dir,
        &stub_deb(&dir, "0.3.0-1", Some(("RBF1:2", "RBF1:1,RBF1:2"))),
    );
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
    // A segment claiming a format no release installed here ever wrote
    // (agentd, which can write these files, forging a "newer" segment):
    // unverifiable, reported as UNKNOWN, and it does NOT block updates.
    let mut seg = FRAME_MAGIC.to_vec();
    seg.extend_from_slice(&64u32.to_be_bytes());
    seg.push(2);
    seg.extend_from_slice(&[0u8; 63]);
    let newer = bb.join("seg-0000000000000009.rbb");
    std::fs::write(&newer, &seg).unwrap();
    let t = ok(&run(&b2, &["install"]));
    assert!(
        t.contains("UNKNOWN") && t.contains("claims RBF1:2") && t.contains("does not block"),
        "{t}"
    );
    assert!(!t.contains("REFUSED"), "{t}");
    // Once a release that writes format 2 was installed, the claim is
    // verified: rolling back to one that cannot read it is refused by
    // name ...
    ok(&run(&b3, &["install"]));
    assert_eq!(installed(&root), "0.3.0-1");
    let o = run(&b3, &["rollback", "0.2.0-1"]);
    let e = stderr(&o);
    assert_eq!(o.status.code(), Some(1), "{e}");
    assert!(
        e.contains("REFUSED") && e.contains("RBF1:2") && e.contains("newer release"),
        "{e}"
    );
    // ... unless the operator accepts exactly that segment.
    let o = run(
        &b3,
        &[
            "rollback",
            "0.2.0-1",
            "--accept-unreadable",
            junk.to_str().unwrap(),
        ],
    );
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert_eq!(installed(&root), "0.3.0-1");
    let t = ok(&run(
        &b3,
        &[
            "rollback",
            "0.2.0-1",
            "--accept-unreadable",
            newer.to_str().unwrap(),
        ],
    ));
    assert!(t.contains("accepted"), "{t}");
    assert_eq!(installed(&root), "0.2.0-1");
}

/// The gate judges the black-box chains on the unit, agentd's and the
/// fleet journal (`/var/lib/robodr/fleet/journal`), and only those: the
/// other state journals (executor v1, the control plane's request journal
/// and evidence exports, the gateway's state, the fleet tool's own JSON
/// state) are not black-box segments, are never reported as unknown frames
/// and never block.
#[test]
fn the_format_gate_reads_the_fleet_journal_and_ignores_other_state() {
    if !dpkg_available("fleet_journal_gate") {
        return;
    }
    let dir = TempDir::new("fleet-gate");
    let root = dpkg_root(&dir);
    let tmp = dir.join("tmp");
    std::fs::create_dir_all(&tmp).unwrap();
    let f = Some(("RBF1:1", "RBF1:1"));
    let b1 = bundle(&dir, &stub_deb(&dir, "0.1.0-1", f));
    // b2 writes format 2, so a format-2 segment is verified below.
    let b2 = bundle(
        &dir,
        &stub_deb(&dir, "0.2.0-1", Some(("RBF1:2", "RBF1:1,RBF1:2"))),
    );
    let run = |b: &Path, args: &[&str]| {
        run_bundle_with(&root, &b.join("install-bundle.sh"), args, true, &tmp)
    };
    ok(&run(&b1, &["install"]));
    let lib = root.join("var/lib/robodr");
    record_black_box(&lib.join("blackbox/agentd"));
    let journal = lib.join("fleet/journal");
    record_black_box(&journal);
    let other: [(&str, &[u8]); 8] = [
        (
            "executor/journal.json",
            b"{\"schema\":\"robodr-executor-journal/v1\"}\n",
        ),
        (
            "control-plane/agentd/requests.journal",
            b"{\"t\":\"h\",\"format\":\"robodr-cp-journal/v1\"}\n",
        ),
        (
            "control-plane/agentd/exports/0123/bundle.rbbx",
            b"RBBXBND1 not a segment",
        ),
        ("firewall-gw/writers.json", b"{}"),
        ("firewall-gw/events.jsonl", b"{}\n"),
        ("fleet/enroll-pending.json", b"{}"),
        ("fleet/rotation-uplink.json", b"{}"),
        (
            "blackbox/agentd/quarantine/damaged-seg3.rbb",
            b"GARBAGE quarantined",
        ),
    ];
    for (p, body) in other {
        let p = lib.join(p);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, body).unwrap();
    }
    let t = ok(&run(&b2, &["install"]));
    assert!(t.contains("black-box formats OK for 0.2.0-1"), "{t}");
    assert!(!t.contains("WARNING"), "{t}");
    assert_eq!(installed(&root), "0.2.0-1");
    // A fleet-journal segment in a format the release cannot read blocks a
    // rollback by name, like one of agentd's.
    let mut seg = FRAME_MAGIC.to_vec();
    seg.extend_from_slice(&64u32.to_be_bytes());
    seg.push(2);
    seg.extend_from_slice(&[0u8; 63]);
    let newer = journal.join("seg-0000000000000009.rbb");
    std::fs::write(&newer, &seg).unwrap();
    let o = run(&b2, &["rollback", "0.1.0-1"]);
    let e = stderr(&o);
    assert_eq!(o.status.code(), Some(1), "{e}");
    assert!(
        e.contains("REFUSED")
            && e.contains("RBF1:2")
            && e.contains("fleet/journal/seg-0000000000000009.rbb"),
        "{e}"
    );
    assert_eq!(installed(&root), "0.2.0-1");
    // The refusal leaves no temporary file behind (nor a stray file named
    // after the refused format in the working directory).
    assert!(
        is_empty_dir(&tmp),
        "temporary files left in {}",
        tmp.display()
    );
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
    // The directory named is judged (its unverifiable segment reported).
    let t = ok(&run(&["install", "--blackbox-dir", bbx1.to_str().unwrap()]));
    assert!(t.contains("bbx1/seg-0000000000000001.rbb"), "{t}");
}

/// The version of package `pkg` in the dpkg root, if dpkg knows it in any
/// state ("" otherwise), and its `db:Status-Abbrev`.
fn dpkg_state(root: &Path, pkg: &str) -> (String, String) {
    let o = sh(Command::new("dpkg-query")
        .arg(format!(
            "--admindir={}",
            root.join("var/lib/dpkg").display()
        ))
        .args(["-W", "-f", "${db:Status-Abbrev}|${Version}", pkg]));
    let t = String::from_utf8_lossy(&o.stdout).into_owned();
    let (st, v) = t.split_once('|').unwrap_or(("", ""));
    (v.to_string(), st.trim().to_string())
}

/// A signed tarball of bundle directory `b` named `name` in `out`, with its
/// signature (default minisign trusted comment: `file:<name>`).
fn signed_tarball_named(out: &Path, b: &Path, secret: &Path, name: &str) -> PathBuf {
    std::fs::create_dir_all(out).unwrap();
    let t = out.join(name);
    ok(&sh(Command::new("tar")
        .arg("-C")
        .arg(b.parent().unwrap())
        .arg("-czf")
        .arg(&t)
        .arg(b.file_name().unwrap())));
    minisign(secret, &t);
    t
}

/// Copy a signed tarball and its signature to `dir/name` (+ `.minisig`).
fn copy_signed(t: &Path, dir: &Path, name: &str) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let to = dir.join(name);
    std::fs::copy(t, &to).unwrap();
    std::fs::copy(
        format!("{}.minisig", t.display()),
        format!("{}.minisig", to.display()),
    )
    .unwrap();
    to
}

/// Review finding (packaging, HIGH): the signed tarball was re-opened for
/// every step (minisign, sha256sum, tar -t, tar -x), so a file swapped
/// after the signature check was what got extracted and installed. Now it
/// must be a regular file and is copied once into the private directory;
/// every check and the extraction read that copy. Also: the signature's
/// trusted comment must name the tarball (a renamed signed bundle is
/// refused), the signed name must match the variant inside, and a signed
/// robodr-focal bundle does not silently replace robodr.
#[test]
fn signed_install_reads_one_private_copy_and_checks_name_and_variant() {
    if !minisign_available("signed_copy") {
        return;
    }
    let dir = TempDir::new("signed-copy");
    let root = dpkg_root(&dir);
    let tmp = dir.join("tmp");
    std::fs::create_dir_all(&tmp).unwrap();
    let (public, secret) = release_key(&dir, "release");
    let pk = public.to_str().unwrap();
    let v = "0.1.0-1";
    let f = Some(("RBF1:1", "RBF1:1"));
    let genuine = bundle_named(&dir, &stub_deb(&dir, v, f), "robodr-0.1.0-all", None);
    let t = signed_tarball(&dir.join("rel"), &genuine, &secret);
    // An unsigned bundle of the same layout with another package inside.
    let evil_dir = dir.join("evil-src");
    let evil = bundle_named(
        &evil_dir,
        &stub_deb_marked(&dir, v, f, "evil"),
        "robodr-0.1.0-all",
        None,
    );
    let evil_t = dir.join("evil.tar.gz");
    ok(&sh(Command::new("tar")
        .arg("-C")
        .arg(&evil_dir)
        .arg("-czf")
        .arg(&evil_t)
        .arg(evil.file_name().unwrap())));
    let trusted = dir.join("trusted");
    std::fs::create_dir_all(&trusted).unwrap();
    let script = trusted.join("install-bundle.sh");
    std::fs::copy(repo().join("packaging/install-bundle.sh"), &script).unwrap();
    let run = |args: &[&str]| run_bundle_with(&root, &script, args, false, &tmp);

    // Not a regular file: a symlink to the genuine tarball, and a FIFO.
    let odd = dir.join("odd");
    std::fs::create_dir_all(&odd).unwrap();
    let link = odd.join("robodr-0.1.0-all-offline.tar.gz");
    std::os::unix::fs::symlink(&t, &link).unwrap();
    let fifo = odd.join("robodr-0.2.0-all-offline.tar.gz");
    ok(&sh(Command::new("mkfifo").arg(&fifo)));
    for p in [&link, &fifo] {
        let o = run(&["install", "--pubkey", pk, "--tarball", p.to_str().unwrap()]);
        assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
        assert!(stderr(&o).contains("not a regular file"), "{}", stderr(&o));
        assert_eq!(installed(&root), "");
    }

    // The tarball is swapped for the unsigned one right after minisign
    // accepted it (a wrapper around the real minisign does the swap, as a
    // same-user process or removable media could): the private copy is
    // what gets installed, never the swapped file.
    let real = ok(&sh(Command::new("sh").args(["-c", "command -v minisign"])))
        .trim()
        .to_string();
    let wrap = dir.join("wrap");
    std::fs::create_dir_all(&wrap).unwrap();
    let w = wrap.join("minisign");
    std::fs::write(
        &w,
        format!(
            "#!/bin/sh\n{real} \"$@\"\nrc=$?\nif [ -n \"${{SWAP_FROM:-}}\" ]; then cp \"$SWAP_FROM\" \"$SWAP_TO\"; fi\nexit $rc\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&w, std::fs::Permissions::from_mode(0o755)).unwrap();
    let swapped = copy_signed(&t, &dir.join("swap"), "robodr-0.1.0-all-offline.tar.gz");
    let o = Command::new("sh")
        .arg(&script)
        .args([
            "install",
            "--pubkey",
            pk,
            "--tarball",
            swapped.to_str().unwrap(),
        ])
        .env("ROBODR_ROOT", &root)
        .env("TMPDIR", &tmp)
        .env_remove("ROBODR_ALLOW_UNSIGNED")
        .env(
            "PATH",
            format!("{}:{}", wrap.display(), std::env::var("PATH").unwrap()),
        )
        .env("SWAP_FROM", &evil_t)
        .env("SWAP_TO", &swapped)
        .output()
        .unwrap();
    let out = ok(&o);
    assert_eq!(
        std::fs::read(&swapped).unwrap(),
        std::fs::read(&evil_t).unwrap(),
        "the wrapper swapped the file: {out}"
    );
    assert_eq!(installed(&root), v);
    assert_eq!(stub_marker(&root), format!("{v} genuine"), "{out}");
    assert!(is_empty_dir(&tmp), "private staging directory removed");

    // A signed tarball renamed to pass for another one (here: the
    // robodr-focal bundle): its trusted comment names the original file.
    let renamed = copy_signed(
        &t,
        &dir.join("renamed"),
        "robodr-focal-0.1.0-all-offline.tar.gz",
    );
    let o = run(&[
        "install",
        "--pubkey",
        pk,
        "--tarball",
        renamed.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(stderr(&o).contains("trusted comment"), "{}", stderr(&o));

    // A genuinely signed robodr-focal bundle does not silently replace the
    // installed robodr (robodr-focal has no robodr-pulsard) ...
    let fdeb = stub_deb_pkg(&dir, "robodr-focal", v, f, "focal", None);
    let fb = bundle_named(
        &dir.join("focal-src"),
        &fdeb,
        "robodr-focal-0.1.0-all",
        None,
    );
    let ft = signed_tarball(&dir.join("rel-focal"), &fb, &secret);
    let ftb = ft.to_str().unwrap();
    let o = run(&["install", "--pubkey", pk, "--tarball", ftb]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("REPLACES robodr") && stderr(&o).contains("--allow-variant-switch"),
        "{}",
        stderr(&o)
    );
    assert_eq!(installed(&root), v);
    // ... a signed tarball whose name names the other variant is refused ...
    let mixed = signed_tarball_named(
        &dir.join("rel-mixed"),
        &fb,
        &secret,
        "robodr-0.1.0-all-offline.tar.gz",
    );
    let o = run(&[
        "install",
        "--pubkey",
        pk,
        "--tarball",
        mixed.to_str().unwrap(),
        "--allow-variant-switch",
    ]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("names the robodr variant but holds robodr-focal"),
        "{}",
        stderr(&o)
    );
    assert_eq!(installed(&root), v);
    // ... and the deliberate switch works.
    let t2 = ok(&run(&[
        "install",
        "--pubkey",
        pk,
        "--tarball",
        ftb,
        "--allow-variant-switch",
    ]));
    assert!(t2.contains("switching from robodr to robodr-focal"), "{t2}");
    assert_eq!(dpkg_state(&root, "robodr-focal").0, v);
    assert!(is_empty_dir(&tmp), "private staging directory removed");
}

/// Review finding (packaging, LOW-MED): only `ii` counted as installed, so
/// after a failed upgrade (robodr half-configured) an older release passed
/// `install` without the downgrade refusal.
#[test]
fn a_half_configured_package_counts_as_installed() {
    if !dpkg_available("half_configured") {
        return;
    }
    let dir = TempDir::new("half");
    let root = dpkg_root(&dir);
    let tmp = dir.join("tmp");
    std::fs::create_dir_all(&tmp).unwrap();
    let f = Some(("RBF1:1", "RBF1:1"));
    let b1 = bundle(&dir, &stub_deb(&dir, "0.1.0-1", f));
    let broken = stub_deb_pkg(
        &dir,
        "robodr",
        "0.2.0-1",
        f,
        "broken",
        Some("#!/bin/sh\necho postinst fails >&2\nexit 1\n"),
    );
    let b2 = bundle_named(&dir, &broken, "b2", None);
    let run = |b: &Path, args: &[&str]| {
        run_bundle_with(&root, &b.join("install-bundle.sh"), args, true, &tmp)
    };
    let o = run(&b2, &["install"]);
    assert_ne!(o.status.code(), Some(0), "{}", stderr(&o));
    let (v, st) = dpkg_state(&root, "robodr");
    assert_eq!(
        (v.as_str(), st.as_str()),
        ("0.2.0-1", "iF"),
        "half-configured"
    );
    let o = run(&b1, &["install"]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(stderr(&o).contains("downgrade"), "{}", stderr(&o));
    assert_eq!(dpkg_state(&root, "robodr").0, "0.2.0-1");
}

/// `install` ends with the installed release's host preflight
/// (`robodr-setup preflight`, sales-readiness T68), run on the same root.
/// It is advisory: a FAIL is a warning, the install still succeeds; a
/// release without robodr-setup is installed without it.
#[test]
fn install_runs_the_host_preflight_advisory_only() {
    if !dpkg_available("host_preflight") {
        return;
    }
    let dir = TempDir::new("preflight");
    let root = dpkg_root(&dir);
    let f = Some(("RBF1:1", "RBF1:1"));
    // 0.1.0: no robodr-setup.
    let b1 = bundle(&dir, &stub_deb(&dir, "0.1.0-1", f));
    let t = ok(&run_bundle(&root, &b1, &["install"]));
    assert!(t.contains("host preflight skipped"), "{t}");
    // 0.2.0: a robodr-setup whose preflight records its arguments and
    // reports a FAIL.
    let deb = stub_deb(&dir, "0.2.0-1", f);
    let st = dir.join("stage-robodr-0.2.0-1");
    let log = dir.join("preflight.args");
    let setup = st.join("usr/sbin/robodr-setup");
    std::fs::create_dir_all(setup.parent().unwrap()).unwrap();
    std::fs::write(
        &setup,
        format!(
            "#!/bin/sh\necho \"$*\" >{}\necho '[FAIL] btf        no BTF'\necho 'preflight: FAIL'\nexit 1\n",
            log.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&setup, std::fs::Permissions::from_mode(0o755)).unwrap();
    ok(&sh(Command::new("dpkg-deb")
        .args(["--root-owner-group", "-Zxz", "--build"])
        .arg(&st)
        .arg(&deb)));
    let b2 = bundle_named(&dir, &deb, "b2", None);
    let t = ok(&run_bundle(&root, &b2, &["install"]));
    assert_eq!(installed(&root), "0.2.0-1");
    assert!(t.contains("[FAIL] btf"), "{t}");
    assert!(
        t.contains("WARNING: the host preflight reports FAIL"),
        "{t}"
    );
    assert_eq!(
        std::fs::read_to_string(&log).unwrap().trim(),
        format!("preflight --root {}", root.display())
    );
}

// ------------------------------------------------------- RPM bundles ---
//
// The same install-bundle.sh drives `rpm -U` for an RPM bundle (RHEL /
// Rocky / Alma 9, Fedora): tested against the real rpm of this host, in a
// separate rpm root (`ROBODR_ROOT`, `rpm --root DIR --initdb`), with stub
// packages built by rpmbuild. Needs root, rpm, rpmbuild and rpm2archive (or
// rpm2cpio + cpio); skipped otherwise unless `ROBODR_REQUIRE_RPM_TEST=1`.

/// Whether the rpm tests can run here.
fn rpm_available(test: &str) -> bool {
    let ok = is_root()
        && have("rpm")
        && have("rpmbuild")
        && (have("rpm2archive") || (have("rpm2cpio") && have("cpio")));
    if !ok {
        assert!(
            std::env::var("ROBODR_REQUIRE_RPM_TEST").as_deref() != Ok("1"),
            "{test}: needs root, rpm, rpmbuild and rpm2archive (ROBODR_REQUIRE_RPM_TEST=1)"
        );
        eprintln!("SKIPPED {test}: needs root, rpm, rpmbuild and rpm2archive");
    }
    ok
}

/// A stub `robodr` RPM of `version` ("<version>-<release>", the form
/// install-bundle.sh compares), noarch; `formats` as [`stub_deb`];
/// `epoch` adds an RPM epoch (refused by install-bundle.sh).
fn stub_rpm(
    dir: &Path,
    version: &str,
    formats: Option<(&str, &str)>,
    marker: &str,
    epoch: Option<u32>,
) -> PathBuf {
    let (ver, rel) = version.rsplit_once('-').unwrap();
    let out = dir.join(format!("rpm-{marker}-{version}"));
    let payload = out.join("payload");
    std::fs::create_dir_all(payload.join("usr/lib/robodr")).unwrap();
    std::fs::write(
        payload.join("usr/lib/robodr/stub-version"),
        format!("{version} {marker}"),
    )
    .unwrap();
    let mut files = String::from("/usr/lib/robodr/stub-version\n");
    if let Some((w, r)) = formats {
        std::fs::create_dir_all(payload.join("usr/share/robodr")).unwrap();
        std::fs::write(
            payload.join("usr/share/robodr/formats"),
            format!("blackbox_write={w}\nblackbox_read={r}\n"),
        )
        .unwrap();
        files.push_str("/usr/share/robodr/formats\n");
    }
    let top = out.join("top");
    std::fs::create_dir_all(top.join("SPECS")).unwrap();
    let spec = top.join("SPECS/robodr.spec");
    std::fs::write(
        &spec,
        format!(
            "Name: robodr\nVersion: {ver}\nRelease: {rel}\n{}Summary: stub\nLicense: none\n\
             BuildArch: noarch\n%description\nstub robodr package for the install-bundle test\n\
             %install\ncp -a {}/. %{{buildroot}}/\n%files\n{files}",
            epoch.map(|e| format!("Epoch: {e}\n")).unwrap_or_default(),
            payload.display()
        ),
    )
    .unwrap();
    ok(&sh(Command::new("rpmbuild")
        .args(["-bb", "--define"])
        .arg(format!("_topdir {}", top.display()))
        .arg(&spec)));
    let rpm = top.join(format!("RPMS/noarch/robodr-{ver}-{rel}.noarch.rpm"));
    assert!(rpm.exists(), "{} not built", rpm.display());
    rpm
}

/// A fresh rpm root (its own rpm database).
fn rpm_root(dir: &Path) -> PathBuf {
    let root = dir.join("root");
    std::fs::create_dir_all(&root).unwrap();
    ok(&sh(Command::new("rpm")
        .arg("--root")
        .arg(&root)
        .arg("--initdb")));
    root
}

fn rpm_installed(root: &Path) -> String {
    let o = sh(Command::new("rpm").arg("--root").arg(root).args([
        "-q",
        "--qf",
        "%{VERSION}-%{RELEASE}",
        "robodr",
    ]));
    if o.status.success() {
        String::from_utf8_lossy(&o.stdout).into_owned()
    } else {
        String::new()
    }
}

#[test]
fn rpm_bundle_install_upgrade_rollback_downgrade_floor_and_format_gate() {
    if !rpm_available("rpm_bundle") {
        return;
    }
    let dir = TempDir::new("rpm");
    let root = rpm_root(&dir);
    let tmp = dir.join("tmp");
    std::fs::create_dir_all(&tmp).unwrap();
    let f = Some(("RBF1:1", "RBF1:1"));
    // v1: legacy (no formats file); v2 current; v3 writes format 2 and
    // carries the security floor v2 in its bundle.
    let (v1, v2, v3) = ("0.1.0~alpha.1-1", "0.1.0-1", "0.2.0-1");
    let b1 = bundle(&dir, &stub_rpm(&dir, v1, None, "genuine", None));
    let b2 = bundle(&dir, &stub_rpm(&dir, v2, f, "genuine", None));
    let b3 = bundle_named(
        &dir,
        &stub_rpm(&dir, v3, Some(("RBF1:2", "RBF1:1,RBF1:2")), "genuine", None),
        "b3",
        Some(v2),
    );
    let run = |b: &Path, args: &[&str]| {
        run_bundle_with(&root, &b.join("install-bundle.sh"), args, true, &tmp)
    };

    // Unsigned install refused without the lab override.
    let o = run_bundle_with(
        &root,
        &b1.join("install-bundle.sh"),
        &["install"],
        false,
        &tmp,
    );
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert_eq!(rpm_installed(&root), "");

    // Install v1 (rpm), the agent writes its black box; upgrade to v2.
    let t = ok(&run(&b1, &["install"]));
    assert!(t.contains("(rpm;"), "{t}");
    assert_eq!(rpm_installed(&root), v1);
    let bb = root.join("var/lib/robodr/blackbox/agentd");
    std::fs::create_dir_all(bb.parent().unwrap()).unwrap();
    record_black_box(&bb);
    let t = ok(&run(&b2, &["install"]));
    assert!(t.contains("black-box formats OK for 0.1.0-1"), "{t}");
    assert_eq!(rpm_installed(&root), v2);
    let kept = root.join("var/lib/robodr/releases").join(v2);
    assert!(kept.join("formats").exists());
    assert!(kept.join("robodr-0.1.0-1.noarch.rpm").exists());

    // rpm's version order: the pre-release v1 is older, so `install` of b1
    // is a downgrade, refused; rollback to the kept v1 works.
    let o = run(&b1, &["install"]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(stderr(&o).contains("downgrade"), "{}", stderr(&o));
    assert_eq!(rpm_installed(&root), v2);
    let t = ok(&run(&b2, &["rollback", v1]));
    assert!(
        t.contains("rolling back to robodr 0.1.0~alpha.1-1 (rpm)"),
        "{t}"
    );
    assert_eq!(rpm_installed(&root), v1);
    assert!(
        black_box_verifies(&bb),
        "the black box survives the rollback"
    );
    // A deliberate downgrade (--allow-downgrade) is possible above the floor.
    ok(&run(&b2, &["install"]));
    ok(&run(&b1, &["install", "--allow-downgrade"]));
    assert_eq!(rpm_installed(&root), v1);

    // v3: its bundle raises the security floor to v2.
    let t = ok(&run(&b3, &["install"]));
    assert!(t.contains("security floor raised to 0.1.0-1"), "{t}");
    assert_eq!(rpm_installed(&root), v3);
    // Below the floor: refused by rollback and by install, no override.
    let o = run(&b3, &["rollback", v1]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(stderr(&o).contains("security floor"), "{}", stderr(&o));
    let o = run(&b1, &["install", "--allow-downgrade"]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(stderr(&o).contains("security floor"), "{}", stderr(&o));
    assert_eq!(rpm_installed(&root), v3);

    // v3 writes format 2: rolling back to v2 (reads only 1) is refused by
    // the format gate, naming the segment.
    let mut seg = FRAME_MAGIC.to_vec();
    seg.extend_from_slice(&64u32.to_be_bytes());
    seg.push(2);
    seg.extend_from_slice(&[0u8; 63]);
    std::fs::write(bb.join("seg-0000000000000009.rbb"), &seg).unwrap();
    let o = run(&b3, &["rollback", v2]);
    let e = stderr(&o);
    assert_eq!(o.status.code(), Some(1), "{e}");
    assert!(
        e.contains("REFUSED") && e.contains("RBF1:2") && e.contains("seg-0000000000000009.rbb"),
        "{e}"
    );
    assert_eq!(rpm_installed(&root), v3);
    // `list` shows what each kept release reads.
    let t = ok(&run(&b3, &["list"]));
    assert!(
        t.contains(&format!("{v3}  black-box formats read: RBF1:1 RBF1:2")),
        "{t}"
    );
    // Archived chain: the rollback proceeds.
    let archive = root.join("var/lib/robodr/archive");
    std::fs::create_dir_all(&archive).unwrap();
    std::fs::rename(&bb, archive.join("blackbox-agentd")).unwrap();
    ok(&run(&b3, &["rollback", v2]));
    assert_eq!(rpm_installed(&root), v2);

    // A tampered kept release is refused.
    let kept3 = root
        .join("var/lib/robodr/releases")
        .join(v3)
        .join("robodr-0.2.0-1.noarch.rpm");
    let mut b = std::fs::read(&kept3).unwrap();
    let n = b.len() - 1;
    b[n] ^= 1;
    std::fs::write(&kept3, b).unwrap();
    let o = run(&b3, &["rollback", v3]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("fails its checksums"), "{}", stderr(&o));
    assert_eq!(rpm_installed(&root), v2);

    // An RPM with an epoch is refused (versions would not compare as written).
    let be = bundle_named(
        &dir,
        &stub_rpm(&dir, "0.3.0-1", f, "epoch", Some(1)),
        "epoch",
        None,
    );
    let o = run(&be, &["install"]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(stderr(&o).contains("epoch"), "{}", stderr(&o));
    assert_eq!(rpm_installed(&root), v2);

    // A .deb bundle on a unit where robodr is installed as an RPM: refused
    // (when dpkg is here to try it).
    if have("dpkg-deb") {
        let _ = dpkg_root(&dir);
        let bd = bundle(&dir, &stub_deb(&dir, "0.4.0-1", f));
        let o = run(&bd, &["install"]);
        assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
        assert!(
            stderr(&o).contains("installed here as an rpm package"),
            "{}",
            stderr(&o)
        );
        assert_eq!(installed(&root), "");
    }
    assert!(
        is_empty_dir(&tmp),
        "temporary files left in {}",
        tmp.display()
    );
}

#[test]
fn rpm_bundle_from_make_bundle_installs_signed_only() {
    if !rpm_available("rpm_signed") {
        return;
    }
    if !have("minisign") {
        assert!(
            std::env::var("ROBODR_REQUIRE_RPM_TEST").as_deref() != Ok("1"),
            "rpm_signed: needs minisign (ROBODR_REQUIRE_RPM_TEST=1)"
        );
        eprintln!("SKIPPED rpm_signed: needs minisign");
        return;
    }
    let dir = TempDir::new("rpm-signed");
    let root = rpm_root(&dir);
    let tmp = dir.join("tmp");
    std::fs::create_dir_all(&tmp).unwrap();
    let (public, secret) = release_key(&dir, "release");
    let rpm = stub_rpm(&dir, "0.1.0-1", Some(("RBF1:1", "RBF1:1")), "genuine", None);
    // The real make-bundle.sh around the RPM.
    let out = dir.join("dist");
    let o = Command::new("bash")
        .arg(repo().join("packaging/make-bundle.sh"))
        .arg("--rpm")
        .arg(&rpm)
        .arg("--out")
        .arg(&out)
        .env("SOURCE_DATE_EPOCH", "1790000000")
        .output()
        .unwrap();
    let t = ok(&o);
    let tarball = PathBuf::from(t.lines().last().unwrap().trim());
    let name = tarball.file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        name.starts_with("robodr-") && name.ends_with("-all-rpm-offline.tar.gz"),
        "{name}"
    );
    let list = ok(&sh(Command::new("tar").arg("-tzf").arg(&tarball)));
    for want in [
        "/robodr-0.1.0-1.noarch.rpm",
        "/install-bundle.sh",
        "/security-floor",
        "/doc/THIRD_PARTY_NOTICES",
        "/doc/GPL-2.0-SOURCE-OFFER",
        "/doc/licenses/LICENSE-GPL-2.0",
        "/SHA256SUMS",
    ] {
        assert!(
            list.lines().any(|l| l.ends_with(want)),
            "{want} missing:\n{list}"
        );
    }
    minisign(&secret, &tarball);
    let trusted = dir.join("trusted");
    std::fs::create_dir_all(&trusted).unwrap();
    let script = trusted.join("install-bundle.sh");
    std::fs::copy(repo().join("packaging/install-bundle.sh"), &script).unwrap();
    let (pk, tb) = (public.to_str().unwrap(), tarball.to_str().unwrap());

    // Tampered tarball: signature fails, nothing installed.
    let bad = out.join("tampered-rpm-offline.tar.gz");
    let mut b = std::fs::read(&tarball).unwrap();
    let n = b.len() / 2;
    b[n] ^= 1;
    std::fs::write(&bad, &b).unwrap();
    std::fs::copy(
        tarball.with_extension("gz.minisig"),
        out.join("tampered-rpm-offline.tar.gz.minisig"),
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
    assert!(
        stderr(&o).contains("SIGNATURE CHECK FAILED"),
        "{}",
        stderr(&o)
    );
    assert_eq!(rpm_installed(&root), "");

    // The genuine one installs from its private extraction.
    let t = ok(&run_bundle_with(
        &root,
        &script,
        &["install", "--pubkey", pk, "--tarball", tb],
        false,
        &tmp,
    ));
    assert!(t.contains("signature OK"), "{t}");
    assert_eq!(rpm_installed(&root), "0.1.0-1");
    assert_eq!(stub_marker(&root), "0.1.0-1 genuine");
    assert!(is_empty_dir(&tmp), "private staging directory removed");
}
