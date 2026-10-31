//! The `deb` and `robodr-rules` installers.
//!
//! `deb` runs the **real** dpkg of this host against a separate dpkg root
//! (`install.dpkg_root`, `dpkg --root=DIR`), with stub packages built by
//! `dpkg-deb`, as `crates/robodr-fleet/tests/packaging.rs` does; it needs
//! root and dpkg and is skipped otherwise (`ROBODR_REQUIRE_DPKG_TEST=1`
//! makes a skip a failure). The host's own dpkg database is never touched.

mod common;

use common::*;
use robodr_pkg::rpk::{HealthCheck, Kind};
use std::path::{Path, PathBuf};
use std::process::Command;

fn have(tool: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {tool}")])
        .output()
        .is_ok_and(|o| o.status.success())
}

fn dpkg_available(test: &str) -> bool {
    let ok = robodr_deliverd::users::is_root() && have("dpkg") && have("dpkg-deb");
    if !ok {
        if std::env::var("ROBODR_REQUIRE_DPKG_TEST").is_ok_and(|v| v == "1") {
            panic!("{test}: needs root and dpkg (ROBODR_REQUIRE_DPKG_TEST=1)");
        }
        eprintln!("SKIPPED {test}: needs root and dpkg");
    }
    ok
}

fn dpkg_root(u: &Unit) -> PathBuf {
    let root = u.cfg.install.dpkg_root.clone().unwrap();
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

/// A stub `.deb` (`Architecture: all`), with `usr/lib/robodr-stub/ok`
/// when `healthy`, and a `postinst` when `script`.
fn stub_deb(dir: &Path, version: &str, healthy: bool, script: bool) -> Vec<u8> {
    let st = dir.join(format!("stage-{version}-{healthy}-{script}"));
    let _ = std::fs::remove_dir_all(&st);
    std::fs::create_dir_all(st.join("DEBIAN")).unwrap();
    std::fs::create_dir_all(st.join("usr/lib/robodr-stub")).unwrap();
    std::fs::write(
        st.join("DEBIAN/control"),
        format!(
            "Package: robodr-stub\nVersion: {version}\nArchitecture: all\n\
             Maintainer: RoboDR tests <tests@invalid>\nDescription: stub\n"
        ),
    )
    .unwrap();
    if script {
        let p = st.join("DEBIAN/postinst");
        std::fs::write(&p, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    }
    std::fs::write(st.join("usr/lib/robodr-stub/version"), version).unwrap();
    if healthy {
        std::fs::write(st.join("usr/lib/robodr-stub/ok"), b"").unwrap();
    }
    let out = dir.join(format!("robodr-stub_{version}.deb"));
    let o = Command::new("dpkg-deb")
        .args(["--root-owner-group", "-Zxz", "--build"])
        .arg(&st)
        .arg(&out)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    std::fs::read(&out).unwrap()
}

fn deb_rpk(u: &Unit, serial: u64, deb: &[u8], scripts_allowed: bool) -> PathBuf {
    let mut s = spec("robodr-stub", serial, Kind::Deb);
    s.sbom_path = Some("sbom.cdx.json".into());
    s.install.allow_maintainer_scripts = scripts_allowed;
    s.health = vec![HealthCheck::FilePresent {
        path: format!(
            "{}/usr/lib/robodr-stub/ok",
            u.cfg.install.dpkg_root.as_ref().unwrap().display()
        ),
    }];
    u.rpk(&s, &[("robodr-stub.deb", deb), ("sbom.cdx.json", SBOM)])
}

fn installed_version(u: &Unit) -> String {
    let o = Command::new("dpkg-query")
        .arg(format!(
            "--admindir={}",
            u.cfg
                .install
                .dpkg_root
                .as_ref()
                .unwrap()
                .join("var/lib/dpkg")
                .display()
        ))
        .args(["-W", "-f", "${Version}", "robodr-stub"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn deb_install_upgrade_and_automatic_rollback_with_real_dpkg() {
    if !dpkg_available("deb_install_upgrade_rollback") {
        return;
    }
    let u = Unit::new("deb");
    let root = dpkg_root(&u);
    let d1 = stub_deb(&u.work, "1.0", true, false);
    let r1 = deb_rpk(&u, 1, &d1, false);
    let b1 = u.bundle(1, None, std::slice::from_ref(&r1));
    u.pack("p1", 1, &[r1], std::slice::from_ref(&b1));
    let mut e = u.open();
    let reps = u.run(&mut e, 5);
    assert!(
        reps.iter()
            .any(|r| r.installed == vec!["robodr-stub 1".to_string()]),
        "{reps:?}"
    );
    assert_eq!(installed_version(&u), "1.0");
    assert_eq!(
        std::fs::read(root.join("usr/lib/robodr-stub/version")).unwrap(),
        b"1.0"
    );
    let staged = u.notes_of("robodr.deliver.staged");
    assert_eq!(staged[0]["deb"]["package"], "robodr-stub");
    assert_eq!(staged[0]["maintainer_scripts_allowed"], false);

    // 2.0 lacks the file its health check needs: dpkg downgrades back.
    let d2 = stub_deb(&u.work, "2.0", false, false);
    let r2 = deb_rpk(&u, 2, &d2, false);
    let b2 = u.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&r2));
    u.pack("p2", 2, &[r2], &[b2]);
    let reps = u.run(&mut e, 5);
    assert!(
        reps.iter()
            .any(|r| r.rolled_back == vec!["robodr-stub 2 -> 1".to_string()]),
        "{reps:?}"
    );
    assert_eq!(installed_version(&u), "1.0");
    assert_eq!(
        std::fs::read(root.join("usr/lib/robodr-stub/version")).unwrap(),
        b"1.0"
    );
    assert!(u
        .rules_found()
        .contains(&"robot.deliver.health_failed".to_string()));
    assert!(u.black_box_verifies());
}

#[test]
fn a_deb_with_maintainer_scripts_needs_the_release_to_allow_them() {
    if !dpkg_available("deb_maintainer_scripts") {
        return;
    }
    let u = Unit::new("deb-scripts");
    dpkg_root(&u);
    let d = stub_deb(&u.work, "1.0", true, true);
    let r = deb_rpk(&u, 1, &d, false);
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    u.pack("p1", 1, &[r], &[b]);
    let mut e = u.open();
    let reps = u.run(&mut e, 4);
    assert!(
        reps.iter().any(|r| r
            .refused
            .iter()
            .any(|x| x.contains("maintainer scripts (postinst)"))),
        "{reps:?}"
    );
    assert_eq!(installed_version(&u), "");
    assert!(u.notes_of("robodr.deliver.activating").is_empty());
}

#[test]
fn a_deb_for_another_architecture_is_refused() {
    if !dpkg_available("deb_arch") {
        return;
    }
    let u = Unit::new("deb-arch");
    dpkg_root(&u);
    stub_deb(&u.work, "1.0", true, false);
    // Rewrite the control's architecture by rebuilding with amd64.
    let st = u.work.join("stage-1.0-true-false");
    let c = std::fs::read_to_string(st.join("DEBIAN/control")).unwrap();
    std::fs::write(
        st.join("DEBIAN/control"),
        c.replace("Architecture: all", "Architecture: amd64"),
    )
    .unwrap();
    let out = u.work.join("amd64.deb");
    assert!(Command::new("dpkg-deb")
        .args(["--root-owner-group", "--build"])
        .arg(&st)
        .arg(&out)
        .status()
        .unwrap()
        .success());
    let r = deb_rpk(&u, 1, &std::fs::read(&out).unwrap(), false);
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    u.pack("p1", 1, &[r], &[b]);
    let mut e = u.open();
    let reps = u.run(&mut e, 4);
    assert!(
        reps.iter()
            .any(|r| r.refused.iter().any(|x| x.contains("amd64"))),
        "{reps:?}"
    );
}

/// Copy `/bin/sh` and the libraries it loads into `root`: dpkg runs
/// maintainer scripts chrooted into `--root`.
fn shell_into(root: &Path) {
    let sh = std::fs::canonicalize("/bin/sh").unwrap();
    let mut files = vec![sh.clone()];
    let o = Command::new("ldd").arg(&sh).output().unwrap();
    for l in String::from_utf8_lossy(&o.stdout).lines() {
        if let Some(p) = l.split_whitespace().find(|w| w.starts_with('/')) {
            files.push(PathBuf::from(p));
        }
    }
    for f in &files {
        let dest = root.join(f.strip_prefix("/").unwrap());
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::fs::copy(f, &dest).unwrap();
    }
    let dest = root.join("bin/sh");
    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
    if !dest.exists() {
        std::fs::copy(&sh, &dest).unwrap();
    }
}

/// T52: every `dpkg --install` carries ROBODR_DELIVERD_INSTALL=1 into the
/// maintainer scripts, so RoboDR's own postinst knows its caller is this
/// agent and does not restart robodr-deliverd.service from inside the
/// dpkg run the agent is waiting for (which would kill dpkg and the
/// postinst with it). Nothing else of the agent's environment leaks.
#[test]
fn maintainer_scripts_see_the_deliverd_install_marker() {
    if !dpkg_available("deb_install_marker") {
        return;
    }
    let u = Unit::new("deb-marker");
    let root = dpkg_root(&u);
    shell_into(&root);
    stub_deb(&u.work, "1.0", true, true);
    let st = u.work.join("stage-1.0-true-true");
    std::fs::write(
        st.join("DEBIAN/postinst"),
        "#!/bin/sh\necho \"marker=${ROBODR_DELIVERD_INSTALL:-unset} \
         home=${HOME:-unset}\" >/postinst-env\nexit 0\n",
    )
    .unwrap();
    let out = u.work.join("marker.deb");
    assert!(Command::new("dpkg-deb")
        .args(["--root-owner-group", "--build"])
        .arg(&st)
        .arg(&out)
        .status()
        .unwrap()
        .success());
    let r = deb_rpk(&u, 1, &std::fs::read(&out).unwrap(), true);
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    u.pack("p1", 1, &[r], &[b]);
    let mut e = u.open();
    let reps = u.run(&mut e, 5);
    assert!(
        reps.iter()
            .any(|r| r.installed == vec!["robodr-stub 1".to_string()]),
        "{reps:?}"
    );
    assert_eq!(
        std::fs::read_to_string(root.join("postinst-env")).unwrap(),
        "marker=1 home=unset\n"
    );
}

/// A stub of RoboDR's own package `package` (`robodr` or
/// `robodr-focal`, conflicting with and replacing the other, as the real
/// ones), shipping `usr/sbin/robodr-deliverd` running `body` and the
/// files `files` (path, content). Returns the `.deb`'s path.
fn robodr_deb(
    u: &Unit,
    package: &str,
    version: &str,
    body: &str,
    files: &[(&str, &str)],
) -> PathBuf {
    let other = if package == "robodr" {
        "robodr-focal"
    } else {
        "robodr"
    };
    let st = u.work.join(format!("agent-stage-{package}-{version}"));
    let _ = std::fs::remove_dir_all(&st);
    std::fs::create_dir_all(st.join("DEBIAN")).unwrap();
    std::fs::create_dir_all(st.join("usr/sbin")).unwrap();
    std::fs::write(
        st.join("DEBIAN/control"),
        format!(
            "Package: {package}\nVersion: {version}\nArchitecture: all\n\
             Conflicts: {other}\nReplaces: {other}\n\
             Maintainer: RoboDR tests <tests@invalid>\nDescription: stub\n"
        ),
    )
    .unwrap();
    let exe = st.join("usr/sbin/robodr-deliverd");
    std::fs::write(&exe, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&exe, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    for (p, text) in files {
        let f = st.join(p);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, text).unwrap();
    }
    let out = u.work.join(format!("{package}_{version}.deb"));
    let o = Command::new("dpkg-deb")
        .args(["--root-owner-group", "-Zxz", "--build"])
        .arg(&st)
        .arg(&out)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    out
}

/// RoboDR's own package `robodr` (as from the designated programme),
/// shipping `usr/sbin/robodr-deliverd` as a shell script running `body`:
/// it stands in for a self-upgrade that replaces the agent's binary.
fn agent_rpk(u: &Unit, serial: u64, version: &str, body: &str) -> PathBuf {
    agent_rpk_with(u, serial, version, body, |_| {})
}

fn agent_rpk_with(
    u: &Unit,
    serial: u64,
    version: &str,
    body: &str,
    edit: impl FnOnce(&mut robodr_release::ops::RpkSpec),
) -> PathBuf {
    let deb = std::fs::read(robodr_deb(u, "robodr", version, body, &[])).unwrap();
    let mut s = spec("robodr", serial, Kind::Deb);
    s.sbom_path = Some("sbom.cdx.json".into());
    s.health = vec![HealthCheck::FilePresent {
        path: format!(
            "{}/usr/sbin/robodr-deliverd",
            u.cfg.install.dpkg_root.as_ref().unwrap().display()
        ),
    }];
    edit(&mut s);
    u.rpk(&s, &[("robodr.deb", &deb), ("sbom.cdx.json", SBOM)])
}

fn package_version(u: &Unit, package: &str) -> String {
    let o = Command::new("dpkg-query")
        .arg(format!(
            "--admindir={}",
            u.cfg
                .install
                .dpkg_root
                .as_ref()
                .unwrap()
                .join("var/lib/dpkg")
                .display()
        ))
        .args(["-W", "-f", "${Version}", package])
        .output()
        .unwrap();
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// T52 follow-up: a deb install that replaced the agent's own binary
/// commits only if the NEW binary passes `self-check`, judged by the old
/// process while it can still roll back. A replacement that cannot start
/// is rolled back to the previous version; one that can is installed and
/// was called as `<path> self-check --config <file>`.
#[test]
fn a_self_upgrade_whose_new_binary_fails_self_check_is_rolled_back() {
    if !dpkg_available("deb_self_check") {
        return;
    }
    let u = Unit::with("deb-self-check", |v| {
        v["install"]["robodr_programme"] = PROGRAMME.into();
    });
    let root = dpkg_root(&u);
    let r1 = agent_rpk(&u, 1, "1.0", "exit 0");
    let b1 = u.bundle(1, None, std::slice::from_ref(&r1));
    u.pack("p1", 1, &[r1], std::slice::from_ref(&b1));
    let mut e = u.open();
    let reps = u.run(&mut e, 5);
    assert!(
        reps.iter()
            .any(|r| r.installed == vec!["robodr 1".to_string()]),
        "{reps:?}"
    );
    // The agent now "runs" version 1's binary.
    let exe = root.join("usr/sbin/robodr-deliverd");
    let cfg_file = u.work.join("deliverd.json");
    e.set_self_check(Some(robodr_deliverd::own::SelfCheck::new(
        robodr_deliverd::own::OwnBinary::of(&exe).unwrap(),
        cfg_file.clone(),
    )));

    // 2.0 passes its declared checks, but its binary cannot start.
    let r2 = agent_rpk(&u, 2, "2.0", "echo cannot start >&2\nexit 1");
    let b2 = u.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&r2));
    u.pack("p2", 2, &[r2], std::slice::from_ref(&b2));
    let reps = u.run(&mut e, 5);
    assert!(
        reps.iter()
            .any(|r| r.rolled_back == vec!["robodr 2 -> 1".to_string()]),
        "{reps:?}"
    );
    assert_eq!(package_version(&u, "robodr"), "1.0");
    let failed: Vec<_> = u
        .notes_of("robodr.deliver.health")
        .into_iter()
        .filter(|n| n["serial"] == 2)
        .collect();
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert_eq!(failed[0]["passed"], false);
    let check = failed[0]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["check"] == "robodr-deliverd self-check")
        .cloned()
        .unwrap();
    assert_eq!(check["passed"], false);
    assert!(
        check["detail"].as_str().unwrap().contains("cannot start"),
        "{check}"
    );

    // 3.0's binary passes its self-check: installed.
    let args = root.join("self-check-args");
    let r3 = agent_rpk(
        &u,
        3,
        "3.0",
        &format!("echo \"$@\" >{}\nexit 0", args.display()),
    );
    let b3 = u.bundle(3, Some(bundle_hash(&b2)), std::slice::from_ref(&r3));
    u.pack("p3", 3, &[r3], &[b3]);
    let reps = u.run(&mut e, 5);
    assert!(
        reps.iter()
            .any(|r| r.installed == vec!["robodr 3".to_string()]),
        "{reps:?}"
    );
    assert_eq!(package_version(&u, "robodr"), "3.0");
    assert_eq!(
        std::fs::read_to_string(&args).unwrap(),
        format!("self-check --config {}\n", cfg_file.display())
    );
    assert!(u.black_box_verifies());
}

/// WP14: when a self-upgrade fails its self-check but the security floor
/// blocks the rollback, the failing binary stays at the path. The engine
/// knows (`own_replacement_failed`), so `run` keeps the old code running
/// instead of exiting 3 into it; a later release that passes clears it.
/// Meanwhile the self-check judges only a switch that replaced the
/// agent's binary: an unrelated deb is installed, not rolled back because
/// the failing binary is still in place.
#[test]
fn a_self_upgrade_whose_rollback_the_floor_blocks_is_known_to_have_failed() {
    if !dpkg_available("deb_self_check_floor") {
        return;
    }
    let u = Unit::with("deb-self-check-floor", |v| {
        v["install"]["robodr_programme"] = PROGRAMME.into();
    });
    let root = dpkg_root(&u);
    let r1 = agent_rpk(&u, 1, "1.0", "exit 0");
    let b1 = u.bundle(1, None, std::slice::from_ref(&r1));
    u.pack("p1", 1, &[r1], std::slice::from_ref(&b1));
    let mut e = u.open();
    u.run(&mut e, 5);
    assert_eq!(package_version(&u, "robodr"), "1.0");
    let exe = root.join("usr/sbin/robodr-deliverd");
    e.set_self_check(Some(robodr_deliverd::own::SelfCheck::new(
        robodr_deliverd::own::OwnBinary::of(&exe).unwrap(),
        u.work.join("deliverd.json"),
    )));
    assert!(!e.own_replacement_failed());

    // 2.0 raises the floor to 2 and its binary cannot start.
    let r2 = agent_rpk_with(&u, 2, "2.0", "exit 1", |s| s.security_floor = 2);
    let b2 = u.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&r2));
    u.pack("p2", 2, &[r2], std::slice::from_ref(&b2));
    let reps = u.run(&mut e, 5);
    assert!(
        reps.iter()
            .any(|r| r.blocked == vec!["robodr 2".to_string()]),
        "{reps:?}"
    );
    assert_eq!(package_version(&u, "robodr"), "2.0");
    assert!(e.own_replacement_failed());

    // An unrelated deb: its switch did not replace the agent's binary.
    let d = stub_deb(&u.work, "1.0", true, false);
    let rs = deb_rpk(&u, 1, &d, false);
    let bs = u.bundle(3, Some(bundle_hash(&b2)), std::slice::from_ref(&rs));
    u.pack("p3", 3, &[rs], std::slice::from_ref(&bs));
    let reps = u.run(&mut e, 5);
    assert!(
        reps.iter()
            .any(|r| r.installed == vec!["robodr-stub 1".to_string()]),
        "{reps:?}"
    );
    assert!(reps.iter().all(|r| r.rolled_back.is_empty()), "{reps:?}");
    let h = u
        .notes_of("robodr.deliver.health")
        .into_iter()
        .find(|n| n["name"] == "robodr-stub")
        .unwrap();
    assert!(
        h["checks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["check"] != "robodr-deliverd self-check"),
        "{h}"
    );
    assert!(e.own_replacement_failed());

    // 3.0 passes: installed, and nothing failing is in place any more.
    let r3 = agent_rpk_with(&u, 3, "3.0", "exit 0", |s| s.security_floor = 2);
    let b3 = u.bundle(4, Some(bundle_hash(&bs)), std::slice::from_ref(&r3));
    u.pack("p4", 4, &[r3], &[b3]);
    let reps = u.run(&mut e, 5);
    assert!(
        reps.iter()
            .any(|r| r.installed == vec!["robodr 3".to_string()]),
        "{reps:?}"
    );
    assert!(!e.own_replacement_failed());
    assert!(u.black_box_verifies());
}

/// WP14: when the agent cannot check a replacement of its own binary
/// (`/proc/self/exe` did not resolve), the skip is noted in the journal
/// and nothing is checked.
#[test]
fn an_unavailable_self_check_is_noted_in_the_journal() {
    let u = Unit::new("self-check-unavailable");
    let mut e = u.open();
    e.self_check_unavailable("no /proc").unwrap();
    assert!(!e.own_replacement_failed());
    e.close().unwrap();
    let n = u.notes_of("robodr.deliver.self_check_unavailable");
    assert_eq!(n.len(), 1, "{n:?}");
    assert_eq!(n[0]["why"], "no /proc");
    assert!(u.black_box_verifies());
}

/// T52, the package side: the upgrade-restart loop of RoboDR's postinst
/// (between its `restart_on_upgrade` markers), with `systemctl` replaced
/// by a shell function that logs. Under the agent's marker every unit but
/// robodr-deliverd.service is try-restarted; without it (apt, an operator,
/// install-bundle.sh) all of them, as before.
#[test]
fn postinst_leaves_the_deliverd_restart_to_the_agent_under_its_marker() {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/deb/postinst");
    let s = std::fs::read_to_string(&p).unwrap();
    let a = s
        .find("# >>> restart_on_upgrade")
        .expect("postinst has no restart_on_upgrade block");
    let b = s.find("# <<< restart_on_upgrade").unwrap();
    let block = &s[a..b];
    let t = Tmp::new("postinst-restart");
    let run = |marker: Option<&str>| -> Vec<String> {
        let log = t.path().join(format!("log-{}", marker.unwrap_or("none")));
        let script = format!("set -e\nsystemctl() {{ echo \"$*\" >>\"$LOG\"; }}\n{block}\n");
        let mut c = Command::new("/bin/sh");
        c.args(["-c", &script, "sh"]).env("LOG", &log);
        match marker {
            Some(m) => c.env("ROBODR_DELIVERD_INSTALL", m),
            None => c.env_remove("ROBODR_DELIVERD_INSTALL"),
        };
        let o = c.output().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        std::fs::read_to_string(&log)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    };
    let all = run(None);
    // The gateway and the executor are never restarted here (gated_restart
    // marks them pending after the block).
    assert_eq!(all.len(), 8, "{all:?}");
    assert!(!all
        .iter()
        .any(|l| l.contains("executor") || l.contains("firewall-gw")));
    assert!(all.contains(&"try-restart robodr-deliverd.service".to_string()));
    let other = run(Some("0"));
    assert_eq!(other, all);
    let under = run(Some("1"));
    let expected: Vec<String> = all
        .iter()
        .filter(|l| *l != "try-restart robodr-deliverd.service")
        .cloned()
        .collect();
    assert_eq!(under, expected);
    assert!(under.contains(&"try-restart robodr-agentd.service".to_string()));
}

/// An RPK of RoboDR's own package `package` at `version` ([`robodr_deb`],
/// a binary that starts, the extra files `files`).
fn robodr_rpk(
    u: &Unit,
    package: &str,
    serial: u64,
    version: &str,
    files: &[(&str, &str)],
) -> PathBuf {
    let deb = std::fs::read(robodr_deb(u, package, version, "exit 0", files)).unwrap();
    let mut s = spec(package, serial, Kind::Deb);
    s.sbom_path = Some("sbom.cdx.json".into());
    s.health = vec![HealthCheck::FilePresent {
        path: format!(
            "{}/usr/sbin/robodr-deliverd",
            u.cfg.install.dpkg_root.as_ref().unwrap().display()
        ),
    }];
    let name = format!("{package}.deb");
    u.rpk(&s, &[(name.as_str(), &deb), ("sbom.cdx.json", SBOM)])
}

/// Reviews H6, M8, M9: RoboDR's own package, delivered from the
/// designated programme, follows install-bundle.sh's rules. The unit's
/// robodr 1.0 came from install-bundle.sh (dpkg, not the agent):
///
/// * the other variant is refused (a switch runs the old variant's prerm;
///   an operator action);
/// * a first delivery that is not the installed version is refused (the
///   agent would have nothing to roll back to), and so is a dpkg
///   downgrade; the installed version itself is adopted;
/// * the unit's security floor and the SOC ring minimum refuse what is
///   below them;
/// * a verified black-box segment the release cannot read refuses it; a
///   release that reads it is installed.
#[test]
fn robodrs_own_package_follows_install_bundles_rules() {
    if !dpkg_available("robodr_rules") {
        return;
    }
    let u = Unit::with("robodr-rules", |v| {
        v["install"]["robodr_programme"] = PROGRAMME.into();
    });
    let root = dpkg_root(&u);
    let o = Command::new("dpkg")
        .arg(format!("--root={}", root.display()))
        .arg("-i")
        .arg(robodr_deb(&u, "robodr", "1.0", "exit 0", &[]))
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let mut e = u.open();
    let mut prev: Option<PathBuf> = None;
    let mut seq = 0;
    let mut deliver = |e: &mut robodr_deliverd::Engine, r: PathBuf| {
        seq += 1;
        let b = u.bundle(
            seq,
            prev.as_ref().map(|p| bundle_hash(p)),
            std::slice::from_ref(&r),
        );
        u.pack(&format!("p{seq}"), seq, &[r], std::slice::from_ref(&b));
        prev = Some(b);
        u.run(e, 5)
    };
    let refused = |reps: &[robodr_deliverd::engine::TickReport], what: &str| {
        assert!(
            reps.iter()
                .any(|r| r.refused.iter().any(|x| x.contains(what))),
            "{what}: {reps:?}"
        );
        assert!(reps.iter().all(|r| r.installed.is_empty()), "{reps:?}");
    };
    // H6: no variant switch.
    let reps = deliver(&mut e, robodr_rpk(&u, "robodr-focal", 1, "1.0", &[]));
    refused(&reps, "variant switch");
    assert_eq!(package_version(&u, "robodr"), "1.0");
    assert_eq!(package_version(&u, "robodr-focal"), "");
    // M8: the first delivery must be the installed version; M9: never a
    // dpkg downgrade.
    let reps = deliver(&mut e, robodr_rpk(&u, "robodr", 2, "2.0", &[]));
    refused(&reps, "first delivery of robodr");
    let reps = deliver(&mut e, robodr_rpk(&u, "robodr", 3, "0.9", &[]));
    refused(&reps, "older than the installed 1.0");
    let reps = deliver(&mut e, robodr_rpk(&u, "robodr", 4, "1.0", &[]));
    assert!(
        reps.iter()
            .any(|r| r.installed == vec!["robodr 4".to_string()]),
        "{reps:?}"
    );
    // M9: the security floor and the SOC ring minimum.
    let rel = root.join("var/lib/robodr/releases");
    std::fs::create_dir_all(rel.join("1.0")).unwrap();
    std::fs::write(
        rel.join("security-floor"),
        "min_version=1.5
source=test
",
    )
    .unwrap();
    let reps = deliver(&mut e, robodr_rpk(&u, "robodr", 5, "1.2", &[]));
    refused(
        &reps,
        "below the unit's security floor (install-bundle.sh) 1.5",
    );
    std::fs::create_dir_all(root.join("var/lib/robodr/fleet")).unwrap();
    std::fs::write(
        root.join("var/lib/robodr/fleet/ring.env"),
        "ring=1
min_version=1.6-1
",
    )
    .unwrap();
    let reps = deliver(&mut e, robodr_rpk(&u, "robodr", 6, "1.5.5", &[]));
    refused(
        &reps,
        "SOC ring information's minimum (robodr-enroll) 1.6~1",
    );
    // M9: the black-box format gate. A kept release writes RBF1:2, so a
    // segment in it is verified; 1.7 reads only the legacy format.
    std::fs::write(
        rel.join("1.0/formats"),
        "blackbox_write=RBF1:2
blackbox_read=RBF1:1,RBF1:2
",
    )
    .unwrap();
    let seg_dir = root.join("var/lib/robodr/blackbox/agentd");
    std::fs::create_dir_all(&seg_dir).unwrap();
    std::fs::write(seg_dir.join("seg-000001.rbb"), b"RBF1\0\0\0\0\x02frame").unwrap();
    let reps = deliver(&mut e, robodr_rpk(&u, "robodr", 7, "1.7", &[]));
    refused(&reps, "reads the black-box formats [RBF1:1]");
    let reads = [(
        "usr/share/robodr/formats",
        "blackbox_write=RBF1:2\nblackbox_read=RBF1:1,RBF1:2\n",
    )];
    let reps = deliver(&mut e, robodr_rpk(&u, "robodr", 8, "1.8", &reads));
    assert!(
        reps.iter()
            .any(|r| r.installed == vec!["robodr 8".to_string()]),
        "{reps:?}"
    );
    assert_eq!(package_version(&u, "robodr"), "1.8");
    assert!(u.black_box_verifies());
}

/// The text of RoboDR's postinst between its `# >>> NAME` and `# <<< NAME`
/// markers.
fn postinst_block(name: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/deb/postinst");
    let s = std::fs::read_to_string(&p).unwrap();
    let a = s
        .find(&format!("# >>> {name}"))
        .unwrap_or_else(|| panic!("postinst has no {name} block"));
    let b = s.find(&format!("# <<< {name}")).unwrap();
    s[a..b].to_string()
}

/// Review H5: under the agent, RoboDR's postinst runs inside the agent's
/// sandbox, where `/etc/robodr/keys` is `InaccessiblePaths=` (an empty
/// read-only mount). Its `systemd-tmpfiles --create` (the real tool, the
/// real block, the root-owned lines of the real tmpfiles.d file, in a
/// private mount namespace with that directory mounted read-only) fails
/// there with EROFS unless the keys directories are excluded, which the
/// block does under the agent's marker (and only then).
#[test]
fn postinst_tmpfiles_survive_the_agents_read_only_keys_directory() {
    let usable = robodr_deliverd::users::is_root()
        && have("unshare")
        && have("mount")
        && Path::new("/usr/bin/systemd-tmpfiles").is_file()
        && Command::new("unshare")
            .args(["-m", "true"])
            .status()
            .is_ok_and(|s| s.success());
    if !usable {
        eprintln!("SKIPPED postinst_tmpfiles: needs root, unshare -m, mount and systemd-tmpfiles");
        return;
    }
    let block = postinst_block("tmpfiles_create");
    let t = Tmp::new("postinst-tmpfiles");
    // Only root:root lines: the test host has none of RoboDR's users.
    let conf = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/tmpfiles.d/robodr.conf"),
    )
    .unwrap();
    let rootonly: String = conf
        .lines()
        .filter(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            f.len() >= 5 && f[0] == "d" && f[3] == "root" && f[4] == "root"
        })
        .map(|l| format!("{l}\n"))
        .collect();
    assert!(rootonly.contains("/etc/robodr/keys/retired"), "{rootonly}");
    std::fs::write(t.path().join("robodr.conf"), rootonly).unwrap();
    // `systemd-tmpfiles` as the block calls it, redirected into the test
    // root and onto the filtered file.
    let bin = t.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let wrapper = bin.join("systemd-tmpfiles");
    std::fs::write(
        &wrapper,
        "#!/bin/sh\nfor a in \"$@\"; do\n    case \"$a\" in /usr/lib/tmpfiles.d/robodr.conf) ;; *) set -- \"$@\" \"$a\" ;; esac\n    shift\ndone\n\
         exec /usr/bin/systemd-tmpfiles --root=\"$ROOT\" \"$@\" \"$CONF\"\n",
    )
    .unwrap();
    std::fs::set_permissions(
        &wrapper,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    let run = |marker: Option<&str>| -> std::process::Output {
        let root = t.path().join(format!("root-{}", marker.unwrap_or("none")));
        let keys = root.join("etc/robodr/keys");
        std::fs::create_dir_all(&keys).unwrap();
        let script = format!(
            "set -e\nmount --bind \"$K\" \"$K\"\nchmod 000 \"$K\"\n\
             mount -o remount,bind,ro \"$K\"\n{block}\n"
        );
        let mut c = Command::new("unshare");
        c.args(["-m", "sh", "-c", &script, "sh"])
            .env("K", &keys)
            .env("ROOT", &root)
            .env("CONF", t.path().join("robodr.conf"))
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    bin.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            );
        match marker {
            Some(m) => c.env("ROBODR_DELIVERD_INSTALL", m),
            None => c.env_remove("ROBODR_DELIVERD_INSTALL"),
        };
        let o = c.output().unwrap();
        if marker.is_some() {
            // The rest of the file was applied.
            assert!(root.join("var/lib/robodr/deliverd").is_dir());
        }
        o
    };
    // Without the marker (apt, install-bundle.sh: no such sandbox) the
    // keys directory is managed, and the read-only mount makes it fail:
    // the failure the agent's dpkg run hit.
    let plain = run(None);
    assert!(!plain.status.success(), "{plain:?}");
    assert!(
        String::from_utf8_lossy(&plain.stderr).contains("Read-only file system"),
        "{plain:?}"
    );
    let under = run(Some("1"));
    assert!(
        under.status.success(),
        "{}",
        String::from_utf8_lossy(&under.stderr)
    );
}

/// T53: deb only. A unit without a dpkg database (an RPM-based host) gets
/// an explicit refusal before anything is unpacked, naming why; no dpkg
/// tool is run (so this needs neither root nor dpkg).
#[test]
fn a_deb_on_a_unit_without_dpkg_is_refused_as_deb_only() {
    let u = Unit::new("deb-on-rpm-host");
    // No dpkg_root(&u): <dpkg_root>/var/lib/dpkg/status does not exist.
    // The staging directory exists (empty), so "nothing staged" below
    // checks something.
    let debs = u.cfg.state_dir.join("debs");
    std::fs::create_dir_all(&debs).unwrap();
    std::fs::set_permissions(&debs, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let r = deb_rpk(&u, 1, b"!<arch>\nnot really a deb\n", false);
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    u.pack("p1", 1, &[r], &[b]);
    let mut e = u.open();
    let reps = u.run(&mut e, 4);
    assert!(
        reps.iter().any(|r| r.refused.iter().any(
            |x| x.contains("kind deb needs a Debian / Ubuntu unit")
                && x.contains("RoboDR delivers no RPM packages")
                // A Debian unit with a wrong dpkg_root gets the same
                // refusal: the reason names that possibility too.
                && x.contains("install.dpkg_root")
        )),
        "{reps:?}"
    );
    assert!(u.notes_of("robodr.deliver.activating").is_empty());
    // Nothing staged.
    assert_eq!(debs.read_dir().unwrap().count(), 0);
}

const RULES_OK: &str = r#"[[rules]]
name = "robodr-delivered-test"
type = "Exec"
condition = 'payload.filename ENDS_WITH "/nc"'
category = "execution"
severity = "medium"
description = "delivered test rule"
"#;

fn rules_rpk(u: &Unit, serial: u64, text: &str) -> PathBuf {
    u.rpk(
        &spec("nav-rules", serial, Kind::RobodrRules),
        &[("robodr/nav.toml", text.as_bytes())],
    )
}

#[test]
fn rules_are_checked_switched_by_link_and_rolled_back_on_a_failed_reload() {
    let u = Unit::with("rules", |v| {
        let active = v["install"]["rules_active"].as_str().unwrap().to_string();
        // The "reload" fails while the active rules contain BROKEN.
        v["install"]["rules_reload"] = serde_json::json!([
            "/bin/sh",
            "-c",
            format!("! grep -rq BROKEN {active}/nav-rules/")
        ]);
    });
    let r1 = rules_rpk(&u, 1, RULES_OK);
    let b1 = u.bundle(1, None, std::slice::from_ref(&r1));
    u.pack("p1", 1, &[r1], std::slice::from_ref(&b1));
    let mut e = u.open();
    let reps = u.run(&mut e, 4);
    assert!(
        reps.iter()
            .any(|r| r.installed == vec!["nav-rules 1".to_string()]),
        "{reps:?}"
    );
    let link = u.cfg.install.rules_active.join("nav-rules");
    assert_eq!(
        std::fs::read_link(&link).unwrap(),
        u.version_dir(&u.cfg.state_dir.join("rules"), "nav-rules", 1)
    );
    assert_eq!(
        std::fs::read_to_string(link.join("robodr/nav.toml")).unwrap(),
        RULES_OK
    );
    // Only the active version is visible below rules_active.
    assert_eq!(
        std::fs::read_dir(&u.cfg.install.rules_active)
            .unwrap()
            .count(),
        1
    );

    // Serial 2 passes the structural check but its reload fails.
    let r2 = rules_rpk(&u, 2, &RULES_OK.replace("delivered test rule", "BROKEN"));
    let b2 = u.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&r2));
    u.pack("p2", 2, &[r2], std::slice::from_ref(&b2));
    let reps = u.run(&mut e, 4);
    assert!(
        reps.iter()
            .any(|r| r.rolled_back == vec!["nav-rules 2 -> 1".to_string()]),
        "{reps:?}"
    );
    assert_eq!(
        std::fs::read_link(&link).unwrap(),
        u.version_dir(&u.cfg.state_dir.join("rules"), "nav-rules", 1)
    );
    let rb = u.notes_of("robodr.deliver.rollback");
    assert!(
        rb[0]["failure"].as_str().unwrap().contains("rules reload"),
        "{rb:?}"
    );

    // Serial 3 does not load in Pulsar at all: refused before the switch.
    let r3 = rules_rpk(&u, 3, &RULES_OK.replace("\"execution\"", "\"fun\""));
    let b3 = u.bundle(3, Some(bundle_hash(&b2)), std::slice::from_ref(&r3));
    u.pack("p3", 3, &[r3], &[b3]);
    let reps = u.run(&mut e, 4);
    assert!(
        reps.iter().any(|r| r
            .refused
            .iter()
            .any(|x| x.contains("not a Pulsar category"))),
        "{reps:?}"
    );
    assert_eq!(
        std::fs::read_link(&link).unwrap(),
        u.version_dir(&u.cfg.state_dir.join("rules"), "nav-rules", 1)
    );
}

#[test]
fn an_unsupported_kind_is_refused_before_anything_happens() {
    let u = Unit::new("kind");
    let mut s = spec("nav-model", 1, Kind::Model);
    s.health = vec![];
    let r = u.rpk(&s, &[("weights.bin", b"\x00\x01")]);
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    u.pack("p1", 1, &[r], &[b]);
    let mut e = u.open();
    let reps = u.run(&mut e, 3);
    assert!(
        reps.iter()
            .any(|r| r.refused.iter().any(|x| x.contains("unsupported"))),
        "{reps:?}"
    );
    // A ros2_node health check cannot be evaluated on the unit: refused.
    let mut s = files_spec(&u, "nav-ros", 1, true);
    s.health.push(HealthCheck::Ros2Node {
        node: "/nav".into(),
    });
    let r = u.rpk(&s, &[("ok", b"x")]);
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    let d = deployment(2, "ring-1", &[UNIT], &[r]);
    pack(
        &u.cfg.media_dir,
        "p2",
        &u.trust_path,
        &d,
        &depot_and_ops(&u.keys),
        &[b],
    );
    let reps = u.run(&mut e, 3);
    assert!(
        reps.iter()
            .any(|r| r.refused.iter().any(|x| x.contains("cannot be evaluated"))),
        "{reps:?}"
    );
}
