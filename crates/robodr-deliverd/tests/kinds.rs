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
        u.cfg.state_dir.join("rules/nav-rules/1")
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
        u.cfg.state_dir.join("rules/nav-rules/1")
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
        u.cfg.state_dir.join("rules/nav-rules/1")
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
