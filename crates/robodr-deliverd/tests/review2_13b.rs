//! Regressions from the second independent review of Sprint 13b
//! (`13b-review2`, findings H-A, M-A, M-B, L-A, L-B, L-E, L-F and the Info
//! items I-B and rules uniqueness). Each test reproduces the finding; every
//! one of them failed on the code before its fix (the commit messages
//! record the runs).
//!
//! Everything runs in temporary roots: dpkg only with `--root` /
//! `--admindir` below the test directory, never the host's database,
//! users or systemd.

mod common;

use common::*;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

// ------------------------------------------------------------------ H-A --

/// `dpkg-query` status abbreviation and version of `package` in the
/// unit's dpkg root (`"ii 2.0"`, or `""` when dpkg does not know it).
fn dpkg_status(u: &Unit, package: &str) -> String {
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
        .args(["-W", "-f", "${db:Status-Abbrev} ${Version}", "--", package])
        .output()
        .unwrap();
    String::from_utf8_lossy(&o.stdout)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn nav_file(u: &Unit) -> String {
    std::fs::read_to_string(
        u.cfg
            .install
            .dpkg_root
            .as_ref()
            .unwrap()
            .join("usr/lib/nav/ok"),
    )
    .unwrap_or_default()
}

/// `nav` serial 2 (floor 2, dpkg 2.0) installed from bundle 1.
fn nav_installed(u: &Unit) -> (robodr_deliverd::Engine, PathBuf) {
    dpkg_root(u);
    let d2 = deb_of(u, "nav", "2.0", "all", "");
    let r2 = u.rpk(
        &deb_spec(u, "nav", 2, 2, "nav"),
        &[("nav.deb", &d2), ("sbom.cdx.json", SBOM)],
    );
    let b1 = u.bundle(1, None, std::slice::from_ref(&r2));
    u.pack("p1", 1, &[r2], std::slice::from_ref(&b1));
    let mut e = u.open();
    let reps = u.run(&mut e, 5);
    assert!(reps.iter().any(|x| !x.installed.is_empty()), "{reps:?}");
    assert_eq!(dpkg_status(u, "nav"), "ii 2.0");
    assert_eq!(nav_file(u), "2.0");
    (e, b1)
}

/// H-A. A legitimately signed deb RPK under **another** name (`nav-ng`,
/// no floor of its own) whose `.deb` declares `Replaces` / `Conflicts` /
/// `Breaks` / `Provides` against the floored `nav` must not install: dpkg
/// would take over nav's files or remove nav while the state still says
/// nav serial 2 is installed at floor 2.
#[test]
fn ha_a_deb_with_relations_on_another_package_is_refused() {
    if !dpkg_ok("ha_relations") {
        return;
    }
    for (i, rel) in [
        "Replaces: nav\n",
        "Conflicts: nav\nReplaces: nav\nProvides: nav\n",
        "Breaks: nav (<< 3)\n",
        "Provides: nav-virtual\n",
    ]
    .iter()
    .enumerate()
    {
        let u = Unit::new(&format!("ha-rel{i}"));
        let (mut e, b1) = nav_installed(&u);
        let old = deb_with(
            &u,
            "nav-ng",
            "1.0",
            "all",
            rel,
            &[
                ("usr/lib/nav/ok", "OLD-nav-1.0-content"),
                ("usr/lib/nav-ng/ok", "1.0"),
            ],
        );
        let r1 = u.rpk(
            &deb_spec(&u, "nav-ng", 1, 1, "nav-ng"),
            &[("nav-ng.deb", &old), ("sbom.cdx.json", SBOM)],
        );
        let b2 = u.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&r1));
        u.pack("p2", 2, &[r1], &[b2]);
        let reps = u.run(&mut e, 5);
        assert_eq!(
            (dpkg_status(&u, "nav"), nav_file(&u)),
            ("ii 2.0".to_string(), "2.0".to_string()),
            "{rel:?}: the floored package was replaced or removed through another RPK: {reps:?}"
        );
        assert_eq!(dpkg_status(&u, "nav-ng"), "", "{rel:?}: {reps:?}");
        assert!(
            reps.iter()
                .any(|x| x.refused.iter().any(|r| r.contains("nav"))),
            "{rel:?}: {reps:?}"
        );
        assert!(!e.state().installed.contains_key("nav-ng"), "{rel:?}");
        assert!(
            u.rules_found()
                .iter()
                .any(|r| r == "robot.deliver.refused"),
            "{rel:?}"
        );
    }
}

/// H-A. After every `dpkg --install` the agent checks that every other
/// deb package the state records is still installed at its recorded
/// version. A switch that changed one anyway (here a `dpkg` that also
/// purges `nav`, standing in for any side effect the relation check does
/// not foresee) is a failed install: the damaged package is restored, the
/// switch is undone or blocked, and a finding is raised.
#[test]
fn ha_an_install_that_changes_another_recorded_package_fails() {
    if !dpkg_ok("ha_invariant") {
        return;
    }
    let tmp = Tmp::new("ha-wrap");
    let wrapper = tmp.path().join("dpkg");
    let u = Unit::with("ha-inv", |v| {
        v["install"]["dpkg"] = serde_json::json!(wrapper);
    });
    let root = u.cfg.install.dpkg_root.clone().unwrap();
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\n/usr/bin/dpkg \"$@\" || exit $?\nfor a in \"$@\"; do\n  case \"$a\" in\n  \
             */nav-ng.deb) /usr/bin/dpkg --root={} --force-depends --purge nav >/dev/null 2>&1 ;;\n  \
             esac\ndone\nexit 0\n",
            root.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (mut e, b1) = nav_installed(&u);
    let d = deb_of(&u, "nav-ng", "1.0", "all", "");
    let r1 = u.rpk(
        &deb_spec(&u, "nav-ng", 1, 1, "nav-ng"),
        &[("nav-ng.deb", &d), ("sbom.cdx.json", SBOM)],
    );
    let b2 = u.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&r1));
    u.pack("p2", 2, &[r1], &[b2]);
    let reps = u.run(&mut e, 6);
    assert_eq!(
        dpkg_status(&u, "nav"),
        "ii 2.0",
        "the recorded package stays removed: {reps:?}"
    );
    assert!(
        reps.iter().all(|x| x.installed.is_empty()),
        "the switch that removed nav counted as installed: {reps:?}"
    );
    assert!(
        e.state().installed.get("nav-ng").is_none_or(|i| !i.healthy),
        "{:?}",
        e.state().installed.get("nav-ng")
    );
    let rules = u.rules_found();
    assert!(
        rules
            .iter()
            .any(|r| r == "robot.deliver.rollback_blocked_floor" || r == "robot.deliver.health_failed"),
        "{rules:?}"
    );
    let notes = u.notes_of("robodr.deliver.rollback_blocked");
    assert!(
        notes.iter().any(|n| n.to_string().contains("nav 2.0")),
        "{notes:?}"
    );
}
