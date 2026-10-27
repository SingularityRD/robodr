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
use std::path::{Path, PathBuf};
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

// ------------------------------------------------------------ M-A / M-B --

fn hw_path(u: &Unit) -> PathBuf {
    robodr_deliverd::highwater::path(&u.cfg.blackbox.dir)
}

fn hw_doc(u: &Unit) -> serde_json::Value {
    let b = std::fs::read(hw_path(u)).unwrap();
    serde_json::from_slice::<serde_json::Value>(&b).unwrap()["doc"].clone()
}

/// A pack with `nav-stack` serial `serial` (security floor `floor`) as
/// deployment `seq` in bundle `seq` after `prev`.
fn nav_pack(u: &Unit, serial: u64, floor: u64, seq: u64, prev: Option<&Path>) -> PathBuf {
    let mut s = files_spec(u, "nav-stack", serial, true);
    s.security_floor = floor;
    let r = u.rpk(&s, &[("ok", format!("v{serial}").as_bytes())]);
    let b = u.bundle(seq, prev.map(bundle_hash), std::slice::from_ref(&r));
    u.pack(&format!("p{seq}"), seq, &[r], std::slice::from_ref(&b));
    b
}

/// M-A. The lock lived only in `state.json`: the first locked start wrote
/// a fresh, unlocked high-water record, and deleting `state.json` a
/// second time lifted the lock. It is now part of the signed record.
#[test]
fn ma_the_lock_survives_deleting_the_state_twice() {
    let u = Unit::new("ma-twice");
    let (e, b1) = installed_v5_floor_5(&u);
    e.close().unwrap();
    flood_journal(&u);
    std::fs::remove_file(u.cfg.state_path()).unwrap();
    std::fs::remove_file(hw_path(&u)).unwrap();
    let e = u.open();
    assert!(e.state().locked.is_some());
    e.close().unwrap();
    assert!(
        !hw_doc(&u)["locked"].is_null(),
        "the first locked start wrote an unlocked high-water record: {}",
        hw_doc(&u)
    );
    std::fs::remove_file(u.cfg.state_path()).unwrap();
    let mut e = u.open();
    assert!(
        e.state().locked.is_some(),
        "deleting the state file a second time lifted the lock"
    );
    nav_pack(&u, 4, 1, 2, Some(&b1));
    let reps = u.run(&mut e, 4);
    assert!(reps.iter().all(|x| x.installed.is_empty()), "{reps:?}");
    // Deleting the record (state present, locked) keeps the lock as well.
    e.close().unwrap();
    std::fs::remove_file(hw_path(&u)).unwrap();
    let e = u.open();
    assert!(e.state().locked.is_some());
}

/// M-B. An older (genuinely signed) high-water record put back after the
/// state file is deleted was accepted: floors, deployment sequence, time
/// floor and chain heads went back. The record's generation is noted in
/// the journal at every write; an older one locks the agent.
#[test]
fn mb_an_older_signed_record_locks() {
    let u = Unit::new("mb-old-hw");
    let b1 = nav_pack(&u, 1, 1, 1, None);
    let mut e = u.open();
    u.run(&mut e, 4);
    assert_eq!(e.state().floor("nav-stack"), 1);
    let old = std::fs::read(hw_path(&u)).unwrap();
    let b2 = nav_pack(&u, 5, 5, 2, Some(&b1));
    u.run(&mut e, 4);
    assert_eq!(e.state().floor("nav-stack"), 5);
    e.close().unwrap();
    std::fs::remove_file(u.cfg.state_path()).unwrap();
    std::fs::write(hw_path(&u), &old).unwrap();
    let mut e = u.open();
    assert!(
        e.state().locked.is_some(),
        "an older signed high-water record was accepted (floor {}, seq {:?})",
        e.state().floor("nav-stack"),
        e.state().last_deployment.as_ref().map(|l| l.seq)
    );
    nav_pack(&u, 4, 1, 3, Some(&b2));
    let reps = u.run(&mut e, 4);
    assert!(reps.iter().all(|x| x.installed.is_empty()), "{reps:?}");
}

/// M-B (variant). An older `state.json` put back while the record is
/// deleted was kept and the record rewritten from it. Now it locks.
#[test]
fn mb_an_older_state_and_a_deleted_record_lock() {
    let u = Unit::new("mb-old-state");
    let b1 = nav_pack(&u, 1, 1, 1, None);
    let mut e = u.open();
    u.run(&mut e, 4);
    let old = std::fs::read(u.cfg.state_path()).unwrap();
    let b2 = nav_pack(&u, 5, 5, 2, Some(&b1));
    u.run(&mut e, 4);
    e.close().unwrap();
    std::fs::write(u.cfg.state_path(), &old).unwrap();
    std::fs::remove_file(hw_path(&u)).unwrap();
    let mut e = u.open();
    assert!(
        e.state().locked.is_some(),
        "an older state file without its record was accepted (floor {})",
        e.state().floor("nav-stack")
    );
    nav_pack(&u, 4, 1, 3, Some(&b2));
    let reps = u.run(&mut e, 4);
    assert!(reps.iter().all(|x| x.installed.is_empty()), "{reps:?}");
}

/// M-B. An older state file with the current record is raised to the
/// record (no lock needed: nothing was lost), and normal restarts never
/// lock.
#[test]
fn mb_an_older_state_with_the_current_record_is_raised() {
    let u = Unit::new("mb-raise");
    let b1 = nav_pack(&u, 1, 1, 1, None);
    let mut e = u.open();
    u.run(&mut e, 4);
    let old = std::fs::read(u.cfg.state_path()).unwrap();
    nav_pack(&u, 5, 5, 2, Some(&b1));
    u.run(&mut e, 4);
    e.close().unwrap();
    for _ in 0..3 {
        let e = u.open();
        assert!(e.state().locked.is_none());
        e.close().unwrap();
    }
    std::fs::write(u.cfg.state_path(), &old).unwrap();
    let e = u.open();
    assert!(e.state().locked.is_none());
    assert_eq!(e.state().floor("nav-stack"), 5);
    assert_eq!(e.state().last_deployment.as_ref().map(|l| l.seq), Some(2));
}

// ------------------------------------------------------------------ L-A --

/// L-A. `reanchor` lifted the lock with no deployment sequence and no
/// chain heads: an older, unexpired deployment replayed. It now rebuilds
/// them from the journal.
#[test]
fn la_reanchor_rebuilds_the_sequence_and_chain_heads_from_the_journal() {
    let u = Unit::new("la-rebuild");
    let b1 = nav_pack(&u, 1, 1, 1, None);
    let mut e = u.open();
    u.run(&mut e, 4);
    let p1 = u.cfg.media_dir.join("p1");
    let replay = u.work.join("replay-p1");
    copy_tree(&p1, &replay);
    nav_pack(&u, 2, 1, 2, Some(&b1));
    u.run(&mut e, 4);
    e.close().unwrap();
    std::fs::remove_file(u.cfg.state_path()).unwrap();
    std::fs::remove_file(hw_path(&u)).unwrap();
    let mut e = u.open();
    assert!(e.state().locked.is_some());
    e.reanchor(&u.trust_path).unwrap();
    assert!(e.state().locked.is_none());
    assert_eq!(
        e.state().last_deployment.as_ref().map(|l| l.seq),
        Some(2),
        "the deployment sequence was not rebuilt"
    );
    assert!(!e.state().chains.is_empty(), "chain heads were not rebuilt");
    // The older deployment (seq 1) does not replay.
    for d in ["p1", "p2"] {
        let _ = std::fs::remove_dir_all(u.cfg.media_dir.join(d));
    }
    copy_tree(&replay, &u.cfg.media_dir.join("again"));
    let reps = u.run(&mut e, 4);
    assert!(reps.iter().all(|x| x.imported.is_empty()), "{reps:?}");
}

/// L-A. With the anchor gone, `reanchor` accepted any trust file signed
/// under the pinned roots, including one older than the journal had seen.
#[test]
fn la_reanchor_refuses_a_trust_file_older_than_the_journal_saw() {
    let u = Unit::new("la-trust");
    let mut t2 = trust_file(&u.keys);
    t2.version = 2;
    let p2 = u.work.join("site-trust-v2.json");
    write_trust(&p2, &t2, &u.keys);
    let st = robodr_release::ops::SiteTrust::anchored(
        &p2,
        &u.cfg.anchor_path(),
        &u.cfg.trust.roots,
        SITE,
        NOW,
    )
    .unwrap();
    assert!(robodr_release::ops::commit_anchor(&st).unwrap());
    let e = u.open();
    e.close().unwrap();
    std::fs::remove_file(u.cfg.state_path()).unwrap();
    std::fs::remove_file(hw_path(&u)).unwrap();
    std::fs::remove_file(u.cfg.anchor_path()).unwrap();
    std::fs::remove_file(robodr_release::ops::sig_path(&u.cfg.anchor_path())).unwrap();
    let mut e = u.open();
    assert!(e.state().locked.is_some());
    let r = e.reanchor(&u.trust_path);
    assert!(
        r.is_err(),
        "a trust file older than the journal's version 2 was accepted: {r:?}"
    );
    assert!(e.state().locked.is_some());
    e.reanchor(&p2).unwrap();
    assert!(e.state().locked.is_none());
}

// ------------------------------------------------------------------ L-B --

/// L-B. The shipped `blackbox.key` is a systemd credential that exists
/// only while the service runs, so `reanchor` (service stopped) could not
/// load it. `reanchor --key FILE` takes the key file directly.
#[test]
fn lb_reanchor_takes_the_black_box_key_file() {
    let u = Unit::new("lb-key");
    std::fs::remove_file(u.cfg.anchor_path()).unwrap();
    std::fs::remove_file(robodr_release::ops::sig_path(&u.cfg.anchor_path())).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut tf = trust_file(&u.keys);
    tf.issued_at = now - 3600;
    tf.expires_at = now + 90 * 86400;
    write_trust(&u.trust_path, &tf, &u.keys);
    let mut v = serde_json::to_value(&u.cfg).unwrap();
    v["blackbox"]["key"] = serde_json::json!(u.dir().join("absent-credential/blackbox.key"));
    let cfgp = u.dir().join("deliverd.json");
    std::fs::write(&cfgp, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    let run = |extra: &[&str]| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_robodr-deliverd"));
        c.args(["reanchor", "--config"])
            .arg(&cfgp)
            .arg("--trust")
            .arg(&u.trust_path)
            .args(extra);
        c.output().unwrap()
    };
    let o = run(&[]);
    assert_eq!(o.status.code(), Some(1), "without the credential it fails");
    let key = u.dir().join("bb.key");
    let o = run(&["--key", key.to_str().unwrap()]);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(u.cfg.anchor_path().exists());
}
