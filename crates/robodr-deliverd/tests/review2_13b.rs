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
use robodr_deliverd::runner::{self, Limits, ProbeLimits, RunAs};
use robodr_pkg::rpk::Kind;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

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

// ------------------------------------------------------------------ L-E --

/// The `migrate_agentd_tree` function of the package's postinst (between
/// its `>>> migrate_agentd_tree` and `<<< migrate_agentd_tree` markers).
fn postinst_migration() -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/deb/postinst");
    let s = std::fs::read_to_string(&p).unwrap();
    let a = s
        .find("# >>> migrate_agentd_tree")
        .expect("postinst has no migrate_agentd_tree block");
    let b = s.find("# <<< migrate_agentd_tree").unwrap();
    s[a..b].to_string()
}

/// L-E. The ownership migration of agentd's trees (old agentd user ->
/// robodr-agentd) followed whatever an exporter (same old user) had
/// planted: a hardlink to its own file became agentd's, symlinks stayed,
/// group-writable modes stayed. Run here on a temporary tree with
/// numeric ids (needs root for chown; never the host's users).
#[test]
fn le_the_postinst_migration_breaks_links_and_normalises_modes() {
    if !robodr_deliverd::users::is_root() {
        if std::env::var("ROBODR_REQUIRE_DPKG_TEST").is_ok_and(|v| v == "1") {
            panic!("le_postinst: needs root");
        }
        eprintln!("SKIPPED le_postinst: needs root");
        return;
    }
    let f = postinst_migration();
    let t = Tmp::new("le");
    let (old, new, grp) = (43_101u32, 43_102u32, 43_103u32);
    let tree = t.path().join("agentd");
    let outside = t.path().join("exporter");
    std::fs::create_dir_all(tree.join("sub")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    let w = |p: &Path, b: &str, mode: u32| {
        std::fs::write(p, b).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    w(&tree.join("agentd.json"), "floor", 0o664);
    w(&tree.join("sub/seg"), "seg", 0o640);
    w(&outside.join("mine"), "exporter", 0o600);
    std::fs::hard_link(outside.join("mine"), tree.join("sub/linked")).unwrap();
    std::os::unix::fs::symlink(outside.join("mine"), tree.join("sub/sym")).unwrap();
    std::fs::set_permissions(tree.join("sub"), std::fs::Permissions::from_mode(0o2775)).unwrap();
    for p in [
        tree.clone(),
        tree.join("sub"),
        tree.join("agentd.json"),
        tree.join("sub/seg"),
        outside.join("mine"),
    ] {
        std::os::unix::fs::lchown(&p, Some(old), Some(old)).unwrap();
    }
    std::os::unix::fs::lchown(tree.join("sub/sym"), Some(old), Some(old)).unwrap();
    let script = format!(
        "set -e\n{f}\nmigrate_agentd_tree \"$1\" {old} {new} {grp}\nmigrate_agentd_tree \"$1\" {old} {new} {grp}\n"
    );
    let o = Command::new("/bin/sh")
        .args(["-c", &script, "sh"])
        .arg(&tree)
        .output()
        .unwrap();
    assert!(
        o.status.success(),
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    let md = |p: &Path| std::fs::symlink_metadata(p).unwrap();
    // The exporter's own inode keeps its owner; agentd's copy is separate.
    assert_eq!(md(&outside.join("mine")).uid(), old);
    let linked = md(&tree.join("sub/linked"));
    assert_eq!(linked.nlink(), 1);
    assert_ne!(linked.ino(), md(&outside.join("mine")).ino());
    assert_eq!((linked.uid(), linked.gid()), (new, grp));
    assert!(std::fs::symlink_metadata(tree.join("sub/sym")).is_err());
    for p in [
        tree.clone(),
        tree.join("sub"),
        tree.join("agentd.json"),
        tree.join("sub/seg"),
    ] {
        let m = md(&p);
        assert_eq!((m.uid(), m.gid()), (new, grp), "{}", p.display());
        assert_eq!(m.mode() & 0o022, 0, "{} keeps group/other write", p.display());
    }
    assert_eq!(std::fs::read_to_string(tree.join("agentd.json")).unwrap(), "floor");
}

// ------------------------------------------------------------------ L-F --

/// L-F. The probe reaper gave up after 64 rounds. A chain deeper than
/// that (each process the parent of the next; the reaper sees one level
/// per round, as each kill re-parents the next) outlived it as a child of
/// the agent, running as the probe user.
#[test]
fn lf_a_deep_chain_of_leftovers_does_not_outlive_the_reaper() {
    if !robodr_deliverd::users::is_root() {
        if std::env::var("ROBODR_REQUIRE_DPKG_TEST").is_ok_and(|v| v == "1") {
            panic!("lf_reaper: needs root");
        }
        eprintln!("SKIPPED lf_reaper: needs root");
        return;
    }
    let t = Tmp::new("lf");
    std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    let chain = t.path().join("chain.sh");
    let done = t.path().join("done");
    std::fs::write(
        &chain,
        format!(
            "#!/bin/sh\nn=$1\nif [ \"$n\" -gt 0 ]; then\n  \"$0\" $((n - 1)) </dev/null >/dev/null 2>&1 &\nelse\n  : > {}\nfi\nexec sleep 60\n",
            done.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&chain, std::fs::Permissions::from_mode(0o755)).unwrap();
    let probe = format!(
        "setsid {} 100 </dev/null >/dev/null 2>&1 &\nwhile [ ! -e {} ]; do sleep 0.05; done\nexit 0\n",
        chain.display(),
        done.display()
    );
    let r = runner::run_probe(
        &["/bin/sh".to_string(), "-c".to_string(), probe],
        RunAs {
            uid: 65_534,
            gid: 65_534,
        },
        Limits {
            timeout: Duration::from_secs(60),
            max_output: 4096,
        },
        ProbeLimits {
            processes: 512,
            ..ProbeLimits::default()
        },
    );
    std::thread::sleep(Duration::from_millis(200));
    let marker = chain.to_string_lossy().into_owned();
    let mut left = Vec::new();
    for e in std::fs::read_dir("/proc").unwrap().flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let Ok(st) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
            continue;
        };
        let field = |k: &str| {
            st.lines()
                .find_map(|l| l.strip_prefix(k))
                .map(|v| v.split_whitespace().next().unwrap_or("").to_string())
                .unwrap_or_default()
        };
        if field("Uid:") != "65534" || field("State:") == "Z" {
            continue;
        }
        let cmd = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        let cmd = String::from_utf8_lossy(&cmd).into_owned();
        // A node of the chain: the script, or the sleep it became.
        if cmd.contains(&marker) || cmd == "sleep\u{0}60\u{0}" {
            left.push(pid);
        }
    }
    // Do not leak them into the other tests.
    for pid in &left {
        let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
    }
    assert!(r.left_processes, "{r:?}");
    assert!(!r.success());
    assert!(
        left.is_empty(),
        "{} processes of the chain survived the reaper: {left:?}",
        left.len()
    );
}

// ----------------------------------------------------------- I-B, rules --

/// I-B. `pack_digest` hashed every byte of every file before the import
/// judged the pack (a huge file stalled each pass). It now caps a file at
/// the largest member a pack can have and falls back to the tree stamp.
#[test]
fn ib_pack_digest_caps_the_bytes_it_hashes() {
    let t = Tmp::new("ib");
    let pack = t.path().join("pack");
    std::fs::create_dir_all(&pack).unwrap();
    std::fs::write(pack.join("deployment.json"), b"{}").unwrap();
    assert!(robodr_deliverd::media::pack_digest(&pack).is_some());
    let f = std::fs::File::create(pack.join("huge")).unwrap();
    // Larger than any member of a valid pack (64 MiB, the SBOM cap).
    f.set_len(65 * 1024 * 1024).unwrap();
    drop(f);
    assert_eq!(robodr_deliverd::media::pack_digest(&pack), None);
}

const RULE_X: &str = r#"[[rules]]
name = "robodr-shared-name"
type = "Exec"
condition = 'payload.filename ENDS_WITH "/nc"'
category = "execution"
severity = "medium"
description = "delivered test rule"
"#;

/// Rule names must be unique across **all** installed rules packages,
/// not only within one (Pulsar would refuse the reload, or shadow one
/// detection with the other).
#[test]
fn a_rule_name_used_by_another_installed_rules_package_is_refused() {
    let u = Unit::new("rules-x");
    let a = u.rpk(
        &spec("rules-a", 1, Kind::RobodrRules),
        &[("robodr/a.toml", RULE_X.as_bytes())],
    );
    let b1 = u.bundle(1, None, std::slice::from_ref(&a));
    u.pack("p1", 1, &[a], std::slice::from_ref(&b1));
    let mut e = u.open();
    let reps = u.run(&mut e, 4);
    assert!(
        reps.iter().any(|r| r.installed == vec!["rules-a 1".to_string()]),
        "{reps:?}"
    );
    let b = u.rpk(
        &spec("rules-b", 1, Kind::RobodrRules),
        &[("robodr/b.toml", RULE_X.as_bytes())],
    );
    let b2 = u.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&b));
    u.pack("p2", 2, &[b], &[b2]);
    let reps = u.run(&mut e, 4);
    assert!(
        reps.iter().all(|r| r.installed.is_empty()),
        "a duplicate rule name across packages was installed: {reps:?}"
    );
    assert!(
        reps.iter()
            .any(|r| r.refused.iter().any(|x| x.contains("rules-a"))),
        "{reps:?}"
    );
}
