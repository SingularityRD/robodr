//! Regressions from the 13b self-review (1, 3 and 4 failed before their
//! fixes; 2 depends on the directory's listing order, which a test cannot
//! choose, so it covers the fix rather than replaying the miss):
//!
//! 1. A release re-signed into another manifest with the **same serial**
//!    was "already active" to the files installer: the agent recorded the
//!    new digest as installed while the old files stayed. Now refused.
//! 2. The media-pack layout check looked at the first 64 entries only, so
//!    a stray file could hide behind 64 others. Now every entry is judged.
//! 3. With a trusted clock the time floor took the system clock at
//!    acceptance: one wrong (future) reading became permanent and expired
//!    everything after the clock was corrected. Now the floor only takes
//!    the deployment's signed creation time, capped by the clock.
//! 4. (unit test in `runner`) A probe that exited normally had its process
//!    group signalled after it was reaped; a probe that left processes
//!    holding its output passed. Now the group is signalled only while it
//!    has members, and the probe fails.

mod common;

use common::*;
use robodr_deliverd::runner::{self, Limits, RunAs};
use robodr_pkg::rpk::Arch;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

#[test]
fn the_same_serial_with_other_content_is_refused() {
    let u = Unit::new("same-serial");
    let (mut e, b1) = installed_v1(&u, "nav-stack");
    let installed = e.state().installed["nav-stack"].ver.digest.clone();
    // Serial 1 again, other payload: another digest.
    let r = u.rpk(
        &files_spec(&u, "nav-stack", 1, true),
        &[("ok", b"v1"), ("extra", b"evil")],
    );
    let b2 = u.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&r));
    u.pack("p2", 2, &[r], &[b2]);
    let reps = u.run(&mut e, 4);
    assert!(
        reps.iter()
            .any(|x| x.refused.iter().any(|y| y.contains("equivocation"))),
        "{reps:?}"
    );
    assert_eq!(e.state().installed["nav-stack"].ver.digest, installed);
    // No version directory of nav-stack holds the other content.
    for d in u.version_dirs(&u.cfg.install.files_root, "nav-stack", 1) {
        assert!(!d.join("extra").exists(), "{}", d.display());
    }
}

#[test]
fn a_stray_file_behind_many_others_is_refused() {
    let u = Unit::new("many-strays");
    let r = u.rpk(&files_spec(&u, "nav-stack", 1, true), &[("ok", b"v1")]);
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    let p: PathBuf = u.pack("p1", 1, &[r], &[b]);
    for i in 0..100 {
        std::fs::write(p.join(format!("zz-stray-{i:03}")), b"x").unwrap();
    }
    let mut e = u.open();
    let reps = u.run(&mut e, 3);
    assert!(
        reps.iter()
            .any(|x| x.refused.iter().any(|y| y.contains("unexpected_file"))),
        "{reps:?}"
    );
    assert!(e.state().deployment.is_none());
}

#[test]
fn a_wrong_future_clock_reading_is_not_made_permanent() {
    let u = Unit::new("future-clock");
    // The clock reads 50 days ahead while the pack is accepted.
    u.clock.set(NOW + 50 * 86400);
    let r = u.rpk(&files_spec(&u, "nav-stack", 1, true), &[("ok", b"v1")]);
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    let mut d = deployment(1, "ring-1", &[UNIT], &[r]);
    d.expires_at = NOW + 60 * 86400;
    pack(
        &u.cfg.media_dir,
        "p1",
        &u.trust_path,
        &d,
        &depot_and_ops(&u.keys),
        &[b],
    );
    let mut e = u.open();
    u.run(&mut e, 4);
    assert_eq!(
        e.state().time_floor,
        NOW - 60,
        "only the signed creation time"
    );
    // The clock is corrected: nothing is stale.
    u.clock.set(NOW + 86400);
    let rep = e.tick().unwrap();
    assert!(rep.stale.is_none(), "{rep:?}");
}

// ---------------------------------------------------------------------------
// Independent adversarial review of Sprint 13b (findings H1..L4). Each test
// reproduces the attack; every one of them failed on the code before its
// fix (see the commit messages for the runs).
// ---------------------------------------------------------------------------

fn chown(p: &Path, uid: u32, gid: u32) {
    std::os::unix::fs::chown(p, Some(uid), Some(gid)).unwrap();
}

fn chmod(p: &Path, mode: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// A fresh, `idle`, otherwise perfect agentd status (what an exporter
/// running as the agentd user can compute: the boot id is world-readable,
/// CLOCK_MONOTONIC is everyone's).
fn forged_idle() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "safety_state": "idle",
        "safety_feed": {"state": "idle", "sources": [], "stats": {}},
        "kind": "robodr.agentd_status",
        "robot_id": UNIT,
        "updated_mono_ms": robodr_agentd::notify::monotonic_ms(),
        "boot_id": BOOT,
        "stale_after_ms": 600_000,
        "running": true,
        "state": "ok"
    }))
    .unwrap()
}

/// H1. `status.json` in agentd's spool is writable by every service of the
/// agentd user (robodr-kafka-publish, robodr-uplink, robodr-spool-export).
/// A forged `idle` written there by one of them must not open the gate.
#[test]
fn h1_a_forged_idle_status_written_by_another_robodr_service_is_unknown() {
    if !robodr_deliverd::users::is_root() {
        eprintln!("SKIPPED h1: needs root (chown)");
        return;
    }
    let u = Unit::with_status(
        "h1-forged",
        |v| {
            let base = Path::new(v["state_dir"].as_str().unwrap())
                .parent()
                .unwrap()
                .to_path_buf();
            v["safety"]["agentd_status"] = base
                .join("spool-agentd/status.json")
                .to_str()
                .unwrap()
                .into();
        },
        false,
    );
    // The robodr-owned spool directory (0750 robodr:robodr) and a forged
    // status in it, written by an exporter (uid/gid 4001 here).
    let spool = u.dir().join("spool-agentd");
    std::fs::create_dir_all(&spool).unwrap();
    chown(&spool, 4001, 4001);
    chmod(&spool, 0o750);
    let f = spool.join("status.json");
    std::fs::write(&f, forged_idle()).unwrap();
    chown(&f, 4001, 4001);
    chmod(&f, 0o640);
    let seen = robodr_deliverd::safety::observe(&u.cfg.safety);
    assert_eq!(
        seen.state,
        robodr_responder::SafetyState::Unknown,
        "a status a non-agentd writer can produce opened the gate: {seen:?}"
    );
    // End to end: the install waits.
    let r = u.rpk(&files_spec(&u, "nav-stack", 1, true), &[("ok", b"v1")]);
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    u.pack("p1", 1, &[r], &[b]);
    let mut e = u.open();
    let reps = u.run(&mut e, 4);
    assert!(reps.iter().all(|x| x.installed.is_empty()), "{reps:?}");
    assert!(
        reps.iter().any(|x| x
            .deferred
            .as_deref()
            .is_some_and(|d| d.contains("safety_state:unknown"))),
        "{reps:?}"
    );
}

// ------------------------------------------------------------------- H2 --

/// H2. Floors are keyed on the RPK name, but `dpkg -i` acts on the
/// `.deb`'s own `Package`. An RPK under another name carrying an older
/// `.deb` of a floored package must not downgrade it.
#[test]
fn h2_an_rpk_under_another_name_cannot_downgrade_a_floored_deb() {
    if !dpkg_ok("h2_other_name") {
        return;
    }
    let u = Unit::new("h2-name");
    dpkg_root(&u);
    let d2 = deb_of(&u, "robodr-stub", "2.0", "all", "");
    let r2 = u.rpk(
        &deb_spec(&u, "robodr-stub", 2, 2, "robodr-stub"),
        &[("robodr-stub.deb", &d2), ("sbom.cdx.json", SBOM)],
    );
    let b1 = u.bundle(1, None, std::slice::from_ref(&r2));
    u.pack("p1", 1, &[r2], std::slice::from_ref(&b1));
    let mut e = u.open();
    let reps = u.run(&mut e, 5);
    assert!(reps.iter().any(|x| !x.installed.is_empty()), "{reps:?}");
    assert_eq!(dpkg_version(&u, "robodr-stub"), "2.0");
    assert_eq!(e.state().floor("robodr-stub"), 2);
    // "legacy-nav" serial 1 (no floor of its own) carries robodr-stub 1.0.
    let d1 = deb_of(&u, "robodr-stub", "1.0", "all", "");
    let r1 = u.rpk(
        &deb_spec(&u, "legacy-nav", 1, 1, "robodr-stub"),
        &[("legacy-nav.deb", &d1), ("sbom.cdx.json", SBOM)],
    );
    let b2 = u.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&r1));
    u.pack("p2", 2, &[r1], &[b2]);
    let reps = u.run(&mut e, 5);
    assert_eq!(
        dpkg_version(&u, "robodr-stub"),
        "2.0",
        "the floored package was downgraded through another RPK name: {reps:?}"
    );
    assert!(reps.iter().any(|x| !x.refused.is_empty()), "{reps:?}");
    assert!(!e.state().installed.contains_key("legacy-nav"));
}

/// H2. RoboDR's own packages are not delivered through a deb RPK unless
/// the RPK belongs to the designated RoboDR programme.
#[test]
fn h2_robodrs_own_package_is_not_replaced_by_a_deb_rpk() {
    if !dpkg_ok("h2_own") {
        return;
    }
    let u = Unit::new("h2-own");
    dpkg_root(&u);
    let d = deb_of(&u, "robodr", "9.9", "all", "");
    let r = u.rpk(
        &deb_spec(&u, "robodr", 1, 1, "robodr"),
        &[("robodr.deb", &d), ("sbom.cdx.json", SBOM)],
    );
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    u.pack("p1", 1, &[r], &[b]);
    let mut e = u.open();
    let reps = u.run(&mut e, 5);
    assert_eq!(dpkg_version(&u, "robodr"), "", "{reps:?}");
    assert!(reps.iter().any(|x| !x.refused.is_empty()), "{reps:?}");
}

/// H2. A `.deb` whose relations would remove RoboDR (`Conflicts` +
/// `Replaces`) is refused too.
#[test]
fn h2_a_deb_that_conflicts_with_robodr_is_refused() {
    if !dpkg_ok("h2_conflicts") {
        return;
    }
    let u = Unit::new("h2-conflicts");
    dpkg_root(&u);
    let d = deb_of(
        &u,
        "nav-evil",
        "1.0",
        "all",
        "Conflicts: robodr, robodr-focal\nReplaces: robodr\n",
    );
    let r = u.rpk(
        &deb_spec(&u, "nav-evil", 1, 1, "nav-evil"),
        &[("nav-evil.deb", &d), ("sbom.cdx.json", SBOM)],
    );
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    u.pack("p1", 1, &[r], &[b]);
    let mut e = u.open();
    let reps = u.run(&mut e, 5);
    assert_eq!(dpkg_version(&u, "nav-evil"), "", "{reps:?}");
    assert!(reps.iter().any(|x| !x.refused.is_empty()), "{reps:?}");
}

/// H2. The `.deb`'s `Architecture` is pinned to the RPK's `arch`.
#[test]
fn h2_the_deb_architecture_must_be_the_rpks() {
    if !dpkg_ok("h2_arch") {
        return;
    }
    let u = Unit::new("h2-arch");
    dpkg_root(&u);
    let d = deb_of(&u, "nav-arch", "1.0", "arm64", "");
    let mut s = deb_spec(&u, "nav-arch", 1, 1, "nav-arch");
    s.arch = Arch::All;
    let r = u.rpk(&s, &[("nav-arch.deb", &d), ("sbom.cdx.json", SBOM)]);
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    u.pack("p1", 1, &[r], &[b]);
    let mut e = u.open();
    let reps = u.run(&mut e, 5);
    assert_eq!(dpkg_version(&u, "nav-arch"), "", "{reps:?}");
    assert!(reps.iter().any(|x| !x.refused.is_empty()), "{reps:?}");
}

// ------------------------------------------------------------------- M1 --

/// M1. The black-box copy of the floors is cyclic: flooded with notes it
/// forgets them. Floors, the deployment sequence and the time floor must
/// survive a lost state file anyway.
#[test]
fn m1_floors_and_sequence_survive_a_flooded_journal_and_a_lost_state_file() {
    let u = Unit::new("m1-flood");
    let (e, b1) = installed_v5_floor_5(&u);
    let tf = e.state().time_floor;
    e.close().unwrap();
    flood_journal(&u);
    std::fs::remove_file(u.cfg.state_path()).unwrap();
    let mut e = u.open();
    assert_eq!(e.state().floor("nav-stack"), 5, "floor lost");
    assert_eq!(
        e.state().last_deployment.as_ref().map(|l| l.seq),
        Some(1),
        "deployment sequence lost"
    );
    assert_eq!(e.state().time_floor, tf, "time floor lost");
    assert!(!e.state().chains.is_empty(), "chain heads lost");
    let r4 = u.rpk(&files_spec(&u, "nav-stack", 4, true), &[("ok", b"v4")]);
    let b2 = u.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&r4));
    u.pack("p2", 2, &[r4], &[b2]);
    let reps = u.run(&mut e, 4);
    assert!(reps.iter().all(|x| x.installed.is_empty()), "{reps:?}");
    assert!(
        reps.iter()
            .any(|x| x.refused.iter().any(|y| y.contains("below_floor"))),
        "{reps:?}"
    );
}

/// M1. When the state file is lost and nothing complete is left to restore
/// from, the agent fails closed: no install until an operator re-anchors.
#[test]
fn m1_a_lost_state_without_a_complete_record_refuses_installs() {
    let u = Unit::new("m1-closed");
    let (e, b1) = installed_v5_floor_5(&u);
    e.close().unwrap();
    flood_journal(&u);
    std::fs::remove_file(u.cfg.state_path()).unwrap();
    remove_named(u.dir(), "highwater");
    let mut e = u.open();
    let r4 = u.rpk(&files_spec(&u, "nav-stack", 4, true), &[("ok", b"v4")]);
    let b2 = u.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&r4));
    u.pack("p2", 2, &[r4], &[b2]);
    let reps = u.run(&mut e, 4);
    assert!(
        reps.iter().all(|x| x.installed.is_empty()),
        "a downgrade below the lost floor was installed: {reps:?}"
    );
    assert_eq!(
        u.current(&u.cfg.install.files_root, "nav-stack")
            .map(|c| c.starts_with('5')),
        Some(true)
    );
}

// ------------------------------------------------------------------- M2 --

/// M2. The findings spool belongs to the agentd user, which can swap the
/// directories root writes through. Root must never create, link or
/// remove anything outside the spool through a swapped `tmp.deliverd/` or
/// a replaced temporary name.
///
/// Deterministic: instead of racing an attacker thread, the writer's test
/// seam (`findings::seam`) swaps the spool at exactly the steps where a
/// path-based writer would follow it: once the directories are open, and
/// between writing the record and naming it. Run with `O_TMPFILE` and with
/// the named-temporary fallback.
#[test]
fn m2_a_swapped_tmp_directory_in_the_spool_is_never_followed() {
    use robodr_agentd::spool::SpoolClass;
    use robodr_deliverd::findings::{seam, spool_write};
    for named in [false, true] {
        let t = Tmp::new("m2-swap");
        let spool = t.path().join("spool");
        for s in ["ready", "acked"] {
            std::fs::create_dir_all(spool.join(s)).unwrap();
        }
        let outside = t.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let pid = std::process::id();
        // Files the attacker wants root to delete, overwrite or link:
        // exactly the names the agent used for its temporaries.
        for seq in 1..=8u64 {
            std::fs::write(outside.join(format!("{seq:020}.json.{pid}")), b"victim").unwrap();
        }
        let victim = outside.join("victim");
        std::fs::write(&victim, b"victim").unwrap();
        // tmp.deliverd/ is a symlink out of the spool before the write.
        std::os::unix::fs::symlink(&outside, spool.join("tmp.deliverd")).unwrap();
        let (sp, v) = (spool.clone(), victim.clone());
        seam::force_named_temp(named);
        seam::set_hook(Some(Box::new(move |step| {
            let td = sp.join("tmp.deliverd");
            let _ = std::fs::remove_file(&td);
            let _ = std::os::unix::fs::symlink(v.parent().unwrap(), &td);
            if step == "written" {
                // Every hidden name in ready/ (the named temporary) becomes
                // a symlink to the victim.
                for e in std::fs::read_dir(sp.join("ready")).unwrap().flatten() {
                    if e.file_name().to_string_lossy().starts_with('.') {
                        let _ = std::fs::remove_file(e.path());
                        let _ = std::os::unix::fs::symlink(&v, e.path());
                    }
                }
            }
        })));
        let mut written = Vec::new();
        for _ in 0..4 {
            match spool_write(
                &spool,
                1_000_000,
                SpoolClass::Normal,
                &mut 0,
                "t",
                "k",
                &[],
                "{}",
            ) {
                Ok(p) => written.push(p),
                // A named temporary removed under the writer cannot be
                // linked any more: that record is lost (the spool's owner
                // can drop records anyway), nothing else happens.
                Err(e) => assert!(named, "{e}"),
            }
        }
        seam::set_hook(None);
        seam::force_named_temp(false);
        let mut bad = Vec::new();
        for e in std::fs::read_dir(&outside).unwrap() {
            let e = e.unwrap();
            let md = std::fs::symlink_metadata(e.path()).unwrap();
            if std::fs::read(e.path()).unwrap() != b"victim"
                || std::os::unix::fs::MetadataExt::nlink(&md) != 1
            {
                bad.push(e.file_name());
            }
        }
        let count = std::fs::read_dir(&outside).unwrap().count();
        assert!(
            bad.is_empty() && count == 9,
            "root wrote, linked or removed files outside the spool (named: {named}): \
             {bad:?}, {count} of 9 left"
        );
        for w in &written {
            let md = std::fs::symlink_metadata(w).unwrap();
            assert!(md.file_type().is_file(), "{}", w.display());
            let r: robodr_agentd::spool::SpoolRecord =
                serde_json::from_slice(&std::fs::read(w).unwrap()).unwrap();
            assert_eq!(r.value, "{}");
        }
    }
}

// ------------------------------------------------------------------- M4 --

/// M4. The kept rollback target's directory is named by serial: the same
/// serial with other content (re-signed into another manifest) overwrote
/// it, so a later rollback would activate content the state does not
/// record.
#[test]
fn m4_the_same_serial_as_a_kept_target_with_other_content_is_refused() {
    let u = Unit::new("m4-kept");
    let (mut e, b1) = installed_v1(&u, "nav-stack");
    let a = e.state().installed["nav-stack"].ver.digest.clone();
    let r2 = u.rpk(&files_spec(&u, "nav-stack", 2, true), &[("ok", b"v2")]);
    let b2 = u.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&r2));
    u.pack("p2", 2, &[r2], std::slice::from_ref(&b2));
    let reps = u.run(&mut e, 4);
    assert!(reps.iter().any(|x| !x.installed.is_empty()), "{reps:?}");
    assert_eq!(e.state().kept["nav-stack"][0].digest, a);
    // Serial 1 again, other content.
    let r1b = u.rpk(
        &files_spec(&u, "nav-stack", 1, true),
        &[("ok", b"v1"), ("evil", b"B")],
    );
    let b3 = u.bundle(3, Some(bundle_hash(&b2)), std::slice::from_ref(&r1b));
    u.pack("p3", 3, &[r1b], &[b3]);
    let reps = u.run(&mut e, 4);
    assert!(
        reps.iter()
            .any(|x| x.refused.iter().any(|y| y.contains("equivocation"))),
        "{reps:?}"
    );
    // No version directory of nav-stack holds the other content.
    for d in std::fs::read_dir(u.cfg.install.files_root.join("nav-stack")).unwrap() {
        assert!(!d.unwrap().path().join("evil").exists());
    }
    assert_eq!(e.state().installed["nav-stack"].ver.serial, 2);
}

// ------------------------------------------------------------------- L1 --

fn world_dir(t: &Tmp) -> PathBuf {
    let d = t.path().join("world");
    std::fs::create_dir_all(&d).unwrap();
    chmod(t.path(), 0o755);
    chmod(&d, 0o1777);
    d
}

fn alive(pid: i32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| {
        s.rsplit(')')
            .next()
            .is_some_and(|r| !r.trim_start().starts_with('Z'))
    })
}

/// L1. A probe that detaches (new session, every descriptor closed)
/// passed, and its process kept running.
#[test]
fn l1_a_probe_that_detaches_fails_and_its_process_is_killed() {
    if !robodr_deliverd::users::is_root() {
        eprintln!("SKIPPED l1: needs root (probe user)");
        return;
    }
    let t = Tmp::new("l1-detach");
    let w = world_dir(&t);
    let pidfile = w.join("pid");
    let script = format!(
        "setsid /bin/sh -c 'echo $$ > {}; exec sleep 30' </dev/null >/dev/null 2>&1 & sleep 0.3; exit 0",
        pidfile.display()
    );
    let r = runner::run(
        &["/bin/sh".to_string(), "-c".to_string(), script],
        Some(RunAs {
            uid: 65_534,
            gid: 65_534,
        }),
        Limits {
            timeout: Duration::from_secs(10),
            max_output: 4096,
        },
    );
    let pid: Option<i32> = std::fs::read_to_string(&pidfile)
        .ok()
        .and_then(|s| s.trim().parse().ok());
    let survived = pid.is_some_and(alive);
    if let Some(p) = pid {
        let _ = Command::new("kill").args(["-9", &p.to_string()]).status();
    }
    assert!(!r.success(), "a detached probe passed: {r:?}");
    assert!(!survived, "the detached process survived the probe: {r:?}");
}

/// L1. Probes run with resource limits of their own.
#[test]
fn l1_a_probe_runs_under_resource_limits() {
    if !robodr_deliverd::users::is_root() {
        eprintln!("SKIPPED l1 limits: needs root (probe user)");
        return;
    }
    let r = runner::run(
        &["/bin/cat".to_string(), "/proc/self/limits".to_string()],
        Some(RunAs {
            uid: 65_534,
            gid: 65_534,
        }),
        Limits {
            timeout: Duration::from_secs(10),
            max_output: 16 * 1024,
        },
    );
    assert!(r.success(), "{r:?}");
    let soft = |what: &str| -> String {
        r.output
            .lines()
            .find(|l| l.starts_with(what))
            .and_then(|l| l[what.len()..].split_whitespace().next())
            .unwrap_or("?")
            .to_string()
    };
    for what in [
        "Max cpu time",
        "Max address space",
        "Max open files",
        "Max processes",
    ] {
        assert_ne!(soft(what), "unlimited", "{what}: {}", r.output);
    }
    assert!(
        soft("Max open files").parse::<u64>().unwrap() <= 256,
        "{}",
        r.output
    );
}

// ------------------------------------------------------------------- L2 --

/// L2. The default probe UID range admitted system accounts (100..=999).
#[test]
fn l2_system_accounts_are_not_probe_users_by_default() {
    let t = Tmp::new("l2-uid");
    std::fs::write(
        t.path().join("passwd"),
        "plc-gw:x:500:500::/:/usr/sbin/nologin\nprobe:x:1500:1500::/:/usr/sbin/nologin\n",
    )
    .unwrap();
    let v = serde_json::json!({
        "format": "robodr-deliverd-config/1",
        "unit": {"id": UNIT, "site": SITE, "model": "ugv-x1", "platform": "ugv-x1", "arch": "arm64"},
        "trust": {"roots": [format!("sha256:{}", "ab".repeat(32))], "clock": "trusted"},
        "health": {"passwd": t.path().join("passwd")}
    });
    let cfg = robodr_deliverd::Config::parse(&serde_json::to_vec(&v).unwrap()).unwrap();
    assert!(
        robodr_deliverd::users::resolve(&cfg, "plc-gw").is_err(),
        "a system account (UID 500) may run probes by default"
    );
    assert_eq!(
        robodr_deliverd::users::resolve(&cfg, "probe").unwrap().uid,
        1500
    );
}

// ------------------------------------------------------------------- L3 --

/// L3. With `clock: untrusted` the maintenance window was still judged on
/// the (untrusted) system clock: whoever sets the clock opens the window.
#[test]
fn l3_with_an_untrusted_clock_a_maintenance_window_stays_closed() {
    use robodr_pkg::deployment::{MaintenanceWindow, Weekday};
    let u = Unit::with("l3-window", |v| v["trust"]["clock"] = "untrusted".into());
    let (wd, minute) = robodr_deliverd::clock::weekday_minute(NOW);
    let day = [
        Weekday::Mon,
        Weekday::Tue,
        Weekday::Wed,
        Weekday::Thu,
        Weekday::Fri,
        Weekday::Sat,
        Weekday::Sun,
    ][wd as usize];
    let r = u.rpk(&files_spec(&u, "nav-stack", 1, true), &[("ok", b"v1")]);
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    let mut d = deployment(1, "ring-1", &[UNIT], &[r]);
    // A window the (attacker-set) system clock is inside.
    d.maintenance_window = Some(MaintenanceWindow {
        days: vec![day],
        start_minute: minute.saturating_sub(5),
        duration_minutes: 30,
    });
    pack(
        &u.cfg.media_dir,
        "p1",
        &u.trust_path,
        &d,
        &depot_and_ops(&u.keys),
        &[b],
    );
    let mut e = u.open();
    let reps = u.run(&mut e, 4);
    assert!(
        reps.iter().all(|x| x.installed.is_empty()),
        "the window was judged on the untrusted system clock: {reps:?}"
    );
    assert!(
        reps.iter().any(|x| x
            .deferred
            .as_deref()
            .is_some_and(|d| d.contains("maintenance_window"))),
        "{reps:?}"
    );
}

// ------------------------------------------------------------------- L4 --

fn first_chunk(dir: &Path) -> Option<PathBuf> {
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        let p = e.path();
        if p.is_dir() {
            if let Some(c) = first_chunk(&p) {
                return Some(c);
            }
        } else if p.parent().is_some_and(|d| d.ends_with("chunks")) {
            return Some(p);
        }
    }
    None
}

/// L4. A refused media entry was remembered by its name and deployment
/// hash: the corrected pack under the same name was never looked at again.
#[test]
fn l4_a_corrected_pack_under_the_same_name_is_judged_again() {
    let u = Unit::new("l4-media");
    let r = u.rpk(&files_spec(&u, "nav-stack", 1, true), &[("ok", b"v1")]);
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    let p = u.pack("p1", 1, &[r], &[b]);
    let chunk = first_chunk(&p.join("bundles")).unwrap();
    let good = std::fs::read(&chunk).unwrap();
    std::fs::write(&chunk, vec![b'X'; good.len()]).unwrap();
    let mut e = u.open();
    let reps = u.run(&mut e, 3);
    assert!(reps.iter().any(|x| !x.refused.is_empty()), "{reps:?}");
    // The operator copies the pack again, correctly; same name, same
    // deployment.json.
    std::fs::write(&chunk, &good).unwrap();
    let reps = u.run(&mut e, 5);
    assert!(
        reps.iter().any(|x| !x.installed.is_empty()),
        "the corrected pack was skipped: {reps:?}"
    );
}
