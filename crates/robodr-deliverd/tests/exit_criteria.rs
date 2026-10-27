//! Sprint 13b exit criteria (`docs/SECURE-DELIVERY.md` §10): a bad release
//! auto-rolls back; a downgrade below the floor is refused; an install is
//! deferred while the safety state is `moving_slow` and proceeds when it is
//! `idle`; every step is recorded in the black box (and reported as a
//! `robot.deliver.*` finding in agentd's spool).
//!
//! The safety state here is agentd's `status.json` written by the test;
//! `agentd_replay.rs` drives the same gate through a real agentd and the
//! replay helper.

mod common;

use common::*;
use robodr_pkg::rpk::Kind;

#[test]
fn a_bad_release_rolls_back_automatically() {
    let u = Unit::new("rollback");
    let good = u.rpk(
        &files_spec(&u, "nav-stack", 1, true),
        &[("ok", b"v1"), ("bin/nav", b"one")],
    );
    let b1 = u.bundle(1, None, std::slice::from_ref(&good));
    u.pack(
        "p1",
        1,
        std::slice::from_ref(&good),
        std::slice::from_ref(&b1),
    );
    let mut e = u.open();
    let reps = u.run(&mut e, 5);
    assert!(
        reps.iter()
            .any(|r| r.installed == vec!["nav-stack 1".to_string()]),
        "{reps:?}"
    );
    let files = &u.cfg.install.files_root;
    assert_eq!(u.current(files, "nav-stack").as_deref(), Some("1"));

    // Serial 2: its health check names a file the release does not ship.
    let bad = u.rpk(
        &files_spec(&u, "nav-stack", 2, false),
        &[("ok", b"v2"), ("bin/nav", b"two")],
    );
    let b2 = u.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&bad));
    u.pack("p2", 2, std::slice::from_ref(&bad), &[b2]);
    let reps = u.run(&mut e, 5);
    assert!(
        reps.iter()
            .any(|r| r.rolled_back == vec!["nav-stack 2 -> 1".to_string()]),
        "{reps:?}"
    );
    assert_eq!(u.current(files, "nav-stack").as_deref(), Some("1"));
    assert_eq!(
        std::fs::read(files.join("nav-stack/current/bin/nav")).unwrap(),
        b"one"
    );
    let st = e.state().clone();
    let inst = &st.installed["nav-stack"];
    assert_eq!((inst.ver.serial, inst.healthy), (1, true));
    assert!(st.txn.is_none());
    assert_eq!(
        st.deployment.as_ref().unwrap().items[0].status,
        robodr_deliverd::state::ItemStatus::Failed
    );
    // The failed version is gone, the good one stays.
    assert!(!files.join("nav-stack/2").exists());
    // Evidence: every step in the black box, in order.
    let kinds: Vec<String> = u
        .notes()
        .iter()
        .map(|n| n["kind"].as_str().unwrap().to_string())
        .collect();
    let seq = [
        "robodr.deliver.pack_imported",
        "robodr.deliver.staged",
        "robodr.deliver.activating",
        "robodr.deliver.switched",
        "robodr.deliver.health",
        "robodr.deliver.rollback",
        "robodr.deliver.rollback",
    ];
    let tail: Vec<&String> = kinds
        .iter()
        .skip_while(|k| {
            // Skip to the second pack.
            k.as_str() != "robodr.deliver.installed"
        })
        .skip(1)
        .collect();
    let mut it = tail.iter();
    for want in seq {
        assert!(
            it.any(|k| k.as_str() == want),
            "{want} missing in order: {tail:?}"
        );
    }
    let health: Vec<_> = u.notes_of("robodr.deliver.health");
    assert_eq!(health.last().unwrap()["passed"], false);
    let rb = u.notes_of("robodr.deliver.rollback");
    assert_eq!(rb.last().unwrap()["phase"], "done");
    assert_eq!(rb.last().unwrap()["to"], 1);
    // Findings: installed (Low), then health_failed (High).
    let f = u.findings();
    assert!(
        f.iter()
            .any(|(r, s, _)| r == "robot.deliver.installed" && s == "low"),
        "{f:?}"
    );
    assert!(f
        .iter()
        .any(|(r, s, _)| r == "robot.deliver.health_failed" && s == "high"));
    assert!(u.black_box_verifies());
    e.close().unwrap();
}

#[test]
fn a_failing_release_that_raised_the_floor_is_not_rolled_back_below_it() {
    let u = Unit::new("blocked");
    let (mut e, b1) = installed_v1(&u, "nav-stack");
    // Serial 2 is a security release (floor 2) and fails its health gate:
    // serial 1 may never run again, so there is no rollback target.
    let mut s2 = files_spec(&u, "nav-stack", 2, false);
    s2.security_floor = 2;
    let r2 = u.rpk(&s2, &[("ok", b"v2")]);
    let b2 = u.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&r2));
    u.pack("p2", 2, &[r2], &[b2]);
    let reps = u.run(&mut e, 5);
    assert!(
        reps.iter()
            .any(|r| r.blocked == vec!["nav-stack 2".to_string()]),
        "{reps:?}"
    );
    assert!(reps.iter().all(|r| r.rolled_back.is_empty()));
    assert_eq!(
        u.current(&u.cfg.install.files_root, "nav-stack").as_deref(),
        Some("2")
    );
    let inst = &e.state().installed["nav-stack"];
    assert_eq!((inst.ver.serial, inst.healthy), (2, false));
    let n = u.notes_of("robodr.deliver.rollback_blocked");
    assert_eq!(n.len(), 1);
    assert_eq!(n[0]["floor"], 2);
    assert!(n[0]["reason"].as_str().unwrap().contains("below the floor"));
    assert!(u
        .findings()
        .iter()
        .any(|(r, s, _)| r == "robot.deliver.rollback_blocked_floor" && s == "critical"));
    // Serial 1 stays out: a deployment naming it is refused.
    let r1 = std::fs::read_dir(u.work.join("rpks"))
        .unwrap()
        .map(|x| x.unwrap().path())
        .find(|p| p.ends_with("rpk_nav-stack_1_arm64"))
        .unwrap();
    let b3 = u.bundle(1, None, std::slice::from_ref(&r1));
    u.pack("p3", 3, &[r1], &[b3]);
    let reps = u.run(&mut e, 3);
    assert!(
        reps.iter()
            .any(|r| r.refused.iter().any(|x| x.contains("below_floor"))),
        "{reps:?}"
    );
}

#[test]
fn a_downgrade_below_the_floor_is_refused() {
    let u = Unit::new("floor");
    let mut s3 = files_spec(&u, "nav-stack", 3, true);
    s3.security_floor = 3;
    let r3 = u.rpk(&s3, &[("ok", b"v3")]);
    let b1 = u.bundle(1, None, std::slice::from_ref(&r3));
    u.pack("p1", 1, &[r3], std::slice::from_ref(&b1));
    let mut e = u.open();
    u.run(&mut e, 5);
    assert_eq!(e.state().floor("nav-stack"), 3);
    assert_eq!(
        u.current(&u.cfg.install.files_root, "nav-stack").as_deref(),
        Some("3")
    );
    let raised = u.notes_of("robodr.deliver.floor_raised");
    assert_eq!(raised.len(), 1);
    assert_eq!(
        (raised[0]["from"].as_u64(), raised[0]["to"].as_u64()),
        (Some(0), Some(3))
    );

    // A validly signed, depot- and operator-approved serial 2: refused.
    let r2 = u.rpk(&files_spec(&u, "nav-stack", 2, true), &[("ok", b"v2")]);
    let b2 = u.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&r2));
    u.pack("p2", 2, &[r2], &[b2]);
    let reps = u.run(&mut e, 5);
    assert!(
        reps.iter()
            .any(|r| r.refused.iter().any(|x| x.contains("below_floor"))),
        "{reps:?}"
    );
    assert_eq!(
        u.current(&u.cfg.install.files_root, "nav-stack").as_deref(),
        Some("3")
    );
    assert!(u
        .version_dirs(&u.cfg.install.files_root, "nav-stack", 2)
        .is_empty());
    let refused = u.notes_of("robodr.deliver.refused");
    assert!(
        refused.iter().any(|n| n["code"] == "below_floor"),
        "{refused:?}"
    );
    assert!(u
        .findings()
        .iter()
        .any(|(r, s, v)| r == "robot.deliver.refused"
            && s == "high"
            && v.to_string().contains("below_floor")));
    // Not even through a deployment that only lists the lower serial for
    // another reason later: the floor is in the state file, fsynced.
    drop(e);
    let st = robodr_deliverd::state::StateFile::new(&u.cfg.state_path())
        .load()
        .unwrap()
        .unwrap();
    assert_eq!(st.floor("nav-stack"), 3);
    assert!(u.black_box_verifies());
}

#[test]
fn install_is_deferred_while_moving_slow_and_proceeds_when_idle() {
    let u = Unit::new("defer");
    u.safety("moving_slow");
    let r = u.rpk(&files_spec(&u, "nav-stack", 1, true), &[("ok", b"v1")]);
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    u.pack("p1", 1, &[r], &[b]);
    let mut e = u.open();
    for _ in 0..3 {
        let rep = e.tick().unwrap();
        assert_eq!(
            rep.deferred.as_deref(),
            Some("nav-stack 1: safety_state:moving_slow"),
            "{rep:?}"
        );
        assert!(rep.installed.is_empty());
    }
    // Staged (the version directory exists), never switched.
    let files = &u.cfg.install.files_root;
    assert!(u.version_dir(files, "nav-stack", 1).join("ok").is_file());
    assert_eq!(u.current(files, "nav-stack"), None);
    assert!(u.notes_of("robodr.deliver.activating").is_empty());
    // One deferral note per change of reason, not one per loop.
    let d = u.notes_of("robodr.deliver.deferred");
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!(d[0]["safety_state"], "moving_slow");
    // Other unsafe states defer too.
    for s in [
        "moving_fast",
        "collaborative_human_nearby",
        "estop_active",
        "unknown",
    ] {
        u.safety(s);
        let rep = e.tick().unwrap();
        assert!(rep.deferred.as_deref().unwrap().ends_with(s), "{rep:?}");
    }
    // A stale or absent status is unknown.
    std::fs::remove_file(&u.cfg.safety.agentd_status).unwrap();
    assert!(e.tick().unwrap().deferred.unwrap().ends_with("unknown"));
    u.safety("idle");
    let rep = e.tick().unwrap();
    assert_eq!(rep.installed, vec!["nav-stack 1".to_string()]);
    assert_eq!(u.current(files, "nav-stack").as_deref(), Some("1"));
    let act = u.notes_of("robodr.deliver.activating");
    assert_eq!(act[0]["safety_state"], "idle");
    let f = u.findings();
    let deferred: Vec<_> = f
        .iter()
        .filter(|x| x.0 == "robot.deliver.deferred_safety")
        .collect();
    assert!(!deferred.is_empty());
    assert_eq!(deferred[0].1, "low");
    assert!(f.iter().any(|x| x.0 == "robot.deliver.installed"));
    assert!(u.black_box_verifies());
}

#[test]
fn safe_state_active_also_allows_the_install() {
    let u = Unit::new("safe-state");
    u.safety("safe_state_active");
    let r = u.rpk(&files_spec(&u, "nav-stack", 1, true), &[("ok", b"v1")]);
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    u.pack("p1", 1, &[r], &[b]);
    let mut e = u.open();
    let reps = u.run(&mut e, 4);
    assert!(reps.iter().any(|x| !x.installed.is_empty()), "{reps:?}");
}

#[test]
fn repeated_deferrals_raise_the_finding_to_medium() {
    let u = Unit::with("defer-medium", |v| {
        v["findings"]["deferral_medium_after"] = 3.into();
    });
    u.safety("moving_fast");
    let r = u.rpk(&files_spec(&u, "nav-stack", 1, true), &[("ok", b"v1")]);
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    u.pack("p1", 1, &[r], &[b]);
    let mut e = u.open();
    for _ in 0..4 {
        e.tick().unwrap();
    }
    let sev: Vec<String> = u
        .findings()
        .into_iter()
        .filter(|f| f.0 == "robot.deliver.deferred_safety")
        .map(|f| f.1)
        .collect();
    assert_eq!(sev, vec!["low".to_string(), "medium".to_string()]);
}

#[test]
fn a_config_package_lands_under_its_root_only() {
    let u = Unit::new("config");
    let mut s = spec("nav-config", 1, Kind::Config);
    s.health = vec![robodr_pkg::rpk::HealthCheck::FilePresent {
        path: format!(
            "{}/nav-config/current/nav.yaml",
            u.cfg.install.config_root.display()
        ),
    }];
    let r = u.rpk(
        &s,
        &[("nav.yaml", b"speed: 1\n"), ("sub/limits.yaml", b"a: 1\n")],
    );
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    u.pack("p1", 1, &[r], &[b]);
    let mut e = u.open();
    let reps = u.run(&mut e, 4);
    assert!(
        reps.iter()
            .any(|x| x.installed == vec!["nav-config 1".to_string()]),
        "{reps:?}"
    );
    let etc = &u.cfg.install.config_root;
    assert_eq!(
        std::fs::read(etc.join("nav-config/current/sub/limits.yaml")).unwrap(),
        b"a: 1\n"
    );
    assert_eq!(u.current(etc, "nav-config").as_deref(), Some("1"));
}
