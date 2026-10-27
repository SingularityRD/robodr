//! A crash at every step leaves a consistent state (`engine` module docs).
//!
//! For each crash point, a fresh unit with serial 1 installed takes a pack
//! with serial 2; the engine "dies" at the point (it returns at once, as
//! if the process had been killed, and is dropped without closing), a new
//! engine opens the same directories, and the test checks after the crash
//! and after recovery:
//!
//! * the active version is 1 or 2, never anything else or nothing;
//! * the state's installed record is the active version once recovery has
//!   finished, there is no intent left, and the floor never went down;
//! * the outcome is the one without a crash: a good release ends installed,
//!   a bad one rolled back to 1.

mod common;

use common::*;
use robodr_deliverd::fault;
use robodr_deliverd::state::{ItemStatus, StateFile};

const GOOD_POINTS: [&str; 6] = [
    "after_stage",
    "after_intent",
    "after_switch",
    "after_health_intent",
    "after_health",
    "state.after_tmp",
];

const BAD_POINTS: [&str; 7] = [
    "after_intent",
    "after_switch",
    "after_health_intent",
    "after_health",
    "after_rollback_intent",
    "after_rollback_switch",
    "state.after_tmp",
];

fn active(u: &Unit) -> Option<String> {
    u.current(&u.cfg.install.files_root, "nav-stack")
}

fn crash_run(point: &str, healthy: bool) {
    let u = Unit::new(&format!("crash-{point}-{healthy}"));
    let (mut e, b1) = installed_v1(&u, "nav-stack");
    let mut s2 = files_spec(&u, "nav-stack", 2, healthy);
    // A good release raises the floor to itself; a bad one keeps 1 so the
    // rollback target is at the floor (a bad release raising the floor
    // past the old one is `rollback_blocked`, exit_criteria.rs).
    let floor = if healthy { 2 } else { 1 };
    s2.security_floor = floor;
    let r2 = u.rpk(&s2, &[("ok", b"v2")]);
    let b2 = u.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&r2));
    u.pack("p2", 2, &[r2], &[b2]);
    // The state.after_tmp point fires at the first state write; import
    // and stage while moving so that write is the intent of the switch.
    if point == "state.after_tmp" {
        u.safety("moving_slow");
        let r = e.tick().unwrap();
        assert!(r.deferred.is_some(), "{r:?}");
        u.safety("idle");
    }
    fault::arm(point);
    let mut crashed = false;
    for _ in 0..6 {
        match e.tick() {
            Ok(_) => {}
            Err(err) => {
                assert!(err.0.contains("simulated crash"), "{point}: {err}");
                crashed = true;
                break;
            }
        }
    }
    fault::disarm();
    assert!(crashed, "{point} never fired (healthy {healthy})");
    drop(e); // killed: no close, no seal
             // Right after the crash: one of the two versions is active.
    let a = active(&u);
    assert!(
        matches!(a.as_deref(), Some("1") | Some("2")),
        "{point}: active after crash {a:?}"
    );
    let st = StateFile::new(&u.cfg.state_path()).load().unwrap().unwrap();
    assert!(st.floor("nav-stack") >= 1);
    // Recovery.
    let mut e = u.open();
    let reps = u.run(&mut e, 8);
    let st = e.state().clone();
    assert!(st.txn.is_none(), "{point}: intent left: {reps:?}");
    let inst = &st.installed["nav-stack"];
    let want = if healthy { 2 } else { 1 };
    assert_eq!(inst.ver.serial, want, "{point} healthy={healthy}: {reps:?}");
    assert!(inst.healthy, "{point}");
    assert_eq!(
        active(&u).as_deref(),
        Some(want.to_string().as_str()),
        "{point}"
    );
    assert_eq!(
        st.floor("nav-stack"),
        floor,
        "{point}: the floor is raised before the switch"
    );
    let item = &st.deployment.as_ref().unwrap().items[0];
    assert_eq!(
        item.status,
        if healthy {
            ItemStatus::Installed
        } else {
            ItemStatus::Failed
        },
        "{point}"
    );
    // A crash is visible in the evidence when it hit mid-switch.
    if !matches!(point, "after_stage" | "state.after_tmp") {
        assert!(
            !u.notes_of("robodr.deliver.recovered").is_empty(),
            "{point}"
        );
    }
    assert!(u.black_box_verifies(), "{point}");
}

#[test]
fn a_crash_at_any_step_of_a_good_release_recovers_to_installed() {
    for p in GOOD_POINTS {
        crash_run(p, true);
    }
}

#[test]
fn a_crash_at_any_step_of_a_bad_release_recovers_to_the_rollback() {
    for p in BAD_POINTS {
        crash_run(p, false);
    }
}

#[test]
fn a_crash_in_the_switch_of_a_first_install_without_rollback_target() {
    // No earlier version: after a crash during the first switch the unit
    // either retries (not switched) or judges the new version.
    for point in ["after_intent", "after_switch"] {
        let u = Unit::new(&format!("crash-first-{point}"));
        let r = u.rpk(&files_spec(&u, "nav-stack", 1, true), &[("ok", b"v1")]);
        let b = u.bundle(1, None, std::slice::from_ref(&r));
        u.pack("p1", 1, &[r], &[b]);
        let mut e = u.open();
        fault::arm(point);
        let mut crashed = false;
        for _ in 0..4 {
            if e.tick().is_err() {
                crashed = true;
                break;
            }
        }
        fault::disarm();
        assert!(crashed);
        drop(e);
        let mut e = u.open();
        u.run(&mut e, 6);
        assert_eq!(e.state().installed["nav-stack"].ver.serial, 1, "{point}");
        assert_eq!(active(&u).as_deref(), Some("1"));
    }
}
