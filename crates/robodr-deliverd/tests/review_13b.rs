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
use std::path::PathBuf;

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
    assert!(!u.cfg.install.files_root.join("nav-stack/1/extra").exists());
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
