//! Regression tests for the gateway review's clock finding 8:
//!
//! - a `restrict_motion` restriction ended at its wall-clock
//!   `expires_unix_ms`: a forward step of the wall clock (NTP, an operator,
//!   a forged time source) lifted it at once. Its TTL now runs on the
//!   monotonic clock from the moment it was applied.
//! - a kernel receive timestamp after the wall clock (the clock stepped
//!   back while the packet waited) gave no queue delay, i.e. "not late";
//!   it is now late (the firewall's fault verdict).

use robodr_firewall_gw::restrict;
use robodr_firewall_gw::runtime::{apply_restriction, queue_timing};
use robodr_firewall_gw::testkit::*;

const WALL: u64 = 1_800_000_000_000;
const MONO: u64 = 5_000_000;

fn restriction(expires_unix_ms: u64) -> restrict::Restriction {
    restrict::parse(&format!(
        r#"{{"format":"robodr-gw-restriction/v1","id":"r-1","factor":0.5,"expires_unix_ms":{expires_unix_ms}}}"#
    ))
    .unwrap()
}

#[test]
fn f8_wall_clock_jump_does_not_lift_a_restriction() {
    let mut gw = gateway(Fixture::Go2);
    // Applied with 60 s left.
    let r = restriction(WALL + 60_000);
    apply_restriction(&mut gw, Some(Ok(Some(r.clone()))), None, WALL, MONO);
    assert!(gw.restriction().is_some());
    // The wall clock jumps a day ahead; 1 s passed on the monotonic clock.
    // Nothing new read, then the same file read again.
    let day = 86_400_000;
    apply_restriction(&mut gw, None, None, WALL + day, MONO + 1_000);
    assert!(gw.restriction().is_some(), "lifted by a wall-clock jump");
    apply_restriction(
        &mut gw,
        Some(Ok(Some(r.clone()))),
        None,
        WALL + day,
        MONO + 2_000,
    );
    assert!(gw.restriction().is_some(), "lifted on re-read after a jump");
    // A backward jump does not extend it: 60 s of monotonic time end it.
    apply_restriction(&mut gw, None, None, WALL - day, MONO + 59_999);
    assert!(gw.restriction().is_some());
    apply_restriction(&mut gw, None, None, WALL - day, MONO + 60_000);
    assert!(gw.restriction().is_none(), "the monotonic TTL ends it");
}

#[test]
fn f8_restriction_applied_directly_gets_a_monotonic_deadline() {
    let mut gw = gateway(Fixture::Go2);
    gw.set_restriction(Some(restriction(WALL + 10_000)));
    apply_restriction(&mut gw, None, None, WALL, MONO);
    assert_eq!(gw.restriction_deadline_ms(), Some(MONO + 10_000));
    apply_restriction(&mut gw, None, None, WALL + 1_000_000, MONO + 5_000);
    assert!(gw.restriction().is_some());
    apply_restriction(&mut gw, None, None, WALL, MONO + 10_000);
    assert!(gw.restriction().is_none());
}

#[test]
fn f8_receive_timestamp_after_the_wall_clock_is_late() {
    let real = 1_800_000_000_000_000_000u64;
    let mono = 7_000_000_000u64;
    // 2 ms in the queue.
    let s = real / 1_000_000_000 - 1;
    let us = 1_000_000 - 2_000;
    assert_eq!(
        queue_timing(mono, real, Some((s, us))),
        (mono - 2_000_000, Some(2_000_000))
    );
    // Stamped 1 s after `real`: late, not "no delay".
    let (arrival, delay) = queue_timing(mono, real, Some((s + 2, 0)));
    assert_eq!(arrival, mono);
    assert_eq!(delay, Some(u64::MAX));
    // An overflowing stamp too; no stamp is no delay.
    assert_eq!(
        queue_timing(mono, real, Some((u64::MAX, 0))).1,
        Some(u64::MAX)
    );
    assert_eq!(queue_timing(mono, real, None), (mono, None));
}
