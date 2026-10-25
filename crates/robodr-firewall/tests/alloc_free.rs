//! Proof that `Firewall::check` (and `fault_verdict`, `drain_events`) never
//! touch the heap after construction.
//!
//! A counting `GlobalAlloc` wrapper around the system allocator counts
//! allocations made **on the current thread** (thread-local counter, so the
//! test harness's other threads cannot interfere). We build the firewall,
//! snapshot the counter, drive every decision path many times, and require
//! the counter to be unchanged.

mod common;
use common::*;
use robodr_firewall::*;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct Counting;

thread_local! {
    static ALLOCS: Cell<u64> = const { Cell::new(0) };
}

fn bump() {
    // `try_with`: during thread teardown the slot may be gone; never panic in
    // the allocator.
    let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        bump();
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        bump();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        bump();
        unsafe { System.realloc(ptr, layout, new_size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        bump();
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn allocs() -> u64 {
    ALLOCS.with(|c| c.get())
}

/// Drive every decision path: pass, limit (speed/accel/jerk), every reject
/// reason, both substitutes, drop, a full event buffer, and fault handling.
fn exercise(f: &mut Fx, rounds: u64) -> usize {
    let mut seen = 0usize;
    let mut now = T0;
    let joints_ok = JointVelocities::from_slice(&[0.1, 0.2, 0.3, 0.4, 0.5, 0.6]).unwrap();
    let joints_fast = JointVelocities::from_slice(&[3.0, 0.2, 0.3, 0.4, 0.5, 0.6]).unwrap();
    let joints_nan = JointVelocities::from_slice(&[f64::NAN, 0.0, 0.0, 0.0, 0.0, 0.0]).unwrap();
    for i in 0..rounds {
        now += 20 * MS;
        let s = now; // fresh stamps
        let cmds = [
            twist_cmd(f.nav, f.base, s, vx(0.2)),             // pass / accel
            twist_cmd(f.nav, f.base, s + 1, vx(1.5)),         // speed (+accel)
            twist_cmd(f.nav, f.base, s + 2, vx(0.0)),         // stop
            twist_cmd(f.nav, f.base, s + 3, vx(-0.8)),        // reversal: accel
            twist_cmd(f.nav, f.base, s + 4, vx(9.0)),         // over hard
            twist_cmd(f.nav, f.base, s + 5, vx(f64::NAN)),    // non-finite
            twist_cmd(f.nav, f.base, s, vx(0.1)),             // out of order
            twist_cmd(f.teleop, f.base, 0, vx(0.1)),          // stale
            twist_cmd(f.teleop, f.base, u64::MAX, vx(0.1)),   // future
            twist_cmd(SourceId::UNKNOWN, f.base, s, vx(0.1)), // unknown source
            twist_cmd(f.arm_src, f.base, s, vx(0.1)),         // unauthorized
            twist_cmd(f.nav, ChannelId(99), s, vx(0.1)),      // unknown channel
            Command::joints(f.nav, f.base, s + 6, joints_ok), // kind mismatch
            Command::joints(f.arm_src, f.arm, s, joints_ok),  // joints pass
            Command::joints(f.arm_src, f.arm, s + 1, joints_fast), // joints limit
            Command::joints(f.arm_src, f.arm, s + 2, joints_nan), // joints reject
        ];
        for c in &cmds {
            let v = f.fw.check(c, now);
            if v.output().is_some() {
                seen += 1;
            }
        }
        // Burst from one source to trip the rate limiter.
        for k in 0..5 {
            f.fw.check(&twist_cmd(f.teleop, f.base, s + 10 + k, vx(0.1)), now);
        }
        // Clock regression.
        f.fw.check(&twist_cmd(f.nav, f.base, s + 20, vx(0.1)), now - 1);
        // Gateway-declared fault.
        f.fw.fault_verdict(&cmds[0], now);
        // Drain without allocating every few rounds; let the buffer overflow
        // in between so the drop path runs too.
        if i % 4 == 3 {
            let mut drained = 0usize;
            let dropped = f.fw.drain_events(|_| drained += 1);
            assert!(drained > 0 && dropped > 0, "buffer should have overflowed");
            seen += drained;
        }
    }
    seen
}

fn cfg(fail_behaviour: FailBehaviour, drop_foreign: bool, fault: FaultPolicy) -> PlatformConfig {
    PlatformConfig {
        fail_behaviour,
        fault_policy: fault,
        foreign_source_action: if drop_foreign {
            ForeignSourceAction::Drop
        } else {
            ForeignSourceAction::Substitute
        },
        // Short enough that both the emitted and the suppressed
        // foreign-substitute paths are exercised.
        foreign_substitute_min_interval_ns: 3_000_000,
        // Small: identical events coalesce, so only a small buffer
        // overflows and exercises the eviction / drop paths.
        event_capacity: 8,
        ..PlatformConfig::default()
    }
}

#[test]
fn check_never_allocates() {
    let platforms = [
        (
            cfg(FailBehaviour::ZeroVelocity, false, FaultPolicy::FailSafe),
            true,
        ),
        (
            cfg(
                FailBehaviour::HoldLast {
                    max_hold_ns: 50 * MS,
                },
                true,
                FaultPolicy::FailOpen,
            ),
            true,
        ),
        (
            cfg(
                FailBehaviour::PassThroughObserveOnly,
                false,
                FaultPolicy::FailSafe,
            ),
            true,
        ),
        // Observe mode (profile not locked).
        (
            cfg(FailBehaviour::ZeroVelocity, false, FaultPolicy::FailSafe),
            false,
        ),
    ];
    for (platform, locked) in platforms {
        // Construction may allocate.
        let mut f = build(platform, locked, |b, a| {
            b.max_linear_accel = Some(2.0);
            b.max_angular_accel = Some(4.0);
            b.max_linear_jerk = Some(30.0);
            b.rate_limit = Some(RateLimit {
                per_second: 100,
                burst: 3,
            });
            a.max_joint_accel = Some(5.0);
            a.max_joint_jerk = Some(50.0);
        });

        let before = allocs();
        let seen = exercise(&mut f, 2_000);
        let after = allocs();
        assert_eq!(
            after - before,
            0,
            "check() allocated {} times (platform {platform:?}, locked {locked})",
            after - before
        );
        assert!(seen > 0);
        // Sanity: the paths were really taken.
        let s = f.fw.stats();
        assert!(s.checked > 40_000);
        assert!(s.faults > 0);
        if locked && platform.fail_behaviour != FailBehaviour::PassThroughObserveOnly {
            assert!(s.limited > 0 && s.rejected > 0 && s.passed > 0, "{s:?}");
        } else {
            assert!(s.would_have > 0, "{s:?}");
        }
    }
}

#[test]
fn counter_detects_allocations() {
    // Guard against a vacuous pass: the counter must see a real allocation.
    let before = allocs();
    let v = std::hint::black_box(vec![1u8; 64]);
    drop(v);
    assert!(allocs() - before >= 1);
    // And drain_deviations (documented as allocating) is visible too.
    let mut f = default_fx();
    f.fw.check(&twist_cmd(SourceId::UNKNOWN, f.base, T0, vx(0.0)), T0);
    let before = allocs();
    let d = f.fw.drain_deviations();
    assert_eq!(d.len(), 1);
    assert!(allocs() > before);
}

/// Drive every joint-frame path: pass, every clamp, every rejection
/// (including too-early, CRC, energised unused slot, gains below minimum,
/// clock regression, foreign sources), hold and damping substitutes, a slow
/// stream, gateway faults and a full event buffer.
fn exercise_joint(f: &mut JFx, rounds: u64) -> usize {
    let mut seen = 0usize;
    let mut now = T0;
    let slots = f.slots;
    for i in 0..rounds {
        now += 2 * MS;
        let s = now;
        let mut crc_bad = f.nominal(s + 1);
        crc_bad.frame.crc_ok = Some(false);
        let mut crc_none = f.nominal(s + 2);
        crc_none.frame.crc_ok = None;
        let mut foreign = f.nominal(s + 3);
        foreign.source = SourceId::UNKNOWN;
        let mut unauth = f.nominal(s + 3);
        unauth.source = f.nav;
        let mut unknown_ch = f.nominal(s + 3);
        unknown_ch.channel = ChannelId(60);
        let clamps = MotorCmd::enabled(1.5, 15.0, 30.0, 150.0, 7.0);
        let unused = MotorCmd::enabled(0.0, 0.0, 1.0, 0.0, 0.0);
        let hard = MotorCmd::enabled(0.0, 0.0, 1e6, 10.0, 0.0);
        let nan = MotorCmd {
            q: f64::NAN,
            ..good()
        };
        let t = now + MS;
        let cmds = [
            (f.nominal(s), now),                        // pass
            (f.with_slot(s + 4, 0, clamps), t),         // every clamp
            (crc_bad, t),                               // crc invalid
            (crc_none, t),                              // crc missing
            (f.with_slot(s + 5, slots - 1, unused), t), // unused slot
            (f.with_slot(s + 6, 1, MotorCmd::OFF), t),  // kp_min
            (f.with_slot(s + 7, 2, hard), t),           // hard
            (f.with_slot(s + 8, 2, nan), t),            // NaN
            (f.nominal(s.saturating_sub(100 * MS)), t), // stale
            (f.nominal(s + 100 * MS), t),               // future
            (f.nominal(s), t),                          // replay
            (foreign, t),                               // unknown source
            (unauth, t),                                // unauthorised
            (unknown_ch, t),                            // unknown channel
            (
                JointCommand::new(f.ctl, f.low, s + 9, jframe(3, 3, |_| good())),
                t,
            ), // shape
            (
                JointCommand::new(f.nav, f.base, s + 9, jframe(3, 3, |_| good())),
                t,
            ), // kind
        ];
        for (c, t) in &cmds {
            if f.fw.check_joint(c, *t).output().is_some() {
                seen += 1;
            }
        }
        // Too early (min interval), then a clock regression, then a fault.
        f.fw.check_joint(&f.nominal(s + 10), t + 100_000);
        f.fw.check_joint(&f.nominal(s + 11), now);
        f.fw.joint_fault_verdict(&f.nominal(s + 12), t + 100_000);
        // A twist on the joint channel through `check`.
        f.fw.check(&twist_cmd(f.ctl, f.low, s, vx(0.1)), t + 100_000);
        // Every 8th round a long gap (slow stream; hold expiry).
        if i % 8 == 7 {
            now += 200 * MS;
        }
        if i % 4 == 3 {
            let mut drained = 0usize;
            f.fw.drain_events(|_| drained += 1);
            seen += drained;
        }
    }
    seen
}

#[test]
fn check_joint_never_allocates() {
    let rate = |s: &mut JointChannelSpec| {
        s.rate = Some(JointRate::around(500.0));
        for m in s.motors.iter_mut().filter(|m| m.enabled) {
            m.kp_min = 5.0;
        }
    };
    let small = |pf: PlatformConfig| PlatformConfig {
        event_capacity: 8,
        foreign_source_action: ForeignSourceAction::Substitute,
        foreign_substitute_min_interval_ns: 3 * MS,
        ..pf
    };
    let cases = [
        (small(humanoid()), true, 35, 29),
        (small(humanoid()), true, 20, 12),
        (small(quadruped(FailBehaviour::ZeroVelocity)), true, 20, 12),
        (
            small(quadruped(FailBehaviour::HoldLast {
                max_hold_ns: 50 * MS,
            })),
            true,
            12,
            12,
        ),
        (
            small(PlatformConfig {
                fault_policy: FaultPolicy::FailOpen,
                ..humanoid()
            }),
            true,
            35,
            35,
        ),
        // Observe mode.
        (small(humanoid()), false, 35, 29),
    ];
    for (platform, locked, slots, active) in cases {
        // Construction may allocate.
        let mut f = build_joint(platform, locked, slots, active, rate);
        let before = allocs();
        let seen = exercise_joint(&mut f, 2_000);
        let after = allocs();
        assert_eq!(
            after - before,
            0,
            "check_joint() allocated {} times ({platform:?}, locked {locked}, {slots}/{active})",
            after - before
        );
        assert!(seen > 0);
        let s = f.fw.stats();
        assert!(s.checked > 30_000 && s.faults > 0, "{s:?}");
        if locked {
            assert!(s.passed > 0 && s.limited > 0 && s.rejected > 0, "{s:?}");
        } else {
            assert!(s.would_have > 0, "{s:?}");
        }
    }
}
