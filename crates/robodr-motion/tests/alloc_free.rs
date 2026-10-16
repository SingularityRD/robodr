//! Verifies the per-event path performs no heap allocation, using a counting
//! global allocator (per thread, so the test harness's own threads do not
//! interfere).

use robodr_events::Severity;
use robodr_motion::*;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct Counting;

thread_local! {
    static ALLOCS: Cell<u64> = const { Cell::new(0) };
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.with(|c| c.set(c.get() + 1));
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.with(|c| c.set(c.get() + 1));
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn allocs() -> u64 {
    ALLOCS.with(|c| c.get())
}

const MS: u64 = 1_000_000;

#[test]
fn per_event_path_is_allocation_free() {
    let mut cfg = MonitorConfig::ugv("alloc-test");
    cfg.command_channels = vec!["/cmd_vel".into()];
    let mut mon = ConsistencyMonitor::new(cfg).unwrap();
    let cap = mon.command_capacity();

    let mut findings = 0u64;
    let mut worst = Severity::Low;
    let before = allocs();
    for k in 0..100_000u64 {
        let t = 1_000 * MS + k * 10 * MS;
        // A trace that exercises every rule: commands on/off, a foreign
        // channel, held robot with mirrored odometry, NaN, stamp games,
        // safety-stop toggles and ticks.
        let phase = (k / 500) % 6;
        let cmd = if phase == 0 { 0.0 } else { 1.0 };
        let channel = if k % 97 == 0 { "/other" } else { "/cmd_vel" };
        mon.on_command(
            &CommandSample {
                t_ns: t,
                channel,
                linear: Some(cmd),
                angular: Some(cmd * 0.3),
                joint_speed_max: None,
                direction_known: true,
            },
            |f| {
                findings += 1;
                worst = worst.max(f.severity);
            },
        );
        let odo_lin = match phase {
            3 => 0.75,     // frozen
            4 => f64::NAN, // invalid
            _ => cmd + (k % 5) as f64 * 1e-3,
        };
        let stamp = if phase == 5 && k % 50 == 0 {
            t - 3_000 * MS
        } else {
            t
        };
        mon.on_feedback(
            t,
            &FeedbackSample {
                t_ns: stamp,
                source: FeedbackSource::WheelOdometry,
                linear: Some(odo_lin),
                angular: Some(cmd * 0.3),
                joint_speed_max: None,
            },
            |f| {
                findings += 1;
                worst = worst.max(f.severity);
            },
        );
        mon.on_feedback(
            t,
            &FeedbackSample {
                t_ns: t,
                source: FeedbackSource::Imu,
                linear: None,
                angular: Some(if phase == 2 { 0.0 } else { cmd * 0.3 }),
                joint_speed_max: None,
            },
            |f| {
                findings += 1;
                worst = worst.max(f.severity);
            },
        );
        if k % 10 == 0 {
            mon.tick(t, |_| findings += 1);
        }
        if k % 1700 == 0 {
            mon.set_safety_stop(t, (k / 1700) % 2 == 1);
        }
    }
    let after = allocs();
    assert_eq!(after - before, 0, "per-event path allocated");
    assert!(findings > 10, "trace should exercise the detectors");
    assert!(worst >= Severity::High);
    assert_eq!(mon.command_capacity(), cap);
}

#[test]
fn guid_keyed_feedback_and_publisher_overflow_are_allocation_free() {
    // Full-GUID keys, a flood beyond PUBLISHER_SLOTS (overflow slot +
    // flagged finding), cross-sensor and frozen paths, all alloc-free.
    let mut mon = ConsistencyMonitor::new(MonitorConfig::ugv("alloc-guid")).unwrap();
    let mut findings = 0u64;
    let before = allocs();
    for k in 0..50_000u64 {
        let t = 1_000 * MS + k * 5 * MS;
        let cmd = if (k / 400) % 2 == 0 { 0.0 } else { 0.8 };
        mon.on_command(
            &CommandSample {
                t_ns: t,
                channel: "/cmd_vel",
                linear: Some(cmd),
                angular: Some(0.0),
                joint_speed_max: None,
                direction_known: true,
            },
            |_| findings += 1,
        );
        let mut guid = [0xA5u8; 16];
        guid[15] = (k % 11) as u8; // 11 writers: > PUBLISHER_SLOTS
        let lin = if k % 3 == 0 { 0.5 } else { cmd };
        mon.on_feedback_guid(
            t,
            &guid,
            &FeedbackSample {
                t_ns: t,
                source: FeedbackSource::WheelOdometry,
                linear: Some(lin),
                angular: Some(0.0),
                joint_speed_max: None,
            },
            |_| findings += 1,
        );
        mon.on_feedback_key(
            t,
            PublisherKey::Id(7),
            &FeedbackSample {
                t_ns: t,
                source: FeedbackSource::Gnss,
                linear: Some(if k % 7 == 0 { 2.0 } else { cmd }),
                angular: None,
                joint_speed_max: None,
            },
            |_| findings += 1,
        );
    }
    assert_eq!(allocs() - before, 0, "per-event path allocated");
    assert!(findings > 0);
    assert!(mon.stats().publisher_overflow > 0);
}
