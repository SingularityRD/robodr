//! Live `AF_PACKET` capture on loopback through `CaptureDatagramSource` ->
//! `Pipeline`. Needs `CAP_NET_RAW`; without it the test prints "SKIPPED"
//! and passes.
//!
//! The *test* sends one ordinary UDP datagram with `std::net::UdpSocket` to
//! generate traffic on `lo`; the capture code itself never transmits.

#![cfg(target_os = "linux")]

mod common;

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::*;
use robodr_capture::RtpsPortMap;
use robodr_ros2_pipeline::{CaptureDatagramSource, DatagramSource, Pipeline, PipelineOptions};

#[test]
fn rogue_sedp_on_loopback_is_caught_live() {
    let src = match CaptureDatagramSource::open_live(
        &["lo".to_string()],
        RtpsPortMap::ros2_default(),
        Duration::from_millis(100),
    ) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("SKIPPED: live capture needs CAP_NET_RAW ({e})");
            return;
        }
        Err(e) => panic!("opening live capture failed: {e}"),
    };
    let stop = Arc::new(AtomicBool::new(false));
    let mut src = src.with_stop_flag(stop.clone());

    // A unique rogue prefix so concurrent loopback traffic cannot collide.
    let mut rogue = [0xe1u8; 12];
    rogue[8..].copy_from_slice(&std::process::id().to_be_bytes());
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    tx.send_to(
        &sedp_datagram(rogue, "rt/cmd_vel", TWIST),
        ("127.0.0.1", 7410),
    )
    .unwrap();
    let flag = stop.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(2));
        flag.store(true, Ordering::Relaxed);
    });

    let mut p = Pipeline::new(robot_profile(true), PipelineOptions::default());
    let rogue_hex: String = rogue.iter().map(|b| format!("{b:02x}")).collect();
    let mut critical = 0;
    while let Some(d) = src.recv().unwrap() {
        for f in p.process_datagram(&d) {
            if f.deviation.rule == "robot.ros2.unauthorized_motion_writer"
                && f.deviation.detail.contains(&rogue_hex)
            {
                assert_eq!(f.src_ip, "127.0.0.1");
                critical += 1;
                stop.store(true, Ordering::Relaxed);
            }
        }
    }
    assert_eq!(critical, 1, "rogue cmd_vel writer seen exactly once");
}
