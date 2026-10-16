//! Harness: ROS 2 sensor configuration (`robodr_ros2_pipeline::Config`, the
//! `[module.robodr-sensor-ros2]` section) deserialisation and validation,
//! then a pipeline built from the validated options.
//!
//! Pulsar deserialises the section from TOML with serde; no TOML parser is
//! available offline, so the harness feeds JSON to the same `Deserialize`
//! impl (the struct shape, defaults and validation are what is under test,
//! not the TOML lexer). Input: arbitrary bytes, tried as JSON. The default
//! route lookup is injected (`eth0` or none) so the result does not depend
//! on the host. The first line of the input, when it is not JSON, is also
//! fed to `default_route_interface` as a `/proc/net/route` table.
//!
//! Invariants beyond "no panic": validation is deterministic; accepted
//! settings keep the domain within `MAX_DOMAIN_ID`, the queue and read
//! timeout within their bounds; a pipeline with an unlocked profile only
//! reports observe-only findings, and never more than
//! `max_findings_per_datagram` (+1 summary) per datagram.
#![allow(dead_code)]

use robodr_events::profile::{Envelope, Profile};
use robodr_ros2_pipeline::config::{
    default_route_interface, valid_ifname, MAX_DOMAIN_ID, MAX_QUEUE_CAPACITY, MAX_READ_TIMEOUT_MS,
    MIN_READ_TIMEOUT_MS,
};
use robodr_ros2_pipeline::{Config, Pipeline};

const DATAGRAMS: [&[u8]; 3] = [
    include_bytes!("../../crates/robodr-rtps/tests/fixtures/fastdds_spdp_participant.bin"),
    include_bytes!("../../crates/robodr-rtps/tests/fixtures/sedp_pub_cmd_vel.bin"),
    include_bytes!("../../crates/robodr-rtps/tests/fixtures/sedp_sub_odom.bin"),
];

fn profile() -> Profile {
    let mut p = Profile {
        model: "ugv-fuzz-x1".into(),
        ..Default::default()
    };
    p.writer_topics.insert("/cmd_vel".into());
    p.motion_envelopes.insert(
        "/cmd_vel".into(),
        Envelope {
            max_linear_speed: Some(0.5),
            max_joint_speed: None,
        },
    );
    p
}

pub fn run(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Some(iface) = default_route_interface(text) {
        assert!(
            valid_ifname(&iface),
            "invalid default-route interface {iface:?}"
        );
    }
    let Ok(cfg) = serde_json::from_str::<Config>(text) else {
        return;
    };
    let with_eth0 = cfg.validate_with(|| Some("eth0".into()));
    assert_eq!(
        format!("{with_eth0:?}"),
        format!("{:?}", cfg.validate_with(|| Some("eth0".into()))),
        "validation is not deterministic"
    );
    let _ = cfg.validate_with(|| None);
    let Ok((settings, _warnings)) = with_eth0 else {
        return;
    };
    assert!(settings.domain_id <= MAX_DOMAIN_ID);
    assert!(settings.profile_path.is_absolute());
    if let Some(c) = &settings.capture {
        assert!(c.queue_capacity >= 1 && c.queue_capacity <= MAX_QUEUE_CAPACITY);
        let ms = c.read_timeout.as_millis() as u64;
        assert!((MIN_READ_TIMEOUT_MS..=MAX_READ_TIMEOUT_MS).contains(&ms));
    }
    let cap = cfg.max_findings_per_datagram;
    let mut pl = Pipeline::new(profile(), settings.pipeline);
    for (i, d) in DATAGRAMS.iter().cycle().take(6).enumerate() {
        let ip = format!("198.51.100.{}", i % 3);
        let findings = pl.process(d, &ip);
        assert!(
            findings.len() <= cap + 1,
            "{} findings > cap {cap}",
            findings.len()
        );
        assert!(
            findings.iter().all(|f| f.is_observe_only()),
            "unlocked profile produced an enforcing finding"
        );
    }
    let _ = pl.finish();
}
