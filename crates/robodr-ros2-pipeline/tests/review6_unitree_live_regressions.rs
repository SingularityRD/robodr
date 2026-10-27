//! Review of the Unitree live integration (legacy UDP sender checks,
//! spoofed-source floods, IP / MAC binding, RTPS on a legacy port, command
//! type names), end to end through `Pipeline`.

mod common;

use std::time::Instant;

use robodr_cdr::unitree_legacy::channels;
use robodr_events::profile::{Envelope, Profile};
use robodr_events::Severity;
use robodr_ros2_pipeline::{rules, LegacyOptions, LegacyUdp, Pipeline, PipelineOptions};

const OPERATOR: &str = "192.168.123.162";
const ROBOT: &str = "192.168.123.10";

fn go1_profile() -> Profile {
    let mut profile = Profile {
        model: "go1".into(),
        locked: true,
        ..Default::default()
    };
    for ch in [channels::HIGH_CMD, channels::LOW_CMD] {
        profile.writer_topics.insert(ch.into());
    }
    profile.motion_envelopes.insert(
        channels::HIGH_CMD.into(),
        Envelope {
            max_linear_speed: Some(1.0),
            ..Default::default()
        },
    );
    profile
}

fn legacy_pipeline() -> Pipeline {
    Pipeline::new(
        go1_profile(),
        PipelineOptions {
            legacy: LegacyOptions {
                enabled: true,
                command_senders: [OPERATOR.parse().unwrap()].into_iter().collect(),
                ..LegacyOptions::default()
            },
            ..Default::default()
        },
    )
}

fn to_low_server() -> LegacyUdp {
    LegacyUdp::new(8080, 8007, ROBOT.parse().unwrap())
}

fn rules_of(o: &robodr_ros2_pipeline::ProcessOutput) -> Vec<(String, Severity)> {
    o.findings
        .iter()
        .map(|f| (f.deviation.rule.to_string(), f.deviation.severity))
        .collect()
}

/// H1: every real Go1 low-level command is sent in the 614-byte compressed
/// form (`comm.h`). Such a frame from a host that is not a listed command
/// sender is a Critical unknown-sender finding, not only "undecodable".
#[test]
fn compressed_low_cmd_from_unknown_host_is_critical() {
    let mut p = legacy_pipeline();
    let o = p.process_legacy_at(
        &[0x5a; 614],
        "192.168.123.66",
        &to_low_server(),
        Instant::now(),
        1,
    );
    let r = rules_of(&o);
    assert!(
        r.contains(&(rules::LEGACY_UNKNOWN_SENDER.to_string(), Severity::Critical)),
        "{r:?}"
    );
    assert!(
        r.iter()
            .any(|(id, _)| id == rules::MOTION_UNDECODABLE_SAMPLE),
        "still reported as not inspected: {r:?}"
    );
    assert_eq!(p.stats().legacy.unknown_sender, 1);
    // From the listed sender: only "not inspected".
    let o = p.process_legacy_at(&[0x5a; 614], OPERATOR, &to_low_server(), Instant::now(), 2);
    let r = rules_of(&o);
    assert!(
        !r.iter().any(|(id, _)| id == rules::LEGACY_UNKNOWN_SENDER),
        "{r:?}"
    );
}

/// H1: the unknown-sender finding of a compressed command is not subject to
/// the shared `undecodable_sample` rate limit: junk on the legacy port that
/// drained that bucket does not hide a later spoofed command sender.
#[test]
fn undecodable_flood_does_not_suppress_unknown_sender() {
    let mut p = legacy_pipeline();
    let t0 = Instant::now();
    // Many undecodable payloads from the listed sender, each with a
    // different length so dedup does not collapse them (unknown lengths).
    for i in 0..200usize {
        let _ = p.process_legacy_at(&vec![0u8; 10 + i], OPERATOR, &to_low_server(), t0, i as u64);
    }
    let o = p.process_legacy_at(&[0x5a; 614], "10.9.9.9", &to_low_server(), t0, 999);
    let r = rules_of(&o);
    assert!(
        r.contains(&(rules::LEGACY_UNKNOWN_SENDER.to_string(), Severity::Critical)),
        "{r:?}"
    );
}

/// M3: a flood of commands from spoofed, ever-changing source addresses
/// gives one finding per sender only up to a bound, then aggregated
/// Critical flood findings with counts (a logarithmic number of them), and
/// bounded memory.
#[test]
fn spoofed_source_flood_is_aggregated() {
    let mut p = legacy_pipeline();
    let t0 = Instant::now();
    let mut per_sender = 0usize;
    let mut flood = Vec::new();
    for i in 0..5000u32 {
        let ip = format!("10.{}.{}.{}", (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
        let o = p.process_legacy_at(&[0x5a; 614], &ip, &to_low_server(), t0, u64::from(i));
        for f in &o.findings {
            if f.deviation.rule == rules::LEGACY_UNKNOWN_SENDER {
                per_sender += 1;
            } else if f.deviation.rule == rules::LEGACY_SENDER_FLOOD {
                flood.push((f.deviation.severity, f.deviation.detail.clone()));
            }
        }
    }
    assert_eq!(
        per_sender,
        robodr_ros2_pipeline::legacy::MAX_REPORTED_UNKNOWN_SENDERS
    );
    assert!(!flood.is_empty() && flood.len() <= 16, "{}", flood.len());
    assert!(flood.iter().all(|(s, _)| *s == Severity::Critical));
    assert!(flood.last().unwrap().1.contains("frames"), "{flood:?}");
    assert_eq!(p.stats().legacy.unknown_sender, 5000);
}

/// M3: a command sender bound to a MAC: the right MAC passes, another MAC
/// is a High mismatch (and the frame is not attributed), an unknown MAC
/// (capture without a link-layer source) is counted, not reported, and a
/// reassembled (fragmented) frame cannot be verified, which is reported.
#[test]
fn command_sender_mac_binding() {
    const MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x62];
    let mut opts = LegacyOptions {
        enabled: true,
        command_senders: [OPERATOR.parse().unwrap()].into_iter().collect(),
        ..LegacyOptions::default()
    };
    opts.sender_macs.insert(OPERATOR.parse().unwrap(), MAC);
    let mut p = Pipeline::new(
        go1_profile(),
        PipelineOptions {
            legacy: opts,
            ..Default::default()
        },
    );
    let t0 = Instant::now();
    let mut high = vec![0u8; robodr_cdr::unitree_legacy::LEGACY_HIGH_CMD_LEN];
    high[22] = 2;
    let ok = to_low_server().with_src_mac(Some(MAC));
    let o = p.process_legacy_at(&high, OPERATOR, &ok, t0, 1);
    assert!(rules_of(&o).is_empty(), "{:?}", rules_of(&o));
    assert_eq!(
        o.motion[0].attribution,
        robodr_ros2_pipeline::SampleAttribution::Bound
    );
    let bad = to_low_server().with_src_mac(Some([0x02, 0, 0, 0, 0, 0x66]));
    let o = p.process_legacy_at(&high, OPERATOR, &bad, t0, 2);
    assert_eq!(
        rules_of(&o),
        [(
            rules::LEGACY_SENDER_MAC_MISMATCH.to_string(),
            Severity::High
        )]
    );
    assert!(o.findings[0].deviation.detail.contains("02:00:00:00:00:66"));
    assert_ne!(
        o.motion[0].attribution,
        robodr_ros2_pipeline::SampleAttribution::Bound
    );
    let unknown = to_low_server();
    let o = p.process_legacy_at(&high, OPERATOR, &unknown, t0, 3);
    assert!(rules_of(&o).is_empty(), "{:?}", rules_of(&o));
    assert_eq!(p.stats().legacy.mac_unverified, 1);
    let frag = to_low_server().with_reassembled(true);
    let o = p.process_legacy_at(&high, OPERATOR, &frag, t0, 4);
    assert_eq!(
        rules_of(&o),
        [(
            rules::LEGACY_SENDER_MAC_MISMATCH.to_string(),
            Severity::High
        )]
    );
}

/// H2: a datagram on a configured legacy port whose payload starts with
/// `RTPS` is inspected by the legacy path too (sender check), and by the
/// RTPS path, plus a High "RTPS on a legacy port" finding: end to end from
/// a pcap through the capture source.
#[test]
fn rtps_on_a_legacy_port_is_inspected_on_both_paths() {
    use robodr_capture::{CaptureFile, RtpsFilter};
    use robodr_ros2_pipeline::{CaptureDatagramSource, DatagramSource};
    let rogue = std::net::Ipv4Addr::new(192, 168, 123, 66);
    let robot = std::net::Ipv4Addr::new(192, 168, 123, 10);
    let spdp = common::spdp_datagram(common::ROGUE, rogue);
    let bytes = common::pcap(&[common::frame(rogue, robot, 8007, &spdp)]);
    let filter = RtpsFilter::default().with_legacy_udp_ports([8007, 8080, 8082, 8090]);
    let mut src = CaptureDatagramSource::new(CaptureFile::new(&bytes[..]).unwrap(), filter);
    let d = src.recv().unwrap().expect("one datagram");
    let udp = d.legacy.expect("delivered as legacy");
    assert!(udp.also_rtps);
    assert_eq!(udp.src_mac, Some([0x02, 0, 0, 0, 0, 2]));
    let mut p = legacy_pipeline();
    let o = p.process_datagram_with_motion(&d, 1);
    let r = rules_of(&o);
    for want in [
        (rules::LEGACY_PORT_RTPS, Severity::High),
        (rules::LEGACY_UNKNOWN_SENDER, Severity::Medium),
        ("robot.ros2.unknown_participant", Severity::High),
    ] {
        assert!(
            r.iter().any(|(id, sev)| id == want.0 && *sev >= want.1),
            "{want:?} in {r:?}"
        );
    }
    assert_eq!(p.stats().legacy.rtps_on_legacy_port, 1);
    assert_eq!(p.stats().datagrams, 1, "one datagram, counted once");
}

fn announce(p: &mut Pipeline, writer: [u8; 4], type_name: &str) -> Vec<(String, Severity)> {
    use common::*;
    let d = datagram(
        LEGIT,
        &[
            spdp_sub(LEGIT, &[ROBOT_IP]),
            sedp_writer_sub(LEGIT, writer, "rt/cmd_vel", type_name),
        ],
    );
    let o = p.process_with_motion_at(
        &d,
        &ROBOT_IP.to_string(),
        robodr_ros2_pipeline::Ingress::Unknown,
        Instant::now(),
        1,
    );
    rules_of(&o)
}

/// M4: a writer announcing an unknown type name on a profiled command
/// channel cannot be inspected at all: High at announcement (not only a
/// rate-limited Medium per sample).
#[test]
fn unknown_type_on_a_command_channel_is_high() {
    let mut p = Pipeline::new(common::robot_profile(true), PipelineOptions::default());
    let r = announce(
        &mut p,
        [0, 0, 0x20, 0x03],
        "geometry_msgs::msg::dds_::Twist_x",
    );
    assert!(
        r.contains(&(
            rules::MOTION_COMMAND_TYPE_MISMATCH.to_string(),
            Severity::High
        )),
        "{r:?}"
    );
    // A known command type: nothing.
    let r = announce(&mut p, [0, 0, 0x21, 0x03], common::TWIST);
    assert!(r.is_empty(), "{r:?}");
    // A feedback type on a command channel.
    let r = announce(&mut p, [0, 0, 0x22, 0x03], common::ODOM);
    assert!(
        r.contains(&(
            rules::MOTION_COMMAND_TYPE_MISMATCH.to_string(),
            Severity::High
        )),
        "{r:?}"
    );
}

/// M4: the profile records the type name of each command channel; a writer
/// announcing another one (even a decodable command type) is High.
#[test]
fn changed_type_on_a_command_channel_is_high() {
    let mut profile = common::robot_profile(true);
    profile
        .motion_types
        .insert("/cmd_vel".into(), common::TWIST.into());
    profile.validate().unwrap();
    let mut p = Pipeline::new(profile, PipelineOptions::default());
    let r = announce(&mut p, [0, 0, 0x20, 0x03], common::TWIST);
    assert!(r.is_empty(), "{r:?}");
    let r = announce(
        &mut p,
        [0, 0, 0x21, 0x03],
        "geometry_msgs::msg::dds_::TwistStamped_",
    );
    assert_eq!(
        r,
        [(
            rules::MOTION_COMMAND_TYPE_MISMATCH.to_string(),
            Severity::High
        )]
    );
}

/// M2: a decoded (declared-layout) legacy `LowCmd` carries its 20-slot
/// joint frame, so a joint firewall on `/unitree_legacy/low_cmd` actually
/// checks it.
#[test]
fn legacy_low_cmd_carries_its_joint_frame() {
    let mut p = legacy_pipeline();
    let low = vec![0u8; robodr_cdr::unitree_legacy::LEGACY_LOW_CMD_LEN];
    let o = p.process_legacy_at(&low, OPERATOR, &to_low_server(), Instant::now(), 1);
    assert_eq!(o.motion.len(), 1);
    assert_eq!(o.motion[0].topic, channels::LOW_CMD);
    let j = o.motion[0].joint.expect("joint frame");
    assert_eq!(
        j.frame.joints.len(),
        robodr_cdr::unitree_legacy::LEGACY_MOTORS
    );
    assert_eq!(j.crc_ok, None);
}
