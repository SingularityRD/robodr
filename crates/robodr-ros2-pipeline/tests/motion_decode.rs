//! The live motion decode path, end to end through `Pipeline`: synthetic
//! RTPS datagrams carrying CDR motion payloads (hand-built from the specs;
//! no capture of a real RMW) -> `MotionCommand` / `MotionFeedback` samples
//! and findings.

mod common;

#[path = "../../robodr-cdr/tests/common/mod.rs"]
mod cdrenc;

use std::time::{Duration, Instant};

use common::*;
use robodr_events::{RobotEvent, Severity};
use robodr_ros2_pipeline::{
    rules, Ingress, MotionOptions, Pipeline, PipelineOptions, ProcessOutput,
};

const LEGIT_CMD_GUID: &str = "aaaaaaaaaaaaaaaaaaaaaaaa00001003";

fn pipeline_with(motion: MotionOptions) -> Pipeline {
    Pipeline::new(
        robot_profile(true),
        PipelineOptions {
            motion,
            ..Default::default()
        },
    )
}

fn pipeline() -> Pipeline {
    pipeline_with(MotionOptions {
        feedback_topics: ["/odom".to_string()].into(),
        ..Default::default()
    })
}

struct Run {
    p: Pipeline,
    t0: Instant,
    n: u64,
}

impl Run {
    fn new(p: Pipeline) -> Self {
        Self {
            p,
            t0: Instant::now(),
            n: 0,
        }
    }

    /// Process at a deterministic time; capture_ns = 1e9 + 1e6 * n.
    fn feed(&mut self, d: &[u8], ip: &str) -> ProcessOutput {
        self.n += 1;
        let now = self.t0 + Duration::from_millis(self.n);
        self.p.process_with_motion_at(
            d,
            ip,
            Ingress::Unknown,
            now,
            1_000_000_000 + self.n * 1_000_000,
        )
    }
}

fn robot_ip() -> String {
    ROBOT_IP.to_string()
}

fn rules_of(o: &ProcessOutput) -> Vec<String> {
    o.findings
        .iter()
        .map(|f| f.deviation.rule.to_string())
        .collect()
}

/// Discovery of the legit graph raises nothing.
fn started() -> Run {
    let mut r = Run::new(pipeline());
    let o = r.feed(&motion_discovery(), &robot_ip());
    assert!(o.findings.is_empty(), "{:?}", rules_of(&o));
    assert!(o.motion.is_empty());
    r
}

#[test]
fn profiled_writer_within_envelope_yields_a_command_and_no_finding() {
    let mut r = started();
    let o = r.feed(&cmd_vel_datagram(LEGIT, CMD_WRITER, 1, 0.5), &robot_ip());
    assert!(o.findings.is_empty(), "{:?}", rules_of(&o));
    assert_eq!(o.motion.len(), 1);
    let s = &o.motion[0];
    match &s.event {
        RobotEvent::MotionCommand(c) => {
            assert_eq!(c.channel, "/cmd_vel");
            assert_eq!(c.linear_speed, Some(0.5));
            assert_eq!(c.angular_speed, Some(0.1));
            assert_eq!(c.source_guid.as_deref(), Some(LEGIT_CMD_GUID));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(s.writer_guid, LEGIT_CMD_GUID);
    assert_eq!(s.topic, "rt/cmd_vel");
    assert_eq!(s.type_name, TWIST);
    assert_eq!(s.sequence_number, 1);
    assert_eq!(s.capture_ns, 1_002_000_000);
    assert_eq!(s.src_ip, robot_ip());
    assert!(!s.from_fragments);
    let st = r.p.stats().motion;
    assert_eq!((st.commands, st.samples, st.undecodable), (1, 1, 0));
    assert_eq!(st.writers_known, 2);
    assert_eq!(st.readers_known, 1);
}

#[test]
fn over_envelope_command_is_a_critical_finding() {
    let mut r = started();
    let o = r.feed(&cmd_vel_datagram(LEGIT, CMD_WRITER, 2, -2.5), &robot_ip());
    assert_eq!(rules_of(&o), vec!["robot.motion.linear_over_envelope"]);
    assert_eq!(o.findings[0].deviation.severity, Severity::Critical);
    assert!(o.findings[0].deviation.detail.contains("/cmd_vel"));
    assert_eq!(o.findings[0].src_ip, robot_ip());
    assert_eq!(o.motion.len(), 1, "the sample is still handed on");
    // NaN is Critical too (never "not greater than the limit").
    let o = r.feed(
        &cmd_vel_datagram(LEGIT, CMD_WRITER, 3, f64::NAN),
        &robot_ip(),
    );
    assert_eq!(rules_of(&o), vec!["robot.motion.non_finite_command"]);
}

#[test]
fn evaluation_can_be_left_to_the_consumer() {
    let mut r = Run::new(pipeline_with(MotionOptions {
        evaluate_commands: false,
        ..Default::default()
    }));
    r.feed(&motion_discovery(), &robot_ip());
    let o = r.feed(&cmd_vel_datagram(LEGIT, CMD_WRITER, 2, 9.0), &robot_ip());
    assert!(o.findings.is_empty(), "{:?}", rules_of(&o));
    assert_eq!(o.motion.len(), 1);
}

#[test]
fn unprofiled_writer_is_critical_and_its_commands_are_still_decoded() {
    let mut r = started();
    let rogue_ip = ROGUE_IP.to_string();
    let d = datagram(
        ROGUE,
        &[
            spdp_sub(ROGUE, &[ROGUE_IP]),
            sedp_writer_sub(ROGUE, ROGUE_ENTITY, "rt/cmd_vel", TWIST),
        ],
    );
    let o = r.feed(&d, &rogue_ip);
    let got = rules_of(&o);
    assert!(
        got.contains(&"robot.ros2.unauthorized_motion_writer".to_string()),
        "{got:?}"
    );
    assert!(o.findings.iter().any(
        |f| f.deviation.rule == "robot.ros2.unauthorized_motion_writer"
            && f.deviation.severity == Severity::Critical
    ));
    // Its (in-envelope) command: decoded, attributed to the rogue writer.
    let o = r.feed(&cmd_vel_datagram(ROGUE, ROGUE_ENTITY, 1, 0.3), &rogue_ip);
    assert!(o.findings.is_empty(), "{:?}", rules_of(&o));
    match &o.motion[0].event {
        RobotEvent::MotionCommand(c) => {
            assert_eq!(
                c.source_guid.as_deref(),
                Some("eeeeeeeeeeeeeeeeeeeeeeee00007703")
            )
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn data_frag_split_payload_is_reassembled_and_decoded() {
    let mut r = started();
    let payload = twist_cdr(4.0, 0.0, true); // 52 bytes, 3 fragments
    let mut all = Vec::new();
    for (i, c) in payload.chunks(20).enumerate() {
        let d = datagram(
            LEGIT,
            &[user_data_frag(CMD_WRITER, 5, i as u32 + 1, 20, 52, c)],
        );
        all.push(r.feed(&d, &robot_ip()));
    }
    assert!(all[0].motion.is_empty() && all[1].motion.is_empty());
    let last = &all[2];
    assert_eq!(last.motion.len(), 1);
    assert!(last.motion[0].from_fragments);
    assert_eq!(rules_of(last), vec!["robot.motion.linear_over_envelope"]);
    // A fragmented sample over the reassembler's cap is not inspected, and
    // that is reported.
    let d = datagram(
        LEGIT,
        &[user_data_frag(
            CMD_WRITER, 6, 1, 1000, 1_000_000, &[0; 1000],
        )],
    );
    let o = r.feed(&d, &robot_ip());
    assert_eq!(rules_of(&o), vec![rules::MOTION_UNDECODABLE_SAMPLE]);
    assert!(o.findings[0].deviation.detail.contains("refused"));
}

#[test]
fn big_endian_submessage_and_payload_decode() {
    let mut r = started();
    let d = datagram(
        LEGIT,
        &[user_data(
            CMD_WRITER,
            CMD_READER,
            9,
            &twist_cdr(0.75, -0.2, false),
            false,
        )],
    );
    let o = r.feed(&d, &robot_ip());
    assert!(o.findings.is_empty(), "{:?}", rules_of(&o));
    match &o.motion[0].event {
        RobotEvent::MotionCommand(c) => {
            assert_eq!(c.linear_speed, Some(0.75));
            assert_eq!(c.angular_speed, Some(-0.2));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn info_ts_is_exposed_but_never_used_as_the_event_time() {
    let mut r = started();
    let d = datagram(
        LEGIT,
        &[
            info_ts(1_760_000_000, 0x4000_0000),
            user_data(CMD_WRITER, CMD_READER, 1, &twist_cdr(0.2, 0.0, true), true),
        ],
    );
    let o = r.feed(&d, &robot_ip());
    let s = &o.motion[0];
    let ts = s.source_timestamp.expect("INFO_TS");
    assert_eq!(ts.seconds, 1_760_000_000);
    assert_eq!(ts.to_unix_ns(), Some(1_760_000_000_250_000_000));
    // The feedback path stamps the capture time, not the claim.
    let odom = cdrenc::odometry(
        robodr_cdr::Representation::CdrLe,
        &cdrenc::OdomSpec {
            frame: b"odom",
            child: b"base_link",
            position: [0.0; 3],
            orientation: [0.0, 0.0, 0.0, 1.0],
            pose_cov: [0.0; 36],
            lin: [0.4, 0.0, 0.0],
            ang: [0.0, 0.0, 0.05],
            twist_cov: [0.0; 36],
        },
    );
    let d = datagram(
        LEGIT,
        &[
            info_ts(5, 0),
            user_data(ODOM_WRITER, [0; 4], 1, &odom, true),
        ],
    );
    let o = r.feed(&d, &robot_ip());
    assert!(o.findings.is_empty(), "{:?}", rules_of(&o));
    match &o.motion[0].event {
        RobotEvent::MotionFeedback(f) => {
            assert_eq!(f.channel, "/odom");
            assert_eq!(f.linear_velocity, Some(0.4));
            assert_eq!(f.angular_velocity, Some(0.05));
            assert_eq!(f.timestamp_ns, o.motion[0].capture_ns);
            assert_eq!(
                f.publisher_guid.as_deref(),
                Some("aaaaaaaaaaaaaaaaaaaaaaaa00001103")
            );
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(o.motion[0].source_timestamp.map(|t| t.seconds), Some(5));
}

#[test]
fn fragmented_odometry_feedback_is_reassembled() {
    let mut r = started();
    let odom = cdrenc::odometry(
        robodr_cdr::Representation::CdrLe,
        &cdrenc::OdomSpec {
            frame: b"odom",
            child: b"base_link",
            position: [1.0; 3],
            orientation: [0.0, 0.0, 0.0, 1.0],
            pose_cov: [0.01; 36],
            lin: [-0.3, 0.0, 0.0],
            ang: [0.0, 0.0, 0.0],
            twist_cov: [0.01; 36],
        },
    );
    assert!(odom.len() > 600);
    let mut samples = Vec::new();
    for (i, c) in odom.chunks(256).enumerate() {
        let d = datagram(
            LEGIT,
            &[user_data_frag(
                ODOM_WRITER,
                3,
                i as u32 + 1,
                256,
                odom.len() as u32,
                c,
            )],
        );
        samples.extend(r.feed(&d, &robot_ip()).motion);
    }
    assert_eq!(samples.len(), 1);
    assert!(matches!(&samples[0].event,
        RobotEvent::MotionFeedback(f) if f.linear_velocity == Some(-0.3)));
}

#[test]
fn feedback_topics_must_be_configured() {
    let mut r = Run::new(pipeline_with(MotionOptions::default()));
    r.feed(&motion_discovery(), &robot_ip());
    let odom = cdrenc::odometry(
        robodr_cdr::Representation::CdrLe,
        &cdrenc::OdomSpec {
            frame: b"",
            child: b"",
            position: [0.0; 3],
            orientation: [0.0; 4],
            pose_cov: [0.0; 36],
            lin: [0.0; 3],
            ang: [0.0; 3],
            twist_cov: [0.0; 36],
        },
    );
    let d = datagram(LEGIT, &[user_data(ODOM_WRITER, [0; 4], 1, &odom, true)]);
    let o = r.feed(&d, &robot_ip());
    assert!(o.motion.is_empty() && o.findings.is_empty());
}

#[test]
fn garbage_payloads_are_undecodable_findings_rate_limited() {
    let mut r = started();
    let garbage: Vec<Vec<u8>> = vec![
        vec![],                             // no encapsulation
        vec![0x00, 0x01, 0, 0, 1, 2, 3],    // truncated Twist
        vec![0x00, 0x03, 0, 0, 1, 0, 0, 0], // PL_CDR_LE
        vec![0x12, 0x34, 0, 0],             // unknown encapsulation
    ];
    let mut details = Vec::new();
    for (i, g) in garbage.iter().enumerate() {
        let d = datagram(
            LEGIT,
            &[user_data(CMD_WRITER, CMD_READER, 10 + i as u32, g, true)],
        );
        let o = r.feed(&d, &robot_ip());
        assert!(o.motion.is_empty());
        assert_eq!(rules_of(&o), vec![rules::MOTION_UNDECODABLE_SAMPLE], "{i}");
        assert_eq!(o.findings[0].deviation.severity, Severity::Medium);
        details.push(o.findings[0].deviation.detail.clone());
    }
    assert!(details[1].contains("truncated"), "{details:?}");
    assert!(details[2].contains("PlCdrLe") || details[2].contains("unsupported"));
    // The same bad sample again: deduplicated.
    let d = datagram(
        LEGIT,
        &[user_data(CMD_WRITER, CMD_READER, 20, &garbage[1], true)],
    );
    assert!(r.feed(&d, &robot_ip()).findings.is_empty());
    assert_eq!(r.p.stats().motion.undecodable, 5);
    // A flood of distinct bad samples is rate limited (default burst 20).
    let mut reported = 0;
    for i in 0..200u32 {
        // Distinct findings need distinct writers: vary the writer entity.
        let w = [0, 1, (i % 250) as u8, 0x03];
        let d = datagram(
            LEGIT,
            &[
                sedp_writer_sub(LEGIT, w, "rt/cmd_vel", TWIST),
                user_data(w, CMD_READER, 1, &[0x00, 0x01, 0, 0], true),
            ],
        );
        reported += r
            .feed(&d, &robot_ip())
            .findings
            .iter()
            .filter(|f| f.deviation.rule == rules::MOTION_UNDECODABLE_SAMPLE)
            .count();
    }
    assert!(reported <= 20, "{reported}");
    assert!(r.p.stats().rate_limited > 0);
}

#[test]
fn unknown_and_wrong_role_types_are_undecodable() {
    let mut r = started();
    let w1 = [0, 0, 0x30, 0x03];
    let w2 = [0, 0, 0x31, 0x03];
    let d = datagram(
        LEGIT,
        &[
            sedp_writer_sub(LEGIT, w1, "rt/cmd_vel", "my_msgs::msg::dds_::Drive_"),
            sedp_writer_sub(LEGIT, w2, "rt/cmd_vel", ODOM),
            user_data(w1, CMD_READER, 1, &twist_cdr(0.1, 0.0, true), true),
        ],
    );
    let o = r.feed(&d, &robot_ip());
    assert_eq!(rules_of(&o), vec![rules::MOTION_UNDECODABLE_SAMPLE]);
    assert!(o.findings[0].deviation.detail.contains("no decoder"));
    let odom = cdrenc::odometry(
        robodr_cdr::Representation::CdrLe,
        &cdrenc::OdomSpec {
            frame: b"",
            child: b"",
            position: [0.0; 3],
            orientation: [0.0; 4],
            pose_cov: [0.0; 36],
            lin: [0.0; 3],
            ang: [0.0; 3],
            twist_cov: [0.0; 36],
        },
    );
    let d = datagram(LEGIT, &[user_data(w2, CMD_READER, 1, &odom, true)]);
    let o = r.feed(&d, &robot_ip());
    assert_eq!(rules_of(&o), vec![rules::MOTION_UNDECODABLE_SAMPLE]);
    assert!(o.findings[0]
        .deviation
        .detail
        .contains("not a command type"));
    assert!(o.motion.is_empty());
}

#[test]
fn data_from_a_never_announced_writer_to_a_motion_reader_is_high() {
    let mut r = started();
    let ghost = [0, 0, 0x66, 0x03];
    let d = cmd_vel_datagram(ROGUE, ghost, 1, 0.2);
    let o = r.feed(&d, &ROGUE_IP.to_string());
    assert!(o.motion.is_empty(), "not attributable, not decoded");
    let f: Vec<_> = o
        .findings
        .iter()
        .filter(|f| f.deviation.rule == rules::MOTION_UNATTRIBUTED_SAMPLE)
        .collect();
    assert_eq!(f.len(), 1, "{:?}", rules_of(&o));
    assert_eq!(f[0].deviation.severity, Severity::High);
    assert!(f[0].deviation.detail.contains("rt/cmd_vel"));
    assert!(f[0]
        .deviation
        .detail
        .contains("eeeeeeeeeeeeeeeeeeeeeeee00006603"));
    // Unattributed DATA to a non-motion reader: nothing.
    let d = datagram(
        ROGUE,
        &[user_data(ghost, [0, 0, 0x55, 0x04], 2, &[0; 8], true)],
    );
    let o = r.feed(&d, &ROGUE_IP.to_string());
    assert!(!rules_of(&o).contains(&rules::MOTION_UNATTRIBUTED_SAMPLE.to_string()));
    // Fragments of an unattributed sample are reported, never buffered.
    let d = datagram(
        ROGUE,
        &[user_data_frag(
            [0, 0, 0x67, 0x03],
            1,
            1,
            100,
            10_000,
            &[0; 100],
        )],
    );
    let o = r.feed(&d, &ROGUE_IP.to_string());
    assert!(rules_of(&o).contains(&rules::MOTION_UNATTRIBUTED_SAMPLE.to_string()));
}

#[test]
fn spoofed_writer_from_an_unbound_ip_is_critical() {
    let mut r = started();
    // The legit participant's prefix and writer, but from the rogue host.
    let o = r.feed(
        &cmd_vel_datagram(LEGIT, CMD_WRITER, 7, 0.2),
        &ROGUE_IP.to_string(),
    );
    let f: Vec<_> = o
        .findings
        .iter()
        .filter(|f| f.deviation.rule == rules::MOTION_SAMPLE_SOURCE_MISMATCH)
        .collect();
    assert_eq!(f.len(), 1, "{:?}", rules_of(&o));
    assert_eq!(f[0].deviation.severity, Severity::Critical);
    assert_eq!(o.motion.len(), 1, "still decoded and handed on");
}

#[test]
fn motion_decode_can_be_disabled() {
    let mut r = Run::new(pipeline_with(MotionOptions {
        enabled: false,
        ..Default::default()
    }));
    r.feed(&motion_discovery(), &robot_ip());
    let o = r.feed(&cmd_vel_datagram(LEGIT, CMD_WRITER, 1, 9.0), &robot_ip());
    assert!(o.motion.is_empty() && o.findings.is_empty());
}

#[test]
fn plain_process_reports_motion_findings_too() {
    let mut p = pipeline();
    assert!(p.process(&motion_discovery(), &robot_ip()).is_empty());
    let f = p.process(&cmd_vel_datagram(LEGIT, CMD_WRITER, 1, 3.0), &robot_ip());
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].deviation.rule, "robot.motion.linear_over_envelope");
}

#[test]
fn hostile_motion_traffic_never_panics_and_stays_bounded() {
    let mut r = Run::new(pipeline_with(MotionOptions {
        feedback_topics: ["/odom".to_string()].into(),
        max_writers: 32,
        max_readers: 32,
        ..Default::default()
    }));
    r.feed(&motion_discovery(), &robot_ip());
    let good = datagram(
        LEGIT,
        &[
            info_ts(1, 2),
            user_data(CMD_WRITER, CMD_READER, 1, &twist_cdr(0.1, 0.0, true), true),
            user_data_frag(CMD_WRITER, 2, 1, 20, 52, &twist_cdr(0.1, 0.0, true)[..20]),
        ],
    );
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for i in 0..3000 {
        let mut m = good.clone();
        let n = 1 + (next() % 4) as usize;
        for _ in 0..n {
            let at = 20 + (next() as usize % (m.len() - 20));
            m[at] = next() as u8;
        }
        if i % 7 == 0 {
            m.truncate(20 + next() as usize % (m.len() - 20));
        }
        let _ = r.feed(&m, &robot_ip());
    }
    // A spray of announced writers keeps the tables bounded.
    for i in 0..500u32 {
        let mut prefix = [0x33; 12];
        prefix[8..].copy_from_slice(&i.to_be_bytes());
        let d = datagram(
            prefix,
            &[sedp_writer_sub(prefix, CMD_WRITER, "rt/chatter", TWIST)],
        );
        let _ = r.feed(&d, &robot_ip());
    }
    let st = r.p.stats().motion;
    assert!(st.writers_known <= 32 && st.readers_known <= 32, "{st:?}");
    assert!(st.writers_evicted > 0);
    // The profiled motion writer survived the spray (non-motion entries are
    // evicted first).
    let o = r.feed(&cmd_vel_datagram(LEGIT, CMD_WRITER, 99, 0.1), &robot_ip());
    assert_eq!(o.motion.len(), 1);
}
