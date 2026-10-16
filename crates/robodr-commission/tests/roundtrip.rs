//! Property test: for any *clean* run, learn -> lock -> check over the same
//! events gives exactly zero deviations.
//!
//! "Clean" means: every GUID that owns an endpoint or sends a motion command
//! was announced as a participant; endpoint names are anything `demangle`
//! can classify (topics, services with both suffix variants, parameter
//! services, all action parts, wrong-transport action names, raw DDS names
//! including ROS internals and look-alikes such as `rtfoo` or a raw
//! `/cmd_vel`) as long as they are valid names; speeds are finite and
//! non-negative; motion feedback may carry anything (it is never a profile
//! deviation). Runs are randomly shuffled, split into several runs and fed
//! either to one learner or to separate learners that are then merged.
//!
//! The PRNG is a std-only SplitMix64 with fixed seeds, so failures are
//! reproducible: the failing seed is printed.

use robodr_commission::{
    lock_with_caps, Checker, Commissioning, HardCaps, LearnConfig, Learner, VecSource,
};
use robodr_events::graph::{Endpoint, Participant};
use robodr_events::profile::Profile;
use robodr_events::{MotionCommand, MotionFeedback, RobotEvent};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn chance(&mut self, num: u64, den: u64) -> bool {
        self.next() % den < num
    }
    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len())]
    }
}

const SEGMENTS: &[&str] = &[
    "cmd_vel",
    "odom",
    "scan",
    "nav",
    "dock",
    "a",
    "b_2",
    "robot1",
    "mast",
    "tf",
    "camera",
    "image_raw",
    "Request",
    "Reply",
    "_action",
];
const RAW: &[&str] = &[
    "ros_discovery_info",
    "vendor_diag",
    "rtfoo",
    "/cmd_vel",
    "cmd_vel",
    "rq/add_two_ints",
    "rq/Request",
    "rr/addRequest",
    "rs/foo",
    "RT/cmd_vel",
    "rt",
    "rt/",
    "DCPSx",
    "raw with space",
];
const PARAMS: &[&str] = &[
    "describe_parameters",
    "get_parameter_types",
    "get_parameters",
    "list_parameters",
    "set_parameters",
    "set_parameters_atomically",
];

fn path(r: &mut Rng) -> String {
    let n = 1 + r.below(3);
    (0..n).map(|_| format!("/{}", r.pick(SEGMENTS))).collect()
}

fn guid(r: &mut Rng) -> String {
    format!(
        "{:024x}",
        (u128::from(r.next()) << 32) | u128::from(r.next() as u32)
    )
}

/// A DDS topic name of a random kind.
fn dds_name(r: &mut Rng) -> String {
    let p = path(r);
    match r.below(12) {
        0..=2 => format!("rt{p}"),
        3 => format!("rq{p}{}", r.pick(&["Request", "Request_"])),
        4 => format!("rr{p}{}", r.pick(&["Reply", "Reply_"])),
        5 => {
            let c = r.pick(&["send_goal", "cancel_goal", "get_result"]);
            if r.chance(1, 2) {
                format!("rq{p}/_action/{c}Request")
            } else {
                format!("rr{p}/_action/{c}Reply")
            }
        }
        6 => format!("rt{p}/_action/{}", r.pick(&["feedback", "status"])),
        // Wrong transport for the component: plain topic / service.
        7 => format!("rt{p}/_action/{}", r.pick(&["send_goal", "bogus"])),
        8 => format!("rq{p}/_action/feedbackRequest"),
        9 => format!("rr{p}/{}Reply", r.pick(PARAMS)),
        10 => r
            .pick(&["rt/rosout", "rt/parameter_events", "rt/tf"])
            .to_string(),
        _ => r.pick(RAW).to_string(),
    }
}

fn speed(r: &mut Rng) -> Option<f64> {
    match r.below(10) {
        0 => None,
        1 => Some(0.0),
        2 => Some(f64::MIN_POSITIVE * r.unit()), // subnormal or zero
        3 => Some(1e9 * (0.5 + r.unit())),       // around the quantisation cut-off
        4 if r.chance(1, 4) => Some(f64::MAX),
        _ => Some(3.0 * r.unit()),
    }
}

fn clean_run(r: &mut Rng) -> Vec<RobotEvent> {
    let guids: Vec<String> = (0..1 + r.below(6)).map(|_| guid(r)).collect();
    let mut evs = Vec::new();
    for g in &guids {
        for _ in 0..1 + r.below(3) {
            evs.push(RobotEvent::Ros2ParticipantDiscovered(Participant {
                guid_prefix: g.clone(),
                src_ip: format!("10.0.0.{}", r.below(250)),
                locators: vec![],
            }));
        }
    }
    // Every ROS node has /rosout and its parameter services.
    evs.push(RobotEvent::Ros2WriterDiscovered(Endpoint {
        guid_prefix: guids[0].clone(),
        topic: "rt/rosout".into(),
        type_name: "rcl_interfaces::msg::dds_::Log_".into(),
    }));
    for _ in 0..r.below(40) {
        let ep = Endpoint {
            guid_prefix: r.pick(&guids).clone(),
            topic: dds_name(r),
            type_name: if r.chance(1, 3) {
                String::new()
            } else {
                "pkg::msg::dds_::T_".into()
            },
        };
        evs.push(if r.chance(1, 2) {
            RobotEvent::Ros2WriterDiscovered(ep)
        } else {
            RobotEvent::Ros2ReaderDiscovered(ep)
        });
    }
    let channels: Vec<String> = (0..r.below(4)).map(|_| path(r)).collect();
    for ch in &channels {
        // A clean run discovers the writer of every channel it commands
        // (`Profile::validate` requires enveloped channels to be writable).
        evs.push(RobotEvent::Ros2WriterDiscovered(Endpoint {
            guid_prefix: r.pick(&guids).clone(),
            topic: format!("rt{ch}"),
            type_name: "geometry_msgs::msg::dds_::Twist_".into(),
        }));
        for _ in 0..1 + r.below(30) {
            let (mut lin, joint) = (speed(r), speed(r));
            if lin.is_none() && joint.is_none() {
                lin = Some(0.25);
            }
            evs.push(RobotEvent::MotionCommand(MotionCommand {
                channel: ch.clone(),
                source_guid: r.chance(2, 3).then(|| r.pick(&guids).clone()),
                linear_speed: lin,
                joint_speed: joint,
                angular_speed: None,
                ..Default::default()
            }));
        }
    }
    for _ in 0..r.below(5) {
        evs.push(RobotEvent::MotionFeedback(MotionFeedback {
            channel: path(r),
            measured_linear_speed: Some(*r.pick(&[f64::NAN, -1.0, f64::INFINITY, 0.3])),
            measured_joint_speed: None,
            linear_velocity: None,
            angular_velocity: None,
            publisher_guid: None,
            timestamp_ns: r.next(),
            ..Default::default()
        }));
    }
    // Shuffle (Fisher-Yates).
    for i in (1..evs.len()).rev() {
        let j = r.below(i + 1);
        evs.swap(i, j);
    }
    evs
}

fn max_speed(evs: &[RobotEvent], linear: bool) -> f64 {
    evs.iter()
        .filter_map(|e| match e {
            RobotEvent::MotionCommand(c) => {
                if linear {
                    c.linear_speed
                } else {
                    c.joint_speed
                }
            }
            _ => None,
        })
        .fold(0.0, f64::max)
}

fn ceiling(r: &mut Rng, max: f64) -> Option<f64> {
    if !r.chance(1, 3) {
        return None;
    }
    let c = if max > 0.0 {
        max * (1.0 + r.unit())
    } else {
        1.0
    };
    Some(if c.is_finite() { c } else { f64::MAX })
}

fn learn(cfg: &LearnConfig, runs: &[Vec<RobotEvent>], merged: bool) -> Commissioning {
    if merged {
        let mut acc: Option<Learner> = None;
        for (i, run) in runs.iter().enumerate() {
            let mut l = Learner::new(cfg.clone()).unwrap();
            l.ingest(&mut VecSource::new(format!("run{i}"), run.clone()))
                .unwrap();
            match &mut acc {
                Some(a) => a.merge(&l),
                None => acc = Some(l),
            }
        }
        acc.unwrap().finish()
    } else {
        let mut l = Learner::new(cfg.clone()).unwrap();
        for (i, run) in runs.iter().enumerate() {
            l.ingest(&mut VecSource::new(format!("run{i}"), run.clone()))
                .unwrap();
        }
        l.finish()
    }
}

#[test]
fn learn_lock_check_over_clean_runs_gives_zero_deviations() {
    let mut cases = 0;
    for seed in 0..400u64 {
        let mut r = Rng(seed.wrapping_mul(0x2545_f491_4f6c_dd1d) ^ 0x5eed);
        let evs = clean_run(&mut r);
        // The anti-poisoning gate is opened fully here (every announced
        // participant accepted, no hard cap below f64::MAX): this property
        // is about routing and envelope math. The default gate is covered
        // by `default_gate_only_ever_tightens` below.
        let cfg = LearnConfig {
            model: "prop-model".into(),
            margin: 1.0 + 2.0 * r.unit(),
            ceiling_linear: ceiling(&mut r, max_speed(&evs, true)),
            ceiling_joint: ceiling(&mut r, max_speed(&evs, false)),
            hard_cap_linear: f64::MAX,
            hard_cap_joint: f64::MAX,
            min_samples: 30,
            learn_readers: r.chance(1, 2),
            min_participant_announcements: 1,
            min_participant_duration: std::time::Duration::ZERO,
            ..Default::default()
        };
        // Split into 1..=3 runs.
        let n_runs = 1 + r.below(3);
        let mut runs: Vec<Vec<RobotEvent>> = vec![Vec::new(); n_runs];
        for e in &evs {
            runs[r.below(n_runs)].push(e.clone());
        }
        let merged = r.chance(1, 2);
        let c = learn(&cfg, &runs, merged);
        let profile = c.profile;

        assert_eq!(profile.validate(), Ok(()), "seed {seed}");
        let signoff = c.signoff.confirm_all("prop-test");
        // Lock with the caps the run was learned with (lock enforces them).
        let caps = HardCaps {
            linear: cfg.hard_cap_linear,
            joint: cfg.hard_cap_joint,
        };
        let locked = lock_with_caps(&profile, &signoff, &caps)
            .unwrap_or_else(|why| panic!("seed {seed}: {why:?}"));
        // Through JSON, exactly as the CLI hands it to `check`.
        let json = serde_json::to_string(&locked).unwrap();
        let locked: Profile = serde_json::from_str(&json).unwrap();
        assert_eq!(
            locked.reader_topics.is_empty(),
            !cfg.learn_readers
                || !evs.iter().any(|e| matches!(e,
                    RobotEvent::Ros2ReaderDiscovered(ep)
                        if ep.ros_name().kind == robodr_events::graph::RosNameKind::Topic)),
            "seed {seed}"
        );

        let mut checker = Checker::new(&locked);
        for (i, run) in runs.iter().enumerate() {
            checker
                .ingest(&mut VecSource::new(format!("run{i}"), run.clone()))
                .unwrap();
        }
        let report = checker.finish();
        assert_eq!(
            report.deviations_total, 0,
            "seed {seed} (learn_readers {}, merged {merged}): {report}\nprofile {json}",
            cfg.learn_readers
        );
        assert_eq!(report.events as usize, evs.len());

        // Negative control: the checker is not vacuous. An unseen service
        // writer from a known participant always deviates.
        let g = locked.participants.iter().next().unwrap().clone();
        let mut c = Checker::new(&locked);
        c.observe(
            "probe",
            1,
            &RobotEvent::Ros2WriterDiscovered(Endpoint {
                guid_prefix: g,
                topic: "rq/never/seen_in_any_runRequest".into(),
                type_name: String::new(),
            }),
        );
        assert_eq!(c.finish().by_rule["robot.ros2.unknown_service"], 1);
        cases += 1;
    }
    assert_eq!(cases, 400);
}

/// With the default anti-poisoning gate and hard caps, the learned profile
/// is always a subset of the permissive one (the gate only ever removes
/// entries and tightens envelopes), every bound is within the hard cap, and
/// the result validates.
#[test]
fn default_gate_only_ever_tightens() {
    for seed in 0..300u64 {
        let mut r = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0xfeed);
        let evs = clean_run(&mut r);
        let permissive = LearnConfig {
            model: "m".into(),
            hard_cap_linear: f64::MAX,
            hard_cap_joint: f64::MAX,
            min_participant_announcements: 1,
            min_participant_duration: std::time::Duration::ZERO,
            ..Default::default()
        };
        let strict = LearnConfig {
            model: "m".into(),
            ..Default::default()
        };
        let runs = vec![evs];
        let a = learn(&permissive, &runs, false).profile;
        let b = learn(&strict, &runs, false).profile;
        assert_eq!(b.validate(), Ok(()), "seed {seed}");
        assert!(b.participants.is_subset(&a.participants), "seed {seed}");
        assert!(b.writer_topics.is_subset(&a.writer_topics), "seed {seed}");
        assert!(b.services.is_subset(&a.services), "seed {seed}");
        assert!(b.actions.is_subset(&a.actions), "seed {seed}");
        assert!(b.raw_dds_topics.is_subset(&a.raw_dds_topics), "seed {seed}");
        for (ch, env) in &b.motion_envelopes {
            let pa = &a.motion_envelopes[ch];
            for (x, y, cap) in [
                (
                    env.max_linear_speed,
                    pa.max_linear_speed,
                    strict.hard_cap_linear,
                ),
                (
                    env.max_joint_speed,
                    pa.max_joint_speed,
                    strict.hard_cap_joint,
                ),
            ] {
                if let Some(x) = x {
                    assert!(x <= cap, "seed {seed}: {x} > {cap}");
                    assert!(x <= y.unwrap(), "seed {seed}");
                }
            }
        }
    }
}
