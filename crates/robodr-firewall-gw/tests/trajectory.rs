//! ROS 2 `JointTrajectory` / `FollowJointTrajectory` goal channels
//! (`crate::trajectory`, README "Joint trajectories"): strict decode on the
//! real Jazzy captures of both RMWs, the adversarial cases (oversized,
//! NaN / Inf, time-reversed, joint-name confusion, multi-DOF, tolerances,
//! non-canonical CDR, DATA_FRAG, foreign writers, replays), time scaling,
//! `restrict_motion`, the gateway findings, and a randomized comparison
//! against an independent reference (the `robodr-cdr` decoder and a limit
//! check written here).

use std::time::Instant;

use robodr_capture::{rtps_datagrams, CaptureFile, RtpsPortMap};
use robodr_firewall_gw::findings::rules;
use robodr_firewall_gw::ip::parse_ipv4_udp;
use robodr_firewall_gw::restrict::Restriction;
use robodr_firewall_gw::rtps::{self, build::Datagram, Content, WalkOptions};
use robodr_firewall_gw::testkit::*;
use robodr_firewall_gw::trajectory::{self, encode, GoalHeader, Layout, Point, TrajectoryVerdict};
use robodr_firewall_gw::{Gateway, PacketMeta, Verdict};

const MS: u64 = 1_000_000;
const T0: u64 = 1_000_000_000;
const TOPIC: &str = "rt/arm_controller/joint_trajectory";
const GOAL_TOPIC: &str = "rq/arm_controller/follow_joint_trajectory/_action/send_goalRequest";
const TRAJ_TYPE: &str = "trajectory_msgs::msg::dds_::JointTrajectory_";
const GOAL_TYPE: &str = "control_msgs::action::dds_::FollowJointTrajectory_SendGoal_Request_";

fn meta(now: u64) -> PacketMeta {
    PacketMeta {
        now_ns: now,
        queue_delay_ns: None,
        instant: Instant::now(),
        src_mac: None,
    }
}

fn run(gw: &mut Gateway, pkt: &[u8], now: u64) -> (Verdict, Vec<u8>) {
    let mut p = pkt.to_vec();
    let v = gw.process(&mut p, meta(now));
    if v != Verdict::AcceptModified {
        assert_eq!(p, pkt, "unmodified verdict {v:?} but bytes changed");
    } else {
        assert_eq!(p.len(), pkt.len(), "rewrite changed the length");
        parse_ipv4_udp(&p).expect("rewritten packet has valid checksums");
    }
    (v, p)
}

/// The payload of the first user DATA (`None`: suppressed to a PAD).
fn out_payload(pkt: &[u8]) -> Option<Vec<u8>> {
    let ip = parse_ipv4_udp(pkt).ok()?;
    let d = &pkt[ip.payload()];
    let mut v = Vec::new();
    rtps::walk(d, WalkOptions::default(), &mut v).ok()?;
    let s = v
        .iter()
        .find(|s| !s.builtin && s.content == Content::Data)?;
    Some(d[s.payload.clone()?].to_vec())
}

fn gw(edit: impl FnOnce(&mut serde_json::Value)) -> Gateway {
    let mut g = trajectory_gateway(edit);
    for (w, topic, ty) in [
        (TRAJ_WRITER, TOPIC, TRAJ_TYPE),
        (GOAL_WRITER, GOAL_TOPIC, GOAL_TYPE),
    ] {
        let p = packet(CONTROLLER_IP, 7410, &sedp_datagram(PREFIX, w, topic, ty));
        assert_eq!(run(&mut g, &p, 1).0, Verdict::Accept);
    }
    g
}

fn time_scaling(v: &mut serde_json::Value) {
    for c in [1, 2] {
        v["channels"][c]["trajectory"]["on_velocity_violation"] = "time_scale".into();
    }
}

fn pkt(entity: [u8; 4], sn: i64, payload: &[u8]) -> Vec<u8> {
    packet(CONTROLLER_IP, DDS_PORT, &data_datagram(entity, sn, payload))
}

/// A smooth 3-joint trajectory: `n` points, `dt` apart, each joint moving
/// at `speed` rad/s.
fn smooth(n: usize, dt: f64, speed: f64) -> Vec<Point> {
    (0..n)
        .map(|i| {
            let t = i as f64 * dt;
            Point {
                velocities: vec![speed, -speed, 0.0],
                ..Point::at(t, &[speed * t, -speed * t, 0.5])
            }
        })
        .collect()
}

fn traj(points: &[Point]) -> Vec<u8> {
    encode(&TRAJ_JOINTS, points, false, None)
}

static NOW: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(T0);

/// One sample through the gateway, 100 ms after the previous one (the
/// gateway clock never goes back, also across tests sharing this counter).
fn decide(g: &mut Gateway, entity: [u8; 4], sn: i64, payload: &[u8]) -> (Verdict, Option<Vec<u8>>) {
    let now = NOW.fetch_add(100 * MS, std::sync::atomic::Ordering::Relaxed);
    let (v, out) = run(g, &pkt(entity, sn, payload), now);
    (v, out_payload(&out))
}

#[test]
fn a_valid_trajectory_and_goal_pass_unchanged() {
    let mut g = gw(|_| {});
    let p = traj(&smooth(10, 0.1, 0.5));
    assert_eq!(
        decide(&mut g, TRAJ_WRITER, 1, &p),
        (Verdict::Accept, Some(p.clone()))
    );
    for big in [false, true] {
        let goal = encode(
            &TRAJ_JOINTS,
            &smooth(5, 0.2, 0.5),
            big,
            Some((GoalHeader::None, [9; 16])),
        );
        let sn = if big { 3 } else { 2 };
        assert_eq!(
            decide(&mut g, GOAL_WRITER, sn, &goal),
            (Verdict::Accept, Some(goal.clone()))
        );
    }
    // An empty trajectory is a stop: passes.
    let stop = traj(&[]);
    assert_eq!(decide(&mut g, TRAJ_WRITER, 2, &stop).1, Some(stop));
    assert_eq!(g.stats.trajectory_refused, 0);
    assert!(g.findings.is_empty());
}

#[test]
fn adversarial_trajectories_are_suppressed_and_reported() {
    let ok = smooth(4, 0.5, 0.5);
    let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
    let with = |f: &dyn Fn(&mut Vec<Point>)| {
        let mut p = ok.clone();
        f(&mut p);
        traj(&p)
    };
    cases.push(("NaN position", with(&|p| p[1].positions[0] = f64::NAN)));
    cases.push((
        "Inf velocity",
        with(&|p| p[2].velocities[1] = f64::INFINITY),
    ));
    cases.push((
        "-Inf effort",
        with(&|p| p[0].effort = vec![0.0, f64::NEG_INFINITY, 0.0]),
    ));
    cases.push(("time reversed", with(&|p| p.swap(1, 2))));
    cases.push(("repeated time", with(&|p| p[2].nanosec = p[1].nanosec)));
    cases.push(("negative time", with(&|p| p[0].sec = -1)));
    cases.push((
        "position out of range",
        with(&|p| p[3].positions[2] = TRAJ_Q + 0.01),
    ));
    cases.push((
        "effort",
        with(&|p| p[1].effort = vec![0.0, TRAJ_EFFORT * 2.0, 0.0]),
    ));
    cases.push((
        "declared velocity",
        with(&|p| p[1].velocities[0] = TRAJ_V * 1.5),
    ));
    cases.push((
        "step hidden by small velocities",
        with(&|p| p[2].positions[0] = 1.9),
    ));
    cases.push((
        "declared acceleration",
        with(&|p| p[1].accelerations = vec![TRAJ_A * 3.0, 0.0, 0.0]),
    ));
    cases.push(("velocity-only point", with(&|p| p[1].positions.clear())));
    cases.push(("short velocities", with(&|p| p[1].velocities.truncate(2))));
    cases.push(("too long", with(&|p| p[3].sec = 25)));
    // Joint-name confusion.
    let names = |n: [&str; 3]| encode(&n, &ok, false, None);
    cases.push((
        "duplicate joint",
        names(["shoulder_pan_joint", "shoulder_pan_joint", "elbow_joint"]),
    ));
    cases.push((
        "case",
        names(["Shoulder_pan_joint", "shoulder_lift_joint", "elbow_joint"]),
    ));
    cases.push((
        "trailing space",
        names(["shoulder_pan_joint ", "shoulder_lift_joint", "elbow_joint"]),
    ));
    cases.push((
        "homoglyph",
        names(["shoulder_pan_jоint", "shoulder_lift_joint", "elbow_joint"]),
    ));
    cases.push((
        "unknown joint",
        names(["wrist_joint", "shoulder_lift_joint", "elbow_joint"]),
    ));
    // Oversized (more points than max_points 64: undecidable before any
    // allocation) and non-canonical encodings.
    cases.push(("65 points", traj(&smooth(65, 0.1, 0.1))));
    let mut x2 = traj(&ok);
    x2[1] = 0x07;
    cases.push(("XCDR2", x2));
    let mut junk = traj(&ok);
    junk.extend_from_slice(&[0, 0, 0, 0]);
    cases.push(("trailing octets", junk));
    let mut big_count = traj(&ok);
    // The points count: after the encapsulation (4), the stamp (8), the
    // empty frame_id (4 + 1, aligned to 16), the names count and names.
    let mut at = 4 + 16 + 4;
    for n in TRAJ_JOINTS {
        at += (4 + n.len() + 1).div_ceil(4) * 4;
    }
    assert_eq!(&big_count[at..at + 4], &4u32.to_le_bytes());
    big_count[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    cases.push(("huge point count", big_count));
    let mut g = gw(|_| {});
    for (i, (what, p)) in cases.iter().enumerate() {
        let (_, out) = decide(&mut g, TRAJ_WRITER, i as i64 + 1, p);
        assert_eq!(out, None, "{what}: forwarded");
    }
    assert_eq!(g.stats.passed, 0, "{:?}", g.stats);
    let devs = g.findings.drain(robodr_events::Mode::Enforce);
    let rejected = devs
        .iter()
        .find(|d| d.deviation.rule == rules::TRAJECTORY_REJECTED)
        .expect("trajectory_rejected finding");
    assert_eq!(rejected.channel.as_deref(), Some("/arm_trajectory"));
    assert!(rejected.count >= 15, "{rejected:?}");
    assert!(devs
        .iter()
        .any(|d| d.deviation.rule == rules::UNDECODABLE_COMMAND));
    assert_eq!(devs.len(), 2, "{devs:?}");
}

#[test]
fn goal_specific_refusals() {
    let ok = smooth(3, 0.5, 0.5);
    let mut g = gw(|_| {});
    let good = encode(&TRAJ_JOINTS, &ok, false, Some((GoalHeader::None, [1; 16])));
    assert!(decide(&mut g, GOAL_WRITER, 1, &good).1.is_some());
    // A non-empty multi-DOF trajectory (one joint name): undecidable.
    let md_names_at = good.len() - 4 * 5 - 4;
    let mut md = good.clone();
    md[md_names_at..md_names_at + 4].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(decide(&mut g, GOAL_WRITER, 2, &md).1, None);
    // A Cyclone request header the channel does not expect: undecidable.
    let cy = encode(
        &TRAJ_JOINTS,
        &ok,
        false,
        Some((GoalHeader::Cyclone, [1; 16])),
    );
    assert_eq!(decide(&mut g, GOAL_WRITER, 3, &cy).1, None);
    // ... and with the channel set for it, it passes.
    let mut g2 = gw(|v| v["channels"][2]["trajectory"]["request_header"] = "cyclone".into());
    assert_eq!(decide(&mut g2, GOAL_WRITER, 1, &cy).1, Some(cy));
    // A plain trajectory on the goal topic is not a goal.
    assert_eq!(decide(&mut g, GOAL_WRITER, 4, &traj(&ok)).1, None);
}

#[test]
fn tolerances_must_name_the_trajectorys_joints() {
    // Build a goal with one path tolerance by hand: the encoder writes
    // empty ones, so splice a JointTolerance in.
    let ok = smooth(3, 0.5, 0.5);
    let base = encode(&TRAJ_JOINTS, &ok, false, Some((GoalHeader::None, [1; 16])));
    let tol = |name: &str, pos: f64| -> Vec<u8> {
        // Tail: path count | goal count | goal_time_tolerance (8).
        let tail = 4 + 4 + 8;
        let mut head = base[..base.len() - tail].to_vec();
        head.extend_from_slice(&1u32.to_le_bytes());
        head.extend_from_slice(&((name.len() + 1) as u32).to_le_bytes());
        head.extend_from_slice(name.as_bytes());
        head.push(0);
        while !(head.len() - 4).is_multiple_of(8) {
            head.push(0);
        }
        for x in [pos, 0.0, 0.0] {
            head.extend_from_slice(&x.to_le_bytes());
        }
        head.extend_from_slice(&0u32.to_le_bytes());
        head.extend_from_slice(&[0; 8]);
        let pad = (4 - (head.len() - 4) % 4) % 4;
        head[3] = pad as u8;
        head.extend(std::iter::repeat_n(0, pad));
        head
    };
    let lim_ok =
        trajectory::decode_strict(&tol("elbow_joint", 0.1), Layout::Goal(GoalHeader::None), 64);
    assert!(lim_ok.is_ok(), "{lim_ok:?}");
    let mut g = gw(|_| {});
    assert!(decide(&mut g, GOAL_WRITER, 1, &tol("elbow_joint", 0.1))
        .1
        .is_some());
    assert_eq!(
        decide(&mut g, GOAL_WRITER, 2, &tol("wrist_joint", 0.1)).1,
        None
    );
    assert_eq!(
        decide(&mut g, GOAL_WRITER, 3, &tol("elbow_joint", f64::NAN)).1,
        None
    );
}

#[test]
fn time_scaling_slows_velocity_violations_down_and_nothing_else() {
    let mut g = gw(time_scaling);
    // 2 rad/s on a 1 rad/s channel: slowed down by ~2.
    let fast = traj(&smooth(5, 0.1, 2.0));
    let (v, out) = decide(&mut g, TRAJ_WRITER, 1, &fast);
    assert_eq!(v, Verdict::AcceptModified, "{:?}", g.stats);
    assert!(out.is_some(), "{:?}", g.stats);
    let out = out.expect("rewritten, forwarded");
    let t = trajectory::decode_strict(&out, Layout::Trajectory, 64).unwrap();
    let before = trajectory::decode_strict(&fast, Layout::Trajectory, 64).unwrap();
    for (a, b) in t.points.iter().zip(&before.points) {
        assert_eq!(a.positions, b.positions, "the path is untouched");
        assert!(a.velocities.iter().all(|v| v.abs() <= TRAJ_V + 1e-9));
    }
    let last = t.points.last().unwrap().time_ns().unwrap();
    assert!((790_000_000..=810_000_001).contains(&last), "{last}");
    assert_eq!(g.stats.trajectory_time_scaled, 1);
    // Beyond max_time_scale (4): refused.
    assert_eq!(
        decide(&mut g, TRAJ_WRITER, 2, &traj(&smooth(5, 0.1, 5.0))).1,
        None
    );
    // A position violation is never time-scaled.
    let mut p = smooth(5, 0.1, 2.0);
    p[4].positions[0] = 3.0;
    assert_eq!(decide(&mut g, TRAJ_WRITER, 3, &traj(&p)).1, None);
    let devs = g.findings.drain(robodr_events::Mode::Enforce);
    assert!(devs
        .iter()
        .any(|d| d.deviation.rule == rules::TRAJECTORY_TIME_SCALED));
    assert!(devs
        .iter()
        .any(|d| d.deviation.rule == rules::TRAJECTORY_REJECTED));
}

#[test]
fn restrict_motion_tightens_the_joint_speed_and_lapses() {
    let mut g = gw(|_| {});
    let p = traj(&smooth(5, 0.1, 0.8));
    assert!(decide(&mut g, TRAJ_WRITER, 1, &p).1.is_some());
    g.set_restriction(Some(Restriction {
        id: "robot_restrict_motion:x:1".into(),
        max_linear_speed: None,
        max_joint_speed: None,
        factor: Some(0.5),
        expires_unix_ms: u64::MAX,
    }));
    assert_eq!(
        decide(&mut g, TRAJ_WRITER, 2, &p).1,
        None,
        "0.8 > 0.5 x 1.0"
    );
    let slow = traj(&smooth(5, 0.1, 0.4));
    assert!(decide(&mut g, TRAJ_WRITER, 3, &slow).1.is_some());
    g.set_restriction(None);
    assert!(decide(&mut g, TRAJ_WRITER, 4, &p).1.is_some());
    let devs = g.findings.drain(robodr_events::Mode::Enforce);
    let changed = devs
        .iter()
        .find(|d| d.deviation.rule == rules::RESTRICTION_CHANGED)
        .unwrap();
    assert_eq!(changed.count, 2, "applied, then lifted");
}

#[test]
fn foreign_fragmented_and_replayed_samples() {
    let mut g = gw(|_| {});
    let p = traj(&smooth(4, 0.5, 0.5));
    // A foreign writer on the trajectory topic: announced, suppressed.
    let ann = packet(
        ATTACKER_IP,
        7410,
        &sedp_datagram(FOREIGN, TRAJ_WRITER, TOPIC, TRAJ_TYPE),
    );
    run(&mut g, &ann, 1);
    let foreign = packet(
        ATTACKER_IP,
        DDS_PORT,
        &Datagram::new(FOREIGN)
            .data(TRAJ_WRITER, 1, &[], &p)
            .finish(),
    );
    assert_eq!(out_payload(&run(&mut g, &foreign, T0).1), None);
    // DATA_FRAG of the authorised writer: suppressed (README: the channel
    // needs a single-DATA trajectory).
    let frag = packet(
        CONTROLLER_IP,
        DDS_PORT,
        &Datagram::new(PREFIX)
            .data_frag(TRAJ_WRITER, 1, 1, 64, p.len() as u32, &p[..64])
            .finish(),
    );
    let (v, _) = run(&mut g, &frag, T0 + MS);
    assert_eq!(v, Verdict::AcceptModified, "the fragment is padded out");
    assert_eq!(g.stats.unsupported_sample, 1);
    // A replay of an accepted sample re-emits it; a refused one stays
    // suppressed.
    assert!(decide(&mut g, TRAJ_WRITER, 5, &p).1.is_some());
    let mut bad = smooth(4, 0.5, 0.5);
    bad[1].positions[0] = 9.0;
    assert_eq!(decide(&mut g, TRAJ_WRITER, 6, &traj(&bad)).1, None);
    assert!(decide(&mut g, TRAJ_WRITER, 5, &p).1.is_some());
    assert_eq!(decide(&mut g, TRAJ_WRITER, 6, &traj(&bad)).1, None);
    assert_eq!(g.stats.replays, 2);
    let devs = g.findings.drain(robodr_events::Mode::Enforce);
    assert!(devs
        .iter()
        .any(|d| d.deviation.rule == rules::FRAGMENTED_COMMAND));
}

#[test]
fn unknown_writer_is_probed_and_decided_strictly() {
    // No SEDP: the probe classifies the trajectory by content, and a
    // trajectory-looking sample in XCDR2 is classified and then fails
    // closed (never passed as "not a motion channel").
    let mut g = trajectory_gateway(|_| {});
    let mut p = traj(&smooth(4, 0.5, 0.5));
    let (_, out) = run(&mut g, &pkt(TRAJ_WRITER, 1, &p), T0);
    assert!(out_payload(&out).is_some());
    p[1] = 0x07;
    let (_, out) = run(&mut g, &pkt([0, 0, 0x0a, 0x03], 1, &p), T0 + MS);
    assert_eq!(out_payload(&out), None);
    assert!(g.stats.probed >= 2, "{:?}", g.stats);
}

// --------------------------------------------------------- real captures

/// Every reassembled `JointTrajectory` (40 points, 6 joints, 5220 octets)
/// that `rmw_fastrtps` and `rmw_cyclonedds` sent in the lab decodes
/// strictly, and passes a channel whose bounds contain it.
#[test]
fn real_rmw_trajectories_decode_strictly() {
    for v in ["fastrtps", "cyclonedds"] {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../fixtures/captures/ros2-jazzy/{v}_frag_run1.pcap"
        ));
        let bytes = std::fs::read(&path).unwrap();
        let mut it = rtps_datagrams(CaptureFile::new(&bytes[..]).unwrap());
        let _ = RtpsPortMap::ros2_default();
        let mut walker = robodr_rtps::UserDataWalker::new(robodr_rtps::UserDataLimits::default());
        let mut found = 0;
        while let Some(p) = it.next_packet() {
            let Some(r) = walker.walk(&p.payload) else {
                continue;
            };
            for s in r.samples {
                if s.payload.len() < 4000 {
                    continue;
                }
                let t = trajectory::decode_strict(&s.payload, Layout::Trajectory, 4096)
                    .unwrap_or_else(|e| panic!("{v}: {e:?}"));
                assert_eq!(t.points.len(), 40, "{v}");
                assert_eq!(t.joint_names.len(), 6, "{v}");
                let lim = trajectory::TrajectoryLimits {
                    joints: t
                        .joint_names
                        .iter()
                        .map(|n| trajectory::JointBounds {
                            name: n.clone(),
                            min_position: -1e6,
                            max_position: 1e6,
                            max_velocity: 1e6,
                            max_acceleration: 1e9,
                            max_effort: 1e9,
                        })
                        .collect(),
                    max_points: 64,
                    max_duration_ns: 3_600_000_000_000,
                    time_scale: false,
                    max_time_scale: 1.0,
                };
                assert_eq!(trajectory::check(&t, &lim), TrajectoryVerdict::Pass, "{v}");
                found += 1;
            }
        }
        assert!(found >= 10, "{v}: {found} trajectories");
    }
}

// --------------------------------------------- reference-firewall comparison

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn f(&mut self, lo: f64, hi: f64) -> f64 {
        lo + (hi - lo) * (self.next() % 1_000_000) as f64 / 1e6
    }
}

/// The reference: `robodr-cdr`'s own (lenient, independent) decoder plus
/// the bounds as the README states them, written here from scratch.
fn reference_passes(payload: &[u8]) -> bool {
    use robodr_cdr::{decode_payload, Limits, MessageKind, MotionMessage};
    let Ok(d) = decode_payload(MessageKind::JointTrajectory, payload, &Limits::default()) else {
        return false;
    };
    let MotionMessage::JointTrajectory(t) = d.message else {
        return false;
    };
    let names: Vec<String> = t
        .joint_names
        .iter()
        .map(|s| s.as_str().unwrap_or("\u{fffd}").to_string())
        .collect();
    let n = names.len();
    for (i, name) in names.iter().enumerate() {
        if !TRAJ_JOINTS.contains(&name.as_str()) || names[..i].contains(name) {
            return false;
        }
    }
    if t.points.is_empty() {
        return true;
    }
    if n == 0 || t.points.len() > 64 {
        return false;
    }
    let mut prev: Option<(f64, Vec<f64>, Vec<f64>)> = None;
    let mut prev2: Option<(f64, Vec<f64>)> = None;
    for p in &t.points {
        let pos: Vec<f64> = p.positions.iter().collect();
        let vel: Vec<f64> = p.velocities.iter().collect();
        let acc: Vec<f64> = p.accelerations.iter().collect();
        let eff: Vec<f64> = p.effort.iter().collect();
        if pos.len() != n
            || [&vel, &acc, &eff]
                .iter()
                .any(|s| !s.is_empty() && s.len() != n)
        {
            return false;
        }
        if [&pos, &vel, &acc, &eff]
            .iter()
            .any(|s| s.iter().any(|x| !x.is_finite()))
        {
            return false;
        }
        let d = p.time_from_start;
        if d.sec < 0 || d.nanosec >= 1_000_000_000 {
            return false;
        }
        let ts = d.sec as f64 + d.nanosec as f64 * 1e-9;
        if pos.iter().any(|q| q.abs() > TRAJ_Q)
            || vel.iter().any(|v| v.abs() > TRAJ_V)
            || acc.iter().any(|a| a.abs() > TRAJ_A)
            || eff.iter().any(|e| e.abs() > TRAJ_EFFORT)
        {
            return false;
        }
        if let Some((pt, ppos, pvel)) = &prev {
            let dt = ts - pt;
            if dt <= 0.0 {
                return false;
            }
            for j in 0..n {
                if (pos[j] - ppos[j]).abs() / dt > TRAJ_V {
                    return false;
                }
                if !vel.is_empty() && !pvel.is_empty() && (vel[j] - pvel[j]).abs() / dt > TRAJ_A {
                    return false;
                }
                if !vel.is_empty()
                    && !pvel.is_empty()
                    && !cubic_within(ppos[j], pvel[j], pos[j], vel[j], dt)
                {
                    return false;
                }
                if let Some((ppt, pppos)) = &prev2 {
                    let dt0 = pt - ppt;
                    let a = 2.0 * ((pos[j] - ppos[j]) / dt - (ppos[j] - pppos[j]) / dt0).abs()
                        / (dt0 + dt);
                    if a > TRAJ_A {
                        return false;
                    }
                }
            }
            prev2 = Some((*pt, ppos.clone()));
        }
        prev = Some((ts, pos, vel));
    }
    let last = prev.map_or(0.0, |p| p.0);
    last <= 20.0
}

/// The Hermite cubic a joint_trajectory_controller executes between two
/// points with velocities, solved analytically here: position within
/// `±TRAJ_Q`, velocity within `TRAJ_V`, acceleration within `TRAJ_A`.
fn cubic_within(p0: f64, v0: f64, p1: f64, v1: f64, t: f64) -> bool {
    let c2 = 3.0 * (p1 - p0) / (t * t) - (2.0 * v0 + v1) / t;
    let c3 = 2.0 * (p0 - p1) / (t * t * t) + (v0 + v1) / (t * t);
    let p = |x: f64| p0 + v0 * x + c2 * x * x + c3 * x * x * x;
    let v = |x: f64| v0 + 2.0 * c2 * x + 3.0 * c3 * x * x;
    let a = |x: f64| 2.0 * c2 + 6.0 * c3 * x;
    let mut pts = vec![0.0, t];
    // Velocity zeros (position extrema).
    let (qa, qb, qc) = (3.0 * c3, 2.0 * c2, v0);
    if qa.abs() > 1e-300 {
        let disc = qb * qb - 4.0 * qa * qc;
        if disc >= 0.0 {
            pts.push((-qb + disc.sqrt()) / (2.0 * qa));
            pts.push((-qb - disc.sqrt()) / (2.0 * qa));
        }
        pts.push(-qb / (2.0 * qa)); // velocity extremum
    } else if qb.abs() > 1e-300 {
        pts.push(-qc / qb);
    }
    pts.iter()
        .filter(|x| (0.0..=t).contains(*x))
        .all(|&x| p(x).abs() <= TRAJ_Q && v(x).abs() <= TRAJ_V && a(x).abs() <= TRAJ_A)
}

/// Random trajectories, mutated or not, with the bounds crossed or not:
/// the gateway forwards a trajectory iff the reference passes it, and
/// what it forwards is byte-identical but for a zeroed `header.stamp`.
/// Mutations that break the encoding are suppressed by the gateway
/// whatever the lenient reference decodes.
#[test]
fn gateway_matches_the_reference() {
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let mut g = gw(|_| {});
    let (mut agree_pass, mut agree_refuse, mut strict_only) = (0, 0, 0);
    for round in 0..3000i64 {
        let n = 1 + rng.below(6);
        let dt = rng.f(0.05, 0.6);
        let speed = rng.f(0.0, 1.3);
        let mut pts = smooth(n, dt, speed);
        match rng.below(8) {
            0 => {
                let i = rng.below(n);
                pts[i].positions[rng.below(3)] = rng.f(-2.5, 2.5);
            }
            1 => {
                let i = rng.below(n);
                pts[i].accelerations = vec![rng.f(-6.0, 6.0), 0.0, 0.0];
            }
            2 => {
                let i = rng.below(n);
                pts[i].effort = vec![rng.f(-30.0, 30.0); 3];
            }
            3 if n > 1 => {
                let i = 1 + rng.below(n - 1);
                pts.swap(i - 1, i);
            }
            4 => pts[rng.below(n)].velocities.clear(),
            _ => {}
        }
        let mut payload = traj(&pts);
        let mutated = rng.below(6) == 0;
        if mutated {
            let i = rng.below(payload.len());
            payload[i] ^= 1 << rng.below(8);
        }
        let (_, out) = decide(&mut g, TRAJ_WRITER, round + 1, &payload);
        let reference = reference_passes(&payload);
        match (out.is_some(), reference) {
            (true, true) => {
                // A non-zero header.stamp is zeroed in place (the
                // controller then starts the trajectory on receipt, which
                // is what the checks assume); nothing else changes.
                let mut want = payload.clone();
                want[4..12].fill(0);
                assert_eq!(out.as_deref(), Some(&want[..]), "round {round}");
                agree_pass += 1;
            }
            (false, false) => agree_refuse += 1,
            (false, true) if mutated => strict_only += 1,
            (got, want) => panic!(
                "round {round}: gateway forwards {got}, reference {want}: {pts:?} mutated {mutated}"
            ),
        }
    }
    assert!(
        agree_pass > 300 && agree_refuse > 300,
        "{agree_pass} {agree_refuse} {strict_only}"
    );
}

/// The shipped trajectory example parses (structure; the gateway itself
/// is built against its firewall configuration and profile on site).
#[test]
fn ros2_arm_example_parses() {
    let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../config/firewall-gw.ros2-arm.example.json");
    let c = robodr_firewall_gw::GatewayConfig::load(&p).unwrap();
    assert_eq!(c.channels.len(), 2);
    assert!(c.channels.iter().all(|ch| ch.codec.is_trajectory()));
    assert!(c.findings_socket.is_some() && c.restriction_path.is_some());
}

/// A restriction also caps the firewall's hold substitute (its last
/// output was computed without the restriction).
#[test]
fn restriction_caps_held_twists_too() {
    use robodr_firewall_gw::ros2;
    let mut g = g1_channels_gateway(|_| {});
    let ann = packet(
        CONTROLLER_IP,
        7410,
        &sedp_datagram(
            PREFIX,
            TWIST_WRITER,
            "rt/cmd_vel",
            "geometry_msgs::msg::dds_::Twist_",
        ),
    );
    run(&mut g, &ann, 1);
    let fast = ros2::encode([0.7, 0.0, 0.0, 0.0, 0.0, 0.0], None, false);
    let (_, out) = decide(&mut g, TWIST_WRITER, 1, &fast);
    assert_eq!(out.as_deref(), Some(&fast[..]));
    g.set_restriction(Some(Restriction {
        id: "r".into(),
        max_linear_speed: Some(0.2),
        max_joint_speed: None,
        factor: None,
        expires_unix_ms: u64::MAX,
    }));
    let lin = |p: &[u8]| ros2::decode_strict(p, false).unwrap().values[0];
    let (_, out) = decide(&mut g, TWIST_WRITER, 2, &fast);
    assert!(lin(&out.unwrap()) <= 0.2 + 1e-12);
    // A non-finite twist is rejected; its substitute (the hold of the
    // firewall's last output, 0.7 unrestricted) is capped.
    let nan = ros2::encode([f64::NAN, 0.0, 0.0, 0.0, 0.0, 0.0], None, false);
    let (_, held) = decide(&mut g, TWIST_WRITER, 3, &nan);
    assert!(held.is_some(), "the fixture holds a rejected twist");
    if let Some(sub) = held {
        assert!(lin(&sub).abs() <= 0.2 + 1e-12, "{}", lin(&sub));
    }
    assert!(g.stats.restriction_capped >= 1);
}
