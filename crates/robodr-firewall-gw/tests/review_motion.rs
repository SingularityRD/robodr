//! Regressions of the independent review of the Sprint 8 gateway work
//! (F1 - F5, F8, too_many_points): each test failed before its fix.

use std::time::{Duration, Instant};

use robodr_cdr::Representation;
use robodr_firewall_gw::findings::rules;
use robodr_firewall_gw::ip::parse_ipv4_udp;
use robodr_firewall_gw::restrict::Restriction;
use robodr_firewall_gw::rtps::{self, Content, WalkOptions};
use robodr_firewall_gw::testkit::*;
use robodr_firewall_gw::trajectory::{self, encode, Layout, Point};
use robodr_firewall_gw::{ros2, sport, Gateway, PacketMeta, Verdict};

const MS: u64 = 1_000_000;
const TOPIC: &str = "rt/arm_controller/joint_trajectory";
const TRAJ_TYPE: &str = "trajectory_msgs::msg::dds_::JointTrajectory_";

fn meta(now: u64) -> PacketMeta {
    PacketMeta {
        now_ns: now,
        queue_delay_ns: None,
        instant: Instant::now(),
        src_mac: None,
    }
}

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

fn send(
    g: &mut Gateway,
    entity: [u8; 4],
    sn: i64,
    payload: &[u8],
    now: u64,
) -> (Verdict, Option<Vec<u8>>) {
    let mut p = packet(CONTROLLER_IP, DDS_PORT, &data_datagram(entity, sn, payload));
    let v = g.process(&mut p, meta(now));
    (v, out_payload(&p))
}

fn announce(g: &mut Gateway, w: [u8; 4], topic: &str, ty: &str) {
    let mut p = packet(CONTROLLER_IP, 7410, &sedp_datagram(PREFIX, w, topic, ty));
    assert_eq!(g.process(&mut p, meta(1)), Verdict::Accept);
}

fn traj_gw(edit: impl FnOnce(&mut serde_json::Value)) -> Gateway {
    let mut g = trajectory_gateway(edit);
    announce(&mut g, TRAJ_WRITER, TOPIC, TRAJ_TYPE);
    g
}

/// F1: a past `header.stamp` is zeroed in place (the controller starts the
/// trajectory now, which is what the checks assume).
#[test]
fn f1_trajectory_stamp_is_zeroed() {
    let mut g = traj_gw(|_| {});
    let pts: Vec<Point> = (0..=10)
        .map(|i| Point::at(i as f64, &[0.18 * i as f64, 0.0, 0.0]))
        .collect();
    let mut p = encode(&TRAJ_JOINTS, &pts, false, None);
    p[4..8].copy_from_slice(&(1_800_000_000i32 - 10).to_le_bytes());
    p[8..12].copy_from_slice(&100_000_000u32.to_le_bytes());
    let (v, out) = send(&mut g, TRAJ_WRITER, 1, &p, 1_000 * MS);
    assert_eq!(v, Verdict::AcceptModified);
    let out = out.expect("forwarded");
    let t = trajectory::decode_strict(&out, Layout::Trajectory, 64).unwrap();
    assert_eq!(t.stamp, (0, 0));
    assert_eq!(&out[12..], &p[12..], "only the stamp changed");
    assert_eq!(g.stats.trajectory_stamp_zeroed, 1);
}

/// F2: the executed cubic (velocities on both points) is bounded, not only
/// the waypoints: an overshoot past `max_position` is refused, an
/// acceleration far above `max_acceleration` refused (reject mode) or
/// slowed down (time_scale mode) until the spline fits.
#[test]
fn f2_spline_between_waypoints_is_bounded() {
    let mut g = traj_gw(|_| {});
    let (q, v) = (TRAJ_Q, TRAJ_V);
    let over = vec![
        Point {
            velocities: vec![v, 0.0, 0.0],
            ..Point::at(0.0, &[q, 0.0, 0.0])
        },
        Point {
            velocities: vec![v, 0.0, 0.0],
            ..Point::at(4.0, &[q, 0.0, 0.0])
        },
    ];
    let (_, out) = send(
        &mut g,
        TRAJ_WRITER,
        1,
        &encode(&TRAJ_JOINTS, &over, false, None),
        1_000 * MS,
    );
    assert_eq!(out, None, "position overshoot ~2.385 > 2.0");
    let jerk = vec![
        Point {
            velocities: vec![v, 0.0, 0.0],
            ..Point::at(0.0, &[0.0, 0.0, 0.0])
        },
        Point {
            velocities: vec![v, 0.0, 0.0],
            ..Point::at(0.05, &[0.0, 0.0, 0.0])
        },
    ];
    let p = encode(&TRAJ_JOINTS, &jerk, false, None);
    let (_, out) = send(&mut g, TRAJ_WRITER, 2, &p, 1_100 * MS);
    assert_eq!(out, None, "120 rad/s^2 against 4");
    let devs = g.findings.drain(robodr_events::Mode::Enforce);
    let r = devs
        .iter()
        .find(|d| d.deviation.rule == rules::TRAJECTORY_REJECTED)
        .unwrap();
    assert_eq!(r.count, 2);
    assert!(
        r.deviation.detail.contains("position"),
        "{}",
        r.deviation.detail
    );
    // A quintic (accelerations on both points) is bounded too: a
    // rest-to-rest move of 0.2 rad in 0.5 s peaks at 10/sqrt(3) * d / T^2
    // ~ 4.62 rad/s^2 mid-segment while both waypoints say 0.
    let rest = |t: f64, q: f64| Point {
        velocities: vec![0.0, 0.0, 0.0],
        accelerations: vec![0.0, 0.0, 0.0],
        ..Point::at(t, &[q, 0.0, 0.0])
    };
    let quintic = vec![rest(0.0, 0.0), rest(0.5, 0.2)];
    let (_, out) = send(
        &mut g,
        TRAJ_WRITER,
        3,
        &encode(&TRAJ_JOINTS, &quintic, false, None),
        1_200 * MS,
    );
    assert_eq!(
        out, None,
        "the quintic's interior acceleration exceeds the bound"
    );
    let gentle = vec![rest(0.0, 0.0), rest(0.5, 0.15)];
    let (_, out) = send(
        &mut g,
        TRAJ_WRITER,
        4,
        &encode(&TRAJ_JOINTS, &gentle, false, None),
        1_300 * MS,
    );
    assert!(out.is_some(), "0.15 rad peaks at ~3.46 rad/s^2");
    // time_scale: slowed until the spline fits.
    let mut g = traj_gw(|v| {
        v["channels"][1]["trajectory"]["on_velocity_violation"] = "time_scale".into();
        v["channels"][1]["trajectory"]["max_time_scale"] = 10.0.into();
    });
    let (verdict, out) = send(&mut g, TRAJ_WRITER, 1, &p, 1_000 * MS);
    assert_eq!(verdict, Verdict::AcceptModified);
    let t = trajectory::decode_strict(&out.unwrap(), Layout::Trajectory, 64).unwrap();
    let dt = t.points[1].time_ns().unwrap() as f64 * 1e-9;
    // Hermite acceleration at the start: 6 v / T (scaled velocities v/k).
    let a0 = 6.0 * t.points[0].velocities[0] / dt;
    assert!(a0 <= TRAJ_A + 1e-9, "{a0}");
}

/// F3: the restriction caps the command before the firewall decides, so
/// lifting it ramps up from the capped speed at the channel's
/// acceleration limit instead of jumping.
#[test]
fn f3_restriction_lift_ramps_from_the_capped_speed() {
    let mut f = g1_channels_firewall();
    f.channels.get_mut("/cmd_vel").unwrap().max_linear_accel = Some(1.0);
    let mut g = Gateway::new(&g1_channels_config(|_| {}), &g1_channels_profile(), &f).unwrap();
    announce(
        &mut g,
        TWIST_WRITER,
        "rt/cmd_vel",
        "geometry_msgs::msg::dds_::Twist_",
    );
    g.set_restriction(Some(Restriction {
        id: "r".into(),
        max_linear_speed: Some(0.1),
        max_joint_speed: None,
        factor: None,
        expires_unix_ms: u64::MAX,
    }));
    let lin = |p: &[u8]| ros2::decode_strict(p, false).unwrap().values[0];
    let fast = ros2::encode([0.7, 0.0, 0.0, 0.0, 0.0, 0.0], None, false);
    let (mut now, mut sn, mut last) = (1_000 * MS, 1, 0.0);
    for _ in 0..15 {
        let (_, out) = send(&mut g, TWIST_WRITER, sn, &fast, now);
        last = lin(&out.unwrap());
        sn += 1;
        now += 100 * MS;
    }
    assert!(last <= 0.1 + 1e-9, "{last}");
    g.set_restriction(None);
    let (_, out) = send(&mut g, TWIST_WRITER, sn, &fast, now);
    let after = lin(&out.unwrap());
    assert!(after - last <= 0.1 + 1e-6, "jump {last} -> {after}");
}

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("gw-review-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// F4: the restriction file is opened without following a symlink and
/// without blocking (a FIFO returns an error at once), and checked on the
/// open descriptor.
#[test]
fn f4_restriction_load_never_blocks_and_checks_the_descriptor() {
    use std::os::unix::fs::PermissionsExt;
    let d = tmp("f4");
    let path = d.join("restriction.json");
    assert!(std::process::Command::new("mkfifo")
        .arg(&path)
        .status()
        .unwrap()
        .success());
    let (tx, rx) = std::sync::mpsc::channel();
    let p2 = path.clone();
    std::thread::spawn(move || {
        let _ = tx.send(robodr_firewall_gw::restrict::load(&p2));
    });
    let r = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("load() returned");
    assert!(r.is_err());
    std::fs::remove_file(&path).unwrap();
    let real = d.join("real.json");
    std::fs::write(
        &real,
        r#"{"format":"robodr-gw-restriction/v1","id":"x","factor":0.5,"expires_unix_ms":9}"#,
    )
    .unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o640)).unwrap();
    std::os::unix::fs::symlink(&real, &path).unwrap();
    assert!(
        robodr_firewall_gw::restrict::load(&path).is_err(),
        "symlink"
    );
    assert!(robodr_firewall_gw::restrict::load(&real).unwrap().is_some());
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o660)).unwrap();
    assert!(
        robodr_firewall_gw::restrict::load(&real).is_err(),
        "group-writable"
    );
    // The watcher thread delivers what it read.
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o640)).unwrap();
    let w = robodr_firewall_gw::restrict::Watcher::spawn(real, Duration::from_millis(10)).unwrap();
    let got = (0..200).find_map(|_| {
        std::thread::sleep(Duration::from_millis(10));
        w.latest()
    });
    assert_eq!(got.unwrap().unwrap().unwrap().id, "x");
}

/// F5: with a listener that never accepts (backlog full), handing lines to
/// the feed never blocks the caller (the packet thread).
#[test]
fn f5_feed_hand_off_never_blocks() {
    let d = tmp("f5");
    let path = d.join("feed.sock");
    let _l = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let p2 = path.clone();
    std::thread::spawn(move || {
        let mut keep = Vec::new();
        for _ in 0..20_000 {
            match std::os::unix::net::UnixStream::connect(&p2) {
                Ok(s) => keep.push(s),
                Err(_) => break,
            }
        }
        std::thread::sleep(Duration::from_secs(60));
    });
    std::thread::sleep(Duration::from_millis(500));
    let mut f = robodr_firewall_gw::feed::FeedThread::spawn(path).unwrap();
    let t0 = Instant::now();
    for _ in 0..robodr_firewall_gw::feed::HANDOFF + 10 {
        f.push("{}".into());
        let _ = f.status();
    }
    assert!(
        t0.elapsed() < Duration::from_millis(200),
        "{:?}",
        t0.elapsed()
    );
    // Either the feed thread is stuck behind the full listener and the
    // hand-off overflowed (dropped), or the kernel let it connect and it
    // kept up (lines queued or sent). Which one happens depends on the
    // host's socket backlog; the property under test is the timing above.
    let s = f.status();
    let accounted = s.dropped + s.sent + s.pending as u64;
    assert!(
        s.dropped >= 10 || accounted >= robodr_firewall_gw::feed::HANDOFF as u64,
        "{s:?}"
    );
}

/// F8: while a restriction is in force the sport `SpeedLevel` cannot be
/// changed through the gateway.
#[test]
fn f8_speed_level_is_refused_while_restricted() {
    let mut cfg = gateway_config(Fixture::Go2);
    cfg.channels[1].allowed_api_ids = None;
    let mut g = Gateway::new(&cfg, &profile(Fixture::Go2), &firewall(Fixture::Go2)).unwrap();
    announce(
        &mut g,
        SPORT_WRITER,
        "rt/api/sport/request",
        "unitree_api::msg::dds_::Request_",
    );
    let req = |id| sport::encode_request(Representation::CdrLe, id, 1015, "{\"data\":1}");
    assert!(send(&mut g, SPORT_WRITER, 1, &req(1), 1_000 * MS)
        .1
        .is_some());
    g.set_restriction(Some(Restriction {
        id: "r".into(),
        max_linear_speed: None,
        max_joint_speed: None,
        factor: Some(0.5),
        expires_unix_ms: u64::MAX,
    }));
    assert_eq!(send(&mut g, SPORT_WRITER, 2, &req(2), 1_100 * MS).1, None);
    assert_eq!(g.stats.restriction_speed_level_refused, 1);
    g.set_restriction(None);
    assert!(send(&mut g, SPORT_WRITER, 3, &req(3), 1_200 * MS)
        .1
        .is_some());
}

/// More points than `max_points` is a bound violation reported as
/// `too_many_points`, not an undecodable payload.
#[test]
fn too_many_points_is_reported_as_such() {
    let mut g = traj_gw(|_| {});
    let pts: Vec<Point> = (0..65)
        .map(|i| Point::at(i as f64 * 0.1, &[0.0; 3]))
        .collect();
    let (_, out) = send(
        &mut g,
        TRAJ_WRITER,
        1,
        &encode(&TRAJ_JOINTS, &pts, false, None),
        1_000 * MS,
    );
    assert_eq!(out, None);
    let devs = g.findings.drain(robodr_events::Mode::Enforce);
    assert_eq!(devs.len(), 1, "{devs:?}");
    assert_eq!(devs[0].deviation.rule, rules::TRAJECTORY_REJECTED);
    assert!(devs[0].deviation.detail.contains("too_many_points"));
}

/// Executor review finding 3: the gateway applied any cap > 0, so a
/// restriction file with `max_linear_speed: 0.0001` or `factor: 0.01`
/// near-stopped a humanoid's locomotion (a fall). On a robot that
/// balances it is now ignored (reported as `restriction_error`) and the
/// restriction in force stays.
#[test]
fn executor_review_f3_restriction_floor_on_a_humanoid() {
    use robodr_firewall_gw::runtime::apply_restriction;
    let mut g = Gateway::new(
        &g1_channels_config(|_| {}),
        &g1_channels_profile(),
        &g1_channels_firewall(),
    )
    .unwrap();
    let r = |lin: Option<f64>, factor: Option<f64>| Restriction {
        id: "r".into(),
        max_linear_speed: lin,
        max_joint_speed: None,
        factor,
        expires_unix_ms: u64::MAX,
    };
    let ok = r(None, Some(0.5));
    assert_eq!(
        apply_restriction(&mut g, Some(Ok(Some(ok.clone()))), None, 1),
        None
    );
    assert_eq!(g.restriction(), Some(&ok));
    for bad in [r(Some(0.0001), None), r(None, Some(0.01))] {
        let err = apply_restriction(&mut g, Some(Ok(Some(bad))), None, 1);
        assert!(err.is_some_and(|e| e.contains("balances")));
        assert_eq!(g.restriction(), Some(&ok), "the one in force stays");
    }
}
