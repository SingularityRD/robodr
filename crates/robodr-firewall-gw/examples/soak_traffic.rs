//! Soak / red-team traffic for the inline gateway through a real kernel
//! (`tools/e2e/gw-netns.sh` builds the namespaces; `tools/e2e/soak.sh`
//! and `tools/e2e/redteam_gw.sh` drive it).
//!
//! ```text
//! soak_traffic setup DIR
//!     writes DIR/profile.json (locked, unsigned: sign it with
//!     `robodr-commission sign`) and DIR/firewall.json: the Go2 fixture
//!     (`/lowcmd` 500 Hz, sport `Move`) plus a 3-joint ROS 2
//!     JointTrajectory channel `/arm_trajectory`.
//! soak_traffic soak CTRL_NS ROB_NS SECONDS STATS.jsonl [INJECT_EVERY_S]
//!     a sender thread in CTRL_NS (192.168.123.164) and a receiver thread
//!     in ROB_NS (192.168.123.161:7411): Go2 LowCmd at 500 Hz, a sport
//!     Move (0.3 m/s) every 500 ms, a smooth trajectory every second,
//!     SEDP every 5 s. Every INJECT_EVERY_S (default 600) one injection
//!     round (logged in STATS with its time): a LowCmd torque over
//!     tau_max (limited), an overshooting trajectory (refused), a foreign
//!     writer's LowCmd (suppressed). One JSON line per minute: sent /
//!     received / modified / lost per stream and the LowCmd
//!     send -> receive latency (p50 / p99 / max, µs) through the bridge.
//! soak_traffic attack CTRL_NS ROB_NS NAME
//!     one red-team scenario (see `attack`), prints JSON lines: what was
//!     sent and what reached the robot side.
//! ```
//!
//! Test tooling only (synthetic frames from the `testkit` feature); never
//! part of a shipped binary.

use std::collections::HashMap;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use robodr_cdr::Representation;
use robodr_events::profile::{Envelope, ProfileMetadata, PROFILE_SCHEMA_VERSION};
use robodr_firewall::{ChannelKind, ChannelSpec};
use robodr_firewall_gw::lowcmd::{self, LowCmdCodec, WireLowCmd};
use robodr_firewall_gw::rtps::{self, Content, WalkOptions};
use robodr_firewall_gw::testkit::*;
use robodr_firewall_gw::trajectory::{encode, Point};
use robodr_firewall_gw::{sport, sys};

extern "C" {
    fn setns(fd: i32, nstype: i32) -> i32;
}
const CLONE_NEWNET: i32 = 0x4000_0000;
const TRAJ_TOPIC: &str = "rt/arm_controller/joint_trajectory";
const TRAJ_TYPE: &str = "trajectory_msgs::msg::dds_::JointTrajectory_";

fn enter(ns: &str) {
    let f = std::fs::File::open(format!("/run/netns/{ns}")).expect("netns file");
    // SAFETY: a valid namespace fd; setns only affects the calling thread.
    #[allow(unsafe_code)]
    let rc = unsafe { setns(f.as_raw_fd(), CLONE_NEWNET) };
    assert_eq!(rc, 0, "setns {ns}: {}", std::io::Error::last_os_error());
}

fn now_s() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn setup(dir: &str) {
    let mut p = profile(Fixture::Go2);
    p.writer_topics.insert("/arm_trajectory".into());
    p.motion_envelopes.insert(
        "/arm_trajectory".into(),
        Envelope {
            max_joint_speed: Some(TRAJ_V),
            ..Default::default()
        },
    );
    p.metadata = Some(ProfileMetadata {
        schema_version: PROFILE_SCHEMA_VERSION,
        profile_version: 1,
        platform: "go2-soak".into(),
        unit_id: None,
        locked_by: "soak harness".into(),
        locked_at: 1_790_000_000,
        parent_digest: None,
        attestation: None,
    });
    let mut f = firewall(Fixture::Go2);
    f.channels.insert(
        "/arm_trajectory".into(),
        ChannelSpec {
            kind: ChannelKind::Joints { count: 3 },
            allowed_sources: vec![guid_hex(&PREFIX, TRAJ_WRITER)],
            ..Default::default()
        },
    );
    std::fs::create_dir_all(dir).unwrap();
    // Unsealed: `tools/e2e/gw-setup.sh` seals it as `robodr-commission
    // lock` writes it (pretty JSON + newline, SHA-256 as the first member).
    let body = serde_json::to_string_pretty(&p).unwrap() + "\n";
    std::fs::write(format!("{dir}/profile.json"), body).unwrap();
    let fj = serde_json::to_string_pretty(&f).unwrap();
    std::fs::write(format!("{dir}/firewall.json"), fj).unwrap();
    println!("{dir}/profile.json {dir}/firewall.json");
}

/// What a datagram carries for the receiver: (writer entity, sn, user
/// DATA present).
fn classify(d: &[u8]) -> Option<([u8; 4], i64, bool)> {
    let mut v = Vec::new();
    rtps::walk(d, WalkOptions::default(), &mut v).ok()?;
    let data = v.iter().find(|s| !s.builtin && s.content == Content::Data);
    let first = v.iter().find(|s| !s.builtin)?;
    let mut w = [0u8; 4];
    w.copy_from_slice(&first.writer[12..16]);
    Some((w, first.sn, data.is_some()))
}

fn lowcmd_of(d: &[u8]) -> Option<WireLowCmd> {
    let mut v = Vec::new();
    rtps::walk(d, WalkOptions::default(), &mut v).ok()?;
    let s = v
        .iter()
        .find(|s| s.content == Content::Data && !s.builtin)?;
    lowcmd::decode_strict(&d[s.payload.clone()?], LowCmdCodec::Go)
        .ok()
        .map(|x| x.msg)
}

struct Receiver {
    rx: mpsc::Receiver<(u64, Vec<u8>)>,
    stop: Arc<AtomicBool>,
    handle: std::thread::JoinHandle<()>,
}

fn receiver(ns: &str) -> Receiver {
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    let ns = ns.to_string();
    let handle = std::thread::spawn(move || {
        enter(&ns);
        let s = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DDS_PORT)).unwrap();
        s.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
        let mut buf = vec![0u8; 65_536];
        while !s2.load(Ordering::SeqCst) {
            if let Ok((n, _)) = s.recv_from(&mut buf) {
                let _ = tx.send((sys::monotonic_ns(), buf[..n].to_vec()));
            }
        }
    });
    Receiver { rx, stop, handle }
}

fn smooth_traj(phase: f64, speed: f64, n: usize) -> Vec<Point> {
    (0..n)
        .map(|i| {
            let t = i as f64 * 0.1;
            let base = 0.3 * phase.sin();
            Point {
                velocities: vec![speed, -speed, 0.0],
                ..Point::at(t, &[base + speed * t, base - speed * t, 0.5])
            }
        })
        .collect()
}

#[derive(Default)]
struct Stream {
    sent: u64,
    received: u64,
    identical: u64,
    modified: u64,
    data_removed: u64,
}

impl Stream {
    fn json(&self) -> serde_json::Value {
        serde_json::json!({"sent": self.sent, "received": self.received, "identical": self.identical,
            "modified": self.modified, "data_removed": self.data_removed})
    }
}

fn quantiles(v: &mut [u64]) -> serde_json::Value {
    v.sort_unstable();
    if v.is_empty() {
        return serde_json::json!(null);
    }
    let q = |p: f64| v[((v.len() as f64 * p).ceil() as usize).clamp(1, v.len()) - 1] / 1000;
    serde_json::json!({"n": v.len(), "p50_us": q(0.5), "p99_us": q(0.99), "p999_us": q(0.999),
        "max_us": v[v.len() - 1] / 1000})
}

fn soak(ctrl: &str, rob: &str, secs: u64, stats: &str, every: u64) {
    let r = receiver(rob);
    let stop_all = Arc::new(AtomicBool::new(false));
    {
        let s = stop_all.clone();
        // SIGTERM / SIGINT end the run cleanly (final stats line).
        robodr_firewall_gw::sys::install_signals().ok();
        std::thread::spawn(move || loop {
            if robodr_firewall_gw::sys::shutdown_requested() {
                s.store(true, Ordering::SeqCst);
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        });
    }
    // Sent records: writer -> sn -> (send mono ns, bytes).
    let (stx, srx) = mpsc::channel::<([u8; 4], i64, u64, Vec<u8>)>();
    let (itx, irx) = mpsc::channel::<String>();
    let ctrl_ns = ctrl.to_string();
    let stop_send = stop_all.clone();
    let sender = std::thread::spawn(move || {
        enter(&ctrl_ns);
        let tx = UdpSocket::bind(SocketAddrV4::new(CONTROLLER_IP, 0)).unwrap();
        let dst = SocketAddrV4::new(ROBOT_IP, DDS_PORT);
        let sedp = SocketAddrV4::new(ROBOT_IP, 7410);
        let spec = lowcmd_spec(Fixture::Go2);
        let period = Duration::from_micros(2000);
        let start = Instant::now();
        let mut last = start;
        let (mut sn, mut tsn, mut ssn, mut fsn) = (0i64, 0i64, 0i64, 0i64);
        let mut next_traj = start;
        let mut next_sport = start;
        let mut next_sedp = start;
        let mut next_inject = start + Duration::from_secs(every);
        let mut i: u64 = 0;
        while start.elapsed() < Duration::from_secs(secs) && !stop_send.load(Ordering::SeqCst) {
            let target = (start + period * i as u32).max(last + period.mul_f64(0.75));
            i += 1;
            while Instant::now() + Duration::from_micros(80) < target {
                std::thread::sleep(Duration::from_micros(50));
            }
            while Instant::now() < target {
                std::hint::spin_loop();
            }
            let now = Instant::now();
            if now >= next_sedp {
                let d = sedp_datagram(PREFIX, TRAJ_WRITER, TRAJ_TOPIC, TRAJ_TYPE);
                let _ = tx.send_to(&d, sedp);
                next_sedp = now + Duration::from_secs(5);
            }
            sn += 1;
            let mut f = mid_frame(
                LowCmdCodec::Go,
                &spec.motors,
                sn as f64 * 0.002,
                (None, None),
            );
            let inject = now >= next_inject;
            if inject {
                // Torque over tau_max inside the hard factor: limited.
                let mut w = f.motor(0).unwrap();
                w.tau = (spec.motors[0].tau_max.unwrap() * 1.3) as f32;
                f.set_motor(0, w);
                f.seal();
            }
            let d = lowcmd_datagram(PREFIX, WRITER, sn, &f, Representation::CdrLe);
            // Recorded before the send: the receiver may see the datagram
            // before the record otherwise.
            let _ = stx.send((WRITER, sn, sys::monotonic_ns(), d.clone()));
            let _ = tx.send_to(&d, dst);
            last = Instant::now();
            if now >= next_sport {
                ssn += 1;
                let p = sport::encode_request(
                    Representation::CdrLe,
                    ssn,
                    1008,
                    r#"{"x":0.3,"y":0.0,"z":0.0}"#,
                );
                let d = data_datagram(SPORT_WRITER, ssn, &p);
                let _ = stx.send((SPORT_WRITER, ssn, sys::monotonic_ns(), d.clone()));
                let _ = tx.send_to(&d, dst);
                next_sport = now + Duration::from_millis(500);
            }
            if now >= next_traj {
                tsn += 1;
                let pts = smooth_traj(tsn as f64 * 0.1, 0.5, 10);
                let d = data_datagram(TRAJ_WRITER, tsn, &encode(&TRAJ_JOINTS, &pts, false, None));
                let _ = stx.send((TRAJ_WRITER, tsn, sys::monotonic_ns(), d.clone()));
                let _ = tx.send_to(&d, dst);
                next_traj = now + Duration::from_secs(1);
            }
            if inject {
                // An overshooting trajectory (a position past max) and a
                // foreign writer's LowCmd.
                tsn += 1;
                let mut pts = smooth_traj(0.0, 0.5, 10);
                pts[9].positions[0] = TRAJ_Q + 0.5;
                let d = data_datagram(TRAJ_WRITER, tsn, &encode(&TRAJ_JOINTS, &pts, false, None));
                let _ = stx.send((TRAJ_WRITER, tsn, sys::monotonic_ns(), d.clone()));
                let _ = tx.send_to(&d, dst);
                fsn += 1;
                let g = mid_frame(LowCmdCodec::Go, &spec.motors, 0.0, (None, None));
                let d = lowcmd_datagram(FOREIGN, WRITER, fsn, &g, Representation::CdrLe);
                let _ = tx.send_to(&d, dst);
                let _ = itx.send(format!(
                    "{{\"t\":{:.3},\"inject\":\"lowcmd_tau_over sn {sn}, traj_overshoot sn {tsn}, foreign_lowcmd\"}}",
                    now_s()
                ));
                next_inject = now + Duration::from_secs(every);
            }
        }
    });

    let mut out = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(stats)
        .unwrap();
    let mut pending: HashMap<([u8; 4], i64), (u64, Vec<u8>)> = HashMap::new();
    let mut streams: HashMap<&'static str, Stream> = HashMap::new();
    let mut lat: Vec<u64> = Vec::new();
    let mut lat_all: Vec<u64> = Vec::new();
    let mut lost: HashMap<&'static str, u64> = HashMap::new();
    let mut foreign_rx = 0u64;
    let name = |w: [u8; 4]| match w {
        WRITER => "lowcmd",
        SPORT_WRITER => "sport",
        TRAJ_WRITER => "trajectory",
        _ => "other",
    };
    let t0 = Instant::now();
    let mut next_report = t0 + Duration::from_secs(60);
    let mut sender_done = false;
    let mut done_at: Option<Instant> = None;
    loop {
        while let Ok((w, sn, t, d)) = srx.try_recv() {
            streams.entry(name(w)).or_default().sent += 1;
            pending.insert((w, sn), (t, d));
        }
        while let Ok(line) = irx.try_recv() {
            writeln!(out, "{line}").unwrap();
        }
        if let Ok((t, d)) = r.rx.recv_timeout(Duration::from_millis(5)) {
            if d.get(8..20) == Some(&FOREIGN[..]) {
                foreign_rx += 1;
                if lowcmd_of(&d).is_some() {
                    writeln!(
                        out,
                        "{{\"t\":{:.3},\"alert\":\"foreign LowCmd DATA reached the robot\"}}",
                        now_s()
                    )
                    .unwrap();
                }
            } else if let Some((w, sn, has_data)) = classify(&d) {
                while let Ok((w, sn, t, d)) = srx.try_recv() {
                    streams.entry(name(w)).or_default().sent += 1;
                    pending.insert((w, sn), (t, d));
                }
                if let Some((ts, sent)) = pending.remove(&(w, sn)) {
                    let s = streams.entry(name(w)).or_default();
                    s.received += 1;
                    if !has_data {
                        s.data_removed += 1;
                    } else if d == sent {
                        s.identical += 1;
                    } else {
                        s.modified += 1;
                    }
                    if w == WRITER {
                        lat.push(t.saturating_sub(ts));
                    }
                }
            }
        }
        if !sender_done && sender.is_finished() {
            sender_done = true;
            done_at = Some(Instant::now());
        }
        let finish = done_at.is_some_and(|d| d.elapsed() > Duration::from_secs(2));
        if Instant::now() >= next_report || finish {
            // Older than 2 s and never received: lost (dropped by the
            // gateway or the kernel).
            let now = sys::monotonic_ns();
            pending.retain(|(w, _), (ts, _)| {
                if now.saturating_sub(*ts) > 2_000_000_000 {
                    *lost.entry(name(*w)).or_default() += 1;
                    false
                } else {
                    true
                }
            });
            lat_all.extend_from_slice(&lat);
            let line = serde_json::json!({
                "t": now_s(), "elapsed_s": t0.elapsed().as_secs(),
                "lowcmd": streams.get("lowcmd").map(Stream::json),
                "sport": streams.get("sport").map(Stream::json),
                "trajectory": streams.get("trajectory").map(Stream::json),
                "lost": lost, "foreign_datagrams_received": foreign_rx,
                "latency_minute": quantiles(&mut lat),
                "latency_total": if finish { quantiles(&mut lat_all) } else { serde_json::json!(null) },
            });
            writeln!(out, "{line}").unwrap();
            lat.clear();
            next_report += Duration::from_secs(60);
            if finish {
                break;
            }
        }
    }
    r.stop.store(true, Ordering::SeqCst);
    let _ = r.handle.join();
}

/// Red-team scenarios against the gateway in the path.
fn attack(ctrl: &str, rob: &str, name: &str) {
    let r = receiver(rob);
    std::thread::sleep(Duration::from_millis(200));
    enter(ctrl);
    let tx = UdpSocket::bind(SocketAddrV4::new(CONTROLLER_IP, 0)).unwrap();
    let dst = SocketAddrV4::new(ROBOT_IP, DDS_PORT);
    let _ = tx.send_to(
        &sedp_datagram(PREFIX, TRAJ_WRITER, TRAJ_TOPIC, TRAJ_TYPE),
        SocketAddrV4::new(ROBOT_IP, 7410),
    );
    std::thread::sleep(Duration::from_millis(50));
    let base_sn = (now_s() as i64 % 100_000) * 1000;
    let mut cases: Vec<(String, Vec<u8>)> = Vec::new();
    let t = |pts: &[Point]| encode(&TRAJ_JOINTS, pts, false, None);
    let set_stamp = |mut p: Vec<u8>, sec: i32, ns: u32| {
        // CDR: 4-byte encapsulation, then header.stamp (int32 sec,
        // uint32 nanosec).
        p[4..8].copy_from_slice(&sec.to_le_bytes());
        p[8..12].copy_from_slice(&ns.to_le_bytes());
        p
    };
    match name {
        "trajectory" => {
            let good = smooth_traj(0.0, 0.5, 10);
            cases.push(("T0 valid trajectory (control)".into(), t(&good)));
            let mut over = good.clone();
            over[9].positions[0] = TRAJ_Q + 0.01;
            cases.push(("T1 last point 0.01 rad past max_position".into(), t(&over)));
            // Points inside the bounds whose cubic spline overshoots: a
            // fast reversal with large boundary velocities.
            let spline = vec![
                Point {
                    velocities: vec![0.0, 0.0, 0.0],
                    ..Point::at(0.0, &[1.9, 0.0, 0.5])
                },
                Point {
                    velocities: vec![1.4, 0.0, 0.0],
                    ..Point::at(1.0, &[1.95, 0.0, 0.5])
                },
                Point {
                    velocities: vec![0.0, 0.0, 0.0],
                    ..Point::at(2.0, &[1.9, 0.0, 0.5])
                },
            ];
            cases.push((
                "T2 points in bounds, spline overshoots past max_position".into(),
                t(&spline),
            ));
            let mut fast = good.clone();
            for p in &mut fast {
                p.velocities = vec![3.0, 0.0, 0.0];
            }
            cases.push(("T3 velocities 3 rad/s (limit 1.0)".into(), t(&fast)));
            let mut jump = good.clone();
            jump[5].positions[0] += 1.5; // 1.5 rad in 0.1 s
            cases.push((
                "T4 position jump between points (implied 15 rad/s)".into(),
                t(&jump),
            ));
            let mut rev = good.clone();
            rev.swap(3, 4);
            cases.push(("T5 time_from_start not increasing".into(), t(&rev)));
            let mut nan = good.clone();
            nan[2].positions[1] = f64::NAN;
            cases.push(("T6 NaN position".into(), t(&nan)));
            cases.push((
                "T7 future header.stamp (+1 h, delays the start)".into(),
                set_stamp(t(&good), now_s() as i32 + 3600, 0),
            ));
            cases.push((
                "T8 past header.stamp (-10 s, controller skips points)".into(),
                set_stamp(t(&good), now_s() as i32 - 10, 0),
            ));
            cases.push((
                "T9 stamp with nanosec >= 1e9".into(),
                set_stamp(t(&good), 1, 2_000_000_000),
            ));
            let names3 = ["shoulder_pan_joint", "shoulder_pan_joint", "elbow_joint"];
            cases.push((
                "T10 duplicate joint name".into(),
                encode(&names3, &good, false, None),
            ));
            let names_swapped = ["elbow_joint", "shoulder_lift_joint", "shoulder_pan_joint"];
            let mut sw = good.clone();
            for p in &mut sw {
                p.positions = vec![p.positions[2], p.positions[1], 2.5];
            }
            cases.push((
                "T11 joint order permuted, elbow at 2.5 (past max 2.0)".into(),
                encode(&names_swapped, &sw, false, None),
            ));
            let long: Vec<Point> = (0..300)
                .map(|i| Point::at(i as f64 * 0.01, &[0.0, 0.0, 0.5]))
                .collect();
            cases.push(("T12 300 points (max_points 64)".into(), t(&long)));
            let late: Vec<Point> = (0..3)
                .map(|i| Point::at(10.0 + 10.0 * i as f64, &[0.0, 0.0, 0.5]))
                .collect();
            cases.push((
                "T14 time_from_start 30 s (max_duration_s 20)".into(),
                t(&late),
            ));
            cases.push((
                "T15 valid trajectory, big-endian CDR".into(),
                encode(&TRAJ_JOINTS, &good, true, None),
            ));
            cases.push((
                "T16 future stamp AND an overshoot (stamp cannot hide it)".into(),
                set_stamp(t(&over), now_s() as i32 + 3600, 0),
            ));
            cases.push((
                "T13 same valid trajectory again with the SAME sn (replay)".into(),
                t(&good),
            ));
        }
        _ => {
            eprintln!("unknown attack {name}");
            std::process::exit(2);
        }
    }
    let mut results = Vec::new();
    for (i, (label, payload)) in cases.iter().enumerate() {
        let sn = if label.starts_with("T13") {
            base_sn + 1
        } else {
            base_sn + 1 + i as i64
        };
        let d = data_datagram(TRAJ_WRITER, sn, payload);
        let _ = tx.send_to(&d, dst);
        let until = Instant::now() + Duration::from_millis(300);
        let mut got: Vec<Vec<u8>> = Vec::new();
        while Instant::now() < until {
            if let Ok((_, x)) = r.rx.recv_timeout(Duration::from_millis(10)) {
                got.push(x);
            }
        }
        let verdict = match got.first() {
            None => "dropped".to_string(),
            Some(x) if x == &d => "forwarded byte-identical".to_string(),
            Some(x) => match classify(x) {
                Some((_, _, false)) | None => "DATA removed (no user DATA left)".into(),
                Some((_, _, true)) => {
                    let diff: Vec<usize> = x
                        .iter()
                        .zip(d.iter())
                        .enumerate()
                        .filter(|(_, (a, b))| a != b)
                        .map(|(i, _)| i)
                        .collect();
                    format!(
                        "forwarded modified ({} bytes differ, first at {:?})",
                        diff.len(),
                        diff.first()
                    )
                }
            },
        };
        let line = serde_json::json!({"case": label, "sn": sn, "verdict": verdict, "datagrams": got.len()});
        println!("{line}");
        results.push(line);
        std::thread::sleep(Duration::from_millis(150));
    }
    r.stop.store(true, Ordering::SeqCst);
    let _ = r.handle.join();
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.first().map(String::as_str) {
        Some("setup") if a.len() == 2 => setup(&a[1]),
        Some("soak") if a.len() >= 5 => soak(
            &a[1],
            &a[2],
            a[3].parse().expect("SECONDS"),
            &a[4],
            a.get(5)
                .map(|s| s.parse().expect("INJECT_EVERY_S"))
                .unwrap_or(600),
        ),
        Some("attack") if a.len() == 4 => attack(&a[1], &a[2], &a[3]),
        _ => {
            eprintln!("usage: soak_traffic setup DIR | soak CTRL ROB SECONDS STATS [EVERY] | attack CTRL ROB NAME");
            std::process::exit(2);
        }
    }
}
