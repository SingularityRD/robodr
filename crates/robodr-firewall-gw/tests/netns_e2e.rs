//! End-to-end test through a real kernel: three network namespaces
//! (controller -> bridge with the gateway -> robot), veth pairs, a Linux
//! bridge with `br_netfilter`, the ruleset rendered by
//! `robodr_firewall_gw::ruleset`, NFQUEUE, and the same run loop the binary
//! uses (`runtime::run`).
//!
//! Needs root, `ip`, `iptables` (nf_tables or legacy) and `nft`, and a
//! kernel with `nfnetlink_queue`, the xtables `NFQUEUE`, `physdev`, `CT`
//! and `conntrack` modules and bridge netfilter. Ignored by default; run
//! with
//!
//! ```text
//! cargo test -p robodr-firewall-gw --test netns_e2e -- --ignored --nocapture
//! ```
//!
//! It proves, on a G1 (humanoid, 35-slot `unitree_hg` `LowCmd_`) stream:
//! a valid frame arrives byte-identical; a violating frame arrives as the
//! hold of the last accepted frame (velocity targets zeroed, valid CRC,
//! same length); a foreign writer's frame arrives with its DATA turned into
//! a PAD; with the gateway stopped (`fail_closed`) nothing passes. It then
//! measures the added latency at 1 kHz and 500 Hz against the same stream
//! with the queue rule removed, and prints p50 / p99 / max.

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::os::fd::AsRawFd;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use robodr_cdr::Representation;
use robodr_firewall_gw::config::GatewayConfig;
use robodr_firewall_gw::lowcmd::{self, LowCmdCodec, WireLowCmd, WireMotor};
use robodr_firewall_gw::rtps::{self, Content, WalkOptions};
use robodr_firewall_gw::runtime::{self, RunOptions};
use robodr_firewall_gw::testkit::*;
use robodr_firewall_gw::{ruleset, sys, Gateway};

extern "C" {
    fn setns(fd: i32, nstype: i32) -> i32;
}
const CLONE_NEWNET: i32 = 0x4000_0000;

fn enter(ns: &str) {
    let f = std::fs::File::open(format!("/run/netns/{ns}")).expect("netns file");
    // SAFETY: a valid namespace fd; setns only affects the calling thread.
    let rc = unsafe { setns(f.as_raw_fd(), CLONE_NEWNET) };
    assert_eq!(rc, 0, "setns {ns}: {}", std::io::Error::last_os_error());
}

fn sh(cmd: &str) {
    let out = Command::new("sh").arg("-c").arg(cmd).output().expect("sh");
    assert!(
        out.status.success(),
        "`{cmd}` failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

struct Topology {
    ctrl: String,
    gw: String,
    rob: String,
    ctrl_port: String,
    rob_port: String,
}

impl Topology {
    fn new() -> Self {
        let id = std::process::id() % 100_000;
        let t = Topology {
            ctrl: format!("rgwc{id}"),
            gw: format!("rgwg{id}"),
            rob: format!("rgwr{id}"),
            ctrl_port: format!("gc{id}"),
            rob_port: format!("gr{id}"),
        };
        for ns in [&t.ctrl, &t.gw, &t.rob] {
            sh(&format!("ip netns add {ns}"));
        }
        sh(&format!(
            "ip link add c0 netns {} type veth peer name {} netns {}",
            t.ctrl, t.ctrl_port, t.gw
        ));
        sh(&format!(
            "ip link add r0 netns {} type veth peer name {} netns {}",
            t.rob, t.rob_port, t.gw
        ));
        sh(&format!("ip -n {g} link add br0 type bridge && ip -n {g} link set {c} master br0 && ip -n {g} link set {r} master br0", g = t.gw, c = t.ctrl_port, r = t.rob_port));
        for l in [t.ctrl_port.as_str(), t.rob_port.as_str(), "br0", "lo"] {
            sh(&format!("ip -n {} link set {l} up", t.gw));
        }
        sh(&format!("ip -n {} addr add {}/24 dev c0 && ip -n {0} link set c0 up && ip -n {0} link set lo up", t.ctrl, CONTROLLER_IP));
        sh(&format!("ip -n {} addr add {}/24 dev r0 && ip -n {0} link set r0 up && ip -n {0} link set lo up", t.rob, ROBOT_IP));
        t
    }
}

impl Drop for Topology {
    fn drop(&mut self) {
        for ns in [&self.ctrl, &self.gw, &self.rob] {
            let _ = Command::new("ip").args(["netns", "del", ns]).status();
        }
    }
}

/// A received datagram: monotonic receive time and bytes.
type Rx = (u64, Vec<u8>);

fn sn_of(d: &[u8]) -> Option<i64> {
    let mut v = Vec::new();
    rtps::walk(d, WalkOptions::default(), &mut v).ok()?;
    v.first().map(|s| s.sn)
}

fn lowcmd_of(d: &[u8]) -> Option<WireLowCmd> {
    let mut v = Vec::new();
    rtps::walk(d, WalkOptions::default(), &mut v).ok()?;
    let s = v.iter().find(|s| s.content == Content::Data)?;
    let dec = lowcmd::decode_strict(&d[s.payload.clone()?], LowCmdCodec::Hg).ok()?;
    assert!(dec.msg.crc_ok());
    Some(dec.msg)
}

fn quantiles(mut v: Vec<u64>) -> (u64, u64, u64, usize) {
    v.sort_unstable();
    if v.is_empty() {
        return (0, 0, 0, 0);
    }
    let q = |p: f64| v[((v.len() as f64 * p).ceil() as usize).clamp(1, v.len()) - 1];
    (q(0.5), q(0.99), *v.last().unwrap(), v.len())
}

#[test]
#[ignore = "needs root, network namespaces, iptables + nft and nfnetlink_queue; run with --ignored"]
fn inline_bridge_end_to_end() {
    let topo = Topology::new();
    let fx = Fixture::G1;
    let mut cfg: GatewayConfig = gateway_config(fx);
    cfg.queue.num = 7;
    cfg.queue.controller_port = topo.ctrl_port.clone();
    cfg.queue.robot_port = topo.rob_port.clone();
    cfg.housekeeping_ms = 50;
    let script = ruleset::render(&cfg, "netns_e2e");
    let script_path = std::env::temp_dir().join(format!("robodr-gw-e2e-{}.sh", std::process::id()));
    std::fs::write(&script_path, &script).unwrap();
    let apply = format!("ip netns exec {} sh {}", topo.gw, script_path.display());
    sh(&apply);

    // Receiver on the robot side.
    let stop_rx = Arc::new(AtomicBool::new(false));
    let (tx_rx, rx_rx) = mpsc::channel::<Rx>();
    let rob = topo.rob.clone();
    let s2 = stop_rx.clone();
    let receiver = std::thread::spawn(move || {
        enter(&rob);
        let s = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DDS_PORT)).unwrap();
        s.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
        let mut buf = vec![0u8; 65_536];
        while !s2.load(Ordering::SeqCst) {
            if let Ok((n, _)) = s.recv_from(&mut buf) {
                let t = sys::monotonic_ns();
                let _ = tx_rx.send((t, buf[..n].to_vec()));
            }
        }
    });

    // The gateway, in the bridge namespace, on the real queue.
    let stop_gw = Arc::new(AtomicBool::new(false));
    let gwns = topo.gw.clone();
    let s3 = stop_gw.clone();
    let gcfg = cfg.clone();
    let gw_thread = std::thread::spawn(move || {
        enter(&gwns);
        // The G1 example is written for a 500 Hz loop (min interval 1 ms);
        // this test also streams at 1 kHz, so widen the rate window.
        let mut fw = firewall(Fixture::G1);
        if let Some(j) = fw.joint_channels.get_mut("/lowcmd") {
            j.rate = Some(robodr_firewall::JointRate {
                expected_hz: 1000.0,
                min_interval_ns: 400_000,
                max_interval_ns: 10_000_000,
            });
        }
        let mut gw = Gateway::new(&gcfg, &profile(Fixture::G1), &fw).unwrap();
        let opts = RunOptions {
            max_packets: None,
            max_duration: Some(Duration::from_secs(120)),
        };
        let r = runtime::run(&gcfg, &mut gw, opts, &|| s3.load(Ordering::SeqCst));
        (r, gw.stats)
    });
    std::thread::sleep(Duration::from_millis(500));

    // Sender on the controller side (this thread).
    enter(&topo.ctrl);
    let tx = UdpSocket::bind(SocketAddrV4::new(CONTROLLER_IP, 0)).unwrap();
    let dst = SocketAddrV4::new(ROBOT_IP, DDS_PORT);
    let send = |d: &[u8]| {
        tx.send_to(d, dst).unwrap();
    };
    let drain = |wait: Duration| -> Vec<Rx> {
        let mut v = Vec::new();
        let until = Instant::now() + wait;
        while Instant::now() < until {
            if let Ok(x) = rx_rx.recv_timeout(Duration::from_millis(10)) {
                v.push(x);
            }
        }
        v
    };
    let spec = lowcmd_spec(fx);
    let pins = (spec.pinned_mode_pr, spec.pinned_mode_machine);
    let spare = spec.motors.iter().position(|m| !m.enabled).unwrap();
    let frame = |phase: f64| mid_frame(LowCmdCodec::Hg, &spec.motors, phase, pins);

    // --- Phase A: correctness through the kernel --------------------------
    let mut good = frame(0.0);
    let mut w = good.motor(0).unwrap();
    w.dq = 0.5;
    good.set_motor(0, w);
    good.seal();
    let d1 = lowcmd_datagram(PREFIX, WRITER, 1, &good, Representation::CdrLe);
    send(&d1);
    let got = drain(Duration::from_millis(150));
    assert_eq!(got.len(), 1, "valid frame forwarded");
    assert_eq!(got[0].1, d1, "valid frame forwarded byte-identical");

    let mut bad = good;
    bad.set_motor(
        spare,
        WireMotor {
            mode: 1,
            kp: 40.0,
            ..Default::default()
        },
    );
    bad.seal();
    let d2 = lowcmd_datagram(PREFIX, WRITER, 2, &bad, Representation::CdrLe);
    send(&d2);
    let got = drain(Duration::from_millis(150));
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].1.len(), d2.len(), "same length");
    let held = lowcmd_of(&got[0].1).expect("a hold, CRC valid");
    let mut expect = good;
    let mut w = expect.motor(0).unwrap();
    w.dq = 0.0;
    expect.set_motor(0, w);
    expect.seal();
    assert_eq!(
        held, expect,
        "violating frame replaced by the hold of the last accepted frame (dq = 0)"
    );

    let d3 = lowcmd_datagram(FOREIGN, WRITER, 1, &good, Representation::CdrLe);
    send(&d3);
    let got = drain(Duration::from_millis(150));
    assert_eq!(got.len(), 1, "datagram forwarded with the sample removed");
    assert!(
        lowcmd_of(&got[0].1).is_none(),
        "foreign writer's sample suppressed (PAD)"
    );
    println!("phase A ok: pass byte-identical, hold on violation, foreign suppressed");

    // --- Phase B: latency through the gateway at 1 kHz and 500 Hz ---------
    let stream = |first_sn: i64, n: i64, period: Duration, violate_every: i64| -> Vec<u64> {
        let mut sent: Vec<(i64, u64)> = Vec::new();
        let start = Instant::now();
        let mut last_send = start;
        for i in 0..n {
            // Paced like a control loop that never catches up in a burst:
            // after an oversleep (this is not an RT host) the next frame
            // still keeps 0.75 periods from the previous one, as the
            // firewall's rate window (min interval 0.4 ms) requires.
            let target = (start + period * i as u32).max(last_send + period.mul_f64(0.75));
            while Instant::now() + Duration::from_micros(80) < target {
                std::thread::sleep(Duration::from_micros(50));
            }
            while Instant::now() < target {
                std::hint::spin_loop();
            }
            let sn = first_sn + i;
            let mut f = frame(sn as f64 * 0.001);
            if violate_every > 0 && i % violate_every == violate_every - 1 {
                // A torque over tau_max inside the hard factor: limited.
                let mut w = f.motor(0).unwrap();
                w.tau = (spec.motors[0].tau_max.unwrap() * 1.3) as f32;
                f.set_motor(0, w);
                f.seal();
            }
            let d = lowcmd_datagram(PREFIX, WRITER, sn, &f, Representation::CdrLe);
            let t = sys::monotonic_ns();
            send(&d);
            last_send = Instant::now();
            sent.push((sn, t));
        }
        let got = drain(Duration::from_millis(300));
        let mut lat = Vec::new();
        for (t, d) in got {
            if let Some(sn) = sn_of(&d) {
                if let Some((_, ts)) = sent.iter().find(|(s, _)| *s == sn) {
                    lat.push(t.saturating_sub(*ts));
                }
            }
        }
        lat
    };
    let mut sn = 100;
    let gw_1k = stream(sn, 3000, Duration::from_millis(1), 33);
    sn += 3000;
    let gw_500 = stream(sn, 1500, Duration::from_millis(2), 33);
    sn += 1500;
    // Baseline: the same traffic with the queue rule removed.
    sh(&format!("ip netns exec {} iptables -F ROBODR_GW", topo.gw));
    let base_1k = stream(sn, 3000, Duration::from_millis(1), 0);
    sn += 3000;
    let base_500 = stream(sn, 1500, Duration::from_millis(2), 0);
    sn += 1500;
    sh(&apply);
    let report = |name: &str, v: &[u64]| {
        let (p50, p99, max, n) = quantiles(v.to_vec());
        println!(
            "{name:<28} n={n:>5}  p50 {:>7.1} us  p99 {:>7.1} us  max {:>8.1} us",
            p50 as f64 / 1e3,
            p99 as f64 / 1e3,
            max as f64 / 1e3
        );
        (p50, p99, max, n)
    };
    let g1 = report("gateway 1 kHz (35 motors)", &gw_1k);
    let g5 = report("gateway 500 Hz (35 motors)", &gw_500);
    let b1 = report("baseline 1 kHz (no queue)", &base_1k);
    let b5 = report("baseline 500 Hz (no queue)", &base_500);
    println!(
        "added latency: 1 kHz p50 {:.1} us, p99 {:.1} us; 500 Hz p50 {:.1} us, p99 {:.1} us",
        (g1.0 as f64 - b1.0 as f64) / 1e3,
        (g1.1 as f64 - b1.1 as f64) / 1e3,
        (g5.0 as f64 - b5.0 as f64) / 1e3,
        (g5.1 as f64 - b5.1 as f64) / 1e3
    );
    // --- Phase D: gateway stopped, fail_closed ----------------------------
    stop_gw.store(true, Ordering::SeqCst);
    let (r, stats) = gw_thread.join().unwrap();
    let r = r.expect("gateway run loop");
    println!(
        "gateway loop: {} packets ({} kernel-stamped), recv->verdict p50 {} ns, p99 {} ns, max {} ns; {:?}",
        r.packets,
        r.stamped,
        r.latency.quantile_ns(0.5),
        r.latency.quantile_ns(0.99),
        r.latency.max_ns,
        stats
    );
    let d = lowcmd_datagram(PREFIX, WRITER, sn, &frame(0.0), Representation::CdrLe);
    send(&d);
    let got = drain(Duration::from_millis(300));
    assert!(
        got.is_empty(),
        "fail_closed: nothing passes while the gateway is down"
    );
    println!("phase D ok: fail_closed while the gateway is down");
    assert!(
        stats.limited >= 100,
        "limited frames rewritten in the stream"
    );
    // Every frame of the streams went through (limited ones rewritten). A
    // frame the gateway reads more than `max_queue_delay_ns` after its
    // arrival gets the fault verdict (a hold, or nothing inside the
    // substitute interval), so allow 0.5 % on this shared, non-RT machine.
    assert!(
        g1.3 >= 2985 && g5.3 >= 1492,
        "frames lost through the gateway: {} / {}",
        g1.3,
        g5.3
    );

    stop_rx.store(true, Ordering::SeqCst);
    receiver.join().unwrap();
    let _ = std::fs::remove_file(&script_path);
    drop(topo);
}
