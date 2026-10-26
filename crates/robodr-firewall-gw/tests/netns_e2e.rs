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
    /// An attacker on the controller-side segment (macvlan on the
    /// controller's link: its own MAC), if requested.
    atk: Option<String>,
    ctrl_port: String,
    rob_port: String,
}

impl Topology {
    fn new(tag: char, attacker: bool) -> Self {
        let id = std::process::id() % 100_000;
        let t = Topology {
            ctrl: format!("rgwc{tag}{id}"),
            gw: format!("rgwg{tag}{id}"),
            rob: format!("rgwr{tag}{id}"),
            atk: attacker.then(|| format!("rgwa{tag}{id}")),
            ctrl_port: format!("gc{tag}{id}"),
            rob_port: format!("gr{tag}{id}"),
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
        if let Some(a) = &t.atk {
            sh(&format!("ip netns add {a}"));
            sh(&format!(
                "ip -n {c} link add link c0 name m0 type macvlan mode bridge && ip -n {c} link set m0 netns {a}",
                c = t.ctrl
            ));
            sh(&format!("ip -n {a} addr add {ATTACKER_IP}/24 dev m0 && ip -n {a} link set m0 up && ip -n {a} link set lo up"));
        }
        t
    }
}

impl Drop for Topology {
    fn drop(&mut self) {
        for ns in [
            Some(&self.ctrl),
            Some(&self.gw),
            Some(&self.rob),
            self.atk.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
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
    let topo = Topology::new('l', false);
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
    // Continue the writer's sequence (phase A used 1 and 2): a jump past
    // `rtps.max_sn_jump` would be held back until confirmed (one frame).
    let mut sn = 3;
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

/// Review finding F1 through the real kernel path: an attacker on the
/// controller-side segment injects a DATA with the motion writer's GUID and
/// a far-future sequence number, first from its own IP, then spoofing the
/// controller's IP (with its own MAC: the kernel reports it in
/// `NFQA_HWADDR`). The robot never receives the spoofed sample, and every
/// genuine frame before and after it arrives byte-identical (before the fix
/// all later genuine frames were suppressed as "replays"). Also checks that
/// SEDP from the controller side is queued, learned and forwarded
/// unchanged.
#[test]
#[ignore = "needs root, network namespaces, iptables + nft and nfnetlink_queue; run with --ignored"]
fn spoofed_future_sequence_number_does_not_stop_the_stream() {
    let topo = Topology::new('s', true);
    let atk_ns = topo.atk.clone().unwrap();
    let fx = Fixture::G1;
    let mut cfg: GatewayConfig = gateway_config(fx);
    cfg.queue.num = 8;
    cfg.queue.controller_port = topo.ctrl_port.clone();
    cfg.queue.robot_port = topo.rob_port.clone();
    cfg.housekeeping_ms = 50;
    cfg.channels[0].allowed_src_ips = vec![CONTROLLER_IP.to_string()];
    let script = ruleset::render(&cfg, "netns_e2e_f1");
    let script_path =
        std::env::temp_dir().join(format!("robodr-gw-e2e-f1-{}.sh", std::process::id()));
    std::fs::write(&script_path, &script).unwrap();
    sh(&format!(
        "ip netns exec {} sh {}",
        topo.gw,
        script_path.display()
    ));

    // Receiver on the robot side: user port and SEDP unicast port.
    let stop_rx = Arc::new(AtomicBool::new(false));
    let (tx_rx, rx_rx) = mpsc::channel::<(u16, Vec<u8>)>();
    let rob = topo.rob.clone();
    let s2 = stop_rx.clone();
    let receiver = std::thread::spawn(move || {
        enter(&rob);
        let socks: Vec<(u16, UdpSocket)> = [DDS_PORT, 7410]
            .into_iter()
            .map(|p| {
                let s = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, p)).unwrap();
                s.set_nonblocking(true).unwrap();
                (p, s)
            })
            .collect();
        let mut buf = vec![0u8; 65_536];
        while !s2.load(Ordering::SeqCst) {
            let mut got = false;
            for (p, s) in &socks {
                if let Ok((n, _)) = s.recv_from(&mut buf) {
                    let _ = tx_rx.send((*p, buf[..n].to_vec()));
                    got = true;
                }
            }
            if !got {
                std::thread::sleep(Duration::from_micros(200));
            }
        }
    });

    let stop_gw = Arc::new(AtomicBool::new(false));
    let gwns = topo.gw.clone();
    let s3 = stop_gw.clone();
    let gcfg = cfg.clone();
    let gw_thread = std::thread::spawn(move || {
        enter(&gwns);
        let mut gw = Gateway::new(&gcfg, &profile(Fixture::G1), &firewall(Fixture::G1)).unwrap();
        let opts = RunOptions {
            max_packets: None,
            max_duration: Some(Duration::from_secs(60)),
        };
        let r = runtime::run(&gcfg, &mut gw, opts, &|| s3.load(Ordering::SeqCst));
        (r, gw.stats)
    });
    std::thread::sleep(Duration::from_millis(500));

    // The attacker's sender, in its own namespace (own MAC).
    let (atk_tx, atk_rx) = mpsc::channel::<(Ipv4Addr, Vec<u8>)>();
    let (atk_done_tx, atk_done) = mpsc::channel::<()>();
    let atk_thread = std::thread::spawn(move || {
        enter(&atk_ns);
        while let Ok((ip, d)) = atk_rx.recv() {
            if ip != ATTACKER_IP {
                // Spoof the controller's IP on the attacker's own link.
                sh(&format!(
                    "ip -n {atk_ns} addr flush dev m0 && ip -n {atk_ns} addr add {ip}/24 dev m0"
                ));
            }
            let s = UdpSocket::bind(SocketAddrV4::new(ip, 0)).unwrap();
            s.send_to(&d, SocketAddrV4::new(ROBOT_IP, DDS_PORT))
                .unwrap();
            let _ = atk_done_tx.send(());
        }
    });

    enter(&topo.ctrl);
    let tx = UdpSocket::bind(SocketAddrV4::new(CONTROLLER_IP, 0)).unwrap();
    let spec = lowcmd_spec(fx);
    let pins = (spec.pinned_mode_pr, spec.pinned_mode_machine);
    let frame = |sn: i64| mid_frame(LowCmdCodec::Hg, &spec.motors, sn as f64 * 0.001, pins);
    let mut sent: Vec<Vec<u8>> = Vec::new();
    let mut stream = |from: i64, to: i64| {
        for sn in from..=to {
            let d = lowcmd_datagram(PREFIX, WRITER, sn, &frame(sn), Representation::CdrLe);
            tx.send_to(&d, SocketAddrV4::new(ROBOT_IP, DDS_PORT))
                .unwrap();
            sent.push(d);
            std::thread::sleep(Duration::from_millis(2));
        }
    };
    let drain = |wait: Duration| -> Vec<(u16, Vec<u8>)> {
        let mut v = Vec::new();
        let until = Instant::now() + wait;
        while Instant::now() < until {
            if let Ok(x) = rx_rx.recv_timeout(Duration::from_millis(10)) {
                v.push(x);
            }
        }
        v
    };
    // SEDP from the controller side: queued, learned, forwarded unchanged.
    let sedp = sedp_datagram(
        PREFIX,
        WRITER,
        "rt/lowcmd",
        "unitree_hg::msg::dds_::LowCmd_",
    );
    tx.send_to(&sedp, SocketAddrV4::new(ROBOT_IP, 7410))
        .unwrap();
    let got = drain(Duration::from_millis(150));
    assert_eq!(got, vec![(7410, sedp.clone())], "SEDP forwarded unchanged");

    stream(1, 50);
    let evil = lowcmd_datagram(PREFIX, WRITER, 1 << 40, &frame(0), Representation::CdrLe);
    atk_tx.send((ATTACKER_IP, evil.clone())).unwrap();
    atk_done.recv().unwrap();
    std::thread::sleep(Duration::from_millis(20));
    stream(51, 150);
    atk_tx.send((CONTROLLER_IP, evil.clone())).unwrap();
    atk_done.recv().unwrap();
    std::thread::sleep(Duration::from_millis(20));
    stream(151, 250);
    let got = drain(Duration::from_millis(300));
    drop(atk_tx);
    atk_thread.join().unwrap();

    let mut genuine = Vec::new();
    let mut spoofed = 0;
    for (port, d) in &got {
        assert_eq!(*port, DDS_PORT);
        let mut v = Vec::new();
        rtps::walk(d, WalkOptions::default(), &mut v).unwrap();
        if v.is_empty() {
            spoofed += 1; // the spoofed datagram, its DATA turned into a PAD
            assert_eq!(d.len(), evil.len());
            continue;
        }
        assert!(
            v.iter().all(|s| s.sn < 1 << 40),
            "spoofed SN reached the robot"
        );
        genuine.push(d.clone());
    }
    assert_eq!(
        spoofed, 2,
        "both spoofed datagrams forwarded without their sample"
    );
    assert_eq!(
        genuine.len(),
        sent.len(),
        "every genuine frame before and after the injection arrived"
    );
    assert_eq!(genuine, sent, "byte-identical, in order");

    stop_gw.store(true, Ordering::SeqCst);
    let (r, stats) = gw_thread.join().unwrap();
    r.expect("gateway run loop");
    println!("F1 e2e gateway stats: {stats:?}");
    assert!(
        stats.discovery_datagrams >= 1,
        "SEDP was queued and learned"
    );
    assert!(
        stats.binding_conflicts >= 1,
        "the spoofed-IP frame was told apart by its MAC (NFQA_HWADDR reported)"
    );
    stop_rx.store(true, Ordering::SeqCst);
    receiver.join().unwrap();
    let _ = std::fs::remove_file(&script_path);
    drop(topo);
}

/// The channels added after S8 through the real kernel path: a G1 with
/// `/lowcmd`, `rt/arm_sdk`, loco on `rt/api/sport/request`, a Dex3 hand, the
/// hand SDK and a ROS 2 `/cmd_vel`, plus an extra queued port range
/// (non-default DDS ports). A too-fast `SetVelocity` arrives limited and
/// with its duration capped, `Damp` arrives as a PAD (the humanoid never
/// goes limp), `Start` byte-identical, an SDK-style arm frame (mode 0 +
/// gains) byte-identical, an out-of-envelope hand frame as a PAD, a
/// too-fast twist limited; a `Damp` to a port in `rtps.extra_port_ranges`
/// is decided, one to a port outside every range is not (the bypass the
/// warning is for), and an SEDP reader of `rt/lowcmd` announcing that port
/// sets the status flag `port_bypass_risk`.
#[test]
#[ignore = "needs root, network namespaces, iptables + nft and nfnetlink_queue; run with --ignored"]
fn new_channels_and_extra_ports_end_to_end() {
    use robodr_cdr::unitree::{ApiService, UnitreeModel};
    use robodr_cdr::ApiCall;
    use robodr_firewall_gw::config::Codec;
    use robodr_firewall_gw::{hand, ros2, sport};

    let topo = Topology::new('n', false);
    let status =
        std::env::temp_dir().join(format!("robodr-gw-e2e-status-{}.json", std::process::id()));
    let mut cfg = g1_channels_config(|v| {
        v["rtps"] = serde_json::json!({"extra_port_ranges": [[30000, 30100]]});
        // `Start` needs the allowlist (F10 e); the arm stream may engage in
        // one frame (the SDK example) when `rt/lowstate` agrees (F1).
        v["channels"][2]["allowed_fsm_ids"] = serde_json::json!([500]);
        v["channels"][1]["max_weight_step"] = serde_json::json!(1.0);
        v["channels"][1]["max_weight_rate_per_s"] = serde_json::json!(1000.0);
    });
    cfg.queue.num = 9;
    cfg.queue.controller_port = topo.ctrl_port.clone();
    cfg.queue.robot_port = topo.rob_port.clone();
    cfg.housekeeping_ms = 50;
    cfg.status_path = Some(status.clone());
    cfg.observe.nflog_group = 4100 + (std::process::id() % 1000) as u16;
    let script = ruleset::render(&cfg, "netns_e2e");
    assert!(script.contains("--dport 30000:30100 -j NFQUEUE"));
    assert!(script.contains("-j NFLOG --nflog-group"));
    let script_path =
        std::env::temp_dir().join(format!("robodr-gw-e2e-n-{}.sh", std::process::id()));
    std::fs::write(&script_path, &script).unwrap();
    sh(&format!(
        "ip netns exec {} sh {}",
        topo.gw,
        script_path.display()
    ));

    const EXTRA: u16 = 30050;
    const OUTSIDE: u16 = 31000;
    let stop_rx = Arc::new(AtomicBool::new(false));
    let (tx_rx, rx_rx) = mpsc::channel::<(u16, Vec<u8>)>();
    let rob = topo.rob.clone();
    let s2 = stop_rx.clone();
    let receiver = std::thread::spawn(move || {
        enter(&rob);
        let socks: Vec<(u16, UdpSocket)> = [DDS_PORT, EXTRA, OUTSIDE]
            .into_iter()
            .map(|p| {
                let s = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, p)).unwrap();
                s.set_read_timeout(Some(Duration::from_millis(5))).unwrap();
                (p, s)
            })
            .collect();
        let mut buf = vec![0u8; 65_536];
        while !s2.load(Ordering::SeqCst) {
            for (p, s) in &socks {
                if let Ok((n, _)) = s.recv_from(&mut buf) {
                    let _ = tx_rx.send((*p, buf[..n].to_vec()));
                }
            }
        }
    });
    let stop_gw = Arc::new(AtomicBool::new(false));
    let gwns = topo.gw.clone();
    let s3 = stop_gw.clone();
    let gcfg = cfg.clone();
    let gw_thread = std::thread::spawn(move || {
        enter(&gwns);
        let mut gw = Gateway::new(&gcfg, &g1_channels_profile(), &g1_channels_firewall()).unwrap();
        let opts = RunOptions {
            max_packets: None,
            max_duration: Some(Duration::from_secs(60)),
        };
        let r = runtime::run(&gcfg, &mut gw, opts, &|| s3.load(Ordering::SeqCst));
        (r, gw.stats)
    });
    std::thread::sleep(Duration::from_millis(500));

    enter(&topo.ctrl);
    let tx = UdpSocket::bind(SocketAddrV4::new(CONTROLLER_IP, 0)).unwrap();
    let send = |port: u16, d: &[u8]| {
        tx.send_to(d, SocketAddrV4::new(ROBOT_IP, port)).unwrap();
    };
    let one = |port: u16| -> Vec<u8> {
        let until = Instant::now() + Duration::from_millis(300);
        let mut got = Vec::new();
        while Instant::now() < until {
            if let Ok((p, d)) = rx_rx.recv_timeout(Duration::from_millis(10)) {
                assert_eq!(p, port, "arrived on the port it was sent to");
                got.push(d);
            }
        }
        assert_eq!(got.len(), 1, "exactly one datagram on {port}");
        got.remove(0)
    };
    let payload = |d: &[u8]| -> Option<Vec<u8>> {
        let mut v = Vec::new();
        rtps::walk(d, WalkOptions::default(), &mut v).ok()?;
        let s = v.iter().find(|s| s.content == Content::Data)?;
        Some(d[s.payload.clone()?].to_vec())
    };
    // Classify every writer (SEDP crosses the bridge, queued and learned).
    for (w, topic, ty) in [
        (ARM_WRITER, "rt/arm_sdk", "unitree_hg::msg::dds_::LowCmd_"),
        (
            LOCO_WRITER,
            "rt/api/sport/request",
            "unitree_api::msg::dds_::Request_",
        ),
        (
            DEX3_WRITER,
            "rt/dex3/left/cmd",
            "unitree_hg::msg::dds_::HandCmd_",
        ),
        (
            TWIST_WRITER,
            "rt/cmd_vel",
            "geometry_msgs::msg::dds_::Twist_",
        ),
    ] {
        send(7410, &sedp_datagram(PREFIX, w, topic, ty));
    }
    std::thread::sleep(Duration::from_millis(200));
    let req = |id: i64, p: &str| sport::encode_request(Representation::CdrLe, 1, id, p);
    let call = |p: &[u8]| {
        sport::decode_strict_for(p, ApiService::Sport, Some(UnitreeModel::G1))
            .unwrap()
            .call
    };

    // Loco: too fast and continuous → limited, duration 1 s.
    let d = data_datagram(
        LOCO_WRITER,
        1,
        &req(7105, "{\"duration\":864000.0,\"velocity\":[2.5,0.0,0.0]}"),
    );
    send(DDS_PORT, &d);
    let got = one(DDS_PORT);
    assert_eq!(got.len(), d.len());
    match call(&payload(&got).expect("limited, not removed")) {
        ApiCall::SetVelocity { vx, duration, .. } => {
            assert!(vx <= TWIST_MAX_LIN && duration <= 1.0, "{vx} {duration}");
        }
        c => panic!("{c:?}"),
    }
    std::thread::sleep(Duration::from_millis(30));
    // Damp: removed. Start: byte-identical.
    send(
        DDS_PORT,
        &data_datagram(LOCO_WRITER, 2, &req(7101, "{\"data\":1}")),
    );
    assert!(
        payload(&one(DDS_PORT)).is_none(),
        "Damp never reaches the robot"
    );
    std::thread::sleep(Duration::from_millis(30));
    let start = data_datagram(LOCO_WRITER, 3, &req(7101, "{\"data\":500}"));
    send(DDS_PORT, &start);
    assert_eq!(one(DDS_PORT), start, "Start byte-identical");

    // Arm SDK (mode 0 + gains, weight 1 at once, SDK style): without the
    // robot's joint state the engagement cannot be verified → removed.
    let arm = |sn| {
        data_datagram(
            ARM_WRITER,
            sn,
            &lowcmd::encode_payload(&arm_frame(1.0, 0.0), Representation::CdrLe),
        )
    };
    send(DDS_PORT, &arm(1));
    assert!(
        payload(&one(DDS_PORT)).is_none(),
        "arm engagement without rt/lowstate removed"
    );
    // The robot publishes rt/lowstate (500 Hz, fragmented like Cyclone's
    // 2 KB `LowState_`) with its arms where the frame's targets are, and
    // announces a reader of rt/lowcmd at a port no rule queues. The gateway
    // sees both only as NFLOG copies.
    let stop_ls = Arc::new(AtomicBool::new(false));
    let s4 = stop_ls.clone();
    let robns = topo.rob.clone();
    let target = arm_frame(1.0, 0.0);
    let q: Vec<f32> = (0..35)
        .map(|i| target.motor(i).map_or(0.0, |m| m.q))
        .collect();
    let ls_thread = std::thread::spawn(move || {
        enter(&robns);
        let s = UdpSocket::bind(SocketAddrV4::new(ROBOT_IP, 0)).unwrap();
        let to = SocketAddrV4::new(CONTROLLER_IP, 7411);
        let reader = sedp_with_locator(
            ROBOT_PREFIX,
            [0, 0, 0x11, 0x04],
            "rt/lowcmd",
            "unitree_hg::msg::dds_::LowCmd_",
            true,
            ROBOT_IP,
            45999,
        );
        s.send_to(&reader, SocketAddrV4::new(CONTROLLER_IP, 7410))
            .unwrap();
        let mut sn = 0;
        while !s4.load(Ordering::SeqCst) {
            sn += 1;
            for d in lowstate_datagram(sn, &q, Some(1024)) {
                let _ = s.send_to(&d, to);
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    });
    std::thread::sleep(Duration::from_millis(300));
    let a2 = arm(2);
    send(DDS_PORT, &a2);
    assert_eq!(
        one(DDS_PORT),
        a2,
        "arm frame byte-identical (engagement verified)"
    );

    // Dex3: out of the finger envelope → removed.
    let fingers: Vec<_> = (0..DEX3_MOTORS)
        .map(|i| ((i as u8) | 0x10, 3.0f32, 0.0, 0.0, 2.0, 0.1))
        .collect();
    send(
        DDS_PORT,
        &data_datagram(
            DEX3_WRITER,
            1,
            &hand::encode(Codec::UnitreeDex3HandCmd, &fingers),
        ),
    );
    assert!(payload(&one(DDS_PORT)).is_none(), "hand frame removed");

    // ROS 2 twist: limited in place.
    send(
        DDS_PORT,
        &data_datagram(
            TWIST_WRITER,
            1,
            &ros2::encode([2.0, 0.0, 0.0, 0.0, 0.0, 0.0], None, false),
        ),
    );
    let w = ros2::decode_strict(&payload(&one(DDS_PORT)).unwrap(), false).unwrap();
    assert!(w.values[0] <= TWIST_MAX_LIN, "{:?}", w.values);

    // Extra port range: decided. Outside every range: not queued.
    std::thread::sleep(Duration::from_millis(30));
    send(
        EXTRA,
        &data_datagram(LOCO_WRITER, 4, &req(7101, "{\"data\":0}")),
    );
    assert!(
        payload(&one(EXTRA)).is_none(),
        "ZeroTorque on an extra port removed"
    );
    let around = data_datagram(LOCO_WRITER, 5, &req(7101, "{\"data\":0}"));
    send(OUTSIDE, &around);
    assert_eq!(
        one(OUTSIDE),
        around,
        "a port outside every queued range bypasses the gateway"
    );
    // ... which the deployment check reports when discovery shows it.
    send(
        7410,
        &sedp_with_locator(
            [9; 12],
            [0, 0, 1, 4],
            "rt/lowcmd",
            "unitree_hg::msg::dds_::LowCmd_",
            true,
            ROBOT_IP,
            u32::from(OUTSIDE),
        ),
    );
    let until = Instant::now() + Duration::from_secs(3);
    let mut flagged = false;
    while Instant::now() < until && !flagged {
        std::thread::sleep(Duration::from_millis(100));
        if let Ok(t) = std::fs::read_to_string(&status) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&t) {
                flagged = v["port_bypass_risk"] == true
                    && v["discovery"]["unqueued_locators"].as_u64() >= Some(1);
            }
        }
    }
    assert!(flagged, "status flag port_bypass_risk set");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&status).unwrap()).unwrap();
    assert!(
        v["discovery"]["robot_unqueued_locators"].as_u64() >= Some(1),
        "robot-side reader flagged: {v}"
    );
    assert!(v["observer"]["lowstate_samples"].as_u64() >= Some(1), "{v}");
    assert_eq!(v["observe_unavailable"], false);
    stop_ls.store(true, Ordering::SeqCst);
    ls_thread.join().unwrap();

    stop_gw.store(true, Ordering::SeqCst);
    let (r, stats) = gw_thread.join().unwrap();
    r.expect("gateway run loop");
    println!("new-channels e2e gateway stats: {stats:?}");
    assert!(stats.loco_refused >= 2 && stats.duration_capped >= 1 && stats.hand_suppressed >= 1);
    stop_rx.store(true, Ordering::SeqCst);
    receiver.join().unwrap();
    let _ = std::fs::remove_file(&script_path);
    let _ = std::fs::remove_file(&status);
    drop(topo);
}
