//! The executor against **real nftables** in isolated network namespaces.
//!
//! Each test builds two namespaces joined by a veth pair: `robot`
//! (10.99.0.1, where the executor installs its rules, through
//! `ip netns exec <robot> nft`) and `peer` (10.99.0.2 "other host",
//! 10.99.0.10 "management", 10.99.0.20 "motion path", 10.99.0.7 "rogue
//! participant"), and sends real UDP datagrams between them. Nothing runs in
//! the host's own namespace.
//!
//! Needs root, `ip` (iproute2) and `nft`. Without them every test prints
//! `SKIPPED` and passes, unless `ROBODR_REQUIRE_NETNS=1` (then they fail).

use std::ffi::OsString;
use std::io::{BufRead, BufReader};
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use robodr_executor::client::Client;
use robodr_executor::config::ExecutorConfig;
use robodr_executor::decision::{codes, Current};
use robodr_executor::engine::{Engine, FixedSafety, Status};
use robodr_executor::nft::{self, NftCommand};
use robodr_executor::order::{Locator, Order, Origin, Target};
use robodr_executor::proto::Key;
use robodr_responder::{
    ActionId, Connectivity, ControlMode, MissionPhase, Morphology, OperationalContext,
    PlatformFamily, ResponsePolicy, RestrictTarget, SafetyState,
};
use serde_json::{json, Value};

const ROBOT: &str = "10.99.0.1";
const OTHER: &str = "10.99.0.2";
const MGMT: &str = "10.99.0.10";
const MOTION: &str = "10.99.0.20";
const ROGUE: &str = "10.99.0.7";
const GUID: &str = "0110a2b3c4d5e6f701000000";
const OTHER_GUID: &str = "0110a2b3c4d5e6f702000000";
const HELPER_ENV: &str = "ROBODR_NETNS_HELPER";
const IP: &str = "/usr/sbin/ip";
const NFT: &str = "/usr/sbin/nft";

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn sh(args: &[&str]) -> Result<String, String> {
    let out = Command::new(args[0])
        .args(&args[1..])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("{}: {e}", args[0]))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!(
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Two namespaces and a veth pair (plus an optional third namespace
/// `far`); removed on drop.
struct Lab {
    robot: String,
    peer: String,
    far: Option<String>,
    dir: PathBuf,
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = sh(&["ip", "netns", "del", &self.robot]);
        let _ = sh(&["ip", "netns", "del", &self.peer]);
        if let Some(f) = &self.far {
            let _ = sh(&["ip", "netns", "del", f]);
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A third namespace `far` (10.98.0.5 behind the robot, which routes; or
/// 10.97.0.10 behind the peer, which routes over a link of `mtu`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Far {
    None,
    BehindRobot,
    BehindPeer { mtu: u32 },
}

const FAR_BEHIND_ROBOT: &str = "10.98.0.5";
const FAR_BEHIND_PEER: &str = "10.97.0.10";

/// A small tmpfs (for full-disk tests); unmounted on drop.
struct Tmpfs(PathBuf);

impl Tmpfs {
    fn new(dir: PathBuf, size: &str) -> Tmpfs {
        std::fs::create_dir_all(&dir).unwrap();
        sh(&[
            "mount",
            "-t",
            "tmpfs",
            "-o",
            &format!("size={size},mode=0700"),
            "tmpfs",
            dir.to_str().unwrap(),
        ])
        .unwrap();
        Tmpfs(dir)
    }

    /// Fill the file system (a filler file up to ENOSPC).
    fn fill(&self) {
        use std::io::Write;
        let mut f = std::fs::File::create(self.0.join("filler")).unwrap();
        let block = vec![0u8; 4096];
        while f.write_all(&block).is_ok() {}
        let _ = f.sync_all();
    }

    fn free(&self) {
        let _ = std::fs::remove_file(self.0.join("filler"));
    }
}

impl Drop for Tmpfs {
    fn drop(&mut self) {
        let _ = sh(&["umount", "-l", self.0.to_str().unwrap()]);
    }
}

fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .map(|l| l.split_whitespace().nth(2) == Some("0"))
        })
        .unwrap_or(false)
}

impl Lab {
    fn new() -> Option<Lab> {
        Self::with(Far::None)
    }

    fn with(far: Far) -> Option<Lab> {
        match Self::try_new(far) {
            Ok(l) => Some(l),
            Err(e) => {
                if std::env::var("ROBODR_REQUIRE_NETNS").as_deref() == Ok("1") {
                    panic!("network namespace lab unavailable: {e}");
                }
                eprintln!("SKIPPED: needs root, ip and nft in a network namespace ({e})");
                None
            }
        }
    }

    fn try_new(far: Far) -> Result<Lab, String> {
        if !is_root() {
            return Err("not root".into());
        }
        sh(&[NFT, "--version"])?;
        sh(&[IP, "-V"])?;
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let id = format!("{}{n:02}", std::process::id() % 100_000);
        let robot = format!("rdxr{id}");
        let peer = format!("rdxp{id}");
        let dir = std::env::temp_dir().join(format!("robodr-executor-netns-{id}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let mut lab = Lab {
            robot: robot.clone(),
            peer: peer.clone(),
            far: None,
            dir,
        };
        let va = format!("rva{id}");
        let vb = format!("rvb{id}");
        sh(&["ip", "netns", "add", &robot])?;
        sh(&["ip", "netns", "add", &peer])?;
        sh(&[
            "ip", "link", "add", &va, "netns", &robot, "type", "veth", "peer", "name", &vb,
            "netns", &peer,
        ])?;
        sh(&[
            "ip",
            "-n",
            &robot,
            "addr",
            "add",
            &format!("{ROBOT}/24"),
            "dev",
            &va,
        ])?;
        for a in [OTHER, MGMT, MOTION, ROGUE] {
            sh(&[
                "ip",
                "-n",
                &peer,
                "addr",
                "add",
                &format!("{a}/24"),
                "dev",
                &vb,
            ])?;
        }
        for (ns, dev) in [(&robot, &va), (&peer, &vb)] {
            sh(&["ip", "-n", ns, "link", "set", dev, "up"])?;
            sh(&["ip", "-n", ns, "link", "set", "lo", "up"])?;
            // Multicast leaves through the lab link.
            sh(&["ip", "-n", ns, "route", "add", "224.0.0.0/4", "dev", dev])?;
        }
        if far != Far::None {
            let f = format!("rdxf{id}");
            sh(&["ip", "netns", "add", &f])?;
            lab.far = Some(f.clone());
            let fa = format!("rfa{id}");
            let fb = format!("rfb{id}");
            let (router, rnet, faddr, raddr) = match far {
                Far::BehindRobot => (&robot, "10.98.0", FAR_BEHIND_ROBOT, "10.98.0.1"),
                _ => (&peer, "10.97.0", FAR_BEHIND_PEER, "10.97.0.1"),
            };
            sh(&[
                "ip", "link", "add", &fa, "netns", router, "type", "veth", "peer", "name", &fb,
                "netns", &f,
            ])?;
            sh(&[
                "ip",
                "-n",
                router,
                "addr",
                "add",
                &format!("{raddr}/24"),
                "dev",
                &fa,
            ])?;
            sh(&[
                "ip",
                "-n",
                &f,
                "addr",
                "add",
                &format!("{faddr}/24"),
                "dev",
                &fb,
            ])?;
            if let Far::BehindPeer { mtu } = far {
                let mtu = mtu.to_string();
                sh(&["ip", "-n", router, "link", "set", &fa, "mtu", &mtu])?;
                sh(&["ip", "-n", &f, "link", "set", &fb, "mtu", &mtu])?;
            }
            sh(&["ip", "-n", router, "link", "set", &fa, "up"])?;
            sh(&["ip", "-n", &f, "link", "set", &fb, "up"])?;
            sh(&["ip", "-n", &f, "link", "set", "lo", "up"])?;
            sh(&["ip", "-n", &f, "route", "add", "default", "via", raddr])?;
            sh(&[
                "ip",
                "netns",
                "exec",
                router,
                "sh",
                "-c",
                "echo 1 > /proc/sys/net/ipv4/ip_forward",
            ])?;
            // The other end of the lab link routes the far network through
            // the router.
            let (other_ns, via) = match far {
                Far::BehindRobot => (&peer, ROBOT),
                _ => (&robot, OTHER),
            };
            sh(&[
                "ip",
                "-n",
                other_ns,
                "route",
                "add",
                &format!("{rnet}.0/24"),
                "via",
                via,
            ])?;
        }
        Ok(lab)
    }

    fn far(&self) -> &str {
        self.far.as_deref().expect("lab without a far namespace")
    }

    fn nft(&self) -> NftCommand {
        // Absolute paths: the executor runs nft with an empty environment.
        NftCommand::with_prefix(
            [IP, "netns", "exec", &self.robot, NFT]
                .iter()
                .map(OsString::from)
                .collect(),
        )
    }

    fn nft_cmd(&self, args: &[&str]) -> Result<String, String> {
        let mut a = vec!["ip", "netns", "exec", &self.robot, "nft"];
        a.extend_from_slice(args);
        sh(&a)
    }

    /// The whole ruleset of the robot namespace, without handles.
    fn ruleset(&self) -> Value {
        let out = self.nft_cmd(&["-j", "list", "ruleset"]).unwrap();
        let mut v: Value = serde_json::from_str(&out).unwrap();
        strip(&mut v);
        if let Some(a) = v["nftables"].as_array_mut() {
            a.retain(|o| o.get("metainfo").is_none());
        }
        v
    }

    fn state_dir(&self, name: &str) -> PathBuf {
        let d = self.dir.join(name);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Send 3 datagrams from `src` (ns `from`) to `dst` and count what
    /// arrives at `dst` (ns `to`).
    fn probe(&self, from: &str, src: &str, to: &str, dst: &str, payload: &[u8]) -> usize {
        let hex: String = payload.iter().map(|b| format!("{b:02x}")).collect();
        self.exchange(
            to,
            &format!("recv {dst} 700"),
            from,
            &format!("send {src} {dst} {hex}"),
        )
    }

    /// Start the receiver `recv_spec` in ns `to`, run the sender
    /// `send_spec` in ns `from`, and return the receiver's count.
    fn exchange(&self, to: &str, recv_spec: &str, from: &str, send_spec: &str) -> usize {
        let exe = std::env::current_exe().unwrap();
        let mut rx = Command::new("ip")
            .args(["netns", "exec", to])
            .arg(&exe)
            .args(["--exact", "netns_helper", "--nocapture", "--test-threads=1"])
            .env(HELPER_ENV, recv_spec)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(rx.stdout.take().unwrap()).lines();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let l = lines.next().expect("receiver ended").unwrap();
            if l.contains("HELPER:ready") {
                break;
            }
            assert!(Instant::now() < deadline, "receiver never got ready");
        }
        let st = Command::new("ip")
            .args(["netns", "exec", from])
            .arg(&exe)
            .args(["--exact", "netns_helper", "--nocapture", "--test-threads=1"])
            .env(HELPER_ENV, send_spec)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(st.success(), "sender failed: {send_spec}");
        let mut count = None;
        for l in lines {
            let l = l.unwrap();
            if let Some(c) = l.split("HELPER:count=").nth(1) {
                count = Some(c.trim().parse().unwrap());
            }
        }
        rx.wait().unwrap();
        count.expect("receiver printed no count")
    }

    fn peer_to_robot(&self, src: &str, dport: u16, payload: &[u8]) -> usize {
        self.probe(
            &self.peer,
            src,
            &self.robot,
            &format!("{ROBOT}:{dport}"),
            payload,
        )
    }
}

fn strip(v: &mut Value) {
    match v {
        Value::Object(o) => {
            o.remove("handle");
            for (_, x) in o.iter_mut() {
                strip(x);
            }
        }
        Value::Array(a) => a.iter_mut().for_each(strip),
        _ => {}
    }
}

/// Runs only as a child: `recv <addr> <ms>` or `send <src> <dst> <hex>`.
#[test]
fn netns_helper() {
    let Ok(spec) = std::env::var(HELPER_ENV) else {
        return;
    };
    let parts: Vec<&str> = spec.split(' ').collect();
    match parts.as_slice() {
        ["recv", addr, ms] => {
            let s = UdpSocket::bind(addr).unwrap();
            s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
            println!("HELPER:ready");
            let window = Duration::from_millis(ms.parse().unwrap());
            let end = Instant::now() + window;
            let mut n = 0;
            let mut buf = vec![0u8; 65536];
            while Instant::now() < end {
                if s.recv_from(&mut buf).is_ok() {
                    n += 1;
                }
            }
            println!("HELPER:count={n}");
        }
        ["mrecv", group_port, ifaddr, ms] => {
            let (group, port) = group_port.split_once(':').unwrap();
            let group: std::net::Ipv4Addr = group.parse().unwrap();
            let s = UdpSocket::bind(("0.0.0.0", port.parse::<u16>().unwrap())).unwrap();
            s.join_multicast_v4(&group, &ifaddr.parse().unwrap())
                .unwrap();
            s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
            println!("HELPER:ready");
            let end = Instant::now() + Duration::from_millis(ms.parse().unwrap());
            let mut n = 0;
            let mut buf = vec![0u8; 65536];
            while Instant::now() < end {
                if s.recv_from(&mut buf).is_ok() {
                    n += 1;
                }
            }
            println!("HELPER:count={n}");
        }
        ["sendlen", src, dst, len] => {
            let s = UdpSocket::bind(src).unwrap();
            let bytes = vec![b'x'; len.parse().unwrap()];
            for _ in 0..3 {
                let _ = s.send_to(&bytes, dst);
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        ["send", src, dst, hex] => {
            let s = UdpSocket::bind(src).unwrap();
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            for _ in 0..3 {
                let _ = s.send_to(&bytes, dst);
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        other => panic!("bad helper spec {other:?}"),
    }
}

fn rtps(guid: &str) -> Vec<u8> {
    let mut p = b"RTPS\x02\x03\x01\x10".to_vec();
    for i in (0..24).step_by(2) {
        p.push(u8::from_str_radix(&guid[i..i + 2], 16).unwrap());
    }
    p.extend_from_slice(&[0x09, 0x01, 0x08, 0x00, 1, 2, 3, 4, 5, 6, 7, 8]);
    p
}

fn config(state_dir: &std::path::Path) -> robodr_executor::Resolved {
    config_with(state_dir, |_| {})
}

/// The lab configuration, with `edit` applied to its JSON first.
fn config_with(
    state_dir: &std::path::Path,
    edit: impl FnOnce(&mut Value),
) -> robodr_executor::Resolved {
    let mut v = config_json(state_dir);
    edit(&mut v);
    ExecutorConfig::parse(&v.to_string())
        .unwrap()
        .validate()
        .unwrap()
}

/// The lab SOC (trust boundary M1): its seed and public key file.
const SOC_SEED: [u8; 32] = [0x33; 32];
const SOC_KEY_ID: &str = "soc:lab:1";

fn soc_key_path() -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = std::env::temp_dir().join(format!("robodr-netns-soc-{}.pub", std::process::id()));
    if !p.exists() {
        let n = SOC_NONCE.fetch_add(1, Ordering::SeqCst);
        let tmp = p.with_extension(format!("tmp{n}"));
        std::fs::write(
            &tmp,
            robodr_executor::soc::testing::public_key_json(&SOC_SEED, SOC_KEY_ID),
        )
        .unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::rename(&tmp, &p).unwrap();
    }
    p
}

static SOC_NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A public key file standing for the robot's own (black-box) key.
fn robot_key_path() -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = std::env::temp_dir().join(format!("robodr-netns-robot-{}.pub", std::process::id()));
    if !p.exists() {
        let n = SOC_NONCE.fetch_add(1, Ordering::SeqCst);
        let tmp = p.with_extension(format!("tmp{n}"));
        std::fs::write(
            &tmp,
            robodr_executor::soc::testing::public_key_json(&[0x77; 32], "robot:blackbox"),
        )
        .unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::rename(&tmp, &p).unwrap();
    }
    p
}

/// Attach the lab SOC's signed request (at `ts_s`, a fresh nonce).
fn sign_at(o: Order, ts_s: u64) -> Order {
    let n = SOC_NONCE.fetch_add(1, Ordering::SeqCst);
    robodr_executor::soc::testing::sign_order(
        o,
        &SOC_SEED,
        "lab-robot",
        ts_s,
        &format!("lab-nonce-{}-{n:012}", std::process::id()),
    )
}

fn config_json(state_dir: &std::path::Path) -> Value {
    json!({
            "schema": "robodr-executor-config/v1",
            "robot_id": "lab-robot",
            "socket": state_dir.join("executor.sock"),
            "key_file": "/nonexistent/executor.key",
            "state_dir": state_dir,
            "policy_path": "/nonexistent/policy.json",
            "network": {
                "management": [{"cidr": MGMT}],
                "uplink": [{"cidr": "10.99.0.11", "proto": "tcp", "port": 443}],
                "control_buses": {"exempt": true, "entries": []},
                "motion_control_path": [
                    {"cidr": MOTION, "udp_ports": [7400, 7600], "note": "robot DDS bus"}
                ],
                // F4: where a quarantine may act (ROGUE / OTHER, not MGMT).
                "quarantine": {"cidrs": ["10.99.0.0/29", "fd00:30::/64"]}
            },
            "ttl": {"default_s": 600, "max_s": 3600},
            "max_safety_age_ms": 1000,
            "soc": {"keys": [soc_key_path()]}
    })
}

fn policy(m: Morphology, fsr: &[RestrictTarget]) -> ResponsePolicy {
    let mut p = ResponsePolicy::conservative_default(PlatformFamily::Ugv);
    p.morphology = m;
    p.oem_validated = true;
    p.fall_safe_restrict = fsr.to_vec();
    p
}

/// A control-plane order; [`submit`] attaches the lab SOC's signed request
/// for it as it is at submission (trust boundary M1).
fn order(id: &str, action: ActionId, m: Morphology) -> Order {
    unsigned(id, action, m)
}

/// Submit `o` to the engine at `now` with the lab SOC's request for it
/// (signed at `now`) when it is a control-plane order without one.
fn submit(
    e: &mut Engine,
    o: &Order,
    s: &mut FixedSafety,
    now: impl Into<robodr_executor::engine::Now>,
) -> robodr_executor::engine::Outcome {
    let now = now.into();
    let o = match o.origin {
        Origin::ControlPlane { .. } if o.soc.is_none() => sign_at(o.clone(), now.wall_ms / 1000),
        _ => o.clone(),
    };
    e.submit(&o, s, now)
}

fn unsigned(id: &str, action: ActionId, m: Morphology) -> Order {
    Order {
        id: id.into(),
        action,
        target: if action == ActionId::QuarantineNode {
            Target::Participant {
                guid_prefix: GUID.parse().unwrap(),
                locators: vec![Locator {
                    ip: ROGUE.parse().unwrap(),
                    port: 7410,
                }],
                guid_only: false,
                excluded: Vec::new(),
                addresses: Vec::new(),
                excluded_addresses: Vec::new(),
                evidence_truncated: false,
            }
        } else {
            Target::None
        },
        ttl_s: Some(600),
        judged_state: SafetyState::Idle,
        context: OperationalContext {
            platform: PlatformFamily::Ugv,
            morphology: m,
            phase: MissionPhase::Parked,
            connectivity: Connectivity::Connected,
            control: ControlMode::Autonomous,
            operator_present: true,
            profile_locked: true,
        },
        plan_morphology: m,
        human_approved: true,
        replay: false,
        origin: Origin::ControlPlane {
            key_id: SOC_KEY_ID.into(),
            requested_by: "lab".into(),
        },
        issued_ms: 0,
        soc: None,
    }
}

fn idle() -> FixedSafety {
    FixedSafety(Current {
        state: SafetyState::Idle,
        age_ms: 1,
    })
}

fn open(lab: &Lab, dir: &std::path::Path, boot: &str, m: Morphology, now: u64) -> Engine {
    Engine::open(config(dir), policy(m, &[]), Box::new(lab.nft()), boot, now).unwrap()
}

/// Foreign tables that must never change.
fn foreign_tables(lab: &Lab) {
    let script = "table ip other {\n chain c {\n  type filter hook input priority 0; policy accept;\n  ip saddr 10.99.0.99 counter accept\n }\n}\ntable inet filter {\n set s { type ipv4_addr; elements = { 10.99.0.98 } }\n chain o { type filter hook output priority 0; policy accept; }\n}\n";
    let path = lab.dir.join("foreign.nft");
    std::fs::write(&path, script).unwrap();
    lab.nft_cmd(&["-f", path.to_str().unwrap()]).unwrap();
}

fn foreign_snapshot(lab: &Lab) -> (String, String) {
    (
        lab.nft_cmd(&["-j", "list", "table", "ip", "other"])
            .unwrap(),
        lab.nft_cmd(&["-j", "list", "table", "inet", "filter"])
            .unwrap(),
    )
}

#[test]
fn isolate_network_blocks_traffic_keeps_management_and_motion_path_and_reverts_exactly() {
    let Some(lab) = Lab::new() else { return };
    foreign_tables(&lab);
    let foreign = foreign_snapshot(&lab);
    let before = lab.ruleset();
    // Baseline: everything gets through.
    assert_eq!(lab.peer_to_robot(&format!("{OTHER}:0"), 9000, b"x"), 3);

    let dir = lab.state_dir("iso");
    let mut e = open(&lab, &dir, "boot-1", Morphology::WheeledMobile, 1_000);
    let o = order("iso-1", ActionId::IsolateNetwork, Morphology::WheeledMobile);
    let out = submit(&mut e, &o, &mut idle(), 1_000);
    assert_eq!(out.status, Status::Verified, "{out:?}");

    // The installed rules are exactly the rendering.
    let mut n = lab.nft();
    let listed = nft::read_table(&mut n).unwrap();
    assert_eq!(nft::verify(listed.as_deref(), &e.rendered()), Ok(()));

    // Traffic: other host blocked, management and motion path allowed.
    assert_eq!(
        lab.peer_to_robot(&format!("{OTHER}:0"), 9000, b"x"),
        0,
        "other host"
    );
    assert_eq!(
        lab.peer_to_robot(&format!("{MGMT}:0"), 9000, b"x"),
        3,
        "management"
    );
    assert_eq!(
        lab.peer_to_robot(&format!("{MOTION}:7410"), 7410, b"x"),
        3,
        "motion path"
    );
    assert_eq!(
        lab.peer_to_robot(&format!("{MOTION}:9100"), 9100, b"x"),
        0,
        "motion host, other port"
    );
    // Loopback inside the robot stays open.
    assert_eq!(
        lab.probe(
            &lab.robot,
            "127.0.0.1:0",
            &lab.robot,
            "127.0.0.1:9001",
            b"x"
        ),
        3,
        "loopback"
    );
    // Egress to the other host is cut too.
    assert_eq!(
        lab.probe(
            &lab.robot,
            &format!("{ROBOT}:0"),
            &lab.peer,
            &format!("{OTHER}:9002"),
            b"x"
        ),
        0,
        "egress"
    );
    // The drop counter saw them.
    let listed = nft::read_table(&mut n).unwrap().unwrap();
    assert!(nft::drop_counters(&listed).values().any(|(p, _)| *p > 0));

    // Revert: the ruleset is exactly what it was before, traffic flows.
    assert_eq!(e.revert("iso-1", "lab", 2_000).status, Status::Reverted);
    assert_eq!(lab.ruleset(), before);
    assert_eq!(lab.peer_to_robot(&format!("{OTHER}:0"), 9000, b"x"), 3);
    // Idempotent.
    assert_eq!(e.revert("iso-1", "lab", 2_100).status, Status::Reverted);
    assert_eq!(lab.ruleset(), before);
    assert_eq!(foreign_snapshot(&lab), foreign, "a foreign table changed");
}

#[test]
fn quarantine_node_drops_the_participant_by_guid_and_locator_only() {
    let Some(lab) = Lab::new() else { return };
    foreign_tables(&lab);
    let foreign = foreign_snapshot(&lab);
    let dir = lab.state_dir("q");
    let mut e = open(&lab, &dir, "boot-1", Morphology::WheeledMobile, 1_000);
    let before = lab.ruleset();
    let out = submit(
        &mut e,
        &order("q-1", ActionId::QuarantineNode, Morphology::WheeledMobile),
        &mut idle(),
        1_000,
    );
    assert_eq!(out.status, Status::Verified, "{out:?}");
    // RTPS with the quarantined GUID prefix, from any address: dropped.
    assert_eq!(
        lab.peer_to_robot(&format!("{OTHER}:0"), 7500, &rtps(GUID)),
        0
    );
    // Another participant: delivered.
    assert_eq!(
        lab.peer_to_robot(&format!("{OTHER}:0"), 7500, &rtps(OTHER_GUID)),
        3
    );
    // Anything from the participant's locator (ip + port): dropped.
    assert_eq!(
        lab.peer_to_robot(&format!("{ROGUE}:7410"), 7500, b"not rtps"),
        0
    );
    // Same host, another port: delivered (quarantine is per participant).
    assert_eq!(
        lab.peer_to_robot(&format!("{ROGUE}:7411"), 7500, b"not rtps"),
        3
    );
    // To the participant's locator from the robot: dropped.
    assert_eq!(
        lab.probe(
            &lab.robot,
            &format!("{ROBOT}:0"),
            &lab.peer,
            &format!("{ROGUE}:7410"),
            b"x"
        ),
        0
    );
    assert_eq!(e.revert("q-1", "lab", 2_000).status, Status::Reverted);
    assert_eq!(lab.ruleset(), before);
    assert_eq!(
        lab.peer_to_robot(&format!("{OTHER}:0"), 7500, &rtps(GUID)),
        3
    );
    assert_eq!(foreign_snapshot(&lab), foreign);
}

/// Review R3-1 with real nftables: a participant's source address is cut
/// whole (any source port, to the robot's DDS ports), which is what makes
/// `containment: "full"` true for a sender using ephemeral ports (Fast
/// DDS); the read-back verifies the new rule shape (`iifname != "lo"`, a
/// port range, an anonymous set of merged ranges).
#[test]
fn r3_1_a_quarantined_address_is_dropped_from_any_source_port() {
    let Some(lab) = Lab::new() else { return };
    let dir = lab.state_dir("r3-1");
    let mut e = open(&lab, &dir, "boot-1", Morphology::WheeledMobile, 1_000);
    let before = lab.ruleset();
    let mut o = order("r3-1", ActionId::QuarantineNode, Morphology::WheeledMobile);
    if let Target::Participant { addresses, .. } = &mut o.target {
        *addresses = vec![ROGUE.parse().unwrap()];
    }
    let out = submit(&mut e, &o, &mut idle(), 1_000);
    assert_eq!(out.status, Status::Verified, "{out:?}");
    let scope = e.status("r3-1").quarantine.expect("scope");
    assert_eq!(
        scope.containment,
        Some(robodr_executor::decision::Containment::Full),
        "{scope:?}"
    );
    // From an ephemeral port, not RTPS / another prefix: dropped.
    assert_eq!(
        lab.peer_to_robot(&format!("{ROGUE}:40000"), 7500, b"not rtps"),
        0
    );
    assert_eq!(
        lab.peer_to_robot(&format!("{ROGUE}:40001"), 7410, &rtps(OTHER_GUID)),
        0
    );
    // Outside the robot's DDS ports (domain 0: 7400-7649): delivered.
    assert_eq!(lab.peer_to_robot(&format!("{ROGUE}:40000"), 7650, b"x"), 3);
    // Another host: delivered.
    assert_eq!(lab.peer_to_robot(&format!("{OTHER}:40000"), 7500, b"x"), 3);
    // To the host, any DDS port: dropped.
    assert_eq!(
        lab.probe(
            &lab.robot,
            &format!("{ROBOT}:0"),
            &lab.peer,
            &format!("{ROGUE}:7500"),
            b"x"
        ),
        0
    );
    assert_eq!(e.revert("r3-1", "lab", 2_000).status, Status::Reverted);
    assert_eq!(lab.ruleset(), before);
    assert_eq!(lab.peer_to_robot(&format!("{ROGUE}:40000"), 7500, b"x"), 3);

    // Several port ranges (adjacent ones merged): an anonymous set, read
    // back exactly.
    let dir = lab.state_dir("r3-1-ranges");
    let cfg = config_with(&dir, |v| {
        v["network"]["quarantine"]["udp_ports"] = json!([[7400, 7409], [7410, 7420], [7500, 7600]]);
    });
    let mut e = Engine::open(
        cfg,
        policy(Morphology::WheeledMobile, &[]),
        Box::new(lab.nft()),
        "boot-1",
        3_000,
    )
    .unwrap();
    let mut o = order("r3-1r", ActionId::QuarantineNode, Morphology::WheeledMobile);
    if let Target::Participant { addresses, .. } = &mut o.target {
        *addresses = vec![ROGUE.parse().unwrap()];
    }
    let out = submit(&mut e, &o, &mut idle(), 3_000);
    assert_eq!(out.status, Status::Verified, "{out:?}");
    assert_eq!(lab.peer_to_robot(&format!("{ROGUE}:40000"), 7415, b"x"), 0);
    assert_eq!(lab.peer_to_robot(&format!("{ROGUE}:40000"), 7550, b"x"), 0);
    assert_eq!(lab.peer_to_robot(&format!("{ROGUE}:40000"), 7450, b"x"), 3);
    assert_eq!(e.revert("r3-1r", "lab", 4_000).status, Status::Reverted);
}

#[test]
fn revert_of_one_action_restores_the_exact_earlier_ruleset() {
    let Some(lab) = Lab::new() else { return };
    foreign_tables(&lab);
    let dir = lab.state_dir("two");
    let mut e = open(&lab, &dir, "boot-1", Morphology::WheeledMobile, 1_000);
    let q = order("q-1", ActionId::QuarantineNode, Morphology::WheeledMobile);
    assert_eq!(
        submit(&mut e, &q, &mut idle(), 1_000).status,
        Status::Verified
    );
    let with_q = lab.ruleset();
    let i = order("i-1", ActionId::IsolateNetwork, Morphology::WheeledMobile);
    assert_eq!(
        submit(&mut e, &i, &mut idle(), 1_000).status,
        Status::Verified
    );
    assert_ne!(lab.ruleset(), with_q);
    assert_eq!(e.revert("i-1", "lab", 2_000).status, Status::Reverted);
    assert_eq!(lab.ruleset(), with_q);
    // The quarantine still works.
    assert_eq!(
        lab.peer_to_robot(&format!("{OTHER}:0"), 7500, &rtps(GUID)),
        0
    );
    assert_eq!(
        lab.peer_to_robot(&format!("{OTHER}:0"), 7500, &rtps(OTHER_GUID)),
        3
    );
}

#[test]
fn ttl_expiry_reverts_with_real_nftables() {
    let Some(lab) = Lab::new() else { return };
    let dir = lab.state_dir("ttl");
    let before = lab.ruleset();
    let mut e = open(&lab, &dir, "boot-1", Morphology::WheeledMobile, 1_000);
    let mut i = order("i-ttl", ActionId::IsolateNetwork, Morphology::WheeledMobile);
    i.ttl_s = Some(1);
    assert_eq!(
        submit(&mut e, &i, &mut idle(), 1_000).status,
        Status::Verified
    );
    assert_eq!(lab.peer_to_robot(&format!("{OTHER}:0"), 9000, b"x"), 0);
    e.tick(1_500);
    assert_eq!(e.status("i-ttl").status, Status::Verified);
    e.tick(2_001);
    assert_eq!(e.status("i-ttl").status, Status::Reverted);
    assert_eq!(lab.ruleset(), before);
    assert_eq!(lab.peer_to_robot(&format!("{OTHER}:0"), 9000, b"x"), 3);
}

#[test]
fn restart_reconciliation_and_reboot_with_real_nftables() {
    let Some(lab) = Lab::new() else { return };
    let dir = lab.state_dir("restart");
    let mut e = open(&lab, &dir, "boot-1", Morphology::WheeledMobile, 1_000);
    let i = order("i-1", ActionId::IsolateNetwork, Morphology::WheeledMobile);
    assert_eq!(
        submit(&mut e, &i, &mut idle(), 1_000).status,
        Status::Verified
    );
    let applied = lab.ruleset();
    drop(e);
    // Restart, same boot: re-verified, unchanged.
    let e = open(&lab, &dir, "boot-1", Morphology::WheeledMobile, 2_000);
    assert_eq!(e.status("i-1").status, Status::Verified);
    assert_eq!(lab.ruleset(), applied);
    drop(e);
    // Reboot (kernel ruleset empty, new boot id): held (nothing installed)
    // until re-validated with a fresh safety state, then re-applied.
    lab.nft_cmd(&["delete", "table", "inet", "robodr"]).unwrap();
    let mut e = open(&lab, &dir, "boot-2", Morphology::WheeledMobile, 3_000);
    assert_eq!(e.status("i-1").status, Status::Held);
    assert!(!nft::table_exists(&mut lab.nft()).unwrap());
    e.rearm_held(
        Ok(Current {
            state: SafetyState::Idle,
            age_ms: 3,
        }),
        3_100,
    );
    assert_eq!(e.status("i-1").status, Status::Verified);
    assert_eq!(lab.ruleset(), applied);
    assert_eq!(lab.peer_to_robot(&format!("{OTHER}:0"), 9000, b"x"), 0);
    drop(e);
    // Operator emergency disable (same boot) while the executor is down:
    // honoured, not re-applied, and orders wait for a re-arm.
    lab.nft_cmd(&["delete", "table", "inet", "robodr"]).unwrap();
    let mut e = open(&lab, &dir, "boot-2", Morphology::WheeledMobile, 4_000);
    assert_eq!(e.status("i-1").status, Status::RemovedExternally);
    assert_eq!(lab.peer_to_robot(&format!("{OTHER}:0"), 9000, b"x"), 3);
    assert!(e.rearm("lab", 4_500).unwrap());
    // ... and while it runs.
    let i2 = order("i-2", ActionId::IsolateNetwork, Morphology::WheeledMobile);
    assert_eq!(
        submit(&mut e, &i2, &mut idle(), 5_000).status,
        Status::Verified
    );
    lab.nft_cmd(&["delete", "table", "inet", "robodr"]).unwrap();
    e.periodic_verify(6_000);
    assert_eq!(e.status("i-2").status, Status::RemovedExternally);
    e.tick(60_000);
    assert!(!nft::table_exists(&mut lab.nft()).unwrap());
    assert!(e.rearm("lab", 60_500).unwrap());
    // Drift: a rule removed by hand is put back.
    let i3 = order("i-3", ActionId::IsolateNetwork, Morphology::WheeledMobile);
    assert_eq!(
        submit(&mut e, &i3, &mut idle(), 61_000).status,
        Status::Verified
    );
    lab.nft_cmd(&["flush", "chain", "inet", "robodr", "input"])
        .unwrap();
    assert_eq!(lab.peer_to_robot(&format!("{OTHER}:0"), 9000, b"x"), 3);
    e.periodic_verify(62_000);
    let listed = nft::read_table(&mut lab.nft()).unwrap();
    assert_eq!(nft::verify(listed.as_deref(), &e.rendered()), Ok(()));
    assert_eq!(lab.peer_to_robot(&format!("{OTHER}:0"), 9000, b"x"), 0);
}

#[test]
fn crash_between_apply_and_journal_write_is_recovered() {
    let Some(lab) = Lab::new() else { return };
    let dir = lab.state_dir("crash");
    let mut e = open(&lab, &dir, "boot-1", Morphology::WheeledMobile, 1_000);
    let q = order("q-1", ActionId::QuarantineNode, Morphology::WheeledMobile);
    assert_eq!(
        submit(&mut e, &q, &mut idle(), 1_000).status,
        Status::Verified
    );
    let before = lab.ruleset();
    robodr_executor::fault::arm(robodr_executor::fault::Point::AfterApply);
    let out = submit(
        &mut e,
        &order("i-1", ActionId::IsolateNetwork, Morphology::WheeledMobile),
        &mut idle(),
        2_000,
    );
    robodr_executor::fault::disarm();
    assert!(out.error.unwrap().contains("fault injected"));
    // The "dead" process left the isolation installed.
    assert_ne!(lab.ruleset(), before);
    assert_eq!(lab.peer_to_robot(&format!("{OTHER}:0"), 9000, b"x"), 0);
    drop(e);
    let e = open(&lab, &dir, "boot-1", Morphology::WheeledMobile, 3_000);
    assert_eq!(e.status("i-1").status, Status::Failed);
    assert_eq!(e.status("q-1").status, Status::Verified);
    assert_eq!(lab.ruleset(), before);
    assert_eq!(lab.peer_to_robot(&format!("{OTHER}:0"), 9000, b"x"), 3);
}

#[test]
fn humanoid_refusals_install_nothing() {
    let Some(lab) = Lab::new() else { return };
    let dir = lab.state_dir("humanoid");
    let before = lab.ruleset();
    // fall_safe_restrict empty (the Unitree G1 example).
    let mut e = open(&lab, &dir, "boot-1", Morphology::Humanoid, 1_000);
    for a in ActionId::ALL {
        let out = submit(
            &mut e,
            &order(a.as_str(), a, Morphology::Humanoid),
            &mut idle(),
            1_000,
        );
        assert!(
            matches!(out.status, Status::Refused | Status::Advisory),
            "{a:?} {out:?}"
        );
        if matches!(a, ActionId::IsolateNetwork | ActionId::QuarantineNode) {
            assert_eq!(out.refusal.unwrap().code, codes::FALL_HAZARD);
        }
    }
    assert_eq!(lab.ruleset(), before);
    // With network listed as fall-safe, an unapproved isolation still waits
    // for a human.
    drop(e);
    let mut e = Engine::open(
        config(&dir),
        policy(Morphology::Humanoid, &[RestrictTarget::Network]),
        Box::new(lab.nft()),
        "boot-1",
        2_000,
    )
    .unwrap();
    // (Unapproved = the planner's: a control-plane order is approved only
    // by the SOC's verified signature.)
    let mut o = order("h-iso", ActionId::IsolateNetwork, Morphology::Humanoid);
    o.human_approved = false;
    o.origin = Origin::Planner {
        rule: "lab".into(),
        finding_id: None,
    };
    assert_eq!(
        submit(&mut e, &o, &mut idle(), 2_000).refusal.unwrap().code,
        codes::NEEDS_APPROVAL
    );
    assert_eq!(lab.ruleset(), before);
}

#[test]
fn protocol_end_to_end_over_the_unix_socket() {
    let Some(lab) = Lab::new() else { return };
    let dir = lab.state_dir("proto");
    let cfgr = config(&dir);
    let sock = cfgr.config.socket.clone();
    let key_bytes = [0x5au8; 32];
    let engine = Engine::open(
        cfgr,
        policy(Morphology::WheeledMobile, &[]),
        Box::new(lab.nft()),
        "boot-1",
        robodr_executor::proto::wall_ms(),
    )
    .unwrap();
    let listener = robodr_executor::server::bind(&sock, 0o600).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let st = stop.clone();
    let server = std::thread::spawn(move || {
        let mut engine = engine;
        let key = Key::from_bytes(key_bytes);
        robodr_executor::server::serve(
            &listener,
            &mut engine,
            &key,
            "boot-1",
            &|| st.load(Ordering::SeqCst),
            &mut |_, _| {},
        )
    });
    let client = Client::new(
        sock.clone(),
        Key::from_bytes(key_bytes),
        Duration::from_secs(5),
    );
    assert_eq!(client.ping().unwrap().0, 0);
    // The safety state is asked for immediately before apply; a changed one
    // refuses.
    let now_s = || robodr_executor::proto::wall_ms() / 1000;
    let mut asked = 0;
    let o = sign_at(
        unsigned("p-1", ActionId::IsolateNetwork, Morphology::WheeledMobile),
        now_s(),
    );
    let out = client
        .submit(&o, &mut || {
            asked += 1;
            Ok((SafetyState::MovingSlow, 3))
        })
        .unwrap();
    assert_eq!(asked, 1);
    assert_eq!(out.refusal.unwrap().code, codes::SAFETY_STATE_CHANGED);
    // Trust boundary M1, over the real socket and kernel: an order that
    // agentd (holding the protocol key) forges without the SOC's signature,
    // or with another key's, installs nothing.
    let before = lab.ruleset();
    let forged = unsigned("p-f1", ActionId::IsolateNetwork, Morphology::WheeledMobile);
    let out = client
        .submit(&forged, &mut || Ok((SafetyState::Idle, 3)))
        .unwrap();
    assert_eq!(out.refusal.unwrap().code, codes::SOC_SIGNATURE_INVALID);
    let mut wrong = robodr_executor::soc::testing::sign_order(
        unsigned("p-f2", ActionId::IsolateNetwork, Morphology::WheeledMobile),
        &[0x44; 32],
        "lab-robot",
        now_s(),
        "lab-forged-nonce-0001",
    );
    let out = client
        .submit(&wrong, &mut || Ok((SafetyState::Idle, 3)))
        .unwrap();
    assert_eq!(out.refusal.unwrap().code, codes::SOC_SIGNATURE_INVALID);
    // A genuine approval for a 60 s isolation stretched by agentd.
    wrong = sign_at(
        unsigned("p-f3", ActionId::IsolateNetwork, Morphology::WheeledMobile),
        now_s(),
    );
    wrong.ttl_s = Some(3600);
    let out = client
        .submit(&wrong, &mut || Ok((SafetyState::Idle, 3)))
        .unwrap();
    assert_eq!(out.refusal.unwrap().code, codes::ORDER_MISMATCH);
    assert_eq!(lab.ruleset(), before, "a forged order changed the ruleset");
    assert_eq!(lab.peer_to_robot(&format!("{OTHER}:0"), 9000, b"x"), 3);
    // The matching signed order is applied.
    let o = sign_at(
        unsigned("p-2", ActionId::IsolateNetwork, Morphology::WheeledMobile),
        now_s(),
    );
    let out = client
        .submit(&o, &mut || Ok((SafetyState::Idle, 3)))
        .unwrap();
    assert_eq!(out.status, Status::Verified, "{out:?}");
    assert_eq!(lab.peer_to_robot(&format!("{OTHER}:0"), 9000, b"x"), 0);
    assert_eq!(client.status("p-2").unwrap().status, Status::Verified);
    let evs = client.events(0).unwrap();
    assert!(evs.iter().any(|e| e.id.as_deref() == Some("p-2")));
    // A client with the wrong key gets nothing done.
    let bad = Client::new(
        sock.clone(),
        Key::from_bytes([1u8; 32]),
        Duration::from_secs(2),
    );
    assert!(bad.revert("p-2", "x").is_err());
    assert_eq!(client.status("p-2").unwrap().status, Status::Verified);
    // Review F3: a revert without the SOC's signature (what agentd, or
    // anyone holding the protocol key, could send) is refused and the
    // isolation stays in force.
    let out = client.revert("p-2", "lab").unwrap();
    assert_eq!(out.status, Status::Verified, "{out:?}");
    assert_eq!(out.refusal.unwrap().code, codes::SOC_SIGNATURE_INVALID);
    assert_eq!(lab.peer_to_robot(&format!("{OTHER}:0"), 9000, b"x"), 0);
    // The SOC's signed revert, through the protocol, lifts it.
    let rv = robodr_executor::soc::SocRequest::sign(
        &SOC_SEED,
        "lab-robot",
        SOC_KEY_ID,
        "POST",
        "/api/v2/robots/lab-robot/action-requests/p-2/revert",
        now_s(),
        &format!("lab-revert-{}-0001", std::process::id()),
        r#"{"reason":"lab","requested_by":"analyst"}"#,
    );
    assert_eq!(
        client
            .revert_signed("p-2", "lab", Some(&rv))
            .unwrap()
            .status,
        Status::Reverted
    );
    assert_eq!(lab.peer_to_robot(&format!("{OTHER}:0"), 9000, b"x"), 3);
    stop.store(true, Ordering::SeqCst);
    let stats = server.join().unwrap();
    assert!(stats.rejected >= 1);
}

// --- Regressions of the executor v1 review -----------------------------------

/// The effect of an isolation built directly (as a journal from an older
/// version could hold it), rendered and installed without the engine.
fn install_effect(lab: &Lab, effect: Value) {
    let effect: robodr_executor::decision::Effect = serde_json::from_value(effect).unwrap();
    let r = nft::render(&[nft::Active {
        id: "direct",
        effect: &effect,
    }]);
    nft::apply(&mut lab.nft(), &r).unwrap();
}

/// H1: a protected entry that names only a GUID prefix must never become an
/// address-free accept: anyone can write that prefix into an RTPS header.
#[test]
fn h1_guid_only_protected_entry_opens_no_hole() {
    let Some(lab) = Lab::new() else { return };
    install_effect(
        &lab,
        json!({
            "kind": "isolate",
            "allow": [{"cidr": MGMT}],
            "protected": [{"guid_prefix": GUID, "low_level": true}]
        }),
    );
    assert_eq!(
        lab.peer_to_robot(&format!("{OTHER}:0"), 7500, &rtps(GUID)),
        0,
        "RTPS carrying the protected prefix from a host outside every allow-list"
    );
    assert_eq!(
        lab.probe(
            &lab.robot,
            &format!("{ROBOT}:0"),
            &lab.peer,
            &format!("{OTHER}:7500"),
            &rtps(GUID)
        ),
        0,
        "egress carrying the protected prefix"
    );
    // Through the engine: GUID + address, the GUID only narrows.
    let dir = lab.state_dir("h1");
    let cfg = config_with(&dir, |v| {
        v["network"]["motion_control_path"] = json!([
            {"cidr": MOTION, "udp_ports": [7400, 7600], "guid_prefix": GUID, "low_level": true}
        ]);
    });
    let mut e = Engine::open(
        cfg,
        policy(Morphology::WheeledMobile, &[]),
        Box::new(lab.nft()),
        "boot-1",
        1_000,
    )
    .unwrap();
    let o = order(
        "iso-h1",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
    );
    let out = submit(&mut e, &o, &mut idle(), 1_000);
    assert_eq!(out.status, Status::Verified, "{out:?}");
    assert_eq!(
        lab.peer_to_robot(&format!("{OTHER}:0"), 7500, &rtps(GUID)),
        0,
        "protected prefix from another host"
    );
    assert_eq!(
        lab.peer_to_robot(&format!("{MOTION}:40000"), 7500, &rtps(GUID)),
        3,
        "protected participant on its address"
    );
    assert_eq!(
        lab.peer_to_robot(&format!("{MOTION}:40000"), 7500, b"not rtps"),
        0,
        "the GUID narrows the entry"
    );
}

/// H2: a quarantine never cuts a low-level path, even when the low-level
/// participant's traffic carries the quarantined GUID prefix (GUIDs change
/// on restart and can collide).
#[test]
fn h2_quarantine_never_cuts_a_low_level_path() {
    let Some(lab) = Lab::new() else { return };
    let dir = lab.state_dir("h2");
    let cfg = config_with(&dir, |v| {
        v["network"]["motion_control_path"] =
            json!([{"cidr": MOTION, "low_level": true, "note": "balance loop"}]);
    });
    let mut e = Engine::open(
        cfg,
        policy(Morphology::WheeledMobile, &[]),
        Box::new(lab.nft()),
        "boot-1",
        1_000,
    )
    .unwrap();
    let q = order("q-h2", ActionId::QuarantineNode, Morphology::WheeledMobile);
    let out = submit(&mut e, &q, &mut idle(), 1_000);
    assert_eq!(out.status, Status::Verified, "{out:?}");
    assert_eq!(
        lab.peer_to_robot(&format!("{MOTION}:7410"), 7410, &rtps(GUID)),
        3,
        "low-level traffic carrying the quarantined prefix"
    );
    assert_eq!(
        lab.probe(
            &lab.robot,
            &format!("{ROBOT}:7410"),
            &lab.peer,
            &format!("{MOTION}:7410"),
            &rtps(GUID)
        ),
        3,
        "low-level egress carrying the quarantined prefix"
    );
    // The quarantine still acts outside the low-level network.
    assert_eq!(
        lab.peer_to_robot(&format!("{OTHER}:0"), 7500, &rtps(GUID)),
        0
    );
    assert_eq!(lab.peer_to_robot(&format!("{ROGUE}:7410"), 7500, b"x"), 0);
}

/// H3: isolation keeps the robot's own DDS discovery (SPDP multicast) and
/// inbound discovery from the protected network.
#[test]
fn h3_isolation_keeps_dds_multicast_discovery() {
    let Some(lab) = Lab::new() else { return };
    let dir = lab.state_dir("h3");
    let cfg = config_with(&dir, |v| {
        // Unicast ports only: discovery must not depend on them.
        v["network"]["motion_control_path"] = json!([{"cidr": MOTION, "udp_ports": [7410, 7600]}]);
    });
    let mut e = Engine::open(
        cfg,
        policy(Morphology::WheeledMobile, &[]),
        Box::new(lab.nft()),
        "boot-1",
        1_000,
    )
    .unwrap();
    let o = order(
        "iso-h3",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
    );
    assert_eq!(
        submit(&mut e, &o, &mut idle(), 1_000).status,
        Status::Verified
    );
    let mc = |from: &str, src: &str, to: &str, ifaddr: &str, port: u16| {
        lab.exchange(
            to,
            &format!("mrecv 239.255.0.1:{port} {ifaddr} 700"),
            from,
            &format!("send {src} 239.255.0.1:{port} {}", hexs(&rtps(GUID))),
        )
    };
    assert_eq!(
        mc(
            &lab.robot,
            &format!("{ROBOT}:40000"),
            &lab.peer,
            MOTION,
            7400
        ),
        3,
        "the robot's SPDP to 239.255.0.1:7400"
    );
    assert_eq!(
        mc(
            &lab.robot,
            &format!("{ROBOT}:40000"),
            &lab.peer,
            MOTION,
            7401
        ),
        3,
        "the robot's user multicast (7401)"
    );
    assert_eq!(
        mc(
            &lab.peer,
            &format!("{MOTION}:40000"),
            &lab.robot,
            ROBOT,
            7400
        ),
        3,
        "SPDP from the protected network"
    );
    assert_eq!(
        mc(
            &lab.peer,
            &format!("{OTHER}:40000"),
            &lab.robot,
            ROBOT,
            7400
        ),
        0,
        "SPDP from a host outside every allow-list"
    );
    assert_eq!(
        mc(
            &lab.robot,
            &format!("{ROBOT}:40000"),
            &lab.peer,
            MOTION,
            9999
        ),
        0,
        "multicast to a port outside the DDS port map"
    );
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// M6: fragments of a protected flow routed through the robot pass (the
/// non-first fragments carry no UDP header to match a port on).
#[test]
fn m6_forwarded_fragments_of_a_protected_flow_pass() {
    let Some(lab) = Lab::with(Far::BehindRobot) else {
        return;
    };
    let dir = lab.state_dir("m6");
    let cfg = config_with(&dir, |v| {
        v["network"]["motion_control_path"] =
            json!([{"cidr": FAR_BEHIND_ROBOT, "udp_ports": [7400, 7600]}]);
    });
    let mut e = Engine::open(
        cfg,
        policy(Morphology::WheeledMobile, &[]),
        Box::new(lab.nft()),
        "boot-1",
        1_000,
    )
    .unwrap();
    let o = order(
        "iso-m6",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
    );
    assert_eq!(
        submit(&mut e, &o, &mut idle(), 1_000).status,
        Status::Verified
    );
    let routed = |from: &str, src: &str, to: &str, dst: &str, len: usize| {
        lab.exchange(
            to,
            &format!("recv {dst} 700"),
            from,
            &format!("sendlen {src} {dst} {len}"),
        )
    };
    let far = lab.far().to_string();
    let f_src = format!("{FAR_BEHIND_ROBOT}:7410");
    assert_eq!(
        routed(&far, &f_src, &lab.peer, &format!("{MOTION}:7410"), 100),
        3,
        "small datagram"
    );
    assert_eq!(
        routed(&far, &f_src, &lab.peer, &format!("{MOTION}:7410"), 4000),
        3,
        "4000-byte datagram (fragmented)"
    );
    assert_eq!(
        routed(
            &lab.peer,
            &format!("{MOTION}:7410"),
            &far,
            &format!("{FAR_BEHIND_ROBOT}:7410"),
            4000
        ),
        3,
        "4000-byte datagram towards the protected host"
    );
    assert_eq!(
        routed(&far, &f_src, &lab.peer, &format!("{OTHER}:9000"), 4000),
        0,
        "fragments accepted by address never complete a datagram whose first \
         fragment is dropped"
    );
}

/// L5: isolation keeps the DHCP client and path MTU discovery working.
#[test]
fn l5_isolation_keeps_dhcp_client_and_path_mtu_discovery() {
    let Some(lab) = Lab::with(Far::BehindPeer { mtu: 1280 }) else {
        return;
    };
    let dir = lab.state_dir("l5");
    let cfg = config_with(&dir, |v| {
        v["network"]["management"] = json!([{"cidr": FAR_BEHIND_PEER}]);
    });
    let mut e = Engine::open(
        cfg,
        policy(Morphology::WheeledMobile, &[]),
        Box::new(lab.nft()),
        "boot-1",
        1_000,
    )
    .unwrap();
    let o = order(
        "iso-l5",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
    );
    assert_eq!(
        submit(&mut e, &o, &mut idle(), 1_000).status,
        Status::Verified
    );
    assert_eq!(
        lab.peer_to_robot(&format!("{OTHER}:67"), 68, b"dhcp offer"),
        3,
        "DHCP server -> client"
    );
    assert_eq!(
        lab.peer_to_robot(&format!("{OTHER}:67"), 69, b"x"),
        0,
        "port 67 to another port"
    );
    assert_eq!(
        lab.probe(
            &lab.robot,
            &format!("{ROBOT}:68"),
            &lab.peer,
            &format!("{OTHER}:67"),
            b"dhcp request"
        ),
        3,
        "DHCP client -> server"
    );
    // Path MTU: 1400 bytes with DF towards the management host behind a
    // 1280-byte link; the router's "fragmentation needed" must reach the
    // robot.
    let far = lab.far().to_string();
    let got = lab.exchange(
        &far,
        &format!("recv {FAR_BEHIND_PEER}:9000 700"),
        &lab.robot,
        &format!("sendlen {ROBOT}:0 {FAR_BEHIND_PEER}:9000 1400"),
    );
    let route = sh(&["ip", "-n", &lab.robot, "route", "get", FAR_BEHIND_PEER]).unwrap();
    assert!(
        route.contains("mtu 1280"),
        "the robot never learned the path MTU: {route}"
    );
    assert!(got >= 1, "nothing reached the management host after PMTU");
}

/// L2: a port rule matches the direction: the destination port for a
/// request, the source port only for a reply.
#[test]
fn l2_port_rules_match_the_direction() {
    let Some(lab) = Lab::new() else { return };
    let dir = lab.state_dir("l2");
    let cfg = config_with(&dir, |v| {
        v["network"]["management"] = json!([{"cidr": MGMT, "proto": "udp", "port": 5000}]);
    });
    let mut e = Engine::open(
        cfg,
        policy(Morphology::WheeledMobile, &[]),
        Box::new(lab.nft()),
        "boot-1",
        1_000,
    )
    .unwrap();
    let o = order(
        "iso-l2",
        ActionId::IsolateNetwork,
        Morphology::WheeledMobile,
    );
    assert_eq!(
        submit(&mut e, &o, &mut idle(), 1_000).status,
        Status::Verified
    );
    assert_eq!(
        lab.peer_to_robot(&format!("{MGMT}:5000"), 9000, b"x"),
        0,
        "source port 5000 to an arbitrary local port (no request seen)"
    );
    assert_eq!(
        lab.peer_to_robot(&format!("{MGMT}:40001"), 5000, b"x"),
        3,
        "request to the local service on 5000"
    );
    assert_eq!(
        lab.probe(
            &lab.robot,
            &format!("{ROBOT}:40002"),
            &lab.peer,
            &format!("{MGMT}:5000"),
            b"q"
        ),
        3,
        "request to the remote service on 5000"
    );
    assert_eq!(
        lab.peer_to_robot(&format!("{MGMT}:5000"), 40002, b"a"),
        3,
        "its reply"
    );
    assert_eq!(
        lab.peer_to_robot(&format!("{MOTION}:7410"), 9100, b"x"),
        0,
        "motion path source port to a port outside the range"
    );
    assert_eq!(
        lab.peer_to_robot(&format!("{MOTION}:40003"), 7410, b"x"),
        3,
        "motion path destination port"
    );
}

/// M3: an operator's `nft delete table inet robodr` is not undone by the
/// next order or revert before the periodic check notices it.
#[test]
fn m3_operator_table_delete_is_not_undone_by_the_next_order() {
    let Some(lab) = Lab::new() else { return };
    let dir = lab.state_dir("m3");
    let mut e = open(&lab, &dir, "boot-1", Morphology::WheeledMobile, 1_000);
    let i = order("i-m3", ActionId::IsolateNetwork, Morphology::WheeledMobile);
    assert_eq!(
        submit(&mut e, &i, &mut idle(), 1_000).status,
        Status::Verified
    );
    lab.nft_cmd(&["delete", "table", "inet", "robodr"]).unwrap();
    let q = order("q-m3", ActionId::QuarantineNode, Morphology::WheeledMobile);
    let out = submit(&mut e, &q, &mut idle(), 1_100);
    assert_eq!(out.status, Status::Refused, "{out:?}");
    assert_eq!(out.refusal.unwrap().code, "operator_disabled");
    assert!(!nft::table_exists(&mut lab.nft()).unwrap());
    assert_eq!(e.status("i-m3").status, Status::RemovedExternally);
    assert_eq!(lab.peer_to_robot(&format!("{OTHER}:0"), 9000, b"x"), 3);
    // A revert of an action installed later, after another removal: the
    // table stays gone.
    assert!(e.rearm("lab", 1_200).unwrap());
    let q2 = order("q-m3b", ActionId::QuarantineNode, Morphology::WheeledMobile);
    let i2 = order("i-m3b", ActionId::IsolateNetwork, Morphology::WheeledMobile);
    assert_eq!(
        submit(&mut e, &q2, &mut idle(), 1_300).status,
        Status::Verified
    );
    assert_eq!(
        submit(&mut e, &i2, &mut idle(), 1_300).status,
        Status::Verified
    );
    lab.nft_cmd(&["delete", "table", "inet", "robodr"]).unwrap();
    assert_eq!(
        e.revert("q-m3b", "lab", 1_400).status,
        Status::RemovedExternally
    );
    assert!(!nft::table_exists(&mut lab.nft()).unwrap());
    assert_eq!(lab.peer_to_robot(&format!("{OTHER}:0"), 9000, b"x"), 3);
}

/// M4: a start that fails after the rules were re-installed (here: the
/// journal cannot be written, disk full) leaves no rule behind.
#[test]
fn m4_failed_start_on_a_full_disk_leaves_no_rule() {
    let Some(lab) = Lab::new() else { return };
    let t = Tmpfs::new(lab.dir.join("m4fs"), "256k");
    let dir = t.0.clone();
    let mut e = open(&lab, &dir, "boot-1", Morphology::WheeledMobile, 1_000);
    let i = order("i-m4", ActionId::IsolateNetwork, Morphology::WheeledMobile);
    assert_eq!(
        submit(&mut e, &i, &mut idle(), 1_000).status,
        Status::Verified
    );
    drop(e);
    t.fill();
    let r = Engine::open(
        config(&dir),
        policy(Morphology::WheeledMobile, &[]),
        Box::new(lab.nft()),
        "boot-1",
        2_000,
    );
    assert!(r.is_err(), "the journal could not be written");
    assert!(
        !nft::table_exists(&mut lab.nft()).unwrap(),
        "rules left without TTL enforcement after a failed start"
    );
    assert_eq!(lab.peer_to_robot(&format!("{OTHER}:0"), 9000, b"x"), 3);
}

/// M5: a revert whose journal write fails (disk full) is never reported
/// `reverted`, and is completed once the disk has room again.
#[test]
fn m5_revert_on_a_full_disk_is_not_reported_reverted() {
    let Some(lab) = Lab::new() else { return };
    let t = Tmpfs::new(lab.dir.join("m5fs"), "256k");
    let dir = t.0.clone();
    let mut e = open(&lab, &dir, "boot-1", Morphology::WheeledMobile, 1_000);
    let i = order("i-m5", ActionId::IsolateNetwork, Morphology::WheeledMobile);
    assert_eq!(
        submit(&mut e, &i, &mut idle(), 1_000).status,
        Status::Verified
    );
    t.fill();
    let out = e.revert("i-m5", "lab", 2_000);
    assert_ne!(out.status, Status::Reverted, "{out:?}");
    // The rules are lifted all the same (the revert does less, never more).
    assert_eq!(lab.peer_to_robot(&format!("{OTHER}:0"), 9000, b"x"), 3);
    e.tick(3_000);
    assert_ne!(e.status("i-m5").status, Status::Reverted);
    t.free();
    e.tick(4_000);
    assert_eq!(e.status("i-m5").status, Status::Reverted);
    drop(e);
    let e = open(&lab, &dir, "boot-1", Morphology::WheeledMobile, 5_000);
    assert_eq!(e.status("i-m5").status, Status::Reverted);
    assert!(!nft::table_exists(&mut lab.nft()).unwrap());
}

/// The files the real binary needs (config, key, policy) in `dir`.
fn binary_files(dir: &std::path::Path, socket: &std::path::Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let key = dir.join("executor.key");
    std::fs::write(&key, "5a".repeat(32)).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let pol = dir.join("policy.json");
    std::fs::write(
        &pol,
        serde_json::to_string(&policy(Morphology::WheeledMobile, &[])).unwrap(),
    )
    .unwrap();
    let mut v = config_json(dir);
    v["socket"] = json!(socket);
    v["key_file"] = json!(key);
    v["policy_path"] = json!(pol);
    v["nft"] = json!(NFT);
    let cfg = dir.join("executor.json");
    std::fs::write(&cfg, v.to_string()).unwrap();
    cfg
}

/// M4: the real binary deletes the table on a fatal start error (here the
/// socket path is taken by a regular file), and `stop-cleanup` (systemd
/// `ExecStopPost=`) does after any run that did not succeed.
#[test]
fn m4_binary_failed_start_and_stop_cleanup_leave_no_rule() {
    let Some(lab) = Lab::new() else { return };
    let dir = lab.state_dir("m4bin");
    let sock = dir.join("taken.sock");
    std::fs::write(&sock, b"not a socket").unwrap();
    let cfg_path = binary_files(&dir, &sock);
    let boot = robodr_executor::boot_id();
    let cfg = robodr_executor::ExecutorConfig::parse(&std::fs::read_to_string(&cfg_path).unwrap())
        .unwrap()
        .validate()
        .unwrap();
    let install = |id: &str| {
        let mut e = Engine::open(
            cfg.clone(),
            policy(Morphology::WheeledMobile, &[]),
            Box::new(lab.nft()),
            &boot,
            robodr_executor::engine::Now::system(),
        )
        .unwrap();
        let o = order(id, ActionId::IsolateNetwork, Morphology::WheeledMobile);
        let out = submit(
            &mut e,
            &o,
            &mut idle(),
            robodr_executor::engine::Now::system(),
        );
        assert_eq!(out.status, Status::Verified, "{out:?}");
        assert!(nft::table_exists(&mut lab.nft()).unwrap());
    };
    install("i-bin1");
    let bin = env!("CARGO_BIN_EXE_robodr-executor");
    let run = |args: &[&str], env: &[(&str, &str)]| {
        let mut c = Command::new(IP);
        c.args(["netns", "exec", &lab.robot, bin]).args(args);
        for (k, v) in env {
            c.env(k, v);
        }
        c.stdin(Stdio::null()).output().unwrap()
    };
    let out = run(&["--config", cfg_path.to_str().unwrap()], &[]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(
        !nft::table_exists(&mut lab.nft()).unwrap(),
        "a failed start left the rules: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let st = robodr_executor::journal::Journal::new(&dir).load();
    match st {
        robodr_executor::journal::Loaded::State(s) => {
            assert!(s.entries.is_empty());
            assert!(!s.operator_disabled);
        }
        other => panic!("{other:?}"),
    }
    // ExecStopPost= after a crash: the table goes, the journal says so.
    install("i-bin2");
    let out = run(
        &["stop-cleanup", "--config", cfg_path.to_str().unwrap()],
        &[("SERVICE_RESULT", "signal")],
    );
    assert!(out.status.success(), "{out:?}");
    assert!(!nft::table_exists(&mut lab.nft()).unwrap());
    // ... but not after a clean stop.
    std::fs::remove_file(&sock).unwrap();
    install("i-bin3");
    let out = run(
        &["stop-cleanup", "--config", cfg_path.to_str().unwrap()],
        &[("SERVICE_RESULT", "success")],
    );
    assert!(out.status.success());
    assert!(nft::table_exists(&mut lab.nft()).unwrap());
    let e = Engine::open(
        cfg.clone(),
        policy(Morphology::WheeledMobile, &[]),
        Box::new(lab.nft()),
        &boot,
        robodr_executor::engine::Now::system(),
    )
    .unwrap();
    assert_eq!(e.status("i-bin2").status, Status::Reverted);
    assert_eq!(e.status("i-bin3").status, Status::Verified);
}

/// L4 and M3 through the protocol: actions held after a reboot are re-armed
/// only when agentd's event poll supplies a fresh safety state; `rearm` ends
/// an emergency disable.
#[test]
fn l4_m3_rearm_through_the_protocol() {
    let Some(lab) = Lab::new() else { return };
    let dir = lab.state_dir("rearm");
    let cfgr = config(&dir);
    let sock = cfgr.config.socket.clone();
    let key_bytes = [0x5bu8; 32];
    let now = robodr_executor::engine::Now::system;
    let mut e = Engine::open(
        cfgr.clone(),
        policy(Morphology::WheeledMobile, &[]),
        Box::new(lab.nft()),
        "boot-1",
        now(),
    )
    .unwrap();
    let i = order("i-pr", ActionId::IsolateNetwork, Morphology::WheeledMobile);
    assert_eq!(
        submit(&mut e, &i, &mut idle(), now()).status,
        Status::Verified
    );
    drop(e);
    // Reboot.
    lab.nft_cmd(&["delete", "table", "inet", "robodr"]).unwrap();
    let engine = Engine::open(
        cfgr.clone(),
        policy(Morphology::WheeledMobile, &[]),
        Box::new(lab.nft()),
        "boot-2",
        now(),
    )
    .unwrap();
    let listener = robodr_executor::server::bind(&sock, 0o600).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let st = stop.clone();
    let server = std::thread::spawn(move || {
        let mut engine = engine;
        let key = Key::from_bytes(key_bytes);
        robodr_executor::server::serve(
            &listener,
            &mut engine,
            &key,
            "boot-2",
            &|| st.load(Ordering::SeqCst),
            &mut |_, _| {},
        )
    });
    let client = Client::new(sock, Key::from_bytes(key_bytes), Duration::from_secs(5));
    assert_eq!(client.health().unwrap().held, 1);
    assert_eq!(client.status("i-pr").unwrap().status, Status::Held);
    // A poll without a safety state, then with an engaged one: still held.
    client.events(0).unwrap();
    client
        .events_with_safety(0, &mut || Ok((SafetyState::EStopActive, 2)))
        .unwrap();
    assert_eq!(client.status("i-pr").unwrap().status, Status::Held);
    assert!(!nft::table_exists(&mut lab.nft()).unwrap());
    // A fresh, known one: re-armed.
    let evs = client
        .events_with_safety(0, &mut || Ok((SafetyState::Idle, 2)))
        .unwrap();
    assert!(evs
        .iter()
        .any(|e| e.kind == robodr_executor::journal::EventKind::Held));
    assert_eq!(client.status("i-pr").unwrap().status, Status::Verified);
    assert_eq!(lab.peer_to_robot(&format!("{OTHER}:0"), 9000, b"x"), 0);
    // Emergency disable, then a new order (refused), then rearm.
    lab.nft_cmd(&["delete", "table", "inet", "robodr"]).unwrap();
    let q = order("q-pr", ActionId::QuarantineNode, Morphology::WheeledMobile);
    let out = client
        .submit(&q, &mut || Ok((SafetyState::Idle, 2)))
        .unwrap();
    assert_eq!(out.refusal.unwrap().code, codes::OPERATOR_DISABLED);
    assert!(client.health().unwrap().operator_disabled);
    // Review finding 2: the protocol socket has no re-arm (agentd holds its
    // key); the operator re-arms on the journal with the executor stopped.
    assert!(robodr_executor::server::serving(&cfgr.config.socket).unwrap());
    stop.store(true, Ordering::SeqCst);
    server.join().unwrap();
    assert!(!robodr_executor::server::serving(&cfgr.config.socket).unwrap());
    let mut e = Engine::open(
        cfgr,
        policy(Morphology::WheeledMobile, &[]),
        Box::new(lab.nft()),
        "boot-2",
        now(),
    )
    .unwrap();
    assert!(e.rearm("lab", now()).unwrap());
    let q2 = order("q-pr2", ActionId::QuarantineNode, Morphology::WheeledMobile);
    let out = submit(&mut e, &q2, &mut idle(), now());
    assert_eq!(out.status, Status::Verified, "{out:?}");
}

/// IPv6 (this kernel may have none: the rules are still loaded and read
/// back), interface-bound entries and the shipped examples render to rules
/// that nft accepts and lists back exactly.
#[test]
fn ipv6_interface_and_example_renderings_read_back_exactly() {
    let Some(lab) = Lab::new() else { return };
    let dir = lab.state_dir("v6");
    let cfg = config_with(&dir, |v| {
        v["network"]["management"] = json!([
            {"cidr": "fd00::10", "proto": "tcp", "port": 22},
            {"cidr": "10.99.0.10", "proto": "udp", "port": 5000}
        ]);
        v["network"]["uplink"] = json!([{"cidr": "fd00:20::/64"}]);
        v["network"]["control_buses"] =
            json!({"exempt": true, "entries": [{"interface": "eth1", "proto": "udp"}]});
        v["network"]["motion_control_path"] = json!([
            {"interface": "eth1", "cidr": "fd00:1::/64", "udp_ports": [7400, 7600],
             "guid_prefix": GUID, "low_level": true},
            {"interface": "eth2", "udp_ports": [7410, 7410]}
        ]);
        v["network"]["discovery"] =
            json!({"multicast_groups": ["239.255.0.1", "ff02::ffff:efff:1"], "domains": [0, 1]});
    });
    let mut e = Engine::open(
        cfg,
        policy(Morphology::WheeledMobile, &[]),
        Box::new(lab.nft()),
        "boot-1",
        1_000,
    )
    .unwrap();
    let i = order("i-v6", ActionId::IsolateNetwork, Morphology::WheeledMobile);
    let out = submit(&mut e, &i, &mut idle(), 1_000);
    assert_eq!(out.status, Status::Verified, "{out:?}");
    let mut q = order("q-v6", ActionId::QuarantineNode, Morphology::WheeledMobile);
    q.target = Target::Participant {
        guid_prefix: OTHER_GUID.parse().unwrap(),
        locators: vec![Locator {
            ip: "fd00:30::7".parse().unwrap(),
            port: 7410,
        }],
        guid_only: false,
        excluded: Vec::new(),
        addresses: Vec::new(),
        excluded_addresses: Vec::new(),
        evidence_truncated: false,
    };
    // Interface-only motion path entries cannot be proven: refused.
    assert_eq!(
        submit(&mut e, &q, &mut idle(), 1_000).refusal.unwrap().code,
        codes::MOTION_PATH
    );
    let listed = nft::read_table(&mut lab.nft()).unwrap();
    assert_eq!(nft::verify(listed.as_deref(), &e.rendered()), Ok(()));
    let text = lab.nft_cmd(&["list", "table", "inet", "robodr"]).unwrap();
    for want in [
        "frag frag-off != 0",
        "ip6 daddr ff02::ffff:efff:1 udp dport { 7400, 7401, 7650, 7651 }",
        "oifname \"eth1\" meta l4proto igmp",
        "tcp flags != syn / syn,ack",
        "ct state established",
        "icmp type destination-unreachable icmp code frag-needed",
        "udp sport 67 udp dport 68",
        "udp sport 547 udp dport 546",
    ] {
        assert!(text.contains(want), "{want:?} missing in\n{text}");
    }
    assert_eq!(e.revert("i-v6", "lab", 2_000).status, Status::Reverted);
    // The shipped examples.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config");
    for name in ["executor.example.json", "executor.unitree-g1.example.json"] {
        let mut v: Value =
            serde_json::from_str(&std::fs::read_to_string(root.join(name)).unwrap()).unwrap();
        let d = lab.state_dir(name);
        v["state_dir"] = json!(d);
        // The lab SOC's key in place of the example's path, and a robot key
        // (another key: the example's robot key files do not exist here).
        v["soc"]["keys"] = json!([soc_key_path()]);
        v["soc"]["robot_keys"] = json!([robot_key_path()]);
        v["robot_id"] = json!("lab-robot");
        let c = ExecutorConfig::parse(&v.to_string())
            .unwrap()
            .validate()
            .unwrap();
        let mut e = Engine::open(
            c,
            policy(Morphology::WheeledMobile, &[]),
            Box::new(lab.nft()),
            "boot-1",
            1_000,
        )
        .unwrap();
        let i = order("i-ex", ActionId::IsolateNetwork, Morphology::WheeledMobile);
        let out = submit(&mut e, &i, &mut idle(), 1_000);
        assert_eq!(out.status, Status::Verified, "{name}: {out:?}");
        assert_eq!(e.revert("i-ex", "lab", 2_000).status, Status::Reverted);
    }
}
