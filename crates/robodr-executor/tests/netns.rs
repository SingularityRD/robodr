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

/// Two namespaces and a veth pair; removed on drop.
struct Lab {
    robot: String,
    peer: String,
    dir: PathBuf,
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = sh(&["ip", "netns", "del", &self.robot]);
        let _ = sh(&["ip", "netns", "del", &self.peer]);
        let _ = std::fs::remove_dir_all(&self.dir);
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
        match Self::try_new() {
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

    fn try_new() -> Result<Lab, String> {
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
        let lab = Lab {
            robot: robot.clone(),
            peer: peer.clone(),
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
        }
        Ok(lab)
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

    /// Send `count` datagrams from `src` (ns `from`) to `dst` and count what
    /// arrives at `dst` (ns `to`).
    fn probe(&self, from: &str, src: &str, to: &str, dst: &str, payload: &[u8]) -> usize {
        let exe = std::env::current_exe().unwrap();
        let mut rx = Command::new("ip")
            .args(["netns", "exec", to])
            .arg(&exe)
            .args(["--exact", "netns_helper", "--nocapture", "--test-threads=1"])
            .env(HELPER_ENV, format!("recv {dst} 700"))
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
        let hex: String = payload.iter().map(|b| format!("{b:02x}")).collect();
        let st = Command::new("ip")
            .args(["netns", "exec", from])
            .arg(&exe)
            .args(["--exact", "netns_helper", "--nocapture", "--test-threads=1"])
            .env(HELPER_ENV, format!("send {src} {dst} {hex}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(st.success(), "sender failed");
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
            let mut buf = [0u8; 2048];
            while Instant::now() < end {
                if s.recv_from(&mut buf).is_ok() {
                    n += 1;
                }
            }
            println!("HELPER:count={n}");
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
    ExecutorConfig::parse(
        &json!({
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
                ]
            },
            "ttl": {"default_s": 600, "max_s": 3600},
            "max_safety_age_ms": 1000
        })
        .to_string(),
    )
    .unwrap()
    .validate()
    .unwrap()
}

fn policy(m: Morphology, fsr: &[RestrictTarget]) -> ResponsePolicy {
    let mut p = ResponsePolicy::conservative_default(PlatformFamily::Ugv);
    p.morphology = m;
    p.oem_validated = true;
    p.fall_safe_restrict = fsr.to_vec();
    p
}

fn order(id: &str, action: ActionId, m: Morphology) -> Order {
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
            key_id: "soc:lab:1".into(),
            requested_by: "lab".into(),
        },
        issued_ms: 0,
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
    let out = e.submit(&o, &mut idle(), 1_000);
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
    let out = e.submit(
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

#[test]
fn revert_of_one_action_restores_the_exact_earlier_ruleset() {
    let Some(lab) = Lab::new() else { return };
    foreign_tables(&lab);
    let dir = lab.state_dir("two");
    let mut e = open(&lab, &dir, "boot-1", Morphology::WheeledMobile, 1_000);
    let q = order("q-1", ActionId::QuarantineNode, Morphology::WheeledMobile);
    assert_eq!(e.submit(&q, &mut idle(), 1_000).status, Status::Verified);
    let with_q = lab.ruleset();
    let i = order("i-1", ActionId::IsolateNetwork, Morphology::WheeledMobile);
    assert_eq!(e.submit(&i, &mut idle(), 1_000).status, Status::Verified);
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
    assert_eq!(e.submit(&i, &mut idle(), 1_000).status, Status::Verified);
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
    assert_eq!(e.submit(&i, &mut idle(), 1_000).status, Status::Verified);
    let applied = lab.ruleset();
    drop(e);
    // Restart, same boot: re-verified, unchanged.
    let e = open(&lab, &dir, "boot-1", Morphology::WheeledMobile, 2_000);
    assert_eq!(e.status("i-1").status, Status::Verified);
    assert_eq!(lab.ruleset(), applied);
    drop(e);
    // Reboot (kernel ruleset empty, new boot id): re-applied, still blocks.
    lab.nft_cmd(&["delete", "table", "inet", "robodr"]).unwrap();
    let e = open(&lab, &dir, "boot-2", Morphology::WheeledMobile, 3_000);
    assert_eq!(e.status("i-1").status, Status::Verified);
    assert_eq!(lab.ruleset(), applied);
    assert_eq!(lab.peer_to_robot(&format!("{OTHER}:0"), 9000, b"x"), 0);
    drop(e);
    // Operator emergency disable (same boot) while the executor is down:
    // honoured, not re-applied.
    lab.nft_cmd(&["delete", "table", "inet", "robodr"]).unwrap();
    let mut e = open(&lab, &dir, "boot-2", Morphology::WheeledMobile, 4_000);
    assert_eq!(e.status("i-1").status, Status::RemovedExternally);
    assert_eq!(lab.peer_to_robot(&format!("{OTHER}:0"), 9000, b"x"), 3);
    // ... and while it runs.
    let i2 = order("i-2", ActionId::IsolateNetwork, Morphology::WheeledMobile);
    assert_eq!(e.submit(&i2, &mut idle(), 5_000).status, Status::Verified);
    lab.nft_cmd(&["delete", "table", "inet", "robodr"]).unwrap();
    e.periodic_verify(6_000);
    assert_eq!(e.status("i-2").status, Status::RemovedExternally);
    e.tick(60_000);
    assert!(!nft::table_exists(&mut lab.nft()).unwrap());
    // Drift: a rule removed by hand is put back.
    let i3 = order("i-3", ActionId::IsolateNetwork, Morphology::WheeledMobile);
    assert_eq!(e.submit(&i3, &mut idle(), 61_000).status, Status::Verified);
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
    assert_eq!(e.submit(&q, &mut idle(), 1_000).status, Status::Verified);
    let before = lab.ruleset();
    robodr_executor::fault::arm(robodr_executor::fault::Point::AfterApply);
    let out = e.submit(
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
        let out = e.submit(
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
    let mut o = order("h-iso", ActionId::IsolateNetwork, Morphology::Humanoid);
    o.human_approved = false;
    assert_eq!(
        e.submit(&o, &mut idle(), 2_000).refusal.unwrap().code,
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
    let mut asked = 0;
    let o = order("p-1", ActionId::IsolateNetwork, Morphology::WheeledMobile);
    let out = client
        .submit(&o, &mut || {
            asked += 1;
            Ok((SafetyState::MovingSlow, 3))
        })
        .unwrap();
    assert_eq!(asked, 1);
    assert_eq!(out.refusal.unwrap().code, codes::SAFETY_STATE_CHANGED);
    let o = order("p-2", ActionId::IsolateNetwork, Morphology::WheeledMobile);
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
    // Revert through the protocol.
    assert_eq!(
        client.revert("p-2", "lab").unwrap().status,
        Status::Reverted
    );
    assert_eq!(lab.peer_to_robot(&format!("{OTHER}:0"), 9000, b"x"), 3);
    stop.store(true, Ordering::SeqCst);
    let stats = server.join().unwrap();
    assert!(stats.rejected >= 1);
}
