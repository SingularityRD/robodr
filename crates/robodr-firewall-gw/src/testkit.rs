//! Test support shared by the integration tests, the latency harness, the
//! end-to-end netns test and the fuzz harness: synthetic Unitree frames
//! inside RTPS datagrams inside IPv4/UDP packets, SEDP announcements, and
//! gateway fixtures built from the shipped example firewall configurations.
//! Not used by the gateway itself, and only compiled with the test-only
//! `testkit` feature (see Cargo.toml), never into the shipped binary.
//!
//! The fixture builders fail fast: a fixture that silently degraded (a
//! missing example configuration read as an empty one) would make every
//! test that uses it vacuous. That is why this module, alone in the crate,
//! may panic outside `cfg(test)`.
#![allow(clippy::panic)]

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use robodr_cdr::Representation;
use robodr_events::profile::{Envelope, Profile};
use robodr_firewall::{ChannelKind, ChannelSpec, FirewallConfig, JointChannelSpec, MotorLimits};

use crate::config::GatewayConfig;
use crate::ip::build_ipv4_udp;
use crate::lowcmd::{self, LowCmdCodec, WireLowCmd, WireMotor};
use crate::rtps::build::Datagram;
use crate::rtps::GuidPrefix;
use crate::Gateway;

/// The participant prefix of the example configurations' allowed writer.
pub const PREFIX: GuidPrefix = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
];
/// Its writer entity (`...00000103`).
pub const WRITER: [u8; 4] = [0, 0, 0x01, 0x03];
/// The sport request writer entity of the fixtures.
pub const SPORT_WRITER: [u8; 4] = [0, 0, 0x02, 0x03];
/// A participant nobody authorised.
pub const FOREIGN: GuidPrefix = [0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8];
pub const CONTROLLER_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 123, 164);
pub const ROBOT_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 123, 161);
pub const ATTACKER_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 123, 99);
/// A user-traffic unicast port of domain 0.
pub const DDS_PORT: u16 = 7411;

/// `../../config` of this crate.
pub fn config_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config")
}

/// A shipped example firewall configuration (panics if it is missing or
/// does not parse: the fixtures are built from it).
pub fn example_firewall(name: &str) -> FirewallConfig {
    let path = config_dir().join(name);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => panic!("fixture firewall {}: {e}", path.display()),
    };
    match FirewallConfig::from_json(&text) {
        Ok(f) => f,
        Err(e) => panic!("fixture firewall {}: {e}", path.display()),
    }
}

/// The 32-hex GUID of `PREFIX` + `entity`.
pub fn guid_hex(prefix: &GuidPrefix, entity: [u8; 4]) -> String {
    prefix
        .iter()
        .chain(entity.iter())
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Which fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fixture {
    /// G1 (humanoid, hg `LowCmd_`, 35 slots).
    G1,
    /// Go2 (quadruped, go `LowCmd_`, 20 slots) + sport API + Go1 legacy
    /// `HighCmd` / `LowCmd` channels.
    Go2,
}

/// A locked profile with the fixture's motion channels.
pub fn profile(fx: Fixture) -> Profile {
    let mut p = Profile {
        model: "unitree-fixture".into(),
        locked: true,
        ..Default::default()
    };
    p.participants
        .insert(guid_hex(&PREFIX, WRITER)[..24].to_string());
    let mut add = |name: &str, env: Envelope| {
        p.writer_topics.insert(name.to_string());
        p.motion_envelopes.insert(name.to_string(), env);
    };
    add(
        "/lowcmd",
        Envelope {
            max_joint_speed: Some(40.0),
            ..Default::default()
        },
    );
    if fx == Fixture::Go2 {
        for name in ["/api/sport/request", "/legacy/high_cmd"] {
            add(
                name,
                Envelope {
                    max_linear_speed: Some(1.5),
                    ..Default::default()
                },
            );
        }
        add(
            "/legacy/low_cmd",
            Envelope {
                max_joint_speed: Some(40.0),
                ..Default::default()
            },
        );
    }
    p
}

/// The fixture's firewall configuration: the shipped example plus, for
/// Go2, a sport twist channel and the two legacy channels.
pub fn firewall(fx: Fixture) -> FirewallConfig {
    match fx {
        Fixture::G1 => example_firewall("firewall.unitree-g1.example.json"),
        Fixture::Go2 => {
            let mut f = example_firewall("firewall.unitree-go2.example.json");
            let src = guid_hex(&PREFIX, WRITER);
            let twist = |src: String| ChannelSpec {
                kind: ChannelKind::Twist,
                allowed_sources: vec![src],
                max_linear_speed: Some(1.0),
                max_angular_speed: Some(1.0),
                ..Default::default()
            };
            f.channels.insert(
                "/api/sport/request".into(),
                twist(guid_hex(&PREFIX, SPORT_WRITER)),
            );
            f.channels.insert("/legacy/high_cmd".into(), twist(src));
            let Some(low) = f.joint_channels.get("/lowcmd").cloned() else {
                panic!("fixture firewall: the Go2 example has no /lowcmd joint channel");
            };
            f.joint_channels.insert("/legacy/low_cmd".into(), low);
            f
        }
    }
}

/// The fixture's gateway configuration (paths are placeholders: tests
/// build the gateway with [`gateway`]).
pub fn gateway_config(fx: Fixture) -> GatewayConfig {
    let src = guid_hex(&PREFIX, WRITER);
    let mut channels = vec![serde_json::json!({
        "firewall_channel": "/lowcmd",
        "codec": if fx == Fixture::G1 { "unitree_hg_lowcmd" } else { "unitree_go_lowcmd" },
    })];
    if fx == Fixture::Go2 {
        // The allowlist includes Damp (1001, `ROBOT_SPORT_API_ID_DAMP`,
        // unitree_sdk2 `include/unitree/robot/go2/sport/sport_api.hpp:19`):
        // it makes the robot go limp and settle to the ground, so it is
        // reachable by anyone who can present an allowed source. Kept on
        // purpose (operators use it as a soft stop and the tests exercise a
        // non-velocity call through the allowlist); a deployment should list
        // only the calls its controller uses (see the README).
        channels.push(serde_json::json!({
            "firewall_channel": "/api/sport/request",
            "codec": "unitree_sport_request",
            "allowed_api_ids": [1003, 1008, 1001, 1004],
        }));
        channels.push(serde_json::json!({
            "firewall_channel": "/legacy/high_cmd",
            "codec": "go1_high_cmd",
            "legacy_sources": { CONTROLLER_IP.to_string(): src.clone() },
            "allowed_high_modes": [0, 1, 2, 5, 6],
        }));
        channels.push(serde_json::json!({
            "firewall_channel": "/legacy/low_cmd",
            "codec": "go1_low_cmd",
            "legacy_sources": { CONTROLLER_IP.to_string(): src },
        }));
    }
    let v = serde_json::json!({
        "mode": "enforce",
        "profile": "/nonexistent/profile.json",
        "firewall": "/nonexistent/firewall.json",
        "queue": { "num": 0, "controller_port": "ctrl0", "robot_port": "robot0" },
        "channels": channels,
    });
    match GatewayConfig::from_json(&v.to_string()) {
        Ok(c) => c,
        Err(e) => panic!("fixture config: {e}"),
    }
}

/// A ready gateway for the fixture.
pub fn gateway(fx: Fixture) -> Gateway {
    match Gateway::new(&gateway_config(fx), &profile(fx), &firewall(fx)) {
        Ok(g) => g,
        Err(e) => panic!("fixture gateway: {e}"),
    }
}

/// A frame holding every enabled slot of `motors` at the middle of its
/// range with moderate gains; `phase` moves the targets a little.
pub fn mid_frame(
    codec: LowCmdCodec,
    motors: &[MotorLimits],
    phase: f64,
    pins: (Option<u8>, Option<u8>),
) -> WireLowCmd {
    let mut m = lowcmd::template(codec);
    for (i, lim) in motors.iter().enumerate() {
        if lim.enabled {
            let (lo, hi) = (lim.q_min.unwrap_or(0.0), lim.q_max.unwrap_or(0.0));
            let q = (lo + hi) / 2.0 + 0.01 * (phase + i as f64).sin();
            m.set_motor(
                i,
                WireMotor {
                    mode: 0x01,
                    q: q as f32,
                    dq: 0.0,
                    tau: 0.0,
                    kp: lim.kp_min.max(20.0) as f32,
                    kd: lim.kd_min.max(1.0) as f32,
                },
            );
        }
    }
    if let WireLowCmd::Hg(h) = &mut m {
        h.mode_pr = pins.0.unwrap_or(0);
        h.mode_machine = pins.1.unwrap_or(0);
    }
    m.seal();
    m
}

/// The fixture's `/lowcmd` motor table and pins.
pub fn lowcmd_spec(fx: Fixture) -> JointChannelSpec {
    match firewall(fx).joint_channels.get("/lowcmd") {
        Some(s) => s.clone(),
        None => panic!("fixture firewall {fx:?}: no /lowcmd joint channel"),
    }
}

/// The codec of the fixture's `/lowcmd`.
pub fn codec(fx: Fixture) -> LowCmdCodec {
    match fx {
        Fixture::G1 => LowCmdCodec::Hg,
        Fixture::Go2 => LowCmdCodec::Go,
    }
}

/// An RTPS datagram `INFO_TS, DATA(lowcmd), HEARTBEAT` from `prefix`.
pub fn lowcmd_datagram(
    prefix: GuidPrefix,
    entity: [u8; 4],
    sn: i64,
    msg: &WireLowCmd,
    rep: Representation,
) -> Vec<u8> {
    let payload = lowcmd::encode_payload(msg, rep);
    Datagram::new(prefix)
        .info_ts(1_700_000_000, 0)
        .data(entity, sn, &[], &payload)
        .heartbeat(entity, 1, sn)
        .finish()
}

/// Wrap an RTPS datagram (or a legacy frame) in IPv4 / UDP.
pub fn packet(src: Ipv4Addr, dst_port: u16, udp_payload: &[u8]) -> Vec<u8> {
    build_ipv4_udp(src, ROBOT_IP, 50_000, dst_port, udp_payload)
}

/// An SEDP publication DATA (PL_CDR_LE) announcing `writer` on `topic`
/// with `type_name`, from participant `prefix`.
pub fn sedp_datagram(prefix: GuidPrefix, writer: [u8; 4], topic: &str, type_name: &str) -> Vec<u8> {
    fn param(out: &mut Vec<u8>, pid: u16, value: &[u8]) {
        let mut v = value.to_vec();
        while !v.len().is_multiple_of(4) {
            v.push(0);
        }
        out.extend_from_slice(&pid.to_le_bytes());
        out.extend_from_slice(&(v.len() as u16).to_le_bytes());
        out.extend_from_slice(&v);
    }
    fn cdr_string(s: &str) -> Vec<u8> {
        let mut v = ((s.len() + 1) as u32).to_le_bytes().to_vec();
        v.extend_from_slice(s.as_bytes());
        v.push(0);
        v
    }
    let mut p = vec![0x00, 0x03, 0x00, 0x00];
    let mut guid = prefix.to_vec();
    guid.extend_from_slice(&writer);
    param(&mut p, 0x005a, &guid); // PID_ENDPOINT_GUID
    let mut part = prefix.to_vec();
    part.extend_from_slice(&[0, 0, 1, 0xc1]);
    param(&mut p, 0x0050, &part); // PID_PARTICIPANT_GUID
    param(&mut p, 0x0005, &cdr_string(topic)); // PID_TOPIC_NAME
    param(&mut p, 0x0007, &cdr_string(type_name)); // PID_TYPE_NAME
    p.extend_from_slice(&[1, 0, 0, 0]); // PID_SENTINEL
    Datagram::new(prefix)
        .data([0, 0, 3, 0xc2], 1, &[], &p)
        .finish()
}

// --- More channels on a G1 (loco, arm SDK, hands, ROS 2 twist) ---------------

/// Writer entities of the extra channels (all in participant [`PREFIX`]).
pub const ARM_WRITER: [u8; 4] = [0, 0, 0x03, 0x03];
pub const LOCO_WRITER: [u8; 4] = [0, 0, 0x04, 0x03];
pub const DEX3_WRITER: [u8; 4] = [0, 0, 0x05, 0x03];
pub const HAND_SDK_WRITER: [u8; 4] = [0, 0, 0x06, 0x03];
pub const TWIST_WRITER: [u8; 4] = [0, 0, 0x07, 0x03];
/// Twist limits of the loco and `/cmd_vel` channels.
pub const TWIST_MAX_LIN: f64 = 0.8;
pub const TWIST_MAX_ANG: f64 = 1.0;
/// Finger joints of the hand channels: `|q| <= 1.5`, `|dq| <= 10`,
/// `|tau| <= 2`, `kp <= 5`, `kd <= 1`.
pub const HAND_Q: f64 = 1.5;
/// Elements of the Dex3 / hand-SDK fixtures.
pub const DEX3_MOTORS: usize = 7;
pub const HAND_SDK_MOTORS: usize = 4;

/// The G1 profile plus the extra channels.
pub fn g1_channels_profile() -> Profile {
    let mut p = profile(Fixture::G1);
    let mut add = |name: &str, env: Envelope| {
        p.writer_topics.insert(name.to_string());
        p.motion_envelopes.insert(name.to_string(), env);
    };
    for name in ["/arm_sdk", "/dex3_left", "/hand_sdk"] {
        add(
            name,
            Envelope {
                max_joint_speed: Some(40.0),
                ..Default::default()
            },
        );
    }
    for name in ["/loco", "/cmd_vel"] {
        add(
            name,
            Envelope {
                max_linear_speed: Some(1.5),
                ..Default::default()
            },
        );
    }
    p
}

fn hand_spec(writer: [u8; 4], n: usize) -> JointChannelSpec {
    let motor = serde_json::json!({
        "enabled": true, "q_min": -HAND_Q, "q_max": HAND_Q, "dq_max": 10.0, "tau_max": 2.0,
        "kp_min": 0.0, "kp_max": 5.0, "kd_min": 0.0, "kd_max": 1.0,
        "allow_limp": true, "max_dq_step": 0.5, "tau_pd_max": 2.0
    });
    let v = serde_json::json!({
        "allowed_sources": [guid_hex(&PREFIX, writer)],
        "require_crc": false,
        "rate": {"expected_hz": 50.0, "min_interval_ns": 1_000_000, "max_interval_ns": 100_000_000},
        "motors": vec![motor; n],
    });
    match serde_json::from_value(v) {
        Ok(s) => s,
        Err(e) => panic!("fixture hand spec: {e}"),
    }
}

/// The G1 firewall plus: `/arm_sdk` (the `/lowcmd` arm envelope, legs and
/// waist disabled, slot 29 the weight), `/dex3_left` and `/hand_sdk`
/// (finger envelope), `/loco` and `/cmd_vel` (twist channels).
pub fn g1_channels_firewall() -> FirewallConfig {
    let mut f = firewall(Fixture::G1);
    let Some(mut arm) = f.joint_channels.get("/lowcmd").cloned() else {
        panic!("fixture firewall: the G1 example has no /lowcmd joint channel");
    };
    arm.allowed_sources = vec![guid_hex(&PREFIX, ARM_WRITER)];
    arm.rate = match serde_json::from_value(serde_json::json!(
        {"expected_hz": 50.0, "min_interval_ns": 1_000_000, "max_interval_ns": 100_000_000}
    )) {
        Ok(r) => Some(r),
        Err(e) => panic!("fixture rate: {e}"),
    };
    for m in arm.motors.iter_mut().take(15) {
        *m = match serde_json::from_value(serde_json::json!({"enabled": false})) {
            Ok(m) => m,
            Err(e) => panic!("fixture motor: {e}"),
        };
    }
    f.joint_channels.insert("/arm_sdk".into(), arm);
    f.joint_channels
        .insert("/dex3_left".into(), hand_spec(DEX3_WRITER, DEX3_MOTORS));
    f.joint_channels.insert(
        "/hand_sdk".into(),
        hand_spec(HAND_SDK_WRITER, HAND_SDK_MOTORS),
    );
    for (name, writer) in [("/loco", LOCO_WRITER), ("/cmd_vel", TWIST_WRITER)] {
        f.channels.insert(
            name.into(),
            ChannelSpec {
                kind: ChannelKind::Twist,
                allowed_sources: vec![guid_hex(&PREFIX, writer)],
                max_linear_speed: Some(TWIST_MAX_LIN),
                max_angular_speed: Some(TWIST_MAX_ANG),
                ..Default::default()
            },
        );
    }
    f
}

/// The gateway configuration of [`g1_channels_firewall`]; `edit` patches
/// the JSON first (extra port ranges, allowlists, the loco model, ...).
pub fn g1_channels_config(edit: impl FnOnce(&mut serde_json::Value)) -> GatewayConfig {
    let mut v = serde_json::json!({
        "mode": "enforce",
        "profile": "/nonexistent/profile.json",
        "firewall": "/nonexistent/firewall.json",
        "queue": { "num": 0, "controller_port": "ctrl0", "robot_port": "robot0" },
        "channels": [
            {"firewall_channel": "/lowcmd", "codec": "unitree_hg_lowcmd"},
            {"firewall_channel": "/arm_sdk", "codec": "unitree_hg_arm_sdk", "weight_slot": 29},
            {"firewall_channel": "/loco", "codec": "unitree_loco_request", "robot_model": "g1"},
            {"firewall_channel": "/dex3_left", "codec": "unitree_dex3_hand_cmd",
             "topic": "rt/dex3/left/cmd"},
            {"firewall_channel": "/hand_sdk", "codec": "unitree_hand_sdk"},
            {"firewall_channel": "/cmd_vel", "codec": "ros2_twist"}
        ],
    });
    edit(&mut v);
    match GatewayConfig::from_json(&v.to_string()) {
        Ok(c) => c,
        Err(e) => panic!("fixture config: {e}"),
    }
}

/// A ready gateway with the extra channels.
pub fn g1_channels_gateway(edit: impl FnOnce(&mut serde_json::Value)) -> Gateway {
    match Gateway::new(
        &g1_channels_config(edit),
        &g1_channels_profile(),
        &g1_channels_firewall(),
    ) {
        Ok(g) => g,
        Err(e) => panic!("fixture gateway: {e}"),
    }
}

/// An RTPS datagram `INFO_TS, DATA(payload)` of `entity` in [`PREFIX`].
pub fn data_datagram(entity: [u8; 4], sn: i64, payload: &[u8]) -> Vec<u8> {
    Datagram::new(PREFIX)
        .info_ts(1_700_000_000, 0)
        .data(entity, sn, &[], payload)
        .heartbeat(entity, 1, sn)
        .finish()
}

/// An arm-SDK frame: arms (15..=28) at mid range with gains, mode 0, the
/// rest off, `motor_cmd[29].q = weight`.
pub fn arm_frame(weight: f32, phase: f64) -> WireLowCmd {
    let spec = g1_channels_firewall();
    let Some(arm) = spec.joint_channels.get("/arm_sdk") else {
        panic!("fixture: no /arm_sdk");
    };
    let mut m = mid_frame(LowCmdCodec::Hg, &arm.motors, phase, (Some(0), None));
    for i in 15..29 {
        if let Some(mut w) = m.motor(i) {
            w.mode = 0;
            m.set_motor(i, w);
        }
    }
    m.set_motor(
        29,
        WireMotor {
            q: weight,
            ..Default::default()
        },
    );
    m.seal();
    m
}

/// An SEDP publication / subscription with its own unicast locator
/// (`PID_UNICAST_LOCATOR`, UDPv4 `ip:port`).
pub fn sedp_with_locator(
    prefix: GuidPrefix,
    entity: [u8; 4],
    topic: &str,
    type_name: &str,
    reader: bool,
    ip: Ipv4Addr,
    port: u32,
) -> Vec<u8> {
    fn param(out: &mut Vec<u8>, pid: u16, value: &[u8]) {
        let mut v = value.to_vec();
        while !v.len().is_multiple_of(4) {
            v.push(0);
        }
        out.extend_from_slice(&pid.to_le_bytes());
        out.extend_from_slice(&(v.len() as u16).to_le_bytes());
        out.extend_from_slice(&v);
    }
    fn cdr_string(s: &str) -> Vec<u8> {
        let mut v = ((s.len() + 1) as u32).to_le_bytes().to_vec();
        v.extend_from_slice(s.as_bytes());
        v.push(0);
        v
    }
    let mut p = vec![0x00, 0x03, 0x00, 0x00];
    let mut guid = prefix.to_vec();
    guid.extend_from_slice(&entity);
    param(&mut p, 0x005a, &guid);
    param(&mut p, 0x0005, &cdr_string(topic));
    param(&mut p, 0x0007, &cdr_string(type_name));
    let mut loc = 1i32.to_le_bytes().to_vec();
    loc.extend_from_slice(&port.to_le_bytes());
    loc.extend_from_slice(&[0u8; 12]);
    loc.extend_from_slice(&ip.octets());
    param(&mut p, 0x002f, &loc); // PID_UNICAST_LOCATOR
    p.extend_from_slice(&[1, 0, 0, 0]);
    // SEDP publications writer (0xc2) / subscriptions writer (0x04c2).
    let w = if reader {
        [0, 0, 4, 0xc2]
    } else {
        [0, 0, 3, 0xc2]
    };
    Datagram::new(prefix).data(w, 1, &[], &p).finish()
}
