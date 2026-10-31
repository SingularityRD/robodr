//! Regression tests for the second review's gateway findings (each test
//! is the attack; it passed unchecked, or evicted state, before the fix):
//!
//! - **H1** a fragmented SEDP announcement whose fragment 1 went to another
//!   participant (harmless topic, kept by the reassembler) and again to
//!   everyone (motion topic, what the robot keeps): the writer used to be
//!   learned as not enforced and its fragmented `LowCmd_` passed.
//! - **H2** an enforced writer evicted from a full table, then re-announced
//!   on another topic by anyone: it used to become "not enforced" and its
//!   twists passed unprobed.
//! - **M1** a writer known as not enforced sending a whole `LowCmd_` in one
//!   DATA_FRAG: the suspicious-payload probe never ran.
//! - **M2** spoofed GUIDs under the authorised prefix from a forbidden IP
//!   evicted the genuine writer's sequence / replay state.

use std::time::{Duration, Instant};

use robodr_cdr::Representation;
use robodr_firewall_gw::config::{UnenforcedUnprobeable, UnknownWriters};
use robodr_firewall_gw::ip::parse_ipv4_udp;
use robodr_firewall_gw::lowcmd::{self, WireLowCmd};
use robodr_firewall_gw::rtps::{self, build::Datagram, Content, GuidPrefix, WalkOptions};
use robodr_firewall_gw::testkit::*;
use robodr_firewall_gw::{ros2, Gateway, GatewayConfig, PacketMeta, Verdict};

const MS: u64 = 1_000_000;
const T0: u64 = 1_000_000_000;
/// A participant nobody runs: the INFO_DST of the H1 attack.
const ELSEWHERE: GuidPrefix = [0x5e; 12];
const SEDP_PORT: u16 = 7410;
const SEDP_PUB: [u8; 4] = [0, 0, 3, 0xc2];
/// The attacker's writer entity (in its own participant `FOREIGN`).
const ROGUE: [u8; 4] = [0, 0, 0x33, 0x03];

fn guid(prefix: GuidPrefix, entity: [u8; 4]) -> [u8; 16] {
    let mut g = [0u8; 16];
    g[..12].copy_from_slice(&prefix);
    g[12..].copy_from_slice(&entity);
    g
}

/// Feeds packets with a controllable monotonic clock (`instant`) so the
/// enforced table's idle eviction can be exercised.
struct Clock(Instant);

impl Clock {
    fn at(&self, s: u64) -> PacketMeta {
        PacketMeta {
            now_ns: T0 + s * 1_000 * MS,
            queue_delay_ns: None,
            instant: self.0 + Duration::from_secs(s),
            src_mac: None,
        }
    }
}

fn send(gw: &mut Gateway, pkt: &[u8], m: PacketMeta) -> (Verdict, Vec<u8>) {
    let mut p = pkt.to_vec();
    let v = gw.process(&mut p, m);
    (v, p)
}

/// The first user sample's bytes left in `pkt`, DATA payload or DATA_FRAG
/// submessage (`None`: suppressed).
fn user_sample(pkt: &[u8]) -> Option<Vec<u8>> {
    let ip = parse_ipv4_udp(pkt).ok()?;
    let d = &pkt[ip.payload()];
    let mut v = Vec::new();
    rtps::walk(d, WalkOptions::default(), &mut v).ok()?;
    let s = v.iter().find(|s| !s.builtin)?;
    match s.payload.clone() {
        Some(r) if s.content == Content::Data => Some(d[r].to_vec()),
        _ => Some(d[s.sub.clone()].to_vec()),
    }
}

/// SEDP publication parameters (endpoint GUID, participant GUID, topic,
/// type), PL_CDR_LE.
fn sedp_payload(prefix: GuidPrefix, writer: [u8; 4], topic: &str, ty: &str) -> Vec<u8> {
    fn param(out: &mut Vec<u8>, pid: u16, value: &[u8]) {
        let mut v = value.to_vec();
        while !v.len().is_multiple_of(4) {
            v.push(0);
        }
        out.extend_from_slice(&pid.to_le_bytes());
        out.extend_from_slice(&(v.len() as u16).to_le_bytes());
        out.extend_from_slice(&v);
    }
    fn s(x: &str) -> Vec<u8> {
        let mut v = ((x.len() + 1) as u32).to_le_bytes().to_vec();
        v.extend_from_slice(x.as_bytes());
        v.push(0);
        v
    }
    let mut p = vec![0x00, 0x03, 0x00, 0x00];
    param(&mut p, 0x005a, &guid(prefix, writer));
    param(&mut p, 0x0050, &guid(prefix, [0, 0, 1, 0xc1]));
    param(&mut p, 0x0005, &s(topic));
    param(&mut p, 0x0007, &s(ty));
    p.extend_from_slice(&[1, 0, 0, 0]);
    p
}

fn frame(phase: f64) -> WireLowCmd {
    let fx = Fixture::G1;
    let spec = lowcmd_spec(fx);
    mid_frame(
        codec(fx),
        &spec.motors,
        phase,
        (spec.pinned_mode_pr, spec.pinned_mode_machine),
    )
}

/// A CRC-valid `LowCmd_` far outside the envelope.
fn evil_frame() -> WireLowCmd {
    let mut bad = frame(0.0);
    let mut w = bad.motor(0).unwrap();
    w.tau = 1e4;
    w.q = 100.0;
    bad.set_motor(0, w);
    bad.seal();
    bad
}

/// `writer`'s `LowCmd_` as one DATA_FRAG holding the whole sample.
fn lowcmd_frag(prefix: GuidPrefix, writer: [u8; 4], sn: i64, m: &WireLowCmd) -> Vec<u8> {
    let payload = lowcmd::encode_payload(m, Representation::CdrLe);
    let n = payload.len();
    Datagram::new(prefix)
        .data_frag(writer, sn, 1, n as u16, n as u32, &payload)
        .finish()
}

/// A G1 gateway that knows the robot's participant (INFO_DST checks).
fn g1(edit: impl FnOnce(&mut GatewayConfig)) -> Gateway {
    let mut cfg = gateway_config(Fixture::G1);
    edit(&mut cfg);
    let mut gw = Gateway::new(&cfg, &profile(Fixture::G1), &firewall(Fixture::G1)).unwrap();
    let spdp = spdp_with_locator(ROBOT_PREFIX, ROBOT_IP, 7410);
    gw.observe(&robot_packet(7400, &spdp), Clock(Instant::now()).at(0));
    assert!(gw.discovery().robot_prefixes().any(|p| *p == ROBOT_PREFIX));
    gw
}

// --------------------------------------------------------------------- H1

/// The review's H1 attack: fragment 1 to ELSEWHERE naming a harmless topic
/// (kept by the gateway), fragment 1 to everyone naming `rt/lowcmd` (what
/// the robot keeps: it drops the first copy), fragment 2. The writer is
/// never learned as not enforced; its fragmented out-of-envelope `LowCmd_`
/// is suppressed, also with `unknown_writers: pass` and
/// `unenforced_unprobeable: pass`.
#[test]
fn h1_contested_fragmented_announcement_never_unenforces_a_writer() {
    let mut gw = g1(|c| {
        c.rtps.unknown_writers = UnknownWriters::Pass;
        c.rtps.unenforced_unprobeable = UnenforcedUnprobeable::Pass;
    });
    let clock = Clock(Instant::now());
    let ty = "unitree_hg::msg::dds_::LowCmd_";
    let harmless = sedp_payload(FOREIGN, ROGUE, "rt/fooxyz", ty);
    let motion = sedp_payload(FOREIGN, ROGUE, "rt/lowcmd", ty);
    assert_eq!(harmless.len(), motion.len());
    let last_diff = (0..harmless.len())
        .rev()
        .find(|&i| harmless[i] != motion[i])
        .unwrap();
    let fs = (last_diff + 1).div_ceil(4) * 4;
    assert!(fs < harmless.len());
    let n = harmless.len() as u32;
    let f1 = |dst: Option<GuidPrefix>, p: &[u8]| {
        let mut d = Datagram::new(FOREIGN);
        if let Some(x) = dst {
            d.raw(rtps::INFO_DST, 0, &x);
        }
        d.data_frag(SEDP_PUB, 1, 1, fs as u16, n, &p[..fs]);
        packet(ATTACKER_IP, SEDP_PORT, &d.finish())
    };
    let f2 = packet(
        ATTACKER_IP,
        SEDP_PORT,
        &Datagram::new(FOREIGN)
            .data_frag(SEDP_PUB, 1, 2, fs as u16, n, &harmless[fs..])
            .finish(),
    );
    send(&mut gw, &f1(Some(ELSEWHERE), &harmless), clock.at(1));
    send(&mut gw, &f1(None, &motion), clock.at(1));
    send(&mut gw, &f2, clock.at(1));
    let w = guid(FOREIGN, ROGUE);
    assert_eq!(gw.discovery().stats.contested, 1);
    assert!(
        gw.discovery().writer(&w).is_none(),
        "never learned as not enforced: {:?}",
        gw.discovery().writer(&w)
    );
    assert!(gw.discovery().is_suspect(&w));
    // A later honest-looking re-announcement on the harmless topic does
    // not clear it.
    let sedp = Datagram::new(FOREIGN)
        .data(SEDP_PUB, 2, &[], &harmless)
        .finish();
    send(&mut gw, &packet(ATTACKER_IP, SEDP_PORT, &sedp), clock.at(2));
    assert!(gw.discovery().writer(&w).is_none());
    assert_eq!(gw.discovery().stats.suspect_kept, 1);
    // The writer's fragmented LowCmd_: suppressed, not passed.
    let pkt = packet(
        ATTACKER_IP,
        DDS_PORT,
        &lowcmd_frag(FOREIGN, ROGUE, 1, &evil_frame()),
    );
    let (_, out) = send(&mut gw, &pkt, clock.at(3));
    assert!(
        user_sample(&out).is_none(),
        "the DATA_FRAG reached the robot"
    );
    assert_eq!(gw.stats.unknown_undecidable, 1);
}

/// A contested announcement on an enforced topic is enforced, whatever its
/// INFO_DST (the robot may have completed it from another copy).
#[test]
fn h1_contested_announcement_on_an_enforced_topic_is_enforced() {
    let mut gw = g1(|_| {});
    let clock = Clock(Instant::now());
    let ty = "unitree_hg::msg::dds_::LowCmd_";
    let motion = sedp_payload(FOREIGN, ROGUE, "rt/lowcmd", ty);
    let other = sedp_payload(FOREIGN, ROGUE, "rt/fooxyz", ty);
    let last_diff = (0..motion.len())
        .rev()
        .find(|&i| motion[i] != other[i])
        .unwrap();
    let fs = (last_diff + 1).div_ceil(4) * 4;
    assert!(fs < motion.len());
    let n = motion.len() as u32;
    let mut d = Datagram::new(FOREIGN);
    d.raw(rtps::INFO_DST, 0, &ELSEWHERE)
        .data_frag(SEDP_PUB, 1, 1, fs as u16, n, &motion[..fs]);
    send(
        &mut gw,
        &packet(ATTACKER_IP, SEDP_PORT, &d.finish()),
        clock.at(1),
    );
    let mut d = Datagram::new(FOREIGN);
    d.data_frag(SEDP_PUB, 1, 1, fs as u16, n, &other[..fs])
        .data_frag(SEDP_PUB, 1, 2, fs as u16, n, &motion[fs..]);
    send(
        &mut gw,
        &packet(ATTACKER_IP, SEDP_PORT, &d.finish()),
        clock.at(1),
    );
    assert_eq!(gw.discovery().stats.contested, 1);
    assert_eq!(
        gw.discovery()
            .writer(&guid(FOREIGN, ROGUE))
            .and_then(|w| w.channel),
        Some(0)
    );
}

// --------------------------------------------------------------------- H2

/// The review's H2 attack on the twist channel: an enforced writer is
/// evicted from a full table (idle), then anyone re-announces its GUID on
/// another topic; its out-of-envelope twist is probed and decided (it used
/// to pass unprobed as a "not enforced" writer's sample), also with
/// `unknown_writers: pass`. The suspect memory is persisted.
#[test]
fn h2_evicted_enforced_writer_is_never_downgraded() {
    let mut gw = g1_channels_gateway(|v| {
        v["rtps"]["max_enforced_writers"] = serde_json::json!(1);
        v["rtps"]["enforced_idle_evict_s"] = serde_json::json!(60);
        v["rtps"]["unknown_writers"] = serde_json::json!("pass");
    });
    let clock = Clock(Instant::now());
    let spdp = spdp_with_locator(ROBOT_PREFIX, ROBOT_IP, 7410);
    gw.observe(&robot_packet(7400, &spdp), clock.at(0));
    let twist_ty = "geometry_msgs::msg::dds_::Twist_";
    // The victim: an enforced twist writer (any participant; here the
    // controller's own, idle after its first announcement).
    let victim = (PREFIX, [0, 0, 0x44, 0x03]);
    let sedp = sedp_datagram(victim.0, victim.1, "rt/cmd_vel", twist_ty);
    send(
        &mut gw,
        &packet(CONTROLLER_IP, SEDP_PORT, &sedp),
        clock.at(0),
    );
    let v = guid(victim.0, victim.1);
    assert_eq!(gw.discovery().writer(&v).and_then(|w| w.channel), Some(5));
    // 61 s later a flood announcement on an enforced topic evicts it.
    let flood = sedp_datagram(FOREIGN, [0, 0, 0x45, 0x03], "rt/cmd_vel", twist_ty);
    send(
        &mut gw,
        &packet(ATTACKER_IP, SEDP_PORT, &flood),
        clock.at(61),
    );
    assert_eq!(gw.discovery().stats.enforced_evicted, 1);
    assert!(gw.discovery().writer(&v).is_none());
    assert!(gw.discovery().is_suspect(&v));
    // Anyone re-announces the victim's GUID on another topic, with the
    // victim's prefix in the RTPS header (unauthenticated).
    let relabel = sedp_datagram(
        victim.0,
        victim.1,
        "rt/chatter",
        "std_msgs::msg::dds_::String_",
    );
    send(
        &mut gw,
        &packet(ATTACKER_IP, SEDP_PORT, &relabel),
        clock.at(62),
    );
    assert!(gw.discovery().writer(&v).is_none(), "downgraded");
    assert_eq!(gw.discovery().stats.suspect_kept, 1);
    // The victim GUID's out-of-envelope twist: probed and decided.
    let twist = ros2::encode([30.0, 0.0, 0.0, 0.0, 0.0, 20.0], None, false);
    let d = Datagram::new(victim.0)
        .data(victim.1, 1, &[], &twist)
        .finish();
    let samples = gw.stats.samples;
    let (_, out) = send(&mut gw, &packet(ATTACKER_IP, DDS_PORT, &d), clock.at(63));
    assert_eq!(gw.stats.samples, samples + 1, "probed and decided");
    assert!(
        user_sample(&out).is_none_or(|p| p != twist),
        "passed as sent"
    );

    // Persisted: a restarted gateway keeps the suspect.
    let dir = std::env::temp_dir().join(format!("rdr-gw-r2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let state = dir.join("writers.json");
    gw.discovery_mut().save(&state).unwrap();
    let text = std::fs::read_to_string(&state).unwrap();
    assert!(text.contains("robodr-firewall-gw-writers/v3"), "{text}");
    let mut gw2 = g1_channels_gateway(|v| {
        v["rtps"]["max_enforced_writers"] = serde_json::json!(1);
        v["rtps"]["unknown_writers"] = serde_json::json!("pass");
    });
    gw2.discovery_mut().load(&state).unwrap();
    assert!(gw2.discovery().is_suspect(&v));
    send(
        &mut gw2,
        &packet(ATTACKER_IP, SEDP_PORT, &relabel),
        clock.at(64),
    );
    assert!(gw2.discovery().writer(&v).is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The suspect memory is bounded: while it is full no enforced writer is
/// evicted (fail closed: the newcomer is refused and probed).
#[test]
fn h2_full_suspect_memory_refuses_eviction() {
    let mut gw = g1_channels_gateway(|v| {
        v["rtps"]["max_enforced_writers"] = serde_json::json!(1);
        v["rtps"]["enforced_idle_evict_s"] = serde_json::json!(60);
    });
    let clock = Clock(Instant::now());
    let twist_ty = "geometry_msgs::msg::dds_::Twist_";
    let cap = robodr_firewall_gw::discovery::SUSPECTS_PER_ENFORCED;
    for i in 0..=cap as u64 {
        let w = [0, 0, 0x50 + i as u8, 0x03];
        let sedp = sedp_datagram(FOREIGN, w, "rt/cmd_vel", twist_ty);
        send(
            &mut gw,
            &packet(ATTACKER_IP, SEDP_PORT, &sedp),
            clock.at(61 * i),
        );
    }
    assert_eq!(gw.discovery().suspects_len(), cap);
    assert_eq!(gw.discovery().stats.enforced_evicted, cap as u64);
    let w = [0, 0, 0x70, 0x03];
    let sedp = sedp_datagram(FOREIGN, w, "rt/cmd_vel", twist_ty);
    send(
        &mut gw,
        &packet(ATTACKER_IP, SEDP_PORT, &sedp),
        clock.at(61 * (cap as u64 + 2)),
    );
    assert_eq!(gw.discovery().stats.enforced_evicted, cap as u64);
    assert_eq!(gw.discovery().stats.enforced_refused, 1);
    assert_eq!(gw.discovery().suspects_len(), cap);
}

// --------------------------------------------------------------------- M1

/// A writer SEDP announced on another topic sends a whole out-of-envelope
/// `LowCmd_` in one DATA_FRAG: suppressed by default, passed only with
/// `rtps.unenforced_unprobeable: pass`.
#[test]
fn m1_unprobeable_sample_of_an_unenforced_writer_is_suppressed() {
    for setting in [UnenforcedUnprobeable::Suppress, UnenforcedUnprobeable::Pass] {
        let mut gw = g1(|c| c.rtps.unenforced_unprobeable = setting);
        let clock = Clock(Instant::now());
        let sedp = sedp_datagram(FOREIGN, ROGUE, "rt/fooxyz", "std_msgs::msg::dds_::String_");
        send(&mut gw, &packet(ATTACKER_IP, SEDP_PORT, &sedp), clock.at(1));
        let w = gw.discovery().writer(&guid(FOREIGN, ROGUE)).unwrap();
        assert_eq!(w.channel, None);
        let pkt = packet(
            ATTACKER_IP,
            DDS_PORT,
            &lowcmd_frag(FOREIGN, ROGUE, 1, &evil_frame()),
        );
        let (v, out) = send(&mut gw, &pkt, clock.at(2));
        match setting {
            UnenforcedUnprobeable::Suppress => {
                assert!(user_sample(&out).is_none(), "{v:?}");
                assert_eq!(gw.stats.unenforced_undecidable, 1);
            }
            UnenforcedUnprobeable::Pass => {
                assert_eq!(v, Verdict::Accept);
                assert_eq!(gw.stats.unenforced_undecidable, 0);
            }
        }
    }
}

// --------------------------------------------------------------------- M2

/// The review's M2 attack: the policy authorises the controller's prefix,
/// the channel only its IP. GUIDs under that prefix from another IP (one
/// more than `max_writers_per_channel`) used to create writer state that
/// ranked as authorised and evicted the genuine writer's; a replay of its
/// first sample from its own (spoofed) IP was then decided afresh.
#[test]
fn m2_spoofed_guids_from_a_forbidden_ip_evict_no_writer_state() {
    let mut cfg = gateway_config(Fixture::G1);
    cfg.channels[0].allowed_src_ips = vec![CONTROLLER_IP.to_string()];
    let fw_text = std::fs::read_to_string(config_dir().join("firewall.unitree-g1.example.json"))
        .unwrap()
        .replace(
            "\"0123456789abcdef0123456700000103\"",
            "\"0123456789abcdef01234567\"",
        );
    let fw = robodr_firewall::FirewallConfig::from_json(&fw_text).unwrap();
    let mut gw = Gateway::new(&cfg, &profile(Fixture::G1), &fw).unwrap();
    let clock = Clock(Instant::now());
    let sedp = sedp_datagram(
        PREFIX,
        WRITER,
        "rt/lowcmd",
        "unitree_hg::msg::dds_::LowCmd_",
    );
    send(
        &mut gw,
        &packet(CONTROLLER_IP, SEDP_PORT, &sedp),
        clock.at(0),
    );
    let first = lowcmd_datagram(PREFIX, WRITER, 1, &frame(0.001), Representation::CdrLe);
    let mut m = clock.at(0);
    m.now_ns += 2 * MS;
    assert_eq!(
        send(&mut gw, &packet(CONTROLLER_IP, DDS_PORT, &first), m).0,
        Verdict::Accept
    );
    for i in 0..=cfg.rtps.max_writers_per_channel as u8 {
        let d = lowcmd_datagram(
            PREFIX,
            [0, 0, 0x60 + i, 0x03],
            1,
            &frame(0.002),
            Representation::CdrLe,
        );
        m.now_ns += 2 * MS;
        send(&mut gw, &packet(ATTACKER_IP, DDS_PORT, &d), m);
    }
    // A replay of sequence number 1 with other content, from the
    // controller's IP: the replay state is still there.
    let replays = gw.stats.replays;
    let replay = lowcmd_datagram(PREFIX, WRITER, 1, &frame(0.003), Representation::CdrLe);
    m.now_ns += 2 * MS;
    let (_, out) = send(&mut gw, &packet(CONTROLLER_IP, DDS_PORT, &replay), m);
    assert_eq!(
        gw.stats.replays,
        replays + 1,
        "decided afresh: state evicted"
    );
    let sent = lowcmd::encode_payload(&frame(0.003), Representation::CdrLe);
    assert!(user_sample(&out).is_none_or(|p| p != sent));
}
