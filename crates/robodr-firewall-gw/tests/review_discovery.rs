//! Regression tests for the gateway review's discovery findings (each test
//! is the attack; it passed unchecked before the fix):
//!
//! - **1** INFO_DST-misaddressed SEDP dispose + re-announcement of the
//!   controller's `rt/lowcmd` writer on another topic: the robot (which
//!   drops misaddressed submessages) stays matched, the gateway used to
//!   forget the writer and pass its `LowCmd_` unchecked. Also: removal by
//!   another sender, enforced-is-forever, persisted; a writer known as not
//!   enforced that sends a motion command.
//! - **2** eviction of an enforced writer by a flood of other writers, and
//!   a padded `Twist` that missed the probe.
//! - **7** a user writer whose entity id has the builtin kind bits.
//! - **9** the state file: symlinks, modes, the temporary file.

use std::time::Instant;

use robodr_cdr::Representation;
use robodr_firewall_gw::ip::parse_ipv4_udp;
use robodr_firewall_gw::lowcmd::{self, LowCmdCodec, WireLowCmd};
use robodr_firewall_gw::rtps::{self, build::Datagram, Content, GuidPrefix, WalkOptions};
use robodr_firewall_gw::testkit::*;
use robodr_firewall_gw::{ros2, Gateway, PacketMeta, Verdict};

const MS: u64 = 1_000_000;
const T0: u64 = 1_000_000_000;
/// A participant nobody runs: the INFO_DST of the attack.
const ELSEWHERE: GuidPrefix = [0x5e; 12];
const SEDP_PORT: u16 = 7410;

/// A fresh directory under the system temp dir, removed on drop.
struct TmpDir(std::path::PathBuf);

impl TmpDir {
    fn new() -> Self {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("rdr-gw-disc-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir(&p).unwrap();
        Self(p)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

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
    }
    (v, p)
}

fn guid(prefix: GuidPrefix, entity: [u8; 4]) -> [u8; 16] {
    let mut g = [0u8; 16];
    g[..12].copy_from_slice(&prefix);
    g[12..].copy_from_slice(&entity);
    g
}

/// The first user DATA payload left in `pkt` (`None`: suppressed).
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

/// A SEDP dispose + unregister of `g` (inline QoS key hash and status,
/// no payload).
fn dispose_body(g: [u8; 16], sn: i64) -> Vec<u8> {
    let mut b = vec![0, 0];
    b.extend_from_slice(&16u16.to_le_bytes());
    b.extend_from_slice(&[0, 0, 0, 0]);
    b.extend_from_slice(&[0, 0, 3, 0xc2]);
    b.extend_from_slice(&((sn >> 32) as i32).to_le_bytes());
    b.extend_from_slice(&(sn as u32).to_le_bytes());
    b.extend_from_slice(&0x0070u16.to_le_bytes());
    b.extend_from_slice(&16u16.to_le_bytes());
    b.extend_from_slice(&g);
    b.extend_from_slice(&0x0071u16.to_le_bytes());
    b.extend_from_slice(&4u16.to_le_bytes());
    b.extend_from_slice(&[0, 0, 0, 3]);
    b.extend_from_slice(&[1, 0, 0, 0]);
    b
}

/// One discovery datagram from `header`: optionally INFO_DST(`dst`), then
/// a dispose of `victim` and its re-announcement on `topic`.
fn hide_writer(
    header: GuidPrefix,
    dst: Option<GuidPrefix>,
    victim: (GuidPrefix, [u8; 4]),
    topic: &str,
    sn: i64,
) -> Vec<u8> {
    let mut d = Datagram::new(header);
    if let Some(p) = dst {
        d.raw(rtps::INFO_DST, 0, &p);
    }
    d.raw(
        rtps::DATA,
        0x02,
        &dispose_body(guid(victim.0, victim.1), sn),
    );
    d.data(
        [0, 0, 3, 0xc2],
        sn + 1,
        &[],
        &sedp_payload(victim.0, victim.1, topic, "std_msgs::msg::dds_::String_"),
    );
    d.finish()
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

/// A `LowCmd_` far outside the envelope (torque 1e4 on slot 0).
fn evil_frame() -> WireLowCmd {
    let mut bad = frame(0.0);
    let mut w = bad.motor(0).unwrap();
    w.tau = 1e4;
    w.q = 100.0;
    bad.set_motor(0, w);
    bad.seal();
    bad
}

fn lowcmd_pkt(src: std::net::Ipv4Addr, sn: i64, m: &WireLowCmd) -> Vec<u8> {
    packet(
        src,
        DDS_PORT,
        &lowcmd_datagram(PREFIX, WRITER, sn, m, Representation::CdrLe),
    )
}

/// The forwarded frame is not the attacker's (suppressed or replaced).
fn assert_not_forwarded_as_sent(out: &[u8], what: &str) {
    if let Some(p) = out_payload(out) {
        let m = lowcmd::decode_strict(&p, LowCmdCodec::Hg).unwrap().msg;
        assert!(
            m.motor(0).unwrap().tau.abs() < 1e3,
            "{what}: the out-of-envelope LowCmd_ reached the robot"
        );
    }
}

/// A G1 gateway that has learned the controller's `rt/lowcmd` writer from
/// SEDP and the robot's participant from its observed SPDP.
fn primed(robot_known: bool) -> Gateway {
    let mut gw = gateway(Fixture::G1);
    if robot_known {
        let spdp = spdp_with_locator(ROBOT_PREFIX, ROBOT_IP, 7410);
        gw.observe(&robot_packet(7400, &spdp), meta(T0));
        assert!(gw.discovery().robot_prefixes().any(|p| *p == ROBOT_PREFIX));
    }
    let sedp = sedp_datagram(
        PREFIX,
        WRITER,
        "rt/lowcmd",
        "unitree_hg::msg::dds_::LowCmd_",
    );
    run(&mut gw, &packet(CONTROLLER_IP, SEDP_PORT, &sedp), T0);
    assert_eq!(
        gw.discovery()
            .writer(&guid(PREFIX, WRITER))
            .unwrap()
            .channel,
        Some(0)
    );
    assert_eq!(
        run(
            &mut gw,
            &lowcmd_pkt(CONTROLLER_IP, 1, &frame(0.001)),
            T0 + 2 * MS
        )
        .0,
        Verdict::Accept
    );
    gw
}

// ------------------------------------------------------------ finding 1

/// The review's attack, every sender variant: INFO_DST(elsewhere) from the
/// attacker's own participant, INFO_DST(elsewhere) under the controller's
/// own prefix, and (no INFO_DST) a relay. Then `LowCmd_` with the
/// controller's GUID from another IP: decided, never forwarded as sent.
#[test]
fn f1_misaddressed_dispose_and_reannouncement_do_not_unenforce_a_writer() {
    for robot_known in [true, false] {
        for (header, dst) in [
            (FOREIGN, Some(ELSEWHERE)),
            (PREFIX, Some(ELSEWHERE)),
            (FOREIGN, None),
        ] {
            let what = format!("robot_known={robot_known} header={header:x?} dst={dst:x?}");
            let mut gw = primed(robot_known);
            let attack = hide_writer(header, dst, (PREFIX, WRITER), "rt/x", 10);
            run(
                &mut gw,
                &packet(ATTACKER_IP, SEDP_PORT, &attack),
                T0 + 4 * MS,
            );
            assert_eq!(
                gw.discovery()
                    .writer(&guid(PREFIX, WRITER))
                    .unwrap()
                    .channel,
                Some(0),
                "{what}: still enforced"
            );
            let samples = gw.stats.samples;
            let (_, out) = run(
                &mut gw,
                &lowcmd_pkt(ATTACKER_IP, 2, &evil_frame()),
                T0 + 6 * MS,
            );
            assert_eq!(gw.stats.samples, samples + 1, "{what}: decided");
            assert_not_forwarded_as_sent(&out, &what);
        }
    }
}

/// A misaddressed or relayed removal of a not-enforced writer is ignored
/// too (it would turn a known writer into an unknown, probed one).
#[test]
fn f1_misaddressed_and_relayed_removals_are_ignored() {
    let mut gw = primed(true);
    let other = [0, 0, 0x0b, 0x03];
    let sedp = sedp_datagram(PREFIX, other, "rt/x", "std_msgs::msg::dds_::String_");
    run(
        &mut gw,
        &packet(CONTROLLER_IP, SEDP_PORT, &sedp),
        T0 + 3 * MS,
    );
    for (header, dst) in [(PREFIX, Some(ELSEWHERE)), (FOREIGN, None)] {
        let mut d = Datagram::new(header);
        if let Some(p) = dst {
            d.raw(rtps::INFO_DST, 0, &p);
        }
        d.raw(rtps::DATA, 0x02, &dispose_body(guid(PREFIX, other), 20));
        run(
            &mut gw,
            &packet(ATTACKER_IP, SEDP_PORT, &d.finish()),
            T0 + 4 * MS,
        );
        assert!(gw.discovery().writer(&guid(PREFIX, other)).is_some());
    }
    assert_eq!(gw.discovery().stats.misaddressed, 1);
    assert_eq!(gw.discovery().stats.relayed_ignored, 1);
    // Addressed to the robot (or everyone), from the owner: forgotten.
    let mut d = Datagram::new(PREFIX);
    d.raw(rtps::INFO_DST, 0, &ROBOT_PREFIX);
    d.raw(rtps::DATA, 0x02, &dispose_body(guid(PREFIX, other), 21));
    run(
        &mut gw,
        &packet(CONTROLLER_IP, SEDP_PORT, &d.finish()),
        T0 + 5 * MS,
    );
    assert!(gw.discovery().writer(&guid(PREFIX, other)).is_none());
}

/// Enforced is forever: even the owner's genuine dispose and an
/// announcement on another topic leave the writer enforced, and the
/// classification survives a restart through `rtps.state_file`.
#[test]
fn f1_enforced_writer_is_never_downgraded_and_is_persisted() {
    let mut gw = primed(true);
    let genuine = hide_writer(PREFIX, None, (PREFIX, WRITER), "rt/x", 10);
    run(
        &mut gw,
        &packet(CONTROLLER_IP, SEDP_PORT, &genuine),
        T0 + 4 * MS,
    );
    assert_eq!(
        gw.discovery()
            .writer(&guid(PREFIX, WRITER))
            .unwrap()
            .channel,
        Some(0)
    );
    assert!(gw.discovery().stats.enforced_kept >= 2);
    let dir = TmpDir::new();
    let path = dir.path().join("writers.json");
    gw.discovery_mut().save(&path).unwrap();
    let mut fresh = gateway(Fixture::G1);
    assert_eq!(fresh.discovery_mut().load(&path).unwrap(), 1);
    // The restarted gateway sees the attacker's re-announcement only.
    let attack = hide_writer(FOREIGN, None, (PREFIX, WRITER), "rt/x", 30);
    run(&mut fresh, &packet(ATTACKER_IP, SEDP_PORT, &attack), T0);
    let (_, out) = run(
        &mut fresh,
        &lowcmd_pkt(ATTACKER_IP, 2, &evil_frame()),
        T0 + 2 * MS,
    );
    assert_eq!(fresh.stats.samples, 1);
    assert_not_forwarded_as_sent(&out, "after restart");
}

/// A writer the gateway only ever saw on another topic (a fresh gateway
/// without state, the robot still matched on `rt/lowcmd`): its CRC-valid
/// `LowCmd_` is suspicious and suppressed, with a finding.
#[test]
fn f1_unenforced_writer_sending_lowcmd_is_suppressed() {
    let mut gw = gateway(Fixture::G1);
    let announce = sedp_datagram(PREFIX, WRITER, "rt/x", "std_msgs::msg::dds_::String_");
    run(&mut gw, &packet(CONTROLLER_IP, SEDP_PORT, &announce), T0);
    assert_eq!(
        gw.discovery()
            .writer(&guid(PREFIX, WRITER))
            .unwrap()
            .channel,
        None
    );
    let (v, out) = run(
        &mut gw,
        &lowcmd_pkt(ATTACKER_IP, 2, &evil_frame()),
        T0 + 2 * MS,
    );
    assert_eq!(v, Verdict::AcceptModified);
    assert!(out_payload(&out).is_none(), "suppressed");
    assert_eq!(gw.stats.suspicious_writer, 1);
    let f = gw.findings.drain(robodr_events::Mode::Enforce);
    assert!(
        f.iter().any(|d| d
            .deviation
            .detail
            .contains("unenforced_writer_motion_payload")),
        "{f:?}"
    );
}

// ------------------------------------------------------------ finding 2

/// The cmd_vel channel's writer, then `n` other writers announced (more
/// than `rtps.max_writers`): the enforced writer is never evicted, and its
/// over-limit twist, padded past 80 octets, is decided.
#[test]
fn f2_flood_of_writers_does_not_evict_an_enforced_writer() {
    let mut gw = g1_channels_gateway(|v| {
        v["rtps"] = serde_json::json!({ "max_writers": 4 });
    });
    let sedp = sedp_datagram(
        PREFIX,
        TWIST_WRITER,
        "rt/cmd_vel",
        "geometry_msgs::msg::dds_::Twist_",
    );
    run(&mut gw, &packet(CONTROLLER_IP, SEDP_PORT, &sedp), T0);
    for i in 0..32u8 {
        let p: GuidPrefix = [0xa0, i, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let d = sedp_datagram(p, [0, 0, 1, 3], "rt/noise", "std_msgs::msg::dds_::String_");
        run(&mut gw, &packet(ATTACKER_IP, SEDP_PORT, &d), T0 + MS);
    }
    assert!(gw.discovery().stats.writers_evicted > 0);
    assert_eq!(
        gw.discovery()
            .writer(&guid(PREFIX, TWIST_WRITER))
            .unwrap()
            .channel,
        Some(5)
    );
    let mut twist = ros2::encode([3.0, 0.0, 0.0, 0.0, 0.0, 0.0], None, false);
    twist.extend_from_slice(&[0u8; 40]);
    let d = data_datagram(TWIST_WRITER, 1, &twist);
    let (_, out) = run(&mut gw, &packet(CONTROLLER_IP, DDS_PORT, &d), T0 + 20 * MS);
    assert_eq!(gw.stats.samples, 1, "decided");
    assert!(
        out_payload(&out).is_none_or(|p| p != twist),
        "not forwarded as sent"
    );
}

/// A writer nobody announced sends a padded over-limit twist (body > 80
/// octets): the probe used to miss it and pass it. Now classified as the
/// twist channel and, not strictly decodable, failed closed.
#[test]
fn f2_unknown_writer_padded_twist_fails_closed() {
    let mut gw = g1_channels_gateway(|_| {});
    for pad in [40usize, 400] {
        let mut twist = ros2::encode([3.0, 0.0, 0.0, 0.0, 0.0, 2.0], None, false);
        twist.extend(std::iter::repeat_n(0u8, pad));
        let w = [0, 0, 0x30, 0x03];
        let d = Datagram::new(FOREIGN).data(w, 1, &[], &twist).finish();
        let (_, out) = run(
            &mut gw,
            &packet(ATTACKER_IP, DDS_PORT, &d),
            T0 + pad as u64 * MS,
        );
        assert!(out_payload(&out).is_none_or(|p| p != twist), "pad {pad}");
    }
    assert_eq!(gw.stats.probed, 1);
}

/// A full enforced table refuses a new enforced writer (finding) and the
/// writer is then probed, also with `unknown_writers: pass`.
#[test]
fn f2_full_enforced_table_refuses_and_probes() {
    let mut cfg = gateway_config(Fixture::G1);
    cfg.rtps.max_enforced_writers = 1;
    cfg.rtps.unknown_writers = robodr_firewall_gw::config::UnknownWriters::Pass;
    let mut gw = Gateway::new(&cfg, &profile(Fixture::G1), &firewall(Fixture::G1)).unwrap();
    let first = sedp_datagram(
        FOREIGN,
        [0, 0, 9, 3],
        "rt/lowcmd",
        "unitree_hg::msg::dds_::LowCmd_",
    );
    run(&mut gw, &packet(ATTACKER_IP, SEDP_PORT, &first), T0);
    let sedp = sedp_datagram(
        PREFIX,
        WRITER,
        "rt/lowcmd",
        "unitree_hg::msg::dds_::LowCmd_",
    );
    run(&mut gw, &packet(CONTROLLER_IP, SEDP_PORT, &sedp), T0 + MS);
    assert_eq!(gw.discovery().stats.enforced_refused, 1);
    let f = gw.findings.drain(robodr_events::Mode::Enforce);
    assert!(
        f.iter()
            .any(|d| d.deviation.detail.contains("enforced_writer_table_full")),
        "{f:?}"
    );
    let (_, out) = run(
        &mut gw,
        &lowcmd_pkt(ATTACKER_IP, 2, &evil_frame()),
        T0 + 4 * MS,
    );
    assert_eq!(gw.stats.samples, 1, "probed and decided");
    assert_not_forwarded_as_sent(&out, "table full");
}

// ------------------------------------------------------------ finding 7

/// A user writer whose entity id has the builtin kind (`0xc3`) but is no
/// standard builtin writer, announced on `rt/cmd_vel`: decided.
#[test]
fn f7_user_writer_with_builtin_kind_bits_is_decided() {
    let mut gw = g1_channels_gateway(|_| {});
    let w = [0, 0, 0x07, 0xc3];
    let sedp = sedp_datagram(PREFIX, w, "rt/cmd_vel", "geometry_msgs::msg::dds_::Twist_");
    run(&mut gw, &packet(CONTROLLER_IP, SEDP_PORT, &sedp), T0);
    assert_eq!(
        gw.discovery().writer(&guid(PREFIX, w)).unwrap().channel,
        Some(5)
    );
    let twist = ros2::encode([3.0, 0.0, 0.0, 0.0, 0.0, 0.0], None, false);
    let d = data_datagram(w, 1, &twist);
    let (v, out) = run(&mut gw, &packet(CONTROLLER_IP, DDS_PORT, &d), T0 + 20 * MS);
    assert_eq!(gw.stats.samples, 1);
    assert_eq!(v, Verdict::AcceptModified);
    assert!(out_payload(&out).is_none_or(|p| p != twist));
    assert!(rtps::is_builtin_entity([0, 0, 3, 0xc2]));
    assert!(!rtps::is_builtin_entity(w));
}

// ------------------------------------------------------------ finding 9

#[test]
fn f9_state_file_symlink_and_modes_are_refused() {
    use std::os::unix::fs::PermissionsExt as _;
    let mut gw = primed(false);
    let dir = TmpDir::new();
    let path = dir.path().join("writers.json");
    gw.discovery_mut().save(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    // A symlink to it: refused.
    let link = dir.path().join("link.json");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    let err = gateway(Fixture::G1)
        .discovery_mut()
        .load(&link)
        .unwrap_err();
    assert!(err.contains("symlink"), "{err}");
    // World-writable: refused.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    let err = gateway(Fixture::G1)
        .discovery_mut()
        .load(&path)
        .unwrap_err();
    assert!(err.contains("writable"), "{err}");
    // A symlink planted at the temporary name is replaced, not followed.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let victim = dir.path().join("victim");
    std::fs::write(&victim, b"keep").unwrap();
    std::os::unix::fs::symlink(&victim, dir.path().join("writers.tmp")).unwrap();
    gw.discovery_mut().save(&path).unwrap();
    assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
    assert_eq!(gateway(Fixture::G1).discovery_mut().load(&path).unwrap(), 1);
}
