//! Regression tests for the S8 gateway review findings:
//!
//! - **F1** sequence-number poisoning: a spoofed DATA carrying the motion
//!   writer's GUID and a far-future sequence number must not change how the
//!   genuine stream is decided, and must never reach the robot (its reader
//!   would then discard the genuine writer's lower numbers as old);
//!   writer restart (sequence numbers start again after a new SEDP
//!   announcement) is handled without a replay hole.
//! - **F2** a DATA_FRAG (or key-only / non-standard DATA) from a writer the
//!   gateway has no classification for cannot be probed: suppressed in
//!   enforce mode.
//! - **F3** non-motor `LowCmd_` fields: `bms_cmd.off` (0xA5 = battery off)
//!   is refused unless the channel allows it; a refused frame's substitute
//!   carries the last accepted frame's non-motor fields.

use std::time::Instant;

use robodr_cdr::Representation;
use robodr_firewall::ForeignSourceAction;
use robodr_firewall_gw::config::{GatewayMode, UnenforcedUnprobeable, UnknownWriters};
use robodr_firewall_gw::ip::parse_ipv4_udp;
use robodr_firewall_gw::lowcmd::{self, LowCmdCodec, WireLowCmd};
use robodr_firewall_gw::rtps::{self, build::Datagram, Content, SampleKind, WalkOptions};
use robodr_firewall_gw::testkit::*;
use robodr_firewall_gw::{Gateway, PacketMeta, Verdict};

const MS: u64 = 1_000_000;
const T0: u64 = 1_000_000_000;
const CTRL_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x64];
const EVIL_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x99];

fn meta(now: u64, mac: Option<[u8; 6]>) -> PacketMeta {
    PacketMeta {
        now_ns: now,
        queue_delay_ns: None,
        instant: Instant::now(),
        src_mac: mac,
    }
}

fn run_mac(gw: &mut Gateway, pkt: &[u8], now: u64, mac: Option<[u8; 6]>) -> (Verdict, Vec<u8>) {
    let mut p = pkt.to_vec();
    let v = gw.process(&mut p, meta(now, mac));
    if v != Verdict::AcceptModified {
        assert_eq!(p, pkt, "unmodified verdict {v:?} but bytes changed");
    } else {
        assert_eq!(p.len(), pkt.len(), "rewrite changed the length");
        parse_ipv4_udp(&p).expect("rewritten packet has valid IP / UDP checksums");
    }
    (v, p)
}

fn run(gw: &mut Gateway, pkt: &[u8], now: u64) -> (Verdict, Vec<u8>) {
    run_mac(gw, pkt, now, None)
}

/// User samples (DATA / DATA_FRAG of non-builtin writers) left in `pkt`.
fn user_samples(pkt: &[u8]) -> Vec<rtps::Sample> {
    let ip = parse_ipv4_udp(pkt).unwrap();
    let mut v = Vec::new();
    rtps::walk(&pkt[ip.payload()], WalkOptions::default(), &mut v).unwrap();
    v.retain(|s| !s.builtin);
    v
}

fn out_lowcmd(pkt: &[u8], codec: LowCmdCodec) -> Option<WireLowCmd> {
    let ip = parse_ipv4_udp(pkt).unwrap();
    let d = &pkt[ip.payload()];
    let s = user_samples(pkt)
        .into_iter()
        .find(|s| s.content == Content::Data && s.kind == SampleKind::Data)?;
    let dec = lowcmd::decode_strict(&d[s.payload.clone().unwrap()], codec)
        .expect("forwarded LowCmd decodes strictly");
    assert!(dec.msg.crc_ok());
    Some(dec.msg)
}

fn frame(fx: Fixture, phase: f64) -> WireLowCmd {
    let spec = lowcmd_spec(fx);
    mid_frame(
        codec(fx),
        &spec.motors,
        phase,
        (spec.pinned_mode_pr, spec.pinned_mode_machine),
    )
}

fn pkt_from(src: std::net::Ipv4Addr, prefix: rtps::GuidPrefix, sn: i64, m: &WireLowCmd) -> Vec<u8> {
    packet(
        src,
        DDS_PORT,
        &lowcmd_datagram(prefix, WRITER, sn, m, Representation::CdrLe),
    )
}

fn genuine(fx: Fixture, sn: i64) -> Vec<u8> {
    pkt_from(CONTROLLER_IP, PREFIX, sn, &frame(fx, sn as f64 * 0.001))
}

fn gw_with(fx: Fixture, bind_ip: bool) -> Gateway {
    let mut cfg = gateway_config(fx);
    if bind_ip {
        cfg.channels[0].allowed_src_ips = vec![CONTROLLER_IP.to_string()];
    }
    Gateway::new(&cfg, &profile(fx), &firewall(fx)).unwrap()
}

fn writer_guid() -> [u8; 16] {
    let mut g = [0u8; 16];
    g[..12].copy_from_slice(&PREFIX);
    g[12..].copy_from_slice(&WRITER);
    g
}

// ------------------------------------------------------------------ F1

/// The review's attack: one spoofed DATA with the motion writer's GUID and
/// a far-future sequence number, from another IP. Before the fix the
/// writer's `last_sn` advanced to it and every later genuine frame was
/// suppressed as a "replay" (robot command timeout -> fall). With and
/// without `allowed_src_ips`.
#[test]
fn f1_future_sn_injection_from_another_ip_does_not_poison_the_stream() {
    for fx in [Fixture::G1, Fixture::Go2] {
        for bind_ip in [false, true] {
            let mut gw = gw_with(fx, bind_ip);
            let mut now = T0;
            for sn in 1..=5 {
                now += 2 * MS;
                assert_eq!(run(&mut gw, &genuine(fx, sn), now).0, Verdict::Accept);
            }
            for evil_sn in [1_i64 << 40, i64::MAX, 6, 7] {
                now += 2 * MS;
                let evil = pkt_from(ATTACKER_IP, PREFIX, evil_sn, &frame(fx, 0.0));
                let (v, out) = run(&mut gw, &evil, now);
                assert_eq!(v, Verdict::AcceptModified, "{fx:?} bind_ip={bind_ip}");
                assert!(
                    user_samples(&out).is_empty(),
                    "{fx:?} bind_ip={bind_ip} sn {evil_sn}: the spoofed sample never reaches the robot"
                );
            }
            for sn in 6..=40 {
                now += 2 * MS;
                let p = genuine(fx, sn);
                let (v, out) = run(&mut gw, &p, now);
                assert_eq!(
                    v,
                    Verdict::Accept,
                    "{fx:?} bind_ip={bind_ip}: genuine SN {sn} after the injection"
                );
                assert_eq!(out, p);
            }
        }
    }
}

/// Same GUID, same (allowed) source IP, but another source MAC: the
/// attacker spoofs the controller's IP on the flat L2 segment. The stream's
/// replay / sequence state is bound to (GUID, source, IP, MAC); the other
/// MAC is a binding conflict and is never forwarded.
#[test]
fn f1_future_sn_injection_with_spoofed_controller_ip_other_mac() {
    let fx = Fixture::G1;
    let mut gw = gw_with(fx, true);
    let mut now = T0;
    for sn in 1..=5 {
        now += 2 * MS;
        let (v, _) = run_mac(&mut gw, &genuine(fx, sn), now, Some(CTRL_MAC));
        assert_eq!(v, Verdict::Accept);
    }
    for evil_sn in [1_i64 << 40, 6] {
        now += 2 * MS;
        let evil = pkt_from(CONTROLLER_IP, PREFIX, evil_sn, &frame(fx, 0.0));
        let (v, out) = run_mac(&mut gw, &evil, now, Some(EVIL_MAC));
        assert_eq!(v, Verdict::AcceptModified);
        assert!(
            user_samples(&out).is_empty(),
            "sn {evil_sn}: conflict suppressed"
        );
    }
    assert!(gw.stats.binding_conflicts >= 2);
    for sn in 6..=30 {
        now += 2 * MS;
        let (v, _) = run_mac(&mut gw, &genuine(fx, sn), now, Some(CTRL_MAC));
        assert_eq!(v, Verdict::Accept, "genuine SN {sn}");
    }
    // A channel can also pin the controller's MAC: then the other MAC is a
    // foreign source outright (also before any binding exists).
    let mut cfg = gateway_config(fx);
    cfg.channels[0].allowed_src_ips = vec![CONTROLLER_IP.to_string()];
    cfg.channels[0].allowed_src_macs = vec!["02:00:00:00:00:64".into()];
    let mut gw = Gateway::new(&cfg, &profile(fx), &firewall(fx)).unwrap();
    let evil = pkt_from(CONTROLLER_IP, PREFIX, 1 << 40, &frame(fx, 0.0));
    let (_, out) = run_mac(&mut gw, &evil, T0, Some(EVIL_MAC));
    assert!(user_samples(&out).is_empty());
    let (_, out) = run_mac(&mut gw, &evil, T0 + 2 * MS, None);
    assert!(
        user_samples(&out).is_empty(),
        "no MAC known: not the pinned MAC"
    );
    for sn in 1..=10 {
        let (v, _) = run_mac(
            &mut gw,
            &genuine(fx, sn),
            T0 + (2 + 2 * sn as u64) * MS,
            Some(CTRL_MAC),
        );
        assert_eq!(v, Verdict::Accept, "genuine SN {sn}");
    }
}

/// The binding is not permanent: when the bound (IP, MAC) has sent nothing
/// for `rtps.binding_takeover_ns`, another (IP, MAC) presenting the same
/// authorised GUID may continue the stream (above the sequence numbers
/// already forwarded). Before that, it is a conflict, also while the bound
/// side's frames are being suppressed (liveness counts every sample).
#[test]
fn f1_binding_takeover_only_after_silence() {
    let fx = Fixture::G1;
    let mut gw = gw_with(fx, true);
    let mut now = T0;
    for sn in 1..=5 {
        now += 2 * MS;
        run_mac(&mut gw, &genuine(fx, sn), now, Some(CTRL_MAC));
    }
    // Bound side keeps sending, but too early (suppressed by the rate rule).
    for sn in 6..=700 {
        now += MS / 2;
        run_mac(&mut gw, &genuine(fx, sn), now, Some(CTRL_MAC));
        if sn % 100 == 0 {
            let (_, out) = run_mac(&mut gw, &genuine(fx, sn + 1000), now, Some(EVIL_MAC));
            assert!(
                user_samples(&out).is_empty(),
                "conflict while the bound side is live"
            );
        }
    }
    // Silence past the takeover time: the other NIC continues.
    now += 1_100 * MS;
    let (v, _) = run_mac(&mut gw, &genuine(fx, 701), now, Some(EVIL_MAC));
    assert_eq!(v, Verdict::Accept, "takeover after silence");
    // Now the old side is the conflicting one.
    now += 2 * MS;
    let (_, out) = run_mac(&mut gw, &genuine(fx, 702), now, Some(CTRL_MAC));
    assert!(user_samples(&out).is_empty());
    // Lower numbers than what was forwarded stay replays for the new side
    // (the sequence boundary is the robot reader's, not the binding's).
    let checked = gw.firewall().stats().checked;
    now += 2 * MS;
    let (_, out) = run_mac(&mut gw, &genuine(fx, 3), now, Some(EVIL_MAC));
    assert!(
        user_samples(&out).is_empty(),
        "not cached any more: suppressed"
    );
    assert_eq!(gw.firewall().stats().checked, checked, "not decided again");
}

/// A sequence-number jump larger than `rtps.max_sn_jump` from the bound
/// (authorised) writer is never forwarded (it would move the robot reader's
/// expected number past the genuine stream) and does not move the gateway's
/// state; a jump confirmed by the next consecutive sample (real packet loss,
/// a cable unplugged while the controller kept writing) is adopted with one
/// tick lost.
#[test]
fn f1_sn_jump_from_the_bound_writer_is_held_until_confirmed() {
    let fx = Fixture::G1;
    let mut gw = gw_with(fx, true);
    let mut now = T0;
    for sn in 1..=5 {
        now += 2 * MS;
        assert_eq!(run(&mut gw, &genuine(fx, sn), now).0, Verdict::Accept);
    }
    // Full spoof (same IP, no MAC distinction): one far-future frame.
    now += 2 * MS;
    let (v, out) = run(&mut gw, &genuine(fx, 1 << 40), now);
    assert_eq!(v, Verdict::AcceptModified);
    assert!(user_samples(&out).is_empty(), "unconfirmed jump suppressed");
    assert_eq!(gw.stats.sn_jumps, 1);
    for sn in 6..=20 {
        now += 2 * MS;
        assert_eq!(
            run(&mut gw, &genuine(fx, sn), now).0,
            Verdict::Accept,
            "genuine SN {sn}"
        );
    }
    // A legitimate jump (loss of ~10 000 frames), then consecutive frames.
    now += 2 * MS;
    let (_, out) = run(&mut gw, &genuine(fx, 10_000), now);
    assert!(user_samples(&out).is_empty());
    for sn in 10_001..=10_010 {
        now += 2 * MS;
        assert_eq!(
            run(&mut gw, &genuine(fx, sn), now).0,
            Verdict::Accept,
            "SN {sn} after the confirmed jump"
        );
    }
    // A small gap (inside the window) is not a jump.
    now += 2 * MS;
    assert_eq!(run(&mut gw, &genuine(fx, 10_040), now).0, Verdict::Accept);
}

/// With `foreign_source_action: substitute`, a foreign sample may carry the
/// platform's substitute — but never under a GUID the policy authorises
/// (that would push the robot reader's sequence number for the genuine
/// writer). Before the fix the substitute rode on the spoofed far-future
/// sequence number.
#[test]
fn f1_foreign_substitute_never_rides_on_a_spoofed_authorised_guid() {
    let fx = Fixture::Go2;
    let mut cfg = gateway_config(fx);
    cfg.channels[0].allowed_src_ips = vec![CONTROLLER_IP.to_string()];
    let mut fw = firewall(fx);
    fw.platform.foreign_source_action = ForeignSourceAction::Substitute;
    fw.platform.foreign_substitute_min_interval_ns = 0;
    let mut gw = Gateway::new(&cfg, &profile(fx), &fw).unwrap();
    let mut now = T0;
    for sn in 1..=5 {
        now += 2 * MS;
        assert_eq!(run(&mut gw, &genuine(fx, sn), now).0, Verdict::Accept);
    }
    now += 2 * MS;
    let evil = pkt_from(ATTACKER_IP, PREFIX, 1 << 40, &frame(fx, 0.0));
    let (_, out) = run(&mut gw, &evil, now);
    assert!(user_samples(&out).is_empty());
    for sn in 6..=20 {
        now += 2 * MS;
        assert_eq!(run(&mut gw, &genuine(fx, sn), now).0, Verdict::Accept);
    }
}

/// A writer that restarts with the same GUID begins again at sequence
/// number 1; it re-announces itself (SEDP) first. An SEDP announcement of
/// the writer from the bound source IP arms a restart: the next lower
/// sequence number (<= `max_sn_jump`) starts a fresh stream. Without that
/// announcement, or with one from another IP, or once the stream has moved
/// on, a lower number is a replay as before.
#[test]
fn f1_writer_restart_after_sedp_without_a_replay_hole() {
    let fx = Fixture::G1;
    let sedp = |src| {
        packet(
            src,
            7410,
            &sedp_datagram(
                PREFIX,
                WRITER,
                "rt/lowcmd",
                "unitree_hg::msg::dds_::LowCmd_",
            ),
        )
    };
    let mut gw = gw_with(fx, true);
    let mut now = T0;
    for sn in 1..=10 {
        now += 2 * MS;
        assert_eq!(run(&mut gw, &genuine(fx, sn), now).0, Verdict::Accept);
    }
    // No announcement: a lower number (other content) is a replay: the
    // bytes decided for it are re-emitted while cached (SN 9), else the
    // sample is suppressed (SN 1); the firewall is not consulted.
    let checked = gw.firewall().stats().checked;
    now += 2 * MS;
    let replay9 = pkt_from(CONTROLLER_IP, PREFIX, 9, &frame(fx, 0.5));
    let (v, out) = run(&mut gw, &replay9, now);
    assert_eq!(v, Verdict::AcceptModified);
    assert_eq!(out_lowcmd(&out, LowCmdCodec::Hg).unwrap(), frame(fx, 0.009));
    now += 2 * MS;
    let restart1 = pkt_from(CONTROLLER_IP, PREFIX, 1, &frame(fx, 0.5));
    let (v, out) = run(&mut gw, &restart1, now);
    assert_eq!(v, Verdict::AcceptModified);
    assert!(user_samples(&out).is_empty());
    assert_eq!(gw.firewall().stats().checked, checked);
    // An announcement from another IP does not arm the restart.
    now += 2 * MS;
    run(&mut gw, &sedp(ATTACKER_IP), now);
    now += 2 * MS;
    let (v, _) = run(&mut gw, &restart1, now);
    assert_eq!(v, Verdict::AcceptModified, "still a replay");
    assert_eq!(gw.firewall().stats().checked, checked);
    // The stream moving on disarms an announcement.
    now += 2 * MS;
    run(&mut gw, &sedp(CONTROLLER_IP), now);
    now += 2 * MS;
    assert_eq!(run(&mut gw, &genuine(fx, 11), now).0, Verdict::Accept);
    now += 2 * MS;
    let (v, _) = run(&mut gw, &restart1, now);
    assert_eq!(v, Verdict::AcceptModified, "still a replay");
    // The real restart: announcement from the bound IP, then 1, 2, 3, ...
    now += 2 * MS;
    run(&mut gw, &sedp(CONTROLLER_IP), now);
    for sn in 1..=20 {
        now += 2 * MS;
        let p = pkt_from(
            CONTROLLER_IP,
            PREFIX,
            sn,
            &frame(fx, 0.5 + sn as f64 * 0.001),
        );
        let (v, out) = run(&mut gw, &p, now);
        assert_eq!(v, Verdict::Accept, "restarted stream SN {sn}");
        assert_eq!(out, p);
    }
    assert_eq!(gw.stats.writer_restarts, 1);
    // ... and the restarted stream is replay-protected again.
    now += 2 * MS;
    let (v, _) = run(&mut gw, &restart1, now);
    assert_eq!(v, Verdict::AcceptModified);
}

// ------------------------------------------------------------------ F2

fn frag_pkt(
    src: std::net::Ipv4Addr,
    writer: [u8; 4],
    sn: i64,
    num: u32,
    frag_size: u16,
    sample_size: u32,
    bytes: &[u8],
) -> Vec<u8> {
    let d = Datagram::new(PREFIX)
        .data_frag(writer, sn, num, frag_size, sample_size, bytes)
        .heartbeat(writer, 1, sn)
        .finish();
    packet(src, DDS_PORT, &d)
}

fn assert_frag_suppressed(gw: &mut Gateway, p: &[u8], now: u64, what: &str) {
    let (v, out) = run(gw, p, now);
    assert_eq!(v, Verdict::AcceptModified, "{what}");
    assert!(user_samples(&out).is_empty(), "{what}: fragment suppressed");
}

/// The review's case: an unknown writer's DATA_FRAG carrying a valid
/// `LowCmd_` passed unchecked (the probe needs a whole payload). Now every
/// fragment of an unknown writer is suppressed in enforce mode: single
/// fragment, several fragments, out of order, oversized.
#[test]
fn f2_unknown_writer_data_frag_is_suppressed() {
    for fx in [Fixture::G1, Fixture::Go2] {
        let mut gw = gateway(fx);
        let payload = lowcmd::encode_payload(&frame(fx, 0.0), Representation::CdrLe);
        let n = payload.len() as u32;
        let mut now = T0;
        // One fragment holding the whole sample.
        now += 2 * MS;
        let p = frag_pkt(CONTROLLER_IP, WRITER, 1, 1, n as u16, n, &payload);
        assert_frag_suppressed(&mut gw, &p, now, "single fragment");
        // Two fragments, in order and out of order.
        for (sn, order) in [(2, [1u32, 2]), (3, [2, 1])] {
            for num in order {
                now += 2 * MS;
                let at = (num as usize - 1) * 512;
                let part = &payload[at..(at + 512).min(payload.len())];
                let p = frag_pkt(CONTROLLER_IP, WRITER, sn, num, 512, n, part);
                assert_frag_suppressed(&mut gw, &p, now, &format!("sn {sn} fragment {num}"));
            }
        }
        // Oversized sample.
        now += 2 * MS;
        let p = frag_pkt(CONTROLLER_IP, WRITER, 4, 1, 1024, 1 << 20, &[0u8; 1024]);
        assert_frag_suppressed(&mut gw, &p, now, "oversized");
        // A foreign participant's fragment too.
        now += 2 * MS;
        let d = Datagram::new(FOREIGN)
            .data_frag(WRITER, 1, 1, n as u16, n, &payload)
            .finish();
        let p = packet(ATTACKER_IP, DDS_PORT, &d);
        assert_frag_suppressed(&mut gw, &p, now, "foreign");
        assert!(gw.stats.unknown_undecidable >= 5, "{:?}", gw.stats);
        // Nothing was classified by these fragments.
        assert!(gw.discovery().writer(&writer_guid()).is_none());
    }
}

/// Key-only and non-standard DATA from an unknown writer cannot be probed
/// either: suppressed.
#[test]
fn f2_unknown_writer_key_only_and_non_standard_data_suppressed() {
    let fx = Fixture::G1;
    let mut gw = gateway(fx);
    // Neither decodes as a `LowCmd_` (a keyless type's key is empty), so
    // the probe cannot classify the writer.
    let payload = [0u8, 1, 0, 0, 0, 0, 0, 0];
    for (i, flags) in [0x08u8 /* K */, 0x04 | 0x10 /* D + N */]
        .into_iter()
        .enumerate()
    {
        let mut body = vec![0, 0, 16, 0, 0, 0, 0, 0];
        body.extend_from_slice(&WRITER);
        body.extend_from_slice(&0i32.to_le_bytes());
        body.extend_from_slice(&(i as u32 + 1).to_le_bytes());
        body.extend_from_slice(&payload);
        let d = Datagram::new(PREFIX).raw(rtps::DATA, flags, &body).finish();
        let p = packet(CONTROLLER_IP, DDS_PORT, &d);
        assert_frag_suppressed(&mut gw, &p, T0 + i as u64 * 2 * MS, "key-only / N");
    }
}

/// What still passes: a fragment of a writer SEDP classified on another
/// topic only with `rtps.unenforced_unprobeable: pass` (review 2, M1: it
/// is suppressed by default); `unknown_writers: pass` opts out of the
/// probe for fragments too; observe mode forwards and counts.
#[test]
fn f2_fragments_that_still_pass() {
    let fx = Fixture::G1;
    let payload = lowcmd::encode_payload(&frame(fx, 0.0), Representation::CdrLe);
    let n = payload.len() as u32;
    let other = [0, 0, 0x0a, 0x03];
    let mut gw = gateway(fx);
    let sedp = packet(
        CONTROLLER_IP,
        7410,
        &sedp_datagram(
            PREFIX,
            other,
            "rt/arm_sdk",
            "unitree_hg::msg::dds_::LowCmd_",
        ),
    );
    run(&mut gw, &sedp, T0);
    let p = frag_pkt(CONTROLLER_IP, other, 1, 1, 512, n, &payload[..512]);
    assert_frag_suppressed(&mut gw, &p, T0 + MS, "unenforced writer");
    assert_eq!(gw.stats.unenforced_undecidable, 1);
    let mut cfg = gateway_config(fx);
    cfg.rtps.unenforced_unprobeable = UnenforcedUnprobeable::Pass;
    let mut gw = Gateway::new(&cfg, &profile(fx), &firewall(fx)).unwrap();
    run(&mut gw, &sedp, T0);
    assert_eq!(run(&mut gw, &p, T0 + MS).0, Verdict::Accept);

    let mut cfg = gateway_config(fx);
    cfg.rtps.unknown_writers = UnknownWriters::Pass;
    let mut gw = Gateway::new(&cfg, &profile(fx), &firewall(fx)).unwrap();
    let p = frag_pkt(CONTROLLER_IP, WRITER, 1, 1, 512, n, &payload[..512]);
    assert_eq!(run(&mut gw, &p, T0).0, Verdict::Accept);

    let mut cfg = gateway_config(fx);
    cfg.mode = GatewayMode::Observe;
    let mut gw = Gateway::new(&cfg, &profile(fx), &firewall(fx)).unwrap();
    assert_eq!(run(&mut gw, &p, T0).0, Verdict::Accept);
    assert_eq!(gw.stats.observe_would_modify, 1);
}

// ------------------------------------------------------------------ F3

fn go_with(m: &WireLowCmd, f: impl FnOnce(&mut robodr_cdr::unitree::GoLowCmd)) -> WireLowCmd {
    let mut m = *m;
    if let WireLowCmd::Go(g) = &mut m {
        f(g);
    }
    m.seal();
    m
}

/// `bms_cmd.off = 0xA5` turns the battery off (SDK `comm.h`). An otherwise
/// valid frame carrying it is refused (decided as an integrity failure, so
/// the platform's substitute applies), and the substitute's non-motor
/// fields come from the last accepted frame (`off = 0`).
#[test]
fn f3_battery_off_is_refused_and_the_substitute_is_safe() {
    let fx = Fixture::Go2;
    let mut gw = gateway(fx);
    let good = go_with(&frame(fx, 0.0), |g| {
        g.led[0] = 7;
        g.fan[1] = 3;
        g.wireless_remote[5] = 9;
    });
    assert_eq!(
        run(&mut gw, &pkt_from(CONTROLLER_IP, PREFIX, 1, &good), T0).0,
        Verdict::Accept
    );
    for (sn, off) in [(2, 0xA5u8), (3, 0x01)] {
        let bad = go_with(&good, |g| {
            g.bms_cmd.off = off;
            g.led[0] = 1;
        });
        let (v, out) = run(
            &mut gw,
            &pkt_from(CONTROLLER_IP, PREFIX, sn, &bad),
            T0 + sn as u64 * 2 * MS,
        );
        assert_eq!(v, Verdict::AcceptModified, "off = {off:#x}");
        let held = out_lowcmd(&out, LowCmdCodec::Go).expect("substitute written");
        let (WireLowCmd::Go(h), WireLowCmd::Go(g)) = (held, good) else {
            unreachable!()
        };
        assert_eq!(h.bms_cmd.off, 0, "never forwarded");
        assert_eq!(
            (h.led, h.fan, h.wireless_remote),
            (g.led, g.fan, g.wireless_remote)
        );
        assert_eq!(
            h.motor_cmd[0].kp, g.motor_cmd[0].kp,
            "hold of the accepted frame"
        );
    }
    assert_eq!(gw.stats.non_motor_rejected, 2);
    // Nothing accepted yet (fresh gateway): the substitute uses the SDK
    // defaults (off = 0), or the sample is suppressed.
    let mut gw = gateway(fx);
    let bad = go_with(&good, |g| g.bms_cmd.off = 0xA5);
    let (_, out) = run(&mut gw, &pkt_from(CONTROLLER_IP, PREFIX, 1, &bad), T0);
    if let Some(WireLowCmd::Go(h)) = out_lowcmd(&out, LowCmdCodec::Go) {
        assert_eq!(h.bms_cmd.off, 0);
    }
    // A channel that explicitly allows it forwards the frame.
    let mut cfg = gateway_config(fx);
    cfg.channels[0].allow_battery_off = true;
    let mut gw = Gateway::new(&cfg, &profile(fx), &firewall(fx)).unwrap();
    assert_eq!(
        run(&mut gw, &pkt_from(CONTROLLER_IP, PREFIX, 1, &bad), T0).0,
        Verdict::Accept
    );
}
