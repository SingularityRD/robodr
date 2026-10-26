//! Gateway verdict paths on synthetic packets: rewrite correctness, the
//! humanoid rule, replay handling, undecidable / fragmented / malformed
//! input, sport API and Go1 legacy channels, observe mode and the
//! configuration refusals.

use std::time::Instant;

use robodr_cdr::Representation;
use robodr_firewall::{Firewall, JointCommand, JointVerdict, MotorMode, SubstituteKind};
use robodr_firewall_gw::config::{GatewayMode, OnGatewayDown};
use robodr_firewall_gw::ip::parse_ipv4_udp;
use robodr_firewall_gw::lowcmd::{self, LowCmdCodec, WireLowCmd, WireMotor};
use robodr_firewall_gw::rtps::{self, build::Datagram, Content, WalkOptions};
use robodr_firewall_gw::testkit::*;
use robodr_firewall_gw::{legacy, sport, Gateway, PacketMeta, Verdict};

const MS: u64 = 1_000_000;
const T0: u64 = 1_000_000_000;

fn meta(now: u64) -> PacketMeta {
    PacketMeta {
        now_ns: now,
        queue_delay_ns: None,
        instant: Instant::now(),
        src_mac: None,
    }
}

/// Process `pkt` at `now`; returns the verdict and the (possibly rewritten)
/// packet.
fn run(gw: &mut Gateway, pkt: &[u8], now: u64) -> (Verdict, Vec<u8>) {
    let mut p = pkt.to_vec();
    let v = gw.process(&mut p, meta(now));
    if v != Verdict::AcceptModified {
        assert_eq!(p, pkt, "unmodified verdict {v:?} but bytes changed");
    } else {
        assert_eq!(p.len(), pkt.len(), "rewrite changed the length");
        parse_ipv4_udp(&p).expect("rewritten packet has valid IP / UDP checksums");
    }
    (v, p)
}

/// The decoded `LowCmd_` of the first user DATA of `pkt`, or `None` if it
/// was suppressed (no user DATA left).
fn out_lowcmd(pkt: &[u8], codec: LowCmdCodec) -> Option<WireLowCmd> {
    let ip = parse_ipv4_udp(pkt).unwrap();
    let d = &pkt[ip.payload()];
    let mut v = Vec::new();
    rtps::walk(d, WalkOptions::default(), &mut v).unwrap();
    let s = v
        .iter()
        .find(|s| !s.builtin && s.content == Content::Data)?;
    let slot = &d[s.payload.clone().unwrap()];
    let dec = lowcmd::decode_strict(slot, codec).expect("forwarded LowCmd decodes strictly");
    assert!(dec.msg.crc_ok(), "forwarded LowCmd has a valid CRC");
    Some(dec.msg)
}

fn lowcmd_pkt(_fx: Fixture, prefix: rtps::GuidPrefix, sn: i64, msg: &WireLowCmd) -> Vec<u8> {
    packet(
        CONTROLLER_IP,
        DDS_PORT,
        &lowcmd_datagram(prefix, WRITER, sn, msg, Representation::CdrLe),
    )
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

/// Every byte outside the first user DATA's payload is unchanged.
fn only_payload_changed(inp: &[u8], out: &[u8]) {
    let ip = parse_ipv4_udp(inp).unwrap();
    let d = &inp[ip.payload()];
    let mut v = Vec::new();
    rtps::walk(d, WalkOptions::default(), &mut v).unwrap();
    let s = v.iter().find(|s| !s.builtin).unwrap();
    let r = s.payload.clone().unwrap();
    let (a, b) = (ip.payload_start + r.start, ip.payload_start + r.end);
    assert_eq!(
        inp[..ip.udp_start + 6],
        out[..ip.udp_start + 6],
        "IP / UDP header"
    );
    assert_eq!(
        inp[ip.udp_start + 8..a],
        out[ip.udp_start + 8..a],
        "RTPS before the payload"
    );
    assert_eq!(inp[b..], out[b..], "RTPS after the payload");
}

#[test]
fn valid_frame_passes_byte_identical() {
    for fx in [Fixture::G1, Fixture::Go2] {
        let mut gw = gateway(fx);
        for i in 0..20 {
            let p = lowcmd_pkt(fx, PREFIX, i + 1, &frame(fx, i as f64 * 0.01));
            let (v, _) = run(&mut gw, &p, T0 + i as u64 * 2 * MS);
            assert_eq!(v, Verdict::Accept, "{fx:?} frame {i}");
        }
        assert_eq!(gw.stats.passed, 20);
        assert_eq!(gw.stats.probed, 1, "classified once by the CRC probe");
    }
}

#[test]
fn limited_frame_is_rewritten_exactly_and_in_place() {
    for fx in [Fixture::G1, Fixture::Go2] {
        for rep in [
            Representation::CdrLe,
            Representation::CdrBe,
            Representation::Cdr2Le,
        ] {
            let mut gw = gateway(fx);
            let mut reference = Firewall::new(firewall(fx).compile(&profile(fx)).unwrap());
            let src = reference.source_id(&guid_hex(&PREFIX, WRITER)).unwrap();
            let ch = reference.channel_id("/lowcmd").unwrap();
            let spec = lowcmd_spec(fx);
            let slot = spec.motors.iter().position(|m| m.enabled).unwrap();
            let lim = spec.motors[slot].clone();
            let mk = |sn: i64, m: &WireLowCmd| {
                // Another topic's DATA after ours: must stay untouched.
                let other = Datagram::new(PREFIX)
                    .info_ts(1_700_000_000, 0)
                    .data(WRITER, sn, &[], &lowcmd::encode_payload(m, rep))
                    .data([0, 0, 0x09, 0x03], sn, &[], &[0, 1, 0, 0, 1, 2, 3, 4])
                    .heartbeat(WRITER, 1, sn)
                    .finish();
                packet(CONTROLLER_IP, DDS_PORT, &other)
            };
            let good = frame(fx, 0.0);
            let now = T0;
            let (v, _) = run(&mut gw, &mk(1, &good), now);
            assert_eq!(v, Verdict::Accept);
            let jf = good.joint_frame().unwrap();
            assert!(reference
                .check_joint(&JointCommand::new(src, ch, now, jf), now)
                .is_passed());

            // tau 1.5 x tau_max (inside the hard factor 2): clamped. 23.7 /
            // 88.0 are not f32 values, so the rounding rule is exercised.
            let mut over = good;
            let mut w = over.motor(slot).unwrap();
            w.tau = (lim.tau_max.unwrap() * 1.5) as f32;
            over.set_motor(slot, w);
            over.seal();
            let pkt = mk(2, &over);
            let now = T0 + 2 * MS;
            let (v, out) = run(&mut gw, &pkt, now);
            assert_eq!(v, Verdict::AcceptModified, "{fx:?} {rep:?}");
            only_payload_changed(&pkt, &out);
            let back = out_lowcmd(&out, codec(fx)).unwrap();
            let rv = reference.check_joint(
                &JointCommand::new(src, ch, now, over.joint_frame().unwrap()),
                now,
            );
            let JointVerdict::Limited { cmd, .. } = rv else {
                panic!("{rv:?}")
            };
            for (i, want) in cmd.frame.motors().iter().enumerate() {
                let got = back.motor(i).unwrap();
                assert_eq!(MotorMode::from_u8(got.mode), want.mode);
                assert_eq!(got.mode, over.motor(i).unwrap().mode, "mode octet kept");
                for (g, w) in [
                    (got.q, want.q),
                    (got.dq, want.dq),
                    (got.tau, want.tau),
                    (got.kp, want.kp),
                    (got.kd, want.kd),
                ] {
                    let g = f64::from(g);
                    assert!(
                        (g - w).abs() <= w.abs() * f64::from(f32::EPSILON),
                        "slot {i}: {g} vs {w}"
                    );
                }
            }
            let tau = f64::from(back.motor(slot).unwrap().tau);
            assert!(
                tau <= lim.tau_max.unwrap(),
                "clamped tau {tau} crosses tau_max"
            );
            assert!(tau > lim.tau_max.unwrap() * 0.999_999);
            // Non-motor fields kept.
            match (back, over) {
                (WireLowCmd::Go(a), WireLowCmd::Go(b)) => {
                    assert_eq!(
                        (
                            a.head,
                            a.level_flag,
                            a.sn,
                            a.bms_cmd,
                            a.wireless_remote,
                            a.reserve
                        ),
                        (
                            b.head,
                            b.level_flag,
                            b.sn,
                            b.bms_cmd,
                            b.wireless_remote,
                            b.reserve
                        )
                    );
                }
                (WireLowCmd::Hg(a), WireLowCmd::Hg(b)) => {
                    assert_eq!(
                        (a.mode_pr, a.mode_machine, a.reserve),
                        (b.mode_pr, b.mode_machine, b.reserve)
                    );
                }
                _ => panic!("codec changed"),
            }
            assert_eq!(gw.stats.limited, 1);
        }
    }
}

/// The humanoid rule at the packet level: a rejected frame becomes a hold
/// of the last accepted frame (dq = 0), never damping or limp; with no
/// frame accepted yet the sample is suppressed.
#[test]
fn humanoid_holds_never_damps() {
    let fx = Fixture::G1;
    let spec = lowcmd_spec(fx);
    let spare = spec.motors.iter().position(|m| !m.enabled).unwrap();
    let mut gw = gateway(fx);
    // Nothing accepted yet: a violating frame is suppressed, not damped.
    let mut bad = frame(fx, 0.0);
    bad.set_motor(
        spare,
        WireMotor {
            mode: 1,
            tau: 5.0,
            ..Default::default()
        },
    );
    bad.seal();
    let (v, out) = run(&mut gw, &lowcmd_pkt(fx, PREFIX, 1, &bad), T0);
    assert_eq!(v, Verdict::AcceptModified);
    assert!(
        out_lowcmd(&out, LowCmdCodec::Hg).is_none(),
        "suppressed (PAD)"
    );
    let ip = parse_ipv4_udp(&out).unwrap();
    let r = robodr_rtps::walk_user_data(&out[ip.payload()]).unwrap();
    assert!(
        r.samples.is_empty(),
        "the passive parser sees no sample either"
    );

    // Accept one frame (with non-zero dq), then violate in several ways.
    let mut good = frame(fx, 0.3);
    for i in 0..35 {
        if spec.motors[i].enabled {
            let mut w = good.motor(i).unwrap();
            w.dq = 0.25;
            w.tau = 1.5;
            good.set_motor(i, w);
        }
    }
    good.seal();
    let (v, _) = run(&mut gw, &lowcmd_pkt(fx, PREFIX, 2, &good), T0 + 4 * MS);
    assert_eq!(v, Verdict::Accept);
    let leg = 3;
    type Violation = Box<dyn Fn(&mut WireLowCmd)>;
    let violations: Vec<Violation> = vec![
        // Unused slot energised.
        Box::new(move |m| {
            m.set_motor(
                spare,
                WireMotor {
                    mode: 1,
                    kp: 50.0,
                    ..Default::default()
                },
            )
        }),
        // A limp leg.
        Box::new(move |m| m.set_motor(leg, WireMotor::default())),
        // Every slot limp.
        Box::new(|m| {
            for i in 0..35 {
                let mut w = m.motor(i).unwrap();
                w.kp = 0.0;
                w.kd = 0.0;
                m.set_motor(i, w);
            }
        }),
        // Torque beyond the hard factor.
        Box::new(move |m| {
            let mut w = m.motor(leg).unwrap();
            w.tau = 1000.0;
            m.set_motor(leg, w);
        }),
        // NaN.
        Box::new(move |m| {
            let mut w = m.motor(leg).unwrap();
            w.q = f32::NAN;
            m.set_motor(leg, w);
        }),
        // Wrong ankle mode.
        Box::new(|m| {
            if let WireLowCmd::Hg(h) = m {
                h.mode_pr = 1;
            }
        }),
    ];
    let mut now = T0 + 4 * MS;
    for (k, f) in violations.iter().enumerate() {
        now += 2 * MS;
        let mut b = good;
        f(&mut b);
        b.seal();
        let (v, out) = run(&mut gw, &lowcmd_pkt(fx, PREFIX, 3 + k as i64, &b), now);
        assert_eq!(v, Verdict::AcceptModified, "violation {k}");
        let held = out_lowcmd(&out, LowCmdCodec::Hg).expect("a hold, not a suppression");
        for i in 0..35 {
            let (h, g) = (held.motor(i).unwrap(), good.motor(i).unwrap());
            assert_eq!(
                (
                    h.mode,
                    h.q.to_bits(),
                    h.tau.to_bits(),
                    h.kp.to_bits(),
                    h.kd.to_bits()
                ),
                (
                    g.mode,
                    g.q.to_bits(),
                    g.tau.to_bits(),
                    g.kp.to_bits(),
                    g.kd.to_bits()
                ),
                "violation {k} slot {i}"
            );
            assert_eq!(h.dq, 0.0);
            if spec.motors[i].enabled {
                assert!(h.kp > 0.0 || h.kd > 0.0, "never limp");
            }
        }
        assert_eq!(held.modes(), good.modes());
    }
    assert_eq!(gw.stats.substituted, violations.len() as u64);
}

#[test]
fn humanoid_hold_past_max_hold_drops_feedforward_only() {
    let fx = Fixture::G1;
    let mut gw = gateway(fx);
    let mut good = frame(fx, 0.0);
    let mut w = good.motor(0).unwrap();
    w.tau = 3.0;
    good.set_motor(0, w);
    good.seal();
    assert_eq!(
        run(&mut gw, &lowcmd_pkt(fx, PREFIX, 1, &good), T0).0,
        Verdict::Accept
    );
    let mut bad = good;
    let mut w = bad.motor(0).unwrap();
    w.tau = 1e4;
    bad.set_motor(0, w);
    bad.seal();
    // 300 ms later (> max_hold 200 ms): still a hold, tau zeroed.
    let (v, out) = run(&mut gw, &lowcmd_pkt(fx, PREFIX, 2, &bad), T0 + 300 * MS);
    assert_eq!(v, Verdict::AcceptModified);
    let h = out_lowcmd(&out, LowCmdCodec::Hg).unwrap();
    assert_eq!(h.motor(0).unwrap().tau, 0.0);
    assert_eq!(h.motor(0).unwrap().kp, good.motor(0).unwrap().kp);
    assert_eq!(gw.firewall().stats().joint_holds_exceeded, 1);
}

#[test]
fn quadruped_damps_after_hold_expires() {
    let fx = Fixture::Go2;
    let spec = lowcmd_spec(fx);
    let mut gw = gateway(fx);
    let good = frame(fx, 0.0);
    assert_eq!(
        run(&mut gw, &lowcmd_pkt(fx, PREFIX, 1, &good), T0).0,
        Verdict::Accept
    );
    let mut bad = good;
    if let WireLowCmd::Go(g) = &mut bad {
        g.crc ^= 0xffff; // integrity failure
    }
    let (v, out) = run(&mut gw, &lowcmd_pkt(fx, PREFIX, 2, &bad), T0 + 2 * MS);
    assert_eq!(v, Verdict::AcceptModified);
    let h = out_lowcmd(&out, LowCmdCodec::Go).unwrap();
    assert_eq!(
        h.motor(0).unwrap().kp,
        good.motor(0).unwrap().kp,
        "hold first"
    );
    // After the 100 ms hold: the damping frame (kp = 0, kd = 3).
    let (v, out) = run(&mut gw, &lowcmd_pkt(fx, PREFIX, 3, &bad), T0 + 200 * MS);
    assert_eq!(v, Verdict::AcceptModified);
    let d = out_lowcmd(&out, LowCmdCodec::Go).unwrap();
    for (i, lim) in spec.motors.iter().enumerate() {
        let m = d.motor(i).unwrap();
        if lim.enabled {
            assert_eq!((m.kp, m.dq, m.tau, m.kd), (0.0, 0.0, 0.0, 3.0));
            assert_eq!(m.mode, 0x01);
        } else {
            assert_eq!(m, WireMotor::default());
        }
    }
    // Non-motor fields of the damping frame come from the last accepted.
    if let (WireLowCmd::Go(a), WireLowCmd::Go(b)) = (d, good) {
        assert_eq!(
            (a.head, a.level_flag, a.bms_cmd),
            (b.head, b.level_flag, b.bms_cmd)
        );
    }
}

#[test]
fn foreign_writer_is_suppressed_and_legit_stream_unaffected() {
    for fx in [Fixture::G1, Fixture::Go2] {
        let mut gw = gateway(fx);
        let good = frame(fx, 0.0);
        let mut now = T0;
        for sn in 1..=10 {
            now += 2 * MS;
            assert_eq!(
                run(&mut gw, &lowcmd_pkt(fx, PREFIX, sn, &good), now).0,
                Verdict::Accept
            );
            // A spoofer interleaves valid-looking frames (valid CRC).
            let (v, out) = run(
                &mut gw,
                &packet(
                    ATTACKER_IP,
                    DDS_PORT,
                    &lowcmd_datagram(FOREIGN, WRITER, sn, &good, Representation::CdrLe),
                ),
                now + MS / 2,
            );
            assert_eq!(v, Verdict::AcceptModified);
            assert!(out_lowcmd(&out, codec(fx)).is_none());
        }
        let devs = gw.firewall_mut().drain_deviations();
        assert!(devs
            .iter()
            .any(|d| d.rule == "robot.firewall.rejected_unknown_source"));
    }
}

#[test]
fn source_ip_binding_makes_a_spoofed_guid_foreign() {
    let fx = Fixture::G1;
    let mut cfg = gateway_config(fx);
    cfg.channels[0].allowed_src_ips = vec![CONTROLLER_IP.to_string()];
    let mut gw = Gateway::new(&cfg, &profile(fx), &firewall(fx)).unwrap();
    let good = frame(fx, 0.0);
    assert_eq!(
        run(&mut gw, &lowcmd_pkt(fx, PREFIX, 1, &good), T0).0,
        Verdict::Accept
    );
    // Same GUID, other IP.
    let spoof = packet(
        ATTACKER_IP,
        DDS_PORT,
        &lowcmd_datagram(PREFIX, WRITER, 2, &good, Representation::CdrLe),
    );
    let (v, out) = run(&mut gw, &spoof, T0 + 2 * MS);
    assert_eq!(v, Verdict::AcceptModified);
    assert!(out_lowcmd(&out, LowCmdCodec::Hg).is_none());
}

#[test]
fn too_early_frame_is_suppressed() {
    let fx = Fixture::Go2;
    let mut gw = gateway(fx);
    let good = frame(fx, 0.0);
    assert_eq!(
        run(&mut gw, &lowcmd_pkt(fx, PREFIX, 1, &good), T0).0,
        Verdict::Accept
    );
    // 0.5 ms later (< min_interval 1 ms): nothing is emitted.
    let (v, out) = run(
        &mut gw,
        &lowcmd_pkt(fx, PREFIX, 2, &frame(fx, 0.1)),
        T0 + MS / 2,
    );
    assert_eq!(v, Verdict::AcceptModified);
    assert!(out_lowcmd(&out, LowCmdCodec::Go).is_none());
}

#[test]
fn two_samples_in_one_datagram_are_decided_in_order() {
    let fx = Fixture::Go2;
    let mut gw = gateway(fx);
    let a = frame(fx, 0.0);
    let b = frame(fx, 0.1);
    let d = Datagram::new(PREFIX)
        .data(
            WRITER,
            1,
            &[],
            &lowcmd::encode_payload(&a, Representation::CdrLe),
        )
        .data(
            WRITER,
            2,
            &[],
            &lowcmd::encode_payload(&b, Representation::CdrLe),
        )
        .heartbeat(WRITER, 1, 2)
        .finish();
    let (v, out) = run(&mut gw, &packet(CONTROLLER_IP, DDS_PORT, &d), T0);
    // The second arrives in the same instant: too early, suppressed.
    assert_eq!(v, Verdict::AcceptModified);
    let ip = parse_ipv4_udp(&out).unwrap();
    let mut s = Vec::new();
    rtps::walk(&out[ip.payload()], WalkOptions::default(), &mut s).unwrap();
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].sn, 1);
}

#[test]
fn retransmission_reemits_the_decided_bytes() {
    let fx = Fixture::G1;
    let mut gw = gateway(fx);
    let good = frame(fx, 0.0);
    let p1 = lowcmd_pkt(fx, PREFIX, 1, &good);
    assert_eq!(run(&mut gw, &p1, T0).0, Verdict::Accept);
    let mut bad = good;
    let mut w = bad.motor(0).unwrap();
    w.tau = 1e4;
    bad.set_motor(0, w);
    bad.seal();
    let p2 = lowcmd_pkt(fx, PREFIX, 2, &bad);
    let (v, held) = run(&mut gw, &p2, T0 + 2 * MS);
    assert_eq!(v, Verdict::AcceptModified);
    let checked = gw.firewall().stats().checked;
    // Reliable retransmission of SN 2 (same bytes): the same hold again,
    // the firewall is not consulted.
    let (v, again) = run(&mut gw, &p2, T0 + 10 * MS);
    assert_eq!(v, Verdict::AcceptModified);
    assert_eq!(again, held);
    // A replay of SN 1 carrying the violating content: the original bytes.
    let p1_evil = lowcmd_pkt(fx, PREFIX, 1, &bad);
    let (v, out) = run(&mut gw, &p1_evil, T0 + 12 * MS);
    assert_eq!(v, Verdict::AcceptModified);
    assert_eq!(out_lowcmd(&out, LowCmdCodec::Hg).unwrap(), good);
    // Sequence number 0 (invalid; receivers drop it): suppressed.
    let (v, out) = run(&mut gw, &lowcmd_pkt(fx, PREFIX, 0, &good), T0 + 14 * MS);
    assert_eq!(v, Verdict::AcceptModified);
    assert!(out_lowcmd(&out, LowCmdCodec::Hg).is_none());
    assert_eq!(gw.firewall().stats().checked, checked);
    assert!(gw.stats.replays >= 2);
}

#[test]
fn undecidable_payloads() {
    let fx = Fixture::G1;
    let mut gw = gateway(fx);
    let good = frame(fx, 0.0);
    assert_eq!(
        run(&mut gw, &lowcmd_pkt(fx, PREFIX, 1, &good), T0).0,
        Verdict::Accept
    );
    // Non-canonical (a padding octet set): an integrity failure, so the
    // authorised writer's sample carries a hold.
    let mut payload = lowcmd::encode_payload(&good, Representation::CdrLe);
    // Body offset 3 is the padding octet after slot 0's mode (hg XCDR1).
    payload[4 + 3] = 0x7f;
    let d = Datagram::new(PREFIX)
        .data(WRITER, 2, &[], &payload)
        .finish();
    let (v, out) = run(&mut gw, &packet(CONTROLLER_IP, DDS_PORT, &d), T0 + 2 * MS);
    assert_eq!(v, Verdict::AcceptModified);
    let h = out_lowcmd(&out, LowCmdCodec::Hg).expect("hold written into the slot");
    assert_eq!(h.motor(0).unwrap().kp, good.motor(0).unwrap().kp);
    // Truncated payload (classified by SEDP): hold where it fits? It does
    // not fit: suppressed.
    gw.discovery_mut().insert(
        {
            let mut g = [0u8; 16];
            g[..12].copy_from_slice(&PREFIX);
            g[12..].copy_from_slice(&WRITER);
            g
        },
        robodr_firewall_gw::discovery::WriterInfo {
            channel: Some(0),
            probed: false,
        },
    );
    let short = Datagram::new(PREFIX)
        .data(WRITER, 3, &[], &payload[..200])
        .finish();
    let (v, out) = run(
        &mut gw,
        &packet(CONTROLLER_IP, DDS_PORT, &short),
        T0 + 10 * MS,
    );
    assert_eq!(v, Verdict::AcceptModified);
    assert!(out_lowcmd(&out, LowCmdCodec::Hg).is_none());
    // A foreign writer's garbage is suppressed (never a substitute).
    let mut fgw = gateway(fx);
    assert_eq!(
        run(&mut fgw, &lowcmd_pkt(fx, PREFIX, 1, &good), T0).0,
        Verdict::Accept
    );
    fgw.discovery_mut().insert(
        {
            let mut g = [0u8; 16];
            g[..12].copy_from_slice(&FOREIGN);
            g[12..].copy_from_slice(&WRITER);
            g
        },
        robodr_firewall_gw::discovery::WriterInfo {
            channel: Some(0),
            probed: false,
        },
    );
    let d = Datagram::new(FOREIGN)
        .data(WRITER, 1, &[], &payload)
        .finish();
    let (v, out) = run(&mut fgw, &packet(ATTACKER_IP, DDS_PORT, &d), T0 + 2 * MS);
    assert_eq!(v, Verdict::AcceptModified);
    assert!(out_lowcmd(&out, LowCmdCodec::Hg).is_none());
}

#[test]
fn fragmented_lowcmd_is_suppressed_and_malformed_datagrams_dropped() {
    let fx = Fixture::G1;
    let mut gw = gateway(fx);
    let good = frame(fx, 0.0);
    // Classify the writer through SEDP first.
    let sedp = packet(
        CONTROLLER_IP,
        7410,
        &sedp_datagram(
            PREFIX,
            WRITER,
            "rt/lowcmd",
            "unitree_hg::msg::dds_::LowCmd_",
        ),
    );
    assert_eq!(run(&mut gw, &sedp, T0).0, Verdict::Accept);
    let payload = lowcmd::encode_payload(&good, Representation::CdrLe);
    let d = Datagram::new(PREFIX)
        .data_frag(WRITER, 1, 1, 512, payload.len() as u32, &payload[..512])
        .heartbeat(WRITER, 1, 1)
        .finish();
    let (v, out) = run(&mut gw, &packet(CONTROLLER_IP, DDS_PORT, &d), T0 + MS);
    assert_eq!(v, Verdict::AcceptModified);
    let ip = parse_ipv4_udp(&out).unwrap();
    let mut s = Vec::new();
    let sum = rtps::walk(&out[ip.payload()], WalkOptions::default(), &mut s).unwrap();
    assert!(s.is_empty() && sum.submessages == 2);
    assert_eq!(gw.stats.unsupported_sample, 1);

    // Truncated RTPS, non-RTPS, bad UDP checksum, IP fragment: dropped.
    let mut trunc = lowcmd_datagram(PREFIX, WRITER, 2, &good, Representation::CdrLe);
    trunc.truncate(trunc.len() - 3);
    assert_eq!(
        run(
            &mut gw,
            &packet(CONTROLLER_IP, DDS_PORT, &trunc),
            T0 + 3 * MS
        )
        .0,
        Verdict::Drop
    );
    assert_eq!(
        run(
            &mut gw,
            &packet(CONTROLLER_IP, DDS_PORT, b"hello"),
            T0 + 4 * MS
        )
        .0,
        Verdict::Drop
    );
    let mut badsum = lowcmd_pkt(fx, PREFIX, 3, &good);
    let n = badsum.len();
    badsum[n - 9] ^= 1;
    assert_eq!(run(&mut gw, &badsum, T0 + 5 * MS).0, Verdict::Drop);
    let mut frag = lowcmd_pkt(fx, PREFIX, 3, &good);
    frag[6] |= 0x20;
    frag[10] = 0;
    frag[11] = 0;
    let c = robodr_capture::checksum::ipv4_header_checksum(&frag[..20]);
    frag[10..12].copy_from_slice(&c.to_be_bytes());
    assert_eq!(run(&mut gw, &frag, T0 + 6 * MS).0, Verdict::Drop);
    assert_eq!(gw.stats.dropped_ip, 2);
}

#[test]
fn sedp_classification_and_other_topics() {
    let fx = Fixture::G1;
    let mut gw = gateway(fx);
    let other_writer = [0, 0, 0x0a, 0x03];
    let sedp = packet(
        CONTROLLER_IP,
        7410,
        &sedp_datagram(
            PREFIX,
            other_writer,
            "rt/arm_sdk",
            "unitree_hg::msg::dds_::LowCmd_",
        ),
    );
    run(&mut gw, &sedp, T0);
    // A LowCmd-shaped sample on another topic (rt/arm_sdk) is not decided.
    let mut bad = frame(fx, 0.0);
    let mut w = bad.motor(0).unwrap();
    w.tau = 1e4;
    bad.set_motor(0, w);
    bad.seal();
    let d = Datagram::new(PREFIX)
        .data(
            other_writer,
            1,
            &[],
            &lowcmd::encode_payload(&bad, Representation::CdrLe),
        )
        .finish();
    assert_eq!(
        run(&mut gw, &packet(CONTROLLER_IP, DDS_PORT, &d), T0 + MS).0,
        Verdict::Accept
    );
    assert_eq!(gw.stats.samples, 0);
    assert_eq!(gw.discovery().len(), 1);
}

#[test]
fn late_packet_gets_the_fault_verdict() {
    let fx = Fixture::G1;
    let mut gw = gateway(fx);
    let good = frame(fx, 0.0);
    assert_eq!(
        run(&mut gw, &lowcmd_pkt(fx, PREFIX, 1, &good), T0).0,
        Verdict::Accept
    );
    let mut p = lowcmd_pkt(fx, PREFIX, 2, &frame(fx, 0.1));
    let m = PacketMeta {
        now_ns: T0 + 2 * MS,
        queue_delay_ns: Some(50 * MS),
        instant: Instant::now(),
        src_mac: None,
    };
    assert_eq!(gw.process(&mut p, m), Verdict::AcceptModified);
    let h = out_lowcmd(&p, LowCmdCodec::Hg).unwrap();
    assert_eq!(
        h.motor(0).unwrap().q,
        good.motor(0).unwrap().q,
        "humanoid fault holds"
    );
    assert_eq!(gw.stats.late, 1);
    assert_eq!(gw.firewall().stats().faults, 1);
}

#[test]
fn sport_move_limit_substitute_allowlist_alias() {
    let mut gw = gateway(Fixture::Go2);
    let req = |id: i64, api: i64, param: &str| {
        let payload = sport::encode_request(Representation::CdrLe, id, api, param);
        let d = Datagram::new(PREFIX)
            .data(SPORT_WRITER, id, &[], &payload)
            .finish();
        packet(CONTROLLER_IP, DDS_PORT, &d)
    };
    let sedp = packet(
        CONTROLLER_IP,
        7410,
        &sedp_datagram(
            PREFIX,
            SPORT_WRITER,
            "rt/api/sport/request",
            "unitree_api::msg::dds_::Request_",
        ),
    );
    run(&mut gw, &sedp, T0);
    let decode = |out: &[u8]| -> Option<robodr_cdr::ApiCall> {
        let ip = parse_ipv4_udp(out).unwrap();
        let d = &out[ip.payload()];
        let mut v = Vec::new();
        rtps::walk(d, WalkOptions::default(), &mut v).unwrap();
        let s = v.iter().find(|s| !s.builtin)?;
        Some(
            sport::decode_strict(&d[s.payload.clone()?], None)
                .unwrap()
                .call,
        )
    };
    let mv = |vx: f64, vy: f64, vz: f64| robodr_cdr::ApiCall::Move { vx, vy, vyaw: vz };
    // Within limits: byte-identical.
    let p = req(1, 1008, r#"{"x":0.5000000000,"y":0.0,"z":0.1000000000}"#);
    assert_eq!(run(&mut gw, &p, T0 + MS).0, Verdict::Accept);
    // Over the 1.0 m/s limit (inside 2x): scaled down, direction kept.
    let p = req(2, 1008, r#"{"x":1.6000000000,"y":0.0,"z":0.0000000000}"#);
    let (v, out) = run(&mut gw, &p, T0 + 1000 * MS);
    assert_eq!(v, Verdict::AcceptModified);
    match decode(&out).unwrap() {
        robodr_cdr::ApiCall::Move { vx, vy, vyaw } => {
            assert!(vx <= 1.0 && vx > 0.999, "{vx}");
            assert_eq!((vy, vyaw), (0.0, 0.0));
        }
        c => panic!("{c:?}"),
    }
    // Over the hard limit: rejected, hold of the last accepted (decelerating
    // only) or zero.
    let p = req(3, 1008, r#"{"x":5.0000000000,"y":0.0,"z":0.0000000000}"#);
    let (v, out) = run(&mut gw, &p, T0 + 2000 * MS);
    assert_eq!(v, Verdict::AcceptModified);
    assert_eq!(decode(&out).unwrap(), mv(0.0, 0.0, 0.0));
    // A call not in the allowlist (1030 = FrontFlip on Go2): suppressed.
    let p = req(4, 1030, "");
    let (v, out) = run(&mut gw, &p, T0 + 3000 * MS);
    assert_eq!(v, Verdict::AcceptModified);
    assert!(decode(&out).is_none());
    // StopMove: passes.
    assert_eq!(
        run(&mut gw, &req(5, 1003, ""), T0 + 4000 * MS).0,
        Verdict::Accept
    );
    // Move hidden as 2^32 + 1008: suppressed.
    let p = req(6, (1i64 << 32) + 1008, r#"{"x":0.1,"y":0.0,"z":0.0}"#);
    let (v, out) = run(&mut gw, &p, T0 + 5000 * MS);
    assert_eq!(v, Verdict::AcceptModified);
    assert!(decode(&out).is_none());
    assert_eq!(gw.stats.api_alias, 1);
    assert_eq!(gw.stats.not_allowlisted, 1);
}

#[test]
fn legacy_high_and_low() {
    let mut gw = gateway(Fixture::Go2);
    let high = |m: u8, vx: f32| packet(CONTROLLER_IP, 8082, &legacy::build_high(m, vx, 0.0, 0.0));
    assert_eq!(run(&mut gw, &high(2, 0.5), T0).0, Verdict::Accept);
    let (v, out) = run(&mut gw, &high(2, 1.5), T0 + 1000 * MS);
    assert_eq!(v, Verdict::AcceptModified);
    let ip = parse_ipv4_udp(&out).unwrap();
    let h = legacy::decode_high(&out[ip.payload()]).unwrap();
    assert!(h.crc_ok && f64::from(h.vx) <= 1.0 && h.vx > 0.99);
    // Foreign IP: dropped.
    let spoof = packet(ATTACKER_IP, 8082, &legacy::build_high(2, 0.2, 0.0, 0.0));
    assert_eq!(run(&mut gw, &spoof, T0 + 2000 * MS).0, Verdict::Drop);
    // Mode 7 (damping) is not allowlisted: dropped.
    assert_eq!(run(&mut gw, &high(7, 0.0), T0 + 3000 * MS).0, Verdict::Drop);
    // Wrong length: dropped.
    assert_eq!(
        run(
            &mut gw,
            &packet(CONTROLLER_IP, 8082, &[0u8; 100]),
            T0 + 4000 * MS
        )
        .0,
        Verdict::Drop
    );

    // LowCmd: limited torque rewritten in place.
    let spec = lowcmd_spec(Fixture::Go2);
    let mut motors = vec![(0u8, [0f32; 5]); 20];
    for (i, m) in spec.motors.iter().enumerate() {
        if m.enabled {
            let q = ((m.q_min.unwrap() + m.q_max.unwrap()) / 2.0) as f32;
            motors[i] = (0x0A, [q, 0.0, 0.0, 20.0, 1.0]);
        }
    }
    let ok = legacy::build_low(&motors);
    assert_eq!(
        run(&mut gw, &packet(CONTROLLER_IP, 8007, &ok), T0 + 5000 * MS).0,
        Verdict::Accept
    );
    let mut over = motors.clone();
    over[0].1[2] = 30.0; // tau over 23.7 (inside 2x)
    let (v, out) = run(
        &mut gw,
        &packet(CONTROLLER_IP, 8007, &legacy::build_low(&over)),
        T0 + 5002 * MS,
    );
    assert_eq!(v, Verdict::AcceptModified);
    let ip = parse_ipv4_udp(&out).unwrap();
    let f = &out[ip.payload()];
    assert!(legacy::crc_ok(f));
    let (mode, vals) = legacy::low_motor(f, 0).unwrap();
    assert_eq!(mode, 0x0A);
    assert!(f64::from(vals[2]) <= 23.7 && vals[2] > 23.69);
    // Hard violation: hold of the last accepted.
    over[0].1[2] = 100.0;
    let (v, out) = run(
        &mut gw,
        &packet(CONTROLLER_IP, 8007, &legacy::build_low(&over)),
        T0 + 5004 * MS,
    );
    assert_eq!(v, Verdict::AcceptModified);
    let ip = parse_ipv4_udp(&out).unwrap();
    let (_, vals) = legacy::low_motor(&out[ip.payload()], 0).unwrap();
    assert!(
        f64::from(vals[2]) <= 23.7,
        "held the last accepted (clamped) frame"
    );
    // The 614-octet compressed form is undecidable: dropped.
    assert_eq!(
        run(
            &mut gw,
            &packet(CONTROLLER_IP, 8007, &[0u8; 614]),
            T0 + 5006 * MS
        )
        .0,
        Verdict::Drop
    );
}

#[test]
fn observe_mode_never_changes_a_packet() {
    let fx = Fixture::G1;
    let mut cfg = gateway_config(fx);
    cfg.mode = GatewayMode::Observe;
    let mut gw = Gateway::new(&cfg, &profile(fx), &firewall(fx)).unwrap();
    let good = frame(fx, 0.0);
    let mut bad = good;
    let mut w = bad.motor(0).unwrap();
    w.tau = 1e4;
    bad.set_motor(0, w);
    bad.seal();
    for (i, f) in [good, bad].iter().enumerate() {
        let p = lowcmd_pkt(fx, PREFIX, i as i64 + 1, f);
        assert_eq!(run(&mut gw, &p, T0 + i as u64 * 2 * MS).0, Verdict::Accept);
    }
    assert_eq!(
        run(
            &mut gw,
            &packet(CONTROLLER_IP, DDS_PORT, b"junk"),
            T0 + 9 * MS
        )
        .0,
        Verdict::Accept
    );
    assert_eq!(gw.stats.observe_would_modify, 1);
    assert_eq!(gw.stats.observe_would_drop, 1);
}

#[test]
fn configuration_refusals() {
    // Humanoid + bypass.
    let mut cfg = gateway_config(Fixture::G1);
    cfg.queue.on_gateway_down = OnGatewayDown::Bypass;
    let e = Gateway::new(&cfg, &profile(Fixture::G1), &firewall(Fixture::G1)).unwrap_err();
    assert!(e.contains("bypass"), "{e}");
    // Quadruped + bypass is an OEM choice: allowed.
    let mut cfg = gateway_config(Fixture::Go2);
    cfg.queue.on_gateway_down = OnGatewayDown::Bypass;
    assert!(Gateway::new(&cfg, &profile(Fixture::Go2), &firewall(Fixture::Go2)).is_ok());
    // Codec / slot mismatch (go codec on the 35-slot G1 channel).
    let mut cfg = gateway_config(Fixture::G1);
    cfg.channels[0].codec = robodr_firewall_gw::Codec::UnitreeGoLowcmd;
    assert!(
        Gateway::new(&cfg, &profile(Fixture::G1), &firewall(Fixture::G1))
            .unwrap_err()
            .contains("slots")
    );
    // Enforce with an unlocked profile.
    let mut p = profile(Fixture::G1);
    p.locked = false;
    assert!(Gateway::new(&gateway_config(Fixture::G1), &p, &firewall(Fixture::G1)).is_err());
    // A channel the firewall does not have.
    let mut cfg = gateway_config(Fixture::G1);
    cfg.channels[0].firewall_channel = "/nope".into();
    assert!(Gateway::new(&cfg, &profile(Fixture::G1), &firewall(Fixture::G1)).is_err());
    // Profile says another type for the channel.
    let mut p = profile(Fixture::G1);
    p.motion_types
        .insert("/lowcmd".into(), "unitree_go::msg::dds_::LowCmd_".into());
    assert!(Gateway::new(&gateway_config(Fixture::G1), &p, &firewall(Fixture::G1)).is_err());
}

#[test]
fn substitute_kind_matches_reference_firewall() {
    // Cross-check: across a random stream, every forwarded LowCmd equals the
    // reference firewall's output (bit-exact for passes and held fields).
    for fx in [Fixture::G1, Fixture::Go2] {
        let mut gw = gateway(fx);
        let mut reference = Firewall::new(firewall(fx).compile(&profile(fx)).unwrap());
        let src = reference.source_id(&guid_hex(&PREFIX, WRITER)).unwrap();
        let ch = reference.channel_id("/lowcmd").unwrap();
        let spec = lowcmd_spec(fx);
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut rnd = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed >> 11) as f64 / (1u64 << 53) as f64
        };
        let mut now = T0;
        let (mut sub, mut lim, mut sup) = (0, 0, 0);
        for sn in 1..=3000i64 {
            now += (1.5e6 + rnd() * 1.0e6) as u64;
            let mut f = frame(fx, sn as f64 * 0.002);
            let r = rnd();
            let slot = spec
                .motors
                .iter()
                .enumerate()
                .filter(|(_, m)| m.enabled)
                .nth((rnd() * 10.0) as usize)
                .map(|(i, _)| i)
                .unwrap_or(0);
            let mut w = f.motor(slot).unwrap();
            if r < 0.05 {
                w.tau = (spec.motors[slot].tau_max.unwrap() * (1.0 + rnd() * 1.5)) as f32;
            } else if r < 0.08 {
                w.kp = (spec.motors[slot].kp_max.unwrap() * (1.0 + rnd() * 1.5)) as f32;
            } else if r < 0.10 {
                w.q += (rnd() * 0.5) as f32;
            }
            f.set_motor(slot, w);
            f.seal();
            let pkt = lowcmd_pkt(fx, PREFIX, sn, &f);
            let (_, out) = run(&mut gw, &pkt, now);
            let rv = reference.check_joint(
                &JointCommand::new(src, ch, now, f.joint_frame().unwrap()),
                now,
            );
            let got = out_lowcmd(&out, codec(fx));
            match (&rv, got) {
                (JointVerdict::Passed { .. }, Some(g)) => assert_eq!(g, f),
                (
                    JointVerdict::Rejected {
                        substitute: None, ..
                    },
                    None,
                ) => sup += 1,
                (v, Some(g)) => {
                    let want = v.output().unwrap().frame;
                    if v.substitute_kind() == Some(SubstituteKind::HoldLast) {
                        sub += 1;
                    } else {
                        lim += 1;
                    }
                    for (i, w) in want.motors().iter().enumerate() {
                        let m = g.motor(i).unwrap();
                        for (a, b) in [
                            (m.q, w.q),
                            (m.dq, w.dq),
                            (m.tau, w.tau),
                            (m.kp, w.kp),
                            (m.kd, w.kd),
                        ] {
                            assert!(
                                (f64::from(a) - b).abs() <= b.abs() * f64::from(f32::EPSILON),
                                "{fx:?} sn {sn} slot {i}: {a} vs {b}"
                            );
                        }
                    }
                }
                (v, g) => panic!("{fx:?} sn {sn}: reference {v:?} vs gateway {g:?}"),
            }
        }
        assert!(
            sub > 10 && lim > 10,
            "{fx:?}: sub {sub} lim {lim} sup {sup}"
        );
    }
}

#[test]
fn shipped_gateway_examples_build() {
    for (name, fx) in [
        ("firewall-gw.unitree-g1.example.json", Fixture::G1),
        ("firewall-gw.unitree-go2.example.json", Fixture::Go2),
    ] {
        let text = std::fs::read_to_string(config_dir().join(name)).unwrap();
        let cfg = robodr_firewall_gw::GatewayConfig::from_json(&text)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            cfg.queue.on_gateway_down,
            OnGatewayDown::FailClosed,
            "{name}: documented default"
        );
        // The G1 example runs against the shipped G1 firewall example; the
        // Go2 example's sport channel needs a twist channel in firewall.json
        // (the fixture adds one, as the README says).
        let fw = if fx == Fixture::G1 {
            example_firewall("firewall.unitree-g1.example.json")
        } else {
            firewall(fx)
        };
        let gw = Gateway::new(&cfg, &profile(fx), &fw).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(gw.mode(), GatewayMode::Enforce);
        let script = robodr_firewall_gw::ruleset::render(&cfg, name);
        assert!(script.contains("--queue-num 0\n") && !script.contains("bypass\n"));
    }
}

#[test]
fn foreign_flood_does_not_evict_the_authorised_writers_state() {
    let fx = Fixture::G1;
    let mut gw = gateway(fx);
    let good = frame(fx, 0.0);
    let p1 = lowcmd_pkt(fx, PREFIX, 1, &good);
    assert_eq!(run(&mut gw, &p1, T0).0, Verdict::Accept);
    // 100 spoofed writers (more than max_writers_per_channel = 16).
    let mut now = T0;
    for k in 0..100u8 {
        now += 2 * MS;
        let mut prefix = FOREIGN;
        prefix[11] = k;
        let p = packet(
            ATTACKER_IP,
            DDS_PORT,
            &lowcmd_datagram(prefix, WRITER, 1, &good, Representation::CdrLe),
        );
        run(&mut gw, &p, now);
    }
    // A replay of the authorised writer's SN 1 is still recognised as a
    // replay (re-emitted from the cache, not decided again).
    let checked = gw.firewall().stats().checked;
    let (v, out) = run(&mut gw, &p1, now + 2 * MS);
    assert_eq!(v, Verdict::Accept);
    assert_eq!(out, p1);
    assert_eq!(gw.firewall().stats().checked, checked);
    assert_eq!(gw.stats.replays_reemitted, 1);
}
