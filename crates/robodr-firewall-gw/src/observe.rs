//! Robot-side observation (review findings F1, F7): a **copy** of the UDP
//! traffic entering the bridge from the robot port (NFLOG,
//! `crate::nflog`), never queued, never verdicted, never dropped: the
//! robot's packets reach the controller whatever the gateway does with
//! the copy, and a stopped gateway changes nothing on that path.
//!
//! Two uses:
//!
//! - **`rt/lowstate`** (the robot's measured joint positions): the arm-SDK
//!   engagement check (`crate::armsdk::weight_gate`) compares the targets
//!   of a frame that hands the arms to the SDK with where the arms are. A
//!   sample is taken from a robot writer the robot's SEDP announced on the
//!   channel's `lowstate_topic`, or, when that announcement was not seen
//!   (a gateway restart), from any robot writer whose payload decodes as
//!   the channel's `LowState_` with a valid Unitree CRC. Fragmented
//!   samples (`hg` `LowState_` is 2 KB) are reassembled (bounded, per
//!   writer). Only robot-side traffic is used: a controller-side sender
//!   cannot feed the gateway a joint state.
//! - **The robot's discovery** (`crate::discovery::Discovery::observe_robot`):
//!   the unqueued-locator check on the robot's own SPDP / SEDP.
//!
//! The copy is parsed leniently at the IP layer (no checksum check: NFLOG
//! copies of locally offloaded packets may carry a partial checksum), and
//! only IPv4 / UDP, non-fragments, are read.

use std::collections::HashMap;

use robodr_cdr::unitree::{decode_unitree, UnitreeKind, UnitreeMessage};
use robodr_cdr::Limits;
use robodr_firewall::MAX_MOTORS;
use robodr_rtps::{EndpointKind, UserDataLimits, UserDataWalker};

use crate::armsdk::JointState;
use crate::config::{Codec, GatewayConfig};
use crate::lowcmd::LowCmdCodec;
use crate::rtps::Guid;

/// Most robot writers remembered (oldest forgotten first).
const MAX_ROBOT_WRITERS: usize = 1024;

/// The UDP payload of an IPv4 packet, read without checksum checks
/// (`None`: not IPv4 / UDP, a fragment, truncated).
pub fn udp_payload(pkt: &[u8]) -> Option<&[u8]> {
    let v_ihl = *pkt.first()?;
    if v_ihl >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(v_ihl & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([*pkt.get(2)?, *pkt.get(3)?]));
    let frag = u16::from_be_bytes([*pkt.get(6)?, *pkt.get(7)?]);
    if ihl < 20 || *pkt.get(9)? != 17 || frag & 0x3fff != 0 || total > pkt.len() || total < ihl + 8
    {
        return None;
    }
    let udp = pkt.get(ihl..total)?;
    let ulen = usize::from(u16::from_be_bytes([*udp.get(4)?, *udp.get(5)?]));
    if ulen < 8 || ulen > udp.len() {
        return None;
    }
    udp.get(8..ulen)
}

/// Counters of the observer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct ObserverStats {
    pub lowstate_samples: u64,
    /// Samples of a lowstate writer that did not decode with a valid CRC.
    pub lowstate_bad: u64,
}

/// The robot-side observer.
pub struct Observer {
    walker: UserDataWalker,
    /// The lowstate topics of the arm-SDK channels and their codec.
    topics: Vec<(String, LowCmdCodec)>,
    /// Robot writers learned from the robot's SEDP: `Some(codec)` = a
    /// lowstate writer, `None` = another topic (not probed).
    writers: HashMap<Guid, Option<LowCmdCodec>>,
    hg: Option<JointState>,
    go: Option<JointState>,
    pub stats: ObserverStats,
}

impl std::fmt::Debug for Observer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Observer")
            .field("topics", &self.topics)
            .field("writers", &self.writers.len())
            .field("stats", &self.stats)
            .finish()
    }
}

impl Observer {
    pub fn new(cfg: &GatewayConfig) -> Self {
        let topics = cfg
            .channels
            .iter()
            .filter_map(|c| {
                let codec = match c.codec {
                    Codec::UnitreeHgArmSdk => LowCmdCodec::Hg,
                    Codec::UnitreeGoArmSdk => LowCmdCodec::Go,
                    _ => return None,
                };
                Some((c.lowstate_topic().to_string(), codec))
            })
            .collect();
        Self {
            walker: UserDataWalker::new(UserDataLimits::default()),
            topics,
            writers: HashMap::new(),
            hg: None,
            go: None,
            stats: ObserverStats::default(),
        }
    }

    /// Whether any channel uses `rt/lowstate`.
    pub fn wants_lowstate(&self) -> bool {
        !self.topics.is_empty()
    }

    /// The last joint state of the robot for a `LowCmd_` codec.
    pub fn joint_state(&self, codec: LowCmdCodec) -> Option<&JointState> {
        match codec {
            LowCmdCodec::Hg => self.hg.as_ref(),
            LowCmdCodec::Go => self.go.as_ref(),
        }
    }

    /// Learn the robot's writers from its discovery.
    pub fn learn(&mut self, report: &robodr_rtps::DatagramReport) {
        for e in &report.endpoints {
            if e.kind != EndpointKind::Writer {
                continue;
            }
            let Some(g) = e.guid else { continue };
            let codec = e
                .topics
                .iter()
                .find_map(|t| self.topics.iter().find(|(lt, _)| lt == t).map(|(_, c)| *c));
            if self.writers.len() >= MAX_ROBOT_WRITERS && !self.writers.contains_key(&g) {
                if let Some(k) = self.writers.keys().next().copied() {
                    self.writers.remove(&k);
                }
            }
            self.writers.insert(g, codec);
        }
        for r in &report.removed_endpoints {
            if let Some(g) = r.guid {
                self.writers.remove(&g);
            }
        }
    }

    /// Take the `rt/lowstate` samples of one robot-side RTPS datagram
    /// (returns how many were taken).
    pub fn lowstate(&mut self, datagram: &[u8], now_ns: u64) -> u64 {
        if self.topics.is_empty() {
            return 0;
        }
        let writers = &self.writers;
        let Some(report) = self.walker.walk_with(datagram, |a| {
            // Known lowstate writers, and writers the robot's SEDP did not
            // describe (probed by content); never other known topics.
            !matches!(writers.get(&a.writer), Some(None))
        }) else {
            return 0;
        };
        let mut taken = 0;
        for s in &report.samples {
            if s.non_standard_payload || s.payload.is_empty() {
                continue;
            }
            let known = self.writers.get(&s.address.writer).copied().flatten();
            let candidates: &[LowCmdCodec] = match known {
                Some(LowCmdCodec::Hg) => &[LowCmdCodec::Hg],
                Some(LowCmdCodec::Go) => &[LowCmdCodec::Go],
                None => &[LowCmdCodec::Hg, LowCmdCodec::Go],
            };
            let mut ok = false;
            for c in candidates {
                if !self.topics.iter().any(|(_, tc)| tc == c) {
                    continue;
                }
                if let Some(js) = decode_lowstate(&s.payload, *c, now_ns) {
                    match c {
                        LowCmdCodec::Hg => self.hg = Some(js),
                        LowCmdCodec::Go => self.go = Some(js),
                    }
                    ok = true;
                    break;
                }
            }
            if ok {
                taken += 1;
                self.stats.lowstate_samples += 1;
            } else if known.is_some() {
                self.stats.lowstate_bad += 1;
            }
        }
        taken
    }
}

/// A `LowState_` payload of `codec` with a valid CRC, as a joint state.
pub fn decode_lowstate(payload: &[u8], codec: LowCmdCodec, now_ns: u64) -> Option<JointState> {
    let kind = match codec {
        LowCmdCodec::Hg => UnitreeKind::HgLowState,
        LowCmdCodec::Go => UnitreeKind::GoLowState,
    };
    let d = decode_unitree(kind, payload, &Limits::default()).ok()?;
    if d.message.crc_ok() != Some(true) {
        return None;
    }
    let mut q = [f32::NAN; MAX_MOTORS];
    let slots = match d.message {
        UnitreeMessage::HgLowState(m) => {
            for (dst, m) in q.iter_mut().zip(m.motor_state.iter()) {
                *dst = m.q;
            }
            m.motor_state.len()
        }
        UnitreeMessage::GoLowState(m) => {
            for (dst, m) in q.iter_mut().zip(m.motor_state.iter()) {
                *dst = m.q;
            }
            m.motor_state.len()
        }
        _ => return None,
    };
    Some(JointState {
        q,
        slots: slots.min(MAX_MOTORS),
        at_ns: now_ns,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_payload_is_lenient_on_checksums_only() {
        let p = crate::ip::build_ipv4_udp(
            std::net::Ipv4Addr::new(10, 0, 0, 1),
            std::net::Ipv4Addr::new(10, 0, 0, 2),
            1,
            2,
            b"abc",
        );
        assert_eq!(udp_payload(&p), Some(&b"abc"[..]));
        let mut bad = p.clone();
        let n = bad.len();
        bad[n - 1] ^= 0xff; // payload (and so the checksum) changed
        assert!(udp_payload(&bad).is_some());
        let mut frag = p.clone();
        frag[6] = 0x20; // more fragments
        assert!(udp_payload(&frag).is_none());
        for cut in 0..p.len() {
            let _ = udp_payload(&p[..cut]);
        }
    }
}
