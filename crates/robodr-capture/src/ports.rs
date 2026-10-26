//! Which UDP datagrams are RTPS: well-known port map plus a magic check.
//!
//! DDSI-RTPS 2.2 §9.6.1.1 derives a participant's default ports from the
//! domain id `d` and participant id `p`:
//!
//! | Traffic | Port |
//! |---|---|
//! | SPDP (metatraffic) multicast | `PB + DG*d + d0` |
//! | Metatraffic unicast (SPDP/SEDP) | `PB + DG*d + d1 + PG*p` |
//! | User multicast | `PB + DG*d + d2` |
//! | User unicast | `PB + DG*d + d3 + PG*p` |
//!
//! with `PB=7400, DG=250, PG=2, d0=0, d1=10, d2=1, d3=11`. SEDP — the
//! traffic that tells us *which topics* a participant writes — goes to the
//! metatraffic unicast ports, which is why the sensor needs packet capture
//! rather than an SPDP multicast socket.
//!
//! ## Ports vs. magic: the trade-off
//!
//! [`RtpsPortMap`] is exact for default configurations but blind to any
//! deployment that overrides the port parameters (Fast DDS XML profiles,
//! Cyclone `<Ports>`, Connext transport settings) — and a rogue participant
//! is free to pick any port. The RTPS magic (`"RTPS"` in the first four bytes
//! of every RTPS message) catches all of those for the cost of a 4-byte
//! compare, but it also matches any non-RTPS UDP payload that happens to start
//! with those bytes (harmless: the parser then rejects it) and costs a
//! user-space copy of every UDP datagram when used without a kernel filter.
//!
//! The default, [`MatchMode::PortsOrMagic`], accepts either; the kernel BPF
//! filter built by [`crate::bpf`] implements the same rule so the extra cost
//! stays in the kernel. [`RtpsPortMap::classify`] still tells the caller
//! whether a datagram used a well-known port, so "RTPS on a non-standard
//! port" can be reported as its own signal. Note that RTPS over TCP
//! (Fast DDS TCP transport, Connext TCP) and shared memory are out of scope
//! for this crate entirely.

use std::collections::BTreeSet;

use crate::decode::UdpDatagram;

/// Port base.
pub const PB: u32 = 7400;
/// Domain id gain.
pub const DG: u32 = 250;
/// Participant id gain.
pub const PG: u32 = 2;
/// Offset: metatraffic (SPDP) multicast.
pub const D0: u32 = 0;
/// Offset: metatraffic unicast.
pub const D1: u32 = 10;
/// Offset: user multicast.
pub const D2: u32 = 1;
/// Offset: user unicast.
pub const D3: u32 = 11;

/// Highest participant id whose ports stay inside the domain's 250-port block:
/// `(DG - D3 - 1) / PG` = 119.
pub const MAX_PARTICIPANT_ID: u16 = ((DG - D3 - 1) / PG) as u16;

/// Highest domain id whose SPDP multicast port fits in 16 bits (232).
pub const MAX_DOMAIN_ID: u16 = ((65_535 - PB - D0) / DG) as u16;

/// The RTPS magic at the start of every RTPS message.
pub const RTPS_MAGIC: [u8; 4] = *b"RTPS";

/// Kind of well-known RTPS port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PortKind {
    MetatrafficMulticast,
    MetatrafficUnicast,
    UserMulticast,
    UserUnicast,
}

impl PortKind {
    /// Discovery (SPDP/SEDP) traffic, as opposed to user data.
    pub fn is_metatraffic(self) -> bool {
        matches!(self, Self::MetatrafficMulticast | Self::MetatrafficUnicast)
    }
}

/// What a well-known port means.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PortClass {
    pub domain: u16,
    /// `None` for the multicast ports, which are shared by all participants.
    pub participant: Option<u16>,
    pub kind: PortKind,
}

/// The well-known port for `kind` in `domain` (participant id ignored for
/// multicast kinds). `None` if it does not fit in 16 bits.
pub fn well_known_port(kind: PortKind, domain: u16, participant: u16) -> Option<u16> {
    let base = PB + DG * u32::from(domain);
    let p = u32::from(participant);
    let port = match kind {
        PortKind::MetatrafficMulticast => base + D0,
        PortKind::MetatrafficUnicast => base + D1 + PG * p,
        PortKind::UserMulticast => base + D2,
        PortKind::UserUnicast => base + D3 + PG * p,
    };
    u16::try_from(port).ok()
}

/// Whether a UDP payload starts with the RTPS magic.
pub fn has_rtps_magic(payload: &[u8]) -> bool {
    payload.len() >= 4 && payload[..4] == RTPS_MAGIC
}

/// The set of well-known RTPS ports for some domains and participant ids
/// `0..=max_participant`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RtpsPortMap {
    domains: BTreeSet<u16>,
    max_participant: u16,
}

impl Default for RtpsPortMap {
    /// [`RtpsPortMap::ros2_default`].
    fn default() -> Self {
        Self::ros2_default()
    }
}

impl RtpsPortMap {
    /// Domains above [`MAX_DOMAIN_ID`] are ignored; `max_participant` is
    /// clamped to [`MAX_PARTICIPANT_ID`] (beyond it, ports would spill into
    /// the next domain's block and become ambiguous).
    pub fn new(domains: impl IntoIterator<Item = u16>, max_participant: u16) -> Self {
        Self {
            domains: domains
                .into_iter()
                .filter(|&d| d <= MAX_DOMAIN_ID)
                .collect(),
            max_participant: max_participant.min(MAX_PARTICIPANT_ID),
        }
    }

    /// ROS 2 default: domain 0 (`ROS_DOMAIN_ID` unset), participant ids up to
    /// 119 (the ROS 2 documentation's per-host participant ceiling of 120).
    pub fn ros2_default() -> Self {
        Self::new([0], MAX_PARTICIPANT_ID)
    }

    /// All valid domains (0..=232), all participant ids. Useful for an
    /// all-seeing commissioning capture.
    pub fn all_domains() -> Self {
        Self::new(0..=MAX_DOMAIN_ID, MAX_PARTICIPANT_ID)
    }

    pub fn domains(&self) -> impl Iterator<Item = u16> + '_ {
        self.domains.iter().copied()
    }

    pub fn max_participant(&self) -> u16 {
        self.max_participant
    }

    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    /// Exact classification of a port against the map.
    pub fn classify(&self, port: u16) -> Option<PortClass> {
        let rel = u32::from(port).checked_sub(PB)?;
        let domain = u16::try_from(rel / DG).ok()?;
        if !self.domains.contains(&domain) {
            return None;
        }
        let off = rel % DG;
        let (kind, participant) = match off {
            D0 => (PortKind::MetatrafficMulticast, None),
            D2 => (PortKind::UserMulticast, None),
            o if o >= D1 => {
                let unicast = o - D1;
                let p = u16::try_from(unicast / PG).ok()?;
                if p > self.max_participant {
                    return None;
                }
                let kind = if unicast.is_multiple_of(PG) {
                    PortKind::MetatrafficUnicast
                } else {
                    PortKind::UserUnicast
                };
                (kind, Some(p))
            }
            _ => return None,
        };
        Some(PortClass {
            domain,
            participant,
            kind,
        })
    }

    pub fn contains(&self, port: u16) -> bool {
        self.classify(port).is_some()
    }

    /// Inclusive port ranges covering every port in the map, merged and
    /// sorted. Per domain: `[base+d0, base+d2]` and
    /// `[base+d1, base+d3+PG*max_participant]` — exact, since the unicast
    /// ports interleave (metatraffic even, user odd) with no gaps. Used to
    /// build the kernel BPF filter.
    pub fn port_ranges(&self) -> Vec<(u16, u16)> {
        let mut ranges: Vec<(u32, u32)> = Vec::new();
        for &d in &self.domains {
            let base = PB + DG * u32::from(d);
            let hi = base + D3 + PG * u32::from(self.max_participant);
            ranges.push((base + D0, base + D2));
            ranges.push((base + D1, hi));
        }
        ranges.sort_unstable();
        let mut merged: Vec<(u16, u16)> = Vec::new();
        for (lo, hi) in ranges {
            let (Ok(lo), hi) = (u16::try_from(lo), u16::try_from(hi).unwrap_or(u16::MAX)) else {
                continue;
            };
            match merged.last_mut() {
                Some(last) if u32::from(lo) <= u32::from(last.1) + 1 => {
                    last.1 = last.1.max(hi);
                }
                _ => merged.push((lo, hi)),
            }
        }
        merged
    }
}

/// How [`RtpsFilter`] decides a datagram is RTPS.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum MatchMode {
    /// Destination port is in the [`RtpsPortMap`].
    PortsOnly,
    /// Payload starts with `"RTPS"`, any port.
    MagicOnly,
    /// Either (default). See the module docs for the trade-off.
    #[default]
    PortsOrMagic,
}

/// The user-space RTPS datagram filter (also the fallback when the kernel
/// BPF filter cannot be attached).
///
/// Besides RTPS it can accept the raw UDP of Unitree's legacy
/// (`unitree_legged_sdk`, Go1 generation) protocol: UDP whose source **or**
/// destination port is in [`RtpsFilter::legacy_udp_ports`] is delivered
/// tagged [`crate::PacketKind::UnitreeLegacy`] — **always**, also when it
/// matches the RTPS rule as well (then flagged
/// [`crate::RtpsPacket::also_rtps`], so the consumer inspects it on both
/// paths): starting a payload with `RTPS` must not skip the legacy sender
/// check. Empty (the default) = off.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RtpsFilter {
    pub ports: RtpsPortMap,
    pub mode: MatchMode,
    /// UDP ports of the Unitree legacy protocol (both directions); empty =
    /// none accepted.
    pub legacy_udp_ports: BTreeSet<u16>,
}

/// Most ports [`RtpsFilter::legacy_udp_ports`] may hold (each costs six
/// kernel BPF instructions).
pub const MAX_LEGACY_UDP_PORTS: usize = 32;

impl RtpsFilter {
    pub fn new(ports: RtpsPortMap, mode: MatchMode) -> Self {
        Self {
            ports,
            mode,
            legacy_udp_ports: BTreeSet::new(),
        }
    }

    /// Also accept Unitree legacy UDP on `ports` (source or destination).
    /// At most [`MAX_LEGACY_UDP_PORTS`] are kept (the lowest).
    #[must_use]
    pub fn with_legacy_udp_ports(mut self, ports: impl IntoIterator<Item = u16>) -> Self {
        self.legacy_udp_ports = ports
            .into_iter()
            .collect::<BTreeSet<u16>>()
            .into_iter()
            .take(MAX_LEGACY_UDP_PORTS)
            .collect();
        self
    }

    /// A UDP datagram of the Unitree legacy protocol: its source or
    /// destination port is a configured legacy port (whether or not it also
    /// [`matches`](Self::matches) as RTPS).
    pub fn is_legacy(&self, d: &UdpDatagram<'_>) -> bool {
        !self.legacy_udp_ports.is_empty()
            && (self.legacy_udp_ports.contains(&d.src_port)
                || self.legacy_udp_ports.contains(&d.dst_port))
    }

    pub fn matches(&self, d: &UdpDatagram<'_>) -> bool {
        let port = || self.ports.contains(d.dst_port);
        let magic = || has_rtps_magic(d.payload);
        match self.mode {
            MatchMode::PortsOnly => port(),
            MatchMode::MagicOnly => magic(),
            MatchMode::PortsOrMagic => port() || magic(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn spec_formulas_domain_0_and_1() {
        // The canonical numbers every DDS user knows.
        assert_eq!(
            well_known_port(PortKind::MetatrafficMulticast, 0, 0),
            Some(7400)
        );
        assert_eq!(well_known_port(PortKind::UserMulticast, 0, 0), Some(7401));
        assert_eq!(
            well_known_port(PortKind::MetatrafficUnicast, 0, 0),
            Some(7410)
        );
        assert_eq!(well_known_port(PortKind::UserUnicast, 0, 0), Some(7411));
        assert_eq!(
            well_known_port(PortKind::MetatrafficUnicast, 0, 1),
            Some(7412)
        );
        assert_eq!(well_known_port(PortKind::UserUnicast, 0, 1), Some(7413));
        assert_eq!(
            well_known_port(PortKind::MetatrafficMulticast, 1, 0),
            Some(7650)
        );
        assert_eq!(
            well_known_port(PortKind::MetatrafficUnicast, 1, 0),
            Some(7660)
        );
        assert_eq!(well_known_port(PortKind::UserUnicast, 1, 2), Some(7665));
        // Domain 232 is the last that fits; 233 overflows.
        assert_eq!(
            well_known_port(PortKind::MetatrafficMulticast, 232, 0),
            Some(65400)
        );
        assert_eq!(
            well_known_port(PortKind::MetatrafficMulticast, 233, 0),
            None
        );
        assert_eq!(well_known_port(PortKind::UserUnicast, 232, 119), None);
        assert_eq!(MAX_DOMAIN_ID, 232);
        assert_eq!(MAX_PARTICIPANT_ID, 119);
    }

    #[test]
    fn classify_roundtrips_with_formulas() {
        let map = RtpsPortMap::new([0, 1, 42, 232], MAX_PARTICIPANT_ID);
        for d in [0u16, 1, 42, 232] {
            for p in 0..=MAX_PARTICIPANT_ID {
                for kind in [
                    PortKind::MetatrafficMulticast,
                    PortKind::MetatrafficUnicast,
                    PortKind::UserMulticast,
                    PortKind::UserUnicast,
                ] {
                    let Some(port) = well_known_port(kind, d, p) else {
                        continue;
                    };
                    let c = map.classify(port).expect("in map");
                    assert_eq!(c.domain, d);
                    assert_eq!(c.kind, kind);
                    let multicast = matches!(
                        kind,
                        PortKind::MetatrafficMulticast | PortKind::UserMulticast
                    );
                    assert_eq!(c.participant, if multicast { None } else { Some(p) });
                }
            }
        }
    }

    #[test]
    fn classify_rejects_outside() {
        let map = RtpsPortMap::new([0], 3);
        assert!(map.classify(7399).is_none());
        assert!(map.classify(7402).is_none()); // gap between d2 and d1
        assert!(map.classify(7409).is_none());
        assert!(map.classify(7417).is_some()); // participant 3 user unicast
        assert!(map.classify(7418).is_none()); // participant 4 > max
        assert!(map.classify(7650).is_none()); // domain 1 not in map
        assert!(map.classify(0).is_none());
        assert!(map.classify(u16::MAX).is_none());
        assert!(PortKind::MetatrafficUnicast.is_metatraffic());
        assert!(!PortKind::UserUnicast.is_metatraffic());
    }

    #[test]
    fn constructor_clamps() {
        let map = RtpsPortMap::new([0, 233, 999], 500);
        assert_eq!(map.domains().collect::<Vec<_>>(), vec![0]);
        assert_eq!(map.max_participant(), MAX_PARTICIPANT_ID);
        assert!(RtpsPortMap::new([], 0).is_empty());
        assert_eq!(RtpsPortMap::all_domains().domains().count(), 233);
    }

    #[test]
    fn port_ranges_are_exact_and_merged() {
        let map = RtpsPortMap::new([0], 2);
        assert_eq!(map.port_ranges(), vec![(7400, 7401), (7410, 7415)]);
        // Domain 0's unicast block touches domain 1's multicast ports and merges;
        // the gap 7652..=7659 (domain 1, offsets 2..=9) stays out.
        let map = RtpsPortMap::new([0, 1], MAX_PARTICIPANT_ID);
        assert_eq!(
            map.port_ranges(),
            vec![(7400, 7401), (7410, 7651), (7660, 7899)]
        );
        // Exhaustive check: a port is in a range iff classify() accepts it.
        for map in [
            RtpsPortMap::new([0, 5, 232], 7),
            RtpsPortMap::all_domains(),
            RtpsPortMap::new([3], 0),
        ] {
            let ranges = map.port_ranges();
            for port in 0..=u16::MAX {
                let in_range = ranges.iter().any(|&(lo, hi)| (lo..=hi).contains(&port));
                assert_eq!(in_range, map.contains(port), "port {port}");
            }
        }
    }

    #[test]
    fn filter_modes() {
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let dg = |port, payload| UdpDatagram {
            src: lo,
            dst: lo,
            src_port: 1,
            dst_port: port,
            payload,
        };
        let on_port_no_magic = dg(7410, b"hello");
        let off_port_magic = dg(5555, b"RTPS\x02\x03");
        let neither = dg(5555, b"RTP");
        let f = |mode| RtpsFilter::new(RtpsPortMap::ros2_default(), mode);
        assert!(f(MatchMode::PortsOnly).matches(&on_port_no_magic));
        assert!(!f(MatchMode::PortsOnly).matches(&off_port_magic));
        assert!(!f(MatchMode::MagicOnly).matches(&on_port_no_magic));
        assert!(f(MatchMode::MagicOnly).matches(&off_port_magic));
        assert!(f(MatchMode::PortsOrMagic).matches(&on_port_no_magic));
        assert!(f(MatchMode::PortsOrMagic).matches(&off_port_magic));
        assert!(!f(MatchMode::PortsOrMagic).matches(&neither));
        assert_eq!(RtpsFilter::default().mode, MatchMode::PortsOrMagic);
    }
}
