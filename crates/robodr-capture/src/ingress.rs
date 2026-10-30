//! Which interface a packet arrived on: per-packet ingress metadata.
//!
//! A loopback source address (`127.0.0.0/8`, `::1`) means "this host" only
//! when the packet really travelled over a loopback interface; on any other
//! interface it can only be forged. The consumer (the ROS 2 binding table)
//! therefore needs to know the ingress interface **per packet**, not per
//! capture: a capture bound to every interface, a `tcpdump -i any` file or a
//! multi-interface pcapng mixes both kinds.
//!
//! # Where the information comes from
//!
//! | Source | `ifindex` | `name` | `loopback` | `pkttype` |
//! |---|---|---|---|---|
//! | live [`crate::afpacket`] | `sockaddr_ll.sll_ifindex` | `if_indextoname`, cached | `sll_hatype == ARPHRD_LOOPBACK` (kernel, per packet) | `sll_pkttype` |
//! | pcapng (`EPB`/`PB`) | — | IDB `if_name` | from the name, see [`loopback_by_name`] | `epb_flags` direction / reception type |
//! | pcapng `SPB` | — | IDB 0 `if_name` | as above | — |
//! | classic pcap | — | only if configured ([`crate::PcapReader::with_interface`]) | from the configured name | — |
//! | Linux cooked SLL (113) frames | — | (source's, unless it is `any`) | `sll_hatype == ARPHRD_LOOPBACK` | `sll_pkttype` |
//! | Linux cooked SLL2 (276) frames | `sll2_if_index` | (source's, unless it is `any`) | `sll2_hatype == ARPHRD_LOOPBACK` | `sll2_pkttype` |
//!
//! Link-layer facts (SLL/SLL2 headers, written by the capturing kernel per
//! packet) take precedence over what the file says about the interface as a
//! whole. A capture-file interface named `any` is libpcap's pseudo-device and
//! says nothing about the real interface, so its name is dropped and its
//! loopback flag is left unknown unless the frame header provides it.
//!
//! # Honest limits
//!
//! - Interface **names** in capture files describe the *capturing* host; the
//!   loopback flag derived from a name ([`loopback_by_name`]) is a heuristic
//!   (`lo`, `lo0`, `lo1`, names containing `loopback`, e.g. Npcap's
//!   `\Device\NPF_Loopback`). A capture whose loopback interface was renamed
//!   would be misjudged; SLL/SLL2 frames do not depend on names.
//! - An ifindex from a capture file is the capturing host's, and is not
//!   resolved to a name (there is no mapping in the file).
//! - Live names are resolved once per ifindex and cached ([`MAX_CACHED_INTERFACES`]);
//!   a later rename is not noticed. The live **loopback flag does not
//!   depend on the name**: it comes from the hardware type the kernel
//!   reports with each packet.
//! - A Linux `lo` capture with link type `ETHERNET` (what `tcpdump -i lo`
//!   writes) carries no per-frame interface facts; only the file's interface
//!   name (pcapng) or the configured name (classic pcap) tells.

use crate::decode::LinkType;

/// Linux `ARPHRD_LOOPBACK`.
pub const ARPHRD_LOOPBACK: u16 = 772;

/// Upper bound on the live ifindex -> name cache. When it is full the cache
/// is cleared and refilled (names are a convenience; the loopback decision
/// does not use them).
pub const MAX_CACHED_INTERFACES: usize = 1024;

/// Longest interface name kept from a capture file (bytes; longer names are
/// cut at a character boundary). Linux names are at most 15 bytes.
pub const MAX_INTERFACE_NAME: usize = 64;

/// Packet direction / addressing class, after Linux `PACKET_*` (`sll_pkttype`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PacketType {
    /// `PACKET_HOST` (0): addressed to this host.
    Host,
    /// `PACKET_BROADCAST` (1).
    Broadcast,
    /// `PACKET_MULTICAST` (2).
    Multicast,
    /// `PACKET_OTHERHOST` (3): addressed to another host (promiscuous).
    OtherHost,
    /// `PACKET_OUTGOING` (4): sent by this host.
    Outgoing,
    /// Received, addressing class unknown (pcapng `epb_flags` "inbound"
    /// without a reception type).
    Inbound,
    /// Any other `PACKET_*` value (loopback-internal, kernel, user, ...).
    Other(u16),
}

impl PacketType {
    /// From a Linux `PACKET_*` value.
    pub fn from_linux(v: u16) -> Self {
        match v {
            0 => Self::Host,
            1 => Self::Broadcast,
            2 => Self::Multicast,
            3 => Self::OtherHost,
            4 => Self::Outgoing,
            o => Self::Other(o),
        }
    }

    /// Sent by the capturing host.
    pub fn is_outgoing(self) -> bool {
        self == Self::Outgoing
    }

    /// From pcapng `epb_flags`: bits 0-1 direction (1 inbound, 2 outbound),
    /// bits 2-4 reception type (1 unicast, 2 multicast, 3 broadcast,
    /// 4 promiscuous). `None` when the direction is not recorded.
    pub fn from_epb_flags(flags: u32) -> Option<Self> {
        match flags & 0b11 {
            1 => Some(match (flags >> 2) & 0b111 {
                1 => Self::Host,
                2 => Self::Multicast,
                3 => Self::Broadcast,
                4 => Self::OtherHost,
                _ => Self::Inbound,
            }),
            2 => Some(Self::Outgoing),
            _ => None,
        }
    }
}

/// Ingress facts a [`crate::PacketSource`] attaches to one captured frame
/// (borrowing the interface name from the source). Every field is optional:
/// `None` means "this source does not know".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PacketIngress<'a> {
    /// Interface index on the capturing host.
    pub ifindex: Option<u32>,
    /// Interface name on the capturing host.
    pub name: Option<&'a str>,
    /// The interface is a loopback interface.
    pub loopback: Option<bool>,
    /// Direction / addressing class.
    pub pkttype: Option<PacketType>,
}

impl PacketIngress<'_> {
    /// Owned copy.
    pub fn to_info(&self) -> IngressInfo {
        IngressInfo {
            ifindex: self.ifindex,
            name: self.name.map(str::to_owned),
            loopback: self.loopback,
            pkttype: self.pkttype,
        }
    }
}

/// Owned per-datagram ingress, as reported in [`crate::RtpsPacket::ingress`]:
/// the source's [`PacketIngress`] refined by the frame's link-layer header
/// (Linux cooked capture) and, for reassembled datagrams, merged over every
/// fragment (see [`IngressInfo::merge_fragment`]).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct IngressInfo {
    pub ifindex: Option<u32>,
    pub name: Option<String>,
    /// `Some(true)`: arrived on a loopback interface; `Some(false)`: on a
    /// non-loopback interface; `None`: unknown.
    pub loopback: Option<bool>,
    pub pkttype: Option<PacketType>,
}

impl IngressInfo {
    /// Borrowed view, for a [`crate::PacketSource`] that stores it.
    pub fn as_packet_ingress(&self) -> PacketIngress<'_> {
        PacketIngress {
            ifindex: self.ifindex,
            name: self.name.as_deref(),
            loopback: self.loopback,
            pkttype: self.pkttype,
        }
    }

    /// Nothing is known.
    pub fn is_unknown(&self) -> bool {
        *self == Self::default()
    }

    /// Fold the ingress of another fragment of the same IP datagram into
    /// this one. Fields that disagree become unknown, except `loopback`,
    /// which is conservative: if **any** fragment arrived on a non-loopback
    /// interface the datagram did (`Some(false)`), so a loopback source
    /// cannot be laundered by completing a forged datagram with a fragment
    /// seen on `lo`. Two `Some(true)` stay `Some(true)`; otherwise unknown.
    pub fn merge_fragment(&mut self, other: &IngressInfo) {
        if self.ifindex != other.ifindex {
            self.ifindex = None;
        }
        if self.name != other.name {
            self.name = None;
        }
        if self.pkttype != other.pkttype {
            self.pkttype = None;
        }
        self.loopback = match (self.loopback, other.loopback) {
            (Some(false), _) | (_, Some(false)) => Some(false),
            (Some(true), Some(true)) => Some(true),
            _ => None,
        };
    }
}

/// Interface facts carried in a Linux cooked-capture header (SLL or SLL2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkIngress {
    /// SLL2 only.
    pub ifindex: Option<u32>,
    /// `ARPHRD_*` hardware type of the interface.
    pub hatype: u16,
    pub pkttype: PacketType,
}

impl LinkIngress {
    pub fn is_loopback(&self) -> bool {
        self.hatype == ARPHRD_LOOPBACK
    }
}

/// Parse the interface facts of a Linux cooked-capture frame. `None` for
/// other link types or a frame shorter than the cooked header.
///
/// SLL (113): `pkttype(2) hatype(2) halen(2) addr(8) protocol(2)`;
/// SLL2 (276): `protocol(2) reserved(2) ifindex(4) hatype(2) pkttype(1)
/// halen(1) addr(8)`; all big-endian (libpcap `sll.h`).
pub fn link_ingress(link: LinkType, frame: &[u8]) -> Option<LinkIngress> {
    let be16 = |at: usize| Some(u16::from_be_bytes(*frame.get(at..)?.first_chunk()?));
    match link {
        LinkType::LINUX_SLL if frame.len() >= 16 => Some(LinkIngress {
            ifindex: None,
            hatype: be16(2)?,
            pkttype: PacketType::from_linux(be16(0)?),
        }),
        LinkType::LINUX_SLL2 => {
            let (h, _) = frame.split_first_chunk::<20>()?;
            Some(LinkIngress {
                ifindex: Some(u32::from_be_bytes([h[4], h[5], h[6], h[7]])),
                hatype: be16(8)?,
                pkttype: PacketType::from_linux(u16::from(h[10])),
            })
        }
        _ => None,
    }
}

/// libpcap's "any" pseudo-interface (cooked capture on every interface).
pub fn is_any_pseudo_interface(name: &str) -> bool {
    name == "any"
}

/// Loopback flag guessed from a capture-file interface name (see the module
/// docs: a heuristic about the capturing host). `lo` / `lo<digits>` (Linux,
/// BSD, macOS) and names containing `loopback` (any case; Npcap
/// `\Device\NPF_Loopback`) are loopback; libpcap's `any` and the empty name
/// are unknown; every other name is a non-loopback interface.
pub fn loopback_by_name(name: &str) -> Option<bool> {
    if name.is_empty() || is_any_pseudo_interface(name) {
        return None;
    }
    let lo_n = name
        .strip_prefix("lo")
        .is_some_and(|rest| rest.bytes().all(|b| b.is_ascii_digit()));
    Some(lo_n || name.to_ascii_lowercase().contains("loopback"))
}

/// Cut a name to at most [`MAX_INTERFACE_NAME`] bytes at a char boundary.
pub(crate) fn bounded_name(raw: &[u8]) -> String {
    let raw = raw.split(|&b| b == 0).next().unwrap_or_default();
    let s = String::from_utf8_lossy(raw);
    let mut end = s.len().min(MAX_INTERFACE_NAME);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

/// Combine what the source knows with the frame's cooked header.
pub fn resolve(src: &PacketIngress<'_>, link: Option<LinkIngress>) -> IngressInfo {
    let mut info = src.to_info();
    if info.name.as_deref().is_some_and(is_any_pseudo_interface) {
        info.name = None;
        info.loopback = None;
    }
    if let Some(l) = link {
        if l.ifindex.is_some() {
            if info.ifindex.is_some() && info.ifindex != l.ifindex {
                // The frame says another interface than the source: the
                // source's name does not belong to it.
                info.name = None;
            }
            info.ifindex = l.ifindex;
        }
        info.loopback = Some(l.is_loopback());
        info.pkttype = Some(l.pkttype);
    }
    info
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synth;

    #[test]
    fn packet_types() {
        for (v, t) in [
            (0, PacketType::Host),
            (1, PacketType::Broadcast),
            (2, PacketType::Multicast),
            (3, PacketType::OtherHost),
            (4, PacketType::Outgoing),
            (7, PacketType::Other(7)),
        ] {
            assert_eq!(PacketType::from_linux(v), t);
        }
        assert!(PacketType::Outgoing.is_outgoing());
        assert!(!PacketType::Host.is_outgoing());
        assert_eq!(PacketType::from_epb_flags(0), None);
        assert_eq!(PacketType::from_epb_flags(3), None);
        assert_eq!(
            PacketType::from_epb_flags(2 | (1 << 2)),
            Some(PacketType::Outgoing)
        );
        assert_eq!(PacketType::from_epb_flags(1), Some(PacketType::Inbound));
        assert_eq!(
            PacketType::from_epb_flags(1 | (1 << 2)),
            Some(PacketType::Host)
        );
        assert_eq!(
            PacketType::from_epb_flags(1 | (2 << 2)),
            Some(PacketType::Multicast)
        );
        assert_eq!(
            PacketType::from_epb_flags(1 | (3 << 2)),
            Some(PacketType::Broadcast)
        );
        assert_eq!(
            PacketType::from_epb_flags(1 | (4 << 2)),
            Some(PacketType::OtherHost)
        );
        assert_eq!(
            PacketType::from_epb_flags(1 | (7 << 2) | 0xffff_0000),
            Some(PacketType::Inbound)
        );
    }

    #[test]
    fn names() {
        for n in ["lo", "lo0", "lo12", "\\Device\\NPF_Loopback", "LOOPBACK"] {
            assert_eq!(loopback_by_name(n), Some(true), "{n}");
        }
        for n in ["eth0", "wlan0", "local", "lo-ext", "docker0", "enp3s0"] {
            assert_eq!(loopback_by_name(n), Some(false), "{n}");
        }
        assert_eq!(loopback_by_name("any"), None);
        assert_eq!(loopback_by_name(""), None);
        assert_eq!(bounded_name(b"eth0\0\0\0"), "eth0");
        assert_eq!(bounded_name(&[b'x'; 300]).len(), MAX_INTERFACE_NAME);
        // Multi-byte char straddling the cut.
        let mut raw = vec![b'a'; MAX_INTERFACE_NAME - 1];
        raw.extend_from_slice("é".as_bytes());
        assert_eq!(bounded_name(&raw).len(), MAX_INTERFACE_NAME - 1);
        assert_eq!(bounded_name(&[0xff, 0xfe]), "\u{fffd}\u{fffd}");
    }

    #[test]
    fn cooked_headers() {
        let f1 = synth::linux_sll_on(4, ARPHRD_LOOPBACK, 0x0800, b"ip");
        let l1 = link_ingress(LinkType::LINUX_SLL, &f1).unwrap();
        assert_eq!(l1.ifindex, None);
        assert!(l1.is_loopback());
        assert_eq!(l1.pkttype, PacketType::Outgoing);
        let f2 = synth::linux_sll2_on(7, 1, 0, 0x0800, b"ip");
        let l2 = link_ingress(LinkType::LINUX_SLL2, &f2).unwrap();
        assert_eq!(l2.ifindex, Some(7));
        assert!(!l2.is_loopback());
        assert_eq!(l2.pkttype, PacketType::Host);
        assert_eq!(link_ingress(LinkType::LINUX_SLL, &f1[..15]), None);
        assert_eq!(link_ingress(LinkType::LINUX_SLL2, &f2[..19]), None);
        assert_eq!(link_ingress(LinkType::ETHERNET, &f2), None);
        assert_eq!(link_ingress(LinkType::LINUX_SLL2, &[]), None);
    }

    #[test]
    fn resolution_prefers_the_frame() {
        let any = PacketIngress {
            name: Some("any"),
            loopback: Some(false),
            ..Default::default()
        };
        assert!(resolve(&any, None).is_unknown());
        let l = LinkIngress {
            ifindex: Some(1),
            hatype: ARPHRD_LOOPBACK,
            pkttype: PacketType::Host,
        };
        let r = resolve(&any, Some(l));
        assert_eq!(
            r,
            IngressInfo {
                ifindex: Some(1),
                name: None,
                loopback: Some(true),
                pkttype: Some(PacketType::Host),
            }
        );
        // Named interface, SLL v1 (no ifindex): name kept, flag from frame.
        let eth = PacketIngress {
            name: Some("eth0"),
            loopback: Some(false),
            ..Default::default()
        };
        let r = resolve(
            &eth,
            Some(LinkIngress {
                ifindex: None,
                hatype: 1,
                pkttype: PacketType::Outgoing,
            }),
        );
        assert_eq!(r.name.as_deref(), Some("eth0"));
        assert_eq!(r.loopback, Some(false));
        // Conflicting ifindex drops the source's name.
        let src = PacketIngress {
            ifindex: Some(2),
            name: Some("eth0"),
            ..Default::default()
        };
        let r = resolve(&src, Some(l));
        assert_eq!((r.ifindex, r.name), (Some(1), None));
    }

    #[test]
    fn fragment_merge_is_conservative() {
        let lo = IngressInfo {
            ifindex: Some(1),
            name: Some("lo".into()),
            loopback: Some(true),
            pkttype: Some(PacketType::Host),
        };
        let eth = IngressInfo {
            ifindex: Some(2),
            name: Some("eth0".into()),
            loopback: Some(false),
            pkttype: Some(PacketType::Host),
        };
        let mut a = lo.clone();
        a.merge_fragment(&lo);
        assert_eq!(a, lo);
        a.merge_fragment(&eth);
        assert_eq!(
            a,
            IngressInfo {
                pkttype: Some(PacketType::Host),
                loopback: Some(false),
                ..Default::default()
            }
        );
        a.merge_fragment(&lo);
        assert_eq!(a.loopback, Some(false), "sticky");
        let mut b = lo.clone();
        b.merge_fragment(&IngressInfo::default());
        assert_eq!(b.loopback, None);
        assert!(b.ifindex.is_none() && b.name.is_none() && b.pkttype.is_none());
    }
}
