//! Validated network values: address prefixes, interface names, port
//! ranges and RTPS GUID prefixes. Everything that reaches an nftables rule
//! passes through one of these types first, so no free text is ever placed
//! in a rule (the rules are built as JSON values, never as shell or nft
//! script text).

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// An IPv4 or IPv6 prefix (`10.0.0.0/8`, `fd00::5/128`, or a bare address
/// meaning a host prefix). Host bits must be zero: `10.0.0.1/8` is refused
/// (it is almost always a typo, and nft would silently mask it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IpNet {
    pub addr: IpAddr,
    pub len: u8,
}

impl IpNet {
    pub fn max_len(addr: IpAddr) -> u8 {
        match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
    }

    pub fn host(addr: IpAddr) -> Self {
        Self {
            addr,
            len: Self::max_len(addr),
        }
    }

    pub fn is_host(&self) -> bool {
        self.len == Self::max_len(self.addr)
    }

    pub fn is_v4(&self) -> bool {
        self.addr.is_ipv4()
    }

    fn bits(addr: IpAddr) -> u128 {
        match addr {
            IpAddr::V4(a) => u128::from(u32::from(a)),
            IpAddr::V6(a) => u128::from(a),
        }
    }

    fn mask(&self) -> u128 {
        let width = u32::from(Self::max_len(self.addr));
        let len = u32::from(self.len);
        if len == 0 {
            return 0;
        }
        let ones: u128 = if len >= 128 {
            u128::MAX
        } else {
            (1u128 << len) - 1
        };
        ones << (width - len)
    }

    /// `ip` lies inside this prefix (same family only).
    pub fn contains(&self, ip: IpAddr) -> bool {
        if self.addr.is_ipv4() != ip.is_ipv4() {
            return false;
        }
        Self::bits(ip) & self.mask() == Self::bits(self.addr) & self.mask()
    }

    /// The two prefixes share at least one address.
    pub fn overlaps(&self, other: &IpNet) -> bool {
        if self.addr.is_ipv4() != other.addr.is_ipv4() {
            return false;
        }
        let shorter = if self.len <= other.len { self } else { other };
        let longer = if self.len <= other.len { other } else { self };
        shorter.contains(longer.addr)
    }
}

impl FromStr for IpNet {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let (a, l) = match s.split_once('/') {
            Some((a, l)) => (a, Some(l)),
            None => (s, None),
        };
        let addr: IpAddr = a
            .parse()
            .map_err(|_| format!("{:?} is not an IP address or prefix", clip(s)))?;
        let max = Self::max_len(addr);
        let len = match l {
            None => max,
            Some(l) => {
                if l.is_empty() || l.len() > 3 || !l.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(format!("{:?}: bad prefix length", clip(s)));
                }
                let n: u8 = l
                    .parse()
                    .map_err(|_| format!("{:?}: bad prefix length", clip(s)))?;
                if n > max {
                    return Err(format!("{:?}: prefix length above {max}", clip(s)));
                }
                n
            }
        };
        let net = IpNet { addr, len };
        let width_mask: u128 = if max == 128 {
            u128::MAX
        } else {
            (1u128 << max) - 1
        };
        if Self::bits(addr) & !net.mask() & width_mask != 0 {
            return Err(format!(
                "{:?}: host bits are set (write the network address)",
                clip(s)
            ));
        }
        Ok(net)
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_host() {
            write!(f, "{}", self.addr)
        } else {
            write!(f, "{}/{}", self.addr, self.len)
        }
    }
}

impl Serialize for IpNet {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for IpNet {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// A network interface name as the kernel accepts it: 1..=15 bytes of
/// `[A-Za-z0-9_.-]`, not `.` / `..`, no wildcard (`*` would match a family
/// of interfaces in nft).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct Iface(String);

impl Iface {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Iface {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let ok = !s.is_empty()
            && s.len() <= 15
            && s != "."
            && s != ".."
            && !s.starts_with('-')
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
        if ok {
            Ok(Iface(s.to_string()))
        } else {
            Err(format!(
                "{:?} is not an interface name (1-15 of [A-Za-z0-9_.-], no wildcard)",
                clip(s)
            ))
        }
    }
}

impl<'de> Deserialize<'de> for Iface {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Transport protocol of an allow-list entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

/// An inclusive port range `[lo, hi]`, `1 <= lo <= hi` (JSON: `[lo, hi]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PortRange {
    pub lo: u16,
    pub hi: u16,
}

impl PortRange {
    pub fn new(lo: u16, hi: u16) -> Result<Self, String> {
        if lo == 0 || lo > hi {
            return Err(format!("port range [{lo}, {hi}]: need 1 <= lo <= hi"));
        }
        Ok(Self { lo, hi })
    }

    pub fn single(p: u16) -> Result<Self, String> {
        Self::new(p, p)
    }

    pub fn contains(&self, p: u16) -> bool {
        (self.lo..=self.hi).contains(&p)
    }

    pub fn overlaps(&self, o: &PortRange) -> bool {
        self.lo <= o.hi && o.lo <= self.hi
    }
}

impl Serialize for PortRange {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        [self.lo, self.hi].serialize(s)
    }
}

impl<'de> Deserialize<'de> for PortRange {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = <[u16; 2]>::deserialize(d)?;
        PortRange::new(v[0], v[1]).map_err(serde::de::Error::custom)
    }
}

/// A 12-byte RTPS GUID prefix. Parsed from 24 lower-case hex digits, or 32
/// (a full GUID: the entity id is dropped, quarantine is per participant).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GuidPrefix(pub [u8; 12]);

impl GuidPrefix {
    /// The prefix as three big-endian 32-bit words (how nftables compares a
    /// 32-bit raw payload field).
    pub fn words(&self) -> [u32; 3] {
        let b = &self.0;
        [
            u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
            u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
        ]
    }

    pub fn to_hex(&self) -> String {
        robodr_blackbox::crypto::to_hex(&self.0)
    }
}

impl FromStr for GuidPrefix {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let ok = (s.len() == 24 || s.len() == 32)
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !ok {
            return Err(format!(
                "{:?} is not an RTPS GUID prefix (24 or 32 lower-case hex digits)",
                clip(s)
            ));
        }
        let bytes = robodr_blackbox::crypto::from_hex(&s[..24])
            .ok_or_else(|| "bad hex in GUID prefix".to_string())?;
        let mut out = [0u8; 12];
        out.copy_from_slice(&bytes);
        Ok(GuidPrefix(out))
    }
}

impl fmt::Display for GuidPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for GuidPrefix {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for GuidPrefix {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// At most 64 characters of untrusted text, for error messages.
pub fn clip(s: &str) -> String {
    s.chars().take(64).collect()
}

/// An identifier as the control plane accepts it: `[A-Za-z0-9._:-]{1,128}`.
pub fn id_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_parse_and_refuse_host_bits() {
        let n: IpNet = "10.1.0.0/16".parse().unwrap();
        assert!(n.contains("10.1.200.3".parse().unwrap()));
        assert!(!n.contains("10.2.0.1".parse().unwrap()));
        assert!(!n.contains("::1".parse().unwrap()));
        assert!("10.1.0.1/16".parse::<IpNet>().is_err());
        assert!("10.1.0.0/33".parse::<IpNet>().is_err());
        assert!("10.1.0.0/".parse::<IpNet>().is_err());
        assert!("10.1.0.0/+8".parse::<IpNet>().is_err());
        assert!("10.1.0.0 ".parse::<IpNet>().is_err());
        assert!("x".parse::<IpNet>().is_err());
        let h: IpNet = "192.168.123.161".parse().unwrap();
        assert!(h.is_host());
        assert_eq!(h.to_string(), "192.168.123.161");
        let z: IpNet = "0.0.0.0/0".parse().unwrap();
        assert!(z.contains("8.8.8.8".parse().unwrap()));
        let v6: IpNet = "fd00::/8".parse().unwrap();
        assert!(v6.contains("fd12::1".parse().unwrap()));
        assert!("fd00::1/8".parse::<IpNet>().is_err());
        let all6: IpNet = "::/0".parse().unwrap();
        assert!(all6.contains("2001:db8::1".parse().unwrap()));
        assert!(n.overlaps(&"10.0.0.0/8".parse().unwrap()));
        assert!(!n.overlaps(&"10.2.0.0/16".parse().unwrap()));
    }

    #[test]
    fn interface_names_are_strict() {
        assert!("eth0".parse::<Iface>().is_ok());
        assert!("enp3s0.100".parse::<Iface>().is_ok());
        for bad in [
            "",
            "eth*",
            "a b",
            "0123456789abcdef",
            "..",
            "-x",
            "eth0\n",
            "e\"x",
        ] {
            assert!(bad.parse::<Iface>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn guid_prefix_words_are_big_endian() {
        let g: GuidPrefix = "0110a2b3c4d5e6f701000000".parse().unwrap();
        assert_eq!(g.words(), [0x0110_a2b3, 0xc4d5_e6f7, 0x0100_0000]);
        let full: GuidPrefix = "0110a2b3c4d5e6f701000000000001c1".parse().unwrap();
        assert_eq!(full, g);
        assert!("0110A2B3C4D5E6F701000000".parse::<GuidPrefix>().is_err());
        assert!("0110a2b3".parse::<GuidPrefix>().is_err());
    }

    #[test]
    fn port_ranges() {
        assert!(PortRange::new(0, 1).is_err());
        assert!(PortRange::new(9, 8).is_err());
        let r = PortRange::new(7400, 7500).unwrap();
        assert!(r.contains(7410));
        assert!(r.overlaps(&PortRange::single(7500).unwrap()));
        assert!(!r.overlaps(&PortRange::single(7501).unwrap()));
        let j = serde_json::to_string(&r).unwrap();
        assert_eq!(j, "[7400,7500]");
        assert_eq!(serde_json::from_str::<PortRange>(&j).unwrap(), r);
    }
}
