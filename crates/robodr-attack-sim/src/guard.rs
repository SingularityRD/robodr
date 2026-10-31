//! Live-send guard: the only path by which this tool puts packets on a
//! network.
//!
//! A live send needs all of:
//!
//! 1. `--i-understand` (the operator acknowledges that this sends attack
//!    traffic to a robot that may be moving: run it only against a robot
//!    that is safe-stopped or on a test stand);
//! 2. the target in an explicit allow-list of CIDRs, each no wider than
//!    /16 (no "allow everything");
//! 3. the target a private (RFC 1918), loopback, link-local or
//!    organisation-local multicast (239.0.0.0/8) address. Public, broadcast
//!    and unspecified addresses are refused whatever the allow-list says.
//!
//! The sender uses ordinary UDP sockets (no raw frames, no spoofed source
//! addresses, multicast TTL 1) and sends the scenario's datagrams only, not
//! the carrier capture.

use crate::net;
use crate::scenario::Frame;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::Instant;

/// Widest allowed allow-list entry.
pub const MIN_PREFIX_LEN: u8 = 16;

/// An IPv4 CIDR block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub net: Ipv4Addr,
    pub len: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Self, GuardError> {
        let bad = || GuardError::BadCidr(s.to_string());
        let (a, l) = s.split_once('/').unwrap_or((s, "32"));
        let net: Ipv4Addr = a.parse().map_err(|_| bad())?;
        let len: u8 = l.parse().map_err(|_| bad())?;
        if len > 32 {
            return Err(bad());
        }
        if len < MIN_PREFIX_LEN {
            return Err(GuardError::TooBroad(s.to_string()));
        }
        Ok(Cidr { net, len })
    }

    fn mask(self) -> u32 {
        u32::MAX.checked_shl(32 - u32::from(self.len)).unwrap_or(0)
    }

    pub fn contains(self, a: Ipv4Addr) -> bool {
        u32::from(a) & self.mask() == u32::from(self.net) & self.mask()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardError {
    NotAcknowledged,
    BadCidr(String),
    TooBroad(String),
    NotAllowed(Ipv4Addr),
    NotLocal(Ipv4Addr),
}

impl fmt::Display for GuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GuardError::NotAcknowledged => f.write_str(
                "refusing to send: live attack traffic needs --i-understand (the robot must be \
                 safe-stopped or on a test stand)",
            ),
            GuardError::BadCidr(s) => write!(f, "bad --allow CIDR {s:?}"),
            GuardError::TooBroad(s) => write!(
                f,
                "--allow {s} is wider than /{MIN_PREFIX_LEN}: list the lab network explicitly"
            ),
            GuardError::NotAllowed(a) => write!(f, "target {a} is not in any --allow CIDR"),
            GuardError::NotLocal(a) => write!(
                f,
                "target {a} is not a private, loopback, link-local or 239/8 multicast address"
            ),
        }
    }
}

impl std::error::Error for GuardError {}

/// Whether `a` may ever be a target.
pub fn is_local_scope(a: Ipv4Addr) -> bool {
    a.is_private() || a.is_loopback() || a.is_link_local() || a.octets().first() == Some(&239)
}

/// A target that passed every check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveTarget {
    pub addr: Ipv4Addr,
}

pub fn check(
    target: Ipv4Addr,
    allow: &[Cidr],
    i_understand: bool,
) -> Result<LiveTarget, GuardError> {
    if !i_understand {
        return Err(GuardError::NotAcknowledged);
    }
    if !is_local_scope(target) {
        return Err(GuardError::NotLocal(target));
    }
    if !allow.iter().any(|c| c.contains(target)) {
        return Err(GuardError::NotAllowed(target));
    }
    Ok(LiveTarget { addr: target })
}

/// What a live send did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SendReport {
    pub sent: usize,
    /// Pre-fragmented frames (sent by the kernel's own fragmentation of
    /// the whole datagram instead) and frames that are not IPv4/UDP.
    pub skipped: usize,
    pub first_send_unix_ms: u64,
    pub last_send_unix_ms: u64,
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Send each frame's UDP payload to `target` at the frame's own port,
/// keeping the frames' relative timing.
pub fn send(target: LiveTarget, frames: &[Frame]) -> std::io::Result<SendReport> {
    let sock = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))?;
    if target.addr.is_multicast() {
        sock.set_multicast_ttl_v4(1)?;
        sock.set_multicast_loop_v4(true)?;
    }
    let mut r = SendReport::default();
    let t0 = frames.first().map(|f| f.ts).unwrap_or_default();
    let w0 = Instant::now();
    for f in frames {
        let Some(d) = net::parse(&f.data) else {
            r.skipped += 1;
            continue;
        };
        let due = f.ts.saturating_sub(t0);
        let now = w0.elapsed();
        if due > now {
            std::thread::sleep(due - now);
        }
        sock.send_to(&d.payload, SocketAddrV4::new(target.addr, d.dst_port))?;
        let ms = unix_ms();
        if r.sent == 0 {
            r.first_send_unix_ms = ms;
        }
        r.last_send_unix_ms = ms;
        r.sent += 1;
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn cidrs(v: &[&str]) -> Vec<Cidr> {
        v.iter().map(|s| Cidr::parse(s).unwrap()).collect()
    }

    #[test]
    fn every_guard_must_pass() {
        let lab = cidrs(&["10.77.10.0/24", "239.255.0.1/32"]);
        let t = Ipv4Addr::new(10, 77, 10, 10);
        assert_eq!(check(t, &lab, false), Err(GuardError::NotAcknowledged));
        assert_eq!(check(t, &lab, true), Ok(LiveTarget { addr: t }));
        let other = Ipv4Addr::new(10, 77, 11, 10);
        assert_eq!(check(other, &lab, true), Err(GuardError::NotAllowed(other)));
        let mc = Ipv4Addr::new(239, 255, 0, 1);
        assert!(check(mc, &lab, true).is_ok());
        // Public, broadcast and unspecified: refused even when "allowed".
        for a in [
            "8.8.8.8/32",
            "255.255.255.255/32",
            "0.0.0.0/32",
            "224.0.0.1/32",
        ] {
            let c = cidrs(&[a]);
            assert!(
                matches!(check(c[0].net, &c, true), Err(GuardError::NotLocal(_))),
                "{a}"
            );
        }
    }

    #[test]
    fn allow_list_entries_are_narrow_and_well_formed() {
        assert!(matches!(
            Cidr::parse("0.0.0.0/0"),
            Err(GuardError::TooBroad(_))
        ));
        assert!(matches!(
            Cidr::parse("10.0.0.0/8"),
            Err(GuardError::TooBroad(_))
        ));
        assert!(Cidr::parse("10.1.0.0/16").is_ok());
        assert!(matches!(
            Cidr::parse("10.1.0.0/33"),
            Err(GuardError::BadCidr(_))
        ));
        assert!(matches!(Cidr::parse("ten/24"), Err(GuardError::BadCidr(_))));
        assert_eq!(Cidr::parse("10.1.2.3").unwrap().len, 32);
        assert!(Cidr::parse("10.1.2.0/24")
            .unwrap()
            .contains(Ipv4Addr::new(10, 1, 2, 255)));
        assert!(!Cidr::parse("10.1.2.0/24")
            .unwrap()
            .contains(Ipv4Addr::new(10, 1, 3, 0)));
    }

    #[test]
    fn sends_payloads_to_the_target_only() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let port = rx.local_addr().unwrap().port();
        let d = net::Udp4 {
            dst_mac: [1; 6],
            src_mac: [2; 6],
            src: Ipv4Addr::new(10, 0, 0, 1),
            dst: Ipv4Addr::new(10, 0, 0, 2),
            src_port: 1,
            dst_port: port,
            payload: b"hello".to_vec(),
        };
        let frames = vec![
            Frame {
                ts: Duration::from_millis(0),
                data: d.frame(),
            },
            Frame {
                ts: Duration::from_millis(1),
                data: vec![0; 10],
            },
        ];
        let t = check(Ipv4Addr::LOCALHOST, &cidrs(&["127.0.0.0/24"]), true).unwrap();
        let r = send(t, &frames).unwrap();
        assert_eq!((r.sent, r.skipped), (1, 1));
        let mut buf = [0u8; 16];
        let n = rx.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
    }
}
