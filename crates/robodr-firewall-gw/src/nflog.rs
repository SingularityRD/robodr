//! A minimal NFLOG (`nfnetlink_log`) client for the robot-side observation
//! (`crate::observe`): the kernel **copies** matching packets to a log
//! group and forwards the originals at once, so nothing the gateway does
//! (or fails to do) with the copies can delay or drop robot traffic.
//!
//! Same structure as [`crate::nfq`]: pure message code ([`parse_packets`],
//! [`build_config`]; every length checked, no panic, fuzzed) and a Linux
//! socket ([`Log`]): `socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)`,
//! bind the group, copy whole packets (`NFULNL_COPY_PACKET`, up to 65535
//! octets), queue threshold 1 and no flush timeout (each packet is sent at
//! once), non-blocking receive. A full socket buffer loses copies
//! (`ENOBUFS`), never packets.
//!
//! Layouts (`linux/netfilter/nfnetlink_log.h`):
//!
//! ```text
//! nlmsghdr { len; type = (NFNL_SUBSYS_ULOG << 8) | msg; flags; seq; pid }
//! nfgenmsg { family; version = 0; be16 res_id = group }
//! NFULA_PACKET_HDR { be16 hw_protocol; u8 hook; u8 pad }   NFULA_PAYLOAD
//! NFULA_CFG_CMD { u8 cmd }   NFULA_CFG_MODE { be32 copy_range; u8 mode; u8 pad }
//! NFULA_CFG_QTHRESH be32   NFULA_CFG_TIMEOUT be32 (1/100 s)
//! ```

/// `NFNL_SUBSYS_ULOG`.
pub const SUBSYS_ULOG: u16 = 4;
pub const MSG_PACKET: u16 = 0;
pub const MSG_CONFIG: u16 = 1;

pub const NFULA_PACKET_HDR: u16 = 1;
pub const NFULA_TIMESTAMP: u16 = 3;
pub const NFULA_IFINDEX_PHYSINDEV: u16 = 6;
pub const NFULA_HWADDR: u16 = 8;
pub const NFULA_PAYLOAD: u16 = 9;

pub const NFULA_CFG_CMD: u16 = 1;
pub const NFULA_CFG_MODE: u16 = 2;
pub const NFULA_CFG_NLBUFSIZ: u16 = 3;
pub const NFULA_CFG_TIMEOUT: u16 = 4;
pub const NFULA_CFG_QTHRESH: u16 = 5;

pub const CFG_CMD_BIND: u8 = 1;
pub const CFG_CMD_UNBIND: u8 = 2;
pub const COPY_PACKET: u8 = 2;

const NLMSG_HDRLEN: usize = 16;
const NFGEN_LEN: usize = 4;
const NLA_HDRLEN: usize = 4;
const NLA_TYPE_MASK: u16 = 0x3fff;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;

fn align4(n: usize) -> Option<usize> {
    n.checked_add(3).map(|x| x & !3)
}

fn ne_u16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn ne_u32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn be_u32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn be_u64(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_be_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// One logged packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Logged<'a> {
    pub hw_protocol: u16,
    /// The network-layer packet (IPv4 for the observe rule).
    pub payload: &'a [u8],
    pub physindev: Option<u32>,
    /// Kernel receive time (seconds, microseconds; CLOCK_REALTIME), when
    /// the skb carried one.
    pub timestamp: Option<(u64, u64)>,
    /// The link-layer source address (`NFULA_HWADDR`,
    /// `struct nfulnl_msg_packet_hw { be16 hw_addrlen; u16 pad; u8
    /// hw_addr[8]; }`), when it is a 6-byte (Ethernet) address.
    pub hw_addr: Option<[u8; 6]>,
}

/// What [`parse_packets`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Item<'a> {
    Packet(Logged<'a>),
    Ack { seq: u32, error: i32 },
    Malformed,
    Other,
}

/// Walk one `recv` buffer of netlink messages.
pub fn parse_packets<'a>(buf: &'a [u8], mut f: impl FnMut(Item<'a>)) {
    let mut at = 0usize;
    while at < buf.len() {
        let Some(len) = ne_u32(buf, at).map(|l| l as usize) else {
            f(Item::Malformed);
            return;
        };
        let Some(end) = at
            .checked_add(len)
            .filter(|&e| len >= NLMSG_HDRLEN && e <= buf.len())
        else {
            f(Item::Malformed);
            return;
        };
        f(parse_one(&buf[at..end]));
        match align4(len).and_then(|a| at.checked_add(a)) {
            Some(n) => at = n,
            None => return,
        }
    }
}

fn parse_one(msg: &[u8]) -> Item<'_> {
    let (Some(ty), Some(seq)) = (ne_u16(msg, 4), ne_u32(msg, 8)) else {
        return Item::Malformed;
    };
    if ty == NLMSG_ERROR {
        return match ne_u32(msg, NLMSG_HDRLEN) {
            Some(e) => Item::Ack {
                seq,
                error: e as i32,
            },
            None => Item::Malformed,
        };
    }
    if ty != (SUBSYS_ULOG << 8) | MSG_PACKET {
        return Item::Other;
    }
    let mut p = Logged {
        hw_protocol: 0,
        payload: &[],
        physindev: None,
        timestamp: None,
        hw_addr: None,
    };
    let mut have_hdr = false;
    let mut at = NLMSG_HDRLEN + NFGEN_LEN;
    if at > msg.len() {
        return Item::Malformed;
    }
    while at < msg.len() {
        let (Some(alen), Some(aty)) = (ne_u16(msg, at), ne_u16(msg, at + 2)) else {
            return Item::Malformed;
        };
        let alen = usize::from(alen);
        let Some(aend) = at
            .checked_add(alen)
            .filter(|&e| alen >= NLA_HDRLEN && e <= msg.len())
        else {
            return Item::Malformed;
        };
        let v = &msg[at + NLA_HDRLEN..aend];
        match aty & NLA_TYPE_MASK {
            NFULA_PACKET_HDR => {
                let Some(b) = v.get(..2) else {
                    return Item::Malformed;
                };
                p.hw_protocol = u16::from_be_bytes([b[0], b[1]]);
                have_hdr = true;
            }
            NFULA_PAYLOAD => p.payload = v,
            NFULA_IFINDEX_PHYSINDEV => p.physindev = be_u32(v, 0),
            NFULA_TIMESTAMP => p.timestamp = be_u64(v, 0).zip(be_u64(v, 8)),
            NFULA_HWADDR => {
                p.hw_addr = match (v.get(..2), v.get(4..10)) {
                    (Some([0, 6]), Some(mac)) => <[u8; 6]>::try_from(mac).ok(),
                    _ => None,
                }
            }
            _ => {}
        }
        match align4(alen).and_then(|a| at.checked_add(a)) {
            Some(n) => at = n,
            None => break,
        }
    }
    if have_hdr {
        Item::Packet(p)
    } else {
        Item::Malformed
    }
}

fn put_attr(out: &mut Vec<u8>, ty: u16, value: &[u8]) {
    let len = (NLA_HDRLEN + value.len()) as u16;
    out.extend_from_slice(&len.to_ne_bytes());
    out.extend_from_slice(&ty.to_ne_bytes());
    out.extend_from_slice(value);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

fn header(out: &mut Vec<u8>, msg: u16, flags: u16, seq: u32, group: u16) {
    out.clear();
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(&((SUBSYS_ULOG << 8) | msg).to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.push(0);
    out.push(0);
    out.extend_from_slice(&group.to_be_bytes());
}

fn finish(out: &mut [u8]) {
    let len = out.len() as u32;
    out[..4].copy_from_slice(&len.to_ne_bytes());
}

/// One configuration request (acknowledged).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Config {
    Bind,
    Unbind,
    CopyPacket {
        range: u32,
    },
    /// Packets batched before the kernel sends (1: at once).
    QueueThreshold(u32),
    /// Flush timeout (1/100 s; 0: none).
    Timeout(u32),
    /// The kernel's per-group netlink buffer (octets).
    BufSize(u32),
}

/// Build one configuration message for `group` into `out`.
pub fn build_config(out: &mut Vec<u8>, seq: u32, group: u16, c: Config) {
    header(out, MSG_CONFIG, NLM_F_REQUEST | NLM_F_ACK, seq, group);
    match c {
        Config::Bind => put_attr(out, NFULA_CFG_CMD, &[CFG_CMD_BIND]),
        Config::Unbind => put_attr(out, NFULA_CFG_CMD, &[CFG_CMD_UNBIND]),
        Config::CopyPacket { range } => {
            let mut v = range.to_be_bytes().to_vec();
            v.extend_from_slice(&[COPY_PACKET, 0]);
            put_attr(out, NFULA_CFG_MODE, &v);
        }
        Config::QueueThreshold(n) => put_attr(out, NFULA_CFG_QTHRESH, &n.to_be_bytes()),
        Config::Timeout(t) => put_attr(out, NFULA_CFG_TIMEOUT, &t.to_be_bytes()),
        Config::BufSize(n) => put_attr(out, NFULA_CFG_NLBUFSIZ, &n.to_be_bytes()),
    }
    finish(out);
}

/// Test / fuzz helper: a packet message as the kernel sends it.
pub fn build_packet_msg(out: &mut Vec<u8>, group: u16, payload: &[u8], physindev: Option<u32>) {
    build_packet_msg_hw(out, group, payload, physindev, None);
}

/// [`build_packet_msg`] with an `NFULA_HWADDR` attribute.
pub fn build_packet_msg_hw(
    out: &mut Vec<u8>,
    group: u16,
    payload: &[u8],
    physindev: Option<u32>,
    hw: Option<[u8; 6]>,
) {
    header(out, MSG_PACKET, 0, 0, group);
    put_attr(out, NFULA_PACKET_HDR, &[0x08, 0x00, 2, 0]);
    if let Some(i) = physindev {
        put_attr(out, NFULA_IFINDEX_PHYSINDEV, &i.to_be_bytes());
    }
    if let Some(m) = hw {
        let mut v = vec![0, 6, 0, 0];
        v.extend_from_slice(&m);
        v.extend_from_slice(&[0, 0]);
        put_attr(out, NFULA_HWADDR, &v);
    }
    put_attr(out, NFULA_PAYLOAD, payload);
    finish(out);
}

#[cfg(target_os = "linux")]
pub use socket::Log;

// FFI: std has no netlink socket API; see `crate::nfq` for the same calls.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod socket {
    use super::*;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::raw::{c_int, c_void};

    extern "C" {
        fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
        fn bind(fd: c_int, addr: *const c_void, len: u32) -> c_int;
        fn setsockopt(fd: c_int, level: c_int, name: c_int, val: *const c_void, len: u32) -> c_int;
        fn sendto(
            fd: c_int,
            buf: *const c_void,
            len: usize,
            flags: c_int,
            addr: *const c_void,
            alen: u32,
        ) -> isize;
        fn recv(fd: c_int, buf: *mut c_void, len: usize, flags: c_int) -> isize;
    }

    const AF_NETLINK: c_int = 16;
    const SOCK_RAW: c_int = 3;
    const SOCK_CLOEXEC: c_int = 0o2_000_000;
    const NETLINK_NETFILTER: c_int = 12;
    const SOL_SOCKET: c_int = 1;
    const SO_RCVBUF: c_int = 8;
    const MSG_DONTWAIT: c_int = 0x40;
    const EINTR: i32 = 4;
    const EAGAIN: i32 = 11;
    const ENOBUFS: i32 = 105;

    #[repr(C)]
    struct SockaddrNl {
        family: u16,
        pad: u16,
        pid: u32,
        groups: u32,
    }

    /// A bound NFLOG group.
    #[derive(Debug)]
    pub struct Log {
        fd: OwnedFd,
        group: u16,
        seq: u32,
        out: Vec<u8>,
        /// Receive buffer.
        pub buf: Vec<u8>,
        /// Receives that reported `ENOBUFS` (copies the kernel dropped).
        pub overruns: u64,
    }

    impl Log {
        /// Open and bind log group `group` (whole packets, sent at once).
        pub fn open(group: u16) -> io::Result<Self> {
            // SAFETY: plain socket(2) call; the result is checked.
            let fd = unsafe { socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `fd` is a fresh, owned descriptor.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            let addr = SockaddrNl {
                family: AF_NETLINK as u16,
                pad: 0,
                pid: 0,
                groups: 0,
            };
            // SAFETY: `addr` is a valid sockaddr_nl of the given size.
            let rc = unsafe {
                bind(
                    fd.as_raw_fd(),
                    (&addr as *const SockaddrNl).cast(),
                    std::mem::size_of::<SockaddrNl>() as u32,
                )
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            let rcvbuf: c_int = 4 << 20;
            // SAFETY: `rcvbuf` is a live c_int for the call.
            let _ = unsafe {
                setsockopt(
                    fd.as_raw_fd(),
                    SOL_SOCKET,
                    SO_RCVBUF,
                    (&rcvbuf as *const c_int).cast(),
                    std::mem::size_of::<c_int>() as u32,
                )
            };
            let mut l = Log {
                fd,
                group,
                seq: 0,
                out: Vec::with_capacity(256),
                buf: vec![0u8; 1 << 17],
                overruns: 0,
            };
            l.config(Config::Bind)?;
            l.config(Config::CopyPacket { range: 0xffff })?;
            l.config(Config::QueueThreshold(1))?;
            l.config(Config::Timeout(0))?;
            Ok(l)
        }

        pub fn group(&self) -> u16 {
            self.group
        }

        pub fn raw_fd(&self) -> RawFd {
            self.fd.as_raw_fd()
        }

        fn send_out(&self) -> io::Result<()> {
            let addr = SockaddrNl {
                family: AF_NETLINK as u16,
                pad: 0,
                pid: 0,
                groups: 0,
            };
            // SAFETY: `out` and `addr` are valid for the given lengths.
            let n = unsafe {
                sendto(
                    self.fd.as_raw_fd(),
                    self.out.as_ptr().cast(),
                    self.out.len(),
                    0,
                    (&addr as *const SockaddrNl).cast(),
                    std::mem::size_of::<SockaddrNl>() as u32,
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        fn recv_flags(&mut self, flags: c_int) -> io::Result<usize> {
            // SAFETY: `buf` is valid for writes of its length.
            let n = unsafe {
                recv(
                    self.fd.as_raw_fd(),
                    self.buf.as_mut_ptr().cast(),
                    self.buf.len(),
                    flags,
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(n as usize)
        }

        /// Send a configuration request and wait (bounded) for its ack.
        pub fn config(&mut self, c: Config) -> io::Result<()> {
            self.seq = self.seq.wrapping_add(1);
            let seq = self.seq;
            let mut out = std::mem::take(&mut self.out);
            build_config(&mut out, seq, self.group, c);
            self.out = out;
            self.send_out()?;
            for _ in 0..64 {
                let n = self.recv_flags(0)?;
                let mut result: Option<i32> = None;
                parse_packets(&self.buf[..n], |it| {
                    if let Item::Ack { seq: s, error } = it {
                        if s == seq {
                            result = Some(error);
                        }
                    }
                });
                match result {
                    Some(0) => return Ok(()),
                    Some(e) => return Err(io::Error::from_raw_os_error(-e)),
                    None => {}
                }
            }
            Err(io::Error::other("no netlink ack"))
        }

        /// Receive what is pending into [`Log::buf`] without blocking:
        /// `Ok(0)` when nothing is (or copies were lost: counted).
        pub fn try_recv(&mut self) -> io::Result<usize> {
            match self.recv_flags(MSG_DONTWAIT) {
                Ok(n) => Ok(n),
                Err(e) if e.raw_os_error() == Some(ENOBUFS) => {
                    self.overruns += 1;
                    Ok(0)
                }
                Err(e) if matches!(e.raw_os_error(), Some(EINTR) | Some(EAGAIN)) => Ok(0),
                Err(e) => Err(e),
            }
        }
    }

    impl Drop for Log {
        fn drop(&mut self) {
            let _ = self.config(Config::Unbind);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_roundtrip_and_config_layout() {
        let mut m = Vec::new();
        build_packet_msg(&mut m, 9, b"\x45abc", Some(7));
        let mut two = m.clone();
        two.extend_from_slice(&m);
        let mut seen = Vec::new();
        parse_packets(&two, |it| seen.push(it));
        assert_eq!(seen.len(), 2);
        match seen[0] {
            Item::Packet(p) => {
                assert_eq!(p.hw_protocol, 0x0800);
                assert_eq!(p.payload, b"\x45abc");
                assert_eq!(p.physindev, Some(7));
            }
            other => panic!("{other:?}"),
        }
        let mut c = Vec::new();
        build_config(&mut c, 3, 9, Config::CopyPacket { range: 0xffff });
        assert_eq!(
            u16::from_ne_bytes([c[4], c[5]]),
            (SUBSYS_ULOG << 8) | MSG_CONFIG
        );
        assert_eq!(&c[18..20], &9u16.to_be_bytes());
        // NFULA_CFG_MODE: len 10, type 2, be32 range, mode 2, pad.
        assert_eq!(u16::from_ne_bytes([c[20], c[21]]), 10);
        assert_eq!(&c[24..28], &0xffffu32.to_be_bytes());
        assert_eq!(c[28], COPY_PACKET);
        assert_eq!(c.len() % 4, 0);
    }

    #[test]
    fn hwaddr_is_parsed_only_for_ethernet() {
        let mac = [2, 0, 0, 0, 0, 0x20];
        let mut m = Vec::new();
        build_packet_msg_hw(&mut m, 9, b"\x45abc", None, Some(mac));
        let mut seen = Vec::new();
        parse_packets(&m, |it| seen.push(it));
        match seen[0] {
            Item::Packet(p) => {
                assert_eq!(p.hw_addr, Some(mac));
                assert_eq!(p.payload, b"\x45abc");
            }
            other => panic!("{other:?}"),
        }
        // Another address length: not a MAC.
        let mut m = Vec::new();
        header(&mut m, MSG_PACKET, 0, 0, 9);
        put_attr(&mut m, NFULA_PACKET_HDR, &[0x08, 0x00, 2, 0]);
        put_attr(&mut m, NFULA_HWADDR, &[0, 8, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
        finish(&mut m);
        let mut seen = Vec::new();
        parse_packets(&m, |it| seen.push(it));
        assert!(matches!(seen[0], Item::Packet(p) if p.hw_addr.is_none()));
        let mut none = Vec::new();
        build_packet_msg(&mut none, 9, b"x", None);
        parse_packets(&none, |it| {
            assert!(matches!(it, Item::Packet(p) if p.hw_addr.is_none()))
        });
    }

    #[test]
    fn malformed_inputs_never_panic() {
        let mut m = Vec::new();
        build_packet_msg(&mut m, 1, &[0u8; 40], None);
        for cut in 0..m.len() {
            parse_packets(&m[..cut], |_| {});
        }
        let mut bad = m.clone();
        bad[20] = 0xff;
        let mut items = Vec::new();
        parse_packets(&bad, |i| items.push(i));
        assert_eq!(items, vec![Item::Malformed]);
    }
}
