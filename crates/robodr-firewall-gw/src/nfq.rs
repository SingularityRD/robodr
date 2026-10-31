//! A minimal NFQUEUE (`nfnetlink_queue`) client: std + `extern "C"` socket
//! calls, no third-party crate.
//!
//! Two halves:
//!
//! - **Pure message code** ([`parse_packets`], [`build_config`],
//!   [`build_verdict`]): netlink / nfnetlink framing and attributes, every
//!   length checked against the buffer, no allocation in the parser, no
//!   panic on any input. This is what the fuzz target exercises.
//! - **The socket** ([`Queue`], Linux only): `socket(AF_NETLINK, SOCK_RAW,
//!   NETLINK_NETFILTER)`, bind to a queue number, copy mode
//!   `NFQNL_COPY_PACKET` (whole packets, up to 65535 octets), queue length,
//!   `NFQA_CFG_F_FAIL_OPEN` per the configured `on_gateway_down`, and one
//!   verdict message per packet (`NFQA_VERDICT_HDR`, plus `NFQA_PAYLOAD`
//!   for a rewritten packet).
//!
//! Why not a crate: the repository's capture path already talks to the
//! kernel with std + `extern "C"` (robodr-capture's `AF_PACKET` source);
//! the netlink surface needed here is a handful of fixed structures, and
//! keeping it in-tree keeps it reviewable and fuzzed with the rest of the
//! packet path (MSRV 1.87, no new licence to clear).
//!
//! Message layouts (`linux/netfilter/nfnetlink_queue.h`, host-endian
//! `nlmsghdr` / `nlattr`, big-endian payload fields):
//!
//! ```text
//! nlmsghdr { u32 len; u16 type = (NFNL_SUBSYS_QUEUE << 8) | msg; u16 flags; u32 seq; u32 pid }
//! nfgenmsg { u8 family; u8 version = 0; be16 res_id = queue number }
//! nlattr*  { u16 len; u16 type; value; pad to 4 }
//! ```

/// `NFNL_SUBSYS_QUEUE`.
pub const SUBSYS_QUEUE: u16 = 3;
pub const MSG_PACKET: u16 = 0;
pub const MSG_VERDICT: u16 = 1;
pub const MSG_CONFIG: u16 = 2;

pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
pub const NLM_F_REQUEST: u16 = 1;
pub const NLM_F_ACK: u16 = 4;

pub const NFQA_PACKET_HDR: u16 = 1;
pub const NFQA_VERDICT_HDR: u16 = 2;
pub const NFQA_TIMESTAMP: u16 = 4;
pub const NFQA_HWADDR: u16 = 9;
pub const NFQA_IFINDEX_INDEV: u16 = 5;
pub const NFQA_IFINDEX_PHYSINDEV: u16 = 7;
pub const NFQA_PAYLOAD: u16 = 10;
pub const NFQA_CAP_LEN: u16 = 13;

pub const NFQA_CFG_CMD: u16 = 1;
pub const NFQA_CFG_PARAMS: u16 = 2;
pub const NFQA_CFG_QUEUE_MAXLEN: u16 = 3;
pub const NFQA_CFG_MASK: u16 = 4;
pub const NFQA_CFG_FLAGS: u16 = 5;

pub const CFG_CMD_BIND: u8 = 1;
pub const CFG_CMD_UNBIND: u8 = 2;
pub const COPY_PACKET: u8 = 2;
pub const CFG_F_FAIL_OPEN: u32 = 1;

pub const NF_DROP: u32 = 0;
pub const NF_ACCEPT: u32 = 1;

const NLMSG_HDRLEN: usize = 16;
const NFGEN_LEN: usize = 4;
const NLA_HDRLEN: usize = 4;
/// `NLA_F_NESTED | NLA_F_NET_BYTEORDER`.
const NLA_TYPE_MASK: u16 = 0x3fff;

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

/// One queued packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet<'a> {
    pub id: u32,
    /// Ethertype of the packet (`0x0800` IPv4).
    pub hw_protocol: u16,
    pub hook: u8,
    /// The network-layer packet.
    pub payload: &'a [u8],
    /// Original length when the copy was truncated.
    pub cap_len: Option<u32>,
    /// Kernel receive time (seconds, microseconds; CLOCK_REALTIME), when
    /// the skb carried one.
    pub timestamp: Option<(u64, u64)>,
    pub indev: Option<u32>,
    pub physindev: Option<u32>,
    /// Source link-layer address (`NFQA_HWADDR`, `struct
    /// nfqnl_msg_packet_hw`: be16 length, pad, 8 octets) when the kernel
    /// reported a 6-octet one (the bridged Ethernet frame's source MAC).
    pub hwaddr: Option<[u8; 6]>,
}

/// What [`parse_packets`] can report besides packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Item<'a> {
    Packet(Packet<'a>),
    /// `NLMSG_ERROR` with this (negative errno, 0 = ack).
    Ack {
        seq: u32,
        error: i32,
    },
    /// A message that is not a well-formed queue packet (skipped).
    Malformed,
    /// Another message type (ignored).
    Other,
}

/// Walk a buffer of netlink messages (one `recv`), calling `f` per item.
/// Stops at the first framing error (`Malformed` reported once).
pub fn parse_packets<'a>(buf: &'a [u8], mut f: impl FnMut(Item<'a>)) {
    let mut at = 0usize;
    while at < buf.len() {
        let Some(len) = ne_u32(buf, at).map(|l| l as usize) else {
            f(Item::Malformed);
            return;
        };
        let Some(msg) = at
            .checked_add(len)
            .filter(|_| len >= NLMSG_HDRLEN)
            .and_then(|end| buf.get(at..end))
        else {
            f(Item::Malformed);
            return;
        };
        f(parse_one(msg));
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
    if ty != (SUBSYS_QUEUE << 8) | MSG_PACKET {
        return Item::Other;
    }
    let mut p = Packet {
        id: 0,
        hw_protocol: 0,
        hook: 0,
        payload: &[],
        cap_len: None,
        timestamp: None,
        indev: None,
        physindev: None,
        hwaddr: None,
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
        let Some(v) = msg.get(at + NLA_HDRLEN..aend) else {
            return Item::Malformed;
        };
        match aty & NLA_TYPE_MASK {
            NFQA_PACKET_HDR => {
                let (Some(id), Some(proto), Some(hook)) = (
                    be_u32(v, 0),
                    v.get(4..)
                        .and_then(|b| b.first_chunk())
                        .map(|b| u16::from_be_bytes(*b)),
                    v.get(6),
                ) else {
                    return Item::Malformed;
                };
                p.id = id;
                p.hw_protocol = proto;
                p.hook = *hook;
                have_hdr = true;
            }
            NFQA_PAYLOAD => p.payload = v,
            NFQA_CAP_LEN => p.cap_len = be_u32(v, 0),
            NFQA_TIMESTAMP => p.timestamp = be_u64(v, 0).zip(be_u64(v, 8)),
            NFQA_IFINDEX_INDEV => p.indev = be_u32(v, 0),
            NFQA_IFINDEX_PHYSINDEV => p.physindev = be_u32(v, 0),
            NFQA_HWADDR => {
                p.hwaddr = match (v.get(..2), v.get(4..10)) {
                    (Some([0, 6]), Some(a)) => <[u8; 6]>::try_from(a).ok(),
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

fn header(out: &mut Vec<u8>, msg: u16, flags: u16, seq: u32, family: u8, queue: u16) {
    out.clear();
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(&((SUBSYS_QUEUE << 8) | msg).to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.push(family);
    out.push(0);
    out.extend_from_slice(&queue.to_be_bytes());
}

fn finish(out: &mut [u8]) {
    let len = out.len() as u32;
    if let Some(head) = out.first_chunk_mut() {
        *head = len.to_ne_bytes();
    }
}

/// One configuration request for `queue` (acknowledged).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Config {
    Bind,
    Unbind,
    /// Copy whole packets up to `range` octets.
    CopyPacket {
        range: u32,
    },
    MaxLen(u32),
    /// `NFQA_CFG_F_FAIL_OPEN` on or off.
    FailOpen(bool),
}

/// Build one configuration message into `out`.
pub fn build_config(out: &mut Vec<u8>, seq: u32, queue: u16, c: Config) {
    header(out, MSG_CONFIG, NLM_F_REQUEST | NLM_F_ACK, seq, 0, queue);
    match c {
        Config::Bind | Config::Unbind => {
            let cmd = if c == Config::Bind {
                CFG_CMD_BIND
            } else {
                CFG_CMD_UNBIND
            };
            put_attr(out, NFQA_CFG_CMD, &[cmd, 0, 0, 0]);
        }
        Config::CopyPacket { range } => {
            let mut v = range.to_be_bytes().to_vec();
            v.push(COPY_PACKET);
            put_attr(out, NFQA_CFG_PARAMS, &v);
        }
        Config::MaxLen(n) => put_attr(out, NFQA_CFG_QUEUE_MAXLEN, &n.to_be_bytes()),
        Config::FailOpen(on) => {
            put_attr(
                out,
                NFQA_CFG_FLAGS,
                &(if on { CFG_F_FAIL_OPEN } else { 0 }).to_be_bytes(),
            );
            put_attr(out, NFQA_CFG_MASK, &CFG_F_FAIL_OPEN.to_be_bytes());
        }
    }
    finish(out);
}

/// Build a verdict message (with the rewritten packet if `payload`).
pub fn build_verdict(out: &mut Vec<u8>, queue: u16, id: u32, verdict: u32, payload: Option<&[u8]>) {
    header(out, MSG_VERDICT, NLM_F_REQUEST, 0, 0, queue);
    let mut v = [0u8; 8];
    v[..4].copy_from_slice(&verdict.to_be_bytes());
    v[4..].copy_from_slice(&id.to_be_bytes());
    put_attr(out, NFQA_VERDICT_HDR, &v);
    if let Some(p) = payload {
        put_attr(out, NFQA_PAYLOAD, p);
    }
    finish(out);
}

/// Test / fuzz helper: a packet message as the kernel sends it.
pub fn build_packet_msg(
    out: &mut Vec<u8>,
    queue: u16,
    id: u32,
    payload: &[u8],
    ts: Option<(u64, u64)>,
    hw: Option<[u8; 6]>,
) {
    header(out, MSG_PACKET, 0, 0, 2, queue);
    let mut h = id.to_be_bytes().to_vec();
    h.extend_from_slice(&0x0800u16.to_be_bytes());
    h.push(2);
    put_attr(out, NFQA_PACKET_HDR, &h);
    if let Some((s, us)) = ts {
        let mut t = s.to_be_bytes().to_vec();
        t.extend_from_slice(&us.to_be_bytes());
        put_attr(out, NFQA_TIMESTAMP, &t);
    }
    if let Some(a) = hw {
        let mut v = vec![0, 6, 0, 0];
        v.extend_from_slice(&a);
        v.extend_from_slice(&[0, 0]);
        put_attr(out, NFQA_HWADDR, &v);
    }
    put_attr(out, NFQA_PAYLOAD, payload);
    finish(out);
}

#[cfg(target_os = "linux")]
pub use socket::Queue;

/// Gaps in the kernel's NFQUEUE packet ids (T8, shed packets). The kernel
/// numbers the packets of a queue in order and delivers them in that
/// order; an id that skips ahead means packets it numbered but never
/// delivered to the gateway (a full netlink receive buffer: dropped, or
/// accepted unchecked when the queue fails open). An id at or below the
/// last one (wrap-around, a rebound queue) starts counting afresh.
#[derive(Debug, Clone, Default)]
pub struct IdGaps {
    last: Option<u32>,
}

impl IdGaps {
    /// Note packet `id`; returns how many ids it skipped.
    pub fn observe(&mut self, id: u32) -> u64 {
        let skipped = match self.last {
            Some(l) if id > l => u64::from(id - l - 1),
            _ => 0,
        };
        self.last = Some(id);
        skipped
    }
}

/// One queue's line of the kernel's `nfnetlink_queue` statistics
/// (`/proc/<pid>/net/netfilter/nfnetlink_queue`; review 2, L3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelQueueStats {
    /// Packets waiting for a verdict now.
    pub queue_total: u32,
    /// Packets the kernel dropped because the queue already held
    /// `queue.max_len` packets (only without `NFQA_CFG_F_FAIL_OPEN`: with
    /// it, i.e. `on_gateway_down: bypass`, such packets are accepted
    /// unchecked and **not counted anywhere**). They take no packet id, so
    /// [`IdGaps`] cannot see them.
    pub queue_dropped: u32,
    /// Packets the kernel could not hand to the socket (a full receive
    /// buffer); they took an id, so [`IdGaps`] counts them already.
    pub user_dropped: u32,
}

/// Parse the statistics line of `queue` from the text of
/// `/proc/net/netfilter/nfnetlink_queue` (one line per bound queue:
/// `queue_num peer_portid queue_total copy_mode copy_range queue_dropped
/// queue_user_dropped id_sequence 1`, decimal). `None`: no such line or
/// a malformed one.
pub fn parse_queue_stats(text: &str, queue: u16) -> Option<KernelQueueStats> {
    text.lines().find_map(|line| {
        let f: Vec<&str> = line.split_whitespace().collect();
        let num = |i: usize| f.get(i).and_then(|x| x.parse::<u32>().ok());
        if num(0)? != u32::from(queue) || f.len() < 8 {
            return None;
        }
        Some(KernelQueueStats {
            queue_total: num(2)?,
            queue_dropped: num(5)?,
            user_dropped: num(6)?,
        })
    })
}

/// Growth of the kernel's (32-bit, wrapping) `queue_dropped` counter
/// between reads. The queue instance, and so the counter, is created when
/// the gateway binds the queue, so the first read counts from zero.
#[derive(Debug, Clone, Default)]
pub struct KernelDrops {
    last: Option<u32>,
}

impl KernelDrops {
    /// Note the counter's value `now`; returns the packets dropped since
    /// the previous read.
    pub fn observe(&mut self, now: u32) -> u64 {
        let before = self.last.unwrap_or(0);
        self.last = Some(now);
        u64::from(now.wrapping_sub(before))
    }
}

// FFI: std has no netlink socket API (AF_NETLINK / NETLINK_NETFILTER,
// `sockaddr_nl`, netlink socket options); this module is the only place the
// queue touches the kernel.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod socket {
    use super::*;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::raw::{c_int, c_long, c_void};
    use std::time::Duration;

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
    const SO_RCVTIMEO: c_int = 20;
    const SOL_NETLINK: c_int = 270;
    const NETLINK_NO_ENOBUFS: c_int = 5;
    const SO_TIMESTAMP: c_int = 29;
    const EINTR: i32 = 4;
    const EAGAIN: i32 = 11;

    #[repr(C)]
    struct SockaddrNl {
        family: u16,
        pad: u16,
        pid: u32,
        groups: u32,
    }

    #[repr(C)]
    struct Timeval {
        tv_sec: c_long,
        tv_usec: c_long,
    }

    /// A bound NFQUEUE.
    #[derive(Debug)]
    pub struct Queue {
        fd: OwnedFd,
        num: u16,
        seq: u32,
        out: Vec<u8>,
        /// Receive buffer (one `recv` may carry several packets).
        pub buf: Vec<u8>,
    }

    fn setopt<T>(fd: c_int, level: c_int, name: c_int, v: &T) -> io::Result<()> {
        // SAFETY: `v` points to a live `T` of `size_of::<T>()` bytes for
        // the duration of the call.
        let rc = unsafe {
            setsockopt(
                fd,
                level,
                name,
                (v as *const T).cast(),
                std::mem::size_of::<T>() as u32,
            )
        };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    impl Queue {
        /// Open and bind queue `num`; `fail_open` sets the overflow
        /// behaviour (see `config::OnGatewayDown`).
        pub fn open(num: u16, max_len: u32, fail_open: bool) -> io::Result<Self> {
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
            let one: c_int = 1;
            // Best effort: without it a full socket buffer reports ENOBUFS,
            // which `recv` below treats as "try again".
            let _ = setopt(fd.as_raw_fd(), SOL_NETLINK, NETLINK_NO_ENOBUFS, &one);
            let rcvbuf: c_int = 4 << 20;
            let _ = setopt(fd.as_raw_fd(), SOL_SOCKET, SO_RCVBUF, &rcvbuf);
            // Kernel receive timestamps are only taken while some socket
            // asks for them (`net_enable_timestamp`); a netlink socket
            // counts. With them, every queued packet carries
            // NFQA_TIMESTAMP = its arrival time on the box, which the run
            // loop uses as the firewall's clock (see `runtime`).
            let _ = setopt(fd.as_raw_fd(), SOL_SOCKET, SO_TIMESTAMP, &one);
            let mut q = Queue {
                fd,
                num,
                seq: 0,
                out: Vec::with_capacity(70_000),
                buf: vec![0u8; 1 << 17],
            };
            q.config(Config::Bind)?;
            q.config(Config::CopyPacket { range: 0xffff })?;
            q.config(Config::MaxLen(max_len))?;
            q.config(Config::FailOpen(fail_open))?;
            Ok(q)
        }

        pub fn num(&self) -> u16 {
            self.num
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

        /// Send a configuration request and wait for its ack.
        pub fn config(&mut self, c: Config) -> io::Result<()> {
            self.seq = self.seq.wrapping_add(1);
            let seq = self.seq;
            let mut out = std::mem::take(&mut self.out);
            build_config(&mut out, seq, self.num, c);
            self.out = out;
            self.send_out()?;
            self.set_timeout(Duration::from_secs(2))?;
            for _ in 0..64 {
                let n = self.recv_raw()?;
                let mut result: Option<i32> = None;
                parse_packets(self.buf.get(..n).unwrap_or_default(), |it| {
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

        pub fn set_timeout(&self, t: Duration) -> io::Result<()> {
            let tv = Timeval {
                tv_sec: t.as_secs() as c_long,
                tv_usec: t.subsec_micros().max(if t.is_zero() { 1 } else { 0 }) as c_long,
            };
            setopt(self.fd.as_raw_fd(), SOL_SOCKET, SO_RCVTIMEO, &tv)
        }

        fn recv_raw(&mut self) -> io::Result<usize> {
            // SAFETY: `buf` is valid for writes of its length.
            let n = unsafe {
                recv(
                    self.fd.as_raw_fd(),
                    self.buf.as_mut_ptr().cast(),
                    self.buf.len(),
                    0,
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(n as usize)
        }

        /// Receive the next batch into [`Queue::buf`]: `Ok(0)` on timeout or
        /// interruption.
        pub fn recv(&mut self) -> io::Result<usize> {
            match self.recv_raw() {
                Ok(n) => Ok(n),
                Err(e) if matches!(e.raw_os_error(), Some(EINTR) | Some(EAGAIN) | Some(105)) => {
                    Ok(0)
                }
                Err(e) => Err(e),
            }
        }

        /// Issue a verdict (with the rewritten packet, if any).
        pub fn verdict(&mut self, id: u32, verdict: u32, payload: Option<&[u8]>) -> io::Result<()> {
            let mut out = std::mem::take(&mut self.out);
            build_verdict(&mut out, self.num, id, verdict, payload);
            self.out = out;
            self.send_out()
        }
    }

    impl Drop for Queue {
        fn drop(&mut self) {
            let _ = self.config(Config::Unbind);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review 2, L3: packets the kernel drops on a full queue take no
    /// packet id, so only its own counter shows them.
    #[test]
    fn kernel_queue_stats_are_read_and_counted() {
        let text = "    0  12345     3 2 65535    17     2      400  1\n\
                    \x20   7  12346     0 2 65535     0     5       90  1\n";
        assert_eq!(
            parse_queue_stats(text, 0),
            Some(KernelQueueStats {
                queue_total: 3,
                queue_dropped: 17,
                user_dropped: 2,
            })
        );
        assert_eq!(parse_queue_stats(text, 7).map(|s| s.user_dropped), Some(5));
        assert_eq!(parse_queue_stats(text, 1), None);
        assert_eq!(parse_queue_stats("0 1 x 2 3 4 5 6 1\n", 0), None);
        assert_eq!(parse_queue_stats("0 1 2\n", 0), None);
        assert_eq!(parse_queue_stats("", 0), None);
        let mut d = KernelDrops::default();
        assert_eq!(d.observe(17), 17, "the instance starts at zero");
        assert_eq!(d.observe(17), 0);
        assert_eq!(d.observe(20), 3);
        assert_eq!(d.observe(1), u64::from(u32::MAX - 18), "32-bit wrap");
    }

    #[test]
    fn id_gaps_count_skipped_packet_ids() {
        let mut g = IdGaps::default();
        assert_eq!(g.observe(5), 0, "the first id is the baseline");
        assert_eq!(g.observe(6), 0);
        assert_eq!(g.observe(10), 3);
        // Wrap-around or a rebound queue: afresh, no false gap.
        assert_eq!(g.observe(2), 0);
        assert_eq!(g.observe(3), 0);
        assert_eq!(g.observe(u32::MAX), u64::from(u32::MAX) - 4);
        assert_eq!(g.observe(1), 0);
    }

    #[test]
    fn packet_roundtrip_and_verdict_layout() {
        let mut m = Vec::new();
        build_packet_msg(
            &mut m,
            7,
            0x1234,
            b"\x45abcdef",
            Some((10, 20)),
            Some([2, 0, 0, 0, 0, 0x64]),
        );
        let mut two = m.clone();
        two.extend_from_slice(&m);
        let mut seen = Vec::new();
        parse_packets(&two, |it| seen.push(it));
        assert_eq!(seen.len(), 2);
        match seen[0] {
            Item::Packet(p) => {
                assert_eq!(p.id, 0x1234);
                assert_eq!(p.hw_protocol, 0x0800);
                assert_eq!(p.payload, b"\x45abcdef");
                assert_eq!(p.timestamp, Some((10, 20)));
                assert_eq!(p.hwaddr, Some([2, 0, 0, 0, 0, 0x64]));
            }
            other => panic!("{other:?}"),
        }
        let mut v = Vec::new();
        build_verdict(&mut v, 7, 0x1234, NF_ACCEPT, Some(b"xyz"));
        assert_eq!(v.len() % 4, 0);
        assert_eq!(
            u32::from_ne_bytes(v[..4].try_into().unwrap()) as usize,
            v.len()
        );
        assert_eq!(
            u16::from_ne_bytes([v[4], v[5]]),
            (SUBSYS_QUEUE << 8) | MSG_VERDICT
        );
        assert_eq!(&v[18..20], &7u16.to_be_bytes());
        // Verdict header attribute: len 12, type 2, verdict, id.
        assert_eq!(u16::from_ne_bytes([v[20], v[21]]), 12);
        assert_eq!(&v[24..28], &NF_ACCEPT.to_be_bytes());
        assert_eq!(&v[28..32], &0x1234u32.to_be_bytes());
    }

    #[test]
    fn malformed_inputs_never_panic() {
        let mut m = Vec::new();
        build_packet_msg(&mut m, 1, 1, &[0u8; 40], None, None);
        for cut in 0..m.len() {
            parse_packets(&m[..cut], |_| {});
        }
        let mut bad = m.clone();
        bad[16 + 4] = 0xff; // attribute length larger than the message
        let mut items = Vec::new();
        parse_packets(&bad, |i| items.push(i));
        assert_eq!(items, vec![Item::Malformed]);
        // An ack.
        let mut ack = vec![0u8; 36];
        ack[..4].copy_from_slice(&36u32.to_ne_bytes());
        ack[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        ack[8..12].copy_from_slice(&5u32.to_ne_bytes());
        let mut items = Vec::new();
        parse_packets(&ack, |i| items.push(i));
        assert_eq!(items, vec![Item::Ack { seq: 5, error: 0 }]);
    }
}
