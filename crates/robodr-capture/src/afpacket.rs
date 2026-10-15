//! Live, read-only capture with a Linux `AF_PACKET` socket.
//!
//! [`AfPacketSource`] opens `socket(AF_PACKET, SOCK_DGRAM, 0)`, optionally
//! attaches a classic BPF program ([`crate::bpf`]) with `SO_ATTACH_FILTER`,
//! and only *then* binds to `ETH_P_ALL` on one interface or on all of them —
//! so no unfiltered packet is ever queued. `SOCK_DGRAM` means the kernel
//! strips the link-layer header and frames arrive as raw IP
//! ([`LinkType::RAW`]), identical for Ethernet, VLAN-offloaded NICs, Wi-Fi,
//! tunnels and loopback.
//!
//! # Read-only guarantee
//! The only libc symbols declared are `socket`, `bind`, `setsockopt`,
//! `getsockopt`, `recvfrom` and `if_nametoindex`; the descriptor is closed by
//! [`OwnedFd`]. There is no `send`, `sendto`, `write` or `PACKET_TX_RING` in
//! this crate, so it cannot inject. The socket does not enable promiscuous
//! mode, so it sees what this host sends and receives (plus broadcast and
//! subscribed multicast) — exactly the robot's own DDS traffic. Watching a
//! SPAN/TAP port on a separate sensor box would need promiscuous mode, which
//! is deliberately not implemented here.
//!
//! # Privileges
//! Opening the socket needs `CAP_NET_RAW` (root has it). Grant it to the
//! sensor binary rather than running as root:
//! `setcap cap_net_raw+ep /usr/bin/robodr-sensor`, or `AmbientCapabilities=
//! CAP_NET_RAW` in the systemd unit. Without it, [`AfPacketSource::open`]
//! returns [`CaptureError::PermissionDenied`].
//!
//! # Behaviour notes
//! - Loopback: every packet sent on `lo` is seen twice (outgoing, then
//!   incoming). Outgoing copies on loopback-type interfaces are skipped so
//!   each datagram is delivered once. Outgoing packets on real interfaces are
//!   kept (they are this robot's own announcements).
//! - Bound to all interfaces, a packet crossing a bridge/veth pair (e.g.
//!   containers) can appear once per interface. Discovery events are
//!   idempotent for graph building, so this only inflates counters.
//! - Timestamps are user-space receive time (`SystemTime::now()`), not kernel
//!   timestamps.
//! - If the kernel filter cannot be attached, the source still works and
//!   [`AfPacketSource::filter_error`] says why; the user-space filter in
//!   [`crate::RtpsDatagrams`] then does all the work.
//! - The kernel drops packets when the socket buffer overflows;
//!   [`AfPacketSource::kernel_stats`] reports those drops (a flood aimed at
//!   blinding the sensor shows up there).
//!
//! # Unsafe surface
//! Confined to this module: six FFI calls and one `OwnedFd::from_raw_fd`, each
//! with a `SAFETY` comment. All structs passed to the kernel are `#[repr(C)]`
//! with compile-time size checks. Supported architectures are those where
//! `SO_RCVTIMEO`/`SO_RCVBUF` have the generic Linux values (x86, x86_64, arm,
//! aarch64, riscv64).

use std::ffi::CString;
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::raw::{c_char, c_int, c_long, c_uint, c_void};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::bpf::{BpfProgram, SockFilter};
use crate::decode::LinkType;
use crate::source::{CaptureError, Packet, PacketSource};

mod sys {
    use std::os::raw::{c_char, c_int, c_uint, c_void};

    // Provided by the C library that std already links on Linux.
    extern "C" {
        pub fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
        pub fn bind(fd: c_int, addr: *const c_void, len: u32) -> c_int;
        pub fn setsockopt(
            fd: c_int,
            level: c_int,
            name: c_int,
            val: *const c_void,
            len: u32,
        ) -> c_int;
        pub fn getsockopt(
            fd: c_int,
            level: c_int,
            name: c_int,
            val: *mut c_void,
            len: *mut u32,
        ) -> c_int;
        pub fn recvfrom(
            fd: c_int,
            buf: *mut c_void,
            len: usize,
            flags: c_int,
            addr: *mut c_void,
            addrlen: *mut u32,
        ) -> isize;
        pub fn if_nametoindex(name: *const c_char) -> c_uint;
    }
}

const AF_PACKET: c_int = 17;
const SOCK_DGRAM: c_int = 2;
const SOCK_CLOEXEC: c_int = 0o2_000_000;
const ETH_P_ALL: u16 = 0x0003;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const SOL_SOCKET: c_int = 1;
const SO_RCVBUF: c_int = 8;
const SO_RCVTIMEO: c_int = 20;
const SO_ATTACH_FILTER: c_int = 26;
const SOL_PACKET: c_int = 263;
const PACKET_STATISTICS: c_int = 6;
const MSG_TRUNC: c_int = 0x20;
const PACKET_OUTGOING: u8 = 4;
const ARPHRD_LOOPBACK: u16 = 772;

/// Receive buffer: larger than any IP packet (64 KiB) incl. loopback GSO.
const RECV_BUF: usize = 1 << 18;

/// `struct sockaddr_ll`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
struct SockaddrLl {
    family: u16,
    protocol: u16, // network byte order
    ifindex: i32,
    hatype: u16,
    pkttype: u8,
    halen: u8,
    addr: [u8; 8],
}

/// `struct sock_fprog`.
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

/// `struct timeval` (the `SO_RCVTIMEO_OLD` layout, `long` fields).
#[repr(C)]
struct Timeval {
    tv_sec: c_long,
    tv_usec: c_long,
}

/// `struct tpacket_stats`.
#[repr(C)]
#[derive(Default)]
struct TpacketStats {
    packets: c_uint,
    drops: c_uint,
}

const _: () = assert!(size_of::<SockaddrLl>() == 20);
const _: () = assert!(size_of::<SockFilter>() == 8);
const _: () = assert!(size_of::<TpacketStats>() == 8);
const _: () = assert!(size_of::<SockFprog>() == 2 * size_of::<usize>());

fn cvt(ret: c_int) -> io::Result<c_int> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// `setsockopt` with a `#[repr(C)]` value. Private: only called with the
/// option structs above.
fn setsockopt<T>(fd: &OwnedFd, level: c_int, name: c_int, val: &T) -> io::Result<()> {
    // SAFETY: `val` is a valid, initialised `T` borrowed for the duration of
    // the call, and we pass its exact size; the kernel only reads that many
    // bytes (and, for SO_ATTACH_FILTER, copies the program the `SockFprog`
    // points at before returning). `fd` is an open socket we own.
    cvt(unsafe {
        sys::setsockopt(
            fd.as_raw_fd(),
            level,
            name,
            (val as *const T).cast::<c_void>(),
            size_of::<T>() as u32,
        )
    })
    .map(drop)
}

/// Resolve an interface name to its index.
pub fn interface_index(name: &str) -> Result<u32, CaptureError> {
    let c = CString::new(name)
        .map_err(|_| CaptureError::Unsupported(format!("interface name {name:?} contains NUL")))?;
    // SAFETY: `c` is a valid NUL-terminated string that outlives the call;
    // if_nametoindex only reads it.
    let idx = unsafe { sys::if_nametoindex(c.as_ptr() as *const c_char) };
    if idx == 0 {
        return Err(CaptureError::Unsupported(format!(
            "no such interface {name:?}"
        )));
    }
    Ok(idx)
}

/// Configuration for [`AfPacketSource::open`].
#[derive(Clone, Debug)]
pub struct AfPacketConfig {
    /// Interfaces to watch by name (e.g. `["eth0", "lo"]`). Empty = all
    /// interfaces, including loopback. One name binds the socket to that
    /// interface; several bind to all and filter by index in user space.
    pub interfaces: Vec<String>,
    /// Kernel filter to attach before binding. `None` = no kernel filter.
    pub kernel_filter: Option<BpfProgram>,
    /// Read timeout, so a capture loop can check for shutdown. `None` blocks.
    pub read_timeout: Option<Duration>,
    /// Requested `SO_RCVBUF` (the kernel caps it at `net.core.rmem_max`).
    pub recv_buffer: Option<usize>,
}

impl Default for AfPacketConfig {
    /// All interfaces, the default RTPS kernel filter, 500 ms timeout, 4 MiB
    /// receive buffer.
    fn default() -> Self {
        Self {
            interfaces: Vec::new(),
            kernel_filter: crate::bpf::rtps_filter_program(&crate::ports::RtpsFilter::default())
                .ok(),
            read_timeout: Some(Duration::from_millis(500)),
            recv_buffer: Some(4 << 20),
        }
    }
}

/// User-space counters of [`AfPacketSource`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AfPacketStats {
    pub received: u64,
    pub delivered: u64,
    pub skipped_non_ip: u64,
    pub skipped_loopback_outgoing: u64,
    pub skipped_interface: u64,
    pub truncated: u64,
}

/// A live, read-only `AF_PACKET` capture. See the module docs.
#[derive(Debug)]
pub struct AfPacketSource {
    fd: OwnedFd,
    buf: Vec<u8>,
    ifindexes: Vec<i32>,
    filter_attached: bool,
    filter_error: Option<String>,
    stats: AfPacketStats,
}

impl AfPacketSource {
    /// Open the socket. Needs `CAP_NET_RAW`.
    pub fn open(cfg: &AfPacketConfig) -> Result<Self, CaptureError> {
        let ifindexes = cfg
            .interfaces
            .iter()
            .map(|n| {
                interface_index(n).and_then(|i| {
                    i32::try_from(i)
                        .map_err(|_| CaptureError::Unsupported("ifindex overflow".into()))
                })
            })
            .collect::<Result<Vec<i32>, _>>()?;

        // Protocol 0: the socket receives nothing until bind(), so the filter
        // is in place before the first packet is queued.
        // SAFETY: plain syscall with integer arguments.
        let raw = unsafe { sys::socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, 0) };
        if raw < 0 {
            let e = io::Error::last_os_error();
            return Err(if e.kind() == io::ErrorKind::PermissionDenied {
                CaptureError::PermissionDenied(format!("AF_PACKET socket needs CAP_NET_RAW ({e})"))
            } else {
                CaptureError::Io(e)
            });
        }
        // SAFETY: `raw` is a freshly created, valid descriptor that nothing
        // else owns; OwnedFd takes sole ownership and closes it on drop.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        let (mut filter_attached, mut filter_error) = (false, None);
        if let Some(prog) = &cfg.kernel_filter {
            let fprog = SockFprog {
                len: prog.len() as u16, // validated <= BPF_MAXINSNS
                filter: prog.instructions().as_ptr(),
            };
            match setsockopt(&fd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog) {
                Ok(()) => filter_attached = true,
                Err(e) => filter_error = Some(e.to_string()),
            }
        }
        if let Some(t) = cfg.read_timeout {
            let t = t.max(Duration::from_micros(1)); // zero would mean "block"
            let tv = Timeval {
                tv_sec: c_long::try_from(t.as_secs()).unwrap_or(c_long::MAX),
                tv_usec: t.subsec_micros() as c_long,
            };
            setsockopt(&fd, SOL_SOCKET, SO_RCVTIMEO, &tv)?;
        }
        if let Some(b) = cfg.recv_buffer {
            let b: c_int = c_int::try_from(b).unwrap_or(c_int::MAX);
            // Best effort: capped by rmem_max, failure is not fatal.
            let _ = setsockopt(&fd, SOL_SOCKET, SO_RCVBUF, &b);
        }

        let addr = SockaddrLl {
            family: AF_PACKET as u16,
            protocol: ETH_P_ALL.to_be(),
            ifindex: if ifindexes.len() == 1 {
                ifindexes[0]
            } else {
                0
            },
            ..Default::default()
        };
        // SAFETY: `addr` is a valid sockaddr_ll and we pass its exact size;
        // the kernel only reads it. `fd` is an open socket we own.
        cvt(unsafe {
            sys::bind(
                fd.as_raw_fd(),
                (&addr as *const SockaddrLl).cast::<c_void>(),
                size_of::<SockaddrLl>() as u32,
            )
        })?;

        Ok(Self {
            fd,
            buf: vec![0; RECV_BUF],
            ifindexes,
            filter_attached,
            filter_error,
            stats: AfPacketStats::default(),
        })
    }

    /// The kernel BPF filter is active.
    pub fn filter_attached(&self) -> bool {
        self.filter_attached
    }

    /// Why attaching the kernel filter failed, if it did.
    pub fn filter_error(&self) -> Option<&str> {
        self.filter_error.as_deref()
    }

    pub fn stats(&self) -> &AfPacketStats {
        &self.stats
    }

    /// Kernel counters `(packets, drops)` since the previous call (reading
    /// resets them). Drops mean the sensor fell behind.
    pub fn kernel_stats(&self) -> Result<(u32, u32), CaptureError> {
        let mut st = TpacketStats::default();
        let mut len = size_of::<TpacketStats>() as u32;
        // SAFETY: `st` is valid writable memory of `len` bytes and `len` is a
        // valid in/out pointer; the kernel writes at most `len` bytes.
        cvt(unsafe {
            sys::getsockopt(
                self.fd.as_raw_fd(),
                SOL_PACKET,
                PACKET_STATISTICS,
                (&mut st as *mut TpacketStats).cast::<c_void>(),
                &mut len,
            )
        })?;
        Ok((st.packets, st.drops))
    }
}

impl PacketSource for AfPacketSource {
    fn next_packet(&mut self) -> Result<Option<Packet<'_>>, CaptureError> {
        let len = loop {
            let mut addr = SockaddrLl::default();
            let mut alen = size_of::<SockaddrLl>() as u32;
            // SAFETY: `buf` is valid writable memory of `buf.len()` bytes;
            // `addr`/`alen` are valid for writes and `alen` holds the size of
            // `addr`, so the kernel writes within bounds. With MSG_TRUNC the
            // return value may exceed `buf.len()` but nothing beyond the
            // buffer is written. `fd` is an open socket we own.
            let n = unsafe {
                sys::recvfrom(
                    self.fd.as_raw_fd(),
                    self.buf.as_mut_ptr().cast::<c_void>(),
                    self.buf.len(),
                    MSG_TRUNC,
                    (&mut addr as *mut SockaddrLl).cast::<c_void>(),
                    &mut alen,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                match e.kind() {
                    io::ErrorKind::Interrupted => continue,
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                        return Err(CaptureError::Timeout)
                    }
                    _ => return Err(CaptureError::Io(e)),
                }
            }
            self.stats.received += 1;
            let proto = u16::from_be(addr.protocol);
            if proto != ETH_P_IP && proto != ETH_P_IPV6 {
                self.stats.skipped_non_ip += 1;
                continue;
            }
            if addr.hatype == ARPHRD_LOOPBACK && addr.pkttype == PACKET_OUTGOING {
                self.stats.skipped_loopback_outgoing += 1;
                continue;
            }
            if !self.ifindexes.is_empty() && !self.ifindexes.contains(&addr.ifindex) {
                self.stats.skipped_interface += 1;
                continue;
            }
            break n as usize;
        };
        if len > self.buf.len() {
            self.stats.truncated += 1;
        }
        self.stats.delivered += 1;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        Ok(Some(Packet {
            ts,
            linktype: LinkType::RAW,
            data: &self.buf[..len.min(self.buf.len())],
            orig_len: u32::try_from(len).unwrap_or(u32::MAX),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Opens a real socket when the test runs with CAP_NET_RAW; otherwise
    /// passes after printing why it was skipped.
    #[test]
    fn open_or_skip_without_privileges() {
        match AfPacketSource::open(&AfPacketConfig {
            interfaces: vec!["lo".into()],
            read_timeout: Some(Duration::from_millis(10)),
            ..Default::default()
        }) {
            Ok(s) => {
                assert!(
                    s.filter_attached(),
                    "kernel rejected filter: {:?}",
                    s.filter_error()
                );
                assert!(s.kernel_stats().is_ok());
            }
            Err(CaptureError::PermissionDenied(m)) => {
                eprintln!("SKIPPED: no CAP_NET_RAW ({m})");
            }
            Err(e) => panic!("unexpected error opening AF_PACKET: {e}"),
        }
    }

    #[test]
    fn unknown_interface_is_an_error() {
        assert!(matches!(
            interface_index("robodr-no-such-if0"),
            Err(CaptureError::Unsupported(_))
        ));
        assert!(matches!(
            interface_index("bad\0name"),
            Err(CaptureError::Unsupported(_))
        ));
        assert!(matches!(
            AfPacketSource::open(&AfPacketConfig {
                interfaces: vec!["robodr-no-such-if0".into()],
                ..Default::default()
            }),
            Err(CaptureError::Unsupported(_))
        ));
        assert!(interface_index("lo").is_ok());
    }
}
