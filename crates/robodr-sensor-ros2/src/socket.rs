//! Receive-only SPDP multicast socket that coexists with the robot's own DDS
//! participants. Pulsar-independent: `std` plus three libc symbols that std
//! already links on Linux.
//!
//! Why not just `UdpSocket::bind(("0.0.0.0", 7400))`:
//!
//! 1. **Coexistence.** Every DDS participant on the host binds the SPDP port
//!    with `SO_REUSEADDR`. On Linux a UDP port can be shared only if *every*
//!    socket on it sets `SO_REUSEADDR`. Binding without it would either fail
//!    (ROS started first) or — worse — make the robot's own DDS participants
//!    fail to bind (sensor started first). A security sensor must never break
//!    the platform it protects, so we set `SO_REUSEADDR` before `bind`, which
//!    `std::net` cannot do. We deliberately do *not* set `SO_REUSEPORT`: that
//!    joins a uid-scoped load-balancing group in which unicast datagrams are
//!    spread across sockets, i.e. we could steal traffic.
//! 2. **No stolen unicast.** We bind to the *group* address, not `0.0.0.0`,
//!    so the kernel only delivers datagrams addressed to the group to this
//!    socket. A unicast datagram to port 7400 (static-peer setups) can then
//!    never be delivered to us instead of to a DDS participant.
//!
//! The socket never transmits. Which DDS vendors set which reuse options is a
//! per-vendor lab-validation item (docs/PULSAR-INTEGRATION.md).

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};

/// Bind a non-blocking UDP socket to `group:port` with `SO_REUSEADDR` and
/// join `group` on `interface`.
pub fn bind_spdp_multicast(
    group: Ipv4Addr,
    port: u16,
    interface: Ipv4Addr,
) -> io::Result<UdpSocket> {
    if !group.is_multicast() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{group} is not a multicast address"),
        ));
    }
    let socket = bind_reuseaddr(SocketAddrV4::new(group, port))?;
    socket.join_multicast_v4(&group, &interface)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// Bind a UDP socket to `addr` with `SO_REUSEADDR` set before `bind`.
#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )
))]
pub fn bind_reuseaddr(addr: SocketAddrV4) -> io::Result<UdpSocket> {
    use std::ffi::{c_int, c_void};
    use std::os::fd::{FromRawFd, OwnedFd};

    // asm-generic values, identical on x86_64, aarch64 and riscv64 (the
    // architectures Pulsar's bpf-builder supports).
    const AF_INET: c_int = 2;
    const SOCK_DGRAM: c_int = 2;
    const SOCK_CLOEXEC: c_int = 0o2_000_000;
    const SOL_SOCKET: c_int = 1;
    const SO_REUSEADDR: c_int = 2;

    /// `struct sockaddr_in` (16 bytes; port and address in network order).
    #[repr(C)]
    struct SockAddrIn {
        sin_family: u16,
        sin_port: u16,
        sin_addr: u32,
        sin_zero: [u8; 8],
    }

    extern "C" {
        fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
        fn setsockopt(
            fd: c_int,
            level: c_int,
            name: c_int,
            value: *const c_void,
            len: u32,
        ) -> c_int;
        fn bind(fd: c_int, addr: *const SockAddrIn, len: u32) -> c_int;
    }

    // SAFETY: plain syscall wrapper; the result is checked before use.
    let fd = unsafe { socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a freshly created, valid descriptor we exclusively own;
    // `OwnedFd` closes it on every early return below.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    let one: c_int = 1;
    // SAFETY: `one` outlives the call and the length matches its type.
    let rc = unsafe {
        setsockopt(
            fd,
            SOL_SOCKET,
            SO_REUSEADDR,
            (&one as *const c_int).cast(),
            std::mem::size_of::<c_int>() as u32,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    let sa = SockAddrIn {
        sin_family: AF_INET as u16,
        sin_port: addr.port().to_be(),
        sin_addr: u32::from_ne_bytes(addr.ip().octets()),
        sin_zero: [0; 8],
    };
    // SAFETY: `sa` is a valid sockaddr_in and the length matches it.
    let rc = unsafe { bind(fd, &sa, std::mem::size_of::<SockAddrIn>() as u32) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(UdpSocket::from(owned))
}

#[cfg(not(all(
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )
)))]
pub fn bind_reuseaddr(_addr: SocketAddrV4) -> io::Result<UdpSocket> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SO_REUSEADDR multicast bind is only implemented for Linux x86_64/aarch64/riscv64",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A port that is free right now (best effort; races are harmless here).
    fn free_port() -> u16 {
        UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[test]
    fn binds_with_the_requested_address_and_port() {
        let port = free_port();
        let s = bind_reuseaddr(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)).unwrap();
        assert_eq!(
            s.local_addr().unwrap(),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into()
        );
    }

    #[test]
    fn two_reuseaddr_sockets_share_a_port() {
        // This is what lets the sensor coexist with DDS participants.
        let port = free_port();
        let addr = SocketAddrV4::new(Ipv4Addr::new(239, 255, 0, 1), port);
        let a = bind_reuseaddr(addr).unwrap();
        let b = bind_reuseaddr(addr).unwrap();
        assert_eq!(a.local_addr().unwrap(), b.local_addr().unwrap());
    }

    #[test]
    fn a_plain_socket_on_the_port_blocks_reuse() {
        // Documents the failure mode the module docs describe: a socket
        // without SO_REUSEADDR makes the port exclusive.
        let plain = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = plain.local_addr().unwrap().port();
        let err = bind_reuseaddr(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
    }

    #[test]
    fn non_multicast_group_is_rejected() {
        let err =
            bind_spdp_multicast(Ipv4Addr::LOCALHOST, 7400, Ipv4Addr::UNSPECIFIED).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn multicast_bind_and_join_on_loopback() {
        // Joining needs a multicast-capable interface; sandboxes without one
        // return an error from the join, which is reported rather than failed.
        let port = free_port();
        match bind_spdp_multicast(Ipv4Addr::new(239, 255, 0, 1), port, Ipv4Addr::UNSPECIFIED) {
            Ok(s) => {
                let mut buf = [0u8; 16];
                // Non-blocking: nothing queued.
                let e = s.recv_from(&mut buf).unwrap_err();
                assert_eq!(e.kind(), io::ErrorKind::WouldBlock);
            }
            Err(e) => eprintln!("multicast join unavailable here: {e}"),
        }
    }
}
