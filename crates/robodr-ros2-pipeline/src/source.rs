//! Datagram sources: the [`DatagramSource`] seam and its capture adapter.
//!
//! The pipeline does not care where RTPS datagrams come from. A source is a
//! **blocking, std-only** producer, so this crate never needs tokio or
//! Pulsar; the Pulsar glue (`robodr-sensor-ros2`) runs a source on its own OS
//! thread and forwards datagrams into its async listener.
//!
//! Sources provided here:
//!
//! - [`CaptureDatagramSource`]: passive capture through `robodr-capture`
//!   (`rtps_datagrams`), over a live `AF_PACKET` socket
//!   ([`CaptureDatagramSource::open_live`], Linux, `CAP_NET_RAW`) or a
//!   pcap/pcapng file ([`CaptureDatagramSource::open_file`]). This is the
//!   source that sees **unicast SEDP** (who writes `rt/cmd_vel`) and loopback
//!   traffic, which the SPDP multicast socket cannot.
//! - [`VecDatagramSource`]: an in-memory list (tests, replays).
//!
//! # Ingress
//!
//! Every captured datagram is tagged with the [`Ingress`] the capture layer
//! reports **for that packet** ([`robodr_capture::IngressInfo`], see
//! [`ingress_of_packet`]): live `AF_PACKET` frames carry the kernel's
//! interface hardware type (so a capture bound to every interface still
//! knows `lo` from `eth0`), pcapng frames carry their Interface Description
//! Block's `if_name`, and Linux cooked-capture frames (`tcpdump -i any`,
//! SLL/SLL2) carry the interface type in their header. Only when the packet
//! says nothing (classic pcap without a configured interface, `tcpdump -i
//! lo` saved as Ethernet in a classic pcap, pcapng without `if_name`) does
//! the source's static tag apply ([`CaptureDatagramSource::with_ingress`],
//! [`ingress_of_interfaces`]), which defaults to [`Ingress::Unknown`].
//!
//! The SPDP multicast socket ([`crate::socket`]) is used directly by the
//! async glue (tokio needs a non-blocking socket), not through this trait.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use robodr_capture::reassembly::ReassemblyStats;

pub use crate::binding::Ingress;
use robodr_capture::{
    CaptureError, CaptureFile, CaptureStats, MatchMode, PacketSource, RtpsDatagrams, RtpsFilter,
    RtpsPortMap,
};

/// One received datagram (UDP payload, starting at `RTPS`) with the source
/// IP it came from, as text (the form `robodr_rtps` reports), and the kind
/// of interface it arrived on when the source knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    pub payload: Vec<u8>,
    pub src_ip: String,
    /// See [`Ingress`]; [`Ingress::Unknown`] from [`Datagram::new`].
    pub ingress: Ingress,
    /// Name of the interface it arrived on, when the source knows it
    /// (evidence only; trust decisions use [`Datagram::ingress`]).
    pub interface: Option<String>,
}

impl Datagram {
    pub fn new(payload: Vec<u8>, src_ip: impl Into<String>) -> Self {
        Self {
            payload,
            src_ip: src_ip.into(),
            ingress: Ingress::Unknown,
            interface: None,
        }
    }

    /// Tag the datagram with the kind of interface it arrived on.
    #[must_use]
    pub fn with_ingress(mut self, ingress: Ingress) -> Self {
        self.ingress = ingress;
        self
    }
}

/// Is the named interface a loopback interface? Linux: `ARPHRD_LOOPBACK`
/// (772) in `/sys/class/net/<name>/type`; elsewhere, or when sysfs is not
/// readable, the name `lo`. Names with `/` or `..` are never loopback.
pub fn is_loopback_interface(name: &str) -> bool {
    if name.is_empty() || name.contains('/') || name.contains("..") {
        return false;
    }
    match std::fs::read_to_string(format!("/sys/class/net/{name}/type")) {
        Ok(t) => t.trim() == "772",
        Err(_) => name == "lo",
    }
}

/// The [`Ingress`] of one captured packet: its interface's loopback flag
/// when the capture layer knows it (`Some(true)` -> `Loopback`,
/// `Some(false)` -> `External`), else `fallback` (the source's static tag).
pub fn ingress_of_packet(info: &robodr_capture::IngressInfo, fallback: Ingress) -> Ingress {
    match info.loopback {
        Some(true) => Ingress::Loopback,
        Some(false) => Ingress::External,
        None => fallback,
    }
}

/// The [`Ingress`] of a capture bound to `interfaces`: all loopback ->
/// `Loopback`, all non-loopback -> `External`, empty (every interface) or
/// mixed -> `Unknown`.
pub fn ingress_of_interfaces(interfaces: &[String], is_loopback: impl Fn(&str) -> bool) -> Ingress {
    if interfaces.is_empty() {
        return Ingress::Unknown;
    }
    let lo = interfaces.iter().filter(|i| is_loopback(i)).count();
    if lo == interfaces.len() {
        Ingress::Loopback
    } else if lo == 0 {
        Ingress::External
    } else {
        Ingress::Unknown
    }
}

/// A blocking producer of RTPS datagrams.
///
/// Contract:
/// - `Ok(Some(d))`: one datagram (UDP payload only, starting at `RTPS`).
/// - `Ok(None)`: the source is finished (end of file, or stopped); it will
///   not be polled again.
/// - `Err(e)`: a terminal error; the caller drops the source and reports it.
///   Transient conditions (EINTR, read timeouts used for polling) are handled
///   inside the implementation, never returned.
///
/// Implementations must stay read-only on the network.
pub trait DatagramSource {
    fn recv(&mut self) -> io::Result<Option<Datagram>>;

    /// Cumulative capture-layer health counters, for sources that have them
    /// (passive capture). Fed to
    /// [`Pipeline::capture_findings`](crate::Pipeline::capture_findings).
    /// Default: none.
    fn capture_health(&self) -> Option<CaptureHealth> {
        None
    }
}

impl<T: DatagramSource + ?Sized> DatagramSource for Box<T> {
    fn recv(&mut self) -> io::Result<Option<Datagram>> {
        (**self).recv()
    }

    fn capture_health(&self) -> Option<CaptureHealth> {
        (**self).capture_health()
    }
}

impl<T: DatagramSource + ?Sized> DatagramSource for &mut T {
    fn recv(&mut self) -> io::Result<Option<Datagram>> {
        (**self).recv()
    }

    fn capture_health(&self) -> Option<CaptureHealth> {
        (**self).capture_health()
    }
}

/// Cumulative capture-layer counters that indicate lost, malformed or
/// tampered-with traffic below RTPS: what the sensor could **not** inspect.
/// Built from `robodr-capture`'s [`CaptureStats`] and IP-[`ReassemblyStats`];
/// the pipeline turns increases into rate-limited `robot.capture.*`
/// findings ([`crate::Pipeline::capture_findings`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct CaptureHealth {
    /// Frames cut short by the snap length or the capture file.
    pub truncated: u64,
    /// Frames whose IP/UDP headers do not decode.
    pub malformed: u64,
    /// IP datagrams dropped because fragments overlapped with conflicting
    /// bytes (a classic IDS-evasion pattern).
    pub ip_fragment_conflicts: u64,
    /// IP datagrams dropped for inconsistent fragment geometry.
    pub ip_fragment_invalid: u64,
    /// IP datagrams that never completed within the reassembly timeout.
    pub ip_fragment_timeouts: u64,
    /// IP datagrams evicted to keep reassembly memory bounded.
    pub ip_fragment_evicted: u64,
    /// IP fragments refused because their destination's reassembly budget
    /// was full (or nothing was evictable): not inspected.
    pub ip_fragment_refused: u64,
    /// Duplicate IP fragments whose bytes differ from the queued copy (the
    /// first copy is kept): an overlap-evasion trait.
    pub ip_fragment_duplicate_conflicts: u64,
    /// IPv4 datagrams restarted by the `max_dist` rule.
    pub ip_fragment_too_far: u64,
    /// IPv4 packets with a wrong header checksum (dropped).
    pub bad_ip_checksum: u64,
    /// UDP datagrams with a wrong checksum (dropped).
    pub bad_udp_checksum: u64,
    /// IP packets that were not UDP (not inspected).
    pub not_udp: u64,
}

impl CaptureHealth {
    /// Every counter of `robodr-capture` that means "not inspected" or
    /// "tampered with below RTPS". Not mapped (benign or informational):
    /// `duplicates` without conflict, `udp_checksum_partial` / `_none` /
    /// `_unverified`, `filtered_out`, `not_ip`, `ipv6_long_ext_chains`.
    pub fn from_stats(c: &CaptureStats, r: &ReassemblyStats) -> Self {
        Self {
            truncated: c.truncated,
            malformed: c.malformed,
            ip_fragment_conflicts: r.dropped_overlap,
            ip_fragment_invalid: r.dropped_invalid,
            ip_fragment_timeouts: r.dropped_timeout,
            ip_fragment_evicted: r.dropped_capacity,
            ip_fragment_refused: r.refused_capacity,
            ip_fragment_duplicate_conflicts: r.duplicate_conflicts,
            ip_fragment_too_far: r.dropped_too_far,
            bad_ip_checksum: c.bad_ip_checksum,
            bad_udp_checksum: c.bad_udp_checksum,
            not_udp: c.not_udp,
        }
    }

    /// Field-wise saturating sum (several capture sources).
    #[must_use]
    pub fn saturating_add(&self, o: &Self) -> Self {
        Self {
            truncated: self.truncated.saturating_add(o.truncated),
            malformed: self.malformed.saturating_add(o.malformed),
            ip_fragment_conflicts: self
                .ip_fragment_conflicts
                .saturating_add(o.ip_fragment_conflicts),
            ip_fragment_invalid: self
                .ip_fragment_invalid
                .saturating_add(o.ip_fragment_invalid),
            ip_fragment_timeouts: self
                .ip_fragment_timeouts
                .saturating_add(o.ip_fragment_timeouts),
            ip_fragment_evicted: self
                .ip_fragment_evicted
                .saturating_add(o.ip_fragment_evicted),
            ip_fragment_refused: self
                .ip_fragment_refused
                .saturating_add(o.ip_fragment_refused),
            ip_fragment_duplicate_conflicts: self
                .ip_fragment_duplicate_conflicts
                .saturating_add(o.ip_fragment_duplicate_conflicts),
            ip_fragment_too_far: self
                .ip_fragment_too_far
                .saturating_add(o.ip_fragment_too_far),
            bad_ip_checksum: self.bad_ip_checksum.saturating_add(o.bad_ip_checksum),
            bad_udp_checksum: self.bad_udp_checksum.saturating_add(o.bad_udp_checksum),
            not_udp: self.not_udp.saturating_add(o.not_udp),
        }
    }
}

/// The latest [`CaptureHealth`] of a source running on another thread (the
/// Pulsar glue runs capture on its own OS thread). Cheap to clone; the
/// source thread [`publish`](Self::publish)es, the pipeline side reads
/// [`latest`](Self::latest).
#[derive(Debug, Clone, Default)]
pub struct SharedHealth(Arc<Mutex<Option<CaptureHealth>>>);

impl SharedHealth {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a snapshot (`None` leaves the previous one).
    pub fn publish(&self, health: Option<CaptureHealth>) {
        if let Some(h) = health {
            // A poisoned lock only means a publisher panicked mid-store of a
            // Copy value; the data is still a valid snapshot.
            let mut g = self.0.lock().unwrap_or_else(|e| e.into_inner());
            *g = Some(h);
        }
    }

    pub fn latest(&self) -> Option<CaptureHealth> {
        *self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// An in-memory list of datagrams; finishes when empty.
#[derive(Debug, Clone, Default)]
pub struct VecDatagramSource(VecDeque<Datagram>);

impl VecDatagramSource {
    pub fn new(datagrams: impl IntoIterator<Item = Datagram>) -> Self {
        Self(datagrams.into_iter().collect())
    }
}

impl DatagramSource for VecDatagramSource {
    fn recv(&mut self) -> io::Result<Option<Datagram>> {
        Ok(self.0.pop_front())
    }
}

/// Bounded queue between the threads of a [`MergedDatagramSource`] and its
/// reader, per sub-source (backpressure: a sub-source blocks when full).
pub const MERGED_QUEUE_PER_SOURCE: usize = 256;

enum MergedMsg {
    Data(Datagram),
    End,
    Err(io::Error),
}

/// Several blocking sources merged into one: each runs on its own OS thread
/// and feeds a bounded channel. Used to capture loopback and non-loopback
/// interfaces separately (so every datagram carries a known [`Ingress`])
/// while the consumer still sees a single [`DatagramSource`].
///
/// - Ends (`Ok(None)`) when every sub-source has ended.
/// - The first sub-source error is returned (terminal, per the trait
///   contract) and `stop` is set so the others wind down.
/// - [`capture_health`](DatagramSource::capture_health) is the field-wise
///   sum of the sub-sources' latest snapshots.
/// - Dropping it sets `stop` (the sub-sources must honour that flag, as
///   [`CaptureDatagramSource::with_stop_flag`] does); threads are detached,
///   not joined, so a drop never blocks for a read timeout.
pub struct MergedDatagramSource {
    rx: std::sync::mpsc::Receiver<MergedMsg>,
    health: Arc<Mutex<Vec<Option<CaptureHealth>>>>,
    live: usize,
    stop: Arc<AtomicBool>,
    reported_end: bool,
}

impl std::fmt::Debug for MergedDatagramSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MergedDatagramSource")
            .field("live", &self.live)
            .field("reported_end", &self.reported_end)
            .finish()
    }
}

impl MergedDatagramSource {
    /// Start one thread per source. `stop` is the flag the sub-sources were
    /// built with.
    pub fn new(
        sources: Vec<Box<dyn DatagramSource + Send>>,
        stop: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        let n = sources.len();
        let (tx, rx) =
            std::sync::mpsc::sync_channel(MERGED_QUEUE_PER_SOURCE.saturating_mul(n.max(1)));
        let health = Arc::new(Mutex::new(vec![None; n]));
        for (i, mut src) in sources.into_iter().enumerate() {
            let tx = tx.clone();
            let health = health.clone();
            std::thread::Builder::new()
                .name(format!("robodr-capture-{i}"))
                .spawn(move || loop {
                    let r = src.recv();
                    if let Some(h) = src.capture_health() {
                        let mut g = health.lock().unwrap_or_else(|e| e.into_inner());
                        if let Some(slot) = g.get_mut(i) {
                            *slot = Some(h);
                        }
                    }
                    let msg = match r {
                        Ok(Some(d)) => MergedMsg::Data(d),
                        Ok(None) => MergedMsg::End,
                        Err(e) => MergedMsg::Err(e),
                    };
                    let last = !matches!(msg, MergedMsg::Data(_));
                    if tx.send(msg).is_err() || last {
                        return;
                    }
                })?;
        }
        Ok(Self {
            rx,
            health,
            live: n,
            stop,
            reported_end: n == 0,
        })
    }
}

impl DatagramSource for MergedDatagramSource {
    fn recv(&mut self) -> io::Result<Option<Datagram>> {
        while !self.reported_end {
            match self.rx.recv() {
                Ok(MergedMsg::Data(d)) => return Ok(Some(d)),
                Ok(MergedMsg::End) => {
                    self.live = self.live.saturating_sub(1);
                    if self.live == 0 {
                        self.reported_end = true;
                    }
                }
                Ok(MergedMsg::Err(e)) => {
                    self.reported_end = true;
                    self.stop.store(true, Ordering::Relaxed);
                    return Err(e);
                }
                Err(_) => self.reported_end = true,
            }
        }
        Ok(None)
    }

    fn capture_health(&self) -> Option<CaptureHealth> {
        let g = self.health.lock().unwrap_or_else(|e| e.into_inner());
        g.iter()
            .flatten()
            .fold(None, |acc: Option<CaptureHealth>, h| {
                Some(acc.map_or(*h, |a| a.saturating_add(h)))
            })
    }
}

impl Drop for MergedDatagramSource {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Consecutive non-RTPS frames after which a live capture returns control to
/// [`CaptureDatagramSource::recv`] so the stop flag is checked even under a
/// flood that never lets the read time out.
pub const LIVE_FRAME_BUDGET: usize = 1024;

/// [`DatagramSource`] over `robodr-capture`'s [`RtpsDatagrams`] glue
/// (decode -> IP reassembly -> RTPS filter), for live capture and files.
///
/// Live sources return from the underlying iterator on every read timeout and
/// after [`LIVE_FRAME_BUDGET`] filtered frames; `recv` then checks the
/// optional stop flag and keeps reading, so a live source only ends when the
/// flag is set or the socket fails. File sources end at end of file; a file
/// that ends mid-record (`Truncated`) or is corrupt yields every datagram it
/// had and then an `Err` (`UnexpectedEof` / `InvalidData`).
#[derive(Debug)]
pub struct CaptureDatagramSource<S> {
    inner: RtpsDatagrams<S>,
    stop: Option<Arc<AtomicBool>>,
    reported_end: bool,
    ingress: Ingress,
}

/// The RTPS filter used for a port map: well-known ports **or** the `RTPS`
/// magic, so RTPS on a non-standard port is not missed.
pub fn rtps_filter(port_map: RtpsPortMap) -> RtpsFilter {
    RtpsFilter::new(port_map, MatchMode::PortsOrMagic)
}

impl<S: PacketSource> CaptureDatagramSource<S> {
    /// Wrap a finite packet source (file, test vector).
    pub fn new(source: S, filter: RtpsFilter) -> Self {
        Self {
            inner: RtpsDatagrams::new(source, filter),
            stop: None,
            reported_end: false,
            ingress: Ingress::Unknown,
        }
    }

    /// Wrap a live packet source: also yields control after
    /// [`LIVE_FRAME_BUDGET`] non-RTPS frames.
    pub fn new_live(source: S, filter: RtpsFilter) -> Self {
        Self {
            inner: RtpsDatagrams::new(source, filter).with_frame_budget(LIVE_FRAME_BUDGET),
            stop: None,
            reported_end: false,
            ingress: Ingress::Unknown,
        }
    }

    /// Stop (return `Ok(None)`) at the next opportunity once `flag` is set.
    /// For a live source the latency is at most one read timeout.
    #[must_use]
    pub fn with_stop_flag(mut self, flag: Arc<AtomicBool>) -> Self {
        self.stop = Some(flag);
        self
    }

    /// Tag datagrams whose packet carries no interface information with
    /// `ingress` (set by [`CaptureDatagramSource::open_live`] from the
    /// interface list). Per-packet information always wins (see
    /// [`ingress_of_packet`]).
    #[must_use]
    pub fn with_ingress(mut self, ingress: Ingress) -> Self {
        self.ingress = ingress;
        self
    }

    /// The fallback [`Ingress`] for packets without interface information.
    pub fn ingress(&self) -> Ingress {
        self.ingress
    }

    /// Capture counters (frames, filtered, truncated, reassembled, ...).
    pub fn stats(&self) -> &CaptureStats {
        self.inner.stats()
    }

    /// IP-reassembly counters.
    pub fn reassembly_stats(&self) -> &ReassemblyStats {
        self.inner.reassembly_stats()
    }

    /// The underlying packet source (e.g. for `AfPacketSource::kernel_stats`).
    pub fn packet_source(&self) -> &S {
        self.inner.source()
    }

    fn stopped(&self) -> bool {
        self.stop
            .as_ref()
            .is_some_and(|f| f.load(Ordering::Relaxed))
    }
}

impl CaptureDatagramSource<CaptureFile<BufReader<File>>> {
    /// Replay a pcap or pcapng file (format detected from its magic).
    pub fn open_file(path: impl AsRef<Path>, port_map: RtpsPortMap) -> io::Result<Self> {
        let path = path.as_ref();
        let file = CaptureFile::open(path).map_err(|e| {
            let e = capture_to_io(&e);
            io::Error::new(e.kind(), format!("{}: {e}", path.display()))
        })?;
        Ok(Self::new(file, rtps_filter(port_map)))
    }
}

#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "riscv64"
    )
))]
impl CaptureDatagramSource<robodr_capture::afpacket::AfPacketSource> {
    /// Open a live, read-only `AF_PACKET` capture (needs `CAP_NET_RAW`).
    ///
    /// `interfaces` empty = all interfaces. The kernel BPF filter is compiled
    /// from the same port map; if it cannot be built or attached, the
    /// user-space filter does all the work (the source still works).
    /// Every datagram is tagged with the ingress the kernel reports for its
    /// packet (`sll_hatype == ARPHRD_LOOPBACK`, see [`ingress_of_packet`]),
    /// also when bound to all interfaces; [`ingress_of_interfaces`] is only
    /// the fallback, which `AF_PACKET` never needs.
    /// ([`crate::config::CaptureSettings::open`] still splits a mixed list
    /// into two sources; that is no longer required for ingress.)
    pub fn open_live(
        interfaces: &[String],
        port_map: RtpsPortMap,
        read_timeout: std::time::Duration,
    ) -> io::Result<Self> {
        use robodr_capture::afpacket::{AfPacketConfig, AfPacketSource};
        let filter = rtps_filter(port_map);
        let cfg = AfPacketConfig {
            interfaces: interfaces.to_vec(),
            kernel_filter: robodr_capture::bpf::rtps_filter_program(&filter).ok(),
            read_timeout: Some(read_timeout),
            ..AfPacketConfig::default()
        };
        let src = AfPacketSource::open(&cfg).map_err(|e| capture_to_io(&e))?;
        Ok(Self::new_live(src, filter)
            .with_ingress(ingress_of_interfaces(interfaces, is_loopback_interface)))
    }
}

impl<S: PacketSource> DatagramSource for CaptureDatagramSource<S> {
    fn recv(&mut self) -> io::Result<Option<Datagram>> {
        loop {
            if self.stopped() || self.reported_end {
                return Ok(None);
            }
            if let Some(p) = self.inner.next_packet() {
                let mut d = Datagram::new(p.payload, p.src.to_string())
                    .with_ingress(ingress_of_packet(&p.ingress, self.ingress));
                d.interface = p.ingress.name;
                return Ok(Some(d));
            }
            if self.inner.is_finished() {
                self.reported_end = true;
                return match self.inner.last_error() {
                    Some(e) => Err(capture_to_io(e)),
                    None => Ok(None),
                };
            }
            // Live: read timeout or frame budget spent. Check the stop flag
            // and read again.
        }
    }

    fn capture_health(&self) -> Option<CaptureHealth> {
        Some(CaptureHealth::from_stats(
            self.inner.stats(),
            self.inner.reassembly_stats(),
        ))
    }
}

/// Map a capture error onto an `io::Error` with a meaningful kind.
pub fn capture_to_io(e: &CaptureError) -> io::Error {
    let kind = match e {
        CaptureError::Io(e) => e.kind(),
        CaptureError::PermissionDenied(_) => io::ErrorKind::PermissionDenied,
        CaptureError::Format(_) => io::ErrorKind::InvalidData,
        CaptureError::Truncated => io::ErrorKind::UnexpectedEof,
        CaptureError::Timeout => io::ErrorKind::TimedOut,
        CaptureError::Unsupported(_) => io::ErrorKind::Unsupported,
    };
    io::Error::new(kind, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use robodr_capture::{synth, LinkType, Packet, PcapWriter, VecSource};
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn rtps(tag: u8) -> Vec<u8> {
        let mut p = b"RTPS\x02\x03\x01\x0f".to_vec();
        p.extend_from_slice(&[tag; 12]);
        p
    }

    fn frame(port: u16, payload: &[u8]) -> (Duration, LinkType, Vec<u8>) {
        let a = Ipv4Addr::new(10, 0, 0, 7);
        (
            Duration::ZERO,
            LinkType::RAW,
            synth::ipv4_udp(a, a, 1, port, payload),
        )
    }

    #[test]
    fn vec_source_drains_then_ends() {
        let mut s = VecDatagramSource::new([Datagram::new(vec![1], "a")]);
        assert_eq!(s.recv().unwrap().unwrap().src_ip, "a");
        assert!(s.recv().unwrap().is_none());
        let mut boxed: Box<dyn DatagramSource> = Box::new(VecDatagramSource::default());
        assert!(boxed.recv().unwrap().is_none());
    }

    #[test]
    fn capture_source_yields_rtps_only() {
        let frames = vec![
            frame(7410, &rtps(1)),
            frame(53, b"dns"),
            frame(20000, &rtps(2)),
        ];
        let mut s = CaptureDatagramSource::new(
            VecSource::new(frames),
            rtps_filter(RtpsPortMap::ros2_default()),
        );
        let a = s.recv().unwrap().unwrap();
        assert_eq!(a.src_ip, "10.0.0.7");
        assert_eq!(a.payload, rtps(1));
        assert_eq!(s.recv().unwrap().unwrap().payload, rtps(2));
        assert!(s.recv().unwrap().is_none());
        assert!(s.recv().unwrap().is_none());
        assert_eq!(s.stats().filtered_out, 1);
        assert_eq!(s.capture_health(), Some(CaptureHealth::default()));
        let boxed: Box<dyn DatagramSource> = Box::new(s);
        assert_eq!(boxed.capture_health(), Some(CaptureHealth::default()));
        assert_eq!(VecDatagramSource::default().capture_health(), None);
    }

    #[test]
    fn shared_health_keeps_the_latest_snapshot() {
        let h = SharedHealth::new();
        assert_eq!(h.latest(), None);
        let snap = CaptureHealth {
            truncated: 3,
            ..Default::default()
        };
        h.clone().publish(Some(snap));
        h.publish(None);
        assert_eq!(h.latest(), Some(snap));
        let t = {
            let h = h.clone();
            std::thread::spawn(move || {
                h.publish(Some(CaptureHealth {
                    malformed: 1,
                    ..Default::default()
                }))
            })
        };
        t.join().unwrap();
        assert_eq!(h.latest().unwrap().malformed, 1);
    }

    #[test]
    fn stop_flag_ends_the_source() {
        let flag = Arc::new(AtomicBool::new(false));
        let mut s = CaptureDatagramSource::new(
            VecSource::new(vec![frame(7410, &rtps(1)), frame(7410, &rtps(2))]),
            RtpsFilter::default(),
        )
        .with_stop_flag(flag.clone());
        assert!(s.recv().unwrap().is_some());
        flag.store(true, Ordering::Relaxed);
        assert!(s.recv().unwrap().is_none());
    }

    /// A "live" source: timeouts, then data, then a fatal error.
    struct Live(u32, Vec<u8>);
    impl PacketSource for Live {
        fn next_packet(&mut self) -> Result<Option<Packet<'_>>, CaptureError> {
            self.0 += 1;
            match self.0 {
                1..=3 => Err(CaptureError::Timeout),
                4 => Ok(Some(Packet {
                    ts: Duration::ZERO,
                    linktype: LinkType::RAW,
                    data: &self.1,
                    orig_len: self.1.len() as u32,
                    ingress: Default::default(),
                })),
                _ => Err(CaptureError::PermissionDenied("gone".into())),
            }
        }
    }

    #[test]
    fn live_timeouts_are_absorbed_and_fatal_errors_surface() {
        let ip = frame(7400, &rtps(9)).2;
        let mut s = CaptureDatagramSource::new_live(Live(0, ip), RtpsFilter::default());
        assert_eq!(s.recv().unwrap().unwrap().payload, rtps(9));
        assert_eq!(s.stats().timeouts, 3);
        let e = s.recv().unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert!(s.recv().unwrap().is_none(), "terminal error reported once");
    }

    #[test]
    fn truncated_file_yields_data_then_error() {
        let f = frame(7410, &rtps(3)).2;
        let mut w = PcapWriter::new(Vec::new(), LinkType::RAW, 65535, false).unwrap();
        w.write_packet(Duration::ZERO, &f, f.len() as u32).unwrap();
        w.write_packet(Duration::ZERO, &f, f.len() as u32).unwrap();
        let mut bytes = w.into_inner();
        bytes.truncate(bytes.len() - 5);
        let mut s = CaptureDatagramSource::new(
            CaptureFile::new(&bytes[..]).unwrap(),
            RtpsFilter::default(),
        );
        assert!(s.recv().unwrap().is_some());
        assert_eq!(s.recv().unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        assert!(s.recv().unwrap().is_none());
    }

    #[test]
    fn missing_or_bad_file_is_an_error() {
        let e = CaptureDatagramSource::open_file("/nonexistent/x.pcap", RtpsPortMap::default())
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        assert!(e.to_string().contains("/nonexistent/x.pcap"));
        let dir = std::env::temp_dir().join(format!("robodr-pl-bad-{}", std::process::id()));
        std::fs::write(&dir, b"definitely not a pcap file").unwrap();
        let e = CaptureDatagramSource::open_file(&dir, RtpsPortMap::default()).unwrap_err();
        std::fs::remove_file(&dir).ok();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn health_maps_every_not_inspected_counter() {
        let c = CaptureStats {
            truncated: 1,
            malformed: 2,
            bad_ip_checksum: 3,
            bad_udp_checksum: 4,
            not_udp: 5,
            udp_checksum_partial: 99,
            filtered_out: 99,
            ..Default::default()
        };
        let r = ReassemblyStats {
            dropped_overlap: 6,
            dropped_invalid: 7,
            dropped_timeout: 8,
            dropped_capacity: 9,
            refused_capacity: 10,
            duplicate_conflicts: 11,
            dropped_too_far: 12,
            duplicates: 99,
            ..Default::default()
        };
        let h = CaptureHealth::from_stats(&c, &r);
        assert_eq!(
            h,
            CaptureHealth {
                truncated: 1,
                malformed: 2,
                ip_fragment_conflicts: 6,
                ip_fragment_invalid: 7,
                ip_fragment_timeouts: 8,
                ip_fragment_evicted: 9,
                ip_fragment_refused: 10,
                ip_fragment_duplicate_conflicts: 11,
                ip_fragment_too_far: 12,
                bad_ip_checksum: 3,
                bad_udp_checksum: 4,
                not_udp: 5,
            }
        );
        let sum = h.saturating_add(&h);
        assert_eq!(sum.not_udp, 10);
        assert_eq!(sum.ip_fragment_refused, 20);
        let max = CaptureHealth {
            bad_ip_checksum: u64::MAX,
            ..Default::default()
        };
        assert_eq!(max.saturating_add(&h).bad_ip_checksum, u64::MAX);
    }

    #[test]
    fn ingress_tagging() {
        assert_eq!(Datagram::new(vec![], "a").ingress, Ingress::Unknown);
        assert_eq!(
            Datagram::new(vec![], "a")
                .with_ingress(Ingress::Loopback)
                .ingress,
            Ingress::Loopback
        );
        let mut s = CaptureDatagramSource::new(
            VecSource::new(vec![frame(7410, &rtps(1))]),
            RtpsFilter::default(),
        )
        .with_ingress(Ingress::External);
        assert_eq!(s.ingress(), Ingress::External);
        assert_eq!(s.recv().unwrap().unwrap().ingress, Ingress::External);
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let lo = |n: &str| n.starts_with("lo");
        assert_eq!(ingress_of_interfaces(&[], lo), Ingress::Unknown);
        assert_eq!(ingress_of_interfaces(&v(&["lo"]), lo), Ingress::Loopback);
        assert_eq!(
            ingress_of_interfaces(&v(&["lo", "lo2"]), lo),
            Ingress::Loopback
        );
        assert_eq!(
            ingress_of_interfaces(&v(&["eth0", "wlan0"]), lo),
            Ingress::External
        );
        assert_eq!(
            ingress_of_interfaces(&v(&["lo", "eth0"]), lo),
            Ingress::Unknown
        );
        assert!(is_loopback_interface("lo"));
        assert!(!is_loopback_interface("robodr-no-such-if0"));
        assert!(!is_loopback_interface(""));
        assert!(!is_loopback_interface("../lo"));
        assert!(!is_loopback_interface("lo/.."));
    }

    #[test]
    fn per_packet_ingress_overrides_the_static_tag() {
        use robodr_capture::IngressInfo;
        let lo_ip = Ipv4Addr::LOCALHOST;
        let ip = synth::ipv4_udp(lo_ip, lo_ip, 1, 7410, &rtps(4));
        let tag = |name: Option<&str>, lo: Option<bool>| IngressInfo {
            name: name.map(str::to_owned),
            loopback: lo,
            ..Default::default()
        };
        let frames = vec![
            (
                Duration::ZERO,
                LinkType::RAW,
                ip.clone(),
                tag(Some("lo"), Some(true)),
            ),
            (
                Duration::ZERO,
                LinkType::RAW,
                ip.clone(),
                tag(Some("eth0"), Some(false)),
            ),
            (Duration::ZERO, LinkType::RAW, ip.clone(), tag(None, None)),
            // tcpdump -i any (SLL2): the frame header decides.
            (
                Duration::ZERO,
                LinkType::LINUX_SLL2,
                synth::linux_sll2_on(2, 1, 0, 0x0800, &ip),
                tag(Some("any"), None),
            ),
        ];
        let mut s =
            CaptureDatagramSource::new(VecSource::with_ingress(frames), RtpsFilter::default())
                .with_ingress(Ingress::Loopback);
        let mut next = || {
            let d = s.recv().unwrap().unwrap();
            (d.ingress, d.interface)
        };
        assert_eq!(next(), (Ingress::Loopback, Some("lo".into())));
        assert_eq!(next(), (Ingress::External, Some("eth0".into())));
        assert_eq!(next(), (Ingress::Loopback, None), "fallback");
        assert_eq!(next(), (Ingress::External, None));
        assert!(s.recv().unwrap().is_none());
        let unknown = IngressInfo::default();
        assert_eq!(
            ingress_of_packet(&unknown, Ingress::Unknown),
            Ingress::Unknown
        );
    }

    /// Reports a fixed health snapshot, then its datagrams, then ends or fails.
    struct Scripted(VecDeque<Datagram>, Option<io::ErrorKind>, CaptureHealth);
    impl DatagramSource for Scripted {
        fn recv(&mut self) -> io::Result<Option<Datagram>> {
            match self.0.pop_front() {
                Some(d) => Ok(Some(d)),
                None => match self.1.take() {
                    Some(k) => Err(io::Error::new(k, "scripted")),
                    None => Ok(None),
                },
            }
        }
        fn capture_health(&self) -> Option<CaptureHealth> {
            Some(self.2)
        }
    }

    fn dgs(tag: &str, n: usize, ing: Ingress) -> VecDeque<Datagram> {
        (0..n)
            .map(|i| Datagram::new(vec![i as u8], tag).with_ingress(ing))
            .collect()
    }

    #[test]
    fn merged_source_interleaves_keeps_ingress_and_sums_health() {
        let stop = Arc::new(AtomicBool::new(false));
        let h = CaptureHealth {
            not_udp: 2,
            ..Default::default()
        };
        let mut m = MergedDatagramSource::new(
            vec![
                Box::new(Scripted(dgs("lo", 300, Ingress::Loopback), None, h)),
                Box::new(Scripted(dgs("eth", 300, Ingress::External), None, h)),
                Box::new(VecDatagramSource::default()),
            ],
            stop.clone(),
        )
        .unwrap();
        let (mut lo, mut eth) = (0, 0);
        while let Some(d) = m.recv().unwrap() {
            match d.src_ip.as_str() {
                "lo" => {
                    assert_eq!(d.ingress, Ingress::Loopback);
                    lo += 1
                }
                _ => {
                    assert_eq!(d.ingress, Ingress::External);
                    eth += 1
                }
            }
        }
        assert_eq!((lo, eth), (300, 300));
        assert!(m.recv().unwrap().is_none(), "ended stays ended");
        assert_eq!(m.capture_health().unwrap().not_udp, 4);
        assert!(!stop.load(Ordering::Relaxed));
        drop(m);
        assert!(stop.load(Ordering::Relaxed), "drop stops the sub-sources");
    }

    #[test]
    fn merged_source_reports_the_first_error_and_stops() {
        let stop = Arc::new(AtomicBool::new(false));
        let mut m = MergedDatagramSource::new(
            vec![Box::new(Scripted(
                dgs("a", 1, Ingress::Unknown),
                Some(io::ErrorKind::PermissionDenied),
                CaptureHealth::default(),
            ))],
            stop.clone(),
        )
        .unwrap();
        assert!(m.recv().unwrap().is_some());
        assert_eq!(
            m.recv().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(stop.load(Ordering::Relaxed));
        assert!(m.recv().unwrap().is_none());
        let mut empty = MergedDatagramSource::new(Vec::new(), stop).unwrap();
        assert!(empty.recv().unwrap().is_none());
        assert_eq!(empty.capture_health(), None);
    }

    #[test]
    fn error_kinds_map() {
        assert_eq!(
            capture_to_io(&CaptureError::Unsupported("x".into())).kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            capture_to_io(&CaptureError::Timeout).kind(),
            io::ErrorKind::TimedOut
        );
    }
}
