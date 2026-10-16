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
//! The SPDP multicast socket ([`crate::socket`]) is used directly by the
//! async glue (tokio needs a non-blocking socket), not through this trait.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use robodr_capture::reassembly::ReassemblyStats;
use robodr_capture::{
    CaptureError, CaptureFile, CaptureStats, MatchMode, PacketSource, RtpsDatagrams, RtpsFilter,
    RtpsPortMap,
};

/// One received datagram (UDP payload, starting at `RTPS`) with the source
/// IP it came from, as text (the form `robodr_rtps` reports).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    pub payload: Vec<u8>,
    pub src_ip: String,
}

impl Datagram {
    pub fn new(payload: Vec<u8>, src_ip: impl Into<String>) -> Self {
        Self {
            payload,
            src_ip: src_ip.into(),
        }
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
    // TODO(capture-hardening): the parallel robodr-capture work adds UDP
    // checksum-failure and eviction counters to CaptureStats. When they land,
    // add them here (e.g. a `udp_checksum_failures` field) and map them in
    // `from_stats` and in `Pipeline::capture_findings`. Not guessed now.
}

impl CaptureHealth {
    pub fn from_stats(c: &CaptureStats, r: &ReassemblyStats) -> Self {
        Self {
            truncated: c.truncated,
            malformed: c.malformed,
            ip_fragment_conflicts: r.dropped_overlap,
            ip_fragment_invalid: r.dropped_invalid,
            ip_fragment_timeouts: r.dropped_timeout,
            ip_fragment_evicted: r.dropped_capacity,
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
        }
    }

    /// Wrap a live packet source: also yields control after
    /// [`LIVE_FRAME_BUDGET`] non-RTPS frames.
    pub fn new_live(source: S, filter: RtpsFilter) -> Self {
        Self {
            inner: RtpsDatagrams::new(source, filter).with_frame_budget(LIVE_FRAME_BUDGET),
            stop: None,
            reported_end: false,
        }
    }

    /// Stop (return `Ok(None)`) at the next opportunity once `flag` is set.
    /// For a live source the latency is at most one read timeout.
    #[must_use]
    pub fn with_stop_flag(mut self, flag: Arc<AtomicBool>) -> Self {
        self.stop = Some(flag);
        self
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
        Ok(Self::new_live(src, filter))
    }
}

impl<S: PacketSource> DatagramSource for CaptureDatagramSource<S> {
    fn recv(&mut self) -> io::Result<Option<Datagram>> {
        loop {
            if self.stopped() || self.reported_end {
                return Ok(None);
            }
            if let Some(p) = self.inner.next_packet() {
                return Ok(Some(Datagram::new(p.payload, p.src.to_string())));
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
