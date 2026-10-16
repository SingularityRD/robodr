//! The [`PacketSource`] abstraction shared by file replay and live capture.

use std::fmt;
use std::io;
use std::time::Duration;

use crate::decode::LinkType;
use crate::ingress::{IngressInfo, PacketIngress};

/// One captured frame, borrowed from the source's internal buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Packet<'a> {
    /// Capture time since the Unix epoch. Zero when the format carries none
    /// (pcapng Simple Packet Blocks).
    pub ts: Duration,
    pub linktype: LinkType,
    /// The captured bytes (possibly fewer than `orig_len`: snap length).
    pub data: &'a [u8],
    /// Length of the frame on the wire.
    pub orig_len: u32,
    /// What the source knows about the interface the frame was captured on
    /// (see [`crate::ingress`]). All `None` when it knows nothing.
    pub ingress: PacketIngress<'a>,
}

impl Packet<'_> {
    /// The capture kept fewer bytes than were on the wire.
    pub fn is_truncated(&self) -> bool {
        (self.data.len() as u64) < u64::from(self.orig_len)
    }
}

/// Errors from a packet source.
#[derive(Debug)]
pub enum CaptureError {
    /// Underlying I/O error.
    Io(io::Error),
    /// Opening a live capture needs `CAP_NET_RAW` (or root).
    PermissionDenied(String),
    /// The file is not a capture we understand, or is corrupt beyond resync.
    Format(String),
    /// The file ends in the middle of a header or record.
    Truncated,
    /// A live read timed out with no packet (transient; read again).
    Timeout,
    /// Something this build does not support (e.g. a named interface absent).
    Unsupported(String),
}

impl CaptureError {
    /// True for errors after which reading again may succeed (timeouts).
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Timeout)
    }
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::PermissionDenied(m) => write!(f, "permission denied: {m}"),
            Self::Format(m) => write!(f, "bad capture file: {m}"),
            Self::Truncated => f.write_str("capture file truncated mid-record"),
            Self::Timeout => f.write_str("read timed out"),
            Self::Unsupported(m) => write!(f, "unsupported: {m}"),
        }
    }
}

impl std::error::Error for CaptureError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for CaptureError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Anything that yields captured frames: a pcap/pcapng file, a live
/// `AF_PACKET` socket, or a test vector.
///
/// Contract: `Ok(Some(packet))` is the next frame; `Ok(None)` is the end of
/// the stream (files only — a live source never ends on its own); `Err` with
/// [`CaptureError::is_transient`] (a live read timeout) means "nothing yet,
/// call again"; any other `Err` is fatal for that source.
///
/// The returned packet borrows the source's buffer, so it must be dropped
/// before the next call (a "lending iterator").
pub trait PacketSource {
    fn next_packet(&mut self) -> Result<Option<Packet<'_>>, CaptureError>;
}

impl<S: PacketSource + ?Sized> PacketSource for &mut S {
    fn next_packet(&mut self) -> Result<Option<Packet<'_>>, CaptureError> {
        (**self).next_packet()
    }
}

impl<S: PacketSource + ?Sized> PacketSource for Box<S> {
    fn next_packet(&mut self) -> Result<Option<Packet<'_>>, CaptureError> {
        (**self).next_packet()
    }
}

/// An in-memory list of owned frames; handy for tests and for replaying
/// frames obtained elsewhere.
#[derive(Clone, Debug, Default)]
pub struct VecSource {
    frames: std::collections::VecDeque<(Duration, LinkType, Vec<u8>, IngressInfo)>,
    current: Option<(Duration, LinkType, Vec<u8>, IngressInfo)>,
}

impl VecSource {
    /// Frames without ingress information.
    pub fn new(frames: impl IntoIterator<Item = (Duration, LinkType, Vec<u8>)>) -> Self {
        Self::with_ingress(
            frames
                .into_iter()
                .map(|(ts, lt, d)| (ts, lt, d, IngressInfo::default())),
        )
    }

    /// Frames each tagged with the interface it was captured on.
    pub fn with_ingress(
        frames: impl IntoIterator<Item = (Duration, LinkType, Vec<u8>, IngressInfo)>,
    ) -> Self {
        Self {
            frames: frames.into_iter().collect(),
            current: None,
        }
    }
}

impl PacketSource for VecSource {
    fn next_packet(&mut self) -> Result<Option<Packet<'_>>, CaptureError> {
        self.current = self.frames.pop_front();
        Ok(self.current.as_ref().map(|(ts, lt, data, ing)| Packet {
            ts: *ts,
            linktype: *lt,
            data,
            orig_len: u32::try_from(data.len()).unwrap_or(u32::MAX),
            ingress: ing.as_packet_ingress(),
        }))
    }
}
