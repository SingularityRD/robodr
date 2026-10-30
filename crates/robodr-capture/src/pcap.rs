//! Capture-file readers: classic pcap and pcapng, plus a classic pcap writer.
//!
//! Both readers stream from any [`Read`] with bounded memory (one record or
//! block buffer, reused) and validate every length before allocating:
//!
//! - **pcap**: microsecond (`a1b2c3d4`) and nanosecond (`a1b23c4d`) magics in
//!   either byte order; version 2.x; link type from the low 16 bits of the
//!   header's link-type field (the upper bits carry FCS info, ignored). A
//!   record longer than [`MAX_RECORD_LEN`] is a format error (a corrupt length
//!   cannot be resynchronised); records longer than the header's snap length
//!   but within the limit are accepted, as some writers do that.
//! - **pcapng**: Section Header (either byte order, re-detected at every new
//!   section), Interface Description (link type, snap length, `if_tsresol`,
//!   `if_tsoffset` per interface), Enhanced Packet, Simple Packet and the
//!   obsolete Packet block. Unknown block types are skipped. Block lengths
//!   must be multiples of 4, at least 12, at most [`MAX_BLOCK_LEN`], and the
//!   trailing copy of the length must match.
//!
//! Interface ingress ([`crate::ingress`]): each packet reports the name of
//! its pcapng interface (`if_name`, cut to
//! [`crate::ingress::MAX_INTERFACE_NAME`] bytes) with a loopback flag
//! derived from that name, and the direction from the EPB's `epb_flags`
//! option when present. Classic pcap records no interface; name it with
//! [`PcapReader::with_interface`] / [`CaptureFile::with_default_interface`]
//! or the ingress stays unknown.
//!
//! A file that ends in the middle of a header or record yields
//! [`CaptureError::Truncated`] (everything before it has been delivered).
//! [`CaptureFile`] sniffs the magic and picks the right reader.

use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::Path;
use std::time::Duration;

use crate::decode::LinkType;
use crate::ingress::{bounded_name, loopback_by_name, IngressInfo, PacketType};
use crate::source::{CaptureError, Packet, PacketSource};

/// Largest classic pcap record we accept (256 KiB, matching libpcap's
/// `MAXIMUM_SNAPLEN`).
pub const MAX_RECORD_LEN: usize = 262_144;

/// Largest pcapng block we accept (record + generous room for options).
pub const MAX_BLOCK_LEN: usize = 4 << 20;

/// Most interfaces we track per pcapng section.
pub const MAX_INTERFACES: usize = 1 << 16;

const PCAP_MAGIC_US: u32 = 0xa1b2_c3d4;
const PCAP_MAGIC_NS: u32 = 0xa1b2_3c4d;
const PCAPNG_SHB: u32 = 0x0a0d_0d0a;
const PCAPNG_BOM: u32 = 0x1a2b_3c4d;
const PCAPNG_IDB: u32 = 1;
const PCAPNG_PB_OBSOLETE: u32 = 2;
const PCAPNG_SPB: u32 = 3;
const PCAPNG_EPB: u32 = 6;

/// Read exactly `buf.len()` bytes. `Ok(false)` on a clean EOF before the first
/// byte; [`CaptureError::Truncated`] on EOF part-way.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<bool, CaptureError> {
    let mut got = 0;
    while got < buf.len() {
        match r.read(buf.get_mut(got..).unwrap_or_default()) {
            Ok(0) if got == 0 => return Ok(false),
            Ok(0) => return Err(CaptureError::Truncated),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(true)
}

fn read_must<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<(), CaptureError> {
    if buf.is_empty() || read_full(r, buf)? {
        Ok(())
    } else {
        Err(CaptureError::Truncated)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u16(self, b: &[u8], at: usize) -> Result<u16, CaptureError> {
        let a = field(b, at)?;
        Ok(match self {
            Self::Little => u16::from_le_bytes(a),
            Self::Big => u16::from_be_bytes(a),
        })
    }
    fn u32(self, b: &[u8], at: usize) -> Result<u32, CaptureError> {
        let a = field(b, at)?;
        Ok(match self {
            Self::Little => u32::from_le_bytes(a),
            Self::Big => u32::from_be_bytes(a),
        })
    }
    fn u64(self, b: &[u8], at: usize) -> Result<u64, CaptureError> {
        let a = field(b, at)?;
        Ok(match self {
            Self::Little => u64::from_le_bytes(a),
            Self::Big => u64::from_be_bytes(a),
        })
    }
}

/// The `N` bytes of `b` at `at`; a field running past the end of its
/// header or block is a format error.
fn field<const N: usize>(b: &[u8], at: usize) -> Result<[u8; N], CaptureError> {
    b.get(at..)
        .and_then(|t| t.first_chunk::<N>())
        .copied()
        .ok_or_else(|| CaptureError::Format("field runs past the end of its block".into()))
}

// ---------------------------------------------------------------- classic pcap

/// Streaming reader for classic pcap files.
#[derive(Debug)]
pub struct PcapReader<R> {
    r: R,
    endian: Endian,
    nanos: bool,
    snaplen: u32,
    linktype: LinkType,
    buf: Vec<u8>,
    /// Classic pcap records carry no interface: whatever the caller says.
    interface: IngressInfo,
}

/// Ingress of a capture interface known only by name (capture files).
fn named_interface(name: &str) -> IngressInfo {
    IngressInfo {
        name: Some(bounded_name(name.as_bytes())),
        loopback: loopback_by_name(name),
        ..Default::default()
    }
}

impl<R: Read> PcapReader<R> {
    /// Read and check the global header.
    pub fn new(mut r: R) -> Result<Self, CaptureError> {
        let mut magic = [0u8; 4];
        read_must(&mut r, &mut magic)?;
        Self::after_magic(magic, r)
    }

    fn after_magic(magic: [u8; 4], mut r: R) -> Result<Self, CaptureError> {
        let (endian, nanos) = match (u32::from_le_bytes(magic), u32::from_be_bytes(magic)) {
            (PCAP_MAGIC_US, _) => (Endian::Little, false),
            (PCAP_MAGIC_NS, _) => (Endian::Little, true),
            (_, PCAP_MAGIC_US) => (Endian::Big, false),
            (_, PCAP_MAGIC_NS) => (Endian::Big, true),
            _ => return Err(CaptureError::Format("not a pcap file (bad magic)".into())),
        };
        let mut h = [0u8; 20];
        read_must(&mut r, &mut h)?;
        let major = endian.u16(&h, 0)?;
        if major != 2 {
            return Err(CaptureError::Format(format!(
                "unsupported pcap version {major}"
            )));
        }
        let snaplen = endian.u32(&h, 12)?;
        let linktype = LinkType(endian.u32(&h, 16)? & 0xffff);
        Ok(Self {
            r,
            endian,
            nanos,
            snaplen,
            linktype,
            buf: Vec::new(),
            interface: IngressInfo::default(),
        })
    }

    /// Name the (single) interface this classic pcap was captured on, e.g.
    /// `"lo"` or `"eth0"`; the loopback flag is derived from the name with
    /// [`loopback_by_name`]. The format does not record it, so without this
    /// every packet's ingress is unknown (except Linux cooked frames, whose
    /// header carries it).
    #[must_use]
    pub fn with_interface(mut self, name: &str) -> Self {
        self.interface = named_interface(name);
        self
    }

    /// Set the interface ingress explicitly (e.g. a loopback flag known from
    /// commissioning).
    #[must_use]
    pub fn with_ingress(mut self, ingress: IngressInfo) -> Self {
        self.interface = ingress;
        self
    }

    pub fn linktype(&self) -> LinkType {
        self.linktype
    }

    pub fn snaplen(&self) -> u32 {
        self.snaplen
    }

    /// Timestamps are nanosecond-resolution (`a1b23c4d` magic).
    pub fn is_nanosecond(&self) -> bool {
        self.nanos
    }
}

impl<R: Read> PacketSource for PcapReader<R> {
    fn next_packet(&mut self) -> Result<Option<Packet<'_>>, CaptureError> {
        let mut h = [0u8; 16];
        if !read_full(&mut self.r, &mut h)? {
            return Ok(None);
        }
        let e = self.endian;
        let sec = e.u32(&h, 0)?;
        let frac = e.u32(&h, 4)?;
        let incl = e.u32(&h, 8)? as usize;
        let orig = e.u32(&h, 12)?;
        if incl > MAX_RECORD_LEN {
            return Err(CaptureError::Format(format!(
                "record length {incl} exceeds {MAX_RECORD_LEN}"
            )));
        }
        self.buf.resize(incl, 0);
        read_must(&mut self.r, &mut self.buf)?;
        let frac_ns = if self.nanos {
            u64::from(frac)
        } else {
            u64::from(frac) * 1_000
        };
        let ts = Duration::from_secs(u64::from(sec)) + Duration::from_nanos(frac_ns);
        Ok(Some(Packet {
            ts,
            linktype: self.linktype,
            data: &self.buf,
            orig_len: orig,
            ingress: self.interface.as_packet_ingress(),
        }))
    }
}

/// Minimal classic pcap writer (little-endian). Writes to files or memory —
/// never to the network. Used for fixtures, fuzz seeds and evidence export.
#[derive(Debug)]
pub struct PcapWriter<W: Write> {
    w: W,
    nanos: bool,
}

impl<W: Write> PcapWriter<W> {
    /// Write the global header.
    pub fn new(mut w: W, linktype: LinkType, snaplen: u32, nanos: bool) -> io::Result<Self> {
        let magic = if nanos { PCAP_MAGIC_NS } else { PCAP_MAGIC_US };
        w.write_all(&magic.to_le_bytes())?;
        w.write_all(&2u16.to_le_bytes())?;
        w.write_all(&4u16.to_le_bytes())?;
        w.write_all(&0i32.to_le_bytes())?; // thiszone
        w.write_all(&0u32.to_le_bytes())?; // sigfigs
        w.write_all(&snaplen.to_le_bytes())?;
        w.write_all(&linktype.0.to_le_bytes())?;
        Ok(Self { w, nanos })
    }

    /// Append one record. Seconds beyond `u32::MAX` are an error.
    pub fn write_packet(&mut self, ts: Duration, data: &[u8], orig_len: u32) -> io::Result<()> {
        let sec = u32::try_from(ts.as_secs())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "timestamp past 2106"))?;
        let frac = if self.nanos {
            ts.subsec_nanos()
        } else {
            ts.subsec_micros()
        };
        let len = u32::try_from(data.len())
            .ok()
            .filter(|&l| l as usize <= MAX_RECORD_LEN)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "record too long"))?;
        self.w.write_all(&sec.to_le_bytes())?;
        self.w.write_all(&frac.to_le_bytes())?;
        self.w.write_all(&len.to_le_bytes())?;
        self.w.write_all(&orig_len.max(len).to_le_bytes())?;
        self.w.write_all(data)
    }

    pub fn into_inner(self) -> W {
        self.w
    }
}

// ---------------------------------------------------------------- pcapng

#[derive(Clone, Debug, PartialEq, Eq)]
struct Interface {
    linktype: LinkType,
    snaplen: u32,
    /// `if_tsresol` byte: MSB clear -> 10^-n, set -> 2^-n.
    tsresol: u8,
    tsoffset: i64,
    /// From `if_name` (or the reader's fallback name).
    ingress: IngressInfo,
}

/// Streaming reader for pcapng files.
#[derive(Debug)]
pub struct PcapNgReader<R> {
    r: R,
    endian: Endian,
    interfaces: Vec<Interface>,
    block: Vec<u8>,
    /// SHB magic already consumed by [`CaptureFile`] sniffing.
    pending_shb: bool,
    /// Ingress for interfaces without an `if_name` option.
    fallback: IngressInfo,
}

impl<R: Read> PcapNgReader<R> {
    /// The first block must be a Section Header Block.
    pub fn new(mut r: R) -> Result<Self, CaptureError> {
        let mut magic = [0u8; 4];
        read_must(&mut r, &mut magic)?;
        if u32::from_le_bytes(magic) != PCAPNG_SHB {
            return Err(CaptureError::Format("not a pcapng file".into()));
        }
        Ok(Self::after_magic(r))
    }

    fn after_magic(r: R) -> Self {
        Self {
            r,
            endian: Endian::Little,
            interfaces: Vec::new(),
            block: Vec::new(),
            pending_shb: true,
            fallback: IngressInfo::default(),
        }
    }

    /// Name for interfaces whose Interface Description Block has no
    /// `if_name` option (the loopback flag is derived from it with
    /// [`loopback_by_name`]). Applies to interfaces declared after the call.
    #[must_use]
    pub fn with_default_interface(mut self, name: &str) -> Self {
        self.fallback = named_interface(name);
        self
    }

    /// Link types of the interfaces declared so far in the current section.
    pub fn interfaces(&self) -> impl Iterator<Item = LinkType> + '_ {
        self.interfaces.iter().map(|i| i.linktype)
    }

    /// Ingress (name, loopback flag) of the interfaces declared so far in
    /// the current section, by interface id.
    pub fn interface_ingress(&self) -> impl Iterator<Item = &IngressInfo> + '_ {
        self.interfaces.iter().map(|i| &i.ingress)
    }

    /// Read the next block into `self.block` (whole block, header to trailer).
    /// Returns the block type, or `None` at clean EOF.
    fn read_block(&mut self) -> Result<Option<u32>, CaptureError> {
        let mut head = [0u8; 8];
        if self.pending_shb {
            self.pending_shb = false;
            head[..4].copy_from_slice(&PCAPNG_SHB.to_le_bytes());
            read_must(&mut self.r, &mut head[4..])?;
        } else if !read_full(&mut self.r, &mut head)? {
            return Ok(None);
        }
        let btype_le = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
        let mut prefix_len = 8;
        let mut bom = [0u8; 4];
        if btype_le == PCAPNG_SHB {
            read_must(&mut self.r, &mut bom)?;
            self.endian = if u32::from_le_bytes(bom) == PCAPNG_BOM {
                Endian::Little
            } else if u32::from_be_bytes(bom) == PCAPNG_BOM {
                Endian::Big
            } else {
                return Err(CaptureError::Format("bad pcapng byte-order magic".into()));
            };
            prefix_len = 12;
        }
        let e = self.endian;
        let btype = e.u32(&head, 0)?;
        let len = e.u32(&head, 4)? as usize;
        let min = if btype == PCAPNG_SHB { 28 } else { 12 };
        if !len.is_multiple_of(4) || len < min || len > MAX_BLOCK_LEN {
            return Err(CaptureError::Format(format!("bad block length {len}")));
        }
        self.block.clear();
        self.block.extend_from_slice(&head);
        if prefix_len == 12 {
            self.block.extend_from_slice(&bom);
        }
        self.block.resize(len, 0);
        // len >= min >= prefix_len, so the tail exists.
        read_must(
            &mut self.r,
            self.block.get_mut(prefix_len..).unwrap_or_default(),
        )?;
        if e.u32(&self.block, len - 4)? as usize != len {
            return Err(CaptureError::Format("block trailer length mismatch".into()));
        }
        Ok(Some(btype))
    }

    fn parse_shb(&mut self) -> Result<(), CaptureError> {
        let major = self.endian.u16(&self.block, 12)?;
        if major != 1 {
            return Err(CaptureError::Format(format!(
                "unsupported pcapng version {major}"
            )));
        }
        self.interfaces.clear();
        Ok(())
    }

    fn parse_idb(&mut self) -> Result<(), CaptureError> {
        let e = self.endian;
        let body = self
            .block
            .get(8..self.block.len().saturating_sub(4))
            .unwrap_or_default();
        if body.len() < 8 {
            return Err(CaptureError::Format(
                "short interface description block".into(),
            ));
        }
        let mut iface = Interface {
            linktype: LinkType(u32::from(e.u16(body, 0)?)),
            snaplen: e.u32(body, 4)?,
            tsresol: 6,
            tsoffset: 0,
            ingress: self.fallback.clone(),
        };
        let mut opts = body.get(8..).unwrap_or_default();
        while opts.len() >= 4 {
            let code = e.u16(opts, 0)?;
            let olen = usize::from(e.u16(opts, 2)?);
            if code == 0 {
                break; // opt_endofopt
            }
            let padded = (olen + 3) & !3;
            if 4 + padded > opts.len() {
                break; // truncated option list: keep what we have
            }
            let Some(val) = opts.get(4..4 + olen) else {
                break;
            };
            match code {
                2 if olen >= 1 => {
                    // if_name (UTF-8, not necessarily NUL-terminated).
                    let name = bounded_name(val);
                    iface.ingress = named_interface(&name);
                }
                9 if olen >= 1 => iface.tsresol = val.first().copied().unwrap_or(iface.tsresol),
                14 if olen >= 8 => iface.tsoffset = e.u64(val, 0)? as i64,
                _ => {}
            }
            opts = opts.get(4 + padded..).unwrap_or_default();
        }
        if self.interfaces.len() >= MAX_INTERFACES {
            return Err(CaptureError::Format("too many interfaces".into()));
        }
        self.interfaces.push(iface);
        Ok(())
    }

    fn iface(&self, id: usize) -> Result<&Interface, CaptureError> {
        self.interfaces
            .get(id)
            .ok_or_else(|| CaptureError::Format(format!("packet for undeclared interface {id}")))
    }
}

/// Convert a pcapng timestamp to time since the epoch. Resolutions finer than
/// 10^-38 s or 2^-127 s are rejected as nonsensical.
fn pcapng_ts(units: u64, tsresol: u8, tsoffset: i64) -> Result<Duration, CaptureError> {
    let exp = u32::from(tsresol & 0x7f);
    let nanos: u128 = if tsresol & 0x80 == 0 {
        if exp > 38 {
            return Err(CaptureError::Format(format!(
                "if_tsresol 10^-{exp} unsupported"
            )));
        }
        let scale = 10u128.pow(exp);
        u128::from(units) * 1_000_000_000 / scale
    } else {
        (u128::from(units) * 1_000_000_000) >> exp
    };
    let secs = (nanos / 1_000_000_000) as u64; // <= units, fits
    let sub = (nanos % 1_000_000_000) as u32;
    let secs = if tsoffset >= 0 {
        secs.saturating_add(tsoffset as u64)
    } else {
        secs.saturating_sub(tsoffset.unsigned_abs())
    };
    Ok(Duration::new(secs, sub))
}

/// pcapng `epb_flags` from an Enhanced Packet Block's options (`opts` =
/// the bytes after the padded packet data). Malformed options end the scan.
fn epb_flags(e: Endian, mut opts: &[u8]) -> Option<u32> {
    while opts.len() >= 4 {
        let code = e.u16(opts, 0).ok()?;
        let olen = usize::from(e.u16(opts, 2).ok()?);
        if code == 0 {
            return None; // opt_endofopt
        }
        let padded = (olen + 3) & !3;
        if 4 + padded > opts.len() {
            return None;
        }
        if code == 2 && olen == 4 {
            return e.u32(opts, 4).ok();
        }
        opts = opts.get(4 + padded..).unwrap_or_default();
    }
    None
}

impl<R: Read> PacketSource for PcapNgReader<R> {
    fn next_packet(&mut self) -> Result<Option<Packet<'_>>, CaptureError> {
        loop {
            let Some(btype) = self.read_block()? else {
                return Ok(None);
            };
            let e = self.endian;
            let blen = self.block.len();
            let body_end = blen - 4;
            // (iface id, ts, data range, orig_len, pkttype)
            let (id, ts, start, caplen, orig, pkttype) = match btype {
                PCAPNG_SHB => {
                    self.parse_shb()?;
                    continue;
                }
                PCAPNG_IDB => {
                    self.parse_idb()?;
                    continue;
                }
                PCAPNG_EPB | PCAPNG_PB_OBSOLETE => {
                    if body_end < 28 {
                        return Err(CaptureError::Format("short packet block".into()));
                    }
                    let b = &self.block;
                    let id = if btype == PCAPNG_EPB {
                        e.u32(b, 8)? as usize
                    } else {
                        usize::from(e.u16(b, 8)?)
                    };
                    let iface = self.iface(id)?;
                    let units = (u64::from(e.u32(b, 12)?) << 32) | u64::from(e.u32(b, 16)?);
                    let caplen = e.u32(b, 20)? as usize;
                    let orig = e.u32(b, 24)?;
                    if caplen > body_end - 28 {
                        return Err(CaptureError::Format("captured length exceeds block".into()));
                    }
                    let ts = pcapng_ts(units, iface.tsresol, iface.tsoffset)?;
                    let pkttype = if btype == PCAPNG_EPB {
                        let opts_at = (28 + caplen + 3) & !3;
                        b.get(opts_at..body_end)
                            .and_then(|o| epb_flags(e, o))
                            .and_then(PacketType::from_epb_flags)
                    } else {
                        None
                    };
                    (id, ts, 28, caplen, orig, pkttype)
                }
                PCAPNG_SPB => {
                    if body_end < 12 {
                        return Err(CaptureError::Format("short simple packet block".into()));
                    }
                    let iface = self.iface(0)?;
                    let orig = e.u32(&self.block, 8)?;
                    let mut caplen = (orig as usize).min(body_end - 12);
                    if iface.snaplen != 0 {
                        caplen = caplen.min(iface.snaplen as usize);
                    }
                    (0, Duration::ZERO, 12, caplen, orig, None)
                }
                _ => continue, // unknown / unneeded block: skip
            };
            let iface = self.iface(id)?;
            let mut ingress = iface.ingress.as_packet_ingress();
            ingress.pkttype = pkttype;
            return Ok(Some(Packet {
                ts,
                linktype: iface.linktype,
                data: self
                    .block
                    .get(start..start + caplen)
                    .ok_or_else(|| CaptureError::Format("captured length exceeds block".into()))?,
                orig_len: orig,
                ingress,
            }));
        }
    }
}

// ---------------------------------------------------------------- auto-detect

/// A pcap or pcapng file, detected from its magic.
#[derive(Debug)]
pub enum CaptureFile<R> {
    Pcap(PcapReader<R>),
    PcapNg(PcapNgReader<R>),
}

impl<R: Read> CaptureFile<R> {
    pub fn new(mut r: R) -> Result<Self, CaptureError> {
        let mut magic = [0u8; 4];
        read_must(&mut r, &mut magic)?;
        if u32::from_le_bytes(magic) == PCAPNG_SHB {
            Ok(Self::PcapNg(PcapNgReader::after_magic(r)))
        } else {
            PcapReader::after_magic(magic, r).map(Self::Pcap)
        }
    }
}

impl<R> CaptureFile<R> {
    /// Name the capture interface where the file does not: the single
    /// interface of a classic pcap, or pcapng interfaces without `if_name`
    /// (see [`PcapReader::with_interface`] /
    /// [`PcapNgReader::with_default_interface`]).
    #[must_use]
    pub fn with_default_interface(self, name: &str) -> Self {
        match self {
            Self::Pcap(mut p) => {
                p.interface = named_interface(name);
                Self::Pcap(p)
            }
            Self::PcapNg(mut p) => {
                p.fallback = named_interface(name);
                Self::PcapNg(p)
            }
        }
    }
}

impl CaptureFile<BufReader<File>> {
    /// Open a capture file from disk.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CaptureError> {
        Self::new(BufReader::new(File::open(path)?))
    }
}

impl<R: Read> PacketSource for CaptureFile<R> {
    fn next_packet(&mut self) -> Result<Option<Packet<'_>>, CaptureError> {
        match self {
            Self::Pcap(p) => p.next_packet(),
            Self::PcapNg(p) => p.next_packet(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Build a pcapng file in memory in either byte order.
    pub(crate) struct NgBuilder {
        pub out: Vec<u8>,
        le: bool,
    }

    impl NgBuilder {
        pub fn new(le: bool) -> Self {
            let mut b = Self {
                out: Vec::new(),
                le,
            };
            b.shb();
            b
        }
        fn u16(&self, v: u16) -> [u8; 2] {
            if self.le {
                v.to_le_bytes()
            } else {
                v.to_be_bytes()
            }
        }
        fn u32(&self, v: u32) -> [u8; 4] {
            if self.le {
                v.to_le_bytes()
            } else {
                v.to_be_bytes()
            }
        }
        pub fn block(&mut self, btype: u32, body: &[u8]) {
            let mut body = body.to_vec();
            while !body.len().is_multiple_of(4) {
                body.push(0);
            }
            let len = (12 + body.len()) as u32;
            let t = self.u32(btype);
            let l = self.u32(len);
            self.out.extend_from_slice(&t);
            self.out.extend_from_slice(&l);
            self.out.extend_from_slice(&body);
            self.out.extend_from_slice(&l);
        }
        pub fn shb(&mut self) {
            let mut body = self.u32(PCAPNG_BOM).to_vec();
            body.extend_from_slice(&self.u16(1));
            body.extend_from_slice(&self.u16(0));
            body.extend_from_slice(&[0xff; 8]); // section length unknown (-1)
            self.block(PCAPNG_SHB, &body);
        }
        pub fn idb(
            &mut self,
            linktype: u16,
            snaplen: u32,
            tsresol: Option<u8>,
            tsoffset: Option<i64>,
        ) {
            let mut body = self.u16(linktype).to_vec();
            body.extend_from_slice(&[0, 0]);
            body.extend_from_slice(&self.u32(snaplen));
            if let Some(r) = tsresol {
                body.extend_from_slice(&self.u16(9));
                body.extend_from_slice(&self.u16(1));
                body.extend_from_slice(&[r, 0, 0, 0]);
            }
            if let Some(o) = tsoffset {
                body.extend_from_slice(&self.u16(14));
                body.extend_from_slice(&self.u16(8));
                let v = if self.le {
                    o.to_le_bytes()
                } else {
                    o.to_be_bytes()
                };
                body.extend_from_slice(&v);
            }
            body.extend_from_slice(&[0, 0, 0, 0]); // opt_endofopt
            self.block(PCAPNG_IDB, &body);
        }
        /// IDB with an `if_name` option.
        pub fn idb_named(&mut self, linktype: u16, name: &[u8]) {
            let mut body = self.u16(linktype).to_vec();
            body.extend_from_slice(&[0, 0]);
            body.extend_from_slice(&self.u32(0));
            body.extend_from_slice(&self.u16(2));
            body.extend_from_slice(&self.u16(name.len() as u16));
            body.extend_from_slice(name);
            while !body.len().is_multiple_of(4) {
                body.push(0);
            }
            body.extend_from_slice(&[0, 0, 0, 0]);
            self.block(PCAPNG_IDB, &body);
        }
        /// EPB with raw option bytes after the (padded) packet data.
        pub fn epb_opts(&mut self, iface: u32, data: &[u8], opts: &[u8]) {
            let mut body = self.u32(iface).to_vec();
            body.extend_from_slice(&[0; 8]);
            body.extend_from_slice(&self.u32(data.len() as u32));
            body.extend_from_slice(&self.u32(data.len() as u32));
            body.extend_from_slice(data);
            while !body.len().is_multiple_of(4) {
                body.push(0);
            }
            body.extend_from_slice(opts);
            self.block(PCAPNG_EPB, &body);
        }
        /// EPB with an `epb_flags` option.
        pub fn epb_flags(&mut self, iface: u32, data: &[u8], flags: u32) {
            let mut o = self.u16(2).to_vec();
            o.extend_from_slice(&self.u16(4));
            o.extend_from_slice(&self.u32(flags));
            o.extend_from_slice(&[0; 4]);
            self.epb_opts(iface, data, &o);
        }
        pub fn epb(&mut self, iface: u32, ts_units: u64, data: &[u8], orig: u32) {
            let mut body = self.u32(iface).to_vec();
            body.extend_from_slice(&self.u32((ts_units >> 32) as u32));
            body.extend_from_slice(&self.u32(ts_units as u32));
            body.extend_from_slice(&self.u32(data.len() as u32));
            body.extend_from_slice(&self.u32(orig));
            body.extend_from_slice(data);
            self.block(PCAPNG_EPB, &body);
        }
        pub fn spb(&mut self, data: &[u8], orig: u32) {
            let mut body = self.u32(orig).to_vec();
            body.extend_from_slice(data);
            self.block(PCAPNG_SPB, &body);
        }
        pub fn obsolete_pb(&mut self, iface: u16, ts_units: u64, data: &[u8]) {
            let mut body = self.u16(iface).to_vec();
            body.extend_from_slice(&self.u16(0));
            body.extend_from_slice(&self.u32((ts_units >> 32) as u32));
            body.extend_from_slice(&self.u32(ts_units as u32));
            body.extend_from_slice(&self.u32(data.len() as u32));
            body.extend_from_slice(&self.u32(data.len() as u32));
            body.extend_from_slice(data);
            self.block(PCAPNG_PB_OBSOLETE, &body);
        }
    }

    /// Classic pcap built by hand in either byte order.
    pub(crate) fn classic(
        le: bool,
        nanos: bool,
        linktype: u32,
        snaplen: u32,
        recs: &[(u32, u32, &[u8], u32)],
    ) -> Vec<u8> {
        let w32 = |v: u32| if le { v.to_le_bytes() } else { v.to_be_bytes() };
        let w16 = |v: u16| if le { v.to_le_bytes() } else { v.to_be_bytes() };
        let mut out = w32(if nanos { PCAP_MAGIC_NS } else { PCAP_MAGIC_US }).to_vec();
        out.extend_from_slice(&w16(2));
        out.extend_from_slice(&w16(4));
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(&w32(snaplen));
        out.extend_from_slice(&w32(linktype));
        for &(sec, frac, data, orig) in recs {
            out.extend_from_slice(&w32(sec));
            out.extend_from_slice(&w32(frac));
            out.extend_from_slice(&w32(data.len() as u32));
            out.extend_from_slice(&w32(orig));
            out.extend_from_slice(data);
        }
        out
    }

    type Collected = (
        Vec<(Duration, LinkType, Vec<u8>, u32)>,
        Option<CaptureError>,
    );

    fn collect<S: PacketSource>(mut s: S) -> Collected {
        let mut v = Vec::new();
        loop {
            match s.next_packet() {
                Ok(Some(p)) => v.push((p.ts, p.linktype, p.data.to_vec(), p.orig_len)),
                Ok(None) => return (v, None),
                Err(e) => return (v, Some(e)),
            }
        }
    }

    #[test]
    fn classic_all_four_magics() {
        for le in [true, false] {
            for nanos in [false, true] {
                let f = classic(
                    le,
                    nanos,
                    1,
                    65535,
                    &[(10, 500, b"abc", 3), (11, 0, b"", 0)],
                );
                let r = PcapReader::new(&f[..]).unwrap();
                assert_eq!(r.linktype(), LinkType::ETHERNET);
                assert_eq!(r.snaplen(), 65535);
                assert_eq!(r.is_nanosecond(), nanos);
                let (pkts, err) = collect(r);
                assert!(err.is_none());
                assert_eq!(pkts.len(), 2);
                let sub = if nanos { 500 } else { 500_000 };
                assert_eq!(pkts[0].0, Duration::new(10, sub));
                assert_eq!(pkts[0].2, b"abc");
                assert_eq!(pkts[1].2, b"");
            }
        }
    }

    #[test]
    fn classic_snaplen_and_fcs_bits() {
        // Link type with FCS bits set in the upper half.
        let f = classic(true, false, 0x1000_0001, 4, &[(1, 0, b"abcd", 100)]);
        let mut r = PcapReader::new(&f[..]).unwrap();
        assert_eq!(r.linktype(), LinkType::ETHERNET);
        let p = r.next_packet().unwrap().unwrap();
        assert!(p.is_truncated());
        assert_eq!(p.orig_len, 100);
    }

    #[test]
    fn classic_truncations() {
        let f = classic(
            true,
            false,
            1,
            65535,
            &[(1, 0, b"abcdef", 6), (2, 0, b"ghijkl", 6)],
        );
        // Header cut anywhere: error at construction.
        for cut in 0..24 {
            assert!(PcapReader::new(&f[..cut]).is_err(), "cut {cut}");
        }
        // Cut inside the second record: first delivered, then Truncated.
        for cut in 24 + 22 + 1..f.len() {
            let (pkts, err) = collect(PcapReader::new(&f[..cut]).unwrap());
            assert_eq!(pkts.len(), 1, "cut {cut}");
            assert!(matches!(err, Some(CaptureError::Truncated)), "cut {cut}");
        }
        // Cut exactly at a record boundary is a clean end.
        let (pkts, err) = collect(PcapReader::new(&f[..24 + 22]).unwrap());
        assert_eq!(pkts.len(), 1);
        assert!(err.is_none());
    }

    #[test]
    fn classic_bogus_lengths_and_headers() {
        let mut f = classic(true, false, 1, 65535, &[(1, 0, b"abc", 3)]);
        f[24 + 8..24 + 12].copy_from_slice(&u32::MAX.to_le_bytes());
        let (_, err) = collect(PcapReader::new(&f[..]).unwrap());
        assert!(matches!(err, Some(CaptureError::Format(_))));
        let mut bad_ver = classic(true, false, 1, 65535, &[]);
        bad_ver[4] = 9;
        assert!(matches!(
            PcapReader::new(&bad_ver[..]),
            Err(CaptureError::Format(_))
        ));
        assert!(matches!(
            PcapReader::new(&b"nope nope nope nope nope"[..]),
            Err(CaptureError::Format(_))
        ));
    }

    #[test]
    fn writer_roundtrip() {
        for nanos in [false, true] {
            let mut w = PcapWriter::new(Vec::new(), LinkType::RAW, 65535, nanos).unwrap();
            w.write_packet(Duration::new(1_700_000_000, 123_456_789), b"hello", 5)
                .unwrap();
            w.write_packet(Duration::new(5, 0), b"", 0).unwrap();
            let bytes = w.into_inner();
            let (pkts, err) = collect(CaptureFile::new(&bytes[..]).unwrap());
            assert!(err.is_none());
            assert_eq!(pkts[0].1, LinkType::RAW);
            assert_eq!(pkts[0].2, b"hello");
            let want = if nanos { 123_456_789 } else { 123_456_000 };
            assert_eq!(pkts[0].0, Duration::new(1_700_000_000, want));
        }
        let mut w = PcapWriter::new(Vec::new(), LinkType::RAW, 65535, false).unwrap();
        assert!(w
            .write_packet(Duration::from_secs(1 << 33), b"", 0)
            .is_err());
        assert!(w
            .write_packet(Duration::ZERO, &vec![0; MAX_RECORD_LEN + 1], 0)
            .is_err());
    }

    #[test]
    fn pcapng_both_endiannesses_and_block_types() {
        for le in [true, false] {
            let mut b = NgBuilder::new(le);
            b.block(0xbad_c0de, b"unknown block is skipped");
            b.idb(1, 0, None, None); // iface 0: Ethernet, microseconds
            b.idb(113, 65535, Some(9), Some(10)); // iface 1: SLL, ns, +10 s
            b.idb(101, 4, Some(0x80 | 10), None); // iface 2: RAW, 2^-10 s
            b.epb(0, 1_500_000, b"eth-frame", 9);
            b.epb(1, 2_000_000_001, b"sll", 3);
            b.epb(2, 2048 + 512, b"raw!", 10);
            b.spb(b"simple-packet", 13);
            b.obsolete_pb(1, 7, b"old");
            let (pkts, err) = collect(CaptureFile::new(&b.out[..]).unwrap());
            assert!(err.is_none(), "{err:?}");
            assert_eq!(pkts.len(), 5);
            assert_eq!(
                pkts[0],
                (
                    Duration::new(1, 500_000_000),
                    LinkType::ETHERNET,
                    b"eth-frame".to_vec(),
                    9
                )
            );
            assert_eq!(pkts[1].0, Duration::new(12, 1));
            assert_eq!(pkts[1].1, LinkType::LINUX_SLL);
            assert_eq!(pkts[2].0, Duration::new(2, 500_000_000));
            assert_eq!(pkts[2].1, LinkType::RAW);
            // SPB: interface 0, no timestamp, snaplen 0 = unlimited.
            assert_eq!(
                pkts[3],
                (
                    Duration::ZERO,
                    LinkType::ETHERNET,
                    b"simple-packet".to_vec(),
                    13
                )
            );
            assert_eq!(pkts[4].2, b"old");
            assert_eq!(pkts[4].0, Duration::new(10, 7));
        }
    }

    #[test]
    fn pcapng_new_section_resets_interfaces_and_endianness() {
        let mut b = NgBuilder::new(true);
        b.idb(1, 0, None, None);
        b.epb(0, 1, b"a", 1);
        let mut b2 = NgBuilder::new(false);
        b2.idb(101, 0, None, None);
        b2.epb(0, 1, b"b", 1);
        b2.epb(1, 1, b"bad", 3); // interface 1 does not exist in section 2
        let mut file = b.out;
        file.extend_from_slice(&b2.out);
        let mut r = PcapNgReader::new(&file[..]).unwrap();
        assert_eq!(
            r.next_packet().unwrap().unwrap().linktype,
            LinkType::ETHERNET
        );
        assert_eq!(r.next_packet().unwrap().unwrap().linktype, LinkType::RAW);
        assert_eq!(r.interfaces().count(), 1);
        assert!(matches!(r.next_packet(), Err(CaptureError::Format(_))));
    }

    #[test]
    fn pcapng_spb_respects_snaplen() {
        let mut b = NgBuilder::new(true);
        b.idb(1, 4, None, None);
        b.spb(b"abcdefgh", 8);
        let (pkts, _) = collect(PcapNgReader::new(&b.out[..]).unwrap());
        assert_eq!(pkts[0].2, b"abcd");
        assert_eq!(pkts[0].3, 8);
    }

    #[test]
    fn pcapng_truncations_and_bogus_lengths() {
        let mut b = NgBuilder::new(true);
        b.idb(1, 0, None, None);
        b.epb(0, 1, b"payload!", 8);
        let full = b.out.clone();
        // SHB is 28 bytes, IDB 24: cutting exactly there is a clean (empty)
        // end; anywhere else inside a block is Truncated.
        for cut in 4..full.len() {
            let (pkts, err) = collect(PcapNgReader::new(&full[..cut]).unwrap());
            assert!(pkts.is_empty(), "cut {cut}");
            if cut == 28 || cut == 52 {
                assert!(err.is_none(), "cut {cut}: {err:?}");
            } else {
                assert!(
                    matches!(err, Some(CaptureError::Truncated)),
                    "cut {cut}: {err:?}"
                );
            }
        }
        assert_eq!(collect(PcapNgReader::new(&full[..]).unwrap()).0.len(), 1);
        // Block length not a multiple of 4.
        let mut bad = full.clone();
        bad[4] = 29;
        assert!(matches!(
            collect(PcapNgReader::new(&bad[..]).unwrap()).1,
            Some(CaptureError::Format(_))
        ));
        // Huge block length.
        let mut huge = full.clone();
        huge[4..8].copy_from_slice(&0x7fff_fff0u32.to_le_bytes());
        assert!(matches!(
            collect(PcapNgReader::new(&huge[..]).unwrap()).1,
            Some(CaptureError::Format(_))
        ));
        // Trailer mismatch on the EPB.
        let mut trailer = full.clone();
        let n = trailer.len();
        trailer[n - 4] ^= 0x10;
        assert!(matches!(
            collect(PcapNgReader::new(&trailer[..]).unwrap()).1,
            Some(CaptureError::Format(_))
        ));
        // Captured length larger than the block.
        let epb_at = full.len() - 12 - 20 - 8;
        let mut cap = full.clone();
        cap[epb_at + 20..epb_at + 24].copy_from_slice(&1000u32.to_le_bytes());
        assert!(matches!(
            collect(PcapNgReader::new(&cap[..]).unwrap()).1,
            Some(CaptureError::Format(_))
        ));
        // Bad byte-order magic.
        let mut bom = full;
        bom[8] = 0;
        assert!(matches!(
            collect(PcapNgReader::new(&bom[..]).unwrap()).1,
            Some(CaptureError::Format(_))
        ));
        // Packet before any interface.
        let mut noif = NgBuilder::new(true);
        noif.epb(0, 1, b"x", 1);
        assert!(matches!(
            collect(PcapNgReader::new(&noif.out[..]).unwrap()).1,
            Some(CaptureError::Format(_))
        ));
        // Not pcapng at all.
        assert!(PcapNgReader::new(&b"\xd4\xc3\xb2\xa1"[..]).is_err());
    }

    #[test]
    fn pcapng_timestamp_conversion() {
        assert_eq!(pcapng_ts(1_000_001, 6, 0).unwrap(), Duration::new(1, 1_000));
        assert_eq!(pcapng_ts(1, 9, 0).unwrap(), Duration::new(0, 1));
        assert_eq!(pcapng_ts(10, 10, 0).unwrap(), Duration::new(0, 1));
        assert_eq!(pcapng_ts(3, 0, 0).unwrap(), Duration::new(3, 0));
        assert_eq!(
            pcapng_ts(1 << 20, 0x80 | 20, 0).unwrap(),
            Duration::new(1, 0)
        );
        assert_eq!(
            pcapng_ts(u64::MAX, 0, i64::MAX).unwrap().as_secs(),
            u64::MAX
        );
        assert_eq!(pcapng_ts(5, 0, -100).unwrap(), Duration::ZERO);
        assert!(pcapng_ts(1, 39, 0).is_err());
        assert!(pcapng_ts(u64::MAX, 0x80 | 127, 0).is_ok());
        assert!(pcapng_ts(u64::MAX, 38, 0).is_ok());
    }

    type WithIngress = Vec<(LinkType, Vec<u8>, IngressInfo)>;

    fn collect_ingress<S: PacketSource>(mut s: S) -> (WithIngress, Option<CaptureError>) {
        let mut v = Vec::new();
        loop {
            match s.next_packet() {
                Ok(Some(p)) => v.push((p.linktype, p.data.to_vec(), p.ingress.to_info())),
                Ok(None) => return (v, None),
                Err(e) => return (v, Some(e)),
            }
        }
    }

    fn named(name: &str, lo: Option<bool>, pt: Option<PacketType>) -> IngressInfo {
        IngressInfo {
            ifindex: None,
            name: Some(name.into()),
            loopback: lo,
            pkttype: pt,
        }
    }

    #[test]
    fn pcapng_per_interface_ingress_and_epb_flags() {
        for le in [true, false] {
            let mut b = NgBuilder::new(le);
            b.idb_named(1, b"lo"); // 0
            b.idb_named(1, b"eth0"); // 1
            b.idb_named(276, b"any"); // 2
            b.idb(101, 0, None, None); // 3: no name
            b.idb_named(1, b"eth1\0\0"); // 4: NUL-padded name
            b.epb(0, 1, b"a", 1);
            b.epb(1, 1, b"b", 1);
            b.epb_flags(1, b"c", 2); // outbound
            b.epb_flags(0, b"d", 1 | (1 << 2)); // inbound unicast
            b.epb(2, 1, b"e", 1);
            b.epb(3, 1, b"f", 1);
            b.epb(4, 1, b"g", 1);
            b.obsolete_pb(1, 1, b"h");
            let (pkts, err) = collect_ingress(CaptureFile::new(&b.out[..]).unwrap());
            assert!(err.is_none(), "{err:?}");
            let ing: Vec<_> = pkts.iter().map(|p| p.2.clone()).collect();
            assert_eq!(ing[0], named("lo", Some(true), None));
            assert_eq!(ing[1], named("eth0", Some(false), None));
            assert_eq!(
                ing[2],
                named("eth0", Some(false), Some(PacketType::Outgoing))
            );
            assert_eq!(ing[3], named("lo", Some(true), Some(PacketType::Host)));
            // "any" is passed through here; the pipeline resolves it with
            // the cooked header (crate::ingress::resolve).
            assert_eq!(ing[4], named("any", None, None));
            assert!(ing[5].is_unknown());
            assert_eq!(ing[6], named("eth1", Some(false), None));
            assert_eq!(ing[7], named("eth0", Some(false), None));
            assert_eq!(pkts[4].0, LinkType::LINUX_SLL2);
        }
    }

    #[test]
    fn pcapng_fallback_name_and_hostile_options() {
        let mut b = NgBuilder::new(true);
        b.idb(1, 0, None, None);
        b.idb_named(1, &[b'x'; 200]);
        b.epb(0, 1, b"a", 1);
        b.epb(1, 1, b"b", 1);
        // Option length running past the block: ignored, no panic.
        b.epb_opts(0, b"c", &[2, 0, 0xff, 0x7f, 1, 0, 0, 0]);
        // Unknown option, then flags.
        b.epb_opts(
            0,
            b"d",
            &[9, 0, 1, 0, 7, 0, 0, 0, 2, 0, 4, 0, 2, 0, 0, 0, 0, 0, 0, 0],
        );
        // epb_flags of the wrong length: ignored.
        b.epb_opts(0, b"e", &[2, 0, 2, 0, 2, 0, 0, 0]);
        b.spb(b"spb", 3);
        let r = PcapNgReader::new(&b.out[..])
            .unwrap()
            .with_default_interface("lo0");
        let (pkts, err) = collect_ingress(r);
        assert!(err.is_none(), "{err:?}");
        assert_eq!(pkts[0].2, named("lo0", Some(true), None));
        assert_eq!(
            pkts[1].2.name.as_deref().map(str::len),
            Some(crate::ingress::MAX_INTERFACE_NAME)
        );
        assert_eq!(pkts[2].2.pkttype, None);
        assert_eq!(pkts[3].2.pkttype, Some(PacketType::Outgoing));
        assert_eq!(pkts[4].2.pkttype, None);
        assert_eq!(pkts[5].2, named("lo0", Some(true), None));
        let r = PcapNgReader::new(&b.out[..]).unwrap();
        let (pkts, _) = collect_ingress(r);
        assert!(pkts[0].2.is_unknown());
    }

    #[test]
    fn classic_pcap_interface_only_when_configured() {
        let f = classic(true, false, 1, 65535, &[(1, 0, b"abc", 3)]);
        let (pkts, _) = collect_ingress(PcapReader::new(&f[..]).unwrap());
        assert!(pkts[0].2.is_unknown());
        let (pkts, _) = collect_ingress(PcapReader::new(&f[..]).unwrap().with_interface("eth0"));
        assert_eq!(pkts[0].2, named("eth0", Some(false), None));
        let (pkts, _) = collect_ingress(
            CaptureFile::new(&f[..])
                .unwrap()
                .with_default_interface("lo"),
        );
        assert_eq!(pkts[0].2, named("lo", Some(true), None));
        let custom = IngressInfo {
            ifindex: Some(3),
            loopback: Some(true),
            ..Default::default()
        };
        let (pkts, _) = collect_ingress(
            PcapReader::new(&f[..])
                .unwrap()
                .with_ingress(custom.clone()),
        );
        assert_eq!(pkts[0].2, custom);
    }

    #[test]
    fn capture_file_autodetects_and_rejects() {
        assert!(matches!(
            CaptureFile::new(&b"\x00\x01\x02\x03rest-of-file-here....."[..]),
            Err(CaptureError::Format(_))
        ));
        assert!(matches!(
            CaptureFile::new(&b"ab"[..]),
            Err(CaptureError::Truncated)
        ));
        let f = classic(false, true, 276, 65535, &[(1, 2, b"x", 1)]);
        let (pkts, _) = collect(CaptureFile::new(&f[..]).unwrap());
        assert_eq!(pkts[0].1, LinkType::LINUX_SLL2);
        assert!(CaptureFile::open("/nonexistent/robodr.pcap").is_err());
    }
}
