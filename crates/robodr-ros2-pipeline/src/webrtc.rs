//! Go2 WebRTC control sessions: detection, classification and peer
//! attribution from what a passive sensor (or the inline gateway's
//! observe copy) can see **without breaking any cryptography**.
//!
//! The Go2 mobile app and the community clients drive the robot over
//! WebRTC: an SDP offer / answer exchanged over HTTP on the robot, then
//! ICE (STUN) connectivity checks, a DTLS handshake and SRTP media plus an
//! SCTP data channel inside DTLS, which carries the motion requests. Its
//! content is encrypted with keys negotiated in the DTLS handshake: a
//! sensor that does not terminate the session cannot read a single command,
//! and this module does not try to. What it does:
//!
//! * **Signalling** on the robot's signalling ports (default 8081 and 9991):
//!   the HTTP request line and headers of each segment, classified as the
//!   two methods community clients use (not published by Unitree; see
//!   "Sources" below):
//!   * `POST /offer` (port 8081, older firmware): the body is a JSON object
//!     with a **plaintext** SDP offer. Its metadata is read: ICE user
//!     fragment, DTLS fingerprint hash algorithm, candidate types and
//!     addresses, media sections. A `token` member is reported by presence
//!     and length only, never by value.
//!   * `POST /con_notify`, then `POST /con_ing_<suffix>` (port 9991, newer
//!     firmware): the robot answers `con_notify` with a public key, the
//!     client sends its SDP AES-encrypted under a key it wraps with that
//!     public key. Only the exchange itself is recorded (which step, body
//!     sizes, the JSON member names of the robot's base64 answer); the SDP
//!     is not readable.
//!   * a WebSocket upgrade or any other HTTP request on those ports.
//! * **ICE / STUN** (RFC 8489 / 8445): binding requests between a peer and
//!   the robot, their ICE username (`remote:local` user fragments, public
//!   in the protocol), `ICE-CONTROLLING` / `USE-CANDIDATE`, the FINGERPRINT
//!   CRC; TURN methods and ChannelData (a relayed, remote session).
//! * **DTLS** (RFC 6347 / 9147 record headers): `ClientHello` /
//!   `ServerHello` / `HelloVerifyRequest` in epoch 0, application data
//!   after the handshake. A session is **established** once both hellos
//!   (or application data in both directions) were seen.
//! * **SRTP / SRTCP** (RFC 7983 demultiplexing): counted, never decoded.
//!
//! [`WebRtcMonitor`] keeps one bounded record per peer (the host on the
//! other side of the robot's flows), attributes it by IP and, where the
//! capture has it, MAC, and raises the findings in [`rules`]. Each finding
//! names the peer and the flows (`peer ip:port <-> robot ip:port`), which is
//! what the inline gateway needs to block the session by flow
//! (`robodr-firewall-gw`, `webrtc` section).
//!
//! # Limits (be honest)
//!
//! * No command inside a WebRTC session is ever seen: a session from an
//!   allowed controller may still drive the robot anywhere. The findings are
//!   about **who** controls the robot over WebRTC and **when**, not what.
//! * Traffic over the robot's Wi-Fi or a cellular modem never crosses the
//!   Ethernet link the sensor watches; a remote session through Unitree's
//!   cloud relays shows up only as the robot's flows to the relay
//!   ([`rules::RELAYED_SESSION`]).
//! * The signalling formats come from community client code, not from
//!   Unitree's SDKs (which contain no WebRTC code); firmware updates may
//!   change ports, paths and bodies. Unknown signalling still shows as
//!   [`rules::MEDIA_WITHOUT_SIGNALLING`] once ICE / DTLS start.
//! * HTTP is read per TCP segment, without stream reassembly: a request
//!   line split over two segments, or an SDP body larger than one segment,
//!   is classified as "other" / without SDP metadata.
//! * Attribution is by IP and MAC, both forgeable on the same L2 segment.
//! * Not run against a real Go2: the parsers are checked against frames
//!   built from the RFCs and from the community clients' message shapes.
//!
//! # Sources
//!
//! Unitree's `unitree_sdk2`, `unitree_ros2` and `unitree_sdk2_python`
//! contain no WebRTC code. The signalling paths, ports and body shapes are
//! those of the community `go2_webrtc_connect` client (local STA / AP
//! connection methods); the AP-mode robot address 192.168.12.1 is from the
//! same client. STUN, TURN, DTLS, SRTP and SDP follow RFC 8489, RFC 8656,
//! RFC 6347, RFC 7983 and RFC 8866.
//!
//! Pure, bounded and panic-free: no I/O, no clock of its own, memory capped
//! by [`WebRtcOptions::max_peers`] and the per-peer limits.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use robodr_events::{Deviation, Severity};
use serde::Serialize;

/// Rule ids (`docs/contracts/robodr.findings.md`, catalog 2.3, Unitree
/// block).
pub mod rules {
    use robodr_events::Severity;

    /// A WebRTC session (Go2 signalling, ICE checks or a DTLS handshake) to
    /// the robot from a peer that is not a listed controller.
    pub const UNKNOWN_CONTROLLER: &str = "robot.unitree.webrtc_unknown_controller";
    /// No controller list is configured: a peer opened a WebRTC session to
    /// the robot for the first time (learn the controllers, then list them).
    pub const NEW_PEER: &str = "robot.unitree.webrtc_new_peer";
    /// A listed controller's IP was seen with another source MAC.
    pub const CONTROLLER_MAC_MISMATCH: &str = "robot.unitree.webrtc_controller_mac_mismatch";
    /// A WebRTC session was attempted or active during a denied window.
    pub const SESSION_IN_DENIED_WINDOW: &str = "robot.unitree.webrtc_session_in_denied_window";
    /// More WebRTC sessions were established at once than allowed (a second
    /// controller next to the operator's).
    pub const CONCURRENT_SESSIONS: &str = "robot.unitree.webrtc_concurrent_sessions";
    /// The robot's WebRTC traffic goes through a TURN relay or to a peer
    /// outside the local networks (remote control through a cloud relay).
    pub const RELAYED_SESSION: &str = "robot.unitree.webrtc_relayed_session";
    /// ICE / DTLS with a peer whose signalling was never seen on the
    /// watched link (signalled over another path, or unknown signalling).
    pub const MEDIA_WITHOUT_SIGNALLING: &str = "robot.unitree.webrtc_media_without_signalling";

    /// Every id with its default severity (the unknown-controller finding
    /// is Critical once its session is established).
    pub const ALL: [(&str, Severity); 7] = [
        (UNKNOWN_CONTROLLER, Severity::High),
        (NEW_PEER, Severity::Medium),
        (CONTROLLER_MAC_MISMATCH, Severity::High),
        (SESSION_IN_DENIED_WINDOW, Severity::High),
        (CONCURRENT_SESSIONS, Severity::High),
        (RELAYED_SESSION, Severity::Medium),
        (MEDIA_WITHOUT_SIGNALLING, Severity::Medium),
    ];
}

/// Default signalling ports: 8081 (`/offer`) and 9991 (`/con_notify`,
/// `/con_ing_*`), as used by community clients.
pub const DEFAULT_SIGNALLING_PORTS: [u16; 2] = [8081, 9991];

/// Most peers tracked at once (the oldest idle one is evicted first).
pub const DEFAULT_MAX_PEERS: usize = 64;
/// Most flows remembered per peer.
pub const MAX_FLOWS_PER_PEER: usize = 8;
/// Most (rule, key) pairs remembered for "report once"; beyond that a new
/// finding is counted in [`WebRtcStats::findings_suppressed`].
pub const MAX_REPORTED: usize = 1024;
/// Largest HTTP header section read (bytes).
pub const MAX_HTTP_HEADER: usize = 8192;
/// Largest signalling body inspected for SDP metadata (bytes).
pub const MAX_SIGNALLING_BODY: usize = 65536;
/// Most SDP candidates kept.
pub const MAX_CANDIDATES: usize = 16;

/// The robot's default WebRTC addresses: 192.168.123.161 (the Go2's
/// Ethernet address, `UDP_SERVER_IP_SPORT` of the SDKs' robot network)
/// and 192.168.12.1 (its access-point address, community clients).
pub fn default_robot_addresses() -> BTreeSet<IpAddr> {
    [
        Ipv4Addr::new(192, 168, 123, 161),
        Ipv4Addr::new(192, 168, 12, 1),
    ]
    .into_iter()
    .map(IpAddr::V4)
    .collect()
}

// ------------------------------------------------------------------ STUN

/// STUN message class (RFC 8489 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StunClass {
    Request,
    Indication,
    Success,
    Error,
}

/// STUN / TURN methods this module names (RFC 8489, RFC 8656).
pub mod stun_method {
    pub const BINDING: u16 = 0x001;
    pub const ALLOCATE: u16 = 0x003;
    pub const REFRESH: u16 = 0x004;
    pub const SEND: u16 = 0x006;
    pub const DATA: u16 = 0x007;
    pub const CREATE_PERMISSION: u16 = 0x008;
    pub const CHANNEL_BIND: u16 = 0x009;

    /// A TURN method (a relayed session).
    pub fn is_turn(m: u16) -> bool {
        matches!(
            m,
            ALLOCATE | REFRESH | SEND | DATA | CREATE_PERMISSION | CHANNEL_BIND
        )
    }
}

/// The parts of a STUN message this module uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stun<'a> {
    pub class: StunClass,
    pub method: u16,
    pub transaction_id: [u8; 12],
    /// `USERNAME` (ICE: `remote-ufrag:local-ufrag`), if valid UTF-8 and at
    /// most 513 bytes.
    pub username: Option<&'a str>,
    pub ice_controlling: bool,
    pub ice_controlled: bool,
    pub use_candidate: bool,
    pub message_integrity: bool,
    /// `FINGERPRINT` present: whether its CRC matches.
    pub fingerprint_ok: Option<bool>,
}

const STUN_COOKIE: u32 = 0x2112_A442;
const FINGERPRINT_XOR: u32 = 0x5354_554e;

fn be16(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([*s.first()?, *s.get(1)?]))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at.checked_add(4)?)?;
    let a: [u8; 4] = s.try_into().ok()?;
    Some(u32::from_be_bytes(a))
}

/// CRC-32 (ISO-HDLC, the STUN FINGERPRINT polynomial), bitwise: STUN
/// messages are small.
fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for b in data {
        crc ^= u32::from(*b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Parse a STUN message (strict: the length field must match the payload,
/// attributes must tile it exactly). `None` if it is not one.
pub fn parse_stun(p: &[u8]) -> Option<Stun<'_>> {
    let t = be16(p, 0)?;
    if t & 0xC000 != 0 {
        return None;
    }
    let len = usize::from(be16(p, 2)?);
    if be32(p, 4)? != STUN_COOKIE || len % 4 != 0 || p.len() != len.checked_add(20)? {
        return None;
    }
    let class = match ((t >> 7) & 0x2) | ((t >> 4) & 0x1) {
        0 => StunClass::Request,
        1 => StunClass::Indication,
        2 => StunClass::Success,
        _ => StunClass::Error,
    };
    let method = (t & 0x000F) | ((t & 0x00E0) >> 1) | ((t & 0x3E00) >> 2);
    let mut transaction_id = [0u8; 12];
    transaction_id.copy_from_slice(p.get(8..20)?);
    let mut s = Stun {
        class,
        method,
        transaction_id,
        username: None,
        ice_controlling: false,
        ice_controlled: false,
        use_candidate: false,
        message_integrity: false,
        fingerprint_ok: None,
    };
    let mut at = 20usize;
    let mut n = 0usize;
    while at < p.len() {
        n += 1;
        if n > 64 {
            return None;
        }
        let ty = be16(p, at)?;
        let alen = usize::from(be16(p, at + 2)?);
        let vstart = at + 4;
        let vend = vstart.checked_add(alen)?;
        let value = p.get(vstart..vend)?;
        let padded = vstart.checked_add(alen.div_ceil(4) * 4)?;
        if padded > p.len() {
            return None;
        }
        match ty {
            0x0006 if alen <= 513 => s.username = std::str::from_utf8(value).ok(),
            0x0008 => s.message_integrity = true,
            0x0025 => s.use_candidate = true,
            0x8029 => s.ice_controlled = true,
            0x802A => s.ice_controlling = true,
            0x8028 => {
                // FINGERPRINT must be last.
                if alen != 4 || padded != p.len() {
                    return None;
                }
                let want = crc32_ieee(p.get(..at)?) ^ FINGERPRINT_XOR;
                s.fingerprint_ok = Some(be32(value, 0)? == want);
            }
            _ => {}
        }
        at = padded;
    }
    Some(s)
}

// ------------------------------------------------------------------ DTLS

/// What the DTLS records of one datagram show (headers only).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct DtlsSummary {
    pub records: u16,
    pub client_hello: bool,
    pub server_hello: bool,
    pub hello_verify: bool,
    /// Application data (content type 23) or any record in an epoch > 0.
    pub encrypted: bool,
    pub alert: bool,
    /// A record header did not fit (the rest of the datagram ignored).
    pub truncated: bool,
}

/// Walk the DTLS records of a datagram (RFC 6347 header: type, version
/// `FE FF` / `FE FD`, epoch, 48-bit sequence, length). `None` if the first
/// record is not DTLS.
pub fn parse_dtls(p: &[u8]) -> Option<DtlsSummary> {
    let mut s = DtlsSummary::default();
    let mut at = 0usize;
    while at < p.len() {
        let ty = *p.get(at)?;
        let ver = be16(p, at + 1);
        let ok_hdr = (20..=26).contains(&ty) && matches!(ver, Some(0xFEFF) | Some(0xFEFD));
        if !ok_hdr {
            if s.records == 0 {
                return None;
            }
            s.truncated = true;
            break;
        }
        let (Some(epoch), Some(len)) = (be16(p, at + 3), be16(p, at + 11)) else {
            if s.records == 0 {
                return None;
            }
            s.truncated = true;
            break;
        };
        let body = at + 13;
        let end = body + usize::from(len);
        if end > p.len() {
            if s.records == 0 {
                return None;
            }
            s.truncated = true;
            break;
        }
        s.records = s.records.saturating_add(1);
        match ty {
            21 => s.alert = true,
            22 if epoch == 0 => match p.get(body) {
                Some(1) => s.client_hello = true,
                Some(2) => s.server_hello = true,
                Some(3) => s.hello_verify = true,
                _ => {}
            },
            23 => s.encrypted = true,
            _ => {}
        }
        if epoch > 0 {
            s.encrypted = true;
        }
        at = end;
    }
    (s.records > 0).then_some(s)
}

/// A UDP payload demultiplexed as RFC 7983 does by its first byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpClass<'a> {
    Stun(Stun<'a>),
    Dtls(DtlsSummary),
    /// TURN ChannelData (first byte 64..=79, RFC 8656 §12).
    ChannelData,
    /// RTP / RTCP (SRTP / SRTCP once keyed; first byte 128..=191).
    Rtp {
        rtcp: bool,
    },
    Other,
}

/// Classify one UDP payload.
pub fn classify_udp(p: &[u8]) -> UdpClass<'_> {
    match p.first() {
        Some(0..=3) => parse_stun(p).map_or(UdpClass::Other, UdpClass::Stun),
        Some(20..=63) => parse_dtls(p).map_or(UdpClass::Other, UdpClass::Dtls),
        Some(64..=79) => {
            let ok = be16(p, 2).is_some_and(|l| usize::from(l) + 4 <= p.len());
            if ok {
                UdpClass::ChannelData
            } else {
                UdpClass::Other
            }
        }
        Some(128..=191) if p.len() >= 8 => {
            let pt = p.get(1).copied().unwrap_or(0) & 0x7f;
            UdpClass::Rtp {
                rtcp: (64..=95).contains(&pt),
            }
        }
        _ => UdpClass::Other,
    }
}

// ------------------------------------------------------------------ HTTP

/// An HTTP/1.x request head found at the start of a TCP segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub host: Option<&'a str>,
    pub content_length: Option<usize>,
    pub websocket: bool,
    /// The bytes after the header section in this segment.
    pub body: &'a [u8],
}

/// An HTTP/1.x response head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse<'a> {
    pub status: u16,
    pub content_length: Option<usize>,
    pub body: &'a [u8],
}

fn http_head(p: &[u8]) -> Option<(Vec<&str>, &[u8])> {
    let lim = p.len().min(MAX_HTTP_HEADER);
    let head = p.get(..lim)?;
    let end = head.windows(4).position(|w| w == b"\r\n\r\n")?;
    let text = std::str::from_utf8(head.get(..end)?).ok()?;
    if !text
        .bytes()
        .all(|b| b == b'\r' || b == b'\n' || (0x20..0x7f).contains(&b) || b == b'\t')
    {
        return None;
    }
    let lines: Vec<&str> = text.split("\r\n").take(65).collect();
    if lines.len() > 64 {
        return None;
    }
    Some((lines, p.get(end + 4..).unwrap_or(&[])))
}

fn header<'a>(lines: &[&'a str], name: &str) -> Option<&'a str> {
    lines.iter().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// Parse the request head at the start of `p` (`None`: not an HTTP/1.x
/// request, or the head is not complete in this segment).
pub fn parse_http_request(p: &[u8]) -> Option<HttpRequest<'_>> {
    let (lines, body) = http_head(p)?;
    let mut rl = lines.first()?.split(' ');
    let method = rl.next()?;
    let path = rl.next()?;
    let ver = rl.next()?;
    if rl.next().is_some()
        || !ver.starts_with("HTTP/1.")
        || method.is_empty()
        || !method.bytes().all(|b| b.is_ascii_uppercase())
        || !path.starts_with('/')
    {
        return None;
    }
    let upgrade = header(&lines, "upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    Some(HttpRequest {
        method,
        path,
        host: header(&lines, "host"),
        content_length: header(&lines, "content-length").and_then(|v| v.parse().ok()),
        websocket: upgrade,
        body,
    })
}

/// Parse the response head at the start of `p`.
pub fn parse_http_response(p: &[u8]) -> Option<HttpResponse<'_>> {
    let (lines, body) = http_head(p)?;
    let mut sl = lines.first()?.splitn(3, ' ');
    let ver = sl.next()?;
    let code = sl.next()?;
    if !ver.starts_with("HTTP/1.") || code.len() != 3 {
        return None;
    }
    Some(HttpResponse {
        status: code.parse().ok()?,
        content_length: header(&lines, "content-length").and_then(|v| v.parse().ok()),
        body,
    })
}

// ------------------------------------------------------------ signalling

/// Which Go2 signalling step a request is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignallingKind {
    /// `POST /offer` with a plaintext SDP (older firmware, port 8081).
    LegacyOffer,
    /// `POST /con_notify` (key exchange start, port 9991).
    ConNotify,
    /// `POST /con_ing_<suffix>` (encrypted SDP offer, port 9991).
    ConIng,
    /// A WebSocket upgrade on a signalling port.
    WebSocket,
    /// Any other HTTP request on a signalling port.
    OtherHttp,
}

/// Metadata of a plaintext SDP (never the session keys: SDP has none, the
/// DTLS keys are negotiated in the handshake).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SdpMeta {
    /// `a=ice-ufrag` (public in ICE; at most 64 token characters).
    pub ice_ufrag: Option<String>,
    /// The hash algorithm of `a=fingerprint` (`sha-256`, ...).
    pub fingerprint_hash: Option<String>,
    /// `(type, address)` of each `a=candidate` (at most
    /// [`MAX_CANDIDATES`]): `host`, `srflx`, `prflx`, `relay`.
    pub candidates: Vec<(String, String)>,
    /// `m=` media kinds (`audio`, `video`, `application`).
    pub media: Vec<String>,
}

/// What a signalling request shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignallingMeta {
    pub kind: SignallingKind,
    pub body_len: usize,
    /// The offer's SDP (legacy method, body complete in the segment).
    pub sdp: Option<SdpMeta>,
    /// A `token` member was present (its value is never kept): its length.
    pub token_len: Option<usize>,
}

fn token_ok(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|b| b.is_ascii_graphic())
}

/// Read the metadata of an SDP (RFC 8866 lines; bounded).
pub fn parse_sdp(sdp: &str) -> SdpMeta {
    let mut m = SdpMeta::default();
    for line in sdp.lines().take(512) {
        let line = line.trim_end_matches('\r');
        if let Some(u) = line.strip_prefix("a=ice-ufrag:") {
            if token_ok(u, 64) && m.ice_ufrag.is_none() {
                m.ice_ufrag = Some(u.to_string());
            }
        } else if let Some(f) = line.strip_prefix("a=fingerprint:") {
            if let Some(alg) = f.split(' ').next() {
                if token_ok(alg, 16) && m.fingerprint_hash.is_none() {
                    m.fingerprint_hash = Some(alg.to_ascii_lowercase());
                }
            }
        } else if let Some(c) = line.strip_prefix("a=candidate:") {
            // foundation component transport priority address port typ TYPE
            let f: Vec<&str> = c.split(' ').collect();
            if let (Some(addr), Some(&"typ"), Some(ty)) = (f.get(4), f.get(6), f.get(7)) {
                if m.candidates.len() < MAX_CANDIDATES && token_ok(ty, 8) && token_ok(addr, 64) {
                    m.candidates.push((ty.to_string(), addr.to_string()));
                }
            }
        } else if let Some(media) = line.strip_prefix("m=") {
            if let Some(k) = media.split(' ').next() {
                if token_ok(k, 16) && m.media.len() < 8 {
                    m.media.push(k.to_string());
                }
            }
        }
    }
    m
}

/// Classify a request on a signalling port and read what is readable.
pub fn classify_signalling(req: &HttpRequest<'_>) -> SignallingMeta {
    let kind = if req.websocket {
        SignallingKind::WebSocket
    } else if req.method == "POST" && (req.path == "/offer" || req.path.starts_with("/offer?")) {
        SignallingKind::LegacyOffer
    } else if req.method == "POST" && req.path == "/con_notify" {
        SignallingKind::ConNotify
    } else if req.method == "POST" && req.path.starts_with("/con_ing_") {
        SignallingKind::ConIng
    } else {
        SignallingKind::OtherHttp
    };
    let mut meta = SignallingMeta {
        kind,
        body_len: req.content_length.unwrap_or(req.body.len()),
        sdp: None,
        token_len: None,
    };
    let complete = req.content_length.is_some_and(|l| l == req.body.len());
    if kind == SignallingKind::LegacyOffer && complete && req.body.len() <= MAX_SIGNALLING_BODY {
        if let Ok(serde_json::Value::Object(o)) = serde_json::from_slice(req.body) {
            if let Some(serde_json::Value::String(sdp)) = o.get("sdp") {
                meta.sdp = Some(parse_sdp(sdp));
            }
            if let Some(serde_json::Value::String(t)) = o.get("token") {
                meta.token_len = Some(t.len());
            }
        }
    }
    meta
}

/// Decode standard base64 (padding optional; whitespace refused).
pub fn base64_decode(s: &[u8]) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(u32::from(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        }))
    };
    let s = s
        .strip_suffix(b"==")
        .or_else(|| s.strip_suffix(b"="))
        .unwrap_or(s);
    if s.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3 + 2);
    for chunk in s.chunks(4) {
        let mut acc = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            acc |= val(*c)? << (18 - 6 * i);
        }
        let bytes = acc.to_be_bytes();
        let n = chunk.len().saturating_sub(1);
        out.extend_from_slice(bytes.get(1..1 + n)?);
    }
    Some(out)
}

/// The robot's answer to `con_notify`: base64 of a JSON object. Only its
/// member names and the length of each string member are returned (the
/// public key in it is not a secret, but nothing here needs it).
pub fn con_notify_answer_members(body: &[u8]) -> Option<Vec<(String, usize)>> {
    if body.len() > MAX_SIGNALLING_BODY {
        return None;
    }
    let raw = base64_decode(body.trim_ascii())?;
    let serde_json::Value::Object(o) = serde_json::from_slice(&raw).ok()? else {
        return None;
    };
    Some(
        o.iter()
            .take(16)
            .filter(|(k, _)| token_ok(k, 32))
            .map(|(k, v)| (k.clone(), v.as_str().map_or(0, str::len)))
            .collect(),
    )
}

// -------------------------------------------------------------- packets

/// Transport of a [`FlowPacket`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4 {
    Tcp,
    Udp,
}

/// One IP packet's flow and payload, as the monitor needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowPacket<'a> {
    /// Wall clock (Unix ns, UTC): deny windows.
    pub wall_ns: u64,
    /// Monotonic clock (ns): idle expiry.
    pub mono_ns: u64,
    pub l4: L4,
    pub src: IpAddr,
    pub src_port: u16,
    pub dst: IpAddr,
    pub dst_port: u16,
    /// The link-layer source, when the capture has it.
    pub src_mac: Option<[u8; 6]>,
    pub payload: &'a [u8],
}

/// `(transport, source, source port, destination, destination port,
/// payload)` of [`decode_ipv4`].
pub type Ipv4Flow<'a> = (L4, Ipv4Addr, u16, Ipv4Addr, u16, &'a [u8]);

/// Decode an IPv4 packet (no options walked beyond IHL, no fragments:
/// a fragment is `None`) into its TCP / UDP flow and payload.
pub fn decode_ipv4(p: &[u8]) -> Option<Ipv4Flow<'_>> {
    let vihl = *p.first()?;
    if vihl >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(vihl & 0x0f) * 4;
    let total = usize::from(be16(p, 2)?);
    if ihl < 20 || total < ihl || total > p.len() {
        return None;
    }
    let frag = be16(p, 6)?;
    if frag & 0x3fff != 0 {
        return None;
    }
    let proto = *p.get(9)?;
    let src = Ipv4Addr::from(be32(p, 12)?);
    let dst = Ipv4Addr::from(be32(p, 16)?);
    let l4 = p.get(ihl..total)?;
    match proto {
        17 => {
            let ulen = usize::from(be16(l4, 4)?);
            if ulen < 8 || ulen > l4.len() {
                return None;
            }
            Some((
                L4::Udp,
                src,
                be16(l4, 0)?,
                dst,
                be16(l4, 2)?,
                l4.get(8..ulen)?,
            ))
        }
        6 => {
            let off = usize::from(*l4.get(12)? >> 4) * 4;
            if off < 20 {
                return None;
            }
            Some((
                L4::Tcp,
                src,
                be16(l4, 0)?,
                dst,
                be16(l4, 2)?,
                l4.get(off..)?,
            ))
        }
        _ => None,
    }
}

// --------------------------------------------------------------- policy

/// A recurring window (UTC) in which no WebRTC session to the robot is
/// allowed (e.g. outside operating hours, during maintenance).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DenyWindow {
    /// Days the window **starts** on: bit 0 Monday ... bit 6 Sunday; 0 =
    /// every day.
    pub days: u8,
    /// Minutes after midnight (UTC), `0..1440`.
    pub start_min: u16,
    /// End (exclusive); smaller than `start_min` = over midnight.
    pub end_min: u16,
}

impl DenyWindow {
    /// Parse `[DAYS ]HH:MM-HH:MM` (UTC): `DAYS` is a comma list of `mon`
    /// .. `sun` or ranges (`mon-fri`), case-insensitive.
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let (days_s, times) = match s.rsplit_once(' ') {
            Some((d, t)) => (Some(d.trim()), t),
            None => (None, s),
        };
        let hm = |t: &str| -> Option<u16> {
            let (h, m) = t.split_once(':')?;
            let (h, m): (u16, u16) = (h.parse().ok()?, m.parse().ok()?);
            (h < 24 && m < 60 && t.len() == 5).then_some(h * 60 + m)
        };
        let (a, b) = times
            .split_once('-')
            .ok_or_else(|| format!("deny window {s:?}: expected HH:MM-HH:MM"))?;
        let (start_min, end_min) = match (hm(a), hm(b)) {
            (Some(x), Some(y)) if x != y => (x, y),
            _ => return Err(format!("deny window {s:?}: bad or empty time range")),
        };
        const NAMES: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
        let day = |d: &str| NAMES.iter().position(|n| n.eq_ignore_ascii_case(d.trim()));
        let mut days = 0u8;
        if let Some(ds) = days_s {
            for part in ds.split(',') {
                let (x, y) = match part.split_once('-') {
                    Some((x, y)) => (day(x), day(y)),
                    None => (day(part), day(part)),
                };
                let (Some(x), Some(y)) = (x, y) else {
                    return Err(format!("deny window {s:?}: unknown day in {part:?}"));
                };
                let mut d = x;
                loop {
                    days |= 1 << d;
                    if d == y {
                        break;
                    }
                    d = (d + 1) % 7;
                }
            }
        }
        Ok(DenyWindow {
            days,
            start_min,
            end_min,
        })
    }

    /// Whether `wall_ns` (Unix ns, UTC) is inside the window.
    pub fn contains(&self, wall_ns: u64) -> bool {
        let mins = wall_ns / 60_000_000_000;
        let min_of_day = (mins % 1440) as u16;
        let day_no = mins / 1440;
        // 1970-01-01 was a Thursday (index 3 from Monday).
        let weekday = ((day_no + 3) % 7) as u8;
        let starts_on = |wd: u8| self.days == 0 || self.days & (1 << wd) != 0;
        if self.start_min < self.end_min {
            (self.start_min..self.end_min).contains(&min_of_day) && starts_on(weekday)
        } else {
            (min_of_day >= self.start_min && starts_on(weekday))
                || (min_of_day < self.end_min && starts_on((weekday + 6) % 7))
        }
    }
}

/// Knobs of the WebRTC monitor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebRtcOptions {
    /// Off by default.
    pub enabled: bool,
    /// The robot's addresses (its WebRTC endpoint).
    pub robot_addresses: BTreeSet<IpAddr>,
    /// TCP ports of the robot's signalling.
    pub signalling_ports: BTreeSet<u16>,
    /// Allowed controllers: IP, optionally bound to a MAC. Empty = no list
    /// (every new peer is reported as [`rules::NEW_PEER`]).
    pub controllers: BTreeMap<IpAddr, Option<[u8; 6]>>,
    /// Windows in which every session is reported.
    pub deny_windows: Vec<DenyWindow>,
    /// Most sessions established at once (default 1).
    pub max_sessions: usize,
    /// A peer without traffic for this long ends its session (default
    /// 30 s; ICE consent checks run every few seconds).
    pub session_idle_ns: u64,
    /// Report sessions through a relay or with non-local peers
    /// ([`rules::RELAYED_SESSION`]); default true.
    pub report_relayed: bool,
    /// Most peers tracked.
    pub max_peers: usize,
}

impl Default for WebRtcOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            robot_addresses: default_robot_addresses(),
            signalling_ports: DEFAULT_SIGNALLING_PORTS.into_iter().collect(),
            controllers: BTreeMap::new(),
            deny_windows: Vec::new(),
            max_sessions: 1,
            session_idle_ns: 30_000_000_000,
            report_relayed: true,
            max_peers: DEFAULT_MAX_PEERS,
        }
    }
}

/// Private, link-local, loopback and unique-local addresses (a peer there
/// is on a local network).
pub fn is_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_private() || v.is_link_local() || v.is_loopback(),
        IpAddr::V6(v) => {
            v.is_loopback()
                || (v.segments().first().copied().unwrap_or(0) & 0xfe00) == 0xfc00
                || (v.segments().first().copied().unwrap_or(0) & 0xffc0) == 0xfe80
                || *v == Ipv6Addr::UNSPECIFIED
        }
    }
}

// ---------------------------------------------------------------- state

/// Session state of a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    /// Only signalling seen.
    Signalling,
    /// ICE checks or a DTLS hello seen.
    Connecting,
    /// DTLS handshake complete (both hellos, or encrypted records both
    /// ways).
    Established,
}

/// One peer's record (bounded).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeerSession {
    pub peer: IpAddr,
    pub mac: Option<String>,
    pub first_mono_ns: u64,
    pub last_mono_ns: u64,
    pub state: SessionState,
    /// Signalling steps seen (in order of first appearance).
    pub signalling: Vec<SignallingKind>,
    /// Metadata of the plaintext SDP offer, if any.
    pub sdp: Option<SdpMeta>,
    /// Whether the robot answered a signalling request (HTTP 2xx).
    pub answered: bool,
    /// `(peer port, robot port)` of the UDP flows (at most
    /// [`MAX_FLOWS_PER_PEER`]).
    pub flows: BTreeSet<(u16, u16)>,
    /// The robot address of the session.
    pub robot: IpAddr,
    pub stun_requests: u64,
    pub stun_responses: u64,
    pub client_hello: bool,
    pub server_hello: bool,
    pub encrypted_in: bool,
    pub encrypted_out: bool,
    pub srtp_packets: u64,
    /// TURN methods or ChannelData seen (a relay).
    pub relayed: bool,
    pub listed: bool,
}

impl PeerSession {
    fn established(&self) -> bool {
        (self.client_hello && self.server_hello) || (self.encrypted_in && self.encrypted_out)
    }

    /// `peer ip:port <-> robot ip:port, ...` (the block targets).
    pub fn flows_text(&self) -> String {
        if self.flows.is_empty() {
            return "no UDP flow yet".into();
        }
        self.flows
            .iter()
            .map(|(pp, rp)| format!("{}:{pp} <-> {}:{rp}", self.peer, self.robot))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct WebRtcStats {
    pub packets: u64,
    pub signalling_requests: u64,
    pub signalling_responses: u64,
    pub stun: u64,
    pub stun_bad_fingerprint: u64,
    pub dtls: u64,
    pub srtp: u64,
    pub turn: u64,
    pub sessions_established: u64,
    pub sessions_ended: u64,
    pub peers_evicted: u64,
    pub findings_suppressed: u64,
}

/// See the module docs.
#[derive(Debug, Clone)]
pub struct WebRtcMonitor {
    opts: WebRtcOptions,
    peers: BTreeMap<IpAddr, PeerSession>,
    /// Peers ever seen with a session (for [`rules::NEW_PEER`]), bounded
    /// like `reported`.
    known: BTreeSet<IpAddr>,
    reported: BTreeSet<(&'static str, String)>,
    pub stats: WebRtcStats,
}

fn mac_text(m: &[u8; 6]) -> String {
    m.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

impl WebRtcMonitor {
    pub fn new(opts: WebRtcOptions) -> Self {
        Self {
            opts,
            peers: BTreeMap::new(),
            known: BTreeSet::new(),
            reported: BTreeSet::new(),
            stats: WebRtcStats::default(),
        }
    }

    pub fn options(&self) -> &WebRtcOptions {
        &self.opts
    }

    /// The tracked peers.
    pub fn sessions(&self) -> impl Iterator<Item = &PeerSession> {
        self.peers.values()
    }

    /// The session of `peer`.
    pub fn session(&self, peer: &IpAddr) -> Option<&PeerSession> {
        self.peers.get(peer)
    }

    fn report(
        &mut self,
        out: &mut Vec<Deviation>,
        rule: &'static str,
        key: String,
        sev: Severity,
        detail: String,
    ) {
        if self.reported.contains(&(rule, key.clone())) {
            return;
        }
        if self.reported.len() >= MAX_REPORTED {
            self.stats.findings_suppressed += 1;
            return;
        }
        self.reported.insert((rule, key));
        out.push(Deviation::new(rule, sev, detail));
    }

    /// End the sessions of peers idle for longer than `session_idle_ns`.
    pub fn expire(&mut self, mono_ns: u64) {
        let idle = self.opts.session_idle_ns;
        let before = self.peers.len();
        self.peers
            .retain(|_, s| mono_ns.saturating_sub(s.last_mono_ns) <= idle);
        let ended = before - self.peers.len();
        self.stats.sessions_ended += ended as u64;
    }

    /// Feed one packet; returns the new findings.
    pub fn process(&mut self, p: &FlowPacket<'_>) -> Vec<Deviation> {
        let mut out = Vec::new();
        if !self.opts.enabled {
            return out;
        }
        let robot_dst = self.opts.robot_addresses.contains(&p.dst);
        let robot_src = self.opts.robot_addresses.contains(&p.src);
        let (inbound, peer, robot, robot_port, peer_port) = match (robot_src, robot_dst) {
            (false, true) => (true, p.src, p.dst, p.dst_port, p.src_port),
            (true, false) => (false, p.dst, p.src, p.src_port, p.dst_port),
            _ => return out,
        };
        self.stats.packets += 1;
        self.expire(p.mono_ns);
        // What this packet is, before touching state.
        let mut sig: Option<SignallingMeta> = None;
        let mut answered = false;
        let mut udp: Option<UdpClass<'_>> = None;
        match p.l4 {
            L4::Tcp if self.opts.signalling_ports.contains(&robot_port) => {
                if inbound {
                    if let Some(r) = parse_http_request(p.payload) {
                        self.stats.signalling_requests += 1;
                        sig = Some(classify_signalling(&r));
                    }
                } else if let Some(r) = parse_http_response(p.payload) {
                    self.stats.signalling_responses += 1;
                    answered = (200..300).contains(&r.status);
                }
            }
            L4::Tcp => return out,
            L4::Udp => {
                let c = classify_udp(p.payload);
                match &c {
                    UdpClass::Stun(s) => {
                        self.stats.stun += 1;
                        if s.fingerprint_ok == Some(false) {
                            self.stats.stun_bad_fingerprint += 1;
                        }
                        if stun_method::is_turn(s.method) {
                            self.stats.turn += 1;
                        }
                    }
                    UdpClass::Dtls(_) => self.stats.dtls += 1,
                    UdpClass::ChannelData => self.stats.turn += 1,
                    UdpClass::Rtp { .. } => self.stats.srtp += 1,
                    UdpClass::Other => return out,
                }
                udp = Some(c);
            }
        }
        // A response to nobody's signalling, or SRTP of an unknown peer,
        // starts nothing.
        let starts = sig.is_some()
            || matches!(
                udp,
                Some(UdpClass::Stun(_) | UdpClass::Dtls(_) | UdpClass::ChannelData)
            );
        if !self.peers.contains_key(&peer) {
            if !starts {
                return out;
            }
            if self.peers.len() >= self.opts.max_peers {
                // Evict the least recently active peer.
                if let Some(old) = self
                    .peers
                    .values()
                    .min_by_key(|s| s.last_mono_ns)
                    .map(|s| s.peer)
                {
                    self.peers.remove(&old);
                    self.stats.peers_evicted += 1;
                }
            }
            let listed = self.opts.controllers.contains_key(&peer);
            self.peers.insert(
                peer,
                PeerSession {
                    peer,
                    mac: None,
                    first_mono_ns: p.mono_ns,
                    last_mono_ns: p.mono_ns,
                    state: SessionState::Signalling,
                    signalling: Vec::new(),
                    sdp: None,
                    answered: false,
                    flows: BTreeSet::new(),
                    robot,
                    stun_requests: 0,
                    stun_responses: 0,
                    client_hello: false,
                    server_hello: false,
                    encrypted_in: false,
                    encrypted_out: false,
                    srtp_packets: 0,
                    relayed: false,
                    listed,
                },
            );
        }
        let Some(s) = self.peers.get_mut(&peer) else {
            return out;
        };
        let was = s.state;
        let was_established = s.established();
        s.last_mono_ns = p.mono_ns;
        if inbound {
            if let Some(m) = p.src_mac {
                if s.mac.is_none() {
                    s.mac = Some(mac_text(&m));
                }
            }
        }
        if let Some(m) = &sig {
            if !s.signalling.contains(&m.kind) && s.signalling.len() < 8 {
                s.signalling.push(m.kind);
            }
            if m.sdp.is_some() {
                s.sdp = m.sdp.clone();
            }
        }
        if answered {
            s.answered = true;
        }
        if let Some(c) = &udp {
            if p.l4 == L4::Udp && s.flows.len() < MAX_FLOWS_PER_PEER {
                s.flows.insert((peer_port, robot_port));
            }
            match c {
                UdpClass::Stun(st) => {
                    if st.method == stun_method::BINDING && st.class == StunClass::Request {
                        s.stun_requests += 1;
                    }
                    if st.method == stun_method::BINDING && st.class == StunClass::Success {
                        s.stun_responses += 1;
                    }
                    if stun_method::is_turn(st.method) {
                        s.relayed = true;
                    }
                }
                UdpClass::Dtls(d) => {
                    s.client_hello |= d.client_hello;
                    s.server_hello |= d.server_hello;
                    if d.encrypted {
                        if inbound {
                            s.encrypted_in = true;
                        } else {
                            s.encrypted_out = true;
                        }
                    }
                }
                UdpClass::ChannelData => s.relayed = true,
                UdpClass::Rtp { .. } => s.srtp_packets += 1,
                UdpClass::Other => {}
            }
            if s.state == SessionState::Signalling {
                s.state = SessionState::Connecting;
            }
        }
        if s.established() {
            s.state = SessionState::Established;
        }
        let snap = s.clone();
        let now_established = snap.established() && !was_established;
        if now_established {
            self.stats.sessions_established += 1;
        }
        let new_activity = snap.state != was || sig.is_some() || now_established;
        if !new_activity && was != SessionState::Signalling {
            // Steady state: only the deny window is re-checked (per day).
            self.check_window(&mut out, &snap, p.wall_ns);
            return out;
        }
        self.findings(&mut out, &snap, p, inbound, sig.as_ref(), now_established);
        out
    }

    fn check_window(&mut self, out: &mut Vec<Deviation>, s: &PeerSession, wall_ns: u64) {
        let hit = self
            .opts
            .deny_windows
            .iter()
            .position(|w| w.contains(wall_ns));
        if let Some(i) = hit {
            let day = wall_ns / 86_400_000_000_000;
            self.report(
                out,
                rules::SESSION_IN_DENIED_WINDOW,
                format!("{}/{i}/{day}", s.peer),
                Severity::High,
                format!(
                    "Go2 WebRTC session ({:?}) between {} and the robot {} during denied window \
                     #{i} (UTC); flows: {}",
                    s.state,
                    s.peer,
                    s.robot,
                    s.flows_text()
                ),
            );
        }
    }

    fn findings(
        &mut self,
        out: &mut Vec<Deviation>,
        s: &PeerSession,
        p: &FlowPacket<'_>,
        inbound: bool,
        sig: Option<&SignallingMeta>,
        now_established: bool,
    ) {
        let peer = s.peer;
        let what = match (sig, s.state) {
            (Some(m), _) => format!("signalling {:?}", m.kind),
            (None, st) => format!("{st:?}"),
        };
        // Who.
        if self.opts.controllers.is_empty() {
            if !self.known.contains(&peer) {
                if self.known.len() < MAX_REPORTED {
                    self.known.insert(peer);
                }
                self.report(
                    out,
                    rules::NEW_PEER,
                    peer.to_string(),
                    Severity::Medium,
                    format!(
                        "new Go2 WebRTC peer {peer} ({what}) with the robot {}; no controller \
                         list is configured (webrtc.controllers)",
                        s.robot
                    ),
                );
            }
        } else if !s.listed {
            let (stage, sev) = if s.state == SessionState::Established {
                ("established", Severity::Critical)
            } else {
                ("attempt", Severity::High)
            };
            self.report(
                out,
                rules::UNKNOWN_CONTROLLER,
                format!("{peer}/{stage}"),
                sev,
                format!(
                    "Go2 WebRTC session {stage} ({what}) from {peer}, which is not a listed \
                     controller (webrtc.controllers); flows: {}",
                    s.flows_text()
                ),
            );
        } else if let (true, Some(Some(want)), Some(got)) =
            (inbound, self.opts.controllers.get(&peer), p.src_mac)
        {
            if *want != got {
                self.report(
                    out,
                    rules::CONTROLLER_MAC_MISMATCH,
                    format!("{peer}/{}", mac_text(&got)),
                    Severity::High,
                    format!(
                        "Go2 WebRTC traffic from listed controller {peer} with link-layer \
                         source {}, not the bound {}: another host may be using its address",
                        mac_text(&got),
                        mac_text(want)
                    ),
                );
            }
        }
        // When.
        self.check_window(out, s, p.wall_ns);
        // How.
        if now_established {
            let live = self
                .peers
                .values()
                .filter(|x| x.state == SessionState::Established)
                .count();
            if live > self.opts.max_sessions {
                let peers: Vec<String> = self
                    .peers
                    .values()
                    .filter(|x| x.state == SessionState::Established)
                    .take(8)
                    .map(|x| x.peer.to_string())
                    .collect();
                self.report(
                    out,
                    rules::CONCURRENT_SESSIONS,
                    format!("{peer}"),
                    Severity::High,
                    format!(
                        "{live} Go2 WebRTC sessions established at once (allowed {}): {}; the \
                         latest is {peer}, flows: {}",
                        self.opts.max_sessions,
                        peers.join(", "),
                        s.flows_text()
                    ),
                );
            }
            if s.signalling.is_empty() {
                self.report(
                    out,
                    rules::MEDIA_WITHOUT_SIGNALLING,
                    peer.to_string(),
                    Severity::Medium,
                    format!(
                        "Go2 WebRTC session established between {peer} and the robot {} \
                         without signalling on the watched link (signalled over Wi-Fi, a relay \
                         or an unknown method); flows: {}",
                        s.robot,
                        s.flows_text()
                    ),
                );
            }
        }
        if self.opts.report_relayed
            && (s.relayed || !is_local(&peer))
            && s.state != SessionState::Signalling
        {
            self.report(
                out,
                rules::RELAYED_SESSION,
                peer.to_string(),
                Severity::Medium,
                format!(
                    "the robot {} exchanges WebRTC traffic with {peer}{}: a remote session \
                     (cloud relay or Internet peer) that bypasses the local controller list",
                    s.robot,
                    if s.relayed {
                        " through TURN"
                    } else {
                        ", outside the local networks"
                    }
                ),
            );
        }
    }
}

#[cfg(test)]
mod tests;
