//! The HTTPS transport of `robodr-uplink`: one `POST` per connection
//! (`Connection: close`), HTTP/1.1, over rustls (ring provider).
//!
//! # TLS
//!
//! * `https://` always. `http://` is refused unless the host is a
//!   **loopback IP literal** (`127.0.0.0/8`, `::1`; not the name
//!   `localhost`, which a resolver could map elsewhere): contract §1 accepts
//!   plain HTTP only from loopback (tests, a local TLS-terminating proxy).
//! * Trust anchors: the operator's CA bundle (PEM, one or more
//!   `CERTIFICATE` sections) and nothing else — no built-in or system
//!   roots. The server certificate is verified by rustls' WebPKI verifier
//!   (chain to one of those anchors, validity period, server name = the
//!   URL's host, serverAuth EKU).
//! * Optional SHA-256 SPKI pins: **in addition** to (never instead of) the
//!   verification above, the end-entity certificate's
//!   `SubjectPublicKeyInfo` (DER, the whole SEQUENCE) must hash to one of
//!   the pins, else the handshake is aborted. Several pins allow a key
//!   rotation (current + next).
//! * There is no switch that disables verification.
//!
//! # HTTP
//!
//! A deliberately small client: `POST`, fixed headers, `Content-Length`
//! body; the response is read with a status line + header cap (32 KiB) and
//! a body cap (1 MiB), `Content-Length`, `chunked` or read-to-close bodies,
//! interim `1xx` responses skipped. No redirects, no proxies, no cookies,
//! no compression, no connection reuse. Every connect, read and write is
//! bounded by the connect timeout and the per-request deadline (the socket
//! timeouts are re-armed with the time left before each operation, so a
//! peer that trickles bytes cannot extend the exchange). Host names are
//! resolved on a helper thread waited for at most the connect timeout
//! (shared with the Kafka client; IP literals bypass it).

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, OtherError,
    RootCertStore, SignatureScheme, StreamOwned,
};
use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::wire;

/// Largest status line + headers accepted.
pub const MAX_HEAD_BYTES: usize = 32 * 1024;
/// Largest response body accepted.
pub const MAX_RESPONSE_BODY: usize = 1024 * 1024;
/// Largest CA bundle file read.
pub const MAX_CA_BUNDLE_BYTES: u64 = 4 * 1024 * 1024;
/// Most interim (1xx) responses skipped before the final one.
const MAX_INTERIM: usize = 8;

/// A parsed `--url` (the API root, `{base}` of contract §1) plus the
/// ingest path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub tls: bool,
    /// Host without brackets (DNS name lower-cased, or an IP literal).
    pub host: String,
    pub port: u16,
    /// Request target: the base path + [`wire::INGEST_PATH`].
    pub path: String,
}

impl Endpoint {
    /// Parse `https://host[:port][/base/path]` (or `http://` to a loopback
    /// IP literal). No user info, query, fragment, percent-escapes or
    /// white space.
    pub fn parse(url: &str) -> Result<Self, String> {
        Self::parse_with_path(url, wire::INGEST_PATH)
    }

    /// [`Endpoint::parse`] with `suffix` appended to the base path instead
    /// of the ingest path (`""`: the base itself). Shared with the fleet
    /// client (`robodr-fleet`), which sends to several paths under the same
    /// API root ([`HttpsTransport::request`]).
    pub fn parse_with_path(url: &str, suffix: &str) -> Result<Self, String> {
        let lower = url
            .get(..8)
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();
        let (tls, rest) = if lower.starts_with("https://") {
            (true, &url[8..])
        } else if lower.starts_with("http://") {
            (false, &url[7..])
        } else {
            return Err(format!(
                "URL must start with https:// (got {:?})",
                wire::trunc(url)
            ));
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        if authority.is_empty() {
            return Err("URL has no host".into());
        }
        if authority.contains('@') {
            return Err("URL must not contain user info".into());
        }
        if !path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~/".contains(&b))
        {
            return Err(
                "URL path may contain only [A-Za-z0-9-._~/] (no query, fragment or escapes)".into(),
            );
        }
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let end = v6.find(']').ok_or("URL: unterminated [IPv6] host")?;
            let host = &v6[..end];
            host.parse::<std::net::Ipv6Addr>()
                .map_err(|_| format!("URL: {host:?} is not an IPv6 address"))?;
            let after = &v6[end + 1..];
            let port = match after.strip_prefix(':') {
                Some(p) => Some(p),
                None if after.is_empty() => None,
                None => return Err("URL: garbage after the [IPv6] host".into()),
            };
            (host.to_string(), port)
        } else {
            match authority.split_once(':') {
                Some((h, p)) => (h.to_string(), Some(p)),
                None => (authority.to_string(), None),
            }
        };
        let port = match port {
            None => {
                if tls {
                    443
                } else {
                    80
                }
            }
            Some(p) => match p.parse::<u16>() {
                Ok(n) if n > 0 && !p.starts_with('0') => n,
                _ => return Err(format!("URL: bad port {:?}", wire::trunc(p))),
            },
        };
        let ip = host.parse::<IpAddr>().ok();
        let host = if ip.is_some() {
            host
        } else {
            let h = host.to_ascii_lowercase();
            let ok = !h.is_empty()
                && h.len() <= 253
                && h.split('.').all(|l| {
                    !l.is_empty()
                        && l.len() <= 63
                        && !l.starts_with('-')
                        && !l.ends_with('-')
                        && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                });
            if !ok {
                return Err(format!("URL: {:?} is not a host name", wire::trunc(&h)));
            }
            h
        };
        if !tls && !ip.is_some_and(|a| a.is_loopback()) {
            return Err(format!(
                "plain http:// is refused for {host:?}: TLS is mandatory except to a loopback IP \
                 literal (127.0.0.0/8, [::1]); use https://"
            ));
        }
        let base = path.trim_end_matches('/');
        Ok(Self {
            tls,
            host,
            port,
            path: format!("{base}{suffix}"),
        })
    }

    /// The `Host` header value.
    pub fn host_header(&self) -> String {
        let h = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default = if self.tls { 443 } else { 80 };
        if self.port == default {
            h
        } else {
            format!("{h}:{}", self.port)
        }
    }

    /// `host:port` for the resolver / a socket address.
    fn addr(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}://{}{}",
            if self.tls { "https" } else { "http" },
            self.host_header(),
            self.path
        )
    }
}

/// Parse a `--spki-sha256` pin: 64 hex digits (case-insensitive).
pub fn parse_pin(s: &str) -> Result<[u8; 32], String> {
    let lower = s.to_ascii_lowercase();
    match robodr_blackbox::crypto::from_hex(&lower) {
        Some(v) if v.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(&v);
            Ok(out)
        }
        _ => Err(format!(
            "SPKI pin must be 64 hex digits (SHA-256 of the DER SubjectPublicKeyInfo), got {:?}",
            wire::trunc(s)
        )),
    }
}

/// SHA-256 of a certificate's DER `SubjectPublicKeyInfo` (the pin value).
pub fn spki_sha256(cert: &CertificateDer<'_>) -> Result<[u8; 32], String> {
    let ee = webpki::EndEntityCert::try_from(cert).map_err(|e| format!("certificate: {e}"))?;
    let spki = ee.subject_public_key_info();
    Ok(robodr_blackbox::crypto::sha256(spki.as_ref()))
}

/// Full WebPKI verification, then the SPKI pin check.
#[derive(Debug)]
struct PinningVerifier {
    inner: Arc<WebPkiServerVerifier>,
    pins: Vec<[u8; 32]>,
}

#[derive(Debug)]
struct PinMismatch;

impl fmt::Display for PinMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "server certificate public key (SPKI SHA-256) matches no configured pin"
        )
    }
}

impl std::error::Error for PinMismatch {}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let ok = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let h = spki_sha256(end_entity)
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        // Pins are public values; a constant-time compare is not needed but
        // costs nothing.
        if self
            .pins
            .iter()
            .any(|p| robodr_blackbox::crypto::ct_eq(p, &h))
        {
            Ok(ok)
        } else {
            Err(rustls::Error::InvalidCertificate(CertificateError::Other(
                OtherError(Arc::new(PinMismatch)),
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Load a PEM CA bundle (regular file, ≤ 4 MiB, at least one certificate;
/// other PEM sections are ignored, a malformed one is an error).
pub fn load_ca_bundle(path: &Path) -> Result<RootCertStore, String> {
    let bytes = crate::fsutil::read_capped(path, MAX_CA_BUNDLE_BYTES)
        .map_err(|e| format!("CA bundle {}: {e}", path.display()))?;
    let mut roots = RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(&bytes) {
        let c = c.map_err(|e| format!("CA bundle {}: {e}", path.display()))?;
        roots
            .add(c)
            .map_err(|e| format!("CA bundle {}: {e}", path.display()))?;
    }
    if roots.is_empty() {
        return Err(format!(
            "CA bundle {}: no CERTIFICATE in it",
            path.display()
        ));
    }
    Ok(roots)
}

/// The rustls client configuration: ring provider, TLS 1.3 and 1.2 (rustls'
/// safe defaults), `roots` only, pins if any.
pub fn client_config(roots: RootCertStore, pins: &[[u8; 32]]) -> Result<ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS: {e}"))?;
    let roots = Arc::new(roots);
    let cfg = if pins.is_empty() {
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        let inner = WebPkiServerVerifier::builder_with_provider(roots, provider)
            .build()
            .map_err(|e| format!("TLS: {e}"))?;
        // `dangerous()` is rustls' name for "custom verifier"; this one runs
        // the full WebPKI verification above first and only adds the pin.
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinningVerifier {
                inner,
                pins: pins.to_vec(),
            }))
            .with_no_client_auth()
    };
    Ok(cfg)
}

/// What [`Transport::post`] sends: headers (besides `Host`,
/// `Content-Length`, `Connection`) and the body.
#[derive(Debug, Clone)]
pub struct HttpRequest<'a> {
    pub headers: Vec<(&'static str, String)>,
    pub body: &'a [u8],
}

/// A received response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    /// The `Retry-After` header, raw.
    pub retry_after: Option<String>,
    pub body: Vec<u8>,
}

/// A request that did not yield a response (connect, TLS, I/O, timeout,
/// malformed response). Always retryable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportError(pub String);

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TransportError {}

/// Sends one request. [`HttpsTransport`] is the real one; tests substitute
/// their own.
pub trait Transport {
    fn post(&mut self, req: &HttpRequest<'_>) -> Result<HttpResponse, TransportError>;
}

/// Timeouts of [`HttpsTransport`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// Name resolution + TCP connect (per address).
    pub connect: Duration,
    /// Whole exchange after the connect: TLS handshake, request, response.
    pub request: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            request: Duration::from_secs(60),
        }
    }
}

/// HTTPS (or loopback HTTP) to one [`Endpoint`].
pub struct HttpsTransport {
    endpoint: Endpoint,
    tls: Option<Arc<ClientConfig>>,
    timeouts: Timeouts,
    user_agent: String,
}

impl HttpsTransport {
    /// `tls` is required for an `https://` endpoint and must be `None` for
    /// `http://` (loopback only, checked by [`Endpoint::parse`]).
    pub fn new(
        endpoint: Endpoint,
        tls: Option<ClientConfig>,
        timeouts: Timeouts,
    ) -> Result<Self, String> {
        if endpoint.tls != tls.is_some() {
            return Err("TLS configuration does not match the URL scheme".into());
        }
        if !endpoint.tls
            && !endpoint
                .host
                .parse::<IpAddr>()
                .is_ok_and(|a| a.is_loopback())
        {
            return Err("plain http:// is refused except to a loopback IP literal".into());
        }
        if timeouts.connect.is_zero() || timeouts.request.is_zero() {
            return Err("timeouts must be > 0".into());
        }
        Ok(Self {
            endpoint,
            tls: tls.map(Arc::new),
            timeouts,
            user_agent: format!("robodr-uplink/{}", env!("CARGO_PKG_VERSION")),
        })
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Replace the `User-Agent` (default `robodr-uplink/<version>`).
    pub fn set_user_agent(&mut self, user_agent: &str) -> Result<(), String> {
        if user_agent.is_empty() || !user_agent.bytes().all(|b| (0x20..0x7f).contains(&b)) {
            return Err("User-Agent must be printable ASCII".into());
        }
        self.user_agent = user_agent.to_string();
        Ok(())
    }

    /// Send `method` to `target` (an origin-form request target such as
    /// `/api/robot-edr/v2/fleet/ring`) on this transport's host, with the
    /// same TLS, timeouts and response limits as [`Transport::post`] (which
    /// is `request("POST", endpoint().path, ..)`). `method` is upper-case
    /// ASCII letters; `target` starts with `/` and holds only
    /// `[A-Za-z0-9-._~/]`.
    pub fn request(
        &mut self,
        method: &str,
        target: &str,
        req: &HttpRequest<'_>,
    ) -> Result<HttpResponse, TransportError> {
        if method.is_empty() || method.len() > 16 || !method.bytes().all(|b| b.is_ascii_uppercase())
        {
            return Err(TransportError(format!("refusing method {method:?}")));
        }
        if !target.starts_with('/')
            || !target
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~/".contains(&b))
        {
            return Err(TransportError(format!(
                "refusing request target {:?}",
                wire::trunc(target)
            )));
        }
        self.exchange(method, target, req)
    }

    fn connect(&self) -> Result<TcpStream, TransportError> {
        let addr = self.endpoint.addr();
        let addrs = crate::kafka::client::resolve(&addr, self.timeouts.connect)
            .map_err(|e| TransportError(format!("{addr}: {e}")))?;
        if addrs.is_empty() {
            return Err(TransportError(format!("{addr}: no address")));
        }
        let mut last = None;
        for a in addrs.iter().take(8) {
            match TcpStream::connect_timeout(a, self.timeouts.connect) {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    return Ok(s);
                }
                Err(e) => last = Some((a, e)),
            }
        }
        Err(TransportError(match last {
            Some((a, e)) => format!("connect {a}: {e}"),
            None => format!("{addr}: no address tried"),
        }))
    }

    fn head(&self, method: &str, target: &str, req: &HttpRequest<'_>) -> Vec<u8> {
        let mut h = format!(
            "{method} {target} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: application/json\r\n\
             Connection: close\r\nContent-Length: {}\r\n",
            self.endpoint.host_header(),
            self.user_agent,
            req.body.len()
        );
        for (k, v) in &req.headers {
            h.push_str(k);
            h.push_str(": ");
            h.push_str(v);
            h.push_str("\r\n");
        }
        h.push_str("\r\n");
        h.into_bytes()
    }
}

impl Transport for HttpsTransport {
    fn post(&mut self, req: &HttpRequest<'_>) -> Result<HttpResponse, TransportError> {
        let target = self.endpoint.path.clone();
        self.exchange("POST", &target, req)
    }
}

impl HttpsTransport {
    fn exchange(
        &mut self,
        method: &str,
        target: &str,
        req: &HttpRequest<'_>,
    ) -> Result<HttpResponse, TransportError> {
        for (k, v) in &req.headers {
            // Header injection is impossible with the values built by the
            // uplink; refuse it anyway.
            if v.bytes().any(|b| b < 0x20 || b == 0x7f) || k.bytes().any(|b| !b.is_ascii_graphic())
            {
                return Err(TransportError(format!(
                    "refusing header {k:?} with control characters"
                )));
            }
        }
        let tcp = self.connect()?;
        let deadline = Instant::now() + self.timeouts.request;
        let stream = DeadlineStream { tcp, deadline };
        let head = self.head(method, target, req);
        let io_err = |e: io::Error| TransportError(describe_io(&e));
        match &self.tls {
            None => {
                let mut s = stream;
                s.write_all(&head).map_err(io_err)?;
                s.write_all(req.body).map_err(io_err)?;
                s.flush().map_err(io_err)?;
                read_response(&mut BufReader::new(s)).map_err(io_err)
            }
            Some(cfg) => {
                let name = ServerName::try_from(self.endpoint.host.clone())
                    .map_err(|e| TransportError(format!("TLS server name: {e}")))?;
                let conn = ClientConnection::new(cfg.clone(), name)
                    .map_err(|e| TransportError(format!("TLS: {e}")))?;
                let mut s = StreamOwned::new(conn, stream);
                // Complete the handshake first, so that a certificate error is
                // reported as such (not as a failed write).
                while s.conn.is_handshaking() {
                    s.conn.complete_io(&mut s.sock).map_err(|e| {
                        TransportError(format!("TLS handshake: {}", describe_io(&e)))
                    })?;
                }
                s.write_all(&head).map_err(io_err)?;
                s.write_all(req.body).map_err(io_err)?;
                s.flush().map_err(io_err)?;
                let r = read_response(&mut BufReader::new(&mut s)).map_err(io_err)?;
                s.conn.send_close_notify();
                let _ = s.conn.complete_io(&mut s.sock);
                Ok(r)
            }
        }
    }
}

fn describe_io(e: &io::Error) -> String {
    // rustls reports handshake failures as io::Error(InvalidData, rustls::Error).
    if let Some(r) = e.get_ref().and_then(|x| x.downcast_ref::<rustls::Error>()) {
        return match r {
            rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(inner))) => {
                format!("invalid peer certificate: {inner}")
            }
            other => other.to_string(),
        };
    }
    match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => format!("timed out ({e})"),
        _ => e.to_string(),
    }
}

/// A TCP stream whose every read and write is bounded by `deadline`.
struct DeadlineStream {
    tcp: TcpStream,
    deadline: Instant,
}

impl DeadlineStream {
    fn left(&self) -> io::Result<Duration> {
        let now = Instant::now();
        if now >= self.deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "request deadline"));
        }
        Ok(self.deadline - now)
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.left()?;
        self.tcp.set_read_timeout(Some(left))?;
        match self.tcp.read(buf) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "request deadline (read)",
            )),
            r => r,
        }
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let left = self.left()?;
        self.tcp.set_write_timeout(Some(left))?;
        match self.tcp.write(buf) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "request deadline (write)",
            )),
            r => r,
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

fn bad(m: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.into())
}

/// Read one CRLF- (or LF-) terminated line, without the terminator; at most
/// `*budget` bytes in total.
fn read_line<R: BufRead>(r: &mut R, budget: &mut usize) -> io::Result<String> {
    let mut buf = Vec::new();
    let n = r.take(*budget as u64 + 1).read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "connection closed before a complete response",
        ));
    }
    // At most `*budget + 1` bytes were read: one more than allowed means the
    // head is too large, whether or not that byte ends the line (checked
    // before subtracting: a line of exactly `budget + 1` bytes must not
    // underflow the budget).
    if n > *budget {
        return Err(bad("response head too large"));
    }
    if buf.last() != Some(&b'\n') {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "connection closed inside the response head",
        ));
    }
    *budget -= n;
    buf.pop();
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    String::from_utf8(buf).map_err(|_| bad("response head is not UTF-8"))
}

/// Parse a response from `r` (see the module docs for the limits).
pub fn read_response<R: BufRead>(r: &mut R) -> io::Result<HttpResponse> {
    let mut interim = 0;
    loop {
        let mut budget = MAX_HEAD_BYTES;
        let status_line = read_line(r, &mut budget)?;
        let mut parts = status_line.splitn(3, ' ');
        let version = parts.next().unwrap_or_default();
        let code = parts.next().unwrap_or_default();
        if version != "HTTP/1.1" && version != "HTTP/1.0" {
            return Err(bad(format!(
                "not an HTTP/1.x response: {:?}",
                wire::trunc(&status_line)
            )));
        }
        if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad(format!("bad status code {:?}", wire::trunc(code))));
        }
        let status: u16 = code.parse().map_err(|_| bad("bad status code"))?;
        if !(100..=599).contains(&status) {
            return Err(bad(format!("status {status} out of range")));
        }
        let mut content_length: Option<usize> = None;
        let mut chunked = false;
        let mut retry_after = None;
        loop {
            let line = read_line(r, &mut budget)?;
            if line.is_empty() {
                break;
            }
            if line.starts_with(' ') || line.starts_with('\t') {
                return Err(bad("obsolete header folding"));
            }
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| bad("header line without a colon"))?;
            let value = value.trim_matches(|c| c == ' ' || c == '\t');
            if name.eq_ignore_ascii_case("content-length") {
                if value.is_empty()
                    || !value.bytes().all(|b| b.is_ascii_digit())
                    || value.len() > 12
                {
                    return Err(bad("bad Content-Length"));
                }
                let n: usize = value.parse().map_err(|_| bad("bad Content-Length"))?;
                if content_length.is_some_and(|c| c != n) {
                    return Err(bad("conflicting Content-Length headers"));
                }
                content_length = Some(n);
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                let last = value.rsplit(',').next().unwrap_or("").trim();
                if !last.eq_ignore_ascii_case("chunked") || value.contains(',') {
                    return Err(bad(format!(
                        "unsupported Transfer-Encoding {:?}",
                        wire::trunc(value)
                    )));
                }
                chunked = true;
            } else if name.eq_ignore_ascii_case("retry-after") {
                retry_after = Some(value.to_string());
            }
        }
        if (100..200).contains(&status) {
            if status == 101 {
                return Err(bad("unexpected 101 Switching Protocols"));
            }
            interim += 1;
            if interim > MAX_INTERIM {
                return Err(bad("too many interim responses"));
            }
            continue;
        }
        if chunked && content_length.is_some() {
            return Err(bad("both Transfer-Encoding and Content-Length"));
        }
        let body = if status == 204 || status == 304 {
            Vec::new()
        } else if chunked {
            read_chunked(r)?
        } else if let Some(n) = content_length {
            if n > MAX_RESPONSE_BODY {
                return Err(bad(format!("response body of {n} bytes is too large")));
            }
            let mut b = vec![0u8; n];
            r.read_exact(&mut b)?;
            b
        } else {
            let mut b = Vec::new();
            r.take(MAX_RESPONSE_BODY as u64 + 1).read_to_end(&mut b)?;
            if b.len() > MAX_RESPONSE_BODY {
                return Err(bad("response body is too large"));
            }
            b
        };
        return Ok(HttpResponse {
            status,
            retry_after,
            body,
        });
    }
}

/// Body length after appending a chunk of `size` bytes (`None` on overflow,
/// possible on 32-bit targets: 8 hex digits are up to 4 GiB).
fn body_len_after(len: usize, size: usize) -> Option<usize> {
    len.checked_add(size)
}

fn read_chunked<R: BufRead>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    let mut budget = MAX_HEAD_BYTES;
    loop {
        let line = read_line(r, &mut budget)?;
        let size_str = line.split(';').next().unwrap_or("").trim();
        if size_str.is_empty()
            || size_str.len() > 8
            || !size_str.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(bad("bad chunk size"));
        }
        let size = usize::from_str_radix(size_str, 16).map_err(|_| bad("bad chunk size"))?;
        if size == 0 {
            // Trailers, up to the empty line.
            loop {
                if read_line(r, &mut budget)?.is_empty() {
                    return Ok(body);
                }
            }
        }
        let end = match body_len_after(body.len(), size) {
            Some(end) if end <= MAX_RESPONSE_BODY => end,
            _ => return Err(bad("response body is too large")),
        };
        let start = body.len();
        body.resize(end, 0);
        r.read_exact(&mut body[start..])?;
        let mut crlf = [0u8; 2];
        r.read_exact(&mut crlf)?;
        if &crlf != b"\r\n" {
            return Err(bad("chunk not followed by CRLF"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_parsing() {
        let e = Endpoint::parse("https://soc.example.org/api").unwrap();
        assert_eq!(
            e,
            Endpoint {
                tls: true,
                host: "soc.example.org".into(),
                port: 443,
                path: "/api/robot-edr/v2/ingest".into()
            }
        );
        assert_eq!(e.host_header(), "soc.example.org");
        assert_eq!(
            e.to_string(),
            "https://soc.example.org/api/robot-edr/v2/ingest"
        );
        let e = Endpoint::parse("HTTPS://SOC.Example.org:8443/").unwrap();
        assert_eq!((e.host.as_str(), e.port), ("soc.example.org", 8443));
        assert_eq!(e.path, "/robot-edr/v2/ingest");
        assert_eq!(e.host_header(), "soc.example.org:8443");
        let e = Endpoint::parse("https://[2001:db8::1]:9443/a/b//").unwrap();
        assert_eq!((e.host.as_str(), e.port), ("2001:db8::1", 9443));
        assert_eq!(e.host_header(), "[2001:db8::1]:9443");
        assert_eq!(e.addr(), "[2001:db8::1]:9443");
        let e = Endpoint::parse("https://10.0.0.5").unwrap();
        assert_eq!(e.addr(), "10.0.0.5:443");
        // Plain HTTP: loopback IP literals only.
        assert!(!Endpoint::parse("http://127.0.0.1:8080/api").unwrap().tls);
        assert!(Endpoint::parse("http://127.9.9.9").is_ok());
        assert!(Endpoint::parse("http://[::1]:80").is_ok());
        for bad in [
            "http://localhost:8080",
            "http://10.0.0.5",
            "http://soc.example.org",
            "http://[2001:db8::1]",
            "http://0.0.0.0",
            "ftp://x",
            "soc.example.org",
            "https://",
            "https://user@host",
            "https://host/a?b",
            "https://host/a#b",
            "https://host/a%20b",
            "https://host/a b",
            "https://host:0",
            "https://host:65536",
            "https://host:08443",
            "https://host:x",
            "https://-bad.example",
            "https://ex_ample.org",
            "https://[::1",
            "https://[::1]x",
            "https://[nope]",
            "https://a:1:2",
        ] {
            assert!(Endpoint::parse(bad).is_err(), "{bad}");
        }
        let err = Endpoint::parse("http://soc.example.org").unwrap_err();
        assert!(err.contains("TLS is mandatory"), "{err}");
    }

    #[test]
    fn pins() {
        let p = parse_pin(&"Ab".repeat(32)).unwrap();
        assert_eq!(p, [0xab; 32]);
        assert!(parse_pin(&"ab".repeat(31)).is_err());
        assert!(parse_pin(&"zz".repeat(32)).is_err());
        assert!(parse_pin("sha256/AAAA").is_err());
    }

    fn parse(s: &[u8]) -> io::Result<HttpResponse> {
        read_response(&mut BufReader::new(s))
    }

    #[test]
    fn responses() {
        let r = parse(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}extra").unwrap();
        assert_eq!(
            (r.status, r.body.as_slice(), r.retry_after),
            (200, &b"{}"[..], None)
        );
        let r = parse(b"HTTP/1.1 429 Too Many\r\nRetry-After:  7 \r\ncontent-length: 0\r\n\r\n")
            .unwrap();
        assert_eq!((r.status, r.retry_after.as_deref()), (429, Some("7")));
        let r = parse(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early\r\nLink: x\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;ext=1\r\nabc\r\n2\r\nde\r\n0\r\nTrailer: x\r\n\r\n").unwrap();
        assert_eq!(r.body, b"abcde");
        let r = parse(b"HTTP/1.0 503 Busy\n\nread to close").unwrap();
        assert_eq!((r.status, r.body.as_slice()), (503, &b"read to close"[..]));
        let r = parse(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap();
        assert!(r.body.is_empty());
        for bad in [
            &b""[..],
            b"HTTP/1.1 200 OK\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc",
            b"HTTP/2 200\r\n\r\n",
            b"SSH-2.0-OpenSSH\r\n\r\n",
            b"HTTP/1.1 20 OK\r\n\r\n",
            b"HTTP/1.1 999 Nope\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
            b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcXX0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n",
            b"HTTP/1.1 200 OK\r\nX: a\r\n folded\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nNoColon\r\n\r\n",
            b"HTTP/1.1 101 Switching\r\n\r\n",
        ] {
            assert!(parse(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        // Head cap.
        let mut big = b"HTTP/1.1 200 OK\r\n".to_vec();
        big.extend(std::iter::repeat_n(b'x', MAX_HEAD_BYTES + 10));
        assert!(parse(&big).is_err());
        // Body cap (read to close).
        let mut big = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        big.extend(std::iter::repeat_n(b'x', MAX_RESPONSE_BODY + 1));
        assert!(parse(&big).is_err());
        // Interim response flood.
        let flood = b"HTTP/1.1 100 Continue\r\n\r\n".repeat(MAX_INTERIM + 1);
        assert!(parse(&flood).is_err());
    }

    /// A head of `total` bytes: status line, one `X:` header padded so the
    /// whole head (CRLFs included) is exactly `total` bytes, empty line.
    fn head_of(total: usize) -> Vec<u8> {
        let status = b"HTTP/1.1 204 No Content\r\n";
        let fixed = status.len() + "X: \r\n".len() + 2;
        let mut h = status.to_vec();
        h.extend_from_slice(b"X: ");
        h.extend(std::iter::repeat_n(b'a', total - fixed));
        h.extend_from_slice(b"\r\n\r\n");
        assert_eq!(h.len(), total);
        h
    }

    /// The head budget is exact: `MAX_HEAD_BYTES` bytes of head are read,
    /// one more byte is refused, and a line ending exactly one byte past the
    /// budget is an error, never an arithmetic underflow (a panic in debug
    /// builds, a wrapped budget in release builds).
    #[test]
    fn head_budget_boundaries_never_underflow() {
        let r = parse(&head_of(MAX_HEAD_BYTES)).unwrap();
        assert_eq!(r.status, 204);
        let e = parse(&head_of(MAX_HEAD_BYTES + 1)).unwrap_err();
        assert!(e.to_string().contains("too large"), "{e}");
        // read_line directly: a line (LF included) of budget + 1 bytes.
        for (input, budget, ok) in [
            (&b"abcde\n"[..], 6usize, true),
            (b"abcde\n", 5, false),
            (b"abcd\r\n", 5, false),
            (b"\n", 0, false),
            (b"\n", 1, true),
        ] {
            let mut b = budget;
            let r = read_line(&mut BufReader::new(input), &mut b);
            assert_eq!(r.is_ok(), ok, "{input:?} {budget}: {r:?}");
            if ok {
                assert_eq!(b, budget - input.len());
            }
        }
    }

    /// Chunk sizes: the largest accepted hex size (8 digits) after some
    /// body bytes is refused as too large without allocating or
    /// overflowing; the chunk-line budget is shared with the trailers.
    #[test]
    fn huge_chunk_sizes_are_refused_without_overflow() {
        for size in ["ffffffff", "FFFFFFFF", "100001", "fffff;x=y"] {
            let msg = format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n{size}\r\n"
            );
            let e = parse(msg.as_bytes()).unwrap_err();
            assert!(e.to_string().contains("too large"), "{size}: {e}");
        }
        // Exactly MAX_RESPONSE_BODY in two chunks: accepted.
        let half = MAX_RESPONSE_BODY / 2;
        let mut msg = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for _ in 0..2 {
            msg.extend_from_slice(format!("{half:x}\r\n").as_bytes());
            msg.extend(std::iter::repeat_n(b'z', half));
            msg.extend_from_slice(b"\r\n");
        }
        msg.extend_from_slice(b"0\r\n\r\n");
        assert_eq!(parse(&msg).unwrap().body.len(), MAX_RESPONSE_BODY);
        // One byte more: refused.
        let mut over = msg[..msg.len() - 5].to_vec();
        over.extend_from_slice(b"1\r\nz\r\n0\r\n\r\n");
        assert!(parse(&over).is_err());
        // The addition itself is checked.
        assert_eq!(body_len_after(usize::MAX - 1, 2), None);
        assert_eq!(body_len_after(1, 2), Some(3));
    }
}
