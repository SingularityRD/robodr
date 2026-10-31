//! TLS for the control plane's TCP listener: rustls (ring provider, TLS 1.3
//! and 1.2 with rustls' safe defaults) as a **server with mandatory client
//! authentication** (mutual TLS).
//!
//! * The robot presents `cert_chain` (PEM, end-entity first) with
//!   `key_file` (PEM PKCS#8 / SEC1 / PKCS#1; a private file).
//! * The SOC must present a client certificate that chains to one of the
//!   CA certificates in `client_ca` (PEM bundle; nothing else is trusted: no
//!   system or built-in roots), is within its validity period and allows
//!   `clientAuth` (rustls' WebPKI client verifier). A handshake without a
//!   client certificate fails.
//! * Optional `crl_files` (up to 16 files, PEM or DER X.509 v2 CRLs;
//!   `client_crl` is the older single-file spelling, merged into the list):
//!   the client certificate chain is also checked for revocation
//!   ([`robodr_blackbox::crl`]). A certificate whose issuer has no CRL is
//!   refused (unknown status fails closed): give a current CRL of every CA
//!   in `client_ca`. `nextUpdate` is enforced: past it, every SOC client is
//!   refused until a fresh CRL is installed. The files are checked for a
//!   change before every handshake and reloaded **without a restart**
//!   (replace them with an atomic `rename`); a reload that fails refuses
//!   every client until fixed. A CRL must carry a CRL number; of several
//!   CRLs of one CA the highest number is used, and an older CRL put back
//!   (lower number) is refused, fail closed. The high-water marks are kept
//!   in `<control_plane.state_dir>/crl-high-water.json` (when that
//!   directory exists), so this also holds across restarts.
//!   `status.json` reports the counters and the CRL in use per CA
//!   (`control_plane.tls.crl`), a refused revoked client is an
//!   authentication failure (`robot.agent.control_plane_unauthenticated`,
//!   reason `Revoked`).
//! * Optional `client_spki_sha256` pins: **in addition to** (never instead
//!   of) the chain check, the SHA-256 of the client end-entity
//!   certificate's DER `SubjectPublicKeyInfo` must be one of them. Several
//!   pins allow a rotation (current + next).
//! * No session resumption (no tickets, no session cache): every connection
//!   (one request each) presents and checks the client certificate afresh.
//!
//! mTLS authenticates the *channel*; every request must still carry a valid
//! Ed25519 SOC signature ([`super::auth`]). A failed handshake is counted
//! as an authentication failure (`robot.agent.control_plane_unauthenticated`).

use std::fmt;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::NoServerSessionStorage;
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, OtherError, RootCertStore,
    ServerConfig, ServerConnection, SignatureScheme, StreamOwned,
};
use serde::Deserialize;

/// Largest certificate / CA / key file read.
pub const MAX_PEM_BYTES: u64 = 1024 * 1024;
/// Most SPKI pins.
pub const MAX_PINS: usize = 16;

/// `control_plane.tls`.
///
/// ```json
/// "tls": {
///   "cert_chain": "/etc/robodr/control-plane/robot.pem",
///   "key_file": "/run/credentials/robodr-agentd.service/cp-tls.key",
///   "client_ca": "/etc/robodr/control-plane/soc-ca.pem",
///   "crl_files": ["/etc/robodr/control-plane/soc-ca.crl.pem"],
///   "client_spki_sha256": ["<64 hex>"]
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSection {
    pub cert_chain: PathBuf,
    pub key_file: PathBuf,
    pub client_ca: PathBuf,
    /// One CRL file (the older spelling of one `crl_files` entry).
    #[serde(default)]
    pub client_crl: Option<PathBuf>,
    /// CRLs (PEM or DER) of the client CAs (see the module docs).
    #[serde(default)]
    pub crl_files: Vec<PathBuf>,
    #[serde(default)]
    pub client_spki_sha256: Vec<String>,
}

/// A loaded server configuration plus what the status reports.
#[derive(Clone)]
pub struct TlsSpec {
    pub config: Arc<ServerConfig>,
    /// SHA-256 of the robot's end-entity SPKI (lower-case hex), for the SOC's
    /// own pin.
    pub server_spki_sha256: String,
    pub client_cas: usize,
    pub client_pins: usize,
    /// CRLs loaded at start from `client_crl` / `crl_files` (0: no
    /// revocation check).
    pub client_crls: usize,
    /// Live revocation counters (with CRLs).
    pub crl: Option<Arc<robodr_blackbox::crl::CrlStats>>,
    /// `notAfter` (Unix seconds) of the robot's own certificate (the leaf
    /// of `cert_chain`), for `robot.agent.credential_expiring`; `None` if
    /// it could not be read.
    pub server_not_after: Option<i64>,
}

impl fmt::Debug for TlsSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsSpec")
            .field("server_spki_sha256", &self.server_spki_sha256)
            .field("client_cas", &self.client_cas)
            .field("client_pins", &self.client_pins)
            .field("client_crls", &self.client_crls)
            .finish()
    }
}

impl PartialEq for TlsSpec {
    fn eq(&self, o: &Self) -> bool {
        self.server_spki_sha256 == o.server_spki_sha256
            && self.client_cas == o.client_cas
            && self.client_pins == o.client_pins
            && self.client_crls == o.client_crls
    }
}

impl Eq for TlsSpec {}

/// Parse a pin: 64 hex digits (case-insensitive).
pub fn parse_pin(s: &str) -> Result<[u8; 32], String> {
    match robodr_blackbox::crypto::from_hex(&s.to_ascii_lowercase()) {
        Some(v) if v.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(&v);
            Ok(out)
        }
        _ => Err(format!(
            "control_plane.tls.client_spki_sha256 {:?}: must be 64 hex digits (SHA-256 of the \
             DER SubjectPublicKeyInfo)",
            robodr_ros2_pipeline::sanitize(s)
        )),
    }
}

/// SHA-256 of a certificate's DER `SubjectPublicKeyInfo`.
pub fn spki_sha256(cert: &CertificateDer<'_>) -> Result<[u8; 32], String> {
    let ee = webpki::EndEntityCert::try_from(cert).map_err(|e| format!("certificate: {e}"))?;
    Ok(robodr_blackbox::crypto::sha256(
        ee.subject_public_key_info().as_ref(),
    ))
}

/// Read a PEM file: absolute, regular (no symlink), owned by `euid` or
/// root, at most [`MAX_PEM_BYTES`]; `secret`: no group/other bits at all,
/// else not group/other-writable. The file is opened first
/// (`O_NOFOLLOW | O_NONBLOCK`: a symlink fails, a FIFO never blocks) and
/// every check is made on the opened descriptor, then read from it: no
/// file swapped in between a check and the read is ever used.
fn read_pem(what: &str, path: &Path, euid: u32, secret: bool) -> Result<Vec<u8>, String> {
    let shown = path.display();
    if !path.is_absolute() {
        return Err(format!(
            "control_plane.tls.{what} {shown}: must be absolute"
        ));
    }
    let f = super::fsutil::open_read_nofollow(path).map_err(|e| {
        if e.raw_os_error() == Some(ELOOP) {
            format!("control_plane.tls.{what} {shown}: not a regular file (symlinks are refused)")
        } else if e.kind() == io::ErrorKind::InvalidInput {
            format!("control_plane.tls.{what} {shown}: not a regular file")
        } else {
            format!("control_plane.tls.{what} {shown}: {e}")
        }
    })?;
    let lmeta = f
        .metadata()
        .map_err(|e| format!("control_plane.tls.{what} {shown}: {e}"))?;
    let mode = lmeta.permissions().mode() & 0o777;
    if secret && mode & 0o077 != 0 {
        return Err(format!(
            "control_plane.tls.{what} {shown}: mode {mode:03o} lets group/others access the \
             private key; chmod 600"
        ));
    }
    if !secret && mode & 0o022 != 0 {
        return Err(format!(
            "control_plane.tls.{what} {shown}: mode {mode:03o} lets group/others write it; chmod 644"
        ));
    }
    if lmeta.uid() != euid && lmeta.uid() != 0 {
        return Err(format!(
            "control_plane.tls.{what} {shown}: owned by uid {}, not by the daemon's uid {euid} or \
             root",
            lmeta.uid()
        ));
    }
    let bytes = super::fsutil::read_capped_file(f, path, MAX_PEM_BYTES)
        .map_err(|e| format!("control_plane.tls.{what} {shown}: {e}"))?;
    Ok(bytes)
}

/// `ELOOP` (Linux; `O_NOFOLLOW` on a symlink).
const ELOOP: i32 = 40;

fn certs(what: &str, path: &Path, pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    let mut out = Vec::new();
    for c in CertificateDer::pem_slice_iter(pem) {
        out.push(c.map_err(|e| format!("control_plane.tls.{what} {}: {e}", path.display()))?);
    }
    if out.is_empty() {
        return Err(format!(
            "control_plane.tls.{what} {}: no CERTIFICATE in it",
            path.display()
        ));
    }
    Ok(out)
}

impl TlsSection {
    /// Load and check everything; build the rustls server configuration.
    pub fn resolve(&self, euid: u32) -> Result<TlsSpec, String> {
        self.resolve_with_crl_state(euid, None)
    }

    /// As [`TlsSection::resolve`]; with `crl_state`, the CRL high-water
    /// marks are kept in that file too
    /// ([`robodr_blackbox::crl::CrlFiles::with_state_file`]).
    pub fn resolve_with_crl_state(
        &self,
        euid: u32,
        crl_state: Option<&Path>,
    ) -> Result<TlsSpec, String> {
        let chain_pem = read_pem("cert_chain", &self.cert_chain, euid, false)?;
        let chain = certs("cert_chain", &self.cert_chain, &chain_pem)?;
        let key_pem = read_pem("key_file", &self.key_file, euid, true)?;
        let key = PrivateKeyDer::from_pem_slice(&key_pem).map_err(|e| {
            format!(
                "control_plane.tls.key_file {}: no usable private key ({e})",
                self.key_file.display()
            )
        })?;
        let ca_pem = read_pem("client_ca", &self.client_ca, euid, false)?;
        let mut roots = RootCertStore::empty();
        for c in certs("client_ca", &self.client_ca, &ca_pem)? {
            roots.add(c).map_err(|e| {
                format!(
                    "control_plane.tls.client_ca {}: {e}",
                    self.client_ca.display()
                )
            })?;
        }
        if self.client_spki_sha256.len() > MAX_PINS {
            return Err(format!(
                "control_plane.tls.client_spki_sha256: at most {MAX_PINS} pins"
            ));
        }
        let pins = self
            .client_spki_sha256
            .iter()
            .map(|p| parse_pin(p))
            .collect::<Result<Vec<_>, _>>()?;
        // `certs` refuses an empty file, so the leaf is there.
        let leaf = chain.first().ok_or_else(|| {
            format!(
                "control_plane.tls.cert_chain {}: no certificate",
                self.cert_chain.display()
            )
        })?;
        let server_spki = spki_sha256(leaf).map_err(|e| {
            format!(
                "control_plane.tls.cert_chain {}: {e}",
                self.cert_chain.display()
            )
        })?;
        let server_not_after = robodr_blackbox::crl::cert_not_after(leaf.as_ref());
        let client_cas = roots.len();
        let files: Vec<PathBuf> = self
            .client_crl
            .iter()
            .chain(self.crl_files.iter())
            .cloned()
            .collect();
        let crls = robodr_blackbox::crl::CrlFiles::with_reader(
            "control_plane.tls.crl_files",
            &files,
            Arc::new(move |p: &Path| read_pem("crl_files", p, euid, false)),
        )?
        .map(|c| match crl_state {
            Some(p) => c.with_state_file(p),
            None => c,
        });
        let (config, crl) = server_config(chain, key, roots, &pins, crls)?;
        let client_crls = crl.as_ref().map_or(0, |c| c.status().crls as usize);
        Ok(TlsSpec {
            config,
            server_spki_sha256: robodr_blackbox::crypto::to_hex(&server_spki),
            client_cas,
            client_pins: pins.len(),
            client_crls,
            crl,
            server_not_after,
        })
    }
}

/// The rustls server configuration (see the module docs).
pub fn server_config(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    client_roots: RootCertStore,
    pins: &[[u8; 32]],
    crls: Option<robodr_blackbox::crl::CrlFiles>,
) -> Result<
    (
        Arc<ServerConfig>,
        Option<Arc<robodr_blackbox::crl::CrlStats>>,
    ),
    String,
> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    // With CRLs: the whole chain; an issuer without a CRL, an expired or
    // an unusable CRL fails closed (robodr_blackbox::crl).
    let (inner, crl) =
        robodr_blackbox::crl::client_verifier(Arc::new(client_roots), provider.clone(), crls)
            .map_err(|e| format!("control_plane.tls.client_ca / crl_files: {e}"))?;
    let verifier: Arc<dyn ClientCertVerifier> = if pins.is_empty() {
        inner
    } else {
        Arc::new(PinningClientVerifier {
            inner,
            pins: pins.to_vec(),
        })
    };
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("control_plane.tls: {e}"))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .map_err(|e| format!("control_plane.tls (certificate / key): {e}"))?;
    // Every connection authenticates afresh.
    cfg.session_storage = Arc::new(NoServerSessionStorage {});
    cfg.send_tls13_tickets = 0;
    Ok((Arc::new(cfg), crl))
}

/// Full WebPKI client verification, then the SPKI pin check.
#[derive(Debug)]
struct PinningClientVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    pins: Vec<[u8; 32]>,
}

#[derive(Debug)]
struct PinMismatch;

impl fmt::Display for PinMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "client certificate public key (SPKI SHA-256) matches no configured pin"
        )
    }
}

impl std::error::Error for PinMismatch {}

impl ClientCertVerifier for PinningClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let ok = self
            .inner
            .verify_client_cert(end_entity, intermediates, now)?;
        let h = spki_sha256(end_entity)
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
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
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// A server-side TLS stream over TCP (with the answer's write deadline).
pub struct TlsStream(pub StreamOwned<ServerConnection, super::http::DeadlineTcp>);

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl super::http::Stream for TlsStream {
    /// The deadline is enforced by the socket wrapper on every read
    /// rustls makes ([`super::http::DeadlineTcp`]), not only between them.
    fn set_read_deadline(&self, d: Duration) -> io::Result<()> {
        super::http::Stream::set_read_deadline(&self.0.sock, d)
    }
    fn set_write_deadline(&self, at: Instant) {
        super::http::Stream::set_write_deadline(&self.0.sock, at);
    }
    fn finish(&mut self) {
        self.close();
    }
}

impl TlsStream {
    /// Send `close_notify` and flush it (best effort).
    pub fn close(&mut self) {
        self.0.conn.send_close_notify();
        let _ = self.0.conn.complete_io(&mut self.0.sock);
    }
}

/// Describe a handshake error (rustls reports them as `InvalidData`).
pub fn describe(e: &io::Error) -> String {
    if let Some(r) = e.get_ref().and_then(|x| x.downcast_ref::<rustls::Error>()) {
        return match r {
            rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(inner))) => {
                format!("invalid client certificate: {inner}")
            }
            rustls::Error::InvalidCertificate(c) => format!("invalid client certificate: {c:?}"),
            rustls::Error::NoCertificatesPresented => "no client certificate presented".into(),
            other => other.to_string(),
        };
    }
    match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => "timed out".into(),
        _ => e.to_string(),
    }
}

/// Run the server handshake on `tcp` before `deadline`. On success the
/// stream and the client end-entity certificate's SPKI SHA-256 (hex).
pub fn accept(
    config: &Arc<ServerConfig>,
    tcp: TcpStream,
    deadline: Instant,
) -> Result<(TlsStream, String), String> {
    let conn = ServerConnection::new(config.clone()).map_err(|e| format!("TLS: {e}"))?;
    let mut s = StreamOwned::new(conn, super::http::DeadlineTcp::new(tcp));
    // rustls' complete_io loops over many socket reads; the wrapper bounds
    // each one by the time left, so a peer dripping bytes cannot stretch
    // the handshake past `deadline` (review finding 1).
    s.sock.set_read_deadline_at(deadline);
    while s.conn.is_handshaking() {
        if Instant::now() >= deadline {
            return Err("timed out".into());
        }
        if let Err(e) = s.conn.complete_io(&mut s.sock) {
            // Let the client see the alert rustls queued (best effort).
            let _ = s.conn.write_tls(&mut s.sock);
            return Err(describe(&e));
        }
    }
    let spki = s
        .conn
        .peer_certificates()
        .and_then(|c| c.first())
        .and_then(|c| spki_sha256(c).ok())
        .map(|h| robodr_blackbox::crypto::to_hex(&h))
        .ok_or_else(|| "no client certificate presented".to_string())?;
    Ok((TlsStream(s), spki))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt;
    use std::thread;

    /// `fx/<name>`: the shared `fixtures/tls/` (its CRL set, `gen.sh crl`).
    fn data(name: &str) -> PathBuf {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        match name.strip_prefix("fx/") {
            Some(n) => root.join("../../fixtures/tls").join(n),
            None => root.join("tests/data/control-tls").join(name),
        }
    }

    fn server() -> Arc<ServerConfig> {
        let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(data("robot.pem"))
            .unwrap()
            .map(|c| c.unwrap())
            .collect();
        let key = PrivateKeyDer::from_pem_file(data("robot.key")).unwrap();
        let mut roots = RootCertStore::empty();
        for c in CertificateDer::pem_file_iter(data("soc-ca.pem")).unwrap() {
            roots.add(c.unwrap()).unwrap();
        }
        server_config(chain, key, roots, &[], None).unwrap().0
    }

    fn client() -> Arc<rustls::ClientConfig> {
        client_as("soc")
    }

    fn client_as(name: &str) -> Arc<rustls::ClientConfig> {
        let mut roots = RootCertStore::empty();
        for c in CertificateDer::pem_file_iter(data("robot-ca.pem")).unwrap() {
            roots.add(c.unwrap()).unwrap();
        }
        let chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_file_iter(data(&format!("{name}.pem")))
                .unwrap()
                .map(|c| c.unwrap())
                .collect();
        let key = PrivateKeyDer::from_pem_file(data(&format!("{name}.key"))).unwrap();
        Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_client_auth_cert(chain, key)
            .unwrap(),
        )
    }

    /// Send `bytes` one at a time, `gap` apart, until `total` has passed
    /// or the server closed.
    fn drip(mut tcp: TcpStream, bytes: &[u8], gap: Duration, total: Duration) {
        let t0 = Instant::now();
        for b in bytes.iter().cycle() {
            if t0.elapsed() > total || tcp.write_all(&[*b]).is_err() {
                return;
            }
            thread::sleep(gap);
        }
    }

    /// Review finding 1 (handshake): a peer that drips one byte per
    /// (socket timeout - epsilon) used to hold the slot far beyond the
    /// deadline (rustls' complete_io loops internally on the one timeout
    /// set before it). The deadline now bounds every read.
    #[test]
    fn handshake_drip_is_bounded_by_the_deadline() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let c = thread::spawn(move || {
            let tcp = TcpStream::connect(addr).unwrap();
            // A handshake record header announcing 16 KiB, then filler.
            let mut rec = vec![0x16, 0x03, 0x01, 0x40, 0x00];
            rec.extend(std::iter::repeat_n(0u8, 16384));
            drip(
                tcp,
                &rec,
                Duration::from_millis(100),
                Duration::from_secs(5),
            );
        });
        let (s, _) = l.accept().unwrap();
        let t0 = Instant::now();
        let r = accept(&server(), s, t0 + Duration::from_secs(1));
        let took = t0.elapsed();
        assert!(r.is_err(), "a dripped handshake must fail");
        assert!(
            took < Duration::from_millis(2500),
            "the handshake deadline (1 s) held for {took:?}"
        );
        c.join().unwrap();
    }

    /// Review finding 1 (request): after the handshake, a dripped
    /// application-data record must not outlive the request deadline
    /// (StreamOwned::read loops complete_io the same way).
    #[test]
    fn request_drip_after_handshake_is_bounded_by_the_deadline() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let c = thread::spawn(move || {
            let mut tcp = TcpStream::connect(addr).unwrap();
            let mut conn = rustls::ClientConnection::new(
                client(),
                rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap(),
            )
            .unwrap();
            while conn.is_handshaking() {
                conn.complete_io(&mut tcp).unwrap();
            }
            conn.writer()
                .write_all(b"GET /api/v2/robots/x HTTP/1.1\r\nHost: robot\r\n")
                .unwrap();
            let mut rec = Vec::new();
            while conn.wants_write() {
                conn.write_tls(&mut rec).unwrap();
            }
            drip(
                tcp,
                &rec,
                Duration::from_millis(100),
                Duration::from_secs(5),
            );
        });
        let (s, _) = l.accept().unwrap();
        let (mut stream, _) =
            accept(&server(), s, Instant::now() + Duration::from_secs(5)).unwrap();
        let t0 = Instant::now();
        let r = super::super::http::read_request(&mut stream, t0 + Duration::from_secs(1));
        let took = t0.elapsed();
        assert_eq!(r.map_err(|e| e.status), Err(408), "after {took:?}");
        assert!(
            took < Duration::from_millis(2500),
            "the request deadline (1 s) held for {took:?}"
        );
        drop(stream);
        c.join().unwrap();
    }

    /// A full handshake of client `name` against `cfg`.
    fn handshake(cfg: &Arc<ServerConfig>, name: &str) -> Result<(), String> {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let client = client_as(name);
        let c = thread::spawn(move || {
            let mut tcp = TcpStream::connect(addr).unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut conn = rustls::ClientConnection::new(
                client,
                rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap(),
            )
            .unwrap();
            while conn.is_handshaking() {
                if conn.complete_io(&mut tcp).is_err() {
                    break;
                }
            }
        });
        let (s, _) = l.accept().unwrap();
        let r = accept(cfg, s, Instant::now() + Duration::from_secs(5)).map(|_| ());
        c.join().unwrap();
        r
    }

    /// Review finding 9: an optional client CRL (`client_crl`): a revoked
    /// SOC client certificate is refused, its unrevoked sibling accepted.
    #[test]
    fn a_client_crl_refuses_revoked_certificates() {
        let d = std::env::temp_dir().join(format!("robodr-tls-crl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        for (f, mode) in [
            ("robot.pem", 0o644),
            ("robot.key", 0o600),
            ("crl-ca.pem", 0o644),
            ("crl-ca.crl.pem", 0o644),
        ] {
            std::fs::copy(data(f), d.join(f)).unwrap();
            std::fs::set_permissions(d.join(f), std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let sec = |crl: bool| TlsSection {
            cert_chain: d.join("robot.pem"),
            key_file: d.join("robot.key"),
            client_ca: d.join("crl-ca.pem"),
            client_crl: crl.then(|| d.join("crl-ca.crl.pem")),
            crl_files: Vec::new(),
            client_spki_sha256: Vec::new(),
        };
        let euid = crate::config::effective_uid();
        // Without the CRL both connect.
        let plain = sec(false).resolve(euid).unwrap();
        assert_eq!(handshake(&plain.config, "soc-revoked"), Ok(()));
        let with = sec(true).resolve(euid).unwrap();
        assert_eq!(with.client_crls, 1);
        assert_eq!(handshake(&with.config, "soc-crl"), Ok(()));
        let e = handshake(&with.config, "soc-revoked").unwrap_err();
        assert!(e.contains("Revoked"), "{e}");
        // A file without a CRL in it is refused at load.
        std::fs::copy(data("crl-ca.pem"), d.join("not-a-crl.pem")).unwrap();
        std::fs::set_permissions(
            d.join("not-a-crl.pem"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let mut bad = sec(true);
        bad.client_crl = Some(d.join("not-a-crl.pem"));
        let e = bad.resolve(euid).unwrap_err();
        assert!(e.contains("crl_files"), "{e}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// `crl_files` (fixtures/tls CRL set): a revoked SOC client is refused
    /// and reported (status counters, the reason names it); a CRL replaced
    /// on disk applies to the next handshake without a restart; a broken
    /// replacement refuses everyone until fixed.
    #[test]
    fn crl_files_refuse_revoked_clients_and_reload_without_restart() {
        let d = std::env::temp_dir().join(format!("robodr-tls-crl2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let put = |from: &str, to: &str, mode: u32| {
            let tmp = d.join(format!(".{to}"));
            std::fs::copy(data(from), &tmp).unwrap();
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)).unwrap();
            std::fs::rename(&tmp, d.join(to)).unwrap();
        };
        put("robot.pem", "robot.pem", 0o644);
        put("robot.key", "robot.key", 0o600);
        put("fx/crl-ca.pem", "soc-ca.pem", 0o644);
        put("fx/crl-ca-empty.crl.pem", "soc-ca.crl", 0o644);
        let sec = TlsSection {
            cert_chain: d.join("robot.pem"),
            key_file: d.join("robot.key"),
            client_ca: d.join("soc-ca.pem"),
            client_crl: None,
            crl_files: vec![d.join("soc-ca.crl")],
            client_spki_sha256: Vec::new(),
        };
        let spec = sec.resolve(crate::config::effective_uid()).unwrap();
        assert_eq!(spec.client_crls, 1);
        let stats = spec.crl.clone().unwrap();
        // Nothing revoked yet.
        assert_eq!(handshake(&spec.config, "fx/crl-revoked-client"), Ok(()));
        // The SOC publishes a CRL revoking it: no restart needed.
        put("fx/crl-ca.crl.pem", "soc-ca.crl", 0o644);
        let e = handshake(&spec.config, "fx/crl-revoked-client").unwrap_err();
        assert!(e.contains("Revoked"), "{e}");
        assert_eq!(handshake(&spec.config, "fx/crl-client"), Ok(()));
        let st = stats.status();
        assert_eq!((st.reloads, st.revoked_rejections), (1, 1));
        assert!(st.last_revoked_spki_sha256.is_some());
        // A broken CRL (not a CRL at all) fails closed, then recovers.
        put("fx/crl-ca.pem", "soc-ca.crl", 0o644);
        let e = handshake(&spec.config, "fx/crl-client").unwrap_err();
        assert!(e.contains("fail closed"), "{e}");
        assert!(stats.status().error.is_some());
        put("fx/crl-ca.crl.pem", "soc-ca.crl", 0o644);
        assert_eq!(handshake(&spec.config, "fx/crl-client"), Ok(()));
        // A group-writable replacement is refused like any other bad file.
        put("fx/crl-ca.crl.pem", "soc-ca.crl", 0o666);
        assert!(handshake(&spec.config, "fx/crl-client").is_err());
        assert!(stats.status().error.unwrap().contains("chmod"));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// An expired CRL (`nextUpdate` passed) does not stop agentd, but
    /// refuses every SOC client of that CA, revoked or not (fail closed).
    #[test]
    fn an_expired_crl_refuses_every_client() {
        let d = std::env::temp_dir().join(format!("robodr-tls-crl3-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        for (f, to, mode) in [
            ("robot.pem", "robot.pem", 0o644),
            ("robot.key", "robot.key", 0o600),
            ("fx/crl-ca.pem", "soc-ca.pem", 0o644),
            ("fx/crl-ca-expired.crl.pem", "soc-ca.crl", 0o644),
        ] {
            std::fs::copy(data(f), d.join(to)).unwrap();
            std::fs::set_permissions(d.join(to), std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let spec = TlsSection {
            cert_chain: d.join("robot.pem"),
            key_file: d.join("robot.key"),
            client_ca: d.join("soc-ca.pem"),
            client_crl: Some(d.join("soc-ca.crl")),
            crl_files: Vec::new(),
            client_spki_sha256: Vec::new(),
        }
        .resolve(crate::config::effective_uid())
        .unwrap();
        for c in ["fx/crl-client", "fx/crl-revoked-client"] {
            let e = handshake(&spec.config, c).unwrap_err();
            assert!(e.contains("ExpiredRevocationList"), "{c}: {e}");
        }
        assert_eq!(spec.crl.unwrap().status().expired_crl_rejections, 2);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Review (TLS, finding 6): `read_pem` checks the opened descriptor:
    /// a FIFO is refused without blocking, a symlink still refused.
    #[test]
    fn read_pem_checks_what_it_opened() {
        let d = std::env::temp_dir().join(format!("robodr-tls-fd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let euid = crate::config::effective_uid();
        let fifo = d.join("soc-ca.crl");
        assert!(std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        let (tx, rx) = std::sync::mpsc::channel();
        let f2 = fifo.clone();
        thread::spawn(move || {
            let _ = tx.send(read_pem("crl_files", &f2, euid, false));
        });
        let r = rx.recv_timeout(Duration::from_secs(5));
        if r.is_err() {
            let _ = std::fs::OpenOptions::new().write(true).open(&fifo);
        }
        let e = r.expect("read_pem blocked on a FIFO").unwrap_err();
        assert!(e.contains("not a regular file"), "{e}");
        std::fs::copy(data("fx/crl-ca.crl.pem"), d.join("real.crl")).unwrap();
        std::fs::set_permissions(d.join("real.crl"), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        std::os::unix::fs::symlink(d.join("real.crl"), d.join("link.crl")).unwrap();
        let e = read_pem("crl_files", &d.join("link.crl"), euid, false).unwrap_err();
        assert!(e.contains("symlinks are refused"), "{e}");
        assert!(read_pem("crl_files", &d.join("real.crl"), euid, false).is_ok());
        std::fs::set_permissions(d.join("real.crl"), std::fs::Permissions::from_mode(0o666))
            .unwrap();
        let e = read_pem("crl_files", &d.join("real.crl"), euid, false).unwrap_err();
        assert!(e.contains("chmod 644"), "{e}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Review (TLS, finding 1): with a state file, an older CRL put back
    /// is refused after a restart too.
    #[test]
    fn crl_high_water_survives_a_restart() {
        let d = std::env::temp_dir().join(format!("robodr-tls-crlhw-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let put = |from: &str, to: &str, mode: u32| {
            let tmp = d.join(format!(".{to}"));
            std::fs::copy(data(from), &tmp).unwrap();
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)).unwrap();
            std::fs::rename(&tmp, d.join(to)).unwrap();
        };
        put("robot.pem", "robot.pem", 0o644);
        put("robot.key", "robot.key", 0o600);
        put("fx/crl-ca.pem", "soc-ca.pem", 0o644);
        put("fx/crl-ca.crl.pem", "soc-ca.crl", 0o644);
        let sec = TlsSection {
            cert_chain: d.join("robot.pem"),
            key_file: d.join("robot.key"),
            client_ca: d.join("soc-ca.pem"),
            client_crl: None,
            crl_files: vec![d.join("soc-ca.crl")],
            client_spki_sha256: Vec::new(),
        };
        let state = d.join(robodr_blackbox::crl::STATE_FILE);
        let euid = crate::config::effective_uid();
        let spec = sec.resolve_with_crl_state(euid, Some(&state)).unwrap();
        let st = spec.crl.unwrap().status();
        assert_eq!(st.in_use.len(), 1);
        assert!(state.exists());
        put("fx/crl-ca-empty.crl.pem", "soc-ca.crl", 0o644);
        let e = sec.resolve_with_crl_state(euid, Some(&state)).unwrap_err();
        assert!(e.contains("goes back"), "{e}");
        let _ = std::fs::remove_dir_all(&d);
    }
}
