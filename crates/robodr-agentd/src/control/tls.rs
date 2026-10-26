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
use rustls::server::{NoServerSessionStorage, WebPkiClientVerifier};
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
///   "client_spki_sha256": ["<64 hex>"]
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSection {
    pub cert_chain: PathBuf,
    pub key_file: PathBuf,
    pub client_ca: PathBuf,
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
}

impl fmt::Debug for TlsSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsSpec")
            .field("server_spki_sha256", &self.server_spki_sha256)
            .field("client_cas", &self.client_cas)
            .field("client_pins", &self.client_pins)
            .finish()
    }
}

impl PartialEq for TlsSpec {
    fn eq(&self, o: &Self) -> bool {
        self.server_spki_sha256 == o.server_spki_sha256
            && self.client_cas == o.client_cas
            && self.client_pins == o.client_pins
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
/// else not group/other-writable.
fn read_pem(what: &str, path: &Path, euid: u32, secret: bool) -> Result<Vec<u8>, String> {
    let shown = path.display();
    if !path.is_absolute() {
        return Err(format!(
            "control_plane.tls.{what} {shown}: must be absolute"
        ));
    }
    let lmeta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("control_plane.tls.{what} {shown}: {e}"))?;
    if !lmeta.file_type().is_file() {
        return Err(format!(
            "control_plane.tls.{what} {shown}: not a regular file (symlinks are refused)"
        ));
    }
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
    let bytes = super::fsutil::read_capped_nofollow(path, MAX_PEM_BYTES)
        .map_err(|e| format!("control_plane.tls.{what} {shown}: {e}"))?;
    Ok(bytes)
}

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
        let server_spki = spki_sha256(&chain[0]).map_err(|e| {
            format!(
                "control_plane.tls.cert_chain {}: {e}",
                self.cert_chain.display()
            )
        })?;
        let client_cas = roots.len();
        let config = server_config(chain, key, roots, &pins)?;
        Ok(TlsSpec {
            config,
            server_spki_sha256: robodr_blackbox::crypto::to_hex(&server_spki),
            client_cas,
            client_pins: pins.len(),
        })
    }
}

/// The rustls server configuration (see the module docs).
pub fn server_config(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    client_roots: RootCertStore,
    pins: &[[u8; 32]],
) -> Result<Arc<ServerConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let inner =
        WebPkiClientVerifier::builder_with_provider(Arc::new(client_roots), provider.clone())
            .build()
            .map_err(|e| format!("control_plane.tls.client_ca: {e}"))?;
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
    Ok(Arc::new(cfg))
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
    fn set_read_deadline(&self, d: Duration) -> io::Result<()> {
        self.0.sock.tcp.set_read_timeout(Some(d))
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
    while s.conn.is_handshaking() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err("timed out".into());
        }
        s.sock
            .tcp
            .set_read_timeout(Some(left.max(Duration::from_millis(1))))
            .map_err(|e| e.to_string())?;
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
