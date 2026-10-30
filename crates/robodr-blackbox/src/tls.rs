//! Blocking TLS helpers shared by the remote head anchor (client
//! [`crate::RemoteHeadAnchor`] and server [`crate::AnchorReceiver`]) and the
//! Kafka producer of `robodr-export`: rustls (ring provider, TLS 1.3 and 1.2
//! with rustls' safe defaults, the same crates and versions as
//! `robodr-uplink` and agentd's control plane) over a `std::net::TcpStream`.
//!
//! # Client ([`ClientTlsFiles`], [`load_client`])
//!
//! * **Server verification is always on.** Trust anchors are the operator's
//!   CA file (PEM, one or more `CERTIFICATE`s) and nothing else: no system
//!   or built-in roots. rustls' WebPKI verifier checks the chain to one of
//!   them, the validity period, the `serverAuth` EKU and the **server
//!   name** (SNI and the name checked are the same: the host of the address
//!   dialled, or the configured `server_name`; an IP literal is checked
//!   against the certificate's IP SANs). There is no switch that disables
//!   any of this.
//! * Optional SHA-256 SPKI pins of the server's end-entity certificate, **in
//!   addition to** (never instead of) the chain check.
//! * Optional client certificate (mutual TLS): `cert_chain` + `key_file`,
//!   both or neither.
//! * Optional `crl_files`: the server's chain is also checked against
//!   these CRLs ([`crate::crl`]: whole chain, unknown status and an expired
//!   CRL fail closed, files reloaded when they change).
//!
//! # Server ([`ServerTlsFiles`], [`load_server`])
//!
//! * `cert_chain` (end-entity first) + `key_file`.
//! * Optional `client_ca`: then a client certificate chaining to it (validity,
//!   `clientAuth` EKU) is **mandatory**; a handshake without one fails.
//! * Optional `crl_files` (needs `client_ca`): client certificates are also
//!   checked against these CRLs ([`crate::crl`]).
//! * No session resumption (no tickets, no cache): every connection
//!   authenticates afresh.
//!
//! # Files
//!
//! Every file is a regular file (symlinks are followed; a FIFO or device
//! is refused without blocking), at most [`MAX_PEM_BYTES`], owned by root
//! or the process's effective user. A private key file must not be
//! group-writable or accessible to others at all (`chmod 600` or `640`); a
//! certificate or CA file must not be writable by group or others. Secret
//! file contents are read into a buffer that is wiped when dropped.
//!
//! # No downgrade
//!
//! Nothing here falls back to plain TCP: a peer that does not complete the
//! handshake (a plaintext server, a TLS 1.0/1.1-only server, a wrong
//! certificate) is an error. Whether plain TCP is allowed at all is the
//! caller's explicit configuration (`allow_plaintext`), never a fallback.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::NoServerSessionStorage;
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, OtherError,
    RootCertStore, ServerConfig, ServerConnection, SignatureScheme, StreamOwned,
};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

/// Largest certificate / CA / key file read.
pub const MAX_PEM_BYTES: u64 = 1024 * 1024;
/// Most SPKI pins.
pub const MAX_PINS: usize = 16;

/// Client-side TLS settings (paths; nothing is read until [`load_client`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientTlsFiles {
    /// PEM CA bundle: the only trust anchors.
    pub ca_file: PathBuf,
    /// Client certificate chain (PEM, end-entity first) for mutual TLS.
    pub cert_chain: Option<PathBuf>,
    /// The client certificate's private key (PEM PKCS#8 / SEC1 / PKCS#1).
    pub key_file: Option<PathBuf>,
    /// Name sent as SNI and verified in the server certificate instead of
    /// the host of the address dialled (a DNS name or an IP literal).
    pub server_name: Option<String>,
    /// SHA-256 pins of the server's end-entity SubjectPublicKeyInfo (64 hex
    /// digits each), checked in addition to the chain.
    pub spki_sha256: Vec<String>,
    /// CRLs (PEM or DER) the server's chain is checked against
    /// ([`crate::crl`]); empty: no revocation check.
    pub crl_files: Vec<PathBuf>,
}

/// A loaded client configuration.
#[derive(Clone)]
pub struct ClientTls {
    pub config: Arc<ClientConfig>,
    /// [`ClientTlsFiles::server_name`], parsed.
    pub server_name: Option<ServerName<'static>>,
    /// A client certificate is presented.
    pub client_auth: bool,
    /// Number of SPKI pins.
    pub pins: usize,
    /// Revocation counters (with `crl_files`).
    pub crl: Option<Arc<crate::crl::CrlStats>>,
}

impl fmt::Debug for ClientTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientTls")
            .field("server_name", &self.server_name)
            .field("client_auth", &self.client_auth)
            .field("pins", &self.pins)
            .field("crl", &self.crl.as_ref().map(|c| c.status()))
            .finish_non_exhaustive()
    }
}

impl ClientTls {
    /// The name verified when dialling `host` (the configured
    /// `server_name`, else `host` itself; `[v6]` brackets are stripped).
    pub fn name_for(&self, host: &str) -> Result<ServerName<'static>, String> {
        match &self.server_name {
            Some(n) => Ok(n.clone()),
            None => server_name(host),
        }
    }
}

/// Server-side TLS settings (paths).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerTlsFiles {
    /// Server certificate chain (PEM, end-entity first).
    pub cert_chain: PathBuf,
    /// Its private key.
    pub key_file: PathBuf,
    /// When set, clients must present a certificate chaining to one of
    /// these CAs (mutual TLS).
    pub client_ca: Option<PathBuf>,
    /// CRLs (PEM or DER) client certificates are checked against
    /// ([`crate::crl`]; needs `client_ca`).
    pub crl_files: Vec<PathBuf>,
}

/// A loaded server configuration.
#[derive(Clone)]
pub struct ServerTls {
    pub config: Arc<ServerConfig>,
    /// Revocation counters (with `crl_files`).
    pub crl: Option<Arc<crate::crl::CrlStats>>,
}

impl fmt::Debug for ServerTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerTls")
            .field("crl", &self.crl.as_ref().map(|c| c.status()))
            .finish_non_exhaustive()
    }
}

/// Parse a TLS server name: a DNS name or an IP literal (`[v6]` brackets
/// allowed).
pub fn server_name(host: &str) -> Result<ServerName<'static>, String> {
    let h = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = h.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(h.to_string()).map_err(|e| format!("TLS server name {h:?}: {e}"))
}

/// The host part of a `host:port` address (`[v6]:port` keeps no brackets).
pub fn host_of(address: &str) -> &str {
    let host = address.rsplit_once(':').map_or(address, |(h, _)| h);
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

/// Parse a pin: 64 hex digits (case-insensitive).
pub fn parse_pin(s: &str) -> Result<[u8; 32], String> {
    match crate::crypto::from_hex(&s.to_ascii_lowercase()) {
        Some(v) if v.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(&v);
            Ok(out)
        }
        _ => Err(format!(
            "SPKI pin {:?}: must be 64 hex digits (SHA-256 of the DER SubjectPublicKeyInfo)",
            s.chars().take(80).collect::<String>()
        )),
    }
}

/// SHA-256 of a certificate's DER `SubjectPublicKeyInfo`.
pub fn spki_sha256(cert: &CertificateDer<'_>) -> Result<[u8; 32], String> {
    let ee = webpki::EndEntityCert::try_from(cert).map_err(|e| format!("certificate: {e}"))?;
    Ok(crate::crypto::sha256(ee.subject_public_key_info().as_ref()))
}

/// Read a PEM file (module docs, "Files"); `secret`: a private key.
pub fn read_pem(
    what: &str,
    path: &Path,
    secret: bool,
) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let shown = path.display();
    // O_NONBLOCK: a FIFO (or a device) swapped in never blocks the open;
    // the fstat below then refuses it. It has no effect on a regular file.
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK)
        .open(path)
        .map_err(|e| format!("{what} {shown}: {e}"))?;
    let meta = f.metadata().map_err(|e| format!("{what} {shown}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{what} {shown}: not a regular file"));
    }
    let euid = crate::keys::effective_uid();
    if meta.uid() != 0 && meta.uid() != euid {
        return Err(format!(
            "{what} {shown}: owned by uid {}, not by root or this process's uid {euid}",
            meta.uid()
        ));
    }
    let mode = meta.permissions().mode() & 0o777;
    if secret && mode & 0o027 != 0 {
        return Err(format!(
            "{what} {shown}: mode {mode:03o} lets others read or the group write the private \
             key; chmod 600 (or 640)"
        ));
    }
    if !secret && mode & 0o022 != 0 {
        return Err(format!(
            "{what} {shown}: mode {mode:03o} lets group/others write it; chmod 644"
        ));
    }
    if meta.len() > MAX_PEM_BYTES {
        return Err(format!("{what} {shown}: larger than {MAX_PEM_BYTES} bytes"));
    }
    // Sized up front and capped at that size plus one, so the buffer never
    // reallocates (no unwiped copy of a secret is left behind).
    let cap = meta.len() + 1;
    let mut buf = zeroize::Zeroizing::new(Vec::with_capacity(cap as usize));
    f.take(cap)
        .read_to_end(&mut buf)
        .map_err(|e| format!("{what} {shown}: {e}"))?;
    if buf.len() as u64 > meta.len() {
        return Err(format!("{what} {shown}: changed while being read"));
    }
    Ok(buf)
}

/// `O_NONBLOCK` (Linux: the same value on x86_64 and aarch64).
const O_NONBLOCK: i32 = 0o4000;

fn certs(what: &str, path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let pem = read_pem(what, path, false)?;
    let mut out = Vec::new();
    for c in CertificateDer::pem_slice_iter(&pem) {
        out.push(c.map_err(|e| format!("{what} {}: {e}", path.display()))?);
    }
    if out.is_empty() {
        return Err(format!("{what} {}: no CERTIFICATE in it", path.display()));
    }
    Ok(out)
}

fn roots(what: &str, path: &Path) -> Result<RootCertStore, String> {
    let mut r = RootCertStore::empty();
    for c in certs(what, path)? {
        r.add(c)
            .map_err(|e| format!("{what} {}: {e}", path.display()))?;
    }
    Ok(r)
}

fn private_key(what: &str, path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    let pem = read_pem(what, path, true)?;
    PrivateKeyDer::from_pem_slice(&pem)
        .map_err(|e| format!("{what} {}: no usable private key ({e})", path.display()))
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Load the client settings (module docs, "Client").
pub fn load_client(f: &ClientTlsFiles) -> Result<ClientTls, String> {
    let roots = Arc::new(roots("ca_file", &f.ca_file)?);
    if f.spki_sha256.len() > MAX_PINS {
        return Err(format!("spki_sha256: at most {MAX_PINS} pins"));
    }
    let pins = f
        .spki_sha256
        .iter()
        .map(|p| parse_pin(p))
        .collect::<Result<Vec<_>, _>>()?;
    let name = f.server_name.as_deref().map(server_name).transpose()?;
    let provider = provider();
    let (inner, crl) = crate::crl::server_verifier(
        roots,
        provider.clone(),
        crate::crl::CrlFiles::new("crl_files", &f.crl_files)?,
    )?;
    // `dangerous()` is rustls' name for "custom verifier"; this one runs the
    // full WebPKI verification first and only adds the pins (if any).
    let b = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinningVerifier {
            inner,
            pins: pins.clone(),
        }));
    let (config, client_auth) = match (&f.cert_chain, &f.key_file) {
        (None, None) => (b.with_no_client_auth(), false),
        (Some(c), Some(k)) => {
            let chain = certs("cert_chain", c)?;
            let key = private_key("key_file", k)?;
            (
                b.with_client_auth_cert(chain, key)
                    .map_err(|e| format!("client certificate / key: {e}"))?,
                true,
            )
        }
        _ => {
            return Err(
                "a client certificate needs both cert_chain and key_file (mutual TLS)".into(),
            )
        }
    };
    Ok(ClientTls {
        config: Arc::new(config),
        server_name: name,
        client_auth,
        pins: pins.len(),
        crl,
    })
}

/// A client key held outside the process (a TPM, Sprint 14a): ECDSA
/// P-256 / SHA-256 only. `sign` receives the SHA-256 digest of the
/// handshake message and returns a DER signature.
pub type ExternalSign = dyn Fn(&[u8; 32]) -> Result<Vec<u8>, String> + Send + Sync;

/// As [`load_client`], with the client certificate's key held elsewhere
/// (`f.key_file` must be unset, `f.cert_chain` set): every signature of
/// the handshake is made by `sign` (`robodr-deliverd` hands it the unit's
/// TPM-resident identity key). Server verification is unchanged.
pub fn load_client_with_signer(
    f: &ClientTlsFiles,
    sign: Arc<ExternalSign>,
) -> Result<ClientTls, String> {
    if f.key_file.is_some() {
        return Err("an external client key replaces key_file; set only cert_chain".into());
    }
    let chain_path = f
        .cert_chain
        .as_ref()
        .ok_or("an external client key needs cert_chain")?;
    let chain = certs("cert_chain", chain_path)?;
    let mut files = f.clone();
    files.cert_chain = None;
    let base = load_client(&files)?;
    // Rebuild with the same verifier and the external key.
    let roots = Arc::new(roots("ca_file", &f.ca_file)?);
    let pins = f
        .spki_sha256
        .iter()
        .map(|p| parse_pin(p))
        .collect::<Result<Vec<_>, _>>()?;
    let provider = provider();
    let (inner, crl) = crate::crl::server_verifier(
        roots,
        provider.clone(),
        crate::crl::CrlFiles::new("crl_files", &f.crl_files)?,
    )?;
    let key: Arc<dyn rustls::sign::SigningKey> = Arc::new(ExternalP256 { sign });
    let certified = Arc::new(rustls::sign::CertifiedKey::new(chain, key));
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinningVerifier { inner, pins }))
        .with_client_cert_resolver(Arc::new(FixedClientCert(certified)));
    Ok(ClientTls {
        config: Arc::new(config),
        server_name: base.server_name,
        client_auth: true,
        pins: base.pins,
        crl,
    })
}

#[derive(Debug)]
struct FixedClientCert(Arc<rustls::sign::CertifiedKey>);

impl rustls::client::ResolvesClientCert for FixedClientCert {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        sigschemes
            .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

struct ExternalP256 {
    sign: Arc<ExternalSign>,
}

impl fmt::Debug for ExternalP256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExternalP256(..)")
    }
}

impl rustls::sign::SigningKey for ExternalP256 {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        offered
            .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| {
                Box::new(ExternalP256Signer {
                    sign: self.sign.clone(),
                }) as Box<dyn rustls::sign::Signer>
            })
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ECDSA
    }
}

struct ExternalP256Signer {
    sign: Arc<ExternalSign>,
}

impl fmt::Debug for ExternalP256Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExternalP256Signer(..)")
    }
}

impl rustls::sign::Signer for ExternalP256Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        (self.sign)(&crate::crypto::sha256(message)).map_err(rustls::Error::General)
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

/// The SubjectPublicKeyInfo (DER) of the peer's end-entity certificate.
pub fn spki_der(cert: &CertificateDer<'_>) -> Result<Vec<u8>, String> {
    let ee = webpki::EndEntityCert::try_from(cert).map_err(|e| format!("certificate: {e}"))?;
    Ok(ee.subject_public_key_info().as_ref().to_vec())
}

/// Load the server settings (module docs, "Server").
pub fn load_server(f: &ServerTlsFiles) -> Result<Arc<ServerConfig>, String> {
    load_server_tls(f).map(|t| t.config)
}

/// As [`load_server`], with the revocation counters.
pub fn load_server_tls(f: &ServerTlsFiles) -> Result<ServerTls, String> {
    let chain = certs("cert_chain", &f.cert_chain)?;
    let key = private_key("key_file", &f.key_file)?;
    let provider = provider();
    let b = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS: {e}"))?;
    let (b, crl) = match &f.client_ca {
        None if !f.crl_files.is_empty() => {
            return Err("crl_files needs client_ca (they check client certificates)".into())
        }
        None => (b.with_no_client_auth(), None),
        Some(ca) => {
            let (v, crl) = crate::crl::client_verifier(
                Arc::new(roots("client_ca", ca)?),
                provider,
                crate::crl::CrlFiles::new("crl_files", &f.crl_files)?,
            )
            .map_err(|e| format!("client_ca {}: {e}", ca.display()))?;
            (b.with_client_cert_verifier(v), crl)
        }
    };
    let mut cfg = b
        .with_single_cert(chain, key)
        .map_err(|e| format!("certificate / key: {e}"))?;
    cfg.session_storage = Arc::new(NoServerSessionStorage {});
    cfg.send_tls13_tickets = 0;
    Ok(ServerTls {
        config: Arc::new(cfg),
        crl,
    })
}

/// Full WebPKI verification (and CRLs), then the SPKI pin check (no pins:
/// WebPKI only).
#[derive(Debug)]
struct PinningVerifier {
    inner: Arc<dyn ServerCertVerifier>,
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
        if self.pins.is_empty() {
            return Ok(ok);
        }
        let h = spki_sha256(end_entity)
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if self.pins.iter().any(|p| crate::crypto::ct_eq(p, &h)) {
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

/// A human-readable reason for a TLS I/O error (rustls reports handshake
/// failures as `io::Error(InvalidData, rustls::Error)`).
pub fn describe(e: &io::Error) -> String {
    if let Some(r) = e.get_ref().and_then(|x| x.downcast_ref::<rustls::Error>()) {
        return match r {
            rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(inner))) => {
                format!("invalid peer certificate: {inner}")
            }
            rustls::Error::InvalidCertificate(c) => format!("invalid peer certificate: {c:?}"),
            other => other.to_string(),
        };
    }
    if matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ) {
        return "timed out".into();
    }
    e.to_string()
}

/// A TCP stream bounded by one deadline: before **every** read and write
/// the socket timeout is set to the time left, and past the deadline the
/// call fails with `TimedOut`. rustls loops over many reads (the handshake's
/// `complete_io`, `StreamOwned::read` while a record is partial), so a
/// timeout armed once would let a peer that sends one byte per timeout hold
/// the connection for ever; this cannot (the pattern of agentd's
/// `DeadlineTcp` and the uplink's `DeadlineStream`).
#[derive(Debug)]
pub struct DeadlineTcp {
    pub tcp: TcpStream,
    deadline: Option<Instant>,
}

impl DeadlineTcp {
    /// No deadline until [`DeadlineTcp::set_deadline`].
    pub fn new(tcp: TcpStream) -> Self {
        Self {
            tcp,
            deadline: None,
        }
    }

    /// Every read and write after this fails once `at` has passed.
    pub fn set_deadline(&mut self, at: Instant) {
        self.deadline = Some(at);
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    fn arm(&self, write: bool) -> io::Result<()> {
        let Some(at) = self.deadline else {
            return Ok(());
        };
        let left = at.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "deadline passed"));
        }
        if write {
            self.tcp.set_write_timeout(Some(left))
        } else {
            self.tcp.set_read_timeout(Some(left))
        }
    }
}

impl Read for DeadlineTcp {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.arm(false)?;
        self.tcp.read(buf).map_err(timed_out)
    }
}

impl Write for DeadlineTcp {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.arm(true)?;
        self.tcp.write(buf).map_err(timed_out)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

/// A socket timeout (`WouldBlock` on Linux) is a `TimedOut`.
fn timed_out(e: io::Error) -> io::Error {
    if e.kind() == io::ErrorKind::WouldBlock {
        io::Error::new(io::ErrorKind::TimedOut, "timed out")
    } else {
        e
    }
}

/// Run the client handshake on `tcp` against `name`, giving up at
/// `deadline`. The returned stream keeps that deadline for every later
/// read and write until the caller moves it ([`DeadlineTcp::set_deadline`]
/// on `sock`).
pub fn connect_client(
    tcp: TcpStream,
    tls: &ClientTls,
    name: ServerName<'static>,
    deadline: Instant,
) -> Result<StreamOwned<ClientConnection, DeadlineTcp>, String> {
    let conn = ClientConnection::new(tls.config.clone(), name).map_err(|e| format!("TLS: {e}"))?;
    let mut sock = DeadlineTcp::new(tcp);
    sock.set_deadline(deadline);
    let mut s = StreamOwned::new(conn, sock);
    while s.conn.is_handshaking() {
        s.conn
            .complete_io(&mut s.sock)
            .map_err(|e| format!("TLS handshake: {}", describe(&e)))?;
    }
    Ok(s)
}

/// Run the server handshake on `tcp`, giving up at `deadline` (kept for
/// later reads and writes, as for [`connect_client`]).
pub fn accept_server(
    tcp: TcpStream,
    config: Arc<ServerConfig>,
    deadline: Instant,
) -> Result<StreamOwned<ServerConnection, DeadlineTcp>, String> {
    let conn = ServerConnection::new(config).map_err(|e| format!("TLS: {e}"))?;
    let mut sock = DeadlineTcp::new(tcp);
    sock.set_deadline(deadline);
    let mut s = StreamOwned::new(conn, sock);
    while s.conn.is_handshaking() {
        s.conn
            .complete_io(&mut s.sock)
            .map_err(|e| format!("TLS handshake: {}", describe(&e)))?;
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_hosts_and_pins() {
        assert_eq!(host_of("127.0.0.1:7461"), "127.0.0.1");
        assert_eq!(host_of("[::1]:7461"), "::1");
        assert_eq!(host_of("anchor.example:7461"), "anchor.example");
        assert!(matches!(server_name("[::1]"), Ok(ServerName::IpAddress(_))));
        assert!(matches!(
            server_name("10.0.0.1"),
            Ok(ServerName::IpAddress(_))
        ));
        assert!(matches!(
            server_name("a.example"),
            Ok(ServerName::DnsName(_))
        ));
        assert!(server_name("bad name").is_err());
        assert!(server_name("").is_err());
        assert!(parse_pin(&"ab".repeat(32)).is_ok());
        assert!(parse_pin(&"AB".repeat(32)).is_ok());
        assert!(parse_pin("ab").is_err());
        assert!(parse_pin(&"zz".repeat(32)).is_err());
    }
}
