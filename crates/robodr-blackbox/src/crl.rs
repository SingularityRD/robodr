//! Certificate revocation lists (X.509 v2 CRLs) for every rustls verifier
//! of the workspace: the remote head anchor (client and receiver), the
//! Kafka producer, `robodr-uplink` / `robodr-enroll` and agentd's control
//! plane all build their WebPKI verifiers through [`server_verifier`] /
//! [`client_verifier`].
//!
//! # Policy (fixed, fail closed)
//!
//! * `crl_files`: up to [`MAX_CRL_FILES`] files, each PEM (one or more
//!   `X509 CRL` sections) or a single DER CRL. A file without a CRL, a CRL
//!   that does not parse, or one rustls refuses is a **configuration
//!   error** at start.
//! * The **whole chain** is checked (end entity and intermediates, not the
//!   trust anchor), and a certificate whose issuer has no CRL in the files
//!   is refused (unknown status fails closed): give a current CRL of every
//!   CA that issues peer certificates.
//! * `nextUpdate` **is enforced**: once a CRL is past it, every handshake
//!   that needs it fails (`ExpiredRevocationList`) until a fresh CRL is put
//!   in place. Start does not fail on an expired CRL (the rest of the
//!   daemon keeps running; the TLS path refuses).
//! * No setting relaxes any of this.
//!
//! # Reload without restart
//!
//! Before every certificate verification (one per handshake) the files are
//! `stat`ed (device, inode, size, mtime, ctime). When any changed they are
//! read again and the verifier rebuilt: a CRL replaced in place (write a
//! new file and `rename` it over the old one) applies to the next
//! handshake. A reload that fails (unreadable, unparsable, no CRL) **fails
//! closed**: every handshake is refused, with the reason in
//! [`CrlStatus::error`], until the files are fixed (the next change is
//! picked up again). The trust anchors, pins and keys are not reloaded.
//!
//! # Status
//!
//! [`CrlStats`] counts reloads and the peers refused as revoked (the last
//! one's SPKI SHA-256 is kept), on an expired CRL, or with an unknown
//! status; the daemons report it ([`CrlStats::status`]).
//!
//! # No OCSP
//!
//! OCSP (and stapling) is deliberately not used: RoboDR fleets run
//! air-gapped or behind a data diode, where a robot cannot reach a
//! responder, and a soft-fail OCSP check protects nothing. A CRL is a
//! signed file that travels with the same out-of-band configuration
//! channel as the CA bundle.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, OtherError, RootCertStore,
    SignatureScheme,
};
use serde::Serialize;
use std::fmt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

/// Most CRL files per verifier.
pub const MAX_CRL_FILES: usize = 16;

/// Reads one CRL file with the component's file checks (owner, mode,
/// size); returns its bytes.
pub type ReadFn = dyn Fn(&Path) -> Result<Vec<u8>, String> + Send + Sync;

/// The CRL files of one verifier.
#[derive(Clone)]
pub struct CrlFiles {
    /// The setting's name in messages (`crl_files`,
    /// `control_plane.tls.crl_files`, `--crl-file`).
    pub what: String,
    pub files: Vec<PathBuf>,
    read: Arc<ReadFn>,
}

impl fmt::Debug for CrlFiles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CrlFiles")
            .field("what", &self.what)
            .field("files", &self.files)
            .finish_non_exhaustive()
    }
}

impl CrlFiles {
    /// `None` without files; at most [`MAX_CRL_FILES`]. Files are read by
    /// [`crate::tls::read_pem`] (regular file, owner root or this user, not
    /// group/other-writable, at most [`crate::tls::MAX_PEM_BYTES`]).
    pub fn new(what: &str, files: &[PathBuf]) -> Result<Option<Self>, String> {
        let w = what.to_string();
        Self::with_reader(
            what,
            files,
            Arc::new(move |p: &Path| crate::tls::read_pem(&w, p, false).map(|b| b.to_vec())),
        )
    }

    /// As [`CrlFiles::new`] with the component's own file checks.
    pub fn with_reader(
        what: &str,
        files: &[PathBuf],
        read: Arc<ReadFn>,
    ) -> Result<Option<Self>, String> {
        if files.is_empty() {
            return Ok(None);
        }
        if files.len() > MAX_CRL_FILES {
            return Err(format!("{what}: at most {MAX_CRL_FILES} files"));
        }
        Ok(Some(Self {
            what: what.to_string(),
            files: files.to_vec(),
            read,
        }))
    }

    /// Read and split every file into CRLs (not yet checked by rustls).
    pub fn load(&self) -> Result<Vec<CertificateRevocationListDer<'static>>, String> {
        let mut out = Vec::new();
        for p in &self.files {
            let shown = p.display();
            let bytes = (self.read)(p)?;
            let mut n = 0;
            for c in CertificateRevocationListDer::pem_slice_iter(&bytes) {
                out.push(c.map_err(|e| format!("{} {shown}: {e}", self.what))?);
                n += 1;
            }
            if n == 0 {
                if bytes.first() == Some(&0x30) {
                    // A single DER CRL.
                    out.push(CertificateRevocationListDer::from(bytes));
                } else {
                    return Err(format!("{} {shown}: no X509 CRL in it", self.what));
                }
            }
        }
        // Each must parse (rustls would refuse it too; the message names
        // the setting).
        for c in &out {
            webpki::OwnedCertRevocationList::from_der(c.as_ref())
                .map_err(|e| format!("{}: a CRL does not parse: {e}", self.what))?;
        }
        Ok(out)
    }

    fn stamps(&self) -> Vec<Option<Stamp>> {
        self.files
            .iter()
            .map(|p| {
                std::fs::metadata(p).ok().map(|m| Stamp {
                    dev: m.dev(),
                    ino: m.ino(),
                    size: m.size(),
                    mtime: (m.mtime(), m.mtime_nsec()),
                    ctime: (m.ctime(), m.ctime_nsec()),
                })
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

/// Live counters of one verifier's revocation checking.
#[derive(Debug, Default)]
pub struct CrlStats {
    files: AtomicU64,
    crls: AtomicU64,
    reloads: AtomicU64,
    reload_failures: AtomicU64,
    revoked: AtomicU64,
    expired: AtomicU64,
    unknown: AtomicU64,
    error: Mutex<Option<String>>,
    last_revoked: Mutex<Option<String>>,
}

/// A snapshot of [`CrlStats`] (status files, heartbeats).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CrlStatus {
    pub files: u64,
    /// CRLs in use (0 while [`CrlStatus::error`] is set).
    pub crls: u64,
    /// Successful reloads after start.
    pub reloads: u64,
    pub reload_failures: u64,
    /// Set while the files on disk are unusable: every handshake is
    /// refused (fail closed).
    pub error: Option<String>,
    /// Peers refused because a CRL lists their (or an intermediate's)
    /// certificate.
    pub revoked_rejections: u64,
    /// Handshakes refused because the CRL needed is past its `nextUpdate`.
    pub expired_crl_rejections: u64,
    /// Handshakes refused because no CRL covers a certificate's issuer.
    pub unknown_status_rejections: u64,
    /// SPKI SHA-256 (hex) of the last peer refused as revoked.
    pub last_revoked_spki_sha256: Option<String>,
}

impl CrlStats {
    pub fn status(&self) -> CrlStatus {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        CrlStatus {
            files: g(&self.files),
            crls: g(&self.crls),
            reloads: g(&self.reloads),
            reload_failures: g(&self.reload_failures),
            error: lock(&self.error).clone(),
            revoked_rejections: g(&self.revoked),
            expired_crl_rejections: g(&self.expired),
            unknown_status_rejections: g(&self.unknown),
            last_revoked_spki_sha256: lock(&self.last_revoked).clone(),
        }
    }

    /// Count a verification failure that is about revocation.
    fn note(&self, e: &rustls::Error, end_entity: &CertificateDer<'_>) {
        match e {
            rustls::Error::InvalidCertificate(CertificateError::Revoked) => {
                self.revoked.fetch_add(1, Ordering::Relaxed);
                *lock(&self.last_revoked) = crate::tls::spki_sha256(end_entity)
                    .ok()
                    .map(|h| crate::crypto::to_hex(&h));
            }
            rustls::Error::InvalidCertificate(
                CertificateError::ExpiredRevocationList
                | CertificateError::ExpiredRevocationListContext { .. },
            ) => {
                self.expired.fetch_add(1, Ordering::Relaxed);
            }
            rustls::Error::InvalidCertificate(CertificateError::UnknownRevocationStatus) => {
                self.unknown.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The CRLs on disk are unusable (reload failed): fail closed.
#[derive(Debug)]
struct CrlUnusable(String);

impl fmt::Display for CrlUnusable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "certificate revocation lists unusable (fail closed): {}",
            self.0
        )
    }
}

impl std::error::Error for CrlUnusable {}

type Build<V> =
    dyn Fn(Vec<CertificateRevocationListDer<'static>>) -> Result<Arc<V>, String> + Send + Sync;

struct Live<V: ?Sized> {
    stamps: Vec<Option<Stamp>>,
    current: Result<Arc<V>, String>,
}

/// A verifier rebuilt from the CRL files whenever they change.
struct Reloading<V: ?Sized> {
    files: CrlFiles,
    build: Box<Build<V>>,
    live: Mutex<Live<V>>,
    stats: Arc<CrlStats>,
}

impl<V: ?Sized> Reloading<V> {
    fn new(files: CrlFiles, build: Box<Build<V>>) -> Result<(Self, Arc<V>), String> {
        let stamps = files.stamps();
        let crls = files.load()?;
        let n = crls.len() as u64;
        let first = build(crls)?;
        let stats = Arc::new(CrlStats::default());
        stats
            .files
            .store(files.files.len() as u64, Ordering::Relaxed);
        stats.crls.store(n, Ordering::Relaxed);
        Ok((
            Self {
                files,
                build,
                live: Mutex::new(Live {
                    stamps,
                    current: Ok(first.clone()),
                }),
                stats,
            },
            first,
        ))
    }

    /// The verifier for this handshake (reloaded first if a file changed).
    fn current(&self) -> Result<Arc<V>, rustls::Error> {
        let stamps = self.files.stamps();
        let mut live = lock(&self.live);
        if stamps != live.stamps {
            live.stamps = stamps;
            let loaded = self.files.load().and_then(|crls| {
                let n = crls.len() as u64;
                (self.build)(crls).map(|v| (v, n))
            });
            match loaded {
                Ok((v, n)) => {
                    self.stats.reloads.fetch_add(1, Ordering::Relaxed);
                    self.stats.crls.store(n, Ordering::Relaxed);
                    *lock(&self.stats.error) = None;
                    live.current = Ok(v);
                }
                Err(e) => {
                    self.stats.reload_failures.fetch_add(1, Ordering::Relaxed);
                    self.stats.crls.store(0, Ordering::Relaxed);
                    *lock(&self.stats.error) = Some(e.clone());
                    live.current = Err(e);
                }
            }
        }
        live.current.clone().map_err(|e| {
            rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(
                CrlUnusable(e),
            ))))
        })
    }
}

/// A server-certificate verifier (for a TLS client): WebPKI, plus the CRLs
/// of `crls` if any (module docs). The stats are `None` without CRLs.
pub fn server_verifier(
    roots: Arc<RootCertStore>,
    provider: Arc<rustls::crypto::CryptoProvider>,
    crls: Option<CrlFiles>,
) -> Result<(Arc<dyn ServerCertVerifier>, Option<Arc<CrlStats>>), String> {
    let Some(files) = crls else {
        let v: Arc<dyn ServerCertVerifier> =
            WebPkiServerVerifier::builder_with_provider(roots, provider)
                .build()
                .map_err(|e| format!("TLS: {e}"))?;
        return Ok((v, None));
    };
    let what = files.what.clone();
    let build: Box<Build<dyn ServerCertVerifier>> = Box::new(move |c| {
        let v: Arc<dyn ServerCertVerifier> =
            WebPkiServerVerifier::builder_with_provider(roots.clone(), provider.clone())
                .with_crls(c)
                .enforce_revocation_expiration()
                .build()
                .map_err(|e| format!("{what}: {e}"))?;
        Ok(v)
    });
    let (reloading, base) = Reloading::new(files, build)?;
    let stats = reloading.stats.clone();
    Ok((Arc::new(CrlServerVerifier { reloading, base }), Some(stats)))
}

/// A client-certificate verifier (for a TLS server; a client certificate
/// is mandatory): WebPKI, plus the CRLs of `crls` if any (module docs).
pub fn client_verifier(
    roots: Arc<RootCertStore>,
    provider: Arc<rustls::crypto::CryptoProvider>,
    crls: Option<CrlFiles>,
) -> Result<(Arc<dyn ClientCertVerifier>, Option<Arc<CrlStats>>), String> {
    let Some(files) = crls else {
        let v = WebPkiClientVerifier::builder_with_provider(roots, provider)
            .build()
            .map_err(|e| format!("TLS: {e}"))?;
        return Ok((v, None));
    };
    let what = files.what.clone();
    let build: Box<Build<dyn ClientCertVerifier>> = Box::new(move |c| {
        WebPkiClientVerifier::builder_with_provider(roots.clone(), provider.clone())
            .with_crls(c)
            .enforce_revocation_expiration()
            .build()
            .map_err(|e| format!("{what}: {e}"))
    });
    let (reloading, base) = Reloading::new(files, build)?;
    let stats = reloading.stats.clone();
    Ok((Arc::new(CrlClientVerifier { reloading, base }), Some(stats)))
}

/// [`server_verifier`] with CRLs. `base` (the verifier built at start)
/// answers everything that does not depend on the CRLs.
struct CrlServerVerifier {
    reloading: Reloading<dyn ServerCertVerifier>,
    base: Arc<dyn ServerCertVerifier>,
}

impl fmt::Debug for CrlServerVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CrlServerVerifier")
            .field("files", &self.reloading.files)
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for CrlServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let v = self.reloading.current()?;
        v.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            .inspect_err(|e| self.reloading.stats.note(e, end_entity))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.base.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.base.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.base.supported_verify_schemes()
    }
}

/// [`client_verifier`] with CRLs.
struct CrlClientVerifier {
    reloading: Reloading<dyn ClientCertVerifier>,
    base: Arc<dyn ClientCertVerifier>,
}

impl fmt::Debug for CrlClientVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CrlClientVerifier")
            .field("files", &self.reloading.files)
            .finish_non_exhaustive()
    }
}

impl ClientCertVerifier for CrlClientVerifier {
    fn offer_client_auth(&self) -> bool {
        self.base.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.base.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.base.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let v = self.reloading.current()?;
        v.verify_client_cert(end_entity, intermediates, now)
            .inspect_err(|e| self.reloading.stats.note(e, end_entity))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.base.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.base.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.base.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/tls")
            .join(name)
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("robodr-crl-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn put(d: &Path, from: &str, to: &str) -> PathBuf {
        let p = d.join(to);
        let tmp = d.join(format!(".{to}.tmp"));
        std::fs::copy(fixture(from), &tmp).unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::rename(&tmp, &p).unwrap();
        p
    }

    fn cert(name: &str) -> CertificateDer<'static> {
        CertificateDer::from_pem_file(fixture(name)).unwrap()
    }

    fn roots() -> Arc<RootCertStore> {
        let mut r = RootCertStore::empty();
        r.add(cert("crl-ca.pem")).unwrap();
        Arc::new(r)
    }

    fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    fn check(v: &Arc<dyn ServerCertVerifier>, leaf: &str) -> Result<(), rustls::Error> {
        v.verify_server_cert(
            &cert(leaf),
            &[],
            &ServerName::try_from("localhost").unwrap(),
            &[],
            UnixTime::now(),
        )
        .map(|_| ())
    }

    #[test]
    fn files_are_bounded_and_must_hold_a_crl() {
        assert!(CrlFiles::new("crl_files", &[]).unwrap().is_none());
        let many = vec![PathBuf::from("/x"); MAX_CRL_FILES + 1];
        assert!(CrlFiles::new("crl_files", &many).is_err());
        let d = tmp("bad");
        let not_crl = put(&d, "crl-ca.pem", "x.pem");
        let f = CrlFiles::new("crl_files", &[not_crl]).unwrap().unwrap();
        let e = f.load().unwrap_err();
        assert!(e.contains("no X509 CRL"), "{e}");
        std::fs::write(d.join("junk.crl"), b"\x30\x03\x02\x01\x00").unwrap();
        std::fs::set_permissions(d.join("junk.crl"), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        let f = CrlFiles::new("crl_files", &[d.join("junk.crl")])
            .unwrap()
            .unwrap();
        let e = f.load().unwrap_err();
        assert!(e.contains("does not parse"), "{e}");
        assert!(server_verifier(roots(), provider(), Some(f)).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn revoked_refused_and_counted_unrevoked_accepted() {
        let d = tmp("revoked");
        let crl = put(&d, "crl-ca.crl.pem", "ca.crl");
        let files = CrlFiles::new("crl_files", &[crl]).unwrap();
        let (v, stats) = server_verifier(roots(), provider(), files).unwrap();
        let stats = stats.unwrap();
        assert_eq!(check(&v, "crl-server.pem"), Ok(()));
        assert_eq!(
            check(&v, "crl-revoked-server.pem"),
            Err(rustls::Error::InvalidCertificate(CertificateError::Revoked))
        );
        let s = stats.status();
        assert_eq!((s.files, s.crls, s.revoked_rejections), (1, 1, 1));
        let spki = crate::tls::spki_sha256(&cert("crl-revoked-server.pem")).unwrap();
        assert_eq!(
            s.last_revoked_spki_sha256,
            Some(crate::crypto::to_hex(&spki))
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_der_crl_is_accepted() {
        let d = tmp("der");
        let der = CertificateRevocationListDer::from_pem_file(fixture("crl-ca.crl.pem")).unwrap();
        std::fs::write(d.join("ca.crl"), der.as_ref()).unwrap();
        std::fs::set_permissions(d.join("ca.crl"), std::fs::Permissions::from_mode(0o644)).unwrap();
        let files = CrlFiles::new("crl_files", &[d.join("ca.crl")]).unwrap();
        let (v, _) = server_verifier(roots(), provider(), files).unwrap();
        assert!(check(&v, "crl-revoked-server.pem").is_err());
        assert_eq!(check(&v, "crl-server.pem"), Ok(()));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn crls_reload_when_the_file_changes_and_fail_closed_when_broken() {
        let d = tmp("reload");
        let crl = put(&d, "crl-ca-empty.crl.pem", "ca.crl");
        let files = CrlFiles::new("crl_files", std::slice::from_ref(&crl)).unwrap();
        let (v, stats) = server_verifier(roots(), provider(), files).unwrap();
        let stats = stats.unwrap();
        assert_eq!(check(&v, "crl-revoked-server.pem"), Ok(()));
        // The new CRL applies to the next verification.
        put(&d, "crl-ca.crl.pem", "ca.crl");
        assert_eq!(
            check(&v, "crl-revoked-server.pem"),
            Err(rustls::Error::InvalidCertificate(CertificateError::Revoked))
        );
        assert_eq!(check(&v, "crl-server.pem"), Ok(()));
        assert_eq!(stats.status().reloads, 1);
        // A broken file: everything is refused, the reason reported.
        put(&d, "crl-ca.pem", "ca.crl");
        let e = check(&v, "crl-server.pem").unwrap_err();
        assert!(e.to_string().contains("CrlUnusable"), "{e}");
        let s = stats.status();
        assert_eq!((s.reload_failures, s.crls), (1, 0));
        assert!(s.error.unwrap().contains("no X509 CRL"));
        // A missing file is no better.
        std::fs::remove_file(&crl).unwrap();
        assert!(check(&v, "crl-server.pem").is_err());
        // Fixed again.
        put(&d, "crl-ca.crl.pem", "ca.crl");
        assert_eq!(check(&v, "crl-server.pem"), Ok(()));
        let s = stats.status();
        assert_eq!((s.reloads, s.error, s.crls), (2, None, 1));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn an_expired_crl_refuses_every_peer_it_covers() {
        let d = tmp("expired");
        let crl = put(&d, "crl-ca-expired.crl.pem", "ca.crl");
        let files = CrlFiles::new("crl_files", &[crl]).unwrap();
        // Start does not fail on it ...
        let (v, stats) = server_verifier(roots(), provider(), files).unwrap();
        // ... but no handshake it covers succeeds, revoked or not.
        for leaf in ["crl-server.pem", "crl-revoked-server.pem"] {
            let e = check(&v, leaf).unwrap_err();
            assert!(
                matches!(
                    e,
                    rustls::Error::InvalidCertificate(
                        CertificateError::ExpiredRevocationListContext { .. }
                            | CertificateError::ExpiredRevocationList
                    )
                ),
                "{e:?}"
            );
        }
        assert_eq!(stats.unwrap().status().expired_crl_rejections, 2);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn an_issuer_without_a_crl_is_refused() {
        let d = tmp("unknown");
        let crl = put(&d, "crl-ca.crl.pem", "ca.crl");
        let mut r = RootCertStore::empty();
        r.add(cert("crl-ca.pem")).unwrap();
        r.add(cert("ca.pem")).unwrap();
        let files = CrlFiles::new("crl_files", &[crl]).unwrap();
        let (v, stats) = server_verifier(Arc::new(r), provider(), files).unwrap();
        assert_eq!(
            check(&v, "server.pem"),
            Err(rustls::Error::InvalidCertificate(
                CertificateError::UnknownRevocationStatus
            ))
        );
        assert_eq!(stats.unwrap().status().unknown_status_rejections, 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn client_verifier_refuses_a_revoked_client() {
        let d = tmp("client");
        let crl = put(&d, "crl-ca.crl.pem", "ca.crl");
        let files = CrlFiles::new("crl_files", &[crl]).unwrap();
        let (v, stats) = client_verifier(roots(), provider(), files).unwrap();
        assert!(v.client_auth_mandatory());
        assert!(!v.root_hint_subjects().is_empty());
        let now = UnixTime::now();
        assert!(v
            .verify_client_cert(&cert("crl-client.pem"), &[], now)
            .is_ok());
        assert_eq!(
            v.verify_client_cert(&cert("crl-revoked-client.pem"), &[], now)
                .map(|_| ()),
            Err(rustls::Error::InvalidCertificate(CertificateError::Revoked))
        );
        assert_eq!(stats.unwrap().status().revoked_rejections, 1);
        let _ = std::fs::remove_dir_all(&d);
    }
}
