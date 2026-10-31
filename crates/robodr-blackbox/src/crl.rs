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
//! * Every CRL must carry a **CRL number** (RFC 5280 §5.2.3): one without
//!   is refused (it cannot be ordered against the CRL it replaces).
//! * A CRL whose issuer is one of the verifier's trust anchors must verify
//!   under that anchor's key **at load** (a forged or corrupted CRL is a
//!   configuration error, not a surprise at the first handshake). A CRL of
//!   an intermediate CA (not a trust anchor) is checked at the handshake,
//!   against the intermediate the peer presents.
//! * **One CRL per issuer** (and issuing distribution point, for
//!   partitioned CRLs): when the files hold several, the one with the
//!   highest CRL number is used and the others are ignored (an old CRL
//!   left in a bundle next to the new one can never win). Two *different*
//!   CRLs with the same issuer and number are a configuration error.
//!   [`CrlStatus::in_use`] names the CRL in use for each issuer.
//! * **No going back**: per issuer, the highest CRL number and
//!   `thisUpdate` loaded so far is a high-water mark. A load whose CRL for
//!   an issuer has a lower number or an older `thisUpdate` (a genuine but
//!   older CRL put back in place would un-revoke certificates) is refused:
//!   at start a configuration error, on a reload **fail closed**
//!   ([`CrlStatus::rollback_refusals`]) until the current CRL is back. The
//!   mark lives in the process; with a state file
//!   ([`CrlFiles::with_state_file`]: the anchor receiver's
//!   `<state_dir>/crl-high-water.json`, agentd's
//!   `<control_plane.state_dir>/crl-high-water.json`) the marks of CRLs
//!   verified against a trust anchor also survive a restart. Elsewhere
//!   (the units' TLS clients, `robodr-uplink`, `robodr-enroll`, the Kafka
//!   producer: no state directory) the mark is per process. A state file
//!   that does not parse refuses start; an operator who really means to go
//!   back (a CA re-keyed and restarted its numbering) removes it.
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
//! read again and the verifier rebuilt: a CRL replaced in place applies to
//! the next handshake. **Replace a CRL file by rename** (write a new file
//! next to it, then `rename` it over the old one): an in-place rewrite can
//! be seen half-written. A file whose `stat` changes while it is read is
//! read once more; if it changes again the load fails (closed). A reload
//! that fails (unreadable, unparsable, no CRL, going back) **fails
//! closed**: every handshake is refused, with the reason in
//! [`CrlStatus::error`], until the files are fixed (the next change is
//! picked up again; while failed, the files are also re-read at most once
//! a second without a change). The trust anchors, pins and keys are not
//! reloaded.
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
use rustls::pki_types::{
    CertificateDer, CertificateRevocationListDer, ServerName, SignatureVerificationAlgorithm,
    UnixTime,
};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, OtherError, RootCertStore,
    SignatureScheme,
};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering as Cmp;
use std::collections::BTreeMap;
use std::fmt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Most CRL files per verifier.
pub const MAX_CRL_FILES: usize = 16;

/// Most issuers (and distribution points) a high-water state file keeps.
pub const MAX_MARKS: usize = 256;

/// Format tag of the high-water state file.
pub const STATE_FORMAT: &str = "robodr-crl-high-water/v1";

/// Conventional name of the high-water state file in a state directory.
pub const STATE_FILE: &str = "crl-high-water.json";

/// While the CRLs are unusable, unchanged files are re-read at most this
/// often (a load that failed on a torn read recovers by itself).
const RETRY_FAILED: Duration = Duration::from_secs(1);

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
    /// Where the high-water marks survive a restart (module docs).
    state: Option<PathBuf>,
}

impl fmt::Debug for CrlFiles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CrlFiles")
            .field("what", &self.what)
            .field("files", &self.files)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// The CRL in use for one issuer (and issuing distribution point).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CrlInUse {
    /// The issuer's common name (else its scope hash).
    pub issuer: String,
    /// SHA-256 (hex) of the issuer name (DER) and the issuing distribution
    /// point: the key of the high-water mark.
    pub scope_sha256: String,
    /// CRL number, hex (big-endian, no leading zero bytes).
    pub crl_number: String,
    /// `thisUpdate`, Unix seconds.
    pub this_update: i64,
    /// `nextUpdate`, Unix seconds (absent in the CRL: `None`). Past it the
    /// CRL no longer vouches for anything and every handshake that needs
    /// it is refused, so this is the date a fresh CRL must be installed by
    /// (agentd's `robot.agent.credential_expiring`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_update: Option<i64>,
    /// The file it came from.
    pub file: String,
    /// Its signature was verified at load against a trust anchor (then its
    /// mark is also persisted, with a state file).
    pub signature_verified: bool,
}

/// One CRL read from the files, with what ordering needs.
struct Candidate {
    der: CertificateRevocationListDer<'static>,
    number: Vec<u8>,
    info: CrlInUse,
}

/// The CRLs of one load: one per scope, highest number.
struct Loaded {
    crls: Vec<CertificateRevocationListDer<'static>>,
    in_use: Vec<(Vec<u8>, CrlInUse)>,
}

/// A trust anchor a CRL signature is checked against at load.
struct Anchor {
    subject: Vec<u8>,
    spki: Vec<u8>,
}

/// What a load checks CRL signatures with.
struct SigCheck {
    anchors: Vec<Anchor>,
    algs: &'static [&'static dyn SignatureVerificationAlgorithm],
}

impl SigCheck {
    fn new(roots: &RootCertStore, provider: &rustls::crypto::CryptoProvider) -> Self {
        Self {
            anchors: roots
                .roots
                .iter()
                .map(|ta| Anchor {
                    subject: ta.subject.as_ref().to_vec(),
                    spki: ta.subject_public_key_info.as_ref().to_vec(),
                })
                .collect(),
            algs: provider.signature_verification_algorithms.all,
        }
    }

    /// `None`: no trust anchor of that name (an intermediate's CRL, checked
    /// at the handshake); else whether one of them verifies it.
    fn verify(&self, m: &CrlMeta<'_>) -> Option<bool> {
        let mut named = false;
        for a in self.anchors.iter().filter(|a| a.subject == m.issuer) {
            named = true;
            let Some((alg, r)) = expect(&a.spki, 0x30) else {
                continue;
            };
            let Some((key, _)) = expect(r, 0x03) else {
                continue;
            };
            let Some((0, key)) = key.content.split_first() else {
                continue;
            };
            let ok = self.algs.iter().any(|v| {
                v.public_key_alg_id().as_ref() == alg.content
                    && v.signature_alg_id().as_ref() == m.sig_alg
                    && v.verify_signature(key, m.tbs, m.sig).is_ok()
            });
            if ok {
                return Some(true);
            }
        }
        named.then_some(false)
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
            state: None,
        }))
    }

    /// Keep the high-water marks (module docs) in `path` too (replaced
    /// atomically, mode 0600; its directory must exist), so that going
    /// back is refused across restarts.
    pub fn with_state_file(mut self, path: &Path) -> Self {
        self.state = Some(path.to_path_buf());
        self
    }

    /// Read one file; read it again if its `stat` changed meanwhile
    /// (module docs, "Reload").
    fn read_stable(&self, p: &Path) -> Result<Vec<u8>, String> {
        for _ in 0..2 {
            let before = stamp(p);
            let bytes = (self.read)(p)?;
            if stamp(p) == before {
                return Ok(bytes);
            }
        }
        Err(format!(
            "{} {}: changed while being read (replace CRL files by rename)",
            self.what,
            p.display()
        ))
    }

    /// Read and split every file into CRLs; keep the newest per scope.
    fn load(&self, sig: &SigCheck) -> Result<Loaded, String> {
        let mut best: BTreeMap<String, Candidate> = BTreeMap::new();
        for p in &self.files {
            let shown = p.display();
            let bytes = self.read_stable(p)?;
            let mut found = Vec::new();
            for c in CertificateRevocationListDer::pem_slice_iter(&bytes) {
                found.push(c.map_err(|e| format!("{} {shown}: {e}", self.what))?);
            }
            if found.is_empty() {
                if bytes.first() == Some(&0x30) {
                    // A single DER CRL.
                    found.push(CertificateRevocationListDer::from(bytes));
                } else {
                    return Err(format!("{} {shown}: no X509 CRL in it", self.what));
                }
            }
            for c in found {
                let cand = self.candidate(c, p, sig)?;
                match best.get(&cand.info.scope_sha256) {
                    None => {}
                    Some(b) => match order(&cand, b) {
                        Cmp::Less => continue,
                        Cmp::Equal if b.der.as_ref() == cand.der.as_ref() => continue,
                        Cmp::Equal => {
                            return Err(format!(
                                "{}: two different CRLs of {} carry CRL number {} ({} and {})",
                                self.what,
                                cand.info.issuer,
                                cand.info.crl_number,
                                b.info.file,
                                cand.info.file
                            ))
                        }
                        Cmp::Greater => {}
                    },
                }
                best.insert(cand.info.scope_sha256.clone(), cand);
            }
        }
        let mut crls = Vec::with_capacity(best.len());
        let mut in_use = Vec::with_capacity(best.len());
        for (_, c) in best {
            crls.push(c.der);
            in_use.push((c.number, c.info));
        }
        Ok(Loaded { crls, in_use })
    }

    fn candidate(
        &self,
        der: CertificateRevocationListDer<'static>,
        p: &Path,
        sig: &SigCheck,
    ) -> Result<Candidate, String> {
        let shown = p.display();
        // rustls would refuse it too; the message names the setting.
        webpki::OwnedCertRevocationList::from_der(der.as_ref())
            .map_err(|e| format!("{} {shown}: a CRL does not parse: {e}", self.what))?;
        let m = CrlMeta::parse(der.as_ref())
            .ok_or_else(|| format!("{} {shown}: a CRL does not parse", self.what))?;
        let issuer = m.issuer_name();
        let number = m.number.clone().ok_or_else(|| {
            format!(
                "{} {shown}: the CRL of {issuer} has no CRL number (RFC 5280 §5.2.3); it \
                 cannot be ordered against the CRL it replaces, so it is refused",
                self.what
            )
        })?;
        let verified = match sig.verify(&m) {
            Some(true) => true,
            Some(false) => {
                return Err(format!(
                    "{} {shown}: the CRL of {issuer} (number {}) does not verify under the trust \
                     anchor of that name (forged or corrupted signature)",
                    self.what,
                    crate::crypto::to_hex(&number)
                ))
            }
            None => false,
        };
        let mut scope = m.issuer.to_vec();
        match m.idp {
            Some(idp) => {
                scope.push(1);
                scope.extend_from_slice(idp);
            }
            None => scope.push(0),
        }
        Ok(Candidate {
            info: CrlInUse {
                issuer,
                scope_sha256: crate::crypto::to_hex(&crate::crypto::sha256(&scope)),
                crl_number: crate::crypto::to_hex(&number),
                this_update: m.this_update,
                next_update: m.next_update,
                file: shown.to_string(),
                signature_verified: verified,
            },
            number,
            der,
        })
    }

    fn stamps(&self) -> Vec<Option<Stamp>> {
        self.files.iter().map(|p| stamp(p)).collect()
    }
}

fn stamp(p: &Path) -> Option<Stamp> {
    std::fs::metadata(p).ok().map(|m| Stamp {
        dev: m.dev(),
        ino: m.ino(),
        size: m.size(),
        mtime: (m.mtime(), m.mtime_nsec()),
        ctime: (m.ctime(), m.ctime_nsec()),
    })
}

/// CRL numbers (no leading zero bytes) compare as unsigned integers.
fn cmp_number(a: &[u8], b: &[u8]) -> Cmp {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

fn order(a: &Candidate, b: &Candidate) -> Cmp {
    cmp_number(&a.number, &b.number).then(a.info.this_update.cmp(&b.info.this_update))
}

// --- Minimal DER reading (the CRL was already parsed by webpki) ---

struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
}

fn tlv(input: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let tag = *input.first()?;
    let l0 = *input.get(1)?;
    let (len, hdr) = if l0 < 0x80 {
        (usize::from(l0), 2usize)
    } else {
        let n = usize::from(l0 & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for b in input.get(2..2 + n)? {
            len = (len << 8) | usize::from(*b);
        }
        (len, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    let content = input.get(hdr..end)?;
    let rest = input.get(end..)?;
    Some((Tlv { tag, content }, rest))
}

fn expect(input: &[u8], tag: u8) -> Option<(Tlv<'_>, &[u8])> {
    let (t, r) = tlv(input)?;
    (t.tag == tag).then_some((t, r))
}

/// The tag and length bytes of a TLV plus its content: the whole element.
fn whole<'a>(input: &'a [u8], rest: &'a [u8]) -> Option<&'a [u8]> {
    input.get(..input.len().checked_sub(rest.len())?)
}

/// What ordering and the signature check need from a CRL.
struct CrlMeta<'a> {
    /// The whole `tbsCertList` element (the signed message).
    tbs: &'a [u8],
    /// `signatureAlgorithm` (content of the AlgorithmIdentifier).
    sig_alg: &'a [u8],
    sig: &'a [u8],
    /// Issuer `Name` (content of the SEQUENCE, as trust anchors keep it).
    issuer: &'a [u8],
    this_update: i64,
    next_update: Option<i64>,
    number: Option<Vec<u8>>,
    idp: Option<&'a [u8]>,
}

impl<'a> CrlMeta<'a> {
    fn parse(der: &'a [u8]) -> Option<Self> {
        let (outer, _) = expect(der, 0x30)?;
        let (tbs, r) = expect(outer.content, 0x30)?;
        let tbs_whole = whole(outer.content, r)?;
        let (alg, r) = expect(r, 0x30)?;
        let (sig, _) = expect(r, 0x03)?;
        let (0, sig) = sig.content.split_first()? else {
            return None;
        };
        let (_, r) = expect(tbs.content, 0x02)?; // version
        let (_, r) = expect(r, 0x30)?; // signature
        let (issuer, r) = expect(r, 0x30)?;
        let (tu, r) = tlv(r)?;
        let this_update = der_time(&tu)?;
        let mut r = r;
        let mut next_update = None;
        if matches!(r.first(), Some(0x17 | 0x18)) {
            let (nu, rest) = tlv(r)?;
            next_update = Some(der_time(&nu)?);
            r = rest;
        }
        if r.first() == Some(&0x30) {
            r = tlv(r)?.1; // revokedCertificates
        }
        let mut number = None;
        let mut idp = None;
        if let Some((exts, _)) = expect(r, 0xa0) {
            let (seq, _) = expect(exts.content, 0x30)?;
            let mut e = seq.content;
            while !e.is_empty() {
                let (ext, rest) = expect(e, 0x30)?;
                e = rest;
                let (oid, mut x) = expect(ext.content, 0x06)?;
                if x.first() == Some(&0x01) {
                    x = tlv(x)?.1; // critical
                }
                let (val, _) = expect(x, 0x04)?;
                match oid.content {
                    // id-ce-cRLNumber 2.5.29.20
                    [0x55, 0x1d, 0x14] => {
                        let (n, _) = expect(val.content, 0x02)?;
                        let mut v = n.content;
                        while let [0, more @ ..] = v {
                            v = more;
                        }
                        number = Some(v.to_vec());
                    }
                    // id-ce-issuingDistributionPoint 2.5.29.28
                    [0x55, 0x1d, 0x1c] => idp = Some(val.content),
                    _ => {}
                }
            }
        }
        Some(Self {
            tbs: tbs_whole,
            sig_alg: alg.content,
            sig,
            issuer: issuer.content,
            this_update,
            next_update,
            number,
            idp,
        })
    }

    /// The issuer's (first) common name, else the hash of its name.
    fn issuer_name(&self) -> String {
        let mut rdns = self.issuer;
        while let Some((set, rest)) = expect(rdns, 0x31) {
            rdns = rest;
            let mut atvs = set.content;
            while let Some((atv, more)) = expect(atvs, 0x30) {
                atvs = more;
                if let Some((oid, v)) = expect(atv.content, 0x06) {
                    if oid.content == [0x55, 0x04, 0x03] {
                        if let Some((val, _)) = tlv(v) {
                            let s: String = String::from_utf8_lossy(val.content)
                                .chars()
                                .filter(|c| !c.is_control())
                                .take(128)
                                .collect();
                            return s;
                        }
                    }
                }
            }
        }
        format!(
            "issuer {}",
            crate::crypto::to_hex(&crate::crypto::sha256(self.issuer))
        )
    }
}

/// UTCTime / GeneralizedTime (`...Z`) to Unix seconds.
fn der_time(t: &Tlv<'_>) -> Option<i64> {
    let s = std::str::from_utf8(t.content).ok()?.strip_suffix('Z')?;
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (y, rest) = match t.tag {
        0x17 => {
            let yy: i64 = s.get(..2)?.parse().ok()?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, s.get(2..)?)
        }
        0x18 => (s.get(..4)?.parse().ok()?, s.get(4..)?),
        _ => return None,
    };
    if rest.len() != 10 {
        return None;
    }
    let n = |i: usize| -> Option<i64> { rest.get(i..i + 2)?.parse().ok() };
    let (mo, d, h, mi, se) = (n(0)?, n(2)?, n(4)?, n(6)?, n(8)?);
    Some(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + se)
}

/// `notAfter` (Unix seconds) of a DER X.509 certificate, `None` if it does
/// not parse that far. Reads only the outer structure (`tbsCertificate`:
/// optional version, serial, signature, issuer, validity); the certificate
/// must already have been accepted by the TLS stack. For expiry warnings
/// (agentd's `robot.agent.credential_expiring`), never for a trust decision.
pub fn cert_not_after(der: &[u8]) -> Option<i64> {
    let (cert, _) = expect(der, 0x30)?;
    let (tbs, _) = expect(cert.content, 0x30)?;
    let mut r = tbs.content;
    if r.first() == Some(&0xa0) {
        r = tlv(r)?.1; // [0] version
    }
    let (_, r) = expect(r, 0x02)?; // serialNumber
    let (_, r) = expect(r, 0x30)?; // signature
    let (_, r) = expect(r, 0x30)?; // issuer
    let (validity, _) = expect(r, 0x30)?;
    let (_, rest) = tlv(validity.content)?; // notBefore
    let (not_after, _) = tlv(rest)?;
    der_time(&not_after)
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

// --- High-water marks ---

#[derive(Debug, Clone, PartialEq, Eq)]
struct Mark {
    number: Vec<u8>,
    this_update: i64,
    issuer: String,
    /// From a CRL verified against a trust anchor (persisted).
    verified: bool,
}

type Marks = BTreeMap<String, Mark>;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateJson {
    format: String,
    marks: Vec<MarkJson>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MarkJson {
    scope_sha256: String,
    issuer: String,
    crl_number: String,
    this_update: i64,
}

fn split_state(p: &Path) -> Result<(&Path, &str), String> {
    match (p.parent(), p.file_name().and_then(|n| n.to_str())) {
        (Some(d), Some(n)) => Ok((d, n)),
        _ => Err(format!("{}: not a file path", p.display())),
    }
}

fn read_marks(p: &Path) -> Result<Marks, String> {
    let shown = p.display();
    let bad = |e: &str| {
        format!(
            "CRL high-water state {shown}: {e}; refusing to start without it (an operator \
             removes it only to accept older CRLs on purpose)"
        )
    };
    let (dir, name) = split_state(p)?;
    let Some(text) = crate::store::read_state(dir, name).map_err(|e| bad(&e.to_string()))? else {
        return Ok(Marks::new());
    };
    let j: StateJson = serde_json::from_str(&text).map_err(|e| bad(&e.to_string()))?;
    if j.format != STATE_FORMAT || j.marks.len() > MAX_MARKS {
        return Err(bad("unknown format"));
    }
    let mut out = Marks::new();
    for m in j.marks {
        let number = crate::crypto::from_hex(&m.crl_number).ok_or_else(|| bad("bad number"))?;
        out.insert(
            m.scope_sha256,
            Mark {
                number,
                this_update: m.this_update,
                issuer: m.issuer,
                verified: true,
            },
        );
    }
    Ok(out)
}

fn write_marks(p: &Path, marks: &Marks) -> Result<(), String> {
    let (dir, name) = split_state(p)?;
    let j = StateJson {
        format: STATE_FORMAT.into(),
        marks: marks
            .iter()
            .filter(|(_, m)| m.verified)
            .take(MAX_MARKS)
            .map(|(k, m)| MarkJson {
                scope_sha256: k.clone(),
                issuer: m.issuer.clone(),
                crl_number: crate::crypto::to_hex(&m.number),
                this_update: m.this_update,
            })
            .collect(),
    };
    let mut b = serde_json::to_vec_pretty(&j).map_err(|e| e.to_string())?;
    b.push(b'\n');
    crate::store::atomic_write(dir, name, &b)
        .map_err(|e| format!("CRL high-water state {}: {e}", p.display()))
}

/// Refuse a load that goes back for any scope.
fn check_marks(what: &str, loaded: &Loaded, marks: &Marks) -> Result<(), String> {
    for (number, u) in &loaded.in_use {
        let Some(m) = marks.get(&u.scope_sha256) else {
            continue;
        };
        if cmp_number(number, &m.number) == Cmp::Less || u.this_update < m.this_update {
            return Err(format!(
                "{what}: the CRL of {} goes back (CRL number {} thisUpdate {} in {}, after \
                 number {} thisUpdate {}): an older CRL would un-revoke certificates; refused \
                 (fail closed) until the current CRL is back",
                u.issuer,
                u.crl_number,
                u.this_update,
                u.file,
                crate::crypto::to_hex(&m.number),
                m.this_update
            ));
        }
    }
    Ok(())
}

/// Raise the marks to `loaded`; whether a persisted one changed.
fn raise_marks(loaded: &Loaded, marks: &mut Marks) -> bool {
    let mut persisted = false;
    for (number, u) in &loaded.in_use {
        let m = Mark {
            number: number.clone(),
            this_update: u.this_update,
            issuer: u.issuer.clone(),
            verified: u.signature_verified,
        };
        let raise = match marks.get(&u.scope_sha256) {
            None => true,
            Some(old) => {
                cmp_number(number, &old.number) == Cmp::Greater
                    || u.this_update > old.this_update
                    || (m.verified && !old.verified)
            }
        };
        if raise {
            persisted |= m.verified;
            marks.insert(u.scope_sha256.clone(), m);
        }
    }
    persisted
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
    rollbacks: AtomicU64,
    revoked: AtomicU64,
    expired: AtomicU64,
    unknown: AtomicU64,
    error: Mutex<Option<String>>,
    state_error: Mutex<Option<String>>,
    in_use: Mutex<Vec<CrlInUse>>,
    last_revoked: Mutex<Option<String>>,
}

/// A snapshot of [`CrlStats`] (status files, heartbeats).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CrlStatus {
    pub files: u64,
    /// CRLs in use (0 while [`CrlStatus::error`] is set).
    pub crls: u64,
    /// The CRL in use per issuer (empty while [`CrlStatus::error`] is set).
    pub in_use: Vec<CrlInUse>,
    /// Successful reloads after start.
    pub reloads: u64,
    pub reload_failures: u64,
    /// Reloads refused because a CRL went back (lower CRL number or older
    /// `thisUpdate` than one already loaded); included in
    /// `reload_failures`.
    pub rollback_refusals: u64,
    /// Set while the files on disk are unusable: every handshake is
    /// refused (fail closed).
    pub error: Option<String>,
    /// Set while the high-water state file could not be written (the marks
    /// still hold in this process).
    pub state_error: Option<String>,
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
            in_use: lock(&self.in_use).clone(),
            reloads: g(&self.reloads),
            reload_failures: g(&self.reload_failures),
            rollback_refusals: g(&self.rollbacks),
            error: lock(&self.error).clone(),
            state_error: lock(&self.state_error).clone(),
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

    fn in_service(&self, loaded: &Loaded) {
        self.crls.store(loaded.crls.len() as u64, Ordering::Relaxed);
        *lock(&self.in_use) = loaded.in_use.iter().map(|(_, u)| u.clone()).collect();
        *lock(&self.error) = None;
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
    marks: Marks,
    tried: Instant,
}

/// A verifier rebuilt from the CRL files whenever they change.
struct Reloading<V: ?Sized> {
    files: CrlFiles,
    sig: SigCheck,
    build: Box<Build<V>>,
    live: Mutex<Live<V>>,
    stats: Arc<CrlStats>,
}

impl<V: ?Sized> Reloading<V> {
    fn new(files: CrlFiles, sig: SigCheck, build: Box<Build<V>>) -> Result<(Self, Arc<V>), String> {
        let mut marks = match &files.state {
            Some(p) => read_marks(p)?,
            None => Marks::new(),
        };
        let stamps = files.stamps();
        let loaded = files.load(&sig)?;
        check_marks(&files.what, &loaded, &marks)?;
        let first = build(loaded.crls.clone())?;
        if raise_marks(&loaded, &mut marks) {
            if let Some(p) = &files.state {
                write_marks(p, &marks)?;
            }
        }
        let stats = Arc::new(CrlStats::default());
        stats
            .files
            .store(files.files.len() as u64, Ordering::Relaxed);
        stats.in_service(&loaded);
        Ok((
            Self {
                files,
                sig,
                build,
                live: Mutex::new(Live {
                    stamps,
                    current: Ok(first.clone()),
                    marks,
                    tried: Instant::now(),
                }),
                stats,
            },
            first,
        ))
    }

    /// Load, check against the marks, build; raise the marks.
    fn reload(&self, marks: &mut Marks) -> Result<Arc<V>, String> {
        let loaded = self.files.load(&self.sig)?;
        if let Err(e) = check_marks(&self.files.what, &loaded, marks) {
            self.stats.rollbacks.fetch_add(1, Ordering::Relaxed);
            return Err(e);
        }
        let v = (self.build)(loaded.crls.clone())?;
        if raise_marks(&loaded, marks) {
            if let Some(p) = &self.files.state {
                // The marks hold in this process either way.
                *lock(&self.stats.state_error) = write_marks(p, marks).err();
            }
        }
        self.stats.in_service(&loaded);
        Ok(v)
    }

    /// The verifier for this handshake (reloaded first if a file changed).
    fn current(&self) -> Result<Arc<V>, rustls::Error> {
        let stamps = self.files.stamps();
        let mut live = lock(&self.live);
        let retry = live.current.is_err() && live.tried.elapsed() >= RETRY_FAILED;
        if stamps != live.stamps || retry {
            live.stamps = stamps;
            live.tried = Instant::now();
            let mut marks = std::mem::take(&mut live.marks);
            let r = self.reload(&mut marks);
            live.marks = marks;
            match r {
                Ok(v) => {
                    self.stats.reloads.fetch_add(1, Ordering::Relaxed);
                    live.current = Ok(v);
                }
                Err(e) => {
                    self.stats.reload_failures.fetch_add(1, Ordering::Relaxed);
                    self.stats.crls.store(0, Ordering::Relaxed);
                    lock(&self.stats.in_use).clear();
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

/// A verifier and its revocation counters (`None` without CRLs).
pub type Verifier<V> = (Arc<V>, Option<Arc<CrlStats>>);

/// A server-certificate verifier (for a TLS client): WebPKI, plus the CRLs
/// of `crls` if any (module docs). The stats are `None` without CRLs.
pub fn server_verifier(
    roots: Arc<RootCertStore>,
    provider: Arc<rustls::crypto::CryptoProvider>,
    crls: Option<CrlFiles>,
) -> Result<Verifier<dyn ServerCertVerifier>, String> {
    let Some(files) = crls else {
        let v: Arc<dyn ServerCertVerifier> =
            WebPkiServerVerifier::builder_with_provider(roots, provider)
                .build()
                .map_err(|e| format!("TLS: {e}"))?;
        return Ok((v, None));
    };
    let what = files.what.clone();
    let sig = SigCheck::new(&roots, &provider);
    let build: Box<Build<dyn ServerCertVerifier>> = Box::new(move |c| {
        let v: Arc<dyn ServerCertVerifier> =
            WebPkiServerVerifier::builder_with_provider(roots.clone(), provider.clone())
                .with_crls(c)
                .enforce_revocation_expiration()
                .build()
                .map_err(|e| format!("{what}: {e}"))?;
        Ok(v)
    });
    let (reloading, base) = Reloading::new(files, sig, build)?;
    let stats = reloading.stats.clone();
    Ok((Arc::new(CrlServerVerifier { reloading, base }), Some(stats)))
}

/// A client-certificate verifier (for a TLS server; a client certificate
/// is mandatory): WebPKI, plus the CRLs of `crls` if any (module docs).
pub fn client_verifier(
    roots: Arc<RootCertStore>,
    provider: Arc<rustls::crypto::CryptoProvider>,
    crls: Option<CrlFiles>,
) -> Result<Verifier<dyn ClientCertVerifier>, String> {
    let Some(files) = crls else {
        let v = WebPkiClientVerifier::builder_with_provider(roots, provider)
            .build()
            .map_err(|e| format!("TLS: {e}"))?;
        return Ok((v, None));
    };
    let what = files.what.clone();
    let sig = SigCheck::new(&roots, &provider);
    let build: Box<Build<dyn ClientCertVerifier>> = Box::new(move |c| {
        WebPkiClientVerifier::builder_with_provider(roots.clone(), provider.clone())
            .with_crls(c)
            .enforce_revocation_expiration()
            .build()
            .map_err(|e| format!("{what}: {e}"))
    });
    let (reloading, base) = Reloading::new(files, sig, build)?;
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
        let e = server_verifier(roots(), provider(), Some(f)).err().unwrap();
        assert!(e.contains("no X509 CRL"), "{e}");
        std::fs::write(d.join("junk.crl"), b"\x30\x03\x02\x01\x00").unwrap();
        std::fs::set_permissions(d.join("junk.crl"), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        let f = CrlFiles::new("crl_files", &[d.join("junk.crl")])
            .unwrap()
            .unwrap();
        let e = server_verifier(roots(), provider(), Some(f)).err().unwrap();
        assert!(e.contains("does not parse"), "{e}");
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

    /// Review (TLS, finding 1): an older genuine CRL put back in place
    /// (lower CRL number) must not un-revoke a certificate.
    #[test]
    fn an_older_crl_put_back_is_refused_fail_closed() {
        let d = tmp("rollback");
        put(&d, "crl-ca.crl.pem", "ca.crl");
        let files = CrlFiles::new("crl_files", &[d.join("ca.crl")]).unwrap();
        let (v, stats) = server_verifier(roots(), provider(), files).unwrap();
        let stats = stats.unwrap();
        assert_eq!(
            check(&v, "crl-revoked-server.pem"),
            Err(rustls::Error::InvalidCertificate(CertificateError::Revoked))
        );
        // CRL number 1 (revokes nothing) after number 2.
        put(&d, "crl-ca-empty.crl.pem", "ca.crl");
        let e = check(&v, "crl-revoked-server.pem").unwrap_err();
        assert!(e.to_string().contains("CrlUnusable"), "{e}");
        assert!(check(&v, "crl-server.pem").is_err());
        let s = stats.status();
        assert!(s.error.unwrap_or_default().contains("goes back"));
        assert_eq!(s.rollback_refusals, 1);
        // The current CRL again: back in service.
        put(&d, "crl-ca.crl.pem", "ca.crl");
        assert_eq!(check(&v, "crl-server.pem"), Ok(()));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Finding 1: the high-water mark survives a restart when the
    /// component gives a state file.
    #[test]
    fn the_high_water_mark_is_persisted() {
        let d = tmp("persist");
        let state = d.join("crl-state.json");
        put(&d, "crl-ca.crl.pem", "ca.crl");
        let files = CrlFiles::new("crl_files", &[d.join("ca.crl")])
            .unwrap()
            .unwrap()
            .with_state_file(&state);
        assert!(server_verifier(roots(), provider(), Some(files.clone())).is_ok());
        assert!(state.exists());
        // "Restart" with the older CRL in place: refused at start.
        put(&d, "crl-ca-empty.crl.pem", "ca.crl");
        let e = server_verifier(roots(), provider(), Some(files.clone()))
            .err()
            .unwrap();
        assert!(e.contains("goes back"), "{e}");
        // Without the state file the process would have accepted it.
        let plain = CrlFiles::new("crl_files", &[d.join("ca.crl")]).unwrap();
        assert!(server_verifier(roots(), provider(), plain).is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Finding 2: two CRLs of one issuer (an old one with the new one
    /// appended): the highest CRL number is used, not the first.
    #[test]
    fn of_two_crls_of_one_issuer_the_newest_is_used() {
        let d = tmp("dup");
        let mut both = std::fs::read(fixture("crl-ca-empty.crl.pem")).unwrap();
        both.extend(std::fs::read(fixture("crl-ca.crl.pem")).unwrap());
        std::fs::write(d.join("ca.crl"), &both).unwrap();
        std::fs::set_permissions(d.join("ca.crl"), std::fs::Permissions::from_mode(0o644)).unwrap();
        let files = CrlFiles::new("crl_files", &[d.join("ca.crl")]).unwrap();
        let (v, stats) = server_verifier(roots(), provider(), files).unwrap();
        assert_eq!(
            check(&v, "crl-revoked-server.pem"),
            Err(rustls::Error::InvalidCertificate(CertificateError::Revoked))
        );
        let s = stats.unwrap().status();
        assert_eq!(s.crls, 1);
        assert_eq!(s.in_use.len(), 1);
        let u = s.in_use.first().unwrap();
        assert_eq!(u.crl_number, "02");
        assert_eq!(u.issuer, "RoboDR test CA with CRLs");
        assert!(u.signature_verified);
        // nextUpdate is reported (agentd warns before it passes):
        // 2125-01-01T00:00:00Z.
        assert_eq!(u.next_update, Some(4_891_363_200));
        let _ = std::fs::remove_dir_all(&d);
    }

    fn pem_der(name: &str) -> Vec<u8> {
        let pem = std::fs::read(fixture(name)).unwrap();
        let mut it = rustls::pki_types::CertificateDer::pem_slice_iter(&pem);
        it.next().unwrap().unwrap().as_ref().to_vec()
    }

    /// Sales-readiness T6: a certificate's `notAfter`, for expiry warnings.
    #[test]
    fn cert_not_after_reads_the_validity() {
        // 2125-01-01T00:00:00Z and 2001-01-01T00:00:00Z.
        assert_eq!(cert_not_after(&pem_der("server.pem")), Some(4_891_363_200));
        assert_eq!(cert_not_after(&pem_der("expired.pem")), Some(978_307_200));
        assert_eq!(cert_not_after(b""), None);
        assert_eq!(cert_not_after(&[0x30, 0x03, 0x30, 0x01, 0x00]), None);
        let mut cut = pem_der("server.pem");
        cut.truncate(cut.len() / 3);
        assert_eq!(cert_not_after(&cut), None);
    }

    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        let n = content.len();
        if n < 0x80 {
            v.push(n as u8);
        } else if n < 0x100 {
            v.extend([0x81, n as u8]);
        } else {
            v.extend([0x82, (n >> 8) as u8, n as u8]);
        }
        v.extend_from_slice(content);
        v
    }

    /// A structurally valid v2 CRL with only an authority key identifier
    /// extension (no CRL number); the signature is junk.
    fn crl_without_number() -> Vec<u8> {
        let alg = der(
            0x30,
            &der(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]),
        );
        let cn = der(0x0c, b"RoboDR test CA with CRLs");
        let name = der(
            0x30,
            &der(
                0x31,
                &der(0x30, &[der(0x06, &[0x55, 0x04, 0x03]), cn].concat()),
            ),
        );
        let aki = der(0x30, &der(0x80, &[7u8; 20]));
        let ext = der(
            0x30,
            &[der(0x06, &[0x55, 0x1d, 0x23]), der(0x04, &aki)].concat(),
        );
        let tbs = der(
            0x30,
            &[
                der(0x02, &[1]),
                alg.clone(),
                name,
                der(0x17, b"000101000000Z"),
                der(0x18, b"21250101000000Z"),
                der(0xa0, &der(0x30, &ext)),
            ]
            .concat(),
        );
        der(0x30, &[tbs, alg, der(0x03, &[0, 1, 2, 3])].concat())
    }

    /// Finding 1: a CRL without a CRL number cannot be ordered: refused.
    #[test]
    fn a_crl_without_a_number_is_refused() {
        let raw = crl_without_number();
        assert!(webpki::OwnedCertRevocationList::from_der(&raw).is_ok());
        let d = tmp("nonumber");
        std::fs::write(d.join("ca.crl"), &raw).unwrap();
        std::fs::set_permissions(d.join("ca.crl"), std::fs::Permissions::from_mode(0o644)).unwrap();
        let f = CrlFiles::new("crl_files", &[d.join("ca.crl")])
            .unwrap()
            .unwrap();
        let e = server_verifier(roots(), provider(), Some(f)).err().unwrap();
        assert!(e.contains("no CRL number"), "{e}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A CRL claiming the trust anchor as issuer whose signature does not
    /// verify is refused at load (it would never be usable).
    #[test]
    fn a_forged_crl_of_a_trust_anchor_is_refused() {
        let d = tmp("forged");
        let mut raw = CertificateRevocationListDer::from_pem_file(fixture("crl-ca.crl.pem"))
            .unwrap()
            .as_ref()
            .to_vec();
        // Change a revoked serial (1002 -> 1003): still well-formed DER.
        let i = raw
            .windows(4)
            .position(|w| w == [0x02, 0x02, 0x10, 0x02])
            .unwrap();
        raw[i + 3] = 0x03;
        std::fs::write(d.join("ca.crl"), &raw).unwrap();
        std::fs::set_permissions(d.join("ca.crl"), std::fs::Permissions::from_mode(0o644)).unwrap();
        let f = CrlFiles::new("crl_files", &[d.join("ca.crl")])
            .unwrap()
            .unwrap();
        let e = server_verifier(roots(), provider(), Some(f)).err().unwrap();
        assert!(e.contains("does not verify"), "{e}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Finding 7: a file that changes while it is read (a torn in-place
    /// write) is read again instead of being used half-written.
    #[test]
    fn a_file_changed_during_the_read_is_read_again() {
        let d = tmp("torn");
        let p = put(&d, "crl-ca.crl.pem", "ca.crl");
        let calls = Arc::new(AtomicU64::new(0));
        let c2 = calls.clone();
        let reader: Arc<ReadFn> = Arc::new(move |p: &Path| {
            if c2.fetch_add(1, Ordering::SeqCst) == 0 {
                // The writer is mid-way: what was read is torn ...
                std::thread::sleep(std::time::Duration::from_millis(30));
                let full = std::fs::read(p).unwrap();
                std::fs::write(p, &full).unwrap();
                return Ok(full.get(..full.len() / 2).unwrap().to_vec());
            }
            std::fs::read(p).map_err(|e| e.to_string())
        });
        let f = CrlFiles::with_reader("crl_files", &[p], reader)
            .unwrap()
            .unwrap();
        let (v, _) = server_verifier(roots(), provider(), Some(f)).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            check(&v, "crl-revoked-server.pem"),
            Err(rustls::Error::InvalidCertificate(CertificateError::Revoked))
        );
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
