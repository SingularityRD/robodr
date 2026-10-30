//! The depot's small X.509 needs (Sprint 14a):
//!
//! * a **site unit CA** (ECDSA P-256, `robodr-seal` key file format): it
//!   issues the depot's TLS server certificate and one client
//!   certificate per enrolled unit, for the unit's TPM-resident identity
//!   key (UIK), only after the enrolment's TPM proofs and the operator
//!   quorum. The depot does not rely on the CA alone: every connection's
//!   client key must be **exactly** the identity key of an enrolled,
//!   non-revoked unit ([`crate::serve`]);
//! * the **EK certificate chain** check at enrolment, with
//!   `rustls-webpki` against the TPM vendor CAs whose digests the site's
//!   trust file lists (`ek_ca_certs`), EKU `tcg-kp-EKCertificate`.
//!
//! The DER writer emits exactly one encoding (definite lengths, minimal
//! integers) and only what `rustls-webpki` needs: v3, ecdsa-with-SHA256,
//! a CN-only name, basicConstraints, keyUsage, extKeyUsage and, for the
//! server, subjectAltName.

use crate::{err, DepotError};
use rustls::pki_types::{CertificateDer, UnixTime};
use sha2::{Digest, Sha256};

const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
const OID_BASIC: &[u8] = &[0x55, 0x1d, 0x13];
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const OID_EKU: &[u8] = &[0x55, 0x1d, 0x25];
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];
const OID_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
const OID_CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
/// `tcg-kp-EKCertificate` (2.23.133.8.1), DER contents.
pub const OID_TCG_EK_CERT: &[u8] = &[0x67, 0x81, 0x05, 0x08, 0x01];

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    let n = body.len();
    if n < 0x80 {
        v.push(n as u8);
    } else {
        let b = (n as u64).to_be_bytes();
        let skip = b.iter().take_while(|&&x| x == 0).count();
        v.push(0x80 | (8 - skip) as u8);
        v.extend_from_slice(&b[skip..]);
    }
    v.extend_from_slice(body);
    v
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn oid(o: &[u8]) -> Vec<u8> {
    tlv(0x06, o)
}

fn uint(v: &[u8]) -> Vec<u8> {
    let mut b: Vec<u8> = v.iter().copied().skip_while(|&x| x == 0).collect();
    if b.is_empty() || b[0] & 0x80 != 0 {
        b.insert(0, 0);
    }
    tlv(0x02, &b)
}

fn name(cn: &str) -> Vec<u8> {
    seq(&[tlv(0x31, &seq(&[oid(OID_CN), tlv(0x0c, cn.as_bytes())]))])
}

/// Days since 1970-01-01 to (year, month, day) (H. Hinnant's algorithm).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn time(t: u64) -> Vec<u8> {
    let (y, mo, d) = civil((t / 86400) as i64);
    let s = t % 86400;
    let (h, mi, se) = (s / 3600, (s % 3600) / 60, s % 60);
    if (1950..2050).contains(&y) {
        tlv(
            0x17,
            format!("{:02}{mo:02}{d:02}{h:02}{mi:02}{se:02}Z", y % 100).as_bytes(),
        )
    } else {
        tlv(
            0x18,
            format!("{y:04}{mo:02}{d:02}{h:02}{mi:02}{se:02}Z").as_bytes(),
        )
    }
}

fn ext(id: &[u8], critical: bool, value: Vec<u8>) -> Vec<u8> {
    let mut p = vec![oid(id)];
    if critical {
        p.push(tlv(0x01, &[0xff]));
    }
    p.push(tlv(0x04, &value));
    seq(&p)
}

/// What a certificate is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Ca,
    /// TLS server, with DNS names.
    Server(Vec<String>),
    /// TLS client (a unit).
    Client,
}

/// Certificate parameters.
#[derive(Debug, Clone)]
pub struct Params<'a> {
    pub issuer_cn: &'a str,
    pub subject_cn: &'a str,
    pub subject_public: &'a [u8; 65],
    pub serial: u64,
    pub not_before: u64,
    pub not_after: u64,
    pub kind: Kind,
}

/// Issue a DER certificate signed by `ca` (ECDSA P-256 / SHA-256).
pub fn issue(p: &Params<'_>, ca: &robodr_seal::keys::PolicyKey) -> Result<Vec<u8>, DepotError> {
    let mut exts = Vec::new();
    match &p.kind {
        Kind::Ca => {
            exts.push(ext(OID_BASIC, true, seq(&[tlv(0x01, &[0xff])])));
            // keyCertSign (bit 5) | cRLSign (bit 6): 0000 0110, 1 unused bit.
            exts.push(ext(OID_KEY_USAGE, true, tlv(0x03, &[0x01, 0x06])));
        }
        Kind::Server(names) => {
            exts.push(ext(OID_BASIC, true, seq(&[])));
            // digitalSignature (bit 0), 7 unused bits.
            exts.push(ext(OID_KEY_USAGE, true, tlv(0x03, &[0x07, 0x80])));
            exts.push(ext(OID_EKU, false, seq(&[oid(OID_SERVER_AUTH)])));
            let gn: Vec<Vec<u8>> = names.iter().map(|n| tlv(0x82, n.as_bytes())).collect();
            exts.push(ext(OID_SAN, false, seq(&gn)));
        }
        Kind::Client => {
            exts.push(ext(OID_BASIC, true, seq(&[])));
            exts.push(ext(OID_KEY_USAGE, true, tlv(0x03, &[0x07, 0x80])));
            exts.push(ext(OID_EKU, false, seq(&[oid(OID_CLIENT_AUTH)])));
        }
    }
    let alg = seq(&[oid(OID_ECDSA_SHA256)]);
    let tbs = seq(&[
        tlv(0xa0, &uint(&[2])),
        uint(&p.serial.to_be_bytes()),
        alg.clone(),
        name(p.issuer_cn),
        seq(&[time(p.not_before), time(p.not_after)]),
        name(p.subject_cn),
        robodr_seal::keys::p256_spki_der(p.subject_public),
        tlv(0xa3, &seq(&exts)),
    ]);
    let digest: [u8; 32] = Sha256::digest(&tbs).into();
    let sig = ca.sign_digest(&digest).map_err(|e| err(e.to_string()))?;
    let mut bits = vec![0u8];
    bits.extend_from_slice(&sig);
    Ok(seq(&[tbs, alg, tlv(0x03, &bits)]))
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64(b: &[u8]) -> String {
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// PEM armour.
pub fn pem(label: &str, der: &[u8]) -> String {
    let mut s = format!("-----BEGIN {label}-----\n");
    for l in b64(der).as_bytes().chunks(64) {
        s.push_str(&String::from_utf8_lossy(l));
        s.push('\n');
    }
    s.push_str(&format!("-----END {label}-----\n"));
    s
}

/// A SEC1 `EC PRIVATE KEY` (P-256) DER for a secret scalar, with its
/// public point: what `rustls` loads as the server key.
pub fn sec1_private_key(secret: &[u8; 32], public: &[u8; 65]) -> Vec<u8> {
    let mut bits = vec![0u8];
    bits.extend_from_slice(public);
    seq(&[
        uint(&[1]),
        tlv(0x04, secret),
        tlv(
            0xa0,
            &oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
        ),
        tlv(0xa1, &tlv(0x03, &bits)),
    ])
}

/// The certificates of a PEM or DER file (DER: exactly one).
pub fn certs_of(bytes: &[u8]) -> Result<Vec<Vec<u8>>, DepotError> {
    use rustls::pki_types::pem::PemObject;
    // PEM (possibly with explanatory text before the armour, as
    // `openssl x509 -text` and swtpm's local CA write it), else one DER.
    if bytes.windows(11).any(|w| w == b"-----BEGIN ") {
        let v: Vec<Vec<u8>> = CertificateDer::pem_slice_iter(bytes)
            .map(|c| c.map(|c| c.as_ref().to_vec()))
            .collect::<Result<_, _>>()
            .map_err(|e| err(format!("PEM: {e:?}")))?;
        if v.is_empty() {
            return Err(err("no certificate in PEM"));
        }
        Ok(v)
    } else {
        Ok(vec![bytes.to_vec()])
    }
}

/// The RSA modulus and exponent of a DER `SubjectPublicKeyInfo` of
/// `rsaEncryption` (strict: minimal lengths as webpki already enforces).
pub fn rsa_spki(spki: &[u8]) -> Result<(Vec<u8>, Vec<u8>), DepotError> {
    struct D<'a>(&'a [u8]);
    impl<'a> D<'a> {
        fn next(&mut self, tag: u8) -> Result<&'a [u8], DepotError> {
            let b = self.0;
            if b.len() < 2 || b[0] != tag {
                return Err(err("SPKI: unexpected DER"));
            }
            let (len, hdr) = if b[1] < 0x80 {
                (usize::from(b[1]), 2)
            } else {
                let n = usize::from(b[1] & 0x7f);
                if n == 0 || n > 2 || b.len() < 2 + n {
                    return Err(err("SPKI: length"));
                }
                (
                    b[2..2 + n]
                        .iter()
                        .fold(0usize, |a, x| (a << 8) | usize::from(*x)),
                    2 + n,
                )
            };
            let end = hdr
                .checked_add(len)
                .filter(|e| *e <= b.len())
                .ok_or_else(|| err("SPKI: truncated"))?;
            self.0 = &b[end..];
            Ok(&b[hdr..end])
        }
    }
    let mut top = D(spki);
    let mut s = D(top.next(0x30)?);
    let mut alg = D(s.next(0x30)?);
    if alg.next(0x06)? != [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01] {
        return Err(err("EK certificate key is not rsaEncryption"));
    }
    let bits = s.next(0x03)?;
    if bits.first() != Some(&0) {
        return Err(err("SPKI: bit string"));
    }
    let mut k = D(&bits[1..]);
    let mut ks = D(k.next(0x30)?);
    let n = ks.next(0x02)?;
    let e = ks.next(0x02)?;
    let strip = |v: &[u8]| {
        v.iter()
            .copied()
            .skip_while(|&x| x == 0)
            .collect::<Vec<u8>>()
    };
    Ok((strip(n), strip(e)))
}

/// Verify an EK certificate chain: `ek_cert` (DER) must chain to one of
/// `cas` (DER, each already checked against the trust file's digests),
/// with `intermediates`, valid at `now`, EKU `tcg-kp-EKCertificate`, and
/// its key must be the EK public area's RSA key.
pub fn verify_ek_chain(
    ek_cert: &[u8],
    cas: &[Vec<u8>],
    intermediates: &[Vec<u8>],
    ek: &robodr_seal::attest::Public,
    now: u64,
) -> Result<(), DepotError> {
    let ders: Vec<CertificateDer<'_>> = cas
        .iter()
        .map(|c| CertificateDer::from(c.as_slice()))
        .collect();
    let anchors: Vec<_> = ders
        .iter()
        .map(|c| webpki::anchor_from_trusted_cert(c).map(|a| a.to_owned()))
        .collect::<Result<_, _>>()
        .map_err(|e| err(format!("EK CA certificate: {e:?}")))?;
    let inter: Vec<CertificateDer<'_>> = intermediates
        .iter()
        .map(|c| CertificateDer::from(c.as_slice()))
        .collect();
    let leaf = CertificateDer::from(ek_cert);
    let ee = webpki::EndEntityCert::try_from(&leaf)
        .map_err(|e| err(format!("EK certificate: {e:?}")))?;
    let algs = rustls::crypto::ring::default_provider()
        .signature_verification_algorithms
        .all;
    ee.verify_for_usage(
        algs,
        &anchors,
        &inter,
        UnixTime::since_unix_epoch(std::time::Duration::from_secs(now)),
        // The EK purpose where an EKU is present (TCG: EK certificates MAY
        // carry it; vendor CA certificates usually carry none).
        webpki::KeyUsage::required_if_present(OID_TCG_EK_CERT),
        None,
        None,
    )
    .map_err(|e| {
        err(format!(
            "EK certificate does not chain to a listed TPM vendor CA: {e:?}"
        ))
    })?;
    let (n, e) = rsa_spki(ee.subject_public_key_info().as_ref())?;
    match &ek.key {
        robodr_seal::attest::PublicKey::Rsa { modulus, exponent } => {
            let mut eb = exponent.to_be_bytes().to_vec();
            while eb.first() == Some(&0) {
                eb.remove(0);
            }
            if *modulus != n || eb != e {
                return Err(err(
                    "the EK certificate is for another key than the EK presented",
                ));
            }
            Ok(())
        }
        _ => Err(err("EK: not RSA")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates_and_times() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(19_723), (2024, 1, 1));
        assert_eq!(civil(11_016), (2000, 2, 29));
        assert_eq!(time(0), tlv(0x17, b"700101000000Z"));
        assert_eq!(time(2_524_608_000), tlv(0x18, b"20500101000000Z"));
    }

    #[test]
    fn issued_chain_verifies_with_webpki() {
        let ca = robodr_seal::keys::PolicyKey::generate().unwrap();
        let leaf = robodr_seal::keys::PolicyKey::generate().unwrap();
        let now = 1_790_000_000;
        let ca_der = issue(
            &Params {
                issuer_cn: "site-a depot CA",
                subject_cn: "site-a depot CA",
                subject_public: &ca.public(),
                serial: 1,
                not_before: now - 10,
                not_after: now + 86400,
                kind: Kind::Ca,
            },
            &ca,
        )
        .unwrap();
        for kind in [Kind::Client, Kind::Server(vec!["depot.site-a".into()])] {
            let der = issue(
                &Params {
                    issuer_cn: "site-a depot CA",
                    subject_cn: "ugv-07",
                    subject_public: &leaf.public(),
                    serial: 2,
                    not_before: now - 10,
                    not_after: now + 86400,
                    kind: kind.clone(),
                },
                &ca,
            )
            .unwrap();
            let c = CertificateDer::from(der.as_slice());
            let ee = webpki::EndEntityCert::try_from(&c).unwrap();
            let cad = CertificateDer::from(ca_der.as_slice());
            let a = [webpki::anchor_from_trusted_cert(&cad).unwrap()];
            let eku: &[u8] = if kind == Kind::Client {
                OID_CLIENT_AUTH
            } else {
                OID_SERVER_AUTH
            };
            ee.verify_for_usage(
                rustls::crypto::ring::default_provider()
                    .signature_verification_algorithms
                    .all,
                &a,
                &[],
                UnixTime::since_unix_epoch(std::time::Duration::from_secs(now)),
                webpki::KeyUsage::required(eku),
                None,
                None,
            )
            .unwrap();
            assert_eq!(
                ee.subject_public_key_info().as_ref(),
                robodr_seal::keys::p256_spki_der(&leaf.public()).as_slice()
            );
        }
    }
}
