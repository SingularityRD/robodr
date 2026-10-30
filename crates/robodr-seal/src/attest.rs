//! TPM 2.0 structures a depot checks at enrolment (`docs/SECURE-DELIVERY.md`
//! §8, Sprint 14a), parsed offline and strictly (TPM 2.0 Part 2): the
//! public area of a key (`TPM2B_PUBLIC`), its name, and the attestation
//! structure an attestation key signs (`TPMS_ATTEST`: `TPM2_Certify`,
//! `TPM2_Quote`).
//!
//! What the checks prove, together with credential activation
//! ([`crate::enrol`]):
//!
//! * the **AK** is a restricted signing key resident in the TPM whose EK
//!   the depot challenged (`TPM2_ActivateCredential` releases the secret
//!   only to the TPM holding that EK, and only for an object with exactly
//!   the AK's name, which covers its attributes);
//! * a *restricted* key signs only what the TPM itself generated
//!   (`TPM_GENERATED_VALUE` magic), so an attestation it signed is the
//!   TPM's own statement: `TPM2_Certify` says "the object with this name
//!   is loaded in me", which needs both keys in one TPM;
//! * the certified object's **name** is a hash over its public area, so its
//!   attributes (`fixedTPM`, `fixedParent`, `sensitiveDataOrigin`: created
//!   inside this TPM, never exportable), its authPolicy (the site's policy
//!   authority, erase epoch and lease) and its public key are exactly the
//!   ones the depot parsed.
//!
//! Every parser consumes the whole input (trailing bytes refuse), bounds
//! every length and never panics (fuzz target `seal_attest`).

use crate::{invalid, unauthentic, SealError};
use sha2::{Digest, Sha256};

pub const TPM_ALG_RSA: u16 = 0x0001;
pub const TPM_ALG_SHA256: u16 = 0x000B;
pub const TPM_ALG_NULL: u16 = 0x0010;
pub const TPM_ALG_ECDSA: u16 = 0x0018;
pub const TPM_ALG_ECDH: u16 = 0x0019;
pub const TPM_ALG_ECC: u16 = 0x0023;
pub const TPM_ECC_NIST_P256: u16 = 0x0003;
pub const TPM_GENERATED_VALUE: u32 = 0xff54_4347;
pub const TPM_ST_ATTEST_CERTIFY: u16 = 0x8017;
pub const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;

/// `TPMA_OBJECT` bits.
pub mod attr {
    pub const FIXED_TPM: u32 = 0x0000_0002;
    pub const FIXED_PARENT: u32 = 0x0000_0010;
    pub const SENSITIVE_DATA_ORIGIN: u32 = 0x0000_0020;
    pub const USER_WITH_AUTH: u32 = 0x0000_0040;
    pub const ADMIN_WITH_POLICY: u32 = 0x0000_0080;
    pub const NO_DA: u32 = 0x0000_0400;
    pub const ENCRYPTED_DUPLICATION: u32 = 0x0000_0800;
    pub const RESTRICTED: u32 = 0x0001_0000;
    pub const DECRYPT: u32 = 0x0002_0000;
    pub const SIGN: u32 = 0x0004_0000;
    /// Created in this TPM, never leaves it.
    pub const RESIDENT: u32 = FIXED_TPM | FIXED_PARENT | SENSITIVE_DATA_ORIGIN;
}

/// Exact attributes of the UWK (`tpm::UWK_ATTRIBUTES`).
pub const UWK_ATTRS: u32 = attr::RESIDENT | attr::DECRYPT | attr::NO_DA;
/// Exact attributes of the unit identity key (`tpm::UIK_ATTRIBUTES`).
pub const UIK_ATTRS: u32 = attr::RESIDENT | attr::USER_WITH_AUTH | attr::SIGN | attr::NO_DA;
/// Attributes an AK must have.
pub const AK_REQUIRED: u32 = attr::RESIDENT | attr::RESTRICTED | attr::SIGN;

/// Largest structure read.
pub const MAX_STRUCT: usize = 4096;

struct R<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> R<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], SealError> {
        let end = self
            .i
            .checked_add(n)
            .filter(|&e| e <= self.b.len())
            .ok_or_else(|| invalid("TPM structure truncated"))?;
        let s = &self.b[self.i..end];
        self.i = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, SealError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, SealError> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Result<u32, SealError> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self) -> Result<u64, SealError> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_be_bytes(a))
    }
    fn tpm2b(&mut self, max: usize) -> Result<&'a [u8], SealError> {
        let n = usize::from(self.u16()?);
        if n > max {
            return Err(invalid("TPM2B longer than allowed"));
        }
        self.take(n)
    }
    fn end(&self) -> Result<(), SealError> {
        if self.i == self.b.len() {
            Ok(())
        } else {
            Err(invalid("trailing bytes after a TPM structure"))
        }
    }
}

/// The key of a public area.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// SEC1 uncompressed P-256 point.
    EccP256([u8; 65]),
    /// RSA modulus and exponent (0 in the structure means 65537).
    Rsa { modulus: Vec<u8>, exponent: u32 },
}

/// A parsed `TPMT_PUBLIC`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Public {
    pub type_alg: u16,
    pub name_alg: u16,
    pub attributes: u32,
    pub auth_policy: Vec<u8>,
    /// Symmetric algorithm of a storage key (`TPM_ALG_NULL` otherwise).
    pub symmetric: u16,
    /// Signing / key-exchange scheme and its hash (`TPM_ALG_NULL`, 0 if none).
    pub scheme: u16,
    pub scheme_hash: u16,
    pub key: PublicKey,
    /// The `TPMT_PUBLIC` bytes (what the name hashes).
    pub tpmt: Vec<u8>,
}

impl Public {
    /// `nameAlg || H(TPMT_PUBLIC)` (SHA-256 only).
    pub fn name(&self) -> [u8; 34] {
        let mut n = [0u8; 34];
        n[..2].copy_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        n[2..].copy_from_slice(&Sha256::digest(&self.tpmt));
        n
    }

    /// The P-256 point, or an error.
    pub fn p256(&self) -> Result<[u8; 65], SealError> {
        match &self.key {
            PublicKey::EccP256(p) => Ok(*p),
            PublicKey::Rsa { .. } => Err(invalid("not a P-256 key")),
        }
    }
}

fn sym_def(r: &mut R<'_>) -> Result<u16, SealError> {
    let alg = r.u16()?;
    if alg != TPM_ALG_NULL {
        r.u16()?; // keyBits
        r.u16()?; // mode
    }
    Ok(alg)
}

fn scheme(r: &mut R<'_>) -> Result<(u16, u16), SealError> {
    let alg = r.u16()?;
    if alg == TPM_ALG_NULL {
        Ok((alg, 0))
    } else {
        Ok((alg, r.u16()?))
    }
}

/// Parse a `TPMT_PUBLIC` (SHA-256 name algorithm, RSA or ECC P-256 only).
pub fn parse_tpmt_public(b: &[u8]) -> Result<Public, SealError> {
    if b.len() > MAX_STRUCT {
        return Err(invalid("public area too large"));
    }
    let mut r = R::new(b);
    let type_alg = r.u16()?;
    let name_alg = r.u16()?;
    if name_alg != TPM_ALG_SHA256 {
        return Err(invalid("public area: name algorithm must be SHA-256"));
    }
    let attributes = r.u32()?;
    let auth_policy = r.tpm2b(64)?.to_vec();
    let (symmetric, scheme_alg, scheme_hash, key) = match type_alg {
        TPM_ALG_ECC => {
            let symmetric = sym_def(&mut r)?;
            let (sa, sh) = scheme(&mut r)?;
            let curve = r.u16()?;
            let (kdf, _) = scheme(&mut r)?;
            if curve != TPM_ECC_NIST_P256 || kdf != TPM_ALG_NULL {
                return Err(invalid("public area: only NIST P-256 without a KDF"));
            }
            let x = r.tpm2b(32)?;
            let y = r.tpm2b(32)?;
            if x.len() != 32 || y.len() != 32 {
                return Err(invalid("public area: P-256 coordinates must be 32 bytes"));
            }
            let mut p = [0u8; 65];
            p[0] = 4;
            p[1..33].copy_from_slice(x);
            p[33..].copy_from_slice(y);
            if p256::PublicKey::from_sec1_bytes(&p).is_err() {
                return Err(invalid("public area: point not on P-256"));
            }
            (symmetric, sa, sh, PublicKey::EccP256(p))
        }
        TPM_ALG_RSA => {
            let symmetric = sym_def(&mut r)?;
            let (sa, sh) = scheme(&mut r)?;
            let bits = r.u16()?;
            let exponent = r.u32()?;
            let n = r.tpm2b(512)?;
            if !matches!(bits, 2048 | 3072 | 4096) || n.len() * 8 != usize::from(bits) {
                return Err(invalid("public area: RSA modulus size"));
            }
            (
                symmetric,
                sa,
                sh,
                PublicKey::Rsa {
                    modulus: n.to_vec(),
                    exponent: if exponent == 0 { 65537 } else { exponent },
                },
            )
        }
        _ => return Err(invalid("public area: only RSA or ECC keys")),
    };
    r.end()?;
    Ok(Public {
        type_alg,
        name_alg,
        attributes,
        auth_policy,
        symmetric,
        scheme: scheme_alg,
        scheme_hash,
        key,
        tpmt: b.to_vec(),
    })
}

/// Parse a `TPM2B_PUBLIC` (as `tpm2_create -u` / `tpm2_createek -u` write).
pub fn parse_tpm2b_public(b: &[u8]) -> Result<Public, SealError> {
    if b.len() < 2 || b.len() > MAX_STRUCT {
        return Err(invalid("public area size"));
    }
    let n = usize::from(u16::from_be_bytes([b[0], b[1]]));
    if n + 2 != b.len() {
        return Err(invalid("TPM2B_PUBLIC size does not match"));
    }
    parse_tpmt_public(&b[2..])
}

/// What was attested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attested {
    /// `TPM2_Certify`: the name of the certified object.
    Certify {
        name: Vec<u8>,
        qualified_name: Vec<u8>,
    },
    /// `TPM2_Quote`: SHA-256 bank selection bitmap (3 bytes) and the digest
    /// of the selected PCR values.
    Quote {
        select: Vec<u8>,
        pcr_digest: Vec<u8>,
    },
}

/// A parsed `TPMS_ATTEST`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attest {
    pub qualified_signer: Vec<u8>,
    pub extra_data: Vec<u8>,
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: bool,
    pub firmware: u64,
    pub attested: Attested,
}

/// Parse a `TPMS_ATTEST` (certify or quote only).
pub fn parse_attest(b: &[u8]) -> Result<Attest, SealError> {
    if b.len() > MAX_STRUCT {
        return Err(invalid("attestation too large"));
    }
    let mut r = R::new(b);
    if r.u32()? != TPM_GENERATED_VALUE {
        return Err(unauthentic("attestation: not TPM-generated (magic)"));
    }
    let st = r.u16()?;
    let qualified_signer = r.tpm2b(66)?.to_vec();
    let extra_data = r.tpm2b(64)?.to_vec();
    let clock = r.u64()?;
    let reset_count = r.u32()?;
    let restart_count = r.u32()?;
    let safe = match r.u8()? {
        0 => false,
        1 => true,
        _ => return Err(invalid("attestation: bad safe flag")),
    };
    let firmware = r.u64()?;
    let attested = match st {
        TPM_ST_ATTEST_CERTIFY => Attested::Certify {
            name: r.tpm2b(66)?.to_vec(),
            qualified_name: r.tpm2b(66)?.to_vec(),
        },
        TPM_ST_ATTEST_QUOTE => {
            if r.u32()? != 1 {
                return Err(invalid("quote: exactly one PCR bank"));
            }
            if r.u16()? != TPM_ALG_SHA256 {
                return Err(invalid("quote: SHA-256 bank only"));
            }
            let n = usize::from(r.u8()?);
            if n != 3 {
                return Err(invalid("quote: 3-byte PCR selection"));
            }
            let select = r.take(n)?.to_vec();
            let pcr_digest = r.tpm2b(32)?.to_vec();
            Attested::Quote { select, pcr_digest }
        }
        _ => return Err(invalid("attestation: neither certify nor quote")),
    };
    r.end()?;
    Ok(Attest {
        qualified_signer,
        extra_data,
        clock,
        reset_count,
        restart_count,
        safe,
        firmware,
        attested,
    })
}

/// Verify an ECDSA P-256 / SHA-256 signature (DER, as `tpm2_* -f plain`
/// writes it) over `msg` by `public`.
pub fn verify_p256(public: &[u8; 65], msg: &[u8], der: &[u8]) -> Result<(), SealError> {
    use p256::ecdsa::signature::Verifier;
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(public)
        .map_err(|_| invalid("not a P-256 public key"))?;
    let sig = p256::ecdsa::Signature::from_der(der)
        .map_err(|_| unauthentic("signature is not DER ECDSA"))?;
    vk.verify(msg, &sig)
        .map_err(|_| unauthentic("signature does not verify"))
}

/// Check that `ak` is usable as an attestation key: resident, restricted,
/// signing only, ECDSA P-256 with SHA-256, no decrypt.
pub fn check_ak(ak: &Public) -> Result<[u8; 65], SealError> {
    if ak.attributes & AK_REQUIRED != AK_REQUIRED || ak.attributes & attr::DECRYPT != 0 {
        return Err(unauthentic(format!(
            "AK attributes 0x{:08x}: not a restricted signing key created in the TPM",
            ak.attributes
        )));
    }
    if ak.scheme != TPM_ALG_ECDSA || ak.scheme_hash != TPM_ALG_SHA256 {
        return Err(invalid("AK must be ECDSA with SHA-256"));
    }
    ak.p256()
}

/// Verify an AK-signed attestation and return it.
pub fn verify_attest(ak: &[u8; 65], attest: &[u8], sig: &[u8]) -> Result<Attest, SealError> {
    verify_p256(ak, attest, sig)?;
    parse_attest(attest)
}

/// Verify that the AK certified the object whose public area is `obj`
/// (`TPM2_Certify`), and that the object was created in the TPM with
/// exactly `attrs`.
pub fn verify_certified(
    ak: &[u8; 65],
    obj: &Public,
    attrs: u32,
    attest: &[u8],
    sig: &[u8],
) -> Result<Attest, SealError> {
    let a = verify_attest(ak, attest, sig)?;
    match &a.attested {
        Attested::Certify { name, .. } if name.as_slice() == obj.name() => {}
        Attested::Certify { .. } => {
            return Err(unauthentic(
                "the AK certified another object than the public area presented",
            ))
        }
        Attested::Quote { .. } => return Err(invalid("expected a certification, got a quote")),
    }
    if obj.attributes != attrs {
        return Err(unauthentic(format!(
            "certified key attributes 0x{:08x}, expected 0x{attrs:08x} (created in the TPM, \
             non-exportable)",
            obj.attributes
        )));
    }
    Ok(a)
}

/// The SHA-256 PCR selection bitmap of `pcrs`.
pub fn pcr_select(pcrs: &[u8]) -> [u8; 3] {
    let mut s = [0u8; 3];
    for p in pcrs {
        if *p < 24 {
            s[usize::from(*p / 8)] |= 1 << (p % 8);
        }
    }
    s
}

/// Verify an AK-signed quote with qualifying data `nonce` over the PCRs
/// `values` (sorted by index).
pub fn verify_quote(
    ak: &[u8; 65],
    attest: &[u8],
    sig: &[u8],
    nonce: &[u8],
    values: &[(u8, [u8; 32])],
) -> Result<Attest, SealError> {
    let a = verify_attest(ak, attest, sig)?;
    if !crate::ct_eq(&a.extra_data, nonce) {
        return Err(unauthentic("quote: not for this challenge (nonce)"));
    }
    let idx: Vec<u8> = values.iter().map(|(i, _)| *i).collect();
    let mut d = Sha256::new();
    for (_, v) in values {
        d.update(v);
    }
    let want: [u8; 32] = d.finalize().into();
    match &a.attested {
        Attested::Quote { select, pcr_digest }
            if select.as_slice() == pcr_select(&idx) && pcr_digest.as_slice() == want =>
        {
            Ok(a)
        }
        Attested::Quote { .. } => Err(unauthentic(
            "quote: the TPM's PCR values are not the ones presented",
        )),
        Attested::Certify { .. } => Err(invalid("expected a quote, got a certification")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The UWK public area `tpm2_create -G ecc256:ecdh -a <UWK attrs>`
    /// wrote on swtpm 0.7 (authPolicy all zero), and the certified name
    /// in the `TPMS_ATTEST` its AK signed.
    const UWK_PUB: &str = "00780023000b000204320020000000000000000000000000000000000000000000000000000000000000000000100019000b00030010002078e908548d94c5488258a608d4ce13bd944554070da8c294527ed532322b32380020a1bb4ce051b520e20bf4876cb2913843dee4f3a20ba2f38c20243e10dce8c8c7";
    const ATTEST: &str = "ff54434780170022000b986fb1d653125d0373c0b28219c9d87d14f23dd77c74f0ea98d130c4246fdeef000400ff55aa000000000000c90000000002000000000120191023001636360022000b21175b15fcdfcde82249d5eacebbc5676b6de3caf93f26673e8aa376f7f6eff10022000b6e5f93f5bae4be2698e6dd0aac53c25d5c7ddde9122448018c8314f36d3165e0";

    #[test]
    fn real_structures_parse() {
        let p = parse_tpm2b_public(&crate::from_hex(UWK_PUB).unwrap()).unwrap();
        assert_eq!(p.attributes, UWK_ATTRS);
        assert_eq!(p.scheme, TPM_ALG_ECDH);
        assert_eq!(
            crate::to_hex(&p.name()),
            "000b21175b15fcdfcde82249d5eacebbc5676b6de3caf93f26673e8aa376f7f6eff1"
        );
        let a = parse_attest(&crate::from_hex(ATTEST).unwrap()).unwrap();
        assert_eq!(a.extra_data, vec![0x00, 0xff, 0x55, 0xaa]);
        assert_eq!(a.reset_count, 2);
        match a.attested {
            Attested::Certify { name, .. } => assert_eq!(name, p.name().to_vec()),
            _ => panic!("not certify"),
        }
    }

    #[test]
    fn truncations_and_trailing_bytes_refuse() {
        for s in [UWK_PUB, ATTEST] {
            let b = crate::from_hex(s).unwrap();
            for n in 0..b.len() {
                assert!(parse_tpm2b_public(&b[..n]).is_err() && parse_attest(&b[..n]).is_err());
            }
            let mut more = b.clone();
            more.push(0);
            assert!(parse_tpm2b_public(&more).is_err() && parse_attest(&more).is_err());
        }
        // A point not on the curve.
        let mut b = crate::from_hex(UWK_PUB).unwrap();
        let l = b.len();
        b[l - 1] ^= 1;
        assert!(parse_tpm2b_public(&b).is_err());
    }

    #[test]
    fn signatures_and_names_are_checked() {
        let k = crate::wrap::p256_random().unwrap();
        let pk = crate::wrap::p256_public_bytes(&k.public_key());
        let sk = p256::ecdsa::SigningKey::from(&k);
        let att = crate::from_hex(ATTEST).unwrap();
        use p256::ecdsa::signature::Signer;
        let sig: p256::ecdsa::Signature = sk.sign(&att);
        let der = sig.to_der().as_bytes().to_vec();
        let uwk = parse_tpm2b_public(&crate::from_hex(UWK_PUB).unwrap()).unwrap();
        verify_certified(&pk, &uwk, UWK_ATTRS, &att, &der).unwrap();
        // Wrong attributes expected (e.g. an imported, exportable key).
        assert!(verify_certified(&pk, &uwk, UWK_ATTRS | attr::USER_WITH_AUTH, &att, &der).is_err());
        // Another object.
        let mut other = uwk.clone();
        other.tpmt[10] ^= 1;
        assert!(verify_certified(&pk, &other, UWK_ATTRS, &att, &der).is_err());
        // Another signer, a flipped attestation byte.
        let k2 = crate::wrap::p256_random().unwrap();
        let pk2 = crate::wrap::p256_public_bytes(&k2.public_key());
        assert!(verify_certified(&pk2, &uwk, UWK_ATTRS, &att, &der).is_err());
        let mut att2 = att.clone();
        att2[20] ^= 1;
        assert!(verify_certified(&pk, &uwk, UWK_ATTRS, &att2, &der).is_err());
    }
}
