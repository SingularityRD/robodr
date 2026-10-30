//! The signed PCR policy (`docs/SECURE-DELIVERY.md` §7.4) and the TPM
//! policy digests, computed offline exactly as a TPM 2.0 computes them
//! (TPM 2.0 Part 3, `TPM2_PolicyPCR`, `TPM2_PolicyNV`,
//! `TPM2_PolicyAuthorize`), so a signing station without a TPM can sign a
//! policy and a unit can check it before asking its TPM.
//!
//! # The two policies
//!
//! **Approved policy** (what the policy authority signs, one per platform
//! and boot-chain generation):
//!
//! ```text
//! PolicyPCR(sha256: selected PCRs = expected values)
//!   AND PolicyNV(floor index, "bit <version> is clear")     (TPM_EO_BITCLEAR)
//! ```
//!
//! **UWK authPolicy** (fixed in the TPM object at enrolment; the UWK has no
//! `userWithAuth`, so the policy is the only way to use it):
//!
//! ```text
//! PolicyAuthorize(policy authority key, policyRef = H("robodr-seal/policy-ref/v1\0" || platform))
//!   AND PolicyNV(erase-epoch counter == E)                   (TPM_EO_EQ)
//! ```
//!
//! `PolicyAuthorize` accepts any approved policy the authority signed for
//! this platform, so an authorised OS or firmware update ships a new
//! signed policy and sealing survives it, while any other boot chain fails
//! (§7.4). Two NV indices make the rest:
//!
//! * the **erase epoch** (`TPM_NT_COUNTER`, §7.6): incrementing it once
//!   makes `== E` false forever (a counter never decreases; a counter
//!   index that is undefined and defined again starts at the highest value
//!   any counter of that TPM ever held), so every key sealed under `E` is
//!   dead, in one NV write, without touching the disk;
//! * the **policy floor** (`TPM_NT_BITS`, 64 bits): bits can be set, never
//!   cleared. An approved policy of version `v` (0..=63) requires bit `v`
//!   clear; revoking every version below `v` sets bits `0..v`. An old
//!   signed policy (an older, possibly vulnerable boot chain) is therefore
//!   refused by the TPM after the unit committed a newer one. A signed
//!   PCR policy alone (`PolicyAuthorize` without the floor) would be valid
//!   forever. Undefining the index (which would clear the bits) needs owner
//!   authorization: provisioning sets one that is not kept on the unit
//!   (`docs/OPERATIONS.md`).
//!
//! Neither NV index has a policy or a password: anyone on the unit may
//! increment the epoch or set floor bits, which only destroys (that is
//! what erase is). Nobody can undo either.
//!
//! # Document (`robodr-seal-policy/1`)
//!
//! Canonical compact JSON (the `robodr-pkg` rules: members in order, no
//! whitespace, unknown members refused):
//! `{format, platform, version, pcr_bank, pcrs: [{index, value}], floor_nv,
//! signature}`. The signature is ECDSA P-256 (DER) over
//! `aHash = SHA-256(approvedPolicy || policyRef)`, exactly what
//! `TPM2_VerifySignature` checks before `TPM2_PolicyAuthorize`; the
//! approved policy is not a member: it is recomputed from the PCR values,
//! the floor index and the version, so every member is bound by the
//! signature through it.

use crate::{invalid, SealError};
use robodr_pkg::common::{is_label, parse_canonical, to_canonical};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const POLICY_FORMAT: &str = "robodr-seal-policy/1";
pub const MAX_POLICY_BYTES: usize = 16 * 1024;
/// Highest policy version (one bit of the 64-bit floor index each).
pub const MAX_VERSION: u32 = 63;
/// Highest PCR index (24 PCRs per bank).
pub const MAX_PCR: u8 = 23;

pub const TPM_ALG_SHA256: u16 = 0x000B;
pub const TPM_CC_POLICY_NV: u32 = 0x0000_0149;
pub const TPM_CC_POLICY_AUTHORIZE: u32 = 0x0000_016A;
pub const TPM_CC_POLICY_PCR: u32 = 0x0000_017F;
pub const TPM_EO_EQ: u16 = 0x0000;
pub const TPM_EO_BITCLEAR: u16 = 0x000B;

/// `TPMA_NV` of the erase-epoch counter once written:
/// `authwrite | nt=counter | authread | no_da | written`.
pub const EPOCH_NV_ATTRIBUTES: u32 = 0x2204_0014;
/// `TPMA_NV` of the policy-floor bit field once written:
/// `authwrite | nt=bits | authread | no_da | written`.
pub const FLOOR_NV_ATTRIBUTES: u32 = 0x2204_0024;
/// What `tpm2_nvdefine -a` gets for them (`written` is set by the TPM).
pub const EPOCH_NV_DEFINE: &str = "authread|authwrite|nt=counter|no_da";
pub const FLOOR_NV_DEFINE: &str = "authread|authwrite|nt=bits|no_da";

const POLICY_REF_DOMAIN: &[u8] = b"robodr-seal/policy-ref/v1\0";

fn h(parts: &[&[u8]]) -> [u8; 32] {
    let mut d = Sha256::new();
    for p in parts {
        d.update(p);
    }
    d.finalize().into()
}

/// TPM name of an NV index (`nameAlg || H(TPMS_NV_PUBLIC)`) with SHA-256,
/// no authPolicy and `size` bytes of data.
pub fn nv_name(index: u32, attributes: u32, size: u16) -> Vec<u8> {
    let mut pubarea = Vec::with_capacity(14);
    pubarea.extend_from_slice(&index.to_be_bytes());
    pubarea.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    pubarea.extend_from_slice(&attributes.to_be_bytes());
    pubarea.extend_from_slice(&0u16.to_be_bytes());
    pubarea.extend_from_slice(&size.to_be_bytes());
    let mut n = TPM_ALG_SHA256.to_be_bytes().to_vec();
    n.extend_from_slice(&h(&[&pubarea]));
    n
}

/// `TPM2_PolicyPCR` over the SHA-256 bank: `pcrs` sorted by index, each
/// with its expected value.
pub fn policy_pcr(prev: &[u8; 32], pcrs: &[(u8, [u8; 32])]) -> [u8; 32] {
    let mut select = [0u8; 3];
    let mut values = Vec::with_capacity(32 * pcrs.len());
    for (i, v) in pcrs {
        select[usize::from(*i / 8)] |= 1 << (i % 8);
        values.extend_from_slice(v);
    }
    let mut sel = Vec::with_capacity(10);
    sel.extend_from_slice(&1u32.to_be_bytes());
    sel.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    sel.push(3);
    sel.extend_from_slice(&select);
    h(&[prev, &TPM_CC_POLICY_PCR.to_be_bytes(), &sel, &h(&[&values])])
}

/// `TPM2_PolicyNV` (offset 0).
pub fn policy_nv(prev: &[u8; 32], nv_name: &[u8], operand_b: &[u8], operation: u16) -> [u8; 32] {
    let args = h(&[operand_b, &0u16.to_be_bytes(), &operation.to_be_bytes()]);
    h(&[prev, &TPM_CC_POLICY_NV.to_be_bytes(), &args, nv_name])
}

/// `TPM2_PolicyAuthorize` (resets the digest).
pub fn policy_authorize(key_name: &[u8], policy_ref: &[u8]) -> [u8; 32] {
    let first = h(&[&[0u8; 32], &TPM_CC_POLICY_AUTHORIZE.to_be_bytes(), key_name]);
    h(&[&first, policy_ref])
}

/// The policyRef bound into a platform's UWKs.
pub fn policy_ref(platform: &str) -> [u8; 32] {
    h(&[POLICY_REF_DOMAIN, platform.as_bytes()])
}

/// The operand of "bit `version` is clear": an 8-byte big-endian mask.
pub fn version_mask(version: u32) -> [u8; 8] {
    (1u64 << version.min(MAX_VERSION)).to_be_bytes()
}

/// The mask that revokes every version below `version`.
pub fn revoke_below_mask(version: u32) -> [u8; 8] {
    ((1u64 << version.min(MAX_VERSION)) - 1).to_be_bytes()
}

/// The approved policy for these PCR values, floor index and version.
pub fn approved_policy(pcrs: &[(u8, [u8; 32])], floor_nv: u32, version: u32) -> [u8; 32] {
    let pcr = policy_pcr(&[0u8; 32], pcrs);
    policy_nv(
        &pcr,
        &nv_name(floor_nv, FLOOR_NV_ATTRIBUTES, 8),
        &version_mask(version),
        TPM_EO_BITCLEAR,
    )
}

/// The authPolicy of a UWK: signed policies of `platform` by the key with
/// TPM name `key_name`, and the erase epoch `epoch` of index `epoch_nv`.
pub fn uwk_auth_policy(key_name: &[u8], platform: &str, epoch_nv: u32, epoch: u64) -> [u8; 32] {
    let a = policy_authorize(key_name, &policy_ref(platform));
    policy_nv(
        &a,
        &nv_name(epoch_nv, EPOCH_NV_ATTRIBUTES, 8),
        &epoch.to_be_bytes(),
        TPM_EO_EQ,
    )
}

/// `aHash` of `TPM2_PolicyAuthorize`: what the authority signs.
pub fn authorization_digest(approved: &[u8; 32], policy_ref: &[u8]) -> [u8; 32] {
    h(&[approved, policy_ref])
}

/// One expected PCR value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcrValue {
    pub index: u8,
    /// 64 lower-case hex.
    pub value: String,
}

/// A signed policy (`robodr-seal-policy/1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicy {
    pub format: String,
    pub platform: String,
    pub version: u32,
    pub pcr_bank: String,
    pub pcrs: Vec<PcrValue>,
    /// `0x` + 8 hex digits.
    pub floor_nv: String,
    /// Lower-case hex of a DER ECDSA signature.
    pub signature: String,
}

/// A policy that parsed and whose values are well-formed (not yet its
/// signature).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedPolicy {
    pub doc: SignedPolicy,
    pub pcrs: Vec<(u8, [u8; 32])>,
    pub floor_nv: u32,
    pub approved: [u8; 32],
    pub policy_ref: [u8; 32],
    pub signature: Vec<u8>,
}

impl CheckedPolicy {
    /// `aHash`.
    pub fn digest(&self) -> [u8; 32] {
        authorization_digest(&self.approved, &self.policy_ref)
    }

    /// The `tpm2_policypcr -l` selection (`sha256:0,2,7`).
    pub fn pcr_list(&self) -> String {
        let idx: Vec<String> = self.pcrs.iter().map(|(i, _)| i.to_string()).collect();
        format!("sha256:{}", idx.join(","))
    }
}

/// `0x01500031` style NV index in the owner NV range used here.
pub fn parse_nv_index(s: &str) -> Result<u32, SealError> {
    robodr_blackbox::tpm_anchor::parse_nv_index(s).map_err(invalid)
}

/// Parse and check a policy document (format, values, recomputed approved
/// policy). The signature is checked by [`verify`].
pub fn parse(bytes: &[u8]) -> Result<CheckedPolicy, SealError> {
    let doc: SignedPolicy = parse_canonical(bytes, MAX_POLICY_BYTES, "seal policy")
        .map_err(|r| invalid(r.to_string()))?;
    if doc.format != POLICY_FORMAT {
        return Err(invalid("seal policy: unsupported format"));
    }
    if !is_label(&doc.platform) {
        return Err(invalid("seal policy: bad platform"));
    }
    if doc.version > MAX_VERSION {
        return Err(invalid(format!(
            "seal policy: version must be 0..={MAX_VERSION}"
        )));
    }
    if doc.pcr_bank != "sha256" {
        return Err(invalid("seal policy: only the sha256 PCR bank"));
    }
    if doc.pcrs.is_empty() || doc.pcrs.len() > usize::from(MAX_PCR) + 1 {
        return Err(invalid("seal policy: 1..=24 PCRs"));
    }
    let mut pcrs = Vec::with_capacity(doc.pcrs.len());
    let mut last: Option<u8> = None;
    for p in &doc.pcrs {
        if p.index > MAX_PCR || last.is_some_and(|l| l >= p.index) {
            return Err(invalid(
                "seal policy: PCR indices 0..=23, strictly increasing",
            ));
        }
        last = Some(p.index);
        let v = crate::from_hex(&p.value)
            .filter(|v| v.len() == 32)
            .ok_or_else(|| invalid("seal policy: PCR value must be 64 lower-case hex"))?;
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        pcrs.push((p.index, a));
    }
    let floor_nv = parse_nv_index(&doc.floor_nv)?;
    if robodr_blackbox::tpm_anchor::format_nv_index(floor_nv) != doc.floor_nv {
        return Err(invalid(
            "seal policy: floor_nv must be 0x + 8 lower-case hex",
        ));
    }
    let signature = crate::from_hex(&doc.signature)
        .filter(|s| (8..=80).contains(&s.len()))
        .ok_or_else(|| invalid("seal policy: bad signature encoding"))?;
    let approved = approved_policy(&pcrs, floor_nv, doc.version);
    let policy_ref = policy_ref(&doc.platform);
    Ok(CheckedPolicy {
        doc,
        pcrs,
        floor_nv,
        approved,
        policy_ref,
        signature,
    })
}

/// Parse and verify a policy's signature against the authority's public
/// key, for `platform` and floor index `floor_nv`.
pub fn verify(
    bytes: &[u8],
    authority: &[u8],
    platform: &str,
    floor_nv: u32,
) -> Result<CheckedPolicy, SealError> {
    let p = parse(bytes)?;
    if p.doc.platform != platform {
        return Err(crate::unauthentic(format!(
            "seal policy is for platform {}, this unit is {platform}",
            p.doc.platform
        )));
    }
    if p.floor_nv != floor_nv {
        return Err(crate::unauthentic(
            "seal policy names another policy-floor NV index",
        ));
    }
    crate::keys::policy_verify(authority, &p.digest(), &p.signature)?;
    Ok(p)
}

/// Sign a policy (the policy authority, offline).
pub fn sign(
    key: &crate::keys::PolicyKey,
    platform: &str,
    version: u32,
    pcrs: &[(u8, [u8; 32])],
    floor_nv: u32,
) -> Result<Vec<u8>, SealError> {
    let mut sorted = pcrs.to_vec();
    sorted.sort_by_key(|(i, _)| *i);
    let approved = approved_policy(&sorted, floor_nv, version);
    let sig = key.sign_digest(&authorization_digest(&approved, &policy_ref(platform)))?;
    let doc = SignedPolicy {
        format: POLICY_FORMAT.into(),
        platform: platform.into(),
        version,
        pcr_bank: "sha256".into(),
        pcrs: sorted
            .iter()
            .map(|(i, v)| PcrValue {
                index: *i,
                value: crate::to_hex(v),
            })
            .collect(),
        floor_nv: robodr_blackbox::tpm_anchor::format_nv_index(floor_nv),
        signature: crate::to_hex(&sig),
    };
    let bytes = to_canonical(&doc).map_err(|r| invalid(r.to_string()))?;
    // Self-check through the parser every unit uses.
    verify(&bytes, &key.public(), platform, floor_nv)?;
    Ok(bytes)
}

/// The expected value of a SHA-256 PCR after extending a zero PCR with
/// `digests` in order (`TPM2_PCR_Extend`): for computing reference values.
pub fn pcr_after(digests: &[[u8; 32]]) -> [u8; 32] {
    let mut v = [0u8; 32];
    for d in digests {
        v = h(&[&v, d]);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        crate::from_hex(s).unwrap()
    }

    /// Digests recorded from swtpm 0.7 / tpm2-tools 5.6 trial sessions
    /// (the prototype of this module): PCRs 0 and 7 all zero, then
    /// PolicyNV `<= 5` on counter 0x01500031, then PolicyAuthorize by a
    /// loaded external P-256 key and PolicyNV `== 1` on counter
    /// 0x01500030.
    #[test]
    fn digests_match_a_real_tpm() {
        assert_eq!(
            crate::to_hex(&nv_name(0x0150_0031, EPOCH_NV_ATTRIBUTES, 8)),
            "000bb87230430613c0be7ded2a91b66f6ae1fcc3a667aa53ba10292ed8e7ca9cb3b1"
        );
        let pcr = policy_pcr(&[0u8; 32], &[(0, [0u8; 32]), (7, [0u8; 32])]);
        assert_eq!(
            crate::to_hex(&pcr),
            "02e3642b3e29eeccfffd8031c00a6f0a0febe5ceea2f6ef6b0322fe81598cf31"
        );
        let nv = policy_nv(
            &pcr,
            &nv_name(0x0150_0031, EPOCH_NV_ATTRIBUTES, 8),
            &5u64.to_be_bytes(),
            0x0009,
        );
        assert_eq!(
            crate::to_hex(&nv),
            "f12e66ae515c044c3f2135b49f9e5fbe925c99676df1b0aeed2b4fcbb56d67ba"
        );
        let key_name =
            unhex("000bfac63e5862acea6804df548a4b656a29b79b8789828ee70d13f16e31a0788c18");
        let a = policy_authorize(&key_name, b"robodr-seal/uwk/v1");
        assert_eq!(
            crate::to_hex(&a),
            "fee67f1579a777b6753851265da41b7fdbda95b9505491a357ad30ec764124e4"
        );
        let u = policy_nv(
            &a,
            &nv_name(0x0150_0030, EPOCH_NV_ATTRIBUTES, 8),
            &1u64.to_be_bytes(),
            TPM_EO_EQ,
        );
        assert_eq!(
            crate::to_hex(&u),
            "3f3d5969f31673e9d023834dd7be9f05e7f868658f2e3e897ccf433919560f6b"
        );
    }

    #[test]
    fn masks() {
        assert_eq!(version_mask(0), 1u64.to_be_bytes());
        assert_eq!(version_mask(5), 32u64.to_be_bytes());
        assert_eq!(revoke_below_mask(5), 31u64.to_be_bytes());
        assert_eq!(revoke_below_mask(0), 0u64.to_be_bytes());
        // A version is never revoked by its own revocation.
        for v in 0..=MAX_VERSION {
            let m = u64::from_be_bytes(revoke_below_mask(v));
            assert_eq!(m & u64::from_be_bytes(version_mask(v)), 0);
        }
    }

    #[test]
    fn sign_and_verify() {
        let k = crate::keys::PolicyKey::generate().unwrap();
        let pcrs = [(7u8, [1u8; 32]), (0u8, [2u8; 32])];
        let b = sign(&k, "ugv-x1", 3, &pcrs, 0x0150_0031).unwrap();
        let p = verify(&b, &k.public(), "ugv-x1", 0x0150_0031).unwrap();
        assert_eq!(p.pcr_list(), "sha256:0,7");
        assert_eq!(p.doc.version, 3);
        // Another platform, floor index or authority: refused.
        assert!(verify(&b, &k.public(), "ugv-x2", 0x0150_0031).is_err());
        assert!(verify(&b, &k.public(), "ugv-x1", 0x0150_0032).is_err());
        let other = crate::keys::PolicyKey::generate().unwrap();
        assert!(verify(&b, &other.public(), "ugv-x1", 0x0150_0031).is_err());
        // Any member changed breaks the signature (the approved policy is
        // recomputed from them), or the canonical form.
        let s = String::from_utf8(b.clone()).unwrap();
        for (from, to) in [
            ("\"version\":3", "\"version\":4"),
            ("\"index\":7", "\"index\":8"),
            ("\"value\":\"0101", "\"value\":\"0102"),
            ("\"platform\":\"ugv-x1\"", "\"platform\":\"ugv-x9\""),
        ] {
            assert!(s.contains(from), "{from}");
            let t = s.replace(from, to);
            assert!(
                verify(t.as_bytes(), &k.public(), "ugv-x1", 0x0150_0031).is_err()
                    && verify(t.as_bytes(), &k.public(), "ugv-x9", 0x0150_0031).is_err(),
                "{from}"
            );
        }
        assert!(parse(format!("{s}\n").as_bytes()).is_err());
        assert!(sign(&k, "ugv-x1", 64, &pcrs, 0x0150_0031).is_err());
    }

    #[test]
    fn pcr_reference_values() {
        let d = [3u8; 32];
        assert_eq!(pcr_after(&[]), [0u8; 32]);
        assert_eq!(pcr_after(&[d]), h(&[&[0u8; 32], &d]));
    }
}
