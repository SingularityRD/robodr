//! Sealed chunks (`docs/SECURE-DELIVERY.md` §7.2).
//!
//! A sealed RPK has a fresh random 256-bit content key `CK`. Its
//! manifest's `seal.seal_id` (32 random bytes) is the HKDF-SHA256 salt of
//! every key derived from it:
//!
//! | label | use |
//! |---|---|
//! | `robodr-seal/chunk-key/v1` | XChaCha20-Poly1305 key of the chunks |
//! | `robodr-seal/nonce-key/v1` | HMAC key of the synthetic nonces |
//! | `robodr-seal/file-digest/v1` | HMAC key of the keyed file digests |
//! | `robodr-seal/ck-commit/v1` | the key commitment `seal.ck_commit` |
//!
//! A chunk is `nonce (24) || ciphertext || tag (16)`. Its associated data
//! binds the RPK (`seal_id`) and the chunk's place: file index in the
//! manifest's `content[]`, position in that file and the file's chunk
//! count, so a chunk moved to another position, file or RPK, or a file
//! truncated or extended by whole chunks, fails authentication (the signed
//! manifest's ciphertext hashes refuse such a tree earlier still). The
//! nonce is **synthetic**: `HMAC(nonce key, AD || SHA-256(plaintext))`,
//! the first 24 bytes. A nonce therefore repeats under one key only for
//! the same plaintext at the same place, which yields the same chunk:
//! reusing a content key for other bytes (a bug, or a rebuild that kept
//! the key) never reuses a nonce for different plaintext. On open the
//! nonce is recomputed from the plaintext and compared in constant time.
//!
//! A chunk that fails authentication is never returned: [`open_chunk`]
//! gives plaintext only after the tag and the nonce check passed, and the
//! caller writes it only then.
//!
//! The key commitment exists because Poly1305 does not commit to its key:
//! the unit checks `ck_commit` right after unwrapping, so a wrap of any
//! other key is refused before a single chunk is opened.

use crate::{invalid, unauthentic, SealError};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Content key length.
pub const CK_LEN: usize = 32;
/// Nonce length (XChaCha20).
pub const NONCE_LEN: usize = 24;
/// Tag length (Poly1305).
pub const TAG_LEN: usize = 16;
/// What a sealed chunk adds to its plaintext piece (equals
/// `robodr_pkg::rpk::SEALED_CHUNK_OVERHEAD`).
pub const OVERHEAD: usize = NONCE_LEN + TAG_LEN;

const CHUNK_AD_DOMAIN: &[u8] = b"robodr-seal/chunk/v1\0";
const FILE_DIGEST_DOMAIN: &[u8] = b"robodr-seal/file/v1\0";

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 keyed with a 32-byte key. HMAC pads a key shorter than the
/// 64-byte block with zeros, so the padded key is the same MAC (RFC 2104),
/// and the fixed-size constructor cannot fail.
fn hmac32(key: &[u8; 32]) -> HmacSha256 {
    let mut k = Zeroizing::new([0u8; 64]);
    k[..32].copy_from_slice(key);
    <HmacSha256 as Mac>::new(hmac::digest::generic_array::GenericArray::from_slice(
        &k[..],
    ))
}

/// A content key. Wiped on drop; never printed.
pub struct ContentKey(Zeroizing<[u8; CK_LEN]>);

impl std::fmt::Debug for ContentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ContentKey(..)")
    }
}

/// A sealed RPK's `seal_id`.
pub type SealId = [u8; 32];

impl ContentKey {
    /// A fresh random key.
    pub fn generate() -> Result<Self, SealError> {
        Ok(Self(crate::random32()?))
    }

    /// From raw bytes (an unwrapped key).
    pub fn from_bytes(b: &[u8]) -> Result<Self, SealError> {
        let a: [u8; CK_LEN] = b
            .try_into()
            .map_err(|_| invalid("content key must be 32 bytes"))?;
        Ok(Self(Zeroizing::new(a)))
    }

    /// The raw key (for wrapping only).
    pub fn expose(&self) -> &[u8; CK_LEN] {
        &self.0
    }

    fn derive(&self, seal_id: &SealId, label: &[u8]) -> Zeroizing<[u8; 32]> {
        let hk = Hkdf::<Sha256>::new(Some(seal_id), &self.0[..]);
        let mut out = Zeroizing::new([0u8; 32]);
        // 32 bytes is always a valid HKDF-SHA256 output length.
        let _ = hk.expand(label, &mut out[..]);
        out
    }

    /// The key commitment (`seal.ck_commit`).
    pub fn commit(&self, seal_id: &SealId) -> [u8; 32] {
        *self.derive(seal_id, b"robodr-seal/ck-commit/v1")
    }

    /// Check `ck_commit` in constant time.
    pub fn check_commit(&self, seal_id: &SealId, ck_commit: &[u8]) -> Result<(), SealError> {
        if crate::ct_eq(&self.commit(seal_id), ck_commit) {
            Ok(())
        } else {
            Err(unauthentic(
                "the unwrapped content key does not match the RPK's key commitment",
            ))
        }
    }

    fn cipher(&self, seal_id: &SealId) -> XChaCha20Poly1305 {
        let k = self.derive(seal_id, b"robodr-seal/chunk-key/v1");
        XChaCha20Poly1305::new((&*k).into())
    }

    /// A keyed digest of a whole file's plaintext (the `sha256` member of
    /// a sealed content file).
    pub fn file_digest(&self, seal_id: &SealId) -> FileDigest {
        let k = self.derive(seal_id, b"robodr-seal/file-digest/v1");
        let mut mac = hmac32(&k);
        mac.update(FILE_DIGEST_DOMAIN);
        FileDigest(mac)
    }
}

/// Streaming keyed file digest.
pub struct FileDigest(HmacSha256);

impl FileDigest {
    pub fn update(&mut self, b: &[u8]) {
        self.0.update(b);
    }

    pub fn finalize(self) -> [u8; 32] {
        self.0.finalize().into_bytes().into()
    }
}

/// Where a chunk belongs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkPlace {
    /// Index of the file in the manifest's `content[]`.
    pub file_index: u32,
    /// Position of the chunk in that file.
    pub pos: u32,
    /// Number of chunks of that file.
    pub count: u32,
}

fn associated_data(seal_id: &SealId, at: ChunkPlace) -> Vec<u8> {
    let mut ad = Vec::with_capacity(CHUNK_AD_DOMAIN.len() + 32 + 12);
    ad.extend_from_slice(CHUNK_AD_DOMAIN);
    ad.extend_from_slice(seal_id);
    ad.extend_from_slice(&at.file_index.to_be_bytes());
    ad.extend_from_slice(&at.pos.to_be_bytes());
    ad.extend_from_slice(&at.count.to_be_bytes());
    ad
}

fn synthetic_nonce(ck: &ContentKey, seal_id: &SealId, ad: &[u8], pt: &[u8]) -> [u8; NONCE_LEN] {
    let k = ck.derive(seal_id, b"robodr-seal/nonce-key/v1");
    let mut mac = hmac32(&k);
    mac.update(ad);
    mac.update(&Sha256::digest(pt));
    let full = mac.finalize().into_bytes();
    let mut n = [0u8; NONCE_LEN];
    n.copy_from_slice(&full[..NONCE_LEN]);
    n
}

/// Seal one plaintext piece.
pub fn seal_chunk(
    ck: &ContentKey,
    seal_id: &SealId,
    at: ChunkPlace,
    pt: &[u8],
) -> Result<Vec<u8>, SealError> {
    if at.count == 0 || at.pos >= at.count {
        return Err(invalid("chunk position out of range"));
    }
    let ad = associated_data(seal_id, at);
    let nonce = synthetic_nonce(ck, seal_id, &ad, pt);
    let ct = ck
        .cipher(seal_id)
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: pt, aad: &ad })
        .map_err(|_| invalid("chunk too large to seal"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open one sealed chunk: plaintext only if the tag and the synthetic
/// nonce verify for this RPK and this place.
pub fn open_chunk(
    ck: &ContentKey,
    seal_id: &SealId,
    at: ChunkPlace,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SealError> {
    if sealed.len() < OVERHEAD {
        return Err(unauthentic("sealed chunk shorter than nonce and tag"));
    }
    if at.count == 0 || at.pos >= at.count {
        return Err(invalid("chunk position out of range"));
    }
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    let ad = associated_data(seal_id, at);
    let pt = Zeroizing::new(
        ck.cipher(seal_id)
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: &ad })
            .map_err(|_| {
                unauthentic(format!(
                    "chunk {} of file {} does not authenticate (tampered, moved, truncated, or \
                     another key)",
                    at.pos, at.file_index
                ))
            })?,
    );
    let want = synthetic_nonce(ck, seal_id, &ad, &pt);
    if !crate::ct_eq(&want, nonce) {
        return Err(unauthentic(format!(
            "chunk {} of file {}: nonce is not the synthetic nonce of its plaintext",
            at.pos, at.file_index
        )));
    }
    Ok(pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> ContentKey {
        ContentKey::from_bytes(&[b; 32]).unwrap()
    }

    const SID: SealId = [7u8; 32];
    const AT: ChunkPlace = ChunkPlace {
        file_index: 1,
        pos: 0,
        count: 2,
    };

    #[test]
    fn round_trip_and_overhead() {
        let ck = key(1);
        let c = seal_chunk(&ck, &SID, AT, b"model weights").unwrap();
        assert_eq!(c.len(), 13 + OVERHEAD);
        assert_eq!(
            &open_chunk(&ck, &SID, AT, &c).unwrap()[..],
            b"model weights"
        );
        // Deterministic for the same key, place and plaintext.
        assert_eq!(c, seal_chunk(&ck, &SID, AT, b"model weights").unwrap());
        // Empty pieces are not produced by the builder, but are sound.
        let e = seal_chunk(&ck, &SID, AT, b"").unwrap();
        assert_eq!(open_chunk(&ck, &SID, AT, &e).unwrap().len(), 0);
    }

    #[test]
    fn place_rpk_and_key_are_bound() {
        let ck = key(1);
        let c = seal_chunk(&ck, &SID, AT, b"secret").unwrap();
        for (what, at) in [
            ("pos", ChunkPlace { pos: 1, ..AT }),
            (
                "file",
                ChunkPlace {
                    file_index: 2,
                    ..AT
                },
            ),
            ("count (truncation)", ChunkPlace { count: 1, ..AT }),
            ("count (extension)", ChunkPlace { count: 3, ..AT }),
        ] {
            let e = open_chunk(&ck, &SID, at, &c).unwrap_err();
            assert_eq!(e.kind, crate::ErrorKind::Unauthentic, "{what}");
        }
        assert!(open_chunk(&ck, &[8u8; 32], AT, &c).is_err(), "other RPK");
        assert!(open_chunk(&key(2), &SID, AT, &c).is_err(), "other key");
        for i in 0..c.len() {
            let mut t = c.clone();
            t[i] ^= 0x01;
            assert!(open_chunk(&ck, &SID, AT, &t).is_err(), "flip at {i}");
        }
        for n in 0..c.len() {
            assert!(
                open_chunk(&ck, &SID, AT, &c[..n]).is_err(),
                "truncated to {n}"
            );
        }
    }

    /// Nonce reuse: the same key used for two different plaintexts at the
    /// same place gives two different nonces; and a chunk sealed with a
    /// chosen nonce (someone holding the key) is refused.
    #[test]
    fn nonces_never_repeat_for_other_plaintext() {
        let ck = key(3);
        let a = seal_chunk(&ck, &SID, AT, b"version one").unwrap();
        let b = seal_chunk(&ck, &SID, AT, b"version two").unwrap();
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
        // Same plaintext at another place: another nonce too.
        let c = seal_chunk(&ck, &SID, ChunkPlace { pos: 1, ..AT }, b"version one").unwrap();
        assert_ne!(a[..NONCE_LEN], c[..NONCE_LEN]);
        // A valid AEAD chunk under the right key whose nonce is not the
        // synthetic one (reused from another chunk) is refused.
        let ad = associated_data(&SID, AT);
        let forged_ct = ck
            .cipher(&SID)
            .encrypt(
                XNonce::from_slice(&a[..NONCE_LEN]),
                Payload {
                    msg: b"version two".as_slice(),
                    aad: &ad,
                },
            )
            .unwrap();
        let mut forged = a[..NONCE_LEN].to_vec();
        forged.extend_from_slice(&forged_ct);
        let e = open_chunk(&ck, &SID, AT, &forged).unwrap_err();
        assert!(e.detail.contains("synthetic nonce"), "{e}");
    }

    #[test]
    fn padded_hmac_key_is_the_same_mac() {
        let k = [0x42u8; 32];
        let mut a = hmac32(&k);
        a.update(b"x");
        let mut b = <HmacSha256 as Mac>::new_from_slice(&k).unwrap();
        b.update(b"x");
        assert_eq!(a.finalize().into_bytes(), b.finalize().into_bytes());
    }

    #[test]
    fn commitment_and_file_digest() {
        let ck = key(4);
        let c = ck.commit(&SID);
        ck.check_commit(&SID, &c).unwrap();
        assert!(key(5).check_commit(&SID, &c).is_err());
        assert!(ck.check_commit(&[0u8; 32], &c).is_err());
        let mut d = ck.file_digest(&SID);
        d.update(b"abc");
        let d1 = d.finalize();
        let mut d = key(5).file_digest(&SID);
        d.update(b"abc");
        assert_ne!(d1, d.finalize());
        // Not the plain SHA-256 (no offline guess confirmation).
        assert_ne!(&d1[..], &Sha256::digest(b"abc")[..]);
    }
}
