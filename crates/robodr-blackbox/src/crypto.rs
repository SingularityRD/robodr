//! Minimal, dependency-free SHA-256 (FIPS 180-4) and HMAC-SHA256 (RFC 2104).
//!
//! crates.io is not reachable in the RoboDR build environment, so the
//! primitives the black box needs are implemented here and pinned to the
//! published test vectors (NIST FIPS 180-4 examples, RFC 4231 test cases 1-7).
//!
//! Scope and limits:
//! - These are straightforward, portable implementations. They are not
//!   hardened against microarchitectural side channels beyond what the
//!   algorithms give for free (SHA-256 has no secret-dependent branches or
//!   table lookups; HMAC only adds XOR with the key).
//! - [`ct_eq`] compares tags without early exit. The optimiser barrier is
//!   `std::hint::black_box`, which is best-effort, not a guarantee.
//! - Key material is wiped on a best-effort basis (no `unsafe` volatile writes).
//!
//! HMAC is a **placeholder authenticity mechanism**: anyone who holds the key
//! can both create and verify tags, so it only proves "written by a holder of
//! the shared key". Production deployments must sign with an asymmetric key
//! (Ed25519 from an audited crate, or TPM-backed ECDSA) through the
//! [`crate::sign::Signer`] / [`crate::sign::Verifier`] traits.

/// SHA-256 round constants (FIPS 180-4 §4.2.2).
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 initial hash value (FIPS 180-4 §5.3.3).
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256 block size in bytes.
pub const BLOCK_LEN: usize = 64;
/// SHA-256 digest size in bytes.
pub const DIGEST_LEN: usize = 32;

/// Streaming SHA-256 hasher.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buf: [u8; BLOCK_LEN],
    buf_len: usize,
    /// Total message length in bytes (mod 2^64; messages are far below 2^61 bytes).
    total_len: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// A fresh hasher.
    pub const fn new() -> Self {
        Self {
            state: H0,
            buf: [0; BLOCK_LEN],
            buf_len: 0,
            total_len: 0,
        }
    }

    /// Absorb `data`.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (BLOCK_LEN - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == BLOCK_LEN {
                let block = self.buf;
                compress(&mut self.state, &block);
                self.buf_len = 0;
            }
        }
        while data.len() >= BLOCK_LEN {
            let (head, rest) = data.split_at(BLOCK_LEN);
            let mut block = [0u8; BLOCK_LEN];
            block.copy_from_slice(head);
            compress(&mut self.state, &block);
            data = rest;
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    /// Pad, finish and return the digest.
    pub fn finalize(mut self) -> [u8; DIGEST_LEN] {
        let bit_len = self.total_len.wrapping_mul(8);
        // 0x80, then zeros up to 56 mod 64, then the 64-bit big-endian bit length.
        let pad_len = if self.buf_len < 56 {
            56 - self.buf_len
        } else {
            120 - self.buf_len
        };
        let mut pad = [0u8; BLOCK_LEN];
        pad[0] = 0x80;
        self.update(&pad[..pad_len]);
        self.update(&bit_len.to_be_bytes());
        debug_assert_eq!(self.buf_len, 0);
        let mut out = [0u8; DIGEST_LEN];
        for (chunk, word) in out.chunks_exact_mut(4).zip(self.state.iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// One SHA-256 compression (FIPS 180-4 §6.2.2).
fn compress(state: &mut [u32; 8], block: &[u8; BLOCK_LEN]) {
    let mut w = [0u32; 64];
    for (wi, chunk) in w.iter_mut().zip(block.chunks_exact(4)) {
        *wi = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (k, wi) in K.iter().zip(w.iter()) {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(*k)
            .wrapping_add(*wi);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *s = s.wrapping_add(v);
    }
}

/// One-shot SHA-256.
pub fn sha256(data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

/// HMAC-SHA256 (RFC 2104 with H = SHA-256, B = 64, L = 32).
///
/// Keys longer than the block size are hashed first, as the RFC requires.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; DIGEST_LEN] {
    let mut k0 = [0u8; BLOCK_LEN];
    if key.len() > BLOCK_LEN {
        k0[..DIGEST_LEN].copy_from_slice(&sha256(key));
    } else {
        k0[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK_LEN];
    let mut opad = [0x5cu8; BLOCK_LEN];
    for ((i, o), k) in ipad.iter_mut().zip(opad.iter_mut()).zip(k0.iter()) {
        *i ^= k;
        *o ^= k;
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_digest);
    let tag = outer.finalize();
    wipe(&mut k0);
    wipe(&mut ipad);
    wipe(&mut opad);
    tag
}

/// Compare two byte strings without an early exit on the first difference.
///
/// The *length* is not treated as secret (tags have a fixed, public length).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

/// Best-effort zeroisation of secret buffers.
pub(crate) fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    std::hint::black_box(&buf);
}

/// Lower-case hex encoding.
pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decode hex (either case). `None` on odd length or a non-hex digit.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    b.chunks_exact(2)
        .map(|p| Some((nibble(p[0])? << 4) | nibble(p[1])?))
        .collect()
}

/// Decode a 64-digit hex string into a 32-byte digest.
pub fn hash_from_hex(s: &str) -> Option<[u8; DIGEST_LEN]> {
    let v = from_hex(s)?;
    v.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        from_hex(s).unwrap()
    }

    // NIST FIPS 180-4 / CAVP example vectors.
    #[test]
    fn sha256_empty() {
        assert_eq!(
            to_hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_abc() {
        assert_eq!(
            to_hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_448_bit() {
        assert_eq!(
            to_hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn sha256_896_bit() {
        assert_eq!(
            to_hex(&sha256(
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
            )),
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
        );
    }

    #[test]
    fn sha256_million_a() {
        // Fed in uneven chunks to also exercise the streaming buffer.
        let mut hasher = Sha256::new();
        let chunk = [b'a'; 997];
        let mut left = 1_000_000usize;
        while left > 0 {
            let n = left.min(chunk.len());
            hasher.update(&chunk[..n]);
            left -= n;
        }
        assert_eq!(
            to_hex(&hasher.finalize()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn sha256_streaming_matches_one_shot_at_every_split() {
        let msg: Vec<u8> = (0..300u32).map(|i| (i * 7 + 3) as u8).collect();
        for len in [0usize, 1, 55, 56, 57, 63, 64, 65, 119, 120, 128, 300] {
            let whole = sha256(&msg[..len]);
            for split in 0..=len {
                let mut s = Sha256::new();
                s.update(&msg[..split]);
                s.update(&msg[split..len]);
                assert_eq!(s.finalize(), whole, "len {len} split {split}");
            }
        }
    }

    // RFC 4231 HMAC-SHA256 test cases 1-7.
    #[test]
    fn rfc4231_case1() {
        let tag = hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            to_hex(&tag),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn rfc4231_case2() {
        let tag = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            to_hex(&tag),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn rfc4231_case3() {
        let tag = hmac_sha256(&[0xaa; 20], &[0xdd; 50]);
        assert_eq!(
            to_hex(&tag),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
    }

    #[test]
    fn rfc4231_case4() {
        let key = h("0102030405060708090a0b0c0d0e0f10111213141516171819");
        let tag = hmac_sha256(&key, &[0xcd; 50]);
        assert_eq!(
            to_hex(&tag),
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
        );
    }

    #[test]
    fn rfc4231_case5_truncated() {
        let tag = hmac_sha256(&[0x0c; 20], b"Test With Truncation");
        assert_eq!(to_hex(&tag[..16]), "a3b6167473100ee06e0c796c2955552b");
    }

    #[test]
    fn rfc4231_case6_long_key() {
        let tag = hmac_sha256(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            to_hex(&tag),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn rfc4231_case7_long_key_long_data() {
        let tag = hmac_sha256(
            &[0xaa; 131],
            b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
        );
        assert_eq!(
            to_hex(&tag),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
        );
    }

    #[test]
    fn hmac_key_of_exactly_block_size_is_not_hashed() {
        // A 64-byte key is used as-is; a 65-byte key is hashed. They differ.
        let k64 = [0x11u8; 64];
        let k65 = [0x11u8; 65];
        assert_ne!(hmac_sha256(&k64, b"m"), hmac_sha256(&k65, b"m"));
        // A key and its zero-padded form are equivalent per RFC 2104.
        let mut padded = [0u8; 64];
        padded[..3].copy_from_slice(b"key");
        assert_eq!(hmac_sha256(b"key", b"m"), hmac_sha256(&padded, b"m"));
    }

    #[test]
    fn ct_eq_behaviour() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(!ct_eq(&[0u8; 32], &[1u8; 32]));
    }

    #[test]
    fn hex_round_trip_and_rejects() {
        let data: Vec<u8> = (0..=255u8).collect();
        assert_eq!(from_hex(&to_hex(&data)).unwrap(), data);
        assert_eq!(from_hex("ABcd").unwrap(), vec![0xab, 0xcd]);
        assert!(from_hex("abc").is_none());
        assert!(from_hex("zz").is_none());
        assert!(from_hex("é1").is_none());
        assert!(hash_from_hex("00").is_none());
        assert!(hash_from_hex(&"ab".repeat(32)).is_some());
    }
}
