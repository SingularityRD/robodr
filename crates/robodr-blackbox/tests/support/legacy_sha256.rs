//! TEST-ONLY reference oracle: the hand-rolled SHA-256 (FIPS 180-4) and
//! HMAC-SHA256 (RFC 2104) that `robodr_blackbox::crypto` used before S10
//! (git `38ac3a7:crates/robodr-blackbox/src/crypto.rs`, lines 31-221),
//! copied VERBATIM except that the secret wipes are plain stores here (they
//! never affected the output) and the module docs. It is kept only so
//! `tests/crypto_differential.rs` can prove that the RustCrypto-backed
//! implementation is byte-for-byte the old one, i.e. every tag and digest
//! already on disk still verifies. Never use it in library code.
//! robodr-ocsf keeps its own, separate oracle
//! (`crates/robodr-ocsf/tests/support/legacy_sha256.rs`, a verbatim copy of
//! its pre-S10 `src/hash.rs`); this file is used by robodr-blackbox only.
#![allow(dead_code)]

fn wipe(buf: &mut [u8]) {
    wipe_words(buf, 0);
}

fn wipe_words<T: Copy>(buf: &mut [T], zero: T) {
    for x in buf.iter_mut() {
        *x = zero;
    }
}

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

impl Drop for Sha256 {
    fn drop(&mut self) {
        wipe_words(&mut self.state, 0);
        wipe(&mut self.buf);
        wipe_words(std::slice::from_mut(&mut self.total_len), 0);
    }
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
                let mut block = self.buf;
                compress(&mut self.state, &block);
                wipe(&mut block);
                self.buf_len = 0;
            }
        }
        while data.len() >= BLOCK_LEN {
            let (head, rest) = data.split_at(BLOCK_LEN);
            let mut block = [0u8; BLOCK_LEN];
            block.copy_from_slice(head);
            compress(&mut self.state, &block);
            wipe(&mut block);
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
    // The schedule is derived from the (possibly secret) block.
    wipe_words(&mut w, 0);
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
    // Both hashers absorb a key-derived block; `Sha256`'s `Drop` wipes
    // their state when `finalize` consumes them.
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(message);
    let mut inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_digest);
    let tag = outer.finalize();
    wipe(&mut inner_digest);
    wipe(&mut k0);
    wipe(&mut ipad);
    wipe(&mut opad);
    tag
}
