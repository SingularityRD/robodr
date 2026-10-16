//! Ed25519 signatures (RFC 8032, PureEdDSA) in dependency-free Rust, and an
//! asymmetric [`Signer`] / [`Verifier`] backend built on them.
//!
//! # Why this exists
//!
//! The interim [`crate::sign::HmacSha256Key`] is symmetric: anyone who can
//! verify can forge. Ed25519 removes that: the robot holds the private seed,
//! fleet verifiers hold only the 32-byte public key and cannot create valid
//! records. crates.io is unreachable in the RoboDR build environment, so the
//! primitive is implemented here, in std-only Rust, behind the same traits.
//!
//! # Status: NOT AUDITED, NOT FORMALLY CONSTANT-TIME
//!
//! This is a straightforward, careful implementation pinned to every RFC 8032
//! §7.1 test vector, the FIPS 180-4 SHA-512 examples, and extra vectors
//! cross-checked against OpenSSL (via Python `cryptography`). It has **not**
//! been reviewed by a cryptographer, fuzzed against Wycheproof, or verified
//! for timing behaviour on any target CPU. **Replace it with a vetted crate
//! (`ed25519-dalek`, with `verify_strict`) as soon as crates.io is available**:
//! keep [`Ed25519SigningKey`] / [`Ed25519VerifyingKey`] as thin wrappers so the
//! `Signer`/`Verifier` contract, the `"ed25519"` algorithm id, the key-id
//! derivation and the on-disk signature format (64 raw bytes) do not change.
//!
//! Side-channel posture (best effort, not a guarantee):
//! - Field arithmetic uses 5×51-bit limbs with `u128` products; no
//!   data-dependent branches or table lookups.
//! - Scalar multiplication by secret scalars (key generation, nonce point
//!   `R = [r]B`) is a fixed 256-iteration double-and-always-add with a
//!   mask-based conditional move; the bit is never branched on.
//! - Reduction mod L is bit-serial with mask-based conditional subtraction.
//! - Field inversion/square root use fixed public exponents.
//! - Not covered: compiler transformations (no `asm` barriers beyond
//!   `std::hint::black_box`), variable-latency `u128` multiplication on some
//!   32-bit CPUs, and point *encoding* (which reads the low bit of `x` and
//!   inverts `Z`; both are fixed-time here but not verified to be).
//! - Secret buffers are wiped on drop on a best-effort basis (no volatile
//!   writes, no protection against copies the compiler may have made).
//!
//! # Verification rules
//!
//! [`verify`] is stricter than the minimum RFC 8032 §5.1.7 requires, in the
//! direction of rejecting more:
//! - signature length must be exactly 64 bytes;
//! - `S` must be canonical (`S < L`), which rules out `S + L` malleability;
//! - `A` and `R` must decode (§5.1.3) and be **canonical**: `y < p`, and
//!   `x = 0` with the sign bit set is rejected;
//! - `A` and `R` must not be of **small order** (order dividing 8, including
//!   the identity). This defeats the "identity key verifies everything" class
//!   of forgeries and matches libsodium / `ed25519-dalek::verify_strict`;
//! - the check is the **cofactorless** equation `[S]B = R + [k]A` with
//!   `k = SHA-512(R || A || M) mod L`.
//!
//! Points of mixed order (a large-order point plus a small-order torsion
//! component) are not rejected; for signatures produced by an honest signer
//! that never happens, and cofactorless verification is deterministic about
//! them. Only PureEdDSA (`Ed25519`) is provided, not `Ed25519ctx`/`Ed25519ph`.

use crate::crypto::{sha256, to_hex, wipe};
use crate::sign::{SignError, Signer, Verifier, MAX_KEY_ID_LEN};
use std::fmt;
use std::io::Read;
use std::sync::OnceLock;

/// Algorithm name recorded in the chain identity for Ed25519 keys.
pub const ED25519: &str = "ed25519";
/// Seed (private key) length in bytes.
pub const SEED_LEN: usize = 32;
/// Public key length in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Signature length in bytes (`R || S`).
pub const SIGNATURE_LEN: usize = 64;

const KEY_ID_DOMAIN: &[u8] = b"robodr-blackbox/ed25519-key-id/v1\0";

// ---------------------------------------------------------------------------
// SHA-512 (FIPS 180-4)
// ---------------------------------------------------------------------------

/// SHA-512 round constants (FIPS 180-4 §4.2.3).
const K512: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

/// SHA-512 initial hash value (FIPS 180-4 §5.3.5).
const H512: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// SHA-512 block size in bytes.
pub const SHA512_BLOCK_LEN: usize = 128;
/// SHA-512 digest size in bytes.
pub const SHA512_DIGEST_LEN: usize = 64;

/// Streaming SHA-512 hasher (FIPS 180-4).
#[derive(Clone)]
pub struct Sha512 {
    state: [u64; 8],
    buf: [u8; SHA512_BLOCK_LEN],
    buf_len: usize,
    /// Total message length in bytes (the spec allows < 2^128 bits).
    total_len: u128,
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha512 {
    /// A fresh hasher.
    pub const fn new() -> Self {
        Self {
            state: H512,
            buf: [0; SHA512_BLOCK_LEN],
            buf_len: 0,
            total_len: 0,
        }
    }

    /// Absorb `data`.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u128);
        if self.buf_len > 0 {
            let take = (SHA512_BLOCK_LEN - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < SHA512_BLOCK_LEN {
                return;
            }
            let block = self.buf;
            compress512(&mut self.state, &block);
            self.buf_len = 0;
        }
        let mut chunks = data.chunks_exact(SHA512_BLOCK_LEN);
        for block in &mut chunks {
            compress512(&mut self.state, block.try_into().expect("128-byte chunk"));
        }
        let rest = chunks.remainder();
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buf_len = rest.len();
    }

    /// Finish and return the 64-byte digest.
    pub fn finalize(mut self) -> [u8; SHA512_DIGEST_LEN] {
        let bit_len = self.total_len.wrapping_mul(8);
        let mut pad = [0u8; 2 * SHA512_BLOCK_LEN];
        pad[0] = 0x80;
        // Pad so that buf_len + pad_len ≡ 112 (mod 128), then 16 length bytes.
        let pad_len = if self.buf_len < 112 {
            112 - self.buf_len
        } else {
            240 - self.buf_len
        };
        pad[pad_len..pad_len + 16].copy_from_slice(&bit_len.to_be_bytes());
        // `update` would also count the padding into `total_len`; that is
        // harmless because the length has already been captured above.
        self.update(&pad[..pad_len + 16]);
        debug_assert_eq!(self.buf_len, 0);
        let mut out = [0u8; SHA512_DIGEST_LEN];
        for (o, w) in out.chunks_exact_mut(8).zip(self.state.iter()) {
            o.copy_from_slice(&w.to_be_bytes());
        }
        out
    }
}

fn compress512(state: &mut [u64; 8], block: &[u8; SHA512_BLOCK_LEN]) {
    let mut w = [0u64; 80];
    for (i, c) in block.chunks_exact(8).enumerate() {
        w[i] = u64::from_be_bytes(c.try_into().expect("8-byte chunk"));
    }
    for t in 16..80 {
        let s0 = w[t - 15].rotate_right(1) ^ w[t - 15].rotate_right(8) ^ (w[t - 15] >> 7);
        let s1 = w[t - 2].rotate_right(19) ^ w[t - 2].rotate_right(61) ^ (w[t - 2] >> 6);
        w[t] = w[t - 16]
            .wrapping_add(s0)
            .wrapping_add(w[t - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for t in 0..80 {
        let big_s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(big_s1)
            .wrapping_add(ch)
            .wrapping_add(K512[t])
            .wrapping_add(w[t]);
        let big_s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = big_s0.wrapping_add(maj);
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

/// One-shot SHA-512.
pub fn sha512(data: &[u8]) -> [u8; SHA512_DIGEST_LEN] {
    let mut h = Sha512::new();
    h.update(data);
    h.finalize()
}

// ---------------------------------------------------------------------------
// Field arithmetic mod p = 2^255 - 19, radix 2^51
// ---------------------------------------------------------------------------

const MASK51: u64 = (1 << 51) - 1;

/// Field element, five 51-bit limbs (little-endian). Every operation returns
/// a weakly reduced element (each limb < 2^52); only [`Fe::to_bytes`]
/// produces the canonical representative.
#[derive(Clone, Copy)]
struct Fe([u64; 5]);

impl Fe {
    const ZERO: Fe = Fe([0; 5]);
    const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    fn from_u64(v: u64) -> Fe {
        Fe::weak_reduce([v, 0, 0, 0, 0])
    }

    /// Decode 32 little-endian bytes, ignoring bit 255. The result may be
    /// the non-canonical representative of a value in `[p, 2^255)`; callers
    /// that care compare against [`Fe::to_bytes`].
    fn from_bytes(b: &[u8; 32]) -> Fe {
        let load = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().expect("8 bytes"));
        Fe([
            load(0) & MASK51,
            (load(6) >> 3) & MASK51,
            (load(12) >> 6) & MASK51,
            (load(19) >> 1) & MASK51,
            (load(24) >> 12) & MASK51,
        ])
    }

    fn weak_reduce(mut l: [u64; 5]) -> Fe {
        let c0 = l[0] >> 51;
        let c1 = l[1] >> 51;
        let c2 = l[2] >> 51;
        let c3 = l[3] >> 51;
        let c4 = l[4] >> 51;
        l[0] &= MASK51;
        l[1] &= MASK51;
        l[2] &= MASK51;
        l[3] &= MASK51;
        l[4] &= MASK51;
        l[0] += c4 * 19;
        l[1] += c0;
        l[2] += c1;
        l[3] += c2;
        l[4] += c3;
        Fe(l)
    }

    /// Canonical little-endian encoding (value in `[0, p)`, bit 255 clear).
    fn to_bytes(self) -> [u8; 32] {
        let mut l = Fe::weak_reduce(self.0).0;
        // Now value < 2p. q = 1 iff value >= p, i.e. value + 19 >= 2^255.
        let mut q = (l[0] + 19) >> 51;
        q = (l[1] + q) >> 51;
        q = (l[2] + q) >> 51;
        q = (l[3] + q) >> 51;
        q = (l[4] + q) >> 51;
        l[0] += 19 * q;
        l[1] += l[0] >> 51;
        l[0] &= MASK51;
        l[2] += l[1] >> 51;
        l[1] &= MASK51;
        l[3] += l[2] >> 51;
        l[2] &= MASK51;
        l[4] += l[3] >> 51;
        l[3] &= MASK51;
        l[4] &= MASK51; // drops 2^255, completing the subtraction of p
        let mut out = [0u8; 32];
        let mut acc: u128 = 0;
        let mut bits = 0u32;
        let mut idx = 0usize;
        for limb in l {
            acc |= (limb as u128) << bits;
            bits += 51;
            while bits >= 8 {
                out[idx] = acc as u8;
                acc >>= 8;
                bits -= 8;
                idx += 1;
            }
        }
        // 255 bits = 31 bytes + 7 bits.
        out[idx] = acc as u8;
        out
    }

    fn add(&self, o: &Fe) -> Fe {
        let (a, b) = (self.0, o.0);
        Fe::weak_reduce([
            a[0] + b[0],
            a[1] + b[1],
            a[2] + b[2],
            a[3] + b[3],
            a[4] + b[4],
        ])
    }

    fn sub(&self, o: &Fe) -> Fe {
        // Add 16p so no limb underflows (inputs are weakly reduced, < 2^52).
        const P16_0: u64 = 16 * ((1 << 51) - 19);
        const P16_N: u64 = 16 * ((1 << 51) - 1);
        let (a, b) = (self.0, o.0);
        Fe::weak_reduce([
            a[0] + P16_0 - b[0],
            a[1] + P16_N - b[1],
            a[2] + P16_N - b[2],
            a[3] + P16_N - b[3],
            a[4] + P16_N - b[4],
        ])
    }

    fn neg(&self) -> Fe {
        Fe::ZERO.sub(self)
    }

    fn mul(&self, o: &Fe) -> Fe {
        let (a, b) = (self.0, o.0);
        let m = |x: u64, y: u64| (x as u128) * (y as u128);
        let b1 = b[1] * 19;
        let b2 = b[2] * 19;
        let b3 = b[3] * 19;
        let b4 = b[4] * 19;
        let c0 = m(a[0], b[0]) + m(a[4], b1) + m(a[3], b2) + m(a[2], b3) + m(a[1], b4);
        let mut c1 = m(a[1], b[0]) + m(a[0], b[1]) + m(a[4], b2) + m(a[3], b3) + m(a[2], b4);
        let mut c2 = m(a[2], b[0]) + m(a[1], b[1]) + m(a[0], b[2]) + m(a[4], b3) + m(a[3], b4);
        let mut c3 = m(a[3], b[0]) + m(a[2], b[1]) + m(a[1], b[2]) + m(a[0], b[3]) + m(a[4], b4);
        let mut c4 = m(a[4], b[0]) + m(a[3], b[1]) + m(a[2], b[2]) + m(a[1], b[3]) + m(a[0], b[4]);
        let mask = MASK51 as u128;
        c1 += c0 >> 51;
        c2 += c1 >> 51;
        c3 += c2 >> 51;
        c4 += c3 >> 51;
        let r0 = (c0 & mask) + (c4 >> 51) * 19;
        let r1 = (c1 & mask) + (r0 >> 51);
        Fe([
            (r0 & mask) as u64,
            r1 as u64,
            (c2 & mask) as u64,
            (c3 & mask) as u64,
            (c4 & mask) as u64,
        ])
    }

    fn square(&self) -> Fe {
        self.mul(self)
    }

    /// `self^e` for a **public** little-endian exponent (branches on `e`).
    fn pow(&self, e: &[u8; 32]) -> Fe {
        let mut r = Fe::ONE;
        for i in (0..256).rev() {
            r = r.square();
            if (e[i / 8] >> (i % 8)) & 1 == 1 {
                r = r.mul(self);
            }
        }
        r
    }

    /// `self^(p-2)`; maps 0 to 0.
    fn invert(&self) -> Fe {
        let mut e = [0xffu8; 32];
        e[0] = 0xeb;
        e[31] = 0x7f;
        self.pow(&e)
    }

    /// `self^((p-5)/8)` = `self^(2^252 - 3)`.
    fn pow_p58(&self) -> Fe {
        let mut e = [0xffu8; 32];
        e[0] = 0xfd;
        e[31] = 0x0f;
        self.pow(&e)
    }

    /// Replace `self` with `o` iff `choice == 1`, without branching.
    fn cmov(&mut self, o: &Fe, choice: u64) {
        let mask = 0u64.wrapping_sub(choice & 1);
        for (s, x) in self.0.iter_mut().zip(o.0.iter()) {
            *s ^= mask & (*s ^ *x);
        }
    }

    fn ct_eq(&self, o: &Fe) -> bool {
        let (a, b) = (self.to_bytes(), o.to_bytes());
        let mut d = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            d |= x ^ y;
        }
        std::hint::black_box(d) == 0
    }

    fn is_zero(&self) -> bool {
        self.ct_eq(&Fe::ZERO)
    }

    fn is_negative(&self) -> u8 {
        self.to_bytes()[0] & 1
    }
}

// ---------------------------------------------------------------------------
// Curve -x^2 + y^2 = 1 + d x^2 y^2, extended coordinates (X:Y:Z:T), T = XY/Z
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

struct Consts {
    d: Fe,
    d2: Fe,
    sqrt_m1: Fe,
    base: Point,
}

fn consts() -> &'static Consts {
    static C: OnceLock<Consts> = OnceLock::new();
    C.get_or_init(|| {
        // d = -121665 / 121666
        let d = Fe::from_u64(121665)
            .neg()
            .mul(&Fe::from_u64(121666).invert());
        // sqrt(-1) = 2^((p-1)/4), (p-1)/4 = 2^253 - 5
        let mut e = [0xffu8; 32];
        e[0] = 0xfb;
        e[31] = 0x1f;
        let sqrt_m1 = Fe::from_u64(2).pow(&e);
        let partial = Consts {
            d,
            d2: d.add(&d),
            sqrt_m1,
            base: Point::IDENTITY,
        };
        // B: y = 4/5, x even (positive).
        let mut b = [0x66u8; 32];
        b[0] = 0x58;
        let base = decode_with(&partial, &b).expect("base point decodes");
        Consts { base, ..partial }
    })
}

impl Point {
    const IDENTITY: Point = Point {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    /// Complete addition (RFC 8032 §5.1.4); also valid for doubling.
    fn add(&self, o: &Point) -> Point {
        let c = consts();
        let a = self.y.sub(&self.x).mul(&o.y.sub(&o.x));
        let b = self.y.add(&self.x).mul(&o.y.add(&o.x));
        let cc = self.t.mul(&c.d2).mul(&o.t);
        let d = self.z.add(&self.z).mul(&o.z);
        let e = b.sub(&a);
        let f = d.sub(&cc);
        let g = d.add(&cc);
        let h = b.add(&a);
        Point {
            x: e.mul(&f),
            y: g.mul(&h),
            t: e.mul(&h),
            z: f.mul(&g),
        }
    }

    fn double(&self) -> Point {
        self.add(self)
    }

    fn cmov(&mut self, o: &Point, choice: u64) {
        self.x.cmov(&o.x, choice);
        self.y.cmov(&o.y, choice);
        self.z.cmov(&o.z, choice);
        self.t.cmov(&o.t, choice);
    }

    /// `[k]self` for a 256-bit little-endian scalar: fixed iteration count,
    /// always adds, selects with a mask (no branch on the scalar bits).
    fn mul_scalar(&self, k: &[u8; 32]) -> Point {
        let mut q = Point::IDENTITY;
        for i in (0..256).rev() {
            q = q.double();
            let sum = q.add(self);
            let bit = ((k[i / 8] >> (i % 8)) & 1) as u64;
            q.cmov(&sum, std::hint::black_box(bit));
        }
        q
    }

    /// Projective equality: X1 Z2 = X2 Z1 and Y1 Z2 = Y2 Z1.
    fn eq(&self, o: &Point) -> bool {
        let x = self.x.mul(&o.z).ct_eq(&o.x.mul(&self.z));
        let y = self.y.mul(&o.z).ct_eq(&o.y.mul(&self.z));
        x & y
    }

    fn is_identity(&self) -> bool {
        self.eq(&Point::IDENTITY)
    }

    /// Order divides 8 (includes the identity).
    fn is_small_order(&self) -> bool {
        self.double().double().double().is_identity()
    }

    /// RFC 8032 §5.1.2 encoding.
    fn encode(&self) -> [u8; 32] {
        let zi = self.z.invert();
        let x = self.x.mul(&zi);
        let y = self.y.mul(&zi);
        let mut out = y.to_bytes();
        out[31] |= x.is_negative() << 7;
        out
    }
}

/// RFC 8032 §5.1.3 decoding with canonicality checks (`y < p`; no `x = 0`
/// with the sign bit set). Does **not** reject small-order points.
fn decode_with(c: &Consts, bytes: &[u8; 32]) -> Option<Point> {
    let sign = bytes[31] >> 7;
    let mut ybytes = *bytes;
    ybytes[31] &= 0x7f;
    let y = Fe::from_bytes(&ybytes);
    if y.to_bytes() != ybytes {
        return None; // y >= p: non-canonical
    }
    let yy = y.square();
    let u = yy.sub(&Fe::ONE);
    let v = c.d.mul(&yy).add(&Fe::ONE);
    // x = u v^3 (u v^7)^((p-5)/8)
    let v3 = v.square().mul(&v);
    let v7 = v3.square().mul(&v);
    let mut x = u.mul(&v3).mul(&u.mul(&v7).pow_p58());
    let vxx = v.mul(&x.square());
    if vxx.ct_eq(&u) {
        // root found
    } else if vxx.ct_eq(&u.neg()) {
        x = x.mul(&c.sqrt_m1);
    } else {
        return None; // not on the curve
    }
    if x.is_zero() && sign == 1 {
        return None; // non-canonical encoding of x = 0
    }
    if x.is_negative() != sign {
        x = x.neg();
    }
    Some(Point {
        x,
        y,
        z: Fe::ONE,
        t: x.mul(&y),
    })
}

/// Strict decoding used for `A` and `R`: canonical and not of small order.
fn decode_strict(bytes: &[u8; 32]) -> Option<Point> {
    let p = decode_with(consts(), bytes)?;
    if p.is_small_order() {
        return None;
    }
    Some(p)
}

// ---------------------------------------------------------------------------
// Scalars mod L = 2^252 + 27742317777372353535851937790883648493
// ---------------------------------------------------------------------------

/// L as little-endian 64-bit limbs.
const L_LIMBS: [u64; 4] = [
    0x5812631a5cf5d3ed,
    0x14def9dea2f79cd6,
    0x0000000000000000,
    0x1000000000000000,
];

/// `a - b` over 256-bit little-endian limbs; returns (difference, borrow).
fn sub256(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], u64) {
    let mut out = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        out[i] = d2;
        borrow = (b1 | b2) as u64;
    }
    (out, borrow)
}

fn limbs_from_bytes(b: &[u8; 32]) -> [u64; 4] {
    let mut l = [0u64; 4];
    for (i, c) in b.chunks_exact(8).enumerate() {
        l[i] = u64::from_le_bytes(c.try_into().expect("8 bytes"));
    }
    l
}

fn limbs_to_bytes(l: &[u64; 4]) -> [u8; 32] {
    let mut b = [0u8; 32];
    for (c, v) in b.chunks_exact_mut(8).zip(l.iter()) {
        c.copy_from_slice(&v.to_le_bytes());
    }
    b
}

/// Reduce a little-endian integer of up to 512 bits mod L. Bit-serial with
/// a mask-selected conditional subtraction (fixed work per input bit).
fn reduce_wide(bytes: &[u8; 64]) -> [u8; 32] {
    let mut r = [0u64; 4]; // invariant: r < L < 2^253
    for i in (0..512).rev() {
        let bit = ((bytes[i / 8] >> (i % 8)) & 1) as u64;
        r[3] = (r[3] << 1) | (r[2] >> 63);
        r[2] = (r[2] << 1) | (r[1] >> 63);
        r[1] = (r[1] << 1) | (r[0] >> 63);
        r[0] = (r[0] << 1) | bit;
        // r < 2L now; subtract L unless that borrows.
        let (d, borrow) = sub256(&r, &L_LIMBS);
        let keep_d = borrow.wrapping_sub(1); // all-ones iff no borrow
        for j in 0..4 {
            r[j] = (d[j] & keep_d) | (r[j] & !keep_d);
        }
    }
    limbs_to_bytes(&r)
}

/// `(a * b + c) mod L` for 256-bit little-endian `a`, `b`, `c`.
fn mul_add_mod_l(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let (a, b, c) = (
        limbs_from_bytes(a),
        limbs_from_bytes(b),
        limbs_from_bytes(c),
    );
    let mut prod = [0u64; 8];
    for i in 0..4 {
        let mut carry: u128 = 0;
        for j in 0..4 {
            let t = prod[i + j] as u128 + (a[i] as u128) * (b[j] as u128) + carry;
            prod[i + j] = t as u64;
            carry = t >> 64;
        }
        prod[i + 4] = carry as u64;
    }
    // + c (the total stays < 2^512 because a, b < 2^256 and c < 2^256).
    let mut carry: u128 = 0;
    for (i, p) in prod.iter_mut().enumerate() {
        let t = *p as u128 + if i < 4 { c[i] as u128 } else { 0 } + carry;
        *p = t as u64;
        carry = t >> 64;
    }
    let mut wide = [0u8; 64];
    for (ch, v) in wide.chunks_exact_mut(8).zip(prod.iter()) {
        ch.copy_from_slice(&v.to_le_bytes());
    }
    let out = reduce_wide(&wide);
    wipe(&mut wide);
    out
}

/// `s < L` (public input, so a plain comparison is fine).
fn scalar_is_canonical(s: &[u8; 32]) -> bool {
    sub256(&limbs_from_bytes(s), &L_LIMBS).1 == 1
}

// ---------------------------------------------------------------------------
// Ed25519 (RFC 8032 §5.1.5 - §5.1.7)
// ---------------------------------------------------------------------------

/// Expanded secret: clamped scalar `s` and the nonce `prefix`.
struct Expanded {
    scalar: [u8; 32],
    prefix: [u8; 32],
}

impl Drop for Expanded {
    fn drop(&mut self) {
        wipe(&mut self.scalar);
        wipe(&mut self.prefix);
    }
}

fn expand(seed: &[u8; SEED_LEN]) -> Expanded {
    let mut h = sha512(seed);
    let mut e = Expanded {
        scalar: [0; 32],
        prefix: [0; 32],
    };
    e.scalar.copy_from_slice(&h[..32]);
    e.prefix.copy_from_slice(&h[32..]);
    wipe(&mut h);
    e.scalar[0] &= 248;
    e.scalar[31] &= 127;
    e.scalar[31] |= 64;
    e
}

fn sign_expanded(
    e: &Expanded,
    public: &[u8; PUBLIC_KEY_LEN],
    message: &[u8],
) -> [u8; SIGNATURE_LEN] {
    let mut h = Sha512::new();
    h.update(&e.prefix);
    h.update(message);
    let mut rh = h.finalize();
    let mut r = reduce_wide(&rh);
    wipe(&mut rh);
    let big_r = consts().base.mul_scalar(&r).encode();
    let mut h = Sha512::new();
    h.update(&big_r);
    h.update(public);
    h.update(message);
    let k = reduce_wide(&h.finalize());
    let s = mul_add_mod_l(&k, &e.scalar, &r);
    wipe(&mut r);
    let mut sig = [0u8; SIGNATURE_LEN];
    sig[..32].copy_from_slice(&big_r);
    sig[32..].copy_from_slice(&s);
    sig
}

/// Derive the public key `A = [s]B` from a 32-byte seed (RFC 8032 §5.1.5).
pub fn public_key_from_seed(seed: &[u8; SEED_LEN]) -> [u8; PUBLIC_KEY_LEN] {
    let e = expand(seed);
    consts().base.mul_scalar(&e.scalar).encode()
}

/// Sign `message` with the key derived from `seed` (RFC 8032 §5.1.6).
/// Deterministic: the same seed and message always give the same signature.
pub fn sign(seed: &[u8; SEED_LEN], message: &[u8]) -> [u8; SIGNATURE_LEN] {
    let e = expand(seed);
    let public = consts().base.mul_scalar(&e.scalar).encode();
    sign_expanded(&e, &public, message)
}

fn verify_point(a_bytes: &[u8; 32], a: &Point, message: &[u8], signature: &[u8]) -> bool {
    let Ok(sig) = <&[u8; SIGNATURE_LEN]>::try_from(signature) else {
        return false;
    };
    let r_bytes: [u8; 32] = sig[..32].try_into().expect("32 bytes");
    let s: [u8; 32] = sig[32..].try_into().expect("32 bytes");
    if !scalar_is_canonical(&s) {
        return false;
    }
    let Some(r) = decode_strict(&r_bytes) else {
        return false;
    };
    let mut h = Sha512::new();
    h.update(&r_bytes);
    h.update(a_bytes);
    h.update(message);
    let k = reduce_wide(&h.finalize());
    let lhs = consts().base.mul_scalar(&s);
    let rhs = r.add(&a.mul_scalar(&k));
    lhs.eq(&rhs)
}

/// Strict, cofactorless Ed25519 verification (see the module docs for the
/// exact rules). Never panics; any malformed input yields `false`.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(a_bytes) = <&[u8; PUBLIC_KEY_LEN]>::try_from(public_key) else {
        return false;
    };
    let Some(a) = decode_strict(a_bytes) else {
        return false;
    };
    verify_point(a_bytes, &a, message, signature)
}

// ---------------------------------------------------------------------------
// Signer / Verifier backend
// ---------------------------------------------------------------------------

/// Why an Ed25519 key could not be created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ed25519Error {
    /// Key id is empty, longer than [`MAX_KEY_ID_LEN`], or not printable ASCII.
    BadKeyId,
    /// Public key is not a canonical encoding of a point of large order.
    InvalidPublicKey,
    /// The operating-system randomness source failed.
    Rng(String),
}

impl fmt::Display for Ed25519Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ed25519Error::BadKeyId => write!(
                f,
                "key id must be 1..={MAX_KEY_ID_LEN} printable ASCII characters"
            ),
            Ed25519Error::InvalidPublicKey => {
                write!(f, "not a valid (canonical, large-order) Ed25519 public key")
            }
            Ed25519Error::Rng(e) => write!(f, "randomness source failed: {e}"),
        }
    }
}

impl std::error::Error for Ed25519Error {}

fn check_key_id(key_id: &str) -> Result<(), Ed25519Error> {
    if key_id.is_empty()
        || key_id.len() > MAX_KEY_ID_LEN
        || !key_id.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(Ed25519Error::BadKeyId);
    }
    Ok(())
}

/// `ed25519:` + first 8 bytes of SHA-256(domain || public key), in hex.
/// Signing and verifying halves derive the same id from the public key.
pub fn derive_key_id(public: &[u8; PUBLIC_KEY_LEN]) -> String {
    let mut m = KEY_ID_DOMAIN.to_vec();
    m.extend_from_slice(public);
    format!("{ED25519}:{}", to_hex(&sha256(&m)[..8]))
}

/// Read a fresh 32-byte seed from `/dev/urandom` (Linux; the kernel CSPRNG,
/// non-blocking once initialised at boot). An all-zero read is treated as a
/// broken source.
pub fn random_seed() -> Result<[u8; SEED_LEN], Ed25519Error> {
    let mut seed = [0u8; SEED_LEN];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut seed))
        .map_err(|e| Ed25519Error::Rng(e.to_string()))?;
    if seed.iter().all(|&b| b == 0) {
        return Err(Ed25519Error::Rng("all-zero output".into()));
    }
    Ok(seed)
}

/// Ed25519 private key (32-byte seed) usable as a recorder [`Signer`].
/// Secret material is wiped on drop (best effort); `Debug` redacts it.
pub struct Ed25519SigningKey {
    key_id: String,
    seed: [u8; SEED_LEN],
    expanded: Expanded,
    public: [u8; PUBLIC_KEY_LEN],
}

impl Ed25519SigningKey {
    /// Key from an existing seed under an explicit key id.
    pub fn from_seed(
        key_id: impl Into<String>,
        seed: &[u8; SEED_LEN],
    ) -> Result<Self, Ed25519Error> {
        let key_id = key_id.into();
        check_key_id(&key_id)?;
        let expanded = expand(seed);
        let public = consts().base.mul_scalar(&expanded.scalar).encode();
        Ok(Self {
            key_id,
            seed: *seed,
            expanded,
            public,
        })
    }

    /// Key from an existing seed, key id derived from the public key
    /// ([`derive_key_id`]).
    pub fn from_seed_with_derived_id(seed: &[u8; SEED_LEN]) -> Self {
        let public = public_key_from_seed(seed);
        Self::from_seed(derive_key_id(&public), seed).expect("derived key id is valid")
    }

    /// Fresh key from [`random_seed`] under an explicit key id.
    pub fn generate(key_id: impl Into<String>) -> Result<Self, Ed25519Error> {
        let mut seed = random_seed()?;
        let k = Self::from_seed(key_id, &seed);
        wipe(&mut seed);
        k
    }

    /// Fresh key from [`random_seed`] with a derived key id.
    pub fn generate_with_derived_id() -> Result<Self, Ed25519Error> {
        let mut seed = random_seed()?;
        let k = Self::from_seed_with_derived_id(&seed);
        wipe(&mut seed);
        Ok(k)
    }

    /// The 32-byte public key `A`.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.public
    }

    /// The matching verifier, under the same key id.
    pub fn verifying_key(&self) -> Ed25519VerifyingKey {
        Ed25519VerifyingKey::from_bytes(self.key_id.clone(), &self.public)
            .expect("public key of a clamped scalar is valid")
    }

    /// **Secret.** The seed, for sealing the key at rest (e.g. to a TPM).
    /// Callers must wipe the returned copy when done.
    pub fn to_seed(&self) -> [u8; SEED_LEN] {
        self.seed
    }

    /// Sign `message`, returning the 64-byte `R || S`.
    pub fn sign_message(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        sign_expanded(&self.expanded, &self.public, message)
    }
}

impl Drop for Ed25519SigningKey {
    fn drop(&mut self) {
        wipe(&mut self.seed);
    }
}

impl fmt::Debug for Ed25519SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519SigningKey")
            .field("key_id", &self.key_id)
            .field("public", &to_hex(&self.public))
            .field("seed", &"<redacted>")
            .finish()
    }
}

impl Signer for Ed25519SigningKey {
    fn algorithm(&self) -> &str {
        ED25519
    }
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        Ok(self.sign_message(message).to_vec())
    }
    fn verify_own(&self, message: &[u8], signature: &[u8]) -> Option<bool> {
        Some(verify(&self.public, message, signature))
    }
}

/// Ed25519 public key usable as a [`Verifier`]. Construction validates the
/// key (canonical, not small order), so a verifier can never be built
/// around a key that would accept forged signatures.
#[derive(Clone)]
pub struct Ed25519VerifyingKey {
    key_id: String,
    public: [u8; PUBLIC_KEY_LEN],
    point: Point,
}

impl Ed25519VerifyingKey {
    /// Wrap a 32-byte public key under an explicit key id.
    pub fn from_bytes(
        key_id: impl Into<String>,
        public: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<Self, Ed25519Error> {
        let key_id = key_id.into();
        check_key_id(&key_id)?;
        let point = decode_strict(public).ok_or(Ed25519Error::InvalidPublicKey)?;
        Ok(Self {
            key_id,
            public: *public,
            point,
        })
    }

    /// Wrap a public key with the derived key id ([`derive_key_id`]).
    pub fn from_bytes_with_derived_id(public: &[u8; PUBLIC_KEY_LEN]) -> Result<Self, Ed25519Error> {
        Self::from_bytes(derive_key_id(public), public)
    }

    /// The 32-byte public key.
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public
    }
}

impl fmt::Debug for Ed25519VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519VerifyingKey")
            .field("key_id", &self.key_id)
            .field("public", &to_hex(&self.public))
            .finish()
    }
}

impl Verifier for Ed25519VerifyingKey {
    fn algorithm(&self) -> &str {
        ED25519
    }
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        verify_point(&self.public, &self.point, message, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::from_hex;

    fn h32(s: &str) -> [u8; 32] {
        from_hex(s).unwrap().try_into().unwrap()
    }

    #[test]
    fn field_constants_match_published_values() {
        let c = consts();
        assert_eq!(
            to_hex(&c.d.to_bytes()),
            "a3785913ca4deb75abd841414d0a700098e879777940c78c73fe6f2bee6c0352"
        );
        assert_eq!(
            to_hex(&c.sqrt_m1.to_bytes()),
            "b0a00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024832b"
        );
        assert!(c.sqrt_m1.square().ct_eq(&Fe::ONE.neg()));
        // Base point x coordinate (RFC 8032 §5.1).
        let zi = c.base.z.invert();
        assert_eq!(
            to_hex(&c.base.x.mul(&zi).to_bytes()),
            "1ad5258f602d56c9b2a7259560c72c695cdcd6fd31e2a4c0fe536ecdd3366921"
        );
    }

    #[test]
    fn field_canonical_encoding_edges() {
        // p, p+1, 2^255-1 encode to 0, 1, 18.
        let p = h32("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        assert_eq!(Fe::from_bytes(&p).to_bytes(), [0u8; 32]);
        let mut p1 = p;
        p1[0] = 0xee;
        assert_eq!(Fe::from_bytes(&p1).to_bytes(), Fe::ONE.to_bytes());
        let max = [0xffu8; 32];
        assert_eq!(Fe::from_bytes(&max).to_bytes(), Fe::from_u64(18).to_bytes());
        // p-1 is canonical and equals -1.
        let mut pm1 = p;
        pm1[0] = 0xec;
        assert_eq!(Fe::from_bytes(&pm1).to_bytes(), pm1);
        assert!(Fe::from_bytes(&pm1).ct_eq(&Fe::ONE.neg()));
        // Inverse round trip.
        let x = Fe::from_bytes(&[0x37; 32]);
        assert!(x.mul(&x.invert()).ct_eq(&Fe::ONE));
        assert!(Fe::ZERO.invert().is_zero());
        // sub wraps correctly.
        assert!(Fe::ZERO.sub(&Fe::ONE).add(&Fe::ONE).is_zero());
    }

    #[test]
    fn field_mul_handles_max_weak_limbs() {
        // Limbs at the top of the weakly reduced range must not overflow.
        let big = Fe([(1 << 52) - 1; 5]);
        let canon = Fe::from_bytes(&big.to_bytes());
        assert!(big.mul(&big).ct_eq(&canon.mul(&canon)));
        assert!(big.sub(&big).is_zero());
    }

    #[test]
    fn base_point_has_order_l() {
        let c = consts();
        let l = limbs_to_bytes(&L_LIMBS);
        assert!(c.base.mul_scalar(&l).is_identity());
        assert!(!c.base.is_small_order());
        let mut lm1 = l;
        lm1[0] -= 1;
        // [L-1]B = -B
        let neg_b = c.base.mul_scalar(&lm1);
        assert!(neg_b.add(&c.base).is_identity());
    }

    #[test]
    fn encode_decode_round_trip() {
        let c = consts();
        let mut p = c.base;
        for _ in 0..20 {
            let enc = p.encode();
            let q = decode_with(c, &enc).unwrap();
            assert!(q.eq(&p));
            assert_eq!(q.encode(), enc);
            p = p.add(&c.base).double();
        }
    }

    #[test]
    fn scalar_reduction_vectors() {
        let l = limbs_to_bytes(&L_LIMBS);
        assert_eq!(
            to_hex(&l),
            "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"
        );
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&l);
        assert_eq!(reduce_wide(&wide), [0u8; 32]);
        assert_eq!(
            to_hex(&reduce_wide(&[0xff; 64])),
            "000f9c44e31106a447938568a71b0ed065bef517d273ecce3d9a307c1b419903"
        );
        assert_eq!(
            to_hex(&reduce_wide(&sha512(b"x"))),
            "43cf46dd2ebae1ea68f92f182a1e4f8d064c42a417ed6011b457821bc8408e06"
        );
        assert!(!scalar_is_canonical(&l));
        let mut lm1 = l;
        lm1[0] -= 1;
        assert!(scalar_is_canonical(&lm1));
        assert!(scalar_is_canonical(&[0; 32]));
        assert!(!scalar_is_canonical(&[0xff; 32]));
        // (L-1)*(L-1) + 0 = 1 mod L
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(mul_add_mod_l(&lm1, &lm1, &[0; 32]), one);
        // 0*x + (L-1) = L-1
        assert_eq!(mul_add_mod_l(&[0; 32], &[0xff; 32], &lm1), lm1);
    }

    #[test]
    fn small_order_points_are_rejected_by_strict_decode() {
        // Identity (0,1) and (0,-1) (order 2).
        let mut id = [0u8; 32];
        id[0] = 1;
        assert!(decode_with(consts(), &id).is_some());
        assert!(decode_strict(&id).is_none());
        let m1 = h32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        assert!(decode_with(consts(), &m1).is_some());
        assert!(decode_strict(&m1).is_none());
        // x = 0 with sign bit set: non-canonical.
        let mut id_neg = id;
        id_neg[31] |= 0x80;
        assert!(decode_with(consts(), &id_neg).is_none());
        // y = p + 1 (non-canonical encoding of y = 1).
        let p1 = h32("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        assert!(decode_with(consts(), &p1).is_none());
    }

    #[test]
    fn random_seed_reads_urandom() {
        let a = random_seed().unwrap();
        let b = random_seed().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn debug_redacts_seed() {
        let k = Ed25519SigningKey::from_seed("dbg", &[0x5a; 32]).unwrap();
        let s = format!("{k:?}");
        assert!(s.contains("redacted"));
        assert!(!s.contains("5a5a5a"));
    }
}
