//! Reed-Solomon erasure coding over GF(2^8), std only.
//!
//! # The code
//!
//! * Field: GF(2^8) with the reducing polynomial `x^8 + x^4 + x^3 + x^2 + 1`
//!   (`0x11D`) and generator `α = 2` — the field of QR codes and of most
//!   storage RS codes.
//! * Code: the classic (BCH-view) systematic Reed-Solomon code `RS(n, k)`,
//!   `n = k + m ≤ 255`, generator polynomial
//!   `g(x) = (x - α^0)(x - α^1)…(x - α^(m-1))`. A codeword is `k` data
//!   symbols followed by the `m` coefficients of
//!   `d(x)·x^m mod g(x)`, highest degree first — exactly the error-correction
//!   codewords of a QR code (the tests check published QR vectors). Symbol
//!   `t` of the codeword (0-based, data first) is the coefficient of
//!   `x^(n-1-t)`.
//! * It is MDS: any `k` of the `n` symbols determine the rest, so up to `m`
//!   **erasures** (symbols known to be missing, at known positions) are
//!   recoverable. (Errors at unknown positions are not decoded here: the
//!   diode identifies damaged files by their SHA-256, which turns every
//!   corruption into an erasure.)
//!
//! # Shards
//!
//! A *shard* is a byte string; shard `t` holds symbol `t` of independent
//! codewords at every byte offset (byte `o` of every shard forms one
//! codeword). Data shards may differ in length: a shorter shard is treated
//! as zero-padded to the parity length, which costs nothing (zero symbols
//! contribute nothing to parity), so callers never materialise the padding.
//!
//! Encoding and decoding are linear maps, precomputed once
//! ([`ReedSolomon::new`], [`ReedSolomon::decoder`]) and then applied with
//! table-driven multiply-accumulate over whole blocks.
//!
//! Erasure decoding: a codeword `c` satisfies `c(α^j) = 0` for
//! `j = 0..m`. With erasures at positions `E` (`|E| = e ≤ m`), the first `e`
//! of these equations form a Vandermonde system in the erased symbols with
//! distinct nodes `α^(n-1-t)`, which is invertible; its inverse times the
//! syndrome contributions of the known symbols is the [`Decoder`]'s matrix.
//!
//! # Why in-crate (S10 review, R8)
//!
//! The parity bytes are part of the signed on-wire batch format
//! ([`crate::manifest::PARITY_SCHEME`]), so a replacement must produce the
//! same bytes. The audited general-purpose crates do not:
//! `reed-solomon-erasure` 6 encodes with a Vandermonde-derived systematic
//! matrix and `reed-solomon-simd` 3 with the Leopard GF(2^16) FFT code; for
//! `k = 4, m = 2` and data column `[11, 48, 85, 122]` they give parity
//! `[26, 89]` and `[142, 154]`, this code (and the BCH-view `reed-solomon`
//! 0.2.1 crate) `[236, 248]`. Switching would make every parity file already
//! shipped unrepairable, so the code stays here and is pinned instead:
//! `tests/fec_oracle.rs` checks the field exhaustively against a table-free
//! multiplier and the encoder and erasure decoder byte for byte against
//! `reed-solomon` 0.2.1 (an independent implementation of the same code,
//! dev-dependency only: unmaintained since 2018, so never shipped), and the
//! `diode_fec` libFuzzer target (`fuzz/`) runs the same oracle comparison.

use std::fmt;

/// Largest codeword length (`k + m`): the multiplicative order of `α`.
pub const MAX_SHARDS: usize = 255;

const fn build_tables() -> ([u8; 512], [u8; 256]) {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    let mut i = 0;
    while i < 255 {
        exp[i] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= 0x11D;
        }
        i += 1;
    }
    // exp[i] for i in 255..512 repeats, so exp[log a + log b] needs no `mod`.
    while i < 512 {
        exp[i] = exp[i - 255];
        i += 1;
    }
    (exp, log)
}

const TABLES: ([u8; 512], [u8; 256]) = build_tables();
static EXP: [u8; 512] = TABLES.0;
static LOG: [u8; 256] = TABLES.1;

/// `a · b` in GF(2^8)/0x11D.
pub fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        EXP[LOG[a as usize] as usize + LOG[b as usize] as usize]
    }
}

/// Multiplicative inverse; `None` for 0.
pub fn gf_inv(a: u8) -> Option<u8> {
    (a != 0).then(|| EXP[255 - LOG[a as usize] as usize])
}

/// `α^e` for any `e` (taken mod 255).
pub fn gf_exp(e: usize) -> u8 {
    EXP[e % 255]
}

/// `dst[i] ^= c · src[i]` for `i < min(len)`.
pub fn mul_acc(dst: &mut [u8], src: &[u8], c: u8) {
    if c == 0 {
        return;
    }
    let lc = LOG[c as usize] as usize;
    for (d, &s) in dst.iter_mut().zip(src) {
        if s != 0 {
            *d ^= EXP[lc + LOG[s as usize] as usize];
        }
    }
}

/// Why a code or decoder cannot be built, or shards do not fit it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FecError {
    /// `k == 0`, `m == 0` or `k + m > 255`.
    BadParameters { k: usize, m: usize },
    /// More erasures than parity shards.
    TooManyErasures { erased: usize, max: usize },
    /// An erasure position is out of range or repeated.
    BadErasure(usize),
    /// Shard counts or lengths do not match the code.
    ShardShape(String),
}

impl fmt::Display for FecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadParameters { k, m } => {
                write!(
                    f,
                    "bad RS parameters k={k} m={m} (need k,m >= 1, k+m <= 255)"
                )
            }
            Self::TooManyErasures { erased, max } => {
                write!(f, "{erased} erasures, at most {max} recoverable")
            }
            Self::BadErasure(p) => write!(f, "bad erasure position {p}"),
            Self::ShardShape(m) => write!(f, "shard shape: {m}"),
        }
    }
}

impl std::error::Error for FecError {}

/// A systematic `RS(k + m, k)` code (see the module docs).
#[derive(Debug, Clone)]
pub struct ReedSolomon {
    k: usize,
    m: usize,
    /// Generator polynomial coefficients, highest degree first, monic:
    /// `gen[0] = 1`, `gen.len() = m + 1`.
    gen: Vec<u8>,
    /// Parity as a linear map of the data: `enc[j * k + i]` is the weight
    /// of data symbol `i` in parity symbol `j`.
    enc: Vec<u8>,
}

impl ReedSolomon {
    pub fn new(k: usize, m: usize) -> Result<Self, FecError> {
        if k == 0 || m == 0 || k + m > MAX_SHARDS {
            return Err(FecError::BadParameters { k, m });
        }
        // g(x) = Π (x - α^i) = Π (x + α^i), highest degree first.
        let mut gen = vec![1u8];
        for i in 0..m {
            let root = gf_exp(i);
            let mut next = vec![0u8; gen.len() + 1];
            for (j, &c) in gen.iter().enumerate() {
                next[j] ^= c;
                next[j + 1] ^= gf_mul(c, root);
            }
            gen = next;
        }
        let mut rs = Self {
            k,
            m,
            gen,
            enc: Vec::new(),
        };
        let mut enc = vec![0u8; m * k];
        let mut unit = vec![0u8; k];
        for i in 0..k {
            unit[i] = 1;
            let p = rs.encode_symbols(&unit);
            unit[i] = 0;
            for (j, &v) in p.iter().enumerate() {
                enc[j * k + i] = v;
            }
        }
        rs.enc = enc;
        Ok(rs)
    }

    pub fn data_shards(&self) -> usize {
        self.k
    }

    pub fn parity_shards(&self) -> usize {
        self.m
    }

    /// Parity symbols of one codeword (`data.len() == k`), by polynomial
    /// division (an LFSR). The reference the block encoder is derived from.
    ///
    /// # Panics
    /// If `data.len() != k`.
    pub fn encode_symbols(&self, data: &[u8]) -> Vec<u8> {
        assert_eq!(data.len(), self.k, "encode_symbols: need k data symbols");
        let m = self.m;
        let mut r = vec![0u8; m];
        for &d in data {
            let fb = d ^ r[0];
            for i in 0..m - 1 {
                r[i] = r[i + 1] ^ gf_mul(fb, self.gen[i + 1]);
            }
            r[m - 1] = gf_mul(fb, self.gen[m]);
        }
        r
    }

    /// Compute the `m` parity shards of `data` (`k` shards of any lengths up
    /// to `parity_len`; shorter ones count as zero-padded). Returns `m`
    /// shards of `parity_len` bytes.
    pub fn encode(&self, data: &[&[u8]], parity_len: usize) -> Result<Vec<Vec<u8>>, FecError> {
        if data.len() != self.k {
            return Err(FecError::ShardShape(format!(
                "{} data shards, code has k={}",
                data.len(),
                self.k
            )));
        }
        if let Some(d) = data.iter().find(|d| d.len() > parity_len) {
            return Err(FecError::ShardShape(format!(
                "data shard of {} bytes > parity length {parity_len}",
                d.len()
            )));
        }
        let mut parity = vec![vec![0u8; parity_len]; self.m];
        for (j, p) in parity.iter_mut().enumerate() {
            for (i, d) in data.iter().enumerate() {
                mul_acc(p, d, self.enc[j * self.k + i]);
            }
        }
        Ok(parity)
    }

    /// A decoder for erasures at `erased` (codeword positions: data shards
    /// `0..k`, parity shards `k..k+m`), at most `m` of them, no repeats.
    pub fn decoder(&self, erased: &[usize]) -> Result<Decoder, FecError> {
        let n = self.k + self.m;
        let e = erased.len();
        if e > self.m {
            return Err(FecError::TooManyErasures {
                erased: e,
                max: self.m,
            });
        }
        let mut seen = vec![false; n];
        for &p in erased {
            if p >= n || seen[p] {
                return Err(FecError::BadErasure(p));
            }
            seen[p] = true;
        }
        let known: Vec<usize> = (0..n).filter(|&t| !seen[t]).collect();
        // Node of position t: X_t = α^(n-1-t).
        let node_log = |t: usize| n - 1 - t;
        // A[j][i] = X_{E_i}^j, B[j][q] = X_{K_q}^j, j < e.
        let mut a = vec![0u8; e * e];
        let mut b = vec![0u8; e * known.len()];
        for j in 0..e {
            for (i, &p) in erased.iter().enumerate() {
                a[j * e + i] = gf_exp(j * node_log(p));
            }
            for (q, &p) in known.iter().enumerate() {
                b[j * known.len() + q] = gf_exp(j * node_log(p));
            }
        }
        let inv = invert(&a, e).ok_or_else(|| {
            // Unreachable for distinct nodes (Vandermonde); kept as an error,
            // never a panic.
            FecError::ShardShape("singular erasure system".into())
        })?;
        // coef = A^-1 · B   (e × |known|).
        let kn = known.len();
        let mut coef = vec![0u8; e * kn];
        for i in 0..e {
            for j in 0..e {
                let w = inv[i * e + j];
                if w == 0 {
                    continue;
                }
                for q in 0..kn {
                    coef[i * kn + q] ^= gf_mul(w, b[j * kn + q]);
                }
            }
        }
        Ok(Decoder {
            erased: erased.to_vec(),
            known,
            coef,
        })
    }

    /// Convenience for whole shards held in memory: fill every `None` in
    /// `shards` (length `k + m`; all present shards of equal length).
    pub fn reconstruct(&self, shards: &mut [Option<Vec<u8>>]) -> Result<(), FecError> {
        if shards.len() != self.k + self.m {
            return Err(FecError::ShardShape(format!(
                "{} shards, code has n={}",
                shards.len(),
                self.k + self.m
            )));
        }
        let erased: Vec<usize> = (0..shards.len()).filter(|&t| shards[t].is_none()).collect();
        if erased.is_empty() {
            return Ok(());
        }
        let dec = self.decoder(&erased)?;
        let len = shards.iter().flatten().map(Vec::len).next().unwrap_or(0);
        if shards.iter().flatten().any(|s| s.len() != len) {
            return Err(FecError::ShardShape("shards differ in length".into()));
        }
        let mut out = vec![vec![0u8; len]; erased.len()];
        {
            let known: Vec<&[u8]> = shards.iter().flatten().map(Vec::as_slice).collect();
            let mut outs: Vec<&mut [u8]> = out.iter_mut().map(Vec::as_mut_slice).collect();
            dec.reconstruct(&known, &mut outs)?;
        }
        for (p, v) in erased.into_iter().zip(out) {
            shards[p] = Some(v);
        }
        Ok(())
    }
}

/// Recovers a fixed set of erased positions from the known ones.
#[derive(Debug, Clone)]
pub struct Decoder {
    erased: Vec<usize>,
    known: Vec<usize>,
    /// `erased.len() × known.len()`, row-major.
    coef: Vec<u8>,
}

impl Decoder {
    /// Erased positions, ascending as given.
    pub fn erased(&self) -> &[usize] {
        &self.erased
    }

    /// Known positions, ascending: the order [`Decoder::reconstruct`] wants
    /// its `known` blocks in.
    pub fn known(&self) -> &[usize] {
        &self.known
    }

    /// From one block of every known shard (in [`Decoder::known`] order,
    /// all the same length), compute the same block of every erased shard
    /// (in [`Decoder::erased`] order) into `out` (overwritten).
    pub fn reconstruct(&self, known: &[&[u8]], out: &mut [&mut [u8]]) -> Result<(), FecError> {
        if known.len() != self.known.len() || out.len() != self.erased.len() {
            return Err(FecError::ShardShape(format!(
                "{} known / {} out blocks, decoder wants {} / {}",
                known.len(),
                out.len(),
                self.known.len(),
                self.erased.len()
            )));
        }
        let len = known.first().map_or(0, |k| k.len());
        if known.iter().any(|k| k.len() != len) || out.iter().any(|o| o.len() != len) {
            return Err(FecError::ShardShape("blocks differ in length".into()));
        }
        let kn = self.known.len();
        for (i, o) in out.iter_mut().enumerate() {
            o.fill(0);
            for (q, src) in known.iter().enumerate() {
                mul_acc(o, src, self.coef[i * kn + q]);
            }
        }
        Ok(())
    }
}

/// Gauss-Jordan inverse of an `n × n` matrix over GF(2^8).
fn invert(a: &[u8], n: usize) -> Option<Vec<u8>> {
    let mut m = a.to_vec();
    let mut inv = vec![0u8; n * n];
    for i in 0..n {
        inv[i * n + i] = 1;
    }
    for col in 0..n {
        let pivot = (col..n).find(|&r| m[r * n + col] != 0)?;
        if pivot != col {
            for c in 0..n {
                m.swap(pivot * n + c, col * n + c);
                inv.swap(pivot * n + c, col * n + c);
            }
        }
        let p = gf_inv(m[col * n + col])?;
        for c in 0..n {
            m[col * n + c] = gf_mul(m[col * n + c], p);
            inv[col * n + c] = gf_mul(inv[col * n + c], p);
        }
        for r in 0..n {
            let f = m[r * n + col];
            if r == col || f == 0 {
                continue;
            }
            for c in 0..n {
                m[r * n + c] ^= gf_mul(f, m[col * n + c]);
                inv[r * n + c] ^= gf_mul(f, inv[col * n + c]);
            }
        }
    }
    Some(inv)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic test bytes (xorshift).
    fn bytes(seed: u64, n: usize) -> Vec<u8> {
        let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn field_tables_known_values() {
        // α^8 = x^4 + x^3 + x^2 + 1 = 0x1D under 0x11D.
        assert_eq!(gf_exp(8), 0x1D);
        assert_eq!(gf_exp(0), 1);
        assert_eq!(gf_exp(255), 1);
        assert_eq!(gf_exp(7), 0x80);
        assert_eq!(gf_mul(0x80, 2), 0x1D);
        // Published 0x11D antilog values (QR code log tables).
        assert_eq!(gf_exp(9), 0x3A);
        assert_eq!(gf_exp(25), 0x03);
        assert_eq!(gf_exp(254), 0x8E);
        // α generates the whole multiplicative group.
        let mut seen = [false; 256];
        for e in 0..255 {
            let v = gf_exp(e);
            assert!(!seen[v as usize], "α^{e} repeats");
            seen[v as usize] = true;
        }
        assert!(!seen[0]);
    }

    #[test]
    fn field_axioms_exhaustive() {
        assert_eq!(gf_inv(0), None);
        for a in 0..=255u8 {
            assert_eq!(gf_mul(a, 0), 0);
            assert_eq!(gf_mul(a, 1), a);
            if a != 0 {
                assert_eq!(gf_mul(a, gf_inv(a).unwrap()), 1, "inverse of {a}");
            }
            for b in 0..=255u8 {
                assert_eq!(gf_mul(a, b), gf_mul(b, a));
                // Carry-less multiply reduced by 0x11D, independently.
                let mut p: u16 = 0;
                for i in 0..8 {
                    if b & (1 << i) != 0 {
                        p ^= (a as u16) << i;
                    }
                }
                for i in (8..16).rev() {
                    if p & (1 << i) != 0 {
                        p ^= 0x11D << (i - 8);
                    }
                }
                assert_eq!(gf_mul(a, b), p as u8, "{a}*{b}");
            }
        }
    }

    #[test]
    fn qr_code_vectors() {
        // QR 1-M, "01234567" (ISO/IEC 18004 Annex I): 16 data + 10 EC codewords.
        let rs = ReedSolomon::new(16, 10).unwrap();
        let data = [
            16, 32, 12, 86, 97, 128, 236, 17, 236, 17, 236, 17, 236, 17, 236, 17,
        ];
        assert_eq!(
            rs.encode_symbols(&data),
            vec![165, 36, 212, 193, 237, 54, 199, 135, 44, 85]
        );
        // QR 1-M, "HELLO WORLD".
        let data = [
            32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17,
        ];
        assert_eq!(
            rs.encode_symbols(&data),
            vec![196, 35, 39, 119, 235, 215, 231, 226, 93, 23]
        );
        // Generator polynomial for 7 EC codewords (QR 1-L), exponents of α:
        // x^7 + α^87 x^6 + α^229 x^5 + α^146 x^4 + α^149 x^3 + α^238 x^2 + α^102 x + α^21.
        let g = ReedSolomon::new(1, 7).unwrap().gen;
        let want: Vec<u8> = [0, 87, 229, 146, 149, 238, 102, 21]
            .iter()
            .map(|&e| gf_exp(e))
            .collect();
        assert_eq!(g, want);
    }

    #[test]
    fn block_encoder_matches_symbol_encoder() {
        for (k, m) in [(1, 1), (3, 2), (10, 4), (200, 55), (1, 254), (254, 1)] {
            let rs = ReedSolomon::new(k, m).unwrap();
            let len = 37;
            let data: Vec<Vec<u8>> = (0..k).map(|i| bytes(i as u64 + 1, len)).collect();
            let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
            let parity = rs.encode(&refs, len).unwrap();
            for o in 0..len {
                let col: Vec<u8> = data.iter().map(|d| d[o]).collect();
                let p: Vec<u8> = parity.iter().map(|p| p[o]).collect();
                assert_eq!(rs.encode_symbols(&col), p, "k={k} m={m} offset {o}");
            }
        }
    }

    /// Every codeword evaluates to 0 at α^0..α^(m-1).
    #[test]
    fn codewords_have_the_generator_roots() {
        let rs = ReedSolomon::new(20, 6).unwrap();
        let data = bytes(9, 20);
        let mut cw = data.clone();
        cw.extend(rs.encode_symbols(&data));
        let n = cw.len();
        for j in 0..6 {
            let mut s = 0u8;
            for (t, &c) in cw.iter().enumerate() {
                s ^= gf_mul(c, gf_exp(j * (n - 1 - t)));
            }
            assert_eq!(s, 0, "syndrome {j}");
        }
    }

    fn subsets(n: usize, max: usize) -> Vec<Vec<usize>> {
        (0u32..1 << n)
            .filter(|b| (b.count_ones() as usize) <= max)
            .map(|b| (0..n).filter(|&i| b & (1 << i) != 0).collect())
            .collect()
    }

    #[test]
    fn exhaustive_small_erasure_patterns() {
        // Every (k, m) with k + m <= 10, every erasure set of size <= m.
        for k in 1..=8usize {
            for m in 1..=(10 - k).min(5) {
                let rs = ReedSolomon::new(k, m).unwrap();
                // Unequal data lengths: shorter shards count as zero-padded.
                let data: Vec<Vec<u8>> = (0..k)
                    .map(|i| bytes((k * 31 + m * 7 + i) as u64, 5 + (i * 3) % 7))
                    .collect();
                let plen = data.iter().map(Vec::len).max().unwrap();
                let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
                let parity = rs.encode(&refs, plen).unwrap();
                let mut full: Vec<Vec<u8>> = data
                    .iter()
                    .map(|d| {
                        let mut d = d.clone();
                        d.resize(plen, 0);
                        d
                    })
                    .collect();
                full.extend(parity);
                for set in subsets(k + m, m) {
                    let mut shards: Vec<Option<Vec<u8>>> = full.iter().cloned().map(Some).collect();
                    for &p in &set {
                        shards[p] = None;
                    }
                    rs.reconstruct(&mut shards).unwrap();
                    for (t, s) in shards.iter().enumerate() {
                        assert_eq!(s.as_ref().unwrap(), &full[t], "k={k} m={m} {set:?}");
                    }
                }
                // One erasure too many is refused, never "decoded".
                let too_many: Vec<usize> = (0..=m).collect();
                assert_eq!(
                    rs.decoder(&too_many).unwrap_err(),
                    FecError::TooManyErasures {
                        erased: m + 1,
                        max: m
                    }
                );
            }
        }
    }

    #[test]
    fn large_code_random_erasures() {
        let (k, m) = (223, 32);
        let rs = ReedSolomon::new(k, m).unwrap();
        let len = 64;
        let data: Vec<Vec<u8>> = (0..k).map(|i| bytes(1000 + i as u64, len)).collect();
        let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
        let mut full = data.clone();
        full.extend(rs.encode(&refs, len).unwrap());
        let mut x = 12345u64;
        for round in 0..20 {
            let mut shards: Vec<Option<Vec<u8>>> = full.iter().cloned().map(Some).collect();
            let mut erased = 0;
            while erased < m {
                x = x
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let p = (x >> 33) as usize % (k + m);
                if shards[p].is_some() {
                    shards[p] = None;
                    erased += 1;
                }
            }
            rs.reconstruct(&mut shards).unwrap();
            for (t, s) in shards.iter().enumerate() {
                assert_eq!(s.as_ref().unwrap(), &full[t], "round {round} shard {t}");
            }
        }
    }

    #[test]
    fn bad_parameters_and_shapes() {
        assert!(ReedSolomon::new(0, 1).is_err());
        assert!(ReedSolomon::new(1, 0).is_err());
        assert!(ReedSolomon::new(200, 56).is_err());
        assert!(ReedSolomon::new(200, 55).is_ok());
        let rs = ReedSolomon::new(3, 2).unwrap();
        assert_eq!(rs.decoder(&[5]).unwrap_err(), FecError::BadErasure(5));
        assert_eq!(rs.decoder(&[1, 1]).unwrap_err(), FecError::BadErasure(1));
        assert!(rs.encode(&[b"a", b"b"], 1).is_err());
        assert!(rs.encode(&[b"a", b"bb", b"c"], 1).is_err());
        let d = rs.decoder(&[0]).unwrap();
        assert_eq!(d.known(), &[1, 2, 3, 4]);
        let mut o = [0u8; 2];
        assert!(d
            .reconstruct(&[b"ab", b"ab", b"ab", b"a"], &mut [&mut o])
            .is_err());
        assert!(d.reconstruct(&[b"ab"], &mut [&mut o]).is_err());
        let mut shards = vec![Some(vec![1u8]), None, Some(vec![1, 2]), None, None];
        assert!(rs.reconstruct(&mut shards).is_err());
        // Nothing erased: nothing to do.
        let mut ok = vec![Some(vec![0u8]); 5];
        rs.reconstruct(&mut ok).unwrap();
    }
}
