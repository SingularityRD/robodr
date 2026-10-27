//! S10 (R8): differential test of the in-crate Reed-Solomon code
//! (`robodr_diode::fec`) against an independent implementation used as an
//! oracle: the `reed-solomon` crate (dev-dependency only), a BCH-view
//! RS(n, k) codec over GF(2^8)/0x11D with generator roots `α^0..α^(m-1)`,
//! i.e. the same code the diode's parity files use (see `src/fec.rs`).
//!
//! Why an oracle and not a replacement: the audited general-purpose crates
//! (`reed-solomon-erasure`: Vandermonde-derived systematic matrix code;
//! `reed-solomon-simd`: Leopard GF(2^16) FFT code) compute *different*
//! parity bytes for the same data, so switching would make every parity file
//! already shipped unrepairable. The parity bytes are part of the signed
//! on-wire format (`PARITY_SCHEME = "rs-gf256-0x11d/1"`), so the in-crate
//! code stays and is pinned here, byte for byte, to an independent codec.
//!
//! Checked:
//! * the field: `gf_mul` / `gf_inv` / `gf_exp` exhaustively against a
//!   bitwise (shift-and-add) GF(2^8)/0x11D multiplier written here;
//! * encoding: `encode_symbols` and the block encoder `encode` (with short,
//!   zero-padded data shards) produce exactly the oracle's ECC bytes, for
//!   random `(k, m)` over the whole range `k + m <= 255`;
//! * decoding: random erasure patterns (up to `m`, data and parity) are
//!   rebuilt to the original bytes, and the oracle's erasure decoder agrees.
//!
//! `ROBODR_FEC_ORACLE_ITERS` scales the random part (default 300).

use robodr_diode::fec::{gf_exp, gf_inv, gf_mul, ReedSolomon, MAX_SHARDS};

/// xorshift64* (deterministic, no rand crate).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    /// `lo..=hi`.
    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + (self.next() % (hi - lo + 1) as u64) as usize
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
    /// `count` distinct values of `0..n`, ascending.
    fn distinct(&mut self, n: usize, count: usize) -> Vec<usize> {
        let mut all: Vec<usize> = (0..n).collect();
        for i in 0..count {
            let j = self.range(i, n - 1);
            all.swap(i, j);
        }
        let mut v = all[..count].to_vec();
        v.sort_unstable();
        v
    }
}

fn iterations() -> usize {
    std::env::var("ROBODR_FEC_ORACLE_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300)
}

/// Shift-and-add multiplication in GF(2^8) with the reducing polynomial
/// x^8 + x^4 + x^3 + x^2 + 1 (0x11D): no tables.
fn bitwise_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        let carry = a & 0x80 != 0;
        a <<= 1;
        if carry {
            a ^= 0x1d;
        }
        b >>= 1;
    }
    p
}

#[test]
fn field_matches_bitwise_arithmetic_exhaustively() {
    for a in 0..=255u8 {
        for b in 0..=255u8 {
            assert_eq!(gf_mul(a, b), bitwise_mul(a, b), "{a} * {b}");
        }
        match gf_inv(a) {
            None => assert_eq!(a, 0),
            Some(i) => assert_eq!(bitwise_mul(a, i), 1, "inverse of {a}"),
        }
    }
    let mut x = 1u8;
    for e in 0..600 {
        assert_eq!(gf_exp(e), x, "alpha^{e}");
        x = bitwise_mul(x, 2);
    }
}

/// The oracle's ECC bytes for one codeword's data symbols.
fn oracle_parity(m: usize, data: &[u8]) -> Vec<u8> {
    reed_solomon::Encoder::new(m).encode(data).ecc().to_vec()
}

#[test]
fn symbol_encoder_matches_oracle_for_edge_parameters() {
    let mut rng = Rng(0xfec0_0001);
    for (k, m) in [
        (1, 1),
        (1, 254),
        (254, 1),
        (2, 2),
        (10, 4),
        (16, 10),
        (128, 127),
        (223, 32),
        (200, 55),
        (MAX_SHARDS - 32, 32),
    ] {
        let rs = ReedSolomon::new(k, m).unwrap();
        for _ in 0..8 {
            let data = rng.bytes(k);
            assert_eq!(
                rs.encode_symbols(&data),
                oracle_parity(m, &data),
                "k={k} m={m}"
            );
        }
        // All-zero data has all-zero parity; a single 1 gives the generator.
        assert_eq!(rs.encode_symbols(&vec![0; k]), vec![0; m]);
    }
}

#[test]
fn block_encoder_matches_oracle_on_random_codes_and_short_shards() {
    let mut rng = Rng(0xfec0_0002);
    for _ in 0..iterations() {
        let k = rng.range(1, 64);
        let m = rng.range(1, 32.min(MAX_SHARDS - k));
        let parity_len = rng.range(0, 96);
        // Data shards of any length up to parity_len (shorter = zero-padded).
        let data: Vec<Vec<u8>> = (0..k)
            .map(|_| {
                let n = rng.range(0, parity_len);
                rng.bytes(n)
            })
            .collect();
        let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
        let rs = ReedSolomon::new(k, m).unwrap();
        let parity = rs.encode(&refs, parity_len).unwrap();
        assert_eq!(parity.len(), m);
        for o in 0..parity_len {
            let column: Vec<u8> = data
                .iter()
                .map(|d| d.get(o).copied().unwrap_or(0))
                .collect();
            let want = oracle_parity(m, &column);
            let got: Vec<u8> = parity.iter().map(|p| p[o]).collect();
            assert_eq!(got, want, "k={k} m={m} offset {o}");
        }
    }
}

#[test]
fn erasure_decoding_rebuilds_and_agrees_with_oracle() {
    let mut rng = Rng(0xfec0_0003);
    for _ in 0..iterations() {
        let k = rng.range(1, 40);
        let m = rng.range(1, 16.min(MAX_SHARDS - k));
        let n = k + m;
        let len = rng.range(1, 24);
        let data: Vec<Vec<u8>> = (0..k).map(|_| rng.bytes(len)).collect();
        let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
        let rs = ReedSolomon::new(k, m).unwrap();
        let parity = rs.encode(&refs, len).unwrap();
        let full: Vec<Vec<u8>> = data.iter().chain(parity.iter()).cloned().collect();
        let e = rng.range(0, m);
        let erased = rng.distinct(n, e);
        let mut shards: Vec<Option<Vec<u8>>> = full.iter().cloned().map(Some).collect();
        for &p in &erased {
            shards[p] = None;
        }
        rs.reconstruct(&mut shards).unwrap();
        for (t, s) in shards.iter().enumerate() {
            assert_eq!(s.as_ref(), Some(&full[t]), "k={k} m={m} erased {erased:?}");
        }
        // The oracle decodes the same erasures, codeword by codeword.
        let dec = reed_solomon::Decoder::new(m);
        let pos: Vec<u8> = erased.iter().map(|&p| p as u8).collect();
        for o in 0..len {
            let mut cw: Vec<u8> = full.iter().map(|s| s[o]).collect();
            for &p in &erased {
                cw[p] = 0;
            }
            let fixed = dec.correct(&cw, Some(&pos)).expect("oracle decodes");
            let want: Vec<u8> = full.iter().map(|s| s[o]).collect();
            assert_eq!(&fixed[..], &want[..], "oracle, offset {o}");
        }
    }
}

#[test]
fn documented_comparison_vector() {
    // src/fec.rs, "Why in-crate": k = 4, m = 2, data column [11, 48, 85, 122].
    // reed-solomon-erasure 6.0.0 gives [26, 89], reed-solomon-simd 3.1.0
    // [142, 154] (measured once, outside this repository); this code and
    // the oracle give [236, 248].
    let rs = ReedSolomon::new(4, 2).unwrap();
    assert_eq!(rs.encode_symbols(&[11, 48, 85, 122]), vec![236, 248]);
    assert_eq!(oracle_parity(2, &[11, 48, 85, 122]), vec![236, 248]);
}

#[test]
fn more_erasures_than_parity_are_refused_like_the_oracle_cannot_decode() {
    let rs = ReedSolomon::new(4, 2).unwrap();
    assert!(rs.decoder(&[0, 1, 2]).is_err());
    assert!(rs.decoder(&[0, 0]).is_err());
    assert!(rs.decoder(&[6]).is_err());
}
