//! Harness: the diode's Reed-Solomon erasure code (`robodr_diode::fec`),
//! differentially against an independent implementation of the same code
//! (the `reed-solomon` 0.2.1 crate: BCH-view RS over GF(2^8)/0x11D, generator
//! roots `α^0..α^(m-1)`; see `crates/robodr-diode/src/fec.rs`, "Why
//! in-crate").
//!
//! Input: `k_byte m_byte len_byte erasure_bytes[8] data...`:
//! `k = 1 + k_byte % 48`, `m = 1 + m_byte % min(32, 255 - k)`,
//! `len = len_byte % 65` (parity length); each data shard takes the next
//! `len` input bytes, and is then truncated to `data_byte % (len + 1)` bytes
//! when the shard-length byte of its slot says so (short shards count as
//! zero-padded). The 64-bit erasure mask (bit `t % 64`) picks erased shards
//! among `k + m`, capped at `m`.
//!
//! Invariants beyond "no panic":
//!
//! * the block encoder's parity equals the oracle's ECC at every byte offset
//!   (data shards zero-padded) and `encode_symbols` agrees with it;
//! * erasing up to `m` shards and reconstructing gives the original shards
//!   back, and the oracle's erasure decoder recovers the same codewords;
//! * more erasures than parity, a repeated or out-of-range position, and
//!   mis-shaped blocks are errors, never panics.
//!
//! Shared via `#[path]` with `crates/robodr-diode/tests/fuzz_smoke.rs`.
#![allow(dead_code)]

use robodr_diode::fec::{FecError, ReedSolomon, MAX_SHARDS};

pub fn run(data: &[u8]) {
    if data.len() < 11 {
        return;
    }
    let k = 1 + usize::from(data[0]) % 48;
    let m = 1 + usize::from(data[1]) % 32.min(MAX_SHARDS - k);
    let len = usize::from(data[2]) % 65;
    let mask = u64::from_le_bytes([
        data[3], data[4], data[5], data[6], data[7], data[8], data[9], data[10],
    ]);
    let mut rest = &data[11..];
    let mut shards: Vec<Vec<u8>> = Vec::with_capacity(k);
    for _ in 0..k {
        let mut s = vec![0u8; len];
        let n = len.min(rest.len());
        s[..n].copy_from_slice(&rest[..n]);
        rest = &rest[n..];
        // A trailing length byte, if any, shortens the shard (zero padding
        // is implicit for the encoder).
        if let Some((&b, tail)) = rest.split_first() {
            rest = tail;
            if b & 0x80 != 0 {
                s.truncate(usize::from(b & 0x7f) % (len + 1));
            }
        }
        shards.push(s);
    }
    let rs = match ReedSolomon::new(k, m) {
        Ok(rs) => rs,
        Err(e) => panic!("valid parameters k={k} m={m} refused: {e}"),
    };
    let refs: Vec<&[u8]> = shards.iter().map(Vec::as_slice).collect();
    let parity = rs.encode(&refs, len).expect("shards fit the parity length");
    assert_eq!(parity.len(), m);
    assert!(parity.iter().all(|p| p.len() == len));

    // 1. Parity equals the oracle's ECC at every offset.
    let enc = reed_solomon::Encoder::new(m);
    for o in 0..len {
        let column: Vec<u8> = shards
            .iter()
            .map(|s| s.get(o).copied().unwrap_or(0))
            .collect();
        let want = enc.encode(&column);
        let got: Vec<u8> = parity.iter().map(|p| p[o]).collect();
        assert_eq!(&got[..], want.ecc(), "k={k} m={m} offset {o}");
        assert_eq!(rs.encode_symbols(&column), got);
    }

    // 2. Erase (at most m) and rebuild; the oracle agrees.
    let n = k + m;
    let full: Vec<Vec<u8>> = shards
        .iter()
        .map(|s| {
            let mut s = s.clone();
            s.resize(len, 0);
            s
        })
        .chain(parity.iter().cloned())
        .collect();
    let erased: Vec<usize> = (0..n)
        .filter(|t| mask >> (t % 64) & 1 == 1)
        .take(m)
        .collect();
    let mut held: Vec<Option<Vec<u8>>> = full.iter().cloned().map(Some).collect();
    for &p in &erased {
        held[p] = None;
    }
    rs.reconstruct(&mut held).expect("at most m erasures");
    for (t, s) in held.iter().enumerate() {
        assert_eq!(s.as_ref(), Some(&full[t]), "shard {t}, erased {erased:?}");
    }
    if !erased.is_empty() {
        let dec = reed_solomon::Decoder::new(m);
        let pos: Vec<u8> = erased.iter().map(|&p| p as u8).collect();
        for o in 0..len {
            let mut cw: Vec<u8> = full.iter().map(|s| s[o]).collect();
            for &p in &erased {
                cw[p] ^= 0x5a;
            }
            let fixed = dec
                .correct(&cw, Some(&pos))
                .expect("oracle decodes <= m erasures");
            let want: Vec<u8> = full.iter().map(|s| s[o]).collect();
            assert_eq!(&fixed[..], &want[..], "oracle offset {o}");
        }
    }

    // 3. Refusals, never panics.
    let too_many: Vec<usize> = (0..=m).collect(); // n = k + m > m
    assert!(matches!(
        rs.decoder(&too_many),
        Err(FecError::TooManyErasures { .. })
    ));
    assert!(rs.decoder(&[n]).is_err());
    assert!(rs.decoder(&[0, 0]).is_err());
    let d = rs.decoder(&erased).expect("at most m distinct erasures");
    // Mis-shaped blocks: no known block although k >= 1 are needed.
    let mut o = vec![0u8; len];
    let mut outs: Vec<&mut [u8]> = vec![o.as_mut_slice()];
    assert!(d.reconstruct(&[], &mut outs).is_err());
}
