//! Harness: key wraps and sealed chunks (`robodr_seal::wrap`,
//! `robodr_seal::chunk`).
//!
//! Input: a selector byte, then bytes. Invariants beyond "no panic":
//!
//! * `wrap::parse` accepts only the two exact lengths of its algorithms;
//! * a wrap that unwraps for the harness X25519 or P-256 key and unit
//!   `ugv-07` never unwraps for unit `ugv-08`, another RPK digest, or as a
//!   volume key (context binding), and re-wrapping the key gives a wrap
//!   that unwraps to the same key;
//! * a chunk that opens with the harness content key at a place is
//!   exactly what sealing that plaintext there produces (synthetic nonce:
//!   one ciphertext per plaintext and place), and does not open at any
//!   other place.
//!
//! Shared via `#[path]` with `crates/robodr-seal/tests/fuzz_smoke.rs`.
#![allow(dead_code)]

use robodr_seal::chunk::{open_chunk, seal_chunk, ChunkPlace, ContentKey};
use robodr_seal::wrap::{self, P256Secret, Unwrapper, WrapContext, X25519Secret};

pub const SEAL_ID: [u8; 32] = [0x5e; 32];

pub fn x25519() -> X25519Secret {
    X25519Secret::from_bytes(&[3u8; 32]).expect("32 bytes")
}

pub fn p256() -> P256Secret {
    P256Secret(p256::SecretKey::from_slice(&[4u8; 32]).expect("scalar"))
}

pub fn ck() -> ContentKey {
    ContentKey::from_bytes(&[6u8; 32]).expect("32 bytes")
}

fn unit_ctx(unit: &str, d: &str) -> WrapContext {
    WrapContext::Unit {
        unit: unit.into(),
        rpk_digest: d.into(),
    }
}

pub fn run(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    if sel & 1 == 0 {
        wraps(rest);
    } else {
        chunks(sel, rest);
    }
}

fn wraps(w: &[u8]) {
    if wrap::parse(w).is_ok() {
        assert!(w.len() == wrap::X25519_WRAP_LEN || w.len() == wrap::P256_WRAP_LEN);
    }
    let digest = "ab".repeat(32);
    let x = x25519();
    let p = p256();
    for by in [&x as &dyn Unwrapper, &p as &dyn Unwrapper] {
        if let Ok(k) = wrap::unwrap(by, w, &unit_ctx("ugv-07", &digest)) {
            assert!(wrap::unwrap(by, w, &unit_ctx("ugv-08", &digest)).is_err());
            assert!(wrap::unwrap(by, w, &unit_ctx("ugv-07", &"cd".repeat(32))).is_err());
            assert!(wrap::unwrap(
                by,
                w,
                &WrapContext::Volume {
                    unit: "ugv-07".into()
                }
            )
            .is_err());
            let again =
                wrap::wrap(&by.recipient(), &k, &unit_ctx("ugv-07", &digest)).expect("wraps");
            assert_eq!(
                *wrap::unwrap(by, &again, &unit_ctx("ugv-07", &digest)).expect("unwraps"),
                *k
            );
        }
    }
}

fn chunks(sel: u8, sealed: &[u8]) {
    let at = ChunkPlace {
        file_index: u32::from(sel >> 4),
        pos: u32::from((sel >> 1) & 3),
        count: 4,
    };
    let key = ck();
    if let Ok(pt) = open_chunk(&key, &SEAL_ID, at, sealed) {
        assert_eq!(seal_chunk(&key, &SEAL_ID, at, &pt).expect("seals"), sealed);
        let elsewhere = ChunkPlace {
            pos: (at.pos + 1) % 4,
            ..at
        };
        assert!(open_chunk(&key, &SEAL_ID, elsewhere, sealed).is_err());
        assert!(open_chunk(&key, &[0u8; 32], at, sealed).is_err());
    }
}

/// Seeds: a wrap to each harness key for ugv-07, and a sealed chunk at a
/// place. (Wraps use a fresh ephemeral key: these seeds are written once
/// by `regenerate_seeds`, not compared byte for byte.)
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    let digest = "ab".repeat(32);
    let wx = wrap::wrap(
        &x25519().recipient(),
        &[1u8; 32],
        &unit_ctx("ugv-07", &digest),
    )
    .expect("wraps");
    let wp = wrap::wrap(
        &p256().recipient(),
        &[2u8; 32],
        &unit_ctx("ugv-07", &digest),
    )
    .expect("wraps");
    let sel = (1u8 << 4) | (2 << 1) | 1;
    let at = ChunkPlace {
        file_index: 1,
        pos: 2,
        count: 4,
    };
    let c = seal_chunk(&ck(), &SEAL_ID, at, b"model weights, piece three").expect("seals");
    vec![
        ("seed-wrap-x25519.bin", [vec![0u8], wx].concat()),
        ("seed-wrap-p256.bin", [vec![0u8], wp].concat()),
        ("seed-chunk.bin", [vec![sel], c].concat()),
    ]
}
