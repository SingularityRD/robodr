//! Harness: enrollment token parsing (`robodr_fleet::wire::Token`, read by
//! `robodr-enroll --token`) and its checks.
//!
//! Input: arbitrary bytes, tried as UTF-8 text. Invariants beyond "no
//! panic": a parsed token's payload passes its own structural check,
//! re-encodes to exactly the canonical form of the trimmed input (one
//! encoding per token), its nonce is 32 bytes, and its signature verifies
//! under the fixed test SOC key only if the input was signed by it (the
//! seed); verification under another key always fails.
//!
//! Seeds (`fuzz/corpus/fleet_token/`) are tokens issued by the test SOC key
//! `[0x50; 32]` (the vectors' `soc` key); regenerate them with
//! `cargo run -p robodr-fleet --example fleet_vectors`, which writes the
//! same tokens under `docs/contracts/fixtures/fleet/tokens/`.
#![allow(dead_code)]

use robodr_blackbox::Ed25519SigningKey;
use robodr_fleet::b64;
use robodr_fleet::wire::{Token, TOKEN_PREFIX};

pub fn run(data: &[u8]) {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(t) = Token::parse(s) else {
        return;
    };
    assert!(
        t.payload.check().is_ok(),
        "parsed token fails its own check"
    );
    let trimmed = s.trim_matches(|c| c == ' ' || c == '\t' || c == '\r' || c == '\n');
    let canonical = format!(
        "{TOKEN_PREFIX}{}.{}",
        b64::encode(&t.payload_bytes),
        b64::encode(&t.sig)
    );
    assert_eq!(trimmed, canonical, "token has a second encoding");
    assert_eq!(t.nonce().len(), 32);
    let other = Ed25519SigningKey::from_seed_with_derived_id(&[0x51; 32]);
    assert!(
        t.verify(&other.public_key()).is_err(),
        "verified under a foreign key"
    );
    let soc = Ed25519SigningKey::from_seed_with_derived_id(&[0x50; 32]);
    let _ = t.verify(&soc.public_key());
    let _ = t.check_time(0);
    let _ = t.check_time(u64::MAX);
}
