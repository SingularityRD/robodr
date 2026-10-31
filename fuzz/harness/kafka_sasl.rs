//! Harness: SASL/SCRAM of the Kafka producer (`robodr_export::kafka::sasl`):
//! what a broker (or whoever answers in its place, the link may be
//! plaintext) sends during authentication.
//!
//! Input: `selector body`. `selector % 4` picks the parser:
//!
//! 0. base64 (`b64_decode` of the body as text, `b64_encode` of the raw
//!    body);
//! 1. `ScramClient::client_final` on the body as `server-first-message`
//!    (SCRAM-SHA-256 when `selector / 4` is even, else SCRAM-SHA-512);
//! 2. `ScramClient::verify_final` on the body as `server-final-message`,
//!    for a client that completed the RFC 7677 exchange;
//! 3. SaslHandshake v1 / SaslAuthenticate v0-1 responses
//!    (`selector / 4` picks which and the version).
//!
//! Invariants beyond "no panic":
//!
//! * base64: `decode(encode(x)) == x`; whatever decodes re-encodes to a
//!   string of the same length (only the padding bits may differ);
//! * `client_final` accepts only a server nonce that strictly extends the
//!   client's, printable without `,`, a non-empty salt and an iteration
//!   count in `MIN_ITERATIONS..=MAX_ITERATIONS` (no downgrade, no CPU
//!   exhaustion), and answers `c=biws,r=<that nonce>,p=<base64 proof of
//!   the hash length>`; a client given no `client_final` verifies nothing;
//! * `verify_final` succeeds only for the server signature of the exchange
//!   (RFC 7677's `v=` value): any other first attribute is refused, `e=` is
//!   always an error;
//! * responses: decode -> encode (the test broker's encoders) -> decode is
//!   the identity.
//!
//! Iteration counts above 8192 that the client would accept are skipped
//! (they are correct, only slow: up to 100 000 PBKDF2 rounds per input).
//!
//! Std-only smoke test: `crates/robodr-export/tests/fuzz_smoke_sasl.rs`.
#![allow(dead_code)]

use robodr_export::kafka::sasl::{
    b64_decode, b64_encode, decode_authenticate_response, decode_handshake_response,
    encode_authenticate_response, encode_handshake_response, Mechanism, ScramClient,
    MAX_ITERATIONS, MIN_ITERATIONS,
};

/// RFC 7677 §3.
pub const RFC_NONCE: &str = "rOprNGfwEbeRWgbNEkqO";
pub const RFC_SERVER_FIRST: &str =
    "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
pub const RFC_SERVER_SIGNATURE: &str = "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

/// Above this the exchange is skipped (slow, not wrong).
const FUZZ_MAX_ITERATIONS: u32 = 8192;

pub fn run(data: &[u8]) {
    let Some((&sel, body)) = data.split_first() else {
        return;
    };
    let s = sel / 4;
    match sel % 4 {
        0 => base64(body),
        1 => {
            let mech = if s.is_multiple_of(2) {
                Mechanism::ScramSha256
            } else {
                Mechanism::ScramSha512
            };
            if let Ok(t) = std::str::from_utf8(body) {
                server_first(mech, t);
            }
        }
        2 => {
            if let Ok(t) = std::str::from_utf8(body) {
                server_final(t);
            }
        }
        _ => responses(s, body),
    }
}

fn base64(body: &[u8]) {
    let enc = b64_encode(body);
    assert_eq!(enc.len(), body.len().div_ceil(3) * 4);
    assert_eq!(b64_decode(&enc).as_deref(), Some(body), "base64 round trip");
    if let Ok(t) = std::str::from_utf8(body) {
        if let Some(raw) = b64_decode(t) {
            assert_eq!(b64_encode(&raw).len(), t.len(), "{t:?}");
            assert!(raw.len() <= t.len() / 4 * 3);
        }
    }
}

/// The attributes `client_final` reads (`r`, `s`, `i` in this order).
fn attrs(t: &str) -> Option<(&str, &str, &str)> {
    let mut it = t.split(',');
    let r = it.next()?.strip_prefix("r=")?;
    let s = it.next()?.strip_prefix("s=")?;
    let i = it.next()?.strip_prefix("i=")?;
    Some((r, s, i))
}

fn server_first(mech: Mechanism, t: &str) {
    if let Some((_, _, i)) = attrs(t) {
        if let Ok(n) = i.parse::<u32>() {
            if n > FUZZ_MAX_ITERATIONS && n <= MAX_ITERATIONS {
                return;
            }
        }
    }
    let mut c = ScramClient::with_nonce(mech, "robodr", RFC_NONCE);
    // Nothing verifies before client-final.
    assert!(c
        .verify_final(&format!("v={RFC_SERVER_SIGNATURE}"))
        .is_err());
    let Ok(out) = c.client_final(t, "pencil") else {
        return;
    };
    let (r, salt, i) = attrs(t).expect("accepted server-first has r, s, i");
    assert!(r.starts_with(RFC_NONCE) && r.len() > RFC_NONCE.len());
    assert!(r.bytes().all(|b| (0x21..0x7f).contains(&b) && b != b','));
    assert!(!b64_decode(salt).expect("accepted salt decodes").is_empty());
    let n: u32 = i.parse().expect("accepted iteration count");
    assert!((MIN_ITERATIONS..=MAX_ITERATIONS).contains(&n));
    let proof = out
        .strip_prefix(&format!("c=biws,r={r},p="))
        .expect("client-final names the server nonce");
    let want = match mech {
        Mechanism::ScramSha256 => 32,
        Mechanism::ScramSha512 => 64,
    };
    assert_eq!(b64_decode(proof).map(|p| p.len()), Some(want));
    // The RFC's signature is for user "user": it never verifies here.
    assert!(c
        .verify_final(&format!("v={RFC_SERVER_SIGNATURE}"))
        .is_err());
}

thread_local! {
    /// A client after the RFC 7677 client-final (4096 PBKDF2 rounds: once).
    static RFC_CLIENT: ScramClient = {
        let mut c = ScramClient::with_nonce(Mechanism::ScramSha256, "user", RFC_NONCE);
        c.client_final(RFC_SERVER_FIRST, "pencil").expect("RFC 7677 server-first");
        c
    };
}

fn server_final(t: &str) {
    let ok = RFC_CLIENT.with(|c| c.verify_final(t).is_ok());
    if t.starts_with("e=") {
        assert!(!ok, "a server error verified");
    }
    if ok {
        let v = t.split(',').next().and_then(|a| a.strip_prefix("v="));
        assert_eq!(
            v.and_then(b64_decode),
            b64_decode(RFC_SERVER_SIGNATURE),
            "{t:?} verified"
        );
    }
}

fn responses(s: u8, body: &[u8]) {
    if s.is_multiple_of(2) {
        if let Ok((code, mechs)) = decode_handshake_response(body) {
            let refs: Vec<&str> = mechs.iter().map(String::as_str).collect();
            let again = encode_handshake_response(code, &refs);
            assert_eq!(
                decode_handshake_response(&again).ok(),
                Some((code, mechs.clone()))
            );
        }
    } else {
        let v = i16::from((s / 2) % 2);
        if let Ok(r) = decode_authenticate_response(v, body) {
            let again = encode_authenticate_response(v, &r);
            assert_eq!(decode_authenticate_response(v, &again).ok(), Some(r));
        }
    }
}

/// The committed seed corpus (`fuzz/corpus/kafka_sasl/`): one accepted
/// input per entry point (RFC 7677's exchange for the SCRAM ones).
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    use robodr_export::kafka::sasl::AuthenticateResponse;
    let s = |sel: u8, body: &[u8]| {
        let mut b = vec![sel];
        b.extend_from_slice(body);
        b
    };
    let auth = AuthenticateResponse {
        error_code: 0,
        error_message: None,
        auth_bytes: format!("v={RFC_SERVER_SIGNATURE}").into_bytes(),
        session_lifetime_ms: 3_600_000,
    };
    vec![
        ("0-base64", s(0, b"Zm9vYmFy")),
        ("0-base64-padded", s(0, b"W22ZaJ0SNY7soEsUEjb6gQ==")),
        ("1-server-first-256", s(1, RFC_SERVER_FIRST.as_bytes())),
        ("1-server-first-512", s(5, RFC_SERVER_FIRST.as_bytes())),
        (
            "2-server-final",
            s(2, format!("v={RFC_SERVER_SIGNATURE}").as_bytes()),
        ),
        ("2-server-error", s(2, b"e=invalid-proof")),
        (
            "3-handshake",
            s(
                3,
                &encode_handshake_response(0, &["SCRAM-SHA-256", "SCRAM-SHA-512"]),
            ),
        ),
        (
            "3-authenticate-v0",
            s(3 + 4, &encode_authenticate_response(0, &auth)),
        ),
        (
            "3-authenticate-v1",
            s(3 + 12, &encode_authenticate_response(1, &auth)),
        ),
    ]
}
