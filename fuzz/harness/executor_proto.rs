//! Harness: the agentd <-> executor protocol (`robodr_executor::proto`,
//! `robodr-executor/1`): what the executor reads from its unix socket
//! (and agentd from the executor's replies).
//!
//! Input: `selector body`. `selector % 4` picks the entry point:
//!
//! 0. `open` on the body as one envelope line, as a request and as the
//!    reply to a fixed nonce, then the `NonceCache` on what was accepted;
//! 1. the body as a message (`Msg` JSON): sealed under the harness key,
//!    then opened (the MAC covers exactly the bytes that are parsed);
//! 2. `read_line` over the body, whole and through a 1-byte `BufReader`;
//! 3. `Key::parse` on the body as key-file text.
//!
//! Invariants beyond "no panic":
//!
//! * a line `open` accepts names a 32-hex-digit nonce; accepted as a reply,
//!   it answers exactly the expected nonce; a request nonce is accepted
//!   once by the `NonceCache`, then refused as `Replayed`;
//! * every message that seals opens to the same message (numbers compared
//!   to the precision JSON keeps), never under another key (`BadMac`),
//!   never outside the timestamp window (`Stale`), never as the reply to
//!   another request (`WrongReply`); a sealed line has no newline but the
//!   last byte and stays under `MAX_LINE`;
//! * `read_line` gives the same result whatever the read sizes, at most
//!   `MAX_LINE` bytes and never a newline.
//!
//! Std-only smoke test: `crates/robodr-executor/tests/fuzz_smoke.rs`.
#![allow(dead_code)]

use robodr_executor::proto::{
    open, read_line, seal, Key, Msg, NonceCache, Reject, MAX_LINE, MAX_SKEW_MS,
};
use std::io::{BufReader, Cursor};

/// The harness clock (Unix ms), fixed so seeds stay inside the window.
pub const NOW_MS: u64 = 1_760_000_000_000;
pub const KEY: [u8; 32] = [0x42; 32];
pub const NONCE: &str = "0123456789abcdef0123456789abcdef";
pub const REPLY_TO: &str = "fedcba9876543210fedcba9876543210";

pub fn run(data: &[u8]) {
    let Some((&sel, body)) = data.split_first() else {
        return;
    };
    match sel % 4 {
        0 => envelope(body),
        1 => message(body),
        2 => lines(body),
        _ => {
            if let Ok(t) = std::str::from_utf8(body) {
                let _ = Key::parse(t);
            }
        }
    }
}

fn hex32(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn envelope(line: &[u8]) {
    let key = Key::from_bytes(KEY);
    if let Ok(r) = open(&key, line, NOW_MS, None) {
        assert!(hex32(&r.nonce), "nonce {:?}", r.nonce);
        assert!(r.reply_to.is_empty() || hex32(&r.reply_to));
        let mut cache = NonceCache::default();
        assert_eq!(cache.check(&r.nonce, 1), Ok(()));
        assert_eq!(cache.check(&r.nonce, 2), Err(Reject::Replayed));
    }
    if let Ok(r) = open(&key, line, NOW_MS, Some(REPLY_TO)) {
        assert_eq!(r.reply_to, REPLY_TO);
    }
}

fn message(body: &[u8]) {
    let Ok(msg) = serde_json::from_slice::<Msg>(body) else {
        return;
    };
    let key = Key::from_bytes(KEY);
    let Ok(line) = seal(&key, NOW_MS, NONCE, REPLY_TO, &msg) else {
        return; // too large
    };
    assert!(line.len() <= MAX_LINE);
    let (last, rest) = line.split_last().expect("sealed line");
    assert_eq!(*last, b'\n');
    assert!(!rest.contains(&b'\n'), "newline inside a sealed line");
    let r = open(&key, rest, NOW_MS, Some(REPLY_TO)).expect("a sealed message opens");
    assert_eq!(r.nonce, NONCE);
    assert!(
        same(
            &serde_json::to_value(&r.msg).expect("value"),
            &serde_json::to_value(&msg).expect("value")
        ),
        "message changed in transit: {msg:?} -> {:?}",
        r.msg
    );
    let other = Key::from_bytes([0x43; 32]);
    assert_eq!(open(&other, rest, NOW_MS, None), Err(Reject::BadMac));
    assert_eq!(
        open(&key, rest, NOW_MS + MAX_SKEW_MS + 1, None),
        Err(Reject::Stale)
    );
    assert_eq!(
        open(&key, rest, NOW_MS, Some(NONCE)),
        Err(Reject::WrongReply)
    );
}

/// JSON equality with numbers compared to f64 precision (serde_json's
/// default float parsing may be one ULP off after a round trip).
fn same(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    use serde_json::Value as V;
    match (a, b) {
        (V::Number(x), V::Number(y)) => match (x.as_f64(), y.as_f64()) {
            (Some(p), Some(q)) if x.is_f64() || y.is_f64() => {
                p == q || (p - q).abs() <= p.abs().max(q.abs()) * 4.0 * f64::EPSILON
            }
            _ => x == y,
        },
        (V::Array(x), V::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| same(p, q))
        }
        (V::Object(x), V::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| same(v, w)))
        }
        _ => a == b,
    }
}

/// The committed seed corpus (`fuzz/corpus/executor_proto/`): a request
/// and a reply line under the harness key, messages of every direction,
/// a multi-line stream and a key file.
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    let key = Key::from_bytes(KEY);
    let line = |msg: &Msg, reply_to: &str| {
        let mut b = vec![0u8];
        let l = seal(&key, NOW_MS, NONCE, reply_to, msg).expect("seed seals");
        b.extend_from_slice(l.strip_suffix(b"\n").unwrap_or(&l));
        b
    };
    let msg = |sel: u8, text: &str| {
        let mut b = vec![sel];
        b.extend_from_slice(text.as_bytes());
        b
    };
    let safety = r#"{"op":"safety","state":"idle","age_ms":120}"#;
    let pong = r#"{"op":"pong","active":2,"boot_id":"b0","operator_disabled":false,"journal_reset":false,"held":0}"#;
    vec![
        ("0-request", line(&Msg::Ping, "")),
        (
            "0-reply",
            line(
                &serde_json::from_str(safety).expect("safety message"),
                REPLY_TO,
            ),
        ),
        ("1-ping", msg(1, r#"{"op":"ping"}"#)),
        ("1-safety", msg(1, safety)),
        ("1-pong", msg(1, pong)),
        (
            "1-revert",
            msg(1, r#"{"op":"revert","id":"act-1","reason":"operator"}"#),
        ),
        ("1-events", msg(1, r#"{"op":"events","since":7}"#)),
        (
            "1-error",
            msg(1, r#"{"op":"error","code":"busy","message":"try later"}"#),
        ),
        ("2-lines", msg(2, "{\"a\":1}\n{\"b\":2}\npartial")),
        ("3-key", msg(3, &"42".repeat(32))),
    ]
}

fn lines(body: &[u8]) {
    let whole = read_line(&mut Cursor::new(body));
    let trickled = read_line(&mut BufReader::with_capacity(1, Cursor::new(body)));
    match (&whole, &trickled) {
        (Ok(a), Ok(b)) => assert_eq!(a, b, "read sizes changed the line"),
        (Err(_), Err(_)) => {}
        _ => panic!("read sizes changed the outcome: {whole:?} vs {trickled:?}"),
    }
    if let Ok(l) = whole {
        assert!(l.len() <= MAX_LINE);
        assert!(!l.contains(&b'\n'));
    }
}
