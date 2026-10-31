//! Harness: the HTTP side of `robodr-uplink` (`robodr_export::uplink::http`
//! and the `Retry-After` handling of `robodr_export::uplink`): what the
//! uplink parses from an ingest server (or from whoever answers in its
//! place) and from its own `--url` / `--spki-sha256` arguments.
//!
//! Input: `selector body`. `selector % 4` picks the parser:
//!
//! 0. `read_response` over the body as a whole **and** through a 1-byte
//!    `BufReader` (a server trickling the response); 1. the same with
//!    `selector / 4` interim `100 Continue` heads prepended;
//! 2. `Endpoint::parse` / `parse_with_path` on the body as a URL;
//! 3. `parse_pin` and `parse_retry_after` / `honoured_retry_after` /
//!    `retry_delay` on the body as text.
//!
//! Invariants beyond "no panic" (and no unbounded allocation):
//!
//! * a response parses the same whatever the read sizes; a parsed response
//!   has a final status (200..=599), a body of at most `MAX_RESPONSE_BODY`
//!   bytes, an empty body for 204 / 304, and `Retry-After` without CR / LF;
//! * an accepted URL: plain `http://` only to a loopback IP literal; host
//!   lower-case (names) or an IP literal; the `Host` header and the
//!   endpoint's display carry no white space or control characters and
//!   re-parse to the same endpoint; the request path is only
//!   `[A-Za-z0-9-._~/]` and ends with the ingest path;
//! * a pin is exactly the 64 hex digits given (case-insensitive);
//!   a `Retry-After` is honoured for at most `MAX_RETRY_AFTER`, and a retry
//!   never comes sooner than the honoured `Retry-After`.
//!
//! Std-only smoke test: `crates/robodr-export/tests/fuzz_smoke_uplink.rs`.
#![allow(dead_code)]

use robodr_export::uplink::http::{parse_pin, read_response, Endpoint, MAX_RESPONSE_BODY};
use robodr_export::uplink::wire::INGEST_PATH;
use robodr_export::uplink::{
    honoured_retry_after, parse_retry_after, retry_delay, RetryPolicy, MAX_RETRY_AFTER,
};
use std::io::{BufReader, Cursor};
use std::time::Duration;

pub fn run(data: &[u8]) {
    let Some((&sel, body)) = data.split_first() else {
        return;
    };
    match sel % 4 {
        0 => response(body),
        1 => {
            let mut b = Vec::new();
            for _ in 0..(sel / 4) % 12 {
                b.extend_from_slice(b"HTTP/1.1 100 Continue\r\n\r\n");
            }
            b.extend_from_slice(body);
            response(&b);
        }
        2 => url(body),
        _ => text(body),
    }
}

fn response(body: &[u8]) {
    let whole = read_response(&mut Cursor::new(body));
    let trickled = read_response(&mut BufReader::with_capacity(1, Cursor::new(body)));
    match (&whole, &trickled) {
        (Ok(a), Ok(b)) => assert_eq!(a, b, "read sizes changed the parsed response"),
        (Err(_), Err(_)) => {}
        _ => panic!("read sizes changed the outcome: {whole:?} vs {trickled:?}"),
    }
    if let Ok(r) = whole {
        assert!((200..=599).contains(&r.status), "status {}", r.status);
        assert!(r.body.len() <= MAX_RESPONSE_BODY);
        if r.status == 204 || r.status == 304 {
            assert!(r.body.is_empty());
        }
        if let Some(ra) = &r.retry_after {
            assert!(!ra.contains(['\r', '\n']));
        }
    }
}

fn url(body: &[u8]) {
    let Ok(s) = std::str::from_utf8(body) else {
        return;
    };
    let Ok(e) = Endpoint::parse(s) else {
        return;
    };
    let ip = e.host.parse::<std::net::IpAddr>().ok();
    if !e.tls {
        assert!(
            ip.is_some_and(|a| a.is_loopback()),
            "plain http accepted for {:?}",
            e.host
        );
    }
    if ip.is_none() {
        assert_eq!(e.host, e.host.to_ascii_lowercase());
    }
    assert!(e.port > 0);
    assert!(e.path.ends_with(INGEST_PATH), "path {:?}", e.path);
    assert!(e
        .path
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-._~/".contains(&b)));
    let host = e.host_header();
    assert!(!host.is_empty());
    assert!(
        host.bytes().all(|b| b.is_ascii_graphic()),
        "Host header {host:?}"
    );
    // The display is a URL the parser takes back to the same endpoint
    // (its path already carries the ingest suffix: parse it without one).
    let shown = e.to_string();
    let again = Endpoint::parse_with_path(&shown, "").expect("a displayed endpoint re-parses");
    assert_eq!(again, e, "display {shown:?} re-parses differently");
}

fn text(body: &[u8]) {
    let Ok(s) = std::str::from_utf8(body) else {
        return;
    };
    if let Ok(pin) = parse_pin(s) {
        let hex: String = pin.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, s.to_ascii_lowercase(), "pin is not the given digits");
    }
    if let Some(ra) = parse_retry_after(s) {
        let h = honoured_retry_after(ra);
        assert!(h <= MAX_RETRY_AFTER);
        assert!(h == ra || ra > MAX_RETRY_AFTER);
        let p = RetryPolicy {
            max_attempts: 6,
            base: Duration::from_millis(500),
            max: Duration::from_secs(300),
        };
        for retry in [0u32, 1, 7, 40, u32::MAX] {
            let d = retry_delay(&p, retry, Some(ra), u64::from(retry).wrapping_mul(0x9e37));
            assert!(d >= h, "retry {retry} sooner than Retry-After");
        }
    }
}

/// The committed seed corpus (`fuzz/corpus/uplink_http/`): one accepted
/// input per parser and response framing.
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    let s = |sel: u8, text: &str| {
        let mut b = vec![sel];
        b.extend_from_slice(text.as_bytes());
        b
    };
    vec![
        (
            "0-200-length",
            s(
                0,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 27\r\n\r\n{\"accepted\":3,\"rejected\":0}",
            ),
        ),
        (
            "0-202-chunked",
            s(
                0,
                "HTTP/1.1 202 Accepted\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: 1\r\n\r\n",
            ),
        ),
        (
            "0-429-retry-after",
            s(
                0,
                "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 120\r\nContent-Length: 0\r\n\r\n",
            ),
        ),
        ("0-204", s(0, "HTTP/1.1 204 No Content\r\n\r\n")),
        (
            "0-close-delimited",
            s(0, "HTTP/1.0 400 Bad Request\r\n\r\n{\"error\":\"schema\"}"),
        ),
        (
            "1-interim-503",
            s(
                1 + 4 * 2,
                "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 30\r\nContent-Length: 2\r\n\r\n{}",
            ),
        ),
        ("2-https-base", s(2, "https://soc.example.org/api/")),
        ("2-https-port", s(2, "https://Ingest.Example.ORG:8443")),
        ("2-https-v6", s(2, "https://[2001:db8::1]:9443/edr")),
        ("2-http-loopback", s(2, "http://127.0.0.1:8080/x")),
        (
            "3-pin",
            s(
                3,
                "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08",
            ),
        ),
        ("3-retry-after", s(3, "3600")),
        ("3-retry-after-huge", s(3, "99999999999999999999999")),
    ]
}
