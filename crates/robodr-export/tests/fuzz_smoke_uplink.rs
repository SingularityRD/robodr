//! Std-only smoke run of the `uplink_http` libFuzzer target
//! (`fuzz/fuzz_targets/uplink_http.rs`): the same harness code
//! (`fuzz/harness/uplink_http.rs`, included by path) driven by the
//! deterministic mutator in `fuzz/harness/smoke.rs` over the committed seed
//! corpus (`fuzz/corpus/uplink_http/`). The seeds are written by
//! `regenerate_seeds` (`--ignored`); `seeds_are_current` fails when the
//! committed files differ, `seeds_take_the_success_paths` checks they still
//! reach the accepting paths. See `fuzz/README.md`.

#[path = "../../../fuzz/harness/smoke.rs"]
mod smoke;
#[path = "../../../fuzz/harness/uplink_http.rs"]
mod uplink_http;

use robodr_export::uplink::http::{parse_pin, read_response, Endpoint};
use robodr_export::uplink::parse_retry_after;

const DIR: &str = env!("CARGO_MANIFEST_DIR");
const TARGET: &str = "uplink_http";

#[test]
#[ignore = "writes fuzz/corpus/uplink_http; run after a format change"]
fn regenerate_seeds() {
    let dir = smoke::corpus_dir(DIR, TARGET);
    std::fs::create_dir_all(&dir).unwrap();
    for (name, bytes) in uplink_http::seeds() {
        std::fs::write(dir.join(name), bytes).unwrap();
    }
}

#[test]
fn seeds_are_current() {
    for (name, bytes) in uplink_http::seeds() {
        let p = smoke::corpus_dir(DIR, TARGET).join(name);
        let on_disk = std::fs::read(&p)
            .unwrap_or_else(|e| panic!("{}: {e} (run regenerate_seeds)", p.display()));
        assert!(
            on_disk == bytes,
            "{} is stale: run regenerate_seeds",
            p.display()
        );
    }
}

#[test]
fn seeds_take_the_success_paths() {
    let mut kinds = std::collections::BTreeSet::new();
    for (name, seed) in uplink_http::seeds() {
        let (&sel, body) = seed.split_first().unwrap();
        kinds.insert(sel % 4);
        let text = std::str::from_utf8(body).unwrap();
        let ok = match sel % 4 {
            // Selector 1: the harness prepends interim heads to the same.
            0 | 1 => read_response(&mut std::io::Cursor::new(body)).is_ok(),
            2 => Endpoint::parse(text).is_ok(),
            _ => parse_pin(text).is_ok() || parse_retry_after(text).is_some(),
        };
        assert!(ok, "seed {name} is refused");
    }
    assert_eq!(kinds.len(), 4, "seeds cover every entry point");
}

/// The harness's own invariants hold on hand-picked hostile responses
/// (each one a parser branch the mutator reaches only by luck).
#[test]
fn uplink_http_hostile_inputs() {
    for r in [
        &b"\x00HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!"[..],
        b"\x00HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
        b"\x00HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n0\r\n\r\n",
        b"\x00HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nfffffffff\r\n",
        b"\x00HTTP/1.1 101 Switching Protocols\r\n\r\n",
        b"\x00HTTP/1.1 200 OK\r\n folded: x\r\n\r\n",
        b"\x01HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        b"\xfdHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        b"\x02http://localhost:8080",
        b"\x02http://10.0.0.1",
        b"\x02https://user@host",
        b"\x02https://host:0",
        b"\x02https://host:080",
        b"\x02https://[::1",
        b"\x02HTTPS://[::1]:443/A/./b",
        b"\x02https://h/\xc3\xa9",
        b"\x03 120 ",
        b"\x03-1",
    ] {
        uplink_http::run(r);
    }
}

#[test]
fn uplink_http_smoke() {
    let seeds = smoke::corpus(DIR, TARGET);
    smoke::run(TARGET, &seeds, 0x7570_6c6b, &uplink_http::run);
}
