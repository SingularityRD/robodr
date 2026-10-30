//! The depot ↔ unit LAN protocol (Sprint 14a, `docs/SECURE-DELIVERY.md`
//! §4.1 step 6), as pure encoders and bounded parsers; the TLS (mutual,
//! the unit's key in its TPM) and the sockets are `robodr-depot`'s and
//! `robodr-deliverd`'s.
//!
//! One request per TLS connection, an HTTP/1.1 subset (so the exchange can
//! be read with ordinary tools), nothing else accepted:
//!
//! ```text
//! GET /v1/pack HTTP/1.1          → 200, body: a pack stream (below)
//! POST /v1/report HTTP/1.1       → 200, body: {"lease": <robodr-lease/1 or null>}
//!   Content-Length: N              (body: the unit's signed report)
//! ```
//!
//! The request names no unit: the depot serves the unit whose enrolled
//! identity key presented the client certificate, and nothing else (a
//! unit cannot ask for another unit's pack). Header blocks are at most
//! [`MAX_HEAD`] bytes, request bodies at most [`MAX_REQUEST_BODY`]; any
//! other method, path, version, header or encoding (chunked, a second
//! `Content-Length`) is refused.
//!
//! **Pack stream** (`robodr-pack-stream/1`): one line with the canonical
//! JSON [`PackListing`] (every file of the unit's media pack, sorted, with
//! size and SHA-256), then the files' bytes concatenated in listing order.
//! The listing is not trusted for anything but sizes: the unit writes the
//! files bounded by the listed sizes, checks each hash, and then imports
//! the result as a media pack, which verifies every signature and hash
//! again (`robodr-deliverd`).

use crate::common::{invalid, is_hex64, is_label, parse_canonical, strictly_sorted, Refusal};
use serde::{Deserialize, Serialize};

pub const PACK_STREAM_FORMAT: &str = "robodr-pack-stream/1";
/// Largest header block (request line + headers + blank line).
pub const MAX_HEAD: usize = 4096;
/// Largest request body (a signed report).
pub const MAX_REQUEST_BODY: usize = 256 * 1024;
/// Largest listing line.
pub const MAX_LISTING: usize = 4 * 1024 * 1024;
/// Most files in a pack stream.
pub const MAX_PACK_FILES: usize = 65536;
/// Largest pack (sum of sizes): 64 GiB.
pub const MAX_PACK_BYTES: u64 = 64 << 30;

/// The two requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    Pack,
    /// With the body length.
    Report(usize),
}

/// One file of a pack stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

/// The first line of a pack stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackListing {
    pub format: String,
    /// Sorted by path.
    pub files: Vec<StreamFile>,
}

/// Whether `path` is a file a media pack may hold: the fixed top-level
/// documents, or `bundles/<label>/<bundle file>` by the bundle grammar.
pub fn is_pack_path(path: &str) -> bool {
    match path {
        "trust.json"
        | "trust.json.sig"
        | "deployment.json"
        | "deployment.json.sig"
        | "lease.json" => true,
        _ => {
            let Some(rest) = path.strip_prefix("bundles/") else {
                return false;
            };
            let Some((label, file)) = rest.split_once('/') else {
                return false;
            };
            is_label(label)
                && (file == crate::bundle::BUNDLE_FILE
                    || file == crate::bundle::BUNDLE_SIG_FILE
                    || crate::bundle::classify(file).is_some())
        }
    }
}

impl PackListing {
    pub fn validate(&self) -> Result<u64, Refusal> {
        if self.format != PACK_STREAM_FORMAT {
            return Err(invalid("pack stream: unsupported format"));
        }
        if self.files.len() > MAX_PACK_FILES {
            return Err(invalid("pack stream: too many files"));
        }
        strictly_sorted(&self.files, |f| f.path.clone(), "pack stream files")?;
        let mut total: u64 = 0;
        for f in &self.files {
            if !is_pack_path(&f.path) || !is_hex64(&f.sha256) {
                return Err(invalid(format!(
                    "pack stream: path {:?} is not a media pack file",
                    crate::common::trunc(&f.path)
                )));
            }
            total = total
                .checked_add(f.size)
                .filter(|t| *t <= MAX_PACK_BYTES)
                .ok_or_else(|| invalid("pack stream: too large"))?;
        }
        for need in [
            "deployment.json",
            "deployment.json.sig",
            "trust.json",
            "trust.json.sig",
        ] {
            if self
                .files
                .binary_search_by(|f| f.path.as_str().cmp(need))
                .is_err()
            {
                return Err(invalid(format!("pack stream: no {need}")));
            }
        }
        Ok(total)
    }
}

/// Parse and validate a listing line (without its newline); the total size.
pub fn parse_listing(line: &[u8]) -> Result<(PackListing, u64), Refusal> {
    let l: PackListing = parse_canonical(line, MAX_LISTING, "pack stream listing")?;
    let total = l.validate()?;
    Ok((l, total))
}

/// The end of the header block in `buf` (index after `\r\n\r\n`).
pub fn head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn lines(head: &[u8]) -> Result<Vec<&str>, Refusal> {
    if head.len() > MAX_HEAD || !head.ends_with(b"\r\n\r\n") {
        return Err(invalid("header block too large or unterminated"));
    }
    let t =
        std::str::from_utf8(&head[..head.len() - 4]).map_err(|_| invalid("header not UTF-8"))?;
    if t.bytes()
        .any(|b| b != b'\r' && b != b'\n' && !(0x20..0x7f).contains(&b))
    {
        return Err(invalid("header: control characters"));
    }
    let v: Vec<&str> = t.split("\r\n").collect();
    if v.iter().any(|l| l.contains('\r') || l.contains('\n')) {
        return Err(invalid("header: bare CR or LF"));
    }
    Ok(v)
}

/// The headers after the first line: only `Host`, `Content-Length`,
/// `Connection: close`, `User-Agent` and `Content-Type` are understood;
/// `Content-Length` at most once. Returns the length (0 when absent).
fn content_length(hs: &[&str]) -> Result<Option<usize>, Refusal> {
    let mut len = None;
    for h in hs {
        let (k, v) = h
            .split_once(':')
            .ok_or_else(|| invalid("header without a colon"))?;
        let v = v.trim();
        match k.to_ascii_lowercase().as_str() {
            "content-length" => {
                if len.is_some()
                    || v.is_empty()
                    || !v.bytes().all(|b| b.is_ascii_digit())
                    || v.len() > 12
                {
                    return Err(invalid("bad or repeated Content-Length"));
                }
                len = Some(v.parse::<usize>().map_err(|_| invalid("Content-Length"))?);
            }
            "host" | "user-agent" | "content-type" => {}
            "connection" if v.eq_ignore_ascii_case("close") => {}
            _ => {
                return Err(invalid(format!(
                    "header {:?} not accepted",
                    crate::common::trunc(k)
                )))
            }
        }
    }
    Ok(len)
}

/// Parse a request header block (see the module docs).
pub fn parse_request(head: &[u8]) -> Result<Request, Refusal> {
    let l = lines(head)?;
    let (first, rest) = l.split_first().ok_or_else(|| invalid("empty request"))?;
    let len = content_length(rest)?;
    match *first {
        "GET /v1/pack HTTP/1.1" if len.unwrap_or(0) == 0 => Ok(Request::Pack),
        "POST /v1/report HTTP/1.1" => match len {
            Some(n) if n > 0 && n <= MAX_REQUEST_BODY => Ok(Request::Report(n)),
            _ => Err(invalid(
                "report: Content-Length 1..=MAX_REQUEST_BODY required",
            )),
        },
        _ => Err(invalid("unknown request")),
    }
}

/// Encode a request header block.
pub fn encode_request(r: Request, host: &str) -> Vec<u8> {
    match r {
        Request::Pack => format!("GET /v1/pack HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
        Request::Report(n) => format!(
            "POST /v1/report HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {n}\r\n\r\n"
        ),
    }
    .into_bytes()
}

/// Encode a response header block (`status` 200, 400, 403, 404, 409, 503).
pub fn encode_response(status: u16, len: u64) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        _ => "Service Unavailable",
    };
    format!("HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Length: {len}\r\n\r\n")
        .into_bytes()
}

/// Parse a response header block: status and body length.
pub fn parse_response(head: &[u8]) -> Result<(u16, u64), Refusal> {
    let l = lines(head)?;
    let (first, rest) = l.split_first().ok_or_else(|| invalid("empty response"))?;
    let status = first
        .strip_prefix("HTTP/1.1 ")
        .and_then(|s| s.get(..3))
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|s| (100..600).contains(s))
        .ok_or_else(|| invalid("bad status line"))?;
    let mut len = None;
    for h in rest {
        let (k, v) = h
            .split_once(':')
            .ok_or_else(|| invalid("header without a colon"))?;
        if k.eq_ignore_ascii_case("content-length") {
            let v = v.trim();
            if len.is_some()
                || v.is_empty()
                || v.len() > 20
                || !v.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(invalid("bad or repeated Content-Length"));
            }
            len = Some(v.parse::<u64>().map_err(|_| invalid("Content-Length"))?);
        } else if k.eq_ignore_ascii_case("transfer-encoding") {
            return Err(invalid("Transfer-Encoding is not accepted"));
        }
    }
    Ok((status, len.ok_or_else(|| invalid("no Content-Length"))?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::to_canonical;

    #[test]
    fn requests() {
        assert_eq!(
            parse_request(&encode_request(Request::Pack, "depot")).unwrap(),
            Request::Pack
        );
        assert_eq!(
            parse_request(&encode_request(Request::Report(10), "depot")).unwrap(),
            Request::Report(10)
        );
        for bad in [
            "GET /v1/pack?unit=ugv-08 HTTP/1.1\r\n\r\n",
            "GET /v1/pack HTTP/1.0\r\n\r\n",
            "GET /v1/../pack HTTP/1.1\r\n\r\n",
            "POST /v1/report HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
            "POST /v1/report HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST /v1/report HTTP/1.1\r\n\r\n",
            "POST /v1/report HTTP/1.1\r\nContent-Length: 999999999\r\n\r\n",
            "GET /v1/pack HTTP/1.1\r\nX-Unit: ugv-08\r\n\r\n",
            "GET /v1/pack HTTP/1.1\r\nHost: a\rb\r\n\r\n",
            "GET /v1/pack HTTP/1.1\r\n",
        ] {
            assert!(parse_request(bad.as_bytes()).is_err(), "{bad:?}");
        }
        assert_eq!(
            parse_response(&encode_response(200, 42)).unwrap(),
            (200, 42)
        );
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").is_err());
    }

    #[test]
    fn listings() {
        let f = |p: &str| StreamFile {
            path: p.into(),
            size: 3,
            sha256: "ab".repeat(32),
        };
        let mut l = PackListing {
            format: PACK_STREAM_FORMAT.into(),
            files: vec![
                f(&format!(
                    "bundles/b0/rpk_nav_1_arm64/chunks/{}",
                    "cd".repeat(32)
                )),
                f("bundles/b0/bundle.json"),
                f("deployment.json"),
                f("deployment.json.sig"),
                f("trust.json"),
                f("trust.json.sig"),
            ],
        };
        l.files.sort_by(|a, b| a.path.cmp(&b.path));
        let b = to_canonical(&l).unwrap();
        assert_eq!(parse_listing(&b).unwrap().1, 18);
        for bad in [
            "../etc/passwd",
            "bundles/b0/../../x",
            "bundles/B0/bundle.json",
            "bundles/b0/rpk_nav_1_arm64/chunks/zz",
            "state.json",
            "bundles/b0",
        ] {
            assert!(!is_pack_path(bad), "{bad}");
            let mut m = l.clone();
            m.files.push(f(bad));
            m.files.sort_by(|a, b| a.path.cmp(&b.path));
            assert!(parse_listing(&to_canonical(&m).unwrap()).is_err(), "{bad}");
        }
        let mut m = l.clone();
        m.files.retain(|x| x.path != "trust.json");
        assert!(parse_listing(&to_canonical(&m).unwrap()).is_err());
    }
}
