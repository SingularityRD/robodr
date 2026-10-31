//! Minimal HTTP/1.1 server side: one request per connection
//! (`Connection: close`), `Content-Length` bodies only, bounded head and
//! body. Enough for `robodr-uplink` and a browser; nothing else.

use std::io::{self, BufRead, BufReader, Read, Write};

/// Longest request head (request line + headers).
pub const MAX_HEAD_BYTES: usize = 16 * 1024;
/// Most headers.
pub const MAX_HEADERS: usize = 64;
/// Largest body: the ingest contract's 4 MiB plus slack.
pub const MAX_BODY_BYTES: usize = 4 * 1024 * 1024 + 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Why a request could not be read: the status to answer with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bad(pub u16, pub &'static str);

fn line<R: BufRead>(r: &mut R, budget: &mut usize) -> Result<String, Bad> {
    let mut buf = Vec::new();
    let mut lim = r.take(*budget as u64 + 1);
    lim.read_until(b'\n', &mut buf)
        .map_err(|_| Bad(400, "read error"))?;
    if buf.len() > *budget {
        return Err(Bad(431, "request head too large"));
    }
    *budget -= buf.len();
    if buf.last() != Some(&b'\n') {
        return Err(Bad(400, "truncated request"));
    }
    buf.pop();
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    String::from_utf8(buf).map_err(|_| Bad(400, "head is not UTF-8"))
}

/// Read one request.
pub fn read_request<R: Read>(stream: R) -> Result<Request, Bad> {
    let mut r = BufReader::new(stream);
    let mut budget = MAX_HEAD_BYTES;
    let start = line(&mut r, &mut budget)?;
    let mut parts = start.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Bad(400, "bad request line"));
    };
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(Bad(505, "HTTP/1.x only"));
    }
    let mut headers = Vec::new();
    loop {
        let l = line(&mut r, &mut budget)?;
        if l.is_empty() {
            break;
        }
        if headers.len() >= MAX_HEADERS {
            return Err(Bad(431, "too many headers"));
        }
        let Some((k, v)) = l.split_once(':') else {
            return Err(Bad(400, "bad header line"));
        };
        if k.is_empty() || k.bytes().any(|b| b <= b' ' || b >= 0x7f) {
            return Err(Bad(400, "bad header name"));
        }
        headers.push((k.to_string(), v.trim_matches([' ', '\t']).to_string()));
    }
    if headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"))
    {
        return Err(Bad(
            501,
            "Transfer-Encoding not supported; send Content-Length",
        ));
    }
    let lens: Vec<&str> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v.as_str())
        .collect();
    let len = match lens.as_slice() {
        [] => 0,
        [v] if !v.is_empty() && v.len() <= 10 && v.bytes().all(|b| b.is_ascii_digit()) => v
            .parse::<usize>()
            .map_err(|_| Bad(400, "bad Content-Length"))?,
        _ => return Err(Bad(400, "bad or repeated Content-Length")),
    };
    if len > MAX_BODY_BYTES {
        return Err(Bad(413, "body too large"));
    }
    let mut body = vec![0; len];
    r.read_exact(&mut body)
        .map_err(|_| Bad(400, "body shorter than Content-Length"))?;
    Ok(Request {
        method: method.to_string(),
        path: target.to_string(),
        headers,
        body,
    })
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Status",
    }
}

/// Write a complete response and close.
pub fn write_response<W: Write>(
    mut w: W,
    status: u16,
    content_type: &str,
    extra: &[(&str, String)],
    body: &[u8],
) -> io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         Connection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\
         Referrer-Policy: no-referrer\r\nX-Frame-Options: DENY\r\n\
         Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; base-uri 'none'\r\n",
        reason(status),
        body.len()
    );
    for (k, v) in extra {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    w.write_all(head.as_bytes())?;
    w.write_all(body)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_post_and_refuses_malformed_ones() {
        let r = read_request(
            &b"POST /x HTTP/1.1\r\nContent-Type: a/b\r\nContent-Length: 3\r\n\r\nabcEXTRA"[..],
        )
        .unwrap();
        assert_eq!((r.method.as_str(), r.path.as_str()), ("POST", "/x"));
        assert_eq!(r.body, b"abc");
        assert_eq!(r.headers[0], ("Content-Type".into(), "a/b".into()));
        for (bad, status) in [
            (&b"GET / HTTP/2\r\n\r\n"[..], 505),
            (b"GET /\r\n\r\n", 400),
            (b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nab", 400),
            (
                b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\na",
                400,
            ),
            (b"POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n", 400),
            (
                b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
                501,
            ),
            (b"POST / HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n", 413),
            (b"GET / HTTP/1.1\r\nno colon\r\n\r\n", 400),
            (b"GET / HTTP/1.1\r\nHost: x", 400),
        ] {
            assert_eq!(
                read_request(bad).unwrap_err().0,
                status,
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
        let mut huge = b"GET / HTTP/1.1\r\n".to_vec();
        huge.extend(std::iter::repeat_n(b'a', MAX_HEAD_BYTES + 10));
        assert_eq!(read_request(&huge[..]).unwrap_err().0, 431);
    }

    #[test]
    fn response_has_security_headers() {
        let mut out = Vec::new();
        write_response(
            &mut out,
            200,
            "text/plain",
            &[("Retry-After", "1".into())],
            b"hi",
        )
        .unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Content-Security-Policy: default-src 'self'"));
        assert!(s.contains("Retry-After: 1\r\n"));
        assert!(s.ends_with("\r\n\r\nhi"));
    }
}
