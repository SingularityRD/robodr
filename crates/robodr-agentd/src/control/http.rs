//! The bounded HTTP/1.1 subset the control plane speaks (std only).
//!
//! One request per connection (`Connection: close` on every answer), no
//! keep-alive, no pipelining, no chunked bodies, no `Expect` handling. The
//! whole request head is at most [`MAX_HEAD_BYTES`] with at most
//! [`MAX_HEADERS`] header lines; the body at most [`MAX_BODY_BYTES`] and only
//! with an exact `Content-Length`. The head must be printable ASCII; the
//! request target is restricted to [`target_char_ok`] (no query string, no
//! fragment). Reading stops at a deadline, so a slow client holds one
//! connection slot for at most that long. Nothing here allocates more than
//! the bounds above and nothing panics on hostile input.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// Longest request head (request line + headers + the blank line).
pub const MAX_HEAD_BYTES: usize = 8192;
/// Most header lines.
pub const MAX_HEADERS: usize = 32;
/// Longest request body.
pub const MAX_BODY_BYTES: usize = 16 * 1024;
/// Longest request target.
pub const MAX_TARGET_BYTES: usize = 1024;
/// Longest header name.
pub const MAX_HEADER_NAME_BYTES: usize = 64;

/// A stream with a settable read timeout (TCP, unix, test doubles).
pub trait Stream: Read + Write {
    fn set_read_deadline(&self, d: Duration) -> io::Result<()>;
}

impl Stream for TcpStream {
    fn set_read_deadline(&self, d: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(d))
    }
}

impl Stream for UnixStream {
    fn set_read_deadline(&self, d: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(d))
    }
}

/// One parsed request. Header names are lower case, in arrival order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// The first value of header `name` (lower case).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// How many times header `name` (lower case) appears.
    pub fn header_count(&self, name: &str) -> usize {
        self.headers.iter().filter(|(n, _)| n == name).count()
    }
}

/// Why a request could not be read; answered with `status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpError {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
}

fn err(status: u16, code: &'static str, message: impl Into<String>) -> HttpError {
    HttpError {
        status,
        code,
        message: message.into(),
    }
}

/// Characters allowed in a request target: RFC 3986 unreserved, `%`
/// (percent-encoding), `/` and `:`. No query (`?`), fragment, spaces or
/// anything a proxy might rewrite.
pub fn target_char_ok(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'%' | b'/' | b':')
}

fn token_char_ok(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')
}

/// Read some bytes before `deadline`: `Ok(0)` at end of stream.
fn read_some<S: Stream>(s: &mut S, buf: &mut [u8], deadline: Instant) -> Result<usize, HttpError> {
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(err(408, "timeout", "the request was not received in time"));
        }
        s.set_read_deadline(left.max(Duration::from_millis(1)))
            .map_err(|e| err(400, "io", format!("socket: {e}")))?;
        match s.read(buf) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(err(408, "timeout", "the request was not received in time"));
            }
            Err(e) => return Err(err(400, "io", format!("socket: {e}"))),
        }
    }
}

fn find_crlfcrlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Read and parse one request before `deadline`.
pub fn read_request<S: Stream>(s: &mut S, deadline: Instant) -> Result<Request, HttpError> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let head_end = loop {
        if let Some(i) = find_crlfcrlf(&buf) {
            break i;
        }
        if buf.len() >= MAX_HEAD_BYTES {
            return Err(err(
                431,
                "head_too_large",
                format!("the request head is longer than {MAX_HEAD_BYTES} bytes"),
            ));
        }
        let room = (MAX_HEAD_BYTES + 4 - buf.len()).min(chunk.len());
        let n = read_some(s, &mut chunk[..room], deadline)?;
        if n == 0 {
            return Err(err(
                400,
                "truncated",
                "the connection closed before the request head ended",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    if head_end > MAX_HEAD_BYTES {
        return Err(err(
            431,
            "head_too_large",
            format!("the request head is longer than {MAX_HEAD_BYTES} bytes"),
        ));
    }
    let (method, target, headers) = parse_head(&buf[..head_end])?;
    let mut rest = buf.split_off(head_end + 4);

    if headers.iter().any(|(n, _)| n == "transfer-encoding") {
        return Err(err(
            400,
            "transfer_encoding",
            "Transfer-Encoding is not supported; send Content-Length",
        ));
    }
    let lengths: Vec<&str> = headers
        .iter()
        .filter(|(n, _)| n == "content-length")
        .map(|(_, v)| v.as_str())
        .collect();
    let len = match lengths.as_slice() {
        [] => 0,
        [v] => {
            if v.is_empty() || v.len() > 7 || !v.bytes().all(|b| b.is_ascii_digit()) {
                return Err(err(400, "content_length", "Content-Length is not a number"));
            }
            v.parse::<usize>()
                .map_err(|_| err(400, "content_length", "Content-Length is not a number"))?
        }
        _ => {
            return Err(err(
                400,
                "content_length",
                "Content-Length appears more than once",
            ))
        }
    };
    if len > MAX_BODY_BYTES {
        return Err(err(
            413,
            "body_too_large",
            format!("the body is longer than {MAX_BODY_BYTES} bytes"),
        ));
    }
    if method == "GET" && len > 0 {
        return Err(err(
            400,
            "body_not_allowed",
            "a GET request carries no body",
        ));
    }
    // Bytes beyond the body (a pipelined request) are dropped: one request
    // per connection.
    rest.truncate(len);
    while rest.len() < len {
        let room = (len - rest.len()).min(chunk.len());
        let n = read_some(s, &mut chunk[..room], deadline)?;
        if n == 0 {
            return Err(err(
                400,
                "truncated",
                "the connection closed before the body ended",
            ));
        }
        rest.extend_from_slice(&chunk[..n]);
    }
    Ok(Request {
        method,
        target,
        headers,
        body: rest,
    })
}

type Head = (String, String, Vec<(String, String)>);

fn parse_head(head: &[u8]) -> Result<Head, HttpError> {
    if !head
        .iter()
        .all(|&b| (0x20..0x7f).contains(&b) || b == b'\r' || b == b'\n' || b == b'\t')
    {
        return Err(err(
            400,
            "bad_head",
            "the request head is not printable ASCII",
        ));
    }
    // ASCII checked above.
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let line = lines.next().unwrap_or_default();
    let parts: Vec<&str> = line.split(' ').collect();
    let [method, target, version] = parts.as_slice() else {
        return Err(err(400, "bad_request_line", "malformed request line"));
    };
    if method.is_empty() || method.len() > 16 || !method.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(err(400, "bad_request_line", "malformed method"));
    }
    if !matches!(*version, "HTTP/1.1" | "HTTP/1.0") {
        return Err(err(505, "bad_version", "only HTTP/1.1 and HTTP/1.0"));
    }
    if !target.starts_with('/')
        || target.len() > MAX_TARGET_BYTES
        || !target.bytes().all(target_char_ok)
    {
        return Err(err(
            400,
            "bad_target",
            "the request target must be an absolute path of [A-Za-z0-9-._~%/:] without a query",
        ));
    }
    let mut headers = Vec::new();
    for l in lines {
        if l.starts_with(' ') || l.starts_with('\t') {
            return Err(err(400, "bad_header", "folded header lines are refused"));
        }
        if l.contains('\n') || l.contains('\r') {
            return Err(err(400, "bad_header", "a bare CR or LF in the head"));
        }
        let Some((name, value)) = l.split_once(':') else {
            return Err(err(400, "bad_header", "a header line without ':'"));
        };
        if name.is_empty() || name.len() > MAX_HEADER_NAME_BYTES || !name.bytes().all(token_char_ok)
        {
            return Err(err(400, "bad_header", "malformed header name"));
        }
        if headers.len() >= MAX_HEADERS {
            return Err(err(
                431,
                "too_many_headers",
                format!("more than {MAX_HEADERS} header lines"),
            ));
        }
        headers.push((
            name.to_ascii_lowercase(),
            value.trim_matches([' ', '\t']).to_string(),
        ));
    }
    Ok((method.to_string(), target.to_string(), headers))
}

/// The reason phrase of a status this server sends.
pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        413 => "Content Too Large",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Unknown",
    }
}

/// Write one JSON answer and close the exchange (`Connection: close`).
/// `extra` header values must be printable ASCII (checked; a bad one is
/// dropped).
pub fn write_response<W: Write>(
    w: &mut W,
    status: u16,
    body: &[u8],
    extra: &[(&str, String)],
) -> io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n",
        reason(status),
        body.len()
    );
    for (n, v) in extra {
        if n.bytes().all(token_char_ok) && v.bytes().all(|b| (0x20..0x7f).contains(&b)) {
            head.push_str(n);
            head.push_str(": ");
            head.push_str(v);
            head.push_str("\r\n");
        }
    }
    head.push_str("\r\n");
    w.write_all(head.as_bytes())?;
    w.write_all(body)?;
    w.flush()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Cursor;

    /// A test stream: reads from `input` in chunks of `step` bytes.
    pub struct Fake {
        pub input: Cursor<Vec<u8>>,
        pub output: Vec<u8>,
        pub step: usize,
        /// Return `WouldBlock` once the input is exhausted (a slow client).
        pub stall: bool,
    }

    impl Fake {
        pub fn new(input: &[u8]) -> Self {
            Self {
                input: Cursor::new(input.to_vec()),
                output: Vec::new(),
                step: usize::MAX,
                stall: false,
            }
        }
    }

    impl Read for Fake {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let pos = self.input.position() as usize;
            if self.stall && pos >= self.input.get_ref().len() {
                std::thread::sleep(Duration::from_millis(5));
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let n = buf.len().min(self.step);
            self.input.read(&mut buf[..n])
        }
    }

    impl Write for Fake {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.output.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Stream for Fake {
        fn set_read_deadline(&self, _: Duration) -> io::Result<()> {
            Ok(())
        }
    }

    fn parse(raw: &[u8]) -> Result<Request, HttpError> {
        let mut f = Fake::new(raw);
        f.step = 7;
        read_request(&mut f, Instant::now() + Duration::from_secs(5))
    }

    #[test]
    fn get_and_post_parse() {
        let r =
            parse(b"GET /api/v1/robots/ugv-007 HTTP/1.1\r\nHost: x\r\nX-RoboDR-Nonce: abc\r\n\r\n")
                .unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.target, "/api/v1/robots/ugv-007");
        assert_eq!(r.header("x-robodr-nonce"), Some("abc"));
        assert!(r.body.is_empty());
        let r = parse(
            b"POST /api/v1/robots/r/action-requests HTTP/1.1\r\ncontent-length: 4\r\n\r\n{}  extra",
        )
        .unwrap();
        assert_eq!(r.body, b"{}  ");
    }

    #[test]
    fn hostile_heads_are_refused() {
        let cases: &[(&[u8], u16)] = &[
            (b"GET /a?b=1 HTTP/1.1\r\n\r\n", 400),
            (b"GET a HTTP/1.1\r\n\r\n", 400),
            (b"get /a HTTP/1.1\r\n\r\n", 400),
            (b"GET /a HTTP/2\r\n\r\n", 505),
            (b"GET /a HTTP/1.1\r\nBad Name: x\r\n\r\n", 400),
            (b"GET /a HTTP/1.1\r\nX: \x01\r\n\r\n", 400),
            (b"GET /a HTTP/1.1\r\nX: \xc3\xa9\r\n\r\n", 400),
            (b"GET /a HTTP/1.1\r\nX: a\r\n folded\r\n\r\n", 400),
            (b"GET /a HTTP/1.1\r\nX: a\nY: b\r\n\r\n", 400),
            (b"GET /a HTTP/1.1\r\nnocolon\r\n\r\n", 400),
            (b"GET /a HTTP/1.1\r\nContent-Length: 2\r\n\r\nab", 400),
            (
                b"POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
                400,
            ),
            (
                b"POST /a HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\na",
                400,
            ),
            (b"POST /a HTTP/1.1\r\nContent-Length: -1\r\n\r\n", 400),
            (b"POST /a HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n", 400),
            (b"POST /a HTTP/1.1\r\nContent-Length: 20000\r\n\r\n", 413),
            (b"POST /a HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc", 400),
            (b"GET /a HTTP/1.1\r\n", 400),
        ];
        for (raw, status) in cases {
            let e = parse(raw).expect_err(&String::from_utf8_lossy(raw));
            assert_eq!(
                e.status,
                *status,
                "{:?}: {e:?}",
                String::from_utf8_lossy(raw)
            );
        }
        let mut many = b"GET /a HTTP/1.1\r\n".to_vec();
        for i in 0..40 {
            many.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
        }
        many.extend_from_slice(b"\r\n");
        assert_eq!(parse(&many).unwrap_err().status, 431);
        let mut long = b"GET /a HTTP/1.1\r\nX: ".to_vec();
        long.extend(std::iter::repeat_n(b'a', MAX_HEAD_BYTES + 10));
        assert_eq!(parse(&long).unwrap_err().status, 431);
        let target = format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(MAX_TARGET_BYTES + 1));
        assert_eq!(parse(target.as_bytes()).unwrap_err().status, 400);
    }

    #[test]
    fn slow_client_times_out() {
        let mut f = Fake::new(b"GET /a HTTP/1.1\r\n");
        f.stall = true;
        let t = Instant::now();
        let e = read_request(&mut f, Instant::now() + Duration::from_millis(100)).unwrap_err();
        assert_eq!(e.status, 408);
        assert!(t.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn response_is_closed_json() {
        let mut out = Vec::new();
        write_response(
            &mut out,
            401,
            b"{}",
            &[("X-Ok", "a".into()), ("X-Bad", "a\r\nInjected: 1".into())],
        )
        .unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("HTTP/1.1 401 Unauthorized\r\n"), "{s}");
        assert!(s.contains("Connection: close\r\n"));
        assert!(s.contains("Content-Length: 2\r\n"));
        assert!(s.contains("X-Ok: a\r\n"));
        assert!(!s.contains("Injected"));
        assert!(s.ends_with("\r\n\r\n{}"));
    }
}
