//! A small, bounded, allocation-free JSON reader for the `parameter` string
//! of `unitree_api::msg::dds_::Request_`.
//!
//! Unitree's clients put a short JSON object there (`{"x":0.3,"y":0,"z":0}`
//! for `Move`, `{"velocity":[..],"duration":1}` for `SetVelocity`,
//! `{"data":1}` for most setters). A few calls send a top-level **array**
//! instead (B2 `TrajectoryFollow`: 30 path-point objects, about 3 KB,
//! `unitree_sdk2py/b2/sport/sport_client.py`); [`validate_document`]
//! accepts either, with the same caps. This reader validates the **whole**
//! document against RFC 8259 and then answers lookups of top-level members.
//! It is deliberately strict where a lenient parser would let a hostile
//! writer hide a value:
//!
//! * size cap [`MAX_JSON_LEN`] and nesting cap [`MAX_JSON_DEPTH`], checked
//!   before / while scanning (no recursion beyond the depth cap);
//! * at most [`MAX_MEMBERS`] top-level members, kept in a fixed array;
//! * a **duplicate top-level key is an error**: which of two `"x"` members
//!   Unitree's parser uses is unknown, so the request is not interpreted;
//! * top-level keys containing escapes are rejected (no Unitree key has
//!   one, and `"x"` would otherwise smuggle a second `"x"`);
//! * the input must be UTF-8; control characters inside strings, leading
//!   zeros, `NaN`, `Infinity`, comments and trailing commas are errors;
//! * numbers are parsed with `str::parse::<f64>` from the validated slice
//!   (out-of-range values become ±inf, which the consumer sees as such).

use std::fmt;

/// Longest parameter string the JSON reader accepts (bytes).
pub const MAX_JSON_LEN: usize = 16 * 1024;
/// Deepest nesting of arrays / objects (the top-level object is depth 1).
pub const MAX_JSON_DEPTH: usize = 8;
/// Most top-level members kept for lookup.
pub const MAX_MEMBERS: usize = 32;

/// Why a parameter string is not acceptable JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JsonError {
    /// Longer than [`MAX_JSON_LEN`].
    TooLong { len: usize },
    /// Nested deeper than [`MAX_JSON_DEPTH`].
    TooDeep { at: usize },
    /// More than [`MAX_MEMBERS`] top-level members.
    TooManyMembers,
    /// Not valid UTF-8.
    NotUtf8,
    /// The document is not a JSON object (or, for
    /// [`validate_document`], not an object or an array).
    NotAnObject,
    /// A grammar violation at byte offset `at`.
    Syntax { at: usize },
    /// The same top-level key twice.
    DuplicateKey { at: usize },
    /// A top-level key with a backslash escape.
    EscapedKey { at: usize },
    /// Bytes after the closing brace (other than whitespace).
    TrailingData { at: usize },
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JsonError::TooLong { len } => {
                write!(f, "JSON of {len} bytes exceeds the {MAX_JSON_LEN}-byte cap")
            }
            JsonError::TooDeep { at } => {
                write!(f, "JSON nested deeper than {MAX_JSON_DEPTH} at offset {at}")
            }
            JsonError::TooManyMembers => {
                write!(f, "JSON object has more than {MAX_MEMBERS} members")
            }
            JsonError::NotUtf8 => write!(f, "JSON is not UTF-8"),
            JsonError::NotAnObject => write!(f, "JSON is not an object"),
            JsonError::Syntax { at } => write!(f, "JSON syntax error at offset {at}"),
            JsonError::DuplicateKey { at } => write!(f, "duplicate JSON key at offset {at}"),
            JsonError::EscapedKey { at } => write!(f, "escaped JSON key at offset {at}"),
            JsonError::TrailingData { at } => write!(f, "data after the JSON object at {at}"),
        }
    }
}

impl std::error::Error for JsonError {}

impl JsonError {
    /// Short stable description (used as an anomaly reason).
    pub fn reason(&self) -> &'static str {
        match self {
            JsonError::TooLong { .. } => "parameter JSON over the size cap",
            JsonError::TooDeep { .. } => "parameter JSON nested too deep",
            JsonError::TooManyMembers => "parameter JSON has too many members",
            JsonError::NotUtf8 => "parameter is not UTF-8",
            JsonError::NotAnObject => "parameter JSON is not an object",
            JsonError::Syntax { .. } => "parameter is not valid JSON",
            JsonError::DuplicateKey { .. } => "parameter JSON repeats a key",
            JsonError::EscapedKey { .. } => "parameter JSON key uses an escape",
            JsonError::TrailingData { .. } => "data after the parameter JSON",
        }
    }
}

/// A JSON value. Strings, arrays and objects are raw spans of the input
/// (escapes unresolved, brackets included).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum JsonValue<'a> {
    Null,
    Bool(bool),
    Number(f64),
    /// The bytes between the quotes, escapes not resolved.
    String(&'a [u8]),
    /// `[...]`, brackets included.
    Array(&'a [u8]),
    /// `{...}`, braces included.
    Object(&'a [u8]),
}

impl<'a> JsonValue<'a> {
    pub fn as_f64(&self) -> Option<f64> {
        match *self {
            JsonValue::Number(n) => Some(n),
            _ => None,
        }
    }

    /// An integral number within `i64` (`1.0` is accepted, `1.5` is not).
    pub fn as_i64(&self) -> Option<i64> {
        let n = self.as_f64()?;
        if n.is_finite() && n.fract() == 0.0 && (-9.0e18..=9.0e18).contains(&n) {
            // In range and integral: the cast is exact.
            Some(n as i64)
        } else {
            None
        }
    }

    /// A JSON boolean, or the integers 0 / 1 (Unitree's C++ jsonize
    /// writes `bool` fields as `true`/`false`; the Python SDK passes
    /// whatever the caller gave).
    pub fn as_bool(&self) -> Option<bool> {
        match *self {
            JsonValue::Bool(b) => Some(b),
            JsonValue::Number(n) if n == 0.0 || n == 1.0 => Some(n == 1.0),
            _ => None,
        }
    }

    /// Up to `N` numbers of an array of numbers, and how many there were.
    /// `None` if this is not an array, an element is not a number, or the
    /// array has more than `N` elements.
    pub fn as_f64_array<const N: usize>(&self) -> Option<([f64; N], usize)> {
        let JsonValue::Array(span) = *self else {
            return None;
        };
        let mut out = [0.0; N];
        let mut n = 0usize;
        let mut p = Parser::new(span);
        p.expect(b'[').ok()?;
        p.ws();
        if p.peek() == Some(b']') {
            return Some((out, 0));
        }
        loop {
            let v = p.value(2).ok()?;
            let slot = out.get_mut(n)?;
            *slot = v.as_f64()?;
            n = n.checked_add(1)?;
            p.ws();
            match p.next() {
                Some(b',') => continue,
                Some(b']') => return Some((out, n)),
                _ => return None,
            }
        }
    }
}

/// A validated top-level JSON object.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct JsonObject<'a> {
    members: [(&'a [u8], JsonValue<'a>); MAX_MEMBERS],
    len: usize,
}

impl<'a> JsonObject<'a> {
    /// The empty object (what an empty parameter string means).
    pub fn empty() -> Self {
        JsonObject {
            members: [(&[][..], JsonValue::Null); MAX_MEMBERS],
            len: 0,
        }
    }

    /// Validates `src` (see the module docs) and indexes its top-level
    /// members.
    pub fn parse(src: &'a [u8]) -> Result<Self, JsonError> {
        if src.len() > MAX_JSON_LEN {
            return Err(JsonError::TooLong { len: src.len() });
        }
        if std::str::from_utf8(src).is_err() {
            return Err(JsonError::NotUtf8);
        }
        let mut obj = Self::empty();
        let mut p = Parser::new(src);
        p.ws();
        if p.peek() != Some(b'{') {
            return Err(JsonError::NotAnObject);
        }
        p.expect(b'{')?;
        p.ws();
        if p.peek() == Some(b'}') {
            p.pos = p.pos.saturating_add(1);
        } else {
            loop {
                p.ws();
                let key_at = p.pos;
                let (key, escaped) = p.string()?;
                if escaped {
                    return Err(JsonError::EscapedKey { at: key_at });
                }
                p.ws();
                p.expect(b':')?;
                let v = p.value(2)?;
                if obj.members().iter().any(|(k, _)| *k == key) {
                    return Err(JsonError::DuplicateKey { at: key_at });
                }
                let slot = obj
                    .members
                    .get_mut(obj.len)
                    .ok_or(JsonError::TooManyMembers)?;
                *slot = (key, v);
                obj.len = obj.len.saturating_add(1);
                p.ws();
                match p.next() {
                    Some(b',') => continue,
                    Some(b'}') => break,
                    _ => return Err(JsonError::Syntax { at: p.pos }),
                }
            }
        }
        p.ws();
        if p.pos < src.len() {
            return Err(JsonError::TrailingData { at: p.pos });
        }
        Ok(obj)
    }

    /// The top-level members in document order.
    pub fn members(&self) -> &[(&'a [u8], JsonValue<'a>)] {
        self.members.get(..self.len).unwrap_or(&[])
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The member called `key` (exact byte match).
    pub fn get(&self, key: &str) -> Option<JsonValue<'a>> {
        self.members()
            .iter()
            .find(|(k, _)| *k == key.as_bytes())
            .map(|(_, v)| *v)
    }
}

/// The top level of a validated parameter document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JsonTop {
    Object,
    Array,
}

/// Validates a whole parameter document whose top level is an object (with
/// every [`JsonObject::parse`] rule: unique, unescaped keys, at most
/// [`MAX_MEMBERS`]) or an array (any length, every element valid, nesting
/// at most [`MAX_JSON_DEPTH`]); [`MAX_JSON_LEN`] and UTF-8 apply to both.
/// An empty document is the empty object (the SDK sends `""` for calls
/// without arguments).
pub fn validate_document(src: &[u8]) -> Result<JsonTop, JsonError> {
    if src.is_empty() {
        return Ok(JsonTop::Object);
    }
    if src.len() > MAX_JSON_LEN {
        return Err(JsonError::TooLong { len: src.len() });
    }
    if std::str::from_utf8(src).is_err() {
        return Err(JsonError::NotUtf8);
    }
    let mut p = Parser::new(src);
    p.ws();
    match p.peek() {
        Some(b'{') => JsonObject::parse(src).map(|_| JsonTop::Object),
        Some(b'[') => {
            p.value(1)?;
            p.ws();
            if p.pos < src.len() {
                return Err(JsonError::TrailingData { at: p.pos });
            }
            Ok(JsonTop::Array)
        }
        _ => Err(JsonError::NotAnObject),
    }
}

struct Parser<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(src: &'a [u8]) -> Self {
        Parser { src, pos: 0 }
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos = self.pos.saturating_add(1);
        Some(b)
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos = self.pos.saturating_add(1);
        }
    }

    fn expect(&mut self, b: u8) -> Result<(), JsonError> {
        if self.peek() == Some(b) {
            self.pos = self.pos.saturating_add(1);
            Ok(())
        } else {
            Err(JsonError::Syntax { at: self.pos })
        }
    }

    fn span(&self, start: usize) -> &'a [u8] {
        self.src.get(start..self.pos).unwrap_or(&[])
    }

    /// A value at nesting `depth` (the enclosing container's depth + 1).
    fn value(&mut self, depth: usize) -> Result<JsonValue<'a>, JsonError> {
        self.ws();
        let start = self.pos;
        match self.peek() {
            Some(b'{') | Some(b'[') if depth > MAX_JSON_DEPTH => {
                Err(JsonError::TooDeep { at: start })
            }
            Some(b'{') => {
                self.container(b'{', b'}', depth)?;
                Ok(JsonValue::Object(self.span(start)))
            }
            Some(b'[') => {
                self.container(b'[', b']', depth)?;
                Ok(JsonValue::Array(self.span(start)))
            }
            Some(b'"') => Ok(JsonValue::String(self.string()?.0)),
            Some(b't') => self.literal(b"true", JsonValue::Bool(true)),
            Some(b'f') => self.literal(b"false", JsonValue::Bool(false)),
            Some(b'n') => self.literal(b"null", JsonValue::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(JsonError::Syntax { at: start }),
        }
    }

    fn container(&mut self, open: u8, close: u8, depth: usize) -> Result<(), JsonError> {
        self.expect(open)?;
        self.ws();
        if self.peek() == Some(close) {
            self.pos = self.pos.saturating_add(1);
            return Ok(());
        }
        let inner = depth.saturating_add(1);
        loop {
            self.ws();
            if open == b'{' {
                self.string()?;
                self.ws();
                self.expect(b':')?;
            }
            self.value(inner)?;
            self.ws();
            match self.next() {
                Some(b',') => continue,
                Some(c) if c == close => return Ok(()),
                _ => return Err(JsonError::Syntax { at: self.pos }),
            }
        }
    }

    fn literal(&mut self, word: &[u8], v: JsonValue<'a>) -> Result<JsonValue<'a>, JsonError> {
        let end = self.pos.saturating_add(word.len());
        if self.src.get(self.pos..end) == Some(word) {
            self.pos = end;
            Ok(v)
        } else {
            Err(JsonError::Syntax { at: self.pos })
        }
    }

    /// A string: returns the raw content and whether it had an escape.
    fn string(&mut self) -> Result<(&'a [u8], bool), JsonError> {
        self.expect(b'"')?;
        let start = self.pos;
        let mut escaped = false;
        loop {
            match self.next() {
                None => return Err(JsonError::Syntax { at: self.pos }),
                Some(b'"') => {
                    let end = self.pos.saturating_sub(1);
                    let s = self.src.get(start..end).unwrap_or(&[]);
                    return Ok((s, escaped));
                }
                Some(b'\\') => {
                    escaped = true;
                    match self.next() {
                        Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => {}
                        Some(b'u') => {
                            for _ in 0..4 {
                                if !self.next().is_some_and(|c| c.is_ascii_hexdigit()) {
                                    return Err(JsonError::Syntax { at: self.pos });
                                }
                            }
                        }
                        _ => return Err(JsonError::Syntax { at: self.pos }),
                    }
                }
                Some(c) if c < 0x20 => return Err(JsonError::Syntax { at: self.pos }),
                Some(_) => {}
            }
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.pos;
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.pos = self.pos.saturating_add(1);
        }
        self.pos.saturating_sub(start)
    }

    fn number(&mut self) -> Result<JsonValue<'a>, JsonError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos = self.pos.saturating_add(1);
        }
        match self.peek() {
            Some(b'0') => {
                self.pos = self.pos.saturating_add(1);
                if self.peek().is_some_and(|c| c.is_ascii_digit()) {
                    return Err(JsonError::Syntax { at: self.pos });
                }
            }
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(JsonError::Syntax { at: self.pos }),
        }
        if self.peek() == Some(b'.') {
            self.pos = self.pos.saturating_add(1);
            if self.digits() == 0 {
                return Err(JsonError::Syntax { at: self.pos });
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos = self.pos.saturating_add(1);
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos = self.pos.saturating_add(1);
            }
            if self.digits() == 0 {
                return Err(JsonError::Syntax { at: self.pos });
            }
        }
        let text = std::str::from_utf8(self.span(start)).map_err(|_| JsonError::NotUtf8)?;
        text.parse::<f64>()
            .map(JsonValue::Number)
            .map_err(|_| JsonError::Syntax { at: start })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unitree_shapes() {
        let o = JsonObject::parse(br#"{"x":0.5,"y":-0.25,"z":1e-1}"#).unwrap();
        assert_eq!(o.len(), 3);
        assert_eq!(o.get("x").unwrap().as_f64(), Some(0.5));
        assert_eq!(o.get("z").unwrap().as_f64(), Some(0.1));
        let o =
            JsonObject::parse(br#" { "velocity" : [0.3, 0, -0.5], "duration": 1.0 } "#).unwrap();
        let (v, n) = o.get("velocity").unwrap().as_f64_array::<3>().unwrap();
        assert_eq!((v, n), ([0.3, 0.0, -0.5], 3));
        assert_eq!(o.get("duration").unwrap().as_f64(), Some(1.0));
        let o = JsonObject::parse(br#"{"data":true}"#).unwrap();
        assert_eq!(o.get("data").unwrap().as_bool(), Some(true));
        assert!(JsonObject::parse(b"{}").unwrap().is_empty());
        let o = JsonObject::parse(br#"{"a":{"b":[1,{"c":null}]},"s":"q\"A"}"#).unwrap();
        assert!(matches!(o.get("a"), Some(JsonValue::Object(_))));
        assert_eq!(o.get("s"), Some(JsonValue::String(br#"q\"A"#)));
        assert_eq!(o.get("data"), None);
    }

    // {"x":1} with a literal backslash before the u.
    #[allow(clippy::byte_char_slices)]
    const ESCAPED_KEY: &[u8] = &[
        b'{', b'"', b'\\', b'u', b'0', b'0', b'7', b'8', b'"', b':', b'1', b'}',
    ];

    #[test]
    fn rejects_hostile_input() {
        let cases: &[(&[u8], JsonError)] = &[
            (br#"{"x":1,"x":2}"#, JsonError::DuplicateKey { at: 7 }),
            // A key with a backslash-u escape: rejected so it cannot
            // smuggle a second "x" (built byte-wise to keep the backslash).
            (ESCAPED_KEY, JsonError::EscapedKey { at: 1 }),
            (b"[1]", JsonError::NotAnObject),
            (b"", JsonError::NotAnObject),
            (br#"{"x":NaN}"#, JsonError::Syntax { at: 5 }),
            (br#"{"x":01}"#, JsonError::Syntax { at: 6 }),
            (br#"{"x":1,}"#, JsonError::Syntax { at: 7 }),
            (br#"{"x":1} x"#, JsonError::TrailingData { at: 8 }),
            (b"{\"x\":\"a\x01\"}", JsonError::Syntax { at: 8 }),
            (b"{\"x\":\"\xff\"}", JsonError::NotUtf8),
            (br#"{"x":1"#, JsonError::Syntax { at: 6 }),
            (br#"{"x":1.}"#, JsonError::Syntax { at: 7 }),
            (br#"{"x":-}"#, JsonError::Syntax { at: 6 }),
            (br#"{"x":tru}"#, JsonError::Syntax { at: 5 }),
            (br#"{"x":"\q"}"#, JsonError::Syntax { at: 8 }),
        ];
        for (src, want) in cases {
            assert_eq!(
                JsonObject::parse(src),
                Err(*want),
                "{}",
                String::from_utf8_lossy(src)
            );
        }
    }

    #[test]
    fn caps() {
        let deep = format!("{{\"a\":{}1{}}}", "[".repeat(7), "]".repeat(7));
        assert!(JsonObject::parse(deep.as_bytes()).is_ok());
        let deeper = format!("{{\"a\":{}1{}}}", "[".repeat(8), "]".repeat(8));
        assert!(matches!(
            JsonObject::parse(deeper.as_bytes()),
            Err(JsonError::TooDeep { .. })
        ));
        // A very deep document is refused without recursing.
        let bomb = format!("{{\"a\":{}", "[".repeat(10_000));
        assert!(matches!(
            JsonObject::parse(bomb.as_bytes()),
            Err(JsonError::TooDeep { .. })
        ));
        let big = vec![b' '; MAX_JSON_LEN + 1];
        assert_eq!(
            JsonObject::parse(&big),
            Err(JsonError::TooLong {
                len: MAX_JSON_LEN + 1
            })
        );
        let many: String = (0..=MAX_MEMBERS)
            .map(|i| format!("\"k{i}\":{i}"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            JsonObject::parse(format!("{{{many}}}").as_bytes()),
            Err(JsonError::TooManyMembers)
        );
        // Huge exponents saturate to infinity (seen as such downstream).
        let o = JsonObject::parse(br#"{"x":1e999,"y":-1e999}"#).unwrap();
        assert_eq!(o.get("x").unwrap().as_f64(), Some(f64::INFINITY));
        assert_eq!(o.get("y").unwrap().as_f64(), Some(f64::NEG_INFINITY));
    }

    #[test]
    fn documents_may_be_arrays() {
        assert_eq!(validate_document(b""), Ok(JsonTop::Object));
        assert_eq!(validate_document(br#" {"a":1} "#), Ok(JsonTop::Object));
        assert_eq!(
            validate_document(br#"[{"x":1,"y":2},{"x":3}]"#),
            Ok(JsonTop::Array)
        );
        assert_eq!(validate_document(b"[]"), Ok(JsonTop::Array));
        // Object rules still apply to an object document.
        assert!(matches!(
            validate_document(br#"{"x":1,"x":2}"#),
            Err(JsonError::DuplicateKey { .. })
        ));
        // Scalars, trailing data, depth and size caps.
        assert_eq!(validate_document(b"1"), Err(JsonError::NotAnObject));
        assert!(matches!(
            validate_document(b"[1] x"),
            Err(JsonError::TrailingData { .. })
        ));
        assert!(matches!(
            validate_document(b"[1,]"),
            Err(JsonError::Syntax { .. })
        ));
        let deep: Vec<u8> = std::iter::repeat_n(b'[', MAX_JSON_DEPTH + 1)
            .chain(std::iter::repeat_n(b']', MAX_JSON_DEPTH + 1))
            .collect();
        assert!(matches!(
            validate_document(&deep),
            Err(JsonError::TooDeep { .. })
        ));
        let ok: Vec<u8> = std::iter::repeat_n(b'[', MAX_JSON_DEPTH)
            .chain(std::iter::repeat_n(b']', MAX_JSON_DEPTH))
            .collect();
        assert_eq!(validate_document(&ok), Ok(JsonTop::Array));
        let mut big = b"[".to_vec();
        big.extend(std::iter::repeat_n(b' ', MAX_JSON_LEN));
        big.push(b']');
        assert!(matches!(
            validate_document(&big),
            Err(JsonError::TooLong { .. })
        ));
        assert_eq!(validate_document(b"[\"\xff\"]"), Err(JsonError::NotUtf8));
    }

    #[test]
    fn arrays_and_scalars() {
        let o =
            JsonObject::parse(br#"{"v":[1,2,3,4],"e":[],"m":[1,"a"],"i":2.0,"f":2.5}"#).unwrap();
        assert!(o.get("v").unwrap().as_f64_array::<3>().is_none());
        assert_eq!(
            o.get("v").unwrap().as_f64_array::<4>(),
            Some(([1.0, 2.0, 3.0, 4.0], 4))
        );
        assert_eq!(o.get("e").unwrap().as_f64_array::<3>(), Some(([0.0; 3], 0)));
        assert!(o.get("m").unwrap().as_f64_array::<3>().is_none());
        assert_eq!(o.get("i").unwrap().as_i64(), Some(2));
        assert_eq!(o.get("f").unwrap().as_i64(), None);
        assert_eq!(o.get("f").unwrap().as_bool(), None);
    }

    #[test]
    fn random_bytes_never_panic() {
        let mut x: u64 = 0x1234_5678_9abc_def1;
        let alphabet = b"{}[]\":,0123456789.eE+-tfnrul\\ ax";
        for _ in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let len = (x % 40) as usize;
            let s: Vec<u8> = (0..len)
                .map(|i| alphabet[((x >> (i % 16 * 4)) as usize + i) % alphabet.len()])
                .collect();
            let _ = JsonObject::parse(&s);
        }
    }
}
