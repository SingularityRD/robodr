//! Shared pieces of every delivery format: the refusal type, the strict
//! canonical-JSON reader, value validators and domain-separated digests.
//!
//! # Canonical JSON (decision, `docs/SECURE-DELIVERY.md` §3.5)
//!
//! Every signed document of this crate is signed and hashed over its **raw
//! bytes**, as in `robodr-diode`, so no canonicalisation is needed to
//! verify. On top of that, a document is accepted only if its bytes are
//! exactly the compact serialisation of the parsed value
//! ([`parse_canonical`]): members in the documented order, no whitespace,
//! no escapes `serde_json` would not write (a `\u` escape of a printable
//! character), optional members present as
//! `null`, no trailing newline. One value therefore has one byte string
//! and one digest, and two parsers (this crate, a depot written later in
//! another language) cannot disagree about what was signed: duplicate
//! keys, unknown keys, `1.0` for `1`, an escaped `A` for `A` and a UTF-8 BOM
//! are all refused before any signature is looked at.

use robodr_blackbox::crypto::{sha256, to_hex};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Longest label (site, programme, platform, unit, group, deployment id).
pub const MAX_LABEL_LEN: usize = 64;
/// Longest key id.
pub const MAX_KEY_ID_LEN: usize = 64;
/// Longest relative path inside an RPK.
pub const MAX_PATH_LEN: usize = 255;
/// Longest path component inside an RPK.
pub const MAX_COMPONENT_LEN: usize = 128;
/// Deepest path inside an RPK (components).
pub const MAX_PATH_DEPTH: usize = 16;

/// Why a document, a signature set or a whole bundle was refused. `code`
/// is stable (it becomes the reason of a `robot.deliver.refused` or
/// `robot.deliver.chain_gap` finding, `docs/SECURE-DELIVERY.md` §9);
/// `detail` is for humans and never contains more than 128 characters of
/// untrusted text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: Code,
    pub detail: String,
}

/// Stable refusal reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Code {
    /// Input larger than the format's hard cap (checked before parsing).
    TooLarge,
    /// Not valid JSON for the format (syntax, unknown or duplicate member,
    /// wrong type, number out of range).
    Malformed,
    /// Valid JSON, but not the one canonical encoding of its value.
    NonCanonical,
    /// Parsed, but a value violates the format (see the detail).
    Invalid,
    /// A value the format reserves for later work (e.g. `sealed` before
    /// Sprint 13c).
    Unsupported,
    /// A signature names a key that the trust file does not list at all.
    UnknownKey,
    /// A signature names a trusted key of another role (key confusion).
    WrongRole,
    /// A signature names a key whose fingerprint is revoked.
    RevokedKey,
    /// A signature does not verify (forged, wrong key, other bytes).
    BadSignature,
    /// Two signatures by the same key (by fingerprint).
    DuplicateSigner,
    /// Fewer distinct valid signers of the required role than the quorum.
    QuorumNotMet,
    /// An RPK whose digest the trust file revokes.
    RevokedRpk,
    /// An RPK serial below the trust file's floor for that package.
    BelowFloor,
    /// Past `expires_at`.
    Expired,
    /// Before `not_before`.
    NotYetValid,
    /// Bytes whose digest is not the one a signed document names.
    DigestMismatch,
    /// A file a signed document lists is absent.
    MissingFile,
    /// A file is present that no signed document lists.
    UnexpectedFile,
    /// A file is present but has another size or hash than listed, or is
    /// not a regular file.
    FileMismatch,
    /// A bundle sequence number skips ahead of the accepted chain.
    ChainGap,
    /// A sequence number at or below the accepted one (old bundle,
    /// deployment or trust file presented again).
    Replay,
    /// The same sequence number as the accepted one with other bytes.
    Equivocation,
    /// The next sequence number, but `prev_bundle_hash` is not the
    /// accepted bundle's hash.
    ChainBroken,
    /// A document for another programme or site.
    WrongScope,
    /// The entry station failed the bundle, or its report contradicts its
    /// own verdict (Sprint 14a, §6.1).
    ScanFailed,
}

impl Code {
    /// The snake_case name used in findings and CLI output.
    pub fn as_str(self) -> &'static str {
        match self {
            Code::TooLarge => "too_large",
            Code::Malformed => "malformed",
            Code::NonCanonical => "non_canonical",
            Code::Invalid => "invalid",
            Code::Unsupported => "unsupported",
            Code::UnknownKey => "unknown_key",
            Code::WrongRole => "wrong_role",
            Code::RevokedKey => "revoked_key",
            Code::BadSignature => "bad_signature",
            Code::DuplicateSigner => "duplicate_signer",
            Code::QuorumNotMet => "quorum_not_met",
            Code::RevokedRpk => "revoked_rpk",
            Code::BelowFloor => "below_floor",
            Code::Expired => "expired",
            Code::NotYetValid => "not_yet_valid",
            Code::DigestMismatch => "digest_mismatch",
            Code::MissingFile => "missing_file",
            Code::UnexpectedFile => "unexpected_file",
            Code::FileMismatch => "file_mismatch",
            Code::ChainGap => "chain_gap",
            Code::Replay => "replay",
            Code::Equivocation => "equivocation",
            Code::ChainBroken => "chain_broken",
            Code::WrongScope => "wrong_scope",
            Code::ScanFailed => "scan_failed",
        }
    }
}

impl Refusal {
    pub fn new(code: Code, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// Prefix the detail with where the problem is (`"rpk foo: ..."`).
    pub fn context(mut self, what: &str) -> Self {
        self.detail = format!("{}: {}", trunc(what), self.detail);
        self
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "refused ({}): {}", self.code.as_str(), self.detail)
    }
}

impl std::error::Error for Refusal {}

/// Shorthand for an [`Code::Invalid`] refusal.
pub(crate) fn invalid(detail: impl Into<String>) -> Refusal {
    Refusal::new(Code::Invalid, detail)
}

/// Parse `bytes` as exactly one canonical `T` (see the module docs).
/// `max` is checked before anything is parsed.
pub fn parse_canonical<T>(bytes: &[u8], max: usize, what: &str) -> Result<T, Refusal>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.len() > max {
        return Err(Refusal::new(
            Code::TooLarge,
            format!("{what}: {} bytes > {max}", bytes.len()),
        ));
    }
    let value: T = serde_json::from_slice(bytes).map_err(|e| {
        Refusal::new(
            Code::Malformed,
            format!("{what}: {}", trunc(&e.to_string())),
        )
    })?;
    let again = serde_json::to_vec(&value).map_err(|e| {
        Refusal::new(
            Code::Malformed,
            format!("{what}: {}", trunc(&e.to_string())),
        )
    })?;
    if again != bytes {
        return Err(Refusal::new(
            Code::NonCanonical,
            format!("{what}: not the canonical compact encoding of its value"),
        ));
    }
    Ok(value)
}

/// The canonical bytes of `value` (what [`parse_canonical`] accepts).
pub fn to_canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, Refusal> {
    serde_json::to_vec(value).map_err(|e| invalid(format!("serialise: {e}")))
}

/// 64 lower-case hex digits.
pub fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `sha256:` + 64 lower-case hex digits: a public-key fingerprint, the same
/// value `robodr-commission` prints and revokes
/// (`robodr_commission::trust::key_fingerprint`).
pub fn is_fingerprint(s: &str) -> bool {
    s.strip_prefix("sha256:").is_some_and(is_hex64)
}

/// Fingerprint of a 32-byte Ed25519 public key: `sha256:<hex of SHA-256 of
/// the raw key bytes>`.
pub fn fingerprint(public: &[u8; 32]) -> String {
    format!("sha256:{}", sha256_hex(public))
}

/// Lower-case hex SHA-256.
pub fn sha256_hex(bytes: &[u8]) -> String {
    to_hex(&sha256(bytes))
}

/// `domain || bytes`.
pub fn domain_message(domain: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(domain.len() + bytes.len());
    m.extend_from_slice(domain);
    m.extend_from_slice(bytes);
    m
}

/// Hex SHA-256 of `domain || bytes`.
pub fn domain_hash(domain: &[u8], bytes: &[u8]) -> String {
    sha256_hex(&domain_message(domain, bytes))
}

/// A label: `[a-z0-9][a-z0-9._-]{0,63}`, no `..`. Sites, programmes,
/// platforms, hardware ids, units, groups, deployment ids.
pub fn is_label(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_LABEL_LEN
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|&c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        })
        && !s.contains("..")
}

/// A package name: `[a-z0-9][a-z0-9.+-]{0,63}`, no `..`. No `_`, so the
/// RPK directory name `rpk_<name>_<serial>_<arch>` splits unambiguously.
pub fn is_pkg_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_LABEL_LEN
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|&c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'+' | b'-')
        })
        && !s.contains("..")
}

/// A key id: `[A-Za-z0-9._:-]{1,64}` (the derived ids `ed25519:<hex>` of
/// `robodr-blackbox` fit).
pub fn is_key_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_KEY_ID_LEN
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'-'))
}

/// A display version: `[A-Za-z0-9][A-Za-z0-9.+~:_-]{0,63}` (Debian version
/// characters). Display only: ordering uses `serial`.
pub fn is_version_display(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_LABEL_LEN
        && b[0].is_ascii_alphanumeric()
        && b.iter().all(|&c| {
            c.is_ascii_alphanumeric() || matches!(c, b'.' | b'+' | b'~' | b':' | b'_' | b'-')
        })
}

/// A relative path inside an RPK: `/`-separated components, each
/// `[A-Za-z0-9_][A-Za-z0-9._+-]{0,127}` (no leading `.` or `-`, so no
/// `.`/`..`, no hidden file, nothing a tool reads as an option), at most
/// [`MAX_PATH_DEPTH`] components and [`MAX_PATH_LEN`] bytes. No absolute
/// path, no empty component, no backslash, NUL or control character.
pub fn is_safe_rel_path(s: &str) -> bool {
    if s.is_empty() || s.len() > MAX_PATH_LEN {
        return false;
    }
    let mut depth = 0;
    for c in s.split('/') {
        depth += 1;
        let b = c.as_bytes();
        if b.is_empty()
            || b.len() > MAX_COMPONENT_LEN
            || !(b[0].is_ascii_alphanumeric() || b[0] == b'_')
            || !b
                .iter()
                .all(|&x| x.is_ascii_alphanumeric() || matches!(x, b'.' | b'_' | b'+' | b'-'))
        {
            return false;
        }
    }
    depth <= MAX_PATH_DEPTH
}

/// At most 128 characters of untrusted text (non-printables as `?`).
pub fn trunc(s: &str) -> String {
    s.chars()
        .take(128)
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .collect()
}

/// Reject a `Vec` that is not strictly ascending by `key` (sorted, no
/// duplicates). Used for every set-valued member, so a set has one
/// encoding.
pub(crate) fn strictly_sorted<T, K: Ord>(
    items: &[T],
    key: impl Fn(&T) -> K,
    what: &str,
) -> Result<(), Refusal> {
    for w in items.windows(2) {
        if key(&w[0]) >= key(&w[1]) {
            return Err(invalid(format!(
                "{what} must be sorted ascending without duplicates"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct T {
        a: u64,
        b: Option<String>,
    }

    #[test]
    fn canonical_reader_refuses_every_alternative_encoding() {
        let ok: T = parse_canonical(br#"{"a":1,"b":null}"#, 100, "t").unwrap();
        assert_eq!(ok, T { a: 1, b: None });
        for (bad, code) in [
            (&br#"{"a":1,"b":null} "#[..], Code::NonCanonical),
            (
                br#"{"a":1,"b":null}
"#,
                Code::NonCanonical,
            ),
            (br#"{ "a":1,"b":null}"#, Code::NonCanonical),
            (br#"{"b":null,"a":1}"#, Code::NonCanonical),
            (br#"{"a":1}"#, Code::NonCanonical),
            (b"{\"a\":1,\"b\":\"\\u0041\"}", Code::NonCanonical),
            (br#"{"a":1.0,"b":null}"#, Code::Malformed),
            (br#"{"a":1,"a":2,"b":null}"#, Code::Malformed),
            (br#"{"a":1,"b":null,"c":0}"#, Code::Malformed),
            (br#"{"a":-1,"b":null}"#, Code::Malformed),
            (br#"{"a":18446744073709551616,"b":null}"#, Code::Malformed),
            (b"\xef\xbb\xbf{\"a\":1,\"b\":null}", Code::Malformed),
            (br#"{"a":1,"b":null}{}"#, Code::Malformed),
            (b"", Code::Malformed),
        ] {
            let e = parse_canonical::<T>(bad, 100, "t").unwrap_err();
            assert_eq!(e.code, code, "{:?}", String::from_utf8_lossy(bad));
        }
        let e = parse_canonical::<T>(&[b' '; 101], 100, "t").unwrap_err();
        assert_eq!(e.code, Code::TooLarge);
    }

    #[test]
    fn validators() {
        for good in ["a", "ugv-x1", "site.01", "a_b", &"a".repeat(64)] {
            assert!(is_label(good), "{good}");
        }
        for bad in [
            "",
            "A",
            "-a",
            ".a",
            "a..b",
            "a/b",
            "a b",
            "é",
            &"a".repeat(65),
        ] {
            assert!(!is_label(bad), "{bad}");
        }
        assert!(is_pkg_name("robodr-agentd"));
        assert!(is_pkg_name("libc6+x"));
        assert!(!is_pkg_name("a_b"));
        assert!(!is_pkg_name("A"));
        assert!(is_key_id("ed25519:0011aabb"));
        assert!(!is_key_id("a b"));
        assert!(!is_key_id(""));
        assert!(!is_key_id(&"k".repeat(65)));
        assert!(is_version_display("1.2.3~rc1+deb12"));
        assert!(!is_version_display("-1"));
        assert!(!is_version_display("1 2"));
        for good in ["a", "usr/lib/x.so.1", "_x/y+z", "a/b/c"] {
            assert!(is_safe_rel_path(good), "{good}");
        }
        let deep = vec!["a"; MAX_PATH_DEPTH + 1].join("/");
        for bad in [
            "",
            "/etc/passwd",
            "../x",
            "a/../b",
            "a/./b",
            ".",
            "..",
            "a//b",
            "a/",
            "a\\b",
            ".hidden",
            "-rf",
            "a\0b",
            "a\nb",
            "é",
            &deep,
            &"a".repeat(129),
        ] {
            assert!(!is_safe_rel_path(bad), "{bad:?}");
        }
        assert!(is_hex64(&"0a".repeat(32)));
        assert!(!is_hex64(&"0A".repeat(32)));
        assert!(is_fingerprint(&format!("sha256:{}", "0a".repeat(32))));
        assert!(!is_fingerprint(&"0a".repeat(32)));
    }

    #[test]
    fn digests_are_domain_separated() {
        assert_ne!(domain_hash(b"a\0", b"x"), domain_hash(b"b\0", b"x"));
        assert_ne!(domain_hash(b"a\0", b"x"), sha256_hex(b"x"));
        assert_eq!(domain_message(b"d\0", b"x"), b"d\0x");
        assert_eq!(trunc("a\nb"), "a?b");
    }
}
