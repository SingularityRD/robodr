//! Redaction for the support bundle.
//!
//! Two layers, both conservative:
//!
//! 1. **Redaction** of what is collected: a value whose *name* reads like a
//!    secret ([`is_secret_name`]: `secret`, `password`, `passphrase`,
//!    `token`, `private`, `psk`, `api_key`, `hmac`, `bearer`,
//!    `authorization`, `cookie`, `sasl`, or a name that is or ends in
//!    `key` such as `hmac_key` / `ROBODR_SIGNING_KEY`, except `public_key`
//!    / `pub_key`) is replaced by [`REDACTED`], unless the name says it is
//!    a reference to one (`*_file`, `*_path`, `*_dir`, `*_socket`, `*_id`,
//!    `*_ids`): a key file's *path* helps support, the key does not. JSON
//!    is redacted structurally; text (TOML, env files, unit files, the
//!    journal) line by line (`NAME=value`, `NAME = value`, `"name": value`,
//!    `Environment=NAME=value`). PEM private-key blocks are dropped whole.
//!    Independently of names, the user information of every URL
//!    (`scheme://user:password@host`) is replaced by [`REDACTED`]
//!    ([`scrub_url_userinfo`]), in JSON strings and in text.
//! 2. **A final scan** ([`secret_markers`]) of every file of the finished
//!    bundle for key material that redaction should have removed (PEM
//!    private keys, minisign secret keys, RoboDR secret key files
//!    `secret_hex`, OpenSSH private keys). Any hit aborts the bundle: it is
//!    better to send nothing than a key.

use serde_json::Value;

/// The replacement text.
pub const REDACTED: &str = "<redacted>";

const SECRET_WORDS: &[&str] = &[
    "secret",
    "password",
    "passwd",
    "passphrase",
    "token",
    "private",
    "psk",
    "api_key",
    "apikey",
    "bearer",
    "authorization",
    "cookie",
    "sasl",
    "credential_value",
    "hmac",
];
const REFERENCE_SUFFIXES: &[&str] = &["_file", "_path", "_dir", "_socket", "_id", "_ids"];

/// A setting named `name` holds a secret.
pub fn is_secret_name(name: &str) -> bool {
    let n = name
        .trim()
        .trim_matches(|c| c == '"' || c == '\'')
        .to_ascii_lowercase()
        .replace('-', "_");
    if REFERENCE_SUFFIXES.iter().any(|s| n.ends_with(s)) {
        return false;
    }
    if SECRET_WORDS.iter().any(|w| n.contains(w)) {
        return true;
    }
    // `key`, `hmac_key`, `ROBODR_SIGNING_KEY`: a key itself. Public keys
    // and lists of trusted (public) keys (`trusted_keys`) are not secret.
    (n == "key" || n.ends_with("_key")) && !(n.ends_with("public_key") || n.ends_with("pub_key"))
}

/// `text` with the user information of every URL (`scheme://user:pw@`)
/// replaced by [`REDACTED`]; `None` when there is none.
///
/// The authority normally ends at the first `/`, `?` or `#`. A password
/// written into a URL without percent-encoding may contain one of those
/// (`https://u:pa#ss@host`), which would cut the authority inside the
/// password and leave `u:pa` behind; [`raw_userinfo_end`] catches that
/// case and redacts up to the `@` that starts the host instead.
pub fn scrub_url_userinfo(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    let mut changed = false;
    while let Some(i) = rest.find("://") {
        let (head, tail) = rest.split_at(i + 3);
        out.push_str(head);
        // The URL ends at anything that cannot be part of one in a log
        // line or a setting; its authority at the path, query or fragment.
        let token_end = tail
            .find(|c: char| matches!(c, '"' | '\'' | '<' | '>' | '`') || c.is_whitespace())
            .unwrap_or(tail.len());
        let token = tail.get(..token_end).unwrap_or_default();
        let end = token.find(['/', '?', '#']).unwrap_or(token.len());
        let (authority, after) = tail.split_at(end);
        let at = authority
            .rfind('@')
            .or_else(|| raw_userinfo_end(token, end));
        match at {
            Some(at) if at > 0 => {
                out.push_str(REDACTED);
                rest = tail.get(at..).unwrap_or_default();
                changed = true;
            }
            _ => {
                out.push_str(authority);
                rest = after;
            }
        }
    }
    out.push_str(rest);
    changed.then_some(out)
}

/// The position of the `@` ending a userinfo that contains a raw `/`, `?`
/// or `#` (so the authority, `token[..end]`, holds no `@`), or `None`.
///
/// It is taken to be one when the authority reads `user:x` where `x` is not
/// a port (not all digits) and an `@` follows later in the URL: `host:8443/
/// p?mail=a@b` and `[::1]:80/a@b` are left alone. Of several `@`, the one
/// that starts the host is the last before the next `/`, `?` or `#`
/// (`u:p#a@s@host/x` redacts `u:p#a@s`).
fn raw_userinfo_end(token: &str, end: usize) -> Option<usize> {
    let authority = token.get(..end)?;
    if authority.starts_with('[') {
        return None;
    }
    let (_, port) = authority.split_once(':')?;
    if port.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let mut at = end + token.get(end..)?.find('@')?;
    loop {
        let seg = token.get(at + 1..)?;
        let seg = seg.get(..seg.find(['/', '?', '#']).unwrap_or(seg.len()))?;
        match seg.find('@') {
            Some(i) => at += 1 + i,
            None => return Some(at),
        }
    }
}

/// Redact a JSON document; `None` when it is not JSON.
pub fn redact_json(text: &str) -> Option<String> {
    let mut v: Value = serde_json::from_str(text).ok()?;
    redact_value(&mut v);
    serde_json::to_string_pretty(&v).ok()
}

fn redact_value(v: &mut Value) {
    match v {
        Value::Object(o) => {
            for (k, x) in o.iter_mut() {
                if is_secret_name(k) {
                    *x = Value::String(REDACTED.into());
                } else {
                    redact_value(x);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(redact_value),
        Value::String(s) => {
            if !secret_markers(s.as_bytes()).is_empty() {
                *s = REDACTED.into();
            } else if let Some(r) = scrub_url_userinfo(s) {
                *s = r;
            }
        }
        _ => {}
    }
}

/// Redact the value of the first `NAME=` / `NAME:` in `line` whose name
/// reads like a secret (everything after it: values may contain the
/// separators); `None` when there is none.
fn redact_assignment(line: &str) -> Option<String> {
    line.char_indices()
        .filter(|(_, c)| matches!(c, '=' | ':'))
        .find_map(|(pos, sep)| {
            let name = line.get(..pos)?;
            // The name is the last word before the separator (`export
            // NAME=`, `  "name":`, `... auth token: x`).
            let word = name
                .split(|c: char| c.is_whitespace() || c == ',' || c == '{' || c == '[')
                .rfind(|w| !w.is_empty())?;
            is_secret_name(word).then(|| format!("{name}{sep} {REDACTED}"))
        })
}

/// Redact text line by line (see the module docs).
pub fn redact_text(text: &str) -> String {
    let named = redact_names(text);
    scrub_url_userinfo(&named).unwrap_or(named)
}

fn redact_names(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_pem = false;
    for line in text.split_inclusive('\n') {
        let body = line.trim_end_matches(['\n', '\r']);
        let nl = line.get(body.len()..).unwrap_or_default();
        if body.contains("-----BEGIN") && body.contains("PRIVATE KEY") {
            in_pem = !body.contains("-----END");
            out.push_str("<redacted private key>");
            out.push_str(nl);
            continue;
        }
        if in_pem {
            if body.contains("-----END") {
                in_pem = false;
            }
            continue;
        }
        let trimmed = body.trim_start();
        if trimmed.starts_with('#') || trimmed.starts_with(';') {
            out.push_str(line);
            continue;
        }
        // systemd `Environment=A=b "C=d"`: redact per assignment.
        if let Some(rest) = trimmed.strip_prefix("Environment=") {
            let indent = body.get(..body.len() - trimmed.len()).unwrap_or_default();
            let parts: Vec<String> = rest
                .split_whitespace()
                .map(|w| {
                    let q = w.starts_with('"');
                    let inner = w.trim_matches('"');
                    match inner.split_once('=') {
                        Some((n, _)) if is_secret_name(n) => {
                            if q {
                                format!("\"{n}={REDACTED}\"")
                            } else {
                                format!("{n}={REDACTED}")
                            }
                        }
                        _ => w.to_string(),
                    }
                })
                .collect();
            out.push_str(indent);
            out.push_str("Environment=");
            out.push_str(&parts.join(" "));
            out.push_str(nl);
            continue;
        }
        match redact_assignment(body) {
            Some(r) => {
                out.push_str(&r);
                out.push_str(nl);
            }
            None => out.push_str(line),
        }
    }
    out
}

/// Secret key material in `bytes`: the names of the markers found.
pub fn secret_markers(bytes: &[u8]) -> Vec<&'static str> {
    const MARKERS: &[(&str, &[&[u8]])] = &[
        ("PEM private key", &[b"-----BEGIN", b"PRIVATE KEY-----"]),
        (
            "OpenSSH private key",
            &[b"-----BEGIN OPENSSH PRIVATE KEY-----"],
        ),
        ("minisign secret key", &[b"minisign encrypted secret key"]),
        ("RoboDR secret key file", &[b"\"secret_hex\""]),
        ("RoboDR secret key file", &[b"secret_hex\\\""]),
    ];
    let mut out = Vec::new();
    for (name, parts) in MARKERS {
        if parts.iter().all(|p| contains(bytes, p)) && !out.contains(name) {
            out.push(*name);
        }
    }
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for s in [
            "password",
            "SASL_PASSWORD",
            "client_secret",
            "secret_hex",
            "api-key",
            "token",
            "ROBODR_KAFKA_SASL_PASSWORD",
            "hmac_key",
            "ROBODR_SIGNING_KEY",
            "key",
            "hmac",
        ] {
            assert!(is_secret_name(s), "{s}");
        }
        for s in [
            "key_file",
            "password_file",
            "token_path",
            "key_id",
            "robot",
            "tick_ms",
            "secret_dir",
            "trusted_keys",
            "public_key",
            "ROBODR_PUB_KEY",
            "signing_key_file",
            "keyring_path",
        ] {
            assert!(!is_secret_name(s), "{s}");
        }
    }

    #[test]
    fn json_is_redacted_structurally() {
        let t = r#"{"a":{"password":"hunter2","password_file":"/etc/x","n":[{"token":5}]},"k":"-----BEGIN PRIVATE KEY----- x"}"#;
        let r = redact_json(t).unwrap();
        assert!(!r.contains("hunter2"));
        assert!(r.contains("/etc/x"));
        assert!(!r.contains("\"token\": 5"));
        assert!(!r.contains("BEGIN PRIVATE"));
        assert!(redact_json("not json").is_none());
    }

    #[test]
    fn text_is_redacted_line_by_line() {
        let t = "ROBODR_SASL_PASSWORD=hunter2\nexport API_TOKEN = abc\n# password=comment-kept\n\
                 Environment=A=1 \"KAFKA_PASSWORD=pw\" B=2\nkey_file = \"/etc/robodr/keys/x\"\n\
                 -----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\ntail\n\
                 2026-10-31 host robodr-uplink[1]: auth token: zzz\n";
        let r = redact_text(t);
        assert!(!r.contains("hunter2"), "{r}");
        assert!(!r.contains("abc"), "{r}");
        assert!(!r.contains("pw\""), "{r}");
        assert!(!r.contains("MIIabc"), "{r}");
        assert!(!r.contains("zzz"), "{r}");
        assert!(r.contains("A=1"), "{r}");
        assert!(r.contains("B=2"), "{r}");
        assert!(r.contains("/etc/robodr/keys/x"), "{r}");
        assert!(r.contains("tail\n"), "{r}");
        assert!(r.contains("# password=comment-kept"), "{r}");
        assert!(secret_markers(r.as_bytes()).is_empty());
    }

    #[test]
    fn url_userinfo_is_scrubbed() {
        let t = "ROBODR_UPLINK_URL=https://robot:hunter2@soc.example:8443/ingest?x=1\n\
                 log: connecting to \"kafka://svc%40x:p@ss@broker:9093\" now\n\
                 plain https://soc.example/a@b and mailto:a@b ftp://@host/\n";
        let r = redact_text(t);
        assert!(!r.contains("hunter2") && !r.contains("robot:"), "{r}");
        assert!(
            r.contains("https://<redacted>@soc.example:8443/ingest?x=1"),
            "{r}"
        );
        assert!(!r.contains("p@ss") && !r.contains("svc%40x"), "{r}");
        assert!(r.contains("kafka://<redacted>@broker:9093"), "{r}");
        // An @ in the path, an address without a scheme and an empty
        // userinfo are left alone.
        assert!(
            r.contains("https://soc.example/a@b and mailto:a@b ftp://@host/"),
            "{r}"
        );
        let j = redact_json(r#"{"endpoint":"https://u:pw@h/x","n":"no url"}"#).unwrap();
        assert!(
            !j.contains("u:pw") && j.contains("https://<redacted>@h/x"),
            "{j}"
        );
        assert!(scrub_url_userinfo("nothing here").is_none());
    }

    #[test]
    fn url_userinfo_with_raw_delimiters_is_scrubbed() {
        // A password with an un-encoded `#`, `?` or `/` (a malformed URL,
        // but written that way into settings and logs).
        for (url, want) in [
            ("https://u:pa#ss@host/x", "https://<redacted>@host/x"),
            ("https://u:pa?ss@host", "https://<redacted>@host"),
            (
                "https://u:pa/ss@host:9093/x?y=1",
                "https://<redacted>@host:9093/x?y=1",
            ),
            (
                "kafka://u:p#a@s@broker/x?e=a@b",
                "kafka://<redacted>@broker/x?e=a@b",
            ),
        ] {
            let r = scrub_url_userinfo(&format!("url={url} next")).unwrap();
            assert_eq!(r, format!("url={want} next"), "{url}");
            assert!(!r.contains("pa") && !r.contains("ss@"), "{r}");
        }
        // A port, an IPv6 literal or a plain host followed by an @ in the
        // path or query is not userinfo.
        for url in [
            "https://soc.example:8443/p?mail=a@b",
            "https://soc.example:/a@b",
            "http://[::1]:80/a@b",
            "https://soc.example/a@b",
            "https://u:x",
        ] {
            assert!(scrub_url_userinfo(url).is_none(), "{url}");
        }
    }

    #[test]
    fn markers() {
        assert_eq!(
            secret_markers(b"{\"key_id\":\"x\",\"secret_hex\":\"00\"}"),
            ["RoboDR secret key file"]
        );
        assert!(!secret_markers(b"-----BEGIN EC PRIVATE KEY-----").is_empty());
        assert!(!secret_markers(b"untrusted comment: minisign encrypted secret key").is_empty());
        assert!(secret_markers(b"{\"public_hex\":\"00\"} -----BEGIN CERTIFICATE-----").is_empty());
    }
}
