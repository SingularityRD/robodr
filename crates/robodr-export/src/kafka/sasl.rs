//! SASL/SCRAM (RFC 5802, RFC 7677) for the Kafka producer: SaslHandshake
//! v1 (key 17) + SaslAuthenticate v0–v1 (key 36), mechanisms
//! `SCRAM-SHA-256` and `SCRAM-SHA-512` (Kafka's KIP-84).
//!
//! * Only over TLS ([`super::ProducerConfig`] refuses SASL on a plain
//!   connection): SCRAM never sends the password, but without TLS the
//!   authenticated connection itself could be taken over.
//! * No `PLAIN` (it sends the password) and no `GSSAPI` / `OAUTHBEARER`.
//! * The password is used as raw UTF-8 bytes, as the Java client does (no
//!   SASLprep); the user name is escaped (`=2C`, `=3D`).
//! * The server's iteration count must be in [`MIN_ITERATIONS`]..=
//!   [`MAX_ITERATIONS`] (Kafka's own minimum; the cap bounds the CPU a
//!   hostile broker can make the client spend), its nonce must extend
//!   ours, mandatory extensions (`m=`) are refused, and its final
//!   signature is checked (constant time): a broker that does not know the
//!   password cannot complete the exchange.
//! * Re-authentication (KIP-368) is not implemented: a connection whose
//!   broker-announced session lifetime is about to end is closed and
//!   re-opened (a fresh authentication) before its next request.
//! * Primitives (ADR-0007): HMAC, PBKDF2 (`Hi`) and SHA-2 are RustCrypto's
//!   `hmac`, `pbkdf2` and `sha2` with their `zeroize` feature (the keyed
//!   hash states are wiped on drop; the derived keys held here are wiped
//!   after use); base64 is `base64ct` (constant time, canonical padding
//!   only). Pinned to RFC 4231 / RFC 7914 / RFC 7677 vectors and to an
//!   independent in-test reference implementation.

use super::wire::{derr, DecodeError, Reader, Writer};
use std::fmt;
use zeroize::Zeroize;

pub const API_SASL_HANDSHAKE: i16 = 17;
pub const API_SASL_AUTHENTICATE: i16 = 36;
/// Versions this client implements.
pub const HANDSHAKE_VERSIONS: (i16, i16) = (1, 1);
pub const AUTHENTICATE_VERSIONS: (i16, i16) = (0, 1);
/// Bounds on the server's iteration count.
pub const MIN_ITERATIONS: u32 = 4096;
pub const MAX_ITERATIONS: u32 = 100_000;
/// Longest user name / password accepted.
pub const MAX_CREDENTIAL_LEN: usize = 1024;

/// A SCRAM mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    ScramSha256,
    ScramSha512,
}

impl Mechanism {
    pub fn name(self) -> &'static str {
        match self {
            Self::ScramSha256 => "SCRAM-SHA-256",
            Self::ScramSha512 => "SCRAM-SHA-512",
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_uppercase().as_str() {
            "SCRAM-SHA-256" => Ok(Self::ScramSha256),
            "SCRAM-SHA-512" => Ok(Self::ScramSha512),
            _ => Err(format!(
                "SASL mechanism {:?}: only SCRAM-SHA-256 and SCRAM-SHA-512 are supported",
                s.chars().take(40).collect::<String>()
            )),
        }
    }

    /// `H(data)` (RustCrypto `sha2`; its state is wiped on drop).
    fn hash(self, data: &[u8]) -> Vec<u8> {
        use sha2_11::Digest;
        match self {
            Self::ScramSha256 => sha2_11::Sha256::digest(data).to_vec(),
            Self::ScramSha512 => sha2_11::Sha512::digest(data).to_vec(),
        }
    }

    /// HMAC (RFC 2104) with this mechanism's hash: RustCrypto `hmac`, whose
    /// keyed inner / outer hash states are wiped on drop (`zeroize`).
    pub fn hmac(self, key: &[u8], msg: &[u8]) -> Vec<u8> {
        use hmac13::{KeyInit, Mac};
        fn run<M: Mac + KeyInit>(key: &[u8], msg: &[u8]) -> Vec<u8> {
            // HMAC takes keys of any length (longer ones are hashed).
            match <M as KeyInit>::new_from_slice(key) {
                Ok(mut m) => {
                    m.update(msg);
                    m.finalize().into_bytes().to_vec()
                }
                Err(_) => Vec::new(),
            }
        }
        match self {
            Self::ScramSha256 => run::<hmac13::Hmac<sha2_11::Sha256>>(key, msg),
            Self::ScramSha512 => run::<hmac13::Hmac<sha2_11::Sha512>>(key, msg),
        }
    }

    fn digest_len(self) -> usize {
        match self {
            Self::ScramSha256 => 32,
            Self::ScramSha512 => 64,
        }
    }

    /// `Hi(password, salt, i)` of RFC 5802: PBKDF2 (RustCrypto `pbkdf2`)
    /// with this HMAC, one block of the digest's length.
    pub fn hi(self, password: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
        let mut out = vec![0u8; self.digest_len()];
        // HMAC accepts any key length, so this cannot fail; were it to,
        // the empty result fails the exchange (the server signature does
        // not verify) instead of panicking.
        let ok = match self {
            Self::ScramSha256 => pbkdf2::pbkdf2::<hmac13::Hmac<sha2_11::Sha256>>(
                password, salt, iterations, &mut out,
            ),
            Self::ScramSha512 => pbkdf2::pbkdf2::<hmac13::Hmac<sha2_11::Sha512>>(
                password, salt, iterations, &mut out,
            ),
        };
        if ok.is_err() {
            out.zeroize();
            out.clear();
        }
        out
    }
}

/// SASL settings of the producer.
#[derive(Clone)]
pub struct SaslConfig {
    pub mechanism: Mechanism,
    pub username: String,
    password: String,
}

impl fmt::Debug for SaslConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SaslConfig")
            .field("mechanism", &self.mechanism)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl Drop for SaslConfig {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

impl SaslConfig {
    pub fn new(mechanism: Mechanism, username: &str, password: &str) -> Result<Self, String> {
        let ok = |s: &str| !s.is_empty() && s.len() <= MAX_CREDENTIAL_LEN && !s.contains('\0');
        if !ok(username) || username.chars().any(char::is_control) {
            return Err(format!(
                "SASL user name: 1..={MAX_CREDENTIAL_LEN} bytes, no control characters"
            ));
        }
        if !ok(password) {
            return Err(format!(
                "SASL password: 1..={MAX_CREDENTIAL_LEN} bytes, no NUL"
            ));
        }
        Ok(Self {
            mechanism,
            username: username.to_string(),
            password: password.to_string(),
        })
    }

    pub(crate) fn password(&self) -> &str {
        &self.password
    }
}

// --- base64 (RFC 4648, standard alphabet, padded) ---------------------------

/// Standard padded base64 (RustCrypto `base64ct`: constant time, so the
/// encoding of a proof or signature does not leak through timing).
pub fn b64_encode(data: &[u8]) -> String {
    use base64ct::Encoding;
    base64ct::Base64::encode_string(data)
}

/// Strict decoding: canonical padding only, no whitespace, no other
/// alphabet (`None` on anything else).
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    use base64ct::Encoding;
    base64ct::Base64::decode_vec(s).ok()
}

// --- SCRAM client ------------------------------------------------------------

/// `saslname` escaping of RFC 5802 §5.1.
fn escape_name(u: &str) -> String {
    u.replace('=', "=3D").replace(',', "=2C")
}

/// The client side of one SCRAM exchange.
pub struct ScramClient {
    mech: Mechanism,
    nonce: String,
    first_bare: String,
    server_signature: Option<Vec<u8>>,
}

impl Drop for ScramClient {
    fn drop(&mut self) {
        if let Some(s) = &mut self.server_signature {
            s.zeroize();
        }
    }
}

impl ScramClient {
    /// Start with a client nonce (printable, no `,`); see [`Self::start`].
    pub fn with_nonce(mech: Mechanism, username: &str, nonce: &str) -> Self {
        let first_bare = format!("n={},r={nonce}", escape_name(username));
        Self {
            mech,
            nonce: nonce.to_string(),
            first_bare,
            server_signature: None,
        }
    }

    /// Start with a fresh random nonce (24 bytes from the kernel CSPRNG).
    pub fn start(mech: Mechanism, username: &str) -> Result<Self, String> {
        let mut n = [0u8; 24];
        robodr_blackbox::crypto::fill_random(&mut n).map_err(|e| format!("SCRAM nonce: {e}"))?;
        Ok(Self::with_nonce(mech, username, &b64_encode(&n)))
    }

    /// `client-first-message` (GS2 header `n,,`: no channel binding).
    pub fn client_first(&self) -> String {
        format!("n,,{}", self.first_bare)
    }

    /// Answer `server-first-message` with `client-final-message`.
    pub fn client_final(&mut self, server_first: &str, password: &str) -> Result<String, String> {
        let mut nonce = None;
        let mut salt = None;
        let mut iters = None;
        for (i, attr) in server_first.split(',').enumerate() {
            let (k, v) = attr
                .split_once('=')
                .ok_or("SCRAM: malformed server-first-message")?;
            match (i, k) {
                (0, "m") => return Err("SCRAM: server requires an unsupported extension".into()),
                (0, "r") => nonce = Some(v),
                (1, "s") => salt = Some(v),
                (2, "i") => iters = Some(v),
                (0..=2, _) => return Err("SCRAM: malformed server-first-message".into()),
                _ => {}
            }
        }
        let (Some(nonce), Some(salt), Some(iters)) = (nonce, salt, iters) else {
            return Err("SCRAM: malformed server-first-message".into());
        };
        if !nonce.starts_with(&self.nonce) || nonce.len() <= self.nonce.len() {
            return Err("SCRAM: the server nonce does not extend the client nonce".into());
        }
        if !nonce
            .bytes()
            .all(|b| (0x21..0x7f).contains(&b) && b != b',')
        {
            return Err("SCRAM: malformed server nonce".into());
        }
        let salt = b64_decode(salt).ok_or("SCRAM: malformed salt")?;
        if salt.is_empty() {
            return Err("SCRAM: empty salt".into());
        }
        let iters: u32 = iters
            .parse()
            .map_err(|_| "SCRAM: malformed iteration count")?;
        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iters) {
            return Err(format!(
                "SCRAM: iteration count {iters} outside {MIN_ITERATIONS}..={MAX_ITERATIONS}"
            ));
        }
        let m = self.mech;
        let without_proof = format!("c=biws,r={nonce}");
        let auth_message = format!("{},{server_first},{without_proof}", self.first_bare);
        let mut salted = m.hi(password.as_bytes(), &salt, iters);
        let mut client_key = m.hmac(&salted, b"Client Key");
        let mut stored_key = m.hash(&client_key);
        let mut client_sig = m.hmac(&stored_key, auth_message.as_bytes());
        let mut proof: Vec<u8> = client_key
            .iter()
            .zip(&client_sig)
            .map(|(a, b)| a ^ b)
            .collect();
        let mut server_key = m.hmac(&salted, b"Server Key");
        self.server_signature = Some(m.hmac(&server_key, auth_message.as_bytes()));
        for v in [
            &mut salted,
            &mut client_key,
            &mut stored_key,
            &mut client_sig,
            &mut server_key,
        ] {
            v.zeroize();
        }
        let out = format!("{without_proof},p={}", b64_encode(&proof));
        proof.zeroize();
        Ok(out)
    }

    /// Check `server-final-message` (`v=` the server signature).
    pub fn verify_final(&self, server_final: &str) -> Result<(), String> {
        if let Some(e) = server_final.strip_prefix("e=") {
            return Err(format!(
                "SCRAM: server error {:?}",
                e.chars().take(80).collect::<String>()
            ));
        }
        let v = server_final
            .split(',')
            .next()
            .and_then(|a| a.strip_prefix("v="))
            .and_then(b64_decode)
            .ok_or("SCRAM: malformed server-final-message")?;
        match &self.server_signature {
            Some(s) if robodr_blackbox::crypto::ct_eq(s, &v) => Ok(()),
            Some(_) => Err(
                "SCRAM: the server signature does not verify (the broker does not know the \
                 credential)"
                    .into(),
            ),
            None => Err("SCRAM: server-final-message before client-final".into()),
        }
    }
}

// --- Wire --------------------------------------------------------------------

pub fn encode_handshake_request(mechanism: &str) -> Result<Vec<u8>, DecodeError> {
    let mut w = Writer::new();
    w.try_string(mechanism)?;
    Ok(w.buf)
}

/// SaslHandshake v1 response: `(error_code, enabled mechanisms)`.
pub fn decode_handshake_response(body: &[u8]) -> Result<(i16, Vec<String>), DecodeError> {
    let mut r = Reader::new(body);
    let code = r.i16()?;
    let n = r.array_len(2)?;
    let mut m = Vec::with_capacity(n.min(64));
    for _ in 0..n {
        m.push(r.string()?.to_string());
    }
    Ok((code, m))
}

pub fn encode_authenticate_request(auth: &[u8]) -> Result<Vec<u8>, DecodeError> {
    let mut w = Writer::new();
    w.try_nullable_bytes(Some(auth))?;
    Ok(w.buf)
}

/// A SaslAuthenticate v0/v1 response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticateResponse {
    pub error_code: i16,
    pub error_message: Option<String>,
    pub auth_bytes: Vec<u8>,
    /// v1: the broker's session lifetime (0: none).
    pub session_lifetime_ms: i64,
}

pub fn decode_authenticate_response(
    version: i16,
    body: &[u8],
) -> Result<AuthenticateResponse, DecodeError> {
    let mut r = Reader::new(body);
    let error_code = r.i16()?;
    let error_message = r.nullable_string()?.map(|s| s.chars().take(200).collect());
    let auth_bytes = match r.nullable_bytes()? {
        Some(b) => b.to_vec(),
        None => return derr("SaslAuthenticate: null auth_bytes"),
    };
    let session_lifetime_ms = if version >= 1 { r.i64()? } else { 0 };
    Ok(AuthenticateResponse {
        error_code,
        error_message,
        auth_bytes,
        session_lifetime_ms,
    })
}

/// Encoders of the broker side (test brokers only).
pub fn encode_handshake_response(code: i16, mechanisms: &[&str]) -> Vec<u8> {
    let mut w = Writer::new();
    w.i16(code);
    let _ = w.try_array_len(mechanisms.len());
    for m in mechanisms {
        let _ = w.try_string(m);
    }
    w.buf
}

/// See [`encode_handshake_response`].
pub fn encode_authenticate_response(version: i16, r: &AuthenticateResponse) -> Vec<u8> {
    let mut w = Writer::new();
    w.i16(r.error_code);
    let _ = w.try_nullable_string(r.error_message.as_deref());
    let _ = w.try_nullable_bytes(Some(&r.auth_bytes));
    if version >= 1 {
        w.i64(r.session_lifetime_ms);
    }
    w.buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_and_rejects_garbage() {
        for (raw, enc) in [
            (&b""[..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(b64_encode(raw), enc);
            assert_eq!(b64_decode(enc).as_deref(), Some(raw));
        }
        for bad in ["Zg=", "Z===", "Zg==Zg==", "Zm9v!A==", "===="] {
            assert_eq!(b64_decode(bad), None, "{bad}");
        }
    }

    /// RFC 7677 §3 (SCRAM-SHA-256), user "user", password "pencil".
    #[test]
    fn rfc7677_vector() {
        let mut c = ScramClient::with_nonce(Mechanism::ScramSha256, "user", "rOprNGfwEbeRWgbNEkqO");
        assert_eq!(c.client_first(), "n,,n=user,r=rOprNGfwEbeRWgbNEkqO");
        let sf = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,\
                  s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        assert_eq!(
            c.client_final(sf, "pencil").unwrap(),
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,\
             p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );
        assert!(c
            .verify_final("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")
            .is_ok());
        assert!(c
            .verify_final("v=7rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")
            .is_err());
        assert!(c.verify_final("e=invalid-proof").is_err());
    }

    /// RFC 4231 test case 2 (HMAC-SHA-256 / -512, key "Jefe").
    #[test]
    fn hmac_vectors() {
        let m = b"what do ya want for nothing?";
        assert_eq!(
            robodr_blackbox::crypto::to_hex(&Mechanism::ScramSha256.hmac(b"Jefe", m)),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            robodr_blackbox::crypto::to_hex(&Mechanism::ScramSha512.hmac(b"Jefe", m)),
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a\
             6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        );
    }

    /// RFC 4231 test case 6: a key longer than the block (hashed first).
    #[test]
    fn hmac_long_key_vectors() {
        let key = [0xaau8; 131];
        let m = b"Test Using Larger Than Block-Size Key - Hash Key First";
        assert_eq!(
            robodr_blackbox::crypto::to_hex(&Mechanism::ScramSha256.hmac(&key, m)),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
        assert_eq!(
            robodr_blackbox::crypto::to_hex(&Mechanism::ScramSha512.hmac(&key, m)),
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352\
             6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
        );
    }

    /// PBKDF2-HMAC-SHA-256 of RFC 7914 §11 (its first block: `Hi` is
    /// exactly one block of the digest's length).
    #[test]
    fn hi_is_one_pbkdf2_block() {
        assert_eq!(
            robodr_blackbox::crypto::to_hex(&Mechanism::ScramSha256.hi(b"passwd", b"salt", 1)),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        );
        assert_eq!(
            robodr_blackbox::crypto::to_hex(&Mechanism::ScramSha256.hi(
                b"Password",
                b"NaCl",
                80_000
            )),
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
        );
        assert_eq!(Mechanism::ScramSha512.hi(b"pw", b"salt", 4096).len(), 64);
    }

    /// The previous in-crate HMAC / PBKDF2 / base64, kept as an
    /// independent reference (over `robodr_blackbox::crypto`'s SHA-2).
    mod reference {
        use super::Mechanism;
        use robodr_blackbox::crypto::{Sha256, Sha512};

        fn hash(m: Mechanism, parts: &[&[u8]]) -> Vec<u8> {
            match m {
                Mechanism::ScramSha256 => {
                    let mut h = Sha256::new();
                    parts.iter().for_each(|p| h.update(p));
                    h.finalize().to_vec()
                }
                Mechanism::ScramSha512 => {
                    let mut h = Sha512::new();
                    parts.iter().for_each(|p| h.update(p));
                    h.finalize().to_vec()
                }
            }
        }

        pub fn hmac(m: Mechanism, key: &[u8], msg: &[u8]) -> Vec<u8> {
            let b = match m {
                Mechanism::ScramSha256 => 64,
                Mechanism::ScramSha512 => 128,
            };
            let kh;
            let key = if key.len() > b {
                kh = hash(m, &[key]);
                &kh[..]
            } else {
                key
            };
            let mut k0 = vec![0u8; b];
            k0[..key.len()].copy_from_slice(key);
            let ipad: Vec<u8> = k0.iter().map(|k| k ^ 0x36).collect();
            let opad: Vec<u8> = k0.iter().map(|k| k ^ 0x5c).collect();
            let ih = hash(m, &[&ipad, msg]);
            hash(m, &[&opad, &ih])
        }

        pub fn hi(m: Mechanism, pw: &[u8], salt: &[u8], iters: u32) -> Vec<u8> {
            let mut s = salt.to_vec();
            s.extend_from_slice(&1u32.to_be_bytes());
            let mut u = hmac(m, pw, &s);
            let mut out = u.clone();
            for _ in 1..iters {
                u = hmac(m, pw, &u);
                out.iter_mut().zip(&u).for_each(|(o, x)| *o ^= x);
            }
            out
        }

        pub fn b64(data: &[u8]) -> String {
            const A: &[u8; 64] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut out = String::new();
            for c in data.chunks(3) {
                let n = (u32::from(c[0]) << 16)
                    | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
                    | u32::from(*c.get(2).unwrap_or(&0));
                for (i, sh) in [18u32, 12, 6, 0].iter().enumerate() {
                    out.push(if i <= c.len() {
                        char::from(A[((n >> sh) & 63) as usize])
                    } else {
                        '='
                    });
                }
            }
            out
        }
    }

    /// The crates against the reference: key lengths around both block
    /// sizes, salts and iteration counts, every base64 tail length.
    #[test]
    fn crates_agree_with_the_reference() {
        for m in [Mechanism::ScramSha256, Mechanism::ScramSha512] {
            for klen in [0usize, 1, 31, 32, 63, 64, 65, 127, 128, 129, 300] {
                let key: Vec<u8> = (0..klen).map(|i| (i * 7 + 3) as u8).collect();
                for msg in [&b""[..], b"Client Key", &[0xffu8; 200][..]] {
                    assert_eq!(
                        m.hmac(&key, msg),
                        reference::hmac(m, &key, msg),
                        "{m:?} {klen}"
                    );
                }
            }
            for (pw, salt, n) in [
                (&b"pencil"[..], &b"\x5b\x6d\x99\x68"[..], 1u32),
                (b"pencil", b"salt-salt-salt", 2),
                (b"p", b"s", 4096),
            ] {
                assert_eq!(m.hi(pw, salt, n), reference::hi(m, pw, salt, n));
            }
        }
        for len in 0..40usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let enc = b64_encode(&data);
            assert_eq!(enc, reference::b64(&data), "{len}");
            assert_eq!(b64_decode(&enc), Some(data));
        }
    }

    /// Non-canonical base64 (padding bits set) is refused: a salt or a
    /// server signature has exactly one encoding.
    #[test]
    fn base64_is_canonical() {
        assert_eq!(b64_decode("Zg=="), Some(b"f".to_vec()));
        for bad in ["Zh==", "Zm9=", "Zg==\n", " Zg==", "Zg", "Zm9v\r\n"] {
            assert_eq!(b64_decode(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn hostile_server_first_messages_are_refused() {
        let mk = || ScramClient::with_nonce(Mechanism::ScramSha512, "u,=x", "abc");
        assert_eq!(mk().client_first(), "n,,n=u=2C=3Dx,r=abc");
        for sf in [
            "r=xyz123,s=c2FsdA==,i=4096", // nonce does not extend ours
            "r=abc,s=c2FsdA==,i=4096",    // nonce not extended
            "r=abcd,s=c2FsdA==,i=4095",   // downgraded iteration count
            "r=abcd,s=c2FsdA==,i=100001", // CPU exhaustion
            "r=abcd,s=,i=4096",           // empty salt
            "r=abcd,s=***,i=4096",        // bad base64
            "m=ext,r=abcd,s=c2FsdA==,i=4096",
            "s=c2FsdA==,r=abcd,i=4096",
            "r=abcd,s=c2FsdA==",
            "garbage",
        ] {
            assert!(mk().client_final(sf, "pw").is_err(), "{sf}");
        }
        // Before client-final nothing verifies.
        assert!(mk().verify_final("v=AAAA").is_err());
        assert!(SaslConfig::new(Mechanism::ScramSha256, "", "pw").is_err());
        assert!(SaslConfig::new(Mechanism::ScramSha256, "u", "").is_err());
        assert!(SaslConfig::new(Mechanism::ScramSha256, "u\n", "pw").is_err());
        let c = SaslConfig::new(Mechanism::ScramSha256, "u", "secret-pw").unwrap();
        assert!(!format!("{c:?}").contains("secret-pw"));
        assert!(Mechanism::parse("PLAIN").is_err());
        assert_eq!(
            Mechanism::parse("scram-sha-512"),
            Ok(Mechanism::ScramSha512)
        );
    }

    #[test]
    fn wire_round_trips() {
        let b = encode_handshake_response(0, &["SCRAM-SHA-256", "PLAIN"]);
        assert_eq!(
            decode_handshake_response(&b).unwrap(),
            (0, vec!["SCRAM-SHA-256".to_string(), "PLAIN".to_string()])
        );
        let r = AuthenticateResponse {
            error_code: 58,
            error_message: Some("no".into()),
            auth_bytes: b"x".to_vec(),
            session_lifetime_ms: 9,
        };
        for v in [0, 1] {
            let d = decode_authenticate_response(v, &encode_authenticate_response(v, &r)).unwrap();
            assert_eq!(d.auth_bytes, b"x");
            assert_eq!(d.session_lifetime_ms, if v == 1 { 9 } else { 0 });
        }
        assert!(decode_authenticate_response(1, &[0, 0]).is_err());
    }
}
