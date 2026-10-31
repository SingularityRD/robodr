//! minisign signature verification (the release signatures of
//! `.github/workflows/release.yml`), so the robot can check a release
//! bundle with RoboDR's own code instead of depending on the `minisign`
//! program (`packaging/install-bundle.sh`, `robodr-deliverd
//! verify-minisign`).
//!
//! Formats (minisign 0.10+, <https://jedisct1.github.io/minisign/>):
//!
//! * public key file: `untrusted comment: ...` then base64 of
//!   `"Ed" || key_id[8] || ed25519_public[32]`;
//! * signature file: `untrusted comment: ...`, base64 of
//!   `"ED" || key_id[8] || sig[64]`, `trusted comment: <text>`, base64 of
//!   `global_sig[64]`.
//!
//! `sig` is Ed25519 over BLAKE2b-512 of the file ("prehashed", `ED`);
//! `global_sig` is Ed25519 over `sig || <text>`, so the trusted comment
//! (which names the release and the file) is signed too.
//!
//! What is refused (stricter than `minisign -V`, never looser):
//!
//! * legacy non-prehashed `Ed` signatures (`minisign -S -l`): every
//!   RoboDR release is signed prehashed, and the legacy form would make
//!   the verifier hold the whole file in memory (`minisign -V -H`
//!   behaves the same);
//! * a key id that differs from the pinned key's;
//! * non-canonical base64, extra lines, a trusted comment with control
//!   characters or over [`MAX_TRUSTED_COMMENT`] bytes, files over
//!   [`MAX_FILE`] bytes;
//! * Ed25519 is `robodr-blackbox`'s strict verification (non-canonical
//!   `S`, small-order `R` or `A` refused).
//!
//! No I/O: the caller hashes the file with [`Blake2b512`] and passes the
//! digest.

use crate::blake2b::{Blake2b512, OUT_LEN};
use crate::common::{Code, Refusal};
use robodr_blackbox::sign_ed25519;

/// Largest public key or signature file accepted (bytes).
pub const MAX_FILE: usize = 4096;
/// Largest trusted comment (minisign's own limit).
pub const MAX_TRUSTED_COMMENT: usize = 1024;

const UNTRUSTED: &str = "untrusted comment: ";
const TRUSTED: &str = "trusted comment: ";

fn refuse(code: Code, detail: impl Into<String>) -> Refusal {
    let mut d: String = detail.into();
    if d.len() > 200 {
        let mut cut = 200;
        while !d.is_char_boundary(cut) {
            cut -= 1;
        }
        d.truncate(cut);
    }
    Refusal { code, detail: d }
}

/// A minisign public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub key_id: [u8; 8],
    pub key: [u8; 32],
}

/// A parsed minisign signature file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub key_id: [u8; 8],
    sig: [u8; 64],
    /// The trusted comment (signed by the global signature).
    pub trusted_comment: String,
    global: [u8; 64],
}

/// minisign's display form of a key id (upper-case hex of the
/// little-endian 64-bit number), as `minisign -G` prints it.
pub fn key_id_hex(id: &[u8; 8]) -> String {
    id.iter().rev().map(|b| format!("{b:02X}")).collect()
}

fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Strict standard base64 with padding; the unused bits of the last
/// symbol must be zero (one encoding per value).
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.is_empty() || !b.len().is_multiple_of(4) {
        return None;
    }
    let pad = b.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 {
        return None;
    }
    let body = b.get(..b.len() - pad)?;
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &c in body {
        acc = (acc << 6) | u32::from(b64_val(c)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // Leftover bits must be zero and match the padding.
    if acc != 0 || (pad == 1 && bits != 2) || (pad == 2 && bits != 4) || (pad == 0 && bits != 0) {
        return None;
    }
    Some(out)
}

/// The lines of a small text file: UTF-8, `\n` (optionally `\r\n`)
/// separated, at most one trailing newline.
fn lines(bytes: &[u8], what: &str) -> Result<Vec<String>, Refusal> {
    if bytes.len() > MAX_FILE {
        return Err(refuse(
            Code::TooLarge,
            format!("{what} over {MAX_FILE} bytes"),
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| refuse(Code::Malformed, format!("{what} is not UTF-8")))?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    Ok(text
        .split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l).to_string())
        .collect())
}

fn fixed<const N: usize>(v: &[u8]) -> Option<[u8; N]> {
    <[u8; N]>::try_from(v).ok()
}

impl PublicKey {
    /// From the base64 key string alone (`minisign -P`).
    pub fn from_base64(s: &str) -> Result<Self, Refusal> {
        let raw = b64_decode(s.trim())
            .ok_or_else(|| refuse(Code::Malformed, "public key: not canonical base64"))?;
        if raw.len() != 42 {
            return Err(refuse(Code::Malformed, "public key: wrong length"));
        }
        let (alg, rest) = raw.split_at(2);
        if alg != b"Ed" {
            return Err(refuse(
                Code::Unsupported,
                "public key: not an Ed25519 minisign key",
            ));
        }
        let (id, key) = rest.split_at(8);
        Ok(Self {
            key_id: fixed(id).ok_or_else(|| refuse(Code::Malformed, "public key: key id"))?,
            key: fixed(key).ok_or_else(|| refuse(Code::Malformed, "public key: key"))?,
        })
    }

    /// From a public key file (`minisign -p`).
    pub fn parse(bytes: &[u8]) -> Result<Self, Refusal> {
        let l = lines(bytes, "public key file")?;
        match l.as_slice() {
            [c, k] if c.starts_with(UNTRUSTED) => Self::from_base64(k),
            _ => Err(refuse(
                Code::Malformed,
                "public key file: want an untrusted comment line and the key line",
            )),
        }
    }
}

impl Signature {
    /// Parse a `.minisig` file.
    pub fn parse(bytes: &[u8]) -> Result<Self, Refusal> {
        let l = lines(bytes, "signature file")?;
        let [c, s, t, g] = l.as_slice() else {
            return Err(refuse(
                Code::Malformed,
                "signature file: want exactly four lines",
            ));
        };
        if !c.starts_with(UNTRUSTED) {
            return Err(refuse(
                Code::Malformed,
                "signature file: no untrusted comment line",
            ));
        }
        let raw = b64_decode(s)
            .ok_or_else(|| refuse(Code::Malformed, "signature: not canonical base64"))?;
        if raw.len() != 74 {
            return Err(refuse(Code::Malformed, "signature: wrong length"));
        }
        let (alg, rest) = raw.split_at(2);
        match alg {
            b"ED" => {}
            b"Ed" => {
                return Err(refuse(
                    Code::Unsupported,
                    "legacy (non-prehashed) minisign signature: RoboDR releases are signed \
                     prehashed (minisign 0.10+ default, never -l)",
                ))
            }
            _ => return Err(refuse(Code::Unsupported, "signature: unknown algorithm")),
        }
        let (id, sig) = rest.split_at(8);
        let tc = t
            .strip_prefix(TRUSTED)
            .ok_or_else(|| refuse(Code::Malformed, "signature file: no trusted comment line"))?;
        if tc.len() > MAX_TRUSTED_COMMENT {
            return Err(refuse(Code::TooLarge, "trusted comment too long"));
        }
        if tc.chars().any(|ch| ch.is_control() && ch != '\t') {
            return Err(refuse(
                Code::Invalid,
                "trusted comment has control characters",
            ));
        }
        let global = b64_decode(g).and_then(|v| fixed::<64>(&v)).ok_or_else(|| {
            refuse(
                Code::Malformed,
                "global signature: not 64 bytes of canonical base64",
            )
        })?;
        Ok(Self {
            key_id: fixed(id).ok_or_else(|| refuse(Code::Malformed, "signature: key id"))?,
            sig: fixed(sig).ok_or_else(|| refuse(Code::Malformed, "signature: bytes"))?,
            trusted_comment: tc.to_string(),
            global,
        })
    }

    /// Check this signature by `pk` over a file whose BLAKE2b-512 is
    /// `digest`, and its trusted comment. Returns the trusted comment.
    pub fn verify_digest(&self, pk: &PublicKey, digest: &[u8; OUT_LEN]) -> Result<&str, Refusal> {
        if self.key_id != pk.key_id {
            return Err(refuse(
                Code::UnknownKey,
                format!(
                    "signed by key {}, not by the pinned key {}",
                    key_id_hex(&self.key_id),
                    key_id_hex(&pk.key_id)
                ),
            ));
        }
        if !sign_ed25519::verify(&pk.key, digest, &self.sig) {
            return Err(refuse(
                Code::BadSignature,
                "signature does not verify for this file",
            ));
        }
        let mut m = Vec::with_capacity(64 + self.trusted_comment.len());
        m.extend_from_slice(&self.sig);
        m.extend_from_slice(self.trusted_comment.as_bytes());
        if !sign_ed25519::verify(&pk.key, &m, &self.global) {
            return Err(refuse(
                Code::BadSignature,
                "the trusted comment's signature does not verify (comment altered)",
            ));
        }
        Ok(&self.trusted_comment)
    }

    /// [`Self::verify_digest`] over `data` held in memory.
    pub fn verify(&self, pk: &PublicKey, data: &[u8]) -> Result<&str, Refusal> {
        let mut h = Blake2b512::new();
        h.update(data);
        self.verify_digest(pk, &h.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Made with minisign 0.11 (`-G -W`, `-S -t "robodr 0.1.0 f"`, and
    // `-S -l` for the legacy form) over FILE.
    const FILE: &[u8] = b"robodr minisign fixture\n";
    const PUB: &str = "untrusted comment: minisign public key 449F1A6A159EC097\n\
        RWSXwJ4VahqfRNkH47hg/lslMnEr9VK4A6iMo0vbcHIu+AJJeJ5woqxf\n";
    const SIG: &str = "untrusted comment: signature from minisign secret key\n\
        RUSXwJ4VahqfRBAZYlck+aZqCDxVxpZZFcy2GsXI+p9QYwMTpAtukjdQ6do3bmwmKuYw4gW6pUBpwoakeUXsXh4k3UfNA+ENUwE=\n\
        trusted comment: robodr 0.1.0 f\n\
        FdTqD3Z6+DWSv/buzVqtrYhZeyfUkKVQjuIz6oG1NyBoMknkYwaXzPv/QlRUEPbatidMlnwGGxQ86oJvao/UDw==\n";
    const LEGACY: &str = "untrusted comment: signature from minisign secret key\n\
        RWSXwJ4VahqfRNxNVcyEHxAOjteRTcfo3VTg7pCEGWPIcU5UgF7hK5MSOeK639yRGH2BNZQ2AugG2xxOuKT6V1CzEi4z5HUoiwE=\n\
        trusted comment: robodr 0.1.0 f\n\
        TitMlioluvL5GaAOB1gF4TfOgK16fpQ6RfdvgFlifAFm/vCFSoX+6uadO1ctCYDNdwJz1yB79ZT6XXiv0bYUBg==\n";
    const OTHER_PUB: &str = "untrusted comment: minisign public key 8640313FA20CA9A6\n\
        RWSmqQyiPzFAhg0/V7Dt05JWBCfsstMxDCPsjDE6CQHp66dFsFjnQoYs\n";

    #[test]
    fn verifies_a_real_minisign_signature() {
        let pk = PublicKey::parse(PUB.as_bytes()).unwrap();
        assert_eq!(key_id_hex(&pk.key_id), "449F1A6A159EC097");
        let s = Signature::parse(SIG.as_bytes()).unwrap();
        assert_eq!(s.verify(&pk, FILE).unwrap(), "robodr 0.1.0 f");
    }

    #[test]
    fn refuses_other_bytes_keys_comments_and_legacy() {
        let pk = PublicKey::parse(PUB.as_bytes()).unwrap();
        let s = Signature::parse(SIG.as_bytes()).unwrap();
        assert_eq!(
            s.verify(&pk, b"robodr minisign fixture!\n")
                .unwrap_err()
                .code,
            Code::BadSignature
        );
        let other = PublicKey::parse(OTHER_PUB.as_bytes()).unwrap();
        assert_eq!(s.verify(&other, FILE).unwrap_err().code, Code::UnknownKey);
        // Same key id, other key bytes: the signature itself fails.
        let mut forged = other.clone();
        forged.key_id = pk.key_id;
        assert_eq!(
            s.verify(&forged, FILE).unwrap_err().code,
            Code::BadSignature
        );
        // A renamed trusted comment (a signed file passed off as another).
        let renamed = SIG.replace("robodr 0.1.0 f", "robodr 0.1.0 g");
        let r = Signature::parse(renamed.as_bytes()).unwrap();
        let e = r.verify(&pk, FILE).unwrap_err();
        assert_eq!(e.code, Code::BadSignature);
        assert!(e.detail.contains("trusted comment"), "{e:?}");
        assert_eq!(
            Signature::parse(LEGACY.as_bytes()).unwrap_err().code,
            Code::Unsupported
        );
    }

    #[test]
    fn refuses_malformed_files() {
        let bad: Vec<String> = vec![
            String::new(),
            SIG.lines().take(3).collect::<Vec<_>>().join("\n"),
            format!("{SIG}extra\n"),
            SIG.replace("untrusted comment:", "comment:"),
            SIG.replace("trusted comment: robodr", "trusted: robodr"),
            // Non-canonical base64 (last symbol's unused bits set).
            SIG.replace("Dw==\n", "Dx==\n"),
            SIG.replace("UwE=", "UwE"),
            SIG.replace("robodr 0.1.0 f", "robodr\u{7}0.1.0 f"),
            SIG.replace("robodr 0.1.0 f", &"x".repeat(MAX_TRUSTED_COMMENT + 1)),
            "x".repeat(MAX_FILE + 1),
        ];
        for b in &bad {
            assert!(Signature::parse(b.as_bytes()).is_err(), "{b:?}");
        }
        assert!(PublicKey::parse(b"untrusted comment: x\n").is_err());
        assert!(PublicKey::parse(PUB.replace("RWS", "RXS").as_bytes()).is_err());
        assert!(PublicKey::from_base64("RWSXwJ4VahqfRNkH47hg").is_err());
        // \r\n line ends are accepted, as minisign does.
        let crlf = SIG.replace('\n', "\r\n");
        let pk = PublicKey::parse(PUB.replace('\n', "\r\n").as_bytes()).unwrap();
        assert!(Signature::parse(crlf.as_bytes())
            .unwrap()
            .verify(&pk, FILE)
            .is_ok());
    }

    /// Deterministic mutation smoke run: no input panics.
    #[test]
    fn mutated_inputs_never_panic() {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let pk = PublicKey::parse(PUB.as_bytes()).unwrap();
        for _ in 0..20_000 {
            let mut b = SIG.as_bytes().to_vec();
            for _ in 0..(next() % 4 + 1) {
                let i = (next() as usize) % b.len();
                match next() % 3 {
                    0 => b[i] = next() as u8,
                    1 => {
                        b.remove(i);
                    }
                    _ => b.insert(i, next() as u8),
                }
            }
            if let Ok(s) = Signature::parse(&b) {
                let _ = s.verify(&pk, FILE);
            }
            let _ = PublicKey::parse(&b);
        }
    }

    /// Fresh key pairs and files signed by the real minisign (skipped
    /// where it is not installed): every size around BLAKE2b's block.
    #[test]
    fn agrees_with_the_minisign_program() {
        let have = std::process::Command::new("minisign")
            .arg("-v")
            .output()
            .is_ok_and(|o| o.status.success());
        if !have {
            eprintln!("SKIPPED agrees_with_the_minisign_program: no minisign");
            return;
        }
        let d = std::env::temp_dir().join(format!("robodr-pkg-minisign-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let run = |args: &[&str]| {
            let o = std::process::Command::new("minisign")
                .args(args)
                .current_dir(&d)
                .stdin(std::process::Stdio::null())
                .output()
                .unwrap();
            assert!(o.status.success(), "{o:?}");
        };
        run(&["-G", "-W", "-p", "k.pub", "-s", "k.sec"]);
        let pk = PublicKey::parse(&std::fs::read(d.join("k.pub")).unwrap()).unwrap();
        for n in [0usize, 1, 127, 128, 129, 256, 1000, 70_000] {
            let data: Vec<u8> = (0..n).map(|i| (i * 31 + n) as u8).collect();
            std::fs::write(d.join("f"), &data).unwrap();
            let tc = format!("robodr 9.9.9 file-{n}");
            run(&["-S", "-s", "k.sec", "-m", "f", "-t", &tc]);
            let s = Signature::parse(&std::fs::read(d.join("f.minisig")).unwrap()).unwrap();
            assert_eq!(s.verify(&pk, &data).unwrap(), tc);
            let mut flipped = data.clone();
            flipped.push(0);
            assert!(s.verify(&pk, &flipped).is_err());
        }
        let _ = std::fs::remove_dir_all(&d);
    }
}
