//! systemd encrypted credentials (`systemd-creds encrypt`,
//! `LoadCredentialEncrypted=`): what key protects one at rest.
//!
//! An encrypted credential starts with a 16-byte id naming the sealing
//! scheme (systemd `src/shared/creds-util.h`, the `CRED_AES256_GCM_BY_*`
//! ids; checked against the constants in `libsystemd-shared-255.so` and
//! against files written by `systemd-creds` 255 with `--with-key=host`,
//! `tpm2`, `host+tpm2` and `tpm2-absent`). The file is base64 (the
//! `systemd-creds` default) or raw binary; both are recognised. Only the
//! header is read: classifying a credential never decrypts it.
//!
//! What this tells and what it does not:
//!
//! * `tpm2` / `host+tpm2`: the credential can only be decrypted on this
//!   machine's TPM (with `host+tpm2` also only with the root-only
//!   `/var/lib/systemd/credential.secret`). A copied disk image or a
//!   stolen SD card does not yield the key.
//! * `host`: encrypted with a key **file** on the same disk; protects
//!   against nothing a disk copy cannot also read.
//! * `null`: `--with-key=tpm2-absent` / null key: integrity only, **no
//!   confidentiality**.
//! * Once systemd has decrypted the credential for the service, the key is
//!   in the service's private credential ramfs and in its memory: TPM
//!   sealing protects keys **at rest**, not against root or the service
//!   user at run time (the TPM does not perform the signatures).

use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Length of the header id.
pub const ID_LEN: usize = 16;

/// `CRED_AES256_GCM_BY_HOST`.
const BY_HOST: [u8; ID_LEN] = hex16(*b"5a1c6a86df9d4096b1d5a65e0862f19a");
/// `CRED_AES256_GCM_BY_TPM2_HMAC`.
const BY_TPM2_HMAC: [u8; ID_LEN] = hex16(*b"0c7cc07b117645919c4b0bea08bc20fe");
/// `CRED_AES256_GCM_BY_TPM2_HMAC_WITH_PK` (signed PCR policy).
const BY_TPM2_HMAC_WITH_PK: [u8; ID_LEN] = hex16(*b"faf7eb9341e3412ca1a436f95a29362f");
/// `CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC`.
const BY_HOST_AND_TPM2_HMAC: [u8; ID_LEN] = hex16(*b"93a894094874449090caf2fc93cab553");
/// `CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK`.
const BY_HOST_AND_TPM2_HMAC_WITH_PK: [u8; ID_LEN] = hex16(*b"af4950a849134eb1a73846304ff30c05");
/// `CRED_AES256_GCM_BY_NULL` (`tpm2-absent`: no confidentiality).
const BY_NULL: [u8; ID_LEN] = hex16(*b"058469daf6f54324800549da0f8ea2fb");

/// Smallest header systemd writes: the id plus four little-endian u32
/// sizes (key, block, IV, tag).
const MIN_HEADER_LEN: usize = ID_LEN + 16;

/// The sealing scheme of an encrypted credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialSeal {
    /// TPM2 only (optionally with a signed PCR policy).
    Tpm2,
    /// The host key **and** the TPM2.
    HostAndTpm2,
    /// The host key file only (`/var/lib/systemd/credential.secret`).
    Host,
    /// The null key: authenticity only, no confidentiality.
    Null,
    /// A systemd credential header id this version does not know.
    Unknown,
}

impl CredentialSeal {
    /// `"tpm2"`, `"host+tpm2"`, `"host"`, `"null"` or `"unknown"`.
    pub fn as_str(self) -> &'static str {
        match self {
            CredentialSeal::Tpm2 => "tpm2",
            CredentialSeal::HostAndTpm2 => "host+tpm2",
            CredentialSeal::Host => "host",
            CredentialSeal::Null => "null",
            CredentialSeal::Unknown => "unknown",
        }
    }

    /// Decrypting needs this machine's TPM.
    pub fn tpm2_bound(self) -> bool {
        matches!(self, CredentialSeal::Tpm2 | CredentialSeal::HostAndTpm2)
    }
}

fn seal_of(id: &[u8; ID_LEN]) -> Option<CredentialSeal> {
    Some(match *id {
        BY_TPM2_HMAC | BY_TPM2_HMAC_WITH_PK => CredentialSeal::Tpm2,
        BY_HOST_AND_TPM2_HMAC | BY_HOST_AND_TPM2_HMAC_WITH_PK => CredentialSeal::HostAndTpm2,
        BY_HOST => CredentialSeal::Host,
        BY_NULL => CredentialSeal::Null,
        _ => return None,
    })
}

/// Classify an encrypted credential from its first bytes (base64 or
/// binary). `Err` when the bytes are not a systemd encrypted credential at
/// all (a plain key file, for instance); [`CredentialSeal::Unknown`] when
/// they look like one with an id this version does not know.
pub fn classify(bytes: &[u8]) -> Result<CredentialSeal, String> {
    // Binary form: the id is the first 16 bytes.
    if let Some(id) = bytes
        .get(..ID_LEN)
        .and_then(|b| <[u8; ID_LEN]>::try_from(b).ok())
    {
        if let Some(s) = seal_of(&id) {
            if bytes.len() < MIN_HEADER_LEN {
                return Err("truncated systemd credential header".into());
            }
            return Ok(s);
        }
    }
    // Base64 form (what `systemd-creds encrypt` writes by default; line
    // breaks allowed).
    let header = base64_prefix(bytes, MIN_HEADER_LEN)
        .ok_or("not a systemd encrypted credential (neither its binary nor base64 form)")?;
    let id = header
        .get(..ID_LEN)
        .and_then(|b| <[u8; ID_LEN]>::try_from(b).ok())
        .ok_or("truncated systemd credential header")?;
    if let Some(s) = seal_of(&id) {
        return Ok(s);
    }
    // A well-formed header with an unknown id: the four sizes systemd
    // writes are small (key 32, block 1..=64, IV 1..=64, tag 16).
    let size = |i: usize| -> Option<u32> {
        header
            .get(ID_LEN + 4 * i..ID_LEN + 4 * i + 4)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map(u32::from_le_bytes)
    };
    match (size(0), size(1), size(2), size(3)) {
        (Some(1..=64), Some(1..=64), Some(1..=64), Some(1..=64)) => Ok(CredentialSeal::Unknown),
        _ => Err("not a systemd encrypted credential (unknown header)".into()),
    }
}

/// [`classify`] the file at `path` (its first 4 KiB; the file is not
/// decrypted).
pub fn classify_file(path: &Path) -> Result<CredentialSeal, String> {
    let f = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut buf = Vec::with_capacity(4096);
    f.take(4096)
        .read_to_end(&mut buf)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    classify(&buf).map_err(|e| format!("{}: {e}", path.display()))
}

/// Decode the first `want` bytes of standard base64 text (whitespace
/// skipped). `None` on any other character before `want` bytes are out.
fn base64_prefix(text: &[u8], want: usize) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    }
    let mut out = Vec::with_capacity(want + 2);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &c in text {
        if out.len() >= want {
            break;
        }
        if c.is_ascii_whitespace() {
            continue;
        }
        acc = (acc << 6) | val(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    (out.len() >= want).then(|| {
        out.truncate(want);
        out
    })
}

/// 32 hex digits to 16 bytes at compile time (a bad digit fails the build:
/// the `panic!` and the indexing only ever run in const evaluation).
#[allow(clippy::panic, clippy::indexing_slicing)]
const fn hex16(h: [u8; 32]) -> [u8; ID_LEN] {
    const fn nib(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("bad hex digit"),
        }
    }
    let mut out = [0u8; ID_LEN];
    let mut i = 0;
    while i < ID_LEN {
        out[i] = (nib(h[2 * i]) << 4) | nib(h[2 * i + 1]);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Headers of credentials written by `systemd-creds` 255 (base64, the
    /// first line of each file, cut after the header sizes).
    const HOST_B64: &str =
        "Whxqht+dQJax1aZeCGLxmiAAAAABAAAADAAAABAAAADthhR/nRa8rFd00foAAAAAijVSZLtVJcEdEGl";

    fn b64(bytes: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for ch in bytes.chunks(3) {
            let n = ch
                .iter()
                .enumerate()
                .fold(0u32, |a, (i, b)| a | (*b as u32) << (16 - 8 * i));
            for i in 0..=ch.len() {
                s.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
            }
        }
        s
    }

    fn header(id: [u8; 16]) -> Vec<u8> {
        let mut v = id.to_vec();
        for n in [32u32, 1, 12, 16] {
            v.extend_from_slice(&n.to_le_bytes());
        }
        v.extend_from_slice(&[0xab; 40]);
        v
    }

    #[test]
    fn real_systemd_header_is_host() {
        assert_eq!(classify(HOST_B64.as_bytes()).unwrap(), CredentialSeal::Host);
    }

    #[test]
    fn every_known_id_in_both_forms() {
        for (id, want) in [
            (BY_TPM2_HMAC, CredentialSeal::Tpm2),
            (BY_TPM2_HMAC_WITH_PK, CredentialSeal::Tpm2),
            (BY_HOST_AND_TPM2_HMAC, CredentialSeal::HostAndTpm2),
            (BY_HOST_AND_TPM2_HMAC_WITH_PK, CredentialSeal::HostAndTpm2),
            (BY_HOST, CredentialSeal::Host),
            (BY_NULL, CredentialSeal::Null),
        ] {
            let h = header(id);
            assert_eq!(classify(&h).unwrap(), want);
            assert_eq!(classify(b64(&h).as_bytes()).unwrap(), want);
            // Line-wrapped base64.
            let wrapped: String = b64(&h)
                .as_bytes()
                .chunks(10)
                .map(|c| format!("{}\n", std::str::from_utf8(c).unwrap()))
                .collect();
            assert_eq!(classify(wrapped.as_bytes()).unwrap(), want);
            assert_eq!(
                want.tpm2_bound(),
                matches!(want, CredentialSeal::Tpm2 | CredentialSeal::HostAndTpm2)
            );
        }
    }

    #[test]
    fn plain_keys_and_garbage_are_not_credentials() {
        // A robodr-blackbox key file, a PEM key, hex, empty.
        for t in [
            &br#"{"format":"robodr-blackbox-key/v2","kind":"secret"}"#[..],
            b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEI\n",
            b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            b"",
            b"Whxq",
        ] {
            assert!(classify(t).is_err(), "{}", String::from_utf8_lossy(t));
        }
        // Truncated binary header with a known id.
        assert!(classify(&BY_TPM2_HMAC).is_err());
    }

    #[test]
    fn unknown_ids_with_a_sane_header_are_unknown() {
        let h = header([0x42; 16]);
        assert_eq!(
            classify(b64(&h).as_bytes()).unwrap(),
            CredentialSeal::Unknown
        );
        assert!(!CredentialSeal::Unknown.tpm2_bound());
    }
}
