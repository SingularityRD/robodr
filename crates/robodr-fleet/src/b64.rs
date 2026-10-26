//! Base64url without padding (RFC 4648 §5), strict.
//!
//! Used for the payload of a fleet envelope and the two parts of an
//! enrollment token (contract `robodr.fleet-api` §2). Decoding is strict so
//! that every byte string has exactly one encoding: only the URL-safe
//! alphabet, no `=` padding, no white space, a length that is not 1 mod 4,
//! and the unused low bits of the last character must be zero.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode `data` (no padding).
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let chars = chunk.len() + 1;
        for i in 0..chars {
            let idx = (n >> (18 - 6 * i)) & 0x3f;
            out.push(char::from(ALPHABET[idx as usize]));
        }
    }
    out
}

fn value(c: u8) -> Option<u32> {
    let v = match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => return None,
    };
    Some(u32::from(v))
}

/// Decode canonical base64url without padding; `None` for anything else.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 2);
    for chunk in bytes.chunks(4) {
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            n |= value(c)? << (18 - 6 * i);
        }
        match chunk.len() {
            4 => out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]),
            3 => {
                if n & 0xff != 0 {
                    return None;
                }
                out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8]);
            }
            2 => {
                if n & 0xffff != 0 {
                    return None;
                }
                out.push((n >> 16) as u8);
            }
            _ => return None,
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors_url_alphabet_no_padding() {
        for (raw, enc) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(raw.as_bytes()), enc);
            assert_eq!(decode(enc).unwrap(), raw.as_bytes());
        }
        assert_eq!(encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(decode("-_8").unwrap(), vec![0xfb, 0xff]);
    }

    #[test]
    fn non_canonical_and_foreign_input_is_refused() {
        for bad in [
            "Z", "Zh", "Zm9", "Zm9v=", "Zm9vYg==", "Zm+v", "Zm/v", "Zm9 v", "Zm9v\n", "Zm9vY",
        ] {
            assert!(decode(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn roundtrip_all_lengths() {
        let data: Vec<u8> = (0..=255u8).collect();
        for n in 0..data.len() {
            assert_eq!(decode(&encode(&data[..n])).unwrap(), &data[..n]);
        }
    }
}
