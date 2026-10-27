//! SHA-256 (RustCrypto `sha2`) and Kafka's murmur2.
//!
//! SHA-256 comes from the audited `sha2` crate since S10 (it was implemented
//! here before; `tests/hash_differential.rs` proves the output is unchanged
//! against that old code, kept there as a test-only oracle). murmur2 stays
//! in-crate: it is Kafka's partitioner hash, not a cryptographic primitive,
//! and is pinned against Apache Kafka's `UtilsTest.testMurmur2` cases.
//!
//! SHA-256 is used for *identifiers* (deterministic finding uids, digests of
//! truncated attacker strings), not for signatures: authenticity of evidence
//! comes from the signed black-box chain, not from this crate.

use sha2::Digest as _;

/// Incremental SHA-256 (`sha2::Sha256`).
#[derive(Clone, Default)]
pub struct Sha256(sha2::Sha256);

impl Sha256 {
    pub fn new() -> Self {
        Self(sha2::Sha256::new())
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub fn finalize(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

/// One-shot SHA-256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(data).into()
}

/// Lower-case hex encoding.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    s
}

/// Hash a sequence of fields with unambiguous framing: a domain-separation tag,
/// then each field as `u64 big-endian length || bytes`. Two different field
/// lists can therefore never produce the same pre-image (no `"a|b" == "a|" + "b"`
/// style collisions, even with attacker-chosen field contents).
pub fn framed_sha256(domain: &str, fields: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&(domain.len() as u64).to_be_bytes());
    h.update(domain.as_bytes());
    h.update(&(fields.len() as u64).to_be_bytes());
    for f in fields {
        h.update(&(f.len() as u64).to_be_bytes());
        h.update(f);
    }
    h.finalize()
}

/// Apache Kafka's `Utils.murmur2` (the default Java partitioner's hash), as a
/// signed 32-bit value exactly like the Java implementation returns.
pub fn kafka_murmur2(data: &[u8]) -> i32 {
    const SEED: u32 = 0x9747_b28c;
    const M: u32 = 0x5bd1_e995;
    const R: u32 = 24;
    let length = data.len();
    let mut h: u32 = SEED ^ (length as u32);
    let chunks = data.chunks_exact(4);
    let tail = chunks.remainder();
    for c in chunks {
        let mut k = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        k = k.wrapping_mul(M);
        k ^= k >> R;
        k = k.wrapping_mul(M);
        h = h.wrapping_mul(M);
        h ^= k;
    }
    match tail.len() {
        3 => {
            h ^= (tail[2] as u32) << 16;
            h ^= (tail[1] as u32) << 8;
            h ^= tail[0] as u32;
            h = h.wrapping_mul(M);
        }
        2 => {
            h ^= (tail[1] as u32) << 8;
            h ^= tail[0] as u32;
            h = h.wrapping_mul(M);
        }
        1 => {
            h ^= tail[0] as u32;
            h = h.wrapping_mul(M);
        }
        _ => {}
    }
    h ^= h >> 13;
    h = h.wrapping_mul(M);
    h ^= h >> 15;
    h as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_fips_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            hex(&sha256(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")),
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
        );
    }

    #[test]
    fn sha256_million_a_and_incremental() {
        let data = vec![b'a'; 1_000_000];
        assert_eq!(
            hex(&sha256(&data)),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
        // Odd-sized incremental feeding must match one-shot.
        let mut h = Sha256::new();
        for chunk in data.chunks(7) {
            h.update(chunk);
        }
        assert_eq!(h.finalize(), sha256(&data));
    }

    #[test]
    fn sha256_padding_boundaries() {
        // Lengths around the 55/56/64 padding boundaries must all be consistent
        // between one-shot and byte-at-a-time hashing.
        for len in 50..=130 {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let mut h = Sha256::new();
            for b in &data {
                h.update(std::slice::from_ref(b));
            }
            assert_eq!(h.finalize(), sha256(&data), "len {len}");
        }
    }

    #[test]
    fn framing_is_unambiguous() {
        let a = framed_sha256("d", &[b"ab", b"c"]);
        let b = framed_sha256("d", &[b"a", b"bc"]);
        let c = framed_sha256("d", &[b"abc"]);
        let d = framed_sha256("e", &[b"ab", b"c"]);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_eq!(a, framed_sha256("d", &[b"ab", b"c"]));
    }

    #[test]
    fn murmur2_matches_kafka_utils_test() {
        // Apache Kafka clients UtilsTest.testMurmur2.
        assert_eq!(kafka_murmur2(b"21"), -973932308);
        assert_eq!(kafka_murmur2(b"foobar"), -790332482);
        assert_eq!(kafka_murmur2(b"a-little-bit-long-string"), -985981536);
        assert_eq!(kafka_murmur2(b"a-little-bit-longer-string"), -1486304829);
        assert_eq!(
            kafka_murmur2(b"lkjh234lh9fiuh90y23oiuhsafujhadof229phr9h19h89h8"),
            -58897971
        );
        assert_eq!(kafka_murmur2(b"abc"), 479470107);
    }
}
