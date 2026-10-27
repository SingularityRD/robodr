//! S10 (R8): `robodr_ocsf::hash` SHA-256 moved from a hand-rolled
//! implementation to RustCrypto `sha2`. Finding uids and attacker-string
//! digests are derived from it, so the output must not change: the pre-S10
//! code (verbatim, test-only, `support/legacy_sha256.rs`) is the oracle here,
//! over every length 0..=300, random messages and random streaming splits.
//! The FIPS 180-4 vectors stay in the unit tests of `src/hash.rs`.

#[path = "support/legacy_sha256.rs"]
mod legacy;

use robodr_ocsf::hash::{framed_sha256, sha256, Sha256};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

#[test]
fn sha256_matches_legacy_for_every_length_up_to_300() {
    let msg: Vec<u8> = (0..300u32).map(|i| (i * 131 + 7) as u8).collect();
    for len in 0..=msg.len() {
        assert_eq!(
            sha256(&msg[..len]),
            legacy::sha256(&msg[..len]),
            "len {len}"
        );
    }
}

#[test]
fn sha256_streaming_matches_legacy_on_random_inputs_and_splits() {
    let mut rng = Rng(0x0c5f_0001);
    for i in 0..3000 {
        let len = match i % 3 {
            0 => rng.below(130),
            1 => 64 * rng.below(20) + rng.below(3),
            _ => rng.below(4000),
        };
        let msg = rng.bytes(len);
        let want = legacy::sha256(&msg);
        assert_eq!(sha256(&msg), want, "one-shot len {len}");
        let mut new = Sha256::new();
        let mut old = legacy::Sha256::new();
        let mut rest = &msg[..];
        while !rest.is_empty() {
            let n = 1 + rng.below(rest.len().min(150));
            let (a, b) = rest.split_at(n);
            new.update(a);
            old.update(a);
            rest = b;
        }
        assert_eq!(new.finalize(), want, "streamed len {len}");
        assert_eq!(old.finalize(), want, "legacy streamed len {len}");
    }
}

#[test]
fn framed_sha256_matches_legacy_framing() {
    // framed_sha256 = SHA-256 over the framing; recompute the framing with
    // the legacy hasher.
    let mut rng = Rng(0x0c5f_0002);
    for _ in 0..500 {
        let domain: String = (0..rng.below(20))
            .map(|_| (b'a' + rng.below(26) as u8) as char)
            .collect();
        let fields: Vec<Vec<u8>> = (0..rng.below(6))
            .map(|_| {
                let n = rng.below(100);
                rng.bytes(n)
            })
            .collect();
        let refs: Vec<&[u8]> = fields.iter().map(|f| f.as_slice()).collect();
        let mut old = legacy::Sha256::new();
        old.update(&(domain.len() as u64).to_be_bytes());
        old.update(domain.as_bytes());
        old.update(&(refs.len() as u64).to_be_bytes());
        for f in &refs {
            old.update(&(f.len() as u64).to_be_bytes());
            old.update(f);
        }
        assert_eq!(framed_sha256(&domain, &refs), old.finalize());
    }
}

#[test]
fn ocsf_and_blackbox_sha256_agree() {
    let mut rng = Rng(0x0c5f_0003);
    for _ in 0..500 {
        let n = rng.below(3000);
        let m = rng.bytes(n);
        assert_eq!(sha256(&m), robodr_blackbox::crypto::sha256(&m));
    }
}
