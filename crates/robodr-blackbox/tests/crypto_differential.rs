//! S10 (R8): `robodr_blackbox::crypto` moved from a hand-rolled SHA-256 /
//! HMAC-SHA256 to RustCrypto `sha2` (HMAC is RFC 2104 over a wiping `sha2`
//! wrapper, after a first version on the `hmac` crate). This proves the new
//! code is the
//! old code, byte for byte, so every record hash, chain head, checkpoint and
//! legacy HMAC tag already on disk still verifies:
//!
//! * differential: the pre-S10 implementation (verbatim, test-only, in
//!   `support/legacy_sha256.rs`) against the new one over every length
//!   0..=300, then random messages, random streaming splits and random HMAC
//!   keys of 0..=200 bytes (short, block-sized and hashed long keys);
//! * NIST CAVP `SHA256ShortMsg.rsp` vectors (Len = 8..56 bits) on top of the
//!   FIPS 180-4 examples and RFC 4231 cases in the unit tests;
//! * vectors computed with an independent implementation (CPython `hashlib`
//!   / `hmac`, i.e. OpenSSL) over a fixed byte pattern at every padding
//!   boundary and HMAC key-length class.

#[path = "support/legacy_sha256.rs"]
mod legacy;

use robodr_blackbox::crypto::{self, from_hex, hmac_sha256, sha256, to_hex, Sha256};

/// xorshift64* (deterministic, no rand crate).
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

fn iterations() -> usize {
    std::env::var("ROBODR_CRYPTO_DIFF_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3000)
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
    let mut rng = Rng(0x5eed_0001);
    for i in 0..iterations() {
        let len = match i % 4 {
            0 => rng.below(130),
            1 => rng.below(1100),
            2 => 64 * rng.below(20) + rng.below(3), // near block boundaries
            _ => rng.below(5000),
        };
        let msg = rng.bytes(len);
        let want = legacy::sha256(&msg);
        assert_eq!(sha256(&msg), want, "one-shot len {len}");
        // Random chunking for both, independently.
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
        if rng.below(2) == 0 {
            new.update(&[]);
        }
        assert_eq!(new.finalize(), want, "streamed len {len}");
        assert_eq!(old.finalize(), want, "legacy streamed len {len}");
    }
}

#[test]
fn hmac_matches_legacy_on_random_keys_and_messages() {
    let mut rng = Rng(0x5eed_0002);
    // Every key length class: empty, short, exactly one block, hashed.
    for klen in 0..=200 {
        let key = rng.bytes(klen);
        let mlen = rng.below(300);
        let msg = rng.bytes(mlen);
        assert_eq!(
            hmac_sha256(&key, &msg),
            legacy::hmac_sha256(&key, &msg),
            "key len {klen}"
        );
    }
    for _ in 0..iterations() {
        let klen = rng.below(201);
        let key = rng.bytes(klen);
        let mlen = rng.below(2000);
        let msg = rng.bytes(mlen);
        assert_eq!(
            hmac_sha256(&key, &msg),
            legacy::hmac_sha256(&key, &msg),
            "key len {} msg len {}",
            key.len(),
            msg.len()
        );
    }
}

#[test]
fn nist_cavp_sha256_short_msg_vectors() {
    // SHA256ShortMsg.rsp, Len = 8, 16, ..., 56.
    for (msg, md) in [
        (
            "d3",
            "28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1",
        ),
        (
            "11af",
            "5ca7133fa735326081558ac312c620eeca9970d1e70a4b95533d956f072d1f98",
        ),
        (
            "b4190e",
            "dff2e73091f6c05e528896c4c831b9448653dc2ff043528f6769437bc7b975c2",
        ),
        (
            "74ba2521",
            "b16aa56be3880d18cd41e68384cf1ec8c17680c45a02b1575dc1518923ae8b0e",
        ),
        (
            "c299209682",
            "f0887fe961c9cd3beab957e8222494abb969b1ce4c6557976df8b0f6d20e9166",
        ),
        (
            "e1dc724d5621",
            "eca0a060b489636225b4fa64d267dabbe44273067ac679f20820bddc6b6a90ac",
        ),
        (
            "06e076f5a442d5",
            "3fd877e27450e6bbd5d74bb82f9870c64c66e109418baa8e6bbcff355e287926",
        ),
    ] {
        let m = from_hex(msg).unwrap();
        assert_eq!(to_hex(&sha256(&m)), md, "msg {msg}");
        assert_eq!(to_hex(&legacy::sha256(&m)), md, "legacy msg {msg}");
    }
}

/// `((i * 31 + seed * 7 + (i >> 3)) & 0xff)`, the pattern the Python side used.
fn pattern(n: usize, seed: usize) -> Vec<u8> {
    (0..n)
        .map(|i| ((i * 31 + seed * 7 + (i >> 3)) & 0xff) as u8)
        .collect()
}

#[test]
fn independent_openssl_vectors_at_padding_boundaries() {
    // python3: hashlib.sha256(pattern(n, 1)).hexdigest()
    for (n, md) in [
        (
            0,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            1,
            "ca358758f6d27e6cf45272937977a748fd88391db679ceda7dc7bf1f005ee879",
        ),
        (
            55,
            "6ddf24d68d459417fe73e7eef1ba76dad966dc558fea8c28eb153e0e5f197c19",
        ),
        (
            56,
            "acf40c653e42a98d77183cbf147d6458cb18e2c3e0f1a8372d2f169e76589da0",
        ),
        (
            57,
            "7493f23772e8c35eb7591cc03d82f0e14a72521ad5323d260748fcc4a4b67e0d",
        ),
        (
            63,
            "be815f9bcd46e97caf5dc981c6d6362f191713885e474de47839a109b73202c1",
        ),
        (
            64,
            "7a6f445cd422720a2045195f7d5b431622f5064f7d1322bf43c7d2f51f5ce399",
        ),
        (
            65,
            "a39f9256eefe0b7067500990fd9a3c0dc3e402f5891b7fbbc710168736baa610",
        ),
        (
            111,
            "8bca34a32decdc3021f086a9ebc8cb0b496021bc1410bca1f7595c0a692373ad",
        ),
        (
            112,
            "a4486f59930b62865194a7627727c0b5be92c94a9135ed0d31445dbc43ba7971",
        ),
        (
            119,
            "593f16ef31b1fbf6a0474103203348f4b1a8938577a0bc39c56547cc8b5b33e4",
        ),
        (
            120,
            "9cec148baf5c286b46aff37909d56682b689a6daea82210923059db919c33cbb",
        ),
        (
            127,
            "a9010e56abb430919dfeb9694362cb35bb58662489a8141d1d30f676a87cdecb",
        ),
        (
            128,
            "8a4c9f48f6192298e2e75348fda4f83cbb9733db5f863a8b6408b0e6e8ece796",
        ),
        (
            129,
            "4d30bce7019e3a62bfd2c43032073680b7e819cd20d0f13c6e56be8c9de6714a",
        ),
        (
            1000,
            "0a731b3bf3729c165588a6294f98a895bafed0203df96c1ac6b69a62799e4e7f",
        ),
    ] {
        let m = pattern(n, 1);
        assert_eq!(to_hex(&sha256(&m)), md, "len {n}");
        assert_eq!(to_hex(&legacy::sha256(&m)), md, "legacy len {n}");
    }
    // python3: hmac.new(pattern(k, 2), pattern(m, 3), hashlib.sha256).hexdigest()
    for (k, m, tag) in [
        (
            0,
            0,
            "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad",
        ),
        (
            1,
            3,
            "85f61e1622f9f33d7272a009dc31cacf45767e6e5199c4c6af0c464195dbb21a",
        ),
        (
            32,
            64,
            "b6a55ba51847a9a483edd0b0bb7d787bd32090955f29464bff3a060daf70d19c",
        ),
        (
            63,
            10,
            "3eabd86960301a9ec8b684ac5235df3983c8f5292e47386b211ea45d5d7509d2",
        ),
        (
            64,
            10,
            "ca3e1bca59f5c3f78c283361c306070e5d0ab0da032b63fffe7e6adb990abc5e",
        ),
        (
            65,
            10,
            "bf7179d68a4a65ecacbf43f3e1063dcfdd62d6c57b41bfc721512a1b160e91ea",
        ),
        (
            128,
            200,
            "934b31de1c27a8a29bf89462c550728f043e20ebbd077b2aaebd337b7af4bbd8",
        ),
        (
            200,
            1,
            "37153ad016c93a6db59fabe4af940d81ecbd10caf29fb47c8c1e5742b55a8a36",
        ),
    ] {
        let (key, msg) = (pattern(k, 2), pattern(m, 3));
        assert_eq!(to_hex(&hmac_sha256(&key, &msg)), tag, "key {k} msg {m}");
        assert_eq!(
            to_hex(&legacy::hmac_sha256(&key, &msg)),
            tag,
            "legacy key {k} msg {m}"
        );
    }
}

#[test]
fn ct_eq_agrees_with_plain_equality() {
    let mut rng = Rng(0x5eed_0003);
    for _ in 0..2000 {
        let alen = rng.below(40);
        let a = rng.bytes(alen);
        let mut b = a.clone();
        match rng.below(3) {
            0 => {}
            1 if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] ^= 1 << rng.below(8);
            }
            _ => {
                let x = rng.next() as u8;
                b.push(x);
            }
        }
        assert_eq!(crypto::ct_eq(&a, &b), a == b);
    }
}
