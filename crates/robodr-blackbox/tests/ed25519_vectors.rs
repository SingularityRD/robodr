//! Ed25519 / SHA-512 known-answer and negative tests.
//!
//! - SHA-512: FIPS 180-4 examples (empty, "abc", 448-bit, 896-bit, one
//!   million 'a') plus padding-boundary lengths cross-checked with OpenSSL.
//! - Ed25519: every RFC 8032 §7.1 vector (TEST 1, 2, 3, 1024, SHA(abc)) plus
//!   extra vectors produced by OpenSSL via Python `cryptography` 50.0.1.
//! - Negative: bit flips in signature / message / public key, `S + L`
//!   malleability, small-order and non-canonical points, wrong lengths.
//! - End to end: a recorder signing with Ed25519, verified with only the
//!   public key.

use robodr_blackbox::crypto::{from_hex, to_hex};
use robodr_blackbox::sign_ed25519::{
    derive_key_id, public_key_from_seed, sha512, sign, verify, Ed25519Error, Sha512, ED25519,
};
use robodr_blackbox::verify::{verify_dir, VerifyOptions};
use robodr_blackbox::{
    Ed25519SigningKey, Ed25519VerifyingKey, Recorder, RecorderConfig, Signer, SteppingClock,
    TimeSource, Verifier,
};
use robodr_events::{Deviation, Severity};

fn hx(s: &str) -> Vec<u8> {
    from_hex(s).expect("valid hex")
}
fn h32(s: &str) -> [u8; 32] {
    hx(s).try_into().expect("32 bytes")
}

// ---------------------------------------------------------------- SHA-512

#[test]
fn sha512_fips_180_4_vectors() {
    let cases: [(&[u8], &str); 4] = [
        (b"", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
        (b"abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
        (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"),
        (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"),
    ];
    for (m, want) in cases {
        assert_eq!(to_hex(&sha512(m)), want, "len {}", m.len());
    }
}

#[test]
fn sha512_million_a_streamed_in_odd_chunks() {
    let mut h = Sha512::new();
    let chunk = [b'a'; 997];
    let mut left = 1_000_000usize;
    while left > 0 {
        let n = left.min(chunk.len());
        h.update(&chunk[..n]);
        left -= n;
    }
    assert_eq!(
        to_hex(&h.finalize()),
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
    );
}

#[test]
fn sha512_padding_boundaries_and_streaming_equivalence() {
    // Message bytes i % 251; digests from OpenSSL (Python hashlib).
    let cases = [
        (111, "a1a111449b198d9b1f538bad7f3fc1022b3a5b1a5e90a0bc860de8512746cbc31599e6c834de3a3235327af0b51ff57bf7acf1974a73014d9c3953812edc7c8d"),
        (112, "c5fbd731d19d2ae1180f001be72c2c1aaba1d7b094b3748880e24593b8e117a750e11c1bd867cc2f96dace8c8b74abd2d5c4f236be444e77d30d1916174070b9"),
        (113, "61b2e77db697dfe5571fff3ed06bd60c41e1e7b7c08a80de01cb16526d9a9a52d690dfbe792278a60f6e2b4c57a97c729773f26e258d2393890c985d645f6715"),
        (127, "eab89674feaa34e27aebeeff3c0a4d70070bb872d5e9f186cf1dbbdee517b6e35724d629ff025a5b07185e911ada7e3c8acf830aa0e4f71777bd2d44f504f7f0"),
        (128, "1dffd5e3adb71d45d2245939665521ae001a317a03720a45732ba1900ca3b8351fc5c9b4ca513eba6f80bc7b1d1fdad4abd13491cb824d61b08d8c0e1561b3f7"),
        (129, "1d9da57fbbdab09afb3506ab2d223d06109d65c1c8ad197f50138f714bc4c3f2fe5787922639c680acad1c651f955990425954ce2cba0c5cc83f2667d878eb0f"),
        (239, "cb4c7fd522756d5781ad3a4f590a1d862906b960e7720136cb3fb36b563caa1ea5689134291fa79c80ccc2b4092b41df32ebdcb36dbe79db483440228c1622a8"),
        (240, "6c48466c9f6c07e4ab762c696b7eeb35cfe236fca73683e5fab873ac3489b4d2eb3d7afcce7e8165dbbf37aded3b5b0c889c0b7e0f1790a8330d8677429d91a5"),
        (256, "7ff1cd1e9773a4b7ba1f40e642db0d879bd5f6cc151a7d3401a0bc7778b8270c108b530fb195f2383f4cec8cf05778e6af4db56811673371674cec1524488f83"),
    ];
    for (n, want) in cases {
        let m: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
        assert_eq!(to_hex(&sha512(&m)), want, "len {n}");
        // Byte-at-a-time and split streaming give the same digest.
        let mut h = Sha512::new();
        for b in &m {
            h.update(std::slice::from_ref(b));
        }
        assert_eq!(to_hex(&h.finalize()), want, "bytewise len {n}");
        for split in [0, 1, n / 2, n] {
            let mut h = Sha512::new();
            h.update(&m[..split]);
            h.update(&[]);
            h.update(&m[split..]);
            assert_eq!(to_hex(&h.finalize()), want, "split {split} len {n}");
        }
    }
}

// ------------------------------------------------------- RFC 8032 §7.1

struct Vector {
    name: &'static str,
    secret: &'static str,
    public: &'static str,
    message: &'static str,
    signature: &'static str,
}

const TEST_1024_MESSAGE: &str = "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0";

const RFC8032: [Vector; 5] = [
    Vector {
        name: "TEST 1",
        secret: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        public: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        message: "",
        signature: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    },
    Vector {
        name: "TEST 2",
        secret: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        public: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        message: "72",
        signature: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    },
    Vector {
        name: "TEST 3",
        secret: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        public: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        message: "af82",
        signature: "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    },
    Vector {
        name: "TEST 1024",
        secret: "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
        public: "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
        message: TEST_1024_MESSAGE,
        signature: "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
    },
    Vector {
        name: "TEST SHA(abc)",
        secret: "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        public: "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        message: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        signature: "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
    },
];

#[test]
fn rfc8032_section_7_1_all_vectors() {
    assert_eq!(hx(TEST_1024_MESSAGE).len(), 1023);
    // SHA(abc) message is literally SHA-512("abc").
    assert_eq!(to_hex(&sha512(b"abc")), RFC8032[4].message);
    for v in &RFC8032 {
        let seed = h32(v.secret);
        let msg = hx(v.message);
        assert_eq!(
            to_hex(&public_key_from_seed(&seed)),
            v.public,
            "{}: public",
            v.name
        );
        let sig = sign(&seed, &msg);
        assert_eq!(to_hex(&sig), v.signature, "{}: signature", v.name);
        assert!(
            verify(&hx(v.public), &msg, &hx(v.signature)),
            "{}: verify",
            v.name
        );

        // Same through the Signer / Verifier traits.
        let sk = Ed25519SigningKey::from_seed(v.name.replace(' ', "_"), &seed).unwrap();
        assert_eq!(to_hex(&sk.public_key()), v.public);
        let tsig = Signer::sign(&sk, &msg).unwrap();
        assert_eq!(to_hex(&tsig), v.signature, "{}: trait signature", v.name);
        assert_eq!(sk.verify_own(&msg, &tsig), Some(true));
        let vk = sk.verifying_key();
        assert!(vk.verify(&msg, &tsig));
        assert_eq!(Verifier::key_id(&vk), Signer::key_id(&sk));
    }
}

/// Extra vectors from OpenSSL (Python `cryptography` 50.0.1): seed =
/// SHA-256("robodr-ed25519-xcheck-<n>"), message byte i = (7 i + n) mod 256.
#[test]
fn openssl_cross_check_vectors() {
    let cases = [
        (1, "2ed2bd4b13a888e4a999d97fe3976a8eb12fb67f4e11d20bbca3b75ab0dcca73", "c385628ceff5aa491c1a78a90003268e9b8df890e332d9662763555265e11bcfefe60efe44efccf72dcb7cfd59553c83761b6a5f2eb88f4ac706b384bc26a607"),
        (63, "fb2ba1cf4d72184fb2a58aecfc9ab5fb257656d15b3fe9967d2e143ec7b3bc78", "6fb42373ad130f276c451dc330689aab932b123f36a7d7de5775d7c0190c7b449235dda38ada9b21a4fff0e3071059b6d6d3a53a890691dc82cbdbda782d010f"),
        (64, "e924be00fe3bdc16a3240b7c63c1f2f4ac632592eac2ac6dc8f9e55a878d09d8", "56a0bac4dd7737e60e8b9a4d2e1f21a62c0541c1b1518c591c529e360f79199b0bf9dfa2bda41128e517311c362339cac7ba8d70747f9aedfb0965f816702108"),
        (111, "78e5c56599930fb6e69f9ce86d81bfadc72556f94f7307257bc67c859083f861", "a76ae273a8204a67f62fc0f2e0cd6d1ff923ec2e5553a1057afb0b68cb713c9ae3bc91690b54c69915fb1b969c4005ce8e02becce2613dbf82a0c86ee27f5c07"),
        (112, "91dab03bab5e21467fa74d042000cc1e6e89c0e57a2ae1b70aeab361930403ab", "50a9c3bfffc7b4a0ff2393db19bd4577de12dc87e09ad9fa3c090e52646ed5772f5214354988ce7d218a8d3d14e44fdec30ee30210a92f6fae3a33fe53935f0f"),
        (127, "0cde2087756995269332ed8e6e717df981c7b10b24c849d41e3b40f581339aac", "f02fc2d04352b238fdc0fd8c831c346ff04d96b7b33ad7c0e1833448e5dd4fa2bcd6db0589db209615c4cb171a9fa54c22b7293539aa00c79b5058cf5733d80f"),
        (128, "d571e588bc59863deb8ec74b34ddb2a8a10d41a9b38e915cdb192163501a2ba2", "09a7bf93abc471f11555ad2b8a2348e5ed70e589b4662356bfc193071eb33ab1cd75a5e992547e5698898cf30dbae0e3d7b4aacd97f3ce21d5bdee512d27bf01"),
        (129, "8ee3893d29eaaf45aa91ba284b3b4c77f6d36d3255c8fdd7d03446b58b85b696", "b7ec6ea189928f991c2a6043426c102c4abc28931867b4e81240f07b77e0f6343a8e533ef4b30ab6217d7cd5113373863830fdfd17eebbb020c3380881768507"),
        (255, "e23e992864fcc7362c803a33375a6a49b82e4f150ce8b3eabcf0df7d17541fd2", "749e6507640b01af0ccb22e72630c599ff0fdee5387420305d769915fac5b9218d860e61c60e477725168366413c55bba074001820c87128a221054f51089b0d"),
        (300, "ed3aaeb7ca5d817db95141a8c97794e414cf414f842157b30f9cafe7fb7851f2", "6cdc46e83766511067a23ddd4e2cef19f1f5589d954ff73df509420cea921001495543e42e1e002966bc5def518e0aa9650ab552733661b1af74981fbd07a20e"),
    ];
    for (n, pk, sig) in cases {
        let seed = robodr_blackbox::crypto::sha256(format!("robodr-ed25519-xcheck-{n}").as_bytes());
        let msg: Vec<u8> = (0..n).map(|i: usize| ((i * 7 + n) & 0xff) as u8).collect();
        assert_eq!(to_hex(&public_key_from_seed(&seed)), pk, "len {n}");
        assert_eq!(to_hex(&sign(&seed, &msg)), sig, "len {n}");
        assert!(verify(&hx(pk), &msg, &hx(sig)));
    }
}

// ------------------------------------------------------------ negatives

/// Every single-bit flip of the signature, message and public key of
/// RFC 8032 TEST 3 is rejected.
#[test]
fn every_single_bit_flip_is_rejected() {
    let v = &RFC8032[2];
    let (pk, msg, sig) = (hx(v.public), hx(v.message), hx(v.signature));
    assert!(verify(&pk, &msg, &sig));
    for bit in 0..sig.len() * 8 {
        let mut s = sig.clone();
        s[bit / 8] ^= 1 << (bit % 8);
        assert!(!verify(&pk, &msg, &s), "signature bit {bit}");
    }
    for bit in 0..msg.len() * 8 {
        let mut m = msg.clone();
        m[bit / 8] ^= 1 << (bit % 8);
        assert!(!verify(&pk, &m, &sig), "message bit {bit}");
    }
    for bit in 0..pk.len() * 8 {
        let mut p = pk.clone();
        p[bit / 8] ^= 1 << (bit % 8);
        assert!(!verify(&p, &msg, &sig), "public key bit {bit}");
        if let Ok(vk) = Ed25519VerifyingKey::from_bytes("k", &p.clone().try_into().unwrap()) {
            assert!(!vk.verify(&msg, &sig), "verifier public key bit {bit}");
        }
    }
}

/// `L` as 32 little-endian bytes.
const L_HEX: &str = "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010";

fn add_256(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let t = a[i] as u16 + b[i] as u16 + carry;
        out[i] = t as u8;
        carry = t >> 8;
    }
    assert_eq!(carry, 0);
    out
}

#[test]
fn s_plus_l_malleability_is_rejected() {
    let l = hx(L_HEX);
    for v in &RFC8032 {
        let (pk, msg, sig) = (hx(v.public), hx(v.message), hx(v.signature));
        let mut mauled = sig.clone();
        mauled[32..].copy_from_slice(&add_256(&sig[32..], &l));
        assert_ne!(mauled, sig);
        assert!(!verify(&pk, &msg, &mauled), "{}: S + L accepted", v.name);
        // S = L exactly and S = 2^256 - 1 are non-canonical too.
        let mut s_eq_l = sig.clone();
        s_eq_l[32..].copy_from_slice(&l);
        assert!(!verify(&pk, &msg, &s_eq_l));
        let mut s_max = sig.clone();
        s_max[32..].copy_from_slice(&[0xff; 32]);
        assert!(!verify(&pk, &msg, &s_max));
    }
}

const IDENTITY: &str = "0100000000000000000000000000000000000000000000000000000000000000";
/// (0, -1): order 2.
const ORDER_2: &str = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
/// An order-8 point (y from the libsodium blacklist).
const ORDER_8: &str = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a";
/// Non-canonical encodings: y = p (i.e. 0) and y = p + 1 (i.e. 1).
const Y_EQ_P: &str = "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
const Y_EQ_P1: &str = "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
/// x = 0 (y = 1) with the sign bit set.
const NEG_ZERO_X: &str = "0100000000000000000000000000000000000000000000000000000000000080";

#[test]
fn small_order_and_non_canonical_public_keys_are_rejected() {
    for bad in [IDENTITY, ORDER_2, ORDER_8, Y_EQ_P, Y_EQ_P1, NEG_ZERO_X] {
        assert_eq!(
            Ed25519VerifyingKey::from_bytes("k", &h32(bad)).unwrap_err(),
            Ed25519Error::InvalidPublicKey,
            "{bad}"
        );
    }
    // Not on the curve (y = 2 has no x).
    let mut y2 = [0u8; 32];
    y2[0] = 2;
    assert!(Ed25519VerifyingKey::from_bytes("k", &y2).is_err());
}

/// The classic "identity key" forgery: A = R = identity, S = 0 satisfies the
/// cofactorless equation for every message. Strict decoding rejects it, and
/// likewise for other small-order A / R.
#[test]
fn small_order_forgeries_are_rejected() {
    let zero_s = [0u8; 32];
    for a in [IDENTITY, ORDER_2, ORDER_8] {
        for r in [IDENTITY, ORDER_2, ORDER_8] {
            let mut sig = h32(r).to_vec();
            sig.extend_from_slice(&zero_s);
            for m in [&b""[..], b"x", b"forged record"] {
                assert!(!verify(&hx(a), m, &sig), "A={a} R={r}");
            }
        }
    }
    // Small-order R under a genuine key.
    let v = &RFC8032[0];
    for r in [IDENTITY, ORDER_2, ORDER_8, Y_EQ_P, Y_EQ_P1, NEG_ZERO_X] {
        let mut sig = h32(r).to_vec();
        sig.extend_from_slice(&hx(v.signature)[32..]);
        assert!(!verify(&hx(v.public), b"", &sig), "R={r}");
    }
}

#[test]
fn malformed_lengths_never_panic() {
    let v = &RFC8032[1];
    let (pk, msg, sig) = (hx(v.public), hx(v.message), hx(v.signature));
    for n in [0, 1, 31, 33, 63, 65, 128] {
        let s: Vec<u8> = sig.iter().copied().cycle().take(n).collect();
        assert!(!verify(&pk, &msg, &s), "sig len {n}");
        let p: Vec<u8> = pk.iter().copied().cycle().take(n).collect();
        assert!(!verify(&p, &msg, &sig), "pk len {n}");
    }
    let vk = Ed25519VerifyingKey::from_bytes("k", &h32(v.public)).unwrap();
    assert!(!vk.verify(&msg, &sig[..63]));
    assert!(!vk.verify(&msg, &[]));
    assert!(!verify(&pk, &msg, &[0xff; 64]));
    assert!(!verify(&[0xff; 32], &msg, &sig));
}

#[test]
fn wrong_key_and_cross_message_are_rejected() {
    let a = Ed25519SigningKey::from_seed("a", &[1; 32]).unwrap();
    let b = Ed25519SigningKey::from_seed("b", &[2; 32]).unwrap();
    let sig = a.sign_message(b"record");
    assert!(a.verifying_key().verify(b"record", &sig));
    assert!(!b.verifying_key().verify(b"record", &sig));
    assert_eq!(b.verify_own(b"record", &sig), Some(false));
    assert_eq!(a.verify_own(b"recorD", &sig), Some(false));
    // Signatures are deterministic.
    assert_eq!(sig, a.sign_message(b"record"));
}

// --------------------------------------------------- keys and key ids

#[test]
fn key_ids_and_construction() {
    let seed = [9u8; 32];
    let sk = Ed25519SigningKey::from_seed_with_derived_id(&seed);
    let vk = Ed25519VerifyingKey::from_bytes_with_derived_id(&sk.public_key()).unwrap();
    assert_eq!(Signer::key_id(&sk), Verifier::key_id(&vk));
    assert_eq!(Signer::key_id(&sk), derive_key_id(&sk.public_key()));
    assert!(Signer::key_id(&sk).starts_with("ed25519:"));
    assert_eq!(Signer::algorithm(&sk), ED25519);
    assert_eq!(Verifier::algorithm(&vk), ED25519);
    assert_eq!(vk.as_bytes(), &sk.public_key());
    assert_eq!(sk.to_seed(), seed);

    for bad in ["", "has space", "tab\t", "ünï"] {
        assert_eq!(
            Ed25519SigningKey::from_seed(bad, &seed).unwrap_err(),
            Ed25519Error::BadKeyId
        );
        assert_eq!(
            Ed25519VerifyingKey::from_bytes(bad, &sk.public_key()).unwrap_err(),
            Ed25519Error::BadKeyId
        );
    }
    assert!(Ed25519SigningKey::from_seed("x".repeat(129), &seed).is_err());
    assert!(Ed25519SigningKey::from_seed("x".repeat(128), &seed).is_ok());

    let dbg = format!("{vk:?}");
    assert!(dbg.contains(&to_hex(&sk.public_key())));
}

#[test]
fn generated_keys_are_distinct_and_work() {
    let a = Ed25519SigningKey::generate("gen-a").unwrap();
    let b = Ed25519SigningKey::generate_with_derived_id().unwrap();
    assert_ne!(a.public_key(), b.public_key());
    let sig = a.sign_message(b"m");
    assert!(verify(&a.public_key(), b"m", &sig));
    assert!(b.verifying_key().verify(b"m", &b.sign_message(b"m")));
}

// ----------------------------------------------------- end to end

struct TempDir(std::path::PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "robodr-bb-ed25519-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        Self(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn recorder_signs_with_ed25519_and_public_key_verifies() {
    let dir = TempDir::new("e2e");
    let seed = [0x42u8; 32];
    let open = |start: u64| {
        Recorder::open(
            RecorderConfig::new(&dir.0, "ugv-01", "boot-a"),
            Box::new(Ed25519SigningKey::from_seed("unit-ed", &seed).unwrap()),
            Box::new(SteppingClock::new(start, 1_000, TimeSource::Rtc)),
        )
        .unwrap()
    };
    // Write, close, reopen (the recorder authenticates its own tail via
    // verify_own), write more.
    let mut rec = open(1);
    for i in 0..5 {
        rec.append_deviation(&Deviation::new(
            "robot.ros2.unknown_participant",
            Severity::High,
            format!("d{i}"),
        ))
        .unwrap();
    }
    rec.close().unwrap();
    let mut rec = open(1_000_000);
    rec.append_deviation(&Deviation::new("robot.test", Severity::Low, "after reopen"))
        .unwrap();
    rec.close().unwrap();

    let pk = public_key_from_seed(&seed);
    let vk = Ed25519VerifyingKey::from_bytes("unit-ed", &pk).unwrap();
    let report = verify_dir(&dir.0, &vk, &VerifyOptions::default()).unwrap();
    assert!(report.is_clean(), "{report:?}");

    // A different public key under the same id does not verify the log.
    let other =
        Ed25519VerifyingKey::from_bytes("unit-ed", &public_key_from_seed(&[0x43; 32])).unwrap();
    let report = verify_dir(&dir.0, &other, &VerifyOptions::default()).unwrap();
    assert!(!report.is_clean());
}
