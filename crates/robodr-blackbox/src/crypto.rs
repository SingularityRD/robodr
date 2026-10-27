//! SHA-256 (RustCrypto `sha2`) and HMAC-SHA256 on top of it, tag comparison
//! (`subtle`), secret wiping (`zeroize`), the kernel CSPRNG and hex helpers.
//!
//! Until S10 the two hash primitives were implemented in this file (crates.io
//! was unreachable where the black box was first written). SHA-256 now comes
//! from the audited RustCrypto `sha2` (the same implementation
//! `ed25519-dalek` already used for SHA-512), behind a wrapper that wipes its
//! state on drop. HMAC-SHA256 is the RFC 2104 construction written here on
//! top of that wrapper (a dozen lines), not the `hmac` crate: `hmac` 0.12
//! leaves the padded key block, the long-key digest and the keyed state that
//! `finalize` consumes unwiped. The output is byte-for-byte
//! the old one, so every HMAC tag, record hash and checkpoint already on disk
//! still verifies: `tests/crypto_differential.rs` checks it against the old
//! code (kept as a test-only oracle in `tests/support/legacy_sha256.rs`) over
//! random inputs, keys and streaming splits, plus NIST CAVP SHA-256 and
//! RFC 4231 HMAC vectors (unit tests below).
//!
//! Scope and limits:
//! - SHA-256 has no secret-dependent branches or table lookups; HMAC only
//!   adds XOR with the key. `sha2` picks SHA-NI / ARMv8 SHA2 instructions at
//!   run time when the CPU has them (`cpufeatures`), else the portable code.
//! - [`ct_eq`] is `subtle`'s constant-time slice comparison (no early exit;
//!   the *length* is public).
//! - [`wipe`] is `zeroize` (volatile writes and a compiler fence). The
//!   [`Sha256`] wrapper wipes the whole hasher state (chaining value and
//!   buffered input) when dropped; [`sha256`] and [`hmac_sha256`] use only
//!   that wrapper, and HMAC wipes its padded key block, `K0` and the inner
//!   digest, so an HMAC key does not linger in a dropped hasher (Ed25519 and
//!   its SHA-512 come from `ed25519-dalek` / `sha2`). This is still best
//!   effort: temporaries inside `sha2` (the block it pads while finalising),
//!   copies the compiler makes in registers or spilled stack slots, and
//!   pages swapped out before the wipe, are not covered.
//! - [`fill_random`] reads the kernel CSPRNG with `getrandom(2)` (blocking
//!   until the pool is initialised), falling back to `/dev/urandom` only
//!   where the syscall does not exist, and fails rather than return
//!   anything weaker.
//!
//! HMAC is a **placeholder authenticity mechanism**: anyone who holds the key
//! can both create and verify tags, so it only proves "written by a holder of
//! the shared key". Production deployments must sign with an asymmetric key
//! (Ed25519 via `crate::sign_ed25519`, or TPM-backed ECDSA) through the
//! [`crate::sign::Signer`] / [`crate::sign::Verifier`] traits.

use std::mem::ManuallyDrop;

use sha2::Digest as _;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroize as _;

/// SHA-256 block size in bytes.
pub const BLOCK_LEN: usize = 64;
/// SHA-256 digest size in bytes.
pub const DIGEST_LEN: usize = 32;

// The state wiped below with `zeroize_flat_type` must be plain data: no
// drop glue that the `ManuallyDrop` would skip (nothing to leak), no pointers
// or heap buffers. It is fixed-size arrays of integers plus a position byte
// in sha2 0.10; a dependency bump that adds drop glue fails the build here
// instead of silently leaking.
const _: () = assert!(!std::mem::needs_drop::<sha2::Sha256>());

/// Overwrite every byte of a plain-data RustCrypto state with zeros.
///
/// `state` must not be used again afterwards (callers own it through a
/// `ManuallyDrop` they are dropping or discarding).
#[allow(unsafe_code)] // `zeroize_flat_type` is an `unsafe fn`.
fn wipe_state<T>(state: &mut ManuallyDrop<T>) {
    let p: *mut T = &mut **state;
    // SAFETY: `p` points to a live, exclusively borrowed `T` of
    // `size_of::<T>()` bytes. `T` is the hasher state asserted above to
    // have no drop glue, and it holds only integers and byte
    // arrays (no pointers, references or niches), for which all-zero is a
    // valid bit pattern; in any case the value is never read again (it is in
    // a `ManuallyDrop` that is being dropped or discarded).
    unsafe { zeroize::zeroize_flat_type(p) };
}

/// Streaming SHA-256 (`sha2::Sha256`) whose state is wiped on drop.
#[derive(Clone)]
pub struct Sha256 {
    inner: ManuallyDrop<sha2::Sha256>,
}

impl Drop for Sha256 {
    fn drop(&mut self) {
        wipe_state(&mut self.inner);
        #[cfg(test)]
        tests::WIPED_HASHERS.with(|n| n.set(n.get() + 1));
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// A fresh hasher.
    pub fn new() -> Self {
        Self {
            inner: ManuallyDrop::new(sha2::Sha256::new()),
        }
    }

    /// Absorb `data`.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Pad, finish and return the digest.
    pub fn finalize(mut self) -> [u8; DIGEST_LEN] {
        // Finalised in place (then reset to the IV); `Drop` wipes it.
        self.inner.finalize_reset().into()
    }
}

/// One-shot SHA-256, through the wiping [`Sha256`] wrapper (the input may
/// be secret, e.g. a key whose id is derived from its digest).
pub fn sha256(data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

/// HMAC-SHA256 (RFC 2104 with H = SHA-256, B = 64, L = 32), built on the
/// wiping [`Sha256`] wrapper:
/// `H((K0 ^ opad) || H((K0 ^ ipad) || message))`, where `K0` is the key
/// zero-padded to B bytes, or `H(key)` zero-padded if the key is longer than
/// B (as the RFC requires).
///
/// Every keyed state (the key hash, the inner and the outer hash) lives in a
/// wrapper that is wiped when dropped, and `K0`, the padded key block and the
/// inner digest are wiped before returning. Nothing keyed is cloned.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; DIGEST_LEN] {
    let mut k0 = [0u8; BLOCK_LEN];
    if key.len() > BLOCK_LEN {
        let mut kh = Sha256::new();
        kh.update(key);
        let mut d = kh.finalize();
        k0[..DIGEST_LEN].copy_from_slice(&d);
        wipe(&mut d);
    } else {
        k0[..key.len()].copy_from_slice(key);
    }
    let mut pad = [0u8; BLOCK_LEN];
    for (p, k) in pad.iter_mut().zip(&k0) {
        *p = k ^ 0x36;
    }
    let mut inner = Sha256::new();
    inner.update(&pad);
    inner.update(message);
    let mut inner_digest = inner.finalize();
    for (p, k) in pad.iter_mut().zip(&k0) {
        *p = k ^ 0x5c;
    }
    wipe(&mut k0);
    let mut outer = Sha256::new();
    outer.update(&pad);
    wipe(&mut pad);
    outer.update(&inner_digest);
    wipe(&mut inner_digest);
    outer.finalize()
}

/// Compare two byte strings without an early exit on the first difference
/// (`subtle::ConstantTimeEq`).
///
/// The *length* is not treated as secret (tags have a fixed, public length).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// Zeroise a secret buffer (`zeroize`: one volatile write per byte, which
/// the compiler may not elide as dead stores, then a compiler fence so later
/// code is not reordered before the wipe). Best effort; see the module docs.
pub fn wipe(buf: &mut [u8]) {
    buf.zeroize();
}

/// Fill `buf` from the kernel CSPRNG.
///
/// Linux/Android: `getrandom(2)` with no flags (blocks only until the
/// kernel pool has been initialised once after boot, never afterwards),
/// retried on `EINTR` and on short reads. Only if the syscall does not exist
/// (`ENOSYS`, pre-3.17 kernels) does it fall back to `/dev/urandom`. Other
/// unix: `/dev/urandom`. Any failure is an error: there is no weaker
/// fallback. A buffer of 16 bytes or more that comes back all zero is
/// treated as a broken source.
pub fn fill_random(buf: &mut [u8]) -> std::io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let r = match getrandom_syscall(buf) {
        Err(e) if e.raw_os_error() == Some(ENOSYS) => urandom(buf),
        r => r,
    };
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let r = urandom(buf);
    r?;
    if buf.len() >= 16 && buf.iter().all(|&b| b == 0) {
        return Err(std::io::Error::other(
            "randomness source returned all-zero bytes",
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
const ENOSYS: i32 = 38;
#[cfg(any(target_os = "linux", target_os = "android"))]
const EINTR: i32 = 4;

#[cfg(any(target_os = "linux", target_os = "android"))]
extern "C" {
    // glibc >= 2.25, musl >= 1.1.20, bionic: the libc wrapper of the syscall.
    fn getrandom(buf: *mut std::ffi::c_void, buflen: usize, flags: u32) -> isize;
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(unsafe_code)] // FFI: no stable std API for getrandom(2).
fn getrandom_syscall(buf: &mut [u8]) -> std::io::Result<()> {
    let mut done = 0usize;
    while done < buf.len() {
        let rest = &mut buf[done..];
        // SAFETY: `rest` is a valid, writable buffer of `rest.len()` bytes;
        // getrandom writes at most that many bytes into it.
        let n = unsafe { getrandom(rest.as_mut_ptr().cast(), rest.len(), 0) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(EINTR) {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            return Err(std::io::Error::other("getrandom returned 0 bytes"));
        }
        done += n as usize;
    }
    Ok(())
}

fn urandom(buf: &mut [u8]) -> std::io::Result<()> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(buf))
}

/// Lower-case hex encoding.
pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decode hex (either case). `None` on odd length or a non-hex digit.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    // Allocated once at its final size: a growing Vec would leave copies of
    // (possibly secret) bytes in the buffers it reallocates away from.
    let mut out = Vec::with_capacity(b.len() / 2);
    for p in b.chunks_exact(2) {
        match (nibble(p[0]), nibble(p[1])) {
            (Some(h), Some(l)) => out.push((h << 4) | l),
            _ => {
                wipe(&mut out);
                return None;
            }
        }
    }
    Some(out)
}

/// Decode a 64-digit hex string into a 32-byte digest.
pub fn hash_from_hex(s: &str) -> Option<[u8; DIGEST_LEN]> {
    let v = from_hex(s)?;
    v.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        /// Number of wiping [`Sha256`] wrappers dropped on this thread.
        pub(super) static WIPED_HASHERS: std::cell::Cell<usize> =
            const { std::cell::Cell::new(0) };
    }

    fn wiped_hashers_during(f: impl FnOnce() -> [u8; DIGEST_LEN]) -> usize {
        let before = WIPED_HASHERS.with(|n| n.get());
        std::hint::black_box(f());
        WIPED_HASHERS.with(|n| n.get()) - before
    }

    // Review L2: the one-shot hash is used on secret input
    // (`HmacSha256Key::with_derived_id`), so it must go through the wiping
    // wrapper rather than a bare `sha2::Sha256` that is dropped unwiped.
    #[test]
    fn one_shot_sha256_goes_through_the_wiping_wrapper() {
        assert_eq!(wiped_hashers_during(|| sha256(b"secret")), 1);
    }

    // Review L1: HMAC is built on the wiping wrapper (inner and outer hash,
    // plus the key hash for a key longer than the block), so no keyed hash
    // state is left unwiped.
    #[test]
    fn hmac_keyed_state_lives_only_in_wiping_wrappers() {
        assert_eq!(wiped_hashers_during(|| hmac_sha256(&[7; 32], b"m")), 2);
        assert_eq!(
            wiped_hashers_during(|| hmac_sha256(&[7; BLOCK_LEN], b"m")),
            2
        );
        assert_eq!(
            wiped_hashers_during(|| hmac_sha256(&[7; BLOCK_LEN + 1], b"m")),
            3
        );
    }

    fn h(s: &str) -> Vec<u8> {
        from_hex(s).unwrap()
    }

    // NIST FIPS 180-4 / CAVP example vectors.
    #[test]
    fn sha256_empty() {
        assert_eq!(
            to_hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_abc() {
        assert_eq!(
            to_hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_448_bit() {
        assert_eq!(
            to_hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn sha256_896_bit() {
        assert_eq!(
            to_hex(&sha256(
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
            )),
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
        );
    }

    #[test]
    fn sha256_million_a() {
        // Fed in uneven chunks to also exercise the streaming buffer.
        let mut hasher = Sha256::new();
        let chunk = [b'a'; 997];
        let mut left = 1_000_000usize;
        while left > 0 {
            let n = left.min(chunk.len());
            hasher.update(&chunk[..n]);
            left -= n;
        }
        assert_eq!(
            to_hex(&hasher.finalize()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn sha256_streaming_matches_one_shot_at_every_split() {
        let msg: Vec<u8> = (0..300u32).map(|i| (i * 7 + 3) as u8).collect();
        for len in [0usize, 1, 55, 56, 57, 63, 64, 65, 119, 120, 128, 300] {
            let whole = sha256(&msg[..len]);
            for split in 0..=len {
                let mut s = Sha256::new();
                s.update(&msg[..split]);
                s.update(&msg[split..len]);
                assert_eq!(s.finalize(), whole, "len {len} split {split}");
            }
        }
    }

    // RFC 4231 HMAC-SHA256 test cases 1-7.
    #[test]
    fn rfc4231_case1() {
        let tag = hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            to_hex(&tag),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn rfc4231_case2() {
        let tag = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            to_hex(&tag),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn rfc4231_case3() {
        let tag = hmac_sha256(&[0xaa; 20], &[0xdd; 50]);
        assert_eq!(
            to_hex(&tag),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
    }

    #[test]
    fn rfc4231_case4() {
        let key = h("0102030405060708090a0b0c0d0e0f10111213141516171819");
        let tag = hmac_sha256(&key, &[0xcd; 50]);
        assert_eq!(
            to_hex(&tag),
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
        );
    }

    #[test]
    fn rfc4231_case5_truncated() {
        let tag = hmac_sha256(&[0x0c; 20], b"Test With Truncation");
        assert_eq!(to_hex(&tag[..16]), "a3b6167473100ee06e0c796c2955552b");
    }

    #[test]
    fn rfc4231_case6_long_key() {
        let tag = hmac_sha256(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            to_hex(&tag),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn rfc4231_case7_long_key_long_data() {
        let tag = hmac_sha256(
            &[0xaa; 131],
            b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
        );
        assert_eq!(
            to_hex(&tag),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
        );
    }

    #[test]
    fn hmac_key_of_exactly_block_size_is_not_hashed() {
        // A 64-byte key is used as-is; a 65-byte key is hashed. They differ.
        let k64 = [0x11u8; 64];
        let k65 = [0x11u8; 65];
        assert_ne!(hmac_sha256(&k64, b"m"), hmac_sha256(&k65, b"m"));
        // A key and its zero-padded form are equivalent per RFC 2104.
        let mut padded = [0u8; 64];
        padded[..3].copy_from_slice(b"key");
        assert_eq!(hmac_sha256(b"key", b"m"), hmac_sha256(&padded, b"m"));
    }

    #[test]
    fn ct_eq_behaviour() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(!ct_eq(&[0u8; 32], &[1u8; 32]));
    }

    #[test]
    fn wipe_zeroes_every_element() {
        let mut b = [0xa5u8; 77];
        wipe(&mut b);
        assert!(b.iter().all(|&x| x == 0));
        let mut e: [u8; 0] = [];
        wipe(&mut e);
    }

    #[test]
    #[allow(unsafe_code)] // inspects the bytes `Drop` left behind
    fn dropped_hasher_state_is_wiped() {
        // What `Drop` runs must clear the whole `sha2` state: the chaining
        // value (never all zero for a live hasher: it starts at the IV) and
        // the buffered (key-derived) input.
        let mut h = Sha256::new();
        h.update(&[0x36; 70]);
        let size = std::mem::size_of::<sha2::Sha256>();
        assert_eq!(std::mem::size_of::<Sha256>(), size);
        // SAFETY: `h` is dropped in place exactly once and then forgotten.
        // `Drop` overwrote all `size` bytes of `h.inner` with volatile byte
        // stores, so every byte read below is initialised; `h` is never used
        // as a `Sha256` again.
        unsafe { std::ptr::drop_in_place(&mut h) };
        let p: *const u8 = (&*h.inner as *const sha2::Sha256).cast();
        // SAFETY: see above; `p` points to `size` initialised bytes inside
        // `h`, which is alive (only its destructor has run).
        let bytes = unsafe { std::slice::from_raw_parts(p, size) };
        assert!(bytes.iter().all(|&b| b == 0), "{bytes:?}");
        std::mem::forget(h);
    }

    #[test]
    fn finalize_matches_one_shot_and_hasher_is_reusable_by_clone() {
        let mut a = Sha256::new();
        a.update(b"ab");
        let b = a.clone();
        a.update(b"c");
        assert_eq!(a.finalize(), sha256(b"abc"));
        assert_eq!(b.finalize(), sha256(b"ab"));
        assert_eq!(Sha256::default().finalize(), sha256(b""));
    }

    #[test]
    fn fill_random_fills_and_differs() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill_random(&mut a).unwrap();
        fill_random(&mut b).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0; 32]);
        // Larger than one getrandom call usually returns is still filled.
        let mut big = vec![0u8; 1 << 20];
        fill_random(&mut big).unwrap();
        assert!(big.iter().filter(|&&x| x == 0).count() < big.len() / 64);
        fill_random(&mut []).unwrap();
        // The fallback path on its own.
        let mut c = [0u8; 32];
        urandom(&mut c).unwrap();
        assert_ne!(c, [0; 32]);
    }

    #[test]
    fn hex_round_trip_and_rejects() {
        let data: Vec<u8> = (0..=255u8).collect();
        assert_eq!(from_hex(&to_hex(&data)).unwrap(), data);
        assert_eq!(from_hex("ABcd").unwrap(), vec![0xab, 0xcd]);
        assert!(from_hex("abc").is_none());
        assert!(from_hex("zz").is_none());
        assert!(from_hex("é1").is_none());
        assert!(hash_from_hex("00").is_none());
        assert!(hash_from_hex(&"ab".repeat(32)).is_some());
    }
}
