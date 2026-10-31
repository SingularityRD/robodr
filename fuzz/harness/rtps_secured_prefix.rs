//! Harness of the `rtps_secured_prefix` target: `robodr_rtps::secured_prefix`
//! (does a DDS-Security GUID prefix belong to the certificate subject an
//! SPDP identity token claims?). Both inputs are attacker-controlled text
//! in a crafted SPDP.
//!
//! Input: 12 bytes of GUID prefix, then the subject text (lossy UTF-8; a
//! shorter input is padded with zeros). Invariants (each a panic on
//! violation):
//!
//! 1. No panic, bounded time, and the answer is deterministic.
//! 2. Only the first 6 prefix bytes count: the answer does not change when
//!    the last 6 are replaced.
//! 3. A match has the DDS-Security "secured" bit (the prefix's first bit)
//!    set, and flipping any other of the 47 hashed bits breaks it.

use robodr_rtps::secured_prefix::prefix_matches_subject;

pub fn run(data: &[u8]) {
    let mut prefix = [0u8; 12];
    for (p, b) in prefix.iter_mut().zip(data) {
        *p = *b;
    }
    let subject = String::from_utf8_lossy(data.get(12..).unwrap_or_default());
    let m = prefix_matches_subject(&prefix, &subject);
    assert_eq!(
        m,
        prefix_matches_subject(&prefix, &subject),
        "deterministic"
    );
    let mut tail = prefix;
    for b in tail.iter_mut().skip(6) {
        *b = !*b;
    }
    assert_eq!(
        m,
        prefix_matches_subject(&tail, &subject),
        "bytes 6..12 must not count"
    );
    if m {
        assert_eq!(prefix[0] & 0x80, 0x80, "a match without the secured bit");
        for bit in 1..48 {
            let mut other = prefix;
            other[bit / 8] ^= 0x80 >> (bit % 8);
            assert!(
                !prefix_matches_subject(&other, &subject),
                "hash bit {bit} ignored"
            );
        }
    }
}
