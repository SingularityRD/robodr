//! Harness: bundle parity over `robodr-diode`'s Reed-Solomon code
//! (`robodr_pkg::parity`: `layout`, `encode_group`, `rebuild_group`,
//! parity file names).
//!
//! Input: `k`, `m`, an erasure bitmask (2 bytes), then `k` data files
//! (each a 1-byte length prefix, times 16, of the following bytes, short
//! at the end). Invariants beyond "no panic":
//!
//! * `layout` covers every data file exactly once, in order, in groups of
//!   at most `k`, each parity length a multiple of the shard size and at
//!   least the group's largest file;
//! * encoding then erasing up to `m` members of a group and rebuilding
//!   gives back every erased member byte for byte (data members up to
//!   their size, zero padding after); more than `m` erasures is refused;
//! * parity names round-trip and nothing else parses as one.
//!
//! The Reed-Solomon code itself is checked against an independent oracle
//! by the `diode_fec` target. Shared via `#[path]` with
//! `crates/robodr-pkg/tests/fuzz_smoke.rs`.
#![allow(dead_code)]

use robodr_pkg::parity::{encode_group, layout, parity_name, parse_parity_name, rebuild_group};

const SHARD: u64 = 512;

pub fn run(data: &[u8]) {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Some((g, j)) = parse_parity_name(s) {
            assert_eq!(parity_name(g as usize, j as usize), s);
        }
    }
    if data.len() < 4 {
        return;
    }
    let k = 1 + (data[0] % 8) as usize;
    let m = 1 + (data[1] % 4) as usize;
    let mask = u16::from_le_bytes([data[2], data[3]]);
    let mut rest = &data[4..];
    let mut files: Vec<Vec<u8>> = Vec::new();
    while files.len() < k * 3 && !rest.is_empty() {
        let n = (rest[0] as usize * 16).min(rest.len() - 1);
        files.push(rest[1..1 + n].to_vec());
        rest = &rest[1 + n..];
    }
    if files.is_empty() {
        return;
    }
    let sizes: Vec<u64> = files.iter().map(|f| f.len() as u64).collect();
    let lay = layout(&sizes, k, m, SHARD).expect("valid parameters");
    let mut next = 0;
    for (r, len) in &lay {
        assert_eq!(r.start, next);
        assert!(r.len() <= k && !r.is_empty());
        next = r.end;
        assert_eq!(len % SHARD, 0);
        assert!(sizes[r.clone()].iter().all(|s| s <= len));
    }
    assert_eq!(next, files.len());
    // One round trip per group.
    for (r, len) in &lay {
        let kg = r.len();
        let group: Vec<Vec<u8>> = files[r.clone()].to_vec();
        let mut parity = vec![vec![0u8; *len as usize]; m];
        encode_group(
            kg,
            m,
            *len,
            SHARD,
            &mut |pos, off, buf| {
                fill(&group[pos], off, buf);
                Ok(())
            },
            &mut |pos, off, bytes| {
                parity[pos - kg][off as usize..off as usize + bytes.len()].copy_from_slice(bytes);
                Ok(())
            },
        )
        .expect("encodes");
        let members: Vec<Vec<u8>> = group
            .iter()
            .cloned()
            .chain(parity.iter().cloned())
            .collect();
        let erased: Vec<usize> = (0..kg + m)
            .filter(|i| mask & (1 << (i % 16)) != 0)
            .collect();
        let mut out = vec![vec![0u8; *len as usize]; kg + m];
        let res = rebuild_group(
            kg,
            m,
            *len,
            SHARD,
            &erased,
            &mut |pos, off, buf| {
                assert!(!erased.contains(&pos));
                fill(&members[pos], off, buf);
                Ok(())
            },
            &mut |pos, off, bytes| {
                out[pos][off as usize..off as usize + bytes.len()].copy_from_slice(bytes);
                Ok(())
            },
        );
        if erased.len() > m {
            assert!(res.is_err());
            continue;
        }
        res.expect("rebuilds");
        for &e in &erased {
            let want = &members[e];
            assert_eq!(&out[e][..want.len()], &want[..], "member {e}");
            assert!(out[e][want.len()..].iter().all(|&b| b == 0));
        }
    }
}

fn fill(src: &[u8], off: u64, buf: &mut [u8]) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b = *src.get(off as usize + i).unwrap_or(&0);
    }
}

/// Seeds: a few file sets with one and two erasures.
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    let mut a = vec![3u8, 1, 0b101, 0];
    for i in 0..5u8 {
        a.push(40 + i);
        a.extend((0..(40 + i as usize) * 16).map(|j| (j * 7 + i as usize) as u8));
    }
    let mut b = vec![0u8, 0, 0b1, 0, 0];
    b.extend([2u8; 33]);
    vec![
        ("seed-groups.bin", a),
        ("seed-single.bin", b),
        ("seed-name.bin", b"g0042-p03.rbpar".to_vec()),
    ]
}
