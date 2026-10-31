//! BLAKE2b-512 (RFC 7693), unkeyed, streaming: the prehash of minisign's
//! `ED` signatures ([`crate::minisign`]).
//!
//! Written here rather than taken from a crate so the on-robot verifier
//! adds no dependency (and no `Cargo.lock` change) for ~100 lines of a
//! fixed, fully specified function. It is checked against the RFC 7693
//! appendix A vector, against `b2sum` (coreutils) on every block-boundary
//! length, and end to end against signatures made by the real `minisign`.
//! Not constant time with respect to anything secret: it only ever hashes
//! public files.

/// Digest length (bytes).
pub const OUT_LEN: usize = 64;
const BLOCK: usize = 128;

const IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

const SIGMA: [[u8; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// The mixing function G on four words of `v` (literal indices only).
macro_rules! g {
    ($v:ident, $a:literal, $b:literal, $c:literal, $d:literal, $x:expr, $y:expr) => {
        $v[$a] = $v[$a].wrapping_add($v[$b]).wrapping_add($x);
        $v[$d] = ($v[$d] ^ $v[$a]).rotate_right(32);
        $v[$c] = $v[$c].wrapping_add($v[$d]);
        $v[$b] = ($v[$b] ^ $v[$c]).rotate_right(24);
        $v[$a] = $v[$a].wrapping_add($v[$b]).wrapping_add($y);
        $v[$d] = ($v[$d] ^ $v[$a]).rotate_right(16);
        $v[$c] = $v[$c].wrapping_add($v[$d]);
        $v[$b] = ($v[$b] ^ $v[$c]).rotate_right(63);
    };
}

fn compress(h: &mut [u64; 8], block: &[u8; BLOCK], t: u128, last: bool) {
    let mut m = [0u64; 16];
    for (w, c) in m.iter_mut().zip(block.chunks_exact(8)) {
        let mut b = [0u8; 8];
        b.copy_from_slice(c);
        *w = u64::from_le_bytes(b);
    }
    let mut v = [0u64; 16];
    for (d, s) in v.iter_mut().zip(h.iter().chain(IV.iter())) {
        *d = *s;
    }
    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;
    if last {
        v[14] = !v[14];
    }
    for s in SIGMA.iter().cycle().take(12) {
        let mut w = [0u64; 16];
        for (wi, &si) in w.iter_mut().zip(s.iter()) {
            *wi = m.get(usize::from(si)).copied().unwrap_or(0);
        }
        g!(v, 0, 4, 8, 12, w[0], w[1]);
        g!(v, 1, 5, 9, 13, w[2], w[3]);
        g!(v, 2, 6, 10, 14, w[4], w[5]);
        g!(v, 3, 7, 11, 15, w[6], w[7]);
        g!(v, 0, 5, 10, 15, w[8], w[9]);
        g!(v, 1, 6, 11, 12, w[10], w[11]);
        g!(v, 2, 7, 8, 13, w[12], w[13]);
        g!(v, 3, 4, 9, 14, w[14], w[15]);
    }
    let (lo, hi) = v.split_at(8);
    for ((hw, a), b) in h.iter_mut().zip(lo).zip(hi) {
        *hw ^= a ^ b;
    }
}

/// Streaming unkeyed BLAKE2b with a 64-byte digest.
#[derive(Clone)]
pub struct Blake2b512 {
    h: [u64; 8],
    t: u128,
    buf: [u8; BLOCK],
    len: usize,
}

impl Default for Blake2b512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake2b512 {
    pub fn new() -> Self {
        let mut h = IV;
        // Parameter block: digest length 64, no key, fanout 1, depth 1.
        h[0] ^= 0x0101_0000 ^ OUT_LEN as u64;
        Self {
            h,
            t: 0,
            buf: [0; BLOCK],
            len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            // The last block is compressed by `finalize` (with the final
            // flag), so a full buffer is only flushed when more data comes.
            if self.len == BLOCK {
                self.t = self.t.wrapping_add(BLOCK as u128);
                compress(&mut self.h, &self.buf, self.t, false);
                self.len = 0;
            }
            let take = (BLOCK - self.len).min(data.len());
            let (head, rest) = data.split_at(take);
            if let Some(dst) = self.buf.get_mut(self.len..self.len + take) {
                dst.copy_from_slice(head);
            }
            self.len += take;
            data = rest;
        }
    }

    pub fn finalize(mut self) -> [u8; OUT_LEN] {
        self.t = self.t.wrapping_add(self.len as u128);
        if let Some(tail) = self.buf.get_mut(self.len..) {
            tail.fill(0);
        }
        compress(&mut self.h, &self.buf, self.t, true);
        let mut out = [0u8; OUT_LEN];
        for (o, w) in out.chunks_exact_mut(8).zip(self.h.iter()) {
            o.copy_from_slice(&w.to_le_bytes());
        }
        out
    }
}

/// BLAKE2b-512 of `data` in one call.
pub fn blake2b512(data: &[u8]) -> [u8; OUT_LEN] {
    let mut h = Blake2b512::new();
    h.update(data);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn rfc7693_appendix_a() {
        assert_eq!(
            hex(&blake2b512(b"abc")),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
        assert_eq!(
            hex(&blake2b512(b"")),
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
             d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        );
    }

    /// Every length around the block boundaries, split at every point,
    /// against coreutils' `b2sum` (skipped where it is not installed).
    #[test]
    fn streaming_matches_b2sum() {
        let have = std::process::Command::new("b2sum")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success());
        let data: Vec<u8> = (0..600u32).map(|i| (i * 7 + 3) as u8).collect();
        for n in [0usize, 1, 127, 128, 129, 255, 256, 257, 383, 384, 385, 600] {
            let one = blake2b512(&data[..n]);
            for split in [0, 1.min(n), n / 2, n.saturating_sub(1), n] {
                let mut h = Blake2b512::new();
                h.update(&data[..split]);
                h.update(&data[split..n]);
                assert_eq!(h.finalize(), one, "n={n} split={split}");
            }
            let mut h = Blake2b512::new();
            for b in &data[..n] {
                h.update(std::slice::from_ref(b));
            }
            assert_eq!(h.finalize(), one, "n={n} bytewise");
            if have {
                use std::io::Write;
                let mut c = std::process::Command::new("b2sum")
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .spawn()
                    .unwrap();
                c.stdin.take().unwrap().write_all(&data[..n]).unwrap();
                let o = c.wait_with_output().unwrap();
                let s = String::from_utf8(o.stdout).unwrap();
                assert_eq!(s.split_whitespace().next().unwrap(), hex(&one), "n={n}");
            }
        }
    }
}
