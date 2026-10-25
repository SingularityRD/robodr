//! Unitree's `crc32_core`: the checksum that `LowCmd` / `LowState` (DDS
//! generation) and the legacy UDP frames carry in their last 4 bytes.
//!
//! Source: `crc32_core` in `unitree_sdk2/example/go2/go2_low_level.cpp`
//! (identical copies in the b2 / go2w / b2w examples, `Crc32Core` in the
//! g1 / h1 / h2 examples) and `CRC._crc_py` in
//! `unitree_sdk2_python/unitree_sdk2py/utils/crc.py`:
//!
//! * the input is a sequence of `uint32` words (the C++ struct read as
//!   `uint32_t*`, little endian on every Unitree target);
//! * CRC-32 polynomial `0x04C11DB7`, initial value `0xFFFFFFFF`, words fed
//!   MSB first, **no** final XOR and no reflection;
//! * the word count is `(sizeof(struct) >> 2) - 1`: every word except the
//!   last, which is the `crc` field itself.
//!
//! The words are the **C++ in-memory image** of the struct (natural
//! alignment, zero padding: the layout the Python SDK spells out with
//! `struct.pack` format strings), not the CDR bytes. The two differ (in
//! XCDR1 `MotorCmd_::mode` follows `bandwidth` without the 2 padding octets
//! the C++ struct has), so the decoders rebuild the image from the decoded
//! fields ([`CrcImage`]) to check the checksum.
//!
//! Padding octets are taken as zero, as the Python SDK packs them. A C++
//! sender whose padding octets are not zero would compute a different CRC;
//! the SDK examples value-initialise their messages, so this is not
//! expected, but it has not been checked against a real robot.

/// The CRC-32 polynomial Unitree uses (MSB-first form).
pub const UNITREE_CRC_POLY: u32 = 0x04C1_1DB7;

/// `crc32_core(ptr, len)` over `words` (see the module docs).
pub fn crc32_core(words: &[u32]) -> u32 {
    let mut crc = CrcState::new();
    for &w in words {
        crc.word(w);
    }
    crc.finish()
}

/// `crc32_core` over `bytes` read as little-endian `uint32` words. A
/// trailing partial word (fewer than 4 octets) is ignored, as the SDK's
/// `len >> 2` word count ignores it.
pub fn crc32_core_le_bytes(bytes: &[u8]) -> u32 {
    let mut crc = CrcState::new();
    for c in bytes.chunks_exact(4) {
        if let [a, b, c, d] = *c {
            crc.word(u32::from_le_bytes([a, b, c, d]));
        }
    }
    crc.finish()
}

/// The checksum a frame of `frame.len()` octets carries: `crc32_core` over
/// the first `(len >> 2) - 1` words (the SDK's convention, used for both
/// the DDS structs and the legacy UDP frames). `None` for a frame shorter
/// than 8 octets.
pub fn frame_crc(frame: &[u8]) -> Option<u32> {
    let words = (frame.len() >> 2).checked_sub(1).filter(|&w| w > 0)?;
    let covered = words.checked_mul(4)?;
    frame.get(..covered).map(crc32_core_le_bytes)
}

#[derive(Debug, Clone, Copy)]
struct CrcState(u32);

impl CrcState {
    fn new() -> Self {
        CrcState(0xFFFF_FFFF)
    }

    fn word(&mut self, data: u32) {
        let mut crc = self.0;
        let mut xbit: u32 = 1 << 31;
        for _ in 0..32 {
            let top = crc & 0x8000_0000 != 0;
            crc = crc.wrapping_shl(1);
            if top {
                crc ^= UNITREE_CRC_POLY;
            }
            if data & xbit != 0 {
                crc ^= UNITREE_CRC_POLY;
            }
            xbit = xbit.wrapping_shr(1);
        }
        self.0 = crc;
    }

    fn finish(self) -> u32 {
        self.0
    }
}

/// Streams the C++ in-memory image of a struct into `crc32_core` without
/// materialising it: octets are collected into little-endian words, padding
/// is explicit ([`CrcImage::pad`]) and the caller stops before the `crc`
/// field. A partial last word is dropped, matching `len >> 2`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CrcImage {
    crc: CrcState,
    word: [u8; 4],
    fill: usize,
    len: usize,
}

impl CrcImage {
    pub(crate) fn new() -> Self {
        CrcImage {
            crc: CrcState::new(),
            word: [0; 4],
            fill: 0,
            len: 0,
        }
    }

    pub(crate) fn u8(&mut self, b: u8) {
        if let Some(slot) = self.word.get_mut(self.fill) {
            *slot = b;
        }
        self.fill = self.fill.saturating_add(1);
        self.len = self.len.saturating_add(1);
        if self.fill >= 4 {
            self.crc.word(u32::from_le_bytes(self.word));
            self.fill = 0;
        }
    }

    pub(crate) fn bytes(&mut self, b: &[u8]) {
        for &x in b {
            self.u8(x);
        }
    }

    /// Zero octets up to the next multiple of `a` (C++ natural alignment).
    pub(crate) fn pad(&mut self, a: usize) {
        while self.len.checked_rem(a).unwrap_or(0) != 0 {
            self.u8(0);
        }
    }

    pub(crate) fn i8(&mut self, v: i8) {
        self.bytes(&v.to_le_bytes());
    }

    pub(crate) fn u16(&mut self, v: u16) {
        self.pad(2);
        self.bytes(&v.to_le_bytes());
    }

    pub(crate) fn i16(&mut self, v: i16) {
        self.pad(2);
        self.bytes(&v.to_le_bytes());
    }

    pub(crate) fn u32(&mut self, v: u32) {
        self.pad(4);
        self.bytes(&v.to_le_bytes());
    }

    pub(crate) fn i32(&mut self, v: i32) {
        self.pad(4);
        self.bytes(&v.to_le_bytes());
    }

    pub(crate) fn f32(&mut self, v: f32) {
        self.pad(4);
        self.bytes(&v.to_le_bytes());
    }

    /// Octets fed so far (the image offset).
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn finish(self) -> u32 {
        self.crc.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Straight transcription of the SDK's `crc32_core` loop, for the
    /// equivalence test below.
    fn reference(words: &[u32]) -> u32 {
        let mut crc: u32 = 0xFFFF_FFFF;
        for &data in words {
            let mut xbit: u32 = 1 << 31;
            for _ in 0..32 {
                if crc & 0x8000_0000 != 0 {
                    crc <<= 1;
                    crc ^= 0x04c1_1db7;
                } else {
                    crc <<= 1;
                }
                if data & xbit != 0 {
                    crc ^= 0x04c1_1db7;
                }
                xbit >>= 1;
            }
        }
        crc
    }

    /// Vectors computed by an independent re-implementation of the SDK's
    /// `crc32_core` (a small Python script, run offline; the SDK packages
    /// were not imported). This pins the implementation to the published
    /// algorithm, not just to the in-crate reference above.
    #[test]
    fn matches_independent_reference_vectors() {
        let v: Vec<u32> = (0..64u32)
            .map(|i| i.wrapping_mul(0x9E37_79B9) ^ 0xA5A5_0F0F)
            .collect();
        assert_eq!(crc32_core(&v[..16]), 0x9321_8db8);
        assert_eq!(crc32_core(&v), 0x711b_ef75);
        // All-zero go LowCmd image: (812 >> 2) - 1 = 202 words.
        assert_eq!(crc32_core(&[0u32; 202]), 0x4b5a_4880);
        // All-zero hg LowCmd image: (1004 >> 2) - 1 = 250 words.
        assert_eq!(crc32_core(&[0u32; 250]), 0xfe17_2f9f);
    }

    #[test]
    fn matches_the_sdk_loop() {
        let words: Vec<u32> = (0..64u32)
            .map(|i| i.wrapping_mul(0x9E37_79B9) ^ 0xA5A5_0F0F)
            .collect();
        for n in 0..words.len() {
            assert_eq!(crc32_core(&words[..n]), reference(&words[..n]));
        }
        assert_eq!(crc32_core(&[]), 0xFFFF_FFFF);
    }

    #[test]
    fn image_streams_le_words_and_drops_partial_word() {
        let mut img = CrcImage::new();
        img.u8(1);
        img.u16(0x0302); // padded to offset 2
        img.u32(0x0706_0504);
        img.u8(0xff); // partial word, dropped
        assert_eq!(img.len(), 9);
        assert_eq!(img.finish(), crc32_core(&[0x0302_0001, 0x0706_0504]));
        assert_eq!(
            crc32_core_le_bytes(&[1, 0, 2, 3, 4, 5, 6, 7, 0xff]),
            crc32_core(&[0x0302_0001, 0x0706_0504])
        );
        assert_eq!(frame_crc(&[0; 7]), None);
        assert_eq!(frame_crc(&[0; 8]), Some(crc32_core(&[0])));
        assert_eq!(frame_crc(&[0; 11]), Some(crc32_core(&[0])));
    }
}
