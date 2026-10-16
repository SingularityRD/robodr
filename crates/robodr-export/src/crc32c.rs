//! CRC-32C (Castagnoli), as used by Kafka's RecordBatch v2.
//!
//! Reflected polynomial `0x82F63B78` (normal form `0x1EDC6F41`), initial
//! value `0xFFFFFFFF`, final XOR `0xFFFFFFFF` — the iSCSI CRC of RFC 3720
//! §12.1 / appendix B.4. Byte-wise table implementation (no SSE4.2): plenty
//! for findings traffic.

const POLY: u32 = 0x82F6_3B78;

const fn build_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ POLY } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

static TABLE: [u32; 256] = build_table();

/// Continue a CRC-32C over `data`; start with `crc = 0`. `update(update(0, a), b)
/// == crc32c(a ++ b)`.
pub fn update(crc: u32, data: &[u8]) -> u32 {
    let mut c = !crc;
    for &b in data {
        c = TABLE[((c ^ u32::from(b)) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

/// CRC-32C of `data`.
pub fn crc32c(data: &[u8]) -> u32 {
    update(0, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_value() {
        // The standard "check" value of the CRC catalogue (CRC-32/ISCSI).
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(b""), 0);
        assert_eq!(crc32c(b"a"), 0xC1D0_4330);
    }

    /// RFC 3720 appendix B.4. The RFC prints the CRC bytes in the order
    /// they are sent (little-endian), e.g. `aa 36 91 8a` = 0x8A9136AA.
    #[test]
    fn rfc3720_vectors() {
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
        assert_eq!(crc32c(&[0xffu8; 32]), 0x62A8_AB43);
        let inc: Vec<u8> = (0u8..32).collect();
        assert_eq!(crc32c(&inc), 0x46DD_794E);
        let dec: Vec<u8> = (0u8..32).rev().collect();
        assert_eq!(crc32c(&dec), 0x113F_DB5C);
        // iSCSI SCSI Read (10) command PDU.
        let pdu: [u8; 48] = [
            0x01, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x14,
            0x00, 0x00, 0x00, 0x18, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(crc32c(&pdu), 0xD996_3A56);
    }

    #[test]
    fn incremental_equals_one_shot() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
        for split in [0, 1, 7, 500, 999, 1000] {
            let (a, b) = data.split_at(split);
            assert_eq!(update(update(0, a), b), crc32c(&data));
        }
    }

    #[test]
    fn table_spot_values() {
        // Well-known entries of the reflected Castagnoli table.
        assert_eq!(TABLE[0], 0);
        assert_eq!(TABLE[1], 0xF26B_8303);
        assert_eq!(TABLE[128], POLY);
        assert_eq!(TABLE[255], 0xAD7D_5351);
    }
}
