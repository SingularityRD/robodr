//! Harness: pcap / pcapng file reader (`robodr_capture::CaptureFile`) and the
//! capture pipeline behind it (`rtps_datagrams`: link decode, port filter,
//! IP reassembly) down to the RTPS parser.
//!
//! Input: the raw bytes of a capture file. Invariants beyond "no panic":
//! the raw reader yields a bounded number of packets (no infinite loop on a
//! zero-length block), every captured packet fits in the input, and every
//! reassembled payload is at most a maximal IP datagram.
#![allow(dead_code)]

use robodr_capture::{rtps_datagrams, CaptureFile, PacketSource};

/// Upper bound on packets per input; a capture record has at least a
/// 16-byte (pcap) or 32-byte (pcapng EPB) header, so this is generous.
pub fn max_packets(len: usize) -> usize {
    len / 12 + 1
}

pub fn run(data: &[u8]) {
    // Raw reader.
    if let Ok(mut src) = CaptureFile::new(data) {
        let mut count = 0usize;
        loop {
            match src.next_packet() {
                Ok(Some(p)) => {
                    assert!(
                        p.data.len() <= data.len(),
                        "packet of {} bytes from a {}-byte file",
                        p.data.len(),
                        data.len()
                    );
                    count += 1;
                    assert!(count <= max_packets(data.len()), "unbounded packet count");
                }
                Ok(None) => break,
                Err(e) if e.is_transient() => panic!("file source returned transient {e:?}"),
                Err(_) => break,
            }
        }
    }
    // Full pipeline (decode + filter + reassembly) and the RTPS parser.
    if let Ok(src) = CaptureFile::new(data) {
        let mut it = rtps_datagrams(src);
        let mut n = 0usize;
        while let Some(pkt) = it.next_packet() {
            assert!(pkt.payload.len() <= 65_535, "oversized datagram");
            let ip = pkt.src.to_string();
            let _ = robodr_rtps::parse_datagram(&pkt.payload, &ip);
            n += 1;
            assert!(n <= max_packets(data.len()), "unbounded datagram count");
        }
    }
}
