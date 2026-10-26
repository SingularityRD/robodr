//! `robodr-commission learn --pcap ... --unitree-legacy`: a profile learned
//! from a capture of a Go1-generation robot (Unitree legacy UDP,
//! `unitree_legged_sdk`), built from the published `comm.h` layout.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use robodr_capture::{synth, LinkType, PcapWriter};
use robodr_cdr::unitree_legacy::{channels, LEGACY_HIGH_CMD_LEN};

const BIN: &str = env!("CARGO_BIN_EXE_robodr-commission");

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "robodr-commission-legacy-{}-{tag}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A `HighCmd` in target-velocity mode with a valid CRC.
fn high_cmd(vx: f32) -> Vec<u8> {
    let mut b = vec![0u8; LEGACY_HIGH_CMD_LEN];
    b[0..3].copy_from_slice(&[0xFE, 0xEF, 0xEE]);
    b[22] = 2;
    b[53..57].copy_from_slice(&vx.to_le_bytes());
    let crc = robodr_cdr::unitree::frame_crc(&b).unwrap();
    let n = b.len();
    b[n - 4..].copy_from_slice(&crc.to_le_bytes());
    b
}

fn capture(dir: &std::path::Path) -> PathBuf {
    let pc = Ipv4Addr::new(192, 168, 123, 15);
    let robot = Ipv4Addr::new(192, 168, 123, 161);
    let mut w = PcapWriter::new(Vec::new(), LinkType::ETHERNET, 65535, false).unwrap();
    for i in 0..40u64 {
        let f = synth::ethernet(
            0x0800,
            &synth::ipv4_udp(
                pc,
                robot,
                8090,
                8082,
                &high_cmd(0.4 + 0.01 * (i % 3) as f32),
            ),
        );
        w.write_packet(
            Duration::from_secs(1_760_000_000) + Duration::from_millis(20 * i),
            &f,
            f.len() as u32,
        )
        .unwrap();
    }
    let p = dir.join("go1.pcap");
    std::fs::write(&p, w.into_inner()).unwrap();
    p
}

#[test]
fn learn_with_unitree_legacy_envelopes_the_legacy_channel() {
    let dir = tmpdir("learn");
    let pcap = capture(&dir);
    let out = dir.join("profile.json");
    let report = dir.join("report.json");
    let o = Command::new(BIN)
        .args([
            "learn",
            "--pcap",
            pcap.to_str().unwrap(),
            "--unitree-legacy",
            "--model",
            "unitree-go1",
            "--out",
            out.to_str().unwrap(),
            "--report",
            report.to_str().unwrap(),
            "--quiet",
        ])
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let p: serde_json::Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    let max = p["motion_envelopes"][channels::HIGH_CMD]["max_linear_speed"]
        .as_f64()
        .unwrap();
    assert!((0.4..1.0).contains(&max), "{max}");
    assert!(p["writer_topics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t == channels::HIGH_CMD));
    // The report lists the command sender for the sensor configuration.
    let r = std::fs::read_to_string(&report).unwrap();
    assert!(r.contains("unitree_legacy_command_senders"), "{r}");
    assert!(r.contains("192.168.123.15"), "{r}");

    // Without the switch nothing is learned from the legacy frames.
    let out2 = dir.join("profile2.json");
    let o = Command::new(BIN)
        .args([
            "learn",
            "--pcap",
            pcap.to_str().unwrap(),
            "--out",
            out2.to_str().unwrap(),
            "--quiet",
        ])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0));
    let p: serde_json::Value = serde_json::from_slice(&std::fs::read(&out2).unwrap()).unwrap();
    assert!(p["motion_envelopes"].as_object().unwrap().is_empty());

    // A bad port is a usage error.
    let o = Command::new(BIN)
        .args([
            "learn",
            "--pcap",
            pcap.to_str().unwrap(),
            "--unitree-legacy-port",
            "0",
            "--out",
            dir.join("p3.json").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("--unitree-legacy-port"));
}
