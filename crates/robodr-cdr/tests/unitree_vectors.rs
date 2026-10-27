//! Independent Unitree test vectors (review item 13).
//!
//! `tests/data/unitree/` holds payloads produced by a reviewer's own CDR
//! writer and C++-image CRC (`gen.py`, `crc.py`; seed 7, random field
//! values), **not** by this crate: `<type>_le.bin` (`CDR_LE`), `_be.bin`
//! (`CDR_BE`), `_x2.bin` (`CDR2_LE`, plain XCDR2) and `<type>.json` (every
//! field value, nested in IDL member order). The CRC of each message was
//! computed by `gen.py` over the C++ natural-layout image with zeroed
//! padding (cross-checked by the reviewer against the Python SDK's
//! `struct` pack formats). They are synthetic values, not robot captures.

use robodr_cdr::unitree::*;
use robodr_cdr::{Limits, Representation};

const DATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/unitree/");

fn read(name: &str) -> Vec<u8> {
    std::fs::read(format!("{DATA}{name}")).unwrap()
}

/// Every number of the JSON document, in document order (the files are
/// nested arrays of numbers only).
fn json_numbers(name: &str) -> Vec<f64> {
    let text = String::from_utf8(read(name)).unwrap();
    text.split(|c: char| matches!(c, '[' | ']' | ',') || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<f64>().unwrap())
        .collect()
}

struct Flat(Vec<f64>);

impl Flat {
    fn u<T: Into<f64>>(&mut self, v: T) {
        self.0.push(v.into());
    }
    fn all<T: Copy + Into<f64>>(&mut self, v: &[T]) {
        for x in v {
            self.u(*x);
        }
    }
}

fn flat_go_low_cmd(c: &GoLowCmd) -> Vec<f64> {
    let mut f = Flat(Vec::new());
    f.all(&c.head);
    f.u(c.level_flag);
    f.u(c.frame_reserve);
    f.all(&c.sn);
    f.all(&c.version);
    f.u(c.bandwidth);
    for m in &c.motor_cmd {
        f.u(m.mode);
        f.all(&[m.q, m.dq, m.tau, m.kp, m.kd]);
        f.all(&m.reserve);
    }
    f.u(c.bms_cmd.off);
    f.all(&c.bms_cmd.reserve);
    f.all(&c.wireless_remote);
    f.all(&c.led);
    f.all(&c.fan);
    f.u(c.gpio);
    f.u(c.reserve);
    f.u(c.crc);
    f.0
}

fn flat_go_imu(f: &mut Flat, i: &GoImuState) {
    f.all(&i.quaternion);
    f.all(&i.gyroscope);
    f.all(&i.accelerometer);
    f.all(&i.rpy);
    f.u(i.temperature);
}

fn flat_go_low_state(s: &GoLowState) -> Vec<f64> {
    let mut f = Flat(Vec::new());
    f.all(&s.head);
    f.u(s.level_flag);
    f.u(s.frame_reserve);
    f.all(&s.sn);
    f.all(&s.version);
    f.u(s.bandwidth);
    flat_go_imu(&mut f, &s.imu_state);
    for m in &s.motor_state {
        f.u(m.mode);
        f.all(&[m.q, m.dq, m.ddq, m.tau_est, m.q_raw, m.dq_raw, m.ddq_raw]);
        f.u(m.temperature);
        f.u(m.lost);
        f.all(&m.reserve);
    }
    let b = &s.bms_state;
    f.all(&[b.version_high, b.version_low, b.status, b.soc]);
    f.u(b.current);
    f.u(b.cycle);
    f.all(&b.bq_ntc);
    f.all(&b.mcu_ntc);
    f.all(&b.cell_vol);
    f.all(&s.foot_force);
    f.all(&s.foot_force_est);
    f.u(s.tick);
    f.all(&s.wireless_remote);
    f.u(s.bit_flag);
    f.u(s.adc_reel);
    f.u(s.temperature_ntc1);
    f.u(s.temperature_ntc2);
    f.u(s.power_v);
    f.u(s.power_a);
    f.all(&s.fan_frequency);
    f.u(s.reserve);
    f.u(s.crc);
    f.0
}

fn flat_hg_low_cmd(c: &HgLowCmd) -> Vec<f64> {
    let mut f = Flat(Vec::new());
    f.u(c.mode_pr);
    f.u(c.mode_machine);
    for m in &c.motor_cmd {
        f.u(m.mode);
        f.all(&[m.q, m.dq, m.tau, m.kp, m.kd]);
        f.u(m.reserve);
    }
    f.all(&c.reserve);
    f.u(c.crc);
    f.0
}

fn flat_hg_low_state(s: &HgLowState) -> Vec<f64> {
    let mut f = Flat(Vec::new());
    f.all(&s.version);
    f.u(s.mode_pr);
    f.u(s.mode_machine);
    f.u(s.tick);
    let i = &s.imu_state;
    f.all(&i.quaternion);
    f.all(&i.gyroscope);
    f.all(&i.accelerometer);
    f.all(&i.rpy);
    f.u(i.temperature);
    for m in &s.motor_state {
        f.u(m.mode);
        f.all(&[m.q, m.dq, m.ddq, m.tau_est]);
        f.all(&m.temperature);
        f.u(m.vol);
        f.all(&m.sensor);
        f.u(m.motorstate);
        f.all(&m.reserve);
    }
    f.all(&s.wireless_remote);
    f.all(&s.reserve);
    f.u(s.crc);
    f.0
}

/// Decodes every encoding of `stem` as `kind` and checks the decoded
/// fields against the JSON and the CRC against `crc`.
fn check(stem: &str, kind: UnitreeKind, crc: u32) {
    let want = json_numbers(&format!("{stem}.json"));
    assert_eq!(*want.last().unwrap(), f64::from(crc), "{stem}: json crc");
    for (suffix, rep) in [
        ("le", Representation::CdrLe),
        ("be", Representation::CdrBe),
        ("x2", Representation::Cdr2Le),
    ] {
        let bytes = read(&format!("{stem}_{suffix}.bin"));
        let d = decode_unitree(kind, &bytes, &Limits::default())
            .unwrap_or_else(|e| panic!("{stem}_{suffix}: {e:?}"));
        assert_eq!(d.encapsulation.representation, rep, "{stem}_{suffix}");
        assert_eq!(d.trailing_bytes, 0, "{stem}_{suffix}");
        let (got, computed, ok) = match d.message {
            UnitreeMessage::GoLowCmd(m) => (flat_go_low_cmd(&m), m.computed_crc(), m.crc_ok()),
            UnitreeMessage::GoLowState(m) => (flat_go_low_state(&m), m.computed_crc(), m.crc_ok()),
            UnitreeMessage::HgLowCmd(m) => (flat_hg_low_cmd(&m), m.computed_crc(), m.crc_ok()),
            UnitreeMessage::HgLowState(m) => (flat_hg_low_state(&m), m.computed_crc(), m.crc_ok()),
            m => panic!("{m:?}"),
        };
        assert_eq!(got.len(), want.len(), "{stem}_{suffix}: field count");
        for (i, (g, w)) in got.iter().zip(&want).enumerate() {
            // f32 fields were written by Python as the exact f32 value in
            // f64 repr, so equality is exact.
            assert_eq!(g, w, "{stem}_{suffix}: field #{i}");
        }
        assert_eq!(computed, crc, "{stem}_{suffix}: computed crc");
        assert!(ok, "{stem}_{suffix}: crc_ok");
        assert_eq!(d.message.crc_ok(), Some(true));
    }
}

#[test]
fn go_low_cmd_independent_vector() {
    check("golowcmd", UnitreeKind::GoLowCmd, 0xe571_104a);
}

#[test]
fn go_low_state_independent_vector() {
    check("golowstate", UnitreeKind::GoLowState, 0x73b6_f94c);
}

#[test]
fn hg_low_cmd_independent_vector() {
    check("hglowcmd", UnitreeKind::HgLowCmd, 0x533c_453a);
}

#[test]
fn hg_low_state_independent_vector() {
    check("hglowstate", UnitreeKind::HgLowState, 0xe09e_bd5e);
}

#[test]
fn a_flipped_bit_breaks_the_crc() {
    let mut bytes = read("hglowcmd_le.bin");
    // motor_cmd[0].q (first byte after mode + 3 padding, after 4-byte
    // encapsulation and the two mode octets + 2 padding).
    bytes[4 + 4 + 4] ^= 0x01;
    let d = decode_unitree(UnitreeKind::HgLowCmd, &bytes, &Limits::default()).unwrap();
    assert_eq!(d.message.crc_ok(), Some(false));
}

/// Review item 12: the Unitree IDL types are `@final` (the generated
/// TypeObjects carry `IS_FINAL`, the Python IDL is `@annotate.final`), and
/// Cyclone DDS takes the extensibility from the type, using the
/// encapsulation only to choose XCDR1 / XCDR2. So a `D_CDR2` header on a
/// final type's payload changes nothing: no DHEADER on any struct, only on
/// non-primitive arrays.
#[test]
fn d_cdr2_header_on_final_types_reads_like_plain_cdr2() {
    for (stem, kind) in [
        ("golowcmd", UnitreeKind::GoLowCmd),
        ("golowstate", UnitreeKind::GoLowState),
        ("hglowcmd", UnitreeKind::HgLowCmd),
        ("hglowstate", UnitreeKind::HgLowState),
    ] {
        let plain = read(&format!("{stem}_x2.bin"));
        let mut delimited = plain.clone();
        delimited[1] = 0x09; // D_CDR2_LE
        let a = decode_unitree(kind, &plain, &Limits::default()).unwrap();
        let b = decode_unitree(kind, &delimited, &Limits::default())
            .unwrap_or_else(|e| panic!("{stem} as D_CDR2: {e:?}"));
        assert_eq!(b.encapsulation.representation, Representation::DCdr2Le);
        assert_eq!(a.message, b.message, "{stem}");
        assert_eq!(b.trailing_bytes, 0);
    }
}
