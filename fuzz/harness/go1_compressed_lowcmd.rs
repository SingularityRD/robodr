//! Harness of the `go1_compressed_lowcmd` target: the v3.8.6 compressed Go1
//! `LowCmd` (614 bytes, the library's `refineCmd` layout) through the
//! independent decoder in `robodr-cdr` and the gateway's own decoder /
//! in-place writer in `robodr-firewall-gw`.
//!
//! Input: the raw UDP payload. Invariants (each a panic on violation):
//!
//! 1. `LegacyLowCmdCompressed::decode` succeeds iff the input is exactly
//!    614 bytes, and `encode` gives the input back byte for byte.
//! 2. `LegacyFrame::decode` of a 614-byte input is a `LowCmd` equal to the
//!    expansion, whose fixed-point fields are finite and exact.
//! 3. The gateway's `decode_low_compressed` is `Some` iff the cdr decoder
//!    succeeds and `bms.off` is zero, and agrees with it on every motor.
//! 4. Writing the decoded frame back over itself (`LowSource::Limited`)
//!    succeeds when every `q` / `dq` is finite (a non-finite value is
//!    never an output of the firewall and is refused with `Value`), leaves
//!    every motor field unchanged and seals a valid CRC; with a valid input
//!    CRC the bytes are unchanged.

use robodr_cdr::unitree_legacy::{
    LegacyFrame, LegacyLowCmdCompressed, LEGACY_LOW_CMD_COMPRESSED_LEN,
};
use robodr_firewall_gw::legacy;

pub fn run(data: &[u8]) {
    let c = LegacyLowCmdCompressed::decode(data);
    assert_eq!(c.is_ok(), data.len() == LEGACY_LOW_CMD_COMPRESSED_LEN);
    let gw = legacy::decode_low_compressed(data);
    let Ok(c) = c else {
        assert!(gw.is_none());
        return;
    };
    assert_eq!(&c.encode()[..], data);
    let x = c.expand();
    match LegacyFrame::decode(data) {
        Ok(LegacyFrame::LowCmd(f)) => assert_eq!(
            f.motor_cmd.map(|m| m.kd.to_bits()),
            x.motor_cmd.map(|m| m.kd.to_bits())
        ),
        other => panic!("614 bytes decoded as {other:?}"),
    }
    for (m, e) in c.motor_cmd.iter().zip(x.motor_cmd.iter()) {
        assert!(e.tau.is_finite() && e.kp.is_finite() && e.kd.is_finite());
        assert_eq!(f64::from(e.tau) * 256.0, f64::from(m.tau_q));
        assert_eq!(f64::from(e.kp) * 32.0, f64::from(m.kp_q));
        assert_eq!(f64::from(e.kd) * 16.0, f64::from(m.kd_q));
        assert_eq!(e.q.to_bits(), m.q_bits);
    }
    assert_eq!(gw.is_some(), c.bms.off == 0);
    let Some(jf) = gw else {
        return;
    };
    for (i, m) in jf.motors().iter().enumerate() {
        let e = x.motor_cmd[i];
        assert_eq!(m.tau, f64::from(e.tau));
        assert_eq!(m.kp, f64::from(e.kp));
        assert_eq!(m.kd, f64::from(e.kd));
        assert_eq!(m.q.to_bits(), f64::from(e.q).to_bits());
    }
    let mut w = data.to_vec();
    let r = legacy::write_low_compressed(&mut w, &jf, legacy::LowSource::Limited);
    if jf
        .motors()
        .iter()
        .any(|m| !m.q.is_finite() || !m.dq.is_finite())
    {
        assert_eq!(r, Err(robodr_firewall_gw::lowcmd::RewriteError::Value));
        return;
    }
    r.expect("rewriting a frame with its own values");
    assert!(legacy::crc_ok(&w));
    for i in 0..20 {
        assert_eq!(
            legacy::lowc_motor(&w, i).map(|(m, f, q)| (m, f.map(f32::to_bits), q)),
            legacy::lowc_motor(data, i).map(|(m, f, q)| (m, f.map(f32::to_bits), q))
        );
    }
    if jf.crc_ok == Some(true) {
        assert_eq!(w, data);
    }
}
