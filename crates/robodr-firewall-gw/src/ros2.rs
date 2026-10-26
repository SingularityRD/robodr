//! ROS 2 velocity commands: `geometry_msgs/msg/Twist` and
//! `geometry_msgs/msg/TwistStamped` (the `/cmd_vel` of most ROS 2 mobile
//! bases; DDS topic `rt/cmd_vel`, types `geometry_msgs::msg::dds_::Twist_`
//! / `TwistStamped_`), decided with the firewall's **twist** path (the
//! same `check` as the sport `Move`).
//!
//! # Strict decode ([`decode_strict`])
//!
//! Plain CDR (XCDR1) only, either endianness, as `rmw_cyclonedds` and
//! `rmw_fastrtps` send it; XCDR2 (a `DHEADER`d appendable layout) is
//! undecidable. The layout is fixed, so canonical means:
//!
//! - `Twist`: six `float64` at body offsets 0..48 (linear x, y, z,
//!   angular x, y, z); the payload is exactly 4 + 48 octets with the
//!   options word zero.
//! - `TwistStamped`: `stamp.sec` (`int32`), `stamp.nanosec` (`uint32`),
//!   `frame_id` (`uint32` length including the NUL, at most 256 octets, no
//!   NUL inside, terminated by one), zero padding to the next multiple of
//!   8, then the six `float64`; nothing after them but the encapsulation
//!   padding the options word announces (zero octets).
//!
//! Anything else is an integrity failure (non-finite twist for the
//! firewall: its source, rate and substitute rules apply).
//!
//! # Rewrite ([`write_twist`])
//!
//! A limited or substitute twist overwrites the six `float64` in place
//! (`f64` exactly as the firewall output it: no rounding), keeps the
//! header, stamp and `frame_id`, and is verified by decoding again.

use robodr_cdr::{Endian, Representation, XcdrVersion};

use crate::lowcmd::{RewriteError, Undecidable};

/// Longest `frame_id` accepted (octets, NUL included).
pub const MAX_FRAME_ID: usize = 256;

/// A strictly decoded twist.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WireTwist {
    /// linear x, y, z, angular x, y, z.
    pub values: [f64; 6],
    /// Offset of the first `float64` in the slot.
    pub offset: usize,
    pub big: bool,
}

fn rep(slot: &[u8]) -> Option<bool> {
    let r = Representation::from_id(u16::from_be_bytes([*slot.first()?, *slot.get(1)?]))?;
    if r.is_parameter_list() || r.version()? != XcdrVersion::Xcdr1 {
        return None;
    }
    Some(r.endian()? == Endian::Big)
}

fn u32_at(b: &[u8], off: usize, big: bool) -> Option<u32> {
    let a: [u8; 4] = b.get(off..off + 4)?.try_into().ok()?;
    Some(if big {
        u32::from_be_bytes(a)
    } else {
        u32::from_le_bytes(a)
    })
}

fn f64_at(b: &[u8], off: usize, big: bool) -> Option<f64> {
    let a: [u8; 8] = b.get(off..off + 8)?.try_into().ok()?;
    Some(if big {
        f64::from_be_bytes(a)
    } else {
        f64::from_le_bytes(a)
    })
}

/// Decode `slot` strictly (module docs). `stamped`: `TwistStamped`.
pub fn decode_strict(slot: &[u8], stamped: bool) -> Result<WireTwist, Undecidable> {
    let big = rep(slot).ok_or(Undecidable::Decode)?;
    let options = slot.get(2..4).ok_or(Undecidable::Decode)?;
    let pad = usize::from(options[1] & 0x03);
    if options[0] != 0 || options[1] & !0x03 != 0 {
        return Err(Undecidable::NonCanonical);
    }
    let body = slot.get(4..).ok_or(Undecidable::Decode)?;
    let start = if stamped {
        let len = u32_at(body, 8, big).ok_or(Undecidable::Decode)? as usize;
        if len == 0 || len > MAX_FRAME_ID {
            return Err(Undecidable::Decode);
        }
        let s = body.get(12..12 + len).ok_or(Undecidable::Decode)?;
        if s.last() != Some(&0) || s[..len - 1].contains(&0) {
            return Err(Undecidable::NonCanonical);
        }
        let end = 12 + len;
        let aligned = end.div_ceil(8) * 8;
        if body
            .get(end..aligned)
            .is_none_or(|p| p.iter().any(|b| *b != 0))
        {
            return Err(Undecidable::NonCanonical);
        }
        aligned
    } else {
        0
    };
    let end = start + 48;
    // The message ends at `end`; the options word announces the padding
    // that rounds the payload to a multiple of 4 (zero octets).
    let want_pad = (4 - end % 4) % 4;
    if pad != want_pad || body.len() != end + pad {
        return Err(Undecidable::Trailing);
    }
    if body.get(end..).is_none_or(|t| t.iter().any(|b| *b != 0)) {
        return Err(Undecidable::Trailing);
    }
    let mut values = [0.0; 6];
    for (i, v) in values.iter_mut().enumerate() {
        *v = f64_at(body, start + 8 * i, big).ok_or(Undecidable::Decode)?;
    }
    Ok(WireTwist {
        values,
        offset: 4 + start,
        big,
    })
}

/// Lenient classification for the unknown-writer probe (review finding
/// F2): could `slot` be this channel's message in **any** encoding a DDS
/// reader might accept (XCDR1 or XCDR2, either endianness, `DHEADER`s,
/// non-zero padding, trailing octets)? Only decides channel membership:
/// the sample is then decided with [`decode_strict`] and fails closed.
/// `Twist`: a body of 48..=80 octets (six `float64`, plus up to three
/// `DHEADER`s and slack). `TwistStamped`: a stamp, a `frame_id` length of
/// 1..=256 and its text, then six `float64` with at most 48 octets of
/// headers / padding / trailing data, with or without a leading
/// `DHEADER`.
pub fn plausible(slot: &[u8], stamped: bool) -> bool {
    let Some(r) = slot
        .get(..2)
        .and_then(|h| Representation::from_id(u16::from_be_bytes([h[0], h[1]])))
    else {
        return false;
    };
    if r.is_parameter_list() {
        return false;
    }
    let big = r.endian() == Some(Endian::Big);
    let body = slot.get(4..).unwrap_or_default();
    if !stamped {
        return (48..=80).contains(&body.len());
    }
    [0usize, 4].iter().any(|&start| {
        let Some(len) = u32_at(body, start + 8, big).map(|l| l as usize) else {
            return false;
        };
        if len == 0 || len > MAX_FRAME_ID {
            return false;
        }
        let end = start + 12 + len;
        body.len() >= end + 48 && body.len() <= end + 48 + 48
    })
}

/// Overwrite the twist in `slot` (decoded as `w`) with `v` and verify.
pub fn write_twist(
    slot: &mut [u8],
    w: &WireTwist,
    v: [f64; 6],
    stamped: bool,
) -> Result<(), RewriteError> {
    if v.iter().any(|x| !x.is_finite()) {
        return Err(RewriteError::Value);
    }
    for (i, x) in v.iter().enumerate() {
        let b = if w.big {
            x.to_be_bytes()
        } else {
            x.to_le_bytes()
        };
        slot.get_mut(w.offset + 8 * i..w.offset + 8 * i + 8)
            .ok_or(RewriteError::Length)?
            .copy_from_slice(&b);
    }
    match decode_strict(slot, stamped) {
        Ok(back) if back.values == v => Ok(()),
        _ => Err(RewriteError::Verify),
    }
}

/// Test / harness helper: a canonical payload.
pub fn encode(values: [f64; 6], stamped: Option<(i32, u32, &str)>, big: bool) -> Vec<u8> {
    let mut body = Vec::new();
    let e32 = |v: u32| {
        if big {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    };
    if let Some((sec, nsec, frame)) = stamped {
        body.extend_from_slice(&e32(sec as u32));
        body.extend_from_slice(&e32(nsec));
        body.extend_from_slice(&e32(frame.len() as u32 + 1));
        body.extend_from_slice(frame.as_bytes());
        body.push(0);
        while body.len() % 8 != 0 {
            body.push(0);
        }
    }
    for v in values {
        body.extend_from_slice(&if big {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        });
    }
    let pad = (4 - body.len() % 4) % 4;
    let mut out = vec![0x00, if big { 0x00 } else { 0x01 }, 0x00, pad as u8];
    out.extend_from_slice(&body);
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_and_rewrite_both_layouts() {
        for big in [false, true] {
            for stamped in [None, Some((5, 7, "base_link")), Some((0, 0, ""))] {
                let p = encode([1.0, 0.5, 0.0, 0.0, 0.0, -0.75], stamped, big);
                let w = decode_strict(&p, stamped.is_some()).unwrap();
                assert_eq!(w.values, [1.0, 0.5, 0.0, 0.0, 0.0, -0.75]);
                let mut s = p.clone();
                write_twist(
                    &mut s,
                    &w,
                    [0.25, 0.0, 0.0, 0.0, 0.0, -0.5],
                    stamped.is_some(),
                )
                .unwrap();
                assert_eq!(s.len(), p.len());
                assert_eq!(
                    decode_strict(&s, stamped.is_some()).unwrap().values,
                    [0.25, 0.0, 0.0, 0.0, 0.0, -0.5]
                );
                // The stamp / frame id octets are untouched.
                assert_eq!(s[..w.offset], p[..w.offset]);
            }
        }
    }

    #[test]
    fn refusals() {
        let p = encode([0.0; 6], None, false);
        let mut long = p.clone();
        long.extend_from_slice(&[0; 4]);
        assert!(decode_strict(&long, false).is_err());
        assert!(decode_strict(&p[..p.len() - 1], false).is_err());
        let mut x2 = p.clone();
        x2[1] = 0x07; // CDR2_LE
        assert!(decode_strict(&x2, false).is_err());
        let s = encode([0.0; 6], Some((1, 2, "odom")), false);
        let mut nul = s.clone();
        nul[4 + 12] = 0; // NUL inside frame_id
        assert_eq!(decode_strict(&nul, true), Err(Undecidable::NonCanonical));
        let mut padx = s.clone();
        padx[4 + 12 + 5] = 1; // padding octet after the frame id
        assert_eq!(decode_strict(&padx, true), Err(Undecidable::NonCanonical));
        // A Twist is not a TwistStamped and vice versa.
        assert!(decode_strict(&p, true).is_err());
        assert!(decode_strict(&s, false).is_err());
    }
}
