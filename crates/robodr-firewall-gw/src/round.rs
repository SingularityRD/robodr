//! Conversion of the firewall's `f64` output to the wire's `f32` without
//! crossing a bound.
//!
//! The firewall decides in `f64`; Unitree frames carry `f32`. A value the
//! firewall clamped to a bound (say `tau_max = 23.7`) is generally not an
//! `f32`, and the nearest `f32` may lie just **outside** the bound
//! (`23.7_f32 = 23.700000762...`). The gateway therefore never rounds to
//! nearest when the value changed:
//!
//! - **Limited fields** ([`away_from`]): the firewall moved the value from
//!   the input `i` to `o`; the bound lies between them or at `o`, so the
//!   safe `f32` is the one on the far side of `o` from `i` (a clamped
//!   magnitude rounds inward, a stepped position rounds toward the previous
//!   target).
//! - **Substitute fields** ([`toward_zero`]): magnitudes only shrink.
//!   Fields of a held frame are taken bit-exact from the frame the gateway
//!   last forwarded (see `lowcmd`), so this only applies to values the
//!   firewall synthesised (the damping `kd`).
//!
//! Every helper returns `None` if the result would not be finite (a value
//! beyond `f32::MAX`), which the caller treats as a fault.

/// `o` as `f32` if exactly representable.
pub fn exact(o: f64) -> Option<f32> {
    let r = o as f32;
    (r.is_finite() && f64::from(r) == o).then_some(r)
}

/// The `f32` nearest `o` on the side of `o` away from `i` (or `o` itself if
/// representable).
pub fn away_from(o: f64, i: f64) -> Option<f32> {
    if !o.is_finite() {
        return None;
    }
    if let Some(r) = exact(o) {
        return Some(r);
    }
    let mut r = o as f32;
    if !r.is_finite() {
        r = if o > 0.0 { f32::MAX } else { f32::MIN };
    }
    let rf = f64::from(r);
    if i > o && rf > o {
        r = r.next_down();
    } else if i < o && rf < o {
        r = r.next_up();
    } else if i == o {
        // Unchanged value that is not an f32 cannot come from an f32 input;
        // treat as a synthesised value.
        return toward_zero(o);
    }
    r.is_finite().then_some(r)
}

/// The `f32` nearest `o` whose magnitude does not exceed `|o|`.
pub fn toward_zero(o: f64) -> Option<f32> {
    if !o.is_finite() {
        return None;
    }
    if let Some(r) = exact(o) {
        return Some(r);
    }
    let mut r = o as f32;
    if !r.is_finite() {
        return None;
    }
    if f64::from(r).abs() > o.abs() {
        r = if r > 0.0 { r.next_down() } else { r.next_up() };
    }
    Some(r)
}

/// `o` as a signed 16-bit fixed-point value of `scale` (the Go1 compressed
/// `LowCmd`'s `tau` / `Kp` / `Kd`: `value = q / scale`), on the side of `o`
/// away from `i` when `o` is not representable (same rule as
/// [`away_from`]). `None` if the result is outside `i16` (the SDK would
/// wrap it) or `o` is not finite.
pub fn fixed_away_from(o: f64, i: f64, scale: f64) -> Option<i16> {
    if !o.is_finite() || !i.is_finite() || !scale.is_finite() || scale <= 0.0 {
        return None;
    }
    let x = o * scale;
    let r = if x == x.trunc() {
        x
    } else if i > o {
        x.floor()
    } else if i < o {
        x.ceil()
    } else {
        x.trunc()
    };
    fixed_i16(r)
}

/// `o` as a fixed-point `i16` of `scale` whose magnitude does not exceed
/// `|o|` (substitute fields; see [`toward_zero`]).
pub fn fixed_toward_zero(o: f64, scale: f64) -> Option<i16> {
    if !o.is_finite() || !scale.is_finite() || scale <= 0.0 {
        return None;
    }
    fixed_i16((o * scale).trunc())
}

fn fixed_i16(r: f64) -> Option<i16> {
    if r.is_finite() && r >= f64::from(i16::MIN) && r <= f64::from(i16::MAX) {
        // Integral and in range: the conversion is exact.
        Some(r as i16)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_point_never_crosses_the_bound() {
        // tau_max 23.7 from 40: 23.7 * 256 = 6067.2 -> 6067 (below).
        let q = fixed_away_from(23.7, 40.0, 256.0).unwrap();
        assert!(f64::from(q) / 256.0 <= 23.7);
        // -23.7 from -40: toward zero.
        let q = fixed_away_from(-23.7, -40.0, 256.0).unwrap();
        assert!(f64::from(q) / 256.0 >= -23.7);
        // kp_min 2.01 from 0: rounds up.
        let q = fixed_away_from(2.01, 0.0, 32.0).unwrap();
        assert!(f64::from(q) / 32.0 >= 2.01);
        assert_eq!(fixed_away_from(1.5, 9.0, 16.0), Some(24));
        assert_eq!(fixed_toward_zero(-0.99, 16.0), Some(-15));
        assert_eq!(fixed_toward_zero(3000.0, 16.0), None);
        assert_eq!(fixed_away_from(f64::NAN, 0.0, 16.0), None);
        assert_eq!(fixed_away_from(1.0, f64::NAN, 16.0), None);
        assert_eq!(fixed_away_from(128.0, 200.0, 256.0), None);
        assert_eq!(fixed_away_from(-128.0, -200.0, 256.0), Some(i16::MIN));
        let mut x = 0.271_828_f64;
        for _ in 0..10_000 {
            x = (x * 1.618_033_988 + 0.37).fract() * 200.0 - 100.0;
            let i = x * 1.5 + 1.0;
            let q = f64::from(fixed_away_from(x, i, 32.0).unwrap()) / 32.0;
            if i > x {
                assert!(q <= x);
            } else if i < x {
                assert!(q >= x);
            }
            assert!((q - x).abs() < 1.0 / 32.0);
            let z = f64::from(fixed_toward_zero(x, 32.0).unwrap()) / 32.0;
            assert!(z.abs() <= x.abs());
        }
    }

    #[test]
    fn rounding_never_crosses_the_bound() {
        // 23.7 rounds up to nearest; a clamp from above must round down.
        assert!(f64::from(23.7_f32) > 23.7);
        let r = away_from(23.7, 40.0).unwrap();
        assert!(f64::from(r) <= 23.7);
        // Clamp of a negative value toward -23.7 from -40: round toward 0.
        let r = away_from(-23.7, -40.0).unwrap();
        assert!(f64::from(r) >= -23.7);
        // Position projected up onto q_min = -1.2345 from -2.0.
        let r = away_from(-1.2345, -2.0).unwrap();
        assert!(f64::from(r) >= -1.2345);
        // Step toward q_prev: target 1.0 stepped back to 0.3333.. from 1.0.
        let o = 0.1 + 0.2 / 3.0;
        let r = away_from(o, 1.0).unwrap();
        assert!(f64::from(r) <= o);
        let r = toward_zero(2.9).unwrap();
        assert!(f64::from(r) <= 2.9);
        let r = toward_zero(-2.9).unwrap();
        assert!(f64::from(r) >= -2.9);
        assert_eq!(exact(0.5), Some(0.5));
        assert_eq!(toward_zero(f64::NAN), None);
        assert_eq!(toward_zero(1e300), None);
        // Representable values are returned exactly.
        assert_eq!(away_from(0.25, 3.0), Some(0.25));
    }

    #[test]
    fn exhaustive_small_grid() {
        let mut x = 0.123_456_789_f64;
        for _ in 0..10_000 {
            x = (x * 1.618_033_988 + 0.37).fract() * 200.0 - 100.0;
            let i = x * 1.5 + 1.0;
            let r = away_from(x, i).unwrap();
            if i > x {
                assert!(f64::from(r) <= x);
            } else if i < x {
                assert!(f64::from(r) >= x);
            }
            assert!((f64::from(r) - x).abs() <= f64::from(f32::EPSILON) * x.abs().max(1.0));
            let z = toward_zero(x).unwrap();
            assert!(f64::from(z).abs() <= x.abs());
        }
    }
}
