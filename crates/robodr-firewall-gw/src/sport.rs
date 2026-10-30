//! Unitree sport API requests (`unitree_api::msg::dds_::Request_` on
//! `rt/api/sport/request`): strict decode and in-place rewrite of a `Move`
//! (api 1008, parameter `{"x": vx, "y": vy, "z": vyaw}`).
//!
//! # Strict decode ([`decode_strict`])
//!
//! As for `LowCmd_`: `robodr-cdr` decodes, this module re-encodes the
//! request canonically (header, the parameter string with its single
//! terminating NUL, the `binary` octet sequence) and the body must match
//! byte for byte, with at most 3 zero octets after it. The parameter must
//! not contain a NUL before its terminator (a C++ reader and a Rust reader
//! could disagree on where such a string ends).
//!
//! The call is interpreted by `robodr-cdr` for the `sport` service
//! ([`ApiCall`]); an `api_id` outside `i32` (the robot dispatches on the
//! low 32 bits, so `2^32 + 1008` *is* `Move`) is reported by the caller as
//! undecidable, never interpreted.
//!
//! # Rewrite ([`write_move`])
//!
//! A limited or substitute `Move` is written as a new parameter string of
//! the **same length**: `{"x":X,"y":Y,"z":Z}` padded with spaces before the
//! closing brace (JSON whitespace). Each number is printed with at most 6
//! decimals, **truncated toward zero**, and then parsed back: if the
//! decimal text would parse to a value of larger magnitude than the
//! firewall's output (decimal / binary rounding), the last digit is moved
//! toward zero again, and the same if the value rounded to the nearest
//! `f32` (the SDK clients keep a `float`) would be larger. So the robot's
//! JSON reader can never read more speed than the firewall allowed. If the text does not fit, fewer decimals are
//! used; if even integers do not fit, the rewrite fails (the caller then
//! suppresses the sample). Every other field of the request (request id,
//! `api_id`, lease, priority, `noreply`, `binary`) is kept. The written
//! slot is decoded again and must read back as a `Move` with the written
//! values.

use std::io::Write as _;
use std::ops::Range;

use robodr_cdr::unitree::{decode_unitree, ApiService, UnitreeKind, UnitreeMessage, UnitreeModel};
use robodr_cdr::{ApiCall, Endian, Limits, Representation, XcdrVersion};

use crate::lowcmd::{RewriteError, Undecidable};

/// The sport `Move` api id.
pub const API_MOVE: i32 = 1008;
/// The sport `StopMove` api id.
pub const API_STOP_MOVE: i32 = 1003;

/// A strictly decoded sport request.
#[derive(Debug, Clone, PartialEq)]
pub struct SportRequest {
    /// The wire api id.
    pub api_id: i64,
    /// The call, interpreted for the `sport` service.
    pub call: ApiCall,
    /// Offset range of the parameter text (terminator excluded) in the slot.
    pub param: Range<usize>,
}

/// Canonical body of a request; returns (length, parameter range in body).
#[allow(clippy::too_many_arguments)]
fn encode_body(
    out: &mut [u8],
    big: bool,
    xcdr2: bool,
    id: i64,
    api_id: i64,
    lease: i64,
    priority: i32,
    noreply: u8,
    param: &[u8],
    binary: &[u8],
) -> Option<(usize, Range<usize>)> {
    let max_align = if xcdr2 { 4 } else { 8 };
    let mut pos = 0usize;
    let mut put = |pos: &mut usize, bytes: &[u8], align: usize| -> Option<()> {
        let a = align.min(max_align).max(1);
        while !(*pos).is_multiple_of(a) {
            *out.get_mut(*pos)? = 0;
            *pos += 1;
        }
        let end = pos.checked_add(bytes.len())?;
        out.get_mut(*pos..end)?.copy_from_slice(bytes);
        *pos = end;
        Some(())
    };
    let e8 = |v: i64| {
        if big {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    };
    let e4 = |v: u32| {
        if big {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    };
    put(&mut pos, &e8(id), 8)?;
    put(&mut pos, &e8(api_id), 8)?;
    put(&mut pos, &e8(lease), 8)?;
    put(&mut pos, &e4(priority as u32), 4)?;
    put(&mut pos, &[noreply], 1)?;
    let slen = u32::try_from(param.len().checked_add(1)?).ok()?;
    put(&mut pos, &e4(slen), 4)?;
    let p0 = pos;
    put(&mut pos, param, 1)?;
    let p1 = pos;
    put(&mut pos, &[0], 1)?;
    put(&mut pos, &e4(u32::try_from(binary.len()).ok()?), 4)?;
    put(&mut pos, binary, 1)?;
    Some((pos, p0..p1))
}

fn rep_of(slot: &[u8]) -> Option<(bool, bool)> {
    let rep = Representation::from_id(u16::from_be_bytes([*slot.first()?, *slot.get(1)?]))?;
    if rep.is_parameter_list() {
        return None;
    }
    Some((
        rep.endian()? == Endian::Big,
        rep.version()? == XcdrVersion::Xcdr2,
    ))
}

/// Largest request body re-encoded on the hot path (stack scratch); a
/// larger request is undecidable. Motion requests are tens of bytes; a B2
/// `TrajectoryFollow` is about 3 KB.
pub const MAX_REQUEST_BODY: usize = 8192;

/// Decode `slot` strictly (module docs), interpreted for the `sport`
/// service.
pub fn decode_strict(
    slot: &[u8],
    model: Option<UnitreeModel>,
) -> Result<SportRequest, Undecidable> {
    decode_strict_for(slot, ApiService::Sport, model)
}

/// [`decode_strict`] for any service (the humanoid locomotion clients:
/// `sport` on G1 / H2 / R1, `loco` on H1).
pub fn decode_strict_for(
    slot: &[u8],
    service: ApiService,
    model: Option<UnitreeModel>,
) -> Result<SportRequest, Undecidable> {
    let (big, xcdr2) = rep_of(slot).ok_or(Undecidable::Decode)?;
    let d = decode_unitree(UnitreeKind::ApiRequest, slot, &Limits::default())
        .map_err(|_| Undecidable::Decode)?;
    let UnitreeMessage::ApiRequest(r) = d.message else {
        return Err(Undecidable::Decode);
    };
    let param = r.parameter.as_bytes();
    if param.contains(&0) {
        return Err(Undecidable::NonCanonical);
    }
    if d.trailing_bytes > 3 {
        return Err(Undecidable::Trailing);
    }
    let body = slot.get(4..).ok_or(Undecidable::Decode)?;
    if body
        .get(d.consumed..)
        .is_none_or(|t| t.iter().any(|b| *b != 0))
    {
        return Err(Undecidable::Trailing);
    }
    let mut scratch = [0u8; MAX_REQUEST_BODY];
    let (n, prange) = encode_body(
        &mut scratch,
        big,
        xcdr2,
        r.id,
        r.api_id,
        r.lease_id,
        r.priority,
        r.noreply_octet,
        param,
        r.binary,
    )
    .ok_or(Undecidable::NonCanonical)?;
    if n != d.consumed || scratch.get(..n) != body.get(..n) {
        return Err(Undecidable::NonCanonical);
    }
    Ok(SportRequest {
        api_id: r.api_id,
        call: r.call(service, model),
        param: 4 + prange.start..4 + prange.end,
    })
}

/// Write `v` with at most `decimals` decimals, truncated toward zero, such
/// that the text parses back to a magnitude `<= |v|` with the same sign
/// (or zero). Returns the number of octets written.
fn write_number(out: &mut [u8], v: f64, decimals: u32) -> Option<usize> {
    if !v.is_finite() {
        return None;
    }
    let scale = 10f64.powi(decimals as i32);
    let mut k = (v * scale).trunc();
    for _ in 0..4 {
        let mut cur = std::io::Cursor::new(&mut *out);
        let t = k / scale;
        if k == 0.0 {
            write!(cur, "0").ok()?;
        } else {
            write!(cur, "{:.*}", decimals as usize, t).ok()?;
        }
        let mut n = usize::try_from(cur.position()).ok()?;
        // Trim trailing zeros of the fraction (and a bare dot): same value.
        if decimals > 0 && k != 0.0 {
            while n > 1 && out.get(n - 1) == Some(&b'0') {
                n -= 1;
            }
            if out.get(n - 1) == Some(&b'.') {
                n -= 1;
            }
        }
        let text = std::str::from_utf8(out.get(..n)?).ok()?;
        let back: f64 = text.parse().ok()?;
        // The robot's SDK reads a double and keeps a `float`: neither may
        // exceed the firewall's value (review finding F10 d).
        let as_f32 = f64::from(back as f32);
        if back.abs() <= v.abs()
            && as_f32.abs() <= v.abs()
            && (back == 0.0 || back.signum() == v.signum())
        {
            return Some(n);
        }
        // Move one unit toward zero and retry.
        k -= k.signum();
    }
    None
}

/// The `Move` parameter of a service: its three keys and what follows
/// them (sport `{"x","y","z"}`; obstacles_avoid `{"x","y","yaw","mode":0}`:
/// the velocity mode).
fn move_shape(service: ApiService) -> ([&'static str; 3], &'static str) {
    match service {
        ApiService::ObstaclesAvoid => (["x", "y", "yaw"], ",\"mode\":0"),
        _ => (["x", "y", "z"], ""),
    }
}

/// Render `{"x":vx,"y":vy,"z":vyaw}` (or the service's shape,
/// [`move_shape`]) into `out` in at most `max` octets, with as many
/// decimals (6 down to 0) as fit. Returns the length.
fn render_move(out: &mut [u8], max: usize, v: [f64; 3], service: ApiService) -> Option<usize> {
    let (keys, suffix) = move_shape(service);
    for decimals in [6u32, 5, 4, 3, 2, 1, 0] {
        let mut pos = 0usize;
        let mut ok = true;
        for (i, (key, val)) in keys.iter().zip(v).enumerate() {
            let pre = if i == 0 { "{\"" } else { ",\"" };
            for part in [pre, key, "\":"] {
                let b = part.as_bytes();
                match out.get_mut(pos..pos + b.len()) {
                    Some(dst) => dst.copy_from_slice(b),
                    None => {
                        ok = false;
                        break;
                    }
                }
                pos += b.len();
            }
            if !ok {
                break;
            }
            match out
                .get_mut(pos..)
                .and_then(|o| write_number(o, val, decimals))
            {
                Some(n) => pos += n,
                None => {
                    ok = false;
                    break;
                }
            }
        }
        if ok && put(out, &mut pos, suffix).is_some() {
            if let Some(b) = out.get_mut(pos) {
                *b = b'}';
                pos += 1;
                if pos <= max {
                    return Some(pos);
                }
            }
        }
    }
    None
}

/// Rewrite the request in `slot` to `Move(vx, vy, vyaw)` (module docs).
/// `req` must be the [`decode_strict`] result for this slot.
pub fn write_move(
    slot: &mut [u8],
    req: &SportRequest,
    v: [f64; 3],
    model: Option<UnitreeModel>,
) -> Result<(), RewriteError> {
    write_move_for(slot, req, v, ApiService::Sport, model)
}

/// [`write_move`] for the velocity `Move` of any service decoded with
/// [`decode_strict_for`] (obstacles_avoid: `{"x","y","yaw","mode":0}`).
pub fn write_move_for(
    slot: &mut [u8],
    req: &SportRequest,
    v: [f64; 3],
    service: ApiService,
    model: Option<UnitreeModel>,
) -> Result<(), RewriteError> {
    let len = req
        .param
        .end
        .checked_sub(req.param.start)
        .ok_or(RewriteError::Length)?;
    let mut text = [0u8; 256];
    let cap = len.min(text.len());
    let n = render_move(&mut text, cap, v, service).ok_or(RewriteError::Length)?;
    let dst = slot
        .get_mut(req.param.clone())
        .ok_or(RewriteError::Length)?;
    let src = text.get(..n - 1).ok_or(RewriteError::Length)?;
    let (body, tail) = dst
        .split_at_mut_checked(src.len())
        .ok_or(RewriteError::Length)?;
    body.copy_from_slice(src);
    // Spaces before the closing brace, then the brace as the last octet.
    let (last, spaces) = tail.split_last_mut().ok_or(RewriteError::Length)?;
    spaces.fill(b' ');
    *last = b'}';
    // Verify.
    let back = decode_strict_for(slot, service, model).map_err(|_| RewriteError::Verify)?;
    match back.call {
        ApiCall::Move { vx, vy, vyaw } => {
            for (got, want) in [vx, vy, vyaw].into_iter().zip(v) {
                if !(got.abs() <= want.abs() && (got == 0.0 || got.signum() == want.signum())) {
                    return Err(RewriteError::Verify);
                }
            }
            Ok(())
        }
        _ => Err(RewriteError::Verify),
    }
}

fn put(out: &mut [u8], pos: &mut usize, t: &str) -> Option<()> {
    let b = t.as_bytes();
    out.get_mut(*pos..pos.checked_add(b.len())?)?
        .copy_from_slice(b);
    *pos += b.len();
    Some(())
}

fn put_number(out: &mut [u8], pos: &mut usize, v: f64, decimals: u32) -> Option<()> {
    let n = write_number(out.get_mut(*pos..)?, v, decimals)?;
    *pos += n;
    Some(())
}

/// Render `{"velocity":[vx,vy,vyaw],"duration":d}` into `out` in at most
/// `max` octets (as [`render_move`]: numbers truncated toward zero).
fn render_set_velocity(out: &mut [u8], max: usize, v: [f64; 3], duration: f64) -> Option<usize> {
    for decimals in [6u32, 5, 4, 3, 2, 1, 0] {
        let mut pos = 0usize;
        let ok = (|| {
            put(out, &mut pos, "{\"velocity\":[")?;
            for (i, val) in v.into_iter().enumerate() {
                if i > 0 {
                    put(out, &mut pos, ",")?;
                }
                put_number(out, &mut pos, val, decimals)?;
            }
            put(out, &mut pos, "],\"duration\":")?;
            put_number(out, &mut pos, duration, decimals)?;
            put(out, &mut pos, "}")
        })();
        if ok.is_some() && pos <= max {
            return Some(pos);
        }
    }
    None
}

/// Rewrite the request in `slot` to `SetVelocity(v, duration)` of the same
/// length (module docs: numbers truncated toward zero, padded with spaces
/// before the closing brace, verified by decoding again for `service` /
/// `model`: the velocity read back never exceeds `v` in magnitude and the
/// duration never exceeds `duration`).
pub fn write_set_velocity(
    slot: &mut [u8],
    req: &SportRequest,
    v: [f64; 3],
    duration: f64,
    service: ApiService,
    model: Option<UnitreeModel>,
) -> Result<(), RewriteError> {
    if !(duration.is_finite() && duration >= 0.0) {
        return Err(RewriteError::Value);
    }
    let len = req
        .param
        .end
        .checked_sub(req.param.start)
        .ok_or(RewriteError::Length)?;
    let mut text = [0u8; 256];
    let cap = len.min(text.len());
    let n = render_set_velocity(&mut text, cap, v, duration).ok_or(RewriteError::Length)?;
    let dst = slot
        .get_mut(req.param.clone())
        .ok_or(RewriteError::Length)?;
    let src = text.get(..n - 1).ok_or(RewriteError::Length)?;
    let (body, tail) = dst
        .split_at_mut_checked(src.len())
        .ok_or(RewriteError::Length)?;
    body.copy_from_slice(src);
    let (last, spaces) = tail.split_last_mut().ok_or(RewriteError::Length)?;
    spaces.fill(b' ');
    *last = b'}';
    let back = decode_strict_for(slot, service, model).map_err(|_| RewriteError::Verify)?;
    match back.call {
        ApiCall::SetVelocity {
            vx,
            vy,
            vyaw,
            duration: d,
        } => {
            for (got, want) in [vx, vy, vyaw].into_iter().zip(v) {
                if !(got.abs() <= want.abs() && (got == 0.0 || got.signum() == want.signum())) {
                    return Err(RewriteError::Verify);
                }
            }
            if !(d.is_finite() && d >= 0.0 && d <= duration) {
                return Err(RewriteError::Verify);
            }
            Ok(())
        }
        _ => Err(RewriteError::Verify),
    }
}

/// Test / harness helper: a serialized `Request_` payload.
pub fn encode_request(rep: Representation, id: i64, api_id: i64, param: &str) -> Vec<u8> {
    let big = rep.endian() == Some(Endian::Big);
    let xcdr2 = rep.version() == Some(XcdrVersion::Xcdr2);
    let mut scratch = vec![0u8; param.len() + 128];
    let (n, _) = encode_body(
        &mut scratch,
        big,
        xcdr2,
        id,
        api_id,
        0,
        0,
        0,
        param.as_bytes(),
        &[],
    )
    .unwrap_or((0, 0..0));
    let pad = (4 - n % 4) % 4;
    let idb = rep.id().to_be_bytes();
    let mut v = vec![idb[0], idb[1], 0, pad as u8];
    v.extend_from_slice(scratch.get(..n).unwrap_or_default());
    v.extend(std::iter::repeat_n(0u8, pad));
    v
}

#[cfg(test)]
mod tests {

    /// F10 (d): the robot reads these numbers into `float` (nlohmann::json
    /// reads a double, the SDK client casts it): the written text must
    /// never read back above the firewall's value as an `f32` either.
    #[test]
    fn written_numbers_never_round_up_as_f32() {
        let mut buf = [0u8; 64];
        for v in [0.8, 0.3, 0.1, 1.1, -0.3, -0.7, 0.123_456_7, 2.5, 1e-7, 0.6] {
            for decimals in [6u32, 3, 1] {
                let n = write_number(&mut buf, v, decimals).unwrap();
                let text = std::str::from_utf8(&buf[..n]).unwrap();
                let back = text.parse::<f64>().unwrap();
                let f = back as f32;
                assert!(
                    f64::from(f).abs() <= f64::abs(v),
                    "{v} written as {text}: f32 {f} is larger"
                );
            }
        }
    }

    use super::*;

    #[test]
    fn decode_and_rewrite_move() {
        for rep in [
            Representation::CdrLe,
            Representation::CdrBe,
            Representation::Cdr2Le,
        ] {
            let p = encode_request(rep, 42, 1008, r#"{"x":1.2,"y":-0.4,"z":0.75}"#);
            let r = decode_strict(&p, None).unwrap();
            assert_eq!(
                r.call,
                ApiCall::Move {
                    vx: 1.2,
                    vy: -0.4,
                    vyaw: 0.75
                }
            );
            let mut s = p.clone();
            write_move(&mut s, &r, [0.5, -0.1666666, 0.31], None).unwrap();
            assert_eq!(s.len(), p.len());
            let b = decode_strict(&s, None).unwrap();
            match b.call {
                ApiCall::Move { vx, vy, vyaw } => {
                    // 27 characters: two decimals fit, truncated toward zero;
                    // 0.31 as an f32 (0.3100000024) is above 0.31, so the
                    // last digit moves toward zero (0.30, trimmed to 0.3).
                    assert_eq!(vx, 0.5);
                    assert_eq!(vy, -0.16);
                    assert_eq!(vyaw, 0.3);
                }
                c => panic!("{c:?}"),
            }
            assert_eq!(b.api_id, 1008);
        }
    }

    #[test]
    fn numbers_never_round_up_in_magnitude() {
        let mut buf = [0u8; 64];
        let mut x = 0.123_f64;
        for _ in 0..20_000 {
            x = (x * 7.31 + 0.017).fract() * 4.0 - 2.0;
            for d in [0u32, 2, 4, 6] {
                let n = write_number(&mut buf, x, d).unwrap();
                let back: f64 = std::str::from_utf8(&buf[..n]).unwrap().parse().unwrap();
                assert!(back.abs() <= x.abs(), "{x} -> {back}");
                assert!(back == 0.0 || back.signum() == x.signum());
            }
        }
    }

    #[test]
    fn long_parameter_keeps_precision() {
        // nlohmann::json dumps doubles at full precision: plenty of room.
        let p = encode_request(
            Representation::CdrLe,
            7,
            1008,
            r#"{"x":0.30000001192092896,"y":0.0,"z":-0.5}"#,
        );
        let r = decode_strict(&p, None).unwrap();
        let mut s = p.clone();
        write_move(&mut s, &r, [0.25, 0.0, -0.123456789], None).unwrap();
        let b = decode_strict(&s, None).unwrap();
        assert_eq!(
            b.call,
            ApiCall::Move {
                vx: 0.25,
                vy: 0.0,
                vyaw: -0.123456
            }
        );
        let text = std::str::from_utf8(&s[b.param.clone()]).unwrap();
        assert!(
            text.starts_with(r#"{"x":0.25,"y":0,"z":-0.123456"#),
            "{text}"
        );
        assert!(text.ends_with(" }"), "{text}");
    }

    #[test]
    fn short_parameter_falls_back_or_fails() {
        // 19 characters: only the integer zero form fits.
        let p = encode_request(Representation::CdrLe, 1, 1008, r#"{"x":1,"y":0,"z":0}"#);
        let r = decode_strict(&p, None).unwrap();
        let mut s = p.clone();
        write_move(&mut s, &r, [0.5, 0.0, 0.0], None).unwrap();
        let b = decode_strict(&s, None).unwrap();
        assert_eq!(
            b.call,
            ApiCall::Move {
                vx: 0.0,
                vy: 0.0,
                vyaw: 0.0
            }
        );
        // Too short for any Move text.
        let p2 = encode_request(Representation::CdrLe, 1, 1008, r#"{"x":1}"#);
        let r2 = decode_strict(&p2, None).unwrap();
        let mut s2 = p2.clone();
        assert!(write_move(&mut s2, &r2, [0.0, 0.0, 0.0], None).is_err());
    }

    #[test]
    fn set_velocity_rewrite_never_exceeds() {
        use robodr_cdr::unitree::UnitreeModel as M;
        for (svc, model, id) in [
            (ApiService::Sport, M::G1, 7105),
            (ApiService::Sport, M::H2, 7105),
            (ApiService::Sport, M::R1, 7105),
            (ApiService::Loco, M::H1, 8105),
        ] {
            // What nlohmann::json writes for SetVelocity(0.3, 0, 0.1,
            // 864000) (`Move(..., continous_move = true)`).
            let p = encode_request(
                Representation::CdrLe,
                9,
                id,
                r#"{"duration":864000.0,"velocity":[0.30000001192092896,0.0,0.10000000149011612]}"#,
            );
            let r = decode_strict_for(&p, svc, Some(model)).unwrap();
            assert!(
                matches!(r.call, ApiCall::SetVelocity { .. }),
                "{:?}",
                r.call
            );
            let mut s = p.clone();
            write_set_velocity(&mut s, &r, [0.2, -0.05, 0.1], 1.0, svc, Some(model)).unwrap();
            assert_eq!(s.len(), p.len());
            match decode_strict_for(&s, svc, Some(model)).unwrap().call {
                ApiCall::SetVelocity {
                    vx,
                    vy,
                    vyaw,
                    duration,
                } => {
                    // Never above the value, also as an f32 (0.2 as f32 is
                    // 0.2000000030: written 0.199999).
                    for (got, want) in [(vx, 0.2f64), (vy, -0.05), (vyaw, 0.1)] {
                        assert!(
                            got.abs() <= want.abs() && (got - want).abs() < 2e-6,
                            "{got}"
                        );
                        assert!(f64::from(got as f32).abs() <= want.abs(), "{got}");
                    }
                    assert_eq!(duration, 1.0);
                }
                c => panic!("{c:?}"),
            }
            // Too short: refused.
            let p2 = encode_request(
                Representation::CdrLe,
                9,
                id,
                r#"{"velocity":[1,0,0],"duration":1}"#,
            );
            let r2 = decode_strict_for(&p2, svc, Some(model)).unwrap();
            let mut s2 = p2.clone();
            assert!(
                write_set_velocity(&mut s2, &r2, [0.5, 0.0, 0.0], 1.0, svc, Some(model)).is_ok()
            );
            let mut s3 = p2.clone();
            assert!(write_set_velocity(
                &mut s3,
                &r2,
                [0.123456, 0.654321, -0.111111],
                1.0,
                svc,
                Some(model)
            )
            .is_ok());
            match decode_strict_for(&s3, svc, Some(model)).unwrap().call {
                ApiCall::SetVelocity { vx, vy, vyaw, .. } => {
                    assert!(vx.abs() <= 0.123456 && vy.abs() <= 0.654321 && vyaw.abs() <= 0.111111);
                }
                c => panic!("{c:?}"),
            }
        }
    }

    #[test]
    fn refusals() {
        let p = encode_request(
            Representation::CdrLe,
            1,
            1008,
            "{\"x\":1\u{0},\"y\":0,\"z\":0}",
        );
        assert_eq!(decode_strict(&p, None), Err(Undecidable::NonCanonical));
        let mut q = encode_request(Representation::CdrLe, 1, 1008, r#"{"x":1,"y":0,"z":0}"#);
        q.extend_from_slice(&[0; 8]);
        assert_eq!(decode_strict(&q, None), Err(Undecidable::Trailing));
        assert_eq!(
            decode_strict(&[0, 1, 0, 0, 1], None),
            Err(Undecidable::Decode)
        );
    }
}
