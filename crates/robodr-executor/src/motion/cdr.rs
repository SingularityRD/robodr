//! Plain CDR (XCDR1, little endian) for the few messages the motion
//! adapters send and the replies they read: `geometry_msgs/Twist`,
//! `action_msgs/srv/CancelGoal`, `controller_manager_msgs/srv/
//! SwitchController` and the Unitree `unitree_api` `Request_` /
//! `Response_`. Alignment is relative to the CDR origin (the octet after
//! the 4-octet encapsulation header); the payload is padded to a multiple
//! of 4 and the options word says by how much.

/// A CDR body writer (little endian).
#[derive(Debug, Default)]
pub struct Enc {
    pub b: Vec<u8>,
}

impl Enc {
    pub fn align(&mut self, n: usize) {
        while !self.b.len().is_multiple_of(n) {
            self.b.push(0);
        }
    }
    pub fn u8(&mut self, v: u8) {
        self.b.push(v);
    }
    pub fn bool(&mut self, v: bool) {
        self.b.push(u8::from(v));
    }
    pub fn u32(&mut self, v: u32) {
        self.align(4);
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    pub fn i32(&mut self, v: i32) {
        self.align(4);
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    pub fn i64(&mut self, v: i64) {
        self.align(8);
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.align(8);
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    pub fn f64(&mut self, v: f64) {
        self.align(8);
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    pub fn string(&mut self, s: &str) {
        self.u32(u32::try_from(s.len() + 1).unwrap_or(u32::MAX));
        self.b.extend_from_slice(s.as_bytes());
        self.b.push(0);
    }
    pub fn strings(&mut self, v: &[String]) {
        self.u32(u32::try_from(v.len()).unwrap_or(u32::MAX));
        for s in v {
            self.string(s);
        }
    }
    /// The serialized payload: `CDR_LE` header, body, padding.
    pub fn payload(self) -> Vec<u8> {
        let pad = (4 - self.b.len() % 4) % 4;
        let mut out = vec![0x00, 0x01, 0x00, pad as u8];
        out.extend_from_slice(&self.b);
        out.extend(std::iter::repeat_n(0u8, pad));
        out
    }
}

/// A CDR body reader (either endianness, from the encapsulation).
#[derive(Debug)]
pub struct Dec<'a> {
    b: &'a [u8],
    pos: usize,
    big: bool,
}

impl<'a> Dec<'a> {
    /// Open a payload (`CDR_BE` / `CDR_LE` only).
    pub fn open(payload: &'a [u8]) -> Result<Self, String> {
        let (h, b) = payload
            .split_first_chunk::<4>()
            .ok_or("payload shorter than its header")?;
        let big = match (h[0], h[1]) {
            (0, 0) => true,
            (0, 1) => false,
            _ => {
                return Err(format!(
                    "unsupported representation {:02x}{:02x}",
                    h[0], h[1]
                ))
            }
        };
        Ok(Dec { b, pos: 0, big })
    }
    fn align(&mut self, n: usize) {
        let r = self.pos % n;
        if r != 0 {
            self.pos += n - r;
        }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let s = self
            .b
            .get(self.pos..self.pos.saturating_add(n))
            .ok_or("truncated")?;
        self.pos += n;
        Ok(s)
    }
    pub fn u8(&mut self) -> Result<u8, String> {
        self.take(1)?
            .first()
            .copied()
            .ok_or_else(|| "truncated".into())
    }
    pub fn u32(&mut self) -> Result<u32, String> {
        self.align(4);
        let a: [u8; 4] = self.take(4)?.try_into().map_err(|_| "truncated")?;
        Ok(if self.big {
            u32::from_be_bytes(a)
        } else {
            u32::from_le_bytes(a)
        })
    }
    pub fn i32(&mut self) -> Result<i32, String> {
        Ok(self.u32()? as i32)
    }
    pub fn u64(&mut self) -> Result<u64, String> {
        self.align(8);
        let a: [u8; 8] = self.take(8)?.try_into().map_err(|_| "truncated")?;
        Ok(if self.big {
            u64::from_be_bytes(a)
        } else {
            u64::from_le_bytes(a)
        })
    }
    pub fn i64(&mut self) -> Result<i64, String> {
        Ok(self.u64()? as i64)
    }
    pub fn f64(&mut self) -> Result<f64, String> {
        Ok(f64::from_bits(self.u64()?))
    }
    pub fn string(&mut self) -> Result<String, String> {
        let n = self.u32()? as usize;
        if n == 0 || n > 4096 {
            return Err("bad string length".into());
        }
        let s = self.take(n)?;
        let (t, nul) = s.split_at(n - 1);
        if nul != [0] {
            return Err("string not terminated".into());
        }
        String::from_utf8(t.to_vec()).map_err(|_| "string not UTF-8".to_string())
    }
    pub fn strings(&mut self, max: usize) -> Result<Vec<String>, String> {
        let n = self.u32()? as usize;
        if n > max {
            return Err("too many strings".into());
        }
        (0..n).map(|_| self.string()).collect()
    }
    /// Octets left after the cursor.
    pub fn left(&self) -> usize {
        self.b.len().saturating_sub(self.pos)
    }
}

/// `geometry_msgs/msg/Twist` (all zero: a stop).
pub fn zero_twist() -> Vec<u8> {
    let mut e = Enc::default();
    for _ in 0..6 {
        e.f64(0.0);
    }
    e.payload()
}

/// The `rmw_cyclonedds` service request header (`cdds_request_header_t`:
/// client id, sequence number), written at the CDR origin.
pub fn request_header(e: &mut Enc, client: u64, seq: i64) {
    e.u64(client);
    e.i64(seq);
}

/// `action_msgs/srv/CancelGoal` request: a zero goal id and a zero stamp
/// cancel **every** goal of the action server (`CancelGoal.srv`).
pub fn cancel_all_goals(client: u64, seq: i64) -> Vec<u8> {
    let mut e = Enc::default();
    request_header(&mut e, client, seq);
    for _ in 0..16 {
        e.u8(0);
    }
    e.i32(0);
    e.u32(0);
    e.payload()
}

/// The `CancelGoal` response: `(return_code, goals canceling)`.
pub fn cancel_response(d: &mut Dec<'_>) -> Result<(i8, usize), String> {
    let code = d.u8()? as i8;
    let n = d.u32()? as usize;
    if n > 4096 || n.saturating_mul(24) > d.left() {
        return Err("bad goals_canceling count".into());
    }
    Ok((code, n))
}

/// The ROS 2 distribution a `controller_manager_msgs` layout follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Distro {
    /// `activate_controllers, deactivate_controllers, strictness,
    /// activate_asap, timeout` (Jazzy).
    Jazzy,
    /// Humble's: the same plus the deprecated `start_controllers`,
    /// `stop_controllers` and `start_asap`.
    Humble,
}

/// `controller_manager_msgs/srv/SwitchController` request, `STRICT` (2):
/// the whole switch happens or nothing does.
pub fn switch_controller(
    client: u64,
    seq: i64,
    distro: Distro,
    activate: &[String],
    deactivate: &[String],
    timeout_s: i32,
) -> Vec<u8> {
    let mut e = Enc::default();
    request_header(&mut e, client, seq);
    e.strings(activate);
    e.strings(deactivate);
    if distro == Distro::Humble {
        e.strings(&[]);
        e.strings(&[]);
    }
    e.i32(2); // STRICT
    if distro == Distro::Humble {
        e.bool(false); // start_asap
    }
    e.bool(true); // activate_asap
    e.i32(timeout_s);
    e.u32(0);
    e.payload()
}

/// The Unitree `unitree_api::msg::dds_::Request_`: header (identity id,
/// api id; lease id; policy priority, noreply), parameter (JSON), binary.
pub fn unitree_request(id: i64, api_id: i64, parameter: &str) -> Vec<u8> {
    let mut e = Enc::default();
    e.i64(id);
    e.i64(api_id);
    e.i64(0); // lease
    e.i32(0); // priority
    e.bool(false); // noreply
    e.string(parameter);
    e.u32(0); // binary
    e.payload()
}

/// A Unitree `Response_`: `(identity id, api id, status code)`.
pub fn unitree_response(payload: &[u8]) -> Result<(i64, i64, i32), String> {
    let mut d = Dec::open(payload)?;
    let id = d.i64()?;
    let api = d.i64()?;
    let code = d.i32()?;
    Ok((id, api, code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts() {
        let t = zero_twist();
        assert_eq!(t.len(), 4 + 48);
        let c = cancel_all_goals(7, 1);
        // header 16 + uuid 16 + stamp 8.
        assert_eq!(c.len(), 4 + 40);
        let mut d = Dec::open(&c).unwrap();
        assert_eq!((d.u64().unwrap(), d.i64().unwrap()), (7, 1));
        let s = switch_controller(1, 2, Distro::Jazzy, &["hold".into()], &["jtc".into()], 5);
        let mut d = Dec::open(&s).unwrap();
        d.u64().unwrap();
        d.i64().unwrap();
        assert_eq!(d.strings(8).unwrap(), ["hold"]);
        assert_eq!(d.strings(8).unwrap(), ["jtc"]);
        assert_eq!(d.i32().unwrap(), 2);
        let r = unitree_request(9, 1015, "{\"data\":-1}");
        let (id, api, _) = unitree_response(&r).unwrap();
        assert_eq!((id, api), (9, 1015));
        // The reference decoder reads the request the same way.
        let m = robodr_cdr::unitree::decode_unitree(
            robodr_cdr::unitree::UnitreeKind::ApiRequest,
            &r,
            &robodr_cdr::Limits::default(),
        )
        .unwrap();
        let robodr_cdr::unitree::UnitreeMessage::ApiRequest(q) = m.message else {
            panic!("not a request");
        };
        assert_eq!(q.dispatched_api_id(), 1015);
    }
}
