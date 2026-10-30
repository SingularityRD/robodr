//! A minimal RTPS 2.3 participant for the ROS 2 adapters: it announces
//! itself (SPDP) and its endpoints (SEDP) to **one** configured peer
//! participant (the robot's ROS 2 host: its metatraffic and user unicast
//! ports), publishes samples from reliable writers (DATA + HEARTBEAT) and
//! reads the peer's samples addressed to it. That is what a ROS 2 topic
//! publish, a service call (`rq/<service>Request` / `rr/<service>Reply`
//! with the `rmw_cyclonedds` request header) and a Unitree SDK request
//! need, and nothing more:
//!
//! - no multicast, no discovery of anyone but the peer, no SEDP reader
//!   (the peer's readers match the announced writers; the peer's reply
//!   writer matches the announced reader);
//! - reliability is announced (`RELIABLE`, so reliable readers match) and
//!   honoured by re-sending: each request is sent with a HEARTBEAT and
//!   re-sent (same sequence number) until its reply arrives or the
//!   deadline passes; ACKNACKs are not parsed (a re-send of the same
//!   sequence number is a duplicate the reader drops);
//! - replies are read with `robodr-rtps`'s user-data walker (DATA_FRAG
//!   reassembled), never trusted beyond their payload (the adapter checks
//!   the request header / identity of every reply).
//!
//! What is verified: the datagrams this module writes parse with
//! `robodr-rtps` (SPDP, SEDP and user DATA, `tests/motion.rs`) and a
//! simulated peer answers through it. Interoperation with a real Cyclone
//! DDS / Fast DDS participant has **not** been verified here (README,
//! "Motion adapters").

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

/// Built-in entity ids (RTPS 2.3 §9.3.1.3).
pub const SPDP_WRITER: [u8; 4] = [0x00, 0x01, 0x00, 0xc2];
pub const SPDP_READER: [u8; 4] = [0x00, 0x01, 0x00, 0xc7];
pub const SEDP_PUB_WRITER: [u8; 4] = [0x00, 0x00, 0x03, 0xc2];
pub const SEDP_PUB_READER: [u8; 4] = [0x00, 0x00, 0x03, 0xc7];
pub const SEDP_SUB_WRITER: [u8; 4] = [0x00, 0x00, 0x04, 0xc2];
pub const SEDP_SUB_READER: [u8; 4] = [0x00, 0x00, 0x04, 0xc7];
pub const PARTICIPANT: [u8; 4] = [0x00, 0x00, 0x01, 0xc1];

/// Where the peer participant listens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    pub ip: Ipv4Addr,
    /// Metatraffic (SPDP / SEDP) unicast port.
    pub meta_port: u16,
    /// User-data unicast port.
    pub user_port: u16,
    /// This host's address on the peer's network (announced as our
    /// locator).
    pub local_ip: Ipv4Addr,
    pub domain_id: u32,
}

/// The RTPS well-known unicast ports of participant `pid` in `domain`
/// (`PB 7400`, `DG 250`, `PG 2`, `d1 10`, `d3 11`).
pub fn unicast_ports(domain: u32, pid: u32) -> Option<(u16, u16)> {
    let base = 7400u32.checked_add(domain.checked_mul(250)?)?;
    let meta = base.checked_add(10)?.checked_add(pid.checked_mul(2)?)?;
    Some((u16::try_from(meta).ok()?, u16::try_from(meta + 1).ok()?))
}

/// A fresh random GUID prefix (`/dev/urandom`; the clock as a fallback).
pub fn random_prefix() -> [u8; 12] {
    let mut p = [0u8; 12];
    let ok = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut p))
        .is_ok();
    if !ok {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.copy_from_slice(&t.to_le_bytes()[..12]);
    }
    p
}

/// RTPS message builder (little-endian submessages).
#[derive(Debug, Clone)]
pub struct Msg {
    b: Vec<u8>,
}

impl Msg {
    pub fn new(prefix: [u8; 12]) -> Self {
        let mut b = b"RTPS".to_vec();
        b.extend_from_slice(&[2, 3]); // protocol 2.3
        b.extend_from_slice(&[0, 0]); // vendor unknown
        b.extend_from_slice(&prefix);
        Msg { b }
    }

    fn sub(&mut self, id: u8, flags: u8, body: &[u8]) -> &mut Self {
        self.b.push(id);
        self.b.push(flags | 0x01); // E: little endian
        self.b
            .extend_from_slice(&u16::try_from(body.len()).unwrap_or(0).to_le_bytes());
        self.b.extend_from_slice(body);
        self
    }

    /// `DATA` with an optional inline QoS (already a parameter list
    /// ending in a sentinel) and a serialized payload.
    pub fn data(
        &mut self,
        reader: [u8; 4],
        writer: [u8; 4],
        sn: i64,
        inline_qos: Option<&[u8]>,
        payload: &[u8],
    ) -> &mut Self {
        let mut b = vec![0, 0];
        b.extend_from_slice(&16u16.to_le_bytes());
        b.extend_from_slice(&reader);
        b.extend_from_slice(&writer);
        b.extend_from_slice(&((sn >> 32) as i32).to_le_bytes());
        b.extend_from_slice(&(sn as u32).to_le_bytes());
        let mut flags = 0x04; // D: serialized data
        if let Some(q) = inline_qos {
            b.extend_from_slice(q);
            flags |= 0x02;
        }
        b.extend_from_slice(payload);
        while !b.len().is_multiple_of(4) {
            b.push(0);
        }
        self.sub(0x15, flags, &b)
    }

    pub fn heartbeat(
        &mut self,
        reader: [u8; 4],
        writer: [u8; 4],
        first: i64,
        last: i64,
        count: u32,
    ) -> &mut Self {
        let mut b = Vec::with_capacity(28);
        b.extend_from_slice(&reader);
        b.extend_from_slice(&writer);
        for sn in [first, last] {
            b.extend_from_slice(&((sn >> 32) as i32).to_le_bytes());
            b.extend_from_slice(&(sn as u32).to_le_bytes());
        }
        b.extend_from_slice(&count.to_le_bytes());
        self.sub(0x07, 0, &b)
    }

    pub fn finish(&self) -> Vec<u8> {
        self.b.clone()
    }
}

/// Parameter-list builder (`PL_CDR_LE`).
#[derive(Debug, Default)]
pub struct Pl {
    b: Vec<u8>,
}

impl Pl {
    pub fn param(mut self, pid: u16, value: &[u8]) -> Self {
        let mut v = value.to_vec();
        while !v.len().is_multiple_of(4) {
            v.push(0);
        }
        self.b.extend_from_slice(&pid.to_le_bytes());
        self.b
            .extend_from_slice(&u16::try_from(v.len()).unwrap_or(0).to_le_bytes());
        self.b.extend_from_slice(&v);
        self
    }
    pub fn string(self, pid: u16, s: &str) -> Self {
        let mut v = u32::try_from(s.len() + 1)
            .unwrap_or(0)
            .to_le_bytes()
            .to_vec();
        v.extend_from_slice(s.as_bytes());
        v.push(0);
        self.param(pid, &v)
    }
    /// The list with its sentinel (an inline QoS).
    pub fn list(mut self) -> Vec<u8> {
        self.b.extend_from_slice(&[1, 0, 0, 0]);
        self.b
    }
    /// A `PL_CDR_LE` serialized payload.
    pub fn payload(self) -> Vec<u8> {
        let mut out = vec![0x00, 0x03, 0x00, 0x00];
        out.extend_from_slice(&self.list());
        out
    }
}

fn locator(ip: Ipv4Addr, port: u16) -> Vec<u8> {
    let mut v = 1i32.to_le_bytes().to_vec(); // LOCATOR_KIND_UDPv4
    v.extend_from_slice(&u32::from(port).to_le_bytes());
    v.extend_from_slice(&[0; 12]);
    v.extend_from_slice(&ip.octets());
    v
}

fn guid(prefix: [u8; 12], entity: [u8; 4]) -> Vec<u8> {
    let mut g = prefix.to_vec();
    g.extend_from_slice(&entity);
    g
}

/// One sample read from the peer.
#[derive(Debug, Clone)]
pub struct Received {
    pub writer: [u8; 16],
    pub payload: Vec<u8>,
}

/// See the module docs.
#[derive(Debug)]
pub struct Participant {
    sock: UdpSocket,
    pub prefix: [u8; 12],
    peer: Peer,
    local_port: u16,
    sn_pub: i64,
    sn_sub: i64,
    hb_count: u32,
    walker: robodr_rtps::UserDataWalker,
}

impl Participant {
    /// Bind an ephemeral UDP port on `peer.local_ip`.
    pub fn open(peer: Peer) -> std::io::Result<Self> {
        let sock = UdpSocket::bind(SocketAddrV4::new(peer.local_ip, 0))?;
        let local_port = sock.local_addr()?.port();
        Ok(Participant {
            sock,
            prefix: random_prefix(),
            peer,
            local_port,
            sn_pub: 0,
            sn_sub: 0,
            hb_count: 0,
            walker: robodr_rtps::UserDataWalker::new(robodr_rtps::UserDataLimits::default()),
        })
    }

    fn send(&self, port: u16, d: &[u8]) -> std::io::Result<()> {
        self.sock
            .send_to(d, SocketAddrV4::new(self.peer.ip, port))
            .map(|_| ())
    }

    /// SPDP: our participant, its locator (this socket) and endpoints.
    pub fn announce(&mut self) -> std::io::Result<()> {
        let loc = locator(self.peer.local_ip, self.local_port);
        let pg = guid(self.prefix, PARTICIPANT);
        let p = Pl::default()
            .param(0x0015, &[2, 3]) // PID_PROTOCOL_VERSION
            .param(0x0016, &[0, 0]) // PID_VENDORID
            .param(0x000f, &self.peer.domain_id.to_le_bytes()) // PID_DOMAIN_ID
            .param(0x0050, &pg) // PID_PARTICIPANT_GUID
            .param(0x0032, &loc) // PID_METATRAFFIC_UNICAST_LOCATOR
            .param(0x0031, &loc) // PID_DEFAULT_UNICAST_LOCATOR
            .param(0x0002, &[20, 0, 0, 0, 0, 0, 0, 0]) // lease 20 s
            // Participant announcer + detector, publications and
            // subscriptions announcers.
            .param(0x0058, &(0b01_0111u32).to_le_bytes())
            .payload();
        let qos = Pl::default().param(0x0070, &pg).list(); // PID_KEY_HASH
        let d = Msg::new(self.prefix)
            .data(SPDP_READER, SPDP_WRITER, 1, Some(&qos), &p)
            .finish();
        self.send(self.peer.meta_port, &d)
    }

    fn endpoint(
        &mut self,
        entity: [u8; 4],
        topic: &str,
        type_name: &str,
        writer: bool,
    ) -> std::io::Result<()> {
        let eg = guid(self.prefix, entity);
        let p = Pl::default()
            .param(0x005a, &eg) // PID_ENDPOINT_GUID
            .param(0x0050, &guid(self.prefix, PARTICIPANT))
            .string(0x0005, topic) // PID_TOPIC_NAME
            .string(0x0007, type_name) // PID_TYPE_NAME
            // PID_RELIABILITY: RELIABLE, max_blocking_time 100 ms.
            .param(0x001a, &[2, 0, 0, 0, 0, 0, 0, 0, 0x9a, 0x99, 0x99, 0x19])
            .param(0x001d, &[0, 0, 0, 0]) // PID_DURABILITY volatile
            .payload();
        let qos = Pl::default().param(0x0070, &eg).list();
        self.hb_count = self.hb_count.wrapping_add(1);
        let (sn, w, r) = if writer {
            self.sn_pub += 1;
            (self.sn_pub, SEDP_PUB_WRITER, SEDP_PUB_READER)
        } else {
            self.sn_sub += 1;
            (self.sn_sub, SEDP_SUB_WRITER, SEDP_SUB_READER)
        };
        let d = Msg::new(self.prefix)
            .data(r, w, sn, Some(&qos), &p)
            .heartbeat(r, w, 1, sn, self.hb_count)
            .finish();
        self.send(self.peer.meta_port, &d)
    }

    /// SEDP `DATA(w)`: a reliable writer of `topic` / `type_name`.
    pub fn announce_writer(
        &mut self,
        entity: [u8; 4],
        topic: &str,
        type_name: &str,
    ) -> std::io::Result<()> {
        self.endpoint(entity, topic, type_name, true)
    }

    /// SEDP `DATA(r)`: a reliable reader of `topic` / `type_name`.
    pub fn announce_reader(
        &mut self,
        entity: [u8; 4],
        topic: &str,
        type_name: &str,
    ) -> std::io::Result<()> {
        self.endpoint(entity, topic, type_name, false)
    }

    /// One user sample of `writer` with sequence number `sn` (and a
    /// HEARTBEAT announcing it) to the peer's user port.
    pub fn publish(&mut self, writer: [u8; 4], sn: i64, payload: &[u8]) -> std::io::Result<()> {
        self.hb_count = self.hb_count.wrapping_add(1);
        let d = Msg::new(self.prefix)
            .data([0; 4], writer, sn, None, payload)
            .heartbeat([0; 4], writer, 1, sn, self.hb_count)
            .finish();
        self.send(self.peer.user_port, &d)
    }

    /// Read the peer's user samples until `accept` returns `Some` or the
    /// deadline passes; `resend` is called every `every` while waiting.
    pub fn wait<T>(
        &mut self,
        deadline: Instant,
        every: Duration,
        mut resend: impl FnMut(&mut Self) -> std::io::Result<()>,
        mut accept: impl FnMut(&Received) -> Option<T>,
    ) -> Result<T, String> {
        let mut buf = vec![0u8; 65_536];
        let mut next = Instant::now() + every;
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err("no answer from the peer before the deadline".into());
            }
            if now >= next {
                resend(self).map_err(|e| format!("send: {e}"))?;
                next = now + every;
            }
            let wait = deadline.min(next).saturating_duration_since(now);
            let _ = self
                .sock
                .set_read_timeout(Some(wait.max(Duration::from_millis(1))));
            let (n, from) = match self.sock.recv_from(&mut buf) {
                Ok(x) => x,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue
                }
                Err(e) => return Err(format!("recv: {e}")),
            };
            if from.ip() != std::net::IpAddr::V4(self.peer.ip) {
                continue;
            }
            let Some(d) = buf.get(..n) else {
                continue;
            };
            let Some(r) = self.walker.walk(d) else {
                continue;
            };
            for s in r.samples {
                if s.address.writer[..12] == self.prefix || s.payload.is_empty() {
                    continue;
                }
                let got = Received {
                    writer: s.address.writer,
                    payload: s.payload.into_owned(),
                };
                if let Some(t) = accept(&got) {
                    return Ok(t);
                }
            }
        }
    }

    /// The UDP port this participant listens on.
    pub fn local_port(&self) -> u16 {
        self.local_port
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn written_datagrams_parse_with_robodr_rtps() {
        let prefix = [1u8; 12];
        let p = Pl::default()
            .param(0x005a, &guid(prefix, [0, 0, 1, 3]))
            .param(0x0050, &guid(prefix, PARTICIPANT))
            .string(0x0005, "rq/controller_manager/switch_controllerRequest")
            .string(
                0x0007,
                "controller_manager_msgs::srv::dds_::SwitchController_Request_",
            )
            .payload();
        let d = Msg::new(prefix)
            .data(SEDP_PUB_READER, SEDP_PUB_WRITER, 1, None, &p)
            .finish();
        let r = robodr_rtps::parse_datagram_detailed(&d).unwrap();
        assert_eq!(r.endpoints.len(), 1, "{r:?}");
        assert_eq!(
            r.endpoints[0].topic,
            "rq/controller_manager/switch_controllerRequest"
        );
        let u = Msg::new(prefix)
            .data(
                [0; 4],
                [0, 0, 1, 3],
                5,
                None,
                &crate::motion::cdr::zero_twist(),
            )
            .heartbeat([0; 4], [0, 0, 1, 3], 1, 5, 1)
            .finish();
        let w = robodr_rtps::walk_user_data(&u).unwrap();
        assert_eq!(w.samples.len(), 1);
        assert_eq!(
            &w.samples[0].payload[..],
            &crate::motion::cdr::zero_twist()[..]
        );
        assert_eq!(unicast_ports(0, 0), Some((7410, 7411)));
        assert_eq!(unicast_ports(1, 2), Some((7664, 7665)));
    }
}
