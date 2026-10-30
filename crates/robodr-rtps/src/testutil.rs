//! Test-only builders for RTPS datagrams in either endianness.

use crate::wire::*;

pub(crate) fn w16(le: bool, x: u16) -> [u8; 2] {
    if le {
        x.to_le_bytes()
    } else {
        x.to_be_bytes()
    }
}

pub(crate) fn w32(le: bool, x: u32) -> [u8; 4] {
    if le {
        x.to_le_bytes()
    } else {
        x.to_be_bytes()
    }
}

/// Parameter-list builder.
pub(crate) struct Pl {
    le: bool,
    b: Vec<u8>,
}

impl Pl {
    pub(crate) fn new(le: bool) -> Self {
        Self { le, b: Vec::new() }
    }

    /// A parameter, value zero-padded to a multiple of 4.
    pub(crate) fn raw(mut self, pid: u16, value: &[u8]) -> Self {
        let mut v = value.to_vec();
        while !v.len().is_multiple_of(4) {
            v.push(0);
        }
        self.b.extend_from_slice(&w16(self.le, pid));
        self.b.extend_from_slice(&w16(self.le, v.len() as u16));
        self.b.extend_from_slice(&v);
        self
    }

    /// A parameter with an exact (possibly misaligned / lying) length field.
    pub(crate) fn raw_len(mut self, pid: u16, len: u16, value: &[u8]) -> Self {
        self.b.extend_from_slice(&w16(self.le, pid));
        self.b.extend_from_slice(&w16(self.le, len));
        self.b.extend_from_slice(value);
        self
    }

    pub(crate) fn string(self, pid: u16, s: &str) -> Self {
        let mut v = w32(self.le, s.len() as u32 + 1).to_vec();
        v.extend_from_slice(s.as_bytes());
        v.push(0);
        self.raw(pid, &v)
    }

    pub(crate) fn octets(self, pid: u16, o: &[u8]) -> Self {
        let mut v = w32(self.le, o.len() as u32).to_vec();
        v.extend_from_slice(o);
        self.raw(pid, &v)
    }

    pub(crate) fn guid(self, pid: u16, g: [u8; 16]) -> Self {
        self.raw(pid, &g)
    }

    pub(crate) fn u32(self, pid: u16, x: u32) -> Self {
        let v = w32(self.le, x);
        self.raw(pid, &v)
    }

    pub(crate) fn locator(self, pid: u16, kind: i32, port: u32, addr: [u8; 16]) -> Self {
        let mut v = w32(self.le, kind as u32).to_vec();
        v.extend_from_slice(&w32(self.le, port));
        v.extend_from_slice(&addr);
        self.raw(pid, &v)
    }

    pub(crate) fn v4(self, pid: u16, ip: [u8; 4], port: u32) -> Self {
        let mut a = [0u8; 16];
        a[12..].copy_from_slice(&ip);
        self.locator(pid, LOCATOR_KIND_UDPV4, port, a)
    }

    pub(crate) fn status(self, flags: u8) -> Self {
        self.raw(PID_STATUS_INFO, &[0, 0, 0, flags])
    }

    pub(crate) fn end(mut self) -> Vec<u8> {
        self.b.extend_from_slice(&w16(self.le, PID_SENTINEL));
        self.b.extend_from_slice(&w16(self.le, 0));
        self.b
    }

    pub(crate) fn no_sentinel(self) -> Vec<u8> {
        self.b
    }
}

pub(crate) fn header(prefix: [u8; 12]) -> Vec<u8> {
    header_v(prefix, [2, 3])
}

pub(crate) fn header_v(prefix: [u8; 12], version: [u8; 2]) -> Vec<u8> {
    let mut d = b"RTPS".to_vec();
    d.extend_from_slice(&version);
    d.extend_from_slice(&[0x01, 0x0f]);
    d.extend_from_slice(&prefix);
    d
}

/// Encapsulation header + parameter list.
pub(crate) fn pl_payload(le: bool, pl: Vec<u8>) -> Vec<u8> {
    let mut p = if le { PL_CDR_LE } else { PL_CDR_BE }
        .to_be_bytes()
        .to_vec();
    p.extend_from_slice(&[0, 0]);
    p.extend(pl);
    p
}

/// A submessage with a consistent length field.
pub(crate) fn submsg(id: u8, flags: u8, body: &[u8]) -> Vec<u8> {
    let mut s = vec![id, flags];
    s.extend_from_slice(&w16(flags & FLAG_E != 0, body.len() as u16));
    s.extend_from_slice(body);
    s
}

pub(crate) enum Payload {
    None,
    Data(Vec<u8>),
    Key(Vec<u8>),
}

/// A DATA submessage.
pub(crate) fn data(
    le: bool,
    writer: [u8; 4],
    inline: Option<Vec<u8>>,
    payload: Payload,
) -> Vec<u8> {
    let mut flags = if le { FLAG_E } else { 0 };
    let mut body = vec![0, 0];
    body.extend_from_slice(&w16(le, 16));
    body.extend_from_slice(&[0, 0, 0, 0]);
    body.extend_from_slice(&writer);
    body.extend_from_slice(&w32(le, 0));
    body.extend_from_slice(&w32(le, 7));
    if let Some(q) = inline {
        flags |= FLAG_Q;
        body.extend(q);
    }
    match payload {
        Payload::None => {}
        Payload::Data(p) => {
            flags |= FLAG_D;
            body.extend(p);
        }
        Payload::Key(p) => {
            flags |= FLAG_K;
            body.extend(p);
        }
    }
    submsg(SUBMSG_DATA, flags, &body)
}

/// A DATA_FRAG submessage.
#[allow(clippy::too_many_arguments)]
pub(crate) fn data_frag(
    le: bool,
    writer: [u8; 4],
    sn: u32,
    start: u32,
    count: u16,
    frag_size: u16,
    sample_size: u32,
    inline: Option<Vec<u8>>,
    frags: &[u8],
) -> Vec<u8> {
    let mut flags = if le { FLAG_E } else { 0 };
    let mut body = vec![0, 0];
    body.extend_from_slice(&w16(le, 28));
    body.extend_from_slice(&[0, 0, 0, 0]);
    body.extend_from_slice(&writer);
    body.extend_from_slice(&w32(le, 0));
    body.extend_from_slice(&w32(le, sn));
    body.extend_from_slice(&w32(le, start));
    body.extend_from_slice(&w16(le, count));
    body.extend_from_slice(&w16(le, frag_size));
    body.extend_from_slice(&w32(le, sample_size));
    if let Some(q) = inline {
        flags |= FLAG_Q;
        body.extend(q);
    }
    body.extend_from_slice(frags);
    submsg(SUBMSG_DATA_FRAG, flags, &body)
}

pub(crate) fn info_src(le: bool, prefix: [u8; 12]) -> Vec<u8> {
    let mut body = vec![0, 0, 0, 0, 2, 3, 0x01, 0x10];
    body.extend_from_slice(&prefix);
    submsg(SUBMSG_INFO_SRC, if le { FLAG_E } else { 0 }, &body)
}

pub(crate) fn info_dst(le: bool, prefix: [u8; 12]) -> Vec<u8> {
    submsg(SUBMSG_INFO_DST, if le { FLAG_E } else { 0 }, &prefix)
}

pub(crate) fn guid_of(prefix: [u8; 12], entity: [u8; 4]) -> [u8; 16] {
    let mut g = [0u8; 16];
    g[..12].copy_from_slice(&prefix);
    g[12..].copy_from_slice(&entity);
    g
}

/// A typical ROS 2 SPDP payload (Fast DDS-like).
pub(crate) fn spdp_payload(le: bool, prefix: [u8; 12]) -> Vec<u8> {
    pl_payload(
        le,
        Pl::new(le)
            .raw(PID_PROTOCOL_VERSION, &[2, 3])
            .raw(PID_VENDORID, &[0x01, 0x0f])
            .guid(PID_PARTICIPANT_GUID, guid_of(prefix, [0, 0, 1, 0xc1]))
            .v4(PID_METATRAFFIC_UNICAST_LOCATOR, [192, 168, 1, 20], 7410)
            .v4(PID_METATRAFFIC_MULTICAST_LOCATOR, [239, 255, 0, 1], 7400)
            .v4(PID_DEFAULT_UNICAST_LOCATOR, [192, 168, 1, 20], 7411)
            .v4(PID_DEFAULT_MULTICAST_LOCATOR, [239, 255, 0, 1], 7401)
            .u32(PID_DOMAIN_ID, 0)
            .string(PID_ENTITY_NAME, "/")
            .octets(PID_USER_DATA, b"enclave=/;")
            .raw(PID_PARTICIPANT_LEASE_DURATION, &{
                let mut v = w32(le, 20).to_vec();
                v.extend_from_slice(&w32(le, 0x8000_0000));
                v
            })
            .end(),
    )
}

/// A typical SEDP payload.
pub(crate) fn sedp_payload(le: bool, ep: [u8; 16], topic: &str, ty: &str) -> Vec<u8> {
    pl_payload(
        le,
        Pl::new(le)
            .guid(PID_ENDPOINT_GUID, ep)
            .string(PID_TOPIC_NAME, topic)
            .string(PID_TYPE_NAME, ty)
            .end(),
    )
}
