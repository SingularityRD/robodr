//! A small evaluator of the rules this crate renders, for tests (here, in
//! agentd's end-to-end tests and in reviews): which verdict table
//! `inet robodr` gives one packet. It understands exactly the expressions
//! [`crate::nft`] renders and refuses anything else (an `Err`, never a
//! guess), so a test cannot pass on an expression it does not model.
//!
//! What it assumes about a packet: not an IP fragment, no IPv6 extension
//! header, conntrack state `new` unless [`Packet::established`]. Real
//! nftables and real traffic are proven in `tests/netns.rs`; this model
//! lets a test reason about a rendered or listed table without root.

use std::net::IpAddr;

use serde_json::Value;

use crate::nft::Rendered;

/// One packet as the model sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// `"input"`, `"forward"` or `"output"`.
    pub chain: String,
    pub iif: String,
    pub oif: String,
    pub saddr: IpAddr,
    pub daddr: IpAddr,
    /// `"udp"` or `"tcp"`.
    pub proto: String,
    pub sport: u16,
    pub dport: u16,
    pub payload: Vec<u8>,
    pub established: bool,
}

impl Packet {
    /// A UDP datagram in `chain` (`input`: received on `eth0`; `output`:
    /// sent on `eth0`; `forward`: both).
    pub fn udp(chain: &str, src: (IpAddr, u16), dst: (IpAddr, u16), payload: &[u8]) -> Self {
        let (iif, oif) = match chain {
            "input" => ("eth0", ""),
            "output" => ("", "eth0"),
            _ => ("eth0", "eth1"),
        };
        Self {
            chain: chain.into(),
            iif: iif.into(),
            oif: oif.into(),
            saddr: src.0,
            daddr: dst.0,
            proto: "udp".into(),
            sport: src.1,
            dport: dst.1,
            payload: payload.to_vec(),
            established: false,
        }
    }

    /// The same packet on another interface pair.
    pub fn on(mut self, iif: &str, oif: &str) -> Self {
        self.iif = iif.into();
        self.oif = oif.into();
        self
    }

    /// The transport header (UDP: 8 bytes) followed by the payload.
    fn transport(&self) -> Vec<u8> {
        let mut t = Vec::with_capacity(8 + self.payload.len());
        t.extend_from_slice(&self.sport.to_be_bytes());
        t.extend_from_slice(&self.dport.to_be_bytes());
        let len = u16::try_from(8 + self.payload.len()).unwrap_or(u16::MAX);
        t.extend_from_slice(&len.to_be_bytes());
        t.extend_from_slice(&[0, 0]);
        t.extend_from_slice(&self.payload);
        t
    }
}

/// An RTPS header whose sender GUID prefix is `prefix` (24 hex digits),
/// followed by an `INFO_TS` submessage.
pub fn rtps(prefix: &str) -> Vec<u8> {
    let mut p = b"RTPS\x02\x03\x01\x10".to_vec();
    for i in (0..24).step_by(2) {
        p.push(u8::from_str_radix(prefix.get(i..i + 2).unwrap_or("00"), 16).unwrap_or(0));
    }
    p.extend_from_slice(&[0x09, 0x01, 0x08, 0x00, 1, 2, 3, 4, 5, 6, 7, 8]);
    p
}

/// The rules of `chain`, from a rendering.
pub fn rendered_chain(r: &Rendered, chain: &str) -> Vec<Vec<Value>> {
    r.chains
        .as_ref()
        .and_then(|c| c.get(chain))
        .map(|rs| rs.iter().map(|x| x.expr.clone()).collect())
        .unwrap_or_default()
}

/// The rules of `chain`, from a table listing (`nft -j list table`
/// objects, or a model's stored objects), in order.
pub fn listed_chain(objs: &[Value], chain: &str) -> Vec<Vec<Value>> {
    objs.iter()
        .filter_map(|o| o.get("rule"))
        .filter(|r| r.get("chain").and_then(Value::as_str) == Some(chain))
        .map(|r| {
            r.get("expr")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        })
        .collect()
}

/// The verdict of `rules` (one chain, policy accept) for `p`:
/// `"accept"` or `"drop"`. An expression the model does not know is an
/// error.
pub fn verdict(rules: &[Vec<Value>], p: &Packet) -> Result<&'static str, String> {
    'rule: for r in rules {
        for e in r {
            if let Some(m) = e.get("match") {
                if !matches(m, p)? {
                    continue 'rule;
                }
            } else if e.get("counter").is_some() {
            } else if e.get("accept").is_some() {
                return Ok("accept");
            } else if e.get("drop").is_some() {
                return Ok("drop");
            } else {
                return Err(format!("unmodelled statement {e}"));
            }
        }
    }
    Ok("accept")
}

/// [`verdict`] of the packet's own chain in a rendering (no table: accept).
pub fn verdict_rendered(r: &Rendered, p: &Packet) -> Result<&'static str, String> {
    verdict(&rendered_chain(r, &p.chain), p)
}

/// [`verdict`] of the packet's own chain in a listing.
pub fn verdict_listed(objs: &[Value], p: &Packet) -> Result<&'static str, String> {
    verdict(&listed_chain(objs, &p.chain), p)
}

/// A value the left side of a match evaluates to (`None`: the packet has
/// no such field, so the match fails whatever its operator).
#[derive(Debug, Clone, PartialEq)]
enum V {
    Addr(IpAddr),
    Num(u64),
    Str(String),
}

fn left(l: &Value, p: &Packet) -> Result<Option<V>, String> {
    if let Some(meta) = l.get("meta") {
        return Ok(match meta.get("key").and_then(Value::as_str) {
            Some("l4proto") => Some(V::Str(p.proto.clone())),
            Some("iifname") => Some(V::Str(p.iif.clone())),
            Some("oifname") => Some(V::Str(p.oif.clone())),
            k => return Err(format!("unmodelled meta key {k:?}")),
        });
    }
    if let Some(ct) = l.get("ct") {
        return match ct.get("key").and_then(Value::as_str) {
            Some("state") => Ok(Some(V::Str(
                if p.established { "established" } else { "new" }.into(),
            ))),
            k => Err(format!("unmodelled ct key {k:?}")),
        };
    }
    if l.get("exthdr").is_some() {
        // No extension header in a modelled packet.
        return Ok(None);
    }
    if let Some(and) = l.get("&").and_then(Value::as_array) {
        let inner = and.first().cloned().unwrap_or(Value::Null);
        let field = inner
            .get("payload")
            .and_then(|x| x.get("field"))
            .and_then(Value::as_str);
        let proto = inner
            .get("payload")
            .and_then(|x| x.get("protocol"))
            .and_then(Value::as_str);
        return match (proto, field) {
            // Never a fragment.
            (Some("ip"), Some("frag-off")) => Ok(p.saddr.is_ipv4().then_some(V::Num(0))),
            (Some("tcp"), Some("flags")) => {
                if p.proto == "tcp" {
                    Err("tcp flags are not modelled".into())
                } else {
                    Ok(None)
                }
            }
            _ => Err(format!("unmodelled bitwise expression {l}")),
        };
    }
    let Some(pl) = l.get("payload") else {
        return Err(format!("unmodelled expression {l}"));
    };
    if pl.get("base").and_then(Value::as_str) == Some("th") {
        let off = pl.get("offset").and_then(Value::as_u64).unwrap_or(u64::MAX);
        let len = pl.get("len").and_then(Value::as_u64).unwrap_or(0);
        if len != 32 || off % 8 != 0 {
            return Err(format!("unmodelled raw payload {l}"));
        }
        let t = p.transport();
        let o = usize::try_from(off / 8).unwrap_or(usize::MAX);
        return Ok(t
            .get(o..)
            .and_then(|b| b.first_chunk())
            .map(|b| V::Num(u64::from(u32::from_be_bytes(*b)))));
    }
    let proto = pl.get("protocol").and_then(Value::as_str).unwrap_or("");
    let field = pl.get("field").and_then(Value::as_str).unwrap_or("");
    Ok(match (proto, field) {
        ("ip", "saddr") => p.saddr.is_ipv4().then_some(V::Addr(p.saddr)),
        ("ip", "daddr") => p.daddr.is_ipv4().then_some(V::Addr(p.daddr)),
        ("ip6", "saddr") => p.saddr.is_ipv6().then_some(V::Addr(p.saddr)),
        ("ip6", "daddr") => p.daddr.is_ipv6().then_some(V::Addr(p.daddr)),
        ("udp" | "tcp", "sport") => (p.proto == proto).then_some(V::Num(u64::from(p.sport))),
        ("udp" | "tcp", "dport") => (p.proto == proto).then_some(V::Num(u64::from(p.dport))),
        ("icmp" | "icmpv6", _) => None,
        _ => return Err(format!("unmodelled payload field {l}")),
    })
}

fn prefix_contains(net: IpAddr, len: u64, ip: IpAddr) -> bool {
    let (a, b, bits): (u128, u128, u64) = match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => (u32::from(n).into(), u32::from(i).into(), 32),
        (IpAddr::V6(n), IpAddr::V6(i)) => (u128::from(n), u128::from(i), 128),
        _ => return false,
    };
    if len == 0 {
        return true;
    }
    let shift = u32::try_from(bits.saturating_sub(len)).unwrap_or(0);
    a.checked_shr(shift) == b.checked_shr(shift)
}

/// Does `v` equal / lie in the right-hand side `r`?
fn member(v: &V, r: &Value) -> Result<bool, String> {
    if let Some(set) = r.get("set").and_then(Value::as_array) {
        for x in set {
            if member(v, x)? {
                return Ok(true);
            }
        }
        return Ok(false);
    }
    if let Some(range) = r.get("range").and_then(Value::as_array) {
        let lo = range.first().and_then(Value::as_u64);
        let hi = range.get(1).and_then(Value::as_u64);
        return match (v, lo, hi) {
            (V::Num(n), Some(lo), Some(hi)) => Ok((lo..=hi).contains(n)),
            _ => Err(format!("unmodelled range {r}")),
        };
    }
    if let Some(pf) = r.get("prefix") {
        let addr = pf
            .get("addr")
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<IpAddr>().ok());
        let len = pf.get("len").and_then(Value::as_u64);
        return match (v, addr, len) {
            (V::Addr(ip), Some(a), Some(l)) => Ok(prefix_contains(a, l, *ip)),
            _ => Err(format!("unmodelled prefix {r}")),
        };
    }
    Ok(match (v, r) {
        (V::Num(n), Value::Number(x)) => Some(*n) == x.as_u64(),
        (V::Addr(ip), Value::String(s)) => s.parse::<IpAddr>().ok() == Some(*ip),
        (V::Str(a), Value::String(s)) => a == s,
        (V::Num(_), Value::String(s)) => return Err(format!("unmodelled symbolic value {s:?}")),
        _ => return Err(format!("unmodelled value {r}")),
    })
}

fn matches(m: &Value, p: &Packet) -> Result<bool, String> {
    let op = m.get("op").and_then(Value::as_str).unwrap_or("==");
    let l = m.get("left").cloned().unwrap_or(Value::Null);
    let r = m.get("right").cloned().unwrap_or(Value::Null);
    let Some(v) = left(&l, p)? else {
        return Ok(false);
    };
    match op {
        "==" => member(&v, &r),
        "!=" => member(&v, &r).map(|b| !b),
        "in" => member(&v, &r),
        o => Err(format!("unmodelled operator {o:?}")),
    }
}
