//! nftables through the `nft` binary, JSON in and out, in the dedicated
//! table `inet robodr` only.
//!
//! * **One table, rendered whole.** The content of `inet robodr` is a pure
//!   function of the set of active actions ([`render`]). Every change
//!   (apply, revert, TTL expiry, restart) is one `nft -j -f -` transaction
//!   that deletes and re-creates the table with exactly the rules of the
//!   new set (or only deletes it when the set is empty), so the kernel
//!   switches atomically between two rendered states, a revert restores
//!   exactly the earlier state, and doing it twice changes nothing.
//! * **Never another table.** Every command names `inet robodr`; nothing
//!   lists, flushes or edits any other table (`flush ruleset` is never
//!   used). An nftables accept only ends the chain it is in, while a drop is
//!   final at its hook, so this table can only ever *remove* traffic: it
//!   cannot open anything another table drops.
//! * **No shell, no script text.** Rules are JSON values built from
//!   validated types ([`crate::net`]); `nft` is spawned with an argument
//!   vector, an empty environment and the batch on stdin.
//! * **Read back.** After every transaction the table is listed
//!   (`nft -j list table inet robodr`) and compared with what was rendered
//!   ([`verify`]): chains, hooks, priorities, policies, every rule's
//!   expressions and comment, in order, and no other object. Counter values
//!   are ignored and anonymous sets compared order-free.
//! * **Protected first.** Each chain starts with accepts for the motion
//!   control path entries no active action may cut, then the quarantine
//!   drops, then the isolation ([`render`]).

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::config::{AllowEntry, ProtectedEntry};
use crate::decision::{DiscoverySpec, Effect, IsolationSpec, QuarantineSpec};
use crate::net::{GuidPrefix, Iface, IpNet, Proto};
use crate::order::Locator;

pub const FAMILY: &str = "inet";
pub const TABLE: &str = "robodr";
/// Base chain priority: just before the conventional `filter` (0).
pub const PRIORITY: i64 = -5;
/// `"RTPS"` as a big-endian 32-bit word (RTPS header magic).
pub const RTPS_MAGIC: u32 = 0x5254_5053;
/// Longest `nft` output read.
pub const MAX_OUTPUT: usize = 8 << 20;
/// Longest an `nft` call may take.
pub const NFT_TIMEOUT: Duration = Duration::from_secs(10);

/// The three base chains of the table.
pub const CHAINS: [(&str, &str); 3] = [
    ("input", "input"),
    ("forward", "forward"),
    ("output", "output"),
];

/// Runs `nft`.
pub trait Nft {
    /// Run `nft <args>` with `stdin`; stdout on exit status 0.
    fn run(&mut self, args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>, String>;
}

/// The real `nft` binary. `prefix` (tests only) runs it through a wrapper
/// such as `ip netns exec <ns>`.
#[derive(Debug, Clone)]
pub struct NftCommand {
    argv: Vec<OsString>,
    timeout: Duration,
}

impl NftCommand {
    pub fn new(nft: &Path) -> Self {
        Self {
            argv: vec![nft.as_os_str().to_owned()],
            timeout: NFT_TIMEOUT,
        }
    }

    /// `prefix` then `nft` (e.g. `["ip", "netns", "exec", "ns1", "nft"]`).
    pub fn with_prefix(argv: Vec<OsString>) -> Self {
        Self {
            argv,
            timeout: NFT_TIMEOUT,
        }
    }
}

fn read_capped(mut r: impl Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            match r.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out.len() < MAX_OUTPUT {
                        out.extend_from_slice(&buf[..n.min(MAX_OUTPUT - out.len())]);
                    }
                }
            }
        }
        out
    })
}

impl Nft for NftCommand {
    fn run(&mut self, args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>, String> {
        let Some((prog, pre)) = self.argv.split_first() else {
            return Err("no nft program".into());
        };
        let mut child = Command::new(prog)
            .args(pre)
            .args(args)
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot run nft: {e}"))?;
        let out = child.stdout.take().map(read_capped);
        let err = child.stderr.take().map(read_capped);
        if let (Some(data), Some(mut w)) = (stdin, child.stdin.take()) {
            // A failed write shows up as an nft error below.
            let _ = w.write_all(data);
        }
        let deadline = Instant::now() + self.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(2))
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("nft did not finish within {:?}", self.timeout));
                }
                Err(e) => return Err(format!("waiting for nft: {e}")),
            }
        };
        let out = out.and_then(|h| h.join().ok()).unwrap_or_default();
        let err = err.and_then(|h| h.join().ok()).unwrap_or_default();
        if status.success() {
            Ok(out)
        } else {
            let msg: String = String::from_utf8_lossy(&err)
                .chars()
                .filter(|c| !c.is_control() || *c == ' ')
                .take(300)
                .collect();
            Err(format!("nft failed ({status}): {msg}"))
        }
    }
}

/// One rendered rule: expressions and comment.
#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub expr: Vec<Value>,
    pub comment: Option<String>,
}

/// The rendered table: rules per base chain (in [`CHAINS`] order), or
/// `None` when no action is active (the table is then absent).
#[derive(Debug, Clone, PartialEq)]
pub struct Rendered {
    pub chains: Option<BTreeMap<String, Vec<Rule>>>,
}

/// An active action, as the renderer sees it.
#[derive(Debug, Clone, Copy)]
pub struct Active<'a> {
    pub id: &'a str,
    pub effect: &'a Effect,
}

/// The comment tag of an order id (ids are up to 128 characters; comments
/// stay short and contain no request text).
pub fn tag(id: &str) -> String {
    let h = robodr_blackbox::crypto::sha256(id.as_bytes());
    robodr_blackbox::crypto::to_hex(&h[..6])
}

fn m(left: Value, right: Value) -> Value {
    json!({"match": {"op": "==", "left": left, "right": right}})
}

fn addr_field(net: &IpNet, field: &str) -> Value {
    let proto = if net.is_v4() { "ip" } else { "ip6" };
    json!({"payload": {"protocol": proto, "field": field}})
}

fn addr_value(net: &IpNet) -> Value {
    if net.is_host() {
        json!(net.addr.to_string())
    } else {
        json!({"prefix": {"addr": net.addr.to_string(), "len": net.len}})
    }
}

fn port_value(lo: u16, hi: u16) -> Value {
    if lo == hi {
        json!(lo)
    } else {
        json!({"range": [lo, hi]})
    }
}

fn port_match(proto: Proto, field: &str, lo: u16, hi: u16) -> Value {
    m(
        json!({"payload": {"protocol": proto.as_str(), "field": field}}),
        port_value(lo, hi),
    )
}

fn raw32(offset_bits: u32, value: u32) -> Value {
    m(
        json!({"payload": {"base": "th", "offset": offset_bits, "len": 32}}),
        json!(value),
    )
}

/// UDP whose RTPS header carries `guid` as the sender's GUID prefix:
/// payload bytes 0..4 = `"RTPS"`, 8..20 = the prefix (transport-header
/// offsets 64 and 128.. bits; the UDP header is 8 bytes).
pub fn guid_exprs(guid: &GuidPrefix) -> Vec<Value> {
    let mut v = vec![m(json!({"meta": {"key": "l4proto"}}), json!("udp"))];
    v.extend(guid_raw(guid));
    v
}

/// The raw RTPS header matches of [`guid_exprs`] without the `meta l4proto
/// udp` (for a rule that already matches a `udp` field before them: nft
/// lists that explicit dependency as redundant and hides it).
fn guid_raw(guid: &GuidPrefix) -> Vec<Value> {
    let w = guid.words();
    vec![
        raw32(64, RTPS_MAGIC),
        raw32(128, w[0]),
        raw32(160, w[1]),
        raw32(192, w[2]),
    ]
}

/// Direction of a match: `In` uses source address / input interface,
/// `Out` destination address / output interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dir {
    In,
    Out,
}

fn ends(dir: Dir) -> (&'static str, &'static str) {
    match dir {
        Dir::In => ("saddr", "iifname"),
        Dir::Out => ("daddr", "oifname"),
    }
}

/// The directions a chain matches an entry in: `input` the source end,
/// `output` the destination end, `forward` both.
fn dirs(chain: &str) -> &'static [Dir] {
    match chain {
        "input" => &[Dir::In],
        "output" => &[Dir::Out],
        _ => &[Dir::In, Dir::Out],
    }
}

fn verdict(mut expr: Vec<Value>, v: &str, counter: bool) -> Vec<Value> {
    if counter {
        expr.push(json!({"counter": null}));
    }
    expr.push(json!({ v: null }));
    expr
}

fn accept(expr: Vec<Value>) -> Vec<Value> {
    verdict(expr, "accept", false)
}

/// Interface and address matches of an entry in one direction.
fn base(cidr: Option<&IpNet>, iface: Option<&Iface>, dir: Dir) -> Vec<Value> {
    let (addr, ifkey) = ends(dir);
    let mut b = Vec::new();
    if let Some(i) = iface {
        b.push(m(json!({"meta": {"key": ifkey}}), json!(i.as_str())));
    }
    if let Some(c) = cidr {
        b.push(m(addr_field(c, addr), addr_value(c)));
    }
    b
}

/// The reply check for a packet from outside that matched a service's
/// **source** port: a TCP segment that is not a bare SYN (it can never open
/// a connection), or a UDP datagram of a flow conntrack has seen both ways.
fn reply_check(p: Proto) -> Value {
    match p {
        Proto::Tcp => json!({"match": {"op": "!=",
            "left": {"&": [{"payload": {"protocol": "tcp", "field": "flags"}}, ["syn", "ack"]]},
            "right": "syn"}}),
        Proto::Udp => json!({"match": {"op": "in",
            "left": {"ct": {"key": "state"}}, "right": "established"}}),
    }
}

/// The port rules of one entry in one direction of `chain`:
/// * every packet addressed **to** a port of the range (a request to a
///   service, local or remote);
/// * from the range: in `output` (the robot's own packets: a local
///   service's replies) always; from outside (`input`, `forward`) only with
///   `reply` (allow entries: [`reply_check`]); never for protected entries
///   (a spoofed source port would otherwise reach any local port).
fn port_rules(
    b: &[Value],
    p: Proto,
    (lo, hi): (u16, u16),
    chain: &str,
    reply: bool,
    tail: &[Value],
) -> Vec<Vec<Value>> {
    let mut out = Vec::new();
    let mut x = b.to_vec();
    x.push(port_match(p, "dport", lo, hi));
    x.extend_from_slice(tail);
    out.push(accept(x));
    let mut x = b.to_vec();
    x.push(port_match(p, "sport", lo, hi));
    if chain == "output" {
        x.extend_from_slice(tail);
        out.push(accept(x));
    } else if reply {
        x.push(reply_check(p));
        x.extend_from_slice(tail);
        out.push(accept(x));
    }
    out
}

/// Non-first IP fragments (no transport header: a port or payload match
/// never sees them) of an entry's traffic, accepted by its address or
/// interface. The first fragment carries the header and is matched as
/// usual, so a datagram whose first fragment is dropped is never
/// reassembled.
fn fragment_rules(cidr: Option<&IpNet>, iface: Option<&Iface>, dir: Dir) -> Vec<Vec<Value>> {
    let v4 = json!({"match": {"op": "!=",
        "left": {"&": [{"payload": {"protocol": "ip", "field": "frag-off"}}, 0x1fff]},
        "right": 0}});
    let v6 = json!({"match": {"op": "!=",
        "left": {"exthdr": {"name": "frag", "field": "frag-off"}}, "right": 0}});
    let b = base(cidr, iface, dir);
    let fams: Vec<Value> = match cidr {
        Some(c) if c.is_v4() => vec![v4],
        Some(_) => vec![v6],
        None => vec![v4, v6],
    };
    fams.into_iter()
        .map(|f| {
            let mut x = b.clone();
            x.push(f);
            accept(x)
        })
        .collect()
}

/// Accept rules for one allow entry in `chain` (see [`port_rules`]), plus
/// its non-first fragments when a port narrows it.
fn allow_rules(e: &AllowEntry, chain: &str) -> Vec<Vec<Value>> {
    let mut out = Vec::new();
    for &dir in dirs(chain) {
        let b = base(e.cidr.as_ref(), e.interface.as_ref(), dir);
        match (e.proto, e.port) {
            (Some(p), Some(port)) => {
                out.extend(port_rules(&b, p, (port, port), chain, true, &[]));
                out.extend(fragment_rules(e.cidr.as_ref(), e.interface.as_ref(), dir));
            }
            (Some(p), None) => {
                let mut x = b;
                x.push(m(json!({"meta": {"key": "l4proto"}}), json!(p.as_str())));
                out.push(accept(x));
            }
            _ => out.push(accept(b)),
        }
    }
    out
}

/// Accept rules for one protected (motion control path) entry in `chain`.
/// An entry without an address and an interface renders nothing: a GUID
/// prefix alone never opens anything (H1; configuration validation refuses
/// such an entry, this is the second line for an older journal).
fn protected_rules(e: &ProtectedEntry, chain: &str) -> Vec<Vec<Value>> {
    if e.cidr.is_none() && e.interface.is_none() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for &dir in dirs(chain) {
        let mut b = base(e.cidr.as_ref(), e.interface.as_ref(), dir);
        match (e.udp_ports, &e.guid_prefix) {
            (Some(r), g) => {
                let tail = g.as_ref().map(guid_raw).unwrap_or_default();
                out.extend(port_rules(
                    &b,
                    Proto::Udp,
                    (r.lo, r.hi),
                    chain,
                    false,
                    &tail,
                ));
            }
            (None, Some(g)) => {
                b.extend(guid_exprs(g));
                out.push(accept(b));
            }
            (None, None) => out.push(accept(b)),
        }
        if e.udp_ports.is_some() || e.guid_prefix.is_some() {
            out.extend(fragment_rules(e.cidr.as_ref(), e.interface.as_ref(), dir));
        }
    }
    out
}

fn locator_rule(l: &Locator, dir: Dir) -> Vec<Value> {
    let net = IpNet::host(l.ip);
    let (addr, _) = ends(dir);
    let port_field = match dir {
        Dir::In => "sport",
        Dir::Out => "dport",
    };
    verdict(
        vec![
            m(addr_field(&net, addr), addr_value(&net)),
            port_match(Proto::Udp, port_field, l.port, l.port),
        ],
        "drop",
        true,
    )
}

fn quarantine_rules(q: &QuarantineSpec, chain: &str) -> Vec<Vec<Value>> {
    let mut out = vec![verdict(guid_exprs(&q.guid_prefix), "drop", true)];
    for l in &q.locators {
        for &dir in dirs(chain) {
            out.push(locator_rule(l, dir));
        }
    }
    out
}

/// A value or, for more than one, an anonymous set.
fn one_or_set(mut v: Vec<Value>) -> Value {
    if v.len() == 1 {
        v.remove(0)
    } else {
        json!({ "set": v })
    }
}

fn icmpv6_types(types: &[&str]) -> Vec<Value> {
    vec![m(
        json!({"payload": {"protocol": "icmpv6", "field": "type"}}),
        one_or_set(types.iter().map(|t| json!(t)).collect()),
    )]
}

fn udp_ports(sport: u16, dport: u16) -> Vec<Value> {
    vec![
        port_match(Proto::Udp, "sport", sport, sport),
        port_match(Proto::Udp, "dport", dport, dport),
    ]
}

/// IPv4 "fragmentation needed" (path MTU discovery).
fn frag_needed() -> Vec<Value> {
    vec![
        m(
            json!({"payload": {"protocol": "icmp", "field": "type"}}),
            json!("destination-unreachable"),
        ),
        m(
            json!({"payload": {"protocol": "icmp", "field": "code"}}),
            json!("frag-needed"),
        ),
    ]
}

/// The interface matches of the discovery interfaces (one rule each, or
/// one rule without an interface match when any interface may carry them).
fn per_interface(d: &DiscoverySpec, ifkey: &str, rest: &[Value]) -> Vec<Vec<Value>> {
    if d.interfaces.is_empty() {
        return vec![accept(rest.to_vec())];
    }
    d.interfaces
        .iter()
        .map(|i| {
            let mut x = vec![m(json!({"meta": {"key": ifkey}}), json!(i.as_str()))];
            x.extend_from_slice(rest);
            accept(x)
        })
        .collect()
}

/// `ip[6] daddr <groups> udp dport <ports>` per address family (`true`:
/// IPv4).
fn discovery_matches(d: &DiscoverySpec) -> Vec<(bool, Vec<Value>)> {
    let ports = one_or_set(d.ports.iter().map(|p| json!(p)).collect());
    let mut out = Vec::new();
    for v4 in [true, false] {
        let groups: Vec<Value> = d
            .groups
            .iter()
            .filter(|g| g.is_ipv4() == v4)
            .map(|g| json!(g.to_string()))
            .collect();
        if groups.is_empty() || d.ports.is_empty() {
            continue;
        }
        let proto = if v4 { "ip" } else { "ip6" };
        out.push((
            v4,
            vec![
                m(
                    json!({"payload": {"protocol": proto, "field": "daddr"}}),
                    one_or_set(groups),
                ),
                m(
                    json!({"payload": {"protocol": "udp", "field": "dport"}}),
                    ports.clone(),
                ),
            ],
        ));
    }
    out
}

/// The robot's own discovery and IGMP (output), and discovery and IGMP
/// queries from the protected networks (input).
fn discovery_rules(s: &IsolationSpec, chain: &str) -> Vec<Vec<Value>> {
    let Some(d) = &s.discovery else {
        return Vec::new();
    };
    let igmp = vec![m(json!({"meta": {"key": "l4proto"}}), json!("igmp"))];
    let mut out = Vec::new();
    match chain {
        "output" => {
            out.extend(per_interface(d, "oifname", &igmp));
            for (_, dm) in discovery_matches(d) {
                out.extend(per_interface(d, "oifname", &dm));
            }
        }
        "input" => {
            out.extend(per_interface(d, "iifname", &igmp));
            for e in &s.protected {
                if e.cidr.is_none() && e.interface.is_none() {
                    continue;
                }
                for (v4, dm) in discovery_matches(d) {
                    if e.cidr.is_some_and(|c| c.is_v4() != v4) {
                        continue;
                    }
                    let mut x = base(e.cidr.as_ref(), e.interface.as_ref(), Dir::In);
                    x.extend(dm);
                    out.push(accept(x));
                }
            }
        }
        _ => {}
    }
    out
}

/// What every host needs to stay reachable at all (L5): loopback, IPv6
/// neighbour / router discovery and MLD, path MTU discovery (ICMP
/// "fragmentation needed", ICMPv6 "packet too big"), and the DHCP / DHCPv6
/// client exchange.
fn host_rules(chain: &str) -> Vec<Vec<Value>> {
    let mut out = Vec::new();
    match chain {
        "input" => {
            out.push(accept(vec![m(
                json!({"meta": {"key": "iifname"}}),
                json!("lo"),
            )]));
            out.push(accept(icmpv6_types(&[
                "packet-too-big",
                "mld-listener-query",
                "nd-router-advert",
                "nd-neighbor-solicit",
                "nd-neighbor-advert",
            ])));
            out.push(accept(frag_needed()));
            out.push(accept(udp_ports(67, 68)));
            out.push(accept(udp_ports(547, 546)));
        }
        "output" => {
            out.push(accept(vec![m(
                json!({"meta": {"key": "oifname"}}),
                json!("lo"),
            )]));
            out.push(accept(icmpv6_types(&[
                "packet-too-big",
                "mld-listener-report",
                "mld-listener-done",
                "nd-router-solicit",
                "nd-neighbor-solicit",
                "nd-neighbor-advert",
                "mld2-listener-report",
            ])));
            out.push(accept(frag_needed()));
            out.push(accept(udp_ports(68, 67)));
            out.push(accept(udp_ports(546, 547)));
        }
        _ => {
            out.push(accept(icmpv6_types(&["packet-too-big"])));
            out.push(accept(frag_needed()));
        }
    }
    out
}

fn isolation_rules(s: &IsolationSpec, chain: &str) -> Vec<Vec<Value>> {
    let mut out = host_rules(chain);
    out.extend(discovery_rules(s, chain));
    // The protected entries are in the preamble (see [`render`]).
    for e in &s.allow {
        out.extend(allow_rules(e, chain));
    }
    out.push(verdict(Vec::new(), "drop", true));
    out
}

/// Comment of the preamble's rules.
pub const PROTECTED_COMMENT: &str = "robodr protected motion_control_path";

/// Render the table for the active actions, per chain:
///
/// 1. **the protected preamble**: accepts for every motion-control-path
///    entry any active action may not cut (the union of the entries frozen
///    in the active isolations and quarantines), before any drop, so no
///    quarantine drop ever reaches a low-level or otherwise protected flow;
/// 2. the quarantines, then
/// 3. the isolation, each in id order.
pub fn render(active: &[Active<'_>]) -> Rendered {
    let mut acts: Vec<&Active<'_>> = active
        .iter()
        .filter(|a| matches!(a.effect, Effect::Isolate(_) | Effect::Quarantine(_)))
        .collect();
    if acts.is_empty() {
        return Rendered { chains: None };
    }
    acts.sort_by(|a, b| a.id.cmp(b.id));
    let mut protected: Vec<&ProtectedEntry> = Vec::new();
    for a in &acts {
        let list = match a.effect {
            Effect::Isolate(s) => &s.protected,
            Effect::Quarantine(q) => &q.protected,
            _ => continue,
        };
        for e in list {
            if !protected.contains(&e) {
                protected.push(e);
            }
        }
    }
    let mut chains = BTreeMap::new();
    for (chain, _) in CHAINS {
        let mut rules = Vec::new();
        for e in &protected {
            rules.extend(protected_rules(e, chain).into_iter().map(|expr| Rule {
                expr,
                comment: Some(PROTECTED_COMMENT.to_string()),
            }));
        }
        for a in &acts {
            if let Effect::Quarantine(q) = a.effect {
                let c = format!("robodr quarantine_node {}", tag(a.id));
                rules.extend(quarantine_rules(q, chain).into_iter().map(|expr| Rule {
                    expr,
                    comment: Some(c.clone()),
                }));
            }
        }
        for a in &acts {
            if let Effect::Isolate(s) = a.effect {
                let c = format!("robodr isolate_network {}", tag(a.id));
                rules.extend(isolation_rules(s, chain).into_iter().map(|expr| Rule {
                    expr,
                    comment: Some(c.clone()),
                }));
            }
        }
        chains.insert(chain.to_string(), rules);
    }
    Rendered {
        chains: Some(chains),
    }
}

fn table_obj() -> Value {
    json!({"table": {"family": FAMILY, "name": TABLE}})
}

/// The `nft -j -f -` transaction that makes the table exactly `r`. The
/// leading add+delete pair removes the table whether or not it exists, in
/// the same atomic transaction.
pub fn transaction(r: &Rendered) -> Value {
    let mut cmds = vec![json!({"add": table_obj()}), json!({"delete": table_obj()})];
    if let Some(chains) = &r.chains {
        cmds.push(json!({"add": table_obj()}));
        for (chain, hook) in CHAINS {
            cmds.push(json!({"add": {"chain": {
                "family": FAMILY, "table": TABLE, "name": chain,
                "type": "filter", "hook": hook, "prio": PRIORITY, "policy": "accept"
            }}}));
        }
        for (chain, _) in CHAINS {
            for rule in chains.get(chain).into_iter().flatten() {
                let mut obj = json!({
                    "family": FAMILY, "table": TABLE, "chain": chain, "expr": rule.expr
                });
                if let Some(c) = &rule.comment {
                    obj["comment"] = json!(c);
                }
                cmds.push(json!({"add": {"rule": obj}}));
            }
        }
    }
    json!({ "nftables": cmds })
}

/// Apply `r` in one transaction.
pub fn apply(nft: &mut dyn Nft, r: &Rendered) -> Result<(), String> {
    let batch = serde_json::to_vec(&transaction(r)).map_err(|e| e.to_string())?;
    nft.run(&["-j", "-f", "-"], Some(&batch)).map(|_| ())
}

/// Delete the table (emergency / revert-all). Absent is fine.
pub fn delete_table(nft: &mut dyn Nft) -> Result<(), String> {
    apply(nft, &Rendered { chains: None })
}

fn parse_list(out: &[u8]) -> Result<Vec<Value>, String> {
    let v: Value =
        serde_json::from_slice(out).map_err(|e| format!("nft -j output is not JSON: {e}"))?;
    v.get("nftables")
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| "nft -j output has no nftables array".into())
}

/// Whether `inet robodr` exists.
pub fn table_exists(nft: &mut dyn Nft) -> Result<bool, String> {
    let out = nft.run(&["-j", "list", "tables"], None)?;
    Ok(parse_list(&out)?.iter().any(|o| {
        o.get("table").is_some_and(|t| {
            t.get("family").and_then(Value::as_str) == Some(FAMILY)
                && t.get("name").and_then(Value::as_str) == Some(TABLE)
        })
    }))
}

/// The table's objects as listed (`None` when the table is absent).
pub fn read_table(nft: &mut dyn Nft) -> Result<Option<Vec<Value>>, String> {
    if !table_exists(nft)? {
        return Ok(None);
    }
    let out = nft.run(&["-j", "list", "table", FAMILY, TABLE], None)?;
    Ok(Some(parse_list(&out)?))
}

/// Replace counter statistics by `null` (they change with traffic) and
/// sort the elements of anonymous sets (nft lists them in its own order).
pub fn normalise_expr(e: &Value) -> Value {
    match e {
        Value::Object(o) if o.contains_key("counter") => json!({"counter": null}),
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, v)| {
                    let v = match (k.as_str(), v) {
                        ("set", Value::Array(a)) => {
                            let mut a: Vec<Value> = a.iter().map(normalise_expr).collect();
                            a.sort_by_key(|x| x.to_string());
                            Value::Array(a)
                        }
                        _ => normalise_expr(v),
                    };
                    (k.clone(), v)
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(normalise_expr).collect()),
        _ => e.clone(),
    }
}

/// Compare a listed table with what was rendered. `Ok(())` only when the
/// table has exactly the three base chains (type, hook, priority, policy)
/// and, per chain, exactly the rendered rules in order (expressions with
/// counters normalised, comments), and nothing else.
pub fn verify(listed: Option<&[Value]>, want: &Rendered) -> Result<(), String> {
    let (objs, chains) = match (listed, &want.chains) {
        (None, None) => return Ok(()),
        (Some(_), None) => return Err("table inet robodr exists but no action is active".into()),
        (None, Some(_)) => return Err("table inet robodr is missing".into()),
        (Some(o), Some(c)) => (o, c),
    };
    let mut seen_chains: BTreeMap<String, Value> = BTreeMap::new();
    let mut seen_rules: BTreeMap<String, Vec<Rule>> = BTreeMap::new();
    for o in objs {
        let Some(obj) = o.as_object() else {
            return Err("unexpected listing entry".into());
        };
        let Some((kind, body)) = obj.iter().next() else {
            continue;
        };
        let in_table = |b: &Value| {
            b.get("family").and_then(Value::as_str) == Some(FAMILY)
                && b.get("table")
                    .or_else(|| b.get("name"))
                    .and_then(Value::as_str)
                    == Some(TABLE)
        };
        match kind.as_str() {
            "metainfo" => {}
            "table" => {
                if !in_table(body) {
                    return Err("listing names another table".into());
                }
            }
            "chain" => {
                if !in_table(body) {
                    return Err("chain of another table in listing".into());
                }
                let name = body.get("name").and_then(Value::as_str).unwrap_or("");
                seen_chains.insert(name.to_string(), body.clone());
            }
            "rule" => {
                if !in_table(body) {
                    return Err("rule of another table in listing".into());
                }
                let chain = body
                    .get("chain")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let expr = body
                    .get("expr")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().map(normalise_expr).collect())
                    .unwrap_or_default();
                let comment = body
                    .get("comment")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                seen_rules
                    .entry(chain)
                    .or_default()
                    .push(Rule { expr, comment });
            }
            other => return Err(format!("unexpected object {other:?} in table inet robodr")),
        }
    }
    if seen_chains.len() != CHAINS.len() {
        return Err(format!(
            "table has {} chains, {} expected",
            seen_chains.len(),
            CHAINS.len()
        ));
    }
    for (name, hook) in CHAINS {
        let Some(c) = seen_chains.get(name) else {
            return Err(format!("chain {name} missing"));
        };
        let ok = c.get("type").and_then(Value::as_str) == Some("filter")
            && c.get("hook").and_then(Value::as_str) == Some(hook)
            && c.get("prio").and_then(Value::as_i64) == Some(PRIORITY)
            && c.get("policy").and_then(Value::as_str) == Some("accept");
        if !ok {
            return Err(format!(
                "chain {name} has the wrong type, hook, priority or policy"
            ));
        }
        let want_rules: Vec<Rule> = chains
            .get(name)
            .map(|rs| {
                rs.iter()
                    .map(|r| Rule {
                        expr: r.expr.iter().map(normalise_expr).collect(),
                        comment: r.comment.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let got = seen_rules.remove(name).unwrap_or_default();
        if got.len() != want_rules.len() {
            return Err(format!(
                "chain {name}: {} rules installed, {} rendered",
                got.len(),
                want_rules.len()
            ));
        }
        for (i, (g, w)) in got.iter().zip(&want_rules).enumerate() {
            if g != w {
                return Err(format!(
                    "chain {name} rule {i} differs: installed {} rendered {}",
                    serde_json::to_string(&g.expr).unwrap_or_default(),
                    serde_json::to_string(&w.expr).unwrap_or_default()
                ));
            }
        }
    }
    if let Some((c, _)) = seen_rules.into_iter().next() {
        return Err(format!("rules in unexpected chain {c:?}"));
    }
    Ok(())
}

/// Packet / byte counters of every drop rule, summed per comment (for
/// status and evidence).
pub fn drop_counters(listed: &[Value]) -> BTreeMap<String, (u64, u64)> {
    let mut out: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for o in listed {
        let Some(r) = o.get("rule") else { continue };
        let comment = r
            .get("comment")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        for e in r
            .get("expr")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(c) = e.get("counter") {
                let p = c.get("packets").and_then(Value::as_u64).unwrap_or(0);
                let b = c.get("bytes").and_then(Value::as_u64).unwrap_or(0);
                let s = out.entry(comment.clone()).or_default();
                s.0 = s.0.saturating_add(p);
                s.1 = s.1.saturating_add(b);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quarantine(g: &str) -> Effect {
        Effect::Quarantine(QuarantineSpec {
            guid_prefix: g.parse().unwrap(),
            locators: vec![Locator {
                ip: "10.0.0.7".parse().unwrap(),
                port: 7410,
            }],
            excluded: vec![],
            protected: vec![],
        })
    }

    #[test]
    fn empty_set_renders_no_table() {
        let r = render(&[]);
        assert_eq!(r.chains, None);
        let t = transaction(&r);
        assert_eq!(t["nftables"].as_array().unwrap().len(), 2);
        assert!(verify(None, &r).is_ok());
        assert!(verify(Some(&[]), &r).is_err());
    }

    #[test]
    fn transaction_names_only_the_robodr_table() {
        let q = quarantine("0110a2b3c4d5e6f701000000");
        let iso = Effect::Isolate(IsolationSpec {
            allow: vec![AllowEntry {
                cidr: Some("10.20.0.0/24".parse().unwrap()),
                interface: None,
                proto: Some(Proto::Tcp),
                port: Some(443),
                note: None,
            }],
            protected: vec![],
            discovery: None,
        });
        let r = render(&[
            Active {
                id: "b",
                effect: &iso,
            },
            Active {
                id: "a",
                effect: &q,
            },
        ]);
        let t = transaction(&r);
        for cmd in t["nftables"].as_array().unwrap() {
            let (_, obj) = cmd.as_object().unwrap().iter().next().unwrap();
            let (_, inner) = obj.as_object().unwrap().iter().next().unwrap();
            assert_eq!(inner["family"], "inet");
            let name = inner.get("table").or_else(|| inner.get("name")).unwrap();
            assert_eq!(name, "robodr");
        }
        let chains = r.chains.unwrap();
        // Quarantine before isolation; isolation ends with a drop.
        let input = &chains["input"];
        assert!(input[0]
            .comment
            .as_deref()
            .unwrap()
            .starts_with("robodr quarantine_node"));
        let last = input.last().unwrap();
        assert_eq!(last.expr.last().unwrap(), &json!({"drop": null}));
    }

    #[test]
    fn verify_detects_any_difference() {
        let q = quarantine("0110a2b3c4d5e6f701000000");
        let r = render(&[Active {
            id: "a",
            effect: &q,
        }]);
        // Build a listing from the rendering itself.
        let mut listed = vec![json!({"table": {"family": "inet", "name": "robodr", "handle": 1}})];
        for (chain, hook) in CHAINS {
            listed.push(json!({"chain": {"family": "inet", "table": "robodr", "name": chain,
                "handle": 1, "type": "filter", "hook": hook, "prio": PRIORITY, "policy": "accept"}}));
        }
        for (chain, _) in CHAINS {
            for rule in &r.chains.as_ref().unwrap()[chain] {
                let expr: Vec<Value> = rule
                    .expr
                    .iter()
                    .map(|e| {
                        if e.get("counter").is_some() {
                            json!({"counter": {"packets": 5, "bytes": 300}})
                        } else {
                            e.clone()
                        }
                    })
                    .collect();
                listed.push(
                    json!({"rule": {"family": "inet", "table": "robodr", "chain": chain,
                    "handle": 9, "comment": rule.comment, "expr": expr}}),
                );
            }
        }
        assert_eq!(verify(Some(&listed), &r), Ok(()));
        let counters = drop_counters(&listed);
        assert!(counters.values().all(|(p, _)| *p > 0));
        // An extra rule.
        let mut extra = listed.clone();
        extra.push(
            json!({"rule": {"family": "inet", "table": "robodr", "chain": "input",
            "handle": 99, "expr": [{"accept": null}]}}),
        );
        assert!(verify(Some(&extra), &r).is_err());
        // A changed policy.
        let mut pol = listed.clone();
        pol[1]["chain"]["policy"] = json!("drop");
        assert!(verify(Some(&pol), &r).is_err());
        // A set inside the table.
        let mut set = listed.clone();
        set.push(json!({"set": {"family": "inet", "table": "robodr", "name": "x"}}));
        assert!(verify(Some(&set), &r).is_err());
        // A rule edited (port changed).
        let mut edited = listed.clone();
        let idx = edited
            .iter()
            .position(|o| {
                o.get("rule")
                    .is_some_and(|r| r["expr"].as_array().unwrap().len() == 4)
            })
            .unwrap();
        edited[idx]["rule"]["expr"][1]["match"]["right"] = json!(7411);
        assert!(verify(Some(&edited), &r).is_err());
        // Missing table.
        assert!(verify(None, &r).is_err());
    }
}
