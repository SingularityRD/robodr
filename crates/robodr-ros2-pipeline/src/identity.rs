//! Run-time resolution of fresh GUID prefixes to the profile's stable
//! participant identities (`Profile::participant_identities`).
//!
//! # The problem
//!
//! DDS stacks draw a new GUID prefix every time a process starts: Fast DDS
//! puts the process id into it, Cyclone DDS draws it at random. A profile
//! that lists only `participants` (GUID prefixes) therefore matches only the
//! run it was learned from; after the robot's next reboot every one of its
//! own nodes is an "unknown participant", and its controller publishing
//! `/cmd_vel` is a Critical "unauthorized motion writer". This was found on
//! the first real ROS 2 captures (Fast DDS and Cyclone DDS, ROS 2 Jazzy):
//! two runs of the same launch never shared a prefix.
//!
//! # What this module does
//!
//! For every SPDP announcement of a prefix that is **not** statically
//! profiled, the pipeline asks [`IdentityResolver::observe_spdp`] whether it
//! matches an identity:
//!
//! | condition | why |
//! |---|---|
//! | the SPDP was sent by the participant itself (not relayed) and carries one `PID_PARTICIPANT_GUID` | a relayed or ambiguous announcement says nothing about where the participant runs |
//! | its source IP is one of the identity's `ips`, and the binding check does not reject it (not contested, not outside an existing binding, not a forged loopback source) | the identity is a place on the robot's network |
//! | `PID_VENDORID` equals `vendor`; for a DDS-Security participant (identity token in SPDP, prefix top bit set) the first two prefix bytes may match instead | a Cyclone process cannot take a Fast DDS node's place; a secured prefix is derived from the certificate subject, and `learn` takes `vendor` from the prefix |
//! | the SPDP user-data enclave equals `enclave`, when set | the SROS 2 enclave is stable per node set |
//! | fewer than `max_instances` live prefixes hold the identity | a rogue started next to the live controller stays unknown |
//!
//! A resolved prefix is added to the pipeline's working copy of
//! `participants` (and marked profiled in the binding table), so every
//! profile check treats it as the participant it replaces. It holds the
//! identity until it disposes itself (SPDP `PID_STATUS_INFO`) or its lease
//! expires (the SPDP `lease_duration`, clamped like the binding's), after
//! which it is removed from the working copy again.
//!
//! When every slot of a matching identity is held,
//! [`rules::IDENTITY_INSTANCES_EXCEEDED`] (High) is raised next to the
//! profile's `robot.ros2.unknown_participant`.
//!
//! # Which identity: node evidence
//!
//! Several processes on one host with one vendor and enclave are
//! indistinguishable at SPDP time, so the first free matching slot is taken
//! *provisionally*. That is enough for "is this a robot participant" (the
//! profile checks), but not for rights given **by name** (`identity:<name>`
//! sources of the Motion Firewall, `safety_feed` writers): process B must
//! not hold controller A's name. Every ROS 2 node serves
//! `/<node>/get_parameters`, so when the participant announces that
//! service's reply writer, [`IdentityResolver::observe_node`] confirms the
//! slot if the node is one of the identity's `nodes`, or moves the
//! participant to the identity that lists the node (swapping with an
//! unconfirmed holder if needed). Only confirmed holdings are handed out by
//! [`IdentityResolver::holders`] / [`IdentityResolver::identity_of`]; an
//! identity whose `nodes` is empty is confirmed at SPDP time (nothing to
//! check it against).
//!
//! # Limits (be honest)
//!
//! - Source IPs are not authenticated (see [`crate::binding`]); an attacker
//!   on the robot's L2 segment who forges a robot IP while the real node is
//!   down can hold its identity. Everything that participant announces is
//!   still checked against the topic / service / action allowlists.
//! - A process that crashes and restarts within its lease (Fast DDS 20 s by
//!   default) finds its own slot still held: the new prefix is an unknown
//!   participant until the old lease expires and its next SPDP resolves it.
//!   A crash-restart of a robot process is worth a finding; commission
//!   `max_instances` 2 for nodes that restart by design.
//! - Several processes on one host with one vendor and enclave are
//!   indistinguishable at SPDP time; give the identity `max_instances` equal
//!   to the number of such processes (`learn` counts them).

use crate::binding::{canonical_ip, MAX_LEASE, MIN_LEASE};
use robodr_events::profile::Profile;
use robodr_rtps::{GuidPrefix, SpdpInfo};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Lease used when SPDP carries none (as the binding table).
const DEFAULT_LEASE: Duration = crate::binding::DEFAULT_LEASE;

/// Rule ids raised by identity resolution.
pub mod rules {
    /// A participant matched an identity of the profile whose every
    /// `max_instances` slot is held by a live participant.
    pub const IDENTITY_INSTANCES_EXCEEDED: &str = "robot.ros2.identity_instances_exceeded";
}

/// Counters of the resolver.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct IdentityStats {
    /// Prefixes resolved to an identity.
    pub resolved: u64,
    /// Resolutions refused because every slot was held.
    pub pool_full: u64,
    /// Identities released by a self-dispose.
    pub released: u64,
    /// Identities released by lease expiry.
    pub expired: u64,
    /// Holdings confirmed by node evidence.
    pub confirmed: u64,
    /// Holdings moved (or swapped) to the identity their node belongs to.
    pub moved: u64,
}

#[derive(Debug, Clone)]
struct Matcher {
    name: String,
    ips: Vec<IpAddr>,
    vendor: [u8; 2],
    enclave: Option<String>,
    nodes: std::collections::BTreeSet<String>,
    max: usize,
}

#[derive(Debug, Clone, Copy)]
struct Holding {
    idx: usize,
    last: Instant,
    lease: Duration,
    /// Source IP and vendor it was resolved from (a move keeps them).
    ip: IpAddr,
    vendor: [u8; 2],
    /// Node evidence matched the identity (or it lists no nodes).
    confirmed: bool,
}

/// What [`IdentityResolver::observe_node`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeEvidence {
    /// The prefix holds no identity, or the evidence changes nothing.
    Nothing,
    /// The holding is confirmed for `identity`.
    Confirmed { identity: String },
    /// The prefix moved from `from` to `to` (confirmed).
    Moved { from: String, to: String },
    /// The node belongs to no identity the prefix could hold: it stays
    /// unconfirmed (its parameter services are not in the profile either,
    /// which the service allowlist reports).
    Unmatched,
}

/// What [`IdentityResolver::observe_spdp`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// No identity matches (or the resolver has none): the prefix stays
    /// unprofiled.
    NoMatch,
    /// Already held by this prefix; its lease was refreshed.
    Refreshed,
    /// The prefix now holds `identity`.
    Resolved { identity: String },
    /// `identity` matches but all of its `max` slots are held by `holders`.
    PoolFull {
        identity: String,
        max: usize,
        holders: Vec<GuidPrefix>,
    },
}

/// See the module docs.
#[derive(Debug, Clone, Default)]
pub struct IdentityResolver {
    ids: Vec<Matcher>,
    held: BTreeMap<GuidPrefix, Holding>,
    stats: IdentityStats,
}

fn parse_vendor(s: &str) -> Option<[u8; 2]> {
    if s.len() != 4 {
        return None;
    }
    let b = u16::from_str_radix(s, 16).ok()?.to_be_bytes();
    Some(b)
}

impl IdentityResolver {
    /// The identities of `profile` (entries that do not parse are skipped:
    /// such a profile fails `Profile::validate` and is observe-only anyway).
    pub fn new(profile: &Profile) -> Self {
        let ids = profile
            .participant_identities
            .iter()
            .filter_map(|(name, id)| {
                let ips: Vec<IpAddr> = id
                    .ips
                    .iter()
                    .filter_map(|s| s.parse::<IpAddr>().ok().map(canonical_ip))
                    .collect();
                if ips.is_empty() {
                    return None;
                }
                Some(Matcher {
                    name: name.clone(),
                    ips,
                    vendor: parse_vendor(&id.vendor)?,
                    enclave: id.enclave.clone(),
                    nodes: id.nodes.clone(),
                    max: usize::try_from(id.max_instances.max(1)).unwrap_or(1),
                })
            })
            .collect();
        Self {
            ids,
            held: BTreeMap::new(),
            stats: IdentityStats::default(),
        }
    }

    /// No identities: resolution is off.
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    pub fn stats(&self) -> &IdentityStats {
        &self.stats
    }

    /// Does `prefix` hold a slot (confirmed or provisional)? It is then a
    /// profiled participant.
    pub fn holds(&self, prefix: &GuidPrefix) -> bool {
        self.held.contains_key(prefix)
    }

    /// The identity `prefix` holds, **confirmed** (see the module docs);
    /// `None` while provisional.
    pub fn identity_of(&self, prefix: &GuidPrefix) -> Option<&str> {
        self.held
            .get(prefix)
            .filter(|h| h.confirmed)
            .and_then(|h| self.ids.get(h.idx))
            .map(|m| m.name.as_str())
    }

    /// Live confirmed holders, prefix -> identity name.
    pub fn holders(&self) -> impl Iterator<Item = (&GuidPrefix, &str)> {
        self.held
            .iter()
            .filter(|(_, h)| h.confirmed)
            .filter_map(|(p, h)| Some((p, self.ids.get(h.idx)?.name.as_str())))
    }

    fn live_holders(&self, idx: usize, now: Instant) -> Vec<GuidPrefix> {
        self.held
            .iter()
            .filter(|(_, h)| h.idx == idx && now.saturating_duration_since(h.last) <= h.lease)
            .map(|(p, _)| *p)
            .collect()
    }

    /// Node evidence for `prefix`: it serves `/<node>/get_parameters`. See
    /// the module docs ("Which identity").
    pub fn observe_node(&mut self, prefix: &GuidPrefix, node: &str, now: Instant) -> NodeEvidence {
        let Some(h) = self.held.get(prefix).copied() else {
            return NodeEvidence::Nothing;
        };
        // Holdings only ever index `ids`, which is fixed at construction.
        let Some(from) = self.ids.get(h.idx) else {
            return NodeEvidence::Nothing;
        };
        if from.nodes.contains(node) {
            if h.confirmed {
                return NodeEvidence::Nothing;
            }
            if let Some(x) = self.held.get_mut(prefix) {
                x.confirmed = true;
            }
            self.stats.confirmed += 1;
            return NodeEvidence::Confirmed {
                identity: from.name.clone(),
            };
        }
        if h.confirmed {
            // Confirmed by another of its nodes: a second node of the same
            // process that the identity does not list changes nothing here.
            return NodeEvidence::Nothing;
        }
        let target =
            self.ids.iter().enumerate().find(|(_, m)| {
                m.nodes.contains(node) && m.ips.contains(&h.ip) && m.vendor == h.vendor
            });
        let Some((to, target)) = target else {
            return NodeEvidence::Unmatched;
        };
        let holders = self.live_holders(to, now);
        if holders.len() >= target.max {
            // Swap with an unconfirmed holder of the target, if any.
            let Some(other) = holders
                .iter()
                .find(|p| self.held.get(*p).is_some_and(|x| !x.confirmed))
                .copied()
            else {
                return NodeEvidence::Unmatched;
            };
            if let Some(x) = self.held.get_mut(&other) {
                x.idx = h.idx;
            }
        }
        if let Some(x) = self.held.get_mut(prefix) {
            x.idx = to;
            x.confirmed = true;
        }
        self.stats.moved += 1;
        self.stats.confirmed += 1;
        NodeEvidence::Moved {
            from: from.name.clone(),
            to: target.name.clone(),
        }
    }

    /// Judge one SPDP announcement of a prefix that is not statically
    /// profiled. The caller has already checked that the SPDP is the
    /// participant's own (not relayed, no alternate GUIDs) and that the
    /// binding check does not reject `ip` for it.
    pub fn observe_spdp(&mut self, spdp: &SpdpInfo, ip: IpAddr, now: Instant) -> Resolution {
        if self.ids.is_empty() {
            return Resolution::NoMatch;
        }
        let ip = canonical_ip(ip);
        let p = spdp.guid_prefix;
        let lease = spdp
            .lease_duration
            .and_then(|d| d.to_std())
            .unwrap_or(DEFAULT_LEASE)
            .clamp(MIN_LEASE, MAX_LEASE);
        if let Some(h) = self.held.get_mut(&p) {
            // Refresh only from one of the identity's own addresses.
            if self.ids.get(h.idx).is_some_and(|m| m.ips.contains(&ip)) {
                h.last = now;
                h.lease = lease;
            }
            return Resolution::Refreshed;
        }
        let Some(vendor) = spdp.vendor_id else {
            return Resolution::NoMatch;
        };
        let enclave = spdp.enclave();
        // DDS-Security derives a secured participant's GUID prefix from its
        // certificate subject (top bit set), so a profile learned from the
        // prefix holds those subject-hash bytes as `vendor` (seen on real
        // Fast DDS 2.6 SROS 2 captures). They are stable per certificate
        // subject and can never equal a real vendor id (0x01xx).
        let secured_hash = (spdp.security.is_secured() && p[0] & 0x80 != 0).then_some([p[0], p[1]]);
        let mut full: Option<Resolution> = None;
        for (idx, m) in self.ids.iter().enumerate() {
            if !m.ips.contains(&ip)
                || (m.vendor != vendor && Some(m.vendor) != secured_hash)
                || m.enclave.as_deref().is_some_and(|e| enclave != Some(e))
            {
                continue;
            }
            let holders = self.live_holders(idx, now);
            if holders.len() < m.max {
                let confirmed = m.nodes.is_empty();
                self.held.insert(
                    p,
                    Holding {
                        idx,
                        last: now,
                        lease,
                        ip,
                        // The matched form (vendor id, or subject hash of
                        // a secured participant), for node-evidence moves.
                        vendor: m.vendor,
                        confirmed,
                    },
                );
                self.stats.resolved += 1;
                return Resolution::Resolved {
                    identity: m.name.clone(),
                };
            }
            full.get_or_insert(Resolution::PoolFull {
                identity: m.name.clone(),
                max: m.max,
                holders,
            });
        }
        match full {
            Some(r) => {
                self.stats.pool_full += 1;
                r
            }
            None => Resolution::NoMatch,
        }
    }

    /// The participant disposed itself: free its slot. Returns the identity
    /// it held.
    pub fn release(&mut self, prefix: &GuidPrefix) -> Option<String> {
        let h = self.held.remove(prefix)?;
        self.stats.released += 1;
        self.ids.get(h.idx).map(|m| m.name.clone())
    }

    /// Free the slots whose lease expired; returns them.
    pub fn expire(&mut self, now: Instant) -> Vec<(GuidPrefix, String)> {
        let gone: Vec<GuidPrefix> = self
            .held
            .iter()
            .filter(|(_, h)| now.saturating_duration_since(h.last) > h.lease)
            .map(|(p, _)| *p)
            .collect();
        gone.into_iter()
            .filter_map(|p| {
                let h = self.held.remove(&p)?;
                self.stats.expired += 1;
                Some((p, self.ids.get(h.idx)?.name.clone()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use robodr_events::profile::ParticipantIdentity;
    use robodr_rtps::RtpsDuration;

    const FAST: [u8; 2] = [0x01, 0x0f];
    const CYC: [u8; 2] = [0x01, 0x10];

    fn profile(max: u32, enclave: Option<&str>) -> Profile {
        let mut p = Profile {
            model: "m".into(),
            ..Default::default()
        };
        p.participant_identities.insert(
            "base".into(),
            ParticipantIdentity {
                ips: ["10.0.0.10".to_owned()].into(),
                vendor: "010f".into(),
                enclave: enclave.map(str::to_owned),
                nodes: Default::default(),
                max_instances: max,
            },
        );
        p
    }

    fn spdp(prefix: u8, vendor: [u8; 2], lease_s: Option<i32>, user: &str) -> SpdpInfo {
        SpdpInfo {
            guid_prefix: [prefix; 12],
            attribution: robodr_rtps::Attribution::ParticipantGuid,
            source: [prefix; 12],
            participant_entity: None,
            protocol_version: None,
            vendor_id: Some(vendor),
            domain_id: None,
            domain_tag: None,
            entity_name: None,
            user_data: Some(user.as_bytes().to_vec()),
            lease_duration: lease_s.map(|seconds| RtpsDuration {
                seconds,
                fraction: 0,
            }),
            metatraffic_unicast: Vec::new(),
            metatraffic_multicast: Vec::new(),
            default_unicast: Vec::new(),
            default_multicast: Vec::new(),
            alternate_guid_prefixes: Vec::new(),
            from_fragments: false,
            security: Default::default(),
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn resolves_by_ip_and_vendor_and_caps_instances() {
        let mut r = IdentityResolver::new(&profile(1, None));
        let t = Instant::now();
        assert_eq!(
            r.observe_spdp(&spdp(1, FAST, Some(20), "enclave=/;"), ip("10.0.0.10"), t),
            Resolution::Resolved {
                identity: "base".into()
            }
        );
        assert_eq!(r.identity_of(&[1; 12]), Some("base"));
        // Same prefix again: refresh.
        assert_eq!(
            r.observe_spdp(&spdp(1, FAST, Some(20), ""), ip("10.0.0.10"), t),
            Resolution::Refreshed
        );
        // A second live process on the same host: pool full.
        assert!(matches!(
            r.observe_spdp(&spdp(2, FAST, Some(20), ""), ip("10.0.0.10"), t),
            Resolution::PoolFull { ref identity, max: 1, ref holders } if identity == "base" && holders == &vec![[1u8; 12]]
        ));
        // Wrong vendor or IP: no match.
        assert_eq!(
            r.observe_spdp(&spdp(3, CYC, None, ""), ip("10.0.0.10"), t),
            Resolution::NoMatch
        );
        assert_eq!(
            r.observe_spdp(&spdp(4, FAST, None, ""), ip("10.0.0.66"), t),
            Resolution::NoMatch
        );
        assert_eq!(r.stats().resolved, 1);
        assert_eq!(r.stats().pool_full, 1);
    }

    #[test]
    fn slot_frees_on_dispose_and_lease_expiry() {
        let mut r = IdentityResolver::new(&profile(1, None));
        let t = Instant::now();
        r.observe_spdp(&spdp(1, FAST, Some(20), ""), ip("10.0.0.10"), t);
        assert_eq!(r.release(&[1; 12]).as_deref(), Some("base"));
        assert!(matches!(
            r.observe_spdp(&spdp(2, FAST, Some(20), ""), ip("10.0.0.10"), t),
            Resolution::Resolved { .. }
        ));
        // Crash: prefix 2 stops beaconing. Within its lease a restart is
        // refused; after it the slot is free again.
        let t2 = t + Duration::from_secs(5);
        assert!(matches!(
            r.observe_spdp(&spdp(3, FAST, Some(20), ""), ip("10.0.0.10"), t2),
            Resolution::PoolFull { .. }
        ));
        let t3 = t + Duration::from_secs(21);
        assert!(matches!(
            r.observe_spdp(&spdp(3, FAST, Some(20), ""), ip("10.0.0.10"), t3),
            Resolution::Resolved { .. }
        ));
        assert_eq!(r.expire(t3), vec![([2; 12], "base".to_owned())]);
        assert_eq!(r.identity_of(&[3; 12]), Some("base"));
    }

    #[test]
    fn refresh_from_foreign_ip_does_not_extend_the_lease() {
        let mut r = IdentityResolver::new(&profile(1, None));
        let t = Instant::now();
        r.observe_spdp(&spdp(1, FAST, Some(10), ""), ip("10.0.0.10"), t);
        let t2 = t + Duration::from_secs(8);
        r.observe_spdp(&spdp(1, FAST, Some(10), ""), ip("10.0.0.66"), t2);
        assert_eq!(r.expire(t + Duration::from_secs(11)).len(), 1);
    }

    #[test]
    fn enclave_is_checked_when_set_and_instances_scale() {
        let mut r = IdentityResolver::new(&profile(2, Some("/robot")));
        let t = Instant::now();
        assert_eq!(
            r.observe_spdp(&spdp(1, FAST, None, "enclave=/;"), ip("10.0.0.10"), t),
            Resolution::NoMatch
        );
        for p in [1, 2] {
            assert!(matches!(
                r.observe_spdp(&spdp(p, FAST, None, "enclave=/robot;"), ip("10.0.0.10"), t),
                Resolution::Resolved { .. }
            ));
        }
        assert!(matches!(
            r.observe_spdp(&spdp(3, FAST, None, "enclave=/robot;"), ip("10.0.0.10"), t),
            Resolution::PoolFull { max: 2, .. }
        ));
    }

    #[test]
    fn empty_profile_resolves_nothing() {
        let mut r = IdentityResolver::new(&Profile::default());
        assert!(r.is_empty());
        assert_eq!(
            r.observe_spdp(&spdp(1, FAST, None, ""), ip("10.0.0.10"), Instant::now()),
            Resolution::NoMatch
        );
    }
}

#[cfg(test)]
mod node_evidence_tests {
    use super::*;
    use robodr_events::profile::ParticipantIdentity;

    /// Two processes on one host, same vendor: identities `a` (node /a) and
    /// `b` (node /b).
    fn resolver() -> IdentityResolver {
        let mut p = Profile {
            model: "m".into(),
            ..Default::default()
        };
        for n in ["a", "b"] {
            p.participant_identities.insert(
                n.into(),
                ParticipantIdentity {
                    ips: ["10.0.0.10".to_owned()].into(),
                    vendor: "010f".into(),
                    enclave: None,
                    nodes: [format!("/{n}")].into(),
                    max_instances: 1,
                },
            );
        }
        IdentityResolver::new(&p)
    }

    fn spdp(prefix: u8) -> SpdpInfo {
        SpdpInfo {
            guid_prefix: [prefix; 12],
            attribution: robodr_rtps::Attribution::ParticipantGuid,
            source: [prefix; 12],
            participant_entity: None,
            protocol_version: None,
            vendor_id: Some([0x01, 0x0f]),
            domain_id: None,
            domain_tag: None,
            entity_name: None,
            user_data: None,
            lease_duration: None,
            metatraffic_unicast: Vec::new(),
            metatraffic_multicast: Vec::new(),
            default_unicast: Vec::new(),
            default_multicast: Vec::new(),
            alternate_guid_prefixes: Vec::new(),
            from_fragments: false,
            security: Default::default(),
        }
    }

    fn ip() -> IpAddr {
        "10.0.0.10".parse().unwrap()
    }

    #[test]
    fn provisional_until_a_node_names_the_identity() {
        let mut r = resolver();
        let t = Instant::now();
        // Process "b" starts first and provisionally takes slot "a".
        assert!(
            matches!(r.observe_spdp(&spdp(2), ip(), t), Resolution::Resolved { ref identity } if identity == "a")
        );
        assert!(r.holds(&[2; 12]));
        assert_eq!(r.identity_of(&[2; 12]), None, "not confirmed yet");
        assert_eq!(r.holders().count(), 0);
        // Its /b/get_parameters service moves it to "b".
        assert_eq!(
            r.observe_node(&[2; 12], "/b", t),
            NodeEvidence::Moved {
                from: "a".into(),
                to: "b".into()
            }
        );
        assert_eq!(r.identity_of(&[2; 12]), Some("b"));
        // Process "a" then gets "a" and confirms it.
        assert!(
            matches!(r.observe_spdp(&spdp(1), ip(), t), Resolution::Resolved { ref identity } if identity == "a")
        );
        assert_eq!(
            r.observe_node(&[1; 12], "/a", t),
            NodeEvidence::Confirmed {
                identity: "a".into()
            }
        );
        assert_eq!(r.holders().count(), 2);
    }

    #[test]
    fn crossed_provisional_slots_are_swapped() {
        let mut r = resolver();
        let t = Instant::now();
        r.observe_spdp(&spdp(1), ip(), t); // -> a (provisional)
        r.observe_spdp(&spdp(2), ip(), t); // -> b (provisional)
                                           // 1 is really "b": swap with the unconfirmed holder 2.
        assert!(matches!(
            r.observe_node(&[1; 12], "/b", t),
            NodeEvidence::Moved { .. }
        ));
        assert_eq!(r.identity_of(&[1; 12]), Some("b"));
        assert_eq!(r.identity_of(&[2; 12]), None);
        assert!(matches!(
            r.observe_node(&[2; 12], "/a", t),
            NodeEvidence::Confirmed { .. }
        ));
        assert_eq!(r.identity_of(&[2; 12]), Some("a"));
        // A confirmed holding is never moved by a later node.
        assert_eq!(r.observe_node(&[2; 12], "/b", t), NodeEvidence::Nothing);
        assert_eq!(r.identity_of(&[2; 12]), Some("a"));
    }

    #[test]
    fn a_node_of_no_identity_stays_unconfirmed() {
        let mut r = resolver();
        let t = Instant::now();
        r.observe_spdp(&spdp(1), ip(), t);
        assert_eq!(
            r.observe_node(&[1; 12], "/rogue", t),
            NodeEvidence::Unmatched
        );
        assert_eq!(r.identity_of(&[1; 12]), None);
        assert!(
            r.holds(&[1; 12]),
            "still a profiled participant for the profile checks"
        );
        // An identity whose real holder is confirmed cannot be taken over.
        r.observe_spdp(&spdp(2), ip(), t); // -> b
        r.observe_node(&[2; 12], "/b", t);
        assert_eq!(r.observe_node(&[1; 12], "/b", t), NodeEvidence::Unmatched);
        assert_eq!(r.identity_of(&[2; 12]), Some("b"));
    }
}
