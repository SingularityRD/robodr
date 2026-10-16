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
//! | `PID_VENDORID` equals `vendor` | a Cyclone process cannot take a Fast DDS node's place |
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
}

#[derive(Debug, Clone)]
struct Matcher {
    name: String,
    ips: Vec<IpAddr>,
    vendor: [u8; 2],
    enclave: Option<String>,
    max: usize,
}

#[derive(Debug, Clone, Copy)]
struct Holding {
    idx: usize,
    last: Instant,
    lease: Duration,
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

    /// The identity `prefix` currently holds.
    pub fn identity_of(&self, prefix: &GuidPrefix) -> Option<&str> {
        self.held.get(prefix).map(|h| self.ids[h.idx].name.as_str())
    }

    /// Live holders, prefix -> identity name.
    pub fn holders(&self) -> impl Iterator<Item = (&GuidPrefix, &str)> {
        self.held
            .iter()
            .map(|(p, h)| (p, self.ids[h.idx].name.as_str()))
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
            if self.ids[h.idx].ips.contains(&ip) {
                h.last = now;
                h.lease = lease;
            }
            return Resolution::Refreshed;
        }
        let Some(vendor) = spdp.vendor_id else {
            return Resolution::NoMatch;
        };
        let enclave = spdp.enclave();
        let mut full: Option<Resolution> = None;
        for (idx, m) in self.ids.iter().enumerate() {
            if !m.ips.contains(&ip)
                || m.vendor != vendor
                || m.enclave.as_deref().is_some_and(|e| enclave != Some(e))
            {
                continue;
            }
            let holders: Vec<GuidPrefix> = self
                .held
                .iter()
                .filter(|(_, h)| h.idx == idx && now.saturating_duration_since(h.last) <= h.lease)
                .map(|(p, _)| *p)
                .collect();
            if holders.len() < m.max {
                self.held.insert(
                    p,
                    Holding {
                        idx,
                        last: now,
                        lease,
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
        Some(self.ids[h.idx].name.clone())
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
                Some((p, self.ids[h.idx].name.clone()))
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
