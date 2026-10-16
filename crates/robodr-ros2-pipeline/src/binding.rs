//! Participant ↔ source-IP binding: who may speak for a GUID prefix.
//!
//! # The problem
//!
//! Without DDS-Security every GUID on the bus is a *claim*. An SEDP
//! announcement whose `PID_ENDPOINT_GUID` carries the prefix of a profiled
//! participant (say nav2) is attributed to that participant by the RTPS
//! parser, whatever host sent it, and the profile then accepts its
//! `rt/cmd_vel` writer. The sender can even put the victim's prefix in the
//! RTPS header, so "header prefix ≠ endpoint prefix" alone does not catch it.
//!
//! # What this module does
//!
//! It learns, per GUID prefix, the **source IPs** its SPDP announcements
//! arrive from and the **unicast locators** it advertises, and judges every
//! SEDP endpoint announcement against that binding:
//!
//! | Situation | Verdict |
//! |---|---|
//! | the prefix is pinned in the config (`participant_ips`) and the source IP is one of the pinned IPs | ok |
//! | pinned, other source IP | mismatch |
//! | bound by SPDP, source IP is a bound source IP or an advertised unicast locator IP | ok |
//! | bound by SPDP, other source IP | mismatch |
//! | relayed (sender prefix ≠ owner prefix, i.e. INFO_SRC / foreign header) or GUID conflict (`PID_PARTICIPANT_GUID` ≠ endpoint GUID prefix), from a configured discovery-server IP | ok (the relay is trusted) |
//! | relayed / GUID conflict from any other IP | mismatch |
//! | no binding yet (SEDP seen before SPDP) | **held** for `hold`; re-judged when the SPDP arrives; still unbound when the hold expires → "never announced" |
//!
//! A mismatch is [`rules::ENDPOINT_SOURCE_MISMATCH`]: **Critical** for a
//! writer on a motion topic of the profile (`motion_envelopes`), **High**
//! otherwise (readers on motion topics included: a reader cannot command,
//! matching the profile's own reader/writer split). "Never announced" is
//! [`rules::ENDPOINT_UNANNOUNCED_PARTICIPANT`], **Medium** (**High** for a
//! writer on a motion topic). An *ambiguous* announcement (the datagram
//! carried conflicting duplicate topic / type / GUID parameters, so another
//! DDS stack may act on a topic other than the one parsed) is judged worst
//! case: a writer in it counts as a motion writer whenever the profile has
//! motion topics.
//!
//! SPDP itself is judged too: an SPDP for an already-bound prefix from an IP
//! outside its binding, or a relayed SPDP from a non-discovery-server IP, is
//! [`rules::PARTICIPANT_SOURCE_MISMATCH`] (High for a profiled participant,
//! Medium otherwise) and is **not learned**.
//!
//! # Bootstrapping decision (SEDP before SPDP)
//!
//! DDS stacks send SEDP only after SPDP, so on a running bus SPDP precedes
//! SEDP. SEDP-before-SPDP happens when the sensor (re)starts mid-session:
//! the robot's next SPDP beacon can be up to one announcement period away
//! (Fast DDS ~3 s, Cyclone DDS up to 30 s). We therefore **hold judgement**
//! for `hold` (default 30 s, `binding.hold_ms`), bounded to `max_pending`
//! held announcements. When the SPDP arrives within the window the held
//! announcement is judged like a fresh one (so a spoofed one from the wrong
//! IP still becomes a Critical mismatch). When the window expires, or the
//! held queue overflows (oldest first), it becomes a Medium
//! "endpoint from never-announced participant" finding — an overflow can
//! therefore not be used to make held announcements disappear. A pinned
//! prefix (`participant_ips`) is judged immediately; it is never held.
//!
//! # Learning, refresh, expiry, eviction
//!
//! - First SPDP for a prefix (sent by the prefix itself, i.e. not relayed)
//!   binds its source IP and its unicast locator IPs (metatraffic + default).
//!   Unspecified and multicast addresses are ignored.
//! - Later SPDP from a bound IP or a locator IP refreshes the binding (adds
//!   the source IP, replaces the locators). This is how multi-homed hosts
//!   bind all their interfaces: each interface's IP is in the locators.
//! - A binding expires one lease after its last refresh (the SPDP
//!   `lease_duration`, clamped to 10 s..=600 s, default 100 s — the RTPS
//!   default). An expired prefix may be re-bound by the next SPDP from any IP
//!   (it mirrors DDS: a participant whose lease expired is gone). While the
//!   real participant is alive and beaconing, nobody else can take its
//!   prefix over.
//! - A self-dispose (SPDP `PID_STATUS_INFO`) from a bound IP removes the
//!   binding.
//! - The table is bounded (`max_participants`). When full, the least
//!   recently refreshed **unprofiled** prefix is evicted first, so a spray of
//!   fake participants cannot push the profiled ones out; only if every entry
//!   is profiled is the oldest profiled one evicted. Evictions are counted
//!   and O(log n) (an ordered index), so a prefix flood costs no O(n) scans.
//! - SPDP relayed by a configured discovery server teaches the locators only
//!   (the server's own IP is never bound to the relayed prefix).
//!
//! # Limits (be honest)
//!
//! - **UDP source addresses are not authenticated.** An attacker on the same
//!   L2 segment can forge the victim's source IP; this check then passes.
//!   It raises the bar (an attacker must forge the IP *and* the prefix, and
//!   cannot receive replies), it does not replace DDS-Security.
//! - Every participant on one host shares that host's IPs, so a process on
//!   the robot's own computer can speak for any participant there. That is
//!   host compromise, which Pulsar's process monitoring covers, not this.
//! - **DHCP / multi-homed / NAT / containers**: an IP change of a live
//!   participant (new DHCP lease before the binding expires, a container
//!   behind NAT, a VPN) shows up as a mismatch. Robots with such networks
//!   must be commissioned: either static addressing, or `participant_ips`
//!   pins listing every address the participant can use, or a
//!   `discovery_server` list. This is a **commissioning item**.
//! - The first SPDP wins: an attacker who announces a profiled prefix before
//!   the real participant ever did binds it; the real participant's SPDP is
//!   then the one reported (`participant_source_mismatch`), which still
//!   surfaces the conflict. Pin the profiled prefixes to close this.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use robodr_events::graph::{ActionRole, RosNameKind};
use robodr_events::profile::Profile;
use robodr_events::{Deviation, Severity};
use robodr_rtps::{
    hex12, EndpointInfo, EndpointKind, GuidPrefix, Locator, ParticipantRemoval, SpdpInfo,
    LOCATOR_KIND_UDPV4, LOCATOR_KIND_UDPV6,
};

use crate::sanitize::MAX_TEXT_CHARS;

/// Rule ids raised by the binding check.
pub mod rules {
    /// An SEDP endpoint announcement for a participant arrived from an IP
    /// not bound to it, or relayed / GUID-conflicting from an untrusted IP.
    pub const ENDPOINT_SOURCE_MISMATCH: &str = "robot.ros2.endpoint_source_mismatch";
    /// An SEDP endpoint for a participant that never announced itself (no
    /// SPDP within the hold window, or the held queue overflowed).
    pub const ENDPOINT_UNANNOUNCED_PARTICIPANT: &str =
        "robot.ros2.endpoint_unannounced_participant";
    /// An SPDP announcement for a bound participant from an IP outside its
    /// binding, or relayed by an untrusted IP. Not learned.
    pub const PARTICIPANT_SOURCE_MISMATCH: &str = "robot.ros2.participant_source_mismatch";
}

/// Default hold window for SEDP seen before its participant's SPDP.
pub const DEFAULT_HOLD: Duration = Duration::from_secs(30);
/// Largest configurable hold window.
pub const MAX_HOLD: Duration = Duration::from_secs(600);
/// Default binding table size.
pub const DEFAULT_MAX_PARTICIPANTS: usize = 1024;
/// Largest configurable binding table size.
pub const MAX_MAX_PARTICIPANTS: usize = 65_536;
/// Default (and max) number of held SEDP announcements.
pub const DEFAULT_MAX_PENDING: usize = 1024;
/// Source IPs remembered per participant (oldest dropped).
pub const MAX_BOUND_IPS: usize = 8;
/// Locator IPs remembered per participant.
pub const MAX_LOCATOR_IPS: usize = 32;
/// Pinned IPs per participant.
pub const MAX_PINNED_IPS: usize = 16;
/// Pinned participants.
pub const MAX_PINNED_PARTICIPANTS: usize = 4096;
/// Discovery-server IPs.
pub const MAX_DISCOVERY_SERVERS: usize = 32;
/// Lease used when SPDP carries none (RTPS default `leaseDuration`).
pub const DEFAULT_LEASE: Duration = Duration::from_secs(100);
/// Lease clamp.
pub const MIN_LEASE: Duration = Duration::from_secs(10);
pub const MAX_LEASE: Duration = Duration::from_secs(600);

/// Knobs of the binding check. Part of
/// [`PipelineOptions`](crate::PipelineOptions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingOptions {
    /// Run the binding check at all.
    pub enabled: bool,
    /// IPs of trusted discovery servers / relays: relayed and GUID-conflicting
    /// announcements from them are accepted.
    pub discovery_servers: Vec<IpAddr>,
    /// Pinned participant → allowed source IPs (authoritative, never
    /// learned over, never evicted).
    pub participant_ips: BTreeMap<GuidPrefix, Vec<IpAddr>>,
    /// How long an SEDP announcement from a not-yet-announced participant is
    /// held before it is reported as "never announced". Zero = report at once.
    pub hold: Duration,
    /// Max learned participants (clamped to 1..=[`MAX_MAX_PARTICIPANTS`]).
    pub max_participants: usize,
    /// Max held SEDP announcements (clamped to 1..=[`DEFAULT_MAX_PENDING`]).
    pub max_pending: usize,
}

impl Default for BindingOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            discovery_servers: Vec::new(),
            participant_ips: BTreeMap::new(),
            hold: DEFAULT_HOLD,
            max_participants: DEFAULT_MAX_PARTICIPANTS,
            max_pending: DEFAULT_MAX_PENDING,
        }
    }
}

/// Counters of the binding table.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct BindingStats {
    /// New bindings from SPDP.
    pub learned: u64,
    /// SPDP from a bound IP / locator.
    pub refreshed: u64,
    /// Expired bindings taken over by a new SPDP.
    pub rebound: u64,
    /// Entries evicted to stay within `max_participants`.
    pub evicted: u64,
    /// Bindings removed by a self-dispose.
    pub removed: u64,
    /// SPDP rejected (mismatching or untrusted relay).
    pub spdp_mismatches: u64,
    /// Endpoint announcements judged a mismatch.
    pub endpoint_mismatches: u64,
    /// Endpoint announcements held for a missing SPDP.
    pub held: u64,
    /// Held announcements resolved by a later SPDP.
    pub held_resolved: u64,
    /// Held announcements reported as never announced (expiry or flush).
    pub held_expired: u64,
    /// Held announcements pushed out by a full queue (also reported).
    pub held_overflow: u64,
    /// Datagrams whose source IP did not parse (binding not judged).
    pub unparsed_src_ip: u64,
}

/// IPv4-mapped IPv6 → IPv4, so `::ffff:10.0.0.5` and `10.0.0.5` match.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// Parse a datagram source IP (as the sources report it).
pub fn parse_src_ip(s: &str) -> Option<IpAddr> {
    s.trim().parse::<IpAddr>().ok().map(canonical_ip)
}

/// The IP of a UDPv4/UDPv6 locator, if it is a usable unicast address.
pub fn locator_ip(l: &Locator) -> Option<IpAddr> {
    let ip = match l.kind {
        LOCATOR_KIND_UDPV4 => {
            let a = &l.address;
            IpAddr::from([a[12], a[13], a[14], a[15]])
        }
        LOCATOR_KIND_UDPV6 => IpAddr::from(l.address),
        _ => return None,
    };
    let ip = canonical_ip(ip);
    (!ip.is_unspecified() && !ip.is_multicast() && ip != IpAddr::from([255, 255, 255, 255]))
        .then_some(ip)
}

/// Parse a 24-hex-digit GUID prefix (case-insensitive).
pub fn parse_prefix(s: &str) -> Option<GuidPrefix> {
    let s = s.trim();
    if s.len() != 24 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 12];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// Is `topic` (an RTPS topic name) a motion topic of the profile?
pub fn is_motion_topic(profile: &Profile, topic: &str) -> bool {
    let ep = robodr_events::graph::Endpoint {
        guid_prefix: String::new(),
        topic: topic.to_string(),
        type_name: String::new(),
    };
    let rn = ep.ros_name();
    matches!(
        rn.kind,
        RosNameKind::Topic
            | RosNameKind::ActionPart {
                role: ActionRole::Topic,
                ..
            }
    ) && profile.motion_envelopes.contains_key(&rn.name)
}

/// A finding produced by the binding check: the deviation and the source IP
/// it is attributed to.
pub type BindingFinding = (Deviation, String);

#[derive(Debug, Clone)]
struct Entry {
    bound_ips: VecDeque<IpAddr>,
    locator_ips: Vec<IpAddr>,
    last_refresh: Instant,
    lease: Duration,
}

impl Entry {
    fn allows(&self, ip: IpAddr) -> bool {
        self.bound_ips.contains(&ip) || self.locator_ips.contains(&ip)
    }

    fn expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_refresh) > self.lease
    }

    fn add_bound(&mut self, ip: IpAddr) {
        if !self.bound_ips.contains(&ip) {
            if self.bound_ips.len() >= MAX_BOUND_IPS {
                self.bound_ips.pop_front();
            }
            self.bound_ips.push_back(ip);
        }
    }
}

/// An SEDP announcement waiting for its participant's SPDP. Only what is
/// needed to judge and report it is kept (the topic is truncated), so the
/// queue's memory is bounded by `max_pending * ~MAX_TEXT_CHARS`.
#[derive(Debug, Clone)]
struct Held {
    participant: GuidPrefix,
    kind: EndpointKind,
    topic: String,
    src_ip: IpAddr,
    deadline: Instant,
    /// The datagram carried conflicting duplicate identity parameters.
    ambiguous: bool,
}

/// Why an endpoint announcement does not match its participant's binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mismatch {
    NotBound,
    NotPinned,
    Relayed,
    GuidConflict,
}

impl Mismatch {
    fn text(self) -> &'static str {
        match self {
            Self::NotBound => "which is not bound to it (not its SPDP source nor an advertised locator)",
            Self::NotPinned => "which is not one of its pinned participant_ips",
            Self::Relayed => {
                "relayed for it by another participant (INFO_SRC / foreign RTPS header) from an IP that is not a configured discovery server"
            }
            Self::GuidConflict => {
                "with PID_PARTICIPANT_GUID disagreeing with the endpoint GUID, from an IP that is not a configured discovery server"
            }
        }
    }
}

enum Verdict {
    Ok,
    Mismatch(Mismatch),
    Unbound,
}

/// The binding table plus the held-announcement queue. Pure: time is passed
/// in. See the module docs.
#[derive(Debug)]
pub struct BindingTable {
    opts: BindingOptions,
    entries: HashMap<GuidPrefix, Entry>,
    /// Eviction order: `(profiled, last_refresh, prefix)`, so the first
    /// element is the least recently refreshed unprofiled entry (O(log n)
    /// eviction even under a flood of fresh prefixes).
    order: BTreeSet<(bool, Instant, GuidPrefix)>,
    profiled: BTreeSet<GuidPrefix>,
    held: VecDeque<Held>,
    /// Held announcements per participant, so the per-SPDP / per-SEDP
    /// "anything held for it?" checks are O(1) instead of a queue scan.
    held_count: HashMap<GuidPrefix, usize>,
    stats: BindingStats,
}

fn kind_str(k: EndpointKind) -> &'static str {
    match k {
        EndpointKind::Writer => "writer",
        EndpointKind::Reader => "reader",
    }
}

/// A writer that could command motion: on a motion topic of the profile,
/// or in an ambiguous announcement (conflicting duplicate topic / GUID
/// parameters: another DDS stack may read a different topic than the one we
/// parsed) while the profile has motion topics at all. Worst case is assumed.
fn motion_capable_writer(
    profile: &Profile,
    kind: EndpointKind,
    topic: &str,
    ambiguous: bool,
) -> bool {
    kind == EndpointKind::Writer
        && (is_motion_topic(profile, topic) || (ambiguous && !profile.motion_envelopes.is_empty()))
}

fn truncate(s: &str) -> String {
    s.chars().take(MAX_TEXT_CHARS).collect()
}

impl BindingTable {
    /// `profiled`: the profile's participant prefixes (protected from
    /// eviction, and their SPDP mismatches are High).
    pub fn new(opts: BindingOptions, profile: &Profile) -> Self {
        let mut opts = opts;
        opts.max_participants = opts.max_participants.clamp(1, MAX_MAX_PARTICIPANTS);
        opts.max_pending = opts.max_pending.clamp(1, DEFAULT_MAX_PENDING);
        opts.hold = opts.hold.min(MAX_HOLD);
        for ips in opts.participant_ips.values_mut() {
            for ip in ips.iter_mut() {
                *ip = canonical_ip(*ip);
            }
        }
        for ip in opts.discovery_servers.iter_mut() {
            *ip = canonical_ip(*ip);
        }
        Self {
            profiled: profile
                .participants
                .iter()
                .filter_map(|p| parse_prefix(p))
                .collect(),
            opts,
            entries: HashMap::new(),
            order: BTreeSet::new(),
            held: VecDeque::new(),
            held_count: HashMap::new(),
            stats: BindingStats::default(),
        }
    }

    pub fn options(&self) -> &BindingOptions {
        &self.opts
    }

    pub fn stats(&self) -> &BindingStats {
        &self.stats
    }

    /// Learned (not pinned) participants.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Held SEDP announcements.
    pub fn held_len(&self) -> usize {
        self.held.len()
    }

    /// Is `prefix` currently bound (learned or pinned)?
    pub fn is_bound(&self, prefix: &GuidPrefix) -> bool {
        self.entries.contains_key(prefix) || self.opts.participant_ips.contains_key(prefix)
    }

    /// Would `ip` be accepted as a source for `prefix`? `None` = no binding.
    pub fn allows(&self, prefix: &GuidPrefix, ip: IpAddr) -> Option<bool> {
        let ip = canonical_ip(ip);
        if let Some(pins) = self.opts.participant_ips.get(prefix) {
            return Some(pins.contains(&ip));
        }
        self.entries.get(prefix).map(|e| e.allows(ip))
    }

    fn trusted_relay(&self, ip: IpAddr) -> bool {
        self.opts.discovery_servers.contains(&ip)
    }

    fn judge(
        &self,
        participant: &GuidPrefix,
        ip: IpAddr,
        relayed: bool,
        conflict: bool,
    ) -> Verdict {
        if relayed || conflict {
            if self.trusted_relay(ip) {
                return Verdict::Ok;
            }
            return Verdict::Mismatch(if relayed {
                Mismatch::Relayed
            } else {
                Mismatch::GuidConflict
            });
        }
        if let Some(pins) = self.opts.participant_ips.get(participant) {
            return if pins.contains(&ip) {
                Verdict::Ok
            } else {
                Verdict::Mismatch(Mismatch::NotPinned)
            };
        }
        match self.entries.get(participant) {
            Some(e) if e.allows(ip) => Verdict::Ok,
            Some(_) => Verdict::Mismatch(Mismatch::NotBound),
            None => Verdict::Unbound,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn mismatch_finding(
        &mut self,
        profile: &Profile,
        participant: &GuidPrefix,
        kind: EndpointKind,
        topic: &str,
        ip: IpAddr,
        why: Mismatch,
        ambiguous: bool,
    ) -> BindingFinding {
        self.stats.endpoint_mismatches += 1;
        let severity = if motion_capable_writer(profile, kind, topic, ambiguous) {
            Severity::Critical
        } else {
            Severity::High
        };
        let topic = truncate(topic);
        let amb = if ambiguous {
            " (ambiguous announcement: conflicting duplicate parameters, the topic may differ)"
        } else {
            ""
        };
        let profiled = if self.profiled.contains(participant) {
            "profiled "
        } else {
            ""
        };
        let detail = format!(
            "{} on {topic} attributed to {profiled}participant {} was announced from {ip}, {}{amb}",
            kind_str(kind),
            hex12(participant),
            why.text()
        );
        (
            Deviation::new(rules::ENDPOINT_SOURCE_MISMATCH, severity, detail),
            ip.to_string(),
        )
    }

    /// Medium; High for a writer that could command motion (see
    /// [`motion_capable_writer`]) — the profile has already accepted it if
    /// it is attributed to a profiled participant.
    fn unannounced_finding(&mut self, profile: &Profile, h: &Held, why: &str) -> BindingFinding {
        let severity = if motion_capable_writer(profile, h.kind, &h.topic, h.ambiguous) {
            Severity::High
        } else {
            Severity::Medium
        };
        let profiled = if self.profiled.contains(&h.participant) {
            "profiled "
        } else {
            ""
        };
        let detail = format!(
            "{} on {} attributed to {profiled}participant {} was announced from {} but that \
             participant never announced itself (no SPDP {why})",
            kind_str(h.kind),
            h.topic,
            hex12(&h.participant),
            h.src_ip
        );
        (
            Deviation::new(rules::ENDPOINT_UNANNOUNCED_PARTICIPANT, severity, detail),
            h.src_ip.to_string(),
        )
    }

    /// Learn from (or judge) one SPDP announcement.
    pub fn observe_spdp(
        &mut self,
        profile: &Profile,
        spdp: &SpdpInfo,
        src_ip: Option<IpAddr>,
        now: Instant,
        out: &mut Vec<BindingFinding>,
    ) {
        if !self.opts.enabled {
            return;
        }
        let Some(ip) = src_ip.map(canonical_ip) else {
            self.stats.unparsed_src_ip += 1;
            return;
        };
        let p = spdp.guid_prefix;
        let locators: Vec<IpAddr> = {
            let mut v: Vec<IpAddr> = Vec::new();
            for l in spdp.metatraffic_unicast.iter().chain(&spdp.default_unicast) {
                if let Some(ip) = locator_ip(l) {
                    if !v.contains(&ip) && v.len() < MAX_LOCATOR_IPS {
                        v.push(ip);
                    }
                }
            }
            v
        };
        let lease = spdp
            .lease_duration
            .and_then(|d| d.to_std())
            .unwrap_or(DEFAULT_LEASE)
            .clamp(MIN_LEASE, MAX_LEASE);

        let reject = |this: &mut Self, why: &str, out: &mut Vec<BindingFinding>| {
            this.stats.spdp_mismatches += 1;
            let profiled = this.profiled.contains(&p);
            let severity = if profiled {
                Severity::High
            } else {
                Severity::Medium
            };
            let detail = format!(
                "SPDP announcement for {}participant {} from {ip} {why}; not learned",
                if profiled { "profiled " } else { "" },
                hex12(&p)
            );
            out.push((
                Deviation::new(rules::PARTICIPANT_SOURCE_MISMATCH, severity, detail),
                ip.to_string(),
            ));
        };

        if spdp.relayed() {
            if !self.trusted_relay(ip) {
                reject(
                    self,
                    "was relayed by another participant from an IP that is not a configured discovery server",
                    out,
                );
                return;
            }
            // Trusted relay: learn the locators only, never the server's IP.
            if self.opts.participant_ips.contains_key(&p) {
                return;
            }
            match self.entries.get_mut(&p) {
                Some(e) => {
                    let old = e.last_refresh;
                    e.locator_ips = locators;
                    e.last_refresh = now;
                    e.lease = lease;
                    self.stats.refreshed += 1;
                    self.reindex(p, Some(old), Some(now));
                }
                None => {
                    self.insert(
                        p,
                        Entry {
                            bound_ips: VecDeque::new(),
                            locator_ips: locators,
                            last_refresh: now,
                            lease,
                        },
                    );
                    self.stats.learned += 1;
                }
            }
            self.resolve_held(profile, &p, out);
            return;
        }

        if let Some(pins) = self.opts.participant_ips.get(&p) {
            if !pins.contains(&ip) {
                reject(self, "which is not one of its pinned participant_ips", out);
                return;
            }
            self.resolve_held(profile, &p, out);
            return;
        }

        match self.entries.get_mut(&p) {
            Some(e) if e.allows(ip) => {
                let old = e.last_refresh;
                e.add_bound(ip);
                e.locator_ips = locators;
                e.last_refresh = now;
                e.lease = lease;
                self.stats.refreshed += 1;
                self.reindex(p, Some(old), Some(now));
            }
            Some(e) if !e.expired(now) => {
                reject(
                    self,
                    "which is outside its current binding (another host claims its GUID prefix)",
                    out,
                );
                return;
            }
            Some(e) => {
                // Lease expired: the old participant is gone, re-bind.
                let old = e.last_refresh;
                e.bound_ips.clear();
                e.add_bound(ip);
                e.locator_ips = locators;
                e.last_refresh = now;
                e.lease = lease;
                self.stats.rebound += 1;
                self.reindex(p, Some(old), Some(now));
            }
            None => {
                let mut e = Entry {
                    bound_ips: VecDeque::new(),
                    locator_ips: locators,
                    last_refresh: now,
                    lease,
                };
                e.add_bound(ip);
                self.insert(p, e);
                self.stats.learned += 1;
            }
        }
        self.resolve_held(profile, &p, out);
    }

    /// Keep the eviction index in step with an entry's `last_refresh`.
    fn reindex(&mut self, p: GuidPrefix, old: Option<Instant>, new: Option<Instant>) {
        let profiled = self.profiled.contains(&p);
        if let Some(old) = old {
            self.order.remove(&(profiled, old, p));
        }
        if let Some(new) = new {
            self.order.insert((profiled, new, p));
        }
    }

    /// Remove a learned entry (and its index key).
    fn remove_entry(&mut self, p: &GuidPrefix) -> bool {
        match self.entries.remove(p) {
            Some(e) => {
                self.reindex(*p, Some(e.last_refresh), None);
                true
            }
            None => false,
        }
    }

    fn insert(&mut self, p: GuidPrefix, e: Entry) {
        let last = e.last_refresh;
        if let Some(old) = self.entries.get(&p).map(|o| o.last_refresh) {
            self.reindex(p, Some(old), None);
        }
        while self.entries.len() >= self.opts.max_participants && !self.entries.contains_key(&p) {
            // Oldest unprofiled first (`false` sorts first); only then the
            // oldest profiled one. O(log n).
            let Some((_, _, victim)) = self.order.pop_first() else {
                break;
            };
            if self.entries.remove(&victim).is_some() {
                self.stats.evicted += 1;
            }
        }
        self.entries.insert(p, e);
        self.reindex(p, None, Some(last));
    }

    /// An SPDP dispose / unregister. Returns `Some(true)` if it came from an
    /// IP bound to the participant (binding removed), `Some(false)` if from
    /// an IP outside the binding (binding kept), `None` if not bound / not
    /// judged.
    pub fn observe_participant_removal(
        &mut self,
        r: &ParticipantRemoval,
        src_ip: Option<IpAddr>,
    ) -> Option<bool> {
        if !self.opts.enabled {
            return None;
        }
        let ip = canonical_ip(src_ip?);
        let p = r.guid_prefix;
        if r.source != p && self.trusted_relay(ip) {
            if self.remove_entry(&p) {
                self.stats.removed += 1;
            }
            return Some(true);
        }
        let allowed = self.allows(&p, ip)?;
        if allowed && self.remove_entry(&p) {
            self.stats.removed += 1;
        }
        Some(allowed)
    }

    /// Judge one SEDP endpoint announcement. Unbound participants are held.
    /// `ambiguous`: the datagram carried conflicting duplicate identity
    /// parameters (topic / type / GUID), so the parsed topic may not be the
    /// one a DDS stack acts on; a writer is then judged as if it were on a
    /// motion topic (worst case).
    pub fn observe_endpoint(
        &mut self,
        profile: &Profile,
        ep: &EndpointInfo,
        src_ip: Option<IpAddr>,
        ambiguous: bool,
        now: Instant,
        out: &mut Vec<BindingFinding>,
    ) {
        if !self.opts.enabled {
            return;
        }
        let Some(ip) = src_ip.map(canonical_ip) else {
            self.stats.unparsed_src_ip += 1;
            return;
        };
        match self.judge(&ep.participant, ip, ep.relayed(), ep.guid_conflict) {
            Verdict::Ok => {}
            Verdict::Mismatch(why) => {
                let f = self.mismatch_finding(
                    profile,
                    &ep.participant,
                    ep.kind,
                    &ep.topic,
                    ip,
                    why,
                    ambiguous,
                );
                out.push(f);
            }
            Verdict::Unbound => {
                let held = Held {
                    participant: ep.participant,
                    kind: ep.kind,
                    topic: truncate(&ep.topic),
                    src_ip: ip,
                    // `hold` is clamped to MAX_HOLD; never panic on overflow.
                    deadline: now.checked_add(self.opts.hold).unwrap_or(now),
                    ambiguous,
                };
                if self.opts.hold.is_zero() {
                    self.stats.held_expired += 1;
                    let f = self.unannounced_finding(profile, &held, "was seen before it");
                    out.push(f);
                    return;
                }
                // Only scan the queue when something is held for this
                // participant (O(1) check), so a flood of fresh prefixes
                // costs no queue scans.
                let repeat = if self.held_count.contains_key(&held.participant) {
                    self.held.iter_mut().find(|h| {
                        h.participant == held.participant
                            && h.kind == held.kind
                            && h.src_ip == held.src_ip
                            && h.topic == held.topic
                    })
                } else {
                    None
                };
                if let Some(h) = repeat {
                    // A repeat keeps its first deadline; ambiguity is sticky.
                    h.ambiguous |= held.ambiguous;
                    return;
                }
                if self.held.len() >= self.opts.max_pending {
                    if let Some(old) = self.pop_held() {
                        self.stats.held_overflow += 1;
                        let f = self.unannounced_finding(
                            profile,
                            &old,
                            "was seen before the held-announcement queue overflowed",
                        );
                        out.push(f);
                    }
                }
                self.stats.held += 1;
                *self.held_count.entry(held.participant).or_insert(0) += 1;
                self.held.push_back(held);
            }
        }
    }

    fn pop_held(&mut self) -> Option<Held> {
        let h = self.held.pop_front()?;
        if let Some(n) = self.held_count.get_mut(&h.participant) {
            *n -= 1;
            if *n == 0 {
                self.held_count.remove(&h.participant);
            }
        }
        Some(h)
    }

    /// Re-judge held announcements of `p` now that it has a binding.
    fn resolve_held(&mut self, profile: &Profile, p: &GuidPrefix, out: &mut Vec<BindingFinding>) {
        if self.held_count.remove(p).is_none() {
            return;
        }
        let (mine, rest): (VecDeque<Held>, VecDeque<Held>) =
            self.held.drain(..).partition(|h| h.participant == *p);
        self.held = rest;
        for h in mine {
            self.stats.held_resolved += 1;
            // Held announcements were neither relayed nor conflicting (those
            // are judged at once), so only the binding matters.
            if let Verdict::Mismatch(why) = self.judge(&h.participant, h.src_ip, false, false) {
                let f = self.mismatch_finding(
                    profile,
                    &h.participant,
                    h.kind,
                    &h.topic,
                    h.src_ip,
                    why,
                    h.ambiguous,
                );
                out.push(f);
            }
        }
    }

    /// Report held announcements whose hold window has passed.
    /// Deadlines are monotonic for a monotonic clock (constant hold), so the
    /// queue is ordered; with a clock that went backwards some entries
    /// expire late, never early, and nothing panics.
    pub fn expire(&mut self, profile: &Profile, now: Instant, out: &mut Vec<BindingFinding>) {
        while self.held.front().is_some_and(|h| h.deadline <= now) {
            if let Some(h) = self.pop_held() {
                self.stats.held_expired += 1;
                let f = self.unannounced_finding(profile, &h, "within the hold window");
                out.push(f);
            }
        }
    }

    /// Report every held announcement now (end of a capture replay).
    pub fn flush(&mut self, profile: &Profile, out: &mut Vec<BindingFinding>) {
        while let Some(h) = self.pop_held() {
            self.stats.held_expired += 1;
            let f = self.unannounced_finding(profile, &h, "before the end of the input");
            out.push(f);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn prefix_parsing() {
        assert_eq!(parse_prefix("0102030405060708090A0b0c").unwrap()[11], 0x0c);
        for bad in [
            "",
            "01",
            "zz02030405060708090a0b0c",
            "0102030405060708090a0b0c0d",
            "é102030405060708090a0b0",
        ] {
            assert!(parse_prefix(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn ip_canonicalisation_and_locators() {
        let mapped: IpAddr = Ipv4Addr::new(10, 0, 0, 5).to_ipv6_mapped().into();
        assert_eq!(canonical_ip(mapped), IpAddr::from([10, 0, 0, 5]));
        assert_eq!(
            parse_src_ip("::ffff:10.0.0.5"),
            Some(IpAddr::from([10, 0, 0, 5]))
        );
        assert_eq!(parse_src_ip("garbage"), None);
        let mut a = [0u8; 16];
        a[12..].copy_from_slice(&[10, 0, 0, 7]);
        let l = |kind, address| Locator {
            kind,
            port: 7410,
            address,
        };
        assert_eq!(
            locator_ip(&l(LOCATOR_KIND_UDPV4, a)),
            Some(IpAddr::from([10, 0, 0, 7]))
        );
        assert_eq!(locator_ip(&l(LOCATOR_KIND_UDPV4, [0; 16])), None);
        let mut m = [0u8; 16];
        m[12..].copy_from_slice(&[239, 255, 0, 1]);
        assert_eq!(locator_ip(&l(LOCATOR_KIND_UDPV4, m)), None);
        assert_eq!(
            locator_ip(&l(LOCATOR_KIND_UDPV6, Ipv6Addr::LOCALHOST.octets())),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert_eq!(locator_ip(&l(16, a)), None); // shared memory etc.
    }
}
