//! Which writer writes which enforced channel: learned from the SEDP / SPDP
//! traffic that crosses the bridge (queued and always accepted), parsed by
//! `robodr-rtps` (with its DATA_FRAG reassembler for large announcements).
//!
//! - A **writer** announcement whose topic, in **any** reading
//!   (`EndpointInfo::topics`, including the alternates a duplicated
//!   `PID_TOPIC_NAME` produces), is an enforced channel's topic maps the
//!   writer GUID to that channel: where DDS stacks would disagree on which
//!   topic a writer writes, the gateway enforces. Other writers are
//!   remembered as "not enforced" so their samples are not probed.
//! - **Enforced is never downgraded** (gateway review, findings 1 and 2):
//!   a writer once classified as enforced is kept in its own table and
//!   never removed. A dispose / unregister, a participant removal or an
//!   announcement of the same GUID on another topic leaves it enforced
//!   (`enforced_kept`). The table is bounded (`rtps.max_enforced_writers`).
//!   When it is full, a new enforced writer takes the place of the writer
//!   seen longest ago (by a sample or an announcement), if that one has
//!   been idle for at least `rtps.enforced_idle_evict_s` (`enforced_evicted`;
//!   DDS writer GUIDs change with every controller restart, so stale ones
//!   pile up). Otherwise the new writer is refused (`enforced_refused`, a
//!   gateway finding) and stays unknown, so its samples are probed. A full
//!   table stays full, so an evicted writer's next samples are probed too
//!   (also with `unknown_writers: pass`), never passed unchecked.
//!   Other writers live in a least-recently-used table (`rtps.max_writers`):
//!   evicting one only makes it unknown again.
//! - **INFO_DST is obeyed**: a robot drops a submessage addressed (INFO_DST)
//!   to another participant, so an announcement or removal addressed to
//!   anyone but the robot's participants (learned from the robot's own
//!   observed SPDP / SEDP, [`Discovery::observe_robot`]) or
//!   `GUIDPREFIX_UNKNOWN` is ignored (`misaddressed`). Until the robot's
//!   participants are known such a destination cannot be checked: the
//!   announcement is learned but marked `unverified`, and a removal is
//!   ignored.
//! - **Only the owner speaks for a writer**: a not-enforced announcement or
//!   a removal whose sender (RTPS header / INFO_SRC prefix) is not the
//!   writer's own participant is ignored (`relayed_ignored`). An
//!   announcement on an enforced topic is learned from anyone (the safe
//!   direction).
//! - SPDP announcements feed `robodr-ros2-pipeline`'s
//!   [`IdentityResolver`] (participant identity from source IP, vendor and
//!   enclave), for `identity:<name>` sources. Only an SPDP sent by the
//!   participant itself (header prefix == announced prefix) is used.
//! - **Ports the queue does not see** (the "non-standard DDS ports"
//!   risk): every SPDP participant's locators (metatraffic and default,
//!   unicast and multicast) and every SEDP endpoint (writer or reader) of an enforced
//!   topic with its own locators (unicast and multicast) are compared with
//!   the queued UDP port ranges (`rtps.domain_ids` and
//!   `rtps.extra_port_ranges`). A UDPv4 locator outside all of them means a
//!   DDS stack that will send (or receive) RTPS the gateway never sees:
//!   counted (`unqueued_locators`), and the gateway's status flag
//!   `port_bypass_risk` is set with the first such locator
//!   ([`Discovery::port_bypass`]). It is the deployment check for that risk:
//!   it can only see the discovery that crosses the queue.
//! - **The robot's side** ([`Discovery::observe_robot`], review finding
//!   F7): the robot's own SPDP / SEDP is bridged unqueued, but the gateway
//!   observes a copy (NFLOG, never dropped: `crate::observe`). The same
//!   check runs on it: every robot participant's locators (where
//!   controller-side peers send unicast discovery and user data) and every
//!   robot reader / writer of an enforced topic with its own locators. A
//!   robot reader of `rt/lowcmd` at a port outside the queued ranges is
//!   exactly where a controller-side stack would send motion samples the
//!   queue never sees. Robot-side announcements never change the writer
//!   map (robot writers are not controller-side motion sources); they only
//!   name the robot's participants (INFO_DST check).
//! - The map can be persisted ([`Discovery::save`] / [`Discovery::load`])
//!   so a restarted gateway, which will not see the robot's earlier SEDP
//!   again, keeps classifying the existing writers (the enforced table
//!   included). A persisted entry is only a classification hint: source
//!   authorisation is still decided per sample. The file is read without
//!   following a symlink and only if it is a regular file owned by root or
//!   the directory's owner and not group / world writable; it is written
//!   through a fresh `O_EXCL` 0600 temporary file and renamed.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::time::Instant;

use robodr_ros2_pipeline::{IdentityResolver, Resolution};
use robodr_rtps::{EndpointKind, FragmentReassembler, ReassemblyLimits, GUIDPREFIX_UNKNOWN};
use serde::{Deserialize, Serialize};

use crate::rtps::{Guid, GuidPrefix};

/// What is known about one writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WriterInfo {
    /// Index of the enforced channel it writes, if any.
    pub channel: Option<usize>,
    /// Learned from a content probe rather than SEDP.
    pub probed: bool,
    /// Not enforced, but announced with the DDS type of an enforced
    /// channel ([`Discovery::with_channel_types`]).
    pub same_type: bool,
    /// Not enforced, and announced under an INFO_DST the gateway could not
    /// check (the robot's participants were not known yet).
    pub unverified: bool,
}

/// Most robot participant prefixes remembered (INFO_DST check).
pub const MAX_ROBOT_PREFIXES: usize = 64;

/// Discovery state.
pub struct Discovery {
    /// Writers classified as enforced (SEDP or the state file): writer ->
    /// (channel, last seen). Never removed or downgraded; evicted only for
    /// a new enforced writer when full and idle long enough (module docs).
    enforced: HashMap<Guid, (usize, Instant)>,
    max_enforced: usize,
    /// How long an enforced writer must have been idle before a new one
    /// may take its place in a full table (`None`: never).
    enforced_idle_evict: Option<std::time::Duration>,
    /// The clock enforced writers' last-seen times are kept on (the last
    /// [`Discovery::learn`] or [`Discovery::set_now`]).
    now: Instant,
    /// Every other writer (SEDP on another topic, probe results), with its
    /// last use; `lru` orders them (least recently used first).
    others: HashMap<Guid, (WriterInfo, u64)>,
    lru: BTreeMap<u64, Guid>,
    clock: u64,
    max_writers: usize,
    /// Enforced topics, index = channel index (None for non-RTPS channels).
    topics: Vec<Option<String>>,
    /// DDS type names of the enforced channels (`same_type`).
    types: Vec<&'static str>,
    /// The robot's participant prefixes (most recent last).
    robot_prefixes: VecDeque<GuidPrefix>,
    reasm: FragmentReassembler,
    identities: IdentityResolver,
    /// Bumped whenever identities change, so cached source resolutions are
    /// recomputed.
    pub epoch: u64,
    /// The writer map changed since the last [`Discovery::save`].
    pub dirty: bool,
    pub stats: DiscoveryStats,
    /// Writers announced or removed by the last [`Discovery::learn`]
    /// (restart evidence, see [`Discovery::take_announced`]).
    announced: Vec<Announced>,
    /// The queued UDP port ranges (locator check).
    queued: Vec<(u16, u16)>,
    /// The first locator seen outside every queued range (module docs).
    port_bypass: Option<String>,
    /// Robot-side discovery (observed, own reassembler).
    robot_reasm: FragmentReassembler,
}

/// A writer (or, for a participant removal, every writer of a participant)
/// that an SEDP / SPDP datagram announced or removed: the evidence a writer
/// restart leaves (a restarted writer re-announces itself before its
/// sequence numbers start again at 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Announced {
    pub guid: Guid,
    /// Only the participant prefix (`guid[..12]`) is meaningful: the
    /// participant was removed.
    pub whole_participant: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct DiscoveryStats {
    pub datagrams: u64,
    pub writers_learned: u64,
    pub writers_enforced: u64,
    pub writers_removed: u64,
    pub writers_evicted: u64,
    pub participants_removed: u64,
    pub identities_resolved: u64,
    /// UDPv4 locators announced outside every queued port range (module
    /// docs), controller side and robot side.
    pub unqueued_locators: u64,
    /// Robot-side discovery datagrams observed.
    pub robot_datagrams: u64,
    /// Robot-side locators outside every queued range (also counted in
    /// `unqueued_locators`).
    pub robot_unqueued_locators: u64,
    /// Announcements / removals ignored because their INFO_DST addressed
    /// another participant than the robot's (or, for a removal, one that
    /// could not be checked yet).
    pub misaddressed: u64,
    /// Not-enforced announcements and removals ignored because another
    /// participant than the writer's own sent them.
    pub relayed_ignored: u64,
    /// Removals, or announcements on another topic, of a writer ever
    /// classified as enforced: the classification was kept.
    pub enforced_kept: u64,
    /// New enforced writers refused because the enforced table was full.
    pub enforced_refused: u64,
    /// Enforced writers idle for `rtps.enforced_idle_evict_s` or more that
    /// a new enforced writer replaced in the full table.
    pub enforced_evicted: u64,
}

/// Persisted form.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateFile {
    format: String,
    /// writer GUID (32 hex) -> topic (empty: not enforced).
    writers: Vec<(String, String)>,
    /// v2: not-enforced writers announced with an enforced channel's type.
    #[serde(default)]
    same_type: Vec<String>,
    /// v2: not-enforced writers announced under an unverified INFO_DST.
    #[serde(default)]
    unverified: Vec<String>,
}

const STATE_FORMAT: &str = "robodr-firewall-gw-writers/v2";
/// Still read (it has no `same_type` / `unverified` lists).
const STATE_FORMAT_V1: &str = "robodr-firewall-gw-writers/v1";
/// Largest state file read.
const MAX_STATE_BYTES: u64 = 4 << 20;
/// `O_NOFOLLOW` (Linux; differs between architectures).
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
const O_NOFOLLOW: i32 = 0o100000;
#[cfg(not(any(target_arch = "aarch64", target_arch = "arm")))]
const O_NOFOLLOW: i32 = 0o400000;
/// `O_NONBLOCK` (Linux).
const O_NONBLOCK: i32 = 0o4000;

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn unhex16(s: &str) -> Option<Guid> {
    if s.len() != 32 {
        return None;
    }
    let mut g = [0u8; 16];
    for (i, b) in g.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(g)
}

fn prefix_of(g: &Guid) -> GuidPrefix {
    crate::rtps::guid_prefix(g)
}

/// How an INFO_DST destination relates to the robot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Addressed {
    /// Every receiver, or one of the robot's participants.
    Robot,
    /// Another participant: the robot ignores the submessage.
    Elsewhere,
    /// A specific participant, but the robot's are not known yet.
    Unverified,
}

impl std::fmt::Debug for Discovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Discovery")
            .field("enforced", &self.enforced.len())
            .field("others", &self.others.len())
            .field("epoch", &self.epoch)
            .field("stats", &self.stats)
            .finish()
    }
}

impl Discovery {
    /// `max_writers`: the not-enforced (least recently used) table;
    /// the enforced table holds as many (see
    /// [`Discovery::with_max_enforced`]).
    pub fn new(
        topics: Vec<Option<String>>,
        max_writers: usize,
        identities: IdentityResolver,
    ) -> Self {
        Self {
            enforced: HashMap::new(),
            max_enforced: max_writers.max(1),
            enforced_idle_evict: None,
            now: Instant::now(),
            others: HashMap::new(),
            lru: BTreeMap::new(),
            clock: 0,
            max_writers: max_writers.max(1),
            topics,
            types: Vec::new(),
            robot_prefixes: VecDeque::new(),
            reasm: FragmentReassembler::new(ReassemblyLimits::default()),
            identities,
            epoch: 0,
            dirty: false,
            stats: DiscoveryStats::default(),
            announced: Vec::new(),
            queued: Vec::new(),
            port_bypass: None,
            robot_reasm: FragmentReassembler::new(ReassemblyLimits::default()),
        }
    }

    /// The size of the enforced table.
    pub fn with_max_enforced(mut self, n: usize) -> Self {
        self.max_enforced = n.max(1);
        self
    }

    /// How long an enforced writer must have been idle before a new
    /// enforced writer may replace it in a full table (`None`: never).
    pub fn with_enforced_idle_evict(mut self, idle: Option<std::time::Duration>) -> Self {
        self.enforced_idle_evict = idle;
        self
    }

    /// Advance the clock enforced writers' last-seen times are kept on
    /// (the gateway calls it per datagram; never moves backwards).
    pub fn set_now(&mut self, now: Instant) {
        self.now = self.now.max(now);
    }

    /// The enforced channels' DDS type names (a not-enforced writer
    /// announced with one of them is marked `same_type`).
    pub fn with_channel_types(mut self, types: Vec<&'static str>) -> Self {
        self.types = types;
        self
    }

    /// The queued UDP port ranges the locator check compares with (none:
    /// no check).
    pub fn with_queued_ranges(mut self, ranges: Vec<(u16, u16)>) -> Self {
        self.queued = ranges;
        self
    }

    /// The first announced locator outside every queued port range, if
    /// any (status flag `port_bypass_risk`).
    pub fn port_bypass(&self) -> Option<&str> {
        self.port_bypass.as_deref()
    }

    fn check_locators<'a>(
        &mut self,
        what: &str,
        locators: impl Iterator<Item = &'a robodr_rtps::Locator>,
    ) {
        if self.queued.is_empty() {
            return;
        }
        for l in locators {
            // UDPv4 only (kind 1): what the IPv4-only ruleset could queue.
            if l.kind != robodr_rtps::LOCATOR_KIND_UDPV4 {
                continue;
            }
            let inside = u16::try_from(l.port)
                .is_ok_and(|p| self.queued.iter().any(|(lo, hi)| (*lo..=*hi).contains(&p)));
            if !inside {
                self.stats.unqueued_locators += 1;
                if self.port_bypass.is_none() {
                    let [.., a, b, c, d] = l.address;
                    self.port_bypass = Some(format!(
                        "{what} announces {a}.{b}.{c}.{d}:{}, outside every queued port range",
                        l.port
                    ));
                }
            }
        }
    }

    fn add_robot_prefix(&mut self, p: GuidPrefix) {
        if p == GUIDPREFIX_UNKNOWN || self.robot_prefixes.contains(&p) {
            return;
        }
        self.robot_prefixes.push_back(p);
        while self.robot_prefixes.len() > MAX_ROBOT_PREFIXES {
            self.robot_prefixes.pop_front();
        }
    }

    /// The robot's participants seen so far (INFO_DST check).
    pub fn robot_prefixes(&self) -> impl Iterator<Item = &GuidPrefix> {
        self.robot_prefixes.iter()
    }

    fn addressed(&self, dest: GuidPrefix) -> Addressed {
        if dest == GUIDPREFIX_UNKNOWN || self.robot_prefixes.contains(&dest) {
            Addressed::Robot
        } else if self.robot_prefixes.is_empty() {
            Addressed::Unverified
        } else {
            Addressed::Elsewhere
        }
    }

    /// Robot-side discovery (observed, never queued; module docs, F7):
    /// the locator check on the robot's participants and on its endpoints
    /// of enforced topics, and the robot's participant prefixes. Returns
    /// the report (the observer learns the robot's `rt/lowstate` writers
    /// from it); `None` if not RTPS.
    pub fn observe_robot(&mut self, datagram: &[u8]) -> Option<robodr_rtps::DatagramReport> {
        let report = self.robot_reasm.parse_datagram_detailed(datagram)?;
        if report.participants.is_empty() && report.endpoints.is_empty() {
            return Some(report);
        }
        self.stats.robot_datagrams += 1;
        self.add_robot_prefix(report.header.guid_prefix);
        let before = self.stats.unqueued_locators;
        for p in &report.participants {
            if p.guid_prefix == p.source {
                self.add_robot_prefix(p.guid_prefix);
            }
            let what = format!("robot participant {}", hex(&p.guid_prefix));
            self.check_locators(
                &what,
                p.metatraffic_unicast
                    .iter()
                    .chain(&p.default_unicast)
                    .chain(&p.metatraffic_multicast)
                    .chain(&p.default_multicast),
            );
        }
        for e in &report.endpoints {
            let topics: Vec<String> = e
                .topics
                .iter()
                .cloned()
                .chain(e.alternates.iter().map(|a| a.topic.clone()))
                .collect();
            if let Some(ch) = self.channel_of(&topics) {
                let what = format!(
                    "robot {} of enforced topic {}",
                    if e.kind == EndpointKind::Writer {
                        "writer"
                    } else {
                        "reader"
                    },
                    self.topics.get(ch).cloned().flatten().unwrap_or_default()
                );
                self.check_locators(
                    &what,
                    e.unicast_locators.iter().chain(&e.multicast_locators),
                );
            }
        }
        self.stats.robot_unqueued_locators += self.stats.unqueued_locators - before;
        Some(report)
    }

    /// The writers the last [`Discovery::learn`] saw announced or removed
    /// (drained).
    pub fn take_announced(&mut self) -> Vec<Announced> {
        std::mem::take(&mut self.announced)
    }

    fn channel_of(&self, topics: &[String]) -> Option<usize> {
        topics.iter().find_map(|t| {
            self.topics
                .iter()
                .position(|c| c.as_deref() == Some(t.as_str()))
        })
    }

    /// Classify `guid` as enforced on `channel` (module docs). `false`:
    /// the enforced table is full and no writer in it has been idle long
    /// enough to make room; the writer was refused (and forgotten, so it is
    /// unknown and probed).
    fn set_enforced(&mut self, guid: Guid, channel: usize) -> bool {
        self.forget_other(&guid);
        let now = self.now;
        if let Some((c, seen)) = self.enforced.get_mut(&guid) {
            *seen = now;
            if *c != channel {
                *c = channel;
                self.dirty = true;
            }
            return true;
        }
        if self.enforced.len() >= self.max_enforced && !self.evict_idle_enforced() {
            self.stats.enforced_refused += 1;
            return false;
        }
        self.enforced.insert(guid, (channel, now));
        self.dirty = true;
        true
    }

    /// Remove the enforced writer seen longest ago if it has been idle for
    /// `enforced_idle_evict` or more. `false`: none qualifies.
    fn evict_idle_enforced(&mut self) -> bool {
        let Some(idle) = self.enforced_idle_evict else {
            return false;
        };
        let Some((&oldest, &(_, seen))) = self
            .enforced
            .iter()
            .min_by_key(|(g, (_, seen))| (*seen, **g))
        else {
            return false;
        };
        if self.now.saturating_duration_since(seen) < idle {
            return false;
        }
        self.enforced.remove(&oldest);
        self.stats.enforced_evicted += 1;
        self.dirty = true;
        true
    }

    /// The enforced table is full: a new enforced writer is admitted only
    /// in place of an idle one, and unknown writers (an evicted one among
    /// them) must be probed whatever `rtps.unknown_writers` says.
    pub fn enforced_full(&self) -> bool {
        self.enforced.len() >= self.max_enforced
    }

    /// Record a not-enforced writer or a probe result (least recently used
    /// table). An enforced writer is never downgraded by it.
    pub fn insert(&mut self, guid: Guid, info: WriterInfo) {
        if self.enforced.contains_key(&guid) {
            return;
        }
        self.clock += 1;
        let now = self.clock;
        if let Some((old_info, used)) = self.others.insert(guid, (info, now)) {
            self.lru.remove(&used);
            if old_info != info {
                self.dirty = true;
            }
        } else {
            self.dirty = true;
        }
        self.lru.insert(now, guid);
        while self.others.len() > self.max_writers {
            let Some((_, old)) = self.lru.pop_first() else {
                break;
            };
            self.others.remove(&old);
            self.stats.writers_evicted += 1;
        }
    }

    fn forget_other(&mut self, guid: &Guid) -> bool {
        match self.others.remove(guid) {
            Some((_, used)) => {
                self.lru.remove(&used);
                self.dirty = true;
                true
            }
            None => false,
        }
    }

    /// What is known about `guid`, without marking it used.
    pub fn writer(&self, guid: &Guid) -> Option<WriterInfo> {
        if let Some(&(ch, _)) = self.enforced.get(guid) {
            return Some(WriterInfo {
                channel: Some(ch),
                ..WriterInfo::default()
            });
        }
        self.others.get(guid).map(|(w, _)| *w)
    }

    /// What is known about `guid`, marking a not-enforced entry used (the
    /// decision path).
    pub fn lookup(&mut self, guid: &Guid) -> Option<WriterInfo> {
        if let Some((ch, seen)) = self.enforced.get_mut(guid) {
            *seen = self.now;
            let ch = *ch;
            return Some(WriterInfo {
                channel: Some(ch),
                ..WriterInfo::default()
            });
        }
        self.clock += 1;
        let now = self.clock;
        let (w, used) = self.others.get_mut(guid)?;
        let old = std::mem::replace(used, now);
        let w = *w;
        self.lru.remove(&old);
        self.lru.insert(now, *guid);
        Some(w)
    }

    /// Writers known (enforced and not).
    pub fn len(&self) -> usize {
        self.enforced.len() + self.others.len()
    }

    pub fn is_empty(&self) -> bool {
        self.enforced.is_empty() && self.others.is_empty()
    }

    /// Writers in the enforced table.
    pub fn enforced_len(&self) -> usize {
        self.enforced.len()
    }

    /// The confirmed identity a participant prefix holds.
    pub fn identity_of(&self, prefix: &GuidPrefix) -> Option<&str> {
        self.identities.identity_of(prefix)
    }

    /// Learn from one RTPS datagram (UDP payload) from `src`.
    pub fn learn(&mut self, datagram: &[u8], src: Ipv4Addr, now: Instant) {
        self.set_now(now);
        self.stats.datagrams += 1;
        self.announced.clear();
        let Some(report) = self.reasm.parse_datagram_detailed(datagram) else {
            return;
        };
        let sender = report.header.guid_prefix;
        for p in &report.participants {
            let what = format!("participant {}", hex(&p.guid_prefix));
            self.check_locators(
                &what,
                p.metatraffic_unicast
                    .iter()
                    .chain(&p.default_unicast)
                    .chain(&p.metatraffic_multicast)
                    .chain(&p.default_multicast),
            );
        }
        for e in &report.endpoints {
            let topics: Vec<String> = e
                .topics
                .iter()
                .cloned()
                .chain(e.alternates.iter().map(|a| a.topic.clone()))
                .collect();
            if let Some(ch) = self.channel_of(&topics) {
                let what = format!(
                    "{} of enforced topic {}",
                    if e.kind == EndpointKind::Writer {
                        "writer"
                    } else {
                        "reader"
                    },
                    self.topics.get(ch).cloned().flatten().unwrap_or_default()
                );
                self.check_locators(
                    &what,
                    e.unicast_locators.iter().chain(&e.multicast_locators),
                );
            }
        }
        for p in &report.participants {
            if p.guid_prefix != sender || self.identities.is_empty() {
                continue;
            }
            if let Resolution::Resolved { .. } =
                self.identities.observe_spdp(p, IpAddr::V4(src), now)
            {
                self.stats.identities_resolved += 1;
                self.epoch += 1;
            }
        }
        for r in &report.removed_participants {
            // Only a removal the robot acts on, sent by the participant
            // itself, forgets anything.
            if self.addressed(r.destination) != Addressed::Robot {
                self.stats.misaddressed += 1;
                continue;
            }
            if r.source != r.guid_prefix {
                self.stats.relayed_ignored += 1;
                continue;
            }
            self.stats.participants_removed += 1;
            let guid = crate::rtps::guid_of(&r.guid_prefix, &[0; 4]);
            self.announced.push(Announced {
                guid,
                whole_participant: true,
            });
            if self.identities.release(&r.guid_prefix).is_some() {
                self.epoch += 1;
            }
            self.stats.enforced_kept += self
                .enforced
                .keys()
                .filter(|g| prefix_of(g) == r.guid_prefix)
                .count() as u64;
            let gone: Vec<Guid> = self
                .others
                .keys()
                .filter(|g| prefix_of(g) == r.guid_prefix)
                .copied()
                .collect();
            for g in gone {
                if self.forget_other(&g) {
                    self.stats.writers_removed += 1;
                }
            }
        }
        for e in &report.endpoints {
            if e.kind != EndpointKind::Writer {
                continue;
            }
            let addressed = self.addressed(e.destination);
            if addressed == Addressed::Elsewhere {
                self.stats.misaddressed += 1;
                continue;
            }
            // Every (GUID, topic) reading, alternates included: an
            // alternate may name another endpoint GUID.
            let mut pairs: Vec<(Guid, &str)> = Vec::new();
            if let Some(g) = e.guid {
                pairs.extend(e.topics.iter().map(|t| (g, t.as_str())));
            }
            for a in &e.alternates {
                if let Some(g) = a.guid.or(e.guid) {
                    pairs.push((g, a.topic.as_str()));
                }
            }
            let same_type = e
                .type_names
                .iter()
                .map(String::as_str)
                .chain(e.alternates.iter().map(|a| a.type_name.as_str()))
                .any(|t| self.types.contains(&t));
            let mut guids: Vec<Guid> = pairs.iter().map(|(g, _)| *g).collect();
            guids.sort_unstable();
            guids.dedup();
            for guid in guids {
                let own = prefix_of(&guid) == e.source;
                let topics: Vec<String> = pairs
                    .iter()
                    .filter(|(g, _)| *g == guid)
                    .map(|(_, t)| (*t).to_string())
                    .collect();
                let channel = self.channel_of(&topics);
                self.stats.writers_learned += 1;
                if own {
                    self.announced.push(Announced {
                        guid,
                        whole_participant: false,
                    });
                }
                match channel {
                    // Enforcing is the safe direction: from anyone.
                    Some(ch) => {
                        self.stats.writers_enforced += 1;
                        self.set_enforced(guid, ch);
                    }
                    None if self.enforced.contains_key(&guid) => {
                        // Never downgraded (module docs).
                        self.stats.enforced_kept += 1;
                    }
                    None if !own => self.stats.relayed_ignored += 1,
                    None => self.insert(
                        guid,
                        WriterInfo {
                            channel: None,
                            probed: false,
                            same_type,
                            unverified: addressed == Addressed::Unverified,
                        },
                    ),
                }
            }
        }
        for r in &report.removed_endpoints {
            if r.kind != EndpointKind::Writer {
                continue;
            }
            let Some(g) = r.guid else {
                continue;
            };
            if self.addressed(r.destination) != Addressed::Robot {
                self.stats.misaddressed += 1;
                continue;
            }
            if prefix_of(&g) != r.source {
                self.stats.relayed_ignored += 1;
                continue;
            }
            self.announced.push(Announced {
                guid: g,
                whole_participant: false,
            });
            if self.enforced.contains_key(&g) {
                self.stats.enforced_kept += 1;
            } else if self.forget_other(&g) {
                self.stats.writers_removed += 1;
            }
        }
    }

    /// Expire identity leases (housekeeping).
    pub fn expire(&mut self, now: Instant) {
        if !self.identities.expire(now).is_empty() {
            self.epoch += 1;
        }
    }

    /// Persist the writer map (atomic rename): enforced writers with their
    /// topic, writers SEDP announced on another topic with an empty topic
    /// (so a restarted gateway does not run them through the lenient
    /// content probe, which may classify a non-motion sample of plausible
    /// shape as a motion channel and suppress it) and their `same_type` /
    /// `unverified` marks. Probed writers are not persisted. Written to a
    /// fresh `O_EXCL` 0600 temporary file (a symlink or file planted at its
    /// name is removed, never followed), then renamed.
    pub fn save(&mut self, path: &Path) -> std::io::Result<()> {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut writers: Vec<(String, String)> = self
            .enforced
            .iter()
            .filter_map(|(g, (ch, _))| Some((hex(g), self.topics.get(*ch)?.clone()?)))
            .collect();
        let mut same_type = Vec::new();
        let mut unverified = Vec::new();
        for (g, (w, _)) in &self.others {
            if w.channel.is_some() || w.probed {
                continue;
            }
            writers.push((hex(g), String::new()));
            if w.same_type {
                same_type.push(hex(g));
            }
            if w.unverified {
                unverified.push(hex(g));
            }
        }
        writers.sort_unstable();
        same_type.sort_unstable();
        unverified.sort_unstable();
        let s = StateFile {
            format: STATE_FORMAT.to_string(),
            writers,
            same_type,
            unverified,
        };
        let text = serde_json::to_string(&s).map_err(std::io::Error::other)?;
        let tmp = path.with_extension("tmp");
        // unlink(2) removes a planted symlink itself, never its target.
        match std::fs::remove_file(&tmp) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)?;
        self.dirty = false;
        Ok(())
    }

    /// Load a persisted map (entries for topics no longer enforced are
    /// skipped). A missing file is not an error. Opened without following
    /// a symlink and without blocking; refused unless a regular file, not
    /// writable by group or others, owned by root or by the owner of its
    /// directory (as the restriction file).
    pub fn load(&mut self, path: &Path) -> Result<usize, String> {
        use std::io::Read as _;
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
        let f = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW | O_NONBLOCK)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(format!("{}: {e} (a symlink is refused)", path.display())),
        };
        let meta = f
            .metadata()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if !meta.file_type().is_file() {
            return Err(format!("{}: not a regular file", path.display()));
        }
        if meta.mode() & 0o022 != 0 {
            return Err(format!("{}: writable by group or others", path.display()));
        }
        let dir_owner = path
            .parent()
            .map(|d| {
                if d.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    d
                }
            })
            .and_then(|d| std::fs::metadata(d).ok())
            .map(|m| m.uid());
        if meta.uid() != 0 && Some(meta.uid()) != dir_owner {
            return Err(format!(
                "{}: owned by uid {}, neither root nor the directory's owner",
                path.display(),
                meta.uid()
            ));
        }
        let mut text = String::new();
        f.take(MAX_STATE_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if text.len() as u64 > MAX_STATE_BYTES {
            return Err(format!("{}: too large", path.display()));
        }
        let s: StateFile =
            serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        if s.format != STATE_FORMAT && s.format != STATE_FORMAT_V1 {
            return Err(format!("{}: unknown format {:?}", path.display(), s.format));
        }
        let same_type: std::collections::HashSet<String> = s.same_type.into_iter().collect();
        let unverified: std::collections::HashSet<String> = s.unverified.into_iter().collect();
        let mut n = 0;
        for (g, topic) in s.writers {
            let Some(guid) = unhex16(&g) else {
                continue;
            };
            if topic.is_empty() {
                self.insert(
                    guid,
                    WriterInfo {
                        channel: None,
                        probed: false,
                        same_type: same_type.contains(&g),
                        unverified: unverified.contains(&g),
                    },
                );
                continue;
            }
            // A topic no longer enforced: let the writer be learned or
            // probed again.
            if let Some(ch) = self.channel_of(std::slice::from_ref(&topic)) {
                if self.set_enforced(guid, ch) {
                    n += 1;
                }
            }
        }
        self.dirty = false;
        Ok(n)
    }
}
