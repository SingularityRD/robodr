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
//! - Endpoint and participant removals (dispose / unregister) forget the
//!   writers.
//! - SPDP announcements feed `robodr-ros2-pipeline`'s
//!   [`IdentityResolver`] (participant identity from source IP, vendor and
//!   enclave), for `identity:<name>` sources. Only an SPDP sent by the
//!   participant itself (header prefix == announced prefix) is used.
//! - The map is bounded ([`Discovery::new`]'s `max_writers`; the oldest
//!   entry is evicted first) and can be persisted
//!   ([`Discovery::save`] / [`Discovery::load`]) so a restarted gateway,
//!   which will not see the robot's earlier SEDP again, keeps classifying
//!   the existing writers. A persisted entry is only a classification hint:
//!   source authorisation is still decided per sample.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::time::Instant;

use robodr_ros2_pipeline::{IdentityResolver, Resolution};
use robodr_rtps::{EndpointKind, FragmentReassembler, ReassemblyLimits};
use serde::{Deserialize, Serialize};

use crate::rtps::{Guid, GuidPrefix};

/// What is known about one writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriterInfo {
    /// Index of the enforced channel it writes, if any.
    pub channel: Option<usize>,
    /// Learned from a content probe rather than SEDP.
    pub probed: bool,
}

/// Discovery state.
pub struct Discovery {
    writers: HashMap<Guid, WriterInfo>,
    order: VecDeque<Guid>,
    max_writers: usize,
    /// Enforced topics, index = channel index (None for non-RTPS channels).
    topics: Vec<Option<String>>,
    reasm: FragmentReassembler,
    identities: IdentityResolver,
    /// Bumped whenever identities change, so cached source resolutions are
    /// recomputed.
    pub epoch: u64,
    /// The writer map changed since the last [`Discovery::save`].
    pub dirty: bool,
    pub stats: DiscoveryStats,
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
}

/// Persisted form.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateFile {
    format: String,
    /// writer GUID (32 hex) -> topic.
    writers: Vec<(String, String)>,
}

const STATE_FORMAT: &str = "robodr-firewall-gw-writers/v1";
/// Largest state file read.
const MAX_STATE_BYTES: u64 = 4 << 20;

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

impl std::fmt::Debug for Discovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Discovery")
            .field("writers", &self.writers.len())
            .field("epoch", &self.epoch)
            .field("stats", &self.stats)
            .finish()
    }
}

impl Discovery {
    pub fn new(
        topics: Vec<Option<String>>,
        max_writers: usize,
        identities: IdentityResolver,
    ) -> Self {
        Self {
            writers: HashMap::new(),
            order: VecDeque::new(),
            max_writers: max_writers.max(1),
            topics,
            reasm: FragmentReassembler::new(ReassemblyLimits::default()),
            identities,
            epoch: 0,
            dirty: false,
            stats: DiscoveryStats::default(),
        }
    }

    fn channel_of(&self, topics: &[String]) -> Option<usize> {
        topics.iter().find_map(|t| {
            self.topics
                .iter()
                .position(|c| c.as_deref() == Some(t.as_str()))
        })
    }

    /// Record a writer (also from a probe).
    pub fn insert(&mut self, guid: Guid, info: WriterInfo) {
        if self.writers.insert(guid, info).is_none() {
            self.order.push_back(guid);
            while self.order.len() > self.max_writers {
                if let Some(old) = self.order.pop_front() {
                    self.writers.remove(&old);
                    self.stats.writers_evicted += 1;
                }
            }
        }
        self.dirty = true;
    }

    fn remove(&mut self, guid: &Guid) {
        if self.writers.remove(guid).is_some() {
            self.order.retain(|g| g != guid);
            self.stats.writers_removed += 1;
            self.dirty = true;
        }
    }

    pub fn writer(&self, guid: &Guid) -> Option<WriterInfo> {
        self.writers.get(guid).copied()
    }

    pub fn len(&self) -> usize {
        self.writers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.writers.is_empty()
    }

    /// The confirmed identity a participant prefix holds.
    pub fn identity_of(&self, prefix: &GuidPrefix) -> Option<&str> {
        self.identities.identity_of(prefix)
    }

    /// Learn from one RTPS datagram (UDP payload) from `src`.
    pub fn learn(&mut self, datagram: &[u8], src: Ipv4Addr, now: Instant) {
        self.stats.datagrams += 1;
        let Some(report) = self.reasm.parse_datagram_detailed(datagram) else {
            return;
        };
        let sender = report.header.guid_prefix;
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
            self.stats.participants_removed += 1;
            if self.identities.release(&r.guid_prefix).is_some() {
                self.epoch += 1;
            }
            let gone: Vec<Guid> = self
                .writers
                .keys()
                .filter(|g| g[..12] == r.guid_prefix)
                .copied()
                .collect();
            for g in gone {
                self.remove(&g);
            }
        }
        for e in &report.endpoints {
            if e.kind != EndpointKind::Writer {
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
            let mut guids: Vec<Guid> = pairs.iter().map(|(g, _)| *g).collect();
            guids.sort_unstable();
            guids.dedup();
            for guid in guids {
                let topics: Vec<String> = pairs
                    .iter()
                    .filter(|(g, _)| *g == guid)
                    .map(|(_, t)| (*t).to_string())
                    .collect();
                let channel = self.channel_of(&topics);
                self.stats.writers_learned += 1;
                if channel.is_some() {
                    self.stats.writers_enforced += 1;
                }
                // An enforced classification is never downgraded by a later
                // announcement of the same GUID on another topic.
                let channel = channel.or(self.writers.get(&guid).and_then(|w| w.channel));
                self.insert(
                    guid,
                    WriterInfo {
                        channel,
                        probed: false,
                    },
                );
            }
        }
        for r in &report.removed_endpoints {
            if r.kind == EndpointKind::Writer {
                if let Some(g) = r.guid {
                    self.remove(&g);
                }
            }
        }
    }

    /// Expire identity leases (housekeeping).
    pub fn expire(&mut self, now: Instant) {
        if !self.identities.expire(now).is_empty() {
            self.epoch += 1;
        }
    }

    /// Persist the enforced-channel writers (atomic rename).
    pub fn save(&mut self, path: &Path) -> std::io::Result<()> {
        let writers: Vec<(String, String)> = self
            .order
            .iter()
            .filter_map(|g| {
                let ch = self.writers.get(g)?.channel?;
                Some((hex(g), self.topics.get(ch)?.clone()?))
            })
            .collect();
        let s = StateFile {
            format: STATE_FORMAT.to_string(),
            writers,
        };
        let text = serde_json::to_string(&s).map_err(std::io::Error::other)?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, path)?;
        self.dirty = false;
        Ok(())
    }

    /// Load a persisted map (entries for topics no longer enforced are
    /// skipped). A missing file is not an error.
    pub fn load(&mut self, path: &Path) -> Result<usize, String> {
        use std::io::Read as _;
        let f = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        let mut text = String::new();
        f.take(MAX_STATE_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if text.len() as u64 > MAX_STATE_BYTES {
            return Err(format!("{}: too large", path.display()));
        }
        let s: StateFile =
            serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        if s.format != STATE_FORMAT {
            return Err(format!("{}: unknown format {:?}", path.display(), s.format));
        }
        let mut n = 0;
        for (g, topic) in s.writers {
            let (Some(guid), Some(ch)) =
                (unhex16(&g), self.channel_of(std::slice::from_ref(&topic)))
            else {
                continue;
            };
            self.insert(
                guid,
                WriterInfo {
                    channel: Some(ch),
                    probed: false,
                },
            );
            n += 1;
        }
        self.dirty = false;
        Ok(n)
    }
}
