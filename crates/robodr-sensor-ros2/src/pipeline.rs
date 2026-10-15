//! Pulsar-independent detection pipeline: datagram -> RTPS events -> profile
//! deviations -> deduplicated, sanitised findings.
//!
//! Nothing in this file needs tokio or `pulsar-core`; it only uses `std`,
//! `robodr-events`, `robodr-rtps` and `serde`. The Pulsar glue in `lib.rs`
//! feeds it datagrams and turns each [`Finding`] into one `send_threat` call.
//! Keeping the logic here means it is unit-testable without the Pulsar
//! dependency tree.
//!
//! ## Datagram sources (seam for `robodr-capture`)
//!
//! The pipeline does not care where datagrams come from. Today they come from
//! the SPDP multicast socket; the capture-based listener (crate
//! `robodr-capture`, which also sees unicast SEDP and loopback traffic) plugs
//! in through [`DatagramSource`], a blocking, std-only trait, so that crate
//! never needs tokio or Pulsar. `lib.rs` bridges a `DatagramSource` onto the
//! async listener with `spawn_blocking_source`.
//!
//! ## Dedup bound
//!
//! Discovery beacons repeat every few seconds, so without dedup one rogue
//! participant would raise a threat per beacon. Without a bound, an attacker
//! spraying random GUIDs could grow the set until the daemon runs out of
//! memory. [`DedupSet`] therefore keeps at most `capacity` entries, evicting
//! the oldest first, and stores a keyed 64-bit hash of each key rather than
//! the key itself, so memory is `O(capacity)` regardless of how long the
//! (attacker-controlled) topic names in a deviation are. Eviction only ever
//! makes a still-present deviation be reported again: the safe direction.
//! The hash is keyed per process (`RandomState`), so an attacker cannot craft
//! a collision to suppress a report.
//!
//! ## Known limits
//!
//! - There is no rate limit on *distinct* deviations: an attacker announcing a
//!   new GUID per packet produces one threat per packet. Each such threat is
//!   a true positive (an unknown participant really did announce itself), but
//!   downstream consumers should rate-limit or aggregate.
//! - Text that reaches the threat (topic names, type names) is attacker
//!   controlled. [`sanitize`] escapes control characters and caps the length
//!   so it cannot inject terminal escapes or newlines into logs.

use std::collections::hash_map::RandomState;
use std::collections::{HashSet, VecDeque};
use std::hash::BuildHasher;

use robodr_events::profile::Profile;
use robodr_events::{Deviation, Severity};
use robodr_rtps as rtps;
use serde::Serialize;

/// Prefix added to the threat description while the profile is not locked.
pub const OBSERVE_ONLY_TAG: &str = "[observe-only] ";

/// Upper bound (in chars) on attacker-influenced text copied into a threat.
pub const MAX_TEXT_CHARS: usize = 512;

/// One received datagram, with the source IP it came from (as text, the form
/// `robodr_rtps::parse_datagram` takes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    pub payload: Vec<u8>,
    pub src_ip: String,
}

impl Datagram {
    pub fn new(payload: Vec<u8>, src_ip: impl Into<String>) -> Self {
        Self {
            payload,
            src_ip: src_ip.into(),
        }
    }
}

/// A blocking producer of RTPS datagrams other than the SPDP socket — the
/// seam for the capture-based listener in `robodr-capture`.
///
/// Contract:
/// - `Ok(Some(d))`: one datagram (UDP payload only, starting at `RTPS`).
/// - `Ok(None)`: the source is finished; it will not be polled again.
/// - `Err(e)`: a terminal error; the source is dropped and the error logged.
///   Transient conditions (EINTR, a timeout used for polling) must be handled
///   inside the implementation, not returned.
///
/// Implementations must stay read-only on the network.
pub trait DatagramSource {
    fn recv(&mut self) -> std::io::Result<Option<Datagram>>;
}

/// Whether the profile is enforceable or still being commissioned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfileMode {
    /// `profile.locked == true`: deviations are real findings that the
    /// responder may act on.
    Locked,
    /// `profile.locked == false`: deviations are reported for commissioning
    /// only and must not drive a response.
    Observe,
}

impl ProfileMode {
    pub fn from_locked(locked: bool) -> Self {
        if locked {
            Self::Locked
        } else {
            Self::Observe
        }
    }

    pub fn is_observe(self) -> bool {
        self == Self::Observe
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Locked => "locked",
            Self::Observe => "observe",
        }
    }
}

/// A new (not previously reported) deviation, ready to become one threat.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub deviation: Deviation,
    pub mode: ProfileMode,
    /// Source IP of the datagram that revealed the deviation.
    pub src_ip: String,
    /// `profile.model` the deviation was evaluated against.
    pub profile_model: String,
}

/// Structured data attached to the threat (`Threat::extra`). Every field is a
/// TOML scalar on purpose: Pulsar stores `extra` as a `toml::Value`, and
/// `Value::try_from` serialises through TOML (see docs/PULSAR-INTEGRATION.md).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ThreatExtra {
    pub rule: &'static str,
    pub severity: Severity,
    pub detail: String,
    pub mode: &'static str,
    pub observe_only: bool,
    pub src_ip: String,
    pub profile_model: String,
}

impl Finding {
    /// Human-readable threat description: the sanitised detail, prefixed with
    /// [`OBSERVE_ONLY_TAG`] in observe mode.
    pub fn description(&self) -> String {
        let detail = sanitize(&self.deviation.detail);
        if self.mode.is_observe() {
            format!("{OBSERVE_ONLY_TAG}{detail}")
        } else {
            detail
        }
    }

    pub fn extra(&self) -> ThreatExtra {
        ThreatExtra {
            rule: self.deviation.rule,
            severity: self.deviation.severity,
            detail: sanitize(&self.deviation.detail),
            mode: self.mode.as_str(),
            observe_only: self.mode.is_observe(),
            src_ip: sanitize(&self.src_ip),
            profile_model: sanitize(&self.profile_model),
        }
    }
}

/// Escape control characters (newlines, ESC, NUL, ...) and cap the length at
/// [`MAX_TEXT_CHARS`] chars, so attacker-chosen names cannot forge log lines
/// or inject terminal escape sequences.
pub fn sanitize(text: &str) -> String {
    let mut out = String::with_capacity(text.len().min(MAX_TEXT_CHARS + 16));
    for (kept, c) in text.chars().enumerate() {
        if kept == MAX_TEXT_CHARS {
            out.push_str("...[truncated]");
            return out;
        }
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// Bounded "have we reported this already?" set. See the module docs.
#[derive(Debug)]
pub struct DedupSet {
    hasher: RandomState,
    seen: HashSet<u64>,
    order: VecDeque<u64>,
    capacity: usize,
}

impl DedupSet {
    /// `capacity` is clamped to at least 1.
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            hasher: RandomState::new(),
            seen: HashSet::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    /// Returns `true` if `key` was not present (i.e. it should be reported).
    /// When full, the oldest entry is evicted first.
    pub fn insert(&mut self, key: &str) -> bool {
        let h = self.hasher.hash_one(key);
        if self.seen.contains(&h) {
            return false;
        }
        while self.order.len() >= self.capacity {
            match self.order.pop_front() {
                Some(old) => {
                    self.seen.remove(&old);
                }
                None => break,
            }
        }
        self.seen.insert(h);
        self.order.push_back(h);
        true
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

/// Dedup key of a deviation: rule + detail. The detail names the GUID, topic
/// and source, so each distinct deviation is reported once, not once per
/// beacon, while two different rogue topics from one host stay two reports.
fn dedup_key(dev: &Deviation) -> String {
    format!("{}|{}", dev.rule, dev.detail)
}

/// Datagram -> findings, against one profile.
#[derive(Debug)]
pub struct Pipeline {
    profile: Profile,
    mode: ProfileMode,
    seen: DedupSet,
}

impl Pipeline {
    pub fn new(profile: Profile, dedup_capacity: usize) -> Self {
        let mode = ProfileMode::from_locked(profile.locked);
        Self {
            profile,
            mode,
            seen: DedupSet::new(dedup_capacity),
        }
    }

    pub fn mode(&self) -> ProfileMode {
        self.mode
    }

    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// Number of distinct deviations currently remembered.
    pub fn remembered(&self) -> usize {
        self.seen.len()
    }

    /// Parse one datagram and return the deviations not reported before.
    /// Never panics: malformed or non-RTPS input yields no findings.
    pub fn process(&mut self, payload: &[u8], src_ip: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for event in rtps::parse_datagram(payload, src_ip) {
            let Some(deviation) = self.profile.evaluate(&event) else {
                continue;
            };
            if !self.seen.insert(&dedup_key(&deviation)) {
                continue;
            }
            findings.push(Finding {
                deviation,
                mode: self.mode,
                src_ip: src_ip.to_string(),
                profile_model: self.profile.model.clone(),
            });
        }
        findings
    }

    pub fn process_datagram(&mut self, datagram: &Datagram) -> Vec<Finding> {
        self.process(&datagram.payload, &datagram.src_ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KNOWN: [u8; 12] = [0xaa; 12];
    const KNOWN_HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaa";

    /// A 20-byte RTPS header (no submessages) with the given GUID prefix.
    fn header(prefix: [u8; 12]) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(b"RTPS");
        d.extend_from_slice(&[2, 2, 0x01, 0x0f]);
        d.extend_from_slice(&prefix);
        d
    }

    fn profile(locked: bool) -> Profile {
        let mut p = Profile {
            model: "amr-v1".into(),
            locked,
            ..Default::default()
        };
        p.participants.insert(KNOWN_HEX.into());
        p
    }

    fn prefix(n: u32) -> [u8; 12] {
        let mut p = [0x11u8; 12];
        p[8..].copy_from_slice(&n.to_be_bytes());
        p
    }

    #[test]
    fn known_participant_yields_nothing() {
        let mut pl = Pipeline::new(profile(true), 16);
        assert!(pl.process(&header(KNOWN), "10.0.0.5").is_empty());
        assert_eq!(pl.remembered(), 0);
    }

    #[test]
    fn unknown_participant_yields_one_finding() {
        let mut pl = Pipeline::new(profile(true), 16);
        let f = pl.process(&header([0xff; 12]), "10.0.0.9");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].deviation.rule, "robot.ros2.unknown_participant");
        assert_eq!(f[0].mode, ProfileMode::Locked);
        assert_eq!(f[0].src_ip, "10.0.0.9");
        assert_eq!(f[0].profile_model, "amr-v1");
    }

    #[test]
    fn repeated_beacons_are_reported_once() {
        let mut pl = Pipeline::new(profile(true), 16);
        let d = header([0xff; 12]);
        assert_eq!(pl.process(&d, "10.0.0.9").len(), 1);
        for _ in 0..100 {
            assert!(pl.process(&d, "10.0.0.9").is_empty());
        }
        assert_eq!(pl.remembered(), 1);
    }

    #[test]
    fn same_guid_from_another_ip_is_a_new_finding() {
        let mut pl = Pipeline::new(profile(true), 16);
        let d = header([0xff; 12]);
        assert_eq!(pl.process(&d, "10.0.0.9").len(), 1);
        assert_eq!(pl.process(&d, "10.0.0.10").len(), 1);
    }

    #[test]
    fn guid_spray_stays_bounded() {
        let cap = 64;
        let mut pl = Pipeline::new(profile(true), cap);
        for n in 0..10_000u32 {
            assert_eq!(pl.process(&header(prefix(n)), "10.0.0.66").len(), 1);
            assert!(pl.remembered() <= cap);
        }
        assert_eq!(pl.remembered(), cap);
    }

    #[test]
    fn eviction_is_oldest_first_and_rereports() {
        let mut pl = Pipeline::new(profile(true), 2);
        let (a, b, c) = (header(prefix(1)), header(prefix(2)), header(prefix(3)));
        assert_eq!(pl.process(&a, "ip").len(), 1);
        assert_eq!(pl.process(&b, "ip").len(), 1);
        assert_eq!(pl.process(&c, "ip").len(), 1); // evicts a
        assert!(pl.process(&b, "ip").is_empty()); // still remembered
        assert!(pl.process(&c, "ip").is_empty());
        assert_eq!(pl.process(&a, "ip").len(), 1); // re-reported: safe side
    }

    #[test]
    fn hostile_input_never_panics_and_yields_nothing() {
        let mut pl = Pipeline::new(profile(true), 16);
        let mut inputs: Vec<Vec<u8>> = vec![
            vec![],
            b"RTPS".to_vec(),
            b"RTPX0000000000000000".to_vec(),
            vec![0xff; 65_535],
        ];
        // Every truncation of a header plus a bogus submessage claiming 0xffff bytes.
        let mut long = header([0xff; 12]);
        long.extend_from_slice(&[0x15, 0x05, 0xff, 0xff, 1, 2, 3]);
        for n in 0..long.len() {
            inputs.push(long[..n].to_vec());
        }
        for i in &inputs {
            let f = pl.process(i, "10.0.0.1");
            // Anything shorter than a header, or not RTPS, yields nothing.
            if i.len() < 20 || &i[..4] != b"RTPS" {
                assert!(f.is_empty());
            }
        }
        // The full crafted datagram still reports its participant exactly once.
        assert!(pl.remembered() <= 1);
    }

    #[test]
    fn locked_description_is_the_detail() {
        let mut pl = Pipeline::new(profile(true), 16);
        let f = pl.process(&header([0xff; 12]), "10.0.0.9").remove(0);
        assert!(!f.description().starts_with(OBSERVE_ONLY_TAG));
        assert_eq!(f.description(), f.deviation.detail);
        let x = f.extra();
        assert_eq!(x.mode, "locked");
        assert!(!x.observe_only);
        assert_eq!(x.severity, Severity::High);
    }

    #[test]
    fn observe_mode_tags_description_and_extra() {
        let mut pl = Pipeline::new(profile(false), 16);
        assert_eq!(pl.mode(), ProfileMode::Observe);
        let f = pl.process(&header([0xff; 12]), "10.0.0.9").remove(0);
        assert!(f.description().starts_with(OBSERVE_ONLY_TAG));
        let x = f.extra();
        assert_eq!(x.mode, "observe");
        assert!(x.observe_only);
        assert_eq!(x.rule, "robot.ros2.unknown_participant");
        assert_eq!(x.src_ip, "10.0.0.9");
        assert_eq!(x.profile_model, "amr-v1");
    }

    #[test]
    fn extra_serialises_to_flat_scalars() {
        let mut pl = Pipeline::new(profile(false), 16);
        let f = pl.process(&header([0xff; 12]), "10.0.0.9").remove(0);
        let v = serde_json::to_value(f.extra()).unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(obj.len(), 7);
        assert!(obj.values().all(|v| !v.is_object() && !v.is_array()));
        assert_eq!(obj["severity"], "high");
        assert_eq!(obj["observe_only"], true);
    }

    #[test]
    fn sanitize_escapes_controls_and_truncates() {
        assert_eq!(sanitize("plain /cmd_vel"), "plain /cmd_vel");
        assert_eq!(sanitize("a\nb"), "a\\nb");
        assert_eq!(sanitize("\u{1b}[31mred"), "\\u{1b}[31mred");
        assert_eq!(sanitize("nul\0"), "nul\\u{0}");
        let long = "x".repeat(MAX_TEXT_CHARS + 10);
        let s = sanitize(&long);
        assert!(s.ends_with("...[truncated]"));
        assert_eq!(s.chars().filter(|&c| c == 'x').count(), MAX_TEXT_CHARS);
        let exact = "y".repeat(MAX_TEXT_CHARS);
        assert_eq!(sanitize(&exact), exact);
        // Multi-byte characters are counted as chars, never split.
        let wide = "ç".repeat(MAX_TEXT_CHARS + 1);
        assert!(sanitize(&wide).starts_with(&"ç".repeat(MAX_TEXT_CHARS)));
    }

    #[test]
    fn dedup_set_basics() {
        let mut s = DedupSet::new(0);
        assert_eq!(s.capacity(), 1);
        assert!(s.is_empty());
        assert!(s.insert("a"));
        assert!(!s.insert("a"));
        assert!(s.insert("b")); // evicts a
        assert_eq!(s.len(), 1);
        assert!(s.insert("a"));
    }

    #[test]
    fn datagram_entry_point_matches_slice_entry_point() {
        let mut pl = Pipeline::new(profile(true), 16);
        let d = Datagram::new(header([0xff; 12]), "10.0.0.9");
        assert_eq!(pl.process_datagram(&d).len(), 1);
        assert!(pl.process(&d.payload, &d.src_ip).is_empty());
    }

    struct VecSource(Vec<Datagram>);
    impl DatagramSource for VecSource {
        fn recv(&mut self) -> std::io::Result<Option<Datagram>> {
            Ok(if self.0.is_empty() {
                None
            } else {
                Some(self.0.remove(0))
            })
        }
    }

    #[test]
    fn a_datagram_source_drives_the_pipeline() {
        let mut src = VecSource(vec![
            Datagram::new(header(KNOWN), "10.0.0.5"),
            Datagram::new(header([0xff; 12]), "10.0.0.9"),
            Datagram::new(header([0xff; 12]), "10.0.0.9"),
        ]);
        let mut pl = Pipeline::new(profile(true), 16);
        let mut total = 0;
        while let Some(d) = src.recv().unwrap() {
            total += pl.process_datagram(&d).len();
        }
        assert_eq!(total, 1);
    }
}
