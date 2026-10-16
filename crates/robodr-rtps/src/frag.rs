//! Bounded DATA_FRAG reassembly for discovery samples.
//!
//! Large SEDP announcements (e.g. with XTypes TypeInformation / TypeObject)
//! exceed one UDP datagram and are sent as DATA_FRAG submessages by Fast DDS
//! and Connext. The stateless [`crate::parse_datagram`] reassembles only
//! within one datagram and counts every discovery fragment
//! (see [`crate::ParseStats::discovery_data_frag`]). A sensor that wants
//! samples spread over several datagrams keeps one [`FragmentReassembler`]
//! per capture and feeds every datagram through it.
//!
//! # Memory bounds
//!
//! Only fragments from builtin discovery writers (SPDP / SEDP) are buffered;
//! user-data fragments are never stored. Every buffer is capped by
//! [`ReassemblyLimits`]:
//!
//! - a sample whose claimed `sampleSize` exceeds `max_sample_bytes` is refused
//!   before anything is allocated;
//! - at most `max_pending_samples` partial samples are kept (hard ceiling
//!   [`HARD_MAX_PENDING_SAMPLES`]), at most `max_pending_per_source` of them
//!   from one source GUID prefix, and their total footprint (buffer +
//!   received-fragment bitmap) never exceeds `max_total_bytes`.
//!
//! So the worst case an attacker can force is `max_total_bytes` of memory and
//! O(`max_pending_samples`) work per fragment.
//!
//! A sample whose fragments all arrive in one DATA_FRAG submessage (the
//! common "one fragment = whole sample" case) is completed at once and never
//! enters the table, so it can neither evict nor be evicted. The stateless
//! [`crate::parse_datagram`] uses a throwaway reassembler per datagram, so it
//! sees those samples, and samples whose fragments all sit in one datagram,
//! too.
//!
//! # Eviction policy
//!
//! The source prefix (RTPS header, or INFO_SRC) is unauthenticated: an
//! attacker can spoof as many prefixes as it likes, even inside one datagram.
//! The policy is built so that a burst of cheap junk does not push out a
//! sample that is already in progress:
//!
//! 1. **Per-source quota.** A source that already holds
//!    `max_pending_per_source` partial samples makes room among *its own*
//!    samples (the one that progressed least recently goes). One prefix can
//!    never take more than its quota of the table.
//! 2. **Stale first.** Under global pressure (count or bytes), a sample that
//!    has not received a new fragment during the last `stale_after_fragments`
//!    discovery fragments fed to the reassembler is evicted first (least
//!    recently progressed first). This is the only way abandoned samples age
//!    out: the crate is pure and has no clock.
//! 3. **Most-represented source, least progress, newest.** Otherwise the
//!    victim comes from the source(s) holding the most partial samples; among
//!    those, the sample with the fewest *received bytes* goes, and on a tie the
//!    most recently created one. A flood of fresh single-fragment samples
//!    (one per spoofed prefix) therefore evicts itself, not an older sample
//!    that has the same or more bytes in hand.
//!
//! Every eviction and every refused fragment is reported as a typed
//! [`FragmentEvent`] in the [`crate::DatagramReport`] of the datagram that
//! caused it (plus [`crate::ParseStats::frag_evicted`] /
//! [`crate::ParseStats::frag_rejected`] and the running
//! [`FragmentReassembler::evicted`] / [`FragmentReassembler::dropped`]
//! counters), so a sensor can raise a finding: a discovery sample it did not
//! get to inspect.
//!
//! ## Remaining denial-of-service limits (honest)
//!
//! A table of finite size fed by unauthenticated identities cannot be made
//! eviction-proof. What an on-path or on-segment attacker can still do:
//!
//! - Evict a specific in-progress sample that holds `R` received bytes by
//!   first filling every other slot with partial samples that each hold more
//!   than `R` bytes (about `(max_pending_samples - 1) * R` bytes of traffic,
//!   bounded by `max_total_bytes`), then sending one more new sample.
//! - Keep such "heavy" junk from going stale by sending it one new fragment
//!   every `stale_after_fragments` fragments; while it does, new samples
//!   compete for the remaining slots and one that is still on its first
//!   fragment is the preferred victim of the next newcomer.
//! - Spoof the legitimate participant's own prefix and use its quota.
//!
//! All of these cost the attacker sustained traffic, and all of them are
//! visible as [`FragmentEvent`]s; none can exceed the memory caps or panic.
//!
//! # Overlaps
//!
//! Like a DDS stack, the first copy of a fragment wins: a later fragment that
//! overlaps already-received bytes only fills the parts not received yet. If
//! the overlapping bytes differ, the first copy is kept and a
//! [`FragmentEventKind::ConflictingOverlap`] event is reported (somebody may be
//! splicing content into another participant's announcement). A fragment
//! whose `sampleSize` / `fragmentSize` / key flag disagrees with the pending
//! sample is refused on its own; the pending sample is left untouched.
//!
//! # Inline QoS of fragmented samples
//!
//! A DATA_FRAG may carry inline QoS (`PID_STATUS_INFO`, `PID_KEY_HASH`).
//! A fragment that brings no new bytes (a duplicate or retransmission) is
//! dropped whole by DDS stacks, inline QoS included, so it is here too: an
//! attacker cannot turn a live announcement into a "removal" by replaying
//! one of its fragments with a disposed / unregistered status. Among the
//! fragments that do bring new bytes, stacks differ on whose inline QoS
//! counts: some take the fragment that created the sample (the first one
//! accepted), some the one at offset 0 (fragment 1). Both readings are kept
//! (the second as an alternate status when it differs), and the decoder
//! treats a sample with any live reading as an announcement, not a removal.
//! Inline QoS on any other fragment is ignored.
//!
//! A fragment whose inline QoS disagrees with what was recorded is reported
//! as [`FragmentEventKind::ConflictingInlineQos`] (and as an
//! [`crate::Anomaly::ConflictingDuplicateParameter`] for that PID): a copy
//! of the creating fragment or of fragment 1 must repeat its status exactly
//! (absent counts as alive), any other fragment conflicts only when it
//! carries a present, different status or key hash (stacks that put inline
//! QoS on fragment 1 only are honest).

use std::collections::HashMap;

use crate::parse::{DiscoveryTopic, EntityId, GuidPrefix, InlineQos};

/// Hard ceiling on `max_sample_bytes`, whatever the caller configures.
pub const HARD_MAX_SAMPLE_BYTES: usize = 1 << 20;
/// Hard ceiling on `max_pending_samples` (each fragment costs a linear scan
/// of the pending table).
pub const HARD_MAX_PENDING_SAMPLES: usize = 1024;

/// Caps for [`FragmentReassembler`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReassemblyLimits {
    /// Largest sample (claimed `sampleSize`) that will be buffered.
    pub max_sample_bytes: usize,
    /// Most partial samples kept at once.
    pub max_pending_samples: usize,
    /// Upper bound on the bytes held by all partial samples together.
    pub max_total_bytes: usize,
    /// Most partial samples kept for one source GUID prefix.
    pub max_pending_per_source: usize,
    /// A partial sample that has not progressed while this many discovery
    /// fragments were fed to the reassembler is stale and is evicted first.
    pub stale_after_fragments: u64,
}

impl Default for ReassemblyLimits {
    fn default() -> Self {
        Self {
            max_sample_bytes: 64 * 1024,
            max_pending_samples: 16,
            max_total_bytes: 256 * 1024,
            max_pending_per_source: 4,
            stale_after_fragments: 1024,
        }
    }
}

/// Why a partial sample was evicted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvictionReason {
    /// Its source reached `max_pending_per_source`.
    SourceQuota,
    /// It had not progressed for `stale_after_fragments` fragments.
    Stale,
    /// The table was full (count or bytes) and it was the policy's victim.
    Pressure,
}

/// Why an incoming discovery fragment was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RejectReason {
    /// Zero sizes / start / count, or fragments beyond the sample's end.
    BadGeometry,
    /// `sampleSize` above `max_sample_bytes`.
    SampleTooLarge,
    /// The sample alone would exceed `max_total_bytes`.
    OverMemoryCap,
    /// Fewer fragment bytes than the header claims.
    ShortData,
    /// `sampleSize` / `fragmentSize` differ from the pending sample's.
    GeometryMismatch,
    /// Key-only flag differs from the pending sample's.
    KeyFlagMismatch,
    /// `max_pending_samples` / `max_pending_per_source` is 0.
    NoCapacity,
}

/// What happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FragmentEventKind {
    /// A partial sample was dropped from the table before completing.
    Evicted(EvictionReason),
    /// An incoming fragment was refused (the pending sample, if any, is kept).
    Rejected(RejectReason),
    /// A fragment overlapped received bytes with different content; the
    /// first copy was kept, the new bytes for those fragments ignored.
    ConflictingOverlap,
    /// A fragment carried an inline QoS parameter (the PID:
    /// `PID_STATUS_INFO` 0x0071 or `PID_KEY_HASH` 0x0070) whose value differs
    /// from the one already recorded for the sample. See the module docs for
    /// which value is used.
    ConflictingInlineQos(u16),
}

/// A discovery sample the reassembler could not (fully) take in. For
/// [`FragmentEventKind::Evicted`] the fields describe the evicted sample, for
/// the other kinds the incoming fragment's sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentEvent {
    pub kind: FragmentEventKind,
    pub topic: DiscoveryTopic,
    /// Source prefix the fragments came from (header / INFO_SRC).
    pub source: GuidPrefix,
    pub writer: EntityId,
    pub sn: u64,
    /// Fragments received so far (0 if the sample was never stored).
    pub received_fragments: u32,
    /// Fragments in the sample (0 if the geometry was unusable).
    pub total_fragments: u32,
}

/// Identity of a sample being reassembled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SampleKey {
    pub source: [u8; 12],
    pub writer: [u8; 4],
    pub sn: u64,
}

/// One DATA_FRAG's worth of fragments, already bounds-checked against its own
/// submessage by the caller.
pub(crate) struct FragIn<'a> {
    pub key: SampleKey,
    pub topic: DiscoveryTopic,
    pub start: u32,
    pub count: u16,
    pub frag_size: u16,
    pub sample_size: u32,
    pub data: &'a [u8],
    pub inline: InlineQos,
    pub key_only: bool,
}

/// Result of feeding one DATA_FRAG.
#[derive(Debug)]
pub(crate) enum FragOutcome {
    /// Stored; the sample is not complete yet.
    Pending,
    /// The sample is complete: its serialized payload, its inline QoS
    /// readings (see the module docs) and whether it is a key-only sample.
    Complete(Vec<u8>, InlineQos, bool),
    /// Refused (see the [`FragmentEvent`] pushed alongside).
    Rejected,
}

struct Pending {
    key: SampleKey,
    topic: DiscoveryTopic,
    sample_size: u32,
    frag_size: u16,
    nfrags: u32,
    got: u32,
    got_bytes: usize,
    buf: Vec<u8>,
    received: Vec<u64>,
    /// Inline QoS of the fragment that created the sample.
    inline: InlineQos,
    /// Inline QoS of the fragment that delivered fragment 1 (offset 0), once
    /// it arrived.
    head_inline: Option<InlineQos>,
    /// Zero-based fragment range `[first, last)` of the creating DATA_FRAG.
    creator_range: (usize, usize),
    key_only: bool,
    /// Creation order (monotonic).
    created: u64,
    /// Reassembler clock when a new fragment last arrived.
    last_progress: u64,
}

impl Pending {
    fn cost(&self) -> usize {
        self.buf.len() + self.received.len() * 8
    }

    fn has(&self, n: usize) -> bool {
        self.received[n / 64] & (1 << (n % 64)) != 0
    }
}

/// Stateful, bounded DATA_FRAG reassembler. See the module docs.
#[derive(Default)]
pub struct FragmentReassembler {
    limits: ReassemblyLimits,
    pending: Vec<Pending>,
    total: usize,
    /// Discovery fragments fed so far (the logical clock).
    clock: u64,
    created: u64,
    completed: u64,
    dropped: u64,
    evicted: u64,
    conflicts: u64,
}

impl FragmentReassembler {
    /// A reassembler with the given caps (`max_sample_bytes` is clamped to
    /// [`HARD_MAX_SAMPLE_BYTES`] and to `max_total_bytes`;
    /// `max_pending_samples` to [`HARD_MAX_PENDING_SAMPLES`];
    /// `max_pending_per_source` to `max_pending_samples`).
    pub fn new(limits: ReassemblyLimits) -> Self {
        let mut limits = limits;
        limits.max_sample_bytes = limits
            .max_sample_bytes
            .min(HARD_MAX_SAMPLE_BYTES)
            .min(limits.max_total_bytes);
        limits.max_pending_samples = limits.max_pending_samples.min(HARD_MAX_PENDING_SAMPLES);
        limits.max_pending_per_source = limits
            .max_pending_per_source
            .min(limits.max_pending_samples);
        Self {
            limits,
            ..Self::default()
        }
    }

    /// The effective limits.
    pub fn limits(&self) -> ReassemblyLimits {
        self.limits
    }

    /// Partial samples currently buffered.
    pub fn pending_samples(&self) -> usize {
        self.pending.len()
    }

    /// Bytes currently held by partial samples (always `<= max_total_bytes`).
    pub fn pending_bytes(&self) -> usize {
        self.total
    }

    /// Samples reassembled so far.
    pub fn completed(&self) -> u64 {
        self.completed
    }

    /// Fragments refused (bad geometry, over a cap, mismatching a pending
    /// sample).
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Partial samples evicted before completing.
    pub fn evicted(&self) -> u64 {
        self.evicted
    }

    /// Conflicting fragments: overlapping bytes with different content, or
    /// a different inline status / key hash (one count per parameter).
    pub fn conflicts(&self) -> u64 {
        self.conflicts
    }

    /// Forget all partial samples (not counted as evictions).
    pub fn clear(&mut self) {
        self.pending.clear();
        self.total = 0;
    }

    fn remove(&mut self, i: usize) -> Pending {
        let p = self.pending.swap_remove(i);
        self.total -= p.cost();
        p
    }

    fn event_for(p: &Pending, kind: FragmentEventKind) -> FragmentEvent {
        FragmentEvent {
            kind,
            topic: p.topic,
            source: p.key.source,
            writer: p.key.writer,
            sn: p.key.sn,
            received_fragments: p.got,
            total_fragments: p.nfrags,
        }
    }

    fn evict(&mut self, i: usize, why: EvictionReason, events: &mut Vec<FragmentEvent>) {
        let p = self.remove(i);
        self.evicted += 1;
        events.push(Self::event_for(&p, FragmentEventKind::Evicted(why)));
    }

    fn reject(
        &mut self,
        f: &FragIn<'_>,
        why: RejectReason,
        nfrags: u32,
        events: &mut Vec<FragmentEvent>,
    ) -> FragOutcome {
        self.dropped += 1;
        events.push(FragmentEvent {
            kind: FragmentEventKind::Rejected(why),
            topic: f.topic,
            source: f.key.source,
            writer: f.key.writer,
            sn: f.key.sn,
            received_fragments: 0,
            total_fragments: nfrags,
        });
        FragOutcome::Rejected
    }

    /// The victim under global pressure (policy steps 2 and 3).
    fn pressure_victim(&self) -> Option<(usize, EvictionReason)> {
        let stale = self
            .pending
            .iter()
            .enumerate()
            .filter(|(_, p)| self.clock - p.last_progress > self.limits.stale_after_fragments)
            .min_by_key(|(_, p)| (p.last_progress, p.created));
        if let Some((i, _)) = stale {
            return Some((i, EvictionReason::Stale));
        }
        let mut per_source: HashMap<[u8; 12], usize> = HashMap::new();
        for p in &self.pending {
            *per_source.entry(p.key.source).or_default() += 1;
        }
        let most = per_source.values().copied().max()?;
        self.pending
            .iter()
            .enumerate()
            .filter(|(_, p)| per_source[&p.key.source] == most)
            .min_by_key(|(_, p)| (p.got_bytes, std::cmp::Reverse(p.created)))
            .map(|(i, _)| (i, EvictionReason::Pressure))
    }

    /// Make room for a new sample of `cost` bytes from `source`.
    fn make_room(&mut self, source: [u8; 12], cost: usize, events: &mut Vec<FragmentEvent>) {
        // 1. Per-source quota: the source pays with its own least recently
        //    progressed sample.
        loop {
            let own: Vec<usize> = (0..self.pending.len())
                .filter(|&i| self.pending[i].key.source == source)
                .collect();
            if own.len() < self.limits.max_pending_per_source {
                break;
            }
            let Some(&i) = own.iter().min_by_key(|&&i| {
                let p = &self.pending[i];
                (p.last_progress, p.created)
            }) else {
                break;
            };
            self.evict(i, EvictionReason::SourceQuota, events);
        }
        // 2./3. Global caps.
        while self.pending.len() >= self.limits.max_pending_samples
            || self.total + cost > self.limits.max_total_bytes
        {
            let Some((i, why)) = self.pressure_victim() else {
                break;
            };
            self.evict(i, why, events);
        }
    }

    pub(crate) fn add(&mut self, f: FragIn<'_>, events: &mut Vec<FragmentEvent>) -> FragOutcome {
        self.clock += 1;
        let sample_size = f.sample_size as usize;
        let frag_size = f.frag_size as usize;
        if f.frag_size == 0 || f.sample_size == 0 || f.start == 0 || f.count == 0 {
            return self.reject(&f, RejectReason::BadGeometry, 0, events);
        }
        if sample_size > self.limits.max_sample_bytes {
            return self.reject(&f, RejectReason::SampleTooLarge, 0, events);
        }
        let nfrags = sample_size.div_ceil(frag_size);
        let nfrags32 = nfrags as u32; // <= sample_size <= 1 MiB
                                      // Zero-based, exclusive range; computed in u64 so it cannot overflow
                                      // on 32-bit targets either.
        let last64 = u64::from(f.start) - 1 + u64::from(f.count);
        if last64 > nfrags as u64 {
            return self.reject(&f, RejectReason::BadGeometry, nfrags32, events);
        }
        let first = f.start as usize - 1; // < nfrags, so it fits
        let last = last64 as usize;
        let offset = first * frag_size; // < sample_size since first < nfrags
        let want = (f.count as usize * frag_size).min(sample_size - offset);
        let Some(data) = f.data.get(..want) else {
            return self.reject(&f, RejectReason::ShortData, nfrags32, events);
        };

        let idx = match self.pending.iter().position(|p| p.key == f.key) {
            Some(i) => {
                let p = &self.pending[i];
                if p.sample_size != f.sample_size || p.frag_size != f.frag_size {
                    return self.reject(&f, RejectReason::GeometryMismatch, p.nfrags, events);
                }
                if p.key_only != f.key_only {
                    return self.reject(&f, RejectReason::KeyFlagMismatch, p.nfrags, events);
                }
                i
            }
            None if first == 0 && last == nfrags => {
                // The whole sample in one submessage: complete it without
                // touching the table, so it can neither evict nor be evicted.
                self.completed += 1;
                return FragOutcome::Complete(data.to_vec(), f.inline, f.key_only);
            }
            None => {
                if self.limits.max_pending_samples == 0 || self.limits.max_pending_per_source == 0 {
                    return self.reject(&f, RejectReason::NoCapacity, nfrags32, events);
                }
                let words = nfrags.div_ceil(64);
                let cost = sample_size + words * 8;
                if cost > self.limits.max_total_bytes {
                    return self.reject(&f, RejectReason::OverMemoryCap, nfrags32, events);
                }
                self.make_room(f.key.source, cost, events);
                // Bounded allocation: sample_size <= max_sample_bytes.
                self.created += 1;
                self.pending.push(Pending {
                    key: f.key,
                    topic: f.topic,
                    sample_size: f.sample_size,
                    frag_size: f.frag_size,
                    nfrags: nfrags32,
                    got: 0,
                    got_bytes: 0,
                    buf: vec![0; sample_size],
                    received: vec![0; words],
                    inline: f.inline,
                    head_inline: None,
                    creator_range: (first, last),
                    key_only: f.key_only,
                    created: self.created,
                    last_progress: self.clock,
                });
                self.total += cost;
                self.pending.len() - 1
            }
        };

        // First copy wins: fill only fragments not received yet, and note a
        // conflict if an already-received one differs.
        let clock = self.clock;
        let p = &mut self.pending[idx];
        let mut conflict = false;
        let mut progressed = false;
        let delivers_head = first == 0 && !p.has(0);
        for n in first..last {
            let lo = n * frag_size - offset;
            let hi = ((n + 1) * frag_size).min(sample_size) - offset;
            if p.has(n) {
                conflict |= data[lo..hi] != p.buf[offset + lo..offset + hi];
                continue;
            }
            p.buf[offset + lo..offset + hi].copy_from_slice(&data[lo..hi]);
            p.received[n / 64] |= 1 << (n % 64);
            p.got += 1;
            p.got_bytes += hi - lo;
            progressed = true;
        }
        if progressed {
            p.last_progress = clock;
        }
        // Inline QoS: compare against every value recorded so far (any
        // fragment, duplicates included), but only record it from the
        // creator (done above) or the fragment that delivered offset 0.
        let mut qos_conflicts: Vec<u16> = Vec::new();
        {
            // A copy of the creating fragment or of fragment 1 must repeat
            // its status exactly (absent = alive); other fragments only
            // conflict on a present, different value (stacks that send
            // inline QoS on fragment 1 only are honest).
            let strict_creator = (first, last) == p.creator_range;
            let strict_head = first == 0;
            let recorded = [
                (Some(&p.inline), strict_creator),
                (p.head_inline.as_ref(), strict_head),
            ];
            let (mut st, mut kh) = (false, false);
            for (r, strict) in recorded {
                let Some(r) = r else { continue };
                st |= match (f.inline.status, r.status) {
                    (Some(a), Some(b)) => a != b,
                    (a, b) if strict => a.unwrap_or_default() != b.unwrap_or_default(),
                    _ => false,
                };
                kh |= matches!((f.inline.key_hash, r.key_hash), (Some(a), Some(b)) if a != b);
            }
            if st {
                qos_conflicts.push(crate::wire::PID_STATUS_INFO);
            }
            if kh {
                qos_conflicts.push(crate::wire::PID_KEY_HASH);
            }
        }
        if delivers_head {
            p.head_inline = Some(f.inline);
        }
        if conflict {
            self.conflicts += 1;
            let ev = Self::event_for(&self.pending[idx], FragmentEventKind::ConflictingOverlap);
            events.push(ev);
        }
        for pid in qos_conflicts {
            self.conflicts += 1;
            let ev = Self::event_for(
                &self.pending[idx],
                FragmentEventKind::ConflictingInlineQos(pid),
            );
            events.push(ev);
        }
        if self.pending[idx].got == self.pending[idx].nfrags {
            let p = self.remove(idx);
            self.completed += 1;
            let inline = match p.head_inline {
                Some(h) => p.inline.with_reading(&h),
                None => p.inline,
            };
            return FragOutcome::Complete(p.buf, inline, p.key_only);
        }
        FragOutcome::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_from(source: [u8; 12], sn: u64) -> SampleKey {
        SampleKey {
            source,
            writer: [0, 0, 3, 0xc2],
            sn,
        }
    }

    fn frag_from<'a>(
        source: [u8; 12],
        sn: u64,
        start: u32,
        count: u16,
        fs: u16,
        size: u32,
        data: &'a [u8],
    ) -> FragIn<'a> {
        FragIn {
            key: key_from(source, sn),
            topic: DiscoveryTopic::Publications,
            start,
            count,
            frag_size: fs,
            sample_size: size,
            data,
            inline: InlineQos::default(),
            key_only: false,
        }
    }

    fn frag<'a>(sn: u64, start: u32, count: u16, fs: u16, size: u32, data: &'a [u8]) -> FragIn<'a> {
        frag_from([1; 12], sn, start, count, fs, size, data)
    }

    /// `add` with a throwaway event sink.
    fn add(r: &mut FragmentReassembler, f: FragIn<'_>) -> FragOutcome {
        r.add(f, &mut Vec::new())
    }

    fn sample(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 + 3) as u8).collect()
    }

    #[test]
    fn reassembles_in_and_out_of_order() {
        let s = sample(250);
        for order in [[0usize, 1, 2], [2, 0, 1], [1, 2, 0]] {
            let mut r = FragmentReassembler::new(ReassemblyLimits::default());
            let mut done = None;
            for (k, &i) in order.iter().enumerate() {
                let lo = i * 100;
                let hi = (lo + 100).min(250);
                match add(&mut r, frag(1, i as u32 + 1, 1, 100, 250, &s[lo..hi])) {
                    FragOutcome::Pending => assert!(k < 2),
                    FragOutcome::Complete(b, _, ko) => {
                        assert!(!ko);
                        done = Some(b)
                    }
                    FragOutcome::Rejected => panic!("rejected"),
                }
            }
            assert_eq!(done.as_deref(), Some(&s[..]));
            assert_eq!(r.pending_samples(), 0);
            assert_eq!(r.pending_bytes(), 0);
            assert_eq!(r.completed(), 1);
        }
    }

    #[test]
    fn multiple_fragments_per_submessage_and_trailing_padding() {
        let s = sample(10);
        let mut r = FragmentReassembler::new(ReassemblyLimits::default());
        let mut d = s[..8].to_vec();
        assert!(matches!(
            add(&mut r, frag(1, 1, 2, 4, 10, &d)),
            FragOutcome::Pending
        ));
        d = s[8..].to_vec();
        d.extend_from_slice(&[0, 0]); // submessage padding past the sample end
        match add(&mut r, frag(1, 3, 1, 4, 10, &d)) {
            FragOutcome::Complete(b, _, _) => assert_eq!(b, s),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn duplicate_fragment_is_idempotent() {
        let s = sample(8);
        let mut r = FragmentReassembler::new(ReassemblyLimits::default());
        let mut ev = Vec::new();
        assert!(matches!(
            r.add(frag(1, 1, 1, 4, 8, &s[..4]), &mut ev),
            FragOutcome::Pending
        ));
        assert!(matches!(
            r.add(frag(1, 1, 1, 4, 8, &s[..4]), &mut ev),
            FragOutcome::Pending
        ));
        assert!(matches!(
            r.add(frag(1, 2, 1, 4, 8, &s[4..]), &mut ev),
            FragOutcome::Complete(..)
        ));
        assert!(ev.is_empty());
        assert_eq!(r.conflicts(), 0);
    }

    #[test]
    fn conflicting_overlap_keeps_first_copy_and_reports_it() {
        let s = sample(8);
        let mut r = FragmentReassembler::new(ReassemblyLimits::default());
        let mut ev = Vec::new();
        assert!(matches!(
            r.add(frag(1, 1, 1, 4, 8, &s[..4]), &mut ev),
            FragOutcome::Pending
        ));
        assert!(matches!(
            r.add(frag(1, 1, 1, 4, 8, b"evil"), &mut ev),
            FragOutcome::Pending
        ));
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].kind, FragmentEventKind::ConflictingOverlap);
        assert_eq!(
            (ev[0].sn, ev[0].received_fragments, ev[0].total_fragments),
            (1, 1, 2)
        );
        assert_eq!(r.conflicts(), 1);
        assert_eq!(r.pending_samples(), 1);
        // A two-fragment submessage overlapping fragment 1 (conflicting) and
        // carrying the missing fragment 2: fragment 2 is still taken.
        let mut both = b"EVIL".to_vec();
        both.extend_from_slice(&s[4..]);
        match r.add(frag(1, 1, 2, 4, 8, &both), &mut ev) {
            FragOutcome::Complete(b, _, _) => assert_eq!(b, s, "first copy of fragment 1 kept"),
            other => panic!("{other:?}"),
        }
        assert_eq!(r.conflicts(), 2);
    }

    #[test]
    fn geometry_mismatch_refuses_the_fragment_not_the_sample() {
        let s = sample(8);
        let mut r = FragmentReassembler::new(ReassemblyLimits::default());
        let mut ev = Vec::new();
        assert!(matches!(
            r.add(frag(1, 1, 1, 4, 8, &s[..4]), &mut ev),
            FragOutcome::Pending
        ));
        assert!(matches!(
            r.add(frag(1, 2, 1, 4, 12, &s[4..]), &mut ev),
            FragOutcome::Rejected
        ));
        let mut ko = frag(1, 2, 1, 4, 8, &s[4..]);
        ko.key_only = true;
        assert!(matches!(r.add(ko, &mut ev), FragOutcome::Rejected));
        assert_eq!(
            ev.iter().map(|e| e.kind).collect::<Vec<_>>(),
            vec![
                FragmentEventKind::Rejected(RejectReason::GeometryMismatch),
                FragmentEventKind::Rejected(RejectReason::KeyFlagMismatch)
            ]
        );
        assert_eq!(r.pending_samples(), 1);
        assert!(matches!(
            r.add(frag(1, 2, 1, 4, 8, &s[4..]), &mut ev),
            FragOutcome::Complete(..)
        ));
    }

    #[test]
    fn hostile_geometry_is_rejected_without_allocation() {
        let mut r = FragmentReassembler::new(ReassemblyLimits::default());
        let d = [0u8; 16];
        let cases = [
            (frag(1, 0, 1, 4, 8, &d), RejectReason::BadGeometry), // start 0
            (frag(1, 1, 0, 4, 8, &d), RejectReason::BadGeometry), // count 0
            (frag(1, 1, 1, 0, 8, &d), RejectReason::BadGeometry), // frag size 0
            (frag(1, 1, 1, 4, 0, &d), RejectReason::BadGeometry), // sample size 0
            (frag(1, 3, 1, 4, 8, &d), RejectReason::BadGeometry), // beyond last fragment
            (
                frag(1, u32::MAX, u16::MAX, 4, 8, &d),
                RejectReason::BadGeometry,
            ), // overflow
            (frag(1, 1, 1, 4, u32::MAX, &d), RejectReason::SampleTooLarge), // 4 GiB claim
            (frag(1, 1, 2, 16, 32, &d), RejectReason::ShortData), // fewer bytes than claimed
        ];
        let mut ev = Vec::new();
        for (c, why) in cases {
            assert!(matches!(r.add(c, &mut ev), FragOutcome::Rejected));
            assert_eq!(ev.pop().unwrap().kind, FragmentEventKind::Rejected(why));
        }
        assert_eq!(r.pending_bytes(), 0);
        assert_eq!(r.dropped(), 8);
    }

    #[test]
    fn one_source_ages_out_its_own_oldest_and_memory_stays_bounded() {
        let limits = ReassemblyLimits {
            max_sample_bytes: 1000,
            max_pending_samples: 3,
            max_total_bytes: 2100,
            ..Default::default()
        };
        let mut r = FragmentReassembler::new(limits);
        assert_eq!(r.limits().max_pending_per_source, 3, "clamped");
        let d = [0u8; 100];
        let mut ev = Vec::new();
        for sn in 0..50u64 {
            assert!(matches!(
                r.add(frag(sn, 1, 1, 100, 1000, &d), &mut ev),
                FragOutcome::Pending
            ));
            assert!(r.pending_samples() <= 3);
            assert!(r.pending_bytes() <= 2100);
        }
        // 1000 + 8 per sample: only two fit under 2100 bytes.
        assert_eq!(r.pending_samples(), 2);
        assert_eq!(r.evicted(), 48);
        assert_eq!(ev.len(), 48);
        assert!(ev
            .iter()
            .all(|e| matches!(e.kind, FragmentEventKind::Evicted(_))));
        // The newest survives.
        assert!(r.pending.iter().any(|p| p.key.sn == 49));
        r.clear();
        assert_eq!(r.pending_bytes(), 0);
    }

    #[test]
    fn per_source_quota_evicts_only_that_source() {
        let mut r = FragmentReassembler::new(ReassemblyLimits::default());
        let mut ev = Vec::new();
        // A legitimate sample from source A.
        add(&mut r, frag_from([0xa; 12], 1, 1, 1, 4, 8, &[1; 4]));
        // 100 samples from one flooding source B.
        for sn in 0..100 {
            r.add(frag_from([0xb; 12], sn, 1, 1, 4, 8, &[2; 4]), &mut ev);
        }
        assert_eq!(r.pending_samples(), 5, "A + B's quota of 4");
        assert!(ev.iter().all(|e| e.kind
            == FragmentEventKind::Evicted(EvictionReason::SourceQuota)
            && e.source == [0xb; 12]));
        assert!(matches!(
            add(&mut r, frag_from([0xa; 12], 1, 2, 1, 4, 8, &[1; 4])),
            FragOutcome::Complete(..)
        ));
    }

    #[test]
    fn many_spoofed_sources_do_not_evict_an_older_sample() {
        let mut r = FragmentReassembler::new(ReassemblyLimits::default());
        let mut ev = Vec::new();
        add(&mut r, frag_from([0xa; 12], 1, 1, 1, 4, 8, &[1; 4]));
        for i in 0..1000u32 {
            let mut src = [0x55; 12];
            src[..4].copy_from_slice(&i.to_be_bytes());
            r.add(frag_from(src, 1, 1, 1, 4, 8, &[2; 4]), &mut ev);
            assert!(r.pending_samples() <= 16);
        }
        assert!(ev.iter().all(|e| e.source != [0xa; 12]));
        assert!(matches!(
            add(&mut r, frag_from([0xa; 12], 1, 2, 1, 4, 8, &[1; 4])),
            FragOutcome::Complete(..)
        ));
    }

    #[test]
    fn more_received_bytes_protect_against_lighter_junk() {
        let mut r = FragmentReassembler::new(ReassemblyLimits::default());
        let mut ev = Vec::new();
        // 15 junk samples first, then the legitimate one, then more junk: the
        // legitimate one is the newest but has more bytes in hand.
        let junk = |r: &mut FragmentReassembler, ev: &mut Vec<FragmentEvent>, i: u32| {
            let mut src = [0x55; 12];
            src[..4].copy_from_slice(&i.to_be_bytes());
            r.add(frag_from(src, 1, 1, 1, 4, 8, &[2; 4]), ev);
        };
        for i in 0..15 {
            junk(&mut r, &mut ev, i);
        }
        add(&mut r, frag_from([0xa; 12], 1, 1, 1, 100, 200, &[1; 100]));
        for i in 15..200 {
            junk(&mut r, &mut ev, i);
        }
        assert!(ev.iter().all(|e| e.source != [0xa; 12]));
        assert!(matches!(
            add(&mut r, frag_from([0xa; 12], 1, 2, 1, 100, 200, &[1; 100])),
            FragOutcome::Complete(..)
        ));
    }

    #[test]
    fn stale_samples_are_evicted_first() {
        let limits = ReassemblyLimits {
            stale_after_fragments: 10,
            ..Default::default()
        };
        let mut r = FragmentReassembler::new(limits);
        let mut ev = Vec::new();
        // 16 distinct sources fill the table; source 0 has the most bytes.
        add(&mut r, frag_from([0; 12], 1, 1, 1, 100, 200, &[1; 100]));
        for i in 1..16u8 {
            add(&mut r, frag_from([i; 12], 1, 1, 1, 4, 8, &[1; 4]));
        }
        // Duplicates are not progress: after 12 more fragments every sample
        // is stale, and the least recently progressed one (source 0, despite
        // holding the most bytes) goes first.
        for _ in 0..12 {
            add(&mut r, frag_from([1; 12], 1, 1, 1, 4, 8, &[1; 4]));
        }
        r.add(frag_from([0x77; 12], 1, 1, 1, 4, 8, &[3; 4]), &mut ev);
        assert_eq!(ev.len(), 1);
        assert_eq!(
            ev[0].kind,
            FragmentEventKind::Evicted(EvictionReason::Stale)
        );
        assert_eq!(ev[0].source, [0; 12]);
    }

    #[test]
    fn limits_are_clamped() {
        let r = FragmentReassembler::new(ReassemblyLimits {
            max_sample_bytes: usize::MAX,
            max_pending_samples: 4,
            max_total_bytes: 10_000,
            ..Default::default()
        });
        assert_eq!(r.limits().max_sample_bytes, 10_000);
        let r = FragmentReassembler::new(ReassemblyLimits {
            max_sample_bytes: usize::MAX,
            max_pending_samples: usize::MAX,
            max_total_bytes: usize::MAX,
            max_pending_per_source: usize::MAX,
            stale_after_fragments: 0,
        });
        assert_eq!(r.limits().max_sample_bytes, HARD_MAX_SAMPLE_BYTES);
        assert_eq!(r.limits().max_pending_samples, HARD_MAX_PENDING_SAMPLES);
        assert_eq!(r.limits().max_pending_per_source, HARD_MAX_PENDING_SAMPLES);
    }

    #[test]
    fn zero_pending_cap_never_stores() {
        for (total, per_source) in [(0, 4), (4, 0)] {
            let mut r = FragmentReassembler::new(ReassemblyLimits {
                max_sample_bytes: 100,
                max_pending_samples: total,
                max_total_bytes: 1000,
                max_pending_per_source: per_source,
                ..Default::default()
            });
            let mut ev = Vec::new();
            assert!(matches!(
                r.add(frag(1, 1, 1, 4, 8, &[0; 4]), &mut ev),
                FragOutcome::Rejected
            ));
            assert_eq!(
                ev[0].kind,
                FragmentEventKind::Rejected(RejectReason::NoCapacity)
            );
            assert_eq!(r.pending_samples(), 0);
        }
    }

    #[test]
    fn whole_sample_in_one_submessage_bypasses_the_table() {
        let s = sample(10);
        // Even with no capacity at all, and with a full table, a sample that
        // arrives whole completes and evicts nothing.
        let mut r = FragmentReassembler::new(ReassemblyLimits {
            max_pending_samples: 0,
            ..Default::default()
        });
        let mut ev = Vec::new();
        match r.add(frag(1, 1, 1, 10, 10, &s), &mut ev) {
            FragOutcome::Complete(b, _, _) => assert_eq!(b, s),
            other => panic!("{other:?}"),
        }
        // Several fragments of one sample in one submessage, plus padding.
        let mut padded = s.clone();
        padded.extend_from_slice(&[0; 3]);
        match r.add(frag(2, 1, 3, 4, 10, &padded), &mut ev) {
            FragOutcome::Complete(b, _, _) => assert_eq!(b, s),
            other => panic!("{other:?}"),
        }
        let mut r = FragmentReassembler::new(ReassemblyLimits::default());
        for i in 0..16u8 {
            add(&mut r, frag_from([i; 12], 1, 1, 1, 4, 8, &[1; 4]));
        }
        assert!(matches!(
            r.add(frag_from([0x99; 12], 1, 1, 1, 10, 10, &s), &mut ev),
            FragOutcome::Complete(..)
        ));
        assert!(ev.is_empty());
        assert_eq!(r.pending_samples(), 16);
        assert_eq!(r.evicted(), 0);
    }

    #[test]
    fn distinct_keys_do_not_mix() {
        let s = sample(8);
        let mut r = FragmentReassembler::new(ReassemblyLimits::default());
        assert!(matches!(
            add(&mut r, frag(1, 1, 1, 4, 8, &s[..4])),
            FragOutcome::Pending
        ));
        assert!(matches!(
            add(&mut r, frag(2, 2, 1, 4, 8, &s[4..])),
            FragOutcome::Pending
        ));
        assert_eq!(r.pending_samples(), 2);
    }
}
