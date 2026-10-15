//! Bounded DATA_FRAG reassembly for discovery samples.
//!
//! Large SEDP announcements (e.g. with XTypes TypeInformation / TypeObject)
//! exceed one UDP datagram and are sent as DATA_FRAG submessages by Fast DDS
//! and Connext. The stateless [`crate::parse_datagram`] only *counts* them
//! (see [`crate::ParseStats::discovery_data_frag`]). A sensor that wants those
//! endpoints keeps one [`FragmentReassembler`] per capture and feeds every
//! datagram through it.
//!
//! # Memory bounds
//!
//! Only fragments from builtin discovery writers (SPDP / SEDP) are buffered;
//! user-data fragments are never stored. Every buffer is capped by
//! [`ReassemblyLimits`]:
//!
//! - a sample whose claimed `sampleSize` exceeds `max_sample_bytes` is refused
//!   before anything is allocated;
//! - at most `max_pending_samples` partial samples are kept, and their total
//!   footprint (buffer + received-fragment bitmap) never exceeds
//!   `max_total_bytes`; when a new sample would break either cap, the *oldest*
//!   partial samples are evicted first.
//!
//! So the worst case an attacker can force is `max_total_bytes` of memory.
//! What an attacker *can* do is flood partial samples to evict legitimate
//! ones: that costs visibility of fragmented announcements, never memory or
//! a panic, and is visible in [`FragmentReassembler::evicted`] /
//! [`FragmentReassembler::dropped`].
//!
//! Overlapping retransmissions are accepted only if the overlapping bytes are
//! identical; a conflicting overlap drops the whole sample (it means somebody
//! is splicing content into another participant's announcement).
//!
//! There is no time-based expiry, because the crate is pure (no clock); stale
//! partial samples age out through the count / byte caps.

use crate::parse::InlineQos;

/// Hard ceiling on `max_sample_bytes`, whatever the caller configures.
pub const HARD_MAX_SAMPLE_BYTES: usize = 1 << 20;

/// Caps for [`FragmentReassembler`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReassemblyLimits {
    /// Largest sample (claimed `sampleSize`) that will be buffered.
    pub max_sample_bytes: usize,
    /// Most partial samples kept at once.
    pub max_pending_samples: usize,
    /// Upper bound on the bytes held by all partial samples together.
    pub max_total_bytes: usize,
}

impl Default for ReassemblyLimits {
    fn default() -> Self {
        Self {
            max_sample_bytes: 64 * 1024,
            max_pending_samples: 16,
            max_total_bytes: 256 * 1024,
        }
    }
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
    /// The sample is complete: its serialized payload, merged inline QoS and
    /// whether it is a key-only sample.
    Complete(Vec<u8>, InlineQos, bool),
    /// Refused (bad geometry, over a cap, conflicting overlap).
    Rejected,
}

struct Pending {
    key: SampleKey,
    sample_size: u32,
    frag_size: u16,
    nfrags: u32,
    got: u32,
    buf: Vec<u8>,
    received: Vec<u64>,
    inline: InlineQos,
    key_only: bool,
}

impl Pending {
    fn cost(&self) -> usize {
        self.buf.len() + self.received.len() * 8
    }
}

/// Stateful, bounded DATA_FRAG reassembler. See the module docs.
#[derive(Default)]
pub struct FragmentReassembler {
    limits: ReassemblyLimits,
    /// Oldest first.
    pending: Vec<Pending>,
    total: usize,
    completed: u64,
    dropped: u64,
    evicted: u64,
}

impl FragmentReassembler {
    /// A reassembler with the given caps (`max_sample_bytes` is clamped to
    /// [`HARD_MAX_SAMPLE_BYTES`], and to `max_total_bytes`).
    pub fn new(limits: ReassemblyLimits) -> Self {
        let mut limits = limits;
        limits.max_sample_bytes = limits
            .max_sample_bytes
            .min(HARD_MAX_SAMPLE_BYTES)
            .min(limits.max_total_bytes);
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

    /// Fragments refused (bad geometry, over a cap, conflicting overlap).
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Partial samples evicted to make room for newer ones.
    pub fn evicted(&self) -> u64 {
        self.evicted
    }

    /// Forget all partial samples.
    pub fn clear(&mut self) {
        self.pending.clear();
        self.total = 0;
    }

    fn remove(&mut self, i: usize) -> Pending {
        let p = self.pending.remove(i);
        self.total -= p.cost();
        p
    }

    fn reject(&mut self) -> FragOutcome {
        self.dropped += 1;
        FragOutcome::Rejected
    }

    pub(crate) fn add(&mut self, f: FragIn<'_>) -> FragOutcome {
        let sample_size = f.sample_size as usize;
        let frag_size = f.frag_size as usize;
        if f.frag_size == 0
            || f.sample_size == 0
            || f.start == 0
            || f.count == 0
            || sample_size > self.limits.max_sample_bytes
        {
            return self.reject();
        }
        let nfrags = sample_size.div_ceil(frag_size);
        // Zero-based, exclusive range; computed in u64 so it cannot overflow
        // on 32-bit targets either.
        let last64 = u64::from(f.start) - 1 + u64::from(f.count);
        if last64 > nfrags as u64 {
            return self.reject();
        }
        let first = f.start as usize - 1; // < nfrags, so it fits
        let last = last64 as usize;
        let offset = first * frag_size; // < sample_size since first < nfrags
        let want = (f.count as usize * frag_size).min(sample_size - offset);
        let Some(data) = f.data.get(..want) else {
            return self.reject(); // fewer bytes than the header claims
        };

        let idx = match self.pending.iter().position(|p| p.key == f.key) {
            Some(i) => {
                let p = &self.pending[i];
                if p.sample_size != f.sample_size || p.frag_size != f.frag_size {
                    self.remove(i);
                    return self.reject();
                }
                i
            }
            None => {
                let words = nfrags.div_ceil(64);
                let cost = sample_size + words * 8;
                if cost > self.limits.max_total_bytes {
                    return self.reject();
                }
                while !self.pending.is_empty()
                    && (self.pending.len() >= self.limits.max_pending_samples
                        || self.total + cost > self.limits.max_total_bytes)
                {
                    self.remove(0);
                    self.evicted += 1;
                }
                if self.limits.max_pending_samples == 0 {
                    return self.reject();
                }
                // Bounded allocation: sample_size <= max_sample_bytes.
                self.pending.push(Pending {
                    key: f.key,
                    sample_size: f.sample_size,
                    frag_size: f.frag_size,
                    nfrags: nfrags as u32,
                    got: 0,
                    buf: vec![0; sample_size],
                    received: vec![0; words],
                    inline: InlineQos::default(),
                    key_only: f.key_only,
                });
                self.total += cost;
                self.pending.len() - 1
            }
        };

        // Overlap check before mutating anything.
        let p = &self.pending[idx];
        let conflict = (first..last).any(|n| {
            if p.received[n / 64] & (1 << (n % 64)) == 0 {
                return false;
            }
            let lo = n * frag_size - offset;
            let hi = ((n + 1) * frag_size).min(sample_size) - offset;
            data[lo..hi] != p.buf[offset + lo..offset + hi]
        });
        if conflict || p.key_only != f.key_only {
            self.remove(idx);
            return self.reject();
        }

        let p = &mut self.pending[idx];
        p.buf[offset..offset + want].copy_from_slice(data);
        for n in first..last {
            let bit = 1u64 << (n % 64);
            if p.received[n / 64] & bit == 0 {
                p.received[n / 64] |= bit;
                p.got += 1;
            }
        }
        p.inline.merge(&f.inline);
        if p.got == p.nfrags {
            let p = self.remove(idx);
            self.completed += 1;
            return FragOutcome::Complete(p.buf, p.inline, p.key_only);
        }
        FragOutcome::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(sn: u64) -> SampleKey {
        SampleKey {
            source: [1; 12],
            writer: [0, 0, 3, 0xc2],
            sn,
        }
    }

    fn frag<'a>(sn: u64, start: u32, count: u16, fs: u16, size: u32, data: &'a [u8]) -> FragIn<'a> {
        FragIn {
            key: key(sn),
            start,
            count,
            frag_size: fs,
            sample_size: size,
            data,
            inline: InlineQos::default(),
            key_only: false,
        }
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
                match r.add(frag(1, i as u32 + 1, 1, 100, 250, &s[lo..hi])) {
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
            r.add(frag(1, 1, 2, 4, 10, &d)),
            FragOutcome::Pending
        ));
        d = s[8..].to_vec();
        d.extend_from_slice(&[0, 0]); // submessage padding past the sample end
        match r.add(frag(1, 3, 1, 4, 10, &d)) {
            FragOutcome::Complete(b, _, _) => assert_eq!(b, s),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn duplicate_fragment_is_idempotent() {
        let s = sample(8);
        let mut r = FragmentReassembler::new(ReassemblyLimits::default());
        assert!(matches!(
            r.add(frag(1, 1, 1, 4, 8, &s[..4])),
            FragOutcome::Pending
        ));
        assert!(matches!(
            r.add(frag(1, 1, 1, 4, 8, &s[..4])),
            FragOutcome::Pending
        ));
        assert!(matches!(
            r.add(frag(1, 2, 1, 4, 8, &s[4..])),
            FragOutcome::Complete(..)
        ));
    }

    #[test]
    fn conflicting_overlap_drops_sample() {
        let s = sample(8);
        let mut r = FragmentReassembler::new(ReassemblyLimits::default());
        assert!(matches!(
            r.add(frag(1, 1, 1, 4, 8, &s[..4])),
            FragOutcome::Pending
        ));
        assert!(matches!(
            r.add(frag(1, 1, 1, 4, 8, b"evil")),
            FragOutcome::Rejected
        ));
        assert_eq!(r.pending_samples(), 0);
        assert_eq!(r.pending_bytes(), 0);
    }

    #[test]
    fn geometry_mismatch_drops_sample() {
        let s = sample(8);
        let mut r = FragmentReassembler::new(ReassemblyLimits::default());
        assert!(matches!(
            r.add(frag(1, 1, 1, 4, 8, &s[..4])),
            FragOutcome::Pending
        ));
        assert!(matches!(
            r.add(frag(1, 2, 1, 4, 12, &s[4..])),
            FragOutcome::Rejected
        ));
        assert_eq!(r.pending_samples(), 0);
    }

    #[test]
    fn hostile_geometry_is_rejected_without_allocation() {
        let mut r = FragmentReassembler::new(ReassemblyLimits::default());
        let d = [0u8; 16];
        let cases = [
            frag(1, 0, 1, 4, 8, &d),               // start 0
            frag(1, 1, 0, 4, 8, &d),               // count 0
            frag(1, 1, 1, 0, 8, &d),               // frag size 0
            frag(1, 1, 1, 4, 0, &d),               // sample size 0
            frag(1, 3, 1, 4, 8, &d),               // beyond last fragment
            frag(1, u32::MAX, u16::MAX, 4, 8, &d), // overflow attempt
            frag(1, 1, 1, 4, u32::MAX, &d),        // 4 GiB claim
            frag(1, 1, 2, 16, 32, &d),             // fewer bytes than claimed
        ];
        for c in cases {
            assert!(matches!(r.add(c), FragOutcome::Rejected));
        }
        assert_eq!(r.pending_bytes(), 0);
        assert_eq!(r.dropped(), 8);
    }

    #[test]
    fn caps_evict_oldest_and_bound_memory() {
        let limits = ReassemblyLimits {
            max_sample_bytes: 1000,
            max_pending_samples: 3,
            max_total_bytes: 2100,
        };
        let mut r = FragmentReassembler::new(limits);
        let d = [0u8; 100];
        for sn in 0..50u64 {
            assert!(matches!(
                r.add(frag(sn, 1, 1, 100, 1000, &d)),
                FragOutcome::Pending
            ));
            assert!(r.pending_samples() <= 3);
            assert!(r.pending_bytes() <= 2100);
        }
        // 1000 + 8 per sample: only two fit under 2100 bytes.
        assert_eq!(r.pending_samples(), 2);
        assert_eq!(r.evicted(), 48);
        // The newest survive.
        assert!(r.pending.iter().any(|p| p.key.sn == 49));
        r.clear();
        assert_eq!(r.pending_bytes(), 0);
    }

    #[test]
    fn limits_are_clamped() {
        let r = FragmentReassembler::new(ReassemblyLimits {
            max_sample_bytes: usize::MAX,
            max_pending_samples: 4,
            max_total_bytes: 10_000,
        });
        assert_eq!(r.limits().max_sample_bytes, 10_000);
        let r = FragmentReassembler::new(ReassemblyLimits {
            max_sample_bytes: usize::MAX,
            max_pending_samples: 4,
            max_total_bytes: usize::MAX,
        });
        assert_eq!(r.limits().max_sample_bytes, HARD_MAX_SAMPLE_BYTES);
    }

    #[test]
    fn zero_pending_cap_never_stores() {
        let mut r = FragmentReassembler::new(ReassemblyLimits {
            max_sample_bytes: 100,
            max_pending_samples: 0,
            max_total_bytes: 1000,
        });
        assert!(matches!(
            r.add(frag(1, 1, 1, 4, 8, &[0; 4])),
            FragOutcome::Rejected
        ));
        assert_eq!(r.pending_samples(), 0);
    }

    #[test]
    fn distinct_keys_do_not_mix() {
        let s = sample(8);
        let mut r = FragmentReassembler::new(ReassemblyLimits::default());
        assert!(matches!(
            r.add(frag(1, 1, 1, 4, 8, &s[..4])),
            FragOutcome::Pending
        ));
        assert!(matches!(
            r.add(frag(2, 2, 1, 4, 8, &s[4..])),
            FragOutcome::Pending
        ));
        assert_eq!(r.pending_samples(), 2);
    }
}
