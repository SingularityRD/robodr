//! Bounded IPv4 / IPv6 fragment reassembly.
//!
//! Why bother: an SEDP announcement with large QoS / type information can
//! exceed the link MTU and be IP-fragmented, and fragmenting a discovery
//! packet on purpose is the cheapest way to hide it from a sensor that ignores
//! fragments. So the capture pipeline reassembles, under hard limits:
//!
//! - at most [`ReassemblyLimits::max_datagrams`] datagrams in flight (oldest
//!   evicted first),
//! - at most [`ReassemblyLimits::max_bytes`] buffered across all of them,
//! - a datagram is abandoned [`ReassemblyLimits::timeout`] after its first
//!   fragment, measured on *capture* timestamps (so replaying a file behaves
//!   the same as live capture),
//! - no datagram may exceed 65 535 bytes of payload.
//!
//! Overlap policy: fragments that overlap with **different** bytes poison the
//! whole datagram, which is then dropped (RFC 5722 mandates this for IPv6;
//! for IPv4 it defeats the classic overlap-based IDS evasion where the
//! receiver and the sensor resolve the overlap differently). Exact duplicates
//! are tolerated. Non-final fragments whose length is not a multiple of 8, or
//! fragments past a known end, also poison the datagram. Poisoned datagrams
//! keep a small tombstone until their timeout so late fragments stay dropped.
//!
//! Drops are counted in [`ReassemblyStats`]; a non-zero `dropped_overlap` is
//! itself worth surfacing as suspicious.

use std::net::IpAddr;
use std::time::Duration;

use crate::decode::IpFragment;

/// Largest reassembled payload (IPv4 total length / IPv6 payload length max).
pub const MAX_DATAGRAM: usize = 65_535;

/// Resource bounds for [`Reassembler`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReassemblyLimits {
    pub max_datagrams: usize,
    pub max_bytes: usize,
    pub timeout: Duration,
}

impl Default for ReassemblyLimits {
    /// 64 datagrams, 1 MiB, 30 s (the Linux `ipfrag_time` default).
    fn default() -> Self {
        Self {
            max_datagrams: 64,
            max_bytes: 1 << 20,
            timeout: Duration::from_secs(30),
        }
    }
}

/// Counters kept by the reassembler.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReassemblyStats {
    pub fragments: u64,
    pub completed: u64,
    /// Datagrams dropped because fragments overlapped with conflicting bytes.
    pub dropped_overlap: u64,
    /// Datagrams dropped for inconsistent fragment geometry.
    pub dropped_invalid: u64,
    /// Datagrams that did not complete within the timeout.
    pub dropped_timeout: u64,
    /// Datagrams evicted to stay within `max_datagrams` / `max_bytes`.
    pub dropped_capacity: u64,
    /// Fragments ignored because their datagram was already poisoned.
    pub ignored_after_drop: u64,
}

/// A reassembled IP payload (UDP header and data, possibly preceded by IPv6
/// extension headers when `protocol` is not UDP).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reassembled {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Key {
    src: IpAddr,
    dst: IpAddr,
    id: u32,
    protocol: u8,
}

#[derive(Debug)]
struct Entry {
    key: Key,
    first_seen: Duration,
    data: Vec<u8>,
    /// Sorted, non-overlapping, non-adjacent covered byte ranges [start, end).
    have: Vec<(usize, usize)>,
    total: Option<usize>,
    poisoned: bool,
}

/// Bounded fragment reassembler. Feed it every [`IpFragment`] with its capture
/// timestamp; it returns the payload when a datagram completes.
#[derive(Debug)]
pub struct Reassembler {
    limits: ReassemblyLimits,
    entries: Vec<Entry>,
    now: Duration,
    stats: ReassemblyStats,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new(ReassemblyLimits::default())
    }
}

enum Verdict {
    Ok,
    Overlap,
    Invalid,
}

impl Reassembler {
    pub fn new(limits: ReassemblyLimits) -> Self {
        Self {
            limits,
            entries: Vec::new(),
            now: Duration::ZERO,
            stats: ReassemblyStats::default(),
        }
    }

    pub fn stats(&self) -> &ReassemblyStats {
        &self.stats
    }

    /// Number of datagrams currently buffered (including tombstones).
    pub fn in_flight(&self) -> usize {
        self.entries.len()
    }

    fn buffered_bytes(&self) -> usize {
        self.entries.iter().map(|e| e.data.len()).sum()
    }

    fn expire(&mut self) {
        let (now, timeout) = (self.now, self.limits.timeout);
        let stats = &mut self.stats;
        self.entries.retain(|e| {
            let alive = e.first_seen.saturating_add(timeout) >= now;
            if !alive && !e.poisoned {
                stats.dropped_timeout += 1;
            }
            alive
        });
    }

    fn evict_oldest(&mut self) -> bool {
        let Some(idx) = self
            .entries
            .iter()
            .enumerate()
            .min_by_key(|(_, e)| e.first_seen)
            .map(|(i, _)| i)
        else {
            return false;
        };
        let e = self.entries.swap_remove(idx);
        if !e.poisoned {
            self.stats.dropped_capacity += 1;
        }
        true
    }

    /// Add one fragment. Returns the reassembled payload when this fragment
    /// completes its datagram.
    pub fn push(&mut self, ts: Duration, frag: &IpFragment<'_>) -> Option<Reassembled> {
        self.stats.fragments += 1;
        self.now = self.now.max(ts);
        self.expire();

        let key = Key {
            src: frag.src,
            dst: frag.dst,
            id: frag.id,
            protocol: frag.protocol,
        };
        let mut idx = match self.entries.iter().position(|e| e.key == key) {
            Some(i) => i,
            None => {
                if self.limits.max_datagrams == 0 {
                    self.stats.dropped_capacity += 1;
                    return None;
                }
                while self.entries.len() >= self.limits.max_datagrams {
                    self.evict_oldest();
                }
                self.entries.push(Entry {
                    key,
                    first_seen: self.now,
                    data: Vec::new(),
                    have: Vec::new(),
                    total: None,
                    poisoned: false,
                });
                self.entries.len() - 1
            }
        };

        if self.entries[idx].poisoned {
            self.stats.ignored_after_drop += 1;
            return None;
        }

        match Self::insert(&mut self.entries[idx], frag) {
            Verdict::Ok => {}
            Verdict::Overlap => {
                self.stats.dropped_overlap += 1;
                Self::poison(&mut self.entries[idx]);
                return None;
            }
            Verdict::Invalid => {
                self.stats.dropped_invalid += 1;
                Self::poison(&mut self.entries[idx]);
                return None;
            }
        }

        // Byte budget: evict other datagrams (oldest first) until we fit; if
        // this datagram alone is over budget, drop it.
        while self.buffered_bytes() > self.limits.max_bytes {
            if self.entries[idx].data.len() > self.limits.max_bytes {
                self.stats.dropped_capacity += 1;
                self.entries.swap_remove(idx);
                return None;
            }
            let victim = self
                .entries
                .iter()
                .enumerate()
                .filter(|&(i, _)| i != idx)
                .min_by_key(|(_, e)| e.first_seen)
                .map(|(i, _)| i);
            match victim {
                Some(v) => {
                    let e = self.entries.swap_remove(v);
                    if !e.poisoned {
                        self.stats.dropped_capacity += 1;
                    }
                    // swap_remove moved the last entry into `v`.
                    if idx == self.entries.len() {
                        idx = v;
                    }
                }
                None => break,
            }
        }
        self.finish_if_complete(idx)
    }

    fn finish_if_complete(&mut self, idx: usize) -> Option<Reassembled> {
        let e = &self.entries[idx];
        let total = e.total?;
        if e.have.as_slice() != [(0, total)] {
            return None;
        }
        let mut e = self.entries.swap_remove(idx);
        e.data.truncate(total);
        self.stats.completed += 1;
        Some(Reassembled {
            src: e.key.src,
            dst: e.key.dst,
            protocol: e.key.protocol,
            payload: e.data,
        })
    }

    fn poison(e: &mut Entry) {
        e.poisoned = true;
        e.data = Vec::new();
        e.have = Vec::new();
    }

    fn insert(e: &mut Entry, frag: &IpFragment<'_>) -> Verdict {
        let start = frag.offset;
        let Some(end) = start.checked_add(frag.data.len()) else {
            return Verdict::Invalid;
        };
        if end > MAX_DATAGRAM || !start.is_multiple_of(8) {
            return Verdict::Invalid;
        }
        if frag.more {
            if frag.data.is_empty() || !frag.data.len().is_multiple_of(8) {
                return Verdict::Invalid;
            }
            if e.total.is_some_and(|t| end > t) {
                return Verdict::Invalid;
            }
        } else {
            if e.total.is_some_and(|t| t != end) {
                return Verdict::Invalid;
            }
            if e.have.last().is_some_and(|&(_, hi)| hi > end) {
                return Verdict::Invalid;
            }
            e.total = Some(end);
        }

        // Overlap check against already-held bytes.
        for &(lo, hi) in &e.have {
            let (os, oe) = (lo.max(start), hi.min(end));
            if os < oe && e.data[os..oe] != frag.data[os - start..oe - start] {
                return Verdict::Overlap;
            }
        }

        if e.data.len() < end {
            e.data.resize(end, 0);
        }
        e.data[start..end].copy_from_slice(frag.data);

        // Merge [start, end) into the sorted interval list.
        let mut merged = Vec::with_capacity(e.have.len() + 1);
        let (mut ns, mut ne) = (start, end);
        let mut placed = false;
        for &(lo, hi) in &e.have {
            if hi < ns {
                merged.push((lo, hi));
            } else if lo > ne {
                if !placed {
                    merged.push((ns, ne));
                    placed = true;
                }
                merged.push((lo, hi));
            } else {
                ns = ns.min(lo);
                ne = ne.max(hi);
            }
        }
        if !placed {
            merged.push((ns, ne));
        }
        e.have = merged;
        Verdict::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    fn frag(id: u32, offset: usize, more: bool, data: &[u8]) -> IpFragment<'_> {
        IpFragment {
            src: ip(1),
            dst: ip(2),
            id,
            protocol: 17,
            offset,
            more,
            data,
        }
    }

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    #[test]
    fn in_order_and_out_of_order() {
        let payload: Vec<u8> = (0..40u8).collect();
        for order in [[0usize, 1, 2], [2, 0, 1], [1, 2, 0], [2, 1, 0]] {
            let mut r = Reassembler::default();
            let parts = [
                frag(7, 0, true, &payload[0..16]),
                frag(7, 16, true, &payload[16..32]),
                frag(7, 32, false, &payload[32..40]),
            ];
            let mut out = None;
            for (n, &i) in order.iter().enumerate() {
                let got = r.push(secs(1), &parts[i]);
                if n < 2 {
                    assert!(got.is_none());
                } else {
                    out = got;
                }
            }
            let out = out.expect("complete");
            assert_eq!(out.payload, payload);
            assert_eq!(out.protocol, 17);
            assert_eq!(r.in_flight(), 0);
            assert_eq!(r.stats().completed, 1);
        }
    }

    #[test]
    fn duplicates_are_tolerated() {
        let mut r = Reassembler::default();
        let d = [1u8; 16];
        assert!(r.push(secs(0), &frag(1, 0, true, &d[..8])).is_none());
        assert!(r.push(secs(0), &frag(1, 0, true, &d[..8])).is_none());
        assert!(r.push(secs(0), &frag(1, 8, false, &d[8..])).is_some());
    }

    #[test]
    fn conflicting_overlap_poisons() {
        let mut r = Reassembler::default();
        assert!(r.push(secs(0), &frag(1, 0, true, &[1; 16])).is_none());
        assert!(r.push(secs(0), &frag(1, 8, false, &[2; 16])).is_none());
        assert_eq!(r.stats().dropped_overlap, 1);
        // Later fragments of the same datagram stay dropped.
        assert!(r.push(secs(0), &frag(1, 16, false, &[1; 8])).is_none());
        assert_eq!(r.stats().ignored_after_drop, 1);
        assert_eq!(r.stats().completed, 0);
    }

    #[test]
    fn invalid_geometry() {
        let mut r = Reassembler::default();
        // Non-final fragment of odd length.
        r.push(secs(0), &frag(1, 0, true, &[0; 7]));
        // Final fragment shorter than data already held.
        r.push(secs(0), &frag(2, 0, true, &[0; 16]));
        r.push(secs(0), &frag(2, 0, false, &[0; 8]));
        // Two different ends.
        r.push(secs(0), &frag(3, 8, false, &[0; 8]));
        r.push(secs(0), &frag(3, 16, false, &[0; 8]));
        // Past 64 KiB.
        r.push(secs(0), &frag(4, 65_528, true, &[0; 16]));
        // Non-final after a known end.
        r.push(secs(0), &frag(5, 0, false, &[0; 8]));
        let mut r2 = Reassembler::default();
        r2.push(secs(0), &frag(5, 8, false, &[0; 8]));
        r2.push(secs(0), &frag(5, 8, true, &[0; 16]));
        assert_eq!(r.stats().dropped_invalid, 4);
        assert_eq!(r2.stats().dropped_invalid, 1);
        // Unfragmented-looking (offset 0, final) completes immediately.
        assert_eq!(r.stats().completed, 1);
    }

    #[test]
    fn timeout_uses_capture_time() {
        let mut r = Reassembler::default();
        r.push(secs(100), &frag(1, 0, true, &[0; 8]));
        assert_eq!(r.in_flight(), 1);
        // 31 s later another datagram arrives: the first one expires.
        r.push(secs(131), &frag(2, 0, true, &[0; 8]));
        assert_eq!(r.stats().dropped_timeout, 1);
        assert!(r.push(secs(131), &frag(1, 8, false, &[0; 8])).is_none());
        // Timestamps going backwards do not resurrect anything or panic.
        r.push(secs(5), &frag(3, 0, true, &[0; 8]));
    }

    #[test]
    fn datagram_count_is_bounded() {
        let mut r = Reassembler::new(ReassemblyLimits {
            max_datagrams: 4,
            ..Default::default()
        });
        for id in 0..100 {
            r.push(secs(u64::from(id)), &frag(id, 0, true, &[0; 8]));
            assert!(r.in_flight() <= 4);
        }
        assert_eq!(r.stats().dropped_capacity, 96);
        // The most recent ones survive and can complete.
        assert!(r.push(secs(100), &frag(99, 8, false, &[0; 8])).is_some());
    }

    #[test]
    fn byte_budget_is_bounded() {
        let mut r = Reassembler::new(ReassemblyLimits {
            max_bytes: 4096,
            ..Default::default()
        });
        let big = vec![0u8; 2048];
        for id in 0..10 {
            r.push(secs(1), &frag(id, 0, true, &big));
            assert!(r.buffered_bytes() <= 4096);
        }
        // A single datagram over budget is dropped outright.
        let huge = vec![0u8; 8192];
        r.push(secs(1), &frag(99, 0, true, &huge));
        assert!(r.buffered_bytes() <= 4096);
        assert!(r.stats().dropped_capacity >= 9);
        // Zero capacity never panics.
        let mut z = Reassembler::new(ReassemblyLimits {
            max_datagrams: 0,
            ..Default::default()
        });
        assert!(z.push(secs(0), &frag(1, 0, false, &[0; 8])).is_none());
    }

    #[test]
    fn eviction_keeping_current_entry_completes() {
        // Budget evicts an older entry while the current one completes.
        let mut r = Reassembler::new(ReassemblyLimits {
            max_bytes: 64,
            ..Default::default()
        });
        r.push(secs(0), &frag(1, 0, true, &[0; 32]));
        r.push(secs(1), &frag(2, 0, true, &[1; 32]));
        let out = r.push(secs(2), &frag(2, 32, false, &[1; 8]));
        assert_eq!(out.map(|o| o.payload.len()), Some(40));
    }
}
