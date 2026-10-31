//! Bounded IPv4 / IPv6 fragment reassembly that follows the Linux kernel.
//!
//! Why bother: an SEDP announcement with large QoS / type information can
//! exceed the link MTU and be IP-fragmented, and fragmenting a discovery
//! packet on purpose is the cheapest way to hide it from a sensor that ignores
//! fragments. Worse, any place where the sensor reassembles *differently*
//! from the robot's own kernel is an evasion: the attacker arranges for the
//! kernel to deliver a datagram the sensor drops (or the reverse, to frame a
//! peer). So this reassembler mirrors the Linux `inet_frag` /
//! `ip_frag_queue` / `ip6_frag_queue` logic (kernels >= 5.x). The rules below
//! were derived from the kernel source; they have **not** been replayed
//! against a live kernel in this repository's tests.
//!
//! - **Duplicates: first wins.** A fragment that lies entirely inside a
//!   "run" of already-queued contiguous fragments is ignored *without
//!   comparing bytes* (`IPFRAG_DUP`). If its bytes differ, that is counted in
//!   [`ReassemblyStats::duplicate_conflicts`] (an overlap-evasion attempt)
//!   but the datagram keeps the first copy, exactly as the kernel does.
//!   Forged first copies are kept out by the capture pipeline, which drops
//!   IPv4 fragments with a bad header checksum *before* reassembly (the
//!   kernel never queues those) and verifies the UDP checksum of the
//!   reassembled datagram (as the receiving socket layer does).
//! - **Ingress.** [`Reassembler::push_with_ingress`] also tracks the
//!   interface every *queued* fragment arrived on and reports the merge
//!   ([`IngressInfo::merge_fragment`]): if any fragment of a datagram came in
//!   on a non-loopback interface, so did the datagram. Ignored duplicates do
//!   not contribute (their bytes are not used either). A restart
//!   (`max_dist`) forgets the dropped fragments' ingress with their bytes.
//! - **Partial overlaps kill the datagram** (`IPFRAG_OVERLAP`, RFC 5722 for
//!   IPv6, "ipfrag: drop overlapping fragments" for IPv4), counted in
//!   [`ReassemblyStats::dropped_overlap`]. As in Linux there is **no
//!   tombstone**: the next fragment with the same key starts a new datagram.
//! - **Geometry** (`end` = offset + length): a last fragment ending before
//!   data already seen, or a second last fragment with a different end, kills
//!   the datagram; so does a non-last fragment past a known end, or an empty
//!   fragment. A non-last IPv4 fragment whose length is not a multiple of 8
//!   is *trimmed* to one; for IPv6 that fragment alone is dropped (the kernel
//!   sends a parameter problem) and the datagram is kept. At completion a
//!   datagram is dropped if its offset-0 fragment's header bytes plus the
//!   reassembled length exceed 65 535 ([`IpFragment::header_len`]: the IPv4
//!   header *with options*, `ip_frag_reasm`; for IPv6 the unfragmentable
//!   extension headers before the Fragment header, `ip6_frag_reasm`); an
//!   IPv6 fragment ending past 65 535 is dropped alone.
//!   An IPv6 *atomic* fragment (offset 0, M = 0, RFC 6946) is delivered at
//!   once without touching any queue.
//! - **`ipfrag_max_dist`** (IPv4 only, default 64): the kernel counts every
//!   fragment it receives from a source; if more than
//!   [`ReassemblyLimits::max_dist`] arrived between two fragments of the same
//!   datagram, its queued fragments are discarded and it restarts
//!   ([`ReassemblyStats::dropped_too_far`]). The receiving kernel only counts
//!   fragments *addressed to it*, so the sensor counts per (source,
//!   destination) pair: fragments the attacker sends to other hosts cannot
//!   make the sensor restart a datagram the robot keeps.
//! - **Key**: IPv4 (src, dst, id, protocol); IPv6 (src, dst, id) — the
//!   upper-layer protocol of an IPv6 datagram is taken from its offset-0
//!   fragment, as in the kernel.
//! - **Timeout** after the first fragment (or after a `max_dist` restart):
//!   [`ReassemblyLimits::timeout`] (30 s, `net.ipv4.ipfrag_time`) for IPv4,
//!   [`ReassemblyLimits::timeout_v6`] (60 s, `net.ipv6.ip6frag_time`) for
//!   IPv6, on *capture* timestamps, so replaying a file behaves like live
//!   capture.
//!
//! # Memory limits: never stricter than the receiving kernel
//! The kernel caps fragment memory per network namespace **and per IP
//! version** at `ipfrag_high_thresh` (4 MiB of skb *truesize*, plus the
//! queue structures); while above it, every arriving fragment is dropped
//! (there is no eviction since Linux 4.17). An earlier version of this module
//! kept one shared 64-datagram table with oldest-first eviction: an attacker
//! interleaving junk first-fragments with a real datagram made the sensor
//! evict a datagram the kernel still delivered. The budgets are now:
//!
//! - **Per destination address and IP version**
//!   ([`ReassemblyLimits::max_bytes_per_dst`], 4 MiB): the stand-in for one
//!   receiving host's `ipfrag_high_thresh`. While a destination's bucket is
//!   above it, new fragments to that destination are *refused*
//!   ([`ReassemblyStats::refused_capacity`]) — never evicting anything. The
//!   sensor charges each fragment its payload plus [`FRAGMENT_OVERHEAD`] and
//!   each datagram [`DATAGRAM_OVERHEAD`], both below what the kernel charges
//!   (skb truesize, `sizeof(struct ipq)`), so the host kernel reaches its
//!   threshold first: when the sensor refuses, the host has refused too.
//!   A flood therefore cannot evict anybody's queued state, and cannot make
//!   the sensor refuse anything the destination itself would accept.
//!   Deliberately **no per-source cap**: the kernel has none, so a
//!   per-source cap would let an attacker hide its own datagram by sending
//!   junk from the same source first.
//! - **Global per IP version** ([`ReassemblyLimits::max_bytes`], 32 MiB;
//!   [`ReassemblyLimits::max_datagrams`], 65 536): bounds the sensor's own
//!   memory when it sees traffic for many hosts (a SPAN port, or fragments
//!   with spoofed destination addresses that no kernel would queue). This
//!   limit has no kernel counterpart, so it **never refuses** a fragment
//!   whose destination is within its own budget: the arriving fragment is
//!   always admitted and room is made by evicting other datagrams
//!   ([`ReassemblyStats::dropped_capacity`]). The victim is the datagram of
//!   that IP version that has gone longest without receiving new bytes
//!   ("least recently progressed"; a duplicate is not progress), never the
//!   arriving fragment's own datagram. (An earlier policy evicted from the
//!   heaviest destination or refused the fragment if it was the arriving
//!   one's: an attacker that made the robot's bucket the heaviest, with
//!   1 MiB of junk the robot's kernel happily queues, and spread 31 MiB over
//!   lighter fake destinations, made the sensor refuse the robot's real
//!   fragment.) Only a fragment that cannot fit even after evicting
//!   everything else (zero limits) is refused
//!   ([`ReassemblyStats::refused_capacity`]).
//!
//! ## What an attacker can still do (honest)
//! A finite table fed by spoofable traffic cannot be eviction-proof. To get
//! a queued datagram `D` evicted, the table must be over the global limit
//! and **every other** queued datagram of that IP version must have
//! received new bytes after `D`'s latest fragment. Since one datagram holds
//! at most 64 KiB, a full table (32 MiB) holds at least ~500 datagrams, so
//! at least ~500 fragments with new bytes (65 535 with the datagram-count
//! limit) must arrive between two consecutive fragments of `D`. Junk queued
//! at leisure *before* `D` is always evicted before `D`. A real datagram's
//! fragments leave the sender back to back (microseconds apart on a LAN),
//! so the attacker has to win a tight race, with sustained traffic, and
//! every eviction is counted in `dropped_capacity`. The pipeline should
//! raise a finding on any increase of `dropped_capacity` or
//! `refused_capacity`.
//!
//! All bookkeeping is O(log n) per fragment (no scans of the table under a
//! flood), apart from amortised compaction of the expiry queue. That
//! includes the runs of one datagram: fragments arriving back to front
//! (8-byte fragments, last first) cost O(log runs) each, not a shift of
//! every queued run.
//!
//! Known differences (all in the "sensor sees a superset" direction, which is
//! a false positive at worst, never an evasion): non-UDP IPv4 fragments are
//! not decoded, so they neither count towards `max_dist` nor use memory here;
//! fragments to a host's other addresses or to multicast groups are charged
//! to separate buckets; the byte accounting under-approximates the kernel's
//! truesize; IPv6 first fragments with a truncated header chain (RFC 7112)
//! are not rejected. Non-default kernel sysctls must be mirrored in
//! [`ReassemblyLimits`] by the integrator.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::IpAddr;
use std::time::Duration;

use crate::decode::IpFragment;
use crate::ingress::IngressInfo;

/// Largest reassembled payload (IPv4 total length / IPv6 payload length max).
pub const MAX_DATAGRAM: usize = 65_535;

/// Largest IPv4 reassembled payload Linux accepts behind an option-less
/// 20-byte header. The reassembler checks the offset-0 fragment's actual
/// header length ([`IpFragment::header_len`]): `header_len + len <= 65 535`.
pub const MAX_IPV4_PAYLOAD: usize = MAX_DATAGRAM - 20;

/// Bytes charged per queued fragment on top of its payload. Deliberately
/// below the kernel's per-skb overhead (`sk_buff` + shared info, > 500
/// bytes) so the sensor's budget lasts longer than the kernel's.
pub const FRAGMENT_OVERHEAD: usize = 64;

/// Bytes charged per datagram in flight (below the kernel's
/// `sizeof(struct ipq)` / `frag_queue`, which it charges the same way).
pub const DATAGRAM_OVERHEAD: usize = 128;

/// Resource bounds for [`Reassembler`]. Build with `..Default::default()`.
/// The byte and datagram limits apply separately to IPv4 and IPv6, like the
/// kernel's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReassemblyLimits {
    /// One destination's bucket (the receiving host's `ipfrag_high_thresh`):
    /// while above it, new fragments to that destination are refused.
    pub max_bytes_per_dst: usize,
    /// All destinations together (sensor memory bound); above it the least
    /// recently progressed datagram (not the arriving fragment's) is evicted.
    pub max_bytes: usize,
    /// Datagrams in flight, all destinations (same eviction rule).
    pub max_datagrams: usize,
    /// IPv4 reassembly timeout (`net.ipv4.ipfrag_time`).
    pub timeout: Duration,
    /// IPv6 reassembly timeout (`net.ipv6.ip6frag_time`).
    pub timeout_v6: Duration,
    /// Linux `net.ipv4.ipfrag_max_dist` (IPv4 only); 0 disables.
    pub max_dist: u32,
}

impl Default for ReassemblyLimits {
    /// 4 MiB per destination (the Linux `ipfrag_high_thresh`), 32 MiB and
    /// 65 536 datagrams per IP version overall, 30 s / 60 s (the Linux
    /// `ipfrag_time` / `ip6frag_time`), `max_dist` 64 (the Linux default).
    fn default() -> Self {
        Self {
            max_bytes_per_dst: 4 << 20,
            max_bytes: 32 << 20,
            max_datagrams: 65_536,
            timeout: Duration::from_secs(30),
            timeout_v6: Duration::from_secs(60),
            max_dist: 64,
        }
    }
}

/// Counters kept by the reassembler. Everything except `fragments` and
/// `completed` is worth surfacing: these are the traces of fragmentation
/// attacks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReassemblyStats {
    pub fragments: u64,
    pub completed: u64,
    /// Datagrams dropped because fragments partially overlapped.
    pub dropped_overlap: u64,
    /// Datagrams (or single IPv6 fragments) dropped for inconsistent geometry.
    pub dropped_invalid: u64,
    /// Datagrams that did not complete within the timeout.
    pub dropped_timeout: u64,
    /// Datagrams **evicted** under global memory pressure (the least
    /// recently progressed one of the IP version, never the arriving
    /// fragment's).
    pub dropped_capacity: u64,
    /// Legacy (poisoned-datagram tombstones were removed to match Linux):
    /// always 0.
    pub ignored_after_drop: u64,
    /// Fragments ignored because they duplicate queued data (first wins).
    pub duplicates: u64,
    /// Of `duplicates`, those whose bytes differed from the queued copy.
    pub duplicate_conflicts: u64,
    /// IPv4 datagrams restarted by the `max_dist` rule.
    pub dropped_too_far: u64,
    /// Fragments refused because their destination's budget was full (the
    /// kernel drops them too), or because they could not fit under the
    /// global limit even after evicting every other datagram (zero limits).
    pub refused_capacity: u64,
}

impl ReassemblyStats {
    /// Datagrams evicted under memory pressure (alias of `dropped_capacity`).
    pub fn evictions(&self) -> u64 {
        self.dropped_capacity
    }

    /// All datagram-level drops, for a single "reassembly failures" figure.
    pub fn dropped_total(&self) -> u64 {
        self.dropped_overlap
            .saturating_add(self.dropped_invalid)
            .saturating_add(self.dropped_timeout)
            .saturating_add(self.dropped_capacity)
            .saturating_add(self.dropped_too_far)
            .saturating_add(self.refused_capacity)
    }
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

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct Key {
    src: IpAddr,
    dst: IpAddr,
    id: u32,
    /// IPv4 protocol; 0 for IPv6 (not part of the kernel's key).
    protocol: u8,
}

type Pair = (IpAddr, IpAddr);

#[derive(Debug)]
struct Entry {
    generation: u64,
    /// Non-overlapping runs of contiguous fragments by start offset (the
    /// kernel's rb-tree of `frag_run`s: only the tail run grows, by
    /// appending; a fragment filling a gap becomes a run of its own). A
    /// map, not a sorted `Vec`: fragments sent back to front would make
    /// every insert shift the whole vector (quadratic per datagram).
    runs: BTreeMap<usize, Vec<u8>>,
    /// [`IpFragment::header_len`] of the offset-0 fragment (0 until seen).
    head_len: usize,
    /// Largest end seen (`q.len`).
    len: usize,
    first_in: bool,
    last_in: bool,
    /// Payload bytes queued (`q.meat`).
    meat: usize,
    /// Bytes charged against the budgets (including [`DATAGRAM_OVERHEAD`]).
    charge: usize,
    /// Upper-layer protocol (IPv6: from the offset-0 fragment).
    protocol: Option<u8>,
    /// Per-pair fragment counter value at the last fragment (max_dist).
    rid: u32,
    /// Reassembler fragment clock when this datagram last received new
    /// bytes (or was created): its key in [`Family::lru`].
    progress: u64,
    /// Merged ingress of the queued fragments (`None` before the first).
    ingress: Option<IngressInfo>,
}

/// One destination's bucket.
#[derive(Debug, Default)]
struct DstUse {
    bytes: usize,
    datagrams: usize,
}

/// Per-(src, dst) state for `max_dist`.
#[derive(Debug, Default, Clone, Copy)]
struct PeerUse {
    rid: u32,
    datagrams: usize,
}

/// Accounting for one IP version.
#[derive(Debug, Default)]
struct Family {
    /// Creation order, for expiry. May hold stale records.
    order: VecDeque<(Duration, u64, Key)>,
    bytes: usize,
    datagrams: usize,
    dsts: HashMap<IpAddr, DstUse>,
    /// Every live datagram by its last progress (least recently progressed
    /// first): the eviction order under global pressure.
    lru: BTreeMap<u64, Key>,
}

#[cfg(test)]
fn family(addr: &IpAddr) -> usize {
    usize::from(addr.is_ipv6())
}

/// The per-version state for IPv6 (`v6`) or IPv4.
fn fam(families: &[Family; 2], v6: bool) -> &Family {
    let [v4f, v6f] = families;
    if v6 {
        v6f
    } else {
        v4f
    }
}

/// [`fam`], mutably.
fn fam_mut(families: &mut [Family; 2], v6: bool) -> &mut Family {
    let [v4f, v6f] = families;
    if v6 {
        v6f
    } else {
        v4f
    }
}

/// Bounded fragment reassembler. Feed it every [`IpFragment`] with its capture
/// timestamp; it returns the payload when a datagram completes.
#[derive(Debug)]
pub struct Reassembler {
    limits: ReassemblyLimits,
    entries: HashMap<Key, Entry>,
    families: [Family; 2],
    peers: HashMap<Pair, PeerUse>,
    next_generation: u64,
    /// Fragments pushed so far (the progress clock).
    clock: u64,
    now: Duration,
    stats: ReassemblyStats,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new(ReassemblyLimits::default())
    }
}

enum Insert {
    Ok,
    Dup { conflict: bool },
    Overlap,
}

impl Reassembler {
    pub fn new(limits: ReassemblyLimits) -> Self {
        Self {
            limits,
            entries: HashMap::new(),
            families: Default::default(),
            peers: HashMap::new(),
            next_generation: 0,
            clock: 0,
            now: Duration::ZERO,
            stats: ReassemblyStats::default(),
        }
    }

    pub fn limits(&self) -> &ReassemblyLimits {
        &self.limits
    }

    pub fn stats(&self) -> &ReassemblyStats {
        &self.stats
    }

    /// Number of datagrams currently buffered.
    pub fn in_flight(&self) -> usize {
        self.entries.len()
    }

    /// Bytes currently charged (both IP versions, all destinations).
    pub fn buffered_bytes(&self) -> usize {
        self.families.iter().map(|f| f.bytes).sum()
    }

    /// Bytes currently charged to one destination address.
    pub fn buffered_bytes_for(&self, dst: IpAddr) -> usize {
        fam(&self.families, dst.is_ipv6())
            .dsts
            .get(&dst)
            .map_or(0, |d| d.bytes)
    }

    /// Add `delta` (may be negative via `sub`) to a key's charge everywhere.
    fn recharge(&mut self, key: &Key, add: usize, sub: usize) {
        if let Some(e) = self.entries.get_mut(key) {
            e.charge = e.charge + add - sub;
        }
        let f = fam_mut(&mut self.families, key.dst.is_ipv6());
        f.bytes = f.bytes + add - sub;
        if let Some(d) = f.dsts.get_mut(&key.dst) {
            d.bytes = d.bytes + add - sub;
        }
    }

    /// Record that `key` just received new bytes.
    fn touch(&mut self, key: &Key) {
        let clock = self.clock;
        let Some(e) = self.entries.get_mut(key) else {
            return;
        };
        let f = fam_mut(&mut self.families, key.dst.is_ipv6());
        f.lru.remove(&e.progress);
        e.progress = clock;
        f.lru.insert(clock, *key);
    }

    fn remove(&mut self, key: &Key) -> Option<Entry> {
        let charge = self.entries.get(key)?.charge;
        self.recharge(key, 0, charge);
        let e = self.entries.remove(key)?;
        let f = fam_mut(&mut self.families, key.dst.is_ipv6());
        f.datagrams -= 1;
        f.lru.remove(&e.progress);
        if let Some(d) = f.dsts.get_mut(&key.dst) {
            d.datagrams -= 1;
            if d.datagrams == 0 {
                f.dsts.remove(&key.dst);
            }
        }
        let pair = (key.src, key.dst);
        if let Some(p) = self.peers.get_mut(&pair) {
            p.datagrams -= 1;
            if p.datagrams == 0 {
                self.peers.remove(&pair);
            }
        }
        Some(e)
    }

    fn is_live(entries: &HashMap<Key, Entry>, key: &Key, generation: u64) -> bool {
        entries.get(key).is_some_and(|e| e.generation == generation)
    }

    fn expire(&mut self) {
        for v6 in [false, true] {
            let timeout = if v6 {
                self.limits.timeout_v6
            } else {
                self.limits.timeout
            };
            while let Some(&(t, generation, key)) = fam(&self.families, v6).order.front() {
                if t.saturating_add(timeout) >= self.now {
                    break;
                }
                fam_mut(&mut self.families, v6).order.pop_front();
                if Self::is_live(&self.entries, &key, generation) {
                    self.remove(&key);
                    self.stats.dropped_timeout += 1;
                }
            }
            // Keep the order queue proportional to the live entries.
            let f = fam_mut(&mut self.families, v6);
            if f.order.len() > 2 * f.datagrams + 1024 {
                let entries = &self.entries;
                f.order.retain(|(_, g, k)| Self::is_live(entries, k, *g));
            }
        }
    }

    /// Record a (new or restarted) datagram generation in the expiry queue.
    fn track(&mut self, key: Key, generation: u64) {
        let now = self.now;
        fam_mut(&mut self.families, key.dst.is_ipv6())
            .order
            .push_back((now, generation, key));
    }

    /// Evict the least recently progressed datagram of the IPv6 (`v6`) or
    /// IPv4 family other than `arriving`. False when there is none.
    fn evict_lru(&mut self, v6: bool, arriving: &Key) -> bool {
        let victim = fam(&self.families, v6)
            .lru
            .values()
            .take(2)
            .find(|k| *k != arriving)
            .copied();
        match victim {
            Some(k) => {
                self.remove(&k);
                self.stats.dropped_capacity += 1;
                true
            }
            None => false,
        }
    }

    /// Kernel `inet_frag_find` threshold check plus the sensor's global
    /// bound, see the module docs.
    fn admit(&mut self, key: &Key, exists: bool) -> bool {
        let v6 = key.dst.is_ipv6();
        let dst_bytes = fam(&self.families, v6)
            .dsts
            .get(&key.dst)
            .map_or(0, |d| d.bytes);
        // Like the kernel: refuse while *above* the threshold.
        if dst_bytes > self.limits.max_bytes_per_dst {
            return false;
        }
        loop {
            let f = fam(&self.families, v6);
            let full = f.bytes > self.limits.max_bytes
                || (!exists && f.datagrams >= self.limits.max_datagrams);
            if !full {
                return true;
            }
            if !self.evict_lru(v6, key) {
                return false;
            }
        }
    }

    fn new_entry(&mut self, key: Key) {
        let generation = self.next_generation;
        self.next_generation += 1;
        self.entries.insert(
            key,
            Entry {
                generation,
                runs: BTreeMap::new(),
                head_len: 0,
                len: 0,
                first_in: false,
                last_in: false,
                meat: 0,
                charge: 0,
                protocol: None,
                rid: 0,
                progress: self.clock,
                ingress: None,
            },
        );
        let f = fam_mut(&mut self.families, key.dst.is_ipv6());
        f.datagrams += 1;
        f.lru.insert(self.clock, key);
        f.dsts.entry(key.dst).or_default().datagrams += 1;
        self.peers.entry((key.src, key.dst)).or_default().datagrams += 1;
        self.track(key, generation);
        self.recharge(&key, DATAGRAM_OVERHEAD, 0);
    }

    /// `ip_frag_reinit`: drop the queued fragments, restart the timer.
    fn reinit(&mut self, key: &Key) {
        let Some(charge) = self.entries.get(key).map(|e| e.charge) else {
            return;
        };
        self.recharge(key, 0, charge - DATAGRAM_OVERHEAD);
        let generation = self.next_generation;
        self.next_generation += 1;
        if let Some(e) = self.entries.get_mut(key) {
            e.runs.clear();
            e.head_len = 0;
            e.len = 0;
            e.first_in = false;
            e.last_in = false;
            e.meat = 0;
            e.protocol = None;
            e.ingress = None;
            e.generation = generation;
        }
        self.track(*key, generation);
    }

    /// Add one fragment. Returns the reassembled payload when this fragment
    /// completes its datagram.
    pub fn push(&mut self, ts: Duration, frag: &IpFragment<'_>) -> Option<Reassembled> {
        self.push_with_ingress(ts, frag, &IngressInfo::default())
            .map(|(r, _)| r)
    }

    /// [`push`](Self::push) for a fragment that arrived on `ingress`; a
    /// completed datagram comes with the merged ingress of its fragments
    /// (see the module docs).
    pub fn push_with_ingress(
        &mut self,
        ts: Duration,
        frag: &IpFragment<'_>,
        ingress: &IngressInfo,
    ) -> Option<(Reassembled, IngressInfo)> {
        self.stats.fragments += 1;
        self.clock += 1;
        self.now = self.now.max(ts);
        self.expire();

        let v4 = frag.src.is_ipv4();
        if !v4 && frag.offset == 0 && !frag.more {
            // RFC 6946 atomic fragment: processed in isolation.
            self.stats.completed += 1;
            return Some((
                Reassembled {
                    src: frag.src,
                    dst: frag.dst,
                    protocol: frag.protocol,
                    payload: frag.data.to_vec(),
                },
                ingress.clone(),
            ));
        }
        let key = Key {
            src: frag.src,
            dst: frag.dst,
            id: frag.id,
            protocol: if v4 { frag.protocol } else { 0 },
        };
        let exists = self.entries.contains_key(&key);
        if !self.admit(&key, exists) {
            self.stats.refused_capacity += 1;
            return None;
        }
        if !exists {
            self.new_entry(key);
        }

        // ip_frag_too_far (IPv4): counts every fragment of this pair.
        if v4 && self.limits.max_dist > 0 {
            let peer = self.peers.entry((key.src, key.dst)).or_default();
            peer.rid = peer.rid.wrapping_add(1);
            let end = peer.rid;
            let e = self.entries.get_mut(&key)?;
            let start = std::mem::replace(&mut e.rid, end);
            if exists && !e.runs.is_empty() && end.wrapping_sub(start) > self.limits.max_dist {
                self.stats.dropped_too_far += 1;
                self.reinit(&key);
            }
        }

        // Geometry, in the kernel's order.
        let offset = frag.offset;
        let mut data = frag.data;
        let Some(mut end) = offset.checked_add(data.len()) else {
            return self.kill_invalid(&key);
        };
        if !v4 && end > MAX_DATAGRAM {
            self.stats.dropped_invalid += 1; // fragment only
            return None;
        }
        {
            let e = self.entries.get_mut(&key)?;
            if !frag.more {
                if end < e.len || (e.last_in && end != e.len) {
                    return self.kill_invalid(&key);
                }
                e.last_in = true;
                e.len = end;
            } else {
                if end % 8 != 0 {
                    if !v4 {
                        self.stats.dropped_invalid += 1; // fragment only
                        return None;
                    }
                    end &= !7;
                    data = data.get(..end.saturating_sub(offset)).unwrap_or(data);
                }
                if end > e.len {
                    if e.last_in {
                        return self.kill_invalid(&key);
                    }
                    e.len = end;
                }
            }
        }
        if end <= offset {
            return self.kill_invalid(&key);
        }

        let e = self.entries.get_mut(&key)?;
        match Self::insert(e, offset, end, data) {
            Insert::Ok => {}
            Insert::Dup { conflict } => {
                self.stats.duplicates += 1;
                if conflict {
                    self.stats.duplicate_conflicts += 1;
                }
                return None;
            }
            Insert::Overlap => {
                self.remove(&key);
                self.stats.dropped_overlap += 1;
                return None;
            }
        }
        if offset == 0 {
            e.first_in = true;
            e.protocol = Some(frag.protocol);
            e.head_len = frag.header_len;
        }
        match &mut e.ingress {
            Some(m) => m.merge_fragment(ingress),
            None => e.ingress = Some(ingress.clone()),
        }
        e.meat += data.len();
        self.recharge(&key, data.len() + FRAGMENT_OVERHEAD, 0);
        self.touch(&key);
        self.finish_if_complete(&key)
    }

    fn kill_invalid<T>(&mut self, key: &Key) -> Option<T> {
        self.remove(key);
        self.stats.dropped_invalid += 1;
        None
    }

    fn finish_if_complete(&mut self, key: &Key) -> Option<(Reassembled, IngressInfo)> {
        let e = self.entries.get(key)?;
        if !(e.first_in && e.last_in && e.meat == e.len) {
            return None;
        }
        let e = self.remove(key)?;
        // ip_frag_reasm: ip_hdrlen(head) + len > 65535; ip6_frag_reasm:
        // unfragmentable headers of the head + len > IPV6_MAXPLEN.
        if e.head_len.saturating_add(e.len) > MAX_DATAGRAM {
            self.stats.dropped_invalid += 1; // "Oversized IP packet"
            return None;
        }
        let mut payload = Vec::with_capacity(e.len);
        for (start, bytes) in &e.runs {
            debug_assert_eq!(*start, payload.len());
            payload.extend_from_slice(bytes);
        }
        self.stats.completed += 1;
        Some((
            Reassembled {
                src: key.src,
                dst: key.dst,
                protocol: e.protocol.unwrap_or(key.protocol),
                payload,
            },
            e.ingress.unwrap_or_default(),
        ))
    }

    /// `inet_frag_queue_insert`.
    /// O(log runs) whatever the arrival order.
    fn insert(e: &mut Entry, offset: usize, end: usize, data: &[u8]) -> Insert {
        let Some(mut tail) = e.runs.last_entry() else {
            e.runs.insert(offset, data.to_vec());
            return Insert::Ok;
        };
        let tail_end = *tail.key() + tail.get().len();
        if tail_end < end {
            // Common case: goes to the end.
            if offset < tail_end {
                return Insert::Overlap;
            }
            if offset == tail_end {
                tail.get_mut().extend_from_slice(data);
            } else {
                e.runs.insert(offset, data.to_vec());
            }
            return Insert::Ok;
        }
        // Runs are disjoint, so the last run starting before `end` is the
        // only candidate to intersect [offset, end).
        match e.runs.range(..end).next_back() {
            Some((&start, bytes)) if start + bytes.len() > offset => {
                if offset >= start && end <= start + bytes.len() {
                    let held = bytes.get(offset - start..end - start);
                    Insert::Dup {
                        conflict: held != Some(data),
                    }
                } else {
                    Insert::Overlap
                }
            }
            _ => {
                #[cfg(test)]
                tests::note_run_insert(e.runs.len());
                e.runs.insert(offset, data.to_vec());
                Insert::Ok
            }
        }
    }

    /// Check the internal accounting invariants (tests only).
    #[cfg(test)]
    fn check_invariants(&self) {
        for (fi, f) in self.families.iter().enumerate() {
            let live: Vec<_> = self
                .entries
                .iter()
                .filter(|(k, _)| family(&k.dst) == fi)
                .collect();
            assert_eq!(f.datagrams, live.len());
            assert_eq!(f.bytes, live.iter().map(|(_, e)| e.charge).sum::<usize>());
            assert_eq!(f.lru.len(), live.len());
            for (k, e) in &live {
                assert_eq!(f.lru.get(&e.progress), Some(*k));
            }
            for (dst, d) in &f.dsts {
                let mine = live.iter().filter(|(k, _)| k.dst == *dst);
                assert_eq!(d.datagrams, mine.clone().count());
                assert_eq!(d.bytes, mine.map(|(_, e)| e.charge).sum::<usize>());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    fn frag(id: u32, offset: usize, more: bool, data: &[u8]) -> IpFragment<'_> {
        frag_from(ip(1), id, offset, more, data)
    }

    fn frag_from(src: IpAddr, id: u32, offset: usize, more: bool, data: &[u8]) -> IpFragment<'_> {
        IpFragment {
            src,
            dst: if src.is_ipv4() {
                ip(2)
            } else {
                "fd00::2".parse::<Ipv6Addr>().unwrap().into()
            },
            id,
            protocol: 17,
            offset,
            more,
            data,
            header_len: if src.is_ipv4() { 20 } else { 0 },
        }
    }

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    fn v6(n: u16) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, n))
    }

    #[test]
    fn in_order_and_out_of_order() {
        let payload: Vec<u8> = (0..40u8).collect();
        for order in [[0usize, 1, 2], [2, 0, 1], [1, 2, 0], [2, 1, 0], [0, 2, 1]] {
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
            assert_eq!(r.buffered_bytes(), 0);
            assert_eq!(r.stats().completed, 1);
        }
    }

    #[test]
    fn duplicates_first_wins_like_linux() {
        let mut r = Reassembler::default();
        let d = [1u8; 16];
        assert!(r.push(secs(0), &frag(1, 0, true, &d[..8])).is_none());
        assert!(r.push(secs(0), &frag(1, 0, true, &d[..8])).is_none());
        // Contained duplicate with different bytes: ignored, first copy kept.
        assert!(r.push(secs(0), &frag(1, 0, true, &[9; 8])).is_none());
        assert_eq!(r.stats().duplicates, 2);
        assert_eq!(r.stats().duplicate_conflicts, 1);
        let out = r.push(secs(0), &frag(1, 8, false, &d[8..])).unwrap();
        assert_eq!(out.payload, d);
        // Contained in a run built by tail appends: still a duplicate.
        let mut r = Reassembler::default();
        r.push(secs(0), &frag(2, 0, true, &[1; 8]));
        r.push(secs(0), &frag(2, 8, true, &[2; 8]));
        r.push(secs(0), &frag(2, 0, true, &[7; 16]));
        assert_eq!(r.stats().duplicate_conflicts, 1);
        let out = r.push(secs(0), &frag(2, 16, false, &[3; 8])).unwrap();
        assert_eq!(&out.payload[..16], &[[1u8; 8], [2; 8]].concat()[..]);
    }

    #[test]
    fn partial_overlap_kills_without_tombstone() {
        let mut r = Reassembler::default();
        assert!(r.push(secs(0), &frag(1, 0, true, &[1; 16])).is_none());
        // Ends past the tail but starts inside it: IPFRAG_OVERLAP.
        assert!(r.push(secs(0), &frag(1, 8, false, &[2; 16])).is_none());
        assert_eq!(r.stats().dropped_overlap, 1);
        assert_eq!(r.in_flight(), 0);
        // Like Linux, the next fragments start a fresh datagram.
        assert!(r.push(secs(0), &frag(1, 0, true, &[1; 16])).is_none());
        assert!(r.push(secs(0), &frag(1, 16, false, &[1; 8])).is_some());
        assert_eq!(r.stats().ignored_after_drop, 0);
        // Overlap through the binary-search path (spanning two runs).
        let mut r = Reassembler::default();
        r.push(secs(0), &frag(3, 0, true, &[0; 8]));
        r.push(secs(0), &frag(3, 32, false, &[0; 8]));
        r.push(secs(0), &frag(3, 16, true, &[0; 8]));
        r.push(secs(0), &frag(3, 8, true, &[0; 16])); // 8..24 straddles 16..24
        assert_eq!(r.stats().dropped_overlap, 1);
        assert_eq!(r.in_flight(), 0);
    }

    #[test]
    fn invalid_geometry() {
        let mut r = Reassembler::default();
        // IPv4 non-final fragment of odd length is trimmed (Linux), 7 -> 0:
        // empty after trimming kills it.
        r.push(secs(0), &frag(1, 0, true, &[0; 7]));
        // Final fragment shorter than data already held.
        r.push(secs(0), &frag(2, 0, true, &[0; 16]));
        r.push(secs(0), &frag(2, 0, false, &[0; 8]));
        // Two different ends.
        r.push(secs(0), &frag(3, 8, false, &[0; 8]));
        r.push(secs(0), &frag(3, 16, false, &[0; 8]));
        // Empty final fragment.
        r.push(secs(0), &frag(4, 8, false, &[]));
        // Unfragmented-looking (offset 0, final) completes immediately.
        assert!(r.push(secs(0), &frag(5, 0, false, &[0; 8])).is_some());
        // Non-final past a known end.
        let mut r2 = Reassembler::default();
        r2.push(secs(0), &frag(5, 8, false, &[0; 8]));
        r2.push(secs(0), &frag(5, 8, true, &[0; 16]));
        assert_eq!(r.stats().dropped_invalid, 4);
        assert_eq!(r2.stats().dropped_invalid, 1);
        assert_eq!(r.stats().completed, 1);
        assert_eq!(r.in_flight(), 0);
    }

    #[test]
    fn ipv4_trims_odd_non_final_fragments() {
        let body: Vec<u8> = (0..40u8).collect();
        let mut r = Reassembler::default();
        // 20 bytes at 0 (trimmed to 16), then the rest from 16.
        assert!(r.push(secs(0), &frag(1, 0, true, &body[..20])).is_none());
        let out = r.push(secs(0), &frag(1, 16, false, &body[16..])).unwrap();
        assert_eq!(out.payload, body);
    }

    #[test]
    fn ipv6_odd_non_final_fragment_dropped_alone() {
        let body: Vec<u8> = (0..40u8).collect();
        let mut r = Reassembler::default();
        assert!(r
            .push(secs(0), &frag_from(v6(1), 1, 0, true, &body[..20]))
            .is_none());
        assert_eq!(r.stats().dropped_invalid, 1);
        assert!(r
            .push(secs(0), &frag_from(v6(1), 1, 0, true, &body[..16]))
            .is_none());
        let out = r.push(secs(0), &frag_from(v6(1), 1, 16, false, &body[16..]));
        assert_eq!(out.unwrap().payload, body);
        // Past 64 KiB: the fragment alone is dropped.
        r.push(secs(0), &frag_from(v6(1), 2, 65_528, true, &[0; 16]));
        assert_eq!(r.stats().dropped_invalid, 2);
    }

    #[test]
    fn ipv6_protocol_comes_from_first_fragment() {
        let mut r = Reassembler::default();
        let mut a = frag_from(v6(1), 9, 8, false, &[0; 8]);
        a.protocol = 60; // differs: same kernel queue, ignored
        assert!(r.push(secs(0), &a).is_none());
        let out = r
            .push(secs(0), &frag_from(v6(1), 9, 0, true, &[0; 8]))
            .unwrap();
        assert_eq!(out.protocol, 17);
    }

    #[test]
    fn oversized_ipv4_dropped_at_completion() {
        let mut r = Reassembler::default();
        let big = vec![0u8; 65_520];
        r.push(secs(0), &frag(1, 0, true, &big));
        assert!(r.push(secs(0), &frag(1, 65_520, false, &[0; 8])).is_none());
        assert_eq!(r.stats().dropped_invalid, 1);
        assert_eq!(r.buffered_bytes(), 0);
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
        // Many completed datagrams do not grow the order queue unboundedly.
        for id in 10..5000 {
            r.push(secs(140), &frag(id, 0, false, &[0; 8]));
        }
        assert!(r.families[0].order.len() <= 2 * r.in_flight() + 1025);
        r.check_invariants();
    }

    /// `ipfrag_max_dist`: 63 fragments from the same source between two of a
    /// datagram's fragments are fine, 64 restart it (verified on Linux 6.x).
    #[test]
    fn max_dist_matches_linux() {
        for (junk, delivered) in [(63u32, true), (64, false)] {
            let mut r = Reassembler::default();
            r.push(secs(0), &frag(1, 0, true, &[1; 8]));
            for j in 0..junk {
                r.push(secs(0), &frag(100 + j, 0, true, &[0; 8]));
            }
            let out = r.push(secs(0), &frag(1, 8, false, &[2; 8]));
            assert_eq!(out.is_some(), delivered, "junk {junk}");
            assert_eq!(r.stats().dropped_too_far, u64::from(!delivered));
        }
        // Other sources do not count; IPv6 has no max_dist.
        let mut r = Reassembler::default();
        r.push(secs(0), &frag(1, 0, true, &[1; 8]));
        for j in 0..200u32 {
            r.push(secs(0), &frag_from(ip(50), j, 0, true, &[0; 8]));
        }
        assert!(r.push(secs(0), &frag(1, 8, false, &[2; 8])).is_some());
        let mut r = Reassembler::default();
        r.push(secs(0), &frag_from(v6(1), 1, 0, true, &[1; 8]));
        for j in 0..200u32 {
            r.push(secs(0), &frag_from(v6(1), 100 + j, 0, true, &[0; 8]));
        }
        assert!(r
            .push(secs(0), &frag_from(v6(1), 1, 8, false, &[2; 8]))
            .is_some());
        // Disabled.
        let mut r = Reassembler::new(ReassemblyLimits {
            max_dist: 0,
            ..Default::default()
        });
        r.push(secs(0), &frag(1, 0, true, &[1; 8]));
        for j in 0..200u32 {
            r.push(secs(0), &frag(100 + j, 0, true, &[0; 8]));
        }
        assert!(r.push(secs(0), &frag(1, 8, false, &[2; 8])).is_some());
    }

    fn to(
        src: IpAddr,
        dst: IpAddr,
        id: u32,
        offset: usize,
        more: bool,
        data: &[u8],
    ) -> IpFragment<'_> {
        IpFragment {
            src,
            dst,
            id,
            protocol: 17,
            offset,
            more,
            data,
            header_len: if src.is_ipv4() { 20 } else { 0 },
        }
    }

    /// Review finding F7a: junk first-fragments (same source, or spoofed
    /// sources) interleaved with a real datagram never evict it. IPv6 has no
    /// `max_dist`, so this is purely the memory policy.
    #[test]
    fn junk_flood_never_evicts_a_queued_datagram() {
        for spoofed in [false, true] {
            let mut r = Reassembler::default();
            r.push(secs(0), &frag_from(v6(1), 1, 0, true, &[1; 8]));
            for j in 0..20_000u32 {
                let src = if spoofed {
                    v6(100 + (j % 60_000) as u16)
                } else {
                    v6(1)
                };
                r.push(secs(0), &frag_from(src, 1000 + j, 0, true, &[0; 8]));
            }
            assert_eq!(r.stats().dropped_capacity, 0);
            let out = r.push(secs(0), &frag_from(v6(1), 1, 8, false, &[2; 8]));
            assert_eq!(out.expect("delivered").payload, [[1u8; 8], [2; 8]].concat());
            r.check_invariants();
        }
    }

    /// While one destination's bucket is above its budget, every fragment to
    /// it is refused (the kernel's `ipfrag_high_thresh` rule) and nothing is
    /// evicted; other destinations are unaffected.
    #[test]
    fn per_destination_budget_refuses_like_the_kernel() {
        let mut r = Reassembler::new(ReassemblyLimits {
            max_bytes_per_dst: 1024,
            ..Default::default()
        });
        let robot = ip(2);
        r.push(secs(0), &frag(1, 0, true, &[1; 8]));
        let mut refused_at = None;
        for j in 0..100u32 {
            r.push(secs(0), &frag_from(ip(66), 100 + j, 0, true, &[0; 64]));
            if refused_at.is_none() && r.stats().refused_capacity > 0 {
                refused_at = Some(j);
            }
        }
        assert!(refused_at.is_some());
        // Bounded by the budget plus at most one admitted datagram.
        assert!(r.buffered_bytes_for(robot) <= 1024 + 64 + FRAGMENT_OVERHEAD + DATAGRAM_OVERHEAD);
        assert_eq!(r.stats().dropped_capacity, 0);
        // The real datagram's next fragment is refused too while above the
        // threshold, exactly like the kernel (it would refuse it first).
        assert!(r.push(secs(0), &frag(1, 8, false, &[2; 8])).is_none());
        // Another destination still reassembles.
        let other = ip(3);
        r.push(secs(0), &to(ip(1), other, 9, 0, true, &[5; 8]));
        assert!(r
            .push(secs(0), &to(ip(1), other, 9, 8, false, &[6; 8]))
            .is_some());
        // After the timeout the bucket drains and the robot accepts again.
        r.push(secs(31), &frag(2, 0, true, &[1; 8]));
        assert!(r.push(secs(31), &frag(2, 8, false, &[2; 8])).is_some());
        r.check_invariants();
    }

    /// Global pressure never refuses a fragment whose destination is within
    /// its budget; it evicts the least recently progressed other datagram,
    /// so junk queued before a real datagram goes first.
    #[test]
    fn global_pressure_evicts_the_least_recently_progressed() {
        let mut r = Reassembler::new(ReassemblyLimits {
            max_bytes: 8 * 1024,
            max_dist: 0,
            ..Default::default()
        });
        let robot = ip(2);
        // A flood to 50 destinations fills the table and churns through it.
        for j in 0..2000u32 {
            let dst = IpAddr::V4(Ipv4Addr::new(10, 1, (j % 50) as u8, 1));
            r.push(secs(0), &to(ip(66), dst, j, 0, true, &[0; 64]));
            assert!(r.buffered_bytes() <= 8 * 1024 + 64 + FRAGMENT_OVERHEAD + DATAGRAM_OVERHEAD);
        }
        assert!(r.stats().dropped_capacity > 0);
        assert_eq!(r.stats().refused_capacity, 0, "never refused");
        // The robot's datagram arrives into the full table and survives a
        // burst of further junk smaller than the table.
        r.push(secs(0), &frag(1, 0, true, &[1; 8]));
        assert!(r.buffered_bytes_for(robot) > 0);
        let in_table = r.in_flight();
        for j in 0..(in_table as u32 - 2) {
            r.push(secs(0), &to(ip(66), ip(77), 5000 + j, 0, true, &[0; 64]));
        }
        assert!(r.push(secs(0), &frag(1, 8, false, &[2; 8])).is_some());
        // A datagram that keeps progressing is never the victim; once every
        // other datagram has progressed after it, it is (the documented
        // limit), and that is counted.
        r.push(secs(0), &frag(2, 0, true, &[1; 8]));
        let before = r.stats().dropped_capacity;
        for j in 0..(2 * in_table as u32) {
            r.push(secs(0), &to(ip(66), ip(77), 9000 + j, 0, true, &[0; 64]));
        }
        assert_eq!(r.buffered_bytes_for(robot), 0, "evicted after a full churn");
        assert!(r.stats().dropped_capacity > before);
        r.check_invariants();

        // Datagram-count pressure works the same way.
        let mut r = Reassembler::new(ReassemblyLimits {
            max_datagrams: 16,
            max_dist: 0,
            ..Default::default()
        });
        for j in 0..100u32 {
            r.push(secs(0), &to(ip(66), ip(200), j, 0, true, &[0; 8]));
            assert!(r.in_flight() <= 16);
        }
        assert_eq!(r.stats().refused_capacity, 0);
        assert_eq!(r.stats().dropped_capacity, 84);
        // The robot's datagrams evict the oldest junk and survive a burst of
        // up to 14 further junk datagrams.
        r.push(secs(0), &frag(1, 0, true, &[1; 8]));
        r.push(secs(0), &frag(2, 0, true, &[1; 8]));
        for j in 0..14u32 {
            r.push(secs(0), &to(ip(66), ip(200), 1000 + j, 0, true, &[0; 8]));
        }
        assert!(r.push(secs(0), &frag(1, 8, false, &[2; 8])).is_some());
        assert!(r.push(secs(0), &frag(2, 8, false, &[2; 8])).is_some());
        // Duplicates are not progress: re-sending a junk fragment does not
        // protect that datagram, it is still the oldest.
        assert_eq!(r.in_flight(), 14);
        r.push(secs(0), &frag(3, 0, true, &[1; 8]));
        r.push(secs(0), &to(ip(66), ip(200), 2000, 0, true, &[0; 8]));
        r.push(secs(0), &to(ip(66), ip(200), 1000, 0, true, &[0; 8])); // dup
        assert_eq!(r.stats().duplicates, 1);
        let before = r.stats().dropped_capacity;
        r.push(secs(0), &to(ip(66), ip(201), 77, 0, true, &[0; 8]));
        assert_eq!(r.stats().dropped_capacity, before + 1);
        // Junk 1001 was not the victim (it completes), junk 1000 was: its
        // last fragment no longer completes it.
        assert!(r
            .push(secs(0), &to(ip(66), ip(200), 1001, 8, false, &[0; 8]))
            .is_some());
        assert!(r
            .push(secs(0), &to(ip(66), ip(200), 1000, 8, false, &[0; 8]))
            .is_none());
        assert!(r.push(secs(0), &frag(3, 8, false, &[2; 8])).is_some());
        // IPv4 pressure never evicts IPv6 state.
        r.push(secs(0), &frag_from(v6(1), 7, 0, true, &[1; 8]));
        for j in 0..100u32 {
            r.push(secs(0), &to(ip(66), ip(201), 1000 + j, 0, true, &[0; 8]));
        }
        assert!(r
            .push(secs(0), &frag_from(v6(1), 7, 8, false, &[2; 8]))
            .is_some());
        r.check_invariants();
        // Zero capacity never panics.
        let mut z = Reassembler::new(ReassemblyLimits {
            max_datagrams: 0,
            ..Default::default()
        });
        assert!(z.push(secs(0), &frag(1, 0, true, &[0; 8])).is_none());
        assert_eq!(z.stats().refused_capacity, 1);
        let mut z = Reassembler::new(ReassemblyLimits {
            max_bytes_per_dst: 0,
            max_bytes: 0,
            ..Default::default()
        });
        z.push(secs(0), &frag(1, 0, true, &[0; 8]));
        assert!(z.push(secs(0), &frag(1, 8, false, &[0; 8])).is_none());
        z.check_invariants();
    }

    /// `max_dist` counts per (source, destination): fragments the attacker
    /// sends to other hosts do not restart the robot's datagram.
    #[test]
    fn max_dist_counts_per_destination() {
        let mut r = Reassembler::default();
        r.push(secs(0), &frag(1, 0, true, &[1; 8]));
        for j in 0..500u32 {
            r.push(secs(0), &to(ip(1), ip(99), j, 0, true, &[0; 8]));
        }
        assert!(r.push(secs(0), &frag(1, 8, false, &[2; 8])).is_some());
        assert_eq!(r.stats().dropped_too_far, 0);
    }

    #[test]
    fn ipv6_timeout_is_60s_ipv4_30s() {
        let mut r = Reassembler::default();
        r.push(secs(0), &frag_from(v6(1), 1, 0, true, &[1; 8]));
        r.push(secs(0), &frag(1, 0, true, &[1; 8]));
        assert!(r.push(secs(45), &frag(1, 8, false, &[2; 8])).is_none());
        assert_eq!(r.stats().dropped_timeout, 1);
        assert!(r
            .push(secs(45), &frag_from(v6(1), 1, 8, false, &[2; 8]))
            .is_some());
        r.push(secs(50), &frag_from(v6(1), 2, 0, true, &[1; 8]));
        r.push(secs(111), &frag(9, 0, true, &[1; 8]));
        assert_eq!(r.stats().dropped_timeout, 3);
        r.check_invariants();
    }

    #[test]
    fn ipv6_atomic_fragment_is_isolated() {
        let mut r = Reassembler::default();
        r.push(secs(0), &frag_from(v6(1), 5, 0, true, &[1; 8]));
        let a = r.push(secs(0), &frag_from(v6(1), 5, 0, false, &[9; 4]));
        assert_eq!(a.unwrap().payload, [9; 4]);
        // The queued datagram is untouched.
        assert!(r
            .push(secs(0), &frag_from(v6(1), 5, 8, false, &[2; 8]))
            .is_some());
    }

    /// Pseudo-random operations keep the accounting consistent.
    #[test]
    fn accounting_invariants_hold_under_churn() {
        let mut r = Reassembler::new(ReassemblyLimits {
            max_bytes: 4096,
            max_bytes_per_dst: 2048,
            max_datagrams: 40,
            max_dist: 5,
            ..Default::default()
        });
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let buf = [0xa5u8; 512];
        for i in 0..20_000u64 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let src = if x & 1 == 0 {
                ip((x >> 8) as u8 % 4)
            } else {
                v6((x >> 8) as u16 % 4)
            };
            let dst = if src.is_ipv4() {
                ip(10 + (x >> 16) as u8 % 4)
            } else {
                v6(10 + (x >> 16) as u16 % 4)
            };
            let off = ((x >> 24) as usize % 16) * 8;
            let len = (x >> 32) as usize % 64;
            let f = to(
                src,
                dst,
                (x >> 40) as u32 % 8,
                off,
                (x >> 50) & 3 != 0,
                &buf[..len],
            );
            r.push(secs(i / 500), &f);
            if i % 997 == 0 {
                r.check_invariants();
            }
        }
        r.check_invariants();
        assert!(r.buffered_bytes() <= 2 * (4096 + 512 + FRAGMENT_OVERHEAD + DATAGRAM_OVERHEAD));
    }

    #[test]
    fn sparse_fragments_cost_only_their_bytes() {
        let mut r = Reassembler::default();
        r.push(secs(0), &frag(1, 65_000, true, &[0; 8]));
        assert_eq!(
            r.buffered_bytes(),
            8 + FRAGMENT_OVERHEAD + DATAGRAM_OVERHEAD
        );
        assert_eq!(r.buffered_bytes_for(ip(2)), r.buffered_bytes());
        r.check_invariants();
    }

    thread_local! {
        /// Runs examined or relocated by mid-queue inserts on this thread.
        static RUN_WORK: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    /// Called by [`Reassembler::insert`] before inserting a run in front of
    /// `queued` others. A tree insert touches O(log queued) runs; charge
    /// `ceil(log2(queued + 1)) + 1`. (A sorted `Vec` would relocate every
    /// following run: the finding this test guards against.)
    pub(super) fn note_run_insert(queued: usize) {
        let cost = u64::from(usize::BITS - queued.leading_zeros()) + 1;
        RUN_WORK.with(|w| w.set(w.get() + cost));
    }

    fn run_work() -> u64 {
        RUN_WORK.with(std::cell::Cell::get)
    }

    /// Review: a datagram sent back to front in 8-byte fragments (8 191
    /// fragments, ~0.5 MB on the wire) made every insert shift the whole
    /// sorted run vector, ~33 M run moves (~1 GB memmove) per datagram. The
    /// work must be O(n log n): below 20 units per fragment here.
    #[test]
    fn reverse_order_fragments_cost_log_per_insert() {
        let mut r = Reassembler::default();
        let n = 8_189usize; // 65 512 bytes + 20-byte header
        let before = run_work();
        let mut out = None;
        // Last fragment first, then every other one back to front.
        for i in (0..n).rev() {
            let more = i + 1 < n;
            out = r.push(secs(0), &frag(77, i * 8, more, &[i as u8; 8]));
            if i > 0 {
                assert!(out.is_none());
            }
        }
        let work = run_work() - before;
        assert!(work <= 20 * n as u64, "{work} run moves for {n} fragments");
        let out = out.expect("datagram completes");
        assert_eq!(out.payload.len(), n * 8);
        assert_eq!(out.payload[8..16], [1u8; 8]);
        // Run semantics unchanged: a fragment spanning two gap-filled runs
        // is a partial overlap (the kernel never merges runs).
        let mut r = Reassembler::default();
        r.push(secs(0), &frag(5, 24, false, &[0; 8]));
        r.push(secs(0), &frag(5, 16, true, &[0; 8]));
        r.push(secs(0), &frag(5, 8, true, &[0; 8]));
        assert!(r.push(secs(0), &frag(5, 8, true, &[0; 16])).is_none());
        assert_eq!(r.stats().dropped_overlap, 1);
        r.check_invariants();
    }

    /// Review: Linux drops an IPv4 datagram when the offset-0 fragment's
    /// header *with options* plus the reassembled length exceeds 65 535; a
    /// fixed 20-byte allowance let the sensor accept what the kernel drops.
    #[test]
    fn ipv4_oversize_counts_head_options() {
        for (ihl, kept) in [(20usize, true), (44, true), (60, false)] {
            let mut r = Reassembler::default();
            // 65 488 + 44 = 65 532 <= 65 535; with 60 bytes: 65 548 > 65 535.
            let mut head = frag(1, 0, true, &[0u8; 65_480]);
            head.header_len = ihl;
            assert!(r.push(secs(0), &head).is_none());
            let got = r.push(secs(0), &frag(1, 65_480, false, &[0; 8]));
            assert_eq!(got.is_some(), kept, "ihl {ihl}");
            assert_eq!(r.stats().dropped_invalid, u64::from(!kept));
        }
        // The header length is taken from the offset-0 fragment only.
        let mut r = Reassembler::default();
        let mut tail = frag(2, 65_480, false, &[0; 8]);
        tail.header_len = 60;
        r.push(secs(0), &tail);
        assert!(r.push(secs(0), &frag(2, 0, true, &[0u8; 65_480])).is_some());
    }

    /// Review: `ip6_frag_reasm` adds the unfragmentable extension headers in
    /// front of the Fragment header of the offset-0 fragment.
    #[test]
    fn ipv6_oversize_counts_unfragmentable_headers() {
        for (unfrag, kept) in [(0usize, true), (40, true), (48, false)] {
            let mut r = Reassembler::default();
            // 65 488 + 48 = 65 536 > 65 535.
            let mut head = frag_from(v6(1), 3, 0, true, &[0u8; 65_480]);
            head.header_len = unfrag;
            assert!(r.push(secs(0), &head).is_none());
            let got = r.push(secs(0), &frag_from(v6(1), 3, 65_480, false, &[0; 8]));
            assert_eq!(got.is_some(), kept, "unfrag {unfrag}");
        }
    }
}
