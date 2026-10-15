//! Bounded "have we reported this already?" set.
//!
//! Discovery beacons repeat every few seconds, so without dedup one rogue
//! participant would raise a threat per beacon. Without a bound, an attacker
//! spraying random GUIDs could grow the set until the daemon runs out of
//! memory. [`DedupSet`] therefore keeps at most `capacity` entries, evicting
//! the oldest first, and stores a keyed 64-bit hash of each key rather than
//! the key itself, so memory is `O(capacity)` regardless of how long the
//! (attacker-controlled) topic names in a deviation are.
//!
//! Eviction only ever makes a still-present deviation be reported again: the
//! safe direction. The hash is keyed per process (`RandomState`), so an
//! attacker cannot craft a collision to suppress a report; an accidental
//! 64-bit collision (probability ~`n²/2⁶⁵`) would suppress one report.

use std::collections::hash_map::RandomState;
use std::collections::{HashSet, VecDeque};
use std::hash::BuildHasher;

/// Hard upper bound on any dedup capacity.
pub const MAX_DEDUP_CAPACITY: usize = 1 << 20;

/// See the module docs.
#[derive(Debug)]
pub struct DedupSet {
    hasher: RandomState,
    seen: HashSet<u64>,
    order: VecDeque<u64>,
    capacity: usize,
}

impl DedupSet {
    /// `capacity` is clamped to `1..=MAX_DEDUP_CAPACITY`.
    pub fn new(capacity: usize) -> Self {
        Self {
            hasher: RandomState::new(),
            seen: HashSet::new(),
            order: VecDeque::new(),
            capacity: capacity.clamp(1, MAX_DEDUP_CAPACITY),
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

    /// Whether `key` is currently remembered (does not insert).
    pub fn contains(&self, key: &str) -> bool {
        self.seen.contains(&self.hasher.hash_one(key))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basics_and_clamping() {
        let mut s = DedupSet::new(0);
        assert_eq!(s.capacity(), 1);
        assert!(s.is_empty());
        assert!(s.insert("a"));
        assert!(!s.insert("a"));
        assert!(s.contains("a"));
        assert!(s.insert("b")); // evicts a
        assert_eq!(s.len(), 1);
        assert!(!s.contains("a"));
        assert!(s.insert("a"));
        assert_eq!(DedupSet::new(usize::MAX).capacity(), MAX_DEDUP_CAPACITY);
    }

    #[test]
    fn oldest_first_eviction() {
        let mut s = DedupSet::new(2);
        assert!(s.insert("a"));
        assert!(s.insert("b"));
        assert!(s.insert("c")); // evicts a
        assert!(!s.insert("b"));
        assert!(!s.insert("c"));
        assert!(s.insert("a"));
    }

    #[test]
    fn spray_stays_bounded() {
        let mut s = DedupSet::new(64);
        for n in 0..10_000 {
            assert!(s.insert(&format!("guid-{n}-{}", "x".repeat(n % 100))));
            assert!(s.len() <= 64);
        }
        assert_eq!(s.len(), 64);
    }
}
