//! Small, dependency-free descriptive statistics for observed speeds.
//!
//! Percentiles use the **nearest-rank** method on the sorted samples: the
//! p-th percentile is the smallest sample such that at least p% of samples are
//! less than or equal to it. It never interpolates, so every reported value is
//! a value that was actually observed. That matters for an audit trail: the
//! OEM can find the command that produced the p99 figure.
//!
//! # Bounded memory
//!
//! A commissioning run can be long, and a hostile one can be a flood, so
//! samples are kept in a [`SampleBuffer`]: exact up to its capacity, then
//! deterministically decimated (keep every 2nd retained sample, then accept
//! only every 2^k-th new one). Count, min and max are always tracked
//! exactly by the caller; only p50/p99 become approximate once a buffer has
//! decimated, and [`SpeedStats::decimated`] says so. Decimation depends on
//! arrival order, so percentiles of a decimated buffer are not
//! order-independent (the learned envelope is: it uses exact maxima).

use serde::{Deserialize, Serialize};

/// Summary of one speed dimension (linear or joint) on one motion channel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpeedStats {
    /// Number of valid (finite, non-negative) samples.
    pub samples: u64,
    pub min: f64,
    pub p50: f64,
    pub p99: f64,
    pub max: f64,
    /// `true` when p50/p99 come from a decimated subset (see the module
    /// docs); `samples`, `min` and `max` are always exact.
    #[serde(default)]
    pub decimated: bool,
}

impl SpeedStats {
    /// Compute stats over `samples`. Non-finite values are ignored (callers are
    /// expected to have filtered them already and reported them as anomalies).
    /// Returns `None` when no finite sample remains.
    pub fn from_samples(samples: &[f64]) -> Option<Self> {
        let mut sorted: Vec<f64> = samples.iter().copied().filter(|v| v.is_finite()).collect();
        if sorted.is_empty() {
            return None;
        }
        sorted.sort_by(f64::total_cmp);
        Some(Self {
            samples: sorted.len() as u64,
            min: sorted[0],
            p50: percentile_sorted(&sorted, 50.0),
            p99: percentile_sorted(&sorted, 99.0),
            max: sorted[sorted.len() - 1],
            decimated: false,
        })
    }

    /// Stats from exact `count`/`min`/`max` plus a retained subset for the
    /// percentiles. Percentiles are clamped into `[min, max]`. Non-finite
    /// inputs are ignored; `None` when `count` is 0 or min/max are not
    /// finite.
    pub fn from_parts(
        count: u64,
        min: f64,
        max: f64,
        retained: &[f64],
        decimated: bool,
    ) -> Option<Self> {
        if count == 0 || !min.is_finite() || !max.is_finite() || min > max {
            return None;
        }
        let mut sorted: Vec<f64> = retained.iter().copied().filter(|v| v.is_finite()).collect();
        sorted.sort_by(f64::total_cmp);
        let pct = |p: f64| {
            if sorted.is_empty() {
                max
            } else {
                percentile_sorted(&sorted, p).clamp(min, max)
            }
        };
        Some(Self {
            samples: count,
            min,
            p50: pct(50.0),
            p99: pct(99.0),
            max,
            decimated,
        })
    }
}

/// Bounded, deterministic sample store (see the module docs). `T` is the
/// sample (the learner stores `(speed, source index)`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SampleBuffer<T> {
    /// Accept one of every `stride` offered samples (1 until first full).
    stride: u64,
    /// Samples offered so far.
    offered: u64,
    retained: Vec<T>,
}

impl<T: Copy> SampleBuffer<T> {
    pub fn new() -> Self {
        Self {
            stride: 1,
            offered: 0,
            retained: Vec::new(),
        }
    }

    /// Offer one sample; `cap` (at least 2) bounds the retained count.
    pub fn push(&mut self, v: T, cap: usize) {
        let cap = cap.max(2);
        let stride = self.stride.max(1);
        if self.offered.is_multiple_of(stride) {
            if self.retained.len() >= cap {
                // Keep every 2nd retained sample: they are exactly the
                // offered samples at multiples of 2 * stride.
                let mut i = 0;
                self.retained.retain(|_| {
                    let keep = i % 2 == 0;
                    i += 1;
                    keep
                });
                self.stride = stride.saturating_mul(2);
            }
            if self.offered.is_multiple_of(self.stride.max(1)) && self.retained.len() < cap {
                self.retained.push(v);
            }
        }
        self.offered = self.offered.saturating_add(1);
    }

    /// Samples offered (retained or not).
    pub fn offered(&self) -> u64 {
        self.offered
    }

    /// Has any sample been dropped by decimation?
    pub fn is_decimated(&self) -> bool {
        self.stride > 1
    }

    pub fn retained(&self) -> &[T] {
        &self.retained
    }
}

/// Nearest-rank percentile of an ascending-sorted, non-empty slice.
/// `p` is clamped to `[0, 100]`; p = 0 yields the minimum. Returns NaN for an
/// empty slice (never panics).
pub fn percentile_sorted(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let p = if p.is_nan() {
        50.0
    } else {
        p.clamp(0.0, 100.0)
    };
    let n = sorted.len();
    let rank = ((p / 100.0) * n as f64).ceil() as usize; // 1-based
    let idx = rank.saturating_sub(1).min(n - 1);
    sorted[idx]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_rank_matches_textbook() {
        // Classic example: 15, 20, 35, 40, 50.
        let v = [15.0, 20.0, 35.0, 40.0, 50.0];
        assert_eq!(percentile_sorted(&v, 5.0), 15.0);
        assert_eq!(percentile_sorted(&v, 30.0), 20.0);
        assert_eq!(percentile_sorted(&v, 40.0), 20.0);
        assert_eq!(percentile_sorted(&v, 50.0), 35.0);
        assert_eq!(percentile_sorted(&v, 100.0), 50.0);
        assert_eq!(percentile_sorted(&v, 0.0), 15.0);
    }

    #[test]
    fn percentile_edge_cases_do_not_panic() {
        assert!(percentile_sorted(&[], 50.0).is_nan());
        assert_eq!(percentile_sorted(&[1.0], 99.0), 1.0);
        assert_eq!(percentile_sorted(&[1.0, 2.0], -5.0), 1.0);
        assert_eq!(percentile_sorted(&[1.0, 2.0], 500.0), 2.0);
        assert_eq!(percentile_sorted(&[1.0, 2.0], f64::NAN), 1.0);
    }

    #[test]
    fn p99_of_hundred_is_99th_value() {
        let v: Vec<f64> = (1..=100).map(f64::from).collect();
        let s = SpeedStats::from_samples(&v).unwrap();
        assert_eq!(s.samples, 100);
        assert_eq!(s.min, 1.0);
        assert_eq!(s.p50, 50.0);
        assert_eq!(s.p99, 99.0);
        assert_eq!(s.max, 100.0);
    }

    #[test]
    fn unsorted_input_and_non_finite_ignored() {
        let s = SpeedStats::from_samples(&[0.3, f64::NAN, 0.1, f64::INFINITY, 0.2]).unwrap();
        assert_eq!(s.samples, 3);
        assert_eq!(s.min, 0.1);
        assert_eq!(s.max, 0.3);
        assert!(SpeedStats::from_samples(&[]).is_none());
        assert!(SpeedStats::from_samples(&[f64::NAN]).is_none());
    }

    #[test]
    fn sample_buffer_is_bounded_and_deterministic() {
        let mut b = SampleBuffer::new();
        for i in 0..100_000u32 {
            b.push(f64::from(i), 64);
        }
        assert!(b.retained().len() <= 64);
        assert!(b.retained().len() >= 32);
        assert!(b.is_decimated());
        assert_eq!(b.offered(), 100_000);
        // Retained samples are evenly spaced offered samples.
        let r = b.retained();
        let step = r[1] - r[0];
        assert!(r.windows(2).all(|w| w[1] - w[0] == step), "{r:?}");
        let mut c = SampleBuffer::new();
        for i in 0..100_000u32 {
            c.push(f64::from(i), 64);
        }
        assert_eq!(b, c);
        // Below capacity: exact.
        let mut d = SampleBuffer::new();
        for i in 0..10u32 {
            d.push(i, 64);
        }
        assert!(!d.is_decimated());
        assert_eq!(d.retained().len(), 10);
        // Degenerate capacities do not panic.
        let mut e = SampleBuffer::new();
        for i in 0..1000u32 {
            e.push(i, 0);
        }
        assert!(e.retained().len() <= 2);
    }

    #[test]
    fn from_parts_clamps_and_rejects_garbage() {
        let s = SpeedStats::from_parts(1000, 0.0, 2.0, &[0.5, 1.0, 1.5], true).unwrap();
        assert_eq!(s.samples, 1000);
        assert_eq!(s.max, 2.0);
        assert_eq!(s.p50, 1.0);
        assert!(s.decimated);
        assert!(SpeedStats::from_parts(0, 0.0, 1.0, &[], false).is_none());
        assert!(SpeedStats::from_parts(3, f64::NAN, 1.0, &[], false).is_none());
        assert!(SpeedStats::from_parts(3, 0.0, f64::INFINITY, &[], false).is_none());
        assert!(SpeedStats::from_parts(3, 2.0, 1.0, &[], false).is_none());
        // No retained samples: percentiles fall back to max.
        assert_eq!(
            SpeedStats::from_parts(3, 0.1, 0.4, &[], true).unwrap().p99,
            0.4
        );
        // Retained outliers outside [min, max] are clamped.
        let s = SpeedStats::from_parts(3, 0.1, 0.4, &[f64::NAN, 9.0], false).unwrap();
        assert_eq!(s.p50, 0.4);
    }
}
