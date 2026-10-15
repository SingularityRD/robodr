//! Small, dependency-free descriptive statistics for observed speeds.
//!
//! Percentiles use the **nearest-rank** method on the sorted samples: the
//! p-th percentile is the smallest sample such that at least p% of samples are
//! less than or equal to it. It never interpolates, so every reported value is
//! a value that was actually observed. That matters for an audit trail: the
//! OEM can find the command that produced the p99 figure.

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
        })
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
}
