//! `blackbox.retention` (T15): how much evidence the black box keeps, what
//! happens when it is full, and the findings that come **before** evidence
//! that never left the unit is lost.
//!
//! ```json
//! "blackbox": {
//!   "retention": {
//!     "mode": "cyclic",
//!     "segments": 8,
//!     "segment_bytes": 8388608,
//!     "unexported_reserve_segments": 8,
//!     "warn_percent": 80
//!   }
//! }
//! ```
//!
//! * `mode` `cyclic` (default): keep `segments` segments of `segment_bytes`
//!   and drop the oldest when a new one starts (every drop is a signed
//!   `SegmentDropped` record). `saturation`: keep everything; once
//!   `segments` are full refuse non-critical records and keep
//!   `critical_reserve_segments` more for critical ones until an export
//!   prunes (`robodr-blackbox export-pending`).
//! * `unexported_reserve_segments` (cyclic; 0 = off, the default):
//!   **pending-export protection** for sites that export the black box
//!   (diode / media, `robodr-blackbox-export.timer`): a segment whose
//!   records are not all covered by the signed export cursor is kept, up
//!   to this many segments beyond `segments`; only when that reserve is
//!   used up is unexported evidence dropped.
//! * Without a `retention` section the recorder's defaults apply (cyclic,
//!   8 x 8 MiB, no reserve): what agentd did before.
//!
//! At start the configuration is checked against the black box's
//! filesystem: the retention it describes (`(segments + reserve) x
//! segment_bytes`, minus what the directory already holds) must fit in the
//! free space, else agentd refuses to start (a store that cannot grow to
//! its configured size fails mid-incident instead).
//!
//! Findings (observe-only self-health, `agentd:blackbox`):
//!
//! | condition | rule (detail prefix) | severity |
//! |---|---|---|
//! | unexported segments reach `warn_percent` of the capacity (protection on, or saturation mode) | `robot.agent.evidence_degraded` (`retention pressure:`) | Medium (High from 95 %) |
//! | cyclic retention dropped unexported evidence (protection on) | `robot.agent.evidence_degraded` (`unexported evidence dropped:`) | High |
//!
//! Both use the catalogued `evidence_degraded` id for now: a dedicated id
//! is a findings-contract minor bump, left to the next one.
//!
//! The pressure finding is raised once per episode (it clears below
//! `warn_percent - 10`). With protection on and `warn_percent` 80, it comes
//! at least `0.2 x (segments + reserve)` segment rotations before the first
//! unexported drop; at the sizing table's write rates that is hours
//! (docs/OPERATIONS.md 6.4, "Black-box sizing"). Plain cyclic retention
//! without an exporter drops by design and raises neither finding.

use robodr_blackbox::{RecorderConfig, RetentionMode, RetentionStatus};
use robodr_events::{Deviation, Severity};
use serde::Deserialize;

/// Unexported black-box evidence fills the configured retention.
///
/// Raised under the catalogued `robot.agent.evidence_degraded` id (valid
/// in every contract minor; the detail says which condition it is) until
/// the next findings-contract minor gives it a dedicated id (a catalog
/// entry is a contract bump: docs/contracts/robodr.findings.md §5).
pub const EVIDENCE_RETENTION_PRESSURE: &str = crate::health::rules::EVIDENCE_DEGRADED;
/// Cyclic retention dropped black-box evidence that had not been exported
/// (same id, see [`EVIDENCE_RETENTION_PRESSURE`]).
pub const EVIDENCE_UNEXPORTED_DROPPED: &str = crate::health::rules::EVIDENCE_DEGRADED;

/// Smallest segment size accepted.
pub const MIN_SEGMENT_BYTES: u64 = 64 * 1024;
/// Largest segment size accepted (a segment is read whole by recovery).
pub const MAX_SEGMENT_BYTES: u64 = 256 * 1024 * 1024;
/// Most segments (normal + reserve) accepted.
pub const MAX_SEGMENTS: u32 = 65_536;

/// Retention mode names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RetentionKind {
    #[default]
    Cyclic,
    Saturation,
}

fn d_segments() -> u32 {
    8
}
fn d_segment_bytes() -> u64 {
    8 * 1024 * 1024
}
fn d_critical() -> u32 {
    1
}
fn d_warn() -> u8 {
    80
}

/// `blackbox.retention`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionConfig {
    #[serde(default)]
    pub mode: RetentionKind,
    #[serde(default = "d_segments")]
    pub segments: u32,
    #[serde(default = "d_segment_bytes")]
    pub segment_bytes: u64,
    /// Cyclic only: pending-export protection (see the module docs).
    #[serde(default)]
    pub unexported_reserve_segments: u32,
    /// Saturation only: segments kept for critical records once full.
    #[serde(default = "d_critical")]
    pub critical_reserve_segments: u32,
    /// Unexported fill (percent of the capacity) that raises
    /// [`EVIDENCE_RETENTION_PRESSURE`]; 50..=99.
    #[serde(default = "d_warn")]
    pub warn_percent: u8,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            mode: RetentionKind::Cyclic,
            segments: d_segments(),
            segment_bytes: d_segment_bytes(),
            unexported_reserve_segments: 0,
            critical_reserve_segments: d_critical(),
            warn_percent: d_warn(),
        }
    }
}

impl RetentionConfig {
    /// Range and consistency checks (no file system access).
    pub fn validate(&self) -> Result<(), String> {
        let p = "blackbox.retention";
        if !(1..=MAX_SEGMENTS).contains(&self.segments) {
            return Err(format!("{p}.segments must be 1..={MAX_SEGMENTS}"));
        }
        if !(MIN_SEGMENT_BYTES..=MAX_SEGMENT_BYTES).contains(&self.segment_bytes) {
            return Err(format!(
                "{p}.segment_bytes must be {MIN_SEGMENT_BYTES}..={MAX_SEGMENT_BYTES}"
            ));
        }
        if !(50..=99).contains(&self.warn_percent) {
            return Err(format!("{p}.warn_percent must be 50..=99"));
        }
        match self.mode {
            RetentionKind::Cyclic => {
                if self.unexported_reserve_segments > MAX_SEGMENTS - self.segments {
                    return Err(format!(
                        "{p}: segments + unexported_reserve_segments must be <= {MAX_SEGMENTS}"
                    ));
                }
            }
            RetentionKind::Saturation => {
                if self.unexported_reserve_segments != 0 {
                    return Err(format!(
                        "{p}.unexported_reserve_segments applies to mode cyclic only \
                         (saturation never drops evidence)"
                    ));
                }
                if !(1..=MAX_SEGMENTS - self.segments).contains(&self.critical_reserve_segments) {
                    return Err(format!(
                        "{p}.critical_reserve_segments must be >= 1 and segments + \
                         critical_reserve_segments <= {MAX_SEGMENTS}"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Segments the store may hold at most.
    pub fn capacity_segments(&self) -> u64 {
        u64::from(self.segments)
            + u64::from(match self.mode {
                RetentionKind::Cyclic => self.unexported_reserve_segments,
                RetentionKind::Saturation => self.critical_reserve_segments,
            })
    }

    /// Bytes the store may grow to (segments only; state files are a few
    /// KiB).
    pub fn capacity_bytes(&self) -> u64 {
        self.capacity_segments().saturating_mul(self.segment_bytes)
    }

    /// Apply to the recorder's configuration.
    pub fn apply(&self, c: &mut RecorderConfig) {
        c.max_segment_bytes = self.segment_bytes;
        match self.mode {
            RetentionKind::Cyclic => {
                c.mode = RetentionMode::Cyclic {
                    max_segments: self.segments,
                };
                c.unexported_reserve_segments = self.unexported_reserve_segments;
            }
            RetentionKind::Saturation => {
                c.mode = RetentionMode::Saturation {
                    max_segments: self.segments,
                    critical_reserve_segments: self.critical_reserve_segments,
                };
                c.unexported_reserve_segments = 0;
            }
        }
    }

    /// The configured retention must fit: `need` = capacity minus what the
    /// directory's segments already hold, against `free` bytes on its
    /// filesystem (`None`: unknown, not checked).
    pub fn check_space(&self, used: u64, free: Option<u64>) -> Result<(), String> {
        let Some(free) = free else {
            return Ok(());
        };
        let need = self.capacity_bytes().saturating_sub(used);
        if need > free {
            return Err(format!(
                "blackbox.retention needs {need} more bytes ({} segments of {} bytes, {used} \
                 already used) but the black box's filesystem has {free} free: lower segments \
                 / segment_bytes / the reserve, or give the black box more space \
                 (docs/OPERATIONS.md 6.4, \"Black-box sizing\")",
                self.capacity_segments(),
                self.segment_bytes
            ));
        }
        Ok(())
    }
}

/// Bytes held by the segment files in `dir` (0 if it does not exist yet).
pub fn segments_bytes(dir: &std::path::Path) -> u64 {
    robodr_blackbox::store::list_segments(dir)
        .map(|v| {
            v.iter()
                .filter_map(|(_, p)| std::fs::symlink_metadata(p).ok())
                .map(|m| m.len())
                .sum()
        })
        .unwrap_or(0)
}

/// Turns successive [`RetentionStatus`] readings into findings (pure).
#[derive(Debug, Clone, Default)]
pub struct RetentionWatch {
    warned: bool,
    drops_seen: u64,
}

impl RetentionWatch {
    /// Findings for this reading. `saturation`: the store refuses instead
    /// of dropping (pressure is reported there too).
    pub fn observe(
        &mut self,
        st: &RetentionStatus,
        warn_percent: u8,
        saturation: bool,
    ) -> Vec<Deviation> {
        let mut out = Vec::new();
        if !(st.protecting || saturation) {
            return out;
        }
        let fill = st.unexported_fill_percent();
        let warn = u64::from(warn_percent);
        if fill >= warn && !self.warned {
            self.warned = true;
            let sev = if fill >= 95 {
                Severity::High
            } else {
                Severity::Medium
            };
            let then = if saturation {
                "when it is full, non-critical records are refused"
            } else {
                "when it is full, the oldest unexported segment is dropped"
            };
            out.push(Deviation::new(
                EVIDENCE_RETENTION_PRESSURE,
                sev,
                format!(
                    "retention pressure: black-box evidence not yet exported fills {fill} % of the retention ({} of \
                     {} segments, {} records after the export position {}); {then}: run the \
                     export (robodr-blackbox export-pending) or check the diode / media path",
                    st.unexported_segments,
                    st.capacity_segments,
                    st.unexported_records,
                    st.confirmed_export_seq
                        .map_or_else(|| "none".to_string(), |s| s.to_string()),
                ),
            ));
        } else if self.warned && fill + 10 < warn {
            self.warned = false;
        }
        // A reopened recorder counts from 0 again.
        if st.unexported_drops < self.drops_seen {
            self.drops_seen = 0;
        }
        if st.protecting && st.unexported_drops > self.drops_seen {
            let delta = st.unexported_drops - self.drops_seen;
            self.drops_seen = st.unexported_drops;
            out.push(Deviation::new(
                EVIDENCE_UNEXPORTED_DROPPED,
                Severity::High,
                format!(
                    "unexported evidence dropped: cyclic retention dropped {delta} black-box segment(s) holding evidence that \
                     had not been exported (the pending-export reserve was used up; each drop \
                     is a signed SegmentDropped record with exported: false): the evidence is \
                     gone from the unit; check the export path and the sizing"
                ),
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st(unexported: u64, cap: u64, drops: u64, protecting: bool) -> RetentionStatus {
        RetentionStatus {
            segments: unexported,
            capacity_segments: cap,
            unexported_segments: unexported,
            unexported_records: unexported * 100,
            confirmed_export_seq: None,
            unexported_drops: drops,
            protecting,
        }
    }

    #[test]
    fn config_defaults_ranges_and_apply() {
        let c: RetentionConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(c, RetentionConfig::default());
        c.validate().unwrap();
        assert_eq!(c.capacity_bytes(), 64 * 1024 * 1024);
        for bad in [
            r#"{"segments": 0}"#,
            r#"{"segment_bytes": 1024}"#,
            r#"{"warn_percent": 100}"#,
            r#"{"mode": "saturation", "unexported_reserve_segments": 2}"#,
            r#"{"mode": "saturation", "critical_reserve_segments": 0}"#,
            r#"{"segments": 65536, "unexported_reserve_segments": 1}"#,
        ] {
            let c: RetentionConfig = serde_json::from_str(bad).unwrap();
            assert!(c.validate().is_err(), "{bad}");
        }
        assert!(serde_json::from_str::<RetentionConfig>(r#"{"mode": "ring"}"#).is_err());
        assert!(serde_json::from_str::<RetentionConfig>(r#"{"segmnets": 4}"#).is_err());
        let c: RetentionConfig = serde_json::from_str(
            r#"{"segments": 4, "segment_bytes": 1048576, "unexported_reserve_segments": 6}"#,
        )
        .unwrap();
        c.validate().unwrap();
        let mut rc = RecorderConfig::new("/x", "d", "b");
        c.apply(&mut rc);
        assert_eq!(rc.mode, RetentionMode::Cyclic { max_segments: 4 });
        assert_eq!(rc.unexported_reserve_segments, 6);
        assert_eq!(rc.max_segment_bytes, 1 << 20);
        assert_eq!(c.capacity_bytes(), 10 << 20);
    }

    #[test]
    fn space_check_counts_what_is_already_there() {
        let c = RetentionConfig {
            segments: 4,
            segment_bytes: 1 << 20,
            ..RetentionConfig::default()
        };
        c.check_space(0, Some(4 << 20)).unwrap();
        assert!(c.check_space(0, Some((4 << 20) - 1)).is_err());
        c.check_space(3 << 20, Some(1 << 20)).unwrap();
        c.check_space(0, None).unwrap();
    }

    #[test]
    fn pressure_once_per_episode_then_drops_reported_by_delta() {
        let mut w = RetentionWatch::default();
        // Plain cyclic (no exporter): drops are by design, nothing raised.
        assert!(w.observe(&st(8, 8, 5, false), 80, false).is_empty());
        let mut w = RetentionWatch::default();
        assert!(w.observe(&st(12, 16, 0, true), 80, false).is_empty());
        let f = w.observe(&st(13, 16, 0, true), 80, false);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_str(), EVIDENCE_RETENTION_PRESSURE);
        assert!(
            f[0].detail.starts_with("retention pressure:"),
            "{}",
            f[0].detail
        );
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(w.observe(&st(14, 16, 0, true), 80, false).is_empty());
        let f = w.observe(&st(16, 16, 2, true), 80, false);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_str(), EVIDENCE_UNEXPORTED_DROPPED);
        assert!(f[0].detail.starts_with("unexported evidence dropped:"));
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].detail.contains("dropped 2 "), "{}", f[0].detail);
        assert!(w.observe(&st(16, 16, 2, true), 80, false).is_empty());
        // An export brings it down; the next episode warns again, High at 95 %.
        assert!(w.observe(&st(2, 16, 2, true), 80, false).is_empty());
        let f = w.observe(&st(16, 16, 2, true), 80, false);
        assert_eq!(f[0].severity, Severity::High);
        // A reopened recorder counts drops from 0.
        assert!(w.observe(&st(16, 16, 0, true), 80, false).is_empty());
        let f = w.observe(&st(16, 16, 1, true), 80, false);
        assert!(f
            .iter()
            .any(|d| d.detail.starts_with("unexported evidence dropped:")));
        // Saturation mode: pressure is reported without protection.
        let mut w = RetentionWatch::default();
        let f = w.observe(&st(9, 10, 0, false), 80, true);
        assert_eq!(f.len(), 1);
        assert!(f[0].detail.contains("refused"));
    }
}
