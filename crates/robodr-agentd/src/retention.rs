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
//!     "warn_percent": 80,
//!     "export": "auto"
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
//! * `export` (default `auto`): whether this site exports the black box,
//!   for the plain-cyclic drop finding below. `auto`: report plain-cyclic
//!   drops of unexported evidence only once an export cursor exists (an
//!   export ran at least once, so the site exports and the exporter fell
//!   behind or stopped). `expected`: report them even before the first
//!   export (a site that must export and wants to hear that it never
//!   did). `none`: the site does not export the black box; plain-cyclic
//!   drops are by design and not reported. `none` refuses a pending-export
//!   reserve (it would hold segments for an export that never comes).
//! * Without a `retention` section the recorder's defaults apply (cyclic,
//!   8 x 8 MiB, no reserve; 12-14 h at the sizing table's soak rate) and
//!   `export` is `auto`: segments are dropped whether exported or not, and
//!   drops of unexported ones are reported only on a unit that has
//!   exported before (below).
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
//! | unexported segments reach `warn_percent` of the capacity (protection on, or saturation mode) | `robot.agent.evidence_retention_pressure` | Medium; High from 95 % (raised again if the episode climbs there) |
//! | cyclic retention dropped unexported evidence (protection on) | `robot.agent.evidence_unexported_dropped` | High, every new drop |
//! | cyclic retention dropped unexported evidence (no reserve: plain cyclic, the default), `export` `auto` with an export cursor, or `expected` | `robot.agent.evidence_unexported_dropped` | Medium, at most once a day with the count since the last report |
//!
//! Both ids are contract 2.5 catalog entries (`robodr-ocsf` `catalog_2_5`);
//! before 2.5 these conditions were reported as `robot.agent.evidence_degraded`,
//! which now again means only that the recorder failed to store evidence.
//!
//! The pressure finding is raised once per episode (it clears below
//! `warn_percent - 10`), and once more at High if an episode that started
//! below 95 % reaches 95 %. With protection on and `warn_percent` 80, it
//! comes at least `0.2 x (segments + reserve)` segment rotations before the
//! first unexported drop; at the sizing table's write rates that is hours
//! (docs/OPERATIONS.md 6.4, "Black-box sizing"). Plain cyclic retention has
//! no pressure finding (without an exporter every segment is unexported, so
//! it would always be full). Its drops of records no export confirmed are
//! reported (Medium, at most once a day) when `export` says the site
//! exports: `expected`, or `auto` once an export cursor exists. On the
//! default configuration a unit that was never exported stays quiet (its
//! cyclic drops are normal operation), and a unit whose exporter stopped
//! says so instead of losing evidence quietly. Drops made while `auto`
//! held the finding back (no cursor yet) are not reported later.
//! Drops are counted per recorder generation (`AgentStats::blackbox_reopens`):
//! a reopened recorder counts from 0, and what the previous one dropped but
//! was not yet reported is carried over.

use robodr_blackbox::{RecorderConfig, RetentionMode, RetentionStatus};
use robodr_events::{Deviation, Severity};
use serde::Deserialize;

/// Unexported black-box evidence fills the configured retention (contract
/// 2.5, docs/contracts/robodr.findings.md §3g).
pub const EVIDENCE_RETENTION_PRESSURE: &str = "robot.agent.evidence_retention_pressure";
/// Cyclic retention dropped black-box evidence that had not been exported
/// (contract 2.5).
pub const EVIDENCE_UNEXPORTED_DROPPED: &str = "robot.agent.evidence_unexported_dropped";

/// Plain cyclic retention (no pending-export reserve): unexported drops
/// are reported at most this often (with the count since the last report).
pub const PLAIN_DROP_REPORT_MS: u64 = 24 * 60 * 60 * 1000;

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

/// `blackbox.retention.export`: whether the site exports the black box
/// (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExportKind {
    /// Report plain-cyclic unexported drops once an export cursor exists.
    #[default]
    Auto,
    /// Report them even before the first export.
    Expected,
    /// The site does not export the black box: never report them.
    None,
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
    /// Whether the site exports the black box (plain-cyclic drop finding).
    #[serde(default)]
    pub export: ExportKind,
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
            export: ExportKind::Auto,
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
        if self.export == ExportKind::None && self.unexported_reserve_segments != 0 {
            return Err(format!(
                "{p}.unexported_reserve_segments needs an export: it holds segments until \
                 an export confirms them, and export is none"
            ));
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
    /// Severity raised in the current pressure episode.
    warned: Option<Severity>,
    /// Recorder generation the counters below belong to.
    generation: Option<u64>,
    /// Unexported drops of this generation already reported.
    drops_seen: u64,
    /// Unexported drops of this generation at the last reading.
    drops_last: u64,
    /// Drops of earlier generations not reported yet.
    drops_carried: u64,
    /// When plain cyclic retention last reported drops.
    plain_reported_ms: Option<u64>,
}

impl RetentionWatch {
    /// Findings for this reading. `saturation`: the store refuses instead
    /// of dropping (pressure is reported there too). `generation`
    /// identifies the recorder (`AgentStats::blackbox_reopens`: a reopened
    /// recorder counts its drops from 0 again); `now_ms` is a monotonic
    /// clock for the plain-cyclic rate limit; `export` gates the
    /// plain-cyclic drop finding.
    pub fn observe(
        &mut self,
        st: &RetentionStatus,
        warn_percent: u8,
        saturation: bool,
        export: ExportKind,
        generation: u64,
        now_ms: u64,
    ) -> Vec<Deviation> {
        let mut out = Vec::new();
        if st.protecting || saturation {
            self.pressure(st, warn_percent, saturation, &mut out);
        }
        self.drops(st, saturation, export, generation, now_ms, &mut out);
        out
    }

    fn pressure(
        &mut self,
        st: &RetentionStatus,
        warn_percent: u8,
        saturation: bool,
        out: &mut Vec<Deviation>,
    ) {
        let fill = st.unexported_fill_percent();
        let warn = u64::from(warn_percent);
        if self.warned.is_some() && fill + 10 < warn {
            self.warned = None;
            return;
        }
        if fill < warn {
            return;
        }
        let sev = if fill >= 95 {
            Severity::High
        } else {
            Severity::Medium
        };
        // Once per episode, and once more if it climbs to High.
        if self.warned == Some(Severity::High) || self.warned == Some(sev) {
            return;
        }
        self.warned = Some(sev);
        let then = if saturation {
            "when it is full, non-critical records are refused"
        } else {
            "when it is full, the oldest unexported segment is dropped"
        };
        out.push(Deviation::new(
            EVIDENCE_RETENTION_PRESSURE,
            sev,
            format!(
                "retention pressure: black-box evidence not yet exported fills {fill} % of the \
                 retention ({} of {} segments, {} records after the export position {}); \
                 {then}: run the export (robodr-blackbox export-pending) or check the diode / \
                 media path",
                st.unexported_segments,
                st.capacity_segments,
                st.unexported_records,
                st.confirmed_export_seq
                    .map_or_else(|| "none".to_string(), |s| s.to_string()),
            ),
        ));
    }

    fn drops(
        &mut self,
        st: &RetentionStatus,
        saturation: bool,
        export: ExportKind,
        generation: u64,
        now_ms: u64,
        out: &mut Vec<Deviation>,
    ) {
        // A new recorder counts from 0: keep what the old one dropped and
        // was not reported yet.
        let reopened = self.generation.is_some_and(|g| g != generation)
            || st.unexported_drops < self.drops_last;
        if reopened {
            self.drops_carried = self
                .drops_carried
                .saturating_add(self.drops_last.saturating_sub(self.drops_seen));
            self.drops_seen = 0;
        }
        self.generation = Some(generation);
        self.drops_last = st.unexported_drops;
        let new = st
            .unexported_drops
            .saturating_sub(self.drops_seen)
            .saturating_add(self.drops_carried);
        if new == 0 || saturation {
            return;
        }
        let dev = if st.protecting {
            Deviation::new(
                EVIDENCE_UNEXPORTED_DROPPED,
                Severity::High,
                format!(
                    "unexported evidence dropped: cyclic retention dropped {new} black-box \
                     segment(s) holding evidence that had not been exported (the \
                     pending-export reserve was used up; each drop is a signed SegmentDropped \
                     record with exported: false): the evidence is gone from the unit; check \
                     the export path and the sizing"
                ),
            )
        } else {
            // Plain cyclic retention drops by design. Report it only where
            // the site exports (an exporter that stopped or fell behind),
            // at most once a day; what is held back here is not reported
            // later.
            let report = match export {
                ExportKind::None => false,
                ExportKind::Expected => true,
                ExportKind::Auto => st.confirmed_export_seq.is_some(),
            };
            if !report {
                self.drops_seen = st.unexported_drops;
                self.drops_carried = 0;
                return;
            }
            if self
                .plain_reported_ms
                .is_some_and(|t| now_ms.saturating_sub(t) < PLAIN_DROP_REPORT_MS)
            {
                return;
            }
            self.plain_reported_ms = Some(now_ms);
            Deviation::new(
                EVIDENCE_UNEXPORTED_DROPPED,
                Severity::Medium,
                format!(
                    "unexported evidence dropped: cyclic retention dropped {new} black-box \
                     segment(s) whose records no export had confirmed (each drop is a signed \
                     SegmentDropped record with exported: false). No pending-export reserve \
                     is configured (blackbox.retention.unexported_reserve_segments = 0), so \
                     the black box keeps only its last {} segments; check that the export \
                     runs (robodr-blackbox export-pending, OPERATIONS 8.2) and set the \
                     reserve, or set blackbox.retention.export to none if this site does not \
                     export the black box. Reported at most once a day",
                    st.capacity_segments
                ),
            )
        };
        self.drops_seen = st.unexported_drops;
        self.drops_carried = 0;
        out.push(dev);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: ExportKind = ExportKind::Auto;

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

    /// Review (WP4): an episode that starts below 95 % is escalated to High
    /// when it crosses 95 %, once.
    #[test]
    fn pressure_escalates_to_high_at_95_percent() {
        let mut w = RetentionWatch::default();
        let f = w.observe(&st(81, 100, 0, true), 80, false, A, 0, 0);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(w
            .observe(&st(90, 100, 0, true), 80, false, A, 0, 0)
            .is_empty());
        let f = w.observe(&st(96, 100, 0, true), 80, false, A, 0, 0);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].detail.starts_with("retention pressure:"));
        assert!(w
            .observe(&st(99, 100, 0, true), 80, false, A, 0, 0)
            .is_empty());
        // Down and up again: a new episode.
        assert!(w
            .observe(&st(10, 100, 0, true), 80, false, A, 0, 0)
            .is_empty());
        let f = w.observe(&st(85, 100, 0, true), 80, false, A, 0, 0);
        assert_eq!(f[0].severity, Severity::Medium);
    }

    /// Review (WP4): a reopened recorder (new generation) counts drops from
    /// 0; drops it made before the next reading are all reported, even when
    /// its counter has already passed the old one.
    #[test]
    fn drops_are_counted_per_recorder_generation() {
        let mut w = RetentionWatch::default();
        let f = w.observe(&st(16, 16, 3, true), 80, false, A, 0, 0);
        assert!(f.iter().any(|d| d.detail.contains("dropped 3 ")), "{f:?}");
        // Reopened (generation 1) and already 4 drops since: 4 new ones.
        let f = w.observe(&st(16, 16, 4, true), 80, false, A, 1, 0);
        assert!(f.iter().any(|d| d.detail.contains("dropped 4 ")), "{f:?}");
        assert!(w
            .observe(&st(16, 16, 4, true), 80, false, A, 1, 0)
            .is_empty());
    }

    /// Review (WP4): plain cyclic retention (no reserve) with `export`
    /// `expected` reports evidence dropped before any export confirmed it:
    /// Medium, at most once a day with the count since the last report.
    #[test]
    fn plain_cyclic_reports_unexported_drops_once_a_day() {
        let day = PLAIN_DROP_REPORT_MS;
        let mut w = RetentionWatch::default();
        assert!(w
            .observe(&st(8, 8, 0, false), 80, false, ExportKind::Expected, 0, 0)
            .is_empty());
        let f = w.observe(
            &st(8, 8, 1, false),
            80,
            false,
            ExportKind::Expected,
            0,
            1_000,
        );
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].rule_str(), EVIDENCE_UNEXPORTED_DROPPED);
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(f[0].detail.starts_with("unexported evidence dropped:"));
        assert!(f[0].detail.contains("unexported_reserve_segments"));
        // More drops within the day: held back, then reported together.
        assert!(w
            .observe(
                &st(8, 8, 5, false),
                80,
                false,
                ExportKind::Expected,
                0,
                1_000 + day / 2
            )
            .is_empty());
        // A reopen in between carries what was not reported yet.
        assert!(w
            .observe(
                &st(8, 8, 2, false),
                80,
                false,
                ExportKind::Expected,
                1,
                1_000 + day / 2 + 1
            )
            .is_empty());
        let f = w.observe(
            &st(8, 8, 2, false),
            80,
            false,
            ExportKind::Expected,
            1,
            1_000 + day,
        );
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].detail.contains("dropped 6 "), "{}", f[0].detail);
        assert!(w
            .observe(
                &st(8, 8, 2, false),
                80,
                false,
                ExportKind::Expected,
                1,
                1_000 + 3 * day
            )
            .is_empty());
    }

    /// Review (WP4 phase 3): on the default configuration (plain cyclic,
    /// `export` `auto`) a unit that was never exported does not report its
    /// cyclic drops (normal operation); once an export cursor exists, drops
    /// of unexported evidence are reported, without the ones from before.
    #[test]
    fn plain_cyclic_default_is_quiet_until_an_export_cursor_exists() {
        let day = PLAIN_DROP_REPORT_MS;
        let mut w = RetentionWatch::default();
        for i in 1..=5u64 {
            assert!(w
                .observe(&st(8, 8, i * 10, false), 80, false, A, 0, i * day)
                .is_empty());
        }
        let mut s = st(8, 8, 53, false);
        s.confirmed_export_seq = Some(1_000);
        let f = w.observe(&s, 80, false, A, 0, 6 * day);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].rule_str(), EVIDENCE_UNEXPORTED_DROPPED);
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(f[0].detail.contains("dropped 3 "), "{}", f[0].detail);
        assert!(f[0].detail.contains("export to none"), "{}", f[0].detail);
    }

    /// Review (WP4 phase 3): `export` `none` silences the plain-cyclic drop
    /// finding even with an export cursor, and refuses a pending-export
    /// reserve.
    #[test]
    fn export_none_never_reports_plain_drops_and_refuses_a_reserve() {
        let mut w = RetentionWatch::default();
        let mut s = st(8, 8, 4, false);
        s.confirmed_export_seq = Some(10);
        for i in 0..5u64 {
            s.unexported_drops += i;
            assert!(w
                .observe(&s, 80, false, ExportKind::None, 0, i * PLAIN_DROP_REPORT_MS)
                .is_empty());
        }
        let c: RetentionConfig = serde_json::from_str(r#"{"export": "none"}"#).unwrap();
        c.validate().unwrap();
        let c: RetentionConfig =
            serde_json::from_str(r#"{"export": "none", "unexported_reserve_segments": 2}"#)
                .unwrap();
        assert!(c.validate().unwrap_err().contains("export is none"));
        assert!(serde_json::from_str::<RetentionConfig>(r#"{"export": "never"}"#).is_err());
        // Protection on: drops are always reported (the reserve means the
        // site exports).
        let mut w = RetentionWatch::default();
        let f = w.observe(&st(16, 16, 1, true), 80, false, A, 0, 0);
        assert!(f
            .iter()
            .any(|d| d.rule_str() == EVIDENCE_UNEXPORTED_DROPPED));
    }

    #[test]
    fn retention_findings_have_their_own_catalogued_ids() {
        for id in [EVIDENCE_RETENTION_PRESSURE, EVIDENCE_UNEXPORTED_DROPPED] {
            assert_ne!(id, crate::health::rules::EVIDENCE_DEGRADED);
            assert!(robodr_ocsf::builder::rule_known(id), "{id}");
        }
    }

    #[test]
    fn pressure_once_per_episode_then_drops_reported_by_delta() {
        let mut w = RetentionWatch::default();
        assert!(w
            .observe(&st(12, 16, 0, true), 80, false, A, 0, 0)
            .is_empty());
        let f = w.observe(&st(13, 16, 0, true), 80, false, A, 0, 0);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_str(), EVIDENCE_RETENTION_PRESSURE);
        assert!(
            f[0].detail.starts_with("retention pressure:"),
            "{}",
            f[0].detail
        );
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(w
            .observe(&st(14, 16, 0, true), 80, false, A, 0, 0)
            .is_empty());
        // Full: the episode escalates to High, and the drop is reported.
        let f = w.observe(&st(16, 16, 2, true), 80, false, A, 0, 0);
        assert_eq!(f.len(), 2, "{f:?}");
        assert!(f[0].detail.starts_with("retention pressure:"));
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[1].rule_str(), EVIDENCE_UNEXPORTED_DROPPED);
        assert!(f[1].detail.starts_with("unexported evidence dropped:"));
        assert_eq!(f[1].severity, Severity::High);
        assert!(f[1].detail.contains("dropped 2 "), "{}", f[1].detail);
        assert!(w
            .observe(&st(16, 16, 2, true), 80, false, A, 0, 0)
            .is_empty());
        // An export brings it down; the next episode warns again, High at 95 %.
        assert!(w
            .observe(&st(2, 16, 2, true), 80, false, A, 0, 0)
            .is_empty());
        let f = w.observe(&st(16, 16, 2, true), 80, false, A, 0, 0);
        assert_eq!(f[0].severity, Severity::High);
        // A reopened recorder (generation 1) counts drops from 0.
        assert!(w
            .observe(&st(16, 16, 0, true), 80, false, A, 1, 0)
            .is_empty());
        let f = w.observe(&st(16, 16, 1, true), 80, false, A, 1, 0);
        assert!(f
            .iter()
            .any(|d| d.detail.starts_with("unexported evidence dropped:")));
        // Saturation mode: pressure is reported without protection.
        let mut w = RetentionWatch::default();
        let f = w.observe(&st(9, 10, 0, false), 80, true, A, 0, 0);
        assert_eq!(f.len(), 1);
        assert!(f[0].detail.contains("refused"));
    }
}
