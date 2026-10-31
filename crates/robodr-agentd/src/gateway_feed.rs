//! The in-path gateway's findings feed (`gateway_feed`): `robodr-firewall-gw`
//! writes one JSON line per aggregated gateway finding (`robot.gateway.*`,
//! findings contract 2.3) and per Motion Firewall deviation
//! (`robot.firewall.*`) to this unix socket; agentd turns each into a
//! finding of its normal pipeline (black box, spool, responder,
//! correlation), source `gateway:<channel>`.
//!
//! ```json
//! {"format":"robodr-gateway-finding/v1","rule":"robot.gateway.trajectory_rejected",
//!  "severity":"high","detail":"channel /arm: 3 time(s) ...","mode":"enforce",
//!  "channel":"/arm","count":3}
//! ```
//!
//! The socket has the same shape and peer check as `host_threats`
//! ([`crate::host::bind_host_socket`]: root and `allowed_uids`, the
//! gateway's service user, may connect; the daemon's own uid too). A line
//! is parsed strictly ([`parse_gateway_line`]). An idle gateway also
//! writes a heartbeat line ([`HEARTBEAT_FORMAT`]): valid data on the input
//! (a quiet gateway is not a silent input), never a finding; a gateway
//! that stops writing is still reported silent after `daemon.silence_ms`.
//! For a finding line, unknown keys, another
//! format, a rule outside `robot.gateway.*` / `robot.firewall.*` (the
//! gateway cannot speak for any other detector) or not in the findings
//! catalog (`robodr_ocsf::builder::rule_known`), or oversized fields are
//! malformed and dropped (counted by the input). The detail is kept as the
//! gateway wrote it (sanitized when logged; tainted in the finding).
//!
//! # Flood limit (sales-readiness T82, red team W2-5)
//!
//! The gateway aggregates per housekeeping period (100 ms by default), so
//! a sustained condition, or a process that may write to the socket and
//! floods it, could still put up to one line per (rule, channel) every
//! 100 ms into the spool. [`FeedLimiter`] bounds that per fixed window of
//! [`WINDOW_NS`] (60 s, opened by the first line): the first [`PER_KEY`]
//! lines of a (rule, channel) are reported one by one ([`CRITICAL_PER_KEY`]
//! for Critical lines), at most [`PER_WINDOW`] in all. A line past its
//! budget is **folded**: still recorded in the black box, not reported;
//! when the window closes each key with folded lines is reported once as
//! an aggregate with the same rule and channel, the most severe folded
//! severity (a Critical fold stays Critical), the summed gateway count and
//! the first folded line's detail. Lines of keys beyond [`MAX_KEYS`] are
//! folded into one `robot.gateway.findings_dropped` aggregate (with the
//! most severe folded severity).

use serde::Deserialize;

use crate::host::{HostThreatsSection, HostThreatsSpec};
use crate::input::Payload;

/// The line format tag (`robodr_firewall_gw::feed::FORMAT`).
pub const FORMAT: &str = "robodr-gateway-finding/v1";
/// The heartbeat line's tag (`robodr_firewall_gw::feed::HEARTBEAT_FORMAT`):
/// `{"format":"robodr-gateway-heartbeat/v1","sent":N,"dropped":N}`, written
/// by an idle gateway so that a quiet feed is not read as a silent input.
pub const HEARTBEAT_FORMAT: &str = "robodr-gateway-heartbeat/v1";

/// A gateway heartbeat: the feed's cumulative lines sent and dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayHeartbeat {
    #[serde(rename = "format")]
    _format: HeartbeatTag,
    pub sent: u64,
    pub dropped: u64,
}

/// Only [`HEARTBEAT_FORMAT`] deserializes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HeartbeatTag;

impl<'de> Deserialize<'de> for HeartbeatTag {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s == HEARTBEAT_FORMAT {
            Ok(HeartbeatTag)
        } else {
            Err(serde::de::Error::custom("not a gateway heartbeat"))
        }
    }
}
/// The decision summary line's tag (`robodr_firewall_gw::summary::FORMAT`,
/// sales-readiness T19): what the gateway enforced (its mode, fail
/// behaviour, the digests of its configuration, firewall and profile
/// files) and how it decided (counters since the previous line), at start,
/// every minute and at stop. Never a finding: agentd appends it to the
/// black box as a note (`gateway summary`; start and stop critical), so it
/// is signed and chained like every record.
pub const SUMMARY_FORMAT: &str = "robodr-gateway-summary/v1";

/// What a summary line says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SummaryEvent {
    Start,
    Interval,
    Stop,
}

/// The decision counters of a summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SummaryCounters {
    pub packets: u64,
    pub accepted: u64,
    pub modified: u64,
    pub dropped: u64,
    pub samples: u64,
    pub passed: u64,
    pub limited: u64,
    pub substituted: u64,
    pub suppressed: u64,
    pub late: u64,
    pub undecidable: u64,
}

/// A gateway decision summary (strict: unknown keys, another format, a
/// malformed digest or restriction id are malformed lines).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewaySummary {
    pub format: String,
    pub event: SummaryEvent,
    pub mode: robodr_events::Mode,
    pub on_gateway_down: OnGatewayDown,
    pub config_sha256: Option<String>,
    pub firewall_sha256: Option<String>,
    pub profile_sha256: Option<String>,
    pub interval_ms: u64,
    pub counters: SummaryCounters,
    pub firewall_faults: u64,
    pub restriction: Option<String>,
}

/// The gateway's `queue.on_gateway_down`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnGatewayDown {
    FailClosed,
    Bypass,
}

fn digest_ok(d: &Option<String>) -> bool {
    d.as_deref().is_none_or(|d| {
        d.strip_prefix("sha256:").is_some_and(|h| {
            h.len() == 64
                && h.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    })
}

fn parse_summary(t: &str) -> Result<Payload, String> {
    let s: GatewaySummary =
        serde_json::from_str(t).map_err(|e| format!("not a gateway summary: {e}"))?;
    if s.format != SUMMARY_FORMAT {
        return Err(format!("format must be {SUMMARY_FORMAT}"));
    }
    if !digest_ok(&s.config_sha256)
        || !digest_ok(&s.firewall_sha256)
        || !digest_ok(&s.profile_sha256)
    {
        return Err("a digest must be sha256:<64 lowercase hex>".into());
    }
    if s.restriction.as_deref().is_some_and(|r| {
        r.is_empty()
            || r.len() > 128
            || !r
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".:_-".contains(&b))
    }) {
        return Err("restriction must match [A-Za-z0-9._:-]{1,128}".into());
    }
    Ok(Payload::GatewaySummary(Box::new(s)))
}

/// Longest accepted detail (characters).
pub const MAX_DETAIL: usize = 1024;
/// Longest accepted rule id / channel name.
pub const MAX_RULE: usize = 128;
pub const MAX_CHANNEL: usize = 256;

/// `gateway_feed` in the configuration: the `host_threats` keys
/// (`socket_path`, `allowed_uids`, `socket_mode`, `max_connections`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct GatewayFeedSection(pub HostThreatsSection);

impl GatewayFeedSection {
    pub fn resolve(&self) -> Result<HostThreatsSpec, String> {
        self.0
            .resolve()
            .map_err(|e| e.replace("host_threats", "gateway_feed"))
    }
}

/// One gateway line.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayLine {
    pub format: String,
    pub rule: String,
    pub severity: robodr_events::Severity,
    pub detail: String,
    pub mode: robodr_events::Mode,
    #[serde(default)]
    pub channel: Option<String>,
    pub count: u64,
}

impl GatewayLine {
    /// The deviation this line stands for (rule, severity and mode as the
    /// gateway reported them; the detail names the gateway).
    pub fn deviation(&self) -> robodr_events::Deviation {
        robodr_events::Deviation::new(
            self.rule.clone(),
            self.severity,
            format!("in-path gateway: {}", self.detail),
        )
        .with_mode(self.mode)
    }

    /// The finding's source key.
    pub fn source(&self) -> String {
        format!("gateway:{}", self.channel.as_deref().unwrap_or("-"))
    }
}

fn rule_ok(r: &str) -> bool {
    // Only ids of the findings catalog: a line naming `robot.firewall.` or
    // a made-up id in the two namespaces would otherwise become a finding
    // with the generic catalog entry (red team 2026-10-30, G3).
    ((r.starts_with("robot.gateway.") || r.starts_with("robot.firewall."))
        && robodr_ocsf::builder::rule_known(r)
        // The gateway's WebRTC monitor: exactly its own ids.
        || robodr_ros2_pipeline::webrtc::rules::ALL
            .iter()
            .any(|(id, _)| *id == r))
        && r.len() <= MAX_RULE
        && r.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_')
}

/// Window of the feed limit (module docs, "Flood limit").
pub const WINDOW_NS: u64 = 60_000_000_000;
/// Lines below Critical reported per (rule, channel) and window.
pub const PER_KEY: u32 = 4;
/// Critical lines reported per (rule, channel) and window.
pub const CRITICAL_PER_KEY: u32 = 8;
/// Lines reported per window in all.
pub const PER_WINDOW: u32 = 256;
/// (rule, channel) keys counted per window.
pub const MAX_KEYS: usize = 128;
/// The rule of the aggregate of lines whose key was not counted.
pub const OVERFLOW_RULE: &str = "robot.gateway.findings_dropped";

/// The decision of [`FeedLimiter::admit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    /// Report the line.
    Report,
    /// Record it only: it is counted into its key's aggregate.
    Fold,
}

#[derive(Debug, Clone)]
struct Folded {
    lines: u64,
    count: u64,
    severity: robodr_events::Severity,
    mode: robodr_events::Mode,
    first: String,
}

impl Folded {
    fn new(l: &GatewayLine) -> Self {
        Folded {
            lines: 0,
            count: 0,
            severity: l.severity,
            mode: l.mode,
            first: l.detail.clone(),
        }
    }

    fn add(&mut self, l: &GatewayLine) {
        self.lines = self.lines.saturating_add(1);
        self.count = self.count.saturating_add(l.count);
        self.severity = self.severity.max(l.severity);
        // An enforce-mode line makes the aggregate enforce mode.
        if l.mode == robodr_events::Mode::Enforce {
            self.mode = l.mode;
        }
    }
}

#[derive(Debug, Clone, Default)]
struct KeyState {
    reported: u32,
    reported_critical: u32,
    folded: Option<Folded>,
}

/// The feed's flood limit (module docs, "Flood limit").
#[derive(Debug, Default)]
pub struct FeedLimiter {
    start_ns: Option<u64>,
    reported: u32,
    keys: std::collections::BTreeMap<(String, Option<String>), KeyState>,
    overflow: Option<(Folded, Option<String>)>,
    /// Lines folded since start (status).
    pub folded_total: u64,
    /// Aggregates reported since start (status).
    pub aggregates_total: u64,
}

impl FeedLimiter {
    /// Report or fold `l` at monotonic `now_ns`. Closes an expired window
    /// first: its aggregates are returned with the decision and must be
    /// reported before the line.
    pub fn admit(&mut self, l: &GatewayLine, now_ns: u64) -> (Admit, Vec<GatewayLine>) {
        let closed = self.tick(now_ns);
        self.start_ns.get_or_insert(now_ns);
        let key = (l.rule.clone(), l.channel.clone());
        let tracked = self.keys.contains_key(&key) || self.keys.len() < MAX_KEYS;
        if !tracked {
            let (f, _) = self
                .overflow
                .get_or_insert_with(|| (Folded::new(l), l.channel.clone()));
            f.add(l);
            self.folded_total = self.folded_total.saturating_add(1);
            return (Admit::Fold, closed);
        }
        let critical = l.severity == robodr_events::Severity::Critical;
        let window_open = self.reported < PER_WINDOW;
        let k = self.keys.entry(key).or_default();
        let within = if critical {
            k.reported_critical < CRITICAL_PER_KEY
        } else {
            k.reported < PER_KEY
        };
        if within && window_open {
            if critical {
                k.reported_critical += 1;
            } else {
                k.reported += 1;
            }
            self.reported += 1;
            return (Admit::Report, closed);
        }
        k.folded.get_or_insert_with(|| Folded::new(l)).add(l);
        self.folded_total = self.folded_total.saturating_add(1);
        (Admit::Fold, closed)
    }

    /// Housekeeping at monotonic `now_ns`: the aggregates of a window that
    /// is [`WINDOW_NS`] old (and the window closed).
    pub fn tick(&mut self, now_ns: u64) -> Vec<GatewayLine> {
        match self.start_ns {
            Some(s) if now_ns.saturating_sub(s) >= WINDOW_NS => self.flush(),
            _ => Vec::new(),
        }
    }

    /// Close the window now (also at stop): one aggregate per key with
    /// folded lines, and the overflow aggregate.
    pub fn flush(&mut self) -> Vec<GatewayLine> {
        self.start_ns = None;
        self.reported = 0;
        let keys = std::mem::take(&mut self.keys);
        let mut out: Vec<GatewayLine> = keys
            .into_iter()
            .filter_map(|((rule, channel), k)| {
                k.folded
                    .map(|f| aggregate(rule, channel, &f, "this rule and channel"))
            })
            .collect();
        if let Some((f, channel)) = self.overflow.take() {
            out.push(aggregate(
                OVERFLOW_RULE.to_string(),
                channel,
                &f,
                &format!("more than {MAX_KEYS} rule and channel pairs"),
            ));
        }
        self.aggregates_total = self.aggregates_total.saturating_add(out.len() as u64);
        out
    }
}

fn aggregate(rule: String, channel: Option<String>, f: &Folded, what: &str) -> GatewayLine {
    let mut detail = format!(
        "{} gateway lines, gateway count {}, folded by the agentd feed limit: {what}, \
         {PER_KEY} or {CRITICAL_PER_KEY} Critical per {} s reported one by one; first: ",
        f.lines,
        f.count,
        WINDOW_NS / 1_000_000_000
    );
    let room = MAX_DETAIL.saturating_sub(detail.chars().count());
    detail.extend(f.first.chars().take(room));
    GatewayLine {
        format: FORMAT.to_string(),
        rule,
        severity: f.severity,
        detail,
        mode: f.mode,
        channel,
        count: f.count.max(1),
    }
}

/// [`crate::input::LineParser`] of the gateway feed.
pub fn parse_gateway_line(t: &str) -> Result<Payload, String> {
    // By the `format` member itself, never by a substring: a finding's
    // detail may quote attacker-chosen text.
    #[derive(Deserialize)]
    struct Tag<'a> {
        #[serde(borrow)]
        format: std::borrow::Cow<'a, str>,
    }
    if serde_json::from_str::<Tag<'_>>(t).is_ok_and(|g| g.format == HEARTBEAT_FORMAT) {
        let h: GatewayHeartbeat =
            serde_json::from_str(t).map_err(|e| format!("not a gateway heartbeat: {e}"))?;
        return Ok(Payload::GatewayHeartbeat(h));
    }
    if serde_json::from_str::<Tag<'_>>(t).is_ok_and(|g| g.format == SUMMARY_FORMAT) {
        return parse_summary(t);
    }
    let l: GatewayLine =
        serde_json::from_str(t).map_err(|e| format!("not a gateway finding: {e}"))?;
    if l.format != FORMAT {
        return Err(format!("format must be {FORMAT}"));
    }
    if !rule_ok(&l.rule) {
        return Err("rule must be a robot.gateway.*, robot.firewall.* or WebRTC monitor id".into());
    }
    if l.detail.chars().count() > MAX_DETAIL
        || l.channel.as_deref().is_some_and(|c| {
            c.is_empty() || c.chars().count() > MAX_CHANNEL || c.chars().any(char::is_control)
        })
        || l.count == 0
    {
        return Err(
            "detail too long, channel empty / too long / with control characters, or \
                    count 0"
                .into(),
        );
    }
    Ok(Payload::Gateway(Box::new(l)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webrtc_findings_of_the_gateway_are_accepted_other_unitree_ids_not() {
        let line = |r: &str| {
            format!(
                r#"{{"format":"robodr-gateway-finding/v1","rule":"{r}","severity":"critical","detail":"x","mode":"enforce","channel":"webrtc","count":1}}"#
            )
        };
        for (id, _) in robodr_ros2_pipeline::webrtc::rules::ALL {
            assert!(parse_gateway_line(&line(id)).is_ok(), "{id}");
        }
        let fake = ["robot", "unitree", "webrtc_anything"].join(".");
        assert!(parse_gateway_line(&line(&fake)).is_err());
        assert!(parse_gateway_line(&line("robot.unitree.legacy_unknown_sender")).is_err());
        assert!(parse_gateway_line(&line(&["robot", "unitree", "webrtc"].join("."))).is_err());
    }

    #[test]
    fn lines_are_strict() {
        let good = r#"{"format":"robodr-gateway-finding/v1","rule":"robot.gateway.trajectory_rejected","severity":"high","detail":"channel /arm: 1","mode":"enforce","channel":"/arm","count":1}"#;
        let Ok(Payload::Gateway(l)) = parse_gateway_line(good) else {
            panic!("good line refused");
        };
        assert_eq!(l.source(), "gateway:/arm");
        let d = l.deviation();
        assert_eq!(d.rule_str(), "robot.gateway.trajectory_rejected");
        assert_eq!(d.severity, robodr_events::Severity::High);
        assert!(d.detail.starts_with("in-path gateway: "));
        let fw = good.replace(
            "robot.gateway.trajectory_rejected",
            "robot.firewall.rejected_stale",
        );
        assert!(parse_gateway_line(&fw).is_ok());
        for bad in [
            good.replace(
                "robot.gateway.trajectory_rejected",
                "robot.ros2.unknown_participant",
            ),
            good.replace("robot.gateway.trajectory_rejected", "robot.gateway.X"),
            good.replace("robodr-gateway-finding/v1", "v2"),
            good.replace("\"count\":1", "\"count\":0"),
            good.replace("\"/arm\",\"count\"", "\"\",\"count\""),
            good.replace("\"count\":1}", "\"count\":1,\"x\":1}"),
            good.replace("channel /arm: 1", &"x".repeat(MAX_DETAIL + 1)),
        ] {
            assert!(parse_gateway_line(&bad).is_err(), "{bad}");
        }
    }

    /// Soak 2026-10-30: the gateway's heartbeat line keeps a quiet feed
    /// alive; it is as strict as a finding line.
    #[test]
    fn heartbeat_lines_are_strict() {
        let hb = r#"{"format":"robodr-gateway-heartbeat/v1","sent":7,"dropped":2}"#;
        match parse_gateway_line(hb) {
            Ok(Payload::GatewayHeartbeat(h)) => assert_eq!((h.sent, h.dropped), (7, 2)),
            other => panic!("{other:?}"),
        }
        // A finding whose detail quotes the heartbeat tag stays a finding.
        let quoted = r#"{"format":"robodr-gateway-finding/v1","rule":"robot.gateway.trajectory_rejected","severity":"high","detail":"robodr-gateway-heartbeat/v1","mode":"enforce","channel":"/arm","count":1}"#;
        assert!(matches!(
            parse_gateway_line(quoted),
            Ok(Payload::Gateway(_))
        ));
        for bad in [
            hb.replace(
                "\"dropped\":2}",
                "\"dropped\":2,\"rule\":\"robot.gateway.x\"}",
            ),
            hb.replace("heartbeat/v1", "heartbeat/v2"),
            hb.replace(",\"dropped\":2", ""),
            hb.replace("7", "-1"),
        ] {
            assert!(parse_gateway_line(&bad).is_err(), "{bad}");
        }
    }

    fn line(rule: &str, sev: robodr_events::Severity, channel: &str) -> GatewayLine {
        GatewayLine {
            format: FORMAT.into(),
            rule: rule.into(),
            severity: sev,
            detail: "d".into(),
            mode: robodr_events::Mode::Enforce,
            channel: Some(channel.into()),
            count: 3,
        }
    }

    /// Sales-readiness T82 (red team W2-5, G8 / G9): every gateway line
    /// became a spool record; a process allowed on the socket (or a
    /// sustained condition, one line per 100 ms housekeeping) filled the
    /// spool. Now each (rule, channel) gets a budget per window and the
    /// rest is one aggregate, Critical included.
    #[test]
    fn a_flood_of_one_rule_is_folded_into_one_aggregate_per_window() {
        use robodr_events::Severity::{Critical, High};
        let mut f = FeedLimiter::default();
        let ms = 1_000_000;
        let mut reported = 0;
        let mut aggregates = Vec::new();
        // 10 lines a second for 60 s, High and Critical, one channel.
        for i in 0..600u64 {
            for sev in [High, Critical] {
                let rule = if sev == Critical {
                    "robot.firewall.rejected_stale"
                } else {
                    "robot.gateway.trajectory_rejected"
                };
                let (a, closed) = f.admit(&line(rule, sev, "/arm"), i * 100 * ms);
                aggregates.extend(closed);
                if a == Admit::Report {
                    reported += 1;
                }
            }
        }
        assert_eq!(reported, PER_KEY + CRITICAL_PER_KEY);
        assert!(aggregates.is_empty());
        aggregates.extend(f.tick(WINDOW_NS));
        assert_eq!(aggregates.len(), 2, "{aggregates:?}");
        let crit = aggregates
            .iter()
            .find(|a| a.rule == "robot.firewall.rejected_stale")
            .unwrap();
        assert_eq!(crit.severity, Critical);
        assert_eq!(crit.count, 3 * u64::from(600 - CRITICAL_PER_KEY));
        assert_eq!(crit.channel.as_deref(), Some("/arm"));
        assert!(crit.detail.chars().count() <= MAX_DETAIL);
        // Aggregates are valid lines of the feed.
        for a in &aggregates {
            let j = format!(
                r#"{{"format":"{}","rule":"{}","severity":"{}","detail":{},"mode":"enforce","channel":"/arm","count":{}}}"#,
                a.format,
                a.rule,
                serde_json::to_value(a.severity).unwrap().as_str().unwrap(),
                serde_json::to_string(&a.detail).unwrap(),
                a.count
            );
            assert!(parse_gateway_line(&j).is_ok(), "{j}");
        }
        // A new window: the budget is back.
        let (a, _) = f.admit(
            &line("robot.gateway.trajectory_rejected", High, "/arm"),
            WINDOW_NS + ms,
        );
        assert_eq!(a, Admit::Report);
        assert_eq!(
            f.folded_total,
            2 * 600 - u64::from(PER_KEY + CRITICAL_PER_KEY)
        );
    }

    /// Many channels: at most PER_WINDOW lines a window in all, keys
    /// beyond MAX_KEYS folded into one `findings_dropped` aggregate that
    /// keeps the most severe severity; another channel's first lines are
    /// not hidden by one busy channel.
    #[test]
    fn the_window_and_the_key_table_are_bounded() {
        use robodr_events::Severity::{Critical, Medium};
        let mut f = FeedLimiter::default();
        let busy = "robot.gateway.sequence_jump";
        for _ in 0..100 {
            f.admit(&line(busy, Medium, "/busy"), 0);
        }
        let (a, _) = f.admit(&line(busy, Medium, "/quiet"), 1);
        assert_eq!(a, Admit::Report, "a busy channel never hides another");
        let mut reported = 0;
        for i in 0..1000 {
            for _ in 0..PER_KEY {
                let (a, _) = f.admit(&line(busy, Medium, &format!("/c{i}")), 2);
                if a == Admit::Report {
                    reported += 1;
                }
            }
        }
        let (a, _) = f.admit(&line(busy, Critical, "/late"), 3);
        assert_eq!(a, Admit::Fold);
        // /busy reported PER_KEY, /quiet 1.
        assert_eq!(reported + PER_KEY + 1, PER_WINDOW);
        let out = f.flush();
        let over = out.iter().find(|l| l.rule == OVERFLOW_RULE).unwrap();
        assert_eq!(over.severity, Critical);
        assert!(robodr_ocsf::builder::rule_known(OVERFLOW_RULE));
    }

    /// T19: the gateway's decision summary is parsed strictly.
    #[test]
    fn summary_lines_are_strict() {
        let d = format!("sha256:{}", "ab".repeat(32));
        let good = format!(
            r#"{{"format":"robodr-gateway-summary/v1","event":"interval","mode":"enforce","on_gateway_down":"fail_closed","config_sha256":"{d}","firewall_sha256":null,"profile_sha256":"{d}","interval_ms":60000,"counters":{{"packets":10,"accepted":8,"modified":1,"dropped":1,"samples":10,"passed":8,"limited":1,"substituted":0,"suppressed":1,"late":0,"undecidable":0}},"firewall_faults":0,"restriction":"r-1"}}"#
        );
        match parse_gateway_line(&good) {
            Ok(Payload::GatewaySummary(s)) => {
                assert_eq!(s.event, SummaryEvent::Interval);
                assert_eq!(s.counters.limited, 1);
            }
            other => panic!("{other:?}"),
        }
        for bad in [
            good.replace(
                "\"restriction\":\"r-1\"}",
                "\"restriction\":\"r-1\",\"x\":1}",
            ),
            good.replace("interval\"", "sometimes\""),
            good.replace(&d, "sha256:XYZ"),
            good.replace("r-1", "r 1\n"),
            good.replace("\"late\":0,", ""),
            good.replace("fail_closed", "fail_open"),
        ] {
            assert!(parse_gateway_line(&bad).is_err(), "{bad}");
        }
    }

    /// Red team 2026-10-30 (gateway feed spoofing, G3): a line naming
    /// `robot.firewall.` (nothing after the prefix) was accepted and became
    /// a finding with that rule id and the generic catalog entry; so was any
    /// made-up id inside the two namespaces. Only catalogued ids pass now.
    #[test]
    fn only_catalogued_gateway_and_firewall_ids_are_accepted() {
        let line = |r: &str| {
            format!(
                r#"{{"format":"robodr-gateway-finding/v1","rule":"{r}","severity":"high","detail":"x","mode":"enforce","channel":"/x","count":1}}"#
            )
        };
        // Joined at run time: the catalog drift test of robodr-ocsf scans
        // the sources for rule id literals.
        let id = |parts: &[&str]| parts.join(".");
        for bad in [
            id(&["robot", "firewall", ""]),
            id(&["robot", "gateway", ""]),
            id(&["robot", "firewall", "", "rejected_stale"]),
            id(&["robot", "firewall", "made_up_rule"]),
            id(&["robot", "gateway", "trajectory_rejected", "x"]),
            id(&["robot", "gateway", "anything"]),
        ] {
            assert!(parse_gateway_line(&line(&bad)).is_err(), "{bad} accepted");
        }
        // Every id the gateway and its firewall emit stays accepted (a
        // drift guard: an id added there must be catalogued too).
        for (id, _) in robodr_firewall_gw::findings::rules::ALL {
            assert!(parse_gateway_line(&line(id)).is_ok(), "{id}");
        }
        let src = include_str!("../../robodr-firewall/src/events.rs");
        let mut n = 0;
        for part in src.split('"').skip(1).step_by(2) {
            if part.starts_with("robot.firewall.") && part.len() > "robot.firewall.".len() {
                assert!(parse_gateway_line(&line(part)).is_ok(), "{part}");
                n += 1;
            }
        }
        assert!(n >= 25, "firewall rule ids found in events.rs: {n}");
    }
}
