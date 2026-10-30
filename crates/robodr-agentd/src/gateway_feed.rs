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
//! is parsed strictly ([`parse_gateway_line`]): unknown keys, another
//! format, a rule outside `robot.gateway.*` / `robot.firewall.*` (the
//! gateway cannot speak for any other detector), or oversized fields are
//! malformed and dropped (counted by the input). The detail is kept as the
//! gateway wrote it (sanitized when logged; tainted in the finding).

use serde::Deserialize;

use crate::host::{HostThreatsSection, HostThreatsSpec};
use crate::input::Payload;

/// The line format tag (`robodr_firewall_gw::feed::FORMAT`).
pub const FORMAT: &str = "robodr-gateway-finding/v1";
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
    (r.starts_with("robot.gateway.") || r.starts_with("robot.firewall."))
        && r.len() <= MAX_RULE
        && r.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_')
}

/// [`crate::input::LineParser`] of the gateway feed.
pub fn parse_gateway_line(t: &str) -> Result<Payload, String> {
    let l: GatewayLine =
        serde_json::from_str(t).map_err(|e| format!("not a gateway finding: {e}"))?;
    if l.format != FORMAT {
        return Err(format!("format must be {FORMAT}"));
    }
    if !rule_ok(&l.rule) {
        return Err("rule must be a robot.gateway.* or robot.firewall.* id".into());
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
}
