//! Contract 2.5: the agent's periodic health record (`robot.agent.health`,
//! `entity_context.agent_health`; sales-readiness T5).

mod common;

use robodr_events::{Deviation, Severity};
use robodr_ocsf::*;

fn health_dev() -> Deviation {
    Deviation::new(AGENT_HEALTH_RULE, Severity::Low, "agent health record")
        .with_mode(robodr_events::Mode::Observe)
}

fn build(h: Option<AgentHealth>, rule: &str) -> Result<FindingEnvelope, Vec<ValidationError>> {
    let dev = Deviation::new(rule.to_string(), Severity::Low, "x");
    let ctx = common::ctx();
    let mut b = FindingBuilder::from_deviation(&dev, &ctx).seen(common::T0, common::T0);
    if let Some(h) = h {
        b = b.agent_health(h);
    }
    b.build()
}

fn health_json() -> String {
    let dev = health_dev();
    let ctx = common::ctx();
    let env = FindingBuilder::from_deviation(&dev, &ctx)
        .agent_health(common::health::sample())
        .seen(common::T0, common::T0 + 60_000)
        .occurrences(2)
        .build()
        .expect("health finding builds");
    to_json(&env).unwrap()
}

#[test]
fn a_health_record_builds_validates_and_round_trips() {
    let json = health_json();
    let back = parse_and_validate(&json).expect("valid");
    let h = back.entity_context.agent_health.as_ref().expect("record");
    assert_eq!(h, &common::health::sample());
    assert_eq!(back.ocsf.unmapped.robodr, back.entity_context);
    assert_eq!(back.title, "Agent health record");
    assert_eq!(back.severity, Severity::Low);
    assert_eq!(back.entity_context.mode, Mode::Observe);
    // Repeats are Updates of one finding per robot: the SOC upserts it and
    // reads `last_seen_time` as the robot's last sign of life.
    assert_eq!(back.ocsf.activity_id, 2);
    assert!(json.contains("\"agent_health\":{\"state\":\"degraded\""));
}

#[test]
fn the_record_is_only_allowed_on_robot_agent_health() {
    // Missing on a health finding.
    let e = build(None, AGENT_HEALTH_RULE).unwrap_err();
    assert!(
        format!("{e:?}").contains("must carry agent_health"),
        "{e:?}"
    );
    // Present on another rule.
    let e = build(Some(common::health::sample()), "robot.agent.input_silent").unwrap_err();
    assert!(format!("{e:?}").contains("only allowed"), "{e:?}");
    // A 2.5 health record relabelled 2.4 (the field did not exist then).
    let down = health_json().replace(
        &format!("\"contract_version\":\"{CONTRACT_VERSION}\""),
        "\"contract_version\":\"2.4.0\"",
    );
    assert!(parse_and_validate(&down).is_err());
}

#[test]
fn bounds_are_enforced_on_parse_and_cut_by_the_builder() {
    let mut h = common::health::sample();
    h.reasons = (0..40).map(|i| format!("reason {i}")).collect();
    h.inputs = (0..40)
        .map(|i| InputFreshness {
            name: format!("socket:/run/x{i}<b>\u{202e}"),
            last_rx_age_ms: None,
            received: 0,
            dropped: 0,
            malformed: 0,
            ended: false,
        })
        .collect();
    let env = build(Some(h), AGENT_HEALTH_RULE).expect("the builder cuts");
    let got = env.entity_context.agent_health.as_ref().unwrap();
    assert_eq!(got.reasons.len(), health_limits::REASONS);
    assert_eq!(got.inputs.len(), health_limits::ITEMS);
    assert_eq!(got.inputs[0].name, "socket:/run/x0?b??");

    // Hand-made oversize lists and an empty name are refused on parse.
    let json = health_json();
    let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let many: Vec<String> = (0..17).map(|i| format!("r{i}")).collect();
    for root in ["/entity_context", "/ocsf/unmapped/robodr"] {
        let ah = v.pointer_mut(&format!("{root}/agent_health")).unwrap();
        ah["reasons"] = serde_json::json!(many);
        ah["versions"][0]["version"] = "".into();
    }
    let e = parse_and_validate(&v.to_string()).unwrap_err();
    let s = format!("{e:?}");
    assert!(s.contains("agent_health/reasons"), "{s}");
    assert!(s.contains("versions/0/version"), "{s}");
    // free > total is nonsense.
    let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
    for root in ["/entity_context", "/ocsf/unmapped/robodr"] {
        v.pointer_mut(&format!("{root}/agent_health/disks/0/free_bytes"))
            .map(|x| *x = 99_000_000_000u64.into())
            .unwrap();
    }
    assert!(parse_and_validate(&v.to_string()).is_err());
    // A record that differs between entity_context and unmapped.
    let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
    v["entity_context"]["agent_health"]["state"] = "ok".into();
    assert!(parse_and_validate(&v.to_string()).is_err());
}

/// The largest record the limits allow (every list full, every name and
/// reason at its byte limit, made of `"` so JSON escaping doubles it, every
/// number at its maximum), duplicated into `ocsf.unmapped.robodr`, still
/// fits `MAX_FINDING_BYTES`: otherwise `validate_for_emit` would drop the
/// liveness record. A limit bump that breaks this fails here, not on a
/// robot.
#[test]
fn a_worst_case_health_record_fits_the_size_limit() {
    use health_limits::{ITEMS, NAME_BYTES, REASONS, REASON_BYTES};
    let name = || "\"".repeat(NAME_BYTES);
    let max = u64::MAX;
    let h = AgentHealth {
        state: HealthLabel::Degraded,
        reasons: (0..REASONS).map(|_| "\"".repeat(REASON_BYTES)).collect(),
        interval_ms: max,
        uptime_ms: max,
        seq: max,
        versions: (0..ITEMS)
            .map(|_| ComponentVersion {
                component: name(),
                version: name(),
            })
            .collect(),
        inputs: (0..ITEMS)
            .map(|_| InputFreshness {
                name: name(),
                last_rx_age_ms: Some(max),
                received: max,
                dropped: max,
                malformed: max,
                ended: false,
            })
            .collect(),
        counters: HealthCounters {
            findings_spooled: max,
            finding_errors: max,
            health_findings: max,
            spool_dropped: max,
            spool_write_errors: max,
            note_errors: max,
        },
        blackbox: BlackBoxHealth {
            degraded: true,
            anchored: true,
            anchor_failures: max,
        },
        reachability: (0..ITEMS)
            .map(|_| Reachability {
                component: name(),
                state: ReachState::NotConfigured,
                last_ok_age_ms: Some(max),
            })
            .collect(),
        credentials: (0..ITEMS)
            .map(|_| CredentialExpiry {
                name: name(),
                expires_ms: max,
                days_to_expiry: i64::MIN,
            })
            .collect(),
        clock: ClockHealth {
            synchronized: Some(false),
            max_error_ms: Some(max),
            source: Some(ClockSource::Adjtimex),
            adjtimex_errno: Some(u32::MAX),
            timesync_age_ms: Some(max),
            wall_jumps: max,
        },
        disks: (0..ITEMS)
            .map(|_| DiskHealth {
                name: name(),
                free_bytes: max,
                total_bytes: max,
            })
            .collect(),
    };
    let dev = Deviation::new(
        AGENT_HEALTH_RULE,
        Severity::Low,
        "health record 18446744073709551615 of robodr-agentd (state degraded, up 18446744073709551 s)",
    )
    .with_mode(robodr_events::Mode::Observe);
    let ctx = common::ctx();
    let env = FindingBuilder::from_deviation(&dev, &ctx)
        .agent_health(h)
        .seen(common::T0, common::T0 + 60_000)
        .occurrences(max)
        .build()
        .expect("worst-case health finding builds");
    let json = to_json(&env).unwrap();
    let limit = robodr_ocsf::validate::MAX_FINDING_BYTES;
    assert!(json.len() <= limit, "{} bytes > {limit}", json.len());
    validate_for_emit(&env).expect("emittable");
    parse_and_validate(&json).expect("parses back");
    eprintln!("worst-case health finding: {} bytes", json.len());
}
