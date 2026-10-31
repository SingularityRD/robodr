//! Decision summaries (`robodr_firewall_gw::summary`, sales-readiness
//! T19): the lines agentd records in its signed black box.

use std::time::{Duration, Instant};

use robodr_firewall_gw::config::OnGatewayDown;
use robodr_firewall_gw::summary::{Event, Summarizer, INTERVAL};
use robodr_firewall_gw::testkit::*;

#[test]
fn lines_carry_deltas_and_provenance() {
    let mut gw = gateway(Fixture::G1);
    gw.provenance.firewall_sha256 = Some(format!("sha256:{}", "a".repeat(64)));
    let t0 = Instant::now();
    let mut s = Summarizer::new(OnGatewayDown::FailClosed, t0);
    let start: serde_json::Value =
        serde_json::from_str(&s.line(Event::Start, &gw, t0).unwrap()).unwrap();
    assert_eq!(start["event"], "start");
    assert_eq!(start["counters"]["packets"], 0);
    assert_eq!(
        start["firewall_sha256"],
        format!("sha256:{}", "a".repeat(64))
    );
    assert!(s.due(&gw, t0 + Duration::from_secs(1)).is_none());
    gw.stats.packets = 10;
    gw.stats.limited = 3;
    let l: serde_json::Value = serde_json::from_str(&s.due(&gw, t0 + INTERVAL).unwrap()).unwrap();
    assert_eq!(l["event"], "interval");
    assert_eq!(l["counters"]["packets"], 10);
    assert_eq!(l["counters"]["limited"], 3);
    assert_eq!(l["interval_ms"], 60_000);
    gw.stats.packets = 15;
    let l: serde_json::Value = serde_json::from_str(
        &s.line(Event::Stop, &gw, t0 + INTERVAL + Duration::from_secs(5))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(l["counters"]["packets"], 5);
    assert_eq!(l["event"], "stop");
    assert_eq!(s.lines, 3);
}
