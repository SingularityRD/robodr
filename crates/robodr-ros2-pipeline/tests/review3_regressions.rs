//! Regressions for the third (independent) review of the pipeline: the
//! PoCs R3-P1..R3-P4 asserted the buggy behaviour; the tests here assert the
//! fixed one (and, for R3-P1, what the pipeline does once `robodr-rtps`
//! exposes the conflict).

mod common;

use std::time::{Duration, Instant};

use common::*;
use robodr_capture::reassembly::ReassemblyStats;
use robodr_capture::CaptureStats;
use robodr_events::Severity;
use robodr_ros2_pipeline::binding::{BindingOptions, Ingress};
use robodr_ros2_pipeline::pipeline::{rules, CHECKSUM_BURST_THRESHOLD, CHECKSUM_BURST_WINDOW};
use robodr_ros2_pipeline::source::{CaptureHealth, Datagram};
use robodr_ros2_pipeline::{Finding, Pipeline, PipelineOptions};

const RIP: &str = "192.168.50.10";
const XIP: &str = "192.168.50.66";

fn max_sev(f: &[Finding]) -> Option<Severity> {
    f.iter().map(|x| x.deviation.severity).max()
}

fn with_rule<'a>(f: &'a [Finding], rule: &str) -> Vec<&'a Finding> {
    f.iter().filter(|x| x.deviation.rule == rule).collect()
}

/// DATA_FRAG (LE) with optional inline QoS PID_STATUS_INFO.
fn frag_q(sn: u32, start: u32, fs: u16, size: u32, status: Option<u8>, frag: &[u8]) -> Vec<u8> {
    let mut body = vec![0, 0];
    body.extend_from_slice(&28u16.to_le_bytes());
    body.extend_from_slice(&[0, 0, 0, 0]);
    body.extend_from_slice(&ENTITY_SEDP_PUB_WRITER);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&sn.to_le_bytes());
    body.extend_from_slice(&start.to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&fs.to_le_bytes());
    body.extend_from_slice(&size.to_le_bytes());
    let mut flags = 0x01u8;
    if let Some(s) = status {
        flags |= 0x02;
        body.extend_from_slice(&[0x71, 0x00, 4, 0, 0, 0, 0, s, 1, 0, 0, 0]);
    }
    body.extend_from_slice(frag);
    while !body.len().is_multiple_of(4) {
        body.push(0);
    }
    let mut s = vec![0x16, flags];
    s.extend_from_slice(&(body.len() as u16).to_le_bytes());
    s.extend_from_slice(&body);
    s
}

/// The F3 attack (rogue rt/cmd_vel writer under the profiled LEGIT prefix,
/// header spoofed too, from the attacker's IP), as fragments in one
/// datagram; `smuggle` adds a byte-identical duplicate of fragment 1 that
/// carries inline status disposed|unregistered.
fn f3_frags(smuggle: bool) -> Vec<u8> {
    let payload = sedp_payload(LEGIT, "rt/cmd_vel", TWIST, 0);
    let n = payload.len() as u32;
    let h = payload.len() / 2 / 4 * 4;
    let mut subs = vec![frag_q(9, 1, h as u16, n, None, &payload[..h])];
    if smuggle {
        subs.push(frag_q(9, 1, h as u16, n, Some(3), &payload[..h]));
    }
    for (i, c) in payload[h..].chunks(h).enumerate() {
        subs.push(frag_q(9, i as u32 + 2, h as u16, n, None, c));
    }
    datagram(LEGIT, &subs)
}

fn bound_pipeline_with(opts: PipelineOptions, t: Instant) -> Pipeline {
    let mut p = Pipeline::new(robot_profile(true), opts);
    assert!(p
        .process_at(&spdp_datagram(LEGIT, ROBOT_IP), RIP, t)
        .is_empty());
    p
}

fn bound_pipeline(t: Instant) -> Pipeline {
    bound_pipeline_with(PipelineOptions::default(), t)
}

/// Options for a sensor running on the robot computer (192.168.50.10).
fn on_robot() -> PipelineOptions {
    PipelineOptions {
        binding: BindingOptions {
            local_addresses: vec![ROBOT_IP.into()],
            ..Default::default()
        },
        ..Default::default()
    }
}

// ---------------------------------------------------------------- R3-P1 ----

/// R3-P1 control: the fragmented F3 attack is a Critical mismatch.
#[test]
fn r3p1_fragmented_f3_is_critical() {
    let t = Instant::now();
    let mut p = bound_pipeline(t);
    let f = p.process_at(&f3_frags(false), XIP, t + Duration::from_secs(1));
    assert_eq!(max_sev(&f), Some(Severity::Critical), "{f:#?}");
    assert_eq!(with_rule(&f, rules::ENDPOINT_SOURCE_MISMATCH).len(), 1);
}

/// R3-P1, pipeline side: a datagram whose discovery content carries
/// conflicting PID_STATUS_INFO values is surfaced as a High
/// `ambiguous_discovery`, never left as a Medium/Low removal only.
/// robodr-rtps reports the duplicate inline-QoS parameter as
/// `Anomaly::ConflictingDuplicateParameter(PID_STATUS_INFO)`, which the
/// pipeline maps to that finding.
#[test]
fn r3p1_status_conflict_reported_by_rtps_is_high() {
    let t = Instant::now();
    let mut p = bound_pipeline(t);
    // A DATA dispose whose inline QoS carries STATUS_INFO twice with
    // different values.
    let mut body = vec![0, 0];
    body.extend_from_slice(&16u16.to_le_bytes());
    body.extend_from_slice(&[0, 0, 0, 0]);
    body.extend_from_slice(&ENTITY_SEDP_PUB_WRITER);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&2u32.to_le_bytes());
    body.extend_from_slice(&param(0x0070, &guid(LEGIT, [0, 0, 0x12, 0x03])));
    body.extend_from_slice(&param(0x0071, &[0, 0, 0, 3]));
    body.extend_from_slice(&param(0x0071, &[0, 0, 0, 0]));
    body.extend_from_slice(&[1, 0, 0, 0]);
    let mut sub = vec![0x15, 0x03];
    sub.extend_from_slice(&(body.len() as u16).to_le_bytes());
    sub.extend_from_slice(&body);
    let f = p.process_at(&datagram(LEGIT, &[sub]), XIP, t + Duration::from_secs(1));
    let amb = with_rule(&f, rules::AMBIGUOUS_DISCOVERY);
    assert_eq!(amb.len(), 1, "{f:#?}");
    assert_eq!(amb[0].deviation.severity, Severity::High);
    assert!(amb[0].deviation.detail.contains("PID_STATUS_INFO"));
}

/// R3-P1 end to end: the duplicate-fragment status smuggling must not
/// downgrade F3. robodr-rtps reports the conflicting PID_STATUS_INFO of the
/// duplicate fragment (`FragmentEventKind::ConflictingInlineQos(0x0071)` and
/// `Anomaly::ConflictingDuplicateParameter(0x0071)`); the pipeline maps it to
/// a High `ambiguous_discovery` naming PID_STATUS_INFO.
#[test]
fn r3p1_status_smuggling_does_not_downgrade_f3() {
    let t = Instant::now();
    let mut p = bound_pipeline(t);
    let f = p.process_at(&f3_frags(true), XIP, t + Duration::from_secs(1));
    assert!(max_sev(&f) >= Some(Severity::High), "{f:#?}");
    let amb = with_rule(&f, rules::AMBIGUOUS_DISCOVERY);
    assert_eq!(amb.len(), 1, "{f:#?}");
    assert_eq!(amb[0].deviation.severity, Severity::High);
    assert!(
        amb[0].deviation.detail.contains("PID_STATUS_INFO"),
        "{f:#?}"
    );
}

/// What the pipeline does today with the smuggled datagram: the removal of a
/// profiled participant's writer from an IP outside its binding is at least
/// Medium (flagged as a spoofed removal), never silently Low.
#[test]
fn r3p1_today_the_smuggled_removal_is_at_least_a_spoofed_removal() {
    let t = Instant::now();
    let mut p = bound_pipeline(t);
    let f = p.process_at(&f3_frags(true), XIP, t + Duration::from_secs(1));
    assert!(max_sev(&f) >= Some(Severity::Medium), "{f:#?}");
    if with_rule(&f, rules::ENDPOINT_SOURCE_MISMATCH).is_empty() {
        let r = with_rule(&f, rules::DISCOVERY_REMOVAL);
        assert!(
            r.iter()
                .any(|x| x.deviation.detail.contains("spoofed removal")),
            "{f:#?}"
        );
    }
}

// ---------------------------------------------------------------- R3-P2 ----

/// R3-P2: every capture-layer counter that means "not inspected" or
/// "tampered with" becomes a finding with a sensible severity.
#[test]
fn r3p2_capture_health_reports_refusals_conflicts_and_checksums() {
    let mut p = Pipeline::new(robot_profile(true), PipelineOptions::default());
    let c = CaptureStats {
        bad_ip_checksum: 5,
        bad_udp_checksum: 5,
        not_udp: 50,
        ..Default::default()
    };
    let r = ReassemblyStats {
        refused_capacity: 50,
        dropped_too_far: 50,
        duplicates: 50,
        duplicate_conflicts: 50,
        ..Default::default()
    };
    let h = CaptureHealth::from_stats(&c, &r);
    assert_ne!(h, CaptureHealth::default());
    let t = Instant::now();
    let f = p.capture_findings_at(&h, t);
    let sev = |rule: &str| {
        let v = with_rule(&f, rule);
        assert_eq!(v.len(), 1, "{rule}: {f:#?}");
        assert_eq!(v[0].src_ip, "capture");
        v[0].deviation.severity
    };
    assert_eq!(sev(rules::CAPTURE_IP_FRAGMENT_REFUSED), Severity::Medium);
    assert_eq!(
        sev(rules::CAPTURE_IP_FRAGMENT_DUPLICATE_CONFLICT),
        Severity::Medium
    );
    assert_eq!(sev(rules::CAPTURE_IP_REASSEMBLY_DROPPED), Severity::Low);
    assert_eq!(sev(rules::CAPTURE_BAD_CHECKSUM), Severity::Low);
    assert_eq!(sev(rules::CAPTURE_NOT_UDP), Severity::Low);
    assert_eq!(f.len(), 5, "{f:#?}");
    // Unchanged counters: nothing new.
    assert!(p.capture_findings_at(&h, t).is_empty());
}

/// Checksum failures: Low when sporadic, Medium when bursty.
#[test]
fn r3p2_checksum_bursts_are_medium() {
    let mut p = Pipeline::new(robot_profile(true), PipelineOptions::default());
    let t = Instant::now();
    let mut h = CaptureHealth::default();
    let step = |p: &mut Pipeline, h: &mut CaptureHealth, n: u64, at: Instant| {
        h.bad_udp_checksum += n;
        let f = p.capture_findings_at(h, at);
        with_rule(&f, rules::CAPTURE_BAD_CHECKSUM)
            .first()
            .map(|x| x.deviation.severity)
    };
    assert_eq!(step(&mut p, &mut h, 1, t), Some(Severity::Low));
    // Spread out: each in its own window, stays Low.
    let mut at = t;
    for _ in 0..5 {
        at += CHECKSUM_BURST_WINDOW + Duration::from_secs(1);
        assert_eq!(step(&mut p, &mut h, 2, at), Some(Severity::Low));
    }
    // A burst within one window crosses the threshold: Medium.
    at += CHECKSUM_BURST_WINDOW + Duration::from_secs(1);
    assert_eq!(
        step(&mut p, &mut h, CHECKSUM_BURST_THRESHOLD / 2, at),
        Some(Severity::Low)
    );
    assert_eq!(
        step(
            &mut p,
            &mut h,
            CHECKSUM_BURST_THRESHOLD,
            at + Duration::from_secs(1)
        ),
        Some(Severity::Medium)
    );
}

/// Capture findings are rate limited (robot.capture.*), not unbounded.
#[test]
fn r3p2_capture_findings_are_rate_limited() {
    let mut p = Pipeline::new(
        robot_profile(true),
        PipelineOptions {
            rate_limit_burst: 2,
            rate_limit_interval: Duration::from_secs(3600),
            ..Default::default()
        },
    );
    let t = Instant::now();
    let mut n = 0;
    for i in 1..=10u64 {
        let h = CaptureHealth {
            ip_fragment_refused: i,
            ..Default::default()
        };
        n += p.capture_findings_at(&h, t).len();
    }
    assert_eq!(n, 2);
    assert_eq!(p.stats().rate_limited, 8);
}

// ---------------------------------------------------------------- R3-P3 ----

/// R3-P3: a conflicting fragment overlap (robodr-rtps `frag_conflicts`) is
/// a Medium `discovery_fragment_conflict`, also with report_anomalies off.
#[test]
fn r3p3_conflicting_fragment_overlap_is_reported() {
    let payload = sedp_payload(ROGUE, "rt/odom", ODOM, 0);
    let n = payload.len() as u32;
    let h = payload.len() / 2 / 4 * 4;
    let f1 = data_frag(ENTITY_SEDP_PUB_WRITER, 1, 1, h as u16, n, &payload[..h]);
    let f1_bad = data_frag(ENTITY_SEDP_PUB_WRITER, 1, 1, h as u16, n, &vec![0x41; h]);
    for anomalies in [true, false] {
        let mut p = Pipeline::new(
            robot_profile(true),
            PipelineOptions {
                report_anomalies: anomalies,
                report_fragmentation: false,
                ..Default::default()
            },
        );
        let f = p.process(&datagram(ROGUE, &[f1.clone(), f1_bad.clone()]), XIP);
        assert_eq!(p.reassembler().conflicts(), 1);
        assert_eq!(p.stats().fragment_conflicts, 1);
        let c = with_rule(&f, rules::DISCOVERY_FRAGMENT_CONFLICT);
        assert_eq!(c.len(), 1, "{f:#?}");
        assert_eq!(c[0].deviation.severity, Severity::Medium);
        assert!(c[0].deviation.detail.contains(&hex_of(ROGUE)), "{f:#?}");
        assert!(with_rule(&f, rules::DISCOVERY_FRAGMENT_REJECTED).is_empty());
    }
}

/// A conflicting overlap makes the reassembled announcement ambiguous: a
/// writer completed in that datagram is judged as a motion writer.
#[test]
fn r3p3_writer_completed_with_a_conflicting_overlap_is_judged_worst_case() {
    let t = Instant::now();
    let mut p = bound_pipeline(t);
    let payload = sedp_payload(LEGIT, "rt/odom", ODOM, 0);
    let n = payload.len() as u32;
    let h = payload.len() / 2 / 4 * 4;
    let mut subs = vec![
        data_frag(ENTITY_SEDP_PUB_WRITER, 1, 1, h as u16, n, &payload[..h]),
        data_frag(ENTITY_SEDP_PUB_WRITER, 1, 1, h as u16, n, &vec![0x41; h]),
    ];
    for (i, c) in payload[h..].chunks(h).enumerate() {
        subs.push(data_frag(
            ENTITY_SEDP_PUB_WRITER,
            1,
            i as u32 + 2,
            h as u16,
            n,
            c,
        ));
    }
    let f = p.process_at(&datagram(LEGIT, &subs), XIP, t);
    let m = with_rule(&f, rules::ENDPOINT_SOURCE_MISMATCH);
    assert_eq!(m.len(), 1, "{f:#?}");
    assert_eq!(m[0].deviation.severity, Severity::Critical, "{f:#?}");
}

fn hex_of(p: [u8; 12]) -> String {
    p.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------- R3-P4 ----

/// R3-P4: the legit participant's own SEDP over loopback (Fast DDS
/// same-host unicast) is no longer a mismatch on the robot computer, with
/// a loopback-ingress capture or one that cannot tell.
#[test]
fn r3p4_same_host_sedp_over_loopback_is_accepted() {
    let t = Instant::now();
    for ingress in [Ingress::Loopback, Ingress::Unknown] {
        let mut p = bound_pipeline_with(on_robot(), t);
        for src in ["127.0.0.1", "::1"] {
            let f = p.process_from_at(
                &sedp_datagram(LEGIT, "rt/cmd_vel", TWIST),
                src,
                ingress,
                t + Duration::from_secs(1),
            );
            assert!(
                with_rule(&f, rules::ENDPOINT_SOURCE_MISMATCH).is_empty(),
                "{ingress:?} {src}: {f:#?}"
            );
            assert!(max_sev(&f) < Some(Severity::High), "{f:#?}");
        }
        assert_eq!(p.stats().binding.same_host_loopback, 2);
    }
}

/// The same datagram with a loopback source seen on a non-loopback
/// interface is forged: Critical.
#[test]
fn r3p4_loopback_source_on_the_wire_is_critical() {
    let t = Instant::now();
    let mut p = bound_pipeline_with(on_robot(), t);
    let d = Datagram::new(sedp_datagram(LEGIT, "rt/odom", ODOM), "127.0.0.1")
        .with_ingress(Ingress::External);
    let f = p.process_datagram(&d);
    let m = with_rule(&f, rules::ENDPOINT_SOURCE_MISMATCH);
    assert_eq!(m.len(), 1, "{f:#?}");
    assert_eq!(m[0].deviation.severity, Severity::Critical);
    assert_eq!(p.stats().binding.spoofed_loopback, 1);
}

/// Loopback attribution is per host, not a blanket pass: a remote
/// participant's prefix spoken over loopback is still a mismatch, and a
/// strict deployment judges unknown-ingress loopback like any source.
#[test]
fn r3p4_loopback_is_not_a_bypass_for_remote_participants() {
    let t = Instant::now();
    let mut p = Pipeline::new(robot_profile(true), on_robot());
    p.process_at(&spdp_datagram(LEGIT, ROGUE_IP), XIP, t);
    let f = p.process_from_at(
        &sedp_datagram(LEGIT, "rt/cmd_vel", TWIST),
        "127.0.0.1",
        Ingress::Loopback,
        t,
    );
    assert_eq!(max_sev(&f), Some(Severity::Critical), "{f:#?}");

    let mut strict = on_robot();
    strict.binding.strict_loopback_ingress = true;
    let mut p = bound_pipeline_with(strict, t);
    let f = p.process_at(&sedp_datagram(LEGIT, "rt/cmd_vel", TWIST), "127.0.0.1", t);
    assert_eq!(with_rule(&f, rules::ENDPOINT_SOURCE_MISMATCH).len(), 1);
}

/// Without knowing this host's addresses the sensor cannot tell that the
/// SPDP source is local: the deployed config detects them
/// (`binding.detect_local_addresses`, default on) and the loopback capture
/// teaches them; a library default (tests, replays) still reports.
#[test]
fn r3p4_local_address_learned_from_loopback_traffic() {
    let t = Instant::now();
    let mut p = bound_pipeline(t);
    // Any datagram from the robot IP on lo proves the IP is this host's.
    p.process_from_at(&spdp_datagram(LEGIT, ROBOT_IP), RIP, Ingress::Loopback, t);
    assert_eq!(
        p.binding().local_addresses(),
        &[std::net::IpAddr::V4(ROBOT_IP)]
    );
    let f = p.process_from_at(
        &sedp_datagram(LEGIT, "rt/cmd_vel", TWIST),
        "127.0.0.1",
        Ingress::Loopback,
        t,
    );
    assert!(
        with_rule(&f, rules::ENDPOINT_SOURCE_MISMATCH).is_empty(),
        "{f:#?}"
    );

    let mut p = bound_pipeline(t);
    let f = p.process_at(&sedp_datagram(LEGIT, "rt/cmd_vel", TWIST), "127.0.0.1", t);
    assert_eq!(with_rule(&f, rules::ENDPOINT_SOURCE_MISMATCH).len(), 1);
}
