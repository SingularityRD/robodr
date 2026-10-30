//! Pipeline-level regressions for the parser security review
//! (`robodr-rtps` PoCs F1..F6) and for hostile input in general: spoofed
//! attribution, duplicate / malformed parameters, fragment games, floods,
//! hostile source strings, a clock going backwards, and the watch tool's
//! output. Every test drives the public API with hand-built datagrams; none
//! touches the network.
//!
//! Each PoC in `robodr-rtps/src/poc_review.rs` asserts the *parser's*
//! behaviour; the tests here assert that the *pipeline* turns that behaviour
//! into a finding (or that the finding survives a flood).

mod common;

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use common::*;
use robodr_events::Severity;
use robodr_ros2_pipeline::binding::BindingOptions;
use robodr_ros2_pipeline::pipeline::rules;
use robodr_ros2_pipeline::source::{Datagram, VecDatagramSource};
use robodr_ros2_pipeline::{Finding, Pipeline, PipelineOptions};

const RIP: &str = "192.168.50.10"; // ROBOT_IP
const XIP: &str = "192.168.50.66"; // ROGUE_IP
const ATT: [u8; 12] = [0x77; 12]; // attacker's own header prefix

fn pipeline() -> Pipeline {
    Pipeline::new(robot_profile(true), PipelineOptions::default())
}

fn pipeline_with(opts: PipelineOptions) -> Pipeline {
    Pipeline::new(robot_profile(true), opts)
}

fn with_rule<'a>(f: &'a [Finding], rule: &str) -> Vec<&'a Finding> {
    f.iter().filter(|x| x.deviation.rule == rule).collect()
}

/// SEDP publication of a writer owned by `owner` on `topic`, sent in a
/// datagram whose RTPS header names `header_prefix`.
fn sedp_from(header_prefix: [u8; 12], owner: [u8; 12], topic: &str) -> Vec<u8> {
    datagram(header_prefix, &[sedp_sub(owner, topic)])
}

/// The legit participant beacons from the robot's IP.
fn bind_legit(p: &mut Pipeline, t: Instant) {
    let f = p.process_at(&spdp_datagram(LEGIT, ROBOT_IP), RIP, t);
    assert!(f.is_empty(), "{f:#?}");
    assert!(p.binding().is_bound(&LEGIT));
}

// ---------------------------------------------------------------- F3 ----

/// F3 exactly as in the PoC: the header prefix *and* the endpoint GUID are
/// the profiled participant's, sent from the attacker's IP. The profile
/// accepts the writer (known participant, allowed topic); only the binding
/// check catches it, Critical because it is a motion writer.
#[test]
fn f3_rogue_writer_with_spoofed_header_is_critical() {
    let t = Instant::now();
    let mut p = pipeline();
    bind_legit(&mut p, t);
    // The real participant's own SEDP from its own IP: nothing.
    assert!(p
        .process_at(&sedp_datagram(LEGIT, "rt/cmd_vel", TWIST), RIP, t)
        .is_empty());
    let f = p.process_at(&sedp_from(LEGIT, LEGIT, "rt/cmd_vel"), XIP, t);
    let m = with_rule(&f, rules::ENDPOINT_SOURCE_MISMATCH);
    assert_eq!(m.len(), 1, "{f:#?}");
    assert_eq!(m[0].deviation.severity, Severity::Critical);
    assert_eq!(m[0].src_ip, XIP);
    assert!(m[0].deviation.detail.contains("profiled participant"));
    assert!(m[0].deviation.detail.contains(LEGIT_HEX));
    // A reader / non-motion writer from the wrong IP: High.
    let f = p.process_at(&sedp_from(LEGIT, LEGIT, "rt/odom"), XIP, t);
    assert_eq!(
        with_rule(&f, rules::ENDPOINT_SOURCE_MISMATCH)[0]
            .deviation
            .severity,
        Severity::High
    );
}

/// F3 variant: attacker's own header prefix, endpoint GUID of the profiled
/// participant. Header prefix != endpoint prefix = relayed from a host that
/// is not a discovery server: Critical at once, even before the victim ever
/// announced itself.
#[test]
fn f3_endpoint_prefix_differing_from_header_prefix_is_critical() {
    let t = Instant::now();
    let mut p = pipeline();
    let f = p.process_at(&sedp_from(ATT, LEGIT, "rt/cmd_vel"), XIP, t);
    let m = with_rule(&f, rules::ENDPOINT_SOURCE_MISMATCH);
    assert_eq!(m.len(), 1, "{f:#?}");
    assert_eq!(m[0].deviation.severity, Severity::Critical);
    assert!(m[0].deviation.detail.contains("relayed"));
    // Same via INFO_SRC (the header says ATT, INFO_SRC says ATT too).
    let d = datagram(ATT, &[info_src(ATT), sedp_sub(LEGIT, "rt/cmd_vel")]);
    let f = p.process_at(&d, "10.9.9.9", t);
    assert_eq!(with_rule(&f, rules::ENDPOINT_SOURCE_MISMATCH).len(), 1);
}

/// F3 variant: the GUID-conflict form (PID_PARTICIPANT_GUID names the
/// victim, endpoint GUID the attacker) from a non-discovery-server IP.
#[test]
fn f3_guid_conflict_is_a_mismatch() {
    let t = Instant::now();
    let mut p = pipeline();
    bind_legit(&mut p, t);
    let d = datagram(ATT, &[sedp_sub_conflict(ATT, LEGIT, "rt/cmd_vel")]);
    let f = p.process_at(&d, XIP, t);
    assert!(
        !with_rule(&f, rules::ENDPOINT_SOURCE_MISMATCH).is_empty(),
        "{f:#?}"
    );
}

/// SEDP before SPDP (sensor restarted mid-session): held, then judged when
/// the victim's SPDP arrives from its own IP -> Critical.
#[test]
fn f3_held_announcement_is_judged_when_spdp_arrives() {
    let t = Instant::now();
    let mut p = pipeline();
    let f = p.process_at(&sedp_from(LEGIT, LEGIT, "rt/cmd_vel"), XIP, t);
    assert!(with_rule(&f, rules::ENDPOINT_SOURCE_MISMATCH).is_empty());
    assert_eq!(p.binding().held_len(), 1);
    let f = p.process_at(
        &spdp_datagram(LEGIT, ROBOT_IP),
        RIP,
        t + Duration::from_secs(2),
    );
    let m = with_rule(&f, rules::ENDPOINT_SOURCE_MISMATCH);
    assert_eq!(m.len(), 1, "{f:#?}");
    assert_eq!(m[0].deviation.severity, Severity::Critical);
    assert_eq!(m[0].src_ip, XIP, "attributed to the sender, not the SPDP");
    assert_eq!(p.binding().held_len(), 0);
}

/// Never announced: the hold expires (tick) or the replay ends (finish).
/// A motion writer attributed to a profiled participant is High, not Medium.
#[test]
fn unannounced_motion_writer_is_high_on_expiry_and_on_finish() {
    let t = Instant::now();
    let mut p = pipeline();
    p.process_at(&sedp_from(LEGIT, LEGIT, "rt/cmd_vel"), XIP, t);
    p.process_at(&sedp_from(LEGIT, LEGIT, "rt/odom"), XIP, t);
    assert!(p.tick_at(t + Duration::from_secs(29)).is_empty());
    let f = p.tick_at(t + Duration::from_secs(31));
    let u = with_rule(&f, rules::ENDPOINT_UNANNOUNCED_PARTICIPANT);
    assert_eq!(u.len(), 2, "{f:#?}");
    let sev: Vec<_> = u.iter().map(|x| x.deviation.severity).collect();
    assert!(sev.contains(&Severity::High) && sev.contains(&Severity::Medium));
    assert!(u.iter().all(|x| x.deviation.detail.contains("profiled")));

    let mut p = pipeline();
    p.process_at(&sedp_from(LEGIT, LEGIT, "rt/cmd_vel"), XIP, t);
    let f = p.finish();
    assert_eq!(
        with_rule(&f, rules::ENDPOINT_UNANNOUNCED_PARTICIPANT)[0]
            .deviation
            .severity,
        Severity::High
    );
    assert!(p.finish().is_empty(), "flushed once");
}

/// A rogue SPDP claiming the profiled prefix after it is bound is reported
/// and not learned; since RoboDR cannot tell which host is the real one, the
/// prefix becomes contested (Critical): the robot's own IP is no longer
/// trusted for it either, until it is pinned (finding 2b of the safety
/// review; previously the first-come binding was kept, which kept a rogue
/// that announced first trusted).
#[test]
fn spoofed_spdp_contests_a_live_profiled_binding() {
    let t = Instant::now();
    let mut p = pipeline();
    bind_legit(&mut p, t);
    let f = p.process_at(&spdp_datagram(LEGIT, ROGUE_IP), XIP, t);
    let m = with_rule(&f, rules::PARTICIPANT_SOURCE_MISMATCH);
    assert_eq!(m.len(), 1, "{f:#?}");
    assert_eq!(m[0].deviation.severity, Severity::Critical);
    assert!(p.binding().is_contested(&LEGIT));
    // Neither host is trusted for the prefix now.
    let f = p.process_at(&sedp_datagram(LEGIT, "rt/cmd_vel", TWIST), RIP, t);
    let m = with_rule(&f, rules::ENDPOINT_SOURCE_MISMATCH);
    assert_eq!(m.len(), 1, "{f:#?}");
    assert_eq!(m[0].deviation.severity, Severity::Critical);
    let f = p.process_at(&sedp_from(LEGIT, LEGIT, "rt/cmd_vel"), XIP, t);
    assert_eq!(with_rule(&f, rules::ENDPOINT_SOURCE_MISMATCH).len(), 1);
}

/// The same with the order reversed (finding 2b): the rogue announces the
/// profiled prefix first, the real participant second. The rogue's IP must
/// not stay trusted.
#[test]
fn rogue_first_spdp_does_not_keep_the_prefix() {
    let t = Instant::now();
    let mut p = pipeline();
    let f = p.process_at(&spdp_datagram(LEGIT, ROGUE_IP), XIP, t);
    assert!(with_rule(&f, rules::PARTICIPANT_SOURCE_MISMATCH).is_empty());
    let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
    assert_eq!(p.binding().allows(&LEGIT, ip(XIP)), Some(true));
    let f = p.process_at(&spdp_datagram(LEGIT, ROBOT_IP), RIP, t);
    let m = with_rule(&f, rules::PARTICIPANT_SOURCE_MISMATCH);
    assert_eq!(m.len(), 1, "{f:#?}");
    assert_eq!(m[0].deviation.severity, Severity::Critical);
    assert!(p.binding().is_contested(&LEGIT));
    assert_eq!(p.binding().allows(&LEGIT, ip(XIP)), Some(false));
    assert_eq!(p.binding().allows(&LEGIT, ip(RIP)), Some(false));
    let f = p.process_at(&sedp_from(LEGIT, LEGIT, "rt/cmd_vel"), XIP, t);
    let m = with_rule(&f, rules::ENDPOINT_SOURCE_MISMATCH);
    assert_eq!(m.len(), 1, "{f:#?}");
    assert_eq!(m[0].deviation.severity, Severity::Critical);
}

/// A pinned prefix cannot be bound first by an attacker ("first SPDP wins"
/// limit closed by `participant_ips`).
#[test]
fn pinned_prefix_cannot_be_claimed_first() {
    let t = Instant::now();
    let mut opts = PipelineOptions::default();
    opts.binding
        .participant_ips
        .insert(LEGIT, vec![ROBOT_IP.into()]);
    let mut p = pipeline_with(opts);
    let f = p.process_at(&spdp_datagram(LEGIT, ROGUE_IP), XIP, t);
    assert_eq!(with_rule(&f, rules::PARTICIPANT_SOURCE_MISMATCH).len(), 1);
    let f = p.process_at(&sedp_from(LEGIT, LEGIT, "rt/cmd_vel"), XIP, t);
    assert_eq!(
        with_rule(&f, rules::ENDPOINT_SOURCE_MISMATCH)[0]
            .deviation
            .severity,
        Severity::Critical
    );
    assert!(p
        .process_at(&sedp_datagram(LEGIT, "rt/cmd_vel", TWIST), RIP, t)
        .is_empty());
}

/// A configured discovery server may relay; nobody else may.
#[test]
fn discovery_server_relay_is_trusted() {
    let t = Instant::now();
    let server: std::net::IpAddr = "10.0.0.2".parse().unwrap();
    let mut opts = PipelineOptions::default();
    opts.binding.discovery_servers.push(server);
    let mut p = pipeline_with(opts);
    let relayed = sedp_from([0x5e; 12], LEGIT, "rt/cmd_vel");
    let f = p.process_at(&relayed, "10.0.0.2", t);
    assert!(
        with_rule(&f, rules::ENDPOINT_SOURCE_MISMATCH).is_empty(),
        "{f:#?}"
    );
    let f = p.process_at(&relayed, "10.0.0.3", t);
    assert_eq!(with_rule(&f, rules::ENDPOINT_SOURCE_MISMATCH).len(), 1);
}

/// Disabling the check is possible (and warned about by the config), and
/// then F3 is not caught: documents why it is on by default.
#[test]
fn binding_disabled_misses_f3() {
    let t = Instant::now();
    let mut p = pipeline_with(PipelineOptions {
        binding: BindingOptions {
            enabled: false,
            ..Default::default()
        },
        ..Default::default()
    });
    p.process_at(&spdp_datagram(LEGIT, ROBOT_IP), RIP, t);
    assert!(p
        .process_at(&sedp_from(LEGIT, LEGIT, "rt/cmd_vel"), XIP, t)
        .is_empty());
}

/// A dispose of the profiled participant's writer from a foreign IP.
#[test]
fn spoofed_endpoint_removal_is_medium() {
    let t = Instant::now();
    let mut p = pipeline();
    bind_legit(&mut p, t);
    let f = p.process_at(&datagram(LEGIT, &[sedp_dispose_sub(LEGIT)]), XIP, t);
    let r = with_rule(&f, rules::DISCOVERY_REMOVAL);
    assert_eq!(r.len(), 1, "{f:#?}");
    assert_eq!(r[0].deviation.severity, Severity::Medium);
    let f = p.process_at(&datagram(LEGIT, &[sedp_dispose_sub(LEGIT)]), RIP, t);
    assert_eq!(
        with_rule(&f, rules::DISCOVERY_REMOVAL)[0]
            .deviation
            .severity,
        Severity::Low
    );
}

// ---------------------------------------------------------- F1 / F2 ----

/// F1: an SEDP announcement in a single DATA_FRAG is reassembled by the
/// pipeline (it uses the stateful reassembler), so the rogue motion writer
/// is seen.
#[test]
fn f1_single_data_frag_writer_is_seen() {
    let payload = sedp_payload(ROGUE, "rt/cmd_vel", TWIST, 0);
    let n = payload.len();
    let d = datagram(
        ROGUE,
        &[data_frag(
            ENTITY_SEDP_PUB_WRITER,
            1,
            1,
            n as u16,
            n as u32,
            &payload,
        )],
    );
    let mut p = pipeline();
    let f = p.process(&d, XIP);
    assert!(
        f.iter().any(
            |x| x.deviation.rule == "robot.ros2.unauthorized_motion_writer"
                && x.deviation.severity == Severity::Critical
        ),
        "{f:#?}"
    );
}

/// F2a: junk partial samples evict the attacker's partial SEDP sample. The
/// announcement is lost, but the eviction is reported (Medium).
#[test]
fn f2a_fragment_eviction_flood_is_reported() {
    let payload = sedp_payload(ROGUE, "rt/cmd_vel", TWIST, 0);
    let half = payload.len() / 2 / 4 * 4;
    let n = payload.len() as u32;
    let mut subs = vec![data_frag(
        ENTITY_SEDP_PUB_WRITER,
        1,
        1,
        half as u16,
        n,
        &payload[..half],
    )];
    for i in 0..40u8 {
        subs.push(info_src([i + 1; 12]));
        subs.push(data_frag(ENTITY_SEDP_PUB_WRITER, 1, 1, 4, 8, &[0; 4]));
    }
    // A small table (the pre-lab defaults), so 40 junk sources overflow it.
    let mut p = pipeline_with(PipelineOptions {
        reassembly: robodr_ros2_pipeline::ReassemblyLimits {
            max_pending_samples: 16,
            max_total_bytes: 256 * 1024,
            max_pending_per_source: 4,
            ..Default::default()
        },
        ..Default::default()
    });
    let f = p.process(&datagram(ROGUE, &subs), XIP);
    let e = with_rule(&f, rules::DISCOVERY_FRAGMENT_EVICTED);
    assert_eq!(e.len(), 1, "{f:#?}");
    assert_eq!(e[0].deviation.severity, Severity::Medium);
    assert!(p.stats().fragment_evictions >= 1);
    assert!(
        p.reassembler().pending_samples()
            <= robodr_ros2_pipeline::ReassemblyLimits::default().max_pending_samples
    );
}

/// F2b: a conflicting duplicate of fragment 1 makes the reassembler drop the
/// sample: reported as rejected (Medium), always.
#[test]
fn f2b_conflicting_duplicate_fragment_is_reported() {
    let payload = sedp_payload(ROGUE, "rt/cmd_vel", TWIST, 0);
    let n = payload.len() as u32;
    let h = payload.len() / 2 / 4 * 4;
    let f1 = data_frag(ENTITY_SEDP_PUB_WRITER, 1, 1, h as u16, n, &payload[..h]);
    let f1_bad = data_frag(ENTITY_SEDP_PUB_WRITER, 1, 1, h as u16, n, &vec![0x41; h]);
    let mut p = pipeline_with(PipelineOptions {
        report_anomalies: false,
        report_fragmentation: false,
        ..Default::default()
    });
    let f = p.process(&datagram(ROGUE, &[f1, f1_bad]), XIP);
    let r = with_rule(&f, rules::DISCOVERY_FRAGMENT_CONFLICT);
    assert_eq!(r.len(), 1, "{f:#?}");
    assert_eq!(r[0].deviation.severity, Severity::Medium);
}

// ----------------------------------------------------------------- F4 ----

/// F4a: duplicate PID_TOPIC_NAME (benign first, `rt/cmd_vel` second). The
/// parser keeps the first; the pipeline raises a High ambiguity finding and
/// judges the writer as a motion writer: from the wrong IP under the
/// profiled prefix it is Critical although the parsed topic is benign.
#[test]
fn f4a_duplicate_topic_is_ambiguous_and_judged_worst_case() {
    let t = Instant::now();
    let payload = pl_payload(&[
        param(0x005a, &guid(LEGIT, ROGUE_ENTITY)),
        string_param(0x0005, "rt/chatter"),
        string_param(0x0005, "rt/cmd_vel"),
        string_param(0x0007, TWIST),
    ]);
    let d = datagram(LEGIT, &[data(ENTITY_SEDP_PUB_WRITER, 1, &payload)]);
    let mut p = pipeline_with(PipelineOptions {
        report_anomalies: false,
        ..Default::default()
    });
    bind_legit(&mut p, t);
    let f = p.process_at(&d, XIP, t);
    let a = with_rule(&f, rules::AMBIGUOUS_DISCOVERY);
    assert_eq!(a.len(), 1, "{f:#?}");
    assert_eq!(a[0].deviation.severity, Severity::High);
    assert!(a[0].deviation.detail.contains("PID_TOPIC_NAME"));
    let m = with_rule(&f, rules::ENDPOINT_SOURCE_MISMATCH);
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].deviation.severity, Severity::Critical);
    assert!(m[0].deviation.detail.contains("rt/chatter"));
    assert!(m[0].deviation.detail.contains("ambiguous"));
    assert_eq!(p.stats().ambiguous_announcements, 1);
}

/// The same duplicate from an unannounced attacker: ambiguity finding at
/// once, and the held announcement expires as a High (motion-capable).
#[test]
fn f4a_ambiguous_unannounced_writer_is_high() {
    let payload = pl_payload(&[
        param(0x005a, &guid(ROGUE, ROGUE_ENTITY)),
        string_param(0x0005, "rt/chatter"),
        string_param(0x0005, "rt/cmd_vel"),
        string_param(0x0007, TWIST),
    ]);
    let d = datagram(ROGUE, &[data(ENTITY_SEDP_PUB_WRITER, 1, &payload)]);
    let mut p = pipeline();
    let f = p.process(&d, XIP);
    assert_eq!(with_rule(&f, rules::AMBIGUOUS_DISCOVERY).len(), 1);
    let f = p.finish();
    let u = with_rule(&f, rules::ENDPOINT_UNANNOUNCED_PARTICIPANT);
    assert_eq!(u[0].deviation.severity, Severity::High, "{f:#?}");
}

/// F4b: interior NUL in the topic. The parser reads the name up to the first
/// NUL (as a C-string based stack does) and flags it non-canonical; the
/// pipeline inspects the announcement (the rogue `cmd_vel` writer is
/// caught) and raises a High ambiguity finding even with anomaly reporting
/// off, because a length-based stack reads a different name.
#[test]
fn f4b_interior_nul_topic_is_inspected_and_ambiguous() {
    let mut v = 13u32.to_le_bytes().to_vec();
    v.extend_from_slice(b"rt/cmd_vel\0x\0");
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
    let payload = pl_payload(&[
        param(0x005a, &guid(ROGUE, ROGUE_ENTITY)),
        param(0x0005, &v),
        string_param(0x0007, TWIST),
    ]);
    let d = datagram(ROGUE, &[data(ENTITY_SEDP_PUB_WRITER, 1, &payload)]);
    let mut p = pipeline_with(PipelineOptions {
        report_anomalies: false,
        ..Default::default()
    });
    let f = p.process(&d, XIP);
    let a = with_rule(&f, rules::AMBIGUOUS_DISCOVERY);
    assert_eq!(a.len(), 1, "{f:#?}");
    assert_eq!(a[0].deviation.severity, Severity::High);
    assert!(a[0].deviation.detail.contains("PID_TOPIC_NAME"));
    let w = with_rule(&f, "robot.ros2.unauthorized_motion_writer");
    assert_eq!(w.len(), 1, "{f:#?}");
    assert_eq!(w[0].deviation.severity, Severity::Critical);
}

/// F4c: a parameter length that is not a multiple of 4. The parser accepts
/// it the way Fast DDS does (next parameter read right after it) and flags
/// it: the announcement is inspected (rogue `cmd_vel` writer caught) and the
/// anomaly is reported.
#[test]
fn f4c_unaligned_parameter_is_inspected_and_flagged() {
    let mut params = param(0x005a, &guid(ROGUE, ROGUE_ENTITY));
    params.extend_from_slice(&0x0005u16.to_le_bytes());
    params.extend_from_slice(&15u16.to_le_bytes());
    params.extend_from_slice(&11u32.to_le_bytes());
    params.extend_from_slice(b"rt/cmd_vel\0");
    let d = datagram(ROGUE, &[data(ENTITY_SEDP_PUB_WRITER, 1, &pl_raw(&params))]);
    let mut p = pipeline();
    let f = p.process(&d, XIP);
    let w = with_rule(&f, "robot.ros2.unauthorized_motion_writer");
    assert_eq!(w.len(), 1, "{f:#?}");
    assert_eq!(w[0].deviation.severity, Severity::Critical);
    let m = with_rule(&f, rules::MALFORMED_DISCOVERY);
    assert!(
        m.iter()
            .any(|x| x.deviation.detail.contains("MisalignedParameterLength")),
        "{f:#?}"
    );
}

// ----------------------------------------------------------------- F5 ----

/// F5: protocol major version 3: nothing parsed, reported as not inspected.
#[test]
fn f5_unsupported_major_version_is_reported() {
    let mut d = header_v(ROGUE, 3, 0);
    d.extend(data(
        ENTITY_SEDP_PUB_WRITER,
        1,
        &sedp_payload(ROGUE, "rt/cmd_vel", TWIST, 0),
    ));
    let mut p = pipeline_with(PipelineOptions {
        report_anomalies: false,
        ..Default::default()
    });
    let f = p.process(&d, XIP);
    let n = with_rule(&f, rules::DISCOVERY_NOT_INSPECTED);
    assert_eq!(n.len(), 1, "{f:#?}");
    assert!(n[0].deviation.detail.contains("UnsupportedProtocolVersion"));
}

// ----------------------------------------------------------------- F6 ----

/// F6: a 64 KiB datagram of distinct INFO_SRC prefixes, with a Critical
/// rogue motion writer hidden at the end. Output is capped, the Critical
/// finding is never the one crowded out, and the overflow is summarised.
#[test]
fn f6_source_flood_is_capped_and_critical_survives() {
    let mut subs = Vec::new();
    let mut len = 20;
    let mut i: u32 = 0;
    let rogue = sedp_sub(ROGUE, "rt/cmd_vel");
    while len + 24 + rogue.len() < 65_000 {
        let mut pfx = [0u8; 12];
        pfx[..4].copy_from_slice(&i.to_be_bytes());
        pfx[11] = 1;
        subs.push(info_src(pfx));
        len += 24;
        i += 1;
    }
    subs.push(info_src(ROGUE));
    subs.push(rogue);
    let d = datagram(ATT, &subs);
    assert!(d.len() <= 65_507);

    let mut p = pipeline();
    let start = Instant::now();
    let f = p.process(&d, XIP);
    let took = start.elapsed();
    let cap = PipelineOptions::default().max_findings_per_datagram;
    assert!(f.len() <= cap + 1, "{} findings", f.len());
    assert!(
        f.iter()
            .any(|x| x.deviation.rule == "robot.ros2.unauthorized_motion_writer"),
        "the Critical finding survives the cap"
    );
    assert_eq!(
        f[0].deviation.severity,
        Severity::Critical,
        "most severe first"
    );
    let c = with_rule(&f, rules::FINDINGS_CAPPED);
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].deviation.severity, Severity::High);
    assert!(p.stats().capped > 2000);
    assert!(p.remembered() <= cap + 1);
    // Generous bound (debug build, shared CI machine): the point is "not
    // quadratic in the pipeline", the parser's own cost is robodr-rtps'.
    assert!(took < Duration::from_secs(20), "{took:?}");

    // Overflowed findings were not remembered: the next copy reports the
    // next batch, never more than the cap.
    let f = p.process(&d, XIP);
    assert!(!f.is_empty() && f.len() <= cap + 1);
}

/// The cap is configurable and clamped (0 behaves as 1, never panics).
#[test]
fn findings_cap_is_clamped() {
    let mut p = pipeline_with(PipelineOptions {
        max_findings_per_datagram: 0,
        ..Default::default()
    });
    let mut subs = Vec::new();
    for i in 0..10u8 {
        subs.push(info_src([i + 1; 12]));
    }
    let f = p.process(&datagram(ATT, &subs), XIP);
    assert_eq!(f.len(), 2, "{f:#?}"); // one finding + the summary
    let mut p = pipeline_with(PipelineOptions {
        max_findings_per_datagram: usize::MAX,
        ..Default::default()
    });
    assert_eq!(p.process(&datagram(ATT, &subs), XIP).len(), 11);
}

// ---------------------------------------------------- bounded memory ----

/// A flood of fake participants (distinct prefixes, each beaconing SPDP)
/// keeps the binding table within `max_participants`, never evicts the
/// profiled participant, and F3 is still caught afterwards.
#[test]
fn participant_flood_keeps_binding_bounded_and_profiled_entry() {
    let t = Instant::now();
    let mut opts = PipelineOptions::default();
    opts.binding.max_participants = 64;
    let mut p = pipeline_with(opts);
    bind_legit(&mut p, t);
    for n in 0..5_000u32 {
        let mut pfx = [0x33u8; 12];
        pfx[8..].copy_from_slice(&n.to_be_bytes());
        let ip = Ipv4Addr::from(0x0a00_0000 + n);
        p.process_at(
            &spdp_datagram(pfx, ip),
            &ip.to_string(),
            t + Duration::from_millis(u64::from(n)),
        );
        assert!(p.binding().len() <= 64);
    }
    assert!(p.binding().is_bound(&LEGIT), "profiled entry kept");
    assert!(p.stats().binding.evicted >= 5_000 - 64);
    let f = p.process_at(
        &sedp_from(LEGIT, LEGIT, "rt/cmd_vel"),
        XIP,
        t + Duration::from_secs(6),
    );
    assert_eq!(
        with_rule(&f, rules::ENDPOINT_SOURCE_MISMATCH)[0]
            .deviation
            .severity,
        Severity::Critical
    );
}

/// Endpoints for thousands of never-announced participants: the held queue
/// stays bounded and overflow is reported, never silently dropped.
#[test]
fn held_queue_flood_is_bounded_and_reported() {
    let t = Instant::now();
    let mut p = pipeline_with(PipelineOptions {
        dedup_capacity: 1 << 16,
        max_findings_per_datagram: 4096,
        ..Default::default()
    });
    let mut overflow = 0;
    for n in 0..3_000u32 {
        let mut pfx = [0x44u8; 12];
        pfx[8..].copy_from_slice(&n.to_be_bytes());
        let f = p.process_at(&sedp_from(pfx, pfx, "rt/odom"), XIP, t);
        overflow += with_rule(&f, rules::ENDPOINT_UNANNOUNCED_PARTICIPANT).len();
        assert!(p.binding().held_len() <= 1024);
    }
    assert_eq!(overflow, 3_000 - 1024);
    assert_eq!(p.stats().binding.held_overflow, 3_000 - 1024);
    let f = p.finish();
    assert_eq!(
        with_rule(&f, rules::ENDPOINT_UNANNOUNCED_PARTICIPANT).len(),
        1024
    );
    assert_eq!(p.binding().held_len(), 0);
}

/// Repeats of the same held announcement do not grow the queue.
#[test]
fn repeated_held_announcement_is_held_once() {
    let t = Instant::now();
    let mut p = pipeline();
    for _ in 0..500 {
        p.process_at(&sedp_from(ROGUE, ROGUE, "rt/odom"), XIP, t);
    }
    assert_eq!(p.binding().held_len(), 1);
}

// ------------------------------------------------- hostile plumbing ----

/// Hostile / garbage source strings: no panic, no binding judgement on an
/// unparseable IP (counted), and the string is sanitised in the output.
#[test]
fn hostile_src_ip_strings() {
    let t = Instant::now();
    let mut p = pipeline();
    bind_legit(&mut p, t);
    for src in ["", "not an ip\n\u{1b}[2J", "999.1.1.1", &"9".repeat(10_000)] {
        let f = p.process_at(&sedp_from(LEGIT, LEGIT, "rt/cmd_vel"), src, t);
        for x in &f {
            let e = x.extra();
            assert!(!e.src_ip.chars().any(char::is_control), "{e:?}");
            assert!(e.src_ip.chars().count() <= robodr_ros2_pipeline::MAX_TEXT_CHARS + 16);
        }
    }
    assert!(p.stats().binding.unparsed_src_ip >= 4);
    // IPv4-mapped IPv6 is the same host.
    assert!(p
        .process_at(
            &sedp_datagram(LEGIT, "rt/cmd_vel", TWIST),
            "::ffff:192.168.50.10",
            t
        )
        .is_empty());
}

/// A clock that goes backwards (replay of an unordered capture, explicit
/// times) never panics and never expires a held announcement early.
#[test]
fn clock_going_backwards_is_harmless() {
    let t = Instant::now() + Duration::from_secs(3600);
    let mut p = pipeline();
    p.process_at(&sedp_from(ROGUE, ROGUE, "rt/odom"), XIP, t);
    let back = t - Duration::from_secs(1800);
    assert!(p.process_at(&header(ROGUE), XIP, back).len() <= 1);
    assert!(p.tick_at(back).is_empty());
    assert_eq!(p.binding().held_len(), 1);
    assert_eq!(p.tick_at(t + Duration::from_secs(31)).len(), 1);
}

/// Capture counters that go down (source restarted) re-base silently.
#[test]
fn capture_counters_going_down_rebase() {
    use robodr_ros2_pipeline::CaptureHealth;
    let mut p = pipeline();
    // Counters near u64::MAX must not overflow when summed.
    let big = CaptureHealth {
        truncated: u64::MAX,
        malformed: u64::MAX,
        ip_fragment_invalid: u64::MAX,
        ip_fragment_timeouts: u64::MAX,
        ..Default::default()
    };
    let f = p.capture_findings(&big);
    assert_eq!(f.len(), 2);
    // Down: re-base silently.
    assert!(p.capture_findings(&CaptureHealth::default()).is_empty());
    // Up again from the new base: reported (a different count, so not a
    // dedup hit).
    let again = CaptureHealth {
        malformed: 5,
        ..Default::default()
    };
    assert_eq!(p.capture_findings(&again).len(), 1);
}

/// Deterministic fuzz: mutated discovery datagrams (bit flips, truncation,
/// splices, length-field corruption) never panic and keep every structure
/// bounded.
#[test]
fn mutation_fuzz_never_panics_and_stays_bounded() {
    let seeds: Vec<Vec<u8>> = vec![
        spdp_datagram(LEGIT, ROBOT_IP),
        sedp_datagram(ROGUE, "rt/cmd_vel", TWIST),
        datagram(ATT, &[info_src(LEGIT), sedp_sub(LEGIT, "rt/cmd_vel")]),
        datagram(LEGIT, &[sedp_dispose_sub(LEGIT)]),
        datagram(ATT, &[sedp_sub_conflict(ATT, LEGIT, "rt/cmd_vel")]),
        sedp_fragmented(ROGUE, "rt/cmd_vel", TWIST, 300, 64).concat(),
    ];
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut rnd = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let t = Instant::now();
    let mut opts = PipelineOptions {
        dedup_capacity: 256,
        ..Default::default()
    };
    opts.binding.max_participants = 32;
    opts.binding.max_pending = 32;
    let mut p = pipeline_with(opts);
    for i in 0..20_000u64 {
        let mut d = seeds[(rnd() as usize) % seeds.len()].clone();
        match rnd() % 5 {
            0 => {
                for _ in 0..1 + rnd() % 8 {
                    let k = (rnd() as usize) % d.len();
                    d[k] ^= 1 << (rnd() % 8);
                }
            }
            1 => d.truncate((rnd() as usize) % (d.len() + 1)),
            2 => {
                let other = &seeds[(rnd() as usize) % seeds.len()];
                let k = (rnd() as usize) % other.len();
                d.extend_from_slice(&other[k..]);
            }
            3 => {
                // Corrupt a 16-bit field after the header (lengths, PIDs).
                if d.len() > 24 {
                    let k = 20 + (rnd() as usize) % (d.len() - 22);
                    let v = (rnd() as u16).to_le_bytes();
                    d[k] = v[0];
                    d[k + 1] = v[1];
                }
            }
            _ => {
                let k = (rnd() as usize) % d.len();
                d[k] = rnd() as u8;
            }
        }
        let src = format!("10.0.{}.{}", rnd() % 4, rnd() % 4);
        let f = p.process_at(&d, &src, t + Duration::from_millis(i));
        assert!(f.len() <= PipelineOptions::default().max_findings_per_datagram + 1);
    }
    p.finish();
    assert!(p.remembered() <= 256);
    assert!(p.binding().len() <= 32);
    assert_eq!(p.binding().held_len(), 0);
    assert!(
        p.reassembler().pending_samples()
            <= robodr_ros2_pipeline::ReassemblyLimits::default().max_pending_samples
    );
}

/// The watch tool's run loop over hostile datagrams: every stdout line is
/// one JSON object without raw control characters; held announcements are
/// flushed at the end of the input.
#[test]
fn watch_run_source_output_is_clean_json_lines() {
    let evil_topic = "rt/cmd_vel\n{\"rule\":\"fake\"}\u{1b}[2J\u{202e}";
    let mut src = VecDatagramSource::new(vec![
        Datagram::new(spdp_datagram(LEGIT, ROBOT_IP), RIP),
        Datagram::new(sedp_from(LEGIT, LEGIT, evil_topic), "192.168.50.66\n"),
        Datagram::new(sedp_from(ROGUE, ROGUE, evil_topic), XIP),
        Datagram::new(b"RTPS".to_vec(), XIP),
        Datagram::new(Vec::new(), XIP),
        Datagram::new(vec![0xff; 70_000], XIP),
    ]);
    let mut p = pipeline();
    let mut out = Vec::new();
    let (n, err) = robodr_ros2_pipeline::watch::run_source(&mut p, &mut src, &mut out).unwrap();
    assert!(err.is_none());
    let text = String::from_utf8(out).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len() as u64, n);
    assert!(n >= 2, "{text}");
    for l in &lines {
        let v: serde_json::Value = serde_json::from_str(l).unwrap();
        assert!(v.is_object());
        assert_ne!(v["rule"], "fake");
        assert!(!l.chars().any(|c| c.is_control()), "{l:?}");
        let detail = v["detail"].as_str().unwrap();
        assert!(
            !detail.chars().any(|c| c.is_control() || c == '\u{202e}'),
            "{detail:?}"
        );
    }
    assert!(lines
        .iter()
        .any(|l| l.contains(rules::ENDPOINT_UNANNOUNCED_PARTICIPANT)));
}

// ------------------------------------------- discovery fragment review ----

/// Review: the discovery reassembler refused SEDP samples above 64 KiB with
/// only a Medium `discovery_fragment_rejected`, while DDS stacks reassemble
/// far larger samples: a rogue `cmd_vel` writer padded past 64 KiB escaped
/// the Critical. The default now takes it in and judges it.
#[test]
fn padded_rogue_motion_writer_over_64k_is_still_critical() {
    let mut p = pipeline();
    // ~100 KiB: two vendor parameters (a parameter holds at most 64 KiB).
    let payload = pl_payload(&[
        param(0x005a, &guid(ROGUE, [0, 0, 0x12, 0x03])),
        param(0x8001, &[0x5a; 50_000]),
        param(0x8002, &[0x5a; 50_000]),
        string_param(0x0005, "rt/cmd_vel"),
        string_param(0x0007, TWIST),
    ]);
    assert!(payload.len() > 64 * 1024);
    let frag_size = 8000usize;
    let mut found = Vec::new();
    for (i, chunk) in payload.chunks(frag_size).enumerate() {
        let d = datagram(
            ROGUE,
            &[data_frag(
                ENTITY_SEDP_PUB_WRITER,
                7,
                i as u32 + 1,
                frag_size as u16,
                payload.len() as u32,
                chunk,
            )],
        );
        found.extend(p.process(&d, XIP));
    }
    assert!(
        with_rule(&found, rules::DISCOVERY_FRAGMENT_REJECTED).is_empty(),
        "{found:#?}"
    );
    assert!(
        found
            .iter()
            .any(|f| f.deviation.severity == Severity::Critical
                && f.deviation.detail.contains("cmd_vel")),
        "{found:#?}"
    );
}

/// Review: an SEDP publications sample refused for a reason a DDS stack does
/// not share (here: over the size cap) is Critical and names the writer
/// prefix; malformed geometry (stacks drop it too) stays Medium.
#[test]
fn refused_sedp_publication_fragments_are_critical() {
    let mut p = pipeline();
    let over = (robodr_rtps::HARD_MAX_SAMPLE_BYTES + 8) as u32;
    let d = datagram(
        ROGUE,
        &[data_frag(
            ENTITY_SEDP_PUB_WRITER,
            3,
            1,
            1024,
            over,
            &[0; 1024],
        )],
    );
    let f = p.process(&d, XIP);
    let r = with_rule(&f, rules::DISCOVERY_FRAGMENT_REJECTED);
    assert_eq!(r.len(), 1, "{f:#?}");
    assert_eq!(r[0].deviation.severity, Severity::Critical);
    assert!(
        r[0].deviation.detail.contains(ROGUE_HEX),
        "{}",
        r[0].deviation.detail
    );
    assert!(r[0].deviation.detail.contains("SampleTooLarge"));
    // Zero fragment size: bad geometry, which every stack drops.
    let d = datagram(
        ROGUE,
        &[data_frag(ENTITY_SEDP_PUB_WRITER, 4, 1, 0, 64, &[0; 4])],
    );
    let f = p.process(&d, XIP);
    let r = with_rule(&f, rules::DISCOVERY_FRAGMENT_REJECTED);
    assert_eq!(r.len(), 1, "{f:#?}");
    assert_eq!(r[0].deviation.severity, Severity::Medium);
}

/// Review: evictions were reported from a diff of the reassembler's
/// cumulative counter, without naming the victim. Now the victim (source
/// prefix, writer, sequence number) is named, and a profiled participant's
/// evicted announcement is High.
#[test]
fn evicted_profiled_discovery_sample_is_named_and_high() {
    let payload = sedp_payload(LEGIT, "rt/cmd_vel", TWIST, 0);
    let half = payload.len() / 2 / 4 * 4;
    let mut p = pipeline_with(PipelineOptions {
        reassembly: robodr_ros2_pipeline::ReassemblyLimits {
            max_pending_samples: 4,
            stale_after_fragments: 4,
            ..Default::default()
        },
        ..Default::default()
    });
    let first = datagram(
        LEGIT,
        &[data_frag(
            ENTITY_SEDP_PUB_WRITER,
            9,
            1,
            half as u16,
            payload.len() as u32,
            &payload[..half],
        )],
    );
    p.process(&first, RIP);
    let mut subs = Vec::new();
    for i in 0..12u8 {
        subs.push(info_src([i + 1; 12]));
        subs.push(data_frag(ENTITY_SEDP_PUB_WRITER, 1, 1, 4, 8, &[0; 4]));
    }
    let f = p.process(&datagram(ROGUE, &subs), XIP);
    let e = with_rule(&f, rules::DISCOVERY_FRAGMENT_EVICTED);
    assert_eq!(e.len(), 1, "{f:#?}");
    assert_eq!(e[0].deviation.severity, Severity::High);
    let detail = &e[0].deviation.detail;
    assert!(
        detail.contains(&format!("sn 9 of writer {LEGIT_HEX}:000003c2")),
        "{detail}"
    );
    assert!(detail.contains("profiled"), "{detail}");
    assert!(p.stats().fragment_evictions >= 1);
}

// ------------------------------------------------- finding text review ----

/// Review: findings were deduplicated on the raw detail, but displayed
/// sanitized and cut to 512 chars, so announcements whose names differed
/// only in the cut-out part became a flood of identical-looking findings;
/// and a long topic pushed the participant / source address out of the
/// displayed detail.
#[test]
fn long_names_dedup_on_displayed_text_and_keep_the_attribution() {
    let mut p = pipeline();
    let t = Instant::now();
    bind_legit(&mut p, t);
    let topic = |mid: char| format!("rt/{}{mid}{}", "a".repeat(1500), "b".repeat(1500));
    // An endpoint of the profiled participant announced from another IP:
    // the binding detail names the topic first, then participant and IP.
    let f1 = p.process_at(&sedp_from(LEGIT, LEGIT, &topic('X')), XIP, t);
    let m1 = with_rule(&f1, rules::ENDPOINT_SOURCE_MISMATCH);
    assert_eq!(m1.len(), 1, "{f1:#?}");
    let shown = m1[0].description();
    assert!(shown.contains(LEGIT_HEX), "{shown}");
    assert!(shown.contains(XIP), "{shown}");
    // Same announcement with a different character in the middle of the
    // name: displayed identically, so it is a duplicate.
    let f2 = p.process_at(&sedp_from(LEGIT, LEGIT, &topic('Y')), XIP, t);
    for f in &f2 {
        assert!(
            !f1.iter().any(|g| g.description() == f.description()),
            "identical-looking finding reported twice: {}",
            f.description()
        );
    }
}
