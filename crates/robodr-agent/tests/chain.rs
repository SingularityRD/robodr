//! End-to-end decision chain tests (a)-(f) plus robustness cases.
//! All inputs are synthetic.

mod common;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use common::*;
use robodr_agent::replay::{self, ReplayOptions};
use robodr_agent::*;
use robodr_blackbox::{FindingKind, RecordKind, RetentionMode};
use robodr_events::{Deviation, Mode, MotionFeedback, RobotEvent, Severity};
use robodr_motion::{FeedbackSource, MonitorConfig};
use robodr_ocsf::{parse_and_validate, FindingEnvelope};
use robodr_responder::{ResponseAction, SafetyState, Step};

fn finding(o: &Outcome) -> FindingEnvelope {
    let f = o
        .finding
        .as_ref()
        .unwrap_or_else(|| panic!("no finding: {:?}", o.finding_errors));
    parse_and_validate(&f.value).unwrap_or_else(|e| panic!("invalid finding: {e:?}"))
}

/// Records every request the agent hands to its executor.
#[derive(Clone, Default)]
struct Capture(Rc<RefCell<Vec<(String, Disposition, bool)>>>);

impl Executor for Capture {
    fn submit(&mut self, r: &ExecutionRequest<'_>) {
        self.0
            .borrow_mut()
            .push((r.plan.rule.clone(), r.disposition, r.recheck().is_ok()));
    }
}

// (a) ------------------------------------------------------------------------

#[test]
fn a_locked_profile_rogue_participant_and_foreign_writer() {
    let dir = tmpdir("a");
    let policy = validated_policy();
    let cap = Capture::default();
    let mut agent = build(config(&dir, demo_profile(true), policy.clone()))
        .with_executor(Box::new(cap.clone()));
    let state = SafetyState::MovingSlow;

    let o1 = agent.handle(at(1_000 * MS), &rogue_participant(), state);
    let o2 = agent.handle(at(1_020 * MS), &rogue_cmd_vel_writer(), state);
    assert_eq!((o1.len(), o2.len()), (1, 1));
    let (high, crit) = (&o1[0], &o2[0]);

    // Deviations.
    assert_eq!(high.deviation.rule_str(), "robot.ros2.unknown_participant");
    assert_eq!(high.deviation.severity, Severity::High);
    assert_eq!(
        crit.deviation.rule_str(),
        "robot.ros2.unauthorized_motion_writer"
    );
    assert_eq!(crit.deviation.severity, Severity::Critical);
    for o in [high, crit] {
        assert_eq!(o.detector, Detector::Profile);
        assert_eq!(o.deviation.mode, Mode::Enforce);
        assert_eq!(o.source, format!("participant:{ROGUE}"));
        assert_eq!(o.guard_violation, None);
    }

    // Plans graded per policy. High while moving slow: matrix limit_motion,
    // override for unknown_participant clamps to [restrict, limit_motion]
    // and restricts the participant; limit_motion <= auto_max_step, so no
    // approval.
    assert_eq!(policy.matrix.get(Severity::High, state), Step::LimitMotion);
    assert_eq!(high.plan.max_step, Step::LimitMotion);
    assert_eq!(
        high.plan.steps(),
        vec![Step::Record, Step::Restrict, Step::LimitMotion]
    );
    assert!(high.plan.actions.contains(&ResponseAction::Restrict {
        target: robodr_responder::RestrictTarget::Participant,
        terminate_process: false
    }));
    assert!(!high.plan.requires_human_approval);
    assert_eq!(high.disposition, Disposition::Eligible);
    // Critical while moving slow: request_safe_state, above auto_max_step
    // (limit_motion) => human approval.
    assert_eq!(
        policy.matrix.get(Severity::Critical, state),
        Step::RequestSafeState
    );
    assert_eq!(crit.plan.max_step, Step::RequestSafeState);
    assert!(crit.plan.requires_human_approval);
    assert_eq!(crit.disposition, Disposition::AwaitingHumanApproval);

    // The executor saw both plans; both re-check clean.
    let seen = cap.0.borrow().clone();
    assert_eq!(seen.len(), 2);
    assert!(seen.iter().all(|(_, _, ok)| *ok));

    // Findings validate, carry the right severity and evidence.
    let fh = finding(high);
    let fc = finding(crit);
    assert_eq!(fh.ocsf.severity_id, 4);
    assert_eq!(fc.ocsf.severity_id, 5);
    assert_eq!(fh.severity, Severity::High);
    assert_eq!(fc.severity, Severity::Critical);
    assert_eq!(fh.entity_context.robot.id, ROBOT);
    assert_eq!(fh.ocsf.finding_info.first_seen_time, 1_767_225_601_000);
    assert_eq!(high.finding.as_ref().unwrap().key, fh.finding_id);
    for (o, f) in [(high, &fh), (crit, &fc)] {
        let refs = o.evidence.refs();
        assert_eq!(refs.len(), 3, "event + deviation + plan");
        assert!(o.evidence.errors.is_empty());
        assert_eq!(f.evidence_links.len(), 3);
        let mut sorted = refs.clone();
        sorted.sort();
        assert_eq!(finding_refs(f), sorted);
    }
    let head = agent.blackbox_head().unwrap();
    let finished = agent.finish().unwrap();
    assert_eq!(finished.stats.deviations, 2);
    assert_eq!(finished.stats.findings, 2);
    assert!(finished.checkpoint.seq > head.0);

    // The black box verifies against the final checkpoint ...
    let v = verifier();
    let rep = verify_blackbox(&dir, &v, Some(finished.checkpoint), Some(ROBOT)).unwrap();
    assert!(rep.is_clean(), "{rep:?}");
    // ... every evidence link resolves to an intact signed record ...
    let mut all = finding_refs(&fh);
    all.extend(finding_refs(&fc));
    let links = resolve_links(&dir, &v, &all).unwrap();
    assert!(links.is_ok(), "{links:?}");
    assert_eq!(links.resolved, 6);
    // ... and holds exactly what the outcome says.
    for o in [high, crit] {
        let ev = record_at(&dir, o.evidence.event.as_ref().unwrap());
        assert_eq!(ev.kind, RecordKind::Event);
        assert!(ev.critical);
        assert!(ev.payload_json::<RobotEvent>().is_some());
        let dv = record_at(&dir, o.evidence.deviation.as_ref().unwrap());
        assert_eq!(dv.kind, RecordKind::Deviation);
        assert_eq!(dv.payload_json::<Deviation>().unwrap(), o.deviation);
        let pl = record_at(&dir, o.evidence.plan.as_ref().unwrap());
        assert_eq!(pl.kind, RecordKind::Note);
        let note: serde_json::Value = pl.payload_json().unwrap();
        assert_eq!(note["kind"], "robodr.response_plan");
        assert_eq!(
            note["plan"],
            serde_json::to_value(&o.plan).unwrap(),
            "plan note mirrors the outcome plan"
        );
        assert_eq!(
            note["deviation"]["seq"],
            o.evidence.deviation.as_ref().unwrap().seq
        );
        // Record time = agent's event time.
        assert!(ev.time.wall_ns >= START_NS + 1_000 * MS);
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

// (b) ------------------------------------------------------------------------

#[test]
fn b_unlocked_profile_is_observe_only_everywhere() {
    let dir = tmpdir("b");
    let mut cfg = config(&dir, demo_profile(false), validated_policy());
    cfg.firewall = Some(
        FirewallSettings::from_profile(&cfg.profile, &BTreeMap::new(), &demo_angular()).unwrap(),
    );
    cfg.monitor = Some(MonitorSettings::new(MonitorConfig::ugv("ugv-demo-x1")));
    let cap = Capture::default();
    let mut agent = build(cfg).with_executor(Box::new(cap.clone()));
    let mut outs = Vec::new();
    for (i, e) in [
        rogue_participant(),
        rogue_cmd_vel_writer(),
        cmd(&format!("{ROGUE}000001c1"), 0.3),
        cmd(LEGIT_WRITER, 0.8),
        cmd(LEGIT_WRITER, 5.0),
    ]
    .iter()
    .enumerate()
    {
        // Spread beyond the rate limiter so nothing is "suppressed".
        let t = (1 + i as u64) * 10_000 * MS;
        outs.extend(agent.handle(at(t), e, SafetyState::MovingFast));
    }
    assert!(outs.len() >= 5, "{}", outs.len());
    let mut saw_would_have_safe_state = false;
    for o in &outs {
        assert!(o.deviation.is_observe_only(), "{}", o.deviation.rule);
        assert_eq!(o.disposition, Disposition::ObserveOnly);
        assert!(o.plan.observe_only);
        assert_eq!(o.plan.actions, vec![ResponseAction::Record]);
        assert_eq!(o.plan.max_step, Step::Record);
        assert!(!o.disposition.is_actionable());
        let f = finding(o);
        assert_eq!(f.entity_context.mode, robodr_ocsf::Mode::Observe);
        if o.plan
            .would_have
            .as_ref()
            .is_some_and(|w| w.max_step == Step::RequestSafeState)
        {
            saw_would_have_safe_state = true;
        }
        if let Some(fw) = &o.firewall {
            // Observe mode: the command is forwarded, enforcement recorded.
            assert_eq!(fw.verdict, "passed");
            assert!(fw.would_have.is_some());
            assert!(!fw.enforcing);
        }
    }
    assert!(saw_would_have_safe_state, "would_have shows enforcement");
    assert!(outs.iter().any(|o| o.detector == Detector::Firewall));
    let seen = cap.0.borrow();
    assert!(seen
        .iter()
        .all(|(_, d, ok)| *d == Disposition::ObserveOnly && *ok));
    drop(seen);
    let fin = agent.finish().unwrap();
    assert!(
        verify_blackbox(&dir, &verifier(), Some(fin.checkpoint), None)
            .unwrap()
            .is_clean()
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn b_policy_not_oem_validated_is_observe_only_even_when_locked() {
    let dir = tmpdir("b2");
    let mut policy = validated_policy();
    policy.oem_validated = false;
    let mut agent = build(config(&dir, demo_profile(true), policy));
    let o = agent.handle(at(MS), &rogue_cmd_vel_writer(), SafetyState::MovingSlow);
    assert_eq!(o.len(), 1);
    assert_eq!(o[0].deviation.mode, Mode::Enforce);
    assert_eq!(o[0].disposition, Disposition::ObserveOnly);
    assert_eq!(o[0].plan.actions, vec![ResponseAction::Record]);
    agent.finish().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

// (c) ------------------------------------------------------------------------

fn firewall_agent(dir: &std::path::Path) -> Agent {
    let mut cfg = config(dir, demo_profile(true), validated_policy());
    let mut allow = BTreeMap::new();
    allow.insert("/cmd_vel".to_string(), vec![LEGIT_WRITER.to_string()]);
    cfg.firewall =
        Some(FirewallSettings::from_profile(&cfg.profile, &allow, &demo_angular()).unwrap());
    build(cfg)
}

#[test]
fn c_over_envelope_command_is_limited_and_reported() {
    let dir = tmpdir("c");
    let mut agent = firewall_agent(&dir);
    // In-envelope command from the allowed writer: nothing at all.
    assert!(agent
        .handle(
            at(100 * MS),
            &cmd(LEGIT_WRITER, 0.3),
            SafetyState::MovingSlow
        )
        .is_empty());
    let outs = agent.handle(
        at(140 * MS),
        &cmd(LEGIT_WRITER, 0.8),
        SafetyState::MovingSlow,
    );
    let rules: Vec<&str> = outs.iter().map(|o| o.deviation.rule_str()).collect();
    assert_eq!(
        rules,
        vec![
            "robot.motion.linear_over_envelope",
            "robot.firewall.limited_speed"
        ]
    );
    let prof = &outs[0];
    let fw = &outs[1];
    assert_eq!(prof.deviation.severity, Severity::Critical);
    assert_eq!(fw.deviation.severity, Severity::High);
    assert_eq!(fw.detector, Detector::Firewall);
    let v = fw.firewall.as_ref().unwrap();
    assert_eq!(v.verdict, "limited");
    assert_eq!(v.limit_reasons, vec!["speed"]);
    assert!(v.enforcing);
    let out = v.output_speed.unwrap();
    assert!(out <= 0.5 && out > 0.49, "{out}");
    // Firewall finding links event, verdict, deviation and plan.
    assert!(fw.evidence.firewall_verdict.is_some());
    assert_eq!(fw.evidence.refs().len(), 4);
    assert_eq!(
        fw.evidence.event, prof.evidence.event,
        "event recorded once"
    );
    let ff = finding(fw);
    assert_eq!(ff.evidence_links.len(), 4);
    let pf = finding(prof);
    let c = pf.entity_context.command.as_ref().unwrap();
    assert_eq!(c.linear_speed, Some(0.8));
    assert_eq!(c.envelope_max_linear_speed, Some(0.5));
    // The verdict note in the black box.
    let note: serde_json::Value = record_at(&dir, fw.evidence.firewall_verdict.as_ref().unwrap())
        .payload_json()
        .unwrap();
    assert_eq!(note["kind"], "robodr.firewall_verdict");
    assert_eq!(note["verdict"], "limited");
    assert_eq!(
        note["event"]["seq"],
        fw.evidence.event.as_ref().unwrap().seq
    );

    // Over the hard limit (2x): rejected with a zero substitute.
    let outs = agent.handle(
        at(10_000 * MS),
        &cmd(LEGIT_WRITER, 1.2),
        SafetyState::MovingSlow,
    );
    let fw = outs
        .iter()
        .find(|o| o.detector == Detector::Firewall)
        .unwrap();
    assert_eq!(
        fw.deviation.rule_str(),
        "robot.firewall.rejected_over_hard_limit"
    );
    let v = fw.firewall.as_ref().unwrap();
    assert_eq!(v.verdict, "rejected");
    assert_eq!(v.substitute, Some("zero"));
    assert_eq!(v.output_speed, Some(0.0));

    // A foreign source on the motion channel: rejected, Critical.
    let outs = agent.handle(
        at(20_000 * MS),
        &cmd(&format!("{ROGUE}000001c1"), 0.2),
        SafetyState::MovingSlow,
    );
    assert_eq!(outs.len(), 1);
    assert_eq!(
        outs[0].deviation.rule_str(),
        "robot.firewall.rejected_unknown_source"
    );
    assert_eq!(outs[0].deviation.severity, Severity::Critical);

    let fin = agent.finish().unwrap();
    assert!(
        verify_blackbox(&dir, &verifier(), Some(fin.checkpoint), Some(ROBOT))
            .unwrap()
            .is_clean()
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn c_non_finite_command_is_rejected_and_still_reported() {
    let dir = tmpdir("c2");
    let mut agent = firewall_agent(&dir);
    for (i, bad) in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY]
        .iter()
        .enumerate()
    {
        let outs = agent.handle(
            at((1 + i as u64) * 10_000 * MS),
            &cmd(LEGIT_WRITER, *bad),
            SafetyState::MovingSlow,
        );
        let rules: Vec<&str> = outs.iter().map(|o| o.deviation.rule_str()).collect();
        assert!(
            rules.contains(&"robot.motion.non_finite_command"),
            "{rules:?}"
        );
        assert!(
            rules.contains(&"robot.firewall.rejected_non_finite"),
            "{rules:?}"
        );
        for o in &outs {
            // A valid finding is produced even though the value cannot be
            // carried as a number; the command context omits it.
            let f = finding(o);
            let c = f.entity_context.command.as_ref().unwrap();
            assert_eq!(c.linear_speed, None);
            assert_eq!(c.envelope_max_linear_speed, Some(0.5));
            assert!(o.evidence.deviation.is_some());
        }
    }
    // A negative (signed) over-envelope command: detected by magnitude and
    // reported as a magnitude.
    let outs = agent.handle(
        at(60_000 * MS),
        &cmd(LEGIT_WRITER, -0.8),
        SafetyState::MovingSlow,
    );
    let o = outs
        .iter()
        .find(|o| o.deviation.rule_str() == "robot.motion.linear_over_envelope")
        .unwrap();
    let f = finding(o);
    assert_eq!(
        f.entity_context.command.as_ref().unwrap().linear_speed,
        Some(0.8)
    );
    agent.finish().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

// (d) ------------------------------------------------------------------------

/// Odometry writer GUID used by the motion runs.
const ODOM_WRITER: &str = "01103f5a8c2e00000000010200000203";

/// How the motion runs' odometry is published.
#[derive(Clone, Copy, PartialEq)]
enum Odom {
    /// Signed `linear_velocity` (plus the magnitude), with its writer GUID.
    Signed,
    /// Only the magnitude `measured_linear_speed`, no writer GUID.
    MagnitudeOnly,
}

/// Commands at `0.4 * dir` m/s every 40 ms (`dir` = +1 forward, -1
/// reversing); honest odometry follows a first-order response; between
/// `inject.0` and `inject.1` (s) odometry reports 1.2 m/s in the commanded
/// direction.
fn motion_run_with(
    dir: &std::path::Path,
    inject: Option<(f64, f64)>,
    sign: f64,
    odom: Odom,
) -> (Vec<Outcome>, AgentStats) {
    let mut cfg = config(dir, demo_profile(true), validated_policy());
    let mut mc = MonitorConfig::ugv("ugv-demo-x1");
    mc.command_channels = vec!["/cmd_vel".into()];
    let mut ms = MonitorSettings::new(mc);
    ms.feedback_sources
        .insert("/odom".into(), FeedbackSource::WheelOdometry);
    cfg.monitor = Some(ms);
    let mut agent = build(cfg);
    let mut outs = Vec::new();
    for k in 1..=300u64 {
        let t = k * 20 * MS;
        let e = if k % 2 == 1 {
            cmd(LEGIT_WRITER, 0.4 * sign)
        } else {
            let ts = t as f64 / 1e9;
            let mut v = if ts < 0.1 {
                0.0
            } else {
                0.4 * (1.0 - (-(ts - 0.1) / 0.3).exp())
            };
            v += 0.004 * (k as f64 * 0.7).sin();
            if let Some((a, b)) = inject {
                if ts >= a && ts < b {
                    v = 1.2 + 0.004 * (k as f64 * 0.7).sin();
                }
            }
            let v = v * sign;
            RobotEvent::MotionFeedback(MotionFeedback {
                channel: "/odom".into(),
                measured_linear_speed: Some(v.abs()),
                measured_joint_speed: None,
                linear_velocity: (odom == Odom::Signed).then_some(v),
                angular_velocity: None,
                publisher_guid: (odom == Odom::Signed).then(|| ODOM_WRITER.to_string()),
                timestamp_ns: t,
            })
        };
        outs.extend(agent.handle(at(t), &e, SafetyState::MovingSlow));
    }
    let stats = agent.stats();
    let fin = agent.finish().unwrap();
    assert!(
        verify_blackbox(dir, &verifier(), Some(fin.checkpoint), None)
            .unwrap()
            .is_clean()
    );
    (outs, stats)
}

fn motion_run(dir: &std::path::Path, inject: Option<(f64, f64)>) -> Vec<Outcome> {
    motion_run_with(dir, inject, 1.0, Odom::Signed).0
}

#[test]
fn d_injected_feedback_divergence_becomes_a_finding() {
    let dir = tmpdir("d");
    let outs = motion_run(&dir, Some((4.0, 5.5)));
    assert_eq!(
        outs.len(),
        1,
        "{:#?}",
        outs.iter().map(|o| &o.deviation).collect::<Vec<_>>()
    );
    let o = &outs[0];
    assert_eq!(o.detector, Detector::MotionMonitor);
    assert_eq!(o.deviation.rule_str(), "robot.motion.feedback_divergence");
    assert_eq!(o.deviation.severity, Severity::High);
    assert_eq!(o.source, "channel:/odom");
    assert_eq!(o.disposition, Disposition::Eligible);
    let f = finding(o);
    assert_eq!(f.entity_context.rule_id, "robot.motion.feedback_divergence");
    assert_eq!(
        f.entity_context
            .ros
            .topic
            .as_ref()
            .map(|t| t.value.as_str()),
        Some("/odom")
    );
    // Fired after the persistence window (>= 0.5 s into the injection).
    assert!(f.ocsf.time >= 1_767_225_600_000 + 4_500);
    let links = resolve_links(&dir, &verifier(), &finding_refs(&f)).unwrap();
    assert!(links.is_ok() && links.resolved == 3, "{links:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn d_honest_feedback_raises_nothing() {
    let dir = tmpdir("d2");
    assert!(motion_run(&dir, None).is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn d_reversing_with_signed_odometry_raises_nothing() {
    // Signed command and signed feedback agree on the direction.
    let dir = tmpdir("d3");
    let (outs, stats) = motion_run_with(&dir, None, -1.0, Odom::Signed);
    assert!(
        outs.is_empty(),
        "{:#?}",
        outs.iter().map(|o| &o.deviation).collect::<Vec<_>>()
    );
    assert_eq!(stats.feedback_magnitude_dropped, 0);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn d_interleaved_second_feedback_publisher_is_reported() {
    // An injected second writer on /odom, interleaving with the real one:
    // the writer GUID reaches the monitor (on_feedback_from).
    let dir = tmpdir("d5");
    let mut cfg = config(&dir, demo_profile(true), validated_policy());
    let mut mc = MonitorConfig::ugv("ugv-demo-x1");
    mc.command_channels = vec!["/cmd_vel".into()];
    let mut ms = MonitorSettings::new(mc);
    ms.feedback_sources
        .insert("/odom".into(), FeedbackSource::WheelOdometry);
    cfg.monitor = Some(ms);
    let mut agent = build(cfg);
    let mut outs = Vec::new();
    for k in 1..=300u64 {
        let t = k * 20 * MS;
        let e = if k % 2 == 1 {
            cmd(LEGIT_WRITER, 0.4)
        } else {
            let publisher = if k % 4 == 0 { ODOM_WRITER } else { ROGUE };
            RobotEvent::MotionFeedback(MotionFeedback {
                channel: "/odom".into(),
                measured_linear_speed: Some(0.4),
                measured_joint_speed: None,
                linear_velocity: Some(0.4),
                angular_velocity: None,
                publisher_guid: Some(publisher.to_string()),
                timestamp_ns: t,
            })
        };
        outs.extend(agent.handle(at(t), &e, SafetyState::MovingSlow));
    }
    assert!(
        outs.iter()
            .any(|o| o.deviation.rule_str() == "robot.motion.multiple_feedback_publishers"),
        "{:#?}",
        outs.iter().map(|o| &o.deviation).collect::<Vec<_>>()
    );
    agent.finish().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn d_magnitude_only_feedback_is_withheld_for_a_signed_source() {
    // Wheel odometry is a signed source: a magnitude against a reversing
    // command must not read as "moving against the command". The linear
    // axis is withheld and counted instead.
    let dir = tmpdir("d4");
    let (outs, stats) = motion_run_with(&dir, None, -1.0, Odom::MagnitudeOnly);
    assert!(
        outs.iter()
            .all(|o| o.deviation.rule_str() != "robot.motion.feedback_divergence"),
        "{:#?}",
        outs.iter().map(|o| &o.deviation).collect::<Vec<_>>()
    );
    assert_eq!(stats.feedback_magnitude_dropped, 150);
    std::fs::remove_dir_all(&dir).unwrap();
}

// (e) ------------------------------------------------------------------------

fn replay_opts(dir: &std::path::Path, key: Vec<u8>) -> ReplayOptions {
    let ex = examples();
    let mut o = ReplayOptions::new(
        ex.join("rogue-ugv.jsonl"),
        ex.join("ugv-demo.profile.json"),
        ex.join("policy-oem-validated.json"),
        dir,
        key,
        ROBOT,
    );
    o.safety = SafetyState::MovingSlow;
    o.firewall = true;
    o.firewall_max_angular = demo_angular();
    o.trusted_keys = Some(ex.join("ugv-demo.trust.json"));
    o
}

#[test]
fn e_tampering_with_the_black_box_after_the_run_is_detected() {
    let dir = tmpdir("e");
    let opts = replay_opts(&dir, KEY.to_vec());
    let mut findings = Vec::new();
    let sum = replay::run(&opts, &mut findings, None, None).unwrap();
    assert!(sum.verified(), "{:?} {:?}", sum.report, sum.links);
    let findings_path = dir.with_extension("findings.jsonl");
    std::fs::write(&findings_path, &findings).unwrap();
    let clean = replay::verify(&dir, &KEY, None, Some(ROBOT), Some(&findings_path)).unwrap();
    assert!(clean.verified(), "{:?}", clean.report);

    // Flip one byte inside the payload of the first deviation record.
    let target = sum.outcomes[0].evidence.deviation.clone().unwrap();
    let seg = dir.join(robodr_blackbox::store::segment_file_name(target.segment));
    let mut bytes = std::fs::read(&seg).unwrap();
    let rec = record_at(&dir, &target);
    let needle = &rec.payload[..20];
    let pos = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap();
    bytes[pos + 10] ^= 0x01;
    std::fs::write(&seg, &bytes).unwrap();

    let v = replay::verify(&dir, &KEY, None, Some(ROBOT), Some(&findings_path)).unwrap();
    assert!(!v.verified());
    assert!(!v.report.is_intact());
    assert!(
        v.report
            .tamper()
            .any(|f| matches!(f.kind, FindingKind::HashMismatch { seq } if seq == target.seq)),
        "{:?}",
        v.report.findings
    );
    let links = v.links.unwrap();
    assert!(!links.is_ok());
    assert_eq!(links.checked - links.resolved, 1, "{links:?}");
    assert!(links.problems[0].contains(&format!("seq {}", target.seq)));

    // Deleting the segment entirely is also reported.
    std::fs::remove_file(&seg).unwrap();
    let v = replay::verify(&dir, &KEY, None, Some(ROBOT), Some(&findings_path)).unwrap();
    assert!(!v.verified());
    assert_eq!(v.links.unwrap().resolved, 0);

    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_file(&findings_path).unwrap();
}

#[test]
fn e_wrong_key_does_not_verify() {
    let dir = tmpdir("e2");
    let mut findings = Vec::new();
    replay::run(&replay_opts(&dir, KEY.to_vec()), &mut findings, None, None).unwrap();
    let v = replay::verify(&dir, &[0x43; 32], None, None, None).unwrap();
    assert!(!v.verified());
    std::fs::remove_dir_all(&dir).unwrap();
}

// (f) ------------------------------------------------------------------------

fn replay_bytes(tag: &str, key: Vec<u8>) -> (Vec<u8>, Vec<u8>, Vec<Vec<u8>>) {
    let dir = tmpdir(tag);
    let mut findings = Vec::new();
    let mut outcomes = Vec::new();
    let sum = replay::run(
        &replay_opts(&dir, key),
        &mut findings,
        Some(&mut outcomes),
        None,
    )
    .unwrap();
    assert!(sum.verified());
    let segs = robodr_blackbox::verify::read_segments(&dir)
        .unwrap()
        .into_iter()
        .map(|s| s.bytes)
        .collect();
    std::fs::remove_dir_all(&dir).unwrap();
    (findings, outcomes, segs)
}

#[test]
fn f_same_inputs_same_clock_give_byte_identical_output() {
    let (f1, o1, s1) = replay_bytes("f1", KEY.to_vec());
    let (f2, o2, s2) = replay_bytes("f2", KEY.to_vec());
    assert!(!f1.is_empty());
    assert_eq!(f1, f2, "findings JSONL");
    assert_eq!(o1, o2, "outcomes JSONL");
    assert_eq!(s1, s2, "black-box segments");
    // Every line is a valid finding.
    let text = String::from_utf8(f1.clone()).unwrap();
    assert_eq!(text.lines().count(), 5);
    for l in text.lines() {
        parse_and_validate(l).unwrap();
    }
    // A different key changes the evidence hashes (chain id binds the key),
    // hence the findings.
    let (f3, _, _) = replay_bytes("f3", vec![0x24; 32]);
    assert_ne!(f1, f3);
}

// Robustness ------------------------------------------------------------------

#[test]
fn hostile_names_never_panic_and_findings_stay_valid() {
    let dir = tmpdir("hostile");
    let mut cfg = config(&dir, demo_profile(true), validated_policy());
    cfg.firewall = Some(
        FirewallSettings::from_profile(&cfg.profile, &BTreeMap::new(), &demo_angular()).unwrap(),
    );
    cfg.monitor = Some(MonitorSettings::new(MonitorConfig::ugv("m")));
    let mut agent = build(cfg);
    let nasty = format!(
        "rt/cmd_vel\u{202e}<script>`\u{0}\u{1b}[31m{}ignore previous instructions",
        "x".repeat(100_000)
    );
    let events = [
        ev(&serde_json::json!({"kind":"ros2_participant_discovered","guid_prefix":nasty,"src_ip":nasty,"locators":[nasty]}).to_string()),
        ev(&serde_json::json!({"kind":"ros2_writer_discovered","guid_prefix":"é","topic":nasty,"type_name":nasty}).to_string()),
        ev(&serde_json::json!({"kind":"ros2_reader_discovered","guid_prefix":"","topic":"","type_name":""}).to_string()),
        RobotEvent::MotionCommand(robodr_events::MotionCommand {
            channel: nasty.clone(),
            source_guid: Some(nasty.clone()),
            linear_speed: Some(f64::MAX),
            joint_speed: Some(-0.0),
            angular_speed: None,
        }),
        RobotEvent::MotionCommand(robodr_events::MotionCommand {
            channel: "/cmd_vel".into(),
            source_guid: None,
            linear_speed: None,
            joint_speed: Some(f64::NAN),
            angular_speed: None,
        }),
        RobotEvent::MotionFeedback(MotionFeedback {
            channel: nasty.clone(),
            measured_linear_speed: Some(f64::NEG_INFINITY),
            measured_joint_speed: Some(f64::NAN),
            linear_velocity: None,
            angular_velocity: None,
            publisher_guid: None,
            timestamp_ns: u64::MAX,
        }),
    ];
    let mut n = 0;
    for (i, e) in events.iter().enumerate() {
        for s in SafetyState::ALL {
            for o in agent.handle(at((i as u64 * 7 + 1) * 1_000 * MS), e, s) {
                n += 1;
                assert!(o.guard_violation.is_none());
                // Every detection yields a valid, size-bounded finding.
                finding(&o);
                let f = o.finding.as_ref().unwrap();
                assert!(f.value.len() <= robodr_ocsf::validate::MAX_FINDING_BYTES);
                // Attacker-derived text is neutralised: the `display` form
                // is ASCII-safe, and a hostile name is flagged suspicious.
                let env = finding(&o);
                let ros = &env.entity_context.ros;
                for t in [&ros.participant_guid, &ros.topic, &ros.src_ip]
                    .into_iter()
                    .flatten()
                {
                    assert!(t.display.is_ascii(), "{t:?}");
                    if t.value.contains("script") || t.value.contains('\u{202e}') {
                        assert!(t.suspicious, "{t:?}");
                    }
                }
                // Published mode = effective mode (observe wins).
                assert_eq!(
                    env.entity_context.mode,
                    robodr_ocsf::effective_mode(robodr_ocsf::Mode::Enforce, &o.deviation)
                );
                if s.safety_system_engaged() {
                    assert_eq!(o.plan.actions, vec![ResponseAction::Record]);
                }
            }
        }
    }
    assert!(n > 10);
    let fin = agent.finish().unwrap();
    assert!(
        verify_blackbox(&dir, &verifier(), Some(fin.checkpoint), None)
            .unwrap()
            .is_intact()
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn storage_refusal_does_not_hide_detections() {
    let dir = tmpdir("sat");
    let mut cfg = config(&dir, demo_profile(true), validated_policy());
    cfg.blackbox.mode = RetentionMode::Saturation {
        max_segments: 1,
        critical_reserve_segments: 1,
    };
    cfg.blackbox.max_segment_bytes = 4096;
    let mut agent = build(cfg);
    let mut refused = 0;
    for i in 0..200u64 {
        // Medium, non-critical deviations: unknown reader from a known
        // participant's sibling... (unknown participant => Medium reader).
        let e = ev(&format!(
            r#"{{"kind":"ros2_reader_discovered","guid_prefix":"{ROGUE}","topic":"rt/t{i}","type_name":""}}"#
        ));
        for o in agent.handle(at((i + 1) * 10 * MS), &e, SafetyState::MovingSlow) {
            assert_eq!(o.deviation.severity, Severity::Medium);
            assert!(o.finding.is_some(), "{:?}", o.finding_errors);
            if !o.evidence.errors.is_empty() {
                refused += 1;
                assert!(
                    o.evidence.errors[0].contains("refused"),
                    "{:?}",
                    o.evidence.errors
                );
            }
        }
    }
    assert!(refused > 0, "saturation never reached");
    assert!(agent.stats().evidence_errors > 0);
    agent.finish().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn clock_regression_is_clamped_and_counted() {
    let dir = tmpdir("clk");
    let mut agent = build(config(&dir, demo_profile(true), validated_policy()));
    agent.handle(at(5_000 * MS), &rogue_participant(), SafetyState::Idle);
    let o = agent.handle(at(1_000 * MS), &rogue_cmd_vel_writer(), SafetyState::Idle);
    assert_eq!(o.len(), 1);
    assert_eq!(agent.stats().clock_regressions, 1);
    let fin = agent.finish().unwrap();
    assert!(
        verify_blackbox(&dir, &verifier(), Some(fin.checkpoint), None)
            .unwrap()
            .is_clean()
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn estop_means_record_only() {
    let dir = tmpdir("estop");
    let mut agent = build(config(&dir, demo_profile(true), validated_policy()));
    let o = agent.handle(at(MS), &rogue_cmd_vel_writer(), SafetyState::EStopActive);
    assert_eq!(o[0].plan.actions, vec![ResponseAction::Record]);
    assert_eq!(o[0].disposition, Disposition::RecordOnly);
    agent.finish().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn repeated_finding_becomes_an_update_with_count() {
    let dir = tmpdir("rep");
    let mut agent = build(config(&dir, demo_profile(true), validated_policy()));
    let a = agent.handle(at(MS), &rogue_participant(), SafetyState::Idle);
    let b = agent.handle(at(2_000 * MS), &rogue_participant(), SafetyState::Idle);
    let (fa, fb) = (finding(&a[0]), finding(&b[0]));
    assert_eq!(fa.finding_id, fb.finding_id);
    assert_eq!(fa.ocsf.activity_id, 1);
    assert_eq!(fb.ocsf.activity_id, 2);
    assert_eq!(fb.ocsf.count, 2);
    assert_eq!(
        fb.ocsf.finding_info.first_seen_time,
        fa.ocsf.finding_info.first_seen_time
    );
    assert_ne!(fa.ocsf.metadata.uid, fb.ocsf.metadata.uid);
    agent.finish().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn invalid_configuration_is_refused() {
    let dir = tmpdir("cfg");
    // Bad robot id.
    let mut c = config(&dir, demo_profile(true), validated_policy());
    c.robot.id = "bad id!".into();
    assert!(matches!(
        Agent::new(c, signer(), clock()),
        Err(AgentError::Config(_))
    ));
    // Invalid profile envelope.
    let mut p = demo_profile(true);
    p.motion_envelopes
        .get_mut("/cmd_vel")
        .unwrap()
        .max_linear_speed = Some(f64::NAN);
    assert!(matches!(
        Agent::new(config(&dir, p, validated_policy()), signer(), clock()),
        Err(AgentError::Profile(_))
    ));
    // Platform mismatch.
    let mut c = config(&dir, demo_profile(true), validated_policy());
    c.context.platform = robodr_responder::PlatformFamily::Drone;
    assert!(matches!(
        Agent::new(c, signer(), clock()),
        Err(AgentError::Config(_))
    ));
    // Firewall source not in the profile.
    let mut c = config(&dir, demo_profile(true), validated_policy());
    let mut allow = BTreeMap::new();
    allow.insert("/cmd_vel".to_string(), vec![ROGUE.to_string()]);
    c.firewall = Some(FirewallSettings::from_profile(&c.profile, &allow, &demo_angular()).unwrap());
    assert!(matches!(
        Agent::new(c, signer(), clock()),
        Err(AgentError::Firewall(_))
    ));
    // Broken monitor config.
    let mut c = config(&dir, demo_profile(true), validated_policy());
    let mut mc = MonitorConfig::ugv("m");
    mc.latency_min_ns = 10;
    mc.latency_max_ns = 1;
    c.monitor = Some(MonitorSettings::new(mc));
    assert!(matches!(
        Agent::new(c, signer(), clock()),
        Err(AgentError::Monitor(_))
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

// Signed findings (contract 1.2) ----------------------------------------------

#[test]
fn findings_are_signed_when_a_finding_key_is_configured() {
    use robodr_blackbox::{Ed25519SigningKey, Verifier};
    use robodr_ocsf::{
        parse_and_validate_signed, signature_header, SignaturePolicy, SignatureStatus,
    };

    let dir = tmpdir("signed-findings");
    let key = Ed25519SigningKey::from_seed("finding-key-1", &[3; 32]).unwrap();
    let mut keys: BTreeMap<String, Box<dyn Verifier>> = BTreeMap::new();
    keys.insert(ROBOT.into(), Box::new(key.verifying_key()));
    let mut agent = build(config(&dir, demo_profile(true), validated_policy()))
        .with_finding_signer(Box::new(key))
        .unwrap();
    assert!(agent.signs_findings());
    let o = agent.handle(
        at(1_000 * MS),
        &rogue_cmd_vel_writer(),
        SafetyState::MovingSlow,
    );
    let f = o[0].finding.as_ref().expect("finding");
    assert!(o[0].finding_errors.is_empty(), "{:?}", o[0].finding_errors);
    let sig = signature_header(&f.headers)
        .unwrap()
        .expect("signature header");
    let v = parse_and_validate_signed(&f.value, Some(sig), &keys, SignaturePolicy::Strict).unwrap();
    assert_eq!(
        v.signature,
        SignatureStatus::Verified {
            unit_id: ROBOT.into(),
            key_id: "finding-key-1".into()
        }
    );
    // The value itself is unchanged by signing (still plain-validates).
    assert_eq!(finding(&o[0]), v.envelope);

    // An HMAC key is refused as a finding key (symmetric: verifiers could forge).
    let dir2 = tmpdir("signed-findings-hmac");
    let err = build(config(&dir2, demo_profile(true), validated_policy()))
        .with_finding_signer(signer())
        .unwrap_err();
    assert!(err.to_string().contains("finding signer"), "{err}");

    // Without a finding key, no signature header (1.1-compatible output).
    let dir3 = tmpdir("unsigned-findings");
    let mut plain = build(config(&dir3, demo_profile(true), validated_policy()));
    assert!(!plain.signs_findings());
    let o = plain.handle(
        at(1_000 * MS),
        &rogue_cmd_vel_writer(),
        SafetyState::MovingSlow,
    );
    let f = o[0].finding.as_ref().unwrap();
    assert_eq!(signature_header(&f.headers).unwrap(), None);
    assert_eq!(
        parse_and_validate_signed(&f.value, None, &keys, SignaturePolicy::Strict).unwrap_err(),
        robodr_ocsf::SignatureError::Missing
    );
}
