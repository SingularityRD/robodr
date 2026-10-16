//! Fail-safe behaviour: clock anomalies, black-box failures, replay
//! isolation, strict configuration. All inputs are synthetic.

mod common;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use common::*;
use robodr_agent::replay::{self, ReplayOptions};
use robodr_agent::*;
use robodr_blackbox::sign::SignError;
use robodr_blackbox::{HmacSha256Key, RecordKind, Signer};
use robodr_firewall::ChannelKind;
use robodr_responder::{SafetyState, Step};

/// Every agent-fault note in the black box, as JSON.
fn fault_notes(dir: &std::path::Path) -> Vec<serde_json::Value> {
    records(dir)
        .into_iter()
        .filter(|(_, r)| r.kind == RecordKind::Note)
        .filter_map(|(_, r)| serde_json::from_slice::<serde_json::Value>(&r.payload).ok())
        .filter(|v| v["kind"] == "robodr.agent_fault")
        .collect()
}

fn intact(dir: &std::path::Path, fin: Finished) -> bool {
    verify_blackbox(dir, &verifier(), Some(fin.checkpoint), Some(ROBOT))
        .unwrap()
        .is_intact()
}

// Clock ------------------------------------------------------------------------

#[test]
fn clock_regression_is_recorded_as_a_signed_fault() {
    let dir = tmpdir("fs-clk");
    let mut agent = build(config(&dir, demo_profile(true), validated_policy()));
    agent.handle(at(5_000 * MS), &rogue_participant(), SafetyState::Idle);
    let o = agent.handle(at(1_000 * MS), &rogue_cmd_vel_writer(), SafetyState::Idle);
    // Detection is unaffected.
    assert_eq!(o.len(), 1);
    assert!(o[0].finding.is_some());
    let faults: Vec<_> = agent.faults().cloned().collect();
    assert_eq!(faults.len(), 1);
    assert_eq!(faults[0].kind, FaultKind::ClockRegression);
    assert_eq!(faults[0].mono_ns, 5_000 * MS, "held, not regressed");
    assert!(faults[0].record.is_some(), "written to the black box");
    assert!(matches!(
        faults[0].clock,
        Some(ClockAnomaly::MonoRegression { observed_ns, held_ns })
            if observed_ns == 1_000 * MS && held_ns == 5_000 * MS
    ));
    let s = agent.stats();
    assert_eq!((s.clock_regressions, s.faults), (1, 1));
    assert!(intact(&dir, agent.finish().unwrap()));
    let notes = fault_notes(&dir);
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0]["fault"], "clock_regression");
    assert_eq!(notes[0]["clock"]["anomaly"], "mono_regression");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn wall_clock_jump_is_recorded_and_does_not_reset_rate_limiting() {
    let dir = tmpdir("fs-wall");
    let mut agent = build(config(&dir, demo_profile(true), validated_policy()));
    let first = agent.handle(
        at(1_000 * MS),
        &rogue_participant(),
        SafetyState::MovingSlow,
    );
    assert!(first[0].plan.max_step > Step::Record);
    // Wall time jumps a day ahead, monotonic time moves 20 ms.
    let jumped = Timestamp {
        wall_ns: START_NS + 1_020 * MS + 86_400_000 * MS,
        mono_ns: 1_020 * MS,
        source: TimeSource::Unknown,
    };
    let again = agent.handle(jumped, &rogue_participant(), SafetyState::MovingSlow);
    // The responder works on monotonic time: still inside the re-issue
    // window, so the repeat is rate-limited, wall jump or not.
    assert!(again[0].plan.suppressed, "{:?}", again[0].plan);
    let f: Vec<_> = agent.faults().cloned().collect();
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].kind, FaultKind::WallClockJump);
    assert_eq!(agent.stats().wall_clock_jumps, 1);
    assert!(intact(&dir, agent.finish().unwrap()));
    assert_eq!(fault_notes(&dir)[0]["fault"], "wall_clock_jump");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn fault_log_is_bounded() {
    let dir = tmpdir("fs-bound");
    let mut agent = build(config(&dir, demo_profile(true), validated_policy()));
    let n = MAX_RETAINED_FAULTS as u64 + 10;
    for i in 0..n {
        // Alternating monotonic regressions.
        let t = if i % 2 == 0 { 10_000 * MS } else { 1 };
        agent.handle(at(t), &rogue_participant(), SafetyState::Idle);
    }
    assert_eq!(agent.faults().count(), MAX_RETAINED_FAULTS);
    let s = agent.stats();
    assert_eq!(s.faults - s.faults_dropped, MAX_RETAINED_FAULTS as u64);
    assert_eq!(agent.take_faults().len(), MAX_RETAINED_FAULTS);
    assert_eq!(agent.faults().count(), 0);
    agent.finish().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

// Black-box failure --------------------------------------------------------------

/// HMAC signer that fails while `down` is set (an HSM/TPM going away).
struct FlakySigner {
    key: HmacSha256Key,
    down: Arc<AtomicBool>,
}

impl Signer for FlakySigner {
    fn algorithm(&self) -> &str {
        self.key.algorithm()
    }
    fn key_id(&self) -> &str {
        self.key.key_id()
    }
    fn sign(&self, m: &[u8]) -> Result<Vec<u8>, SignError> {
        if self.down.load(Ordering::SeqCst) {
            return Err(SignError::new("simulated signer outage"));
        }
        self.key.sign(m)
    }
    fn verify_own(&self, m: &[u8], sig: &[u8]) -> Option<bool> {
        self.key.verify_own(m, sig)
    }
}

#[test]
fn evidence_outage_never_weakens_the_plan_and_is_recorded() {
    let state = SafetyState::MovingSlow;
    // Reference run with a healthy black box.
    let ref_dir = tmpdir("fs-ref");
    let mut reference = build(config(&ref_dir, demo_profile(true), validated_policy()));
    let r1 = reference.handle(at(1_000 * MS), &rogue_participant(), state);
    let r2 = reference.handle(at(1_020 * MS), &rogue_cmd_vel_writer(), state);
    reference.finish().unwrap();

    let dir = tmpdir("fs-flaky");
    let down = Arc::new(AtomicBool::new(false));
    let signer = Box::new(FlakySigner {
        key: HmacSha256Key::new("test-key", &KEY).unwrap(),
        down: down.clone(),
    });
    let mut agent = Agent::new(
        config(&dir, demo_profile(true), validated_policy()),
        signer,
        clock(),
    )
    .unwrap();
    down.store(true, Ordering::SeqCst);
    let o1 = agent.handle(at(1_000 * MS), &rogue_participant(), state);
    let o2 = agent.handle(at(1_020 * MS), &rogue_cmd_vel_writer(), state);
    assert!(agent.evidence_degraded());
    for (o, r) in [(&o1[0], &r1[0]), (&o2[0], &r2[0])] {
        // Same plan and disposition as with a healthy black box.
        assert_eq!(o.plan, r.plan);
        assert_eq!(o.disposition, r.disposition);
        // Still a valid finding, without evidence links.
        assert!(o.finding.is_some(), "{:?}", o.finding_errors);
        assert!(o.evidence.refs().is_empty());
        assert!(!o.evidence.errors.is_empty());
    }
    let f: Vec<_> = agent.faults().cloned().collect();
    assert_eq!(f[0].kind, FaultKind::EvidenceWriteFailed);
    assert!(f[0].record.is_none());
    assert_eq!(
        f.iter()
            .filter(|f| f.kind == FaultKind::EvidenceWriteFailed)
            .count(),
        1,
        "one fault per outage, not per append: {f:?}"
    );

    // The signer comes back: the next append succeeds and the gap is
    // recorded in the chain.
    down.store(false, Ordering::SeqCst);
    let o3 = agent.handle(at(3_000 * MS), &rogue_participant(), state);
    assert!(!agent.evidence_degraded());
    assert!(!o3[0].evidence.refs().is_empty());
    let rec = agent
        .faults()
        .find(|f| f.kind == FaultKind::EvidenceRecovered)
        .cloned()
        .unwrap();
    assert!(rec.record.is_some());
    assert!(rec.detail.contains("appends lost"), "{}", rec.detail);
    let lost = agent.stats().evidence_errors;
    assert!(lost >= 4, "{lost}");
    assert!(intact(&dir, agent.finish().unwrap()));
    let notes = fault_notes(&dir);
    assert!(notes.iter().any(|n| n["fault"] == "evidence_recovered"));
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_dir_all(&ref_dir).unwrap();
}

#[test]
fn black_box_io_failure_is_recovered_by_reopening() {
    let dir = tmpdir("fs-io");
    let mut cfg = config(&dir, demo_profile(true), validated_policy());
    // Small segments so the next append must rotate (create a file).
    cfg.blackbox.max_segment_bytes = 4096;
    cfg.record_all_events = true;
    let mut agent = build(cfg);
    let state = SafetyState::MovingSlow;
    agent.handle(at(1_000 * MS), &rogue_participant(), state);
    // The directory disappears under the agent: rotation fails with an I/O
    // error.
    std::fs::remove_dir_all(&dir).unwrap();
    let mut t = 1_000 * MS;
    let mut recovered = false;
    for _ in 0..400 {
        t += 20 * MS;
        let o = agent.handle(at(t), &cmd(LEGIT_WRITER, 0.1), state);
        assert!(o.iter().all(|o| o.finding.is_some()));
        if agent.stats().blackbox_reopens > 0 {
            recovered = true;
            break;
        }
    }
    assert!(recovered, "{:?}", agent.faults().collect::<Vec<_>>());
    assert!(agent
        .faults()
        .any(|f| f.kind == FaultKind::EvidenceWriteFailed));
    // Detections after recovery carry evidence again.
    let o = agent.handle(at(t + 2_000 * MS), &rogue_cmd_vel_writer(), state);
    assert!(o[0].evidence.deviation.is_some(), "{:?}", o[0].evidence);
    let fin = agent.finish().unwrap();
    // A fresh chain was started in the recreated directory and verifies.
    assert!(intact(&dir, fin));
    std::fs::remove_dir_all(&dir).unwrap();
}

// Replay isolation ---------------------------------------------------------------

fn replay_opts(dir: &std::path::Path) -> ReplayOptions {
    let ex = examples();
    let mut o = ReplayOptions::new(
        ex.join("rogue-ugv.jsonl"),
        ex.join("ugv-demo.profile.json"),
        ex.join("policy-oem-validated.json"),
        dir,
        KEY.to_vec(),
        ROBOT,
    );
    o.safety = SafetyState::MovingSlow;
    o.firewall = true;
    o.firewall_max_angular = demo_angular();
    o
}

/// (replay flag, steps offered without approval) per request.
type Seen = Vec<(bool, Vec<Step>)>;

#[derive(Clone, Default)]
struct Capture(Rc<RefCell<Seen>>);

impl Executor for Capture {
    fn submit(&mut self, r: &ExecutionRequest<'_>) {
        self.0
            .borrow_mut()
            .push((r.replay, r.steps_without_approval()));
    }
}

#[test]
fn replay_agent_requests_are_marked_and_offer_nothing() {
    let dir = tmpdir("fs-replay-mark");
    let opts = replay_opts(&dir);
    let cap = Capture::default();
    let mut agent = replay::build_agent(&opts)
        .unwrap()
        .with_executor(Box::new(cap.clone()));
    assert!(agent.is_replay());
    agent.tick(&rogue_participant(), SafetyState::MovingSlow);
    agent.tick(&rogue_cmd_vel_writer(), SafetyState::MovingSlow);
    agent.finish().unwrap();
    let seen = cap.0.borrow();
    assert!(!seen.is_empty());
    for (replay, steps) in seen.iter() {
        assert!(*replay);
        assert!(steps.is_empty(), "{steps:?}");
    }
    // A live agent with the same plan would offer steps (sanity check).
    let live_dir = tmpdir("fs-live");
    let cap = Capture::default();
    let mut live = build(config(&live_dir, demo_profile(true), validated_policy()))
        .with_executor(Box::new(cap.clone()));
    live.handle(at(MS), &rogue_participant(), SafetyState::MovingSlow);
    live.finish().unwrap();
    assert!(cap.0.borrow().iter().any(|(r, s)| !r && !s.is_empty()));
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_dir_all(&live_dir).unwrap();
}

#[test]
fn replay_refuses_a_used_black_box_directory() {
    let dir = tmpdir("fs-replay-used");
    let opts = replay_opts(&dir);
    let mut out = Vec::new();
    replay::run(&opts, &mut out, None, None).unwrap();
    let before = robodr_blackbox::verify::read_segments(&dir).unwrap();
    let err = replay::run(&opts, &mut Vec::new(), None, None).unwrap_err();
    assert!(err.to_string().contains("not empty"), "{err}");
    // Nothing was appended to the existing chain.
    let after = robodr_blackbox::verify::read_segments(&dir).unwrap();
    assert_eq!(
        before.iter().map(|s| &s.bytes).collect::<Vec<_>>(),
        after.iter().map(|s| &s.bytes).collect::<Vec<_>>()
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn replay_retains_a_bounded_number_of_outcomes() {
    let full_dir = tmpdir("fs-replay-full");
    let full = replay::run(&replay_opts(&full_dir), &mut Vec::new(), None, None).unwrap();
    let dir = tmpdir("fs-replay-cap");
    let mut opts = replay_opts(&dir);
    opts.max_retained_outcomes = 1;
    let mut findings = Vec::new();
    let capped = replay::run(&opts, &mut findings, None, None).unwrap();
    let total = full.outcomes.len() as u64;
    assert!(total > 1);
    assert_eq!(capped.outcomes.len(), 1);
    assert_eq!(capped.outcomes_dropped, total - 1);
    assert_eq!(capped.by_severity.values().sum::<u64>(), total);
    assert_eq!(capped.by_disposition, full.by_disposition);
    // Every finding is still written and every link still checked.
    assert_eq!(
        String::from_utf8(findings).unwrap().lines().count() as u64,
        total
    );
    assert_eq!(capped.links, full.links);
    assert!(capped.verified());
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_dir_all(&full_dir).unwrap();
}

// Configuration ------------------------------------------------------------------

#[test]
fn strict_parsing_refuses_unknown_fields_and_out_of_range_numbers() {
    // A typo in "locked" would silently leave the profile in observe mode.
    let e = strict_from_str::<robodr_events::profile::Profile>(r#"{"model":"m","lockd":true}"#)
        .unwrap_err();
    assert!(e.contains("/lockd"), "{e}");
    // Nested unknown field.
    let e = strict_from_str::<robodr_events::profile::Profile>(
        r#"{"model":"m","motion_envelopes":{"/cmd_vel":{"max_linear_sped":0.5}}}"#,
    )
    .unwrap_err();
    assert!(
        e.contains("/motion_envelopes//cmd_vel/max_linear_sped"),
        "{e}"
    );
    // Monitor config defaults everything; a misspelt field must not pass.
    let mut v = serde_json::to_value(robodr_motion::MonitorConfig::ugv("m")).unwrap();
    v["latency_max_nss"] = serde_json::json!(5);
    let e = strict_from_str::<robodr_motion::MonitorConfig>(&v.to_string()).unwrap_err();
    assert!(e.contains("latency_max_nss"), "{e}");
    // Round trip of a valid config is accepted.
    let ok = serde_json::to_string(&robodr_motion::MonitorConfig::ugv("m")).unwrap();
    strict_from_str::<robodr_motion::MonitorConfig>(&ok).unwrap();
    // Out-of-range and non-JSON numbers.
    for bad in [
        r#"{"model":"m","motion_envelopes":{"/c":{"max_linear_speed":1e400}}}"#,
        r#"{"model":"m","motion_envelopes":{"/c":{"max_linear_speed":NaN}}}"#,
        r#"{"model":"m","motion_envelopes":{"/c":{"max_linear_speed":Infinity}}}"#,
    ] {
        assert!(
            strict_from_str::<robodr_events::profile::Profile>(bad).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn replay_loaders_are_strict() {
    let dir = tmpdir("fs-load");
    let p = dir.join("profile.json");
    std::fs::write(&p, r#"{"model":"m","lockd":true}"#).unwrap();
    assert!(replay::load_profile(&p).is_err());
    std::fs::write(&p, r#"{"model":"m","locked":true}"#).unwrap();
    assert!(replay::load_profile(&p).unwrap().locked);
    let m = dir.join("monitor.json");
    std::fs::write(&m, r#"{"bogus":1}"#).unwrap();
    assert!(replay::load_monitor_config(&m).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn configuration_that_would_disable_protection_is_refused() {
    let dir = tmpdir("fs-cfg");
    let bad = |c: AgentConfig| match Agent::new(c, signer(), clock()) {
        Err(AgentError::Config(m)) => m,
        other => panic!("accepted: {other:?}"),
    };
    // An infinite firewall limit (the firewall itself would accept it).
    let mut c = config(&dir, demo_profile(true), validated_policy());
    let mut fw =
        FirewallSettings::from_profile(&c.profile, &BTreeMap::new(), &demo_angular()).unwrap();
    fw.channels.get_mut("/cmd_vel").unwrap().max_linear_speed = Some(f64::INFINITY);
    c.firewall = Some(fw);
    assert!(bad(c).contains("max_linear_speed"));
    // NaN hard-reject factor.
    let mut c = config(&dir, demo_profile(true), validated_policy());
    let mut fw =
        FirewallSettings::from_profile(&c.profile, &BTreeMap::new(), &demo_angular()).unwrap();
    fw.channels.get_mut("/cmd_vel").unwrap().hard_reject_factor = f64::NAN;
    c.firewall = Some(fw);
    assert!(bad(c).contains("hard_reject_factor"));
    // Zero Kafka partitions.
    let mut c = config(&dir, demo_profile(true), validated_policy());
    c.kafka_partitions = Some(0);
    assert!(bad(c).contains("kafka_partitions"));
    // A profile version no finding could carry: refused at start, not on
    // every finding.
    let mut c = config(&dir, demo_profile(true), validated_policy());
    c.profile_version = "v\u{1b}[31m".repeat(100);
    assert!(bad(c).contains("valid finding"));
    let mut c = config(&dir, demo_profile(true), validated_policy());
    c.robot.site = String::new();
    assert!(bad(c).contains("valid finding"));
    // Empty feedback channel name.
    let mut c = config(&dir, demo_profile(true), validated_policy());
    let mut ms = MonitorSettings::new(robodr_motion::MonitorConfig::ugv("m"));
    ms.feedback_sources
        .insert(String::new(), robodr_motion::FeedbackSource::Imu);
    c.monitor = Some(ms);
    assert!(bad(c).contains("feedback channel"));
    // Nothing was created for the refused configurations.
    assert!(!dir
        .join(robodr_blackbox::store::segment_file_name(0))
        .exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn firewall_twist_channels_need_an_explicit_angular_bound() {
    let p = demo_profile(true);
    // Taken from the agent config, never a built-in default.
    let fw = FirewallSettings::from_profile(&p, &BTreeMap::new(), &demo_angular()).unwrap();
    let spec = &fw.channels["/cmd_vel"];
    assert_eq!(spec.kind, ChannelKind::Twist);
    assert_eq!(spec.max_angular_speed, Some(DEMO_MAX_ANGULAR));
    fw.validate().unwrap();
    // Absent: fail closed with a configuration error naming the channel.
    match FirewallSettings::from_profile(&p, &BTreeMap::new(), &BTreeMap::new()) {
        Err(AgentError::Config(m)) => {
            assert!(
                m.contains("/cmd_vel") && m.contains("max_angular_speed"),
                "{m}"
            )
        }
        other => panic!("accepted: {other:?}"),
    }
    // A hand-built settings value without it is refused by Agent::new.
    let dir = tmpdir("fs-ang");
    let mut c = config(&dir, demo_profile(true), validated_policy());
    let mut fw = fw;
    fw.channels.get_mut("/cmd_vel").unwrap().max_angular_speed = None;
    c.firewall = Some(fw);
    match Agent::new(c, signer(), clock()) {
        Err(AgentError::Config(m)) => assert!(m.contains("max_angular_speed"), "{m}"),
        other => panic!("accepted: {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A signer that cannot check its own signatures (like a hardware key whose
/// public half is configured separately).
struct OpaqueSigner(HmacSha256Key);

impl Signer for OpaqueSigner {
    fn algorithm(&self) -> &str {
        self.0.algorithm()
    }
    fn key_id(&self) -> &str {
        self.0.key_id()
    }
    fn sign(&self, m: &[u8]) -> Result<Vec<u8>, SignError> {
        self.0.sign(m)
    }
}

#[test]
fn signer_without_self_verification_needs_an_explicit_verifier() {
    let dir = tmpdir("fs-opaque");
    let opaque = || Box::new(OpaqueSigner(HmacSha256Key::new("test-key", &KEY).unwrap()));
    // Refused: the black box could not authenticate the chain it resumes.
    match Agent::new(
        config(&dir, demo_profile(true), validated_policy()),
        opaque(),
        clock(),
    ) {
        Err(AgentError::BlackBox(e)) => assert!(e.to_string().contains("verify"), "{e}"),
        other => panic!("accepted: {other:?}"),
    }
    // A verifier for another key is refused too.
    let wrong = Arc::new(HmacSha256Key::new("other-key", &[7u8; 32]).unwrap());
    assert!(Agent::new_with_verifier(
        config(&dir, demo_profile(true), validated_policy()),
        opaque(),
        wrong,
        clock(),
    )
    .is_err());
    // With the matching verifier it runs, and reopens (resume) work too.
    let verifier = Arc::new(HmacSha256Key::new("test-key", &KEY).unwrap());
    for _ in 0..2 {
        let mut agent = Agent::new_with_verifier(
            config(&dir, demo_profile(true), validated_policy()),
            opaque(),
            verifier.clone(),
            clock(),
        )
        .unwrap();
        let o = agent.handle(
            at(1_000 * MS),
            &rogue_participant(),
            SafetyState::MovingSlow,
        );
        assert!(
            !o[0].evidence.refs().is_empty(),
            "{:?}",
            o[0].evidence.errors
        );
        agent.finish().unwrap();
    }
    let _ = std::fs::remove_dir_all(&dir);
}
