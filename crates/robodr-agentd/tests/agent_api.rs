//! The two `robodr-agent` entry points the daemon relies on:
//! `Agent::handle_external` (pipeline / self-health deviations) and
//! `Agent::record_note`.

mod common;

use robodr_agent::{Agent, AgentConfig, Detector, Disposition, ReplayClock};
use robodr_blackbox::{HmacSha256Key, RecorderConfig, TimeSource, Timestamp};
use robodr_events::{Deviation, Mode, Severity};
use robodr_ocsf::{PlatformFamily as OcsfPlatform, RobotInfo, Subject};
use robodr_responder::{
    Connectivity, ControlMode, MissionPhase, OperationalContext, ResponsePolicy, SafetyState, Step,
};

use common::*;

const START: u64 = 1_767_225_600_000 * 1_000_000;

fn agent(dir: &std::path::Path, locked: bool) -> Agent {
    let mut profile = common::pcap::robot_profile(locked);
    profile.model = "ugv-demo-x1".into();
    let policy = ResponsePolicy::from_json(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../robodr-agent/examples/policy-oem-validated.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let ctx = OperationalContext {
        platform: policy.platform,
        morphology: policy.morphology,
        phase: MissionPhase::Transit,
        connectivity: Connectivity::Connected,
        control: ControlMode::Autonomous,
        operator_present: true,
        profile_locked: locked,
    };
    let robot = RobotInfo {
        id: ROBOT.into(),
        model: "ugv-demo-x1".into(),
        platform_family: OcsfPlatform::LinuxRos2,
        site: "lab".into(),
        firmware: None,
    };
    let cfg = AgentConfig::new(
        robot,
        profile,
        policy,
        ctx,
        RecorderConfig::new(dir, ROBOT, "boot"),
    );
    Agent::new(
        cfg,
        Box::new(HmacSha256Key::new(KEY_ID, &KEY).unwrap()),
        Box::new(ReplayClock::new(START, 0, 1_000_000, TimeSource::Unknown)),
    )
    .unwrap()
}

fn at(ms: u64) -> Timestamp {
    Timestamp {
        wall_ns: START + ms * 1_000_000,
        mono_ns: ms * 1_000_000,
        source: TimeSource::Unknown,
    }
}

fn subject() -> Subject {
    Subject {
        src_ip: Some("192.168.50.66".into()),
        ..Subject::default()
    }
}

#[test]
fn sensor_deviation_is_planned_recorded_and_reported_like_an_own_one() {
    let d = tmpdir("api-sensor");
    let mut a = agent(&d.join("bb"), true);
    let dev = Deviation::new(
        "robot.ros2.unauthorized_motion_writer",
        Severity::Critical,
        "rogue writer",
    );
    let o = a.handle_external(
        at(10),
        Detector::Sensor,
        "src:192.168.50.66",
        subject(),
        dev,
        SafetyState::MovingSlow,
    );
    assert_eq!(o.detector, Detector::Sensor);
    assert_eq!(o.deviation.mode, Mode::Enforce);
    assert!(o.plan.max_step > Step::Record, "{:?}", o.plan);
    assert!(o.disposition.is_actionable());
    assert!(o.evidence.deviation.is_some() && o.evidence.plan.is_some());
    assert!(o.evidence.event.is_none());
    let f = o.finding.expect("finding");
    let env = robodr_ocsf::parse_and_validate(&f.value).unwrap();
    assert_eq!(env.entity_context.mode, robodr_ocsf::Mode::Enforce);
    // An observe-mode pipeline deviation stays observe-only.
    let o = a.handle_external(
        at(20),
        Detector::Sensor,
        "src:x",
        subject(),
        Deviation::new("robot.x.y", Severity::Critical, "d").with_mode(Mode::Observe),
        SafetyState::MovingSlow,
    );
    assert_eq!(o.disposition, Disposition::ObserveOnly);
    let n = a
        .record_note(at(30), "test", &serde_json::json!({"kind": "t"}), false)
        .unwrap();
    assert!(n.seq > 0);
    let fin = a.finish().unwrap();
    let report =
        robodr_agent::verify_blackbox(&d.join("bb"), &verifier(), Some(fin.checkpoint), None)
            .unwrap();
    assert!(report.is_intact());
}

#[test]
fn self_health_and_unlocked_profiles_never_yield_an_action() {
    for locked in [true, false] {
        let d = tmpdir("api-health");
        let mut a = agent(&d.join("bb"), locked);
        for (det, sev) in [
            (Detector::SelfHealth, Severity::Critical),
            (Detector::SelfHealth, Severity::High),
            (Detector::Sensor, Severity::Critical),
        ] {
            if det == Detector::Sensor && locked {
                continue;
            }
            let o = a.handle_external(
                at(10),
                det,
                "input:x",
                Subject::default(),
                Deviation::new("robot.agent.input_silent", sev, "blind"),
                SafetyState::CollaborativeHumanNearby,
            );
            assert_eq!(o.deviation.mode, Mode::Observe);
            assert_eq!(o.disposition, Disposition::ObserveOnly, "{o:?}");
            assert_eq!(o.plan.max_step, Step::Record);
            assert!(o.guard_violation.is_none());
            let env = robodr_ocsf::parse_and_validate(&o.finding.unwrap().value).unwrap();
            assert_eq!(env.entity_context.mode, robodr_ocsf::Mode::Observe);
        }
        a.finish().unwrap();
    }
}
