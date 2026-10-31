//! Motion actions (Sprint 8, `crate::motion`) end to end through the
//! engine, against in-process simulated peers on loopback: a gateway that
//! reads the restriction file with `robodr-firewall-gw`'s own parser and
//! reports it in its status file, a ROS 2 / Unitree participant that
//! parses our RTPS with `robodr-rtps` and answers service calls / SDK
//! requests, and a PX4 that speaks MAVLink 2. Plus the gates: adapter not
//! validated or missing, safety states (moving fast), two-person
//! approvals (missing, the requester, duplicates, replays), morphology,
//! rollback rules, TTL revert across an executor restart.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use robodr_responder::{
    ActionId, Morphology, PlatformFamily, ResponsePolicy, SafeBehaviour, SafetyState,
};
use serde_json::{json, Value};

use crate::decision::{codes, Current};
use crate::engine::{Engine, FixedSafety, Now, Outcome, Status};
use crate::motion::{cdr, mavlink as mav, rtps, MotionRequest};
use crate::order::{Order, Origin, Target};
use crate::tests::{ctx, soc_key_path, FakeNft, SOC_KEY_ID, SOC_SEED};

fn wall_ms() -> u64 {
    crate::proto::wall_ms()
}

fn now() -> Now {
    Now {
        wall_ms: wall_ms(),
        boot_ms: Some(wall_ms()),
    }
}

fn at(ms: u64) -> Now {
    Now {
        wall_ms: ms,
        boot_ms: Some(ms),
    }
}

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "robodr-executor-motion-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn state(s: SafetyState) -> FixedSafety {
    FixedSafety(Current {
        state: s,
        age_ms: 5,
    })
}

fn config(dir: &std::path::Path, motion: Value) -> crate::Resolved {
    let mut v: Value =
        serde_json::from_str(&crate::tests::config_json(dir.to_str().unwrap())).unwrap();
    v["motion"] = motion;
    crate::ExecutorConfig::parse(&v.to_string())
        .unwrap()
        .validate()
        .unwrap()
}

fn policy(platform: PlatformFamily, m: Morphology) -> ResponsePolicy {
    let mut p = ResponsePolicy::conservative_default(platform);
    p.morphology = m;
    p.oem_validated = true;
    p
}

fn engine(dir: &std::path::Path, motion: Value, p: ResponsePolicy, t: Now) -> Engine {
    Engine::open(
        config(dir, motion),
        p,
        Box::new(FakeNft::default()),
        "b1",
        t,
    )
    .unwrap()
}

static NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn nonce() -> String {
    format!("motion-nonce-{:020}", NONCE.fetch_add(1, Ordering::SeqCst))
}

/// A SOC-signed order; `approved_by` goes into the signed body.
fn signed(
    id: &str,
    action: ActionId,
    m: Morphology,
    target: Target,
    ttl: Option<u64>,
    approved_by: &[&str],
    judged: SafetyState,
) -> Order {
    let mut o = Order {
        id: id.into(),
        action,
        target,
        ttl_s: ttl,
        judged_state: judged,
        context: ctx(m),
        plan_morphology: m,
        human_approved: true,
        replay: false,
        origin: Origin::ControlPlane {
            key_id: SOC_KEY_ID.into(),
            requested_by: "analyst@soc".into(),
        },
        issued_ms: wall_ms(),
        soc: None,
    };
    let mut body: Value = serde_json::from_str(&crate::soc::testing::body_for(&o)).unwrap();
    if !approved_by.is_empty() {
        body["approved_by"] = json!(approved_by);
    }
    o.soc = Some(Box::new(crate::soc::SocRequest::sign(
        &SOC_SEED,
        "ugv-007",
        SOC_KEY_ID,
        "POST",
        "/api/v2/robots/ugv-007/action-requests",
        wall_ms() / 1000,
        &nonce(),
        &body.to_string(),
    )));
    o
}

/// The SOC's signed revert of `id`.
fn revert_req(id: &str, approved_by: &[&str]) -> crate::soc::SocRequest {
    let mut body = json!({"requested_by": "analyst@soc", "reason": "done"});
    if !approved_by.is_empty() {
        body["approved_by"] = json!(approved_by);
    }
    crate::soc::SocRequest::sign(
        &SOC_SEED,
        "ugv-007",
        SOC_KEY_ID,
        "POST",
        &format!("/api/v2/robots/ugv-007/action-requests/{id}/revert"),
        wall_ms() / 1000,
        &nonce(),
        &body.to_string(),
    )
}

fn restrict(caps: f64) -> Target {
    Target::Motion(MotionRequest {
        max_linear_speed: Some(caps),
        ..Default::default()
    })
}

fn code(o: &Outcome) -> String {
    o.refusal
        .as_ref()
        .map(|r| r.code.clone())
        .unwrap_or_default()
}

// ------------------------------------------------------------ sim peers

struct Sim {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Sim {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// A simulated gateway: every 10 ms it reads the restriction file with
/// the gateway's own loader (expiry on the real clock) and writes its
/// status `restriction`.
fn sim_gateway(restriction: std::path::PathBuf, status: std::path::PathBuf) -> Sim {
    let stop = Arc::new(AtomicBool::new(false));
    let s = stop.clone();
    let handle = std::thread::spawn(move || {
        while !s.load(Ordering::SeqCst) {
            let r = robodr_firewall_gw::restrict::load(&restriction)
                .ok()
                .flatten()
                .filter(|r| !r.expired(wall_ms()));
            let v = json!({"restriction": r.map(|r| json!({"id": r.id, "factor": r.factor,
                "max_linear_speed": r.max_linear_speed}))});
            let tmp = status.with_extension("tmp");
            let _ = std::fs::write(&tmp, v.to_string());
            let _ = std::fs::rename(&tmp, &status);
            std::thread::sleep(Duration::from_millis(10));
        }
    });
    Sim {
        stop,
        handle: Some(handle),
    }
}

/// What a simulated ROS 2 peer saw: `(topic, payload)` of every user
/// sample, and the topics / types announced.
type Seen = Arc<Mutex<Vec<(String, Vec<u8>)>>>;
type Announced = Arc<Mutex<Vec<(String, String)>>>;

/// A simulated ROS 2 participant on loopback: learns writer GUID -> topic
/// from our SEDP (parsed with `robodr-rtps`), records user samples and
/// answers with `reply(topic, payload)` from its own writer.
fn sim_ros2(
    reply: impl Fn(&str, &[u8]) -> Option<Vec<u8>> + Send + 'static,
) -> (Sim, u16, Seen, Announced) {
    sim_ros2_rmw(FastReply::No, reply)
}

/// How a simulated peer correlates its replies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FastReply {
    /// `rmw_cyclonedds`: the reply closure echoes the payload header.
    No,
    /// `rmw_fastrtps` (Humble): the reply names the request's related
    /// sample identity GUID when it is a reader (else the request writer)
    /// and the request's sequence number, in its inline QoS.
    Yes,
    /// A forger that knows the GUIDs but not the sequence number.
    WrongSn,
    /// A reply without a related sample identity.
    NoIdentity,
}

/// [`sim_ros2`] for a given RMW behaviour.
fn sim_ros2_rmw(
    fast: FastReply,
    reply: impl Fn(&str, &[u8]) -> Option<Vec<u8>> + Send + 'static,
) -> (Sim, u16, Seen, Announced) {
    sim_ros2_inner(fast, false, reply)
}

/// [`sim_ros2_rmw`]; with `late`, the first SEDP announcement of every
/// endpoint is lost (as a real peer drops one that arrives before it
/// processed our SPDP), so its samples are not matched until the endpoint
/// is announced again.
fn sim_ros2_inner(
    fast: FastReply,
    late: bool,
    reply: impl Fn(&str, &[u8]) -> Option<Vec<u8>> + Send + 'static,
) -> (Sim, u16, Seen, Announced) {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    let port = sock.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let seen: Seen = Arc::default();
    let ann: Announced = Arc::default();
    let (s, sn, an) = (stop.clone(), seen.clone(), ann.clone());
    let handle = std::thread::spawn(move || {
        let mut topics: std::collections::HashMap<[u8; 16], String> = Default::default();
        let mut lost: std::collections::HashSet<[u8; 16]> = Default::default();
        let mut buf = vec![0u8; 65536];
        let mut out_sn = 0i64;
        while !s.load(Ordering::SeqCst) {
            let Ok((n, from)) = sock.recv_from(&mut buf) else {
                continue;
            };
            let d = &buf[..n];
            if let Some(r) = robodr_rtps::parse_datagram_detailed(d) {
                for e in &r.endpoints {
                    if let Some(g) = e.guid {
                        if late && lost.insert(g) {
                            continue;
                        }
                        topics.insert(g, e.topic.clone());
                    }
                    an.lock()
                        .unwrap()
                        .push((e.topic.clone(), e.type_name.clone()));
                }
            }
            let Some(u) = robodr_rtps::walk_user_data(d) else {
                continue;
            };
            for smp in u.samples {
                let topic = topics.get(&smp.address.writer).cloned().unwrap_or_default();
                sn.lock()
                    .unwrap()
                    .push((topic.clone(), smp.payload.to_vec()));
                if let Some(p) = reply(&topic, &smp.payload) {
                    out_sn += 1;
                    let req_sn = smp.address.sequence_number;
                    let related = match smp.inline_qos.related_sample_identity {
                        Some((g, _)) if g[15] & 0x04 != 0 => g,
                        _ => smp.address.writer,
                    };
                    let qos = match fast {
                        FastReply::No | FastReply::NoIdentity => None,
                        FastReply::Yes => Some(rtps::related_identity_qos(related, req_sn)),
                        FastReply::WrongSn => Some(rtps::related_identity_qos(related, req_sn + 1)),
                    };
                    let m = rtps::Msg::new([9; 12])
                        .data([0; 4], [0, 0, 9, 3], out_sn, qos.as_deref(), &p)
                        .finish();
                    let _ = sock.send_to(&m, from);
                }
            }
        }
    });
    (
        Sim {
            stop,
            handle: Some(handle),
        },
        port,
        seen,
        ann,
    )
}

fn ros2_peer(port: u16) -> Value {
    json!({"peer_ip": "127.0.0.1", "peer_meta_port": port, "peer_user_port": port,
           "local_ip": "127.0.0.1", "timeout_ms": 1500, "resend_ms": 100,
           "participant_prefix": "0f0e0d0c0b0a090807060504"})
}

/// Echo a service request's header in front of `body`.
fn service_reply(req: &[u8], body: impl FnOnce(&mut cdr::Enc)) -> Option<Vec<u8>> {
    let mut d = cdr::Dec::open(req).ok()?;
    let (c, s) = (d.u64().ok()?, d.i64().ok()?);
    let mut e = cdr::Enc::default();
    cdr::request_header(&mut e, c, s);
    body(&mut e);
    Some(e.payload())
}

// ----------------------------------------------------------------- tests

#[test]
fn gateway_restriction_round_trip_and_ttl_revert_across_a_restart() {
    let d = tmpdir("gw");
    let gwdir = d.join("gw");
    std::fs::create_dir_all(&gwdir).unwrap();
    let (rp, sp) = (gwdir.join("restriction.json"), gwdir.join("status.json"));
    let _gw = sim_gateway(rp.clone(), sp.clone());
    let motion = json!({"restrict_motion": ["gateway"],
        "gateway": {"oem_validated": true, "restriction_path": rp, "status_path": sp,
                    "verify_timeout_ms": 2000}});
    let p = policy(PlatformFamily::Ugv, Morphology::WheeledMobile);
    let t0 = now();
    let mut e = engine(&d, motion.clone(), p.clone(), t0);
    let o = signed(
        "rm-1",
        ActionId::RestrictMotion,
        Morphology::WheeledMobile,
        restrict(0.3),
        Some(60),
        &[],
        SafetyState::MovingFast,
    );
    let out = e.submit(&o, &mut state(SafetyState::MovingFast), t0);
    assert_eq!(out.status, Status::Verified, "{out:?}");
    let r = robodr_firewall_gw::restrict::load(&rp).unwrap().unwrap();
    assert_eq!(r.id, "rm-1");
    assert_eq!(r.max_linear_speed, Some(0.3));
    assert_eq!(r.expires_unix_ms, t0.wall_ms + 60_000);
    // A second restriction while one is in force: refused.
    let o2 = signed(
        "rm-2",
        ActionId::RestrictMotion,
        Morphology::WheeledMobile,
        restrict(0.2),
        Some(60),
        &[],
        SafetyState::Idle,
    );
    assert_eq!(
        code(&e.submit(&o2, &mut state(SafetyState::Idle), t0)),
        codes::ALREADY_ACTIVE
    );
    // The executor dies; it comes back after the TTL (same boot): the
    // restriction is lifted at reconciliation.
    drop(e);
    let later = at(t0.wall_ms + 61_000);
    let e = engine(&d, motion, p, later);
    assert_eq!(e.status("rm-1").status, Status::Reverted);
    assert!(!rp.exists(), "restriction file removed");
    // ... and the gateway does not report it any more.
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&sp).unwrap()).unwrap();
    assert!(v["restriction"].is_null(), "{v}");
}

#[test]
fn gateway_that_never_confirms_fails_and_cleans_up() {
    let d = tmpdir("gw-dead");
    let (rp, sp) = (d.join("restriction.json"), d.join("status.json"));
    std::fs::write(&sp, "{\"restriction\": null}").unwrap();
    let motion = json!({"restrict_motion": ["gateway"],
        "gateway": {"oem_validated": true, "restriction_path": rp, "status_path": sp,
                    "verify_timeout_ms": 200}});
    let mut e = engine(
        &d,
        motion,
        policy(PlatformFamily::Ugv, Morphology::WheeledMobile),
        now(),
    );
    let o = signed(
        "rm-x",
        ActionId::RestrictMotion,
        Morphology::WheeledMobile,
        restrict(0.3),
        Some(60),
        &[],
        SafetyState::Idle,
    );
    let out = e.submit(&o, &mut state(SafetyState::Idle), now());
    assert_eq!(out.status, Status::Failed, "{out:?}");
    assert!(!rp.exists());
}

#[test]
fn unitree_speed_level_is_set_and_reverted_at_ttl() {
    let (sim, port, seen, ann) = sim_ros2(|topic, p| {
        if topic != "rt/api/sport/request" {
            return None;
        }
        let m = robodr_cdr::unitree::decode_unitree(
            robodr_cdr::unitree::UnitreeKind::ApiRequest,
            p,
            &robodr_cdr::Limits::default(),
        )
        .ok()?;
        let robodr_cdr::unitree::UnitreeMessage::ApiRequest(q) = m.message else {
            return None;
        };
        // Response_: identity (id, api id), status code 0, data, binary.
        let mut e = cdr::Enc::default();
        e.i64(q.id);
        e.i64(q.api_id);
        e.i32(0);
        e.string("");
        e.u32(0);
        Some(e.payload())
    });
    let d = tmpdir("unitree");
    // Review finding 3: on a quadruped an absolute cap is judged against
    // the envelope (0.5 of 1.0 here).
    let motion = json!({"restrict_motion": ["unitree_sport"],
        "envelope": {"max_linear_speed": 1.0},
        "unitree_sport": {"oem_validated": true, "ros2": ros2_peer(port)}});
    let t0 = now();
    let mut e = engine(
        &d,
        motion,
        policy(PlatformFamily::Other, Morphology::Quadruped),
        t0,
    );
    // Below min_motion_factor on a quadruped: refused.
    let low = Target::Motion(MotionRequest {
        factor: Some(0.1),
        ..Default::default()
    });
    let mut o = signed(
        "u0",
        ActionId::RestrictMotion,
        Morphology::Quadruped,
        low,
        Some(30),
        &[],
        SafetyState::MovingSlow,
    );
    // A factor is the planner's: the control plane never signs one.
    o.origin = Origin::Planner {
        rule: "r".into(),
        finding_id: None,
    };
    o.soc = None;
    o.human_approved = false;
    assert_eq!(
        code(&e.submit(&o, &mut state(SafetyState::MovingSlow), t0)),
        codes::FALL_HAZARD
    );
    let o = signed(
        "u1",
        ActionId::RestrictMotion,
        Morphology::Quadruped,
        restrict(0.5),
        Some(30),
        &[],
        SafetyState::MovingSlow,
    );
    let out = e.submit(&o, &mut state(SafetyState::MovingSlow), t0);
    assert_eq!(out.status, Status::Verified, "{out:?}");
    assert!(out.note.unwrap().contains("SpeedLevel(-1)"));
    assert!(ann
        .lock()
        .unwrap()
        .iter()
        .any(|(t, ty)| t == "rt/api/sport/request" && ty == "unitree_api::msg::dds_::Request_"));
    e.tick(at(t0.wall_ms + 31_000));
    assert_eq!(e.status("u1").status, Status::Reverted);
    let params: Vec<String> = seen
        .lock()
        .unwrap()
        .iter()
        .filter_map(|(_, p)| {
            let m = robodr_cdr::unitree::decode_unitree(
                robodr_cdr::unitree::UnitreeKind::ApiRequest,
                p,
                &robodr_cdr::Limits::default(),
            )
            .ok()?;
            match m.message {
                robodr_cdr::unitree::UnitreeMessage::ApiRequest(q) => {
                    Some(String::from_utf8_lossy(q.parameter.as_bytes()).into_owned())
                }
                _ => None,
            }
        })
        .collect();
    assert!(params.iter().any(|p| p == "{\"data\":-1}"), "{params:?}");
    assert!(params.iter().any(|p| p == "{\"data\":0}"), "{params:?}");
    drop(sim);
}

#[test]
fn nav2_safe_pause_needs_two_people_and_a_validated_adapter() {
    let cancels = Arc::new(Mutex::new(0usize));
    let c2 = cancels.clone();
    let (_sim, port, seen, _) = sim_ros2(move |topic, p| {
        if topic.starts_with("rq/") && topic.ends_with("/_action/cancel_goalRequest") {
            *c2.lock().unwrap() += 1;
            return service_reply(p, |e| {
                e.u8(0); // ERROR_NONE
                e.u32(0);
            });
        }
        None
    });
    let d = tmpdir("nav2");
    let nav2 = |validated: bool| {
        json!({"safe_pause": "nav2",
               "nav2": {"oem_validated": validated, "ros2": ros2_peer(port),
                        "actions": ["/navigate_to_pose"], "zero_twists": 3,
                        "zero_twist_interval_ms": 10}})
    };
    let p = policy(PlatformFamily::Ugv, Morphology::WheeledMobile);
    let mut e = engine(&d, nav2(false), p.clone(), now());
    let pause = |id: &str, ab: &[&str], s: SafetyState| {
        signed(
            id,
            ActionId::SafePause,
            Morphology::WheeledMobile,
            Target::None,
            None,
            ab,
            s,
        )
    };
    // The site did not validate the adapter.
    let out = e.submit(
        &pause("p0", &["alice", "bob"], SafetyState::Idle),
        &mut state(SafetyState::Idle),
        now(),
    );
    assert_eq!(code(&out), codes::ADAPTER_NOT_VALIDATED);
    drop(e);
    let mut e = engine(&d, nav2(true), p.clone(), now());
    // Approvals: missing, one, the requester counted, the same person twice.
    for (id, ab) in [
        ("p1", &[][..]),
        ("p2", &["alice"][..]),
        ("p3", &["analyst@soc", "alice"][..]),
        ("p4", &["alice", " alice"][..]),
    ] {
        let out = e.submit(
            &pause(id, ab, SafetyState::Idle),
            &mut state(SafetyState::Idle),
            now(),
        );
        assert_eq!(code(&out), codes::APPROVAL_MISSING, "{id}: {out:?}");
    }
    // Moving fast: not by default (an abrupt stop at speed is a hazard).
    let out = e.submit(
        &pause("p5", &["alice", "bob"], SafetyState::MovingFast),
        &mut state(SafetyState::MovingFast),
        now(),
    );
    assert_eq!(code(&out), codes::SAFETY_STATE_NOT_ALLOWED);
    // Judged idle, moving fast at the moment of apply: refused, nothing sent.
    let out = e.submit(
        &pause("p6", &["alice", "bob"], SafetyState::Idle),
        &mut state(SafetyState::MovingFast),
        now(),
    );
    assert_eq!(code(&out), codes::SAFETY_STATE_CHANGED);
    assert_eq!(*cancels.lock().unwrap(), 0);
    // The planner can never order it.
    let mut planner = pause("p7", &[], SafetyState::Idle);
    planner.origin = Origin::Planner {
        rule: "r".into(),
        finding_id: None,
    };
    planner.soc = None;
    planner.human_approved = false;
    assert_eq!(
        code(&e.submit(&planner, &mut state(SafetyState::Idle), now())),
        codes::APPROVAL_MISSING
    );
    // Two people: cancel + zero twists.
    let good = pause("p8", &["alice", "bob"], SafetyState::Idle);
    let out = e.submit(&good, &mut state(SafetyState::Idle), now());
    assert_eq!(out.status, Status::Verified, "{out:?}");
    assert_eq!(*cancels.lock().unwrap(), 1);
    let twists = seen
        .lock()
        .unwrap()
        .iter()
        .filter(|(t, p)| t == "rt/cmd_vel" && *p == cdr::zero_twist())
        .count();
    assert_eq!(twists, 3);
    // Replays: the same request again is a duplicate (not sent again); its
    // signature on another order is a nonce replay.
    assert!(
        e.submit(&good, &mut state(SafetyState::Idle), now())
            .duplicate
    );
    let mut stolen = good.clone();
    stolen.id = "p9".into();
    assert_eq!(
        code(&e.submit(&stolen, &mut state(SafetyState::Idle), now())),
        codes::SOC_NONCE_REPLAYED
    );
    assert_eq!(*cancels.lock().unwrap(), 1);
    // The revert of a two-person action needs two approvers too.
    let out = e.revert_request(
        "p8",
        "done",
        Some(&revert_req("p8", &["alice"])),
        &mut state(SafetyState::Idle),
        now(),
    );
    assert_eq!(code(&out), codes::APPROVAL_MISSING);
    assert_eq!(e.status("p8").status, Status::Verified);
    let out = e.revert_request(
        "p8",
        "done",
        Some(&revert_req("p8", &["alice", "bob"])),
        &mut state(SafetyState::Idle),
        now(),
    );
    assert_eq!(out.status, Status::Reverted, "{out:?}");
    assert!(e.state().events.iter().any(|ev| ev
        .detail
        .contains("cancelled navigation goals are not restored")));
}

#[test]
fn ros2_control_switch_and_its_inverse() {
    let switches = Arc::new(Mutex::new(Vec::<(Vec<String>, Vec<String>)>::new()));
    let s2 = switches.clone();
    let (_sim, port, _, ann) = sim_ros2(move |topic, p| {
        if topic != "rq/controller_manager/switch_controllerRequest" {
            return None;
        }
        let mut d = cdr::Dec::open(p).ok()?;
        d.u64().ok()?;
        d.i64().ok()?;
        let a = d.strings(16).ok()?;
        let x = d.strings(16).ok()?;
        s2.lock().unwrap().push((a, x));
        service_reply(p, |e| e.bool(true))
    });
    let d = tmpdir("r2c");
    let motion = json!({"safe_pause": "ros2_control",
        "ros2_control": {"oem_validated": true, "ros2": ros2_peer(port),
                         "deactivate": ["joint_trajectory_controller"],
                         "activate": ["hold_controller"]}});
    let mut e = engine(
        &d,
        motion,
        policy(PlatformFamily::Arm, Morphology::Arm),
        now(),
    );
    let o = signed(
        "c1",
        ActionId::SafePause,
        Morphology::Arm,
        Target::None,
        None,
        &["alice", "bob"],
        SafetyState::CollaborativeHumanNearby,
    );
    let out = e.submit(&o, &mut state(SafetyState::CollaborativeHumanNearby), now());
    assert_eq!(out.status, Status::Verified, "{out:?}");
    assert!(ann.lock().unwrap().iter().any(|(t, ty)| t
        == "rr/controller_manager/switch_controllerReply"
        && ty == "controller_manager_msgs::srv::dds_::SwitchController_Response_"));
    let out = e.revert_request(
        "c1",
        "done",
        Some(&revert_req("c1", &["alice", "carol"])),
        &mut state(SafetyState::Idle),
        now(),
    );
    assert_eq!(out.status, Status::Reverted, "{out:?}");
    let s = switches.lock().unwrap();
    assert_eq!(
        s[0],
        (
            vec!["hold_controller".to_string()],
            vec!["joint_trajectory_controller".to_string()]
        )
    );
    assert_eq!(
        s.last().unwrap(),
        &(
            vec!["joint_trajectory_controller".to_string()],
            vec!["hold_controller".to_string()]
        )
    );
}

/// A simulated PX4: heartbeats in its current mode every 50 ms; a
/// `DO_SET_MODE` is acknowledged (or refused) and switches the mode.
fn sim_px4(accept: bool) -> (Sim, SocketAddr, Arc<Mutex<u32>>) {
    sim_px4_with(accept, None)
}

/// [`sim_px4`] whose `COMMAND_ACK` names `ack_to` instead of the sender.
fn sim_px4_with(accept: bool, ack_to: Option<(u8, u8)>) -> (Sim, SocketAddr, Arc<Mutex<u32>>) {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    let addr = sock.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let mode = Arc::new(Mutex::new(mav::px4_custom_mode(mav::PX4_MAIN_AUTO, 4))); // MISSION
    let (s, m2) = (stop.clone(), mode.clone());
    let handle = std::thread::spawn(move || {
        let mut gcs: Option<SocketAddr> = None;
        let mut buf = [0u8; 2048];
        let mut seq = 0u8;
        let mut last = std::time::Instant::now();
        while !s.load(Ordering::SeqCst) {
            if let Ok((n, from)) = sock.recv_from(&mut buf) {
                gcs = Some(from);
                for f in mav::decode_all(&buf[..n]).unwrap_or_default() {
                    if let Some((p, cmd, ts, tc)) = mav::parse_command_long(&f) {
                        assert_eq!((ts, tc), (1, 1));
                        let ok = accept && cmd == mav::MAV_CMD_DO_SET_MODE && p[0] == 1.0;
                        if ok {
                            *m2.lock().unwrap() = mav::px4_custom_mode(p[1] as u8, p[2] as u8);
                        }
                        seq = seq.wrapping_add(1);
                        let (ts, tc) = ack_to.unwrap_or((f.sysid, f.compid));
                        let ack = mav::command_ack(cmd, if ok { 0 } else { 2 }, ts, tc);
                        let fr = mav::encode(seq, 1, 1, mav::MSG_COMMAND_ACK, &ack).unwrap();
                        let _ = sock.send_to(&fr, from);
                    }
                }
            }
            if let (Some(g), true) = (gcs, last.elapsed() > Duration::from_millis(50)) {
                last = std::time::Instant::now();
                let hb = mav::Heartbeat {
                    custom_mode: *m2.lock().unwrap(),
                    mav_type: 2,
                    autopilot: 12,
                    base_mode: 0x81,
                    system_status: 4,
                };
                seq = seq.wrapping_add(1);
                let fr = mav::encode(seq, 1, 1, mav::MSG_HEARTBEAT, &hb.payload()).unwrap();
                let _ = sock.send_to(&fr, g);
            }
        }
    });
    (
        Sim {
            stop,
            handle: Some(handle),
        },
        addr,
        mode,
    )
}

#[test]
fn px4_hold_and_rtl_through_mavlink() {
    let (_sim, addr, mode) = sim_px4(true);
    let d = tmpdir("px4");
    let motion = json!({"safe_pause": "px4", "request_safe_state": "px4",
        "px4": {"oem_validated": true, "address": addr.to_string(), "bind": "127.0.0.1:0",
                "timeout_ms": 3000}});
    let mut p = policy(PlatformFamily::Drone, Morphology::Aerial);
    p.safe_state = SafeBehaviour::ReturnToLaunch;
    let mut e = engine(&d, motion.clone(), p.clone(), now());
    let o = signed(
        "h1",
        ActionId::SafePause,
        Morphology::Aerial,
        Target::None,
        None,
        &["alice", "bob"],
        SafetyState::MovingSlow,
    );
    let out = e.submit(&o, &mut state(SafetyState::MovingSlow), now());
    assert_eq!(out.status, Status::Verified, "{out:?}");
    assert_eq!(
        *mode.lock().unwrap(),
        mav::px4_custom_mode(4, mav::PX4_SUB_AUTO_LOITER)
    );
    // Lifting the pause never resumes the mission.
    let out = e.revert_request(
        "h1",
        "done",
        Some(&revert_req("h1", &["alice", "bob"])),
        &mut state(SafetyState::Idle),
        now(),
    );
    assert_eq!(out.status, Status::Reverted);
    assert_eq!(
        *mode.lock().unwrap(),
        mav::px4_custom_mode(4, mav::PX4_SUB_AUTO_LOITER)
    );
    // request_safe_state with the policy's RTL: applied, not reversible.
    let o = signed(
        "s1",
        ActionId::RequestSafeState,
        Morphology::Aerial,
        Target::None,
        None,
        &["alice", "bob"],
        SafetyState::MovingSlow,
    );
    let out = e.submit(&o, &mut state(SafetyState::MovingSlow), now());
    assert_eq!(out.status, Status::Applied, "{out:?}");
    assert_eq!(
        *mode.lock().unwrap(),
        mav::px4_custom_mode(4, mav::PX4_SUB_AUTO_RTL)
    );
    assert_eq!(e.status("s1").status, Status::Applied);
    // A vehicle that refuses: failed, honestly.
    let (_sim2, addr2, _) = sim_px4(false);
    let mut m2 = motion;
    m2["px4"]["address"] = json!(addr2.to_string());
    let d2 = tmpdir("px4-refuse");
    let mut e2 = engine(&d2, m2, p, now());
    let o = signed(
        "h2",
        ActionId::SafePause,
        Morphology::Aerial,
        Target::None,
        None,
        &["alice", "bob"],
        SafetyState::Idle,
    );
    let out = e2.submit(&o, &mut state(SafetyState::Idle), now());
    assert_eq!(out.status, Status::Failed, "{out:?}");
    assert!(out.error.unwrap().contains("refused"));
}

#[test]
fn gates_of_the_motion_actions() {
    let d = tmpdir("gates");
    let motion = json!({"safe_pause": "nav2", "rollback_config": "rollback",
        "nav2": {"oem_validated": true, "ros2": ros2_peer(9)},
        "rollback": {"oem_validated": true, "program": "/bin/true"}});
    // A drone policy (Hold) with the Nav2 adapter: behaviour unsupported.
    let mut e = engine(
        &d,
        motion.clone(),
        policy(PlatformFamily::Drone, Morphology::Aerial),
        now(),
    );
    let o = signed(
        "g1",
        ActionId::SafePause,
        Morphology::Aerial,
        Target::None,
        None,
        &["a", "b"],
        SafetyState::Idle,
    );
    assert_eq!(
        code(&e.submit(&o, &mut state(SafetyState::Idle), now())),
        codes::BEHAVIOUR_UNSUPPORTED
    );
    // No adapter for request_safe_state.
    let o = signed(
        "g2",
        ActionId::RequestSafeState,
        Morphology::Aerial,
        Target::None,
        None,
        &["a", "b"],
        SafetyState::Idle,
    );
    assert_eq!(
        code(&e.submit(&o, &mut state(SafetyState::Idle), now())),
        codes::NO_ADAPTER
    );
    // No restrict_motion adapter: refused (not advisory) once motion is set.
    let o = signed(
        "g3",
        ActionId::RestrictMotion,
        Morphology::Aerial,
        restrict(0.5),
        Some(10),
        &[],
        SafetyState::Idle,
    );
    assert_eq!(
        code(&e.submit(&o, &mut state(SafetyState::Idle), now())),
        codes::NO_ADAPTER
    );
    // A workspace zone no adapter can enforce: refused, never dropped.
    let zone = Target::Motion(MotionRequest {
        max_linear_speed: Some(0.5),
        workspace_zone: Some("dock".into()),
        ..Default::default()
    });
    let o = signed(
        "g3b",
        ActionId::RestrictMotion,
        Morphology::Aerial,
        zone,
        Some(10),
        &[],
        SafetyState::Idle,
    );
    assert_eq!(
        code(&e.submit(&o, &mut state(SafetyState::Idle), now())),
        codes::INVALID_ORDER
    );
    drop(e);
    // A humanoid never pauses (it would fall).
    let d2 = tmpdir("gates-h");
    let mut e = engine(
        &d2,
        motion.clone(),
        policy(PlatformFamily::Other, Morphology::Humanoid),
        now(),
    );
    let o = signed(
        "g4",
        ActionId::SafePause,
        Morphology::Humanoid,
        Target::None,
        None,
        &["a", "b"],
        SafetyState::Idle,
    );
    assert_eq!(
        code(&e.submit(&o, &mut state(SafetyState::Idle), now())),
        codes::FALL_HAZARD
    );
    drop(e);
    // Rollback: the profile never, the program only idle.
    let d3 = tmpdir("gates-r");
    let mut e = engine(
        &d3,
        motion,
        policy(PlatformFamily::Ugv, Morphology::WheeledMobile),
        now(),
    );
    let rb = |cfg: &str| {
        Target::Motion(MotionRequest {
            config: Some(cfg.into()),
            to_version: Some("1.2.0".into()),
            ..Default::default()
        })
    };
    let o = signed(
        "r1",
        ActionId::RollbackConfig,
        Morphology::WheeledMobile,
        rb("profile"),
        None,
        &["a", "b"],
        SafetyState::Idle,
    );
    assert_eq!(
        code(&e.submit(&o, &mut state(SafetyState::Idle), now())),
        codes::NOT_EXECUTOR_ACTION
    );
    let o = signed(
        "r2",
        ActionId::RollbackConfig,
        Morphology::WheeledMobile,
        rb("program"),
        None,
        &["a", "b"],
        SafetyState::MovingSlow,
    );
    assert_eq!(
        code(&e.submit(&o, &mut state(SafetyState::MovingSlow), now())),
        codes::REQUIRES_IDLE
    );
    let o = signed(
        "r3",
        ActionId::RollbackConfig,
        Morphology::WheeledMobile,
        rb("program"),
        None,
        &["a", "b"],
        SafetyState::Idle,
    );
    let out = e.submit(&o, &mut state(SafetyState::Idle), now());
    assert_eq!(out.status, Status::Applied, "{out:?}");
    // An order whose parameters differ from the signed ones.
    let mut o = signed(
        "r4",
        ActionId::RollbackConfig,
        Morphology::WheeledMobile,
        rb("program"),
        None,
        &["a", "b"],
        SafetyState::Idle,
    );
    o.target = rb("program2");
    assert_eq!(
        code(&e.submit(&o, &mut state(SafetyState::Idle), now())),
        codes::ORDER_MISMATCH
    );
    let _ = soc_key_path();
}

#[test]
fn motion_configuration_is_strict() {
    let d = tmpdir("cfg");
    let peer = json!({"peer_ip": "10.0.0.2", "local_ip": "10.0.0.1"});
    let base = |motion: Value| {
        let mut v: Value =
            serde_json::from_str(&crate::tests::config_json(d.to_str().unwrap())).unwrap();
        v["motion"] = motion;
        crate::ExecutorConfig::parse(&v.to_string()).and_then(crate::ExecutorConfig::validate)
    };
    assert!(base(json!({"safe_pause": "nav2", "nav2": {"ros2": peer}})).is_ok());
    if let Err(e) = base(json!({"restrict_motion": ["unitree_sport", "gateway"],
        "gateway": {"restriction_path": "/r", "status_path": "/s", "verify_timeout_ms": 1000},
        "unitree_sport": {"ros2": {"peer_ip": "10.0.0.2", "local_ip": "10.0.0.1",
                                   "timeout_ms": 1000}}}))
    {
        panic!("{e}");
    }
    for bad in [
        json!({"restrict_motion": ["nav2"], "nav2": {"ros2": peer}}),
        json!({"safe_pause": "gateway"}),
        json!({"safe_pause": "nav2"}),
        json!({"restrict_motion": ["gateway", "gateway"],
               "gateway": {"restriction_path": "/r", "status_path": "/s"}}),
        json!({"restrict_motion": ["gateway", "unitree_sport"],
               "gateway": {"restriction_path": "/r", "status_path": "/s",
                           "verify_timeout_ms": 1000},
               "unitree_sport": {"ros2": {"peer_ip": "10.0.0.2", "local_ip": "10.0.0.1",
                                          "timeout_ms": 1000}}}),
        json!({"nav2": {"ros2": {"peer_ip": "10.0.0.2", "local_ip": "10.0.0.1",
               "peer_participant_prefix": "0102"}}}),
        json!({"gateway": {"restriction_path": "r", "status_path": "/s"}}),
        json!({"nav2": {"ros2": peer, "bogus": 1}}),
        json!({"nav2": {"ros2": {"peer_ip": "224.0.0.1", "local_ip": "10.0.0.1"}}}),
        json!({"nav2": {"ros2": {"peer_ip": "10.0.0.2", "local_ip": "10.0.0.1", "rmw": "connextdds"}}}),
        json!({"ros2_control": {"ros2": peer, "deactivate": []}}),
        json!({"ros2_control": {"ros2": peer, "deactivate": ["a"], "activate": ["a"]}}),
        json!({"px4": {"address": "10.0.0.3:14540", "bind": "0.0.0.0:0", "system_id": 1}}),
        json!({"rollback": {"program": "rollback.sh"}}),
        json!({"rollback_config": "rollback"}),
        json!({"safe_pause_ttl_s": 0}),
        json!({"unitree_sport": {"ros2": peer, "speed_level": 2}}),
        // Over the time budget agentd waits for (MOTION_BUDGET_MS).
        json!({"safe_pause": "nav2", "nav2": {"ros2": {"peer_ip": "10.0.0.2",
               "local_ip": "10.0.0.1", "timeout_ms": 3000}}}),
        json!({"rollback_config": "rollback",
               "rollback": {"program": "/bin/true", "timeout_ms": 2500}}),
    ] {
        assert!(base(bad.clone()).is_err(), "{bad} accepted");
    }
}

#[test]
fn a_motion_target_crosses_the_agentd_protocol_unchanged() {
    let o = signed(
        "rt",
        ActionId::RestrictMotion,
        Morphology::WheeledMobile,
        Target::Motion(MotionRequest {
            max_linear_speed: Some(0.4),
            max_joint_speed: Some(0.9),
            workspace_zone: Some("dock-a".into()),
            ..Default::default()
        }),
        Some(30),
        &[],
        SafetyState::Idle,
    );
    let j = serde_json::to_string(&o).unwrap();
    assert!(j.contains("\"kind\":\"motion\""), "{j}");
    let back: Order = serde_json::from_str(&j).unwrap();
    assert_eq!(back, o);
    // Unknown keys in the motion target are refused like everywhere.
    let bad = j.replace("\"kind\":\"motion\"", "\"kind\":\"motion\",\"speed\":9");
    assert!(serde_json::from_str::<Order>(&bad).is_err());
    // A non-finite parameter is an invalid order.
    let mut nan = o.clone();
    nan.target = Target::Motion(MotionRequest {
        factor: Some(f64::NAN),
        ..Default::default()
    });
    assert!(nan.validate().is_err());
}

// ------------------------------------------- review of the motion branch

/// Motion ports that only record (the engine's gates are under test).
#[derive(Clone, Default)]
struct Rec(Arc<Mutex<Vec<String>>>);

impl crate::motion::MotionPorts for Rec {
    fn apply(
        &mut self,
        _m: &crate::motion::MotionSection,
        s: &crate::motion::MotionSpec,
    ) -> Result<String, String> {
        self.0.lock().unwrap().push(format!("apply {}", s.id));
        Ok("ok".into())
    }
    fn revert(
        &mut self,
        _m: &crate::motion::MotionSection,
        s: &crate::motion::MotionSpec,
    ) -> Result<String, String> {
        self.0.lock().unwrap().push(format!("revert {}", s.id));
        Ok("ok".into())
    }
    fn verify(
        &mut self,
        _m: &crate::motion::MotionSection,
        _s: &crate::motion::MotionSpec,
    ) -> Result<(), String> {
        Ok(())
    }
}

fn r2c_motion(port: u16) -> Value {
    json!({"safe_pause": "ros2_control",
        "ros2_control": {"oem_validated": true, "ros2": ros2_peer(port),
                         "deactivate": ["joint_trajectory_controller"],
                         "activate": ["hold_controller"]}})
}

/// F6: one person spelled in another case, or with an invisible
/// character, is not a second approver; email-like identifiers are names.
#[test]
fn review_f6_approvers_are_compared_normalised() {
    use crate::motion::approvers_ok;
    let r = "analyst@soc";
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let pause = ActionId::SafePause;
    assert!(approvers_ok(pause, r, &s(&["Analyst@soc", "ANALYST@SOC"])).is_err());
    assert!(approvers_ok(pause, r, &s(&["alice@soc", "ALICE@soc"])).is_err());
    assert!(approvers_ok(
        pause,
        r,
        &s(&["analyst@soc\u{200b}", "analyst@soc\u{feff}"])
    )
    .is_err());
    assert!(approvers_ok(pause, r, &s(&["alice\u{200b}", "bob"])).is_err());
    assert!(approvers_ok(pause, r, &s(&["alice", "bob\u{0301}"])).is_err());
    assert!(approvers_ok(pause, "Alice", &s(&["alice", "bob"])).is_err());
    assert!(approvers_ok(pause, r, &s(&["alice.smith+ops@soc.example", "bob_o'neil"])).is_err());
    assert!(approvers_ok(pause, r, &s(&["alice.smith+ops@soc.example", "bob-2@soc"])).is_ok());
    assert!(approvers_ok(pause, r, &s(&["a", "b"])).is_ok());
    // End to end: the pause is refused, nothing applied.
    let d = tmpdir("rv-f6");
    let rec = Rec::default();
    let mut e = engine(
        &d,
        r2c_motion(9),
        policy(PlatformFamily::Arm, Morphology::Arm),
        now(),
    )
    .with_motion_ports(Box::new(rec.clone()));
    let o = signed(
        "p-f6",
        ActionId::SafePause,
        Morphology::Arm,
        Target::None,
        None,
        &["Analyst@soc", "ANALYST@SOC"],
        SafetyState::Idle,
    );
    let out = e.submit(&o, &mut state(SafetyState::Idle), now());
    assert_eq!(code(&out), codes::APPROVAL_MISSING, "{out:?}");
    assert!(rec.0.lock().unwrap().is_empty());
}

/// F7: a safe_pause held across a reboot is not re-applied while the
/// robot moves fast (the adapter's allowed states); it stays held and is
/// re-armed once the state allows it.
#[test]
fn review_f7_rearm_checks_the_allowed_states() {
    let d = tmpdir("rv-f7");
    let p = policy(PlatformFamily::Arm, Morphology::Arm);
    {
        let mut e = Engine::open(
            config(&d, r2c_motion(9)),
            p.clone(),
            Box::new(FakeNft::default()),
            "b1",
            now(),
        )
        .unwrap()
        .with_motion_ports(Box::new(Rec::default()));
        let o = signed(
            "p-f7",
            ActionId::SafePause,
            Morphology::Arm,
            Target::None,
            None,
            &["alice", "bob"],
            SafetyState::Idle,
        );
        let out = e.submit(&o, &mut state(SafetyState::Idle), now());
        assert_eq!(out.status, Status::Verified, "{out:?}");
    }
    let rec = Rec::default();
    let mut e = Engine::open(
        config(&d, r2c_motion(9)),
        p,
        Box::new(FakeNft::default()),
        "b2",
        now(),
    )
    .unwrap()
    .with_motion_ports(Box::new(rec.clone()));
    assert_eq!(e.status("p-f7").status, Status::Held);
    let fast = Current {
        state: SafetyState::MovingFast,
        age_ms: 5,
    };
    e.rearm_held(Ok(fast), now());
    assert!(
        rec.0.lock().unwrap().is_empty(),
        "applied while moving fast"
    );
    assert_eq!(e.status("p-f7").status, Status::Held);
    let idle = Current {
        state: SafetyState::Idle,
        age_ms: 5,
    };
    e.rearm_held(Ok(idle), now());
    assert_eq!(rec.0.lock().unwrap().as_slice(), ["apply p-f7"]);
    assert_eq!(e.status("p-f7").status, Status::Verified);
}

/// F10: service calls carry random correlation ids (not derived from the
/// request or the controllers), and with `peer_participant_prefix` only
/// the peer's own writers can answer.
#[test]
fn review_f10_service_replies_are_hard_to_forge() {
    let headers = Arc::new(Mutex::new(Vec::<(u64, i64)>::new()));
    let h2 = headers.clone();
    let (_sim, port, _, _) = sim_ros2(move |topic, p| {
        if topic != "rq/controller_manager/switch_controllerRequest" {
            return None;
        }
        let mut d = cdr::Dec::open(p).ok()?;
        h2.lock().unwrap().push((d.u64().ok()?, d.i64().ok()?));
        service_reply(p, |e| e.bool(true))
    });
    let pol = policy(PlatformFamily::Arm, Morphology::Arm);
    let pause = |id: &str| {
        signed(
            id,
            ActionId::SafePause,
            Morphology::Arm,
            Target::None,
            None,
            &["alice", "bob"],
            SafetyState::Idle,
        )
    };
    // The sim answers from prefix 09..09.
    let mut m = r2c_motion(port);
    m["ros2_control"]["ros2"]["peer_participant_prefix"] = json!("090909090909090909090909");
    let d = tmpdir("rv-f10a");
    let mut e = engine(&d, m.clone(), pol.clone(), now());
    let out = e.submit(&pause("c1"), &mut state(SafetyState::Idle), now());
    assert_eq!(out.status, Status::Verified, "{out:?}");
    let out = e.revert_request(
        "c1",
        "done",
        Some(&revert_req("c1", &["alice", "bob"])),
        &mut state(SafetyState::Idle),
        now(),
    );
    assert_eq!(out.status, Status::Reverted, "{out:?}");
    drop(e);
    let d = tmpdir("rv-f10b");
    let mut e = engine(&d, m.clone(), pol.clone(), now());
    let out = e.submit(&pause("c1"), &mut state(SafetyState::Idle), now());
    assert_eq!(out.status, Status::Verified, "{out:?}");
    {
        let h = headers.lock().unwrap();
        assert!(h.len() >= 3, "{h:?}");
        let mut distinct: Vec<(u64, i64)> = h.clone();
        distinct.sort_unstable();
        distinct.dedup();
        // Same request, same controllers, same id: still fresh ids.
        assert_eq!(distinct.len(), h.len(), "{h:?}");
        assert!(h.iter().all(|&(_, s)| s > 1), "{h:?}");
    }
    drop(e);
    // A reply from any other participant is not the peer's.
    m["ros2_control"]["ros2"]["peer_participant_prefix"] = json!("080808080808080808080808");
    let d = tmpdir("rv-f10c");
    let mut e = engine(&d, m, pol, now());
    let out = e.submit(&pause("c2"), &mut state(SafetyState::Idle), now());
    assert_eq!(out.status, Status::Failed, "{out:?}");
}

/// F10: a PX4 `COMMAND_ACK` must name our own system / component; the
/// zero targets (not addressed to anyone) are not ours.
#[test]
fn review_f10_px4_ack_must_be_addressed_to_us() {
    let (_sim, addr, _) = sim_px4_with(true, Some((0, 0)));
    let d = tmpdir("rv-px4");
    let motion = json!({"safe_pause": "px4",
        "px4": {"oem_validated": true, "address": addr.to_string(), "bind": "127.0.0.1:0",
                "timeout_ms": 1500}});
    let mut e = engine(
        &d,
        motion,
        policy(PlatformFamily::Drone, Morphology::Aerial),
        now(),
    );
    let o = signed(
        "h1",
        ActionId::SafePause,
        Morphology::Aerial,
        Target::None,
        None,
        &["alice", "bob"],
        SafetyState::Idle,
    );
    let out = e.submit(&o, &mut state(SafetyState::Idle), now());
    assert_eq!(out.status, Status::Failed, "{out:?}");
}

/// Minor: a `to_version` starting with `-` would reach the rollback
/// program as an option; it is refused, and the version is passed as
/// `--to-version=<v>`.
#[test]
fn review_rollback_version_is_never_an_option() {
    use std::os::unix::fs::PermissionsExt;
    let d = tmpdir("rv-rb");
    let log = d.join("argv.log");
    let prog = d.join("rollback.sh");
    std::fs::write(
        &prog,
        format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n", log.display()),
    )
    .unwrap();
    std::fs::set_permissions(&prog, std::fs::Permissions::from_mode(0o755)).unwrap();
    let motion = json!({"rollback_config": "rollback",
        "rollback": {"oem_validated": true, "program": prog}});
    let mut e = engine(
        &d,
        motion,
        policy(PlatformFamily::Ugv, Morphology::WheeledMobile),
        now(),
    );
    let rb = |v: &str| {
        Target::Motion(MotionRequest {
            config: Some("program".into()),
            to_version: Some(v.into()),
            ..Default::default()
        })
    };
    for (id, v) in [
        ("rb1", "-rf"),
        ("rb2", "--help"),
        ("rb3", "1.2 3"),
        ("rb4", "a/b"),
    ] {
        let o = signed(
            id,
            ActionId::RollbackConfig,
            Morphology::WheeledMobile,
            rb(v),
            None,
            &["a", "b"],
            SafetyState::Idle,
        );
        let out = e.submit(&o, &mut state(SafetyState::Idle), now());
        assert_eq!(code(&out), codes::INVALID_ORDER, "{v}: {out:?}");
    }
    assert!(!log.exists());
    if robodr_blackbox::keys::effective_uid() != 0 {
        // Review finding 8: only a root-owned program runs.
        return;
    }
    let o = signed(
        "rb5",
        ActionId::RollbackConfig,
        Morphology::WheeledMobile,
        rb("1.2.0"),
        None,
        &["a", "b"],
        SafetyState::Idle,
    );
    let out = e.submit(&o, &mut state(SafetyState::Idle), now());
    assert_eq!(out.status, Status::Applied, "{out:?}");
    let argv = std::fs::read_to_string(&log).unwrap();
    assert_eq!(
        argv,
        "--config program --to-version=1.2.0 --request-id rb5\n\
         --verify --config program --to-version=1.2.0\n"
    );
}

// ------------------------------------------------ review of 2026-10-30

fn engine_cfg(
    dir: &std::path::Path,
    motion: Value,
    p: ResponsePolicy,
    t: Now,
    edit: impl FnOnce(&mut Value),
) -> Engine {
    let mut v: Value =
        serde_json::from_str(&crate::tests::config_json(dir.to_str().unwrap())).unwrap();
    v["motion"] = motion;
    edit(&mut v);
    let c = crate::ExecutorConfig::parse(&v.to_string())
        .unwrap()
        .validate()
        .unwrap();
    Engine::open(c, p, Box::new(FakeNft::default()), "b1", t).unwrap()
}

fn planner(mut o: Order) -> Order {
    o.origin = Origin::Planner {
        rule: "r".into(),
        finding_id: None,
    };
    o.soc = None;
    o.human_approved = false;
    o
}

fn reverts(rec: &Rec) -> usize {
    rec.0
        .lock()
        .unwrap()
        .iter()
        .filter(|x| x.starts_with("revert"))
        .count()
}

fn pause_order(id: &str) -> Order {
    signed(
        id,
        ActionId::SafePause,
        Morphology::Arm,
        Target::None,
        None,
        &["alice", "bob"],
        SafetyState::Idle,
    )
}

/// Review finding 1: a safe_pause that reached `safe_pause_ttl_s` was
/// undone by the TTL housekeeping (re-activating the motion controllers
/// with no human and no safety check, even in e_stop_active). Now its TTL
/// is reported and the pause stays in force.
#[test]
fn review_finding_1_pause_ttl_is_reported_never_lifted() {
    let d = tmpdir("rv1-ttl");
    let rec = Rec::default();
    let t0 = now();
    let mut e = engine(
        &d,
        r2c_motion(9),
        policy(PlatformFamily::Arm, Morphology::Arm),
        t0,
    )
    .with_motion_ports(Box::new(rec.clone()));
    let out = e.submit(&pause_order("p-ttl"), &mut state(SafetyState::Idle), t0);
    assert_eq!(out.status, Status::Verified, "{out:?}");
    let late = |s: u64| Now {
        wall_ms: t0.wall_ms + s * 1000,
        boot_ms: t0.boot_ms.map(|b| b + s * 1000),
    };
    e.tick(late(3601));
    e.tick(late(3700));
    assert_eq!(reverts(&rec), 0, "the TTL lifted the pause");
    assert_eq!(e.status("p-ttl").status, Status::Verified);
    let expired: Vec<_> = e
        .state()
        .events
        .iter()
        .filter(|ev| ev.kind == crate::journal::EventKind::Expired)
        .collect();
    assert_eq!(expired.len(), 1, "{expired:?}");
    assert!(expired[0].detail.starts_with("HIGH:"), "{expired:?}");
    // A plain (unsigned, internal) revert does not lift it either.
    e.revert("p-ttl", "test", late(3800));
    assert_eq!(reverts(&rec), 0);
    assert_eq!(e.status("p-ttl").status, Status::Verified);
    // A restart after the TTL: not undone at reconciliation (SystemPorts
    // would be called there), back to active at the next tick.
    drop(e);
    let rec2 = Rec::default();
    let mut e = engine(
        &d,
        r2c_motion(9),
        policy(PlatformFamily::Arm, Morphology::Arm),
        late(3900),
    )
    .with_motion_ports(Box::new(rec2.clone()));
    e.tick(late(3901));
    assert_eq!(reverts(&rec2), 0);
    assert_eq!(e.status("p-ttl").status, Status::Verified);
}

/// Review finding 1: lifting a pause needs the two-person signed revert
/// **and** a safety state now that is known, fresh, not engaged and
/// allowed by the pause's adapters.
#[test]
fn review_finding_1_pause_lift_rechecks_the_safety_state() {
    let d = tmpdir("rv1-lift");
    let rec = Rec::default();
    let mut e = engine(
        &d,
        r2c_motion(9),
        policy(PlatformFamily::Arm, Morphology::Arm),
        now(),
    )
    .with_motion_ports(Box::new(rec.clone()));
    let out = e.submit(&pause_order("p-lift"), &mut state(SafetyState::Idle), now());
    assert_eq!(out.status, Status::Verified, "{out:?}");
    for (s, want) in [
        (SafetyState::EStopActive, codes::SAFETY_SYSTEM_ENGAGED),
        (SafetyState::Unknown, codes::SAFETY_STATE_UNAVAILABLE),
        (SafetyState::MovingFast, codes::SAFETY_STATE_NOT_ALLOWED),
    ] {
        let out = e.revert_request(
            "p-lift",
            "done",
            Some(&revert_req("p-lift", &["alice", "bob"])),
            &mut state(s),
            now(),
        );
        assert_eq!(code(&out), want, "{s:?}: {out:?}");
        assert_eq!(out.status, Status::Verified, "{s:?}");
    }
    let mut stale = FixedSafety(Current {
        state: SafetyState::Idle,
        age_ms: 60_000,
    });
    let out = e.revert_request(
        "p-lift",
        "done",
        Some(&revert_req("p-lift", &["alice", "bob"])),
        &mut stale,
        now(),
    );
    assert_eq!(code(&out), codes::SAFETY_STATE_STALE, "{out:?}");
    // Unsigned: refused before anything else.
    let out = e.revert_request("p-lift", "x", None, &mut state(SafetyState::Idle), now());
    assert_eq!(code(&out), codes::SOC_SIGNATURE_INVALID, "{out:?}");
    assert_eq!(reverts(&rec), 0);
    let out = e.revert_request(
        "p-lift",
        "done",
        Some(&revert_req("p-lift", &["alice", "bob"])),
        &mut state(SafetyState::Idle),
        now(),
    );
    assert_eq!(out.status, Status::Reverted, "{out:?}");
    assert_eq!(reverts(&rec), 1);
}

/// Review finding 1: an operator's emergency disable dropped every action
/// and undid the pause with it. The pause is now left in force.
#[test]
fn review_finding_1_operator_disable_leaves_the_pause() {
    let d = tmpdir("rv1-op");
    let rec = Rec::default();
    let nft = FakeNft::default();
    let mut e = Engine::open(
        config(&d, r2c_motion(9)),
        policy(PlatformFamily::Arm, Morphology::Arm),
        Box::new(nft.clone()),
        "b1",
        now(),
    )
    .unwrap()
    .with_motion_ports(Box::new(rec.clone()));
    let i = signed(
        "i-op",
        ActionId::IsolateNetwork,
        Morphology::Arm,
        Target::None,
        Some(60),
        &[],
        SafetyState::Idle,
    );
    let out = e.submit(&i, &mut state(SafetyState::Idle), now());
    assert_eq!(out.status, Status::Verified, "{out:?}");
    let out = e.submit(&pause_order("p-op"), &mut state(SafetyState::Idle), now());
    assert_eq!(out.status, Status::Verified, "{out:?}");
    nft.0.lock().unwrap().table = None;
    e.periodic_verify(wall_ms());
    assert!(e.state().operator_disabled);
    assert_eq!(reverts(&rec), 0, "the operator disable lifted the pause");
}

/// Review finding 3: an absolute cap was checked for finiteness only, so
/// `max_joint_speed: 0.0001` (or a planner's absolute cap) could near-stop
/// a balancing robot. On a robot that balances, an absolute cap must be
/// at least `min_motion_factor` of the configured envelope; a planner
/// order carries a factor only.
#[test]
fn review_finding_3_absolute_caps_have_a_floor() {
    let unitree = |env: Option<Value>| {
        let mut m = json!({"restrict_motion": ["unitree_sport"],
            "unitree_sport": {"oem_validated": true, "ros2": ros2_peer(9)}});
        if let Some(e) = env {
            m["envelope"] = e;
        }
        m
    };
    let caps = |lin: Option<f64>, joint: Option<f64>| {
        Target::Motion(MotionRequest {
            max_linear_speed: lin,
            max_joint_speed: joint,
            ..Default::default()
        })
    };
    let quad = policy(PlatformFamily::Other, Morphology::Quadruped);
    let q = |id: &str, t: Target| {
        signed(
            id,
            ActionId::RestrictMotion,
            Morphology::Quadruped,
            t,
            Some(30),
            &[],
            SafetyState::Idle,
        )
    };
    // No envelope: an absolute cap cannot be judged.
    let rec = Rec::default();
    let mut e = engine(&tmpdir("rv3-a"), unitree(None), quad.clone(), now())
        .with_motion_ports(Box::new(rec.clone()));
    let out = e.submit(
        &q("c1", caps(None, Some(0.0001))),
        &mut state(SafetyState::Idle),
        now(),
    );
    assert_eq!(code(&out), codes::FALL_HAZARD, "{out:?}");
    drop(e);
    // With one: below the floor refused, above it applied.
    let env = json!({"max_linear_speed": 1.0, "max_joint_speed": 2.0});
    let mut e = engine(&tmpdir("rv3-b"), unitree(Some(env)), quad.clone(), now())
        .with_motion_ports(Box::new(rec.clone()));
    for (id, t) in [
        ("c2", caps(None, Some(0.0001))),
        ("c3", caps(Some(0.01), None)),
        ("c4", caps(Some(0.9), Some(0.1))),
    ] {
        let out = e.submit(&q(id, t), &mut state(SafetyState::Idle), now());
        assert_eq!(code(&out), codes::FALL_HAZARD, "{id}: {out:?}");
    }
    assert!(rec.0.lock().unwrap().is_empty());
    let out = e.submit(
        &q("c5", caps(Some(0.5), Some(1.0))),
        &mut state(SafetyState::Idle),
        now(),
    );
    assert_eq!(out.status, Status::Verified, "{out:?}");
    drop(e);
    // The planner: a factor only, on any robot.
    let wheeled = policy(PlatformFamily::Ugv, Morphology::WheeledMobile);
    let mut e = engine(&tmpdir("rv3-c"), unitree(None), wheeled, now())
        .with_motion_ports(Box::new(Rec::default()));
    let p = planner(signed(
        "plan:c6",
        ActionId::RestrictMotion,
        Morphology::WheeledMobile,
        caps(Some(0.0001), None),
        Some(30),
        &[],
        SafetyState::Idle,
    ));
    let out = e.submit(&p, &mut state(SafetyState::Idle), now());
    assert_eq!(code(&out), codes::INVALID_ORDER, "{out:?}");
}

/// Review finding 4: restrict_motion went to the motion planner before
/// the approval rules, so a planner order on a humanoid (ADR-0012 rule 3)
/// or on a site with `require_approval_for_all_containment` was executed
/// without a human.
#[test]
fn review_finding_4_restrict_motion_needs_a_human_where_containment_does() {
    let m = json!({"restrict_motion": ["unitree_sport"],
        "unitree_sport": {"oem_validated": true, "ros2": ros2_peer(9)}});
    let factor = || {
        Target::Motion(MotionRequest {
            factor: Some(0.5),
            ..Default::default()
        })
    };
    let rec = Rec::default();
    let mut e = engine(
        &tmpdir("rv4-a"),
        m.clone(),
        policy(PlatformFamily::Other, Morphology::Humanoid),
        now(),
    )
    .with_motion_ports(Box::new(rec.clone()));
    let p = planner(signed(
        "plan:h1",
        ActionId::RestrictMotion,
        Morphology::Humanoid,
        factor(),
        Some(30),
        &[],
        SafetyState::Idle,
    ));
    let out = e.submit(&p, &mut state(SafetyState::Idle), now());
    assert_eq!(code(&out), codes::NEEDS_APPROVAL, "{out:?}");
    drop(e);
    let mut e = engine_cfg(
        &tmpdir("rv4-b"),
        m,
        policy(PlatformFamily::Ugv, Morphology::WheeledMobile),
        now(),
        |v| v["require_approval_for_all_containment"] = json!(true),
    )
    .with_motion_ports(Box::new(rec.clone()));
    let p = planner(signed(
        "plan:w1",
        ActionId::RestrictMotion,
        Morphology::WheeledMobile,
        factor(),
        Some(30),
        &[],
        SafetyState::Idle,
    ));
    let out = e.submit(&p, &mut state(SafetyState::Idle), now());
    assert_eq!(code(&out), codes::NEEDS_APPROVAL, "{out:?}");
    assert!(rec.0.lock().unwrap().is_empty());
}

/// Review finding 7: the requester was not held to the approver grammar,
/// so "alice" plus an invisible character (or a Cyrillic "а") passed as a
/// requester different from the approvers alice and bob.
#[test]
fn review_finding_7_requester_is_a_name_too() {
    use crate::motion::approvers_ok;
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let ab = s(&["alice", "bob"]);
    for rb in ["alice\u{200b}", "\u{430}lice", " alice", "alice bob", ""] {
        let r = approvers_ok(ActionId::SafePause, rb, &ab);
        assert_eq!(
            r.map_err(|r| r.code).unwrap_err(),
            codes::APPROVAL_MISSING,
            "{rb:?}"
        );
    }
    assert!(approvers_ok(ActionId::SafePause, "carol", &ab).is_ok());
}

/// Review finding 8: the site rollback program ran with the executor's
/// ambient CAP_NET_ADMIN, whoever could write it. A program that is not
/// root-owned and protected (file and directory) is refused and never
/// run; the child is started with its ambient capabilities cleared.
#[test]
fn review_finding_8_rollback_program_must_be_protected() {
    use std::os::unix::fs::PermissionsExt;
    let d = tmpdir("rv8");
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
    let log = d.join("ran.log");
    let prog = d.join("rollback.sh");
    std::fs::write(
        &prog,
        format!(
            "#!/bin/sh\ngrep CapAmb /proc/self/status >> '{}'\n",
            log.display()
        ),
    )
    .unwrap();
    let motion = json!({"rollback_config": "rollback",
        "rollback": {"oem_validated": true, "program": prog}});
    let mut e = engine(
        &d,
        motion,
        policy(PlatformFamily::Ugv, Morphology::WheeledMobile),
        now(),
    );
    let rb = |id: &str| {
        signed(
            id,
            ActionId::RollbackConfig,
            Morphology::WheeledMobile,
            Target::Motion(MotionRequest {
                config: Some("program".into()),
                to_version: Some("1.2.0".into()),
                ..Default::default()
            }),
            None,
            &["a", "b"],
            SafetyState::Idle,
        )
    };
    // Group-writable: refused, not run.
    std::fs::set_permissions(&prog, std::fs::Permissions::from_mode(0o775)).unwrap();
    let out = e.submit(&rb("rb8a"), &mut state(SafetyState::Idle), now());
    assert_eq!(out.status, Status::Failed, "{out:?}");
    // Not root (a CI runner): the file is the test user's, so the ownership
    // check refuses it before the mode check is reached.
    let why = if robodr_blackbox::keys::effective_uid() == 0 {
        "writable"
    } else {
        "not root"
    };
    assert!(out.error.as_deref().unwrap_or("").contains(why), "{out:?}");
    assert!(!log.exists(), "a writable program was run");
    // In a directory others can write: refused too.
    std::fs::set_permissions(&prog, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(crate::motion::adapters::program_ok(&prog).is_err());
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
    // A symlink to it: refused.
    let link = d.join("link.sh");
    std::os::unix::fs::symlink(&prog, &link).unwrap();
    assert!(crate::motion::adapters::program_ok(&link).is_err());
    if robodr_blackbox::keys::effective_uid() != 0 {
        // The positive case needs a root-owned file.
        return;
    }
    let out = e.submit(&rb("rb8b"), &mut state(SafetyState::Idle), now());
    assert_eq!(out.status, Status::Applied, "{out:?}");
    let ran = std::fs::read_to_string(&log).unwrap();
    assert!(
        ran.lines()
            .all(|l| l.trim_end().ends_with("0000000000000000")),
        "{ran}"
    );
}

// ------------------------------------- review of the sealed journal (11)

/// Motion ports whose undo fails.
#[derive(Clone, Default)]
struct FailUndo(Arc<Mutex<Vec<String>>>);

impl crate::motion::MotionPorts for FailUndo {
    fn apply(
        &mut self,
        _m: &crate::motion::MotionSection,
        s: &crate::motion::MotionSpec,
    ) -> Result<String, String> {
        self.0.lock().unwrap().push(format!("apply {}", s.id));
        Ok("ok".into())
    }
    fn revert(
        &mut self,
        _m: &crate::motion::MotionSection,
        s: &crate::motion::MotionSpec,
    ) -> Result<String, String> {
        self.0.lock().unwrap().push(format!("revert {}", s.id));
        Err("controller manager unreachable".into())
    }
    fn verify(
        &mut self,
        _m: &crate::motion::MotionSection,
        _s: &crate::motion::MotionSpec,
    ) -> Result<(), String> {
        Ok(())
    }
}

fn gw_motion(d: &std::path::Path) -> Value {
    json!({"restrict_motion": ["gateway"],
        "gateway": {"oem_validated": true, "restriction_path": d.join("restriction.json"),
                    "status_path": d.join("status.json"), "verify_timeout_ms": 2000}})
}

/// An engine with a gateway restriction (or, `pause`, a safe_pause) in
/// force, on the given motion ports.
fn motion_in_force(
    d: &std::path::Path,
    id: &str,
    pause: bool,
    ports: Box<dyn crate::motion::MotionPorts + Send>,
) -> Engine {
    let (motion, p, o) = if pause {
        (
            r2c_motion(9),
            policy(PlatformFamily::Arm, Morphology::Arm),
            signed(
                id,
                ActionId::SafePause,
                Morphology::Arm,
                Target::None,
                None,
                &["alice", "bob"],
                SafetyState::Idle,
            ),
        )
    } else {
        (
            gw_motion(d),
            policy(PlatformFamily::Ugv, Morphology::WheeledMobile),
            signed(
                id,
                ActionId::RestrictMotion,
                Morphology::WheeledMobile,
                restrict(0.3),
                Some(600),
                &[],
                SafetyState::Idle,
            ),
        )
    };
    let mut e = engine(d, motion, p, now()).with_motion_ports(ports);
    let out = e.submit(&o, &mut state(SafetyState::Idle), now());
    assert_eq!(out.status, Status::Verified, "{out:?}");
    e
}

fn journal_of(d: &std::path::Path) -> crate::journal::State {
    match crate::journal::Journal::new(d).load() {
        crate::journal::Loaded::State(s) => s,
        other => panic!("{other:?}"),
    }
}

/// Review finding 11: `revert-all` and `stop-cleanup` undo motion actions
/// through their adapters (a gateway restriction is not lifted by deleting
/// the nft table); an undo that fails leaves the action `reverting`, never
/// reported reverted. A safe_pause is never lifted by either (ADR-0006).
#[test]
fn review_11_revert_all_and_abandon_undo_motion_actions() {
    // revert-all, undo succeeds.
    let d = tmpdir("rv11-ra");
    let rec = Rec::default();
    let mut e = motion_in_force(&d, "rm-ra", false, Box::new(rec.clone()));
    assert_eq!(e.revert_all("operator", now()).unwrap(), 1);
    assert!(rec.0.lock().unwrap().contains(&"revert rm-ra".to_string()));
    assert_eq!(e.status("rm-ra").status, Status::Reverted);
    // revert-all, undo fails: still reverting.
    let d = tmpdir("rv11-ra-fail");
    let fail = FailUndo::default();
    let mut e = motion_in_force(&d, "rm-raf", false, Box::new(fail.clone()));
    assert!(e.revert_all("operator", now()).is_err());
    assert!(fail
        .0
        .lock()
        .unwrap()
        .contains(&"revert rm-raf".to_string()));
    assert_eq!(e.status("rm-raf").status, Status::Reverting);
    // revert-all leaves a pause in force.
    let d = tmpdir("rv11-ra-pause");
    let rec = Rec::default();
    let mut e = motion_in_force(&d, "p-ra", true, Box::new(rec.clone()));
    assert!(e.revert_all("operator", now()).is_err());
    assert!(!rec
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|x| x.starts_with("revert")));
    assert_eq!(e.status("p-ra").status, Status::Verified);
    // stop-cleanup (abandon), undo succeeds.
    let d = tmpdir("rv11-ab");
    drop(motion_in_force(
        &d,
        "rm-ab",
        false,
        Box::new(Rec::default()),
    ));
    let c = config(&d, gw_motion(&d));
    let mut nft = FakeNft::default();
    let mut rec = Rec::default();
    let n =
        crate::engine::abandon(Some(&c), &mut nft, "stopped", wall_ms(), None, &mut rec).unwrap();
    assert_eq!(n, 1);
    assert!(rec.0.lock().unwrap().contains(&"revert rm-ab".to_string()));
    let s = journal_of(&d);
    assert!(s.entries.is_empty());
    assert_eq!(
        s.finished("rm-ab").map(|f| f.result),
        Some(crate::journal::Final::Reverted)
    );
    // stop-cleanup, undo fails: kept `reverting` for the next start.
    let d = tmpdir("rv11-ab-fail");
    drop(motion_in_force(
        &d,
        "rm-abf",
        false,
        Box::new(Rec::default()),
    ));
    let c = config(&d, gw_motion(&d));
    let mut fail = FailUndo::default();
    let n =
        crate::engine::abandon(Some(&c), &mut nft, "stopped", wall_ms(), None, &mut fail).unwrap();
    assert_eq!(n, 0);
    let s = journal_of(&d);
    assert_eq!(s.entries.len(), 1);
    assert_eq!(s.entries[0].phase, crate::journal::Phase::Reverting);
    // stop-cleanup leaves a pause in force (and journalled).
    let d = tmpdir("rv11-ab-pause");
    drop(motion_in_force(&d, "p-ab", true, Box::new(Rec::default())));
    let c = config(&d, r2c_motion(9));
    let mut rec = Rec::default();
    let n =
        crate::engine::abandon(Some(&c), &mut nft, "stopped", wall_ms(), None, &mut rec).unwrap();
    assert_eq!(n, 0);
    assert!(rec.0.lock().unwrap().is_empty());
    let s = journal_of(&d);
    assert_eq!(s.entries.len(), 1);
    assert_eq!(s.entries[0].phase, crate::journal::Phase::Active);
}

// ------------------------------------- sales-readiness T42: the pause latch

fn overridden(e: &Engine) -> Vec<String> {
    e.state()
        .events
        .iter()
        .filter(|ev| ev.kind == crate::journal::EventKind::Overridden)
        .map(|ev| ev.detail.clone())
        .collect()
}

/// T42: a Nav2 pause was not a latch: a goal sent after the cancel set the
/// robot moving again unnoticed. Now every `safe_pause_latch_s` every goal
/// is cancelled again; a goal found is reported `overridden` (HIGH) and
/// zero twists follow. A peer that stops answering is one `drift` event,
/// not one per run.
#[test]
fn t42_nav2_pause_is_latched_and_an_override_is_reported() {
    // Goals the simulated Nav2 holds; a cancel cancels them all.
    let goals = Arc::new(Mutex::new(1u32));
    let answering = Arc::new(AtomicBool::new(true));
    let (g2, a2) = (goals.clone(), answering.clone());
    let (_sim, port, seen, _) = sim_ros2(move |topic, p| {
        if !a2.load(Ordering::SeqCst) {
            return None;
        }
        if topic.starts_with("rq/") && topic.ends_with("/_action/cancel_goalRequest") {
            let n = std::mem::take(&mut *g2.lock().unwrap());
            return service_reply(p, |e| {
                e.u8(0); // ERROR_NONE
                e.u32(n);
                for i in 0..n {
                    for b in 0..16u8 {
                        e.u8(b ^ i as u8);
                    }
                    e.i32(1);
                    e.u32(0);
                }
            });
        }
        None
    });
    let twists = |seen: &Seen| {
        seen.lock()
            .unwrap()
            .iter()
            .filter(|(t, _)| t == "rt/cmd_vel")
            .count()
    };
    let d = tmpdir("t42-nav2");
    let motion = json!({"safe_pause": "nav2", "safe_pause_latch_s": 2,
        "nav2": {"oem_validated": true, "ros2": ros2_peer(port),
                 "actions": ["/navigate_to_pose"], "zero_twists": 3,
                 "zero_twist_interval_ms": 10}});
    let t0 = now();
    let late = |ms: u64| Now {
        wall_ms: t0.wall_ms + ms,
        boot_ms: t0.boot_ms.map(|b| b + ms),
    };
    let mut e = engine(
        &d,
        motion,
        policy(PlatformFamily::Ugv, Morphology::WheeledMobile),
        t0,
    );
    let o = signed(
        "lp1",
        ActionId::SafePause,
        Morphology::WheeledMobile,
        Target::None,
        None,
        &["alice", "bob"],
        SafetyState::Idle,
    );
    let out = e.submit(&o, &mut state(SafetyState::Idle), t0);
    assert_eq!(out.status, Status::Verified, "{out:?}");
    assert_eq!(twists(&seen), 3);
    // Before the interval: nothing is sent.
    e.tick(late(1_000));
    assert_eq!(twists(&seen), 3);
    // Nobody moved it: re-cancelled, nothing found, no event.
    e.tick(late(2_100));
    assert!(overridden(&e).is_empty());
    assert_eq!(twists(&seen), 3);
    // Someone sends a navigation goal while paused.
    *goals.lock().unwrap() = 2;
    e.tick(late(10_000));
    let ov = overridden(&e);
    assert_eq!(ov.len(), 1, "{ov:?}");
    assert!(ov[0].starts_with("HIGH:"), "{ov:?}");
    assert!(ov[0].contains("2 navigation goal(s)"), "{ov:?}");
    assert_eq!(
        *goals.lock().unwrap(),
        0,
        "the new goals were not cancelled"
    );
    assert_eq!(twists(&seen), 6, "no zero twists after the override");
    assert_eq!(e.status("lp1").status, Status::Verified);
    // The peer stops answering: one drift event per change, not per run.
    answering.store(false, Ordering::SeqCst);
    let drifts = |e: &Engine| {
        e.state()
            .events
            .iter()
            .filter(|ev| ev.kind == crate::journal::EventKind::Drift)
            .count()
    };
    e.tick(late(20_000));
    e.tick(late(30_000));
    assert_eq!(drifts(&e), 1);
    answering.store(true, Ordering::SeqCst);
    e.tick(late(40_000));
    assert_eq!(overridden(&e).len(), 1);
    assert_eq!(e.status("lp1").status, Status::Verified);
}

/// T42: a PX4 hold was not a latch: a mode change (a mission resumed,
/// offboard) moved the vehicle again unnoticed. Now its mode is read back
/// every `safe_pause_latch_s`; another mode is reported `overridden`
/// (HIGH) and hold is set again, but a pilot's manual mode is reported and
/// left to the pilot.
#[test]
fn t42_px4_hold_is_latched_but_a_pilot_keeps_manual_control() {
    let (_sim, addr, mode) = sim_px4(true);
    let d = tmpdir("t42-px4");
    let motion = json!({"safe_pause": "px4",
        "px4": {"oem_validated": true, "address": addr.to_string(), "bind": "127.0.0.1:0",
                "timeout_ms": 3000}});
    let t0 = now();
    let late = |ms: u64| Now {
        wall_ms: t0.wall_ms + ms,
        boot_ms: t0.boot_ms.map(|b| b + ms),
    };
    let mut e = engine(
        &d,
        motion,
        policy(PlatformFamily::Drone, Morphology::Aerial),
        t0,
    );
    let o = signed(
        "lh1",
        ActionId::SafePause,
        Morphology::Aerial,
        Target::None,
        None,
        &["alice", "bob"],
        SafetyState::MovingSlow,
    );
    let out = e.submit(&o, &mut state(SafetyState::MovingSlow), t0);
    assert_eq!(out.status, Status::Verified, "{out:?}");
    let hold = mav::px4_custom_mode(mav::PX4_MAIN_AUTO, mav::PX4_SUB_AUTO_LOITER);
    assert_eq!(*mode.lock().unwrap(), hold);
    e.tick(late(2_100));
    assert!(overridden(&e).is_empty());
    // A ground station resumes the mission while paused.
    *mode.lock().unwrap() = mav::px4_custom_mode(mav::PX4_MAIN_AUTO, 4);
    e.tick(late(5_000));
    let ov = overridden(&e);
    assert_eq!(ov.len(), 1, "{ov:?}");
    assert!(
        ov[0].starts_with("HIGH:") && ov[0].contains("AUTO.MISSION"),
        "{ov:?}"
    );
    assert_eq!(*mode.lock().unwrap(), hold, "hold was not set again");
    // Offboard (a companion computer steering it): set back to hold too.
    *mode.lock().unwrap() = mav::px4_custom_mode(6, 0);
    e.tick(late(8_000));
    assert_eq!(overridden(&e).len(), 2);
    assert_eq!(*mode.lock().unwrap(), hold);
    // A pilot takes manual control (POSCTL): reported, never taken away.
    let posctl = mav::px4_custom_mode(3, 0);
    *mode.lock().unwrap() = posctl;
    e.tick(late(11_000));
    let ov = overridden(&e);
    assert_eq!(ov.len(), 3, "{ov:?}");
    assert!(
        ov[2].contains("POSCTL") && ov[2].contains("left to the pilot"),
        "{ov:?}"
    );
    assert_eq!(
        *mode.lock().unwrap(),
        posctl,
        "the latch took control from the pilot"
    );
    assert_eq!(e.status("lh1").status, Status::Verified);
}

#[test]
fn t42_latch_interval_is_validated() {
    let d = tmpdir("t42-cfg");
    for bad in [0, 61] {
        let mut v: Value =
            serde_json::from_str(&crate::tests::config_json(d.to_str().unwrap())).unwrap();
        v["motion"] = json!({"safe_pause_latch_s": bad});
        let r = crate::ExecutorConfig::parse(&v.to_string()).and_then(|c| c.validate());
        assert!(r.is_err(), "safe_pause_latch_s {bad} accepted");
    }
    assert!(mav::px4_is_manual(mav::px4_custom_mode(1, 0)));
    assert!(mav::px4_is_manual(mav::px4_custom_mode(3, 2)));
    assert!(
        !mav::px4_is_manual(mav::px4_custom_mode(3, 1)),
        "ORBIT is commanded"
    );
    assert!(!mav::px4_is_manual(mav::px4_custom_mode(6, 0)));
    assert!(!mav::px4_is_manual(mav::px4_custom_mode(4, 4)));
}

// ------------------------------ sales-readiness T18: rmw_fastrtps services

/// T18: the ROS 2 adapters only spoke `rmw_cyclonedds` (`rmw: fastrtps`
/// was refused), so a robot on the ROS 2 default RMW could not be paused.
/// Now `rmw: fastrtps` sends the bare request with our reply reader as its
/// related sample identity and takes the reply that names it and the
/// request's sequence number; a reply that names another sequence number,
/// or none, is not an answer.
#[test]
fn t18_fastrtps_service_calls_pause_and_lift_and_forged_replies_fail() {
    let pol = policy(PlatformFamily::Arm, Morphology::Arm);
    let pause = |id: &str| {
        signed(
            id,
            ActionId::SafePause,
            Morphology::Arm,
            Target::None,
            None,
            &["alice", "bob"],
            SafetyState::Idle,
        )
    };
    let requests = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let sim = |fast: FastReply, reqs: Arc<Mutex<Vec<Vec<u8>>>>| {
        sim_ros2_rmw(fast, move |topic, p| {
            if topic != "rq/controller_manager/switch_controllerRequest" {
                return None;
            }
            reqs.lock().unwrap().push(p.to_vec());
            let mut e = cdr::Enc::default();
            e.bool(true);
            Some(e.payload())
        })
    };
    let (_s, port, _, ann) = sim(FastReply::Yes, requests.clone());
    let mut m = r2c_motion(port);
    m["ros2_control"]["ros2"]["rmw"] = json!("fastrtps");
    let d = tmpdir("t18-fast");
    let mut e = engine(&d, m.clone(), pol.clone(), now());
    let out = e.submit(&pause("f1"), &mut state(SafetyState::Idle), now());
    assert_eq!(out.status, Status::Verified, "{out:?}");
    let out = e.revert_request(
        "f1",
        "done",
        Some(&revert_req("f1", &["alice", "bob"])),
        &mut state(SafetyState::Idle),
        now(),
    );
    assert_eq!(out.status, Status::Reverted, "{out:?}");
    {
        // The request is the bare SwitchController request (no
        // rmw_cyclonedds header): the activate list comes first.
        let r = requests.lock().unwrap();
        assert!(r.len() >= 2, "{}", r.len());
        let mut dec = cdr::Dec::open(&r[0]).unwrap();
        assert_eq!(
            dec.strings(16).unwrap(),
            vec!["hold_controller".to_string()]
        );
        // Same topic and type names as rmw_cyclonedds.
        let a = ann.lock().unwrap();
        assert!(a.iter().any(
            |(t, ty)| t == "rq/controller_manager/switch_controllerRequest"
                && ty == "controller_manager_msgs::srv::dds_::SwitchController_Request_"
        ));
        assert!(a.iter().any(
            |(t, ty)| t == "rr/controller_manager/switch_controllerReply"
                && ty == "controller_manager_msgs::srv::dds_::SwitchController_Response_"
        ));
    }
    drop(e);
    // A reply naming another sequence number, or no request at all, is
    // not an answer: the call fails (nothing is believed applied).
    for (tag, fast) in [("sn", FastReply::WrongSn), ("none", FastReply::NoIdentity)] {
        let (_s, port, _, _) = sim(fast, Arc::default());
        let mut m = r2c_motion(port);
        m["ros2_control"]["ros2"]["rmw"] = json!("fastrtps");
        m["ros2_control"]["ros2"]["timeout_ms"] = json!(400);
        let d = tmpdir(&format!("t18-forged-{tag}"));
        let mut e = engine(&d, m, pol.clone(), now());
        let out = e.submit(&pause("f2"), &mut state(SafetyState::Idle), now());
        assert_eq!(out.status, Status::Failed, "{tag}: {out:?}");
    }
    // A cyclonedds peer is not answered by a fastrtps client, nor the
    // reverse: the RMW must match the robot's.
    let (_s, port, _, _) = sim(FastReply::No, Arc::default());
    let mut m = r2c_motion(port);
    m["ros2_control"]["ros2"]["rmw"] = json!("fastrtps");
    m["ros2_control"]["ros2"]["timeout_ms"] = json!(400);
    let d = tmpdir("t18-mismatch");
    let mut e = engine(&d, m, pol, now());
    let out = e.submit(&pause("f3"), &mut state(SafetyState::Idle), now());
    assert_eq!(out.status, Status::Failed, "{out:?}");
}

/// T18 against a **real** ROS 2 node (`tools/e2e/ros2-peer/run.sh` starts
/// it in a container and runs this test): the `nav2` safe_pause over the
/// node's RMW (`ROBODR_ROS2_RMW`: `fastrtps` or `cyclonedds`), the zero
/// twists reaching its subscriber, and the latch finding the goals the
/// node "received" while paused. Ignored without the container.
/// T18, found against a real Cyclone DDS: the zero twists were published
/// after one announcement of their writer; a peer that dropped it (it
/// arrived before the peer processed our SPDP) never matched the writer
/// and dropped every twist. Each twist now re-announces the writer.
#[test]
fn t18_zero_twists_reach_a_peer_that_missed_the_first_announcement() {
    let (_sim, port, seen, _) = sim_ros2_inner(FastReply::No, true, |topic, p| {
        if topic.ends_with("/_action/cancel_goalRequest") {
            return service_reply(p, |e| {
                e.u8(0);
                e.u32(0);
            });
        }
        None
    });
    let d = tmpdir("t18-late");
    let motion = json!({"safe_pause": "nav2",
        "nav2": {"oem_validated": true, "ros2": ros2_peer(port),
                 "actions": ["/navigate_to_pose"], "zero_twists": 4,
                 "zero_twist_interval_ms": 10}});
    let mut e = engine(
        &d,
        motion,
        policy(PlatformFamily::Ugv, Morphology::WheeledMobile),
        now(),
    );
    let o = signed(
        "late1",
        ActionId::SafePause,
        Morphology::WheeledMobile,
        Target::None,
        None,
        &["alice", "bob"],
        SafetyState::Idle,
    );
    let out = e.submit(&o, &mut state(SafetyState::Idle), now());
    assert_eq!(out.status, Status::Verified, "{out:?}");
    std::thread::sleep(Duration::from_millis(50));
    let twists = seen
        .lock()
        .unwrap()
        .iter()
        .filter(|(t, _)| t == "rt/cmd_vel")
        .count();
    assert!(twists >= 3, "{twists} zero twist(s) matched");
}

#[test]
#[ignore = "needs a ROS 2 peer: tools/e2e/ros2-peer/run.sh"]
fn t18_real_ros2_peer() {
    let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} not set"));
    let (peer_ip, local_ip, rmw, out) = (
        env("ROBODR_ROS2_PEER_IP"),
        env("ROBODR_ROS2_LOCAL_IP"),
        env("ROBODR_ROS2_RMW"),
        env("ROBODR_ROS2_PEER_OUT"),
    );
    let peer_state = || -> Value {
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap_or_default())
            .unwrap_or(Value::Null)
    };
    let motion = json!({"safe_pause": "nav2", "safe_pause_latch_s": 1,
        "nav2": {"oem_validated": true,
                 "ros2": {"peer_ip": peer_ip, "local_ip": local_ip, "rmw": rmw,
                          "timeout_ms": 3000, "resend_ms": 200},
                 "actions": ["/navigate_to_pose"], "zero_twists": 5,
                 "zero_twist_interval_ms": 50}});
    let d = tmpdir(&format!("t18-real-{rmw}"));
    let t0 = now();
    let mut e = engine(
        &d,
        motion,
        policy(PlatformFamily::Ugv, Morphology::WheeledMobile),
        t0,
    );
    let o = signed(
        "real1",
        ActionId::SafePause,
        Morphology::WheeledMobile,
        Target::None,
        None,
        &["alice", "bob"],
        SafetyState::Idle,
    );
    let out = e.submit(&o, &mut state(SafetyState::Idle), t0);
    assert_eq!(out.status, Status::Verified, "{out:?}");
    let note = out.note.unwrap_or_default();
    assert!(note.contains("1 goal(s) cancelling"), "{note}");
    // The zero twists reach the node's subscriber (reliable, so all of
    // them once matched; at least one).
    let mut st = Value::Null;
    for _ in 0..50 {
        st = peer_state();
        if st["zero_twists"].as_u64().unwrap_or(0) >= 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(st["zero_twists"].as_u64().unwrap_or(0) >= 1, "{st}");
    assert_eq!(st["other_twists"], 0, "{st}");
    // Latch: nothing found, then the 2 goals the node scripts.
    let late = |ms: u64| Now {
        wall_ms: t0.wall_ms + ms,
        boot_ms: t0.boot_ms.map(|b| b + ms),
    };
    e.tick(late(1_100));
    assert!(overridden(&e).is_empty(), "{:?}", e.state().events);
    e.tick(late(10_000));
    let ov = overridden(&e);
    assert_eq!(ov.len(), 1, "{:?}", e.state().events);
    assert!(ov[0].contains("2 navigation goal(s)"), "{ov:?}");
    let st = peer_state();
    assert_eq!(st["cancels"], 3, "{st}");
    eprintln!("peer: {st}");
}
