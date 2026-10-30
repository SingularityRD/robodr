//! The real adapters behind [`super::SystemPorts`] (see the module docs of
//! [`super`] for what each does and how it is undone).

use std::io::Write as _;
use std::net::UdpSocket;
use std::path::Path;
use std::time::{Duration, Instant};

use robodr_responder::{ActionId, SafeBehaviour};

use super::cdr::{self, Dec};
use super::mavlink::{self as mav, Heartbeat};
use super::rtps::{Participant, Received};
use super::{AdapterKind, MotionSection, MotionSpec, Ros2Peer};

fn missing(k: AdapterKind) -> String {
    format!("adapter {} is not configured", k.as_str())
}

/// Apply every adapter of `spec` in order; on a failure the ones already
/// applied are undone (best effort) and the error names both.
pub fn apply(m: &MotionSection, spec: &MotionSpec) -> Result<String, String> {
    let mut notes = Vec::new();
    for (i, k) in spec.adapters.iter().enumerate() {
        match apply_one(m, spec, *k) {
            Ok(n) => notes.push(format!("{}: {n}", k.as_str())),
            Err(e) => {
                let mut undo = Vec::new();
                for done in spec.adapters.iter().take(i) {
                    if let Err(u) = revert_one(m, spec, *done) {
                        undo.push(format!("{} not undone: {u}", done.as_str()));
                    }
                }
                let mut msg = format!("{}: {e}", k.as_str());
                if !undo.is_empty() {
                    msg.push_str(&format!(" ({})", undo.join("; ")));
                }
                return Err(msg);
            }
        }
    }
    Ok(notes.join("; "))
}

/// Undo every adapter of `spec` (in reverse order); every one is tried.
pub fn revert(m: &MotionSection, spec: &MotionSpec) -> Result<String, String> {
    let mut ok = Vec::new();
    let mut err = Vec::new();
    for k in spec.adapters.iter().rev() {
        match revert_one(m, spec, *k) {
            Ok(n) => ok.push(format!("{}: {n}", k.as_str())),
            Err(e) => err.push(format!("{}: {e}", k.as_str())),
        }
    }
    if err.is_empty() {
        Ok(ok.join("; "))
    } else {
        Err(err.join("; "))
    }
}

/// Periodic read-back: only the gateway restriction can be read back
/// without commanding anything.
pub fn verify(m: &MotionSection, spec: &MotionSpec) -> Result<(), String> {
    if spec.adapters.contains(&AdapterKind::Gateway) {
        let g = m
            .gateway
            .as_ref()
            .ok_or_else(|| missing(AdapterKind::Gateway))?;
        if gateway_restriction_id(&g.status_path)?.as_deref() != Some(spec.id.as_str()) {
            return Err("the gateway does not report the restriction".into());
        }
    }
    Ok(())
}

fn apply_one(m: &MotionSection, spec: &MotionSpec, k: AdapterKind) -> Result<String, String> {
    match k {
        AdapterKind::Gateway => gateway_apply(m, spec),
        AdapterKind::UnitreeSport => {
            let u = m.unitree_sport.as_ref().ok_or_else(|| missing(k))?;
            unitree_speed_level(u, spec, u.speed_level)
        }
        AdapterKind::Nav2 => nav2_pause(m, spec),
        AdapterKind::Ros2Control => {
            let c = m.ros2_control.as_ref().ok_or_else(|| missing(k))?;
            switch(c, &c.activate, &c.deactivate)
        }
        AdapterKind::Px4 => px4_mode(m, spec),
        AdapterKind::Rollback => rollback(m, spec),
    }
}

fn revert_one(m: &MotionSection, spec: &MotionSpec, k: AdapterKind) -> Result<String, String> {
    match k {
        AdapterKind::Gateway => gateway_revert(m, spec),
        AdapterKind::UnitreeSport => {
            let u = m.unitree_sport.as_ref().ok_or_else(|| missing(k))?;
            unitree_speed_level(u, spec, 0)
        }
        AdapterKind::Nav2 => Ok(
            "nothing to undo: cancelled navigation goals are not restored; \
                                 the operator re-issues the mission"
                .into(),
        ),
        AdapterKind::Ros2Control => {
            let c = m.ros2_control.as_ref().ok_or_else(|| missing(k))?;
            switch(c, &c.deactivate, &c.activate)
        }
        AdapterKind::Px4 => Ok(
            "no mode change: the vehicle stays in hold until its operator \
                                switches mode (the executor never resumes a mission)"
                .into(),
        ),
        AdapterKind::Rollback => Err("a rollback is not reversible".into()),
    }
}

// ----------------------------------------------------------------- gateway

/// The `restriction.id` the gateway reports (`None`: no restriction).
fn gateway_restriction_id(status: &Path) -> Result<Option<String>, String> {
    let text = crate::config::read_small(status)?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", status.display()))?;
    Ok(v.get("restriction")
        .and_then(|r| r.get("id"))
        .and_then(|i| i.as_str())
        .map(str::to_string))
}

fn poll(timeout: Duration, mut f: impl FnMut() -> Result<bool, String>) -> Result<(), String> {
    let until = Instant::now() + timeout;
    let mut last = None;
    loop {
        match f() {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(e) => last = Some(e),
        }
        if Instant::now() >= until {
            return Err(last.unwrap_or_else(|| "not confirmed before the deadline".into()));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn gateway_apply(m: &MotionSection, spec: &MotionSpec) -> Result<String, String> {
    let g = m
        .gateway
        .as_ref()
        .ok_or_else(|| missing(AdapterKind::Gateway))?;
    let mut v = serde_json::json!({
        "format": "robodr-gw-restriction/v1",
        "id": spec.id,
        "expires_unix_ms": spec.deadline_ms,
    });
    let r = &spec.request;
    for (k, x) in [
        ("max_linear_speed", r.max_linear_speed),
        ("max_joint_speed", r.max_joint_speed),
        ("factor", r.factor),
    ] {
        if let Some(x) = x {
            v[k] = x.into();
        }
    }
    let p = &g.restriction_path;
    let dir = p.parent().ok_or("restriction_path has no directory")?;
    let tmp = dir.join(format!(".restriction.{}.tmp", std::process::id()));
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o640)
            .open(&tmp)
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        f.write_all(v.to_string().as_bytes())
            .and_then(|()| f.sync_all())
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
    }
    std::fs::rename(&tmp, p).map_err(|e| format!("{}: {e}", p.display()))?;
    let id = spec.id.clone();
    let confirmed = poll(Duration::from_millis(g.verify_timeout_ms), || {
        Ok(gateway_restriction_id(&g.status_path)?.as_deref() == Some(id.as_str()))
    });
    match confirmed {
        Ok(()) => Ok(format!(
            "restriction {} written to {} and reported by the gateway",
            spec.id,
            p.display()
        )),
        Err(e) => {
            let _ = std::fs::remove_file(p);
            Err(format!(
                "the gateway did not report the restriction ({e}); file removed"
            ))
        }
    }
}

fn gateway_revert(m: &MotionSection, spec: &MotionSpec) -> Result<String, String> {
    let g = m
        .gateway
        .as_ref()
        .ok_or_else(|| missing(AdapterKind::Gateway))?;
    let p = &g.restriction_path;
    // Only our own restriction is removed (a newer one stays).
    let ours = match crate::config::read_small(p) {
        Ok(t) => serde_json::from_str::<serde_json::Value>(&t)
            .ok()
            .and_then(|v| v.get("id").and_then(|i| i.as_str()).map(str::to_string))
            .is_some_and(|i| i == spec.id),
        Err(_) => false,
    };
    if ours {
        std::fs::remove_file(p).map_err(|e| format!("{}: {e}", p.display()))?;
    }
    let id = spec.id.clone();
    poll(Duration::from_millis(g.verify_timeout_ms), || {
        Ok(gateway_restriction_id(&g.status_path)?.as_deref() != Some(id.as_str()))
    })
    .map_err(|e| format!("the gateway still reports the restriction: {e}"))?;
    Ok("restriction removed; the gateway no longer reports it".into())
}

// ----------------------------------------------------------------- ROS 2

/// A 64-bit id from a string (FNV-1a; Unitree request ids, client ids).
fn id64(s: &str) -> u64 {
    s.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

const REQ_WRITER: [u8; 4] = [0, 0, 0x01, 0x03];
const REP_READER: [u8; 4] = [0, 0, 0x02, 0x04];
const TOPIC_WRITER: [u8; 4] = [0, 0, 0x03, 0x03];

/// A service call with the `rmw_cyclonedds` request header: the reply
/// whose header carries our client id and sequence number.
fn call_service(
    p: &Ros2Peer,
    service: &str,
    srv_type: &str,
    request: &[u8],
    client: u64,
    seq: i64,
) -> Result<Vec<u8>, String> {
    let mut part = Participant::open(p.peer()?).map_err(|e| format!("socket: {e}"))?;
    let name = service.trim_start_matches('/');
    let req_topic = format!("rq/{name}Request");
    let rep_topic = format!("rr/{name}Reply");
    let send = |part: &mut Participant| -> std::io::Result<()> {
        part.announce()?;
        part.announce_writer(REQ_WRITER, &req_topic, &format!("{srv_type}Request_"))?;
        part.announce_reader(REP_READER, &rep_topic, &format!("{srv_type}Response_"))?;
        part.publish(REQ_WRITER, 1, request)
    };
    send(&mut part).map_err(|e| format!("send: {e}"))?;
    let deadline = Instant::now() + Duration::from_millis(p.timeout_ms);
    part.wait(
        deadline,
        Duration::from_millis(p.resend_ms),
        send,
        |r: &Received| {
            let mut d = Dec::open(&r.payload).ok()?;
            (d.u64().ok()? == client && d.i64().ok()? == seq).then(|| r.payload.clone())
        },
    )
}

/// Skip the request header of a reply.
fn reply_body(payload: &[u8]) -> Result<Dec<'_>, String> {
    let mut d = Dec::open(payload)?;
    d.u64()?;
    d.i64()?;
    Ok(d)
}

fn nav2_pause(m: &MotionSection, spec: &MotionSpec) -> Result<String, String> {
    let n = m.nav2.as_ref().ok_or_else(|| missing(AdapterKind::Nav2))?;
    let client = id64(&spec.id);
    let mut notes = Vec::new();
    for (i, a) in n.actions.iter().enumerate() {
        let seq = i as i64 + 1;
        let req = cdr::cancel_all_goals(client, seq);
        let rep = call_service(
            &n.ros2,
            &format!("{a}/_action/cancel_goal"),
            "action_msgs::srv::dds_::CancelGoal_",
            &req,
            client,
            seq,
        )
        .map_err(|e| format!("{a}: cancel_goal: {e}"))?;
        let (code, count) = cdr::cancel_response(&mut reply_body(&rep)?)?;
        // ERROR_NONE (0); UNKNOWN_GOAL_ID (2) / GOAL_TERMINATED (3): there
        // was nothing to cancel. REJECTED (1) or anything else fails.
        if !matches!(code, 0 | 2 | 3) {
            return Err(format!("{a}: cancel_goal answered return_code {code}"));
        }
        notes.push(format!("{a}: {count} goal(s) cancelling (code {code})"));
    }
    let mut part = Participant::open(n.ros2.peer()?).map_err(|e| format!("socket: {e}"))?;
    let topic = format!("rt{}", n.cmd_vel_topic);
    part.announce().map_err(|e| format!("send: {e}"))?;
    part.announce_writer(TOPIC_WRITER, &topic, "geometry_msgs::msg::dds_::Twist_")
        .map_err(|e| format!("send: {e}"))?;
    let z = cdr::zero_twist();
    for sn in 1..=i64::from(n.zero_twists) {
        part.publish(TOPIC_WRITER, sn, &z)
            .map_err(|e| format!("send: {e}"))?;
        std::thread::sleep(Duration::from_millis(n.zero_twist_interval_ms));
    }
    notes.push(format!(
        "{} zero twist(s) on {}",
        n.zero_twists, n.cmd_vel_topic
    ));
    Ok(notes.join("; "))
}

fn switch(
    c: &super::Ros2ControlAdapter,
    activate: &[String],
    deactivate: &[String],
) -> Result<String, String> {
    let client = id64(&format!("{activate:?}{deactivate:?}"));
    let seq = 1;
    let req = cdr::switch_controller(
        client,
        seq,
        c.distro,
        activate,
        deactivate,
        c.switch_timeout_s,
    );
    let rep = call_service(
        &c.ros2,
        &format!("{}/switch_controller", c.controller_manager),
        "controller_manager_msgs::srv::dds_::SwitchController_",
        &req,
        client,
        seq,
    )?;
    let ok = reply_body(&rep)?.u8()?;
    if ok != 1 {
        return Err(format!(
            "switch_controller refused (activate {activate:?}, deactivate {deactivate:?})"
        ));
    }
    Ok(format!(
        "controllers switched: activated {activate:?}, deactivated {deactivate:?}"
    ))
}

fn unitree_speed_level(
    u: &super::UnitreeAdapter,
    spec: &MotionSpec,
    level: i32,
) -> Result<String, String> {
    const SPEED_LEVEL: i64 = 1015;
    let id = (id64(&format!("{}:{level}", spec.id)) >> 1) as i64;
    let req = cdr::unitree_request(id, SPEED_LEVEL, &format!("{{\"data\":{level}}}"));
    let mut part = Participant::open(u.ros2.peer()?).map_err(|e| format!("socket: {e}"))?;
    let (rq, rs) = (u.request_topic.clone(), u.response_topic.clone());
    let send = |part: &mut Participant| -> std::io::Result<()> {
        part.announce()?;
        part.announce_writer(REQ_WRITER, &rq, "unitree_api::msg::dds_::Request_")?;
        part.announce_reader(REP_READER, &rs, "unitree_api::msg::dds_::Response_")?;
        part.publish(REQ_WRITER, 1, &req)
    };
    send(&mut part).map_err(|e| format!("send: {e}"))?;
    let deadline = Instant::now() + Duration::from_millis(u.ros2.timeout_ms);
    let code = part.wait(
        deadline,
        Duration::from_millis(u.ros2.resend_ms),
        send,
        |r: &Received| {
            let (rid, api, code) = cdr::unitree_response(&r.payload).ok()?;
            (rid == id && api == SPEED_LEVEL).then_some(code)
        },
    )?;
    if code != 0 {
        return Err(format!("SpeedLevel({level}) answered status code {code}"));
    }
    Ok(format!("sport SpeedLevel({level}) acknowledged"))
}

// ------------------------------------------------------------------ PX4

fn px4_mode(m: &MotionSection, spec: &MotionSpec) -> Result<String, String> {
    let p = m.px4.as_ref().ok_or_else(|| missing(AdapterKind::Px4))?;
    let sub = match (spec.action, spec.behaviour) {
        (ActionId::RequestSafeState, Some(SafeBehaviour::ReturnToLaunch)) => mav::PX4_SUB_AUTO_RTL,
        _ => mav::PX4_SUB_AUTO_LOITER,
    };
    let want = mav::px4_custom_mode(mav::PX4_MAIN_AUTO, sub);
    let sock = UdpSocket::bind(p.bind).map_err(|e| format!("bind {}: {e}", p.bind))?;
    let deadline = Instant::now() + Duration::from_millis(p.timeout_ms);
    let mut seq: u8 = 0;
    let mut send = |msgid: u32, payload: &[u8]| -> Result<(), String> {
        seq = seq.wrapping_add(1);
        let f = mav::encode(seq, p.system_id, p.component_id, msgid, payload)
            .ok_or("MAVLink encode")?;
        sock.send_to(&f, p.address)
            .map(|_| ())
            .map_err(|e| format!("send: {e}"))
    };
    let gcs = Heartbeat {
        custom_mode: 0,
        mav_type: 6,  // MAV_TYPE_GCS
        autopilot: 8, // MAV_AUTOPILOT_INVALID
        base_mode: 0,
        system_status: 4,
    };
    let cmd = mav::command_long(
        [
            mav::MAV_MODE_FLAG_CUSTOM_MODE_ENABLED,
            f32::from(mav::PX4_MAIN_AUTO),
            f32::from(sub),
            0.0,
            0.0,
            0.0,
            0.0,
        ],
        mav::MAV_CMD_DO_SET_MODE,
        p.target_system,
        p.target_component,
    );
    let mut buf = [0u8; 2048];
    let mut before: Option<u32> = None;
    let mut acked = false;
    let mut next_send = Instant::now();
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(format!(
                "no {} before the deadline (mode before: {before:?})",
                if acked {
                    "heartbeat in the new mode"
                } else {
                    "COMMAND_ACK accepted"
                }
            ));
        }
        if now >= next_send {
            send(mav::MSG_HEARTBEAT, &gcs.payload())?;
            if !acked {
                send(mav::MSG_COMMAND_LONG, &cmd)?;
            }
            next_send = now + Duration::from_millis(500);
        }
        let _ = sock.set_read_timeout(Some(
            deadline
                .min(next_send)
                .saturating_duration_since(now)
                .max(Duration::from_millis(1)),
        ));
        let (n, from) = match sock.recv_from(&mut buf) {
            Ok(x) => x,
            Err(_) => continue,
        };
        if from != std::net::SocketAddr::V4(p.address) {
            continue;
        }
        let Ok(frames) = mav::decode_all(buf.get(..n).unwrap_or_default()) else {
            continue;
        };
        for f in frames {
            if f.sysid != p.target_system || f.compid != p.target_component {
                continue;
            }
            if let Some(hb) = Heartbeat::parse(&f) {
                before.get_or_insert(hb.custom_mode);
                if acked && hb.custom_mode == want {
                    return Ok(format!(
                        "PX4 mode AUTO.{} confirmed by heartbeat (was custom_mode {:#010x})",
                        if sub == mav::PX4_SUB_AUTO_RTL {
                            "RTL"
                        } else {
                            "LOITER"
                        },
                        before.unwrap_or(0)
                    ));
                }
            }
            if let Some((c, result, ts, tc)) = mav::parse_command_ack(&f) {
                // The target fields are an extension: an autopilot that does not
                // fill them sends zeros.
                let to_us = (ts, tc) == (p.system_id, p.component_id) || (ts, tc) == (0, 0);
                if c == mav::MAV_CMD_DO_SET_MODE && to_us {
                    if result != mav::MAV_RESULT_ACCEPTED {
                        return Err(format!("DO_SET_MODE refused (MAV_RESULT {result})"));
                    }
                    acked = true;
                }
            }
        }
    }
}

// -------------------------------------------------------------- rollback

fn run(program: &Path, args: &[&str], timeout: Duration) -> Result<(), String> {
    let mut child = std::process::Command::new(program)
        .args(args)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("{}: {e}", program.display()))?;
    let until = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(st)) if st.success() => return Ok(()),
            Ok(Some(st)) => return Err(format!("{} exited with {st}", program.display())),
            Ok(None) if Instant::now() >= until => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{} timed out", program.display()));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err(format!("{}: {e}", program.display())),
        }
    }
}

fn rollback(m: &MotionSection, spec: &MotionSpec) -> Result<String, String> {
    let r = m
        .rollback
        .as_ref()
        .ok_or_else(|| missing(AdapterKind::Rollback))?;
    let v = spec.request.to_version.as_deref().ok_or("no to_version")?;
    let t = Duration::from_secs(r.timeout_s);
    run(
        &r.program,
        &[
            "--config",
            "program",
            "--to-version",
            v,
            "--request-id",
            &spec.id,
        ],
        t,
    )?;
    run(
        &r.program,
        &["--verify", "--config", "program", "--to-version", v],
        t,
    )
    .map_err(|e| format!("rolled back but --verify failed: {e}"))?;
    Ok(format!(
        "program rolled back to {v} and verified by the site program"
    ))
}
