//! The real adapters behind [`super::SystemPorts`] (see the module docs of
//! [`super`] for what each does and how it is undone).

use std::io::Write as _;
use std::net::UdpSocket;
use std::path::Path;
use std::time::{Duration, Instant};

use robodr_responder::{ActionId, SafeBehaviour};

use super::cdr::{self, Dec};
use super::mavlink::{self as mav, Heartbeat};
use super::rtps::{self, Participant, Received};
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
            unitree_speed_level(u, u.speed_level)
        }
        AdapterKind::Nav2 => nav2_pause(m),
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
            unitree_speed_level(u, 0)
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
        if let (Some(x), Some(o)) = (x, v.as_object_mut()) {
            o.insert(k.into(), x.into());
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

/// Fresh correlation ids for one service call (review F10): a random
/// client id and a random sequence number above 1, so a reply cannot be
/// precomputed from the request, the controllers or the order id.
fn correlation() -> (u64, i64) {
    let client = rtps::random_u64() | 1;
    let seq = ((rtps::random_u64() >> 2) | 2) as i64;
    (client, seq)
}

/// Length of the `rmw_cyclonedds` request header (client id, sequence
/// number) after the 4-octet encapsulation header.
const CDDS_HEADER: usize = 16;

/// `payload` (encapsulation, header, body) without the `rmw_cyclonedds`
/// request header. The header is 16 octets, so the body's CDR alignment
/// (relative to the end of the encapsulation) is unchanged.
fn without_header(payload: &[u8]) -> Result<Vec<u8>, String> {
    let (encap, rest) = payload
        .split_first_chunk::<4>()
        .ok_or("payload shorter than its encapsulation")?;
    let body = rest
        .get(CDDS_HEADER..)
        .ok_or("payload shorter than its request header")?;
    let mut out = encap.to_vec();
    out.extend_from_slice(body);
    Ok(out)
}

/// A service call. `request` is the `rmw_cyclonedds` payload (with its
/// request header `client`, `seq`); the answer is the reply's payload
/// **without** a request header (encapsulation and body), whichever RMW
/// the peer runs (`p.rmw`, sales-readiness T18):
///
/// - `cyclonedds`: the reply whose header carries our client id and
///   sequence number;
/// - `fastrtps`: the request is sent without the header, with a random
///   sequence number and our reply reader as its related sample identity;
///   the reply is the sample whose related sample identity names our
///   reply reader or our request writer (both with fresh random entity
///   keys) and that sequence number.
fn call_service(
    p: &Ros2Peer,
    service: &str,
    srv_type: &str,
    request: &[u8],
    client: u64,
    seq: i64,
) -> Result<Vec<u8>, String> {
    let mut part = Participant::open(p.peer()?, p.prefix()?).map_err(|e| format!("socket: {e}"))?;
    let (req_w, rep_r) = (rtps::fresh_entity(0x03), rtps::fresh_entity(0x04));
    let name = service.trim_start_matches('/');
    let req_topic = format!("rq/{name}Request");
    let rep_topic = format!("rr/{name}Reply");
    let (payload, sn, qos) = match p.rmw {
        super::Rmw::Cyclonedds => (request.to_vec(), 1, None),
        super::Rmw::Fastrtps => {
            // Review F10 for this RMW: the correlation is the GUIDs (fresh
            // random entity keys) and a random sequence number. Kept below
            // 2^16 + 2: a real Fast DDS reader (Humble) never delivers a
            // first sample numbered near 2^31 (tools/e2e/ros2-peer). That
            // leaves 16 bits here: with `participant_prefix` configured (our
            // prefix known) a forger guesses one of two 24-bit entity keys
            // and this number, about 2^39 tries within `timeout_ms`; without
            // it our random 96-bit prefix is in the GUID as well. Weaker
            // than the cyclonedds path's 64-bit client id (a forged reply
            // could confirm a cancel that did not happen);
            // `peer_participant_prefix` narrows answers to the peer's own
            // writers.
            let sn = 2 + i64::from(rtps::random_u64() as u16);
            let qos =
                rtps::related_identity_qos(rtps::guid_of(part.prefix, rep_r), rtps::SN_UNKNOWN);
            (without_header(request)?, sn, Some(qos))
        }
    };
    let send = |part: &mut Participant| -> std::io::Result<()> {
        part.announce()?;
        part.announce_writer(req_w, &req_topic, &format!("{srv_type}Request_"))?;
        part.announce_reader(rep_r, &rep_topic, &format!("{srv_type}Response_"))?;
        part.publish_with(req_w, sn, qos.as_deref(), &payload)
    };
    send(&mut part).map_err(|e| format!("send: {e}"))?;
    let deadline = Instant::now() + Duration::from_millis(p.timeout_ms);
    let peer = p.peer_prefix()?;
    let ours = [
        rtps::guid_of(part.prefix, rep_r),
        rtps::guid_of(part.prefix, req_w),
    ];
    let rmw = p.rmw;
    part.wait(
        deadline,
        Duration::from_millis(p.resend_ms),
        send,
        |r: &Received| {
            from_peer(peer, r)?;
            match rmw {
                super::Rmw::Cyclonedds => {
                    let mut d = Dec::open(&r.payload).ok()?;
                    (d.u64().ok()? == client && d.i64().ok()? == seq)
                        .then(|| without_header(&r.payload).ok())
                        .flatten()
                }
                super::Rmw::Fastrtps => {
                    let (g, s) = r.related?;
                    (ours.contains(&g) && s == sn).then(|| r.payload.clone())
                }
            }
        },
    )
}

/// With `peer_participant_prefix` configured, only a sample of one of the
/// peer's own writers is an answer (review F10).
fn from_peer(peer: Option<[u8; 12]>, r: &Received) -> Option<()> {
    match peer {
        Some(p) if r.writer[..12] != p => None,
        _ => Some(()),
    }
}

/// The body of a reply ([`call_service`] removed any request header).
fn reply_body(payload: &[u8]) -> Result<Dec<'_>, String> {
    Dec::open(payload)
}

fn nav2_pause(m: &MotionSection) -> Result<String, String> {
    let n = m.nav2.as_ref().ok_or_else(|| missing(AdapterKind::Nav2))?;
    let (mut notes, _) = nav2_cancel_all(n)?;
    notes.push(nav2_zero_twists(n)?);
    Ok(notes.join("; "))
}

/// `CancelGoal` (every goal) on each action server: the notes and how
/// many goals were cancelling in all.
fn nav2_cancel_all(n: &super::Nav2Adapter) -> Result<(Vec<String>, u64), String> {
    let mut notes = Vec::new();
    let mut total: u64 = 0;
    for a in &n.actions {
        let (client, seq) = correlation();
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
        total = total.saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
    }
    Ok((notes, total))
}

/// A burst of zero `Twist` on `cmd_vel`.
fn nav2_zero_twists(n: &super::Nav2Adapter) -> Result<String, String> {
    let mut part =
        Participant::open(n.ros2.peer()?, n.ros2.prefix()?).map_err(|e| format!("socket: {e}"))?;
    let topic = format!("rt{}", n.cmd_vel_topic);
    let tw = rtps::fresh_entity(0x03);
    let z = cdr::zero_twist();
    for sn in 1..=i64::from(n.zero_twists) {
        // Announced with every twist (T18, found against a real Cyclone
        // DDS): a peer drops samples of a writer it has not matched yet,
        // and an announcement that arrived before it knew this participant
        // is not repeated by anyone else.
        part.announce().map_err(|e| format!("send: {e}"))?;
        part.announce_writer(tw, &topic, "geometry_msgs::msg::dds_::Twist_")
            .map_err(|e| format!("send: {e}"))?;
        part.publish(tw, sn, &z).map_err(|e| format!("send: {e}"))?;
        std::thread::sleep(Duration::from_millis(n.zero_twist_interval_ms));
    }
    Ok(format!(
        "{} zero twist(s) on {}",
        n.zero_twists, n.cmd_vel_topic
    ))
}

/// Re-assert a `safe_pause` in force (sales-readiness T42, see
/// [`super::MotionPorts::latch`]). `nav2`: every goal is cancelled again;
/// any goal that was cancelling was sent while paused (the first cancel
/// left none in a cancelable state): overridden, and a zero-twist burst
/// follows. `px4`: the heartbeat's mode is read back; any mode but hold is
/// overridden and hold is set again, except a pilot's manual mode, which
/// is reported but never taken away from the pilot. `ros2_control`: not
/// observed (a controller switch is state the controller manager keeps).
pub fn latch(m: &MotionSection, spec: &MotionSpec) -> Result<super::Latch, String> {
    use super::Latch;
    if spec.action != ActionId::SafePause {
        return Ok(Latch::Held(String::new()));
    }
    let mut held = Vec::new();
    let mut overridden = Vec::new();
    let mut kinds = Vec::new();
    for k in &spec.adapters {
        match k {
            AdapterKind::Nav2 => {
                let n = m.nav2.as_ref().ok_or_else(|| missing(*k))?;
                let (notes, total) = nav2_cancel_all(n).map_err(|e| format!("nav2: {e}"))?;
                if total == 0 {
                    held.push("nav2: no goal".to_string());
                } else {
                    let tw = nav2_zero_twists(n).map_err(|e| format!("nav2: {e}"))?;
                    kinds.push("nav2:goals".to_string());
                    overridden.push(format!(
                        "nav2: {total} navigation goal(s) sent while paused were cancelled ({}); \
                         {tw}",
                        notes.join("; ")
                    ));
                }
            }
            AdapterKind::Px4 => {
                let p = m.px4.as_ref().ok_or_else(|| missing(*k))?;
                let mode = px4_read_mode(p).map_err(|e| format!("px4: {e}"))?;
                let hold = mav::px4_custom_mode(mav::PX4_MAIN_AUTO, mav::PX4_SUB_AUTO_LOITER);
                if mode == hold {
                    held.push("px4: in hold".to_string());
                } else if mav::px4_is_manual(mode) {
                    kinds.push(format!("px4:manual:{}", mav::px4_mode_name(mode)));
                    overridden.push(format!(
                        "px4: a pilot switched to manual mode {} while paused: left to the pilot \
                         (a manual mode is never taken away)",
                        mav::px4_mode_name(mode)
                    ));
                } else {
                    let again = px4_mode(m, spec).map_err(|e| {
                        format!(
                            "px4: mode {} while paused; setting hold again failed: {e}",
                            mav::px4_mode_name(mode)
                        )
                    })?;
                    kinds.push(format!("px4:mode:{}", mav::px4_mode_name(mode)));
                    overridden.push(format!(
                        "px4: mode changed to {} while paused; hold set again: {again}",
                        mav::px4_mode_name(mode)
                    ));
                }
            }
            other => held.push(format!("{}: not observed", other.as_str())),
        }
    }
    if overridden.is_empty() {
        Ok(Latch::Held(held.join("; ")))
    } else {
        Ok(Latch::Overridden {
            kind: kinds.join("+"),
            note: overridden.join("; "),
        })
    }
}

fn switch(
    c: &super::Ros2ControlAdapter,
    activate: &[String],
    deactivate: &[String],
) -> Result<String, String> {
    let (client, seq) = correlation();
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

fn unitree_speed_level(u: &super::UnitreeAdapter, level: i32) -> Result<String, String> {
    const SPEED_LEVEL: i64 = 1015;
    let id = (rtps::random_u64() >> 1) as i64;
    let req = cdr::unitree_request(id, SPEED_LEVEL, &format!("{{\"data\":{level}}}"));
    let mut part =
        Participant::open(u.ros2.peer()?, u.ros2.prefix()?).map_err(|e| format!("socket: {e}"))?;
    let (rq, rs) = (u.request_topic.clone(), u.response_topic.clone());
    let (req_w, rep_r) = (rtps::fresh_entity(0x03), rtps::fresh_entity(0x04));
    let send = |part: &mut Participant| -> std::io::Result<()> {
        part.announce()?;
        part.announce_writer(req_w, &rq, "unitree_api::msg::dds_::Request_")?;
        part.announce_reader(rep_r, &rs, "unitree_api::msg::dds_::Response_")?;
        part.publish(req_w, 1, &req)
    };
    send(&mut part).map_err(|e| format!("send: {e}"))?;
    let deadline = Instant::now() + Duration::from_millis(u.ros2.timeout_ms);
    let peer = u.ros2.peer_prefix()?;
    let code = part.wait(
        deadline,
        Duration::from_millis(u.ros2.resend_ms),
        send,
        |r: &Received| {
            from_peer(peer, r)?;
            let (rid, api, code) = cdr::unitree_response(&r.payload).ok()?;
            (rid == id && api == SPEED_LEVEL).then_some(code)
        },
    )?;
    if code != 0 {
        return Err(format!("SpeedLevel({level}) answered status code {code}"));
    }
    Ok(format!(
        "sport SpeedLevel({level}) acknowledged (the sport API takes a speed level, not the \
         requested caps)"
    ))
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
                // The target fields are an extension (PX4 fills them). Review
                // F10: only an ack naming our own system / component is ours;
                // zero targets (an autopilot that does not fill them, or a
                // forger's broadcast) never confirm, the call fails closed.
                let to_us = (ts, tc) == (p.system_id, p.component_id);
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

/// The vehicle's `custom_mode` from its heartbeat (a GCS heartbeat is sent
/// so the autopilot streams to this address; nothing is commanded).
fn px4_read_mode(p: &super::Px4Adapter) -> Result<u32, String> {
    let sock = UdpSocket::bind(p.bind).map_err(|e| format!("bind {}: {e}", p.bind))?;
    let deadline = Instant::now() + Duration::from_millis(p.timeout_ms);
    let gcs = Heartbeat {
        custom_mode: 0,
        mav_type: 6,  // MAV_TYPE_GCS
        autopilot: 8, // MAV_AUTOPILOT_INVALID
        base_mode: 0,
        system_status: 4,
    };
    let mut seq: u8 = 0;
    let mut buf = [0u8; 2048];
    let mut next_send = Instant::now();
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err("no heartbeat from the autopilot before the deadline".into());
        }
        if now >= next_send {
            seq = seq.wrapping_add(1);
            let f = mav::encode(
                seq,
                p.system_id,
                p.component_id,
                mav::MSG_HEARTBEAT,
                &gcs.payload(),
            )
            .ok_or("MAVLink encode")?;
            sock.send_to(&f, p.address)
                .map_err(|e| format!("send: {e}"))?;
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
                return Ok(hb.custom_mode);
            }
        }
    }
}

// -------------------------------------------------------------- rollback

/// The rollback program may be run (review finding 8): a regular file
/// owned by root and not writable by group or others, in a directory that
/// is owned by root and not writable by group or others either (whoever
/// can replace it chooses what the executor runs).
pub fn program_ok(program: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;
    // The program itself is never followed through a symlink; its
    // directory may be reached through one (`/bin` → `/usr/bin`).
    let check = |p: &Path, what: &str, follow: bool| -> Result<(), String> {
        let md = if follow {
            std::fs::metadata(p)
        } else {
            std::fs::symlink_metadata(p)
        }
        .map_err(|e| format!("{}: {e}", p.display()))?;
        if !follow && !md.file_type().is_file() {
            return Err(format!(
                "{}: not a regular file (a symlink is refused)",
                p.display()
            ));
        }
        if md.uid() != 0 {
            return Err(format!(
                "{} ({what}) is owned by uid {}, not root",
                p.display(),
                md.uid()
            ));
        }
        if md.mode() & 0o022 != 0 {
            return Err(format!(
                "{} ({what}) is writable by group or others",
                p.display()
            ));
        }
        Ok(())
    };
    check(program, "the rollback program", false)?;
    if let Some(dir) = program.parent() {
        check(dir, "its directory", true)?;
    }
    Ok(())
}

/// Clear the ambient capability set of the calling process
/// (`PR_CAP_AMBIENT_CLEAR_ALL`): run in the child between `fork` and
/// `exec`, so the rollback program does not inherit the executor's ambient
/// CAP_NET_ADMIN (review finding 8; `nft` still needs it, so the
/// executor keeps its own).
#[allow(unsafe_code)]
fn drop_ambient_caps(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt as _;
    extern "C" {
        fn prctl(option: std::ffi::c_int, ...) -> std::ffi::c_int;
    }
    const PR_CAP_AMBIENT: std::ffi::c_int = 47;
    const PR_CAP_AMBIENT_CLEAR_ALL: std::ffi::c_ulong = 4;
    // SAFETY: the closure runs in the forked child before `exec`; it only
    // makes one `prctl(2)` system call (async-signal-safe), with integer
    // arguments, allocating nothing and touching no shared state. A failure
    // fails the spawn (the program is not run with the capability).
    unsafe {
        cmd.pre_exec(|| {
            let zero: std::ffi::c_ulong = 0;
            if prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, zero, zero, zero) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

fn run(program: &Path, args: &[&str], timeout: Duration) -> Result<(), String> {
    program_ok(program)?;
    let mut cmd = std::process::Command::new(program);
    cmd.args(args)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    drop_ambient_caps(&mut cmd);
    let mut child = cmd
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
    // Planned only when it matches the version grammar (never a leading
    // `-`); passed as one `--to-version=<v>` argument either way.
    if !super::version_ok(v) {
        return Err(format!("to_version {v:?} is not a version"));
    }
    let to = format!("--to-version={v}");
    let t = Duration::from_millis(r.timeout_ms);
    run(
        &r.program,
        &["--config", "program", &to, "--request-id", &spec.id],
        t,
    )?;
    run(&r.program, &["--verify", "--config", "program", &to], t)
        .map_err(|e| format!("rolled back but --verify failed: {e}"))?;
    Ok(format!(
        "program rolled back to {v} and verified by the site program"
    ))
}
