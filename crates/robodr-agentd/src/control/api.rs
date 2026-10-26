//! The action-request API: strict request bodies (an allow-list of action
//! classes and parameters, the TTL rules), the Cyber-Jidoka judgment of an
//! action against the robot's current safety state and response policy,
//! the bounded request store and the answers.
//!
//! The SOC only *requests*. `authority` must be `"request"`; no override,
//! force or motion field exists (an unknown field refuses the body); the
//! strongest action is `request_safe_state`, a request the platform's
//! safety controller decides on. An accepted request is offered to an
//! [`ActionExecutor`]; the only one in this crate, [`RecordingExecutor`],
//! executes nothing, so every accepted request is answered
//! [`Status::RecordedNotExecuted`] with `"executed": false`.

use std::collections::{HashMap, VecDeque};

use robodr_events::profile::Profile;
use robodr_events::Severity;
use robodr_responder::policy::MIN_MOTION_FACTOR_FLOOR;
use robodr_responder::{
    check_invariants, OperationalContext, Rationale, ResponseAction, ResponsePlan, ResponsePolicy,
    RestrictTarget, SafetyState, Step,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::auth::API_VERSION;

/// Longest time a time-limited action may stand (24 h).
pub const MAX_TTL_SECONDS: u64 = 86_400;
/// Bounds of the free-text fields (characters).
pub const MAX_REASON_CHARS: usize = 500;
pub const MAX_REQUESTED_BY_CHARS: usize = 100;
/// Longest request id (`[A-Za-z0-9._:-]`).
pub const MAX_REQUEST_ID_LEN: usize = 128;
/// Highest speed cap a `restrict_motion` may name (m/s or rad/s).
pub const MAX_SPEED_CAP: f64 = 10.0;
/// The rule name of the plan an accepted request is checked as (internal:
/// never a finding, so not a `robot.*` rule id).
pub const PLAN_RULE: &str = "control_plane:action_request";

/// The action classes are the responder's vendor-neutral catalog
/// ([`robodr_responder::actions`]): names, ladder step, reversibility and
/// the TTL rule come from there, so the control plane and the planner can
/// never disagree on what an action is (`catalog_matches_the_responder`
/// test). On the wire a request names an action by its namespace-free name
/// (`restrict_motion`); a SOC that registers actions under the catalog's
/// `robot_<name>` wire names maps them back with
/// [`ActionKind::parse_wire`].
pub use robodr_responder::ActionId as ActionKind;

/// Parameters each action may carry (the others refuse every parameter).
pub fn allowed_params(action: ActionKind) -> &'static [&'static str] {
    match action {
        ActionKind::RestrictMotion => &["max_linear_speed", "max_joint_speed", "workspace_zone"],
        ActionKind::QuarantineNode => &["participant_guid", "node"],
        ActionKind::RollbackConfig => &["config", "to_version"],
        ActionKind::IsolateNetwork
        | ActionKind::RecordEvidence
        | ActionKind::SafePause
        | ActionKind::RequestSafeState => &[],
    }
}

/// A refused call: HTTP status, stable code and a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
}

impl ApiError {
    pub fn new(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub fn body(&self) -> Value {
        error_body(self.code, &self.message)
    }
}

pub fn error_body(code: &str, message: &str) -> Value {
    json!({"error": {"code": code, "message": message}})
}

fn bad(code: &'static str, message: impl Into<String>) -> ApiError {
    ApiError::new(400, code, message)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSubmit {
    request_id: String,
    action: String,
    #[serde(default)]
    parameters: Option<RawParams>,
    #[serde(default)]
    ttl_seconds: Option<u64>,
    #[serde(default)]
    reason: Option<String>,
    requested_by: String,
    source: String,
    authority: String,
}

/// Every parameter any action may carry; anything else refuses the body.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawParams {
    max_linear_speed: Option<f64>,
    max_joint_speed: Option<f64>,
    workspace_zone: Option<String>,
    participant_guid: Option<String>,
    node: Option<String>,
    config: Option<String>,
    to_version: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRevert {
    #[serde(default)]
    reason: Option<String>,
    requested_by: String,
}

/// The validated parameters of an action.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Params {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_linear_speed: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_joint_speed: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_zone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub participant_guid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_version: Option<String>,
}

/// One validated action request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRequest {
    pub request_id: String,
    pub action: ActionKind,
    pub parameters: Params,
    pub ttl_seconds: Option<u64>,
    pub reason: String,
    pub requested_by: String,
    pub source: String,
}

impl ActionRequest {
    /// What makes two requests with one id the same request.
    pub fn digest(&self) -> String {
        let canon = serde_json::to_string(&(self.action, &self.parameters, self.ttl_seconds))
            .unwrap_or_default();
        robodr_blackbox::crypto::to_hex(&robodr_blackbox::crypto::sha256(canon.as_bytes()))
    }
}

/// A validated revert body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RevertRequest {
    pub reason: String,
    pub requested_by: String,
}

fn name_ok(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// `[A-Za-z0-9._:-]{1,128}`.
pub fn request_id_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_REQUEST_ID_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}

/// A plain ROS 2 node name: optional leading `/`, 1..=16 segments of
/// `[A-Za-z][A-Za-z0-9_]{0,63}`.
pub fn ros_name_ok(s: &str) -> bool {
    let body = s.strip_prefix('/').unwrap_or(s);
    let segs: Vec<&str> = body.split('/').collect();
    !body.is_empty()
        && segs.len() <= 16
        && segs.iter().all(|seg| {
            let mut b = seg.bytes();
            seg.len() <= 64
                && b.next().is_some_and(|c| c.is_ascii_alphabetic())
                && b.all(|c| c.is_ascii_alphanumeric() || c == b'_')
        })
}

fn guid_ok(s: &str) -> bool {
    (s.len() == 24 || s.len() == 32)
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn text(what: &str, s: &str, max_chars: usize, required: bool) -> Result<String, ApiError> {
    if required && s.trim().is_empty() {
        return Err(bad("invalid_field", format!("{what} is empty")));
    }
    if s.chars().count() > max_chars {
        return Err(bad(
            "invalid_field",
            format!("{what} is longer than {max_chars} characters"),
        ));
    }
    if s.chars().any(char::is_control) {
        return Err(bad(
            "invalid_field",
            format!("{what} contains control characters"),
        ));
    }
    Ok(s.to_string())
}

fn json_error(e: &serde_json::Error) -> ApiError {
    let m = e.to_string();
    let code = if m.contains("unknown field") {
        "unknown_field"
    } else if m.contains("duplicate field") {
        "duplicate_field"
    } else {
        "invalid_request"
    };
    bad(code, robodr_ros2_pipeline::sanitize(&m))
}

/// The body as UTF-8 text holding a JSON object whose `parameters`, if
/// any, is an object (serde would also take a struct written as an array).
fn object_text(body: &[u8]) -> Result<&str, ApiError> {
    let t =
        std::str::from_utf8(body).map_err(|_| bad("invalid_request", "the body is not UTF-8"))?;
    let v: Value = serde_json::from_str(t).map_err(|e| json_error(&e))?;
    let params_ok = v
        .get("parameters")
        .is_none_or(|p| p.is_object() || p.is_null());
    if !v.is_object() || !params_ok {
        return Err(bad(
            "invalid_request",
            "the body must be a JSON object (and parameters an object)",
        ));
    }
    Ok(t)
}

fn speed(what: &str, v: Option<f64>) -> Result<Option<f64>, ApiError> {
    match v {
        None => Ok(None),
        Some(x) if x.is_finite() && x > 0.0 && x <= MAX_SPEED_CAP => Ok(Some(x)),
        Some(_) => Err(bad(
            "invalid_parameter",
            format!(
                "{what} must be in (0, {MAX_SPEED_CAP}]: a cap of 0 is a stop, ask for safe_pause \
                 instead"
            ),
        )),
    }
}

/// Parse and validate a submit body.
pub fn parse_submit(body: &[u8]) -> Result<ActionRequest, ApiError> {
    let text_body = object_text(body)?;
    let raw: RawSubmit = serde_json::from_str(text_body).map_err(|e| json_error(&e))?;
    if raw.authority != "request" {
        return Err(bad(
            "authority_not_allowed",
            "authority must be \"request\": the SOC requests, the robot decides; there is no \
             override",
        ));
    }
    let action = ActionKind::parse(&raw.action).ok_or_else(|| {
        bad(
            "unknown_action",
            format!(
                "action {:?} is not one of {:?}",
                robodr_ros2_pipeline::sanitize(&raw.action),
                ActionKind::ALL.map(ActionKind::as_str)
            ),
        )
    })?;
    if !request_id_ok(&raw.request_id) {
        return Err(bad(
            "invalid_request_id",
            format!("request_id must match [A-Za-z0-9._:-]{{1,{MAX_REQUEST_ID_LEN}}}"),
        ));
    }
    let p = raw.parameters.unwrap_or_default();
    let present: Vec<&str> = [
        ("max_linear_speed", p.max_linear_speed.is_some()),
        ("max_joint_speed", p.max_joint_speed.is_some()),
        ("workspace_zone", p.workspace_zone.is_some()),
        ("participant_guid", p.participant_guid.is_some()),
        ("node", p.node.is_some()),
        ("config", p.config.is_some()),
        ("to_version", p.to_version.is_some()),
    ]
    .into_iter()
    .filter(|(_, set)| *set)
    .map(|(n, _)| n)
    .collect();
    let stray: Vec<&str> = present
        .iter()
        .copied()
        .filter(|n| !allowed_params(action).contains(n))
        .collect();
    if !stray.is_empty() {
        return Err(bad(
            "parameter_not_allowed",
            format!("{} takes no parameter {stray:?}", action.as_str()),
        ));
    }
    let mut params = Params::default();
    match action {
        ActionKind::RestrictMotion => {
            params.max_linear_speed = speed("max_linear_speed", p.max_linear_speed)?;
            params.max_joint_speed = speed("max_joint_speed", p.max_joint_speed)?;
            if let Some(z) = p.workspace_zone {
                if !name_ok(&z, 64) {
                    return Err(bad(
                        "invalid_parameter",
                        "workspace_zone must match [A-Za-z0-9._-]{1,64}",
                    ));
                }
                params.workspace_zone = Some(z);
            }
            if present.is_empty() {
                return Err(bad(
                    "invalid_parameter",
                    "restrict_motion needs max_linear_speed, max_joint_speed or workspace_zone",
                ));
            }
        }
        ActionKind::QuarantineNode => match (p.participant_guid, p.node) {
            (Some(g), None) if guid_ok(&g) => params.participant_guid = Some(g),
            (None, Some(n)) if ros_name_ok(&n) => params.node = Some(n),
            (Some(_), None) => {
                return Err(bad(
                    "invalid_parameter",
                    "participant_guid must be 24 or 32 lower-case hex",
                ))
            }
            (None, Some(_)) => {
                return Err(bad(
                    "invalid_parameter",
                    "node must be a plain ROS 2 node name",
                ))
            }
            _ => {
                return Err(bad(
                    "invalid_parameter",
                    "quarantine_node needs exactly one of participant_guid, node",
                ))
            }
        },
        ActionKind::RollbackConfig => {
            let kind = p.config.unwrap_or_else(|| "profile".into());
            if kind != "profile" && kind != "program" {
                return Err(bad(
                    "invalid_parameter",
                    "config must be profile or program",
                ));
            }
            params.config = Some(kind);
            if let Some(v) = p.to_version {
                if !name_ok(&v, 64) {
                    return Err(bad(
                        "invalid_parameter",
                        "to_version must match [A-Za-z0-9._-]{1,64}",
                    ));
                }
                params.to_version = Some(v);
            }
        }
        _ => {}
    }
    match (action.time_limited(), raw.ttl_seconds) {
        (true, None) => {
            return Err(bad(
                "ttl_required",
                format!("{} is time-limited: give ttl_seconds", action.as_str()),
            ))
        }
        (true, Some(t)) if !(1..=MAX_TTL_SECONDS).contains(&t) => {
            return Err(bad(
                "ttl_out_of_range",
                format!("ttl_seconds must be 1..={MAX_TTL_SECONDS}"),
            ))
        }
        (false, Some(_)) => {
            return Err(bad(
                "ttl_not_allowed",
                format!(
                    "{} does not expire: lifting it is a person's call; remove ttl_seconds",
                    action.as_str()
                ),
            ))
        }
        _ => {}
    }
    let source = raw.source;
    if source.is_empty()
        || source.len() > 32
        || !source
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        return Err(bad("invalid_field", "source must match [a-z0-9_-]{1,32}"));
    }
    Ok(ActionRequest {
        request_id: raw.request_id,
        action,
        parameters: params,
        ttl_seconds: raw.ttl_seconds,
        reason: text(
            "reason",
            raw.reason.as_deref().unwrap_or(""),
            MAX_REASON_CHARS,
            false,
        )?,
        requested_by: text(
            "requested_by",
            &raw.requested_by,
            MAX_REQUESTED_BY_CHARS,
            true,
        )?,
        source,
    })
}

/// Parse and validate a revert body.
pub fn parse_revert(body: &[u8]) -> Result<RevertRequest, ApiError> {
    let t = object_text(body)?;
    let raw: RawRevert = serde_json::from_str(t).map_err(|e| json_error(&e))?;
    Ok(RevertRequest {
        reason: text(
            "reason",
            raw.reason.as_deref().unwrap_or(""),
            MAX_REASON_CHARS,
            false,
        )?,
        requested_by: text(
            "requested_by",
            &raw.requested_by,
            MAX_REQUESTED_BY_CHARS,
            true,
        )?,
    })
}

/// The smallest speed limits of the profile's motion envelopes, to tell a
/// restriction from a relaxation.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct EnvelopeCaps {
    pub linear: Option<f64>,
    pub joint: Option<f64>,
}

impl EnvelopeCaps {
    pub fn of(profile: &Profile) -> Self {
        let min = |f: fn(&robodr_events::profile::Envelope) -> Option<f64>| {
            profile
                .motion_envelopes
                .values()
                .filter_map(f)
                .filter(|v| v.is_finite() && *v > 0.0)
                .reduce(f64::min)
        };
        Self {
            linear: min(|e| e.max_linear_speed),
            joint: min(|e| e.max_joint_speed),
        }
    }
}

/// What the judgment sees.
#[derive(Debug, Clone, Copy)]
pub struct Situation<'a> {
    pub state: SafetyState,
    pub context: &'a OperationalContext,
    pub policy: &'a ResponsePolicy,
    pub caps: EnvelopeCaps,
}

/// A refusal: a stable code, a reason and the safety state judged against.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Refusal {
    pub code: &'static str,
    pub reason: String,
    pub safety_state: SafetyState,
}

/// An accepted request: its ladder step and the plan actions it stands for.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Accepted {
    pub step: Step,
    pub actions: Vec<ResponseAction>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    Accept(Accepted),
    Refuse(Refusal),
}

/// The highest step the policy's matrix allows in `state` for any severity.
pub fn policy_ceiling(policy: &ResponsePolicy, state: SafetyState) -> Step {
    let r = policy.matrix.row(state);
    [r.low, r.medium, r.high, r.critical]
        .into_iter()
        .max()
        .unwrap_or(Step::Record)
}

fn step_name(s: Step) -> &'static str {
    match s {
        Step::Record => "record",
        Step::Restrict => "restrict",
        Step::LimitMotion => "limit_motion",
        Step::SafePause => "safe_pause",
        Step::RequestSafeState => "request_safe_state",
    }
}

fn state_name(s: SafetyState) -> String {
    serde_json::to_value(s)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".into())
}

/// Judge one request against the robot's current safety state, its
/// operational context and the response policy (Cyber-Jidoka), in order:
///
/// 0. `record_evidence` is evidence capture only (a Record-only plan, it
///    sends nothing to the platform): accepted in every state, including
///    observe mode and while the safety system is engaged;
/// 1. the safety system is engaged (e-stop / safe state): refused, the
///    safety system has authority and gets no competing request;
/// 2. observe mode (profile not locked or policy not OEM-validated):
///    refused, RoboDR only records; a context whose morphology differs from
///    the policy's: refused (`morphology_mismatch`);
/// 3. a motion-affecting step (`limit_motion` and up) while a human holds
///    command (teleop / manual) or in take-off / landing: refused, the
///    person in command decides;
/// 4. an action refused for the robot's morphology
///    ([`ActionKind::refused_for`]): `safe_pause` / `request_safe_state` on
///    a robot that falls when de-energised (humanoid) and `rollback_config`
///    (a controller restart) on any robot that needs active balance
///    (humanoid, quadruped) — refused (`fall_hazard`) whatever the safety
///    state, `idle` included (a legged robot balances while idle);
///    `rollback_config` while the robot is not `idle`: refused (no program
///    or profile change in motion);
/// 5. a step above what the policy's matrix allows in this state for any
///    severity: refused;
/// 6. a `restrict_motion` cap above the profile's envelope: refused (it
///    would not restrict); on a robot that needs active balance, a cap
///    below the policy's `min_motion_factor` of the envelope, or a cap with
///    no envelope to judge it against: refused (`fall_hazard`, a near-stop
///    envelope also stops the balance corrections);
/// 7. the plan it stands for must pass `robodr_responder::check_invariants`
///    (as a human-approved plan: the SOC's approval).
///
/// An `unknown` safety state does not refuse by itself: the planner needs a
/// human's approval there, and a SOC request is human-approved (noted).
pub fn judge(req: &ActionRequest, key_id: &str, s: &Situation<'_>) -> Decision {
    let refuse = |code: &'static str, reason: String| {
        Decision::Refuse(Refusal {
            code,
            reason,
            safety_state: s.state,
        })
    };
    let step = req.action.step();
    let name = state_name(s.state);
    let morphology = s.policy.morphology;
    if req.action == ActionKind::RecordEvidence {
        return Decision::Accept(Accepted {
            step: Step::Record,
            actions: vec![ResponseAction::Record],
            notes: vec![
                "evidence capture only: nothing is sent to the platform (accepted in every \
                 safety state and in observe mode)"
                    .into(),
            ],
        });
    }
    if s.state.safety_system_engaged() {
        return refuse(
            "safety_system_engaged",
            format!(
                "the safety system is engaged ({name}): it has authority, RoboDR sends it no \
                 competing request"
            ),
        );
    }
    if !s.context.profile_locked {
        return refuse(
            "observe_mode",
            "the model profile is not locked and enforced: RoboDR runs observe-only and only \
             records"
                .into(),
        );
    }
    if !s.policy.oem_validated {
        return refuse(
            "observe_mode",
            "the response policy is not OEM-validated: RoboDR runs observe-only and only records"
                .into(),
        );
    }
    if s.context.morphology != morphology {
        return refuse(
            "morphology_mismatch",
            format!(
                "the robot's context says {} but the response policy says {}: RoboDR does not \
                 act on a plan made for another body",
                s.context.morphology.as_str(),
                morphology.as_str()
            ),
        );
    }
    if step.is_motion_affecting() {
        if s.context.control.human_in_command() {
            return refuse(
                "human_in_command",
                "a person is commanding motion (teleop / manual): motion-affecting requests are \
                 theirs to make"
                    .into(),
            );
        }
        if s.context.phase.is_transient() {
            return refuse(
                "transient_phase",
                "take-off / landing: interrupting motion now is itself a hazard".into(),
            );
        }
    }
    if req.action.refused_for(morphology) {
        let why = if req.action == ActionKind::RollbackConfig {
            "restarts the controller whose configuration it rolls back"
        } else {
            "may damp or de-energise the actuators"
        };
        return refuse(
            "fall_hazard",
            format!(
                "{} {why}, and this robot is configured as {} (it balances actively, also while \
                 idle): it would fall. Never executed here; ask the operator / the platform's \
                 own safety function, or use restrict_motion within min_motion_factor",
                req.action.as_str(),
                morphology.as_str()
            ),
        );
    }
    if req.action == ActionKind::RollbackConfig && s.state != SafetyState::Idle {
        return refuse(
            "requires_idle",
            format!("a configuration or program rollback needs an idle robot (now {name})"),
        );
    }
    let ceiling = policy_ceiling(s.policy, s.state);
    if step > ceiling {
        return refuse(
            "above_policy",
            format!(
                "the response policy allows at most {} while {name}; {} is {}",
                step_name(ceiling),
                req.action.as_str(),
                step_name(step)
            ),
        );
    }
    let mut notes = Vec::new();
    let mut actions = vec![ResponseAction::Record];
    match req.action {
        ActionKind::RestrictMotion => {
            let p = &req.parameters;
            let mut factor: f64 = 1.0;
            for (what, want, cap) in [
                ("max_linear_speed", p.max_linear_speed, s.caps.linear),
                ("max_joint_speed", p.max_joint_speed, s.caps.joint),
            ] {
                let Some(want) = want else { continue };
                match cap {
                    Some(cap) if want > cap => {
                        return refuse(
                            "not_a_restriction",
                            format!(
                                "{what} {want} is above the profile's envelope ({cap}): it would \
                                 not restrict"
                            ),
                        )
                    }
                    Some(cap) => factor = factor.min(want / cap),
                    None if morphology.needs_active_balance() => {
                        return refuse(
                            "fall_hazard",
                            format!(
                                "{what}: the profile has no envelope to judge the cap against, \
                                 and this robot ({}) balances actively: a cap that may be a \
                                 near-stop is not accepted",
                                morphology.as_str()
                            ),
                        )
                    }
                    None => notes.push(format!(
                        "{what}: the profile has no envelope to compare with; the cap is \
                         recorded as given"
                    )),
                }
            }
            if !(factor.is_finite() && factor > 0.0 && factor <= 1.0) {
                return refuse(
                    "invalid_parameter",
                    "the requested caps do not give a valid envelope scale".into(),
                );
            }
            let floor = s.policy.min_motion_factor.max(MIN_MOTION_FACTOR_FLOOR);
            if morphology.needs_active_balance() && factor < floor {
                return refuse(
                    "fall_hazard",
                    format!(
                        "the requested caps scale the envelope to {factor} of the profile's, below \
                         this {} robot's min_motion_factor {floor}: a near-stop envelope also \
                         stops the balance corrections it needs",
                        morphology.as_str()
                    ),
                );
            }
            if let Some(z) = &p.workspace_zone {
                notes.push(format!(
                    "workspace_zone {z}: recorded with the request (the plan vocabulary has no \
                     zone; the envelope scale covers speeds only)"
                ));
            }
            actions.push(ResponseAction::LimitMotion { factor });
        }
        ActionKind::QuarantineNode => actions.push(ResponseAction::Restrict {
            target: RestrictTarget::Participant,
            terminate_process: false,
        }),
        ActionKind::IsolateNetwork => actions.push(ResponseAction::Restrict {
            target: RestrictTarget::Network,
            terminate_process: false,
        }),
        ActionKind::SafePause => actions.push(ResponseAction::SafePause {
            behaviour: s.policy.safe_pause,
        }),
        ActionKind::RequestSafeState => actions.push(ResponseAction::RequestSafeState {
            behaviour: s.policy.safe_state,
        }),
        // No ladder action beyond Record: evidence capture is the Record
        // step itself (handled above); the rollback is recorded with the
        // request.
        ActionKind::RecordEvidence | ActionKind::RollbackConfig => {}
    }
    if s.state == SafetyState::Unknown && step.is_motion_affecting() {
        notes.push(
            "safety state unknown: the planner requires a human's approval for this step; the \
             SOC's approval of this request stands for it"
                .into(),
        );
    }
    let max_step = actions
        .iter()
        .map(ResponseAction::step)
        .max()
        .unwrap_or(Step::Record);
    let plan = ResponsePlan {
        rule: PLAN_RULE.into(),
        severity: Severity::High,
        source: format!("soc:{key_id}"),
        safety_state: s.state,
        max_step,
        actions: actions.clone(),
        requires_human_approval: true,
        observe_only: false,
        suppressed: false,
        would_have: None,
        rationale: Rationale::default(),
        morphology: s.policy.morphology,
        advisory: Vec::new(),
    };
    if let Err(v) = check_invariants(&plan, s.state, s.context) {
        return refuse(
            "invariant_violation",
            format!("the plan this request stands for breaks the responder invariant {v}"),
        );
    }
    Decision::Accept(Accepted {
        step,
        actions,
        notes,
    })
}

/// A request's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Accepted, recorded as a plan in the signed black box, **not
    /// executed** (no executor): nothing was sent to the robot.
    RecordedNotExecuted,
    /// Handed to an executor that has not answered (no such executor here).
    Pending,
    /// An executor reports it applied (no such executor here).
    Applied,
    /// Judged unsafe or not allowed in the current state; never retried.
    Refused,
    /// An executor failed (no such executor here).
    Failed,
    // --- executor v1 (robodr-executor, `executor.enabled`) ---------------
    /// The executor applied it and the read-back matched.
    Verified,
    /// The executor removed it again (revert request, TTL, reconciliation).
    Reverted,
}

impl Status {
    /// The request took effect on the robot (applied, verified, or applied
    /// and reverted since).
    pub fn executed(self) -> bool {
        matches!(self, Status::Applied | Status::Verified | Status::Reverted)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Status::RecordedNotExecuted => "recorded_not_executed",
            Status::Pending => "pending",
            Status::Applied => "applied",
            Status::Refused => "refused",
            Status::Failed => "failed",
            Status::Verified => "verified",
            Status::Reverted => "reverted",
        }
    }
}

/// An accepted request offered to an executor.
#[derive(Debug, Clone, Copy)]
pub struct AcceptedAction<'a> {
    pub request: &'a ActionRequest,
    pub key_id: &'a str,
    pub step: Step,
    pub actions: &'a [ResponseAction],
    pub safety_state: SafetyState,
    pub context: &'a OperationalContext,
}

/// What an executor did with an accepted request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutorOutcome {
    RecordedNotExecuted,
    Pending,
    Applied,
    Failed(String),
    // --- executor v1 -------------------------------------------------------
    Verified,
    Reverted,
    /// The executor's own checks refused it (nothing applied).
    Refused {
        code: &'static str,
        reason: String,
    },
}

/// Status, error and refusal a stored request takes for an executor
/// outcome (executor v1).
fn outcome_status(
    out: ExecutorOutcome,
    state: SafetyState,
) -> (Status, Option<String>, Option<Refusal>) {
    match out {
        ExecutorOutcome::RecordedNotExecuted => (Status::RecordedNotExecuted, None, None),
        ExecutorOutcome::Pending => (Status::Pending, None, None),
        ExecutorOutcome::Applied => (Status::Applied, None, None),
        ExecutorOutcome::Failed(e) => (Status::Failed, Some(e), None),
        ExecutorOutcome::Verified => (Status::Verified, None, None),
        ExecutorOutcome::Reverted => (Status::Reverted, None, None),
        ExecutorOutcome::Refused { code, reason } => (
            Status::Refused,
            None,
            Some(Refusal {
                code,
                reason,
                safety_state: state,
            }),
        ),
    }
}

/// Receives accepted requests. A real executor must follow
/// `robodr_agent::executor`'s contract (re-check against the *current*
/// safety state, only request, never block: hand off to its own bounded
/// queue). None exists in this repository.
pub trait ActionExecutor {
    /// Shown in answers and the status (`"recording"`).
    fn name(&self) -> &'static str;
    /// Whether it can act on the robot at all.
    fn executes(&self) -> bool;
    fn submit(&mut self, a: &AcceptedAction<'_>) -> ExecutorOutcome;
    // --- executor v1 -------------------------------------------------------
    /// Ask for a revert of an accepted request; `None` (the default): this
    /// executor cannot revert.
    fn revert(&mut self, _request_id: &str, _reason: &str) -> Option<ExecutorOutcome> {
        None
    }
    /// The executor's latest word on a request it was given (`None`:
    /// nothing new). Asked before a request's state is answered.
    fn refresh(&mut self, _request_id: &str) -> Option<ExecutorOutcome> {
        None
    }
}

/// Executes nothing: every accepted request stays a recorded plan.
#[derive(Debug, Default, Clone, Copy)]
pub struct RecordingExecutor;

impl ActionExecutor for RecordingExecutor {
    fn name(&self) -> &'static str {
        "recording"
    }
    fn executes(&self) -> bool {
        false
    }
    fn submit(&mut self, _: &AcceptedAction<'_>) -> ExecutorOutcome {
        ExecutorOutcome::RecordedNotExecuted
    }
}

/// One parsed call handed to the engine.
#[derive(Debug, Clone, PartialEq)]
pub enum Call {
    Robot,
    Submit(ActionRequest),
    Get(String),
    Revert(String, RevertRequest),
    /// Authenticated but refused before judgment (bad body): recorded.
    Invalid(ApiError),
    /// Record an evidence export's note (`robodr.control_plane_evidence_export`);
    /// answered `{"evidence": "<reference>"}` or 503 `evidence_unavailable`.
    EvidenceNote(Box<Value>),
}

/// Who sent a call and how (recorded with it, so the black box can prove
/// the request: `body` and the signature re-verify offline).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct Meta {
    pub key_id: String,
    pub nonce: String,
    pub timestamp: u64,
    pub signature: String,
    pub method: String,
    pub target: String,
    pub body: String,
    pub peer: String,
}

/// An answer: HTTP status and JSON body.
#[derive(Debug, Clone, PartialEq)]
pub struct Answer {
    pub status: u16,
    pub body: Value,
}

impl Answer {
    pub fn ok(body: Value) -> Self {
        Self { status: 200, body }
    }
    pub fn error(e: &ApiError) -> Self {
        Self {
            status: e.status,
            body: e.body(),
        }
    }
}

/// What the engine needs from the daemon.
pub trait Host {
    /// The safety state to judge by now (live feed or configuration).
    fn safety_state(&mut self) -> SafetyState;
    /// `"safety_feed"` or `"configuration"`.
    fn safety_source(&self) -> &'static str;
    fn context(&self) -> OperationalContext;
    fn policy(&self) -> &ResponsePolicy;
    fn caps(&self) -> EnvelopeCaps;
    /// `ok`, `degraded` or `unknown`.
    fn health(&self) -> &'static str;
    /// Wall clock, Unix ms.
    fn wall_ms(&self) -> u64;
    /// Append a signed note to the black box; the evidence URI.
    fn record(&mut self, what: &str, note: &Value) -> Result<String, String>;
}

/// A revert attempt, as recorded.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RevertRecord {
    pub requested_by: String,
    pub reason: String,
    pub at_ms: u64,
    pub result: &'static str,
    pub evidence: String,
}

/// A stored request.
#[derive(Debug, Clone, PartialEq)]
pub struct Stored {
    pub request: ActionRequest,
    pub digest: String,
    pub key_id: String,
    pub status: Status,
    pub refusal: Option<Refusal>,
    pub safety_state: SafetyState,
    pub accepted: Option<Accepted>,
    pub error: Option<String>,
    pub received_ms: u64,
    pub evidence: String,
    pub executor: &'static str,
    pub revert: Option<RevertRecord>,
}

/// Engine counters (`status.json`, heartbeat).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct EngineStats {
    pub submitted: u64,
    pub recorded_not_executed: u64,
    pub refused: u64,
    pub duplicates: u64,
    pub conflicts: u64,
    pub reverts: u64,
    pub invalid: u64,
    /// Requests answered `failed` because the black box did not take them.
    pub record_failures: u64,
    /// Oldest requests dropped from the store when it was full.
    pub evicted: u64,
    pub stored: u64,
    /// Requests restored from the journal at start.
    pub restored: u64,
    /// Dangling decisions settled at start from the black box: recorded
    /// (committed) or not (aborted).
    pub resolved_committed: u64,
    pub resolved_aborted: u64,
    /// Damaged journal entries skipped at start.
    pub journal_damaged: u64,
    /// Journal appends / compactions that failed.
    pub journal_errors: u64,
    /// Requests answered `failed` because the journal could not take them.
    pub journal_refusals: u64,
    /// Evidence exports recorded.
    pub evidence_exports: u64,
}

/// The main-thread half: judges, records, stores and answers.
pub struct Engine {
    robot_id: String,
    store: HashMap<String, Stored>,
    order: VecDeque<String>,
    max: usize,
    executor: Box<dyn ActionExecutor>,
    /// The persistent request state (`None`: in memory only, unit tests).
    journal: Option<super::state::RequestJournal>,
    pub stats: EngineStats,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("robot_id", &self.robot_id)
            .field("stored", &self.store.len())
            .field("executor", &self.executor.name())
            .finish()
    }
}

const NOT_EXECUTED_NOTE: &str = "accepted and recorded in the signed black box as a plan; this \
                                 agentd has no executor and sent nothing to the robot";

impl Engine {
    pub fn new(robot_id: &str, max: usize, executor: Box<dyn ActionExecutor>) -> Self {
        Self {
            robot_id: robot_id.to_string(),
            store: HashMap::new(),
            order: VecDeque::new(),
            max: max.max(1),
            executor,
            journal: None,
            stats: EngineStats::default(),
        }
    }

    /// An engine on a persistent journal, with the requests it restored
    /// (oldest first; dangling decisions already resolved).
    pub fn with_journal(
        robot_id: &str,
        max: usize,
        executor: Box<dyn ActionExecutor>,
        journal: super::state::RequestJournal,
        restored: Vec<Stored>,
    ) -> Self {
        let mut e = Self::new(robot_id, max, executor);
        for s in restored {
            e.insert(s);
        }
        e.stats.evicted = 0;
        e.stats.restored = e.store.len() as u64;
        e.journal = Some(journal);
        e.maybe_compact(true);
        e
    }

    /// Compact the journal when it holds more than twice the store (or
    /// `force`).
    fn maybe_compact(&mut self, force: bool) {
        let live = self.store.len();
        let Some(j) = self.journal.as_mut() else {
            return;
        };
        if force || j.lines() > 2 * live + 64 {
            let order = &self.order;
            let store = &self.store;
            if j.compact(order.iter().filter_map(|id| store.get(id)))
                .is_err()
            {
                self.stats.journal_errors += 1;
            }
        }
    }

    /// Append to the journal (if any); `false` on failure (counted).
    fn journal(&mut self, e: &super::state::Entry) -> bool {
        match self.journal.as_mut() {
            None => true,
            Some(j) => {
                if j.append(e).is_ok() {
                    true
                } else {
                    self.stats.journal_errors += 1;
                    false
                }
            }
        }
    }

    pub fn executor_name(&self) -> &'static str {
        self.executor.name()
    }

    // --- executor v1 -------------------------------------------------------
    /// Replace the executor (agentd's `executor.enabled`).
    pub fn set_executor(&mut self, executor: Box<dyn ActionExecutor>) {
        self.executor = executor;
    }

    /// Take the executor's latest word on a stored request. A change is
    /// journalled before it is taken (and answered): a request that read
    /// `verified` still reads `verified` after a restart, when the link's
    /// in-memory outcomes are gone. If the journal does not take it, the
    /// stored state stays as it was (counted in `journal_errors`) and the
    /// next query asks again: no answer claims a state the robot could
    /// forget.
    fn refresh(&mut self, id: &str) {
        let Some(s) = self.store.get(id) else {
            return;
        };
        if !matches!(
            s.status,
            Status::Pending | Status::Applied | Status::Verified
        ) {
            return;
        }
        let Some(out) = self.executor.refresh(id) else {
            return;
        };
        let (status, err, refusal) = outcome_status(out, s.safety_state);
        let error = err.or_else(|| s.error.clone());
        let refusal = refusal.or_else(|| s.refusal.clone());
        if status == s.status && error == s.error && refusal == s.refusal {
            return;
        }
        let entry = super::state::Entry::Executor {
            request_id: id.to_string(),
            status: status.as_str().to_string(),
            error: error.clone(),
            refusal: refusal.as_ref().map(super::state::PRefusal::of),
        };
        if !self.journal(&entry) {
            return;
        }
        if let Some(s) = self.store.get_mut(id) {
            s.status = status;
            s.error = error;
            s.refusal = refusal;
        }
        self.maybe_compact(false);
    }

    /// Take (and journal) the executor's latest word on a request now, not
    /// only when it is next queried (the daemon calls this for every
    /// outcome the executor link reports).
    pub fn sync(&mut self, id: &str) {
        self.refresh(id);
    }

    /// Stored requests this engine's executor may still change (`pending`,
    /// `applied`, `verified`), oldest first: after a restart the executor
    /// is asked for their state.
    pub fn open_executor_requests(&self) -> Vec<String> {
        let name = self.executor.name();
        self.order
            .iter()
            .filter_map(|id| self.store.get(id))
            .filter(|s| {
                s.executor == name
                    && matches!(
                        s.status,
                        Status::Pending | Status::Applied | Status::Verified
                    )
            })
            .map(|s| s.request.request_id.clone())
            .collect()
    }

    pub fn executes(&self) -> bool {
        self.executor.executes()
    }

    pub fn get(&self, request_id: &str) -> Option<&Stored> {
        self.store.get(request_id)
    }

    pub fn handle(&mut self, call: &Call, meta: &Meta, host: &mut dyn Host) -> Answer {
        match call {
            Call::Robot => self.robot(host),
            Call::Submit(req) => self.submit(req, meta, host),
            Call::Get(id) => {
                self.refresh(id);
                match self.store.get(id) {
                    Some(s) => Answer::ok(self.answer(s, false, host.wall_ms())),
                    None => Answer::error(&unknown_request()),
                }
            }
            Call::Revert(id, rv) => self.revert(id, rv, meta, host),
            Call::EvidenceNote(note) => match host.record("control-plane evidence export", note) {
                Ok(uri) => {
                    self.stats.evidence_exports += 1;
                    Answer::ok(json!({"evidence": uri}))
                }
                Err(e) => {
                    self.stats.record_failures += 1;
                    Answer::error(&ApiError::new(
                        503,
                        "evidence_unavailable",
                        format!(
                            "the black box did not take the export note ({}); nothing was \
                                 exported, retry later",
                            robodr_ros2_pipeline::sanitize(&e)
                        ),
                    ))
                }
            },
            Call::Invalid(e) => {
                self.stats.invalid += 1;
                let note = json!({
                    "kind": "robodr.control_plane_rejected",
                    "api": API_VERSION,
                    "error": {"code": e.code, "message": e.message, "status": e.status},
                    "request": meta,
                });
                if host
                    .record("control-plane rejected request", &note)
                    .is_err()
                {
                    self.stats.record_failures += 1;
                }
                Answer::error(e)
            }
        }
    }

    fn robot(&self, host: &mut dyn Host) -> Answer {
        let state = host.safety_state();
        let ctx = host.context();
        let observe = !ctx.profile_locked || !host.policy().oem_validated;
        Answer::ok(json!({
            "robot_id": self.robot_id,
            "online": true,
            "api": API_VERSION,
            "safety_state": {
                "state": state,
                "source": host.safety_source(),
                "safety_system_engaged": state.safety_system_engaged(),
            },
            "mode": if observe { "observe" } else { "enforce" },
            "health": host.health(),
            "executor": self.executor.name(),
            "executes_actions": self.executor.executes(),
            "morphology": host.policy().morphology.as_str(),
            // Only what this robot may be asked for: an action refused for
            // its morphology (`fall_hazard`) is not advertised.
            "actions": ActionKind::ALL
                .into_iter()
                .filter(|a| !a.refused_for(host.policy().morphology))
                .map(ActionKind::as_str)
                .collect::<Vec<_>>(),
        }))
    }

    fn submit(&mut self, req: &ActionRequest, meta: &Meta, host: &mut dyn Host) -> Answer {
        let digest = req.digest();
        self.refresh(&req.request_id);
        if let Some(s) = self.store.get(&req.request_id) {
            if s.digest == digest {
                self.stats.duplicates += 1;
                return Answer::ok(self.answer(s, true, host.wall_ms()));
            }
            self.stats.conflicts += 1;
            return Answer::error(&ApiError::new(
                409,
                "request_id_conflict",
                "this request_id was already used for another action, parameters or ttl",
            ));
        }
        self.stats.submitted += 1;
        let state = host.safety_state();
        let ctx = host.context();
        let decision = judge(
            req,
            &meta.key_id,
            &Situation {
                state,
                context: &ctx,
                policy: host.policy(),
                caps: host.caps(),
            },
        );
        let (status, refusal, accepted, error) = match decision {
            Decision::Refuse(r) => (Status::Refused, Some(r), None, None),
            Decision::Accept(a) => {
                let out = self.executor.submit(&AcceptedAction {
                    request: req,
                    key_id: &meta.key_id,
                    step: a.step,
                    actions: &a.actions,
                    safety_state: state,
                    context: &ctx,
                });
                let (st, err, refusal) = outcome_status(out, state);
                (st, refusal, Some(a), err)
            }
        };
        let received_ms = host.wall_ms();
        let mut stored = Stored {
            request: req.clone(),
            digest,
            key_id: meta.key_id.clone(),
            status,
            refusal: refusal.clone(),
            safety_state: state,
            accepted: accepted.clone(),
            error: error.clone(),
            received_ms,
            evidence: String::new(),
            executor: self.executor.name(),
            revert: None,
        };
        let failed = |code: &str, message: String| {
            Answer::ok(json!({
                "request_id": req.request_id,
                "status": "failed",
                "executed": false,
                "state": {"error": {"code": code, "message": message}}
            }))
        };
        // 1. The journal learns of the decision before anything records it.
        let decision_id = match super::fsutil::random_hex16() {
            Ok(d) => d,
            Err(e) => {
                self.stats.journal_refusals += 1;
                return failed(
                    "state_unavailable",
                    format!("no randomness for a decision id ({e}); nothing was decided"),
                );
            }
        };
        if !self.journal(&super::state::Entry::Begin {
            decision_id: decision_id.clone(),
            stored: super::state::PStored::of(&stored),
        }) {
            self.stats.journal_refusals += 1;
            return failed(
                "state_unavailable",
                "the request journal did not take the request; nothing was decided or stored, \
                 retry later"
                    .into(),
            );
        }
        let note = json!({
            "kind": "robodr.control_plane_request",
            "api": API_VERSION,
            "robot_id": self.robot_id,
            "decision_id": decision_id,
            "request": req,
            "authority": "request",
            "auth": meta,
            "safety_state": state,
            "safety_source": host.safety_source(),
            "context": ctx,
            "policy_oem_validated": host.policy().oem_validated,
            "decision": if refusal.is_some() { "refused" } else { "accepted" },
            "refusal": refusal,
            "plan": accepted,
            "executor": self.executor.name(),
            "executed": status.executed(),
            "status": status.as_str(),
            "error": error,
        });
        // 2. The black box.
        let evidence = match host.record("control-plane request", &note) {
            Ok(uri) => uri,
            Err(e) => {
                // Fail closed: nothing is claimed that is not in evidence.
                self.stats.record_failures += 1;
                // A failed abort is settled at the next start: the black
                // box holds no note with this decision id.
                let _ = self.journal(&super::state::Entry::Abort { decision_id });
                return failed(
                    "evidence_unavailable",
                    format!(
                        "the black box did not take the request ({}); nothing was decided or \
                         stored, retry later",
                        robodr_ros2_pipeline::sanitize(&e)
                    ),
                );
            }
        };
        // 3. Commit. A failed commit is settled at the next start from the
        // black box (the note exists), so the state is still answered.
        let _ = self.journal(&super::state::Entry::Commit {
            decision_id,
            evidence: evidence.clone(),
        });
        match status {
            Status::Refused => self.stats.refused += 1,
            Status::RecordedNotExecuted => self.stats.recorded_not_executed += 1,
            _ => {}
        }
        stored.evidence = evidence;
        let answer = self.answer(&stored, false, received_ms);
        self.insert(stored);
        self.maybe_compact(false);
        Answer::ok(answer)
    }

    fn insert(&mut self, s: Stored) {
        while self.store.len() >= self.max {
            match self.order.pop_front() {
                Some(old) => {
                    if self.store.remove(&old).is_some() {
                        self.stats.evicted += 1;
                    }
                }
                None => break,
            }
        }
        self.order.push_back(s.request.request_id.clone());
        self.store.insert(s.request.request_id.clone(), s);
        self.stats.stored = self.store.len() as u64;
    }

    fn revert(&mut self, id: &str, rv: &RevertRequest, meta: &Meta, host: &mut dyn Host) -> Answer {
        let now = host.wall_ms();
        // executor v1: judge the revert by the executor's latest word (a TTL
        // may have lifted it already).
        self.refresh(id);
        let Some(s) = self.store.get(id) else {
            return Answer::error(&unknown_request());
        };
        self.stats.reverts += 1;
        let (result, refusal): (&'static str, Option<Refusal>) = if !s.request.action.reversible() {
            let reason = if s.request.action == ActionKind::RecordEvidence {
                "record_evidence is evidence capture: evidence is never reverted".to_string()
            } else {
                format!(
                    "{} is not reversible by request: an operator restores the robot",
                    s.request.action.as_str()
                )
            };
            (
                "refused",
                Some(Refusal {
                    code: "not_reversible",
                    reason,
                    safety_state: s.safety_state,
                }),
            )
        } else {
            match s.status {
                Status::RecordedNotExecuted | Status::Refused | Status::Failed => {
                    ("not_applied", None)
                }
                Status::Reverted => ("reverted", None),
                Status::Pending | Status::Applied | Status::Verified => {
                    // executor v1: the executor reverts (or queues it).
                    match self.executor.revert(id, &rv.reason) {
                        Some(ExecutorOutcome::Reverted) => ("reverted", None),
                        Some(ExecutorOutcome::Pending) => ("pending", None),
                        Some(ExecutorOutcome::Failed(_)) => ("failed", None),
                        _ => (
                            "refused",
                            Some(Refusal {
                                code: "revert_unsupported",
                                reason: format!(
                                    "the {} executor cannot revert requests",
                                    self.executor.name()
                                ),
                                safety_state: s.safety_state,
                            }),
                        ),
                    }
                }
            }
        };
        // What changes the stored state is journalled first: the first
        // revert record (`not_applied`, or an executor revert `pending` /
        // `reverted`: the daemon dispatches a staged executor revert only
        // once this record exists) and a status that becomes `reverted`.
        let sets_revert =
            matches!(result, "not_applied" | "pending" | "reverted") && s.revert.is_none();
        let sets_status = result == "reverted" && s.status != Status::Reverted;
        let changes = sets_revert || sets_status;
        let decision_id = if changes {
            let d = match super::fsutil::random_hex16() {
                Ok(d) => d,
                Err(_) => {
                    self.stats.journal_refusals += 1;
                    return Answer::error(&ApiError::new(
                        503,
                        "state_unavailable",
                        "no randomness for a decision id; nothing was recorded, retry later",
                    ));
                }
            };
            let begin = super::state::Entry::RevertBegin {
                decision_id: d.clone(),
                request_id: id.to_string(),
                revert: super::state::PRevert::of(&RevertRecord {
                    requested_by: rv.requested_by.clone(),
                    reason: rv.reason.clone(),
                    at_ms: now,
                    result,
                    evidence: String::new(),
                }),
            };
            if !self.journal(&begin) {
                self.stats.journal_refusals += 1;
                return Answer::error(&ApiError::new(
                    503,
                    "state_unavailable",
                    "the request journal did not take the revert; nothing was recorded, retry \
                     later",
                ));
            }
            Some(d)
        } else {
            None
        };
        let Some(s) = self.store.get(id) else {
            return Answer::error(&unknown_request());
        };
        let note = json!({
            "kind": "robodr.control_plane_revert",
            "api": API_VERSION,
            "robot_id": self.robot_id,
            "decision_id": decision_id,
            "request_id": id,
            "action": s.request.action,
            "revert": rv,
            "auth": meta,
            "request_status": s.status.as_str(),
            "result": result,
            "refusal": refusal,
            "executed": false,
        });
        let evidence = match host.record("control-plane revert", &note) {
            Ok(uri) => uri,
            Err(e) => {
                self.stats.record_failures += 1;
                if let Some(d) = decision_id {
                    let _ = self.journal(&super::state::Entry::RevertAbort { decision_id: d });
                }
                return Answer::ok(json!({
                    "request_id": id,
                    "status": "failed",
                    "executed": false,
                    "state": {"error": {"code": "evidence_unavailable",
                                        "message": robodr_ros2_pipeline::sanitize(&e)}},
                }));
            }
        };
        if let Some(d) = decision_id {
            let _ = self.journal(&super::state::Entry::RevertCommit {
                decision_id: d,
                evidence: evidence.clone(),
            });
        }
        let robot_id = self.robot_id.clone();
        let Some(s) = self.store.get_mut(id) else {
            return Answer::error(&unknown_request());
        };
        if sets_status {
            s.status = Status::Reverted;
        }
        if sets_revert && s.revert.is_none() {
            s.revert = Some(RevertRecord {
                requested_by: rv.requested_by.clone(),
                reason: rv.reason.clone(),
                at_ms: now,
                result,
                evidence: evidence.clone(),
            });
        }
        let mut body = answer_of(s, &robot_id, false, now);
        body["status"] = json!(result);
        body["revert_evidence"] = json!(evidence);
        match refusal {
            Some(r) => body["refusal"] = json!(r),
            None => {
                if let Some(o) = body.as_object_mut() {
                    o.remove("refusal");
                }
            }
        }
        Answer::ok(body)
    }

    fn answer(&self, s: &Stored, duplicate: bool, now_ms: u64) -> Value {
        answer_of(s, &self.robot_id, duplicate, now_ms)
    }
}

fn unknown_request() -> ApiError {
    ApiError::new(
        404,
        "unknown_request",
        "no request with this id on this robot",
    )
}

/// The request-state answer for a stored request.
pub fn answer_of(s: &Stored, robot_id: &str, duplicate: bool, now_ms: u64) -> Value {
    let expires = s
        .request
        .ttl_seconds
        .map(|t| s.received_ms.saturating_add(t.saturating_mul(1000)));
    let mut state = json!({
        "robot_id": robot_id,
        "action": s.request.action,
        "parameters": s.request.parameters,
        "ttl_seconds": s.request.ttl_seconds,
        "requested_by": s.request.requested_by,
        "received_at_ms": s.received_ms,
        "expires_at_ms": expires,
        "expired": expires.is_some_and(|e| now_ms >= e),
        "decision": if s.refusal.is_some() { "refused" } else { "accepted" },
        "safety_state": s.safety_state,
        "executor": s.executor,
        "executed": s.status.executed(),
        "evidence": s.evidence,
    });
    if let Some(a) = &s.accepted {
        state["ladder_step"] = json!(a.step);
        state["plan_actions"] = json!(a.actions);
        if !a.notes.is_empty() {
            state["notes"] = json!(a.notes);
        }
    }
    if s.status == Status::RecordedNotExecuted {
        state["note"] = json!(NOT_EXECUTED_NOTE);
    }
    if let Some(e) = &s.error {
        state["error"] = json!(e);
    }
    if let Some(r) = &s.revert {
        state["revert"] = json!(r);
    }
    let mut out = json!({
        "request_id": s.request.request_id,
        "status": s.status.as_str(),
        "executed": s.status.executed(),
        "state": state,
    });
    if duplicate {
        out["duplicate"] = json!(true);
    }
    if let Some(r) = &s.refusal {
        out["refusal"] = json!(r);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use robodr_responder::{Connectivity, ControlMode, MissionPhase, Morphology, PlatformFamily};

    fn ctx() -> OperationalContext {
        OperationalContext {
            platform: PlatformFamily::Ugv,
            morphology: Morphology::WheeledMobile,
            phase: MissionPhase::Transit,
            connectivity: Connectivity::Connected,
            control: ControlMode::Autonomous,
            operator_present: true,
            profile_locked: true,
        }
    }

    fn policy() -> ResponsePolicy {
        let mut p = ResponsePolicy::conservative_default(PlatformFamily::Ugv);
        p.oem_validated = true;
        p.morphology = Morphology::WheeledMobile;
        p
    }

    /// A policy and matching context for morphology `m`.
    fn body_plan(m: Morphology) -> (OperationalContext, ResponsePolicy) {
        let mut p = policy();
        p.morphology = m;
        (
            OperationalContext {
                morphology: m,
                ..ctx()
            },
            p,
        )
    }

    fn body(action: &str, params: Value, ttl: Option<u64>) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "request_id": "robot_x:ugv-007:0123456789abcdef",
            "action": action,
            "parameters": params,
            "ttl_seconds": ttl,
            "reason": "rogue writer on /cmd_vel",
            "requested_by": "analyst@soc",
            "source": "soc-a",
            "authority": "request",
        }))
        .unwrap()
    }

    fn code(r: Result<ActionRequest, ApiError>) -> &'static str {
        r.expect_err("refused").code
    }

    #[test]
    fn every_class_parses_with_its_own_parameters() {
        let ok = [
            body(
                "restrict_motion",
                json!({"max_linear_speed": 0.5}),
                Some(600),
            ),
            body(
                "restrict_motion",
                json!({"workspace_zone": "zone-a"}),
                Some(1),
            ),
            body(
                "quarantine_node",
                json!({"participant_guid": "0110a2b3c4d5e6f701000000"}),
                None,
            ),
            body(
                "quarantine_node",
                json!({"node": "/rogue/teleop_node"}),
                None,
            ),
            body("isolate_network", json!({}), Some(86_400)),
            body("safe_pause", json!({}), None),
            body("request_safe_state", json!({}), None),
            body(
                "rollback_config",
                json!({"config": "program", "to_version": "v1.2"}),
                None,
            ),
            body("rollback_config", json!({}), None),
        ];
        for b in ok {
            let r = parse_submit(&b);
            assert!(r.is_ok(), "{}: {r:?}", String::from_utf8_lossy(&b));
        }
        let r = parse_submit(&body("rollback_config", json!({}), None)).unwrap();
        assert_eq!(r.parameters.config.as_deref(), Some("profile"));
        // Absent parameters are an empty object.
        let mut v: Value = serde_json::from_slice(&body("safe_pause", json!({}), None)).unwrap();
        v.as_object_mut().unwrap().remove("parameters");
        assert!(parse_submit(&serde_json::to_vec(&v).unwrap()).is_ok());
    }

    #[test]
    fn allow_list_refuses_everything_else() {
        assert_eq!(
            code(parse_submit(&body("fly_away", json!({}), None))),
            "unknown_action"
        );
        assert_eq!(
            code(parse_submit(&body("robot_safe_pause", json!({}), None))),
            "unknown_action"
        );
        // A motion command, force or override never reaches the judgment.
        assert_eq!(
            code(parse_submit(&body(
                "safe_pause",
                json!({"linear_x": 1.0}),
                None
            ))),
            "unknown_field"
        );
        assert_eq!(
            code(parse_submit(&body(
                "request_safe_state",
                json!({"force": true}),
                None
            ))),
            "unknown_field"
        );
        assert_eq!(
            code(parse_submit(&body(
                "safe_pause",
                json!({"max_linear_speed": 0.5}),
                None
            ))),
            "parameter_not_allowed"
        );
        assert_eq!(
            code(parse_submit(&body(
                "restrict_motion",
                json!({"node": "/a"}),
                Some(10)
            ))),
            "parameter_not_allowed"
        );
        let mut v: Value = serde_json::from_slice(&body("safe_pause", json!({}), None)).unwrap();
        v["authority"] = json!("override");
        assert_eq!(
            code(parse_submit(&serde_json::to_vec(&v).unwrap())),
            "authority_not_allowed"
        );
        v["authority"] = json!("request");
        v["override"] = json!(true);
        assert_eq!(
            code(parse_submit(&serde_json::to_vec(&v).unwrap())),
            "unknown_field"
        );
        // Duplicate keys refuse the body.
        let dup = br#"{"request_id":"a","action":"safe_pause","action":"request_safe_state","requested_by":"x","source":"s","authority":"request"}"#;
        assert_eq!(code(parse_submit(dup)), "duplicate_field");
        assert_eq!(code(parse_submit(b"\xff")), "invalid_request");
        assert_eq!(code(parse_submit(b"[]")), "invalid_request");
    }

    #[test]
    fn parameter_values_are_checked() {
        for p in [
            json!({"max_linear_speed": 0.0}),
            json!({"max_linear_speed": -1.0}),
            json!({"max_linear_speed": 11.0}),
            json!({"workspace_zone": "a b"}),
            json!({}),
        ] {
            assert_eq!(
                code(parse_submit(&body("restrict_motion", p.clone(), Some(5)))),
                "invalid_parameter",
                "{p}"
            );
        }
        for p in [
            json!({"participant_guid": "0110A2B3C4D5E6F701000000"}),
            json!({"participant_guid": "01"}),
            json!({"node": "1bad"}),
            json!({"node": "/a/../b"}),
            json!({"node": "/a", "participant_guid": "0110a2b3c4d5e6f701000000"}),
            json!({}),
        ] {
            assert_eq!(
                code(parse_submit(&body("quarantine_node", p.clone(), None))),
                "invalid_parameter",
                "{p}"
            );
        }
        assert_eq!(
            code(parse_submit(&body(
                "rollback_config",
                json!({"config": "firmware"}),
                None
            ))),
            "invalid_parameter"
        );
        let mut v: Value = serde_json::from_slice(&body("safe_pause", json!({}), None)).unwrap();
        v["request_id"] = json!("a/b");
        assert_eq!(
            code(parse_submit(&serde_json::to_vec(&v).unwrap())),
            "invalid_request_id"
        );
        v["request_id"] = json!("ok");
        v["reason"] = json!("line\nbreak");
        assert_eq!(
            code(parse_submit(&serde_json::to_vec(&v).unwrap())),
            "invalid_field"
        );
        v["reason"] = json!("x".repeat(501));
        assert_eq!(
            code(parse_submit(&serde_json::to_vec(&v).unwrap())),
            "invalid_field"
        );
        v["reason"] = json!("");
        v["requested_by"] = json!(" ");
        assert_eq!(
            code(parse_submit(&serde_json::to_vec(&v).unwrap())),
            "invalid_field"
        );
        v["requested_by"] = json!("a");
        v["source"] = json!("SOC A");
        assert_eq!(
            code(parse_submit(&serde_json::to_vec(&v).unwrap())),
            "invalid_field"
        );
    }

    #[test]
    fn ttl_rules() {
        assert_eq!(
            code(parse_submit(&body(
                "restrict_motion",
                json!({"max_linear_speed": 1.0}),
                None
            ))),
            "ttl_required"
        );
        assert_eq!(
            code(parse_submit(&body("isolate_network", json!({}), None))),
            "ttl_required"
        );
        assert_eq!(
            code(parse_submit(&body(
                "isolate_network",
                json!({}),
                Some(86_401)
            ))),
            "ttl_out_of_range"
        );
        assert_eq!(
            code(parse_submit(&body("isolate_network", json!({}), Some(0)))),
            "ttl_out_of_range"
        );
        for a in [
            "quarantine_node",
            "safe_pause",
            "request_safe_state",
            "rollback_config",
        ] {
            let p = if a == "quarantine_node" {
                json!({"node": "/x"})
            } else {
                json!({})
            };
            assert_eq!(
                code(parse_submit(&body(a, p, Some(60)))),
                "ttl_not_allowed",
                "{a}"
            );
        }
        let mut v: Value =
            serde_json::from_slice(&body("isolate_network", json!({}), None)).unwrap();
        v["ttl_seconds"] = json!(1.5);
        assert_eq!(
            code(parse_submit(&serde_json::to_vec(&v).unwrap())),
            "invalid_request"
        );
    }

    fn req(action: &str, params: Value, ttl: Option<u64>) -> ActionRequest {
        parse_submit(&body(action, params, ttl)).unwrap()
    }

    fn judged(
        r: &ActionRequest,
        state: SafetyState,
        c: &OperationalContext,
        p: &ResponsePolicy,
    ) -> Decision {
        judged_caps(
            r,
            state,
            c,
            p,
            EnvelopeCaps {
                linear: Some(1.0),
                joint: None,
            },
        )
    }

    fn judged_caps(
        r: &ActionRequest,
        state: SafetyState,
        c: &OperationalContext,
        p: &ResponsePolicy,
        caps: EnvelopeCaps,
    ) -> Decision {
        judge(
            r,
            "soc-1",
            &Situation {
                state,
                context: c,
                policy: p,
                caps,
            },
        )
    }

    fn refusal(d: Decision) -> &'static str {
        match d {
            Decision::Refuse(r) => r.code,
            Decision::Accept(a) => panic!("accepted: {a:?}"),
        }
    }

    /// A request for `a` with the parameters and TTL it needs.
    fn valid_req(a: ActionKind) -> ActionRequest {
        match a {
            ActionKind::RestrictMotion => req(
                "restrict_motion",
                json!({"max_linear_speed": 0.5}),
                Some(60),
            ),
            ActionKind::QuarantineNode => req("quarantine_node", json!({"node": "/n"}), None),
            ActionKind::IsolateNetwork => req("isolate_network", json!({}), Some(60)),
            _ => req(a.as_str(), json!({}), None),
        }
    }

    #[test]
    fn catalog_matches_the_responder() {
        use robodr_responder::actions::{ActionId, CATALOG};
        // One list: every catalog action is accepted by the request parser
        // under its catalog name, and nothing else is.
        assert_eq!(ActionKind::ALL, ActionId::ALL);
        assert_eq!(ActionKind::ALL.len(), CATALOG.len());
        for spec in CATALOG {
            let a = ActionKind::parse(spec.name).expect("catalog name parses");
            assert_eq!(a, spec.id);
            assert_eq!(a.step(), spec.step);
            assert_eq!(a.reversible(), spec.reversible);
            assert_eq!(a.time_limited(), spec.time_limited);
            assert!(!spec.autonomous);
            let r = valid_req(a);
            assert_eq!(r.action, a, "{}", spec.name);
            assert_eq!(serde_json::to_value(r.action).unwrap(), json!(spec.name));
        }
        for wire in CATALOG.map(|c| c.wire_name) {
            assert_eq!(
                code(parse_submit(&body(wire, json!({}), None))),
                "unknown_action",
                "the request names the action, not its wire name: {wire}"
            );
        }
    }

    #[test]
    fn record_evidence_is_accepted_as_a_record_only_plan() {
        let r = req("record_evidence", json!({}), None);
        assert_eq!(r.action, ActionKind::RecordEvidence);
        assert_eq!(
            code(parse_submit(&body(
                "record_evidence",
                json!({"node": "/n"}),
                None
            ))),
            "parameter_not_allowed"
        );
        assert_eq!(
            code(parse_submit(&body("record_evidence", json!({}), Some(60)))),
            "ttl_not_allowed"
        );
        match judged(&r, SafetyState::MovingFast, &ctx(), &policy()) {
            Decision::Accept(a) => {
                assert_eq!(a.actions, vec![ResponseAction::Record]);
            }
            Decision::Refuse(x) => panic!("refused: {x:?}"),
        }
    }

    #[test]
    fn humanoid_refuses_de_energising_actions() {
        let (c, p) = body_plan(Morphology::Humanoid);
        for a in ActionKind::ALL {
            let r = valid_req(a);
            let d = judged(&r, SafetyState::MovingSlow, &c, &p);
            if a.may_de_energise() {
                assert_eq!(refusal(d), "fall_hazard", "{a:?}");
            } else {
                assert!(
                    !matches!(d, Decision::Refuse(ref x) if x.code == "fall_hazard"),
                    "{a:?}"
                );
            }
        }
        // Every other morphology keeps its safe pause.
        for m in Morphology::ALL {
            if m.falls_when_de_energised() {
                continue;
            }
            let (c, p) = body_plan(m);
            let r = req("safe_pause", json!({}), None);
            assert!(
                matches!(
                    judged(&r, SafetyState::MovingSlow, &c, &p),
                    Decision::Accept(_)
                ),
                "{m:?}"
            );
        }
    }

    #[test]
    fn balancing_robots_refuse_rollback_even_when_idle() {
        // M3 / H2: a rollback restarts the controller; a legged robot
        // reports idle while it balances.
        let rb = req("rollback_config", json!({}), None);
        for m in [Morphology::Humanoid, Morphology::Quadruped] {
            let (c, p) = body_plan(m);
            let d = judged(&rb, SafetyState::Idle, &c, &p);
            assert_eq!(refusal(d), "fall_hazard", "{m:?}");
        }
        let (c, p) = body_plan(Morphology::WheeledMobile);
        assert!(matches!(
            judged(&rb, SafetyState::Idle, &c, &p),
            Decision::Accept(_)
        ));
    }

    #[test]
    fn balancing_robots_refuse_near_stop_motion_caps() {
        // M2: a near-zero joint speed cap makes a balancing robot fall.
        let caps = EnvelopeCaps {
            linear: Some(1.0),
            joint: Some(2.0),
        };
        let tiny = req(
            "restrict_motion",
            json!({"max_joint_speed": 1e-9}),
            Some(60),
        );
        let ok = req("restrict_motion", json!({"max_joint_speed": 1.0}), Some(60));
        for m in [Morphology::Humanoid, Morphology::Quadruped] {
            let (c, p) = body_plan(m);
            let d = judged_caps(&tiny, SafetyState::MovingSlow, &c, &p, caps);
            assert_eq!(refusal(d), "fall_hazard", "{m:?}");
            // 0.39 of the envelope: below the 0.4 the OEM configured.
            let mut q = p.clone();
            q.min_motion_factor = 0.4;
            q.limit_motion_factor = 0.5;
            let low = req(
                "restrict_motion",
                json!({"max_joint_speed": 0.78}),
                Some(60),
            );
            assert_eq!(
                refusal(judged_caps(&low, SafetyState::MovingSlow, &c, &q, caps)),
                "fall_hazard"
            );
            match judged_caps(&ok, SafetyState::MovingSlow, &c, &p, caps) {
                Decision::Accept(a) => assert_eq!(
                    a.actions,
                    vec![
                        ResponseAction::Record,
                        ResponseAction::LimitMotion { factor: 0.5 }
                    ]
                ),
                d => panic!("{m:?}: {d:?}"),
            }
            // No envelope to judge a joint cap against: refused, not
            // recorded as given.
            let none = EnvelopeCaps {
                linear: Some(1.0),
                joint: None,
            };
            assert_eq!(
                refusal(judged_caps(&ok, SafetyState::MovingSlow, &c, &p, none)),
                "fall_hazard"
            );
        }
        // A wheeled robot may be slowed to a crawl.
        let (c, p) = body_plan(Morphology::WheeledMobile);
        assert!(matches!(
            judged_caps(&tiny, SafetyState::MovingSlow, &c, &p, caps),
            Decision::Accept(_)
        ));
    }

    #[test]
    fn record_evidence_is_accepted_in_observe_mode_and_while_engaged() {
        // L3: evidence capture sends nothing to the platform.
        let r = req("record_evidence", json!({}), None);
        let mut observe = ctx();
        observe.profile_locked = false;
        let mut unvalidated = policy();
        unvalidated.oem_validated = false;
        for (state, c, p) in [
            (SafetyState::EStopActive, ctx(), policy()),
            (SafetyState::SafeStateActive, ctx(), policy()),
            (SafetyState::MovingSlow, observe, policy()),
            (SafetyState::MovingSlow, ctx(), unvalidated),
        ] {
            match judged(&r, state, &c, &p) {
                Decision::Accept(a) => assert_eq!(a.actions, vec![ResponseAction::Record]),
                Decision::Refuse(x) => panic!("{state:?}: refused {x:?}"),
            }
        }
        // Everything else is still refused there.
        let q = req("isolate_network", json!({}), Some(60));
        assert_eq!(
            refusal(judged(&q, SafetyState::EStopActive, &ctx(), &policy())),
            "safety_system_engaged"
        );
    }

    #[test]
    fn morphology_mismatch_is_refused() {
        let mut p = policy();
        p.morphology = Morphology::Humanoid;
        let q = req("isolate_network", json!({}), Some(60));
        assert_eq!(
            refusal(judged(&q, SafetyState::MovingSlow, &ctx(), &p)),
            "morphology_mismatch"
        );
    }

    #[test]
    fn engaged_safety_system_refuses_everything_but_evidence() {
        let (c, p) = (ctx(), policy());
        for a in ActionKind::ALL {
            if a == ActionKind::RecordEvidence {
                continue;
            }
            let r = match a {
                ActionKind::RestrictMotion => req(
                    "restrict_motion",
                    json!({"max_linear_speed": 0.5}),
                    Some(60),
                ),
                ActionKind::QuarantineNode => req("quarantine_node", json!({"node": "/n"}), None),
                ActionKind::IsolateNetwork => req("isolate_network", json!({}), Some(60)),
                _ => req(a.as_str(), json!({}), None),
            };
            for s in [SafetyState::EStopActive, SafetyState::SafeStateActive] {
                assert_eq!(
                    refusal(judged(&r, s, &c, &p)),
                    "safety_system_engaged",
                    "{a:?}"
                );
            }
        }
    }

    #[test]
    fn observe_mode_and_human_command_refuse() {
        let r = req("safe_pause", json!({}), None);
        let mut c = ctx();
        c.profile_locked = false;
        assert_eq!(
            refusal(judged(&r, SafetyState::MovingSlow, &c, &policy())),
            "observe_mode"
        );
        let mut p = policy();
        p.oem_validated = false;
        assert_eq!(
            refusal(judged(&r, SafetyState::MovingSlow, &ctx(), &p)),
            "observe_mode"
        );
        let mut c = ctx();
        c.control = ControlMode::Teleop;
        assert_eq!(
            refusal(judged(&r, SafetyState::MovingSlow, &c, &policy())),
            "human_in_command"
        );
        // A non-motion step is still fine with a human in command.
        let q = req("isolate_network", json!({}), Some(60));
        assert!(matches!(
            judged(&q, SafetyState::MovingSlow, &c, &policy()),
            Decision::Accept(_)
        ));
        let mut c = ctx();
        c.phase = MissionPhase::Landing;
        assert_eq!(
            refusal(judged(&r, SafetyState::MovingSlow, &c, &policy())),
            "transient_phase"
        );
    }

    #[test]
    fn policy_ceiling_and_restriction_checks() {
        let (c, p) = (ctx(), policy());
        // Idle row tops out at safe_pause: a safe-state request is above it.
        let r = req("request_safe_state", json!({}), None);
        assert_eq!(
            refusal(judged(&r, SafetyState::Idle, &c, &p)),
            "above_policy"
        );
        assert!(matches!(
            judged(&r, SafetyState::MovingFast, &c, &p),
            Decision::Accept(_)
        ));
        // Rollback only while idle.
        let rb = req("rollback_config", json!({}), None);
        assert_eq!(
            refusal(judged(&rb, SafetyState::MovingSlow, &c, &p)),
            "requires_idle"
        );
        assert!(matches!(
            judged(&rb, SafetyState::Idle, &c, &p),
            Decision::Accept(_)
        ));
        // A cap above the envelope does not restrict.
        let up = req(
            "restrict_motion",
            json!({"max_linear_speed": 2.0}),
            Some(60),
        );
        assert_eq!(
            refusal(judged(&up, SafetyState::MovingSlow, &c, &p)),
            "not_a_restriction"
        );
        let down = req(
            "restrict_motion",
            json!({"max_linear_speed": 0.25}),
            Some(60),
        );
        match judged(&down, SafetyState::MovingSlow, &c, &p) {
            Decision::Accept(a) => {
                assert_eq!(a.step, Step::LimitMotion);
                assert_eq!(
                    a.actions,
                    vec![
                        ResponseAction::Record,
                        ResponseAction::LimitMotion { factor: 0.25 }
                    ]
                );
            }
            d => panic!("{d:?}"),
        }
    }

    #[test]
    fn unknown_state_accepts_with_a_note() {
        let r = req("request_safe_state", json!({}), None);
        match judged(&r, SafetyState::Unknown, &ctx(), &policy()) {
            Decision::Accept(a) => {
                assert_eq!(a.step, Step::RequestSafeState);
                assert!(a.notes.iter().any(|n| n.contains("unknown")), "{a:?}");
            }
            d => panic!("{d:?}"),
        }
    }

    #[test]
    fn plan_vocabulary_tops_at_a_safe_state_request() {
        for a in ActionKind::ALL {
            assert!(a.step() <= Step::RequestSafeState);
        }
    }

    // ---------------------------------------------------------- engine ----

    struct FakeHost {
        state: SafetyState,
        ctx: OperationalContext,
        policy: ResponsePolicy,
        notes: Vec<Value>,
        fail: bool,
        now: u64,
    }

    impl FakeHost {
        fn new(state: SafetyState) -> Self {
            Self {
                state,
                ctx: ctx(),
                policy: policy(),
                notes: Vec::new(),
                fail: false,
                now: 1_000_000,
            }
        }
    }

    impl Host for FakeHost {
        fn safety_state(&mut self) -> SafetyState {
            self.state
        }
        fn safety_source(&self) -> &'static str {
            "configuration"
        }
        fn context(&self) -> OperationalContext {
            self.ctx
        }
        fn policy(&self) -> &ResponsePolicy {
            &self.policy
        }
        fn caps(&self) -> EnvelopeCaps {
            EnvelopeCaps::default()
        }
        fn health(&self) -> &'static str {
            "ok"
        }
        fn wall_ms(&self) -> u64 {
            self.now
        }
        fn record(&mut self, _: &str, note: &Value) -> Result<String, String> {
            if self.fail {
                return Err("black box unavailable".into());
            }
            self.notes.push(note.clone());
            Ok(format!(
                "robodr-blackbox://ugv-007/0/{}?sha256=00",
                self.notes.len()
            ))
        }
    }

    fn meta() -> Meta {
        Meta {
            key_id: "soc-1".into(),
            ..Meta::default()
        }
    }

    fn engine() -> Engine {
        Engine::new("ugv-007", 4, Box::new(RecordingExecutor))
    }

    #[test]
    fn accepted_is_recorded_not_executed() {
        let mut e = engine();
        let mut h = FakeHost::new(SafetyState::MovingSlow);
        let r = req("safe_pause", json!({}), None);
        let a = e.handle(&Call::Submit(r.clone()), &meta(), &mut h);
        assert_eq!(a.status, 200);
        assert_eq!(a.body["status"], "recorded_not_executed");
        assert_eq!(a.body["executed"], false);
        assert_eq!(a.body["state"]["executor"], "recording");
        assert_eq!(a.body["state"]["ladder_step"], "safe_pause");
        assert_eq!(
            a.body["state"]["evidence"],
            "robodr-blackbox://ugv-007/0/1?sha256=00"
        );
        assert!(a.body.get("duplicate").is_none());
        assert_eq!(h.notes.len(), 1);
        let n = &h.notes[0];
        assert_eq!(n["kind"], "robodr.control_plane_request");
        assert_eq!(n["decision"], "accepted");
        assert_eq!(n["executed"], false);
        assert_eq!(n["status"], "recorded_not_executed");
        assert_eq!(n["safety_state"], "moving_slow");
        // Resubmitting returns the stored request, nothing new is recorded.
        let d = e.handle(&Call::Submit(r.clone()), &meta(), &mut h);
        assert_eq!(d.body["duplicate"], true);
        assert_eq!(d.body["status"], "recorded_not_executed");
        assert_eq!(h.notes.len(), 1);
        // The same id for another action is a conflict.
        let mut other = req("request_safe_state", json!({}), None);
        other.request_id = r.request_id.clone();
        assert_eq!(e.handle(&Call::Submit(other), &meta(), &mut h).status, 409);
        // GET answers the same state; unknown ids are 404.
        let g = e.handle(&Call::Get(r.request_id.clone()), &meta(), &mut h);
        assert_eq!(g.body["status"], "recorded_not_executed");
        assert_eq!(
            e.handle(&Call::Get("nope".into()), &meta(), &mut h).status,
            404
        );
        // Revert of a plan that never took effect: not_applied, recorded.
        let rv = RevertRequest {
            reason: "false positive".into(),
            requested_by: "analyst".into(),
        };
        let v = e.handle(
            &Call::Revert(r.request_id.clone(), rv.clone()),
            &meta(),
            &mut h,
        );
        assert_eq!(v.body["status"], "not_applied");
        assert_eq!(v.body["executed"], false);
        assert_eq!(
            h.notes.last().unwrap()["kind"],
            "robodr.control_plane_revert"
        );
        assert_eq!(e.stats.recorded_not_executed, 1);
        assert_eq!(e.stats.duplicates, 1);
        assert_eq!(e.stats.conflicts, 1);
    }

    #[test]
    fn refusal_in_an_unsafe_state_is_recorded_and_answered() {
        let mut e = engine();
        let mut h = FakeHost::new(SafetyState::EStopActive);
        let r = req("request_safe_state", json!({}), None);
        let a = e.handle(&Call::Submit(r.clone()), &meta(), &mut h);
        assert_eq!(a.body["status"], "refused");
        assert_eq!(a.body["refusal"]["code"], "safety_system_engaged");
        assert_eq!(a.body["refusal"]["safety_state"], "estop_active");
        assert_eq!(h.notes[0]["decision"], "refused");
        // An irreversible request is never reverted by request.
        let v = e.handle(
            &Call::Revert(
                r.request_id,
                RevertRequest {
                    reason: String::new(),
                    requested_by: "a".into(),
                },
            ),
            &meta(),
            &mut h,
        );
        assert_eq!(v.body["status"], "refused");
        assert_eq!(v.body["refusal"]["code"], "not_reversible");
    }

    #[test]
    fn no_evidence_no_claim() {
        let mut e = engine();
        let mut h = FakeHost::new(SafetyState::MovingSlow);
        h.fail = true;
        let r = req("safe_pause", json!({}), None);
        let a = e.handle(&Call::Submit(r.clone()), &meta(), &mut h);
        assert_eq!(a.body["status"], "failed");
        assert_eq!(a.body["state"]["error"]["code"], "evidence_unavailable");
        assert!(
            e.get(&r.request_id).is_none(),
            "not stored: a retry is judged anew"
        );
        assert_eq!(e.stats.record_failures, 1);
    }

    #[test]
    fn invalid_calls_are_recorded() {
        let mut e = engine();
        let mut h = FakeHost::new(SafetyState::MovingSlow);
        let err = ApiError::new(400, "unknown_action", "x");
        let a = e.handle(&Call::Invalid(err), &meta(), &mut h);
        assert_eq!(a.status, 400);
        assert_eq!(a.body["error"]["code"], "unknown_action");
        assert_eq!(h.notes[0]["kind"], "robodr.control_plane_rejected");
        assert_eq!(e.stats.invalid, 1);
    }

    #[test]
    fn store_is_bounded() {
        let mut e = engine();
        let mut h = FakeHost::new(SafetyState::MovingSlow);
        for i in 0..6 {
            let mut r = req("safe_pause", json!({}), None);
            r.request_id = format!("r{i}");
            e.handle(&Call::Submit(r), &meta(), &mut h);
        }
        assert_eq!(e.stats.stored, 4);
        assert_eq!(e.stats.evicted, 2);
        assert!(e.get("r0").is_none() && e.get("r5").is_some());
    }

    #[test]
    fn robot_snapshot_says_it_executes_nothing() {
        let e = engine();
        let mut h = FakeHost::new(SafetyState::EStopActive);
        let a = e.robot(&mut h);
        assert_eq!(a.body["online"], true);
        assert_eq!(a.body["safety_state"]["state"], "estop_active");
        assert_eq!(a.body["safety_state"]["safety_system_engaged"], true);
        assert_eq!(a.body["executes_actions"], false);
        assert_eq!(a.body["mode"], "enforce");
        assert_eq!(a.body["actions"].as_array().unwrap().len(), 7);
    }

    #[test]
    fn robot_snapshot_does_not_advertise_refused_actions() {
        // L4: a humanoid never advertises safe_pause / request_safe_state /
        // rollback_config; a quadruped never rollback_config.
        let e = engine();
        for (m, gone) in [
            (
                Morphology::Humanoid,
                &["safe_pause", "request_safe_state", "rollback_config"][..],
            ),
            (Morphology::Quadruped, &["rollback_config"][..]),
            (Morphology::WheeledMobile, &[][..]),
        ] {
            let mut h = FakeHost::new(SafetyState::Idle);
            (h.ctx, h.policy) = body_plan(m);
            let a = e.robot(&mut h);
            let listed: Vec<&str> = a.body["actions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            for g in gone {
                assert!(!listed.contains(g), "{m:?} advertises {g}");
            }
            assert_eq!(listed.len(), 7 - gone.len(), "{m:?}: {listed:?}");
            assert_eq!(a.body["morphology"], m.as_str());
        }
    }

    /// The status mapping a future executor would get (none exists).
    struct Applying;
    impl ActionExecutor for Applying {
        fn name(&self) -> &'static str {
            "test-applying"
        }
        fn executes(&self) -> bool {
            true
        }
        fn submit(&mut self, _: &AcceptedAction<'_>) -> ExecutorOutcome {
            ExecutorOutcome::Applied
        }
    }

    #[test]
    fn executor_outcome_maps_to_the_status() {
        let mut e = Engine::new("ugv-007", 4, Box::new(Applying));
        let mut h = FakeHost::new(SafetyState::MovingSlow);
        let a = e.handle(
            &Call::Submit(req("safe_pause", json!({}), None)),
            &meta(),
            &mut h,
        );
        assert_eq!(a.body["status"], "applied");
        assert_eq!(a.body["executed"], true);
        assert!(a.body["state"].get("note").is_none());
    }

    // --- Persistence: the request journal (state.rs) ---------------------

    use crate::control::fsutil::fault;
    use crate::control::state;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("robodr-cp-st-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The black-box references of `h`'s notes that carry `ids` (what the
    /// daemon's reconciliation finds in the real black box).
    fn found_in(h: &FakeHost, ids: &[String]) -> std::collections::BTreeMap<String, String> {
        let mut out = std::collections::BTreeMap::new();
        for (i, n) in h.notes.iter().enumerate() {
            if let Some(d) = n["decision_id"].as_str() {
                if ids.iter().any(|x| x == d) {
                    out.insert(
                        d.to_string(),
                        format!("robodr-blackbox://ugv-007/0/{}?sha256=00", i + 1),
                    );
                }
            }
        }
        out
    }

    /// Restart: open the journal, settle dangling decisions against `h`.
    fn restart(dir: &std::path::Path, h: &FakeHost, max: usize) -> (Engine, (usize, usize)) {
        let (mut j, mut r) = state::open(dir, max).unwrap();
        let ids: Vec<String> = r
            .pending
            .keys()
            .chain(r.pending_reverts.keys())
            .cloned()
            .collect();
        let settled = state::resolve(&mut j, &mut r, &found_in(h, &ids), max).unwrap();
        (
            Engine::with_journal("ugv-007", max, Box::new(RecordingExecutor), j, r.stored),
            settled,
        )
    }

    fn sub(id: &str, action: &str, params: Value, ttl: Option<u64>) -> Call {
        let mut b: Value = serde_json::from_slice(&body(action, params, ttl)).unwrap();
        b["request_id"] = json!(id);
        Call::Submit(parse_submit(&serde_json::to_vec(&b).unwrap()).unwrap())
    }

    fn get(e: &mut Engine, h: &mut FakeHost, id: &str) -> Answer {
        e.handle(&Call::Get(id.into()), &meta(), h)
    }

    #[test]
    fn request_state_survives_a_restart() {
        let d = tmp("restart");
        let mut h = FakeHost::new(SafetyState::MovingSlow);
        let (mut e, _) = restart(&d, &h, 16);
        let a1 = e.handle(
            &sub(
                "r-1",
                "restrict_motion",
                json!({"max_linear_speed": 0.5}),
                Some(600),
            ),
            &meta(),
            &mut h,
        );
        assert_eq!(a1.body["status"], "recorded_not_executed", "{}", a1.body);
        h.state = SafetyState::EStopActive;
        let a2 = e.handle(&sub("r-2", "safe_pause", json!({}), None), &meta(), &mut h);
        assert_eq!(a2.body["status"], "refused");
        let rv = Call::Revert(
            "r-1".into(),
            parse_revert(br#"{"requested_by": "analyst@soc", "reason": "fp"}"#).unwrap(),
        );
        let a3 = e.handle(&rv, &meta(), &mut h);
        assert_eq!(a3.body["status"], "not_applied");
        let before: Vec<Value> = ["r-1", "r-2"]
            .iter()
            .map(|id| get(&mut e, &mut h, id).body)
            .collect();
        let notes = h.notes.len();
        drop(e);
        // A restart: the same answers, a resubmission is a duplicate (not
        // judged or recorded again), another body under the id a conflict.
        let (mut e, settled) = restart(&d, &h, 16);
        assert_eq!(settled, (0, 0));
        assert_eq!(e.stats.restored, 2);
        for (id, b) in ["r-1", "r-2"].iter().zip(&before) {
            assert_eq!(&get(&mut e, &mut h, id).body, b, "{id}");
        }
        assert!(before[0]["state"]["revert"]["evidence"].is_string());
        let dup = e.handle(
            &sub(
                "r-1",
                "restrict_motion",
                json!({"max_linear_speed": 0.5}),
                Some(600),
            ),
            &meta(),
            &mut h,
        );
        assert_eq!(dup.body["duplicate"], true);
        assert_eq!(h.notes.len(), notes);
        let c = e.handle(
            &sub(
                "r-1",
                "restrict_motion",
                json!({"max_linear_speed": 0.4}),
                Some(600),
            ),
            &meta(),
            &mut h,
        );
        assert_eq!(
            (c.status, c.body["error"]["code"].as_str()),
            (409, Some("request_id_conflict"))
        );
        // The second revert after the restart: the first one is kept.
        let again = e.handle(&rv, &meta(), &mut h);
        assert_eq!(again.body["state"]["revert"], before[0]["state"]["revert"]);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Crash between the black-box note and the journal commit: the
    /// decision is in the black box, so the restart commits it with that
    /// note's reference; the answer the SOC got stays true.
    #[test]
    fn crash_after_the_note_before_the_commit_is_committed_from_the_black_box() {
        let d = tmp("commit");
        let mut h = FakeHost::new(SafetyState::MovingSlow);
        let (mut e, _) = restart(&d, &h, 16);
        // Appends: 1 = begin, 2 = commit (torn: the process dies there).
        fault::arm("journal.append.torn", 2);
        let a = e.handle(&sub("c-1", "safe_pause", json!({}), None), &meta(), &mut h);
        assert!(fault::fired());
        assert_eq!(a.body["status"], "recorded_not_executed");
        drop(e);
        let (mut e, settled) = restart(&d, &h, 16);
        assert_eq!(settled, (1, 0));
        let g = get(&mut e, &mut h, "c-1");
        assert_eq!(g.body["status"], "recorded_not_executed");
        assert_eq!(g.body["state"]["evidence"], a.body["state"]["evidence"]);
        // Settled durably: the next restart has nothing dangling.
        drop(e);
        let (_, settled) = restart(&d, &h, 16);
        assert_eq!(settled, (0, 0));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Crash between the journal begin and the black-box note: nothing was
    /// recorded, so the restart aborts it; a resubmission is judged anew.
    #[test]
    fn crash_after_the_begin_before_the_note_is_aborted() {
        let d = tmp("abort");
        let mut h = FakeHost::new(SafetyState::MovingSlow);
        let (mut e, _) = restart(&d, &h, 16);
        // The black box refuses (no note) and the abort append is torn (the
        // process dies): only the begin is durable.
        h.fail = true;
        fault::arm("journal.append.torn", 2);
        let a = e.handle(&sub("a-1", "safe_pause", json!({}), None), &meta(), &mut h);
        assert_eq!(a.body["status"], "failed");
        assert_eq!(a.body["state"]["error"]["code"], "evidence_unavailable");
        drop(e);
        h.fail = false;
        let (mut e, settled) = restart(&d, &h, 16);
        assert_eq!(settled, (0, 1));
        assert_eq!(get(&mut e, &mut h, "a-1").status, 404);
        let a = e.handle(&sub("a-1", "safe_pause", json!({}), None), &meta(), &mut h);
        assert_eq!(a.body["status"], "recorded_not_executed");
        assert!(a.body.get("duplicate").is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A journal that cannot take the begin refuses the request before
    /// anything is decided or recorded (fail closed).
    #[test]
    fn a_failing_journal_refuses_before_recording() {
        let d = tmp("refuse");
        let mut h = FakeHost::new(SafetyState::MovingSlow);
        let (mut e, _) = restart(&d, &h, 16);
        fault::arm("journal.append.torn", 1);
        let a = e.handle(&sub("f-1", "safe_pause", json!({}), None), &meta(), &mut h);
        assert_eq!(a.body["status"], "failed");
        assert_eq!(a.body["state"]["error"]["code"], "state_unavailable");
        assert!(h.notes.is_empty(), "nothing recorded");
        assert_eq!(e.stats.journal_refusals, 1);
        assert_eq!(get(&mut e, &mut h, "f-1").status, 404);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Crash between a revert's note and its commit: settled from the
    /// black box like a request.
    #[test]
    fn crash_during_a_revert_is_settled_from_the_black_box() {
        let d = tmp("revert");
        let mut h = FakeHost::new(SafetyState::MovingSlow);
        let (mut e, _) = restart(&d, &h, 16);
        e.handle(&sub("v-1", "safe_pause", json!({}), None), &meta(), &mut h);
        // Appends from here: 1 = revert_begin, 2 = revert_commit (torn).
        fault::arm("journal.append.torn", 2);
        let rv = Call::Revert(
            "v-1".into(),
            parse_revert(br#"{"requested_by": "analyst@soc"}"#).unwrap(),
        );
        let a = e.handle(&rv, &meta(), &mut h);
        assert!(fault::fired());
        assert_eq!(a.body["status"], "not_applied");
        drop(e);
        let (mut e, settled) = restart(&d, &h, 16);
        assert_eq!(settled, (1, 0));
        let g = get(&mut e, &mut h, "v-1");
        assert_eq!(
            g.body["state"]["revert"]["evidence"],
            a.body["revert_evidence"]
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The journal is compacted to the live store and keeps the newest
    /// `max_requests` across restarts.
    #[test]
    fn journal_is_bounded_by_compaction() {
        let d = tmp("bounded");
        let mut h = FakeHost::new(SafetyState::MovingSlow);
        let (mut e, _) = restart(&d, &h, 16);
        for i in 0..200 {
            e.handle(
                &sub(&format!("b-{i}"), "safe_pause", json!({}), None),
                &meta(),
                &mut h,
            );
        }
        assert!(e.stats.journal_errors == 0);
        drop(e);
        let lines = std::fs::read_to_string(d.join(state::REQUEST_JOURNAL))
            .unwrap()
            .lines()
            .count();
        assert!(lines <= 2 * 16 + 64 + 3, "{lines}");
        let (mut e, _) = restart(&d, &h, 16);
        assert_eq!(e.stats.restored, 16);
        assert_eq!(get(&mut e, &mut h, "b-199").status, 200);
        assert_eq!(get(&mut e, &mut h, "b-184").status, 200);
        assert_eq!(get(&mut e, &mut h, "b-183").status, 404);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// executor v1 on the v2 journal: an executor that answers through
    /// `refresh` (as `executor_link::ControlExecutor` does).
    #[derive(Clone, Default)]
    struct Scripted(std::sync::Arc<std::sync::Mutex<HashMap<String, ExecutorOutcome>>>);

    impl Scripted {
        fn set(&self, id: &str, o: ExecutorOutcome) {
            self.0.lock().unwrap().insert(id.into(), o);
        }
    }

    impl ActionExecutor for Scripted {
        fn name(&self) -> &'static str {
            "robodr-executor"
        }
        fn executes(&self) -> bool {
            true
        }
        fn submit(&mut self, _: &AcceptedAction<'_>) -> ExecutorOutcome {
            ExecutorOutcome::Pending
        }
        fn revert(&mut self, _: &str, _: &str) -> Option<ExecutorOutcome> {
            Some(ExecutorOutcome::Pending)
        }
        fn refresh(&mut self, id: &str) -> Option<ExecutorOutcome> {
            self.0.lock().unwrap().get(id).cloned()
        }
    }

    /// A restart with the executor link's memory empty (a fresh
    /// [`Scripted`]).
    fn restart_exec(dir: &std::path::Path, h: &FakeHost, x: &Scripted) -> Engine {
        let (mut e, _) = restart(dir, h, 16);
        e.set_executor(Box::new(x.clone()));
        e
    }

    #[test]
    fn executor_states_are_journalled_and_survive_a_restart() {
        let d = tmp("exec");
        let mut h = FakeHost::new(SafetyState::Idle);
        let x = Scripted::default();
        let mut e = restart_exec(&d, &h, &x);
        let a = e.handle(
            &sub("x-1", "isolate_network", json!({}), Some(600)),
            &meta(),
            &mut h,
        );
        assert_eq!(a.body["status"], "pending", "{}", a.body);
        e.handle(
            &sub(
                "x-2",
                "quarantine_node",
                json!({"node": "/rogue/teleop_node"}),
                None,
            ),
            &meta(),
            &mut h,
        );
        e.handle(
            &sub("x-3", "isolate_network", json!({}), Some(60)),
            &meta(),
            &mut h,
        );
        // x-1 verified (queried), x-2 verified and only synced (nobody
        // asked), x-3 refused by the executor's own check.
        x.set("x-1", ExecutorOutcome::Verified);
        x.set("x-2", ExecutorOutcome::Verified);
        x.set(
            "x-3",
            ExecutorOutcome::Refused {
                code: "no_management_channel",
                reason: "no management channel".into(),
            },
        );
        let v1 = get(&mut e, &mut h, "x-1").body;
        assert_eq!(v1["status"], "verified");
        assert_eq!(v1["executed"], true);
        e.sync("x-2");
        let v3 = get(&mut e, &mut h, "x-3").body;
        assert_eq!(v3["refusal"]["code"], "no_management_channel", "{v3}");
        assert_eq!(
            e.open_executor_requests(),
            vec!["x-1".to_string(), "x-2".to_string()]
        );
        drop(e);

        // Restart: the link knows nothing; the journal does.
        let x = Scripted::default();
        let mut e = restart_exec(&d, &h, &x);
        assert_eq!(get(&mut e, &mut h, "x-1").body, v1);
        assert_eq!(get(&mut e, &mut h, "x-2").body["status"], "verified");
        assert_eq!(get(&mut e, &mut h, "x-3").body, v3);
        // A revert: staged (`pending`), then the executor reports it.
        let rv = Call::Revert(
            "x-1".into(),
            parse_revert(br#"{"requested_by": "analyst@soc", "reason": "done"}"#).unwrap(),
        );
        assert_eq!(e.handle(&rv, &meta(), &mut h).body["status"], "pending");
        x.set("x-1", ExecutorOutcome::Reverted);
        let r1 = get(&mut e, &mut h, "x-1").body;
        assert_eq!(r1["status"], "reverted");
        assert_eq!(r1["state"]["revert"]["result"], "pending");
        // Asked again: already reverted, nothing new is journalled.
        assert_eq!(e.handle(&rv, &meta(), &mut h).body["status"], "reverted");
        drop(e);
        let x = Scripted::default();
        let mut e = restart_exec(&d, &h, &x);
        assert_eq!(get(&mut e, &mut h, "x-1").body, r1);
        assert_eq!(e.stats.journal_damaged, 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A journal that cannot take the executor's word keeps the stored
    /// state (never answered, so never forgotten); the next query retries.
    #[test]
    fn an_executor_state_the_journal_does_not_take_is_not_answered() {
        let d = tmp("exec-fail");
        let mut h = FakeHost::new(SafetyState::Idle);
        let x = Scripted::default();
        let mut e = restart_exec(&d, &h, &x);
        e.handle(
            &sub("y-1", "isolate_network", json!({}), Some(60)),
            &meta(),
            &mut h,
        );
        x.set("y-1", ExecutorOutcome::Verified);
        fault::arm("survive.journal.append.short_write", 1);
        assert_eq!(get(&mut e, &mut h, "y-1").body["status"], "pending");
        assert_eq!(e.stats.journal_errors, 1);
        assert_eq!(get(&mut e, &mut h, "y-1").body["status"], "verified");
        drop(e);
        let mut e = restart_exec(&d, &h, &Scripted::default());
        assert_eq!(get(&mut e, &mut h, "y-1").body["status"], "verified");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn persisted_entries_that_do_not_convert_back_are_damage() {
        let d = tmp("convert");
        let mut h = FakeHost::new(SafetyState::MovingSlow);
        let (mut e, _) = restart(&d, &h, 16);
        e.handle(&sub("k-1", "safe_pause", json!({}), None), &meta(), &mut h);
        drop(e);
        // A snapshot with a refusal code this code never writes.
        let (mut j, r) = state::open(&d, 16).unwrap();
        let mut p = state::PStored::of(&r.stored[0]);
        p.request.request_id = "k-2".into();
        p.refusal = Some(state::PRefusal {
            code: "override_granted".into(),
            reason: String::new(),
            safety_state: SafetyState::MovingSlow,
        });
        j.append(&state::Entry::Stored { stored: p }).unwrap();
        drop(j);
        let (_, r) = state::open(&d, 16).unwrap();
        assert_eq!(r.stored.len(), 1);
        assert_eq!(r.damaged, 1);
        let _ = std::fs::remove_dir_all(&d);
    }
}
