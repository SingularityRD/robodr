//! Per-model response policy: the severity x safety-state matrix, rule
//! overrides, platform safe behaviours and escalation tuning.
//!
//! A policy is data (JSON), written with and validated by the OEM for one
//! robot model. [`ResponsePolicy::validate`] rejects any policy that tries to
//! exceed the crate's invariants (anything but `record` while the safety
//! system is engaged, a safe behaviour that makes no physical sense for the
//! platform, a motion factor outside `(0, 1]`, unbounded tables). The planner
//! *also* enforces every invariant at plan time, so a policy that slipped past
//! validation still cannot cause an unsafe plan.

use std::collections::BTreeSet;
use std::fmt;

use robodr_events::Severity;
use serde::{Deserialize, Serialize};

use crate::action::{RestrictTarget, SafeBehaviour, Step};
use crate::state::{PlatformFamily, SafetyState};

/// Schema tag every policy file must carry.
pub const SCHEMA: &str = "robodr.response-policy/v1";

/// Hard caps that keep a policy (and the planner's memory) bounded.
pub const MAX_RULE_OVERRIDES: usize = 256;
pub const MAX_RULE_ID_LEN: usize = 128;
pub const MAX_MODEL_LEN: usize = 128;
/// Upper bound on the escalation threshold (also the per-source hit buffer).
pub const MAX_ESCALATION_THRESHOLD: u32 = 64;
/// Repeated deviations can never raise a plan by more than this many rungs.
pub const MAX_ESCALATION_STEPS: u8 = 2;
/// One day: upper bound for any time window, to reject nonsense values.
pub const MAX_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;

/// Max ladder step for each severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeverityRow {
    pub low: Step,
    pub medium: Step,
    pub high: Step,
    pub critical: Step,
}

impl SeverityRow {
    pub const fn uniform(s: Step) -> Self {
        SeverityRow {
            low: s,
            medium: s,
            high: s,
            critical: s,
        }
    }

    pub fn get(&self, sev: Severity) -> Step {
        match sev {
            Severity::Low => self.low,
            Severity::Medium => self.medium,
            Severity::High => self.high,
            Severity::Critical => self.critical,
        }
    }

    fn cells(&self) -> [Step; 4] {
        [self.low, self.medium, self.high, self.critical]
    }
}

/// The full severity x safety-state matrix. Every state must be present
/// (`deny_unknown_fields` + no defaults), so a policy cannot silently omit one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Matrix {
    pub idle: SeverityRow,
    pub moving_slow: SeverityRow,
    pub moving_fast: SeverityRow,
    pub collaborative_human_nearby: SeverityRow,
    pub estop_active: SeverityRow,
    pub safe_state_active: SeverityRow,
    pub unknown: SeverityRow,
}

impl Matrix {
    pub fn row(&self, state: SafetyState) -> &SeverityRow {
        match state {
            SafetyState::Idle => &self.idle,
            SafetyState::MovingSlow => &self.moving_slow,
            SafetyState::MovingFast => &self.moving_fast,
            SafetyState::CollaborativeHumanNearby => &self.collaborative_human_nearby,
            SafetyState::EStopActive => &self.estop_active,
            SafetyState::SafeStateActive => &self.safe_state_active,
            SafetyState::Unknown => &self.unknown,
        }
    }

    pub fn get(&self, sev: Severity, state: SafetyState) -> Step {
        self.row(state).get(sev)
    }
}

/// Per-rule override. The matrix step for this rule is clamped into
/// `[min_step, max_step]`; `restrict`, if given, replaces the default
/// restrict targets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleOverride {
    pub rule: String,
    #[serde(default = "step_record")]
    pub min_step: Step,
    #[serde(default = "step_top")]
    pub max_step: Step,
    #[serde(default)]
    pub restrict: Option<Vec<RestrictTarget>>,
}

fn step_record() -> Step {
    Step::Record
}
fn step_top() -> Step {
    Step::RequestSafeState
}

/// Escalation and hysteresis tuning. Times are milliseconds on the caller's
/// monotonic clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscalationPolicy {
    /// Window in which repeated deviations from one source are counted.
    pub window_ms: u64,
    /// Deviations within `window_ms` that raise the source one rung.
    pub threshold: u32,
    /// Maximum rungs escalation may add (<= [`MAX_ESCALATION_STEPS`]).
    pub max_escalation_steps: u8,
    /// Escalation never pushes a plan above this step on its own.
    pub ceiling: Step,
    /// No deviation from a source for this long resets it (de-escalation).
    pub quiet_period_ms: u64,
    /// A plan that is not higher than the last issued one is reduced to
    /// Record if it comes within this interval (rate limit / anti-oscillation).
    pub min_reissue_interval_ms: u64,
}

/// A per-model response policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponsePolicy {
    /// Must equal [`SCHEMA`].
    pub schema: String,
    /// Robot model this policy is for (matches the model profile).
    pub model: String,
    pub platform: PlatformFamily,
    /// Set only after OEM sign-off. While false, every plan is observe-only.
    pub oem_validated: bool,
    pub matrix: Matrix,
    #[serde(default)]
    pub rule_overrides: Vec<RuleOverride>,
    /// Highest step that may be carried out without a human approving.
    pub auto_max_step: Step,
    /// Envelope scale factor for `LimitMotion`, in `(0, 1]`.
    pub limit_motion_factor: f64,
    /// Behaviour requested for `SafePause`.
    pub safe_pause: SafeBehaviour,
    /// Behaviour requested for `RequestSafeState`.
    pub safe_state: SafeBehaviour,
    /// Restrict targets used when no rule override names any.
    pub default_restrict: Vec<RestrictTarget>,
    /// Allow a `Process` restriction to terminate the process, only ever
    /// while the robot is `Idle`. Default false (quarantine only).
    #[serde(default)]
    pub allow_terminate_when_idle: bool,
    pub escalation: EscalationPolicy,
}

/// Why a policy was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    Json(String),
    Schema(String),
    Model(String),
    /// The matrix allows more than Record while the safety system is engaged.
    SafetySystemCell {
        state: SafetyState,
        step: Step,
    },
    InvalidSafeBehaviour {
        field: &'static str,
        behaviour: SafeBehaviour,
        platform: PlatformFamily,
    },
    LimitMotionFactor(String),
    EmptyRestrictTargets,
    DuplicateRestrictTarget,
    TooManyOverrides(usize),
    BadRuleId(String),
    DuplicateRule(String),
    OverrideRange {
        rule: String,
        min: Step,
        max: Step,
    },
    Escalation(&'static str),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::Json(e) => write!(f, "policy JSON: {e}"),
            PolicyError::Schema(s) => write!(f, "unsupported schema {s:?}, expected {SCHEMA:?}"),
            PolicyError::Model(m) => write!(f, "invalid model name {m:?}"),
            PolicyError::SafetySystemCell { state, step } => write!(
                f,
                "matrix allows {step:?} in {state:?}; only record is permitted while the safety system is engaged"
            ),
            PolicyError::InvalidSafeBehaviour {
                field,
                behaviour,
                platform,
            } => write!(f, "{field}: {behaviour:?} is not a valid safe behaviour for {platform:?}"),
            PolicyError::LimitMotionFactor(v) => {
                write!(f, "limit_motion_factor {v} must be finite and in (0, 1]")
            }
            PolicyError::EmptyRestrictTargets => write!(f, "restrict target lists must not be empty"),
            PolicyError::DuplicateRestrictTarget => write!(f, "duplicate restrict target"),
            PolicyError::TooManyOverrides(n) => {
                write!(f, "{n} rule overrides exceed the cap of {MAX_RULE_OVERRIDES}")
            }
            PolicyError::BadRuleId(r) => write!(f, "invalid rule id {r:?}"),
            PolicyError::DuplicateRule(r) => write!(f, "duplicate override for rule {r:?}"),
            PolicyError::OverrideRange { rule, min, max } => {
                write!(f, "override {rule}: min_step {min:?} > max_step {max:?}")
            }
            PolicyError::Escalation(e) => write!(f, "escalation: {e}"),
        }
    }
}

impl std::error::Error for PolicyError {}

impl ResponsePolicy {
    /// The built-in conservative default for a platform family. It is **not**
    /// OEM-validated, so a responder using it is observe-only until the OEM
    /// signs off (and flips `oem_validated`). See the crate README for the
    /// reasoning behind each cell.
    pub fn conservative_default(platform: PlatformFamily) -> Self {
        use Step::*;
        let (safe_pause, safe_state) = match platform {
            PlatformFamily::Ugv | PlatformFamily::Amr => {
                (SafeBehaviour::ControlledStop, SafeBehaviour::ControlledStop)
            }
            PlatformFamily::Drone => (SafeBehaviour::Hold, SafeBehaviour::Hold),
            PlatformFamily::Arm => (
                SafeBehaviour::ProtectiveStopCategory2,
                SafeBehaviour::ProtectiveStopCategory2,
            ),
            PlatformFamily::Other => (
                SafeBehaviour::PlatformDefined,
                SafeBehaviour::PlatformDefined,
            ),
        };
        let row = |low, medium, high, critical| SeverityRow {
            low,
            medium,
            high,
            critical,
        };
        ResponsePolicy {
            schema: SCHEMA.to_string(),
            model: "default".to_string(),
            platform,
            oem_validated: false,
            matrix: Matrix {
                idle: row(Record, Restrict, Restrict, SafePause),
                moving_slow: row(Record, Record, LimitMotion, RequestSafeState),
                moving_fast: row(Record, Record, LimitMotion, RequestSafeState),
                collaborative_human_nearby: row(Record, LimitMotion, SafePause, RequestSafeState),
                estop_active: SeverityRow::uniform(Record),
                safe_state_active: SeverityRow::uniform(Record),
                unknown: row(Record, Record, Restrict, RequestSafeState),
            },
            rule_overrides: Vec::new(),
            auto_max_step: LimitMotion,
            limit_motion_factor: 0.5,
            safe_pause,
            safe_state,
            default_restrict: vec![RestrictTarget::Participant],
            allow_terminate_when_idle: false,
            escalation: EscalationPolicy {
                window_ms: 60_000,
                threshold: 3,
                max_escalation_steps: 1,
                ceiling: LimitMotion,
                quiet_period_ms: 300_000,
                min_reissue_interval_ms: 5_000,
            },
        }
    }

    /// Parse and validate a policy from JSON. Never panics on hostile input.
    pub fn from_json(s: &str) -> Result<Self, PolicyError> {
        let p: ResponsePolicy =
            serde_json::from_str(s).map_err(|e| PolicyError::Json(e.to_string()))?;
        p.validate()?;
        Ok(p)
    }

    /// Serialize to pretty JSON.
    pub fn to_json(&self) -> String {
        // Serialization of this plain struct cannot fail except on non-finite
        // floats, which `validate` rejects; fall back to a marker regardless.
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }

    /// Look up the override for a rule id.
    pub fn override_for(&self, rule: &str) -> Option<&RuleOverride> {
        self.rule_overrides.iter().find(|o| o.rule == rule)
    }

    /// Reject any policy that tries to exceed the invariants or is malformed.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.schema != SCHEMA {
            return Err(PolicyError::Schema(self.schema.clone()));
        }
        if self.model.is_empty()
            || self.model.len() > MAX_MODEL_LEN
            || self.model.chars().any(char::is_control)
        {
            return Err(PolicyError::Model(self.model.clone()));
        }
        for state in [SafetyState::EStopActive, SafetyState::SafeStateActive] {
            for step in self.matrix.row(state).cells() {
                if step != Step::Record {
                    return Err(PolicyError::SafetySystemCell { state, step });
                }
            }
        }
        for (field, b) in [
            ("safe_pause", self.safe_pause),
            ("safe_state", self.safe_state),
        ] {
            if !b.allowed_for(self.platform) {
                return Err(PolicyError::InvalidSafeBehaviour {
                    field,
                    behaviour: b,
                    platform: self.platform,
                });
            }
        }
        let f = self.limit_motion_factor;
        if !(f.is_finite() && f > 0.0 && f <= 1.0) {
            return Err(PolicyError::LimitMotionFactor(f.to_string()));
        }
        validate_targets(&self.default_restrict)?;
        if self.rule_overrides.len() > MAX_RULE_OVERRIDES {
            return Err(PolicyError::TooManyOverrides(self.rule_overrides.len()));
        }
        let mut seen = BTreeSet::new();
        for o in &self.rule_overrides {
            if !valid_rule_id(&o.rule) {
                return Err(PolicyError::BadRuleId(o.rule.clone()));
            }
            if !seen.insert(o.rule.as_str()) {
                return Err(PolicyError::DuplicateRule(o.rule.clone()));
            }
            if o.min_step > o.max_step {
                return Err(PolicyError::OverrideRange {
                    rule: o.rule.clone(),
                    min: o.min_step,
                    max: o.max_step,
                });
            }
            if let Some(t) = &o.restrict {
                validate_targets(t)?;
            }
        }
        let e = &self.escalation;
        if e.window_ms == 0 || e.window_ms > MAX_WINDOW_MS {
            return Err(PolicyError::Escalation("window_ms must be in 1..=86400000"));
        }
        if e.threshold < 2 || e.threshold > MAX_ESCALATION_THRESHOLD {
            return Err(PolicyError::Escalation("threshold must be in 2..=64"));
        }
        if e.max_escalation_steps > MAX_ESCALATION_STEPS {
            return Err(PolicyError::Escalation("max_escalation_steps must be <= 2"));
        }
        if e.quiet_period_ms < e.window_ms || e.quiet_period_ms > MAX_WINDOW_MS {
            return Err(PolicyError::Escalation(
                "quiet_period_ms must be >= window_ms and <= 86400000",
            ));
        }
        if e.min_reissue_interval_ms > e.quiet_period_ms {
            return Err(PolicyError::Escalation(
                "min_reissue_interval_ms must be <= quiet_period_ms",
            ));
        }
        Ok(())
    }
}

fn validate_targets(t: &[RestrictTarget]) -> Result<(), PolicyError> {
    if t.is_empty() {
        return Err(PolicyError::EmptyRestrictTargets);
    }
    let set: BTreeSet<_> = t.iter().collect();
    if set.len() != t.len() {
        return Err(PolicyError::DuplicateRestrictTarget);
    }
    Ok(())
}

fn valid_rule_id(r: &str) -> bool {
    !r.is_empty()
        && r.len() <= MAX_RULE_ID_LEN
        && r.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}
