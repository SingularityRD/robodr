//! The robot's physical safety state and operational context: the inputs that
//! condition every response decision besides the deviation itself.
//!
//! These are *reported* by the platform (safety controller status, mission
//! executive, teleop link). RoboDR never derives them by guessing; when the
//! platform cannot say, the caller must pass [`SafetyState::Unknown`], which
//! the planner treats conservatively (no automatic motion-affecting steps).

use serde::{Deserialize, Serialize};

/// The robot's current physical safety / motion state, as reported by the
/// platform. Ordering of variants carries no meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyState {
    /// Powered, not moving, no motion commanded.
    Idle,
    /// Moving within the reduced-speed band.
    MovingSlow,
    /// Moving above the reduced-speed band.
    MovingFast,
    /// A human is inside the collaborative / protective zone (speed & separation
    /// monitoring active), moving or not.
    CollaborativeHumanNearby,
    /// The emergency stop is engaged. The safety system has authority.
    #[serde(rename = "estop_active")]
    EStopActive,
    /// The platform is already in its safe state (protective stop, loiter,
    /// controlled stop...). The safety system has authority.
    SafeStateActive,
    /// The platform did not (or could not) report its state.
    Unknown,
}

impl SafetyState {
    /// Every variant, for exhaustive tests and matrix iteration.
    pub const ALL: [SafetyState; 7] = [
        SafetyState::Idle,
        SafetyState::MovingSlow,
        SafetyState::MovingFast,
        SafetyState::CollaborativeHumanNearby,
        SafetyState::EStopActive,
        SafetyState::SafeStateActive,
        SafetyState::Unknown,
    ];

    /// True when the platform's own safety function is already engaged. In
    /// these states RoboDR only records: the safety system has authority and
    /// must not receive competing requests.
    pub fn safety_system_engaged(self) -> bool {
        matches!(
            self,
            SafetyState::EStopActive | SafetyState::SafeStateActive
        )
    }

    /// True when the robot is known to be stationary and not under a safety
    /// stop. Only here may a process restriction escalate to termination —
    /// and never on a morphology that balances while idle
    /// ([`Morphology::needs_active_balance`]).
    pub fn is_idle(self) -> bool {
        matches!(self, SafetyState::Idle)
    }
}

/// Platform family. Determines which safe behaviours are physically sensible
/// (see [`crate::action::SafeBehaviour::allowed_for`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformFamily {
    /// Unmanned ground vehicle.
    Ugv,
    /// Autonomous mobile robot (indoor logistics etc.).
    Amr,
    /// Multirotor / fixed-wing UAV.
    Drone,
    /// Industrial or collaborative manipulator arm.
    Arm,
    /// Anything else (humanoid, legged, marine...). Only the platform's own
    /// configured safe behaviour may be requested. A policy for this family
    /// must declare its [`Morphology`]: a humanoid never gets an executable
    /// safe pause / safe state.
    Other,
}

impl PlatformFamily {
    pub const ALL: [PlatformFamily; 5] = [
        PlatformFamily::Ugv,
        PlatformFamily::Amr,
        PlatformFamily::Drone,
        PlatformFamily::Arm,
        PlatformFamily::Other,
    ];
}

/// The robot's body plan (morphology), set per model in the response policy
/// (`"morphology"`). [`PlatformFamily`] decides which safe behaviours make
/// physical sense; the morphology decides whether an action that may stop
/// the robot's balance may be *executed* at all.
///
/// # Required, and fail-safe when absent
///
/// A policy must declare its morphology when it is OEM-validated or its
/// platform is [`PlatformFamily::Other`] (the family that covers humanoids
/// and legged robots); [`crate::ResponsePolicy::validate`] rejects it
/// otherwise. Where it may still be omitted (a not-yet-validated policy of
/// another family, which runs observe-only), it reads as
/// [`Morphology::Unspecified`], which gets the **most conservative**
/// treatment: that of a humanoid. RoboDR never assumes a robot stands on its
/// own.
///
/// # Two hazards
///
/// * **Falls when de-energised** ([`Morphology::falls_when_de_energised`]:
///   humanoid, unspecified). A biped stands only while its joint
///   controllers actively balance it. The way most humanoid stacks
///   implement "pause", "safe state" or "protective stop" is to switch the
///   joints to a damping or zero-torque mode (or to cut motor power): the
///   robot then **falls**, from standing height, with tens of kilograms of
///   mass, onto whatever and whoever is next to it. A fall is a worse
///   hazard than the cyber event that prompted it, and RoboDR cannot know
///   which implementation a given platform uses. So the planner never puts
///   `SafePause` or `RequestSafeState` into a plan's executable actions; it
///   lists them in `ResponsePlan::advisory` (a recommendation for the
///   operator and the platform's own safety function, which may know a
///   safe sit-down or crouch sequence). The substitute containment it plans
///   instead **always needs a human's approval**: `LimitMotion` (never
///   below the policy's `min_motion_factor`) plus only the restrict targets
///   the OEM listed in the policy's `fall_safe_restrict`. Cutting the
///   network or quarantining a DDS participant is balance-safe only when
///   the balance loop itself is not networked: on Unitree G1/H1 the
///   low-level loop is a DDS writer of `rt/lowcmd`, and silencing that
///   writer trips the motor watchdog, which damps the joints — the robot
///   falls. The control plane refuses SOC requests for these actions with
///   `fall_hazard` for the same reason.
/// * **Needs active balance** ([`Morphology::needs_active_balance`]:
///   humanoid, quadruped, unspecified). The standing posture is held by a
///   running controller process. A legged robot reports `idle` while it
///   stands and actively balances, so `idle` does not mean "safe to stop a
///   process": if the controller process dies, freezes or restarts, a
///   humanoid falls from standing height and a quadruped drops onto its
///   belly (a smaller but real hazard: ~15-50 kg from ~0.3-0.5 m, legs
///   folding under it). For these morphologies a process is never
///   terminated (`allow_terminate_when_idle` is rejected), a process
///   quarantine always needs a human's approval (RoboDR cannot tell the
///   balance controller from a payload process), `rollback_config` (a
///   controller restart) is refused, and the motion envelope is never
///   scaled below the policy's `min_motion_factor` (a near-zero joint speed
///   cap also prevents the balance corrections the robot needs).
///
/// Quadrupeds keep an executable `safe_pause` / `request_safe_state` when
/// the OEM validated a `platform_defined` behaviour (e.g. a controlled
/// stand-down); a quadruped whose "damp" mode collapses the body should be
/// configured as `humanoid` if no safe sequence exists. Wheeled platforms,
/// arms and aerial vehicles keep the per-family rules unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Morphology {
    /// Biped / humanoid: balance is active; de-energising means falling.
    Humanoid,
    /// Four-legged robot: balance is active while standing.
    Quadruped,
    /// Wheeled or tracked ground platform (UGV, AMR).
    WheeledMobile,
    /// Manipulator arm (fixed or on a stable base).
    Arm,
    /// Multirotor / fixed-wing aerial vehicle.
    Aerial,
    /// Declared by the OEM: none of the above, statically stable when its
    /// actuators stop (it neither falls nor needs a balance controller).
    Other,
    /// Not declared (the default). Treated like a humanoid: every
    /// fall-prone rule applies. Rejected in an OEM-validated policy and on
    /// platform `other`.
    #[default]
    Unspecified,
}

impl Morphology {
    pub const ALL: [Morphology; 7] = [
        Morphology::Humanoid,
        Morphology::Quadruped,
        Morphology::WheeledMobile,
        Morphology::Arm,
        Morphology::Aerial,
        Morphology::Other,
        Morphology::Unspecified,
    ];

    /// True when damping or de-energising the actuators makes the robot
    /// fall, so actions that may do so (`safe_pause`, `request_safe_state`)
    /// are advisory only and their substitutes need approval. Humanoid and
    /// unspecified.
    pub fn falls_when_de_energised(self) -> bool {
        matches!(self, Morphology::Humanoid | Morphology::Unspecified)
    }

    /// True when the robot's posture is held by a running balance
    /// controller (it collapses if that process stops, even while `idle`):
    /// no process termination, process quarantine only with approval, no
    /// `rollback_config`, a floor on motion scaling. Humanoid, quadruped
    /// and unspecified.
    pub fn needs_active_balance(self) -> bool {
        matches!(
            self,
            Morphology::Humanoid | Morphology::Quadruped | Morphology::Unspecified
        )
    }

    /// `serde` helper: the default is not serialised.
    pub fn is_unspecified(&self) -> bool {
        matches!(self, Morphology::Unspecified)
    }

    /// The JSON name (`humanoid`, ...).
    pub fn as_str(self) -> &'static str {
        match self {
            Morphology::Humanoid => "humanoid",
            Morphology::Quadruped => "quadruped",
            Morphology::WheeledMobile => "wheeled_mobile",
            Morphology::Arm => "arm",
            Morphology::Aerial => "aerial",
            Morphology::Other => "other",
            Morphology::Unspecified => "unspecified",
        }
    }
}

/// Mission phase as reported by the mission executive / autopilot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionPhase {
    /// On the ground / parked / between jobs.
    Parked,
    /// Moving between task locations (includes a drone cruising in flight).
    Transit,
    /// Executing the task itself (manipulation, survey...).
    Task,
    /// Drone take-off, or any comparable transient phase.
    Takeoff,
    /// Drone landing, or docking/approach for ground platforms.
    Landing,
    /// Not reported.
    Unknown,
}

impl MissionPhase {
    pub const ALL: [MissionPhase; 6] = [
        MissionPhase::Parked,
        MissionPhase::Transit,
        MissionPhase::Task,
        MissionPhase::Takeoff,
        MissionPhase::Landing,
        MissionPhase::Unknown,
    ];

    /// Transient phases in which interrupting motion is itself a hazard.
    /// Motion-affecting steps here always require a human decision.
    pub fn is_transient(self) -> bool {
        matches!(self, MissionPhase::Takeoff | MissionPhase::Landing)
    }
}

/// Link to the operator / fleet control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Connectivity {
    Connected,
    Degraded,
    Disconnected,
}

impl Connectivity {
    pub const ALL: [Connectivity; 3] = [
        Connectivity::Connected,
        Connectivity::Degraded,
        Connectivity::Disconnected,
    ];
}

/// Who is commanding motion right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlMode {
    /// On-board autonomy is commanding motion.
    Autonomous,
    /// A remote operator is teleoperating. They hold command authority, so
    /// motion-affecting steps are proposed to them, never imposed.
    Teleop,
    /// A local operator (pendant, hand controller) is in control.
    Manual,
}

impl ControlMode {
    pub const ALL: [ControlMode; 3] = [
        ControlMode::Autonomous,
        ControlMode::Teleop,
        ControlMode::Manual,
    ];

    /// A human holds command authority over motion.
    pub fn human_in_command(self) -> bool {
        matches!(self, ControlMode::Teleop | ControlMode::Manual)
    }
}

/// Everything about the robot's situation the planner needs besides its
/// safety state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OperationalContext {
    pub platform: PlatformFamily,
    /// The robot's morphology as the component building the context knows
    /// it (its own configuration). The planner refuses to act when it
    /// differs from the policy's, and [`crate::check_invariants`] refuses a
    /// plan made for another morphology, so an executor never trusts a
    /// plan's own `morphology` field. Default (when absent from JSON):
    /// [`Morphology::Unspecified`], the most conservative.
    #[serde(default)]
    pub morphology: Morphology,
    pub phase: MissionPhase,
    pub connectivity: Connectivity,
    pub control: ControlMode,
    /// A qualified operator is on site / on console and can approve actions.
    pub operator_present: bool,
    /// The model profile is locked (OEM-approved). If false the robot is in
    /// observe mode and the responder only records (see crate docs).
    pub profile_locked: bool,
}
