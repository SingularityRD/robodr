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
    /// stop. Only here may a process restriction escalate to termination.
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
    /// configured safe behaviour may be requested. See also [`Morphology`]:
    /// a humanoid never gets an executable safe pause / safe state.
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
/// (`"morphology"`, default `other`). [`PlatformFamily`] decides which safe
/// behaviours make physical sense; the morphology decides whether a
/// safe behaviour may be *executed* at all.
///
/// # Why a humanoid never gets `safe_pause` / `request_safe_state`
///
/// A biped stands only while its joint controllers actively balance it. The
/// way most humanoid stacks implement "pause", "safe state" or "protective
/// stop" is to switch the joints to a damping or zero-torque mode (or to cut
/// motor power): the robot then **falls**, from standing height, with
/// tens of kilograms of mass, onto whatever and whoever is next to it. A
/// fall is a worse hazard than the cyber event that prompted it, and RoboDR
/// cannot know which implementation a given platform uses. So for
/// [`Morphology::Humanoid`] the planner never puts `SafePause` or
/// `RequestSafeState` into a plan's executable actions; it lists them in
/// `ResponsePlan::advisory` (a recommendation for the operator and the
/// platform's own safety function, which may know a safe sit-down or
/// crouch sequence) and contains the threat with the steps that keep the
/// robot balanced: `LimitMotion`, network isolation and participant
/// quarantine. The control plane refuses SOC requests for these actions on
/// a humanoid for the same reason.
///
/// Quadrupeds, wheeled platforms, arms and aerial vehicles are statically
/// stable when stopped or have a platform-specific safe behaviour (controlled
/// stop, protective stop category 2, hold / return-to-launch), so the
/// existing per-family rules apply to them unchanged. A quadruped whose
/// "damp" mode collapses the body should be configured with a
/// `platform_defined` safe behaviour that the OEM has validated, or as
/// `humanoid` if no safe sequence exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Morphology {
    /// Biped / humanoid: balance is active; de-energising means falling.
    Humanoid,
    /// Four-legged robot.
    Quadruped,
    /// Wheeled or tracked ground platform (UGV, AMR).
    WheeledMobile,
    /// Manipulator arm (fixed or on a stable base).
    Arm,
    /// Multirotor / fixed-wing aerial vehicle.
    Aerial,
    /// Unspecified (the default; keeps pre-morphology policies unchanged).
    #[default]
    Other,
}

impl Morphology {
    pub const ALL: [Morphology; 6] = [
        Morphology::Humanoid,
        Morphology::Quadruped,
        Morphology::WheeledMobile,
        Morphology::Arm,
        Morphology::Aerial,
        Morphology::Other,
    ];

    /// True when damping or de-energising the actuators makes the robot
    /// fall, so actions that may do so (`safe_pause`, `request_safe_state`)
    /// are advisory only.
    pub fn falls_when_de_energised(self) -> bool {
        matches!(self, Morphology::Humanoid)
    }

    /// `serde` helper: the default is not serialised, so plans of
    /// pre-morphology policies keep their exact JSON.
    pub fn is_other(&self) -> bool {
        matches!(self, Morphology::Other)
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
    pub phase: MissionPhase,
    pub connectivity: Connectivity,
    pub control: ControlMode,
    /// A qualified operator is on site / on console and can approve actions.
    pub operator_present: bool,
    /// The model profile is locked (OEM-approved). If false the robot is in
    /// observe mode and the responder only records (see crate docs).
    pub profile_locked: bool,
}
