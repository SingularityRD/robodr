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
    /// configured safe behaviour may be requested.
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
