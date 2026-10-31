//! Source-specific parts of the live safety-state feed ([`crate::safety`]):
//!
//! * [`unitree`]: native Unitree safety-state sources (`SportModeState_`,
//!   `LowState_`), gap T17;
//! * [`context`]: the live operational context (control mode, mission
//!   phase, connectivity) from Unitree sport mode and remote, ROS 2
//!   lifecycle (Nav2) and the uplink status, gap T46.
//!
//! The passive tap, the writer trust and the per-source bookkeeping stay in
//! [`crate::safety`]; these modules only turn a trusted sample (or a status
//! file) into claims.

pub mod context;
pub mod unitree;
