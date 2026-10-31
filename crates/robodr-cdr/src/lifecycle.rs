//! Decoder for `lifecycle_msgs/msg/TransitionEvent`, the message a ROS 2
//! managed (lifecycle) node publishes on `<node>/transition_event` at every
//! state change (Nav2's `bt_navigator`, `controller_server`, ... and its
//! `lifecycle_manager` drive them). `robodr-agentd`'s live operational
//! context reads it passively to tell whether the autonomy stack is active.
//!
//! Like the [`crate::std_msgs`] types, this is **not** a motion message: it
//! is not in [`crate::MessageKind`] or the [`crate::Registry`].
//!
//! Layout (`lifecycle_msgs` IDL; every struct `@appendable` by XTypes
//! default, so DHEADER-wrapped under `D_CDR2_*` as configured by
//! [`crate::Limits::d_cdr2_nesting`]):
//!
//! ```text
//! TransitionEvent { uint64 timestamp;            // ns, publisher clock
//!                   Transition { uint8 id; string label; } transition;
//!                   State      { uint8 id; string label; } start_state;
//!                   State      { uint8 id; string label; } goal_state; }
//! ```
//!
//! The state ids are fixed by `lifecycle_msgs/msg/State`: primary states
//! 1 unconfigured, 2 inactive, 3 active, 4 finalized; transition states
//! 10 configuring, 11 cleaningup, 12 shuttingdown, 13 activating,
//! 14 deactivating, 15 errorprocessing (0 unknown). The labels are free
//! text and are kept only for display ([`LifecycleState::label`]).
//!
//! # Hostile input
//!
//! Strings obey [`crate::Limits::max_string_len`] (checked before the bytes
//! are touched) and need not be UTF-8; trailing bytes are reported as for
//! every other decoder; no panics, no allocation.
//!
//! # Not verified
//!
//! Derived from the `lifecycle_msgs` definitions and checked against
//! hand-built vectors only, not against a capture of a real Nav2 stack.

use crate::encap::Encapsulation;
use crate::error::DecodeError;
use crate::reader::{CdrStr, Reader};
use crate::{DecodeAnomaly, Limits, MAX_END_PADDING};

/// DDS type name announced in SEDP.
pub const TRANSITION_EVENT_DDS: &str = "lifecycle_msgs::msg::dds_::TransitionEvent_";
/// ROS interface name.
pub const TRANSITION_EVENT_ROS: &str = "lifecycle_msgs/msg/TransitionEvent";

/// Does `name` (DDS or ROS) name `lifecycle_msgs/msg/TransitionEvent`?
pub fn is_transition_event(name: &str) -> bool {
    name == TRANSITION_EVENT_DDS || name == TRANSITION_EVENT_ROS
}

/// The `lifecycle_msgs/msg/State` ids and their canonical names.
pub const STATE_NAMES: [(u8, &str); 11] = [
    (0, "unknown"),
    (1, "unconfigured"),
    (2, "inactive"),
    (3, "active"),
    (4, "finalized"),
    (10, "configuring"),
    (11, "cleaningup"),
    (12, "shuttingdown"),
    (13, "activating"),
    (14, "deactivating"),
    (15, "errorprocessing"),
];

/// The canonical name of a state id (`None` for an id the message
/// definition does not define).
pub fn state_name(id: u8) -> Option<&'static str> {
    STATE_NAMES.iter().find(|(i, _)| *i == id).map(|(_, n)| *n)
}

/// The id of a canonical state name.
pub fn state_id(name: &str) -> Option<u8> {
    STATE_NAMES
        .iter()
        .find(|(_, n)| *n == name)
        .map(|(i, _)| *i)
}

/// `lifecycle_msgs/msg/State` (and `Transition`, same layout).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleState<'a> {
    pub id: u8,
    /// As sent; not trusted for anything but display.
    pub label: CdrStr<'a>,
}

/// `lifecycle_msgs/msg/TransitionEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionEvent<'a> {
    /// Publisher clock (ns); a wire claim, not used as the event time.
    pub timestamp: u64,
    pub transition: LifecycleState<'a>,
    pub start_state: LifecycleState<'a>,
    pub goal_state: LifecycleState<'a>,
}

/// A successful [`decode_transition_event`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionEventDecoded<'a> {
    pub encapsulation: Encapsulation,
    pub event: TransitionEvent<'a>,
    pub consumed: usize,
    pub trailing_bytes: usize,
}

impl TransitionEventDecoded<'_> {
    /// [`DecodeAnomaly::ExcessTrailingBytes`] when more than
    /// [`MAX_END_PADDING`] bytes follow the message.
    pub fn anomalies(&self) -> Vec<DecodeAnomaly> {
        if self.trailing_bytes > MAX_END_PADDING {
            vec![DecodeAnomaly::ExcessTrailingBytes {
                trailing: self.trailing_bytes,
                allowed: MAX_END_PADDING,
            }]
        } else {
            Vec::new()
        }
    }
}

fn read_state<'a>(r: &mut Reader<'a>) -> Result<LifecycleState<'a>, DecodeError> {
    r.structure(|r| {
        Ok(LifecycleState {
            id: r.u8()?,
            label: r.string()?,
        })
    })
}

/// Decodes one serialized `TransitionEvent` (encapsulation header
/// included). Same encapsulations and caps as [`crate::decode_payload`].
pub fn decode_transition_event<'a>(
    payload: &'a [u8],
    limits: &Limits,
) -> Result<TransitionEventDecoded<'a>, DecodeError> {
    let (encapsulation, mut r) = crate::open_reader(payload, limits)?;
    let event = r.structure(|r| {
        Ok(TransitionEvent {
            timestamp: r.u64()?,
            transition: read_state(r)?,
            start_state: read_state(r)?,
            goal_state: read_state(r)?,
        })
    })?;
    Ok(TransitionEventDecoded {
        encapsulation,
        event,
        consumed: r.pos(),
        trailing_bytes: r.remaining(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_ids_round_trip() {
        for (id, n) in STATE_NAMES {
            assert_eq!(state_name(id), Some(n));
            assert_eq!(state_id(n), Some(id));
        }
        assert_eq!(state_name(5), None);
        assert_eq!(state_id("Active"), None);
        assert!(is_transition_event(TRANSITION_EVENT_DDS));
        assert!(is_transition_event(TRANSITION_EVENT_ROS));
        assert!(!is_transition_event("lifecycle_msgs/msg/State"));
        // Truncated / empty bodies are errors, never panics (the full
        // vectors live in tests/lifecycle.rs, built with the shared encoder).
        for n in 0..24 {
            let mut p = vec![0, 1, 0, 0];
            p.extend(std::iter::repeat_n(0u8, n));
            assert!(decode_transition_event(&p, &Limits::default()).is_err());
        }
    }
}
