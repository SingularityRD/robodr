//! Harness: the full `robodr-cdr` decoder surface on one payload: every
//! `MessageKind` (the standard ROS 2 kinds as well as the Unitree ones) via
//! `decode_payload`, `decode_by_type_name` (DDS and ROS names) and the
//! built-in `Registry`; the `std_msgs` decoders the safety feed uses
//! (`decode_std`); the encapsulation header; and the event conversion of
//! every decoded message. (`cdr_unitree` covers the Unitree-specific readers
//! in more depth; this target is the generic decoder.)
//!
//! Input: `limits_byte payload`. `limits_byte % 4` picks the caps: the
//! sensor defaults, tight caps, generous caps, or the defaults with
//! `DelimitedNesting::TopLevelOnly`.
//!
//! Invariants beyond "no panic":
//!
//! * `decode_payload(kind)` == `decode_by_type_name(dds name)` ==
//!   `decode_by_type_name(ros name)` == `Registry::with_builtin().decode`,
//!   and `MessageKind::from_type_name` maps both names back to the kind;
//! * a successful decode has `consumed + trailing == payload - 4`, the
//!   message reports its kind and role, `anomalies` flags exactly the excess
//!   trailing bytes (> 3), and the decode is deterministic;
//! * caps only ever reject: whatever decodes under the tight caps decodes
//!   to the same message under the generous ones (same nesting);
//! * `Encapsulation::parse` splits off exactly 4 bytes and its
//!   representation id round-trips; `decode_std` obeys the same length
//!   invariant;
//! * the event conversions (`to_event`, `to_command`, `to_feedback`) are
//!   total, and a command-role message never yields feedback (nor the
//!   reverse).
//!
//! Shared via `#[path]` with `crates/robodr-cdr/tests/fuzz_smoke.rs`.
#![allow(dead_code)]

use robodr_cdr::std_msgs::{decode_std, StdKind};
use robodr_cdr::{
    decode_by_type_name, decode_payload, DecodeAnomaly, DelimitedNesting, Encapsulation,
    EventContext, Limits, MessageKind, MotionRole, Registry, Representation, MAX_END_PADDING,
};

const CTX: EventContext<'static> = EventContext {
    channel: "rt/cmd_vel",
    writer_guid: Some("0123456789abcdef01234567"),
    timestamp_ns: 1,
};

fn tight() -> Limits {
    Limits {
        max_payload_len: 4096,
        max_string_len: 16,
        max_sequence_len: 8,
        max_trajectory_points: 2,
        ..Limits::default()
    }
}

fn generous(nesting: DelimitedNesting) -> Limits {
    Limits {
        max_payload_len: 1 << 20,
        max_string_len: 1 << 16,
        max_sequence_len: 1 << 16,
        max_trajectory_points: 1 << 12,
        d_cdr2_nesting: nesting,
    }
}

pub fn run(data: &[u8]) {
    let Some((&sel, payload)) = data.split_first() else {
        return;
    };
    let limits = match sel % 4 {
        0 => Limits::default(),
        1 => tight(),
        2 => generous(DelimitedNesting::AllStructs),
        _ => Limits {
            d_cdr2_nesting: DelimitedNesting::TopLevelOnly,
            ..Limits::default()
        },
    };
    let registry = Registry::with_builtin();

    if let Ok((enc, body)) = Encapsulation::parse(payload) {
        assert_eq!(body.len() + 4, payload.len());
        let id = enc.representation.id();
        assert_eq!(Representation::from_id(id), Some(enc.representation));
        assert!(enc.padding() <= 3);
    } else {
        // Only a short payload or an unknown representation id is refused.
        let id = payload.get(..2).map(|b| u16::from_be_bytes([b[0], b[1]]));
        assert!(payload.len() < 4 || id.and_then(Representation::from_id).is_none());
    }

    for kind in MessageKind::ALL {
        let a = decode_payload(kind, payload, &limits);
        assert_eq!(
            MessageKind::from_type_name(kind.dds_type_name()),
            Some(kind)
        );
        assert_eq!(
            MessageKind::from_type_name(kind.ros_type_name()),
            Some(kind)
        );
        // Compared through `Debug` (shortest round-trip float formatting):
        // `PartialEq` would call two decodes of the same NaN different.
        let same = |b: &dyn std::fmt::Debug| format!("{a:?}") == format!("{b:?}");
        assert!(same(&decode_by_type_name(
            kind.dds_type_name(),
            payload,
            &limits
        )));
        assert!(same(&decode_by_type_name(
            kind.ros_type_name(),
            payload,
            &limits
        )));
        assert!(same(&registry.decode(
            kind.dds_type_name(),
            payload,
            &limits
        )));
        assert!(
            same(&decode_payload(kind, payload, &limits)),
            "deterministic"
        );
        let Ok(d) = a else { continue };
        assert_eq!(d.consumed + d.trailing_bytes, payload.len() - 4, "{kind:?}");
        assert_eq!(d.message.kind(), kind);
        assert_eq!(d.message.role(), kind.role());
        let excess = d
            .anomalies()
            .iter()
            .any(|x| matches!(x, DecodeAnomaly::ExcessTrailingBytes { .. }));
        assert_eq!(excess, d.trailing_bytes > MAX_END_PADDING);
        let _ = d.message.to_event(&CTX);
        let cmd = d.message.to_command(&CTX);
        let fb = d.message.to_feedback(&CTX);
        match kind.role() {
            MotionRole::Command => assert!(fb.is_none(), "{kind:?} gave feedback"),
            MotionRole::Feedback => assert!(cmd.is_none(), "{kind:?} gave a command"),
        }
        let _ = d.message.joint_command_frame();
        let _ = d.message.joint_state_frame();
        let _ = d.message.unverifiable_reason();
        let _ = d.message.unitree_crc_ok();
        // Caps only reject: a tight-cap success decodes the same way with
        // generous caps (same nesting rule).
        if limits == tight() {
            let g = decode_payload(kind, payload, &generous(DelimitedNesting::AllStructs));
            let g = g.map(|x| format!("{:?}", x.message));
            assert_eq!(g, Ok(format!("{:?}", d.message)), "{kind:?}");
        }
    }

    for kind in [StdKind::Bool, StdKind::UInt8, StdKind::String] {
        assert_eq!(StdKind::from_type_name(kind.dds_type_name()), Some(kind));
        assert_eq!(StdKind::from_type_name(kind.ros_type_name()), Some(kind));
        if let Ok(d) = decode_std(kind, payload, &limits) {
            assert_eq!(d.consumed + d.trailing_bytes, payload.len() - 4);
            assert_eq!(d.value.kind(), kind);
            assert_eq!(
                !d.anomalies().is_empty(),
                d.trailing_bytes > MAX_END_PADDING
            );
        }
    }
}
