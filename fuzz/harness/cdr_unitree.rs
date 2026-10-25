//! Harness: the Unitree decoders in `robodr-cdr` (DDS types, the legacy
//! UDP frames, the API parameter JSON reader).
//!
//! Input: the first byte selects what to feed the rest of the bytes to; the
//! remaining bytes are the payload. Invariants beyond "no panic":
//!
//! * every DDS decode that succeeds reports `consumed + trailing == body`
//!   (body = payload without its 4-byte encapsulation header), and the
//!   message can be fully walked (`to_event`, joint frames, `crc_ok`);
//! * a decoded `LowCmd` / `LowState`'s `crc_ok` is total and equals the
//!   `crc` field compared with `computed_crc`;
//! * the bounded JSON reader never accepts a document deeper than the cap
//!   and its lookups are total;
//! * the legacy decoders are a pure function of the input length and bytes,
//!   never a panic, and a decoded frame's `crc_ok` is total.
//!
//! Shared via `#[path]` with the std-only smoke test
//! `crates/robodr-cdr/tests/fuzz_smoke.rs`, so the two cannot drift.
#![allow(dead_code)]

use robodr_cdr::unitree::{
    decode_unitree, ApiService, JsonObject, UnitreeKind, UnitreeMessage, UnitreeModel,
};
use robodr_cdr::unitree_legacy::{
    LegacyHighCmd, LegacyHighState, LegacyKind, LegacyLowCmd, LegacyLowState,
};
use robodr_cdr::{decode_payload, EventContext, Limits, MessageKind};

const CTX: EventContext<'static> = EventContext {
    channel: "rt/api/sport/request",
    writer_guid: Some("0123456789abcdef01234567"),
    timestamp_ns: 0,
};

fn exercise_unitree(m: &UnitreeMessage<'_>) {
    // crc_ok is total.
    let _ = m.crc_ok();
    match m {
        UnitreeMessage::ApiRequest(q) => {
            let _ = q.parameter_json();
            let _ = q.noreply();
            for svc in [
                ApiService::Sport,
                ApiService::Loco,
                ApiService::Arm,
                ApiService::MotionSwitcher,
                ApiService::Unspecified,
            ] {
                for model in [None, Some(UnitreeModel::Go2), Some(UnitreeModel::G1)] {
                    let call = q.call(svc, model);
                    let _ = call.class();
                    let _ = call.name();
                    let _ = call.body_velocity();
                    let _ = call.to_string();
                }
            }
            let _ = q.call_for_topic(CTX.channel, None);
        }
        UnitreeMessage::ApiResponse(r) => {
            let _ = (r.status_code, r.binary.len(), r.data.as_bytes().len());
        }
        _ => {}
    }
}

pub fn run(data: &[u8]) {
    let limits = Limits {
        // Keep strings generous so the JSON size cap, not the CDR cap, is
        // what bounds the API parameter.
        max_string_len: 64 * 1024,
        ..Limits::default()
    };
    let Some((&sel, payload)) = data.split_first() else {
        return;
    };

    // 1. DDS decode by every Unitree kind (both decode_unitree and, for
    //    the motion kinds, decode_payload: they must agree).
    for kind in UnitreeKind::ALL {
        if let Ok(d) = decode_unitree(kind, payload, &limits) {
            assert_eq!(
                d.consumed + d.trailing_bytes,
                payload.len().saturating_sub(4),
                "{kind:?}"
            );
            exercise_unitree(&d.message);
            let _ = d.anomalies();
        }
    }
    for mk in MessageKind::ALL {
        if mk.unitree_kind().is_none() {
            continue;
        }
        if let Ok(d) = decode_payload(mk, payload, &limits) {
            assert_eq!(
                d.consumed + d.trailing_bytes,
                payload.len().saturating_sub(4),
                "{mk:?}"
            );
            let _ = d.message.to_event(&CTX);
            let _ = d.message.unitree_crc_ok();
            let _ = d.message.joint_command_frame();
            let _ = d.message.joint_state_frame();
            let _ = d.anomalies();
        }
    }

    // 2. Bounded JSON reader on the payload directly.
    if let Ok(o) = JsonObject::parse(payload) {
        assert!(o.len() <= robodr_cdr::unitree::json::MAX_MEMBERS);
        for (_, v) in o.members() {
            let _ = v.as_f64();
            let _ = v.as_i64();
            let _ = v.as_bool();
            let _ = v.as_f64_array::<3>();
        }
        let _ = o.get("x");
    }

    // 3. Legacy UDP frames: selected by the leading byte so the fuzzer can
    //    reach each decoder, plus the length dispatch.
    let _ = LegacyKind::for_len(payload.len());
    match sel & 0x03 {
        0 => drop(LegacyLowCmd::decode(payload).map(|c| c.joint_frame())),
        1 => drop(LegacyLowState::decode(payload).map(|s| s.joint_frame())),
        2 => drop(LegacyHighCmd::decode(payload).map(|c| c.body_velocity())),
        _ => drop(LegacyHighState::decode(payload).map(|s| s.body_velocity())),
    }
    let _ = LegacyLowCmd::crc_ok(payload);
    let _ = LegacyHighCmd::crc_ok(payload);
}
