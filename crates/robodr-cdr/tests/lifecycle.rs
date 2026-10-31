//! `lifecycle_msgs/msg/TransitionEvent`: a hand-written XCDR1 vector and
//! round trips through the independent test encoder in every
//! encapsulation. Hand-built vectors only, not a capture of a real Nav2.

mod common;

use common::*;
use robodr_cdr::lifecycle::{decode_transition_event, state_id, state_name};
use robodr_cdr::{DecodeError, Limits, Representation};

fn event(
    rep: Representation,
    ts: i64,
    tr: (u8, &[u8]),
    start: (u8, &[u8]),
    goal: (u8, &[u8]),
) -> Vec<u8> {
    let mut e = Enc::new(rep);
    e.structure(|e| {
        e.i64(ts);
        for (id, label) in [tr, start, goal] {
            e.structure(|e| {
                e.byte(id);
                e.string(label);
            });
        }
    });
    e.finish()
}

#[test]
fn hand_vector_cdr_le() {
    // activate finished: activating (13) -> active (3).
    let v = hex("00 01 00 00            encapsulation CDR_LE
         2a 00 00 00 00 00 00 00 @0 timestamp 42
         04                     @8 transition.id = 4 (activate)
         00 00 00               pad to 12
         09 00 00 00            @12 len 9
         61 63 74 69 76 61 74 65 00  @16 activate NUL
         0d                     @25 start_state.id = 13
         00 00                  pad to 28
         0b 00 00 00            @28 len 11
         61 63 74 69 76 61 74 69 6e 67 00 @32 activating NUL
         03                     @43 goal_state.id = 3
         07 00 00 00            @44 len 7
         61 63 74 69 76 65 00   @48 active NUL
         00                     end padding");
    let d = decode_transition_event(&v, &Limits::default()).unwrap();
    assert_eq!(d.event.timestamp, 42);
    assert_eq!(d.event.transition.id, 4);
    assert_eq!(d.event.start_state.id, 13);
    assert_eq!(d.event.goal_state.id, 3);
    assert_eq!(d.event.goal_state.label.as_bytes(), b"active");
    assert_eq!(d.trailing_bytes, 1);
    assert!(d.anomalies().is_empty());
    // The encoder produces the same bytes.
    let e = event(
        Representation::CdrLe,
        42,
        (4, b"activate"),
        (13, b"activating"),
        (3, b"active"),
    );
    assert_eq!(&e[..e.len()], &v[..v.len() - 1]);
}

#[test]
fn round_trip_every_encapsulation() {
    for rep in ALL_REPS {
        let p = event(
            rep,
            -1,
            (3, b"cleanup"),
            (2, b"inactive"),
            (1, b"unconfigured"),
        );
        let d = decode_transition_event(&p, &Limits::default())
            .unwrap_or_else(|e| panic!("{rep:?}: {e}"));
        assert_eq!(d.event.timestamp, u64::MAX, "{rep:?}");
        assert_eq!(d.event.start_state.id, 2, "{rep:?}");
        assert_eq!(d.event.goal_state.id, 1, "{rep:?}");
        assert_eq!(d.event.goal_state.label.as_bytes(), b"unconfigured");
        assert_eq!(state_name(d.event.goal_state.id), Some("unconfigured"));
        assert_eq!(state_id("active"), Some(3));
    }
}

#[test]
fn hostile_payloads_are_errors() {
    let good = event(Representation::CdrLe, 1, (1, b"x"), (2, b"y"), (3, b"z"));
    // Every truncation is an error, never a panic.
    for n in 0..good.len() - 1 {
        assert!(
            decode_transition_event(good.get(..n).unwrap(), &Limits::default()).is_err(),
            "prefix {n}"
        );
    }
    // A label longer than the string cap is refused before it is read.
    let long = vec![b'a'; 300];
    let p = event(Representation::CdrLe, 1, (1, b"x"), (2, b"y"), (3, &long));
    let lim = Limits {
        max_string_len: 64,
        ..Limits::default()
    };
    assert!(decode_transition_event(&p, &lim).is_err());
    // Parameter-list encapsulation is not a plain struct.
    let mut pl = good.clone();
    pl[1] = 3; // PL_CDR_LE
    assert!(matches!(
        decode_transition_event(&pl, &Limits::default()),
        Err(DecodeError::UnsupportedRepresentation(_))
    ));
    // Excess trailing bytes are reported.
    let mut t = good;
    t.extend_from_slice(&[0; 8]);
    let d = decode_transition_event(&t, &Limits::default()).unwrap();
    assert!(!d.anomalies().is_empty());
}
