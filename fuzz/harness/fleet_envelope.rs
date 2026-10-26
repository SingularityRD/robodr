//! Harness: fleet envelopes and SOC answers (`robodr_fleet::wire`): what
//! `robodr-enroll` reads from the SOC or from vetted media — enrollment,
//! rotate, retire and cancel answers, profile approvals, ring information, profile
//! offers, error bodies — and what the SOC reads (requests).
//!
//! Input: arbitrary bytes, offered to `Envelope::parse` for every type, to
//! the payload parser of that type, to `Offer::parse` and `error_code`.
//! Invariants beyond "no panic": a parsed envelope re-serialises to bytes
//! that parse to the same envelope and payload (canonical base64url), its
//! signatures are distinct and bounded, and no signature verifies under a
//! key that did not make it (the fixed foreign key); a parsed offer's
//! digest is the digest of its profile bytes.
//!
//! Seeds (`fuzz/corpus/fleet_envelope/`) are the contract vectors' bodies
//! (`docs/contracts/fixtures/fleet/`), copied by the vector generator.
#![allow(dead_code)]

use robodr_blackbox::Ed25519SigningKey;
use robodr_fleet::wire::{self, Envelope};

const TYPES: [&str; 11] = [
    wire::T_TOKEN,
    wire::T_ENROLL_REQUEST,
    wire::T_ENROLL_ANSWER,
    wire::T_ROTATE_REQUEST,
    wire::T_ROTATE_ANSWER,
    wire::T_RETIRE_REQUEST,
    wire::T_RETIRE_ANSWER,
    wire::T_CANCEL_REQUEST,
    wire::T_CANCEL_ANSWER,
    wire::T_APPROVAL,
    wire::T_RING,
];

pub fn run(data: &[u8]) {
    let foreign = Ed25519SigningKey::from_seed_with_derived_id(&[0x7f; 32]);
    for kind in TYPES {
        let Ok(o) = Envelope::parse(data, kind) else {
            continue;
        };
        assert!(!o.envelope.sigs.is_empty() && o.envelope.sigs.len() <= wire::MAX_SIGS);
        let again =
            Envelope::parse(&o.envelope.to_bytes(), kind).expect("re-serialised envelope parses");
        assert_eq!(again, o, "envelope does not round-trip");
        for id in o.signers() {
            assert!(
                o.verify_by(id, &foreign.public_key()).is_err(),
                "foreign key verifies"
            );
        }
        let p = &o.payload;
        let _ = match kind {
            wire::T_ENROLL_REQUEST => wire::EnrollRequest::parse(p).map(|_| ()),
            wire::T_ENROLL_ANSWER => wire::EnrollAnswer::parse(p).map(|_| ()),
            wire::T_ROTATE_REQUEST => wire::RotateRequest::parse(p).map(|_| ()),
            wire::T_ROTATE_ANSWER => {
                wire::KeyAnswer::parse(p, wire::ROTATE_ANSWER_FORMAT, "overlap").map(|_| ())
            }
            wire::T_RETIRE_REQUEST => wire::RetireRequest::parse(p).map(|_| ()),
            wire::T_RETIRE_ANSWER => {
                wire::KeyAnswer::parse(p, wire::RETIRE_ANSWER_FORMAT, "retired").map(|_| ())
            }
            wire::T_CANCEL_REQUEST => wire::CancelRequest::parse(p).map(|_| ()),
            wire::T_CANCEL_ANSWER => {
                wire::KeyAnswer::parse(p, wire::CANCEL_ANSWER_FORMAT, "cancelled").map(|_| ())
            }
            wire::T_APPROVAL => wire::Approval::parse(p).map(|_| ()),
            wire::T_RING => wire::RingInfo::parse(p).map(|_| ()),
            _ => Ok(()),
        };
        if kind == wire::T_ENROLL_REQUEST {
            let _ = o.verify_mac(&[0x33; 32]);
        }
    }
    if let Ok((o, profile, _sig)) = wire::Offer::parse(data) {
        assert_eq!(o.digest, wire::digest(&profile));
    }
    let _ = wire::error_code(data);
}
