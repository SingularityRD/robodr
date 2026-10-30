//! Anchoring a signed record in a TPM NV counter (Sprint 14b,
//! `docs/SECURE-DELIVERY.md` §6.4): the technique of `robodr-blackbox`'s
//! `TpmNvCounterAnchor`, for a record that is rewritten in place (the
//! unit's signed high-water record of floors, the depot's database).
//!
//! The record carries `nv`, the counter value it belongs to. A write is:
//! write the new record with `nv = T + 1` (durably), **then** increment
//! the counter to `T + 1`. At open, with the counter at `T`:
//!
//! | record `nv` | counter | verdict |
//! |---|---|---|
//! | `T` | `T` | current |
//! | `T + 1` | `T` | the last write crashed before its increment: [`Verdict::CompleteIncrement`] |
//! | `< T` | `T` | an older record (disk or backup restored): **rollback** |
//! | `> T + 1` | `T` | the counter is behind the record: another TPM, or cleared |
//! | any | unwritten | the counter was undefined and defined again (owner authorization), or another TPM |
//! | none | unwritten | first anchored write ([`Verdict::Migrate`]: a record from before the anchor) |
//! | none | `T` | a record from before the anchor after the anchor was used: **rollback** |
//! | any | undefined | the index is gone |
//!
//! A counter never decreases, and one defined again starts at the highest
//! value any counter of the TPM ever held, so neither a restored disk nor
//! a recreated index reopens an old record. Records are signed, so an
//! attacker can only present records the writer wrote. What stays open:
//! a crash between the first (migration) increment and the record write
//! locks the writer until an operator re-anchors it.

use crate::tpm_ident::Counter;

/// What to do with a record and a counter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The record is the newest.
    Current,
    /// The record is one ahead: increment the counter now.
    CompleteIncrement,
    /// No anchor yet (record without `nv`, counter unwritten): the next
    /// write increments first and records the value it reads back.
    Migrate,
    /// Refuse: the reason.
    Locked(String),
}

/// Judge `record_nv` (the value the record names, `None` for a record
/// written before the anchor) against `counter`.
pub fn judge(record_nv: Option<u64>, counter: Counter) -> Verdict {
    match (record_nv, counter) {
        (None, Counter::Unwritten) => Verdict::Migrate,
        (_, Counter::Undefined) => Verdict::Locked(
            "the anti-rollback NV counter is not defined (provision it; if it was, it has been \
             undefined with the owner authorization, or this is another TPM)"
                .into(),
        ),
        (Some(r), Counter::Unwritten) => Verdict::Locked(format!(
            "the record is anchored at NV counter value {r}, but the counter is unwritten: it \
             was undefined and defined again, or this is another TPM"
        )),
        (None, Counter::Value(t)) => Verdict::Locked(format!(
            "a record from before the anchor while the NV counter is at {t}: an older record \
             was restored (rollback)"
        )),
        (Some(r), Counter::Value(t)) if r == t => Verdict::Current,
        (Some(r), Counter::Value(t)) if t.checked_add(1) == Some(r) => Verdict::CompleteIncrement,
        (Some(r), Counter::Value(t)) if r < t => Verdict::Locked(format!(
            "the record is anchored at NV counter value {r}, the counter is at {t}: an older \
             record was restored (rollback)"
        )),
        (Some(r), Counter::Value(t)) => Verdict::Locked(format!(
            "the record names NV counter value {r}, the counter is only at {t}: another TPM, or \
             it was cleared"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdicts() {
        use Counter::*;
        assert_eq!(judge(None, Unwritten), Verdict::Migrate);
        assert_eq!(judge(Some(9), Value(9)), Verdict::Current);
        assert_eq!(judge(Some(10), Value(9)), Verdict::CompleteIncrement);
        for (r, c) in [
            (Some(8), Value(9)),
            (Some(12), Value(9)),
            (Some(9), Unwritten),
            (None, Value(9)),
            (Some(9), Undefined),
            (None, Undefined),
        ] {
            assert!(matches!(judge(r, c), Verdict::Locked(_)), "{r:?} {c:?}");
        }
        assert!(matches!(
            judge(Some(u64::MAX), Value(u64::MAX - 5)),
            Verdict::Locked(_)
        ));
        assert_eq!(
            judge(Some(u64::MAX), Value(u64::MAX - 1)),
            Verdict::CompleteIncrement
        );
    }
}
