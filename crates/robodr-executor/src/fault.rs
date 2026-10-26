//! Test-only crash points (feature `fault-injection`). A point armed on the
//! current thread makes the engine stop right there, as if the process
//! died: nothing after the point runs (no journal update, no rollback).
//! Tests then open a new engine on the same state directory and check the
//! reconciliation.

use std::cell::Cell;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Point {
    /// After the `applying` intent is journalled, before `nft -f`.
    AfterIntent,
    /// After `nft -f` installed the rules, before the read-back and the
    /// journal's `active` write.
    AfterApply,
    /// After the `reverting` intent, before the transaction.
    AfterRevertIntent,
    /// Every journal write fails (not a crash: an I/O error).
    JournalWrite,
}

thread_local! {
    static ARMED: Cell<Option<Point>> = const { Cell::new(None) };
}

/// Arm `p` on this thread (until [`disarm`]).
pub fn arm(p: Point) {
    ARMED.with(|a| a.set(Some(p)));
}

pub fn disarm() {
    ARMED.with(|a| a.set(None));
}

/// True when `p` is armed on this thread.
pub fn hit(p: Point) -> bool {
    ARMED.with(|a| a.get() == Some(p))
}
