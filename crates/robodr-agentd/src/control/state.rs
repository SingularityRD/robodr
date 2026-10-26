//! The persistent request-state journal (`<state_dir>/requests.journal`):
//! the control plane's request store survives a restart, so a status query
//! after a restart returns the same state, an idempotent resubmission is
//! still a duplicate and a revert still finds its request.
//!
//! # Protocol (per decision, on the main loop)
//!
//! ```text
//! 1. judge                        (no side effect)
//! 2. journal: begin {decision_id, state without evidence}      fsync
//! 3. black box: the decision note, carrying decision_id        fsync
//! 4. journal: commit {decision_id, evidence}                    fsync
//!    or, if 3 failed: abort {decision_id}                       fsync
//! 5. answer
//! ```
//!
//! A revert that changes a request's state (the first `not_applied`)
//! follows the same steps with `revert_begin` / `revert_commit` /
//! `revert_abort`.
//!
//! Crash points: before 2, nothing happened (a resubmission is judged
//! anew). Between 2 and 4 the journal holds a dangling `begin`: at the next
//! start the black box decides ([`resolve`]): a note with that
//! `decision_id` means the decision was recorded (it is committed with that
//! note's reference); none means nothing was recorded (aborted: like an
//! `evidence_unavailable` failure, nothing was decided). The answer of step
//! 5 is never sent before 4 is durable or resolvable, so no answer claims a
//! state the robot could forget.
//!
//! Compaction keeps the newest `max_requests` requests as `stored`
//! snapshots (crash-safe, see [`super::journal`]).

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::Path;

use robodr_responder::SafetyState;
use serde::{Deserialize, Serialize};

use super::api::{Accepted, ActionRequest, Refusal, RevertRecord, Status, Stored};
use super::journal::{Journal, Loaded};

/// The request journal's file name.
pub const REQUEST_JOURNAL: &str = "requests.journal";

/// Refusal codes a stored request can carry (a persisted code must be one
/// of these; anything else is damage).
pub const REFUSAL_CODES: [&str; 13] = [
    "safety_system_engaged",
    "observe_mode",
    "morphology_mismatch",
    "human_in_command",
    "transient_phase",
    "fall_hazard",
    "requires_idle",
    "above_policy",
    "not_a_restriction",
    "invalid_parameter",
    "invariant_violation",
    "not_reversible",
    "revert_unsupported",
];

fn static_code(s: &str) -> Option<&'static str> {
    REFUSAL_CODES.iter().copied().find(|c| *c == s)
}

fn static_executor(s: &str) -> Option<&'static str> {
    ["recording"].into_iter().find(|c| *c == s)
}

fn static_revert_result(s: &str) -> Option<&'static str> {
    ["not_applied"].into_iter().find(|c| *c == s)
}

fn parse_status(s: &str) -> Option<Status> {
    Some(match s {
        "recorded_not_executed" => Status::RecordedNotExecuted,
        "pending" => Status::Pending,
        "applied" => Status::Applied,
        "refused" => Status::Refused,
        "failed" => Status::Failed,
        _ => return None,
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PRefusal {
    pub code: String,
    pub reason: String,
    pub safety_state: SafetyState,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PRevert {
    pub requested_by: String,
    pub reason: String,
    pub at_ms: u64,
    pub result: String,
    pub evidence: String,
}

/// A stored request as persisted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PStored {
    pub request: ActionRequest,
    pub digest: String,
    pub key_id: String,
    pub status: String,
    pub refusal: Option<PRefusal>,
    pub safety_state: SafetyState,
    pub accepted: Option<Accepted>,
    pub error: Option<String>,
    pub received_ms: u64,
    pub evidence: String,
    pub executor: String,
    pub revert: Option<PRevert>,
}

impl PStored {
    pub fn of(s: &Stored) -> Self {
        Self {
            request: s.request.clone(),
            digest: s.digest.clone(),
            key_id: s.key_id.clone(),
            status: s.status.as_str().to_string(),
            refusal: s.refusal.as_ref().map(|r| PRefusal {
                code: r.code.to_string(),
                reason: r.reason.clone(),
                safety_state: r.safety_state,
            }),
            safety_state: s.safety_state,
            accepted: s.accepted.clone(),
            error: s.error.clone(),
            received_ms: s.received_ms,
            evidence: s.evidence.clone(),
            executor: s.executor.to_string(),
            revert: s.revert.as_ref().map(PRevert::of),
        }
    }

    /// Back to a [`Stored`]; `None` if anything is not what this code
    /// writes (then the entry is damage).
    pub fn to_stored(&self) -> Option<Stored> {
        if !super::api::request_id_ok(&self.request.request_id)
            || self.request.digest() != self.digest
        {
            return None;
        }
        let refusal = match &self.refusal {
            None => None,
            Some(r) => Some(Refusal {
                code: static_code(&r.code)?,
                reason: r.reason.clone(),
                safety_state: r.safety_state,
            }),
        };
        let revert = match &self.revert {
            None => None,
            Some(r) => Some(r.to_record()?),
        };
        Some(Stored {
            request: self.request.clone(),
            digest: self.digest.clone(),
            key_id: self.key_id.clone(),
            status: parse_status(&self.status)?,
            refusal,
            safety_state: self.safety_state,
            accepted: self.accepted.clone(),
            error: self.error.clone(),
            received_ms: self.received_ms,
            evidence: self.evidence.clone(),
            executor: static_executor(&self.executor)?,
            revert,
        })
    }
}

impl PRevert {
    pub fn of(r: &RevertRecord) -> Self {
        Self {
            requested_by: r.requested_by.clone(),
            reason: r.reason.clone(),
            at_ms: r.at_ms,
            result: r.result.to_string(),
            evidence: r.evidence.clone(),
        }
    }

    pub fn to_record(&self) -> Option<RevertRecord> {
        Some(RevertRecord {
            requested_by: self.requested_by.clone(),
            reason: self.reason.clone(),
            at_ms: self.at_ms,
            result: static_revert_result(&self.result)?,
            evidence: self.evidence.clone(),
        })
    }
}

/// One journal entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case", deny_unknown_fields)]
pub enum Entry {
    /// A complete request (compaction snapshot).
    Stored {
        stored: PStored,
    },
    /// A decision about to be recorded (`stored.evidence` empty).
    Begin {
        decision_id: String,
        stored: PStored,
    },
    Commit {
        decision_id: String,
        evidence: String,
    },
    Abort {
        decision_id: String,
    },
    RevertBegin {
        decision_id: String,
        request_id: String,
        revert: PRevert,
    },
    RevertCommit {
        decision_id: String,
        evidence: String,
    },
    RevertAbort {
        decision_id: String,
    },
}

/// The journal plus its bookkeeping.
#[derive(Debug)]
pub struct RequestJournal {
    journal: Journal,
    /// Append failures since start.
    pub errors: u64,
    /// Compactions since start.
    pub compactions: u64,
}

/// What [`open`] restored.
#[derive(Debug, Default)]
pub struct Restored {
    /// Requests in store order (oldest first).
    pub stored: Vec<Stored>,
    /// Dangling decisions: `decision_id -> begin`.
    pub pending: BTreeMap<String, PStored>,
    /// Dangling reverts: `decision_id -> (request id, revert)`.
    pub pending_reverts: BTreeMap<String, (String, PRevert)>,
    pub torn_bytes: u64,
    /// Damaged lines plus entries that do not convert back.
    pub damaged: usize,
    pub quarantined: Option<String>,
    pub created: bool,
}

/// Open the journal in `dir` and replay it (newest `max` requests kept).
pub fn open(dir: &Path, max: usize) -> std::io::Result<(RequestJournal, Restored)> {
    let (journal, loaded): (Journal, Loaded<Entry>) =
        Journal::open(dir, REQUEST_JOURNAL, "requests")?;
    let mut r = Restored {
        torn_bytes: loaded.torn_bytes,
        damaged: loaded.damaged,
        quarantined: loaded.quarantined.map(|p| p.display().to_string()),
        created: loaded.created,
        ..Restored::default()
    };
    let mut store: HashMap<String, Stored> = HashMap::new();
    let mut order: VecDeque<String> = VecDeque::new();
    let mut insert = |s: Stored, store: &mut HashMap<String, Stored>| {
        let id = s.request.request_id.clone();
        if store.insert(id.clone(), s).is_none() {
            order.push_back(id);
        }
        while store.len() > max {
            match order.pop_front() {
                Some(old) => {
                    store.remove(&old);
                }
                None => break,
            }
        }
    };
    for e in loaded.entries {
        match e {
            Entry::Stored { stored } => match stored.to_stored() {
                Some(s) => insert(s, &mut store),
                None => r.damaged += 1,
            },
            Entry::Begin {
                decision_id,
                stored,
            } => {
                r.pending.insert(decision_id, stored);
            }
            Entry::Commit {
                decision_id,
                evidence,
            } => match r.pending.remove(&decision_id) {
                Some(mut p) => {
                    p.evidence = evidence;
                    match p.to_stored() {
                        Some(s) => insert(s, &mut store),
                        None => r.damaged += 1,
                    }
                }
                None => r.damaged += 1,
            },
            Entry::Abort { decision_id } => {
                r.pending.remove(&decision_id);
            }
            Entry::RevertBegin {
                decision_id,
                request_id,
                revert,
            } => {
                r.pending_reverts.insert(decision_id, (request_id, revert));
            }
            Entry::RevertCommit {
                decision_id,
                evidence,
            } => match r.pending_reverts.remove(&decision_id) {
                Some((id, mut rv)) => {
                    rv.evidence = evidence;
                    match (store.get_mut(&id), rv.to_record()) {
                        (Some(s), Some(rec)) if s.revert.is_none() => s.revert = Some(rec),
                        // Evicted since, or already reverted: nothing to do.
                        (_, Some(_)) => {}
                        (_, None) => r.damaged += 1,
                    }
                }
                None => r.damaged += 1,
            },
            Entry::RevertAbort { decision_id } => {
                r.pending_reverts.remove(&decision_id);
            }
        }
    }
    r.stored = order
        .into_iter()
        .filter_map(|id| store.remove(&id))
        .collect();
    Ok((
        RequestJournal {
            journal,
            errors: 0,
            compactions: 0,
        },
        r,
    ))
}

/// Settle the dangling decisions of `r` with the black box's verdict
/// (`found`: `decision_id -> evidence reference` of the notes that exist):
/// a recorded one is committed, an unrecorded one aborted. Appends the
/// resolution to the journal. Returns (committed, aborted).
pub fn resolve(
    j: &mut RequestJournal,
    r: &mut Restored,
    found: &BTreeMap<String, String>,
    max: usize,
) -> std::io::Result<(usize, usize)> {
    let (mut committed, mut aborted) = (0, 0);
    for (id, mut p) in std::mem::take(&mut r.pending) {
        match found.get(&id) {
            Some(ev) => {
                p.evidence = ev.clone();
                j.journal.append(&Entry::Commit {
                    decision_id: id,
                    evidence: ev.clone(),
                })?;
                match p.to_stored() {
                    Some(s) => {
                        r.stored
                            .retain(|o| o.request.request_id != s.request.request_id);
                        r.stored.push(s);
                        if r.stored.len() > max {
                            let cut = r.stored.len() - max;
                            r.stored.drain(..cut);
                        }
                    }
                    None => r.damaged += 1,
                }
                committed += 1;
            }
            None => {
                j.journal.append(&Entry::Abort { decision_id: id })?;
                aborted += 1;
            }
        }
    }
    for (id, (rid, mut rv)) in std::mem::take(&mut r.pending_reverts) {
        match found.get(&id) {
            Some(ev) => {
                rv.evidence = ev.clone();
                j.journal.append(&Entry::RevertCommit {
                    decision_id: id,
                    evidence: ev.clone(),
                })?;
                if let (Some(s), Some(rec)) = (
                    r.stored.iter_mut().find(|s| s.request.request_id == rid),
                    rv.to_record(),
                ) {
                    if s.revert.is_none() {
                        s.revert = Some(rec);
                    }
                }
                committed += 1;
            }
            None => {
                j.journal.append(&Entry::RevertAbort { decision_id: id })?;
                aborted += 1;
            }
        }
    }
    Ok((committed, aborted))
}

impl RequestJournal {
    /// Append and count a failure (the caller decides what a failure means).
    pub fn append(&mut self, e: &Entry) -> std::io::Result<()> {
        let r = self.journal.append(e);
        if r.is_err() {
            self.errors += 1;
        }
        r
    }

    /// Entries in the file.
    pub fn lines(&self) -> usize {
        self.journal.lines()
    }

    /// Rewrite as snapshots of `stored` (oldest first).
    pub fn compact<'a>(&mut self, stored: impl Iterator<Item = &'a Stored>) -> std::io::Result<()> {
        let entries: Vec<Entry> = stored
            .map(|s| Entry::Stored {
                stored: PStored::of(s),
            })
            .collect();
        let r = self.journal.compact(&entries);
        match &r {
            Ok(()) => self.compactions += 1,
            Err(_) => self.errors += 1,
        }
        r
    }
}
