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
//! A revert that changes a request's state (the first revert record:
//! `not_applied`, or an executor revert `pending` / `reverted`; or a status
//! that becomes `reverted`) follows the same steps with `revert_begin` /
//! `revert_commit` / `revert_abort`.
//!
//! executor v1: the executor's word on a request (`verified`, `refused`,
//! `failed`, `reverted`, ...) is one `executor` entry, appended (fsync)
//! before the new state is answered; it is the executor's own record, not a
//! decision, so it has no begin/commit pair. A request that read `verified`
//! reads `verified` after a restart.
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
use super::journal::{AnchorCheck, Head, Journal, Loaded, Sealing};

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

/// The refusal code an executor answer carries when it names none
/// (`crate::executor_link`).
pub const EXECUTOR_REFUSED: &str = "executor_refused";

/// A persisted refusal code: the control plane's own, or (executor v1) the
/// executor's (`robodr_executor::decision::codes`).
fn static_code(s: &str) -> Option<&'static str> {
    REFUSAL_CODES
        .iter()
        .copied()
        .find(|c| *c == s)
        .or_else(|| robodr_executor::decision::codes::intern(s))
        .or((s == EXECUTOR_REFUSED).then_some(EXECUTOR_REFUSED))
}

fn static_executor(s: &str) -> Option<&'static str> {
    ["recording", "robodr-executor"]
        .into_iter()
        .find(|c| *c == s)
}

fn static_revert_result(s: &str) -> Option<&'static str> {
    ["not_applied", "pending", "reverted"]
        .into_iter()
        .find(|c| *c == s)
}

fn parse_status(s: &str) -> Option<Status> {
    Some(match s {
        "recorded_not_executed" => Status::RecordedNotExecuted,
        "pending" => Status::Pending,
        "applied" => Status::Applied,
        "refused" => Status::Refused,
        "failed" => Status::Failed,
        "verified" => Status::Verified,
        "reverted" => Status::Reverted,
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
    /// Review R2-3 (absent when `None`, so a journal without quarantine
    /// scopes reads as before).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantine: Option<super::api::QuarantineScope>,
}

impl PRefusal {
    pub fn of(r: &Refusal) -> Self {
        Self {
            code: r.code.to_string(),
            reason: r.reason.clone(),
            safety_state: r.safety_state,
        }
    }

    pub fn to_refusal(&self) -> Option<Refusal> {
        Some(Refusal {
            code: static_code(&self.code)?,
            reason: self.reason.clone(),
            safety_state: self.safety_state,
        })
    }
}

impl PStored {
    pub fn of(s: &Stored) -> Self {
        Self {
            request: s.request.clone(),
            digest: s.digest.clone(),
            key_id: s.key_id.clone(),
            status: s.status.as_str().to_string(),
            refusal: s.refusal.as_ref().map(PRefusal::of),
            safety_state: s.safety_state,
            accepted: s.accepted.clone(),
            error: s.error.clone(),
            received_ms: s.received_ms,
            evidence: s.evidence.clone(),
            executor: s.executor.to_string(),
            revert: s.revert.as_ref().map(PRevert::of),
            quarantine: s.quarantine.clone(),
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
            Some(r) => Some(r.to_refusal()?),
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
            quarantine: self
                .quarantine
                .clone()
                .map(super::api::QuarantineScope::bounded),
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
    /// executor v1: the executor's word on a stored request (its status,
    /// error and refusal after it, and how far an applied quarantine
    /// reaches: review R2-3, absent when unknown).
    Executor {
        request_id: String,
        status: String,
        error: Option<String>,
        refusal: Option<PRefusal>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        quarantine: Option<super::api::QuarantineScope>,
    },
}

/// Apply an `executor` entry to a stored request; `false` if it does not
/// convert back (damage). An entry for a request no longer stored (evicted)
/// is ignored.
fn apply_executor(
    store: &mut HashMap<String, Stored>,
    request_id: &str,
    status: &str,
    error: &Option<String>,
    refusal: &Option<PRefusal>,
    quarantine: &Option<super::api::QuarantineScope>,
) -> bool {
    let Some(status) = parse_status(status) else {
        return false;
    };
    let refusal = match refusal {
        None => None,
        Some(r) => match r.to_refusal() {
            Some(r) => Some(r),
            None => return false,
        },
    };
    if let Some(s) = store.get_mut(request_id) {
        s.status = status;
        s.error = error.clone();
        s.refusal = refusal;
        if quarantine.is_some() {
            s.quarantine = quarantine.clone().map(super::api::QuarantineScope::bounded);
        }
    }
    true
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
    /// Of `damaged`, lines whose seal did not verify (an edit or deletion).
    pub forged: usize,
    /// The journal is sealed under another key (named).
    pub wrong_key: Option<String>,
    /// A v1 journal was adopted (one-time upgrade).
    pub upgraded_from_v1: bool,
    /// A v1 journal after sealing had started (a downgrade): damage.
    pub legacy_refused: bool,
    /// The comparison with the black box's newest head.
    pub anchor: AnchorCheck,
}

impl Restored {
    /// The journal may have lost committed requests (damage, an edit, a
    /// rollback, a tail after the black box's newest head, an unsealed v1
    /// file): the black box is the record, reconcile with it.
    pub fn untrusted(&self) -> bool {
        self.damaged > 0
            || self.upgraded_from_v1
            || matches!(
                self.anchor,
                AnchorCheck::RolledBack(_) | AnchorCheck::Unanchored(_)
            )
    }
}

/// Open the journal in `dir` and replay it (newest `max` requests kept).
pub fn open(
    dir: &Path,
    max: usize,
    sealing: &Sealing,
) -> std::io::Result<(RequestJournal, Restored)> {
    let (journal, loaded): (Journal, Loaded<Entry>) = Journal::open(
        dir,
        REQUEST_JOURNAL,
        "requests",
        &sealing.key,
        sealing.requests.as_ref(),
        sealing.adopt_legacy,
    )?;
    let mut r = Restored {
        torn_bytes: loaded.torn_bytes,
        damaged: loaded.damaged,
        quarantined: loaded.quarantined.map(|p| p.display().to_string()),
        created: loaded.created,
        forged: loaded.forged,
        wrong_key: loaded.wrong_key,
        upgraded_from_v1: loaded.upgraded_from_v1,
        legacy_refused: loaded.legacy_refused,
        anchor: loaded.anchor,
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
                        (Some(s), Some(rec)) => apply_revert(s, rec),
                        // Evicted since: nothing to do.
                        (None, Some(_)) => {}
                        (_, None) => r.damaged += 1,
                    }
                }
                None => r.damaged += 1,
            },
            Entry::RevertAbort { decision_id } => {
                r.pending_reverts.remove(&decision_id);
            }
            Entry::Executor {
                request_id,
                status,
                error,
                refusal,
                quarantine,
            } => {
                if !apply_executor(
                    &mut store,
                    &request_id,
                    &status,
                    &error,
                    &refusal,
                    &quarantine,
                ) {
                    r.damaged += 1;
                } else if !store.contains_key(&request_id) {
                    // Its decision is still dangling (a commit that did not
                    // reach the journal): carry the executor's word into the
                    // begin, so the black box's verdict settles it with it.
                    for p in r.pending.values_mut() {
                        if p.request.request_id == request_id {
                            p.status.clone_from(&status);
                            p.error.clone_from(&error);
                            p.refusal.clone_from(&refusal);
                            if quarantine.is_some() {
                                p.quarantine.clone_from(&quarantine);
                            }
                        }
                    }
                }
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

/// What [`rebuild`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rebuilt {
    /// Requests restored from their black-box notes.
    pub requests: usize,
    /// Revert records restored from their notes.
    pub reverts: usize,
    /// Request ids whose note did not convert back (their resubmission is
    /// refused: their state is unknown).
    pub unreadable: Vec<String>,
}

/// A request note back to a [`Stored`] (its decision-time state; the
/// executor's later word, if any, comes from the executor's resync).
fn stored_from_note(n: &super::evidence::RequestNote) -> Option<Stored> {
    let v = &n.note;
    let from = |k: &str| v.get(k).cloned().unwrap_or(serde_json::Value::Null);
    let request: ActionRequest = serde_json::from_value(from("request")).ok()?;
    let p = PStored {
        digest: request.digest(),
        request,
        key_id: v.get("auth")?.get("key_id")?.as_str()?.to_string(),
        status: v.get("status")?.as_str()?.to_string(),
        refusal: serde_json::from_value(from("refusal")).ok()?,
        safety_state: serde_json::from_value(from("safety_state")).ok()?,
        accepted: serde_json::from_value(from("plan")).ok()?,
        error: serde_json::from_value(from("error")).ok()?,
        received_ms: n.wall_ms,
        evidence: n.evidence.clone(),
        executor: v.get("executor")?.as_str()?.to_string(),
        revert: None,
        quarantine: None,
    };
    p.to_stored()
}

/// Control plane v2 review, finding 4: after the request journal was
/// damaged, restore from the black box (the record) every request whose
/// signed `robodr.control_plane_request` note exists but that the journal
/// lost, and every revert record its `robodr.control_plane_revert` note
/// proves. `notes` oldest first; the newest `max` requests are kept.
pub fn rebuild(r: &mut Restored, notes: &[super::evidence::RequestNote], max: usize) -> Rebuilt {
    let mut out = Rebuilt::default();
    let journalled: std::collections::HashSet<String> = r
        .stored
        .iter()
        .map(|s| s.request.request_id.clone())
        .collect();
    for n in notes {
        let v = &n.note;
        match v.get("kind").and_then(serde_json::Value::as_str) {
            Some("robodr.control_plane_request") => {
                let Some(id) = v
                    .get("request")
                    .and_then(|q| q.get("request_id"))
                    .and_then(serde_json::Value::as_str)
                else {
                    continue;
                };
                if journalled.contains(id) || r.stored.iter().any(|s| s.request.request_id == id) {
                    continue;
                }
                match stored_from_note(n) {
                    Some(s) => {
                        out.requests += 1;
                        r.stored.push(s);
                    }
                    None => out.unreadable.push(id.to_string()),
                }
            }
            Some("robodr.control_plane_revert") => {
                let id = v.get("request_id").and_then(serde_json::Value::as_str);
                let result = v
                    .get("result")
                    .and_then(serde_json::Value::as_str)
                    .and_then(static_revert_result);
                let rv = v.get("revert");
                let text = |k: &str| {
                    rv.and_then(|r| r.get(k))
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string)
                };
                let (Some(id), Some(result), Some(requested_by), Some(reason)) =
                    (id, result, text("requested_by"), text("reason"))
                else {
                    continue;
                };
                if let Some(s) = r.stored.iter_mut().find(|s| s.request.request_id == id) {
                    let changes = s.revert.is_none()
                        || (result == "reverted" && s.status != Status::Reverted);
                    if changes {
                        apply_revert(
                            s,
                            RevertRecord {
                                requested_by,
                                reason,
                                at_ms: n.wall_ms,
                                result,
                                evidence: n.evidence.clone(),
                            },
                        );
                        out.reverts += 1;
                    }
                }
            }
            _ => {}
        }
    }
    r.stored.sort_by_key(|s| s.received_ms);
    if r.stored.len() > max {
        let cut = r.stored.len() - max;
        r.stored.drain(..cut);
    }
    out
}

/// A committed revert on its request: the first revert record is kept, and
/// an executor revert that reported `reverted` makes the request
/// `reverted`.
fn apply_revert(s: &mut Stored, rec: RevertRecord) {
    if rec.result == "reverted" {
        s.status = Status::Reverted;
    }
    if s.revert.is_none() {
        s.revert = Some(rec);
    }
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
                    apply_revert(s, rec);
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

    /// Where the journal ends now (anchored in the black box).
    pub fn head(&self) -> Head {
        self.journal.head()
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every refusal code the executor can answer (including the review's
    /// `locators_required`, `operator_disabled`, `config_unavailable`)
    /// survives the v2 journal: an `executor` entry carrying it converts
    /// back, so a refused request still reads refused after a restart.
    #[test]
    fn every_executor_refusal_code_survives_the_journal() {
        for code in robodr_executor::decision::codes::ALL
            .into_iter()
            .chain([EXECUTOR_REFUSED])
        {
            let p = PRefusal {
                code: code.to_string(),
                reason: "r".into(),
                safety_state: SafetyState::Idle,
            };
            let r = p.to_refusal().unwrap_or_else(|| panic!("{code} lost"));
            assert_eq!(r.code, code);
            let mut store = HashMap::new();
            assert!(apply_executor(
                &mut store,
                "absent",
                "refused",
                &None,
                &Some(p),
                &None
            ));
        }
        for s in ["pending", "verified", "reverted", "failed", "refused"] {
            assert_eq!(parse_status(s).map(|s| s.as_str()), Some(s));
        }
        // A code this build does not know is damage, never silently mapped.
        let p = PRefusal {
            code: "no_such_code".into(),
            reason: "r".into(),
            safety_state: SafetyState::Idle,
        };
        assert!(p.to_refusal().is_none());
    }
}
