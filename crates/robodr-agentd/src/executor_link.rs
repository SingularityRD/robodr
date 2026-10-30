//! agentd's link to the executor process (`executor`, executor v1; off by
//! default: with `executor.enabled = false` or no section, nothing changes
//! and every accepted request stays `recorded_not_executed`).
//!
//! agentd holds **no** `CAP_NET_ADMIN`: it hands orders to
//! `robodr-executor` (a separate unit with that capability only) over the
//! authenticated unix-socket protocol of `robodr_executor::proto`.
//!
//! ```text
//!  control plane: judged + approved request ─┐
//!  planner: Eligible plan, steps_without_approval_for(own morphology) ─┤
//!                                            ▼
//!                  staged (main loop) ── dispatched only once the request /
//!                                        plan note is in the black box
//!                                            ▼ bounded queue (try_send)
//!                  worker thread ── submit ─► robodr-executor ─ confirm ─┐
//!                     │  ◄── safety state now (SafetyCell, age) ─────────┘
//!                     │  ◄── outcome (verified / refused / failed)
//!                     └─ polls events (TTL reverts, drift, revert failures)
//!                                            ▼
//!                  main loop: outcomes → request states; events → signed
//!                  black-box notes (`robodr.executor_event`); record_evidence
//!                  → black-box mark (agentd owns the black box)
//! ```
//!
//! The detection loop never blocks on the executor: orders go through a
//! bounded queue to one worker thread (a full queue fails the order, it is
//! never retried silently).

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use robodr_agent::executor::{ExecutionRequest, Executor};
use robodr_executor::client::Client;
use robodr_executor::decision::codes;
use robodr_executor::engine::{Outcome, Status as ExStatus};
use robodr_executor::journal::{Event, EventKind, JournalHead};
use robodr_executor::order::{ExcludedAddress, ExcludedLocator, Locator, Order, Origin, Target};
use robodr_executor::proto::Key;
use robodr_executor::soc::SocRequest;
use robodr_responder::{ActionId, Morphology, ResponseAction, RestrictTarget, SafetyState, Step};
use robodr_ros2_pipeline::{BindingTable, QuarantineTarget};
use serde::{Deserialize, Serialize};

use crate::control::api::{
    AcceptedAction, ActionExecutor, ExecutorOutcome, Meta, QuarantineScope, ScopeExcluded,
    ScopeExcludedAddress,
};

fn default_socket() -> PathBuf {
    PathBuf::from("/run/robodr-executor/executor.sock")
}
fn default_timeout_ms() -> u64 {
    5_000
}
fn default_true() -> bool {
    true
}

/// Orders waiting for the worker.
pub const QUEUE: usize = 16;
/// Outcomes remembered.
pub const MAX_OUTCOMES: usize = 1024;
/// Events waiting to be recorded.
pub const MAX_PENDING_EVENTS: usize = 256;
/// How often the worker asks for new events.
pub const POLL: Duration = Duration::from_secs(1);

/// `executor` in agentd.json.
///
/// ```json
/// "executor": {
///   "enabled": true,
///   "socket": "/run/robodr-executor/executor.sock",
///   "key_file": "/run/credentials/robodr-agentd.service/executor.key"
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorSection {
    /// Off (the default): observe / record only, nothing reaches the
    /// executor.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_socket")]
    pub socket: PathBuf,
    /// The shared protocol key (64 hex digits), required when enabled.
    #[serde(default)]
    pub key_file: Option<PathBuf>,
    /// Also hand the planner's executable steps (Eligible plans, no human
    /// needed) to the executor; `false` = SOC-approved requests only.
    #[serde(default = "default_true")]
    pub planner_orders: bool,
    /// Per-exchange deadline, 500..=30000 ms.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

/// A validated, enabled [`ExecutorSection`].
#[derive(Debug, Clone)]
pub struct ExecutorSpec {
    pub socket: PathBuf,
    pub key: Key,
    pub planner_orders: bool,
    pub timeout: Duration,
}

impl ExecutorSection {
    /// `Ok(None)` when disabled.
    pub fn resolve(&self) -> Result<Option<ExecutorSpec>, String> {
        if !self.enabled {
            return Ok(None);
        }
        if !self.socket.is_absolute() {
            return Err("executor.socket must be an absolute path".into());
        }
        if !(500..=30_000).contains(&self.timeout_ms) {
            return Err("executor.timeout_ms must be 500..=30000".into());
        }
        let Some(kf) = &self.key_file else {
            return Err("executor.key_file is required when executor.enabled is true".into());
        };
        let key = Key::load(kf).map_err(|e| format!("executor.key_file: {e}"))?;
        Ok(Some(ExecutorSpec {
            socket: self.socket.clone(),
            key,
            planner_orders: self.planner_orders,
            timeout: Duration::from_millis(self.timeout_ms),
        }))
    }
}

/// agentd's current safety state, published by the main loop and read by
/// the worker when the executor asks (immediately before it applies).
#[derive(Debug, Clone, Default)]
pub struct SafetyCell(Arc<Mutex<Option<(SafetyState, Instant)>>>);

impl SafetyCell {
    pub fn set(&self, s: SafetyState) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some((s, Instant::now()));
    }

    /// The state and its age (ms), or why there is none.
    pub fn get(&self) -> Result<(SafetyState, u64), String> {
        match *self.0.lock().unwrap_or_else(PoisonError::into_inner) {
            Some((s, at)) => Ok((
                s,
                u64::try_from(at.elapsed().as_millis()).unwrap_or(u64::MAX),
            )),
            None => Err("agentd has not evaluated the safety state yet".into()),
        }
    }
}

/// Counters (`status.json` `executor`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct LinkStats {
    pub submitted: u64,
    pub verified: u64,
    pub refused: u64,
    pub failed: u64,
    pub reverted: u64,
    pub revert_failures: u64,
    pub queue_full: u64,
    pub unreachable: u64,
    pub events: u64,
    pub evidence_marks: u64,
    /// Staged orders dropped because their request / plan was not recorded.
    pub dropped_unrecorded: u64,
    /// The executor found its journal unreadable and reset it (High: what
    /// was in force is gone; see `robodr-executor status`).
    pub journal_resets: u64,
}

enum Job {
    Submit(Order),
    Revert(String, String, Option<Box<SocRequest>>),
    /// Ask the executor for the state of requests restored from agentd's
    /// journal (after a restart the link's outcomes are empty).
    Resync(Vec<String>),
}

#[derive(Default)]
struct Shared {
    outcomes: HashMap<String, Outcome>,
    order: VecDeque<String>,
    /// Requests whose outcome changed since the main loop last looked
    /// (it journals the new state at once, control plane v2).
    changed: VecDeque<String>,
    events: VecDeque<Event>,
    last_seq: u64,
    stats: LinkStats,
    /// The executor's journal head as agentd last knew it (from the black
    /// box at start, then from every `events` answer): sent back as the
    /// anchor (review of gap 1, findings 1 and 2).
    head: Option<JournalHead>,
    /// Journal heads that changed the epoch or went backwards, with the
    /// alarm they call for (taken by the main loop: recorded, finding).
    head_alarms: VecDeque<(JournalHead, String)>,
}

/// What an `events` answer's head means against the head agentd knew
/// (review of gap 1, finding 1). Returns the alarm, if any, and the
/// `last_seq` to continue from (`None`: unchanged).
pub fn judge_head(
    known: Option<&JournalHead>,
    got: &JournalHead,
    last_seq: u64,
) -> (Option<String>, Option<u64>) {
    let restart = |next_seq: u64| (next_seq.saturating_sub(1) < last_seq).then_some(0);
    match known {
        None => (None, restart(got.next_seq)),
        Some(k) if k.epoch != got.epoch => (
            Some(format!(
                "robodr-executor's journal epoch changed ({} to {}, now at event {}): its journal \
                 was reset or replaced; whatever it held is gone",
                robodr_ros2_pipeline::sanitize(&k.epoch),
                robodr_ros2_pipeline::sanitize(&got.epoch),
                got.next_seq
            )),
            restart(got.next_seq),
        ),
        Some(k) if got.next_seq < k.next_seq => (
            Some(format!(
                "robodr-executor's journal went backwards (event {} after {} in epoch {}): an \
                 older copy was put back",
                got.next_seq,
                k.next_seq,
                robodr_ros2_pipeline::sanitize(&got.epoch)
            )),
            Some(got.next_seq.saturating_sub(1).min(last_seq)),
        ),
        Some(_) => (None, None),
    }
}

impl Shared {
    fn put(&mut self, o: Outcome) {
        match o.status {
            ExStatus::Verified => self.stats.verified += 1,
            ExStatus::Refused => self.stats.refused += 1,
            ExStatus::Failed => self.stats.failed += 1,
            ExStatus::Reverted => self.stats.reverted += 1,
            _ => {}
        }
        if !self.outcomes.contains_key(&o.id) {
            self.order.push_back(o.id.clone());
        }
        if self.changed.len() < MAX_OUTCOMES && !self.changed.contains(&o.id) {
            self.changed.push_back(o.id.clone());
        }
        self.outcomes.insert(o.id.clone(), o);
        while self.outcomes.len() > MAX_OUTCOMES {
            match self.order.pop_front() {
                Some(old) => {
                    self.outcomes.remove(&old);
                }
                None => break,
            }
        }
    }
}

/// What the main loop does with a staged item.
#[derive(Debug, Clone)]
pub enum Staged {
    /// Send once the request (or plan) is recorded.
    Submit(Order),
    /// Send once the revert note is recorded, with the SOC's signed revert
    /// request (executor review F3).
    Revert {
        id: String,
        reason: String,
        soc: Option<Box<SocRequest>>,
    },
    /// `record_evidence`: a black-box mark done by the main loop.
    Evidence(Order),
}

/// The link: worker thread, queue and shared state.
pub struct ExecutorLink {
    /// SPDP locators seen in participant events (see [`LocatorBook`]).
    book: LocatorBook,
    shared: Arc<Mutex<Shared>>,
    staged: Arc<Mutex<Vec<Staged>>>,
    tx: Option<SyncSender<Job>>,
    worker: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    safety: SafetyCell,
    pub planner_orders: bool,
}

impl std::fmt::Debug for ExecutorLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutorLink").finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn unreachable_outcome(id: &str, e: &str) -> Outcome {
    Outcome {
        id: id.into(),
        status: ExStatus::Failed,
        action: None,
        refusal: None,
        error: Some(format!("executor unreachable: {e}")),
        applied_ms: None,
        deadline_ms: None,
        duplicate: false,
        note: None,
        quarantine: None,
    }
}

impl ExecutorLink {
    /// Start the worker. Nothing is sent until orders are dispatched.
    pub fn start(spec: &ExecutorSpec, safety: SafetyCell) -> Result<Self, String> {
        Self::start_anchored(spec, safety, None)
    }

    /// [`ExecutorLink::start`] with the executor journal head agentd's
    /// black box holds (`anchor`, review of gap 1): sent with every event
    /// poll, so an older executor journal put back is reset by the executor.
    pub fn start_anchored(
        spec: &ExecutorSpec,
        safety: SafetyCell,
        anchor: Option<JournalHead>,
    ) -> Result<Self, String> {
        let (tx, rx) = sync_channel::<Job>(QUEUE);
        let shared = Arc::new(Mutex::new(Shared {
            head: anchor,
            ..Shared::default()
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let client = Client::new(spec.socket.clone(), spec.key.clone(), spec.timeout);
        let (sh, st, cell) = (shared.clone(), stop.clone(), safety.clone());
        let worker = std::thread::Builder::new()
            .name("agentd-executor".into())
            .spawn(move || {
                let mut watch: Vec<String> = Vec::new();
                while !st.load(Ordering::SeqCst) {
                    match rx.recv_timeout(POLL) {
                        Ok(Job::Submit(order)) => {
                            let out =
                                client
                                    .submit(&order, &mut || cell.get())
                                    .unwrap_or_else(|e| {
                                        lock(&sh).stats.unreachable += 1;
                                        unreachable_outcome(&order.id, &e)
                                    });
                            if out.status == ExStatus::Verified {
                                watch.push(order.id.clone());
                            }
                            lock(&sh).put(out);
                        }
                        Ok(Job::Revert(id, reason, soc)) => {
                            match client.revert_signed(&id, &reason, soc.as_deref()) {
                                Ok(out) => lock(&sh).put(out),
                                Err(e) => {
                                    let mut g = lock(&sh);
                                    g.stats.unreachable += 1;
                                    g.stats.revert_failures += 1;
                                    // The executor still holds it (or its TTL
                                    // will lift it): report, keep watching.
                                    if let Some(o) = g.outcomes.get_mut(&id) {
                                        o.error = Some(format!("revert not delivered: {e}"));
                                    }
                                }
                            }
                        }
                        Ok(Job::Resync(ids)) => {
                            for id in ids {
                                if st.load(Ordering::SeqCst) {
                                    break;
                                }
                                match client.status(&id) {
                                    Ok(o) if o.status == ExStatus::Unknown => {}
                                    Ok(o) => {
                                        if o.status == ExStatus::Verified && !watch.contains(&id) {
                                            watch.push(id.clone());
                                        }
                                        lock(&sh).put(o);
                                    }
                                    Err(_) => {
                                        lock(&sh).stats.unreachable += 1;
                                        break;
                                    }
                                }
                            }
                        }
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                    // Events (TTL reverts, drift, revert failures) and the
                    // state of watched actions.
                    // The safety state goes along: actions the executor holds
                    // after a reboot are re-armed only with a fresh one. So
                    // does the journal head agentd anchored (review of gap 1).
                    let mut polled = None;
                    for _ in 0..2 {
                        let (since, anchor) = {
                            let g = lock(&sh);
                            (g.last_seq, g.head.clone())
                        };
                        let Ok((evs, head)) =
                            client.events_anchored(since, anchor.as_ref(), &mut || cell.get())
                        else {
                            break;
                        };
                        let Some(head) = head else {
                            // An executor that reports no head (older).
                            polled = Some(evs);
                            break;
                        };
                        let mut g = lock(&sh);
                        let (alarm, reset) = judge_head(g.head.as_ref(), &head, g.last_seq);
                        g.head = Some(head.clone());
                        if let Some(a) = alarm {
                            g.head_alarms.push_back((head.clone(), a));
                        }
                        match reset {
                            // The sequence restarted: read it again from
                            // its start (these events were filtered against
                            // the old one).
                            Some(s) if s < g.last_seq => g.last_seq = s,
                            _ => {
                                polled = Some(evs);
                                break;
                            }
                        }
                    }
                    if let Some(evs) = polled {
                        let mut changed = Vec::new();
                        {
                            let mut g = lock(&sh);
                            for ev in evs {
                                g.last_seq = g.last_seq.max(ev.seq);
                                g.stats.events += 1;
                                if ev.kind == EventKind::RevertFailed {
                                    g.stats.revert_failures += 1;
                                }
                                if ev.kind == EventKind::JournalReset {
                                    g.stats.journal_resets += 1;
                                }
                                if let Some(id) = &ev.id {
                                    changed.push(id.clone());
                                }
                                if g.events.len() < MAX_PENDING_EVENTS {
                                    g.events.push_back(ev);
                                }
                            }
                        }
                        for id in changed {
                            if watch.contains(&id) {
                                if let Ok(o) = client.status(&id) {
                                    if o.status != ExStatus::Verified {
                                        watch.retain(|w| w != &id);
                                    }
                                    lock(&sh).put(o);
                                }
                            }
                        }
                    }
                }
            })
            .map_err(|e| format!("executor link thread: {e}"))?;
        Ok(Self {
            book: LocatorBook::default(),
            shared,
            staged: Arc::new(Mutex::new(Vec::new())),
            tx: Some(tx),
            worker: Some(worker),
            stop,
            safety,
            planner_orders: spec.planner_orders,
        })
    }

    pub fn safety(&self) -> &SafetyCell {
        &self.safety
    }

    /// The control plane's executor (shares this link).
    pub fn control_executor(&self, own: Morphology) -> ControlExecutor {
        ControlExecutor {
            shared: self.shared.clone(),
            staged: self.staged.clone(),
            own,
        }
    }

    /// The agent's (planner's) executor (shares this link).
    pub fn planner_executor(&self, own: Morphology) -> PlannerExecutor {
        PlannerExecutor {
            staged: self.staged.clone(),
            own,
        }
    }

    /// Everything staged since the last call.
    pub fn take_staged(&self) -> Vec<Staged> {
        std::mem::take(&mut *lock(&self.staged))
    }

    /// Hand an order or revert to the worker (never blocks). A full queue
    /// fails the order.
    pub fn dispatch(&self, s: Staged) {
        let Some(tx) = &self.tx else { return };
        let (job, id) = match s {
            Staged::Submit(o) => {
                let id = o.id.clone();
                (Job::Submit(o), id)
            }
            Staged::Revert { id, reason, soc } => (Job::Revert(id.clone(), reason, soc), id),
            Staged::Evidence(_) => return,
        };
        let mut g = lock(&self.shared);
        g.stats.submitted += 1;
        match tx.try_send(job) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                g.stats.queue_full += 1;
                drop(g);
                lock(&self.shared).put(unreachable_outcome(&id, "queue full"));
            }
        }
    }

    /// Record an outcome produced in agentd (evidence marks).
    pub fn put(&self, o: Outcome) {
        let mut g = lock(&self.shared);
        if o.status == ExStatus::Verified && o.action == Some(ActionId::RecordEvidence) {
            g.stats.evidence_marks += 1;
        }
        g.put(o);
    }

    /// Ask the executor, once, for the state of the requests agentd
    /// restored (never blocks; a full queue skips it: the requests keep
    /// their journalled state until the executor's next word).
    pub fn resync(&self, ids: Vec<String>) {
        if ids.is_empty() {
            return;
        }
        if let Some(tx) = &self.tx {
            if tx.try_send(Job::Resync(ids)).is_err() {
                lock(&self.shared).stats.queue_full += 1;
            }
        }
    }

    /// Requests whose outcome changed since the last call.
    pub fn take_changed(&self) -> Vec<String> {
        lock(&self.shared).changed.drain(..).collect()
    }

    pub fn count_dropped(&self) {
        lock(&self.shared).stats.dropped_unrecorded += 1;
    }

    /// Executor events not yet recorded.
    pub fn take_events(&self) -> Vec<Event> {
        lock(&self.shared).events.drain(..).collect()
    }

    /// The executor's journal head as agentd knows it now.
    pub fn journal_head(&self) -> Option<JournalHead> {
        lock(&self.shared).head.clone()
    }

    /// Journal heads that changed the epoch or went backwards, with their
    /// alarm (review of gap 1).
    pub fn take_head_alarms(&self) -> Vec<(JournalHead, String)> {
        lock(&self.shared).head_alarms.drain(..).collect()
    }

    pub fn stats(&self) -> LinkStats {
        lock(&self.shared).stats
    }

    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.tx = None;
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}

impl Drop for ExecutorLink {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn map(o: &Outcome) -> Option<ExecutorOutcome> {
    Some(match o.status {
        // Review R2-3: how far a quarantine reaches goes to the SOC.
        ExStatus::Verified => match &o.quarantine {
            Some(q) => ExecutorOutcome::VerifiedQuarantine(QuarantineScope {
                locators: q
                    .locators
                    .iter()
                    .map(|l| SocketAddr::new(l.ip, l.port).to_string())
                    .collect(),
                excluded: q
                    .excluded
                    .iter()
                    .map(|x| ScopeExcluded {
                        locator: SocketAddr::new(x.ip, x.port).to_string(),
                        reason: x.reason.clone(),
                    })
                    .collect(),
                addresses: q.addresses.iter().map(ToString::to_string).collect(),
                excluded_addresses: q
                    .excluded_addresses
                    .iter()
                    .map(|x| ScopeExcludedAddress {
                        address: x.ip.to_string(),
                        reason: x.reason.clone(),
                    })
                    .collect(),
                evidence_truncated: q.evidence_truncated,
            }),
            None => ExecutorOutcome::Verified,
        },
        ExStatus::Applying => ExecutorOutcome::Pending,
        // A revert in progress (or failing and retried): the rules may still
        // be in force, so the request keeps its state (`revert_failures`
        // and the executor's events say why).
        ExStatus::Reverting => return None,
        // Held after a reboot until re-validated with a fresh safety state.
        ExStatus::Held => return None,
        ExStatus::Reverted | ExStatus::RemovedExternally => ExecutorOutcome::Reverted,
        ExStatus::Advisory => ExecutorOutcome::RecordedNotExecuted,
        // A non-reversible motion action took effect (Sprint 8).
        ExStatus::Applied => ExecutorOutcome::Applied,
        ExStatus::Failed => ExecutorOutcome::Failed(
            o.error
                .clone()
                .unwrap_or_else(|| "the executor could not apply it".into()),
        ),
        ExStatus::Refused => {
            let r = o.refusal.clone();
            ExecutorOutcome::Refused {
                code: r
                    .as_ref()
                    .and_then(|r| codes::intern(&r.code))
                    .unwrap_or("executor_refused"),
                reason: r
                    .map(|r| r.reason)
                    .unwrap_or_else(|| "the executor refused it".into()),
            }
        }
        ExStatus::Unknown => return None,
    })
}

/// The control plane's executor: an accepted request becomes an order,
/// staged until the request note is in the black box.
pub struct ControlExecutor {
    shared: Arc<Mutex<Shared>>,
    staged: Arc<Mutex<Vec<Staged>>>,
    own: Morphology,
}

/// The order for an accepted control-plane request.
pub fn order_for(a: &AcceptedAction<'_>, own: Morphology, now_ms: u64) -> Order {
    let p = &a.request.parameters;
    let target = match a.request.action {
        ActionId::QuarantineNode => match (&p.participant_guid, &p.node) {
            (Some(g), _) => match g.parse() {
                Ok(guid_prefix) => Target::Participant {
                    guid_prefix,
                    locators: Vec::new(),
                    guid_only: false,
                    excluded: Vec::new(),
                    addresses: Vec::new(),
                    excluded_addresses: Vec::new(),
                    evidence_truncated: false,
                },
                Err(_) => Target::Node { name: g.clone() },
            },
            (None, Some(n)) => Target::Node { name: n.clone() },
            (None, None) => Target::None,
        },
        // Sprint 8: the executor's motion adapters act on these (and check
        // them against the signed body).
        ActionId::RestrictMotion => Target::Motion(robodr_executor::motion::MotionRequest {
            max_linear_speed: p.max_linear_speed,
            max_joint_speed: p.max_joint_speed,
            workspace_zone: p.workspace_zone.clone(),
            ..Default::default()
        }),
        ActionId::RollbackConfig => Target::Motion(robodr_executor::motion::MotionRequest {
            config: Some(p.config.clone().unwrap_or_else(|| "profile".into())),
            to_version: p.to_version.clone(),
            ..Default::default()
        }),
        _ => Target::None,
    };
    Order {
        id: a.request.request_id.clone(),
        action: a.request.action,
        target,
        ttl_s: a.request.ttl_seconds,
        judged_state: a.safety_state,
        context: *a.context,
        plan_morphology: own,
        human_approved: true,
        replay: false,
        origin: Origin::ControlPlane {
            key_id: a.key_id.to_string(),
            requested_by: a.request.requested_by.clone(),
        },
        issued_ms: now_ms,
        // Executor M1: the SOC's request as it was signed. `human_approved`
        // above is only a claim; the executor accepts it only when this
        // request verifies with its own copy of the SOC keys and matches
        // the order.
        soc: Some(Box::new(soc_request(a.meta))),
    }
}

/// The SOC's request exactly as it was signed and received (forwarded to
/// the executor, which verifies it with its own keys).
pub fn soc_request(meta: &Meta) -> SocRequest {
    SocRequest {
        method: meta.method.clone(),
        target: meta.target.clone(),
        key_id: meta.key_id.clone(),
        timestamp: meta.timestamp,
        nonce: meta.nonce.clone(),
        signature: meta.signature.clone(),
        body: meta.body.clone(),
    }
}

impl ActionExecutor for ControlExecutor {
    fn name(&self) -> &'static str {
        "robodr-executor"
    }

    fn executes(&self) -> bool {
        true
    }

    fn submit(&mut self, a: &AcceptedAction<'_>) -> ExecutorOutcome {
        let order = order_for(a, self.own, robodr_executor::proto::wall_ms());
        let staged = if a.request.action == ActionId::RecordEvidence {
            Staged::Evidence(order)
        } else {
            Staged::Submit(order)
        };
        lock(&self.staged).push(staged);
        ExecutorOutcome::Pending
    }

    fn revert(&mut self, request_id: &str, reason: &str, signed: &Meta) -> Option<ExecutorOutcome> {
        lock(&self.staged).push(Staged::Revert {
            id: request_id.to_string(),
            reason: reason.to_string(),
            soc: Some(Box::new(soc_request(signed))),
        });
        Some(ExecutorOutcome::Pending)
    }

    fn refresh(&mut self, request_id: &str) -> Option<ExecutorOutcome> {
        lock(&self.shared).outcomes.get(request_id).and_then(map)
    }

    // control plane v2 review, finding 6: held after the executor's reboot.
    fn held(&self, request_id: &str) -> bool {
        lock(&self.shared)
            .outcomes
            .get(request_id)
            .is_some_and(|o| o.status == ExStatus::Held)
    }

    // control plane v2 review, finding 3.
    fn discard(&mut self, request_id: &str, revert: bool) {
        lock(&self.staged).retain(|s| match s {
            Staged::Submit(o) | Staged::Evidence(o) => revert || o.id != request_id,
            Staged::Revert { id, .. } => !revert || id != request_id,
        });
    }
}

/// The planner's executor: the steps a real executor may request without
/// a human ([`ExecutionRequest::steps_without_approval_for`] with the
/// executor's own morphology: not a replay, Eligible, invariants hold,
/// state unchanged and not engaged) become orders, staged until the plan's
/// black-box note exists (the agent records it before calling `submit`).
pub struct PlannerExecutor {
    staged: Arc<Mutex<Vec<Staged>>>,
    own: Morphology,
}

/// The orders for an eligible plan (empty when nothing may be requested).
pub fn orders_for_plan(req: &ExecutionRequest<'_>, own: Morphology, now_ms: u64) -> Vec<Order> {
    let steps = req.steps_without_approval_for(req.safety_state, own);
    // Nothing that is not backed by black-box evidence leaves agentd.
    if steps.is_empty() || req.evidence.is_empty() {
        return Vec::new();
    }
    let p = req.plan;
    let mut out = Vec::new();
    for a in &p.actions {
        if !steps.contains(&a.step()) {
            continue;
        }
        let (action, target) = match a {
            ResponseAction::Restrict {
                target: RestrictTarget::Network,
                ..
            } => (ActionId::IsolateNetwork, Target::None),
            ResponseAction::Restrict {
                target: RestrictTarget::Participant,
                ..
            } => match p.source.parse() {
                Ok(g) => (
                    ActionId::QuarantineNode,
                    Target::Participant {
                        guid_prefix: g,
                        locators: Vec::new(),
                        guid_only: false,
                        excluded: Vec::new(),
                        addresses: Vec::new(),
                        excluded_addresses: Vec::new(),
                        evidence_truncated: false,
                    },
                ),
                // A source that is not a GUID prefix cannot be quarantined.
                Err(_) => continue,
            },
            // Sprint 8: a motion limit becomes a restriction of the
            // envelope by the plan's factor (the executor's restrict_motion
            // adapters; advisory there without them).
            ResponseAction::LimitMotion { factor } => (
                ActionId::RestrictMotion,
                Target::Motion(robodr_executor::motion::MotionRequest {
                    factor: Some(*factor),
                    ..Default::default()
                }),
            ),
            // A process is never acted on by the executor; safe pause and
            // safe state need two people (never a planner order).
            _ => continue,
        };
        if a.step() == Step::Record {
            continue;
        }
        let key = format!(
            "{}|{}|{}|{}",
            req.finding_id.unwrap_or(""),
            p.rule,
            p.source,
            action.as_str()
        );
        let h = robodr_blackbox::crypto::sha256(key.as_bytes());
        out.push(Order {
            id: format!("plan:{}", robodr_blackbox::crypto::to_hex(&h[..12])),
            action,
            target,
            ttl_s: None,
            judged_state: req.safety_state,
            context: *req.context,
            plan_morphology: p.morphology,
            human_approved: false,
            replay: req.replay,
            origin: Origin::Planner {
                rule: p.rule.chars().take(200).collect(),
                finding_id: req.finding_id.map(|f| f.chars().take(200).collect()),
            },
            issued_ms: now_ms,
            soc: None,
        });
    }
    out
}

impl Executor for PlannerExecutor {
    fn submit(&mut self, req: &ExecutionRequest<'_>) {
        // The plan note precedes this call (the agent records first), so
        // the orders are dispatched by the main loop right away.
        let orders = orders_for_plan(req, self.own, robodr_executor::proto::wall_ms());
        let mut g = lock(&self.staged);
        for o in orders {
            g.push(Staged::Submit(o));
        }
    }
}

// --- Quarantine locators (executor review H2, review of the F3 fix) ---------
// The executor quarantines a participant only when the order carries its
// SPDP unicast locators (or agentd vouches for a GUID-prefix-only
// quarantine) and they lie outside every motion-path entry it may not cut.
// agentd fills them in when it dispatches an order from the pipeline's
// binding table ([`BindingTable::quarantine_target`]: only the prefix's own
// locators on addresses it was seen sending from, never another
// participant's, none for a contested, pinned or profiled-by-a-foreign-host
// prefix). A participant event of a JSONL input is asked only for a prefix
// the binding table does not know at all, and its locators go through the
// same filters ([`BindingTable::vouch_external`], review M7): it can never
// override the table's answer.

/// Participants' SPDP unicast locators (and the event's source address)
/// from `ros2_participant_discovered` events (bounded, oldest forgotten
/// first).
#[derive(Debug, Default)]
pub struct LocatorBook {
    map: HashMap<[u8; 12], BookEntry>,
    order: VecDeque<[u8; 12]>,
}

/// One participant event's locators and source address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BookEntry {
    pub locators: Vec<SocketAddr>,
    /// The event's `src_ip` (the only observed evidence for the locators).
    pub src: Option<IpAddr>,
}

/// Participants remembered by the [`LocatorBook`].
pub const MAX_BOOK: usize = 1024;

impl LocatorBook {
    /// Learn the locators of a participant event (`ip:port` strings).
    pub fn observe(&mut self, p: &robodr_events::graph::Participant) {
        let Ok(g) = p
            .guid_prefix
            .to_ascii_lowercase()
            .parse::<robodr_executor::net::GuidPrefix>()
        else {
            return;
        };
        let locators: Vec<SocketAddr> = p
            .locators
            .iter()
            .filter_map(|l| l.parse::<SocketAddr>().ok())
            .filter(|sa| locator(*sa).is_some())
            .take(robodr_ros2_pipeline::binding::MAX_LOCATOR_IPS)
            .collect();
        if locators.is_empty() {
            return;
        }
        let e = BookEntry {
            locators,
            src: robodr_ros2_pipeline::binding::parse_src_ip(&p.src_ip),
        };
        if self.map.insert(g.0, e).is_none() {
            self.order.push_back(g.0);
            while self.order.len() > MAX_BOOK {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
        }
    }

    pub fn get(&self, g: &[u8; 12]) -> Option<&BookEntry> {
        self.map.get(g)
    }
}

fn locator(sa: SocketAddr) -> Option<Locator> {
    let ip = sa.ip();
    (sa.port() != 0 && !ip.is_unspecified() && !ip.is_multicast()).then_some(Locator {
        ip,
        port: sa.port(),
    })
}

/// Why a vouched locator is not in the order (review R2-6).
pub const OVER_LIMIT: &str = "over the order's locator limit (16): not acted on";
pub const NOT_UNICAST: &str = "not a unicast locator (port 0, unspecified or multicast)";
/// Why a vouched source address is not in the order (review R3-1).
pub const OVER_LIMIT_ADDRESSES: &str = "over the order's address limit (16): not cut whole";
pub const NOT_UNICAST_ADDRESS: &str = "not a unicast address (unspecified or multicast)";
const _: () = assert!(robodr_executor::order::MAX_ADDRESSES == 16);
const _: () = assert!(robodr_executor::order::MAX_LOCATORS == 16);

/// Fill a participant order's locators when it carries none, with what
/// `vouch` answers for its prefix (and the [`LocatorBook`] entry, if any):
/// the locators, whether a GUID-prefix-only quarantine is vouched for, and
/// what was left out and why (carried in the order as evidence).
pub fn attach_locators(
    mut o: Order,
    vouch: impl FnOnce(&[u8; 12], Option<&BookEntry>) -> QuarantineTarget,
    book: &LocatorBook,
) -> Order {
    if let Target::Participant {
        guid_prefix,
        locators,
        guid_only,
        excluded,
        addresses,
        excluded_addresses,
        evidence_truncated,
    } = &mut o.target
    {
        if locators.is_empty() && addresses.is_empty() {
            let t = vouch(&guid_prefix.0, book.get(&guid_prefix.0));
            let mut left: Vec<(SocketAddr, &str)> = t.excluded;
            // Review R2-6: what does not fit the order (or is not a unicast
            // locator) is listed as left out, never dropped silently.
            for sa in t.locators {
                match locator(sa) {
                    Some(l) if locators.len() < robodr_executor::order::MAX_LOCATORS => {
                        locators.push(l);
                    }
                    Some(_) => left.push((sa, OVER_LIMIT)),
                    None => left.push((sa, NOT_UNICAST)),
                }
            }
            // Review R3-1: the observed source addresses, cut whole.
            let mut left_addr: Vec<(IpAddr, &str)> = t.excluded_addresses;
            for a in t.addresses {
                if a.is_unspecified() || a.is_multicast() {
                    left_addr.push((a, NOT_UNICAST_ADDRESS));
                } else if addresses.len() < robodr_executor::order::MAX_ADDRESSES {
                    addresses.push(a);
                } else {
                    left_addr.push((a, OVER_LIMIT_ADDRESSES));
                }
            }
            *evidence_truncated = t.evidence_truncated
                || left_addr.len() > robodr_executor::order::MAX_EXCLUDED_ADDRESSES
                || left.len() > robodr_executor::order::MAX_EXCLUDED;
            *excluded_addresses = left_addr
                .into_iter()
                .take(robodr_executor::order::MAX_EXCLUDED_ADDRESSES)
                .map(|(ip, why)| ExcludedAddress {
                    ip,
                    reason: why.into(),
                })
                .collect();
            *guid_only = t.guid_only;
            *excluded = left
                .into_iter()
                .take(robodr_executor::order::MAX_EXCLUDED)
                .map(|(sa, why)| ExcludedLocator {
                    ip: sa.ip(),
                    port: sa.port(),
                    reason: why.into(),
                })
                .collect();
        }
    }
    o
}

impl ExecutorLink {
    /// Remember the locators of a participant event.
    pub fn observe_event(&mut self, ev: &robodr_events::RobotEvent) {
        if let robodr_events::RobotEvent::Ros2ParticipantDiscovered(p) = ev {
            self.book.observe(p);
        }
    }

    /// [`attach_locators`] with this link's book.
    pub fn with_locators(
        &self,
        o: Order,
        vouch: impl FnOnce(&[u8; 12], Option<&BookEntry>) -> QuarantineTarget,
    ) -> Order {
        attach_locators(o, vouch, &self.book)
    }
}

/// [`attach_locators`]'s `vouch` for agentd: the binding table's answer,
/// or, for a prefix it does not know, the event's locators through the
/// table's filters.
pub fn vouch_with(
    binding: &BindingTable,
    now: std::time::Instant,
) -> impl FnOnce(&[u8; 12], Option<&BookEntry>) -> QuarantineTarget + '_ {
    move |g, entry| match entry {
        Some(e) => binding.vouch_external(g, &e.locators, e.src, now),
        None => binding.quarantine_target(g, now),
    }
}

// --- control plane v2 review, finding 3 ---------------------------------------
/// Whether the daemon may release a staged control-plane order: its
/// request must be stored (recorded in the black box and journalled), still
/// `pending` (never handed out before), and be the request the order was
/// made for (same action, TTL and SOC key): a stale order staged by a call
/// that failed can never ride on a later request with the same id.
pub fn release_ok(o: &Order, stored: Option<&crate::control::api::Stored>) -> bool {
    let Some(s) = stored else {
        return false;
    };
    let key_ok = match &o.origin {
        Origin::ControlPlane { key_id, .. } => *key_id == s.key_id,
        Origin::Planner { .. } => false,
    };
    key_ok
        && s.status == crate::control::api::Status::Pending
        && s.request.action == o.action
        && s.request.ttl_seconds == o.ttl_s
}

#[cfg(test)]
mod tests {
    use super::*;
    use robodr_agent::Disposition;
    use robodr_events::{Deviation, Severity};
    use robodr_responder::{
        plan_stateless, Connectivity, ControlMode, MissionPhase, OperationalContext,
        PlatformFamily, ResponsePolicy,
    };

    fn ctx(m: Morphology) -> OperationalContext {
        OperationalContext {
            platform: PlatformFamily::Ugv,
            morphology: m,
            phase: MissionPhase::Transit,
            connectivity: Connectivity::Connected,
            control: ControlMode::Autonomous,
            operator_present: true,
            profile_locked: true,
        }
    }

    #[test]
    fn disabled_section_resolves_to_nothing() {
        let s: ExecutorSection = serde_json::from_str("{}").unwrap();
        assert!(!s.enabled);
        assert!(s.resolve().unwrap().is_none());
        let s: ExecutorSection = serde_json::from_str(r#"{"enabled": true}"#).unwrap();
        assert!(s.resolve().is_err(), "enabled without a key");
        assert!(serde_json::from_str::<ExecutorSection>(r#"{"enable": true}"#).is_err());
    }

    #[test]
    fn planner_orders_only_for_eligible_plans_on_the_own_body() {
        let mut pol = ResponsePolicy::conservative_default(PlatformFamily::Ugv);
        pol.oem_validated = true;
        pol.morphology = Morphology::WheeledMobile;
        let c = ctx(Morphology::WheeledMobile);
        let dev = Deviation::new("robot.x", Severity::High, "d");
        let mut plan = plan_stateless(
            &pol,
            &dev,
            "0110a2b3c4d5e6f701000000",
            SafetyState::MovingSlow,
            &c,
        );
        // Make the restrict a participant restrict (what a rogue writer
        // deviation plans).
        for a in plan.actions.iter_mut() {
            if let ResponseAction::Restrict { target, .. } = a {
                *target = RestrictTarget::Participant;
            }
        }
        let refs = [robodr_ocsf::BlackBoxRef {
            segment: 0,
            seq: 1,
            sha256: "00".repeat(32),
        }];
        let req = ExecutionRequest {
            plan: &plan,
            disposition: Disposition::of(&plan),
            safety_state: SafetyState::MovingSlow,
            context: &c,
            evidence: &refs,
            finding_id: Some("f1"),
            replay: false,
        };
        // Without evidence: nothing.
        let bare = ExecutionRequest {
            evidence: &[],
            ..req
        };
        assert!(orders_for_plan(&bare, Morphology::WheeledMobile, 0).is_empty());
        let orders = orders_for_plan(&req, Morphology::WheeledMobile, 0);
        assert!(orders.iter().all(|o| !o.human_approved));
        assert!(orders.iter().any(|o| o.action == ActionId::QuarantineNode));
        // Sprint 8: the plan's motion limit becomes a restriction order with
        // the policy's factor (the executor's default TTL).
        let rm: Vec<_> = orders
            .iter()
            .filter(|o| o.action == ActionId::RestrictMotion)
            .collect();
        if plan
            .actions
            .iter()
            .any(|a| matches!(a, ResponseAction::LimitMotion { .. }))
        {
            assert_eq!(rm.len(), 1, "{:?}", plan.actions);
            assert!(matches!(
                &rm[0].target,
                Target::Motion(m) if m.factor == Some(pol.limit_motion_factor)
            ));
            assert_eq!(rm[0].ttl_s, None);
        }
        assert!(
            orders.iter().all(|o| matches!(
                o.action,
                ActionId::QuarantineNode | ActionId::RestrictMotion
            )),
            "{:?}",
            plan.actions
        );
        // Another body, a replay: nothing.
        assert!(orders_for_plan(&req, Morphology::Humanoid, 0).is_empty());
        let replay = ExecutionRequest {
            replay: true,
            ..req
        };
        assert!(orders_for_plan(&replay, Morphology::WheeledMobile, 0).is_empty());
        // A source that is not a GUID prefix: no quarantine order.
        let mut p2 = plan.clone();
        p2.source = "/teleop".into();
        let r2 = ExecutionRequest { plan: &p2, ..req };
        assert!(!orders_for_plan(&r2, Morphology::WheeledMobile, 0)
            .iter()
            .any(|o| o.action == ActionId::QuarantineNode));
    }

    #[test]
    fn outcomes_map_to_request_states() {
        let mut o = unreachable_outcome("r", "x");
        assert!(matches!(map(&o), Some(ExecutorOutcome::Failed(_))));
        o.status = ExStatus::Refused;
        o.refusal = Some(robodr_executor::Refusal::new(codes::FALL_HAZARD, "no"));
        assert!(matches!(
            map(&o),
            Some(ExecutorOutcome::Refused {
                code: "fall_hazard",
                ..
            })
        ));
        o.status = ExStatus::Verified;
        assert_eq!(map(&o), Some(ExecutorOutcome::Verified));
        // Review R2-3: the quarantine's reach goes along.
        o.quarantine = Some(robodr_executor::engine::QuarantineScope {
            locators: Vec::new(),
            excluded: vec![ExcludedLocator {
                ip: "10.0.0.68".parse().unwrap(),
                port: 7410,
                reason: "why".into(),
            }],
            addresses: Vec::new(),
            excluded_addresses: Vec::new(),
            evidence_truncated: false,
            containment: None,
        });
        match map(&o) {
            Some(ExecutorOutcome::VerifiedQuarantine(q)) => {
                assert_eq!(q.containment(), "guid_only");
                assert_eq!(q.excluded[0].locator, "10.0.0.68:7410");
            }
            other => panic!("{other:?}"),
        }
        o.quarantine = None;
        o.status = ExStatus::RemovedExternally;
        assert_eq!(map(&o), Some(ExecutorOutcome::Reverted));
        o.status = ExStatus::Unknown;
        assert_eq!(map(&o), None);
        o.status = ExStatus::Reverting;
        assert_eq!(map(&o), None, "a failing revert never reads as lifted");
    }

    /// The executor verifies the SOC signature over the same bytes the
    /// control plane does (executor M1): one signing message, two copies.
    #[test]
    fn executor_and_control_plane_sign_the_same_message() {
        for body in [&b""[..], b"{\"a\":1}"] {
            assert_eq!(
                robodr_executor::soc::signing_message(
                    "POST",
                    "/api/v2/robots/r%3A1/action-requests",
                    "r:1",
                    "soc:k:1",
                    1_792_000_000,
                    "nonce-nonce-nonce-1",
                    body
                ),
                crate::control::auth::signing_message(
                    "POST",
                    "/api/v2/robots/r%3A1/action-requests",
                    "r:1",
                    "soc:k:1",
                    1_792_000_000,
                    "nonce-nonce-nonce-1",
                    body
                )
            );
        }
        assert_eq!(
            robodr_executor::soc::API_VERSION,
            crate::control::auth::API_VERSION
        );
    }

    #[test]
    fn quarantine_orders_get_the_participants_spdp_locators() {
        let g = "0110a2b3c4d5e6f701000000";
        let o = Order {
            id: "q".into(),
            action: ActionId::QuarantineNode,
            target: Target::Participant {
                guid_prefix: g.parse().unwrap(),
                locators: Vec::new(),
                guid_only: false,
                excluded: Vec::new(),
                addresses: Vec::new(),
                excluded_addresses: Vec::new(),
                evidence_truncated: false,
            },
            ttl_s: None,
            judged_state: SafetyState::Idle,
            context: ctx(Morphology::WheeledMobile),
            plan_morphology: Morphology::WheeledMobile,
            human_approved: true,
            replay: false,
            origin: Origin::Planner {
                rule: "r".into(),
                finding_id: None,
            },
            issued_ms: 0,
            soc: None,
        };
        let locs = |o: &Order| match &o.target {
            Target::Participant { locators, .. } => locators.clone(),
            _ => panic!(),
        };
        let mut book = LocatorBook::default();
        let table = BindingTable::new(
            robodr_ros2_pipeline::BindingOptions::default(),
            &robodr_events::profile::Profile::default(),
        );
        let now = std::time::Instant::now();
        // Nothing known: none, nothing vouched (the executor refuses).
        let out = attach_locators(o.clone(), vouch_with(&table, now), &book);
        assert!(locs(&out).is_empty());
        assert!(matches!(
            out.target,
            Target::Participant {
                guid_only: false,
                ..
            }
        ));
        // What the vouch answers is carried over (multicast / port 0 dropped).
        let out = attach_locators(
            o.clone(),
            |p, _| {
                assert_eq!(robodr_blackbox::crypto::to_hex(p), g);
                QuarantineTarget {
                    locators: vec![
                        "10.0.0.7:7410".parse().unwrap(),
                        "239.255.0.1:7400".parse().unwrap(),
                        "10.0.0.7:0".parse().unwrap(),
                    ],
                    excluded: vec![("10.0.0.9:7410".parse().unwrap(), "why")],
                    known: true,
                    guid_only: true,
                    addresses: vec!["10.0.0.7".parse().unwrap(), "239.255.0.1".parse().unwrap()],
                    excluded_addresses: vec![("10.0.0.9".parse().unwrap(), "seen elsewhere")],
                    evidence_truncated: true,
                }
            },
            &book,
        );
        assert_eq!(
            locs(&out),
            vec![Locator {
                ip: "10.0.0.7".parse().unwrap(),
                port: 7410
            }]
        );
        match &out.target {
            Target::Participant {
                guid_only,
                excluded,
                addresses,
                excluded_addresses,
                evidence_truncated,
                ..
            } => {
                assert!(guid_only);
                assert_eq!(excluded[0].reason, "why");
                // Review R3-1: the addresses go along (multicast left out).
                assert_eq!(addresses, &vec!["10.0.0.7".parse::<IpAddr>().unwrap()]);
                assert_eq!(excluded_addresses.len(), 2, "{excluded_addresses:?}");
                assert_eq!(excluded_addresses[1].reason, NOT_UNICAST_ADDRESS);
                assert!(evidence_truncated);
            }
            _ => panic!(),
        }
        // A participant event for a prefix the table does not know: its
        // locators through the table's filters (only those on the event's
        // source address).
        book.observe(&robodr_events::graph::Participant {
            guid_prefix: g.into(),
            src_ip: "10.0.0.8".into(),
            locators: vec![
                "10.0.0.8:7412".into(),
                "10.0.0.50:7410".into(),
                "127.0.0.1:7410".into(),
                "junk".into(),
            ],
        });
        let out = attach_locators(o, vouch_with(&table, now), &book);
        assert_eq!(
            locs(&out),
            vec![Locator {
                ip: "10.0.0.8".parse().unwrap(),
                port: 7412
            }]
        );
    }

    /// Review of gap 1, finding 1: a new epoch whose sequence restarted
    /// reads the events again from the start; a sequence that went back
    /// in the same epoch is an alarm; an older executor (no head) changes
    /// nothing.
    #[test]
    fn journal_heads_are_judged() {
        let h = |e: &str, n: u64| JournalHead {
            epoch: e.into(),
            next_seq: n,
        };
        assert_eq!(judge_head(None, &h("a", 40), 39), (None, None));
        assert_eq!(judge_head(Some(&h("a", 40)), &h("a", 42), 39), (None, None));
        let (alarm, reset) = judge_head(Some(&h("a", 40)), &h("b", 3), 39);
        assert!(alarm.unwrap().contains("epoch changed"));
        assert_eq!(reset, Some(0), "the sequence restarted: read from 0");
        let (alarm, reset) = judge_head(Some(&h("a", 40)), &h("b", 45), 39);
        assert!(alarm.is_some());
        assert_eq!(reset, None, "continued numbering: nothing missed");
        let (alarm, reset) = judge_head(Some(&h("a", 40)), &h("a", 30), 39);
        assert!(alarm.unwrap().contains("went backwards"));
        assert_eq!(reset, Some(29));
    }

    #[test]
    fn safety_cell_reports_age() {
        let c = SafetyCell::default();
        assert!(c.get().is_err());
        c.set(SafetyState::Idle);
        let (s, age) = c.get().unwrap();
        assert_eq!(s, SafetyState::Idle);
        assert!(age < 1000);
    }
}
