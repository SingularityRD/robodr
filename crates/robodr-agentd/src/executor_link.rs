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
use robodr_executor::journal::{Event, EventKind};
use robodr_executor::order::{Order, Origin, Target};
use robodr_executor::proto::Key;
use robodr_responder::{ActionId, Morphology, ResponseAction, RestrictTarget, SafetyState, Step};
use serde::{Deserialize, Serialize};

use crate::control::api::{AcceptedAction, ActionExecutor, ExecutorOutcome};

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
}

enum Job {
    Submit(Order),
    Revert(String, String),
}

#[derive(Default)]
struct Shared {
    outcomes: HashMap<String, Outcome>,
    order: VecDeque<String>,
    events: VecDeque<Event>,
    last_seq: u64,
    stats: LinkStats,
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
    /// Send once the revert note is recorded.
    Revert { id: String, reason: String },
    /// `record_evidence`: a black-box mark done by the main loop.
    Evidence(Order),
}

/// The link: worker thread, queue and shared state.
pub struct ExecutorLink {
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
    }
}

impl ExecutorLink {
    /// Start the worker. Nothing is sent until orders are dispatched.
    pub fn start(spec: &ExecutorSpec, safety: SafetyCell) -> Result<Self, String> {
        let (tx, rx) = sync_channel::<Job>(QUEUE);
        let shared = Arc::new(Mutex::new(Shared::default()));
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
                        Ok(Job::Revert(id, reason)) => match client.revert(&id, &reason) {
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
                        },
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                    // Events (TTL reverts, drift, revert failures) and the
                    // state of watched actions.
                    let since = lock(&sh).last_seq;
                    if let Ok(evs) = client.events(since) {
                        let mut changed = Vec::new();
                        {
                            let mut g = lock(&sh);
                            for ev in evs {
                                g.last_seq = g.last_seq.max(ev.seq);
                                g.stats.events += 1;
                                if ev.kind == EventKind::RevertFailed {
                                    g.stats.revert_failures += 1;
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
            Staged::Revert { id, reason } => (Job::Revert(id.clone(), reason), id),
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

    pub fn count_dropped(&self) {
        lock(&self.shared).stats.dropped_unrecorded += 1;
    }

    /// Executor events not yet recorded.
    pub fn take_events(&self) -> Vec<Event> {
        lock(&self.shared).events.drain(..).collect()
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
        ExStatus::Verified => ExecutorOutcome::Verified,
        ExStatus::Applying => ExecutorOutcome::Pending,
        // A revert in progress (or failing and retried): the rules may still
        // be in force, so the request keeps its state (`revert_failures`
        // and the executor's events say why).
        ExStatus::Reverting => return None,
        ExStatus::Reverted | ExStatus::RemovedExternally => ExecutorOutcome::Reverted,
        ExStatus::Advisory => ExecutorOutcome::RecordedNotExecuted,
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
                },
                Err(_) => Target::Node { name: g.clone() },
            },
            (None, Some(n)) => Target::Node { name: n.clone() },
            (None, None) => Target::None,
        },
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

    fn revert(&mut self, request_id: &str, reason: &str) -> Option<ExecutorOutcome> {
        lock(&self.staged).push(Staged::Revert {
            id: request_id.to_string(),
            reason: reason.to_string(),
        });
        Some(ExecutorOutcome::Pending)
    }

    fn refresh(&mut self, request_id: &str) -> Option<ExecutorOutcome> {
        lock(&self.shared).outcomes.get(request_id).and_then(map)
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
                    },
                ),
                // A source that is not a GUID prefix cannot be quarantined.
                Err(_) => continue,
            },
            // A process is never acted on by executor v1; motion limits are
            // advisory (the plan is already recorded); safe pause and safe
            // state are never executor actions.
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
        assert!(orders
            .iter()
            .all(|o| o.action == ActionId::QuarantineNode && !o.human_approved));
        assert!(!orders.is_empty(), "{:?}", plan.actions);
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
        assert!(orders_for_plan(&r2, Morphology::WheeledMobile, 0).is_empty());
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
        o.status = ExStatus::RemovedExternally;
        assert_eq!(map(&o), Some(ExecutorOutcome::Reverted));
        o.status = ExStatus::Unknown;
        assert_eq!(map(&o), None);
        o.status = ExStatus::Reverting;
        assert_eq!(map(&o), None, "a failing revert never reads as lifted");
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
