//! The executor core: one action at a time, precheck → safety re-check →
//! journal intent → apply → read-back verify → commit, and revert, TTL
//! expiry, periodic verification and restart reconciliation.
//!
//! The engine owns the table `inet robodr`: its content is always
//! [`nft::render`] of the journal's `active` entries (plus the one
//! `applying` entry while it is being installed). Every function takes the
//! time ([`Now`]: wall clock and CLOCK_BOOTTIME) from its caller.
//!
//! * **Time.** Within a boot, expiry is decided on CLOCK_BOOTTIME: a
//!   wall-clock step (NTP, an operator) neither extends nor shortens an
//!   action. Across a reboot only the wall-clock deadline exists; more TTL
//!   left than the action was ever given counts as expired.
//! * **Operator emergency disable** (`nft delete table inet robodr`) is
//!   detected before every transaction (order, revert, retry) and by the
//!   periodic read-back: every action is dropped as `removed_externally`
//!   and every order is refused (`operator_disabled`) until
//!   `robodr-executor rearm`. Nothing the executor does re-creates the
//!   table in between.
//! * **Reboot.** An active action is not re-installed blindly: it is
//!   re-validated against the current configuration and policy (the
//!   precheck of its stored order) and held until agentd supplies a fresh,
//!   known safety state that is not engaged ([`Engine::rearm_held`]).

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

use robodr_responder::{ActionId, ResponsePolicy};
use serde::{Deserialize, Serialize};

use crate::config::{ExecutorConfig, Resolved};
use crate::decision::{self, codes, Current, Effect, Refusal};
use crate::journal::{Entry, EventKind, Final, Finished, Journal, Loaded, Phase, State};
use crate::nft::{self, Active, Nft, Rendered};
use crate::order::Order;

/// The time, as the engine needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Now {
    /// Wall clock, Unix ms.
    pub wall_ms: u64,
    /// CLOCK_BOOTTIME, ms (`None` when unreadable: the wall clock decides).
    pub boot_ms: Option<u64>,
}

impl Now {
    /// The system's clocks.
    pub fn system() -> Now {
        Now {
            wall_ms: crate::proto::wall_ms(),
            boot_ms: boottime_ms(),
        }
    }
}

impl From<u64> for Now {
    /// One number for both clocks (tests and tools).
    fn from(ms: u64) -> Now {
        Now {
            wall_ms: ms,
            boot_ms: Some(ms),
        }
    }
}

/// CLOCK_BOOTTIME in ms, from `/proc/uptime` (the kernel's boot-time
/// clock: monotonic, counts suspend, starts at boot). `None` when
/// unreadable.
pub fn boottime_ms() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/uptime").ok()?;
    let first = s.split_whitespace().next()?;
    let (sec, frac) = first.split_once('.').unwrap_or((first, "0"));
    let sec: u64 = sec.parse().ok()?;
    let mut cs = frac.chars().take(3).collect::<String>();
    while cs.len() < 3 {
        cs.push('0');
    }
    let ms: u64 = cs.parse().ok()?;
    sec.checked_mul(1000)?.checked_add(ms)
}

/// Where the engine gets the platform's current safety state from,
/// immediately before it applies anything.
pub trait SafetyOracle {
    fn current(&mut self) -> Result<Current, String>;
}

/// An oracle that always answers the same (tests, tools).
#[derive(Debug, Clone, Copy)]
pub struct FixedSafety(pub Current);

impl SafetyOracle for FixedSafety {
    fn current(&mut self) -> Result<Current, String> {
        Ok(self.0)
    }
}

/// An action's state as reported to agentd.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Applied and the read-back matched (the rules are in force).
    Verified,
    /// Being installed (only seen if asked mid-transaction).
    Applying,
    /// A revert is in progress or failed and is being retried.
    Reverting,
    /// Removed (by request, TTL or reconciliation).
    Reverted,
    /// Refused before anything was applied.
    Refused,
    /// The apply failed and was rolled back (or could not be committed).
    Failed,
    /// Recorded only (v1 `restrict_motion`).
    Advisory,
    /// A non-reversible motion action took effect (`request_safe_state`,
    /// `rollback_config`); there is nothing to revert.
    Applied,
    /// Removed from outside (`nft delete table inet robodr`).
    RemovedExternally,
    /// After a reboot: waiting for re-validation and a fresh safety check
    /// (not installed).
    Held,
    /// No action with this id.
    Unknown,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Verified => "verified",
            Status::Applying => "applying",
            Status::Reverting => "reverting",
            Status::Reverted => "reverted",
            Status::Refused => "refused",
            Status::Failed => "failed",
            Status::Advisory => "advisory",
            Status::Applied => "applied",
            Status::RemovedExternally => "removed_externally",
            Status::Held => "held",
            Status::Unknown => "unknown",
        }
    }
}

/// The answer for one action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Outcome {
    pub id: String,
    pub status: Status,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<ActionId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<Refusal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u64>,
    /// A resubmission of an order already known (not executed again).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub duplicate: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// What an active quarantine reaches (review R2-3): the locators it
    /// cuts (empty: the GUID-prefix payload drop alone) and the announced
    /// ones left out, with the reason. Only on the state of an applied
    /// `quarantine_node`; an older agentd ignores it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantine: Option<QuarantineScope>,
}

/// See [`Outcome::quarantine`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineScope {
    pub locators: Vec<crate::order::Locator>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded: Vec<crate::order::ExcludedLocator>,
    /// Review R3-1: the source addresses cut whole (to and from the
    /// robot's DDS ports, any source port).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<std::net::IpAddr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded_addresses: Vec<crate::order::ExcludedAddress>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub evidence_truncated: bool,
    /// [`crate::decision::Containment`] of the rules in force (agentd
    /// recomputes it from the fields above with the same definition).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub containment: Option<crate::decision::Containment>,
}

fn quarantine_scope(e: &Effect) -> Option<QuarantineScope> {
    match e {
        Effect::Quarantine(q) => Some(QuarantineScope {
            locators: q.locators.clone(),
            excluded: q.excluded.clone(),
            addresses: q.addresses.clone(),
            excluded_addresses: q.excluded_addresses.clone(),
            evidence_truncated: q.evidence_truncated,
            containment: Some(q.containment()),
        }),
        _ => None,
    }
}

impl Outcome {
    fn bare(id: &str, status: Status) -> Self {
        Self {
            id: id.into(),
            status,
            action: None,
            refusal: None,
            error: None,
            applied_ms: None,
            deadline_ms: None,
            duplicate: false,
            note: None,
            quarantine: None,
        }
    }
}

/// What a quarantine left out (review of the F3 fix, H2): the locators not
/// acted on and why, and whether only the GUID-prefix drop is in force.
fn quarantine_note(e: &Effect) -> Option<String> {
    let Effect::Quarantine(q) = e else {
        return None;
    };
    let mut parts = Vec::new();
    if q.locators.is_empty() && q.addresses.is_empty() {
        parts.push(format!(
            "GUID-prefix drop only for participant {} (no locator or source address could be \
             vouched for)",
            q.guid_prefix
        ));
    }
    if !q.excluded_addresses.is_empty() {
        parts.push(format!(
            "source addresses left out (not cut whole): {}",
            q.excluded_addresses
                .iter()
                .map(|x| format!("{} ({})", x.ip, x.reason))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if q.evidence_truncated {
        parts.push(
            "agentd forgot some of the participant's observed source addresses: not all of \
             them are cut"
                .to_string(),
        );
    }
    if !q.excluded.is_empty() {
        parts.push(format!(
            "locators left out (not acted on): {}",
            q.excluded
                .iter()
                .map(|x| format!("{}:{} ({})", x.ip, x.port, x.reason))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    (!parts.is_empty()).then(|| parts.join("; "))
}

/// More of the action's TTL is left than it was ever given: the wall clock
/// moved back. The action is treated as expired (the safe direction), so a
/// clock step can never make an action outlive its TTL.
fn clock_moved_back(e: &Entry, now_ms: u64) -> bool {
    e.deadline_ms.saturating_sub(now_ms) > e.ttl_s.saturating_mul(1000)
}

/// Whether `e` has expired at `now`: on CLOCK_BOOTTIME within the boot its
/// boot deadline belongs to, on the wall clock otherwise.
fn expired(e: &Entry, now: Now) -> bool {
    match (e.boot_deadline_ms, now.boot_ms) {
        (Some(bd), Some(b)) => b >= bd || bd.saturating_sub(b) > e.ttl_s.saturating_mul(1000),
        _ => e.deadline_ms <= now.wall_ms || clock_moved_back(e, now.wall_ms),
    }
}

/// The executor core.
pub struct Engine {
    cfg: Resolved,
    policy: ResponsePolicy,
    nft: Box<dyn Nft + Send>,
    journal: Journal,
    state: State,
    boot_id: String,
    last_verify_boot_ms: u64,
    /// The configuration file, re-read (with the policy it names) before
    /// every order and re-arm ([`Engine::with_reload`]).
    reload: Option<PathBuf>,
    /// Ids whose `journal_error` event was emitted (no event per retry).
    unjournalled: BTreeSet<String>,
    /// The last reason held actions could not be re-armed (one event per
    /// change).
    last_hold_reason: Option<String>,
    /// Journal writes that failed (reported in status).
    pub journal_errors: u64,
    /// The executor's own SOC replay store (trust boundary M1).
    soc_replay: crate::soc::ReplayStore,
    /// The platform adapters of motion actions (Sprint 8).
    motion: Box<dyn crate::motion::MotionPorts + Send>,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("active", &self.state.entries.len())
            .field("boot_id", &self.boot_id)
            .finish()
    }
}

/// A crash point was hit (fault-injection builds only): stop like a dead
/// process.
#[cfg(feature = "fault-injection")]
macro_rules! crash_point {
    ($p:expr, $id:expr) => {
        if crate::fault::hit($p) {
            let mut o = Outcome::bare($id, Status::Failed);
            o.error = Some(format!("fault injected: crashed at {:?}", $p));
            return o;
        }
    };
}
#[cfg(not(feature = "fault-injection"))]
macro_rules! crash_point {
    ($p:expr, $id:expr) => {};
}

impl Engine {
    /// Open the journal in `cfg.state_dir` and reconcile the table with it
    /// (see [`crate::journal`]): `applying` / `reverting` entries are
    /// dropped, expired ones reverted, the rest re-applied and verified
    /// (same boot) or held for re-validation (after a reboot); a table that
    /// vanished during this boot while actions were active was removed by
    /// an operator and is not re-installed.
    ///
    /// Any error deletes table `inet robodr` before it is returned: a start
    /// that fails never leaves rules without the process that enforces
    /// their TTL.
    ///
    /// The state files are **unsealed** here (executor v1 format, for tests
    /// and tools); the daemon opens them with [`Engine::open_sealed`].
    pub fn open(
        cfg: Resolved,
        policy: ResponsePolicy,
        nft: Box<dyn Nft + Send>,
        boot_id: &str,
        now: impl Into<Now>,
    ) -> Result<Self, String> {
        Self::open_with(cfg, policy, nft, boot_id, now.into(), None)
    }

    /// [`Engine::open`] with the journal and the SOC replay store sealed
    /// under `seal` (gap 1, [`crate::journal::seal`]; the key is derived
    /// from the link key, [`crate::proto::Key::state_seal_key`]). A journal
    /// whose seal does not verify, or an unsealed v1 journal, is handled
    /// like an unreadable one (table deleted, `journal_reset` event, High)
    /// and every order is refused until `robodr-executor rearm`; a replay
    /// store that fails its seal is fenced.
    pub fn open_sealed(
        cfg: Resolved,
        policy: ResponsePolicy,
        nft: Box<dyn Nft + Send>,
        boot_id: &str,
        now: impl Into<Now>,
        seal: Arc<robodr_blackbox::StateSealKey>,
    ) -> Result<Self, String> {
        Self::open_with(cfg, policy, nft, boot_id, now.into(), Some(seal))
    }

    fn open_with(
        cfg: Resolved,
        policy: ResponsePolicy,
        nft: Box<dyn Nft + Send>,
        boot_id: &str,
        now: Now,
        seal: Option<Arc<robodr_blackbox::StateSealKey>>,
    ) -> Result<Self, String> {
        let journal = match &seal {
            None => Journal::new(&cfg.config.state_dir),
            Some(k) => Journal::sealed(&cfg.config.state_dir, k.clone()),
        };
        let soc_replay = crate::soc::ReplayStore::open_sealed(
            &cfg.config.state_dir,
            now.wall_ms / 1000,
            cfg.config.soc.max_clock_skew_s,
            journal.path().exists(),
            seal,
        );
        let mut e = Engine {
            state: State::empty(boot_id),
            cfg,
            policy,
            nft,
            journal,
            boot_id: boot_id.to_string(),
            last_verify_boot_ms: now.boot_ms.unwrap_or(now.wall_ms),
            reload: None,
            unjournalled: BTreeSet::new(),
            last_hold_reason: None,
            journal_errors: 0,
            soc_replay,
            motion: Box::new(crate::motion::SystemPorts),
        };
        if let Some(why) = e.soc_replay.fenced_because.clone() {
            e.state.event(
                now.wall_ms,
                EventKind::Reconciled,
                None,
                None,
                format!(
                    "SOC replay store untrusted ({why}): requests signed before this start are \
                     refused (soc_request_stale)"
                ),
            );
        }
        match e.open_inner(now) {
            Ok(()) => Ok(e),
            Err(err) => {
                let del = nft::delete_table(e.nft.as_mut());
                Err(match del {
                    Ok(()) => format!(
                        "{err} (table inet robodr deleted: no rule outlives a failed start)"
                    ),
                    Err(d) => format!("{err}; deleting table inet robodr failed too: {d}"),
                })
            }
        }
    }

    fn open_inner(&mut self, now: Now) -> Result<(), String> {
        match self.journal.load() {
            Loaded::Fresh => {
                let leftover = nft::table_exists(self.nft.as_mut())?;
                if leftover {
                    nft::delete_table(self.nft.as_mut())?;
                    self.state.event(
                        now.wall_ms,
                        EventKind::Reconciled,
                        None,
                        None,
                        "no journal: a leftover table inet robodr was removed",
                    );
                }
            }
            Loaded::Corrupt(why) => {
                nft::delete_table(self.nft.as_mut())?;
                self.state.journal_reset_ms = Some(now.wall_ms);
                self.state.event(
                    now.wall_ms,
                    EventKind::JournalReset,
                    None,
                    None,
                    format!(
                        "HIGH: the journal was unreadable ({why}): table inet robodr deleted, \
                         every action reverted, history lost, starting empty"
                    ),
                );
            }
            Loaded::Untrusted(why) => {
                // Gap 1: never believed, never silently reset. Fail towards
                // doing nothing on the robot (as for an unreadable journal)
                // and refuse every order until the operator re-arms.
                nft::delete_table(self.nft.as_mut())?;
                self.state.journal_reset_ms = Some(now.wall_ms);
                self.state.event(
                    now.wall_ms,
                    EventKind::JournalReset,
                    None,
                    None,
                    format!(
                        "HIGH: {why}: not trusted; table inet robodr deleted, every action \
                         reverted, history lost, starting empty; orders are refused until \
                         `robodr-executor rearm`"
                    ),
                );
            }
            Loaded::State(s) => {
                self.state = s;
                self.reconcile(now)?;
            }
        }
        self.state.boot_id = self.boot_id.clone();
        self.journal.save(&self.state)
    }

    /// Re-read the configuration file (and the policy it names) before every
    /// order and re-arm. The socket, key, state directory and `nft` path keep
    /// their values (a restart changes them).
    pub fn with_reload(mut self, config_path: PathBuf) -> Self {
        self.reload = Some(config_path);
        self
    }

    fn reload_config(&mut self) -> Result<(), Refusal> {
        let Some(p) = &self.reload else {
            return Ok(());
        };
        let fail = |e: String| {
            Refusal::new(
                codes::CONFIG_UNAVAILABLE,
                format!("the configuration or response policy could not be re-read: {e}"),
            )
        };
        let text = crate::config::read_small(p).map_err(fail)?;
        let mut new = ExecutorConfig::parse(&text)
            .and_then(ExecutorConfig::validate)
            .map_err(fail)?;
        let policy = crate::config::load_policy(&new.config.policy_path).map_err(fail)?;
        let old = &self.cfg.config;
        new.config.socket = old.socket.clone();
        new.config.key_file = old.key_file.clone();
        new.config.state_dir = old.state_dir.clone();
        new.config.nft = old.nft.clone();
        new.socket_mode = self.cfg.socket_mode;
        self.cfg = new;
        self.policy = policy;
        Ok(())
    }

    fn reconcile(&mut self, now: Now) -> Result<(), String> {
        let same_boot = self.state.boot_id == self.boot_id;
        let mut summary = Vec::new();
        let entries = std::mem::take(&mut self.state.entries);
        let mut keep = Vec::new();
        let mut held = Vec::new();
        for mut en in entries {
            match en.phase {
                Phase::Applying => {
                    // A motion action may have reached its adapter.
                    self.motion_best_effort(&en, now.wall_ms, "interrupted apply");
                    self.finish(
                        &en,
                        Final::Failed,
                        now.wall_ms,
                        "interrupted between apply and commit (crash or stop): reverted at restart",
                    );
                    self.state.event(
                        now.wall_ms,
                        EventKind::Failed,
                        Some(&en.id),
                        Some(en.action),
                        "interrupted between apply and commit: reverted at restart",
                    );
                    summary.push(format!("{} interrupted apply reverted", en.id));
                }
                Phase::Reverting if !self.motion_settled(&en, now.wall_ms) => {
                    summary.push(format!("{} revert retried every tick", en.id));
                    keep.push(en);
                }
                Phase::Reverting => {
                    self.finish(
                        &en,
                        Final::Reverted,
                        now.wall_ms,
                        "revert completed at restart",
                    );
                    self.state.event(
                        now.wall_ms,
                        EventKind::Reverted,
                        Some(&en.id),
                        Some(en.action),
                        "revert completed at restart",
                    );
                    summary.push(format!("{} revert completed", en.id));
                }
                _ if {
                    // A boot deadline of another boot means nothing here.
                    if !same_boot {
                        en.boot_deadline_ms = None;
                    }
                    expired(&en, now)
                } =>
                {
                    self.state.event(
                        now.wall_ms,
                        EventKind::Expired,
                        Some(&en.id),
                        Some(en.action),
                        "TTL expired while the executor was down (or the clock moved back)",
                    );
                    if !self.motion_settled(&en, now.wall_ms) {
                        en.phase = Phase::Reverting;
                        summary.push(format!("{} expired, revert retried every tick", en.id));
                        keep.push(en);
                        continue;
                    }
                    self.finish(
                        &en,
                        Final::Reverted,
                        now.wall_ms,
                        "TTL expired (at restart)",
                    );
                    self.state.event(
                        now.wall_ms,
                        EventKind::Reverted,
                        Some(&en.id),
                        Some(en.action),
                        "reverted at restart: TTL expired",
                    );
                    summary.push(format!("{} expired", en.id));
                }
                Phase::Active if same_boot => keep.push(en),
                Phase::Active | Phase::Held => held.push(en),
            }
        }
        // After a reboot: re-validate against the current configuration and
        // policy, then hold until a fresh safety check (never re-installed
        // blindly).
        for mut en in held {
            if en.boot_deadline_ms.is_none() {
                let left = en
                    .deadline_ms
                    .saturating_sub(now.wall_ms)
                    .min(en.ttl_s.saturating_mul(1000));
                en.boot_deadline_ms = now.boot_ms.map(|b| b.saturating_add(left));
            }
            match self.revalidate(&en) {
                Ok(effect) => {
                    en.effect = effect;
                    en.phase = Phase::Held;
                    self.state.event(
                        now.wall_ms,
                        EventKind::Held,
                        Some(&en.id),
                        Some(en.action),
                        "after a reboot: re-validated against the current configuration and \
                         policy, held until a fresh safety check allows it",
                    );
                    summary.push(format!("{} held", en.id));
                    keep.push(en);
                }
                Err(r) => {
                    let why = format!("not re-applied after a reboot: {}: {}", r.code, r.reason);
                    self.finish(&en, Final::Reverted, now.wall_ms, &why);
                    self.state.event(
                        now.wall_ms,
                        EventKind::Reverted,
                        Some(&en.id),
                        Some(en.action),
                        why,
                    );
                    summary.push(format!("{} not re-applied", en.id));
                }
            }
        }
        let installed = keep
            .iter()
            .any(|e| e.phase == Phase::Active && is_nft(&e.effect));
        if installed && same_boot && !nft::table_exists(self.nft.as_mut())? {
            self.state.entries = keep;
            self.operator_removed(
                now.wall_ms,
                "table inet robodr was removed while the executor was down (same boot): \
                 operator emergency disable honoured, not re-applied",
            );
            summary.push("removed externally: executor disabled until rearm".into());
            keep = std::mem::take(&mut self.state.entries);
        }
        self.state.entries = keep;
        let r = self.rendered();
        let ok = nft::apply(self.nft.as_mut(), &r).and_then(|()| self.read_verify(&r));
        if let Err(err) = ok {
            // Cannot re-establish the journalled state: fail towards doing
            // nothing on the robot.
            let entries = std::mem::take(&mut self.state.entries);
            let del = nft::delete_table(self.nft.as_mut())
                .and_then(|()| self.read_verify(&Rendered { chains: None }));
            for en in &entries {
                let why = format!("could not be re-applied at restart ({err}): reverted");
                self.finish(en, Final::Reverted, now.wall_ms, &why);
                self.state.event(
                    now.wall_ms,
                    EventKind::Reverted,
                    Some(&en.id),
                    Some(en.action),
                    why,
                );
            }
            if let Err(e2) = del {
                self.state.event(
                    now.wall_ms,
                    EventKind::RevertFailed,
                    None,
                    None,
                    format!(
                        "restart: re-apply failed ({err}) and deleting the table failed ({e2})"
                    ),
                );
                return Err(format!(
                    "re-apply failed ({err}), table delete failed ({e2})"
                ));
            }
            summary.push(format!("re-apply failed: {err}"));
        } else if installed {
            summary.push(format!(
                "{} active action(s) re-applied and verified",
                self.state
                    .entries
                    .iter()
                    .filter(|e| e.phase == Phase::Active)
                    .count()
            ));
        }
        self.state.event(
            now.wall_ms,
            EventKind::Reconciled,
            None,
            None,
            if summary.is_empty() {
                "nothing to do".to_string()
            } else {
                summary.join("; ")
            },
        );
        Ok(())
    }

    /// The precheck of a held entry's order against the current
    /// configuration and policy; the effect it would have now.
    fn revalidate(&self, en: &Entry) -> Result<Effect, Refusal> {
        let Some(order) = &en.order else {
            return Err(Refusal::new(
                codes::INVALID_ORDER,
                "the journal entry holds no order to re-validate (written by executor v1.0)",
            ));
        };
        // Review F9 (b): an approval is only as good as its key; a key the
        // site removed (or that no longer loads) re-arms nothing.
        if let crate::order::Origin::ControlPlane { key_id, .. } = &order.origin {
            if order.human_approved {
                let keys = self.soc_keys()?;
                if !keys.iter().any(|k| &k.key_id == key_id) {
                    return Err(Refusal::new(
                        codes::APPROVAL_KEY_REMOVED,
                        format!(
                            "approved with SOC key {:?}, which is no longer configured \
                             (soc.keys): not re-armed",
                            crate::net::clip(key_id)
                        ),
                    ));
                }
            }
        }
        let p = decision::precheck(order, &self.policy, &self.cfg)?;
        Ok(p.effect)
    }

    /// The configured SOC keys (`soc.keys`, minus nothing: one bad file or
    /// a key equal to one of the robot's own refuses them all,
    /// `soc_keys_unavailable`).
    fn soc_keys(&self) -> Result<Vec<crate::soc::SocKey>, Refusal> {
        let c = &self.cfg.config;
        crate::soc::load_keys_checked(&c.soc.keys, &c.soc.robot_keys, &c.robot_id).map_err(|e| {
            Refusal::new(
                codes::SOC_KEYS_UNAVAILABLE,
                format!(
                    "the SOC key configuration cannot be trusted ({e}): every control-plane \
                     order is refused until it is fixed"
                ),
            )
        })
    }

    fn finish(&mut self, en: &Entry, result: Final, at_ms: u64, detail: &str) {
        self.state.finish(Finished {
            id: en.id.clone(),
            digest: en.digest.clone(),
            action: en.action,
            result,
            at_ms,
            refusal: None,
            detail: Some(detail.to_string()),
        });
    }

    fn save(&mut self) -> Result<(), String> {
        let r = self.journal.save(&self.state);
        if r.is_err() {
            self.journal_errors = self.journal_errors.saturating_add(1);
        }
        r
    }

    /// The rendering of the current journal: `active` and `applying`
    /// entries (never `reverting` or `held` ones).
    pub fn rendered(&self) -> Rendered {
        let act: Vec<Active<'_>> = self
            .state
            .entries
            .iter()
            .filter(|e| matches!(e.phase, Phase::Active | Phase::Applying))
            .map(|e| Active {
                id: &e.id,
                effect: &e.effect,
            })
            .collect();
        nft::render(&act)
    }

    fn read_verify(&mut self, r: &Rendered) -> Result<(), String> {
        let listed = nft::read_table(self.nft.as_mut())?;
        nft::verify(listed.as_deref(), r)
    }

    fn install(&mut self) -> Result<(), String> {
        let r = self.rendered();
        nft::apply(self.nft.as_mut(), &r)?;
        self.read_verify(&r)
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    pub fn policy(&self) -> &ResponsePolicy {
        &self.policy
    }

    pub fn config(&self) -> &Resolved {
        &self.cfg
    }

    /// Actions held after a reboot (waiting for [`Engine::rearm_held`]).
    pub fn has_held(&self) -> bool {
        self.state.entries.iter().any(|e| e.phase == Phase::Held)
    }

    /// Every action is dropped as `removed_externally` and the executor is
    /// disabled until [`Engine::rearm`] (the operator removed the table).
    fn operator_removed(&mut self, now_ms: u64, detail: &str) {
        let entries = std::mem::take(&mut self.state.entries);
        for en in &entries {
            // The executor is disabled: its motion actions are lifted too.
            self.motion_best_effort(en, now_ms, "executor disabled by the operator");
            self.finish(en, Final::RemovedExternally, now_ms, detail);
            self.state.event(
                now_ms,
                EventKind::RemovedExternally,
                Some(&en.id),
                Some(en.action),
                detail.to_string(),
            );
        }
        if !self.state.operator_disabled {
            self.state.operator_disabled = true;
            self.state.event(
                now_ms,
                EventKind::RemovedExternally,
                None,
                None,
                "operator emergency disable (table inet robodr removed): every order is refused \
                 until `robodr-executor rearm`",
            );
        }
        let _ = self.save();
    }

    /// Before a transaction: is the table gone while the journal says rules
    /// are in force? Then an operator removed it: honour that (nothing is
    /// re-created) and answer `true`. An nft error answers `false` (the
    /// transaction then reports it).
    fn removed_by_operator(&mut self, now_ms: u64) -> bool {
        if !self
            .state
            .entries
            .iter()
            .any(|e| e.phase == Phase::Active && is_nft(&e.effect))
        {
            return false;
        }
        match nft::table_exists(self.nft.as_mut()) {
            Ok(false) => {
                self.operator_removed(
                    now_ms,
                    "table inet robodr was removed from outside (emergency disable): action \
                     dropped, not re-applied",
                );
                true
            }
            _ => false,
        }
    }

    /// The operator's explicit re-arm after an emergency disable (and the
    /// acknowledgement of a journal reset). Returns whether the executor was
    /// disabled.
    pub fn rearm(&mut self, reason: &str, now: impl Into<Now>) -> Result<bool, String> {
        let now = now.into();
        let was = self.state.operator_disabled;
        self.state.operator_disabled = false;
        self.state.journal_reset_ms = None;
        self.state.event(
            now.wall_ms,
            EventKind::Rearmed,
            None,
            None,
            format!(
                "re-armed by the operator{}: {}",
                if was { "" } else { " (was not disabled)" },
                crate::net::clip(reason)
            ),
        );
        self.save()?;
        Ok(was)
    }

    /// Execute one order (see the module docs). Never panics; every path
    /// ends in an outcome and, unless refused before anything happened, an
    /// event.
    pub fn submit(
        &mut self,
        order: &Order,
        oracle: &mut dyn SafetyOracle,
        now: impl Into<Now>,
    ) -> Outcome {
        let now = now.into();
        let now_ms = now.wall_ms;
        let digest = order.digest();
        if let Some(en) = self.state.entry(&order.id) {
            if en.digest == digest {
                let mut o = self.status(&order.id);
                o.duplicate = true;
                return o;
            }
            return self.refused_conflict(order);
        }
        if let Some(f) = self.state.finished(&order.id) {
            if f.digest == digest {
                let mut o = self.status(&order.id);
                o.duplicate = true;
                return o;
            }
            return self.refused_conflict(order);
        }
        self.removed_by_operator(now_ms);
        if self.state.operator_disabled {
            return self.refuse(
                order,
                &digest,
                Refusal::new(
                    codes::OPERATOR_DISABLED,
                    "the operator removed table inet robodr (emergency disable): nothing is \
                     executed until `robodr-executor rearm`",
                ),
                now_ms,
            );
        }
        if self.state.journal_reset_ms.is_some() {
            // Gap 1: the journal could not be trusted (unreadable, edited,
            // another key, unsealed) and was reset; nothing new is
            // executed until the operator has looked (`rearm`).
            return self.refuse(
                order,
                &digest,
                Refusal::new(
                    codes::JOURNAL_RESET,
                    "the executor's journal was unreadable or failed its seal and was reset: \
                     nothing is executed until `robodr-executor rearm`",
                ),
                now_ms,
            );
        }
        if let Err(r) = self.reload_config() {
            return self.refuse(order, &digest, r, now_ms);
        }
        // Trust boundary (M1): the approval is the SOC's, verified here.
        let order = match self.authenticate(order, now_ms) {
            Ok(o) => o,
            Err(r) => return self.refuse(order, &digest, r, now_ms),
        };
        let order = &order;
        let planned = match decision::precheck(order, &self.policy, &self.cfg) {
            Ok(p) => p,
            Err(r) => return self.refuse(order, &digest, r, now_ms),
        };
        if matches!(planned.effect, Effect::Motion(_)) {
            return self.submit_motion(order, digest, planned, oracle, now);
        }
        let ttl = match planned.effect {
            Effect::Evidence => {
                return self.refuse(
                    order,
                    &digest,
                    Refusal::new(
                        codes::EVIDENCE_ELSEWHERE,
                        "record_evidence is carried out by agentd (it owns the black box), \
                         not by the executor process",
                    ),
                    now_ms,
                )
            }
            Effect::Advisory { ref note } => {
                let note = note.clone();
                self.state.finish(Finished {
                    id: order.id.clone(),
                    digest,
                    action: order.action,
                    result: Final::Advisory,
                    at_ms: now_ms,
                    refusal: None,
                    detail: Some(note.clone()),
                });
                self.state.event(
                    now_ms,
                    EventKind::Advisory,
                    Some(&order.id),
                    Some(order.action),
                    note.clone(),
                );
                let _ = self.save();
                let mut o = Outcome::bare(&order.id, Status::Advisory);
                o.action = Some(order.action);
                o.note = Some(note);
                return o;
            }
            _ => planned.ttl_s.unwrap_or(self.cfg.config.ttl.default_s),
        };
        // One isolation at a time; one quarantine per participant (a held
        // action does not count: the new order supersedes it).
        let clash = self
            .state
            .entries
            .iter()
            .filter(|e| e.phase != Phase::Held)
            .find(|e| clashes(&e.effect, &planned.effect));
        if let Some(c) = clash {
            let r = Refusal::new(
                codes::ALREADY_ACTIVE,
                format!(
                    "{} is already in force for this target (request {}): revert it first",
                    order.action.as_str(),
                    c.id
                ),
            );
            return self.refuse(order, &digest, r, now_ms);
        }
        // Immediately before apply: the platform's safety state now.
        let current = oracle.current();
        if let Err(r) = decision::recheck_safety(order, current, self.cfg.config.max_safety_age_ms)
        {
            return self.refuse(order, &digest, r, now_ms);
        }
        let superseded: Vec<Entry> = self
            .state
            .entries
            .iter()
            .filter(|e| e.phase == Phase::Held && clashes(&e.effect, &planned.effect))
            .cloned()
            .collect();
        for en in &superseded {
            self.state.entries.retain(|e| e.id != en.id);
            let why = format!("held after a reboot, superseded by request {}", order.id);
            self.finish(en, Final::Reverted, now_ms, &why);
            self.state.event(
                now_ms,
                EventKind::Reverted,
                Some(&en.id),
                Some(en.action),
                why,
            );
        }
        let deadline = now_ms.saturating_add(ttl.saturating_mul(1000));
        self.state.entries.push(Entry {
            id: order.id.clone(),
            digest: digest.clone(),
            action: order.action,
            origin: order.origin.clone(),
            effect: planned.effect.clone(),
            phase: Phase::Applying,
            ttl_s: ttl,
            applied_ms: now_ms,
            deadline_ms: deadline,
            boot_deadline_ms: now
                .boot_ms
                .map(|b| b.saturating_add(ttl.saturating_mul(1000))),
            order: Some(order.clone()),
        });
        if let Err(e) = self.save() {
            self.state.entries.retain(|en| en.id != order.id);
            let mut o = Outcome::bare(&order.id, Status::Failed);
            o.action = Some(order.action);
            o.error = Some(format!("journal write failed, nothing applied: {e}"));
            self.state.event(
                now_ms,
                EventKind::Failed,
                Some(&order.id),
                Some(order.action),
                o.error.clone().unwrap_or_default(),
            );
            return o;
        }
        crash_point!(crate::fault::Point::AfterIntent, &order.id);
        let r = self.rendered();
        if let Err(e) = nft::apply(self.nft.as_mut(), &r) {
            return self.rollback(order, &format!("nft apply failed: {e}"), now_ms);
        }
        crash_point!(crate::fault::Point::AfterApply, &order.id);
        if let Err(e) = self.read_verify(&r) {
            return self.rollback(order, &format!("read-back did not match: {e}"), now_ms);
        }
        if let Some(en) = self.state.entries.iter_mut().find(|en| en.id == order.id) {
            en.phase = Phase::Active;
        }
        if let Err(e) = self.save() {
            return self.rollback(order, &format!("journal commit failed: {e}"), now_ms);
        }
        self.state.event(
            now_ms,
            EventKind::Applied,
            Some(&order.id),
            Some(order.action),
            match quarantine_note(&planned.effect) {
                Some(n) => format!("installed in table inet robodr, ttl {ttl} s; {n}"),
                None => format!("installed in table inet robodr, ttl {ttl} s"),
            },
        );
        self.state.event(
            now_ms,
            EventKind::Verified,
            Some(&order.id),
            Some(order.action),
            "read-back matches the rendered rules",
        );
        let _ = self.save();
        self.status(&order.id)
    }

    /// The order as the executor accepts it: `human_approved` is true only
    /// when the SOC's signed request verifies with the executor's own keys
    /// and matches the order ([`crate::soc::verify`]); a planner order can
    /// never claim an approval. The returned order carries no SOC request
    /// (the journal keeps the verified flag, not the request).
    fn authenticate(&mut self, order: &Order, now_ms: u64) -> Result<Order, Refusal> {
        let mut o = order.clone();
        match &order.origin {
            crate::order::Origin::Planner { .. } => {
                if order.human_approved || order.soc.is_some() {
                    return Err(Refusal::new(
                        codes::APPROVAL_MISSING,
                        "a planner order claims a human approval: only a SOC-signed request \
                         carries one",
                    ));
                }
            }
            crate::order::Origin::ControlPlane { .. } => {
                let keys = self.soc_keys()?;
                let cx = crate::soc::Context {
                    keys: &keys,
                    robot_id: &self.cfg.config.robot_id,
                    max_skew_s: self.cfg.config.soc.max_clock_skew_s,
                    now_ms,
                };
                let approvers = crate::soc::verify(order, &cx, &mut self.soc_replay)?;
                // With a `motion` section the two-person actions can be
                // executed: their approvers are checked here (without one
                // they are refused `not_executor_action` by the precheck).
                if crate::motion::two_person(order.action) && self.cfg.config.motion.is_some() {
                    if let crate::order::Origin::ControlPlane { requested_by, .. } = &order.origin {
                        crate::motion::approvers_ok(order.action, requested_by, &approvers)?;
                    }
                }
                o.human_approved = true;
            }
        }
        o.soc = None;
        Ok(o)
    }

    /// Re-arm the actions held after a reboot, with the platform's safety
    /// state now (asked from agentd): it must be known, fresh and not
    /// engaged ([`decision::recheck_rearm`]); each held order is prechecked
    /// again against the current configuration and policy. Without a usable
    /// state they stay held (and expire at their deadline).
    pub fn rearm_held(&mut self, current: Result<Current, String>, now: impl Into<Now>) {
        let now = now.into();
        let now_ms = now.wall_ms;
        if !self.has_held() {
            return;
        }
        let state_now = current.as_ref().ok().map(|c| c.state);
        if let Err(r) = decision::recheck_rearm(current, self.cfg.config.max_safety_age_ms) {
            let why = format!("{}: {}", r.code, r.reason);
            if self.last_hold_reason.as_deref() != Some(why.as_str()) {
                self.state.event(
                    now_ms,
                    EventKind::Held,
                    None,
                    None,
                    format!("held actions not re-armed: {why}"),
                );
                self.last_hold_reason = Some(why);
                let _ = self.save();
            }
            return;
        }
        self.last_hold_reason = None;
        if self.removed_by_operator(now_ms) || self.state.operator_disabled {
            return;
        }
        let reload = self.reload_config().err();
        let held: Vec<Entry> = self
            .state
            .entries
            .iter()
            .filter(|e| e.phase == Phase::Held)
            .cloned()
            .collect();
        let mut armed = Vec::new();
        let mut waiting = Vec::new();
        for en in held {
            if let Some(why) = state_now.and_then(|s| self.motion_rearm_blocked(&en.effect, s)) {
                waiting.push(format!("{}: {why}", en.id));
                continue;
            }
            let check = match &reload {
                Some(r) => Err(r.clone()),
                None => self.revalidate(&en),
            };
            let clash = self
                .state
                .entries
                .iter()
                .filter(|e| e.phase == Phase::Active)
                .find(|e| check.as_ref().is_ok_and(|eff| clashes(&e.effect, eff)))
                .map(|e| e.id.clone());
            match (check, clash) {
                (Ok(effect), None) => {
                    if let Some(x) = self.state.entries.iter_mut().find(|x| x.id == en.id) {
                        x.effect = effect;
                        x.phase = Phase::Applying;
                    }
                    armed.push(en.id.clone());
                }
                (check, clash) => {
                    let why = match (check, clash) {
                        (Err(r), _) => format!("not re-armed: {}: {}", r.code, r.reason),
                        (_, Some(c)) => format!("not re-armed: request {c} is in force"),
                        _ => String::new(),
                    };
                    self.state.entries.retain(|x| x.id != en.id);
                    self.finish(&en, Final::Reverted, now_ms, &why);
                    self.state.event(
                        now_ms,
                        EventKind::Reverted,
                        Some(&en.id),
                        Some(en.action),
                        why,
                    );
                }
            }
        }
        if !waiting.is_empty() {
            let why = format!("held actions not re-armed: {}", waiting.join("; "));
            if self.last_hold_reason.as_deref() != Some(why.as_str()) {
                self.state
                    .event(now_ms, EventKind::Held, None, None, why.clone());
                self.last_hold_reason = Some(why);
            }
        }
        if armed.is_empty() {
            let _ = self.save();
            return;
        }
        let done = self.save().and_then(|()| self.install());
        for id in &armed {
            let Some(pos) = self.state.entries.iter().position(|x| &x.id == id) else {
                continue;
            };
            match &done {
                Ok(()) => {
                    let Some(en) = self.state.entries.get_mut(pos) else {
                        continue;
                    };
                    en.phase = Phase::Active;
                    let action = en.action;
                    self.state.event(
                        now_ms,
                        EventKind::Verified,
                        Some(id),
                        Some(action),
                        "re-armed after a reboot (re-validated, safety state fresh and not \
                         engaged): installed and verified",
                    );
                }
                Err(e) => {
                    let en = self.state.entries.remove(pos);
                    let why = format!("could not be re-armed after a reboot ({e}): reverted");
                    self.finish(&en, Final::Reverted, now_ms, &why);
                    self.state
                        .event(now_ms, EventKind::Reverted, Some(id), Some(en.action), why);
                }
            }
        }
        if done.is_err() {
            let _ = self.install();
        }
        self.motion_rearmed(&armed, now_ms);
        let _ = self.save();
    }

    fn refused_conflict(&mut self, order: &Order) -> Outcome {
        let mut o = Outcome::bare(&order.id, Status::Refused);
        o.action = Some(order.action);
        o.refusal = Some(Refusal::new(
            codes::ID_CONFLICT,
            "this id was already used for another action, target or ttl",
        ));
        o
    }

    fn refuse(&mut self, order: &Order, digest: &str, r: Refusal, now_ms: u64) -> Outcome {
        self.state.event(
            now_ms,
            EventKind::Refused,
            Some(&order.id),
            Some(order.action),
            format!("{}: {}", r.code, r.reason),
        );
        self.state.finish(Finished {
            id: order.id.clone(),
            digest: digest.to_string(),
            action: order.action,
            result: Final::Refused,
            at_ms: now_ms,
            refusal: Some(r.clone()),
            detail: None,
        });
        let _ = self.save();
        let mut o = Outcome::bare(&order.id, Status::Refused);
        o.action = Some(order.action);
        o.refusal = Some(r);
        o
    }

    /// Undo a failed apply: drop the entry and re-render without it.
    fn rollback(&mut self, order: &Order, why: &str, now_ms: u64) -> Outcome {
        let en = self
            .state
            .entries
            .iter()
            .position(|e| e.id == order.id)
            .map(|i| self.state.entries.remove(i));
        let undo = self.install();
        if let Some(en) = &en {
            self.finish(en, Final::Failed, now_ms, why);
        }
        self.state.event(
            now_ms,
            EventKind::Failed,
            Some(&order.id),
            Some(order.action),
            why.to_string(),
        );
        if let Err(e) = &undo {
            self.state.event(
                now_ms,
                EventKind::RevertFailed,
                Some(&order.id),
                Some(order.action),
                format!(
                    "rolling back the failed apply did not verify ({e}); the periodic \
                         check retries (ttl {})",
                    order
                        .ttl_s
                        .map_or_else(|| "default".to_string(), |t| format!("{t}s"))
                ),
            );
        }
        let _ = self.save();
        let mut o = Outcome::bare(&order.id, Status::Failed);
        o.action = Some(order.action);
        o.error = Some(match undo {
            Ok(()) => format!("{why}; rolled back"),
            Err(e) => format!("{why}; rollback did not verify: {e}"),
        });
        o
    }

    /// A revert **requested** over the protocol (agentd, for the SOC or
    /// its own planner). An action the SOC approved (a control-plane
    /// origin) is lifted only with the SOC's signed revert request
    /// ([`crate::soc::verify_revert`], review finding F3); a refusal leaves
    /// it in force and answers its status with the refusal. A planner
    /// action, an unknown or finished id, and an action already reverting
    /// are handled as [`Engine::revert`].
    ///
    /// Review finding 1: an active `safe_pause` is lifted **only** here,
    /// after its two-person signed revert verified, and only when the
    /// safety state now (`oracle`, asked from agentd over the same
    /// connection) is known, fresh, not engaged and one the pause's
    /// adapters allow; otherwise the pause stays in force and the refusal
    /// is answered. No other path undoes a pause.
    pub fn revert_request(
        &mut self,
        id: &str,
        reason: &str,
        soc: Option<&crate::soc::SocRequest>,
        oracle: &mut dyn SafetyOracle,
        now: impl Into<Now>,
    ) -> Outcome {
        let now = now.into();
        let pause = self
            .state
            .entry(id)
            .filter(|en| en.phase == Phase::Active)
            .and_then(|en| match &en.effect {
                Effect::Motion(spec) if spec.lift_needs_people() => Some(spec.clone()),
                _ => None,
            });
        let needs = self.state.entry(id).and_then(|en| match &en.origin {
            crate::order::Origin::ControlPlane { .. } if en.phase != Phase::Reverting => {
                Some(en.action)
            }
            _ => None,
        });
        if let Some(action) = needs {
            let checked = self.soc_keys().and_then(|keys| {
                let cx = crate::soc::Context {
                    keys: &keys,
                    robot_id: &self.cfg.config.robot_id,
                    max_skew_s: self.cfg.config.soc.max_clock_skew_s,
                    now_ms: now.wall_ms,
                };
                let (rb, approvers) =
                    crate::soc::verify_revert(id, soc, &cx, &mut self.soc_replay)?;
                if crate::motion::two_person(action) {
                    crate::motion::approvers_ok(action, &rb, &approvers)?;
                }
                Ok(())
            });
            let checked = match (checked, &pause) {
                (Ok(()), Some(spec)) => self.lift_safety_ok(spec, oracle),
                (c, _) => c,
            };
            if let Err(r) = checked {
                self.state.event(
                    now.wall_ms,
                    EventKind::Refused,
                    Some(id),
                    Some(action),
                    format!("revert refused: {}: {}", r.code, r.reason),
                );
                let _ = self.save();
                let mut o = self.status(id);
                o.refusal = Some(r);
                return o;
            }
        }
        self.revert_inner(id, reason, now, needs.is_some() && pause.is_some())
    }

    /// Revert one action (TTL, reconciliation, operator, or a request that
    /// [`Engine::revert_request`] authorised). Idempotent: an action
    /// already finished answers its final status. `reverted` is answered
    /// only once the journal records it (see [`crate::journal`]).
    pub fn revert(&mut self, id: &str, reason: &str, now: impl Into<Now>) -> Outcome {
        self.revert_inner(id, reason, now.into(), false)
    }

    /// [`Engine::revert`]; `lift`: a `safe_pause` may be undone (only
    /// [`Engine::revert_request`] sets it, after the two-person signed
    /// revert and the safety re-check).
    fn revert_inner(&mut self, id: &str, reason: &str, now: Now, lift: bool) -> Outcome {
        let now_ms = now.wall_ms;
        let Some(pos) = self.state.entries.iter().position(|e| e.id == id) else {
            return self.status(id);
        };
        if self
            .state
            .entries
            .get(pos)
            .is_some_and(|e| e.phase == Phase::Held)
        {
            // Not installed: nothing to remove.
            let en = self.state.entries.remove(pos);
            self.finish(&en, Final::Reverted, now_ms, reason);
            self.state.event(
                now_ms,
                EventKind::Reverted,
                Some(id),
                Some(en.action),
                reason.to_string(),
            );
            if self.save().is_err() {
                self.state.entries.push(en);
                self.state.history.retain(|h| h.id != id);
                let mut o = self.status(id);
                o.error = Some("journal write failed: retried".into());
                return o;
            }
            return self.status(id);
        }
        if self.removed_by_operator(now_ms) {
            return self.status(id);
        }
        if let Some(en) = self.state.entries.get_mut(pos) {
            en.phase = Phase::Reverting;
        }
        if let Err(e) = self.save() {
            self.journal_failed(id, now_ms, &e);
        }
        crash_point!(crate::fault::Point::AfterRevertIntent, id);
        self.finish_revert(id, reason, now_ms, lift)
    }

    fn journal_failed(&mut self, id: &str, now_ms: u64, e: &str) {
        if self.unjournalled.insert(id.to_string()) {
            let action = self.state.entry(id).map(|x| x.action);
            self.state.event(
                now_ms,
                EventKind::JournalError,
                Some(id),
                action,
                format!(
                    "journal write failed ({e}): the revert is reported `reverting` until it is \
                     journalled; retried every tick"
                ),
            );
        }
    }

    fn finish_revert(&mut self, id: &str, reason: &str, now_ms: u64, lift: bool) -> Outcome {
        let Some(en) = self.state.entry(id).cloned() else {
            return self.status(id);
        };
        if self.removed_by_operator(now_ms) {
            return self.status(id);
        }
        if let Err(o) = self.motion_undo(&en, reason, now_ms, lift) {
            return *o;
        }
        match self.install() {
            Ok(()) => {
                // The rules are lifted (a `reverting` entry is never
                // rendered). Report `reverted` only once the journal says
                // so: otherwise a restart would re-apply it.
                let before = self.state.clone();
                self.state.entries.retain(|e| e.id != id);
                self.finish(&en, Final::Reverted, now_ms, reason);
                self.state.event(
                    now_ms,
                    EventKind::Reverted,
                    Some(id),
                    Some(en.action),
                    reason.to_string(),
                );
                if let Err(e) = self.save() {
                    self.state = before;
                    self.journal_failed(id, now_ms, &e);
                    let mut o = self.status(id);
                    o.error = Some(format!(
                        "the rules are lifted but the revert could not be journalled ({e}): \
                         retried every tick"
                    ));
                    return o;
                }
                self.unjournalled.remove(id);
                self.status(id)
            }
            Err(e) => {
                self.state.event(
                    now_ms,
                    EventKind::RevertFailed,
                    Some(id),
                    Some(en.action),
                    format!(
                        "{reason}: revert did not verify ({e}); retried every tick (ttl {}s, \
                         deadline {} ms)",
                        en.ttl_s, en.deadline_ms
                    ),
                );
                let _ = self.save();
                let mut o = self.status(id);
                o.error = Some(format!("revert did not verify: {e}"));
                o
            }
        }
    }

    /// Housekeeping, every 500 ms or so: retry failed reverts, revert
    /// expired actions (held ones included), and every `verify_interval_s`
    /// read the table back.
    pub fn tick(&mut self, now: impl Into<Now>) {
        let now = now.into();
        let now_ms = now.wall_ms;
        let reverting: Vec<String> = self
            .state
            .entries
            .iter()
            .filter(|e| e.phase == Phase::Reverting)
            .map(|e| e.id.clone())
            .collect();
        for id in reverting {
            self.finish_revert(&id, "revert retried", now_ms, false);
        }
        let expired: Vec<(String, ActionId)> = self
            .state
            .entries
            .iter()
            .filter(|e| matches!(e.phase, Phase::Active | Phase::Held) && expired(e, now))
            .map(|e| (e.id.clone(), e.action))
            .collect();
        for (id, action) in expired {
            if self.pause_outlives_ttl(&id, now_ms) {
                continue;
            }
            self.state.event(
                now_ms,
                EventKind::Expired,
                Some(&id),
                Some(action),
                "TTL expired",
            );
            self.revert(&id, "TTL expired: automatic revert", now);
        }
        let every = self.cfg.config.verify_interval_s.saturating_mul(1000);
        let mono = now.boot_ms.unwrap_or(now_ms);
        if mono.abs_diff(self.last_verify_boot_ms) >= every {
            self.last_verify_boot_ms = mono;
            self.periodic_verify(now_ms);
        }
    }

    /// Read the table back and compare. A table that disappeared while
    /// actions were active is an operator's emergency disable: every action
    /// is dropped, nothing is re-applied and orders are refused until
    /// `rearm`. Any other difference is drift: the rendering is re-applied.
    pub fn periodic_verify(&mut self, now_ms: u64) {
        self.motion_verify(now_ms);
        let r = self.rendered();
        let listed = match nft::read_table(self.nft.as_mut()) {
            Ok(l) => l,
            Err(e) => {
                self.state.event(
                    now_ms,
                    EventKind::Drift,
                    None,
                    None,
                    format!("could not read table inet robodr: {e}"),
                );
                let _ = self.save();
                return;
            }
        };
        if listed.is_none() && r.chains.is_some() {
            self.operator_removed(
                now_ms,
                "table inet robodr was removed from outside (emergency disable): action \
                 dropped, not re-applied",
            );
            return;
        }
        if let Err(diff) = nft::verify(listed.as_deref(), &r) {
            let fixed = self.install();
            self.state.event(
                now_ms,
                EventKind::Drift,
                None,
                None,
                match &fixed {
                    Ok(()) => format!("table differed from the rendering ({diff}): re-applied"),
                    Err(e) => format!("table differed ({diff}); re-applying failed: {e}"),
                },
            );
            let _ = self.save();
        }
    }

    /// Remove every action (operator `revert-all`, a failed start).
    pub fn revert_all(&mut self, reason: &str, now: impl Into<Now>) -> Result<usize, String> {
        let now_ms = now.into().wall_ms;
        let entries = std::mem::take(&mut self.state.entries);
        let del = nft::delete_table(self.nft.as_mut())
            .and_then(|()| self.read_verify(&Rendered { chains: None }));
        for en in &entries {
            self.finish(en, Final::Reverted, now_ms, reason);
            self.state.event(
                now_ms,
                EventKind::Reverted,
                Some(&en.id),
                Some(en.action),
                reason.to_string(),
            );
        }
        del?;
        self.save()?;
        Ok(entries.len())
    }

    /// The state of action `id`.
    pub fn status(&self, id: &str) -> Outcome {
        if let Some(en) = self.state.entry(id) {
            let mut o = Outcome::bare(
                id,
                match en.phase {
                    Phase::Applying => Status::Applying,
                    Phase::Active => Status::Verified,
                    Phase::Reverting => Status::Reverting,
                    Phase::Held => Status::Held,
                },
            );
            o.action = Some(en.action);
            o.applied_ms = Some(en.applied_ms);
            o.deadline_ms = Some(en.deadline_ms);
            o.note = quarantine_note(&en.effect);
            o.quarantine = quarantine_scope(&en.effect);
            return o;
        }
        if let Some(f) = self.state.finished(id) {
            let mut o = Outcome::bare(
                id,
                match f.result {
                    Final::Reverted => Status::Reverted,
                    Final::Failed => Status::Failed,
                    Final::Refused => Status::Refused,
                    Final::Advisory => Status::Advisory,
                    Final::Applied => Status::Applied,
                    Final::RemovedExternally => Status::RemovedExternally,
                },
            );
            o.action = Some(f.action);
            o.refusal = f.refusal.clone();
            o.note = f.detail.clone();
            return o;
        }
        Outcome::bare(id, Status::Unknown)
    }

    /// Events with `seq > since`, at most `max`.
    pub fn events_since(&self, since: u64, max: usize) -> Vec<crate::journal::Event> {
        self.state
            .events
            .iter()
            .filter(|e| e.seq > since)
            .take(max)
            .cloned()
            .collect()
    }
}

/// Two effects on the same target: one isolation at a time, one
/// quarantine per participant, one motion action of each kind.
fn clashes(a: &Effect, b: &Effect) -> bool {
    match (a, b) {
        (Effect::Isolate(_), Effect::Isolate(_)) => true,
        (Effect::Quarantine(x), Effect::Quarantine(y)) => x.guid_prefix == y.guid_prefix,
        (Effect::Motion(x), Effect::Motion(y)) => x.action == y.action,
        _ => false,
    }
}

/// An effect rendered into table `inet robodr`.
fn is_nft(e: &Effect) -> bool {
    matches!(e, Effect::Isolate(_) | Effect::Quarantine(_))
}

#[path = "engine_motion.rs"]
mod motion_exec;

/// Delete the table and mark every journalled action reverted, without
/// reconciling (systemd `ExecStopPost=` after a failed run, and a fatal
/// start error): no rule outlives the process that enforces its TTL. The
/// journal write is best effort (the disk may be full): a later start in
/// the same boot then finds the table gone and treats it as an emergency
/// disable (re-arm needed), never re-installing anything blindly.
pub fn abandon(
    cfg: Option<&Resolved>,
    nft: &mut dyn Nft,
    why: &str,
    now_ms: u64,
) -> Result<usize, String> {
    let del = nft::delete_table(nft);
    let mut n = 0;
    if let Some(cfg) = cfg {
        let j = Journal::new(&cfg.config.state_dir);
        if let Loaded::State(mut s) = j.load() {
            let entries = std::mem::take(&mut s.entries);
            n = entries.len();
            for en in &entries {
                s.finish(Finished {
                    id: en.id.clone(),
                    digest: en.digest.clone(),
                    action: en.action,
                    result: Final::Reverted,
                    at_ms: now_ms,
                    refusal: None,
                    detail: Some(why.to_string()),
                });
                s.event(
                    now_ms,
                    EventKind::Reverted,
                    Some(&en.id),
                    Some(en.action),
                    why.to_string(),
                );
            }
            if n > 0 {
                let _ = j.save(&s);
            }
        }
    }
    del.map(|()| n)
}
