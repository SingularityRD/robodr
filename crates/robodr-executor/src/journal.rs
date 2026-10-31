//! The executor's persistent state (`<state_dir>/journal.json`, schema
//! `robodr-executor-journal/v1`): the active actions with their deadlines,
//! a bounded history of finished ones and a bounded event log agentd reads.
//!
//! **Write-ahead.** An action is written as `applying` (fsynced) *before*
//! the transaction that installs it, and becomes `active` only after the
//! read-back verified it; a revert is written as `reverting` before the
//! transaction that removes it. The table is always rendered from the
//! `active` entries plus the one `applying` entry in flight, never from
//! `reverting` or `held` ones. After a crash at any point,
//! [`crate::engine`]'s reconciliation therefore knows exactly which rules
//! may be installed: `applying` and `reverting` entries are dropped (their
//! transaction may or may not have run; re-rendering without them reverts
//! them), active ones whose deadline passed are reverted, the rest are
//! re-applied and verified (same boot) or held for re-validation and a
//! fresh safety check (after a reboot).
//!
//! A revert is reported `reverted` only once the journal says so: when the
//! write fails (disk full), the rules are lifted all the same, the entry
//! stays `reverting` and the write is retried every tick.
//!
//! Writes are atomic: a temporary file in the same directory, fsync,
//! rename, fsync of the directory.
//!
//! **Sealed (gap 1).** The daemon's journal ([`Journal::sealed`]) is
//! written as [`SEALED_FORMAT`]: a seal line, then the JSON ([`seal`]),
//! under a key derived from the link key. A journal whose seal does not
//! verify, or an unsealed v1 journal, loads as [`Loaded::Untrusted`]:
//! never believed (the engine handles it like an unreadable one and refuses
//! orders until `rearm`). [`Journal::seal_legacy`] is the one-time upgrade
//! (`robodr-executor seal-journal`). The seal detects edits, not an older
//! sealed copy put back: that is what the **epoch** and agentd's anchor
//! are for (below).
//!
//! **Epoch and anchor (review of gap 1).** Every journal carries a random
//! [`State::epoch`] that a reset replaces (the old one is kept as
//! [`State::prev_epoch`]). Every `events` answer carries the journal's head
//! ([`JournalHead`]: epoch and `next_seq`); agentd records it in signed
//! black-box notes and sends the newest head it knows back with every
//! `events` request ([`crate::engine::Engine::check_anchor`]). A journal
//! whose epoch is neither the anchored one nor its successor, or whose
//! `next_seq` is behind the anchor, is an older copy put back (or a
//! deleted journal): it is reset like one that fails its seal.
//!
//! **First start.** A sealed journal that is simply missing is not taken
//! for a first start: unless the first-start marker [`INIT_MARKER`]
//! (created by the package on first install) exists in the state
//! directory, a missing journal is a reset (table deleted, SOC replay
//! store fenced, orders refused until `rearm`). The marker is consumed by
//! the first start.
//!
//! Every write goes to a fresh temporary file (random name, created
//! exclusively, no symlink followed) and is renamed into place
//! ([`write_atomic`]).

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use robodr_blackbox::crypto::{from_hex, to_hex};
use robodr_blackbox::StateSealKey;
use robodr_responder::ActionId;
use serde::{Deserialize, Serialize};

use crate::decision::{Effect, Refusal};
use crate::order::{Order, Origin};

pub const SCHEMA: &str = "robodr-executor-journal/v1";
pub const FILE: &str = "journal.json";
/// Finished actions kept for status queries.
pub const MAX_HISTORY: usize = 256;
/// Events kept for agentd.
pub const MAX_EVENTS: usize = 512;
/// Largest journal file read.
pub const MAX_JOURNAL_BYTES: u64 = 8 << 20;
/// The first-start marker (state directory): created by the package on
/// first install (`packaging/deb/postinst`, `packaging/rpm/post`) or by
/// the operator; without it a missing sealed journal is a reset.
pub const INIT_MARKER: &str = "first-start";
/// Created once the journal has been written sealed: from then on
/// `seal-journal` (the one-time v1 upgrade) is refused.
pub const SEALED_MARKER: &str = "sealed";

/// `O_NOFOLLOW` (Linux: 0o400000, except 0o100000 on arm / aarch64 /
/// powerpc; the BSDs and macOS: 0x100).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub const O_NOFOLLOW: i32 = if cfg!(any(
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "powerpc",
    target_arch = "powerpc64"
)) {
    0o100000
} else {
    0o400000
};
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub const O_NOFOLLOW: i32 = 0x100;

/// 16 random bytes, lower-case hex (journal epochs, temporary names).
/// Falls back to the clock and the process id when the kernel CSPRNG
/// cannot be read (an epoch must exist; uniqueness is what matters).
pub fn random_hex16() -> String {
    let mut b = [0u8; 16];
    match robodr_blackbox::crypto::fill_random(&mut b) {
        Ok(()) => to_hex(&b),
        Err(_) => format!(
            "{:016x}{:08x}{:08x}",
            crate::proto::wall_ms(),
            std::process::id(),
            crate::proto::mono_ms() & 0xffff_ffff
        ),
    }
}

/// Atomically replace `dir/name` with `data`: a new temporary file with a
/// random name (created exclusively, mode 0600, never through a symlink),
/// fsync, rename, fsync of the directory. A planted file or symlink at a
/// temporary name is never written through (review finding 8).
pub fn write_atomic(dir: &Path, name: &str, data: &[u8]) -> std::io::Result<()> {
    let tmp = dir.join(format!("{name}.tmp-{}", random_hex16()));
    let res = (|| -> std::io::Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, dir.join(name))?;
        File::open(dir)?.sync_all()
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// Where a journal ends, as agentd anchors it: its epoch and the next
/// event sequence number (review of gap 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalHead {
    pub epoch: String,
    pub next_seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Applying,
    Active,
    Reverting,
    /// After a reboot: not installed until it is re-validated against the
    /// current configuration and policy and a fresh safety state allows it
    /// ([`crate::engine::Engine::rearm_held`]).
    Held,
}

/// One installed (or being installed / removed) action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub digest: String,
    pub action: ActionId,
    pub origin: Origin,
    pub effect: Effect,
    pub phase: Phase,
    pub ttl_s: u64,
    /// Wall clock (Unix ms).
    pub applied_ms: u64,
    pub deadline_ms: u64,
    /// The deadline on CLOCK_BOOTTIME (ms) of the boot in
    /// [`State::boot_id`]: within a boot it decides expiry (a wall-clock
    /// step changes nothing); the wall-clock deadline is used across a
    /// reboot only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_deadline_ms: Option<u64>,
    /// The order, for the re-validation after a reboot (absent in journals
    /// of executor v1.0: such an entry is reverted at a reboot).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<Order>,
}

/// How a finished action ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Final {
    /// Reverted (request, TTL, restart reconciliation, revert-all).
    Reverted,
    /// Never took effect: the apply failed and was rolled back.
    Failed,
    /// Refused before anything was applied.
    Refused,
    /// Recorded only (`restrict_motion` without a `motion` section).
    Advisory,
    /// The table was removed from outside (operator emergency disable).
    RemovedExternally,
    /// A non-reversible motion action (`request_safe_state`,
    /// `rollback_config`) took effect through its adapter; nothing to undo.
    Applied,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finished {
    pub id: String,
    pub digest: String,
    pub action: ActionId,
    pub result: Final,
    pub at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<Refusal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// What happened (agentd records every event in its black box).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Applied,
    Verified,
    Refused,
    Failed,
    Advisory,
    Reverted,
    /// A revert's transaction or read-back failed: the rules may still be
    /// in place. Retried every tick; agentd reports it as High.
    RevertFailed,
    /// The TTL expired (a `reverted` event follows).
    Expired,
    /// The installed table differed from the rendering and was re-applied.
    Drift,
    /// The table disappeared while actions were active (operator
    /// `nft delete table inet robodr`): every action is dropped, nothing is
    /// re-applied.
    RemovedExternally,
    /// Restart reconciliation finished (detail: what it did); also the
    /// commissioning notes of a configuration re-read changed (detail
    /// starts with `commissioning`).
    Reconciled,
    /// The journal was unreadable: the table was deleted and the executor
    /// started empty. High severity: whatever was in force is gone and its
    /// history lost (status flag `journal_reset_ms` until `rearm`).
    JournalReset,
    /// After a reboot an action waits for re-validation and a fresh safety
    /// check before it is installed again.
    Held,
    /// The operator re-armed the executor after an emergency disable.
    Rearmed,
    /// A journal write failed (disk full, I/O error); retried.
    JournalError,
    /// Someone set the robot moving again while a `safe_pause` was in
    /// force (a navigation goal, a flight-mode change; sales-readiness
    /// T42): the latch cancelled it / set hold again (detail: what it
    /// found). agentd reports it as High.
    Overridden,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    pub at_ms: u64,
    pub kind: EventKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<ActionId>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct State {
    pub schema: String,
    /// Boot the active entries were last applied in.
    pub boot_id: String,
    pub next_seq: u64,
    pub entries: Vec<Entry>,
    pub history: VecDeque<Finished>,
    pub events: VecDeque<Event>,
    /// The operator removed table `inet robodr` (emergency disable): no
    /// order is executed until `robodr-executor rearm`.
    #[serde(default)]
    pub operator_disabled: bool,
    /// The journal was found unreadable and reset at this time (Unix ms);
    /// cleared by `rearm`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal_reset_ms: Option<u64>,
    /// This journal's random epoch: replaced by every reset (empty in
    /// journals written before it existed; assigned at the next start).
    #[serde(default)]
    pub epoch: String,
    /// The epoch this one replaced (a reset): agentd may still anchor it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_epoch: Option<String>,
}

impl State {
    pub fn empty(boot_id: &str) -> Self {
        Self {
            schema: SCHEMA.into(),
            boot_id: boot_id.into(),
            next_seq: 1,
            entries: Vec::new(),
            history: VecDeque::new(),
            events: VecDeque::new(),
            operator_disabled: false,
            journal_reset_ms: None,
            epoch: random_hex16(),
            prev_epoch: None,
        }
    }

    /// Where this journal ends (what agentd anchors).
    pub fn head(&self) -> JournalHead {
        JournalHead {
            epoch: self.epoch.clone(),
            next_seq: self.next_seq,
        }
    }

    pub fn event(
        &mut self,
        at_ms: u64,
        kind: EventKind,
        id: Option<&str>,
        action: Option<ActionId>,
        detail: impl Into<String>,
    ) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        self.events.push_back(Event {
            seq,
            at_ms,
            kind,
            id: id.map(str::to_string),
            action,
            detail: detail.into(),
        });
        while self.events.len() > MAX_EVENTS {
            self.events.pop_front();
        }
    }

    pub fn finish(&mut self, f: Finished) {
        self.history.retain(|h| h.id != f.id);
        self.history.push_back(f);
        while self.history.len() > MAX_HISTORY {
            self.history.pop_front();
        }
    }

    pub fn entry(&self, id: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == id)
    }

    pub fn finished(&self, id: &str) -> Option<&Finished> {
        self.history.iter().rev().find(|h| h.id == id)
    }
}

/// Format of the sealed journal file (gap 1): one line
/// `robodr-executor-journal/v2 <key id> <64 hex tag>`, then the JSON state
/// (schema [`SCHEMA`]). See [`seal`].
pub const SEALED_FORMAT: &str = "robodr-executor-journal/v2";
/// Purpose of the state-seal key derived from the executor's link key.
pub const SEAL_PURPOSE: &str = "executor/state/v1";

/// Seal `json` as a `format` file under `key` (gap 1: the executor's
/// state files are tamper-evident):
///
/// ```text
/// <format> <key id> <64 hex: HMAC-SHA256(K, format 0x00 | len|key id | len|json)>\n<json>
/// ```
///
/// `K` is the [`robodr_blackbox::StateSealKey`] derived from the executor's
/// link key (purpose [`SEAL_PURPOSE`]): whoever can write the state
/// directory but does not hold that key cannot edit the file without the
/// next load seeing it. A seal does not tell an older sealed file from the
/// current one (see the crate README, "Trust boundary").
pub fn seal(key: &StateSealKey, format: &str, json: &[u8]) -> Vec<u8> {
    let tag = key.tag(format, &[key.key_id().as_bytes(), json]);
    let mut out = format!("{format} {} {}\n", key.key_id(), to_hex(&tag)).into_bytes();
    out.extend_from_slice(json);
    out
}

/// Why a sealed file was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unsealed {
    /// No seal line at all: a file of a release that did not seal (v1).
    Legacy,
    /// The seal line is malformed, names another key, or the tag does not
    /// verify (reason).
    Bad(String),
}

/// The JSON of a [`seal`]ed `format` file, if its seal verifies under
/// `key`.
pub fn unseal<'a>(key: &StateSealKey, format: &str, bytes: &'a [u8]) -> Result<&'a [u8], Unsealed> {
    let prefix = format!("{format} ");
    if !bytes.starts_with(prefix.as_bytes()) {
        return Err(if bytes.first() == Some(&b'{') {
            Unsealed::Legacy
        } else {
            Unsealed::Bad(format!("no {format} seal line"))
        });
    }
    let Some(nl) = bytes.iter().position(|b| *b == b'\n') else {
        return Err(Unsealed::Bad("the seal line is not terminated".into()));
    };
    let (Some(line), Some(json)) = (bytes.get(prefix.len()..nl), bytes.get(nl + 1..)) else {
        return Err(Unsealed::Bad("malformed seal line".into()));
    };
    let line = std::str::from_utf8(line)
        .map_err(|_| Unsealed::Bad("the seal line is not UTF-8".into()))?;
    let mut parts = line.split(' ');
    let (Some(key_id), Some(tag), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(Unsealed::Bad("malformed seal line".into()));
    };
    if key_id != key.key_id() {
        return Err(Unsealed::Bad(format!(
            "sealed under another key ({}; this executor's is {})",
            crate::net::clip(key_id),
            key.key_id()
        )));
    }
    let ok = from_hex(tag).is_some_and(|t| key.check(format, &[key.key_id().as_bytes(), json], &t));
    if ok {
        Ok(json)
    } else {
        Err(Unsealed::Bad(
            "the seal does not verify: the file was edited".into(),
        ))
    }
}

/// The journal file.
#[derive(Debug)]
pub struct Journal {
    dir: PathBuf,
    /// The state-seal key (gap 1); `None`: unsealed, as executor v1 wrote it
    /// (tests and tools only: the daemon always seals).
    seal: Option<Arc<StateSealKey>>,
}

/// Outcome of loading.
#[derive(Debug)]
pub enum Loaded {
    Fresh,
    State(State),
    /// Present but unreadable (reason).
    Corrupt(String),
    /// Readable but not trusted (gap 1): the seal does not verify, names
    /// another key, or the file is an unsealed v1 journal that was not
    /// upgraded with `robodr-executor seal-journal` (reason).
    Untrusted(String),
}

impl Journal {
    /// An unsealed journal (executor v1 format; tests and tools).
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
            seal: None,
        }
    }

    /// A journal sealed under `key` ([`SEALED_FORMAT`]).
    pub fn sealed(dir: &Path, key: Arc<StateSealKey>) -> Self {
        Self {
            dir: dir.to_path_buf(),
            seal: Some(key),
        }
    }

    pub fn is_sealed(&self) -> bool {
        self.seal.is_some()
    }

    pub fn path(&self) -> PathBuf {
        self.dir.join(FILE)
    }

    pub fn load(&self) -> Loaded {
        let p = self.path();
        let text = match crate::config::read_small(&p) {
            Ok(t) => t,
            Err(_) if !p.exists() => return Loaded::Fresh,
            Err(e) => return Loaded::Corrupt(e),
        };
        if text.len() as u64 > MAX_JOURNAL_BYTES {
            return Loaded::Corrupt("journal too large".into());
        }
        let json = match &self.seal {
            None => text.as_bytes(),
            Some(k) => match unseal(k, SEALED_FORMAT, text.as_bytes()) {
                Ok(j) => j,
                Err(Unsealed::Legacy) => {
                    return Loaded::Untrusted(
                        "the journal is unsealed (executor v1): run `robodr-executor \
                         seal-journal` once after the upgrade, with the executor stopped"
                            .into(),
                    )
                }
                Err(Unsealed::Bad(why)) => {
                    return Loaded::Untrusted(format!("the journal failed its seal: {why}"))
                }
            },
        };
        match serde_json::from_slice::<State>(json) {
            Ok(s) if s.schema == SCHEMA => Loaded::State(s),
            Ok(_) => Loaded::Corrupt(format!("journal schema is not {SCHEMA}")),
            Err(e) => Loaded::Corrupt(format!("journal: {e}")),
        }
    }

    /// The one-time upgrade (`robodr-executor seal-journal`, executor
    /// stopped): read an unsealed v1 journal and write it sealed. Refused
    /// for a journal that is already sealed, missing, or unreadable, and
    /// once the journal has ever been written sealed ([`SEALED_MARKER`]):
    /// then an unsealed file is a plant, not an upgrade (review finding 7).
    /// The adopted entries are not trusted as installed: the state is
    /// marked as of no boot, so the next start re-validates every active
    /// entry and holds it until a fresh safety check ([`Phase::Held`]), and
    /// it starts a new epoch.
    pub fn seal_legacy(&self) -> Result<String, String> {
        let Some(key) = &self.seal else {
            return Err("no state-seal key".into());
        };
        let marker = self.dir.join(SEALED_MARKER);
        if std::fs::symlink_metadata(&marker).is_ok() {
            return Err(format!(
                "{} exists: this executor has written its journal sealed before, so an unsealed \
                 journal is not an upgrade (planted or restored) and is not adopted; start the \
                 executor: it resets the journal and refuses orders until `rearm`",
                marker.display()
            ));
        }
        let p = self.path();
        let text = crate::config::read_small(&p)?;
        match unseal(key, SEALED_FORMAT, text.as_bytes()) {
            Ok(_) => return Err(format!("{} is sealed already", p.display())),
            Err(Unsealed::Bad(why)) => {
                return Err(format!(
                    "{} is not an unsealed v1 journal ({why})",
                    p.display()
                ))
            }
            Err(Unsealed::Legacy) => {}
        }
        let mut s = match Journal::new(&self.dir).load() {
            Loaded::State(s) => s,
            _ => return Err(format!("{} is not a readable v1 journal", p.display())),
        };
        // Not trusted as installed: re-validated and held at the next start.
        s.boot_id = String::new();
        s.prev_epoch = None;
        s.epoch = random_hex16();
        self.save(&s)?;
        self.mark_sealed();
        Ok(format!(
            "{} sealed ({} active action(s), held for re-validation at the next start, key {})",
            p.display(),
            s.entries.len(),
            key.key_id()
        ))
    }

    /// Atomically replace the journal with `s`.
    pub fn save(&self, s: &State) -> Result<(), String> {
        #[cfg(feature = "fault-injection")]
        if crate::fault::hit(crate::fault::Point::JournalWrite) {
            return Err("fault injected: journal write".into());
        }
        let json = serde_json::to_vec_pretty(s).map_err(|e| e.to_string())?;
        let data = match &self.seal {
            None => json,
            Some(k) => seal(k, SEALED_FORMAT, &json),
        };
        write_atomic(&self.dir, FILE, &data)
            .map_err(|e| format!("journal {}: {e}", self.path().display()))
    }

    /// Record that the journal has been written sealed ([`SEALED_MARKER`];
    /// best effort, idempotent).
    pub fn mark_sealed(&self) {
        if self.seal.is_none() {
            return;
        }
        if std::fs::symlink_metadata(self.dir.join(SEALED_MARKER)).is_err() {
            let _ = write_atomic(&self.dir, SEALED_MARKER, b"robodr-executor-journal/v2\n");
        }
    }

    /// The first-start marker ([`INIT_MARKER`]) exists.
    pub fn init_marker(&self) -> bool {
        std::fs::symlink_metadata(self.dir.join(INIT_MARKER)).is_ok()
    }

    /// Consume the first-start marker (best effort).
    pub fn consume_init_marker(&self) {
        let _ = std::fs::remove_file(self.dir.join(INIT_MARKER));
    }
}
