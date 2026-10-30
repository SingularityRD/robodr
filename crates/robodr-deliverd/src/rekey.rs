//! `robodr-deliverd rekey` (review L-R3-3): carry the agent's evidence
//! and anti-rollback baseline over a rotation of the unit's black-box key
//! (`docs/OPERATIONS.md` §4.3, §11.3).
//!
//! The delivery journal and the high-water record are signed with the
//! black-box key. After a rotation the recorder refuses the old chain
//! (`KeyMismatch`) and the record no longer verifies, so the agent would
//! lock itself; deleting `blackbox/deliverd` instead would also discard
//! the anti-rollback history. `rekey`, with the service stopped:
//!
//! 1. checks both key files (the old one must open the journal: the
//!    journal must verify completely with it, and so must the record);
//! 2. notes the hand-over in the old journal (`robodr.deliver.key_retired`)
//!    and closes it with its seal;
//! 3. builds the new generation next to it (`<dir>.rekey-new`): a journal
//!    signed with the new key whose first note (`robodr.deliver.rekeyed`)
//!    carries the baseline (floors, record generation, trust version,
//!    newest deployment, chain heads, time floor; [`crate::journal::History`]
//!    reads it like the notes it replaces), and the high-water record,
//!    one generation newer, signed with the new key (a lock in it is
//!    kept);
//! 4. renames the old directory to `<dir>.archived-g<generation>` (kept:
//!    it still verifies with the retired key) and the new one into place.
//!
//! An interrupted run is finished by running it again: a missing journal
//! directory next to a complete `<dir>.rekey-new` is moved into place.
//! Nothing is ever lowered: the new record is the old one (floors raised
//! to those the journal noted) with the next generation.

use crate::config::Config;
use crate::highwater;
use crate::journal::{kinds, Journal};
use crate::state::StateFile;
use robodr_blackbox::KeyFile;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// The note that closes the old journal.
pub const KEY_RETIRED: &str = "robodr.deliver.key_retired";

fn load(p: &Path, what: &str, allow_hmac: bool) -> Result<KeyFile, String> {
    crate::journal::load_blackbox_key(p, allow_hmac, what)
}

fn sibling(dir: &Path, suffix: &str) -> Result<PathBuf, String> {
    let name = dir
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("{}: no directory name", dir.display()))?;
    let parent = dir
        .parent()
        .ok_or_else(|| format!("{}: no parent directory", dir.display()))?;
    Ok(parent.join(format!("{name}.{suffix}")))
}

fn sync_parent(dir: &Path) -> Result<(), String> {
    if let Some(p) = dir.parent() {
        crate::fsx::sync_dir(p).map_err(|e| format!("{}: {e}", p.display()))?;
    }
    Ok(())
}

/// Re-sign the agent's journal generation and high-water record from
/// `old_key` to `new_key` (secret key files). The service must be stopped.
pub fn rekey(cfg: &Config, old_key: &Path, new_key: &Path) -> Result<Value, String> {
    let dir = &cfg.blackbox.dir;
    let staging = sibling(dir, "rekey-new")?;
    // A legacy HMAC key (old: the migration off HMAC) needs
    // blackbox.allow_hmac, like every other load of the black-box key.
    let allow_hmac = cfg.blackbox.allow_hmac;
    let old_kf = load(old_key, "old key", allow_hmac)?;
    let new_kf = load(new_key, "new key", allow_hmac)?;
    let old = old_kf.signer().map_err(|e| format!("old key: {e}"))?;
    let new = new_kf.signer().map_err(|e| format!("new key: {e}"))?;
    if old.key_id() == new.key_id() {
        return Err(format!(
            "the old and the new key have the same key id ({}); a rotation needs a new key id",
            old.key_id()
        ));
    }
    // Finish an interrupted run.
    if std::fs::symlink_metadata(dir).is_err()
        && highwater::path(&staging).is_file()
        && Journal::has_records(&staging)
    {
        std::fs::rename(&staging, dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        sync_parent(dir)?;
        return Ok(json!({"finished": "an interrupted rekey", "journal": dir}));
    }
    let has_records = Journal::has_records(dir);
    let state = StateFile::new(&cfg.state_path()).load()?;
    // 1. Everything must verify with the old key.
    let hw = highwater::load(dir, old.as_ref()).map_err(|e| {
        format!(
            "{e}; rekey needs a record that verifies with the old key (a locked agent: \
             reanchor it with --key <old key> first)"
        )
    })?;
    let Some(hw) = hw else {
        if has_records || state.is_some() {
            return Err(
                "the high-water record is missing; reanchor the agent with --key <old key> \
                 first"
                    .into(),
            );
        }
        return Ok(json!({"rekeyed": false,
                         "why": "no journal and no record yet: start the agent with the new key"}));
    };
    if hw.site != cfg.unit.site || hw.unit != cfg.unit.id {
        return Err(format!(
            "high-water record of unit {} at site {}, this is {} at {}",
            hw.unit, hw.site, cfg.unit.id, cfg.unit.site
        ));
    }
    if has_records {
        let v = old_kf.verifier().map_err(|e| format!("old key: {e}"))?;
        let r = robodr_blackbox::verify::verify_dir(dir, v.as_ref(), &Default::default())
            .map_err(|e| format!("{}: {e}", dir.display()))?;
        if !r.is_intact() {
            return Err(format!(
                "{}: the delivery journal does not verify with the old key ({})",
                dir.display(),
                r.tamper()
                    .next()
                    .map(|f| format!("{f:?}"))
                    .unwrap_or_default()
            ));
        }
    }
    let history = Journal::history(dir, old.as_ref());
    let state_gen = state.as_ref().map_or(0, |s| s.hw_generation);
    let newest = history.hw_generation.max(state_gen);
    if hw.generation < newest {
        return Err(format!(
            "the high-water record is generation {}, older than the generation {newest} the \
             journal or the state file noted; reanchor the agent with --key <old key> first",
            hw.generation
        ));
    }
    let mut doc = hw.clone();
    doc.generation = hw.generation.max(newest).saturating_add(1);
    for (n, f) in &history.floors {
        let e = doc.floors.entry(n.clone()).or_insert(0);
        *e = (*e).max(*f);
    }
    doc.time_floor = doc.time_floor.max(history.time_floor);
    let mut archive = sibling(dir, &format!("archived-g{}", hw.generation))?;
    let mut n = 1;
    while std::fs::symlink_metadata(&archive).is_ok() {
        n += 1;
        archive = sibling(dir, &format!("archived-g{}-{n}", hw.generation))?;
    }
    // 2. Close the old journal with the hand-over (this also takes its
    // single-writer lock: a running agent makes this fail).
    if has_records {
        let mut j = Journal::open_with(dir, &cfg.unit.id, old_key, allow_hmac)
            .map_err(|e| format!("{e} (stop robodr-deliverd first)"))?;
        j.note(
            KEY_RETIRED,
            json!({"old_key_id": old.key_id(), "new_key_id": new.key_id(),
                   "generation": doc.generation, "archived_to": archive}),
        )?;
        j.close()?;
    }
    // 3. The new generation, beside it.
    crate::fsx::remove_any(&staging).map_err(|e| format!("{}: {e}", staging.display()))?;
    let res = (|| -> Result<(), String> {
        let mut j = Journal::open_with(&staging, &cfg.unit.id, new_key, allow_hmac)?;
        j.note(
            kinds::REKEYED,
            json!({"generation": doc.generation, "trust_version": history.trust_version,
                   "time_floor": doc.time_floor, "floors": doc.floors,
                   "last_deployment": doc.last_deployment.clone().or(history.last_deployment.clone()),
                   "chains": doc.chains, "locked": doc.locked,
                   "old_key_id": old.key_id(), "new_key_id": new.key_id(),
                   "archived": archive, "digest": doc.digest()?}),
        )?;
        j.close()?;
        highwater::store(&staging, &doc, new.as_ref())?;
        crate::fsx::sync_dir(&staging).map_err(|e| format!("{}: {e}", staging.display()))
    })();
    if let Err(e) = res {
        let _ = crate::fsx::remove_any(&staging);
        return Err(e);
    }
    // 4. Swap.
    std::fs::rename(dir, &archive).map_err(|e| format!("{}: {e}", dir.display()))?;
    std::fs::rename(&staging, dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    sync_parent(dir)?;
    Ok(
        json!({"rekeyed": true, "old_key_id": old.key_id(), "new_key_id": new.key_id(),
              "generation": doc.generation, "archived": archive, "journal": dir,
              "floors": doc.floors, "locked": doc.locked.map(|l| l.why)}),
    )
}
