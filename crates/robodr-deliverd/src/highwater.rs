//! The high-water record (review M1): the agent's anti-rollback and
//! anti-replay baseline, kept **outside** the state file and outside the
//! cyclic delivery journal, so that losing `state.json` does not reopen a
//! downgrade, a replayed deployment or an expired one.
//!
//! ```text
//! <blackbox.dir>/highwater.json   robodr-deliverd-highwater/1, signed
//! ```
//!
//! It holds exactly what must never go backwards: the floors, the accepted
//! deployment's sequence (and digest, expiry), the time floor and the
//! bundle chain heads. It is rewritten (atomically) **before** every state
//! write that moves any of them, so it is never behind the state file; it
//! is never rotated or evicted (the journal's `floor_raised` notes age out
//! after about 16 MiB of notes; this file does not). It lives in the
//! black-box directory, a tree separate from the state directory.
//!
//! **Integrity.** The record is signed with the unit's black-box key (the
//! key the delivery journal is signed with), over a domain-separated
//! encoding of the document. A record that does not verify, or names
//! another unit or site, is not used: the agent reports it and treats it
//! as missing.
//!
//! **Honest limit.** Root can delete the file, like the state file. The
//! agent then fails closed: when the state file is missing and no valid
//! record is left while the journal shows the unit had a history, it
//! locks itself (no import, no install, no rollback) until an operator
//! re-anchors it (`robodr-deliverd reanchor`). A TPM NV counter (14b)
//! closes the remaining gap.

use crate::state::{LastDeployment, State};
use robodr_blackbox::Signer;
use robodr_pkg::bundle::ChainState;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// `format` of the record.
pub const HIGHWATER_FORMAT: &str = "robodr-deliverd-highwater/1";
/// File name in the black-box directory.
pub const HIGHWATER_FILE: &str = "highwater.json";
/// Largest record read.
pub const MAX_HIGHWATER_BYTES: usize = 1024 * 1024;
/// Signature domain (prefix of the signed bytes).
const DOMAIN: &[u8] = b"robodr-deliverd-highwater/1\n";

/// The baseline itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HighWater {
    pub format: String,
    pub site: String,
    pub unit: String,
    pub floors: BTreeMap<String, u64>,
    pub last_deployment: Option<LastDeployment>,
    pub time_floor: u64,
    pub chains: Vec<ChainState>,
}

/// The file: the document, the signing key id and the signature (hex).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Signed {
    doc: HighWater,
    key_id: String,
    sig: String,
}

/// The record's path for black-box directory `dir`.
pub fn path(dir: &Path) -> PathBuf {
    dir.join(HIGHWATER_FILE)
}

fn message(doc: &HighWater) -> Result<Vec<u8>, String> {
    let mut m = DOMAIN.to_vec();
    m.extend(serde_json::to_vec(doc).map_err(|e| e.to_string())?);
    Ok(m)
}

impl HighWater {
    /// The baseline of `s`.
    pub fn of(s: &State) -> Self {
        Self {
            format: HIGHWATER_FORMAT.into(),
            site: s.site.clone(),
            unit: s.unit.clone(),
            floors: s.floors.clone(),
            last_deployment: s.last_deployment.clone(),
            time_floor: s.time_floor,
            chains: s.chains.clone(),
        }
    }

    /// Structural checks (the same rules as the state's fields).
    fn validate(&self) -> Result<(), String> {
        let mut s = State::new(&self.site, &self.unit);
        s.floors = self.floors.clone();
        s.last_deployment = self.last_deployment.clone();
        s.time_floor = self.time_floor;
        s.chains = self.chains.clone();
        if self.format != HIGHWATER_FORMAT {
            return Err("high-water record: bad format".into());
        }
        s.validate().map_err(|e| format!("high-water record: {e}"))
    }

    /// Raise `s` to this baseline (never lowers anything). Returns what
    /// moved, for the evidence.
    pub fn raise(&self, s: &mut State) -> Vec<serde_json::Value> {
        let mut moved = Vec::new();
        for (name, f) in &self.floors {
            if let Some(old) = s.raise_floor(name, *f) {
                moved.push(serde_json::json!({"floor": name, "state": old, "high_water": f}));
            }
        }
        if let Some(l) = &self.last_deployment {
            if s.last_deployment.as_ref().is_none_or(|x| x.seq < l.seq) {
                moved.push(serde_json::json!({
                    "deployment_seq": l.seq,
                    "state": s.last_deployment.as_ref().map(|x| x.seq)
                }));
                s.last_deployment = Some(l.clone());
            }
        }
        if self.time_floor > s.time_floor {
            moved.push(serde_json::json!({"time_floor": self.time_floor, "state": s.time_floor}));
            s.time_floor = self.time_floor;
        }
        for c in &self.chains {
            if s.chain(&c.programme)
                .is_none_or(|x| x.bundle_seq < c.bundle_seq)
            {
                moved.push(serde_json::json!({
                    "chain": c.programme,
                    "bundle_seq": c.bundle_seq,
                    "state": s.chain(&c.programme).map(|x| x.bundle_seq)
                }));
                s.set_chain(c.clone());
            }
        }
        moved
    }
}

/// Read and verify the record in `dir` with `key` (the black-box signer,
/// which verifies its own signatures). `Ok(None)`: no record. `Err`: a
/// record is there but unreadable, malformed or not signed by `key`.
pub fn load(dir: &Path, key: &dyn Signer) -> Result<Option<HighWater>, String> {
    let p = path(dir);
    let Some(b) = crate::fsx::read_optional(&p, MAX_HIGHWATER_BYTES)
        .map_err(|e| format!("{}: {e}", p.display()))?
    else {
        return Ok(None);
    };
    let s: Signed = serde_json::from_slice(&b).map_err(|e| {
        format!(
            "{}: {}",
            p.display(),
            robodr_pkg::common::trunc(&e.to_string())
        )
    })?;
    s.doc.validate()?;
    let sig = hex_decode(&s.sig).ok_or("high-water record: bad signature encoding")?;
    if s.key_id != key.key_id() {
        return Err(format!(
            "high-water record: signed by key {}, not the unit's black-box key {}",
            robodr_pkg::common::trunc(&s.key_id),
            key.key_id()
        ));
    }
    match key.verify_own(&message(&s.doc)?, &sig) {
        Some(true) => Ok(Some(s.doc)),
        Some(false) => Err("high-water record: the signature does not verify".into()),
        None => Err("high-water record: the black-box key cannot verify its signature".into()),
    }
}

/// Sign `doc` with `key` and replace the record in `dir` atomically.
pub fn store(dir: &Path, doc: &HighWater, key: &dyn Signer) -> Result<(), String> {
    let sig = key
        .sign(&message(doc)?)
        .map_err(|e| format!("high-water record: signing: {e}"))?;
    let s = Signed {
        doc: doc.clone(),
        key_id: key.key_id().to_string(),
        sig: robodr_blackbox::crypto::to_hex(&sig),
    };
    let bytes = serde_json::to_vec_pretty(&s).map_err(|e| e.to_string())?;
    let p = path(dir);
    crate::fsx::write_atomic(&p, &bytes, 0o640).map_err(|e| format!("{}: {e}", p.display()))
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || s.len() > 4096 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> Box<dyn Signer> {
        robodr_blackbox::KeyFile::ed25519_from_seed(&[seed; 32], Some("hw-test"))
            .unwrap()
            .signer()
            .unwrap()
    }

    #[test]
    fn round_trip_and_tampering() {
        let d = std::env::temp_dir().join(format!("deliverd-hw-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let k = key(1);
        assert_eq!(load(&d, k.as_ref()).unwrap(), None);
        let mut s = State::new("site-a", "ugv-07");
        s.raise_floor("nav", 5);
        s.time_floor = 77;
        let hw = HighWater::of(&s);
        store(&d, &hw, k.as_ref()).unwrap();
        assert_eq!(load(&d, k.as_ref()).unwrap(), Some(hw.clone()));
        // Another key, or a lowered floor, is refused.
        assert!(load(&d, key(2).as_ref()).is_err());
        let txt = std::fs::read_to_string(path(&d)).unwrap();
        std::fs::write(path(&d), txt.replace("\"nav\": 5", "\"nav\": 1")).unwrap();
        assert!(load(&d, k.as_ref())
            .unwrap_err()
            .contains("does not verify"));
        // Raising never lowers.
        let mut t = State::new("site-a", "ugv-07");
        t.raise_floor("nav", 9);
        assert_eq!(hw.raise(&mut t).len(), 1, "only the time floor moves");
        assert_eq!(t.floor("nav"), 9);
        assert_eq!(t.time_floor, 77);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
