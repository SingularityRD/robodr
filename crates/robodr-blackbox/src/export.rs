//! Store-and-forward: anchors, checkpoints, export bundles and the receiver.
//!
//! An air-gapped unit cannot stream evidence; it exports it, typically through
//! a one-way diode, when a path exists. The recorder keeps an *export cursor*
//! (the last record known to have left the unit). [`crate::Recorder::export_pending`]
//! produces a [`Bundle`]: every record after the cursor, in raw canonical
//! frames, plus the chain identity and the cursor as anchor. The receiving
//! side ([`Receiver`]) verifies each bundle independently (hashes, signatures,
//! chain id, linkage to the previous bundle) and only then advances its own
//! state, so a gap, replay or substitution between bundles is detected.
//!
//! # Bundle wire format (`RBBXBND1`)
//!
//! `"RBBXBND1" | u32 id_len | identity JSON | u8 has_anchor |
//! [chain_id 32 | seq u64 | hash 32]? | u64 frames_len | frames`
//!
//! The identity JSON and anchor are *not* trusted on their own: the identity
//! is checked against the signed `chain_id` of every record, and the anchor is
//! checked against the first record's signed `prev_hash`.

use crate::crypto::{from_hex, hash_from_hex, to_hex};
use crate::record::{
    scan_frames, signing_message, ChainIdentity, Hash, Record, ScanItem, MAX_SIG_LEN,
};
use crate::sign::Verifier;
use crate::verify::{verify_segments, Finding, FindingKind, Report, SegmentData, VerifyOptions};
use serde::{Deserialize, Serialize};
use std::fmt;

/// A trusted chain position: "record `seq` of chain `chain_id` has `hash`".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    pub chain_id: Hash,
    pub seq: u64,
    pub hash: Hash,
}

#[derive(Serialize, Deserialize)]
struct AnchorJson {
    chain_id: String,
    seq: u64,
    hash: String,
}

impl Anchor {
    pub fn to_json(&self) -> String {
        serde_json::to_string(&AnchorJson {
            chain_id: to_hex(&self.chain_id),
            seq: self.seq,
            hash: to_hex(&self.hash),
        })
        .unwrap_or_default()
    }

    pub fn from_json(s: &str) -> Option<Self> {
        let j: AnchorJson = serde_json::from_str(s).ok()?;
        Some(Self {
            chain_id: hash_from_hex(&j.chain_id)?,
            seq: j.seq,
            hash: hash_from_hex(&j.hash)?,
        })
    }
}

/// A signed chain position, produced by every seal. Keep the latest one
/// somewhere the attacker cannot rewind (fleet side, TPM NV index) and pass it
/// to verification: deleting records after it is then detected.
///
/// The signature is the seal record's own signature over its hash. The `seq`
/// is not covered by the signature on its own; it is checked against the log
/// (the record hash commits to it), so a forged `seq` can only cause a false
/// alarm, never hide a truncation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub chain_id: Hash,
    pub seq: u64,
    pub hash: Hash,
    pub key_id: String,
    pub sig: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct CheckpointJson {
    chain_id: String,
    seq: u64,
    hash: String,
    key_id: String,
    sig: String,
}

impl Checkpoint {
    /// Signature check under `verifier`.
    pub fn verify(&self, verifier: &dyn Verifier) -> bool {
        verifier.verify(&signing_message(&self.hash), &self.sig)
    }

    pub fn anchor(&self) -> Anchor {
        Anchor {
            chain_id: self.chain_id,
            seq: self.seq,
            hash: self.hash,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(&CheckpointJson {
            chain_id: to_hex(&self.chain_id),
            seq: self.seq,
            hash: to_hex(&self.hash),
            key_id: self.key_id.clone(),
            sig: to_hex(&self.sig),
        })
        .unwrap_or_default()
    }

    pub fn from_json(s: &str) -> Option<Self> {
        let j: CheckpointJson = serde_json::from_str(s).ok()?;
        let sig = from_hex(&j.sig)?;
        if sig.len() > MAX_SIG_LEN {
            return None;
        }
        Some(Self {
            chain_id: hash_from_hex(&j.chain_id)?,
            seq: j.seq,
            hash: hash_from_hex(&j.hash)?,
            key_id: j.key_id,
            sig,
        })
    }
}

const BUNDLE_MAGIC: &[u8; 8] = b"RBBXBND1";
const MAX_IDENTITY_JSON: usize = 64 * 1024;

/// Why bundle bytes could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleError(pub String);

impl fmt::Display for BundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid bundle: {}", self.0)
    }
}

impl std::error::Error for BundleError {}

/// A verifiable export unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    pub identity: ChainIdentity,
    /// The record preceding the first one in this bundle (the exporter's
    /// cursor), or `None` for a bundle that starts at genesis.
    pub anchor: Option<Anchor>,
    /// Concatenated raw frames, exactly as stored.
    pub frames: Vec<u8>,
}

impl Bundle {
    pub fn to_bytes(&self) -> Vec<u8> {
        let id = serde_json::to_vec(&self.identity).unwrap_or_default();
        let mut out = Vec::with_capacity(8 + 4 + id.len() + 1 + 72 + 8 + self.frames.len());
        out.extend_from_slice(BUNDLE_MAGIC);
        out.extend_from_slice(&(id.len() as u32).to_be_bytes());
        out.extend_from_slice(&id);
        match &self.anchor {
            Some(a) => {
                out.push(1);
                out.extend_from_slice(&a.chain_id);
                out.extend_from_slice(&a.seq.to_be_bytes());
                out.extend_from_slice(&a.hash);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&(self.frames.len() as u64).to_be_bytes());
        out.extend_from_slice(&self.frames);
        out
    }

    /// Strict parse; never panics on hostile input.
    pub fn from_bytes(b: &[u8]) -> Result<Self, BundleError> {
        let err = |m: &str| BundleError(m.to_string());
        let mut p = 0usize;
        let mut take = |n: usize| -> Result<&[u8], BundleError> {
            let end = p
                .checked_add(n)
                .filter(|&e| e <= b.len())
                .ok_or_else(|| err("truncated"))?;
            let s = &b[p..end];
            p = end;
            Ok(s)
        };
        if take(8)? != BUNDLE_MAGIC {
            return Err(err("bad magic"));
        }
        let l = take(4)?;
        let id_len = u32::from_be_bytes([l[0], l[1], l[2], l[3]]) as usize;
        if id_len > MAX_IDENTITY_JSON {
            return Err(err("identity too large"));
        }
        let identity: ChainIdentity =
            serde_json::from_slice(take(id_len)?).map_err(|e| BundleError(e.to_string()))?;
        let anchor = match take(1)?[0] {
            0 => None,
            1 => {
                let mut chain_id = [0u8; 32];
                chain_id.copy_from_slice(take(32)?);
                let mut s = [0u8; 8];
                s.copy_from_slice(take(8)?);
                let mut hash = [0u8; 32];
                hash.copy_from_slice(take(32)?);
                Some(Anchor {
                    chain_id,
                    seq: u64::from_be_bytes(s),
                    hash,
                })
            }
            _ => return Err(err("bad anchor flag")),
        };
        let mut s = [0u8; 8];
        s.copy_from_slice(take(8)?);
        let frames_len = usize::try_from(u64::from_be_bytes(s)).map_err(|_| err("too large"))?;
        let frames = take(frames_len)?.to_vec();
        if p != b.len() {
            return Err(err("trailing bytes"));
        }
        Ok(Self {
            identity,
            anchor,
            frames,
        })
    }

    /// Decodable records, in order (no integrity checks).
    pub fn records(&self) -> Vec<Record> {
        scan_frames(&self.frames)
            .items
            .into_iter()
            .filter_map(|i| match i {
                ScanItem::Record(r) => Some(r.record),
                ScanItem::Malformed { .. } => None,
            })
            .collect()
    }

    /// `(seq, hash)` of the last decodable record.
    pub fn last(&self) -> Option<(u64, Hash)> {
        self.records().last().map(|r| (r.seq, r.hash))
    }

    /// Verify independently. `trusted` is the receiver's own last position for
    /// this chain; without it the bundle's own anchor is used and flagged as
    /// unverified (first contact).
    pub fn verify(
        &self,
        verifier: &dyn Verifier,
        trusted: Option<&Anchor>,
        expected_device_id: Option<&str>,
    ) -> Report {
        let chain = trusted
            .map(|a| a.chain_id)
            .unwrap_or_else(|| self.identity.chain_id());
        let opts = VerifyOptions {
            expected_chain_id: Some(chain),
            expected_device_id: expected_device_id.map(str::to_string),
            trusted_anchor: trusted.cloned().or_else(|| self.anchor.clone()),
            checkpoint: None,
        };
        let seg = SegmentData {
            name: "bundle".to_string(),
            bytes: self.frames.clone(),
        };
        let mut report = verify_segments(std::slice::from_ref(&seg), verifier, &opts);
        if trusted.is_none() {
            if let Some(a) = &self.anchor {
                report.push(Finding::new(
                    FindingKind::AnchorUnverified { anchor_seq: a.seq },
                    None,
                ));
            }
        }
        if self.identity.chain_id() == chain {
            if let Some(dev) = expected_device_id {
                if self.identity.device_id != dev
                    && !report
                        .findings
                        .iter()
                        .any(|f| matches!(f.kind, FindingKind::WrongDevice { .. }))
                {
                    report.push(Finding::new(
                        FindingKind::WrongDevice {
                            expected: dev.to_string(),
                            found: self.identity.device_id.clone(),
                        },
                        None,
                    ));
                }
            }
        }
        report
    }
}

/// Fleet-side (or diode-far-side) state for one device's chain.
#[derive(Debug, Clone, Default)]
pub struct Receiver {
    expected_device_id: Option<String>,
    state: Option<Anchor>,
}

impl Receiver {
    /// A receiver with no prior state; optionally pinned to a device id.
    pub fn new(expected_device_id: Option<String>) -> Self {
        Self {
            expected_device_id,
            state: None,
        }
    }

    /// Resume from a persisted position.
    pub fn with_state(expected_device_id: Option<String>, state: Anchor) -> Self {
        Self {
            expected_device_id,
            state: Some(state),
        }
    }

    /// Last accepted position.
    pub fn state(&self) -> Option<&Anchor> {
        self.state.as_ref()
    }

    /// Verify `bundle` against the current state; advance only if intact.
    pub fn accept(&mut self, bundle: &Bundle, verifier: &dyn Verifier) -> Report {
        let report = bundle.verify(
            verifier,
            self.state.as_ref(),
            self.expected_device_id.as_deref(),
        );
        if report.is_intact() {
            if let Some((seq, hash)) = bundle.last() {
                let newer = self.state.as_ref().is_none_or(|s| seq > s.seq);
                if newer {
                    self.state = Some(Anchor {
                        chain_id: self
                            .state
                            .as_ref()
                            .map(|s| s.chain_id)
                            .unwrap_or_else(|| bundle.identity.chain_id()),
                        seq,
                        hash,
                    });
                }
            }
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> ChainIdentity {
        ChainIdentity {
            device_id: "ugv-7".into(),
            boot_id: "boot".into(),
            key_id: "k".into(),
            algorithm: "hmac-sha256".into(),
            created_wall_ns: 9,
        }
    }

    #[test]
    fn bundle_bytes_round_trip() {
        for anchor in [
            None,
            Some(Anchor {
                chain_id: [1; 32],
                seq: 77,
                hash: [2; 32],
            }),
        ] {
            let b = Bundle {
                identity: id(),
                anchor,
                frames: vec![1, 2, 3, 4],
            };
            assert_eq!(Bundle::from_bytes(&b.to_bytes()).unwrap(), b);
        }
    }

    #[test]
    fn bundle_parse_rejects_hostile_bytes() {
        let b = Bundle {
            identity: id(),
            anchor: None,
            frames: vec![9; 10],
        }
        .to_bytes();
        for cut in 0..b.len() {
            assert!(Bundle::from_bytes(&b[..cut]).is_err());
        }
        let mut extra = b.clone();
        extra.push(0);
        assert!(Bundle::from_bytes(&extra).is_err());
        let mut flag = b.clone();
        let flag_pos = 8 + 4 + serde_json::to_vec(&id()).unwrap().len();
        flag[flag_pos] = 7;
        assert!(Bundle::from_bytes(&flag).is_err());
        let mut x = 0x1234_5678_9abc_def0u64;
        for len in 0..300 {
            let mut v = BUNDLE_MAGIC.to_vec();
            for _ in 0..len {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                v.push(x as u8);
            }
            let _ = Bundle::from_bytes(&v);
        }
    }

    #[test]
    fn anchor_and_checkpoint_json_round_trip() {
        let a = Anchor {
            chain_id: [3; 32],
            seq: 5,
            hash: [4; 32],
        };
        assert_eq!(Anchor::from_json(&a.to_json()).unwrap(), a);
        let c = Checkpoint {
            chain_id: [3; 32],
            seq: 5,
            hash: [4; 32],
            key_id: "k".into(),
            sig: vec![1, 2],
        };
        assert_eq!(Checkpoint::from_json(&c.to_json()).unwrap(), c);
        assert!(Checkpoint::from_json("{}").is_none());
        assert!(Anchor::from_json("not json").is_none());
    }
}
