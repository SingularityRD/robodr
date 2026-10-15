//! Closing the loop: does every finding's evidence link point at a real,
//! intact, signed black-box record?
//!
//! [`verify_blackbox`] runs the black box's own verifier over the directory
//! (hash chain, signatures, seals, checkpoint). [`resolve_links`] then looks
//! up each `robodr-blackbox://<robot>/<segment>/<seq>?sha256=<hash>` reference
//! (taken from the typed `ocsf.evidences[].data`, which the OCSF validator
//! keeps identical to `evidence_links`) and checks that the record exists in
//! that segment, that its stored hash equals the link's hash, that the hash
//! recomputes from the record's fields, and that its signature verifies.
//! Together: a finding's evidence is exactly what the signed chain holds.
//!
//! Limits: the HMAC key that verifies is also the key that signs (see the
//! `robodr-blackbox` README); a holder of the key can rewrite history. The
//! checkpoint passed to [`verify_blackbox`] should come from off the unit.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use robodr_blackbox::crypto::to_hex;
use robodr_blackbox::record::{scan_frames, signing_message, ScanItem};
use robodr_blackbox::store::parse_segment_file_name;
use robodr_blackbox::verify::{read_segments, verify_dir};
use robodr_blackbox::{Checkpoint, Record, Report, Verifier, VerifyOptions};
use robodr_ocsf::{BlackBoxRef, FindingEnvelope};
use serde::Serialize;

/// Run the black-box verifier over `dir`. `checkpoint` should be a trusted
/// copy (e.g. [`crate::Finished::checkpoint`] kept off-unit); `None` falls
/// back to the directory's own `checkpoint.json`.
pub fn verify_blackbox(
    dir: &Path,
    verifier: &dyn Verifier,
    checkpoint: Option<Checkpoint>,
    expected_device_id: Option<&str>,
) -> io::Result<Report> {
    let opts = VerifyOptions {
        checkpoint,
        expected_device_id: expected_device_id.map(str::to_string),
        ..VerifyOptions::default()
    };
    verify_dir(dir, verifier, &opts)
}

/// The black-box references a finding carries.
pub fn finding_refs(env: &FindingEnvelope) -> Vec<BlackBoxRef> {
    env.ocsf
        .evidences
        .iter()
        .map(|e| BlackBoxRef {
            segment: e.data.segment,
            seq: e.data.seq,
            sha256: e.data.sha256.clone(),
        })
        .collect()
}

/// Result of [`resolve_links`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct LinkReport {
    pub checked: usize,
    pub resolved: usize,
    /// One line per link that did not resolve, with the reason.
    pub problems: Vec<String>,
}

impl LinkReport {
    pub fn is_ok(&self) -> bool {
        self.problems.is_empty() && self.resolved == self.checked
    }
}

/// Resolve every reference against the records in `dir`. Malformed bytes
/// are skipped (the verifier reports them); a reference to a record that
/// cannot be decoded is reported as missing.
pub fn resolve_links(
    dir: &Path,
    verifier: &dyn Verifier,
    refs: &[BlackBoxRef],
) -> io::Result<LinkReport> {
    let mut index: BTreeMap<(u64, u64), Record> = BTreeMap::new();
    for seg in read_segments(dir)? {
        let Some(idx) = parse_segment_file_name(&seg.name) else {
            continue;
        };
        for item in scan_frames(&seg.bytes).items {
            if let ScanItem::Record(r) = item {
                index.entry((idx, r.record.seq)).or_insert(r.record);
            }
        }
    }
    let mut rep = LinkReport::default();
    for r in refs {
        rep.checked += 1;
        let at = format!("segment {} seq {}", r.segment, r.seq);
        let Some(rec) = index.get(&(r.segment, r.seq)) else {
            rep.problems.push(format!("{at}: no such record"));
            continue;
        };
        if to_hex(&rec.hash) != r.sha256 {
            rep.problems.push(format!(
                "{at}: link hash differs from the stored record hash"
            ));
        } else if rec.compute_hash() != rec.hash {
            rep.problems
                .push(format!("{at}: record contents do not match its hash"));
        } else if !verifier.verify(&signing_message(&rec.hash), &rec.sig) {
            rep.problems.push(format!("{at}: bad signature"));
        } else {
            rep.resolved += 1;
        }
    }
    Ok(rep)
}
