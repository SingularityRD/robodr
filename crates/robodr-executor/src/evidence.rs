//! The `record_evidence` adapter: a black-box **mark** (a signed, fsynced
//! note) that names the evidence **bundle** (the black-box references that
//! back the request: its own request note, the finding's records). It runs
//! inside agentd, which owns the black box; the executor process has no
//! access to it.
//!
//! precheck: well formed, not a replay (accepted in every safety state and
//! morphology, observe mode included: it sends nothing to the platform) ·
//! apply: append the mark (critical: fsynced before the reference is
//! returned) · verify: the sink confirms the reference names a durable
//! record of this robot's store · revert: not applicable (evidence is
//! never reverted) · TTL: none.

use serde_json::{json, Value};

use robodr_responder::ActionId;

use crate::decision::{codes, Refusal};
use crate::engine::{Outcome, Status};
use crate::order::Order;

/// Where marks go (agentd's black box).
pub trait EvidenceSink {
    /// Append a critical (fsynced) signed note; its evidence reference.
    fn mark(&mut self, note: &Value) -> Result<String, String>;
    /// The reference names a record the store holds.
    fn verify(&mut self, reference: &str) -> Result<(), String>;
}

/// Most references in one bundle.
pub const MAX_BUNDLE_REFS: usize = 64;

/// Run `record_evidence` for `order`, bundling `refs` (black-box
/// references, e.g. the control-plane request note). The checks are
/// [`crate::decision::precheck`]'s rules 1, 2 and 4 (well formed, not a
/// replay, the action is `record_evidence`); evidence capture is accepted in
/// every safety state and morphology, observe mode included.
pub fn record(order: &Order, refs: &[String], sink: &mut dyn EvidenceSink, now_ms: u64) -> Outcome {
    let mut out = Outcome {
        id: order.id.clone(),
        status: Status::Failed,
        action: Some(order.action),
        refusal: None,
        error: None,
        applied_ms: None,
        deadline_ms: None,
        duplicate: false,
        note: None,
        quarantine: None,
    };
    let refuse = |code: &'static str, why: String| Refusal::new(code, why);
    let check = if let Err(e) = order.validate() {
        Err(refuse(codes::INVALID_ORDER, e))
    } else if order.replay {
        Err(refuse(
            codes::REPLAY,
            "a replay never reaches the black box as a live mark".into(),
        ))
    } else if order.action != ActionId::RecordEvidence {
        Err(refuse(
            codes::INVALID_ORDER,
            "not a record_evidence order".into(),
        ))
    } else {
        Ok(())
    };
    if let Err(r) = check {
        out.status = Status::Refused;
        out.refusal = Some(r);
        return out;
    }
    let bundle: Vec<&String> = refs.iter().take(MAX_BUNDLE_REFS).collect();
    let note = json!({
        "kind": "robodr.evidence_mark",
        "order_id": order.id,
        "origin": order.origin,
        "safety_state": order.judged_state,
        "bundle": bundle,
        "bundle_truncated": refs.len() > MAX_BUNDLE_REFS,
        "at_ms": now_ms,
    });
    let uri = match sink.mark(&note) {
        Ok(u) => u,
        Err(e) => {
            out.error = Some(format!("black-box mark failed: {e}"));
            return out;
        }
    };
    if let Err(e) = sink.verify(&uri) {
        out.error = Some(format!("black-box mark did not verify: {e}"));
        return out;
    }
    out.status = Status::Verified;
    out.applied_ms = Some(now_ms);
    out.note = Some(format!("evidence mark {uri}"));
    out
}
