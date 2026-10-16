//! Operator sign-off evidence carried by a locked profile (the two-person
//! rule, enforced on the unit).
//!
//! `lock` refuses a draft until operators from the operators trust list
//! have signed its confirmed sign-off (`motion_quorum` distinct operators
//! when it has motion items). That check runs on the commissioning
//! workstation only; a profile signing key holder could otherwise hand-build
//! a locked profile, seal it and sign it (`robodr-commission sign`), and the
//! unit would never see that no operator signed anything. So `lock` embeds
//! the evidence in the locked profile's metadata
//! (`metadata.attestation`: the exact sign-off text and the exact text of its
//! `.sig` bundle, see [`attestation_for`]), and the loader verifies it
//! ([`verify_attestation`]) against the operators listed in the
//! root-signed trust file:
//!
//! 1. the sign-off parses strictly, has its shape, an intact item digest,
//!    a named operator, every item confirmed and is for this model;
//! 2. it is bound to **this** profile's content: its `profile_sha256` is
//!    the [`draft_digest`] of the profile with `locked = false` and no
//!    metadata (the canonical draft `lock` locked; a sign-off for any other
//!    content does not match);
//! 3. the floor recomputed from the content ([`required_items`]: every
//!    motion channel reviewed, every unbounded dimension confirmed) is met;
//! 4. every signature in the bundle is valid over the exact sign-off bytes
//!    under a key of the operators list (any invalid or unknown one
//!    refuses), at least one is, and the sign-off's `operator` is among the
//!    signers and equals `metadata.locked_by` (trimmed, as `lock` stamps it);
//! 5. with motion items, at least `motion_quorum` (of the trust file)
//!    distinct operators signed.
//!
//! # Limits
//!
//! * The binding is to the canonical serialisation of the content. A
//!   sign-off bound to the raw bytes of a hand-edited draft that is not in
//!   canonical form cannot be verified on the unit; `lock` refuses to
//!   produce such a profile (`signoff --in` binds to the canonical form).
//! * The evidence proves operators signed *this content*; it cannot prove
//!   they reviewed it carefully (see `signoff`'s limits).
//! * The operators list is as trustworthy as the trust file: with trust
//!   roots configured the trust file is root-signed (see the parent
//!   module); without roots, whoever can edit the trust file can list their
//!   own operator keys.

use super::ProfileTrustError;
use crate::signoff::{
    draft_digest, motion_items, required_items, satisfies, verify_signoff_signatures,
    OperatorTrust, Signoff, SignoffSignatures,
};
use robodr_events::profile::{Profile, ProfileAttestation};
use std::collections::BTreeSet;

/// What a verified attestation says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationSummary {
    /// The sign-off's operator (= `metadata.locked_by`).
    pub operator: String,
    /// Distinct operators with a valid signature.
    pub signers: BTreeSet<String>,
    /// Motion review items in the sign-off (the quorum applies when > 0).
    pub motion_items: usize,
    /// The quorum that was required (0 without motion items).
    pub quorum: usize,
}

/// The evidence `lock` embeds: the exact sign-off text and its signature
/// bundle's text.
pub fn attestation_for(signoff_text: &str, sigs: &SignoffSignatures) -> ProfileAttestation {
    ProfileAttestation {
        signoff: signoff_text.to_string(),
        signatures: sigs.to_text(),
    }
}

/// The digest a sign-off for `profile` must carry: [`draft_digest`] of the
/// profile as a draft (`locked = false`, no metadata).
pub fn content_digest(profile: &Profile) -> String {
    let mut d = profile.clone();
    d.locked = false;
    d.metadata = None;
    draft_digest(&d)
}

/// Verify the attestation of a (signature-verified) locked profile against
/// the operators list (see the module docs). The profile must carry
/// metadata; without an attestation it is [`ProfileTrustError::Unattested`].
pub fn verify_attestation(
    profile: &Profile,
    operators: &OperatorTrust,
) -> Result<AttestationSummary, ProfileTrustError> {
    let bad = |detail: String| ProfileTrustError::BadAttestation { detail };
    let Some(meta) = profile.metadata.as_ref() else {
        return Err(ProfileTrustError::LegacyUnversioned);
    };
    let Some(att) = meta.attestation.as_ref() else {
        return Err(ProfileTrustError::Unattested);
    };
    crate::profile_file::reject_duplicate_keys(&att.signoff)
        .map_err(|e| bad(format!("sign-off: {e}")))?;
    let so: Signoff =
        serde_json::from_str(&att.signoff).map_err(|e| bad(format!("sign-off: {e}")))?;
    so.check_shape()
        .map_err(|e| bad(format!("sign-off: {e}")))?;
    if !so.items_intact() {
        return Err(bad(
            "sign-off items were deleted, added or reworded (items_sha256 differs)".into(),
        ));
    }
    let operator = so.operator.trim();
    if operator.is_empty() {
        return Err(bad("the sign-off names no operator".into()));
    }
    if let Some(i) = so.unconfirmed().next() {
        return Err(bad(format!("sign-off item {:?} is not confirmed", i.id)));
    }
    if so.model != profile.model {
        return Err(bad(format!(
            "the sign-off is for model {:?}, the profile is {:?}",
            so.model, profile.model
        )));
    }
    let want = content_digest(profile);
    if so.profile_sha256 != want {
        return Err(bad(format!(
            "the sign-off is for draft {}, this profile's content is {want} (a sign-off for \
             other content)",
            so.profile_sha256
        )));
    }
    for req in required_items(profile) {
        if !so.items.iter().any(|i| satisfies(i, &req)) {
            return Err(bad(format!(
                "required item missing for {}: {}",
                req.subject, req.why
            )));
        }
    }
    let sigs =
        SignoffSignatures::parse(&att.signatures).map_err(|e| bad(format!("signatures: {e}")))?;
    let v = verify_signoff_signatures(att.signoff.as_bytes(), &sigs, operators);
    if let Some(p) = v.problems.first() {
        return Err(bad(format!("operator signature: {p}")));
    }
    if v.signers.is_empty() {
        return Err(bad("no operator signature".into()));
    }
    if !v.signers.contains_key(operator) {
        return Err(bad(format!(
            "the sign-off's operator {operator:?} did not sign it (signers: {:?})",
            v.signers.keys().collect::<Vec<_>>()
        )));
    }
    if meta.locked_by.trim() != operator {
        return Err(bad(format!(
            "locked_by {:?} is not the sign-off's operator {operator:?}",
            meta.locked_by
        )));
    }
    let motion = motion_items(&so).count();
    let quorum = if motion > 0 {
        operators.motion_quorum().max(1)
    } else {
        0
    };
    if v.signers.len() < quorum {
        return Err(ProfileTrustError::AttestationQuorumNotMet {
            have: v.signers.len(),
            need: quorum,
        });
    }
    Ok(AttestationSummary {
        operator: operator.to_string(),
        signers: v.signers.into_keys().collect(),
        motion_items: motion,
        quorum,
    })
}
