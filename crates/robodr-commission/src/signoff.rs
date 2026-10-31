//! Operator sign-off: the confirmation list a human must work through
//! before a draft profile can be locked.
//!
//! # Why
//!
//! Commissioning learns "whatever was on the bus" as normal. An attacker (or
//! a forgotten laptop running `ros2 topic pub`) present during the clean run
//! would be baked into the allowlist. The learner already refuses to learn
//! what it cannot justify (see `learner`: quarantined participants, caps,
//! unattributed samples), but some things it must learn and a human must
//! still look at: who is allowed to command motion, participants that
//! appeared late or only briefly, participants seen from several IPs, thin
//! motion statistics, capacity overflow during the run.
//!
//! # How
//!
//! `learn` writes, next to the draft profile, a [`Signoff`] file listing
//! those items, each `"confirmed": false`, bound to the exact draft bytes by
//! SHA-256 (`profile_sha256`). The operator reviews each item, sets
//! `"confirmed": true` and fills `"operator"`. [`crate::ops::lock`] refuses
//! unless the sign-off belongs to this draft (same model, same digest),
//! names an operator and confirms every item.
//!
//! # The item set is bound too
//!
//! Confirming every item is meaningless if items can simply be deleted.
//! Two independent checks stop that at lock:
//!
//! * `items_sha256` is the SHA-256 of the draft digest plus every item's id
//!   and reason ([`items_digest`]), computed when the list is generated.
//!   `lock` recomputes it from the items present: a deleted, added or
//!   reworded item is refused (`SignoffItemsTampered`). Only `confirmed` and
//!   `operator` are outside the digest; they are what the operator edits.
//! * A floor recomputed from the draft alone ([`required_items`]): every
//!   motion channel of the draft must be covered by a confirmed item that
//!   names it (`motion_writer`, `motion_unattributed` or
//!   `motion_channel_unreviewed`), whatever the list says.
//!
//! The list binds the draft by `profile_sha256`: the SHA-256 of the draft
//! bytes `learn` wrote, which is its canonical serialisation
//! ([`draft_digest`]); `lock` also accepts the digest of the draft's exact
//! bytes. [`Signoff::for_profile`] (`signoff --in`) binds the canonical
//! form, which is what the unit re-checks when it verifies the attestation.
//!
//! A draft edited by hand or produced by `merge` no longer matches its
//! learned sign-off. [`Signoff::for_profile`] then builds a conservative
//! list from the profile alone (every participant and every motion channel
//! must be confirmed), because the learner's provenance is gone.
//!
//! # Operator signatures (who confirmed it)
//!
//! `items_sha256` and `profile_sha256` are plain hashes: anyone who can
//! write the files can recompute them after deleting an item or flipping
//! `"confirmed"`. What makes the confirmation an authenticated decision is
//! the operator's **Ed25519 signature** over the exact bytes of the
//! confirmed sign-off file ([`SignoffSignatures`], `<signoff>.sig`):
//!
//! * The operator reviews and confirms the list, then runs
//!   `robodr-commission signoff --signoff S --sign-key OP.key`. The tool
//!   refuses to sign a list that is not fully confirmed, names no operator,
//!   has a broken item digest or (with `--in`) belongs to another draft. The
//!   signature covers [`SIGNOFF_SIG_DOMAIN`] followed by the file bytes, so
//!   one changed byte voids it; every later signer signs the same bytes.
//! * Operator keys are robodr-blackbox key files (`robodr-blackbox-key/v2`,
//!   Ed25519, secret file mode 0600; `robodr-commission keygen` or
//!   `robodr-blackbox keygen`). Their public halves are listed, each bound
//!   to an operator name, in an **operators trust list**
//!   ([`OperatorTrust`], `robodr-operators/v1`, built by
//!   `robodr-commission operators`). The list is refused when it is a
//!   symlink or writable by group/others, lists a key id or a public key
//!   twice, or asks for a quorum it cannot meet.
//! * `lock --operators operators.json` verifies every signature in
//!   `<signoff>.sig` ([`verify_signoff_signatures`]): any malformed, unknown
//!   or invalid signature refuses the lock (fail closed), at least one
//!   valid signature is required, the sign-off's `operator` must be the
//!   name bound to one of the valid signers (so `locked_by` in the locked
//!   profile is an authenticated identity), and if the list has motion
//!   items ([`MOTION_REVIEW_KINDS`]) at least `motion_quorum` **distinct
//!   operators** (names, not keys) must have signed: the two-person rule
//!   (`motion_quorum` in the trust list, raised per lock with
//!   `--motion-quorum`).
//! * The unit enforces the same rule: `lock` embeds the exact sign-off and
//!   its signature bundle in the locked profile (`metadata.attestation`),
//!   and the loaders verify it against the operators list carried in the
//!   (root-signed) profile trust file (`crate::trust::attestation`), so a
//!   profile signing key alone cannot produce an enforceable profile.
//!
//! # The floor: what the draft itself requires
//!
//! The learner's item list rests on evidence (the run) that `lock` cannot
//! see again. What it can recompute from the draft bytes, which the list is
//! bound to by `profile_sha256`, it does ([`required_items`]): every motion
//! channel needs a confirmed motion review item and every motion dimension
//! left `null` (unlimited) needs a confirmed `envelope_dimension_unbounded`
//! item, whatever the list says. A recomputed (forged) list therefore can
//! drop learner findings (late participants, outliers) but never the motion
//! review, and it still needs an authorised operator's signature over the
//! list it ends up with.
//!
//! # Trust model and limits
//!
//! * Trusted: the operators trust list (installed by the OEM's security
//!   officer, as integrity-protected as the profile trust file), the
//!   operators' secret keys, and the commissioning workstation while
//!   `learn` runs (the learner is not a separate signing identity: a learner
//!   key on the same workstation would add no assurance over the operator
//!   signature that follows it).
//! * Not trusted: anyone with write access to the draft, the sign-off or the
//!   `.sig` file. They can delete items and recompute the digests, but the
//!   result has no valid operator signature, or (if an operator signs it)
//!   the operator signed exactly the list they were shown.
//! * Limits: a careless or colluding operator (or, with a quorum, colluding
//!   operators) can still confirm anything; the signature makes that a
//!   named, non-repudiable decision, not a correct one. Ed25519 is
//!   robodr-blackbox's wrapper over the audited `ed25519-dalek` crate. No
//!   key expiry or revocation list: revoke by removing the key
//!   from the trust list.

use crate::to_json;
use robodr_blackbox::crypto::{from_hex, sha256, to_hex};
use robodr_blackbox::sign_ed25519::{ED25519, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use robodr_blackbox::{Ed25519VerifyingKey, Signer, Verifier};
use robodr_events::profile::Profile;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// Value of [`Signoff::format`].
pub const SIGNOFF_FORMAT: &str = "robodr-commission-signoff/1";

/// One item a human must confirm.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignoffItem {
    /// Stable id, `<kind>:<subject>`; unique within a sign-off.
    pub id: String,
    /// e.g. `motion_writer`, `participant_late`.
    pub kind: String,
    pub subject: String,
    /// Why a human must look at it.
    pub reason: String,
    /// Set to `true` by the operator after review.
    pub confirmed: bool,
}

impl SignoffItem {
    pub fn new(kind: &str, subject: &str, reason: impl Into<String>) -> Self {
        Self {
            id: format!("{kind}:{subject}"),
            kind: kind.into(),
            subject: subject.into(),
            reason: reason.into(),
            confirmed: false,
        }
    }
}

/// The confirmation list for one draft profile. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signoff {
    /// Always [`SIGNOFF_FORMAT`].
    pub format: String,
    pub model: String,
    /// Lower-case hex SHA-256 of the draft profile file bytes
    /// ([`draft_digest`]).
    pub profile_sha256: String,
    /// [`items_digest`] of `profile_sha256` and the items as generated:
    /// binds the item set (see the module docs).
    pub items_sha256: String,
    /// Who reviewed it; must be non-empty to lock.
    pub operator: String,
    /// Sorted by id, ids unique.
    pub items: Vec<SignoffItem>,
}

/// SHA-256 (hex) of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    to_hex(&sha256(bytes))
}

/// Digest of the item set: SHA-256 over a domain tag, `profile_sha256` and
/// every item's `(id, reason)`, sorted by id (so reordering the file does
/// not matter, but deleting, adding or rewording an item does).
pub fn items_digest(profile_sha256: &str, items: &[SignoffItem]) -> String {
    let mut by_id: Vec<(&str, &str)> = items
        .iter()
        .map(|i| (i.id.as_str(), i.reason.as_str()))
        .collect();
    by_id.sort_unstable();
    // JSON encoding keeps the framing unambiguous whatever the strings hold.
    let body = serde_json::to_string(&("robodr-commission-signoff-items/1", profile_sha256, by_id))
        .unwrap_or_default();
    sha256_hex(body.as_bytes())
}

/// Item kinds that count as a review of a motion channel for the floor
/// ([`required_items`]).
pub const MOTION_REVIEW_KINDS: [&str; 3] = [
    "motion_writer",
    "motion_unattributed",
    "motion_channel_unreviewed",
];

/// Kind of the item that confirms one `participant_identities` entry
/// ([`required_items`]: every identity needs one).
pub const IDENTITY_KIND: &str = "participant_identity";

/// The sign-off item for identity `name`. Its reason spells the matcher
/// out, so the item digest binds what the operator confirmed.
pub fn identity_item(name: &str, id: &robodr_events::profile::ParticipantIdentity) -> SignoffItem {
    let list = |s: &BTreeSet<String>| s.iter().cloned().collect::<Vec<_>>().join(", ");
    SignoffItem::new(
        IDENTITY_KIND,
        name,
        format!(
            "after a restart, any participant announcing from [{}] with RTPS vendor {}{} is \
             accepted as '{name}' (nodes: [{}]), up to {} at a time, with every right its \
             learned participants had (motion topics included): confirm these addresses and \
             nodes belong to the robot",
            list(&id.ips),
            id.vendor,
            id.enclave
                .as_deref()
                .map(|e| format!(" and enclave {e}"))
                .unwrap_or_default(),
            list(&id.nodes),
            id.max_instances
        ),
    )
}

/// Kind of the item that must confirm a `null` (unlimited) motion
/// dimension ([`required_items`]).
pub const UNBOUNDED_DIMENSION_KIND: &str = "envelope_dimension_unbounded";

/// Kind of the item that confirms one [`Profile::bound_config`] entry
/// (a response policy, Motion Firewall envelope or executor motion section
/// bound into the profile by `bind`). Its subject is `"<role> <digest>"`,
/// so the operators sign the exact file they reviewed. It counts as a
/// motion item: the two-person rule (`motion_quorum`) applies, because
/// these files decide whether motion may be acted on (`oem_validated`) and
/// how commands are bounded.
pub const BOUND_CONFIG_KIND: &str = "bound_config";

/// The sign-off subject of the binding `role` -> `digest`.
pub fn bound_config_subject(role: &str, digest: &str) -> String {
    format!("{role} {digest}")
}

/// The sign-off item for the binding `role` -> `digest`; `summary` (what
/// the file says, e.g. `oem_validated: true, morphology: quadruped`) goes
/// into the reason, which the item digest binds.
pub fn bound_config_item(role: &str, digest: &str, summary: &str) -> SignoffItem {
    SignoffItem::new(
        BOUND_CONFIG_KIND,
        &bound_config_subject(role, digest),
        format!(
            "{role} file {digest} is bound into this profile: once locked and signed, the unit \
             honours it (and only it) for {}. Review its content ({summary}) and confirm it is \
             the OEM-validated file for this robot",
            match role {
                "response_policy" => "oem_validated, morphology and the safe behaviour",
                "executor_motion" => "the executor's motion adapters and their oem_validated flags",
                _ => "the Motion Firewall envelope and its allowed sources",
            }
        ),
    )
}

/// One entry of the floor recomputed from a draft ([`required_items`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    /// A motion channel, or `"<channel> <dimension>"`.
    pub subject: String,
    /// Item kinds that satisfy it.
    pub kinds: &'static [&'static str],
    /// `true`: the item's subject must equal `subject`; `false`: it may
    /// also extend it (`"<subject> <rest>"`, e.g. `motion_writer` items
    /// name the channel and the writer).
    pub exact: bool,
    pub why: String,
}

/// What every sign-off for `profile` must contain, confirmed, whatever list
/// was generated (the floor `lock` recomputes from the draft bytes):
/// * per participant identity `name`: an [`IDENTITY_KIND`] item for `name`;
/// * per motion channel `ch`: an item whose kind is in
///   [`MOTION_REVIEW_KINDS`] and whose subject is `ch` or starts with
///   `"<ch> "`;
/// * per motion dimension left `null` (unlimited) on a channel that bounds
///   the other one: an [`UNBOUNDED_DIMENSION_KIND`] item for
///   `"<ch> <dimension>"`. (A channel bounding neither is refused by
///   `lock` outright.)
/// * per [`Profile::bound_config`] entry: a [`BOUND_CONFIG_KIND`] item for
///   `"<role> <digest>"`.
pub fn required_items(profile: &Profile) -> Vec<Requirement> {
    let mut out = Vec::new();
    for (role, digest) in &profile.bound_config {
        out.push(Requirement {
            subject: bound_config_subject(role, digest),
            kinds: &[BOUND_CONFIG_KIND],
            exact: true,
            why: format!(
                "{role} {digest} is bound into the draft, so a confirmed {BOUND_CONFIG_KIND} item \
                 for exactly that file is required"
            ),
        });
    }
    for name in profile.participant_identities.keys() {
        out.push(Requirement {
            subject: name.clone(),
            kinds: &[IDENTITY_KIND],
            exact: true,
            why: format!(
                "participant identity {name} is in the draft, so a confirmed {IDENTITY_KIND} \
                 item for it is required"
            ),
        });
    }
    for (ch, env) in &profile.motion_envelopes {
        out.push(Requirement {
            subject: ch.clone(),
            kinds: &MOTION_REVIEW_KINDS,
            exact: false,
            why: format!(
                "motion channel {ch} is in the draft, so a confirmed review of who may command \
                 it ({}) is required",
                MOTION_REVIEW_KINDS.join(" / ")
            ),
        });
        let dims = [
            ("linear", env.max_linear_speed),
            ("joint", env.max_joint_speed),
        ];
        if dims.iter().any(|(_, b)| b.is_some()) {
            for (dim, b) in dims {
                if b.is_none() {
                    out.push(Requirement {
                        subject: format!("{ch} {dim}"),
                        kinds: &[UNBOUNDED_DIMENSION_KIND],
                        exact: true,
                        why: format!(
                            "{ch} has no {dim} bound (null = unlimited), so a confirmed \
                             {UNBOUNDED_DIMENSION_KIND} item for it is required"
                        ),
                    });
                }
            }
        }
    }
    out
}

/// Does `item` (confirmed) satisfy `req`?
pub fn satisfies(item: &SignoffItem, req: &Requirement) -> bool {
    item.confirmed
        && req.kinds.contains(&item.kind.as_str())
        && (item.subject == req.subject
            || (!req.exact
                && item
                    .subject
                    .strip_prefix(req.subject.as_str())
                    .is_some_and(|rest| rest.starts_with(' '))))
}

/// Does `item` (confirmed) satisfy the floor requirement for `channel`?
pub fn covers(item: &SignoffItem, channel: &str) -> bool {
    item.confirmed
        && MOTION_REVIEW_KINDS.contains(&item.kind.as_str())
        && (item.subject == channel
            || item
                .subject
                .strip_prefix(channel)
                .is_some_and(|rest| rest.starts_with(' ')))
}

/// Digest that binds a sign-off to a draft: SHA-256 of the exact bytes the
/// draft is written as ([`crate::to_json`]).
pub fn draft_digest(profile: &Profile) -> String {
    // Serialising a Profile cannot fail (no maps with non-string keys, and
    // serde_json writes non-finite floats as null).
    sha256_hex(to_json(profile).unwrap_or_default().as_bytes())
}

impl Signoff {
    /// A sign-off for `profile` with the given items (deduplicated by id,
    /// sorted, all unconfirmed).
    pub fn new(profile: &Profile, items: impl IntoIterator<Item = SignoffItem>) -> Self {
        let mut by_id: BTreeMap<String, SignoffItem> = BTreeMap::new();
        for it in items {
            by_id.entry(it.id.clone()).or_insert(it);
        }
        let mut s = Self {
            format: SIGNOFF_FORMAT.into(),
            model: profile.model.clone(),
            profile_sha256: String::new(),
            items_sha256: String::new(),
            operator: String::new(),
            items: by_id.into_values().collect(),
        };
        s.rebind(draft_digest(profile));
        s
    }

    /// Bind the list to other draft bytes (e.g. a hand-edited file whose
    /// bytes differ from the canonical form) and re-seal the item set.
    pub fn rebind(&mut self, profile_sha256: String) {
        self.profile_sha256 = profile_sha256;
        self.items_sha256 = items_digest(&self.profile_sha256, &self.items);
    }

    /// Does `items_sha256` match the items present?
    pub fn items_intact(&self) -> bool {
        self.items_sha256 == items_digest(&self.profile_sha256, &self.items)
    }

    /// Conservative sign-off built from a profile alone (hand-edited or
    /// merged drafts): every participant and every motion channel must be
    /// confirmed individually.
    pub fn for_profile(profile: &Profile) -> Self {
        let mut items = Vec::new();
        for g in &profile.participants {
            items.push(SignoffItem::new(
                "participant_unreviewed",
                g,
                "provenance unknown (edited or merged draft): confirm this participant belongs \
                 on the robot",
            ));
        }
        for (name, id) in &profile.participant_identities {
            items.push(identity_item(name, id));
        }
        for (role, digest) in &profile.bound_config {
            items.push(bound_config_item(
                role,
                digest,
                "provenance unknown (edited or merged draft): open the file and check it",
            ));
        }
        for (ch, env) in &profile.motion_envelopes {
            items.push(SignoffItem::new(
                "motion_channel_unreviewed",
                ch,
                "provenance unknown (edited or merged draft): confirm this motion channel, its \
                 envelope and every participant allowed to write it",
            ));
            for (dim, b) in [
                ("linear", env.max_linear_speed),
                ("joint", env.max_joint_speed),
            ] {
                if b.is_none() {
                    items.push(SignoffItem::new(
                        UNBOUNDED_DIMENSION_KIND,
                        &format!("{ch} {dim}"),
                        format!(
                            "{ch} has no {dim} bound (null = unlimited): confirm that {dim} \
                             commands on it must not be limited, or set a bound"
                        ),
                    ));
                }
            }
        }
        Self::new(profile, items)
    }

    /// Items not yet confirmed.
    pub fn unconfirmed(&self) -> impl Iterator<Item = &SignoffItem> {
        self.items.iter().filter(|i| !i.confirmed)
    }

    /// Mark everything confirmed by `operator`. For tests and for callers
    /// that collected the confirmations through their own UI; the CLI never
    /// does this on its own.
    pub fn confirm_all(mut self, operator: &str) -> Self {
        self.operator = operator.into();
        for i in &mut self.items {
            i.confirmed = true;
        }
        self
    }

    /// Structural problems (format, duplicate ids). Content checks against a
    /// profile are in [`crate::ops::lock`].
    pub fn check_shape(&self) -> Result<(), String> {
        if self.format != SIGNOFF_FORMAT {
            return Err(format!(
                "sign-off format {:?} is not {SIGNOFF_FORMAT:?}",
                self.format
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for i in &self.items {
            if !seen.insert(i.id.as_str()) {
                return Err(format!("sign-off item id {:?} appears twice", i.id));
            }
            if i.id != format!("{}:{}", i.kind, i.subject) {
                return Err(format!(
                    "sign-off item id {:?} does not match its kind/subject",
                    i.id
                ));
            }
        }
        for (name, v) in [
            ("profile_sha256", &self.profile_sha256),
            ("items_sha256", &self.items_sha256),
        ] {
            if v.len() != 64 || !v.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                return Err(format!("sign-off {name} is not 64 lower-case hex chars"));
            }
        }
        Ok(())
    }
}

impl fmt::Display for Signoff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Operator sign-off required ({} item(s), {} unconfirmed):",
            self.items.len(),
            self.unconfirmed().count()
        )?;
        for i in &self.items {
            writeln!(
                f,
                "  [{}] {}: {}",
                if i.confirmed { "x" } else { " " },
                i.id,
                i.reason
            )?;
        }
        Ok(())
    }
}

// ------------------------------------------------- operator signatures --

/// Domain separation prefix of a sign-off signature.
pub const SIGNOFF_SIG_DOMAIN: &[u8] = b"robodr-signoff-sig/v1\0";
/// Value of [`SignoffSignatures::format`].
pub const SIGNOFF_SIGS_FORMAT: &str = "robodr-signoff-sigs/v1";
/// Value of the operators trust list's `format`.
pub const OPERATORS_FORMAT: &str = "robodr-operators/v1";
/// Max keys in an operators trust list.
pub const MAX_OPERATOR_KEYS: usize = 64;
/// Max signatures on one sign-off.
pub const MAX_SIGNOFF_SIGNATURES: usize = 64;
/// Max size of an operators trust list or a signature file.
pub const MAX_OPERATORS_BYTES: u64 = 256 * 1024;

/// The signature file of a sign-off: the file name with `.sig` appended.
pub fn signoff_sig_path(signoff: &Path) -> PathBuf {
    let mut s = signoff.as_os_str().to_os_string();
    s.push(".sig");
    PathBuf::from(s)
}

/// The message an operator signs: [`SIGNOFF_SIG_DOMAIN`] followed by the
/// exact bytes of the confirmed sign-off file.
pub fn signoff_signed_message(signoff_bytes: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIGNOFF_SIG_DOMAIN.len() + signoff_bytes.len());
    m.extend_from_slice(SIGNOFF_SIG_DOMAIN);
    m.extend_from_slice(signoff_bytes);
    m
}

/// `sha256:<hex>` of the sign-off bytes (diagnostics and binding of the
/// signature file to one exact version of the list).
pub fn signoff_file_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

/// One operator's signature over a sign-off.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorSignature {
    pub algorithm: String,
    pub key_id: String,
    pub signature_hex: String,
}

/// The signature file of a sign-off (`<signoff>.sig`,
/// `robodr-signoff-sigs/v1`): every operator who signed these exact bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignoffSignatures {
    pub format: String,
    /// [`signoff_file_digest`] of the signed bytes.
    pub signoff_digest: String,
    pub signatures: Vec<OperatorSignature>,
}

impl SignoffSignatures {
    /// An empty signature set for these sign-off bytes.
    pub fn new(signoff_bytes: &[u8]) -> Self {
        Self {
            format: SIGNOFF_SIGS_FORMAT.into(),
            signoff_digest: signoff_file_digest(signoff_bytes),
            signatures: Vec::new(),
        }
    }

    /// Add `signer`'s signature over `signoff_bytes`. Refuses bytes other
    /// than the ones the set is for, a non-Ed25519 signer, a key that
    /// already signed and more than [`MAX_SIGNOFF_SIGNATURES`] signatures.
    pub fn add(&mut self, signoff_bytes: &[u8], signer: &dyn Signer) -> Result<(), String> {
        if self.signoff_digest != signoff_file_digest(signoff_bytes) {
            return Err(format!(
                "the existing signatures are for sign-off {}, this file is {}: the list changed \
                 after it was signed, so those signatures are void",
                self.signoff_digest,
                signoff_file_digest(signoff_bytes)
            ));
        }
        if signer.algorithm() != ED25519 {
            return Err(format!(
                "key algorithm {:?} cannot sign a sign-off (need {ED25519:?})",
                signer.algorithm()
            ));
        }
        if self.signatures.iter().any(|s| s.key_id == signer.key_id()) {
            return Err(format!(
                "key {:?} has already signed this sign-off",
                signer.key_id()
            ));
        }
        if self.signatures.len() >= MAX_SIGNOFF_SIGNATURES {
            return Err(format!("more than {MAX_SIGNOFF_SIGNATURES} signatures"));
        }
        let sig = signer
            .sign(&signoff_signed_message(signoff_bytes))
            .map_err(|e| e.to_string())?;
        self.signatures.push(OperatorSignature {
            algorithm: signer.algorithm().into(),
            key_id: signer.key_id().into(),
            signature_hex: to_hex(&sig),
        });
        Ok(())
    }

    /// Parse a signature file (strict: unknown or duplicate keys refused,
    /// format and digest shape checked, at most
    /// [`MAX_SIGNOFF_SIGNATURES`] entries). Signatures themselves are
    /// checked by [`verify_signoff_signatures`].
    pub fn parse(text: &str) -> Result<Self, String> {
        crate::profile_file::reject_duplicate_keys(text).map_err(|e| e.to_string())?;
        let s: Self = serde_json::from_str(text).map_err(|e| e.to_string())?;
        if s.format != SIGNOFF_SIGS_FORMAT {
            return Err(format!(
                "format {:?}, expected {SIGNOFF_SIGS_FORMAT:?}",
                s.format
            ));
        }
        if !s
            .signoff_digest
            .strip_prefix("sha256:")
            .is_some_and(is_hex64)
        {
            return Err("signoff_digest is not sha256:<64 hex>".into());
        }
        if s.signatures.len() > MAX_SIGNOFF_SIGNATURES {
            return Err(format!("more than {MAX_SIGNOFF_SIGNATURES} signatures"));
        }
        Ok(s)
    }

    /// The file text (pretty JSON, trailing newline).
    pub fn to_text(&self) -> String {
        to_json(self).unwrap_or_default()
    }
}

fn is_hex64(v: &str) -> bool {
    v.len() == 64 && v.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// One entry of an operators list as stored in JSON (the operators trust
/// list, and the `operators` member of a profile trust file).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorKeyJson {
    pub operator: String,
    pub algorithm: String,
    pub key_id: String,
    pub public_hex: String,
}

fn one() -> usize {
    1
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorsJson {
    format: String,
    /// Distinct operators who must sign a sign-off with motion items.
    #[serde(default = "one")]
    motion_quorum: usize,
    operators: Vec<OperatorKeyJson>,
}

/// The operators trust list (`robodr-operators/v1`): which Ed25519 keys may
/// sign a sign-off, the operator name each is bound to, and the two-person
/// rule for motion items (`motion_quorum`, default 1). See the module docs.
#[derive(Debug, Clone)]
pub struct OperatorTrust {
    keys: BTreeMap<String, (String, Ed25519VerifyingKey)>,
    motion_quorum: usize,
}

impl OperatorTrust {
    /// Build a trust list from `(operator, key)` pairs. Refuses an empty
    /// list, more than [`MAX_OPERATOR_KEYS`] keys, an empty or padded
    /// operator name, a key id or a public key listed twice, and a quorum
    /// of 0 or above the number of distinct operators.
    pub fn new(
        entries: Vec<(String, Ed25519VerifyingKey)>,
        motion_quorum: usize,
    ) -> Result<Self, String> {
        if entries.is_empty() {
            return Err("no operators".into());
        }
        if entries.len() > MAX_OPERATOR_KEYS {
            return Err(format!("more than {MAX_OPERATOR_KEYS} operator keys"));
        }
        let mut keys = BTreeMap::new();
        let mut publics = BTreeSet::new();
        for (op, vk) in entries {
            if op.trim().is_empty() || op.trim() != op || op.chars().any(char::is_control) {
                return Err(format!(
                    "operator name {op:?} must be non-empty, without surrounding spaces or \
                     control characters"
                ));
            }
            let id = Verifier::key_id(&vk).to_string();
            if !publics.insert(*vk.as_bytes()) {
                return Err(format!(
                    "key {id:?}: the same public key is listed twice (one person would count \
                     as two operators)"
                ));
            }
            if keys.insert(id.clone(), (op, vk)).is_some() {
                return Err(format!("key id {id:?} listed twice"));
            }
        }
        let t = Self {
            keys,
            motion_quorum,
        };
        let distinct = t.operators().len();
        if motion_quorum == 0 || motion_quorum > distinct {
            return Err(format!(
                "motion_quorum {motion_quorum} must be between 1 and the number of distinct \
                 operators ({distinct})"
            ));
        }
        Ok(t)
    }

    /// Parse a trust list's text (strict JSON, see [`OperatorTrust::new`];
    /// keys must be valid Ed25519 public keys).
    pub fn parse(text: &str) -> Result<Self, String> {
        crate::profile_file::reject_duplicate_keys(text).map_err(|e| e.to_string())?;
        let j: OperatorsJson = serde_json::from_str(text).map_err(|e| e.to_string())?;
        if j.format != OPERATORS_FORMAT {
            return Err(format!(
                "format {:?}, expected {OPERATORS_FORMAT:?}",
                j.format
            ));
        }
        Self::from_entries(j.operators, j.motion_quorum)
    }

    /// Build a trust list from its JSON entries (see [`OperatorTrust::new`];
    /// keys must be valid Ed25519 public keys).
    pub fn from_entries(
        entries: Vec<OperatorKeyJson>,
        motion_quorum: usize,
    ) -> Result<Self, String> {
        if entries.len() > MAX_OPERATOR_KEYS {
            return Err(format!("more than {MAX_OPERATOR_KEYS} operator keys"));
        }
        let mut out = Vec::with_capacity(entries.len());
        for k in entries {
            if k.algorithm != ED25519 {
                return Err(format!(
                    "key {:?}: algorithm {:?} is not supported (only {ED25519:?})",
                    k.key_id, k.algorithm
                ));
            }
            let public: [u8; PUBLIC_KEY_LEN] = from_hex(&k.public_hex)
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| {
                    format!(
                        "key {:?}: public_hex is not {PUBLIC_KEY_LEN} bytes of hex",
                        k.key_id
                    )
                })?;
            let vk = Ed25519VerifyingKey::from_bytes(k.key_id.clone(), &public)
                .map_err(|e| format!("key {:?}: {e}", k.key_id))?;
            out.push((k.operator, vk));
        }
        Self::new(out, motion_quorum)
    }

    /// The JSON entries of this list (sorted by key id).
    pub fn entries(&self) -> Vec<OperatorKeyJson> {
        self.keys
            .iter()
            .map(|(id, (op, vk))| OperatorKeyJson {
                operator: op.clone(),
                algorithm: ED25519.into(),
                key_id: id.clone(),
                public_hex: to_hex(vk.as_bytes()),
            })
            .collect()
    }

    /// Every operator public key.
    pub fn public_keys(&self) -> impl Iterator<Item = &Ed25519VerifyingKey> {
        self.keys.values().map(|(_, vk)| vk)
    }

    /// Read a trust list: not a symlink, a regular file, not writable by
    /// group or others, at most [`MAX_OPERATORS_BYTES`]; then
    /// [`OperatorTrust::parse`].
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = read_protected(path, MAX_OPERATORS_BYTES)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// The trust list's file text.
    pub fn to_text(&self) -> String {
        let j = OperatorsJson {
            format: OPERATORS_FORMAT.into(),
            motion_quorum: self.motion_quorum,
            operators: self.entries(),
        };
        to_json(&j).unwrap_or_default()
    }

    /// The operator a key id is bound to.
    pub fn operator_of(&self, key_id: &str) -> Option<&str> {
        self.keys.get(key_id).map(|(op, _)| op.as_str())
    }

    /// Distinct operator names.
    pub fn operators(&self) -> BTreeSet<&str> {
        self.keys.values().map(|(op, _)| op.as_str()).collect()
    }

    /// Distinct operators who must sign a sign-off with motion items.
    pub fn motion_quorum(&self) -> usize {
        self.motion_quorum
    }
}

/// Result of [`verify_signoff_signatures`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignatureVerdict {
    /// Operator name -> key ids with a valid signature.
    pub signers: BTreeMap<String, BTreeSet<String>>,
    /// Every signature that is not valid, and why (any entry refuses a
    /// lock: fail closed).
    pub problems: Vec<String>,
}

/// Check every signature in `sigs` over `signoff_bytes` against `trust`.
pub fn verify_signoff_signatures(
    signoff_bytes: &[u8],
    sigs: &SignoffSignatures,
    trust: &OperatorTrust,
) -> SignatureVerdict {
    let mut v = SignatureVerdict::default();
    let digest = signoff_file_digest(signoff_bytes);
    if sigs.signoff_digest != digest {
        v.problems.push(format!(
            "the signatures are for sign-off {}, the file given is {digest}: it was changed \
             after signing (signatures void; re-sign)",
            sigs.signoff_digest
        ));
        return v;
    }
    let msg = signoff_signed_message(signoff_bytes);
    let mut seen = BTreeSet::new();
    for s in &sigs.signatures {
        let id: String = s.key_id.chars().take(128).collect();
        if !seen.insert(s.key_id.as_str()) {
            v.problems.push(format!("key {id:?} signed twice"));
            continue;
        }
        let Some((op, key)) = trust.keys.get(&s.key_id) else {
            v.problems
                .push(format!("key {id:?} is not in the operators trust list"));
            continue;
        };
        let sig = from_hex(&s.signature_hex).filter(|b| b.len() == SIGNATURE_LEN);
        match sig {
            Some(sig) if s.algorithm == ED25519 && key.verify(&msg, &sig) => {
                v.signers
                    .entry(op.clone())
                    .or_default()
                    .insert(s.key_id.clone());
            }
            _ => v.problems.push(format!(
                "signature by key {id:?} ({op}) does not verify over this sign-off"
            )),
        }
    }
    v
}

/// Items that review who may command motion ([`MOTION_REVIEW_KINDS`])
/// or a bound safety configuration ([`BOUND_CONFIG_KIND`]): the ones the
/// two-person rule applies to.
pub fn motion_items(s: &Signoff) -> impl Iterator<Item = &SignoffItem> {
    s.items
        .iter()
        .filter(|i| MOTION_REVIEW_KINDS.contains(&i.kind.as_str()) || i.kind == BOUND_CONFIG_KIND)
}

/// Read a file others must not be able to modify: no symlink at `path`, a
/// regular file, `mode & 0o022 == 0` (Unix), at most `max` bytes.
pub(crate) fn read_protected(path: &Path, max: u64) -> io::Result<String> {
    let lmeta = std::fs::symlink_metadata(path)?;
    if lmeta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "is a symbolic link (refused)",
        ));
    }
    let f = std::fs::File::open(path)?;
    let meta = f.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.ino() != lmeta.ino() || meta.dev() != lmeta.dev() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "file changed while opening",
            ));
        }
        let mode = meta.mode() & 0o7777;
        if mode & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("mode {mode:04o} lets group/others modify it; chmod go-w"),
            ));
        }
    }
    let mut s = String::new();
    f.take(max + 1).read_to_string(&mut s)?;
    if s.len() as u64 > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("larger than {max} bytes"),
        ));
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use robodr_events::profile::Envelope;

    fn prof() -> Profile {
        let mut p = Profile {
            model: "m".into(),
            ..Default::default()
        };
        p.participants.insert("a".repeat(24));
        p.motion_envelopes.insert(
            "/cmd_vel".into(),
            Envelope {
                max_linear_speed: Some(1.0),
                max_joint_speed: None,
                ..Default::default()
            },
        );
        p
    }

    #[test]
    fn conservative_signoff_lists_everything_unconfirmed() {
        let s = Signoff::for_profile(&prof());
        // participant, motion channel, and the unbounded joint dimension.
        assert_eq!(s.items.len(), 3);
        assert_eq!(s.unconfirmed().count(), 3);
        assert!(s
            .items
            .iter()
            .any(|i| i.id == "envelope_dimension_unbounded:/cmd_vel joint"));
        assert!(s.items_intact());
        assert!(s.operator.is_empty());
        assert_eq!(s.check_shape(), Ok(()));
        assert_eq!(s.profile_sha256, draft_digest(&prof()));
        let c = s.clone().confirm_all("alice");
        assert_eq!(c.unconfirmed().count(), 0);
        assert!(s.to_string().contains("[ ] participant_unreviewed:"));
        assert!(c.to_string().contains("[x]"));
    }

    #[test]
    fn duplicate_ids_are_merged_and_sorted() {
        let s = Signoff::new(
            &prof(),
            [
                SignoffItem::new("b", "x", "1"),
                SignoffItem::new("a", "y", "2"),
                SignoffItem::new("b", "x", "3"),
            ],
        );
        assert_eq!(
            s.items.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(),
            vec!["a:y", "b:x"]
        );
        assert_eq!(s.items[1].reason, "1");
    }

    #[test]
    fn shape_errors() {
        let good = Signoff::for_profile(&prof());
        let mut s = good.clone();
        s.format = "v0".into();
        assert!(s.check_shape().is_err());
        let mut s = good.clone();
        s.items.push(s.items[0].clone());
        assert!(s.check_shape().unwrap_err().contains("twice"));
        let mut s = good.clone();
        s.items[0].subject = "other".into();
        assert!(s.check_shape().is_err());
        let mut s = good.clone();
        s.profile_sha256 = "ABC".into();
        assert!(s.check_shape().is_err());
        // Unknown fields are rejected on parse (no silent typos such as
        // "confirmd": true).
        let j = serde_json::to_string(&good)
            .unwrap()
            .replace("\"confirmed\":false", "\"confirmd\":true");
        assert!(serde_json::from_str::<Signoff>(&j).is_err());
    }

    #[test]
    fn item_set_is_bound_by_digest() {
        let s = Signoff::for_profile(&prof()).confirm_all("op");
        // Confirming and naming the operator do not touch the digest.
        assert!(s.items_intact());
        let mut del = s.clone();
        del.items.pop();
        assert!(!del.items_intact());
        let mut add = s.clone();
        let mut extra = SignoffItem::new("x", "y", "z");
        extra.confirmed = true;
        add.items.push(extra);
        assert!(!add.items_intact());
        let mut reword = s.clone();
        reword.items[0].reason = "fine".into();
        assert!(!reword.items_intact());
        // Reordering the file is harmless.
        let mut rev = s.clone();
        rev.items.reverse();
        assert!(rev.items_intact());
        // Rebinding to other bytes re-seals; a bare digest swap does not.
        let mut swapped = s.clone();
        swapped.profile_sha256 = "0".repeat(64);
        assert!(!swapped.items_intact());
        let mut rebound = s.clone();
        rebound.rebind("0".repeat(64));
        assert!(rebound.items_intact());
        // Shape: items_sha256 must be hex.
        let mut bad = s.clone();
        bad.items_sha256 = "zz".into();
        assert!(bad.check_shape().unwrap_err().contains("items_sha256"));
        // Ids/reasons with framing characters cannot collide.
        let a = items_digest("d", &[SignoffItem::new("k", "a\",b", "r")]);
        let b = items_digest("d", &[SignoffItem::new("k", "a", "b\",r")]);
        assert_ne!(a, b);
    }

    #[test]
    fn floor_requires_a_review_per_motion_channel() {
        let req = required_items(&prof());
        // The channel, and its unbounded joint dimension.
        assert_eq!(req.len(), 2);
        assert_eq!(req[0].subject, "/cmd_vel");
        assert_eq!(req[1].subject, "/cmd_vel joint");
        let mut unb = SignoffItem::new(UNBOUNDED_DIMENSION_KIND, "/cmd_vel joint", "r");
        assert!(!satisfies(&unb, &req[1]));
        unb.confirmed = true;
        assert!(satisfies(&unb, &req[1]));
        assert!(!satisfies(&unb, &req[0]), "wrong kind");
        // Exact subject for dimensions: no prefix matching.
        let mut longer = SignoffItem::new(UNBOUNDED_DIMENSION_KIND, "/cmd_vel joint x", "r");
        longer.confirmed = true;
        assert!(!satisfies(&longer, &req[1]));
        // Both dimensions bounded: no dimension requirement; neither
        // bounded: none either (lock refuses the channel outright).
        let mut p = prof();
        p.motion_envelopes
            .get_mut("/cmd_vel")
            .unwrap()
            .max_joint_speed = Some(1.0);
        assert_eq!(required_items(&p).len(), 1);
        p.motion_envelopes
            .get_mut("/cmd_vel")
            .unwrap()
            .max_joint_speed = None;
        p.motion_envelopes
            .get_mut("/cmd_vel")
            .unwrap()
            .max_linear_speed = None;
        assert_eq!(required_items(&p).len(), 1);
        let mut it = SignoffItem::new("motion_writer", "/cmd_vel aaaa", "r");
        assert!(!covers(&it, "/cmd_vel"), "unconfirmed does not cover");
        it.confirmed = true;
        assert!(covers(&it, "/cmd_vel"));
        // Prefix of another channel name does not count.
        assert!(!covers(&it, "/cmd"));
        let mut other = SignoffItem::new("participant_late", "/cmd_vel", "r");
        other.confirmed = true;
        assert!(!covers(&other, "/cmd_vel"), "wrong kind");
        let mut exact = SignoffItem::new("motion_channel_unreviewed", "/cmd_vel", "r");
        exact.confirmed = true;
        assert!(covers(&exact, "/cmd_vel"));
    }

    // ---------------------------------------------- operator signatures --

    fn key(id: &str, seed: u8) -> robodr_blackbox::Ed25519SigningKey {
        robodr_blackbox::Ed25519SigningKey::from_seed(id, &[seed; 32]).unwrap()
    }

    fn trust(entries: &[(&str, &robodr_blackbox::Ed25519SigningKey)], q: usize) -> OperatorTrust {
        OperatorTrust::new(
            entries
                .iter()
                .map(|(n, k)| (n.to_string(), k.verifying_key()))
                .collect(),
            q,
        )
        .unwrap()
    }

    fn confirmed_text() -> String {
        to_json(&Signoff::for_profile(&prof()).confirm_all("alice")).unwrap()
    }

    #[test]
    fn signatures_verify_and_bind_the_exact_bytes() {
        let (ka, kb, kx) = (key("ka", 1), key("kb", 2), key("kx", 3));
        let t = trust(&[("alice", &ka), ("bob", &kb)], 2);
        let text = confirmed_text();
        let mut sigs = SignoffSignatures::new(text.as_bytes());
        sigs.add(text.as_bytes(), &ka).unwrap();
        sigs.add(text.as_bytes(), &kb).unwrap();
        assert!(sigs
            .add(text.as_bytes(), &ka)
            .unwrap_err()
            .contains("already signed"));
        let back = SignoffSignatures::parse(&sigs.to_text()).unwrap();
        assert_eq!(back, sigs);
        let v = verify_signoff_signatures(text.as_bytes(), &back, &t);
        assert!(v.problems.is_empty(), "{:?}", v.problems);
        assert_eq!(
            v.signers.keys().cloned().collect::<Vec<_>>(),
            ["alice", "bob"]
        );

        // One changed byte (a space) voids every signature.
        let edited = text.replacen("  ", "   ", 1);
        let v = verify_signoff_signatures(edited.as_bytes(), &back, &t);
        assert!(v.signers.is_empty());
        assert!(v.problems[0].contains("changed after signing"));
        assert!(sigs
            .clone()
            .add(edited.as_bytes(), &kx)
            .unwrap_err()
            .contains("void"));

        // Digest swapped to the edited bytes: the signatures fail.
        let mut forged = back.clone();
        forged.signoff_digest = signoff_file_digest(edited.as_bytes());
        let v = verify_signoff_signatures(edited.as_bytes(), &forged, &t);
        assert!(v.signers.is_empty());
        assert_eq!(v.problems.len(), 2, "{:?}", v.problems);

        // Unknown key, garbage signature, wrong algorithm, duplicate entry.
        let mut other = SignoffSignatures::new(text.as_bytes());
        other.add(text.as_bytes(), &kx).unwrap();
        other.signatures.push(OperatorSignature {
            algorithm: ED25519.into(),
            key_id: "ka".into(),
            signature_hex: "00".repeat(SIGNATURE_LEN),
        });
        other.signatures.push(OperatorSignature {
            algorithm: "hmac-sha256".into(),
            key_id: "kb".into(),
            signature_hex: "zz".into(),
        });
        other.signatures.push(other.signatures[1].clone());
        let v = verify_signoff_signatures(text.as_bytes(), &other, &t);
        assert!(v.signers.is_empty());
        assert_eq!(v.problems.len(), 4, "{:?}", v.problems);
        assert!(v.problems[0].contains("not in the operators trust list"));
        assert!(v.problems[3].contains("signed twice"));

        // HMAC signers are refused.
        let hk = robodr_blackbox::HmacSha256Key::new("h", &[9; 32]).unwrap();
        assert!(SignoffSignatures::new(text.as_bytes())
            .add(text.as_bytes(), &hk)
            .unwrap_err()
            .contains("cannot sign"));
        assert_eq!(
            signoff_sig_path(Path::new("/x/so.json")),
            PathBuf::from("/x/so.json.sig")
        );
    }

    #[test]
    fn signature_file_parse_is_strict() {
        let text = confirmed_text();
        let mut sigs = SignoffSignatures::new(text.as_bytes());
        sigs.add(text.as_bytes(), &key("ka", 1)).unwrap();
        let good = sigs.to_text();
        assert!(SignoffSignatures::parse(&good).is_ok());
        for bad in [
            good.replace(SIGNOFF_SIGS_FORMAT, "robodr-signoff-sigs/v0"),
            good.replace("\"signatures\"", "\"signatures\": [], \"signatures\""),
            good.replace("\"format\"", "\"extra\": 1, \"format\""),
            good.replace("sha256:", "md5:"),
            "{}".into(),
            "[".into(),
        ] {
            assert!(SignoffSignatures::parse(&bad).is_err(), "{bad}");
        }
        let mut many = sigs.clone();
        many.signatures = vec![sigs.signatures[0].clone(); MAX_SIGNOFF_SIGNATURES + 1];
        assert!(SignoffSignatures::parse(&many.to_text()).is_err());
        let mut full = SignoffSignatures::new(text.as_bytes());
        full.signatures = vec![sigs.signatures[0].clone(); MAX_SIGNOFF_SIGNATURES];
        assert!(full
            .add(text.as_bytes(), &key("new", 4))
            .unwrap_err()
            .contains("more than"));
    }

    #[test]
    fn operator_trust_list_rules() {
        let (ka, ka2, kb) = (key("ka", 1), key("ka2", 5), key("kb", 2));
        let t = trust(&[("alice", &ka), ("alice", &ka2), ("bob", &kb)], 2);
        assert_eq!(t.operators().len(), 2, "two keys, one person");
        assert_eq!(t.operator_of("ka2"), Some("alice"));
        assert_eq!(t.operator_of("nope"), None);
        let back = OperatorTrust::parse(&t.to_text()).unwrap();
        assert_eq!(back.to_text(), t.to_text());
        assert_eq!(back.motion_quorum(), 2);
        // motion_quorum defaults to 1.
        let one = t.to_text().replace("  \"motion_quorum\": 2,\n", "");
        assert_eq!(OperatorTrust::parse(&one).unwrap().motion_quorum(), 1);

        let vk = |k: &robodr_blackbox::Ed25519SigningKey| k.verifying_key();
        let same_pub =
            robodr_blackbox::Ed25519VerifyingKey::from_bytes("other", vk(&ka).as_bytes()).unwrap();
        for (entries, q, want) in [
            (vec![], 1, "no operators"),
            (vec![("a".to_string(), vk(&ka))], 0, "between 1"),
            (
                vec![("a".into(), vk(&ka)), ("a".into(), vk(&kb))],
                2,
                "between 1",
            ),
            (
                vec![("a".into(), vk(&ka)), ("b".into(), same_pub)],
                1,
                "listed twice",
            ),
            (
                vec![
                    ("a".into(), vk(&ka)),
                    ("b".into(), key("ka", 9).verifying_key()),
                ],
                1,
                "listed twice",
            ),
            (vec![(" a".into(), vk(&ka))], 1, "operator name"),
            (vec![("".into(), vk(&ka))], 1, "operator name"),
            (vec![("a\u{7}".into(), vk(&ka))], 1, "operator name"),
        ] {
            let e = OperatorTrust::new(entries, q).unwrap_err();
            assert!(e.contains(want), "{e}");
        }
        let good = t.to_text();
        for bad in [
            good.replace(OPERATORS_FORMAT, "robodr-operators/v0"),
            good.replace("\"ed25519\"", "\"hmac-sha256\""),
            good.replace("\"format\"", "\"x\": 1, \"format\""),
            good.replace("\"format\"", "\"format\": \"a\", \"format\""),
            good.replacen(&to_hex(vk(&ka).as_bytes()), "00", 1),
            // Not a valid curve point (small order / non-canonical).
            good.replacen(&to_hex(vk(&ka).as_bytes()), &"ff".repeat(32), 1),
        ] {
            assert!(OperatorTrust::parse(&bad).is_err(), "{bad}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn operator_trust_file_must_be_protected() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("robodr-ops-trust-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let t = trust(&[("alice", &key("ka", 1))], 1);
        let f = d.join("operators.json");
        std::fs::write(&f, t.to_text()).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(OperatorTrust::load(&f).is_ok());
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(OperatorTrust::load(&f)
            .unwrap_err()
            .contains("group/others"));
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        let link = d.join("link.json");
        std::os::unix::fs::symlink(&f, &link).unwrap();
        assert!(OperatorTrust::load(&link)
            .unwrap_err()
            .contains("symbolic link"));
        assert!(OperatorTrust::load(&d).is_err(), "a directory");
        assert!(OperatorTrust::load(&d.join("missing")).is_err());
        let big = d.join("big.json");
        std::fs::write(&big, vec![b' '; MAX_OPERATORS_BYTES as usize + 1]).unwrap();
        assert!(OperatorTrust::load(&big).unwrap_err().contains("larger"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn motion_items_are_the_motion_review_kinds() {
        let s = Signoff::new(
            &prof(),
            [
                SignoffItem::new("motion_writer", "/cmd_vel aaaa", "r"),
                SignoffItem::new("participant_late", "aaaa", "r"),
                SignoffItem::new("motion_channel_unreviewed", "/cmd_vel", "r"),
            ],
        );
        assert_eq!(motion_items(&s).count(), 2);
        assert_eq!(motion_items(&Signoff::new(&prof(), [])).count(), 0);
    }
}
