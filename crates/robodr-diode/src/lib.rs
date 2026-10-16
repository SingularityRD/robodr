//! # robodr-diode
//!
//! One-way export of RoboDR findings and black-box evidence from an
//! air-gapped robot or fleet console to the SOC (AutoSecOps), across a data
//! diode or on controlled removable media. Implements the "Air-gapped
//! transport" section of `docs/contracts/robot-edr.findings.md`.
//!
//! * [`pack`] (low side): [`Packer`] turns validated
//!   [`FindingEnvelope`](robodr_ocsf::FindingEnvelope)s and
//!   `robodr-blackbox` export bundles into **batches**: one directory per
//!   batch, sequence-numbered per unit, size-bounded, with a manifest that
//!   lists every file's size and SHA-256, chains to the previous batch's
//!   hash and is signed with a `robodr_blackbox::Signer`. Batches are
//!   published atomically (temp dir + rename) into an outbox.
//! * [`unpack`] (high side): [`Importer`] authenticates each batch with a
//!   [`Keyring`] of `robodr_blackbox::Verifier`s before parsing it, checks
//!   sequence/chain per unit against persisted state (gaps held and
//!   reported, duplicates dropped, conflicts and replays quarantined),
//!   re-validates every finding with [`robodr_ocsf::parse_and_validate`],
//!   checks that every finding's robot (and every bundle's device) is the
//!   unit or on the unit's allow-list, and emits Kafka-ready records (JSON
//!   Lines) for the `robot-edr.findings` publisher. Bad batches go to
//!   `quarantine/<unique>/` with a reason file; a problem with one inbox
//!   entry never stops the others from being imported.
//! * [`manifest`]: the wire format and its limits.
//!
//! There is **no network code**: moving the outbox to the inbox (diode
//! transfer agent, removable media) and publishing the emitted records to
//! Kafka are outside this crate.
//!
//! ## Forward-error friendliness
//!
//! A one-way link cannot ask for retransmission. Units of loss and
//! retransmission are whole files and whole batches: each file is verified
//! independently (a corrupt or truncated file is identified by name), a
//! rejected batch does not advance the importer state, and re-sending a batch
//! (or the whole outbox history) is idempotent — identical batches are
//! recognised by hash and dropped, and the Kafka records carry the
//! deterministic `finding_id` / `event-uid` the consumer deduplicates on.
//! Application-level FEC (e.g. parity files) is **not** implemented; use the
//! diode vendor's FEC and send each batch more than once if the link is lossy.
//!
//! ## Keys
//!
//! The binaries ([`cli`]) sign with a unit's Ed25519 secret key file and
//! verify with Ed25519 **public** key files only, so the SOC holds no key
//! that can sign batches; legacy symmetric HMAC keys need an explicit
//! `--allow-hmac`. The library itself is algorithm-agnostic: any
//! `robodr_blackbox::Signer` / `Verifier`.
//!
//! See `README.md` in this crate for the threat model and honest limits
//! (notably: the Ed25519 implementation is in-crate and not audited).

pub mod cli;
mod fsutil;
pub mod manifest;
pub mod pack;
pub mod unpack;

pub use manifest::{batch_dir_name, batch_hash, FileEntry, FileKind, Manifest, SignatureFile};
pub use pack::{PackConfig, PackError, PackState, Packer, PublishedBatch};
pub use unpack::{
    AcceptedBatch, EntryError, ImportConfig, ImportError, ImportReport, ImportState, Importer,
    Keyring, QuarantineReason, UnitState,
};
