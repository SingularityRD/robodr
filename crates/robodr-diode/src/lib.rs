//! # robodr-diode
//!
//! One-way export of RoboDR findings and black-box evidence from an
//! air-gapped robot or fleet console to the SOC, across a data
//! diode or on controlled removable media. Implements the "Air-gapped
//! transport" section of `docs/contracts/robodr.findings.md`.
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
//!   Lines) for the findings publisher. Bad batches go to
//!   `quarantine/<unique>/` with a reason file; a problem with one inbox
//!   entry never stops the others from being imported.
//! * [`manifest`]: the wire format and its limits.
//! * [`fec`]: Reed-Solomon erasure coding over GF(2^8) (std only) for the
//!   optional per-batch parity files.
//!
//! There is **no network code**: moving the outbox to the inbox (diode
//! transfer agent, removable media) and publishing the emitted records to
//! Kafka are outside this crate.
//!
//! ## Forward error correction and retransmission
//!
//! A one-way link cannot ask for retransmission. Units of loss and repair
//! are whole files and whole batches:
//!
//! * **Parity** (opt-in, [`PackConfig::parity_shards`] `= m`): each batch
//!   carries `m` Reed-Solomon parity files over its data files, listed and
//!   hashed in the signed manifest; the importer rebuilds up to `m` missing
//!   or corrupt files (detected by their SHA-256), accepts a rebuilt file
//!   only if its hash equals the manifest's, and then verifies the batch as
//!   usual. More damage quarantines it as `fec_unrecoverable`.
//! * **Resend**: the packer archives published batches and
//!   [`Packer::resend`] re-emits one byte for byte for manual
//!   retransmission. Re-sending is idempotent: identical batches are
//!   recognised by hash and dropped, and the Kafka records carry the
//!   deterministic `finding_id` / `event-uid` the consumer deduplicates on.
//!
//! ## Single instance
//!
//! Packer and importer each hold an exclusive `flock` on `<state>.lock`
//! while open; a second instance on the same state file fails with a clear
//! error ([`PackError::Locked`], [`ImportError::Locked`]).
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
//! (notably: signing keys are files on the unit, not TPM-held).

pub mod cli;
pub mod fec;
mod fsutil;
pub mod manifest;
pub mod pack;
pub mod unpack;

pub use manifest::{
    batch_dir_name, batch_hash, FileEntry, FileKind, Manifest, ParitySpec, SignatureFile,
};
pub use pack::{PackConfig, PackError, PackState, Packer, PublishedBatch, ResentBatch};
pub use unpack::{
    AcceptedBatch, EntryError, ImportConfig, ImportError, ImportReport, ImportState, Importer,
    Keyring, QuarantineReason, UnitState,
};
