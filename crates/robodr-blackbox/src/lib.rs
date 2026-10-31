//! Signed, hash-chained black-box evidence recorder for RoboDR.
//!
//! The black box is the robot's tamper-evident flight recorder: every robot
//! event, deviation and free-form note is appended as a [`record::Record`]
//! that is hash-chained to its predecessor, bound to a chain identity
//! (device, boot, key) and signed. Storage is append-only segment files with
//! crash recovery, cyclic or saturation retention, and store-and-forward
//! export bundles that a receiver verifies independently.
//!
//! Modules:
//! - [`crypto`]: in-crate SHA-256 / HMAC-SHA256 (no crypto crates available
//!   offline), tested against NIST and RFC 4231 vectors.
//! - [`sign`]: [`sign::Signer`] / [`sign::Verifier`] traits; the interim
//!   [`sign::HmacSha256Key`]. **HMAC is a placeholder**: production must
//!   use an asymmetric key ([`Ed25519SigningKey`], or a TPM-backed
//!   non-exportable key) behind the same traits.
//! - [`keys`]: key files (`robodr-blackbox-key/v1`, mode 0600, permission
//!   checked) and [`keys::Keyring`] (key id -> verifier) for verifying across
//!   a [`Recorder::rotate_key`].
//! - [`sign_ed25519`]: Ed25519 (RFC 8032) behind those traits
//!   ([`Ed25519SigningKey`] / [`Ed25519VerifyingKey`]), thin wrappers over
//!   the audited `ed25519-dalek` crate (strict verification).
//! - [`record`]: canonical record encoding and framing.
//! - [`time`]: timestamps with a time-source tag (no NTP on air-gapped units).
//! - [`store`]: the [`Recorder`]: crash recovery, quarantine of damaged
//!   closed segments, the `head.json` high-water mark and optional external
//!   [`HeadAnchor`].
//! - [`tpm_anchor`]: [`TpmNvCounterAnchor`], a [`HeadAnchor`] on a TPM 2.0 NV
//!   monotonic counter (through `tpm2-tools`) plus a signed sidecar file.
//! - [`remote_anchor`]: [`RemoteHeadAnchor`], a [`HeadAnchor`] kept off the
//!   unit by an [`AnchorReceiver`] (`robodr-anchor-receiver`), with signed
//!   marks and nonce-bound, receiver-signed answers.
//! - [`verify`]: [`verify::verify_segments`] / [`verify::verify_dir`].
//! - [`export`]: [`export::Bundle`], [`export::Receiver`], checkpoints.
//!
//! The crate is protective only: it records and proves what happened. It
//! takes no action on the robot.
//!
//! See `README.md` in this crate for the format specification and threat model.
//!
//! ```
//! use robodr_blackbox::{Recorder, RecorderConfig, HmacSha256Key, SteppingClock, TimeSource};
//! use robodr_blackbox::verify::{verify_dir, VerifyOptions};
//! use robodr_events::{Deviation, Severity};
//!
//! let dir = std::env::temp_dir().join(format!("robodr-bb-doc-{}", std::process::id()));
//! let _ = std::fs::remove_dir_all(&dir);
//! let key = [0x42u8; 32];
//! let cfg = RecorderConfig::new(&dir, "ugv-01", "boot-a");
//! let mut rec = Recorder::open(
//!     cfg,
//!     Box::new(HmacSha256Key::new("unit-key", &key).unwrap()),
//!     Box::new(SteppingClock::new(1, 1_000, TimeSource::Rtc)),
//! ).unwrap();
//! rec.append_deviation(&Deviation::new("robot.ros2.unknown_participant", Severity::High, "x"))
//!     .unwrap();
//! rec.close().unwrap();
//!
//! let verifier = HmacSha256Key::new("unit-key", &key).unwrap();
//! let report = verify_dir(&dir, &verifier, &VerifyOptions::default()).unwrap();
//! assert!(report.is_clean());
//! std::fs::remove_dir_all(&dir).unwrap();
//! ```

// S10: `unsafe` is denied crate-wide; each item that needs it (FFI to libc
// symbols std already links) carries a local `#[allow(unsafe_code)]` and a
// `// SAFETY:` comment on every block.
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::undocumented_unsafe_blocks)]
// Review L3 (S10, R9): agentd links this library and release builds use
// `panic = "abort"`, so a panic here kills the daemon. Non-test code has no
// unwrap / expect / panic!-family call; slice indexing and arithmetic are
// left to review and fuzzing.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

pub mod backup;
pub mod crl;
pub mod crypto;
pub mod export;
pub mod keys;
pub mod outbox;
pub mod record;
pub mod remote_anchor;
pub mod secret_file;
pub mod sign;
pub mod sign_ed25519;
pub mod state_seal;
pub mod store;
pub mod time;
pub mod tls;
pub mod tpm_anchor;
pub mod verify;

pub use export::{Ack, Anchor, Bundle, Checkpoint, Receiver, SignedCursor};
pub use keys::{KeyFile, KeyFileError, Keyring, PreviousKeys};
pub use record::{ChainIdentity, Hash, Record, RecordKind};
pub use remote_anchor::{AnchorReceiver, RemoteAnchorConfig, RemoteHeadAnchor, RemoteMark};
pub use sign::{HmacSha256Key, Signer, Verifier};
pub use sign_ed25519::{Ed25519SigningKey, Ed25519VerifyingKey};
pub use state_seal::StateSealKey;
pub use store::{
    AnchoredHead, AppendOutcome, EntryKind, Error, FileHeadAnchor, FsyncPolicy, HeadAnchor,
    MemoryHeadAnchor, OpenIncident, Recorder, RecorderConfig, Refusal, RetentionMode,
    RetentionStatus,
};
pub use time::{Clock, SteppingClock, SystemClock, TimeSource, Timestamp};
pub use tpm_anchor::{TpmAnchorConfig, TpmNvCounterAnchor};
pub use verify::{
    Finding, FindingKind, FindingLevel, Location, Report, SegmentData, VerifyOptions,
};
