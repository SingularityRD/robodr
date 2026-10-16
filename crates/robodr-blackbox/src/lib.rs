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
//!   use an asymmetric, non-exportable key (Ed25519 via an audited crate or
//!   TPM-backed ECDSA) behind the same traits.
//! - [`record`]: canonical record encoding and framing.
//! - [`time`]: timestamps with a time-source tag (no NTP on air-gapped units).
//! - [`store`]: the [`Recorder`].
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

pub mod crypto;
pub mod export;
pub mod record;
pub mod sign;
pub mod store;
pub mod time;
pub mod verify;

pub use export::{Ack, Anchor, Bundle, Checkpoint, Receiver, SignedCursor};
pub use record::{ChainIdentity, Hash, Record, RecordKind};
pub use sign::{HmacSha256Key, Signer, Verifier};
pub use store::{
    AppendOutcome, EntryKind, Error, FsyncPolicy, Recorder, RecorderConfig, Refusal, RetentionMode,
};
pub use time::{Clock, SteppingClock, SystemClock, TimeSource, Timestamp};
pub use verify::{
    Finding, FindingKind, FindingLevel, Location, Report, SegmentData, VerifyOptions,
};
