//! RoboDR operator tools (sales-readiness T68, T69, T70).
//!
//! * [`preflight`] and [`setup`]: `robodr-setup`, the first-boot tool. Host
//!   preflight (BTF, bpffs, nf_tables, systemd, glibc, clock, disk, key
//!   directory), key generation for a role, the role's `agentd.json` from
//!   the shipped examples, and the fingerprints of the public keys to
//!   register with the SOC.
//! * [`redact`] and [`bundle`]: `robodr-support-bundle`, a diagnostics
//!   archive for RoboDR support: versions, unit state and journal, status
//!   files, the nftables ruleset, redacted configuration, a manifest with
//!   the SHA-256 of every file. Keys, credentials and evidence are never
//!   collected, and the finished bundle is scanned for secret material
//!   before it is written (fail closed).
//! * [`metrics`]: `robodr-metrics`, a Prometheus textfile exporter of
//!   `robodr-agentd`'s `status.json` and `robodr-uplink`'s
//!   `uplink-status.json`, and of the systemd state of RoboDR's units (no
//!   listening socket; node_exporter's textfile collector serves it).
//!
//! Commands are run through [`exec`]: absolute search path, cleared
//! environment, no stdin, bounded output and a timeout.

// S10: release builds use `panic = "abort"`; non-test code has no unwrap /
// expect / panic!-family call and no unchecked indexing.
#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

pub mod args;
pub mod bundle;
pub mod exec;
pub mod metrics;
pub mod preflight;
pub mod redact;
pub mod setup;
pub mod time;

use sha2::{Digest, Sha256};

/// Lower-case hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// SHA-256 of `bytes`, lower-case hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// `path` (absolute) re-rooted under `root` (`/` = the host itself; tests
/// use a temporary tree).
pub fn rooted(root: &std::path::Path, path: &str) -> std::path::PathBuf {
    root.join(path.trim_start_matches('/'))
}
