//! Build identity of a RoboDR binary, for its `--version` line.
//!
//! ```text
//! robodr-agentd 0.1.0 (commit 3f1c…e2, source-date-epoch 1761868800, target aarch64-unknown-linux-musl)
//! ```
//!
//! * `commit`: `ROBODR_BUILD_COMMIT`, else `GITHUB_SHA` (set in every
//!   GitHub Actions job: CI, release, independent rebuild), else `unknown`.
//!   Never read from `git` at build time: the reproducibility builds copy
//!   the tree without `.git` and must produce the release's bytes.
//! * `source-date-epoch`: `SOURCE_DATE_EPOCH` (every release build sets it
//!   to the commit time), else `unset`.
//! * `target`: the Rust target triple the binary was built for.
//!
//! The build fails on a malformed value (build.rs), so a release cannot
//! carry a garbled identity. Combined with the published SHA256SUMS and
//! the reproducibility record, the line names the exact source and build
//! inputs of the binary a support case is about.
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

#[cfg(test)]
mod check;

/// The commit the binary was built from (hex), or `unknown`.
pub const COMMIT: &str = env!("ROBODR_BUILDINFO_COMMIT");
/// `SOURCE_DATE_EPOCH` of the build (decimal seconds), or `unset`.
pub const SOURCE_DATE_EPOCH: &str = env!("ROBODR_BUILDINFO_EPOCH");
/// The Rust target triple.
pub const TARGET: &str = env!("ROBODR_BUILDINFO_TARGET");

/// `<binary> <version> (commit C, source-date-epoch E, target T)`, without
/// a newline. `version` is the caller's `env!("CARGO_PKG_VERSION")`.
pub fn version_line(binary: &str, version: &str) -> String {
    format!(
        "{binary} {version} (commit {COMMIT}, source-date-epoch {SOURCE_DATE_EPOCH}, target {TARGET})"
    )
}

#[cfg(test)]
mod tests {
    use super::check::{select_commit, select_epoch, select_target};
    use super::*;

    #[test]
    fn line_names_commit_epoch_and_target() {
        let l = version_line("robodr-x", "1.2.3");
        assert!(l.starts_with("robodr-x 1.2.3 (commit "), "{l}");
        assert!(
            l.contains(&format!("source-date-epoch {SOURCE_DATE_EPOCH},")),
            "{l}"
        );
        assert!(l.ends_with(&format!("target {TARGET})")), "{l}");
        assert!(!l.contains('\n'));
        assert!(!TARGET.is_empty());
    }

    #[test]
    fn commit_selection() {
        let sha = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(select_commit(None, None).as_deref(), Ok("unknown"));
        assert_eq!(select_commit(Some(""), Some("")).as_deref(), Ok("unknown"));
        assert_eq!(select_commit(None, Some(sha)).as_deref(), Ok(sha));
        // The explicit variable wins over GitHub's.
        assert_eq!(
            select_commit(Some("abcdef1"), Some(sha)).as_deref(),
            Ok("abcdef1")
        );
        for bad in [
            "ABCDEF1",
            "abc",
            "g123456",
            "0123456 ",
            "abc\ndef0",
            &"a".repeat(65),
        ] {
            assert!(select_commit(Some(bad), None).is_err(), "{bad:?}");
            assert!(select_commit(None, Some(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn epoch_selection() {
        assert_eq!(select_epoch(None).as_deref(), Ok("unset"));
        assert_eq!(select_epoch(Some("")).as_deref(), Ok("unset"));
        assert_eq!(
            select_epoch(Some("1761868800")).as_deref(),
            Ok("1761868800")
        );
        for bad in ["-1", "1e9", " 1", "12345678901234567890", "now"] {
            assert!(select_epoch(Some(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn target_selection() {
        assert_eq!(
            select_target(Some("aarch64-unknown-linux-musl")).as_deref(),
            Ok("aarch64-unknown-linux-musl")
        );
        for bad in [None, Some(""), Some("x86_64 linux"), Some("a,b")] {
            assert!(select_target(bad).is_err(), "{bad:?}");
        }
    }
}
