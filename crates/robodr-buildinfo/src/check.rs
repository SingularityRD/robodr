// Validation of the build identity inputs. Shared by build.rs (through
// `include!`, so the build refuses a malformed value) and the library's
// unit tests. No std beyond `str`.

/// The commit as recorded: `ROBODR_BUILD_COMMIT`, else `GITHUB_SHA` (every
/// GitHub Actions job, so CI's two reproducibility builds and its release
/// build agree), else `unknown`. A set value must be a lower-case hex
/// object id of 7 to 64 characters (SHA-1 or SHA-256 repositories).
pub fn select_commit(robodr: Option<&str>, github: Option<&str>) -> Result<String, String> {
    let pick = [("ROBODR_BUILD_COMMIT", robodr), ("GITHUB_SHA", github)]
        .into_iter()
        .find_map(|(n, v)| v.filter(|v| !v.is_empty()).map(|v| (n, v)));
    match pick {
        None => Ok("unknown".to_string()),
        Some((name, v)) => {
            if (7..=64).contains(&v.len())
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                Ok(v.to_string())
            } else {
                Err(format!(
                    "{name}={v:?} is not a lower-case hex commit id (7 to 64 characters)"
                ))
            }
        }
    }
}

/// `SOURCE_DATE_EPOCH` as recorded: decimal seconds (1 to 19 digits, so it
/// fits an i64), or `unset` when absent or empty.
pub fn select_epoch(v: Option<&str>) -> Result<String, String> {
    match v.filter(|v| !v.is_empty()) {
        None => Ok("unset".to_string()),
        Some(v) if v.len() <= 19 && v.bytes().all(|b| b.is_ascii_digit()) => Ok(v.to_string()),
        Some(v) => Err(format!(
            "SOURCE_DATE_EPOCH={v:?} is not a decimal Unix time"
        )),
    }
}

/// The target triple cargo builds for: printable ASCII label characters.
pub fn select_target(v: Option<&str>) -> Result<String, String> {
    match v {
        Some(t)
            if !t.is_empty()
                && t.len() <= 128
                && t.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')) =>
        {
            Ok(t.to_string())
        }
        other => Err(format!("TARGET={other:?} is not a target triple")),
    }
}
