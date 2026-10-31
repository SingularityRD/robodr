//! When an external Python check counts as "not installed".

use std::process::Output;

/// The integrations scripts exit 2 with "... is required" when a Python
/// module they need is missing. Exit 2 is also a usage or tooling error
/// (argparse, a bad argument): that is a failure, never a skip.
pub fn missing_module(o: &Output) -> bool {
    o.status.code() == Some(2) && String::from_utf8_lossy(&o.stderr).contains(" is required")
}
