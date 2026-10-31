//! The rule ids of the trusted catalog, read from the catalog source.
#![allow(dead_code)]
//!
//! The catalog is a set of `match` functions in `src/builder.rs` with no
//! enumerable list, so the tests read the literal match arms
//! (`"robot.x.y" => RuleInfo {` or `"robot.x.y" => e(`) from the source and
//! check every id they find with [`robodr_ocsf::builder::rule_known`]: a
//! string that is not a catalog id fails the tests, and an arm the reader
//! misses shows up as a count change in the detection-catalog drift test.

/// Every literal rule id with a catalog entry, sorted, deduplicated.
pub fn catalog_rule_ids() -> Vec<String> {
    let src = include_str!("../../src/builder.rs");
    let mut ids: Vec<String> = src
        .lines()
        .filter_map(|line| {
            let t = line.trim_start();
            let rest = t.strip_prefix('"')?;
            let end = rest.find('"')?;
            let (id, tail) = rest.split_at(end);
            let tail = tail.get(1..)?.trim_start();
            (id.starts_with("robot.") && tail.starts_with("=>")).then(|| id.to_string())
        })
        .collect();
    ids.sort();
    ids.dedup();
    for id in &ids {
        assert!(
            robodr_ocsf::builder::rule_known(id),
            "{id} looks like a catalog arm but has no catalog entry"
        );
    }
    ids
}

/// Prefix match arms (`r if r.starts_with("robot.x.")`): every other id
/// under the prefix gets that arm's entry.
pub fn catalog_prefix_arms() -> Vec<String> {
    let src = include_str!("../../src/builder.rs");
    let mut out: Vec<String> = src
        .lines()
        .filter_map(|line| {
            let t = line.trim_start();
            let rest = t.strip_prefix("r if r.starts_with(\"")?;
            let end = rest.find('"')?;
            rest.get(..end).map(str::to_string)
        })
        .collect();
    out.sort();
    out.dedup();
    out
}
