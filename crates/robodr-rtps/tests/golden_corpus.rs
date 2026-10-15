//! Golden-corpus regression: every `tests/fixtures/*.bin` is parsed and the
//! sorted, de-duplicated set of `(kind, guid_prefix, topic)` is compared with
//! the checked-in `tests/fixtures/<name>.json` next to it.
//!
//! The directory is scanned, so a real capture dropped in as `<name>.bin`
//! (one UDP payload per file) is covered automatically once its `.json` is
//! blessed. To (re)write the expected files after an intended parser change:
//!
//! ```text
//! ROBODR_BLESS=1 cargo test -p robodr-rtps --test golden_corpus
//! ```
//!
//! and review the `.json` diff before committing it. Only the stable
//! projection is snapshotted; locators, src_ip and type names are not, so the
//! parser can grow fields without churning the corpus.

mod common;

use common::{bless, fixtures_dir, key, SRC_IP};
use robodr_rtps::parse_datagram;
use serde_json::{json, Value};

fn snapshot(datagram: &[u8]) -> Value {
    let mut keys: Vec<_> = parse_datagram(datagram, SRC_IP).iter().map(key).collect();
    keys.sort();
    keys.dedup();
    Value::Array(
        keys.into_iter()
            .map(|(kind, guid, topic)| json!({ "kind": kind, "guid_prefix": guid, "topic": topic }))
            .collect(),
    )
}

#[test]
fn golden_corpus_matches() {
    let mut bins: Vec<_> = std::fs::read_dir(fixtures_dir())
        .expect("fixtures dir")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "bin"))
        .collect();
    bins.sort();
    assert!(
        bins.len() >= 8,
        "expected the synthetic corpus, found {bins:?}"
    );

    let mut failures = Vec::new();
    for bin in &bins {
        let got = snapshot(&std::fs::read(bin).unwrap());
        let json_path = bin.with_extension("json");
        if bless() {
            let mut text = serde_json::to_string_pretty(&got).unwrap();
            text.push('\n');
            std::fs::write(&json_path, text).unwrap();
            continue;
        }
        let want: Value = match std::fs::read_to_string(&json_path) {
            Ok(t) => serde_json::from_str(&t)
                .unwrap_or_else(|e| panic!("{}: invalid JSON: {e}", json_path.display())),
            Err(_) => {
                failures.push(format!(
                    "{}: missing (run with ROBODR_BLESS=1)",
                    json_path.display()
                ));
                continue;
            }
        };
        if got != want {
            failures.push(format!(
                "{}:\n  expected {want}\n  got      {got}",
                bin.file_name().unwrap().to_string_lossy()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "golden mismatches:\n{}",
        failures.join("\n")
    );
}
