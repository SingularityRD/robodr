//! Harness: the diode batch manifest and signature file
//! (`robodr_diode::manifest`): JSON parse, `check` / `check_import`, and the
//! derived values the importer relies on.
//!
//! Input: `manifest JSON \0 signature-file JSON` (no NUL: everything is the
//! manifest and the signature file is skipped). Invariants beyond "no
//! panic":
//!
//! * a manifest that passes `check` also passes `check_import` (import only
//!   widens the accepted contract versions), and every file name it lists
//!   is a safe, kind-matching, unique name; data files come before parity
//!   files; with parity, `k + m <= 255`, `1 <= m <= 32` and every parity file
//!   has exactly `parity_len(max data size, shard_size)` bytes;
//! * `total_size` is the saturating sum of the declared sizes;
//! * serialise -> parse is the identity and keeps both verdicts;
//! * `batch_hash` and `manifest_signing_message` are deterministic, the
//!   message is the domain prefix followed by the exact bytes, the hash is
//!   64 lower-case hex digits;
//! * the signature file parses with `deny_unknown_fields` or not at all,
//!   and survives a serialise -> parse round trip.
//!
//! Shared via `#[path]` with `crates/robodr-diode/tests/fuzz_smoke.rs`.
#![allow(dead_code)]

use robodr_diode::fec::MAX_SHARDS;
use robodr_diode::manifest::{
    batch_hash, is_hex_digest, is_safe_file_name, manifest_signing_message, parity_len, FileKind,
    Manifest, SignatureFile, MAX_PARITY_SHARDS,
};

pub fn run(data: &[u8]) {
    let (manifest_bytes, sig_bytes) = match data.iter().position(|&b| b == 0) {
        Some(i) => (&data[..i], Some(&data[i + 1..])),
        None => (data, None),
    };

    // Derived values on the raw bytes (whatever they are).
    let h = batch_hash(manifest_bytes);
    assert!(is_hex_digest(&h), "batch hash {h:?}");
    assert_eq!(h, batch_hash(manifest_bytes));
    let msg = manifest_signing_message(manifest_bytes);
    assert!(msg.ends_with(manifest_bytes));
    assert_eq!(
        msg.len(),
        b"robodr-diode/manifest/v1\0".len() + manifest_bytes.len()
    );
    assert!(msg.starts_with(b"robodr-diode/manifest/v1\0"));

    if let Ok(m) = serde_json::from_slice::<Manifest>(manifest_bytes) {
        check_manifest(&m);
        let again = serde_json::to_vec(&m).expect("a parsed manifest serialises");
        let m2: Manifest = serde_json::from_slice(&again).expect("round trip parses");
        assert_eq!(m, m2);
        assert_eq!(m.check(), m2.check());
        assert_eq!(m.check_import(), m2.check_import());
    }

    if let Some(sb) = sig_bytes {
        if let Ok(s) = serde_json::from_slice::<SignatureFile>(sb) {
            let again = serde_json::to_vec(&s).expect("serialises");
            let s2: SignatureFile = serde_json::from_slice(&again).expect("round trip");
            assert_eq!(s, s2);
        }
    }
}

fn check_manifest(m: &Manifest) {
    let total = m.files.iter().fold(0u64, |a, f| a.saturating_add(f.size));
    assert_eq!(m.total_size(), total);
    assert_eq!(
        m.data_files().count() + m.parity_files().count(),
        m.files.len()
    );
    let strict = m.check();
    let import = m.check_import();
    if strict.is_ok() {
        assert!(import.is_ok(), "check ok but check_import {import:?}");
    }
    if import.is_err() {
        return;
    }
    // Accepted for import: the structural guarantees the importer uses.
    assert!(m.batch_seq >= 1);
    assert_eq!(m.prev_batch_hash.is_none(), m.batch_seq == 1);
    assert!(!m.files.is_empty());
    let mut names = std::collections::BTreeSet::new();
    let mut seen_parity = false;
    for f in &m.files {
        assert!(is_safe_file_name(&f.name), "{:?}", f.name);
        assert!(names.insert(f.name.clone()), "duplicate {:?}", f.name);
        assert!(is_hex_digest(&f.sha256));
        assert!(
            !f.name.contains('/') && !f.name.contains('\\') && !f.name.starts_with('.'),
            "{:?}",
            f.name
        );
        if f.kind == FileKind::Parity {
            seen_parity = true;
        } else {
            assert!(!seen_parity, "data file after a parity file");
        }
    }
    match &m.parity {
        None => assert_eq!(m.parity_files().count(), 0),
        Some(p) => {
            let k = m.data_files().count();
            let mm = m.parity_files().count();
            assert_eq!(p.data_shards as usize, k);
            assert_eq!(p.parity_shards as usize, mm);
            assert!(k >= 1 && (1..=MAX_PARITY_SHARDS).contains(&mm) && k + mm <= MAX_SHARDS);
            assert!(p.shard_size > 0);
            let max_data = m.data_files().map(|f| f.size).max().unwrap_or(0);
            let plen = parity_len(max_data, p.shard_size);
            // Rounded up to the stripe height (or saturated).
            assert!((plen >= max_data && plen.is_multiple_of(p.shard_size)) || plen == u64::MAX);
            assert!(m.parity_files().all(|f| f.size == plen));
        }
    }
}
