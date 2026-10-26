//! Harness: a whole diode batch through the high-side importer
//! (`robodr_diode::Importer::run`): signature file, authentication, manifest
//! parsing and checks, sequence checks, file checks (sizes, SHA-256,
//! findings JSONL, black-box bundles), parity repair, emission.
//!
//! Input: `flags entries...`, each entry `name_len(1) name len(u16 LE)
//! bytes`. The entries are written as files of one batch directory in a
//! fresh inbox (a per-thread directory under `$TMPDIR`; names that are not a
//! single plain path component are skipped). Flags:
//!
//! * bit 0: sign `MANIFEST.json` with the harness key (writes a valid
//!   `MANIFEST.sig`), so mutations reach everything behind authentication;
//! * bit 1: name the directory after the manifest's `unit_id` / `batch_seq`
//!   (`rdd_<unit>_<seq>`), else `rdd_ugv-007_0000000000000001`;
//! * bit 2: the operator accepts a gap up to that `batch_seq`, so
//!   `batch_seq > 1` reaches the file checks on first contact.
//!
//! Invariants beyond "no panic":
//!
//! * `run` succeeds (only failing to list the inbox is a run error) and the
//!   entry gets exactly one disposition (accepted, duplicate, held,
//!   quarantined, in transit or a per-entry error);
//! * an accepted batch carried a signature that verifies with the unit's key
//!   over the exact manifest bytes, its manifest passes `check_import`, and
//!   its output holds `records.jsonl` and a byte-identical `MANIFEST.json`;
//! * a second run over the now empty inbox accepts nothing.
//!
//! Shared via `#[path]` with `crates/robodr-diode/tests/fuzz_smoke.rs`.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use robodr_blackbox::crypto::{hmac_sha256, to_hex};
use robodr_blackbox::HmacSha256Key;
use robodr_diode::manifest::{
    batch_dir_name, manifest_signing_message, Manifest, SignatureFile, FORMAT, MANIFEST_FILE,
    SIGNATURE_FILE,
};
use robodr_diode::{ImportConfig, Importer, Keyring};

pub const UNIT: &str = "ugv-007";
pub const KEY_ID: &str = "diode-ugv-007";
pub const KEY: [u8; 32] = [7; 32];
/// `now` of every run (2026-09-21, inside the findings time window).
pub const NOW: u64 = 1_790_000_100_000;

fn scratch_path() -> PathBuf {
    let t = format!("{:?}", std::thread::current().id());
    let t: String = t.chars().filter(char::is_ascii_digit).collect();
    std::env::temp_dir().join(format!("robodr-fuzz-diode-{}-{t}", std::process::id()))
}

/// Remove this thread's scratch directory (call after a run).
pub fn cleanup() {
    let _ = std::fs::remove_dir_all(scratch_path());
}

fn fresh_root() -> PathBuf {
    let root = scratch_path();
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("inbox")).expect("create fuzz temp dir");
    root
}

/// One plain path component, nothing the importer could be tricked into
/// following out of the batch directory by the *harness* itself.
fn plain_name(name: &[u8]) -> Option<&str> {
    let s = std::str::from_utf8(name).ok()?;
    let ok = !s.is_empty()
        && s != "."
        && s != ".."
        && !s.contains('/')
        && !s.contains('\0')
        && s.len() <= 100;
    ok.then_some(s)
}

/// The entries of the input, in order (later duplicates win).
pub fn split(data: &[u8]) -> (u8, Vec<(String, Vec<u8>)>) {
    let Some((&flags, mut rest)) = data.split_first() else {
        return (0, Vec::new());
    };
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    while let Some((&nl, r)) = rest.split_first() {
        let nl = usize::from(nl);
        if r.len() < nl + 2 {
            break;
        }
        let name = &r[..nl];
        let len = usize::from(u16::from_le_bytes([r[nl], r[nl + 1]]));
        let body = &r[nl + 2..];
        let take = len.min(body.len());
        if let Some(n) = plain_name(name) {
            out.retain(|(k, _)| k != n);
            out.push((n.to_string(), body[..take].to_vec()));
        }
        rest = &body[take..];
    }
    (flags, out)
}

/// Build the input format from named files (seed generation, tests).
pub fn join(flags: u8, files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut v = vec![flags];
    for (n, b) in files {
        let len = u16::try_from(b.len()).expect("seed file fits u16");
        v.push(u8::try_from(n.len()).expect("short name"));
        v.extend_from_slice(n.as_bytes());
        v.extend_from_slice(&len.to_le_bytes());
        v.extend_from_slice(b);
    }
    v
}

/// The harness key's signature file for `manifest`.
pub fn signature_file(manifest: &[u8]) -> Vec<u8> {
    let sig = hmac_sha256(&KEY, &manifest_signing_message(manifest));
    let s = SignatureFile {
        format: FORMAT.into(),
        algorithm: "hmac-sha256".into(),
        key_id: KEY_ID.into(),
        sig: to_hex(&sig),
    };
    let mut b = serde_json::to_vec(&s).expect("serialises");
    b.push(b'\n');
    b
}

fn keyring() -> Keyring {
    let mut k = Keyring::new();
    k.add(
        UNIT,
        Box::new(HmacSha256Key::new(KEY_ID, &KEY).expect("valid key")),
    )
    .expect("add key");
    k
}

fn file<'a>(files: &'a [(String, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
    files
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, b)| b.as_slice())
}

pub fn run(data: &[u8]) {
    let (flags, mut files) = split(data);
    let manifest_bytes = file(&files, MANIFEST_FILE).map(<[u8]>::to_vec);
    let parsed: Option<Manifest> = manifest_bytes
        .as_deref()
        .and_then(|b| serde_json::from_slice(b).ok());
    if flags & 1 != 0 {
        if let Some(mb) = &manifest_bytes {
            let sig = signature_file(mb);
            files.retain(|(n, _)| n != SIGNATURE_FILE);
            files.push((SIGNATURE_FILE.to_string(), sig));
        }
    }
    let dir_name = match (&parsed, flags & 2 != 0) {
        (Some(m), true) if !m.unit_id.contains('/') && !m.unit_id.starts_with('.') => {
            batch_dir_name(&m.unit_id, m.batch_seq)
        }
        _ => batch_dir_name(UNIT, 1),
    };
    if plain_name(dir_name.as_bytes()).is_none() {
        return;
    }

    let root = fresh_root();
    let batch = root.join("inbox").join(&dir_name);
    std::fs::create_dir_all(&batch).expect("create batch dir");
    for (n, b) in &files {
        std::fs::write(batch.join(n), b).expect("write batch file");
    }

    let mut cfg = ImportConfig::under(&root);
    if flags & 4 != 0 {
        if let Some(m) = &parsed {
            cfg.accept_gaps.push((m.unit_id.clone(), m.batch_seq));
        }
    }
    let mut imp = Importer::open(cfg, keyring()).expect("importer opens on a fresh root");
    let report = imp.run(NOW).expect("run never fails on a listable inbox");
    let dispositions = report.accepted.len()
        + report.duplicates.len()
        + report.held.len()
        + report.quarantined.len()
        + report.in_transit.len()
        + report.errors.len();
    assert_eq!(dispositions, 1, "{report:?}");

    if let Some(a) = report.accepted.first() {
        let mb = manifest_bytes
            .as_deref()
            .expect("accepted without a manifest");
        let m: Manifest = serde_json::from_slice(mb).expect("accepted manifest parses");
        assert_eq!(m.check_import(), Ok(()));
        assert_eq!(
            (a.unit_id.as_str(), a.seq),
            (m.unit_id.as_str(), m.batch_seq)
        );
        let sig: SignatureFile = serde_json::from_slice(
            file(&files, SIGNATURE_FILE).expect("accepted without a signature"),
        )
        .expect("accepted signature file parses");
        let want = to_hex(&hmac_sha256(&KEY, &manifest_signing_message(mb)));
        assert_eq!(
            sig.sig, want,
            "accepted with a signature that does not verify"
        );
        assert!(a.output.join("records.jsonl").is_file());
        assert_eq!(
            std::fs::read(a.output.join(MANIFEST_FILE)).expect("manifest copy"),
            mb
        );
        assert_inside(&a.output, &root);
    }

    let again = imp.run(NOW).expect("second run");
    assert!(again.accepted.is_empty(), "{again:?}");
    drop(imp);
}

fn assert_inside(p: &Path, root: &Path) {
    let p = p.canonicalize().expect("output exists");
    let root = root.canonicalize().expect("root exists");
    assert!(
        p.starts_with(&root),
        "{} escapes {}",
        p.display(),
        root.display()
    );
}
