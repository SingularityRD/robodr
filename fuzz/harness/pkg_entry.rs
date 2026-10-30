//! Harness: the entry report (`robodr_pkg::entry`, Sprint 14a) and the
//! depot ↔ unit wire framing (`robodr_pkg::wire`).
//!
//! Input: a selector byte, then the document. `0`: `report \0 report.sig`
//! (verified against the harness site and bundle); `1`: a pack-stream
//! listing line; `2`: a request header block; `3`: a response header
//! block. Invariants beyond "no panic":
//!
//! * a report that parses is exactly its canonical encoding, with
//!   `scanned_at < expires_at` at most 30 days apart and sorted lists;
//!   one that verifies is for the harness site, bundle and RPK list, is
//!   signed by the entry key, passes, and lists nothing at or above its
//!   `fail_on`;
//! * a listing that parses names only media-pack paths (no traversal),
//!   sorted, with the four signed documents, within the size cap;
//! * a request is one of the two the protocol has; a report body is
//!   1..=`MAX_REQUEST_BODY` bytes.
//!
//! Shared via `#[path]` with `crates/robodr-pkg/tests/fuzz_smoke.rs`.
#![allow(dead_code)]

#[path = "pkg_common.rs"]
mod pkg_common;

use pkg_common::*;
use robodr_pkg::bundle::{BundleManifest, BundleRpk, VerifiedBundle, BUNDLE_FORMAT};
use robodr_pkg::common::to_canonical;
use robodr_pkg::entry::{self, EntryReport, RpkScan, Severity, Verdict, ENTRY_FORMAT};
use robodr_pkg::rpk::Arch;
use robodr_pkg::sig::Signers;
use robodr_pkg::wire::{self, PackListing, Request, StreamFile, PACK_STREAM_FORMAT};

/// The bundle the harness reports are for.
pub fn bundle() -> VerifiedBundle {
    VerifiedBundle {
        manifest: BundleManifest {
            format: BUNDLE_FORMAT.into(),
            programme: PROGRAMME.into(),
            bundle_seq: 2,
            prev_bundle_hash: Some("cd".repeat(32)),
            created_at: NOW - 100,
            rpks: vec![BundleRpk {
                dir: "rpk_nav_7_arm64".into(),
                name: "nav".into(),
                serial: 7,
                arch: Arch::Arm64,
                digest: "ab".repeat(32),
            }],
            files: vec![],
            parity: None,
        },
        hash: "ef".repeat(32),
        signers: Signers::default(),
    }
}

pub fn report() -> EntryReport {
    EntryReport {
        format: ENTRY_FORMAT.into(),
        site: SITE.into(),
        station: "entry-1".into(),
        programme: PROGRAMME.into(),
        bundle_seq: 2,
        bundle_hash: "ef".repeat(32),
        scanned_at: NOW - 60,
        expires_at: NOW + 86_400,
        vulndb: None,
        rpks: vec![RpkScan {
            digest: "ab".repeat(32),
            name: "nav".into(),
            serial: 7,
            sbom: None,
            vulnerabilities: vec![],
        }],
        fail_on: Severity::High,
        verdict: Verdict::Pass,
    }
}

pub fn run(data: &[u8]) {
    let Some((&sel, doc)) = data.split_first() else {
        return;
    };
    match sel % 4 {
        0 => report_doc(doc),
        1 => {
            if let Ok((l, total)) = wire::parse_listing(doc) {
                assert_eq!(to_canonical(&l).expect("ser"), doc);
                assert!(total <= wire::MAX_PACK_BYTES);
                assert!(l.files.windows(2).all(|w| w[0].path < w[1].path));
                for f in &l.files {
                    assert!(wire::is_pack_path(&f.path));
                    assert!(!f.path.contains(".."));
                }
            }
        }
        2 => match wire::parse_request(doc) {
            Ok(Request::Report(n)) => assert!(n > 0 && n <= wire::MAX_REQUEST_BODY),
            Ok(Request::Pack) | Err(_) => {}
        },
        _ => {
            let _ = wire::parse_response(doc);
        }
    }
}

fn report_doc(doc: &[u8]) {
    let parts = split(doc, 2);
    if let Ok(r) = entry::parse_entry_report(parts[0]) {
        assert_eq!(to_canonical(&r).expect("ser"), parts[0]);
        assert!(r.scanned_at < r.expires_at);
        assert!(r.expires_at - r.scanned_at <= entry::MAX_REPORT_LIFETIME_S);
    }
    let Some(sig) = parts.get(1) else {
        return;
    };
    if let Ok(v) = entry::verify_entry_report(parts[0], sig, trust(), &bundle(), NOW) {
        let r = &v.report;
        assert_eq!(r.site, SITE);
        assert_eq!(r.bundle_hash, bundle().hash);
        assert_eq!(r.verdict, Verdict::Pass);
        assert!(r.worst().is_none_or(|w| w < r.fail_on));
        assert_eq!(v.signers.count(robodr_pkg::sig::Role::Entry), 1);
    }
}

/// Seeds: a signed passing report, a listing, both requests, a response.
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    let doc = to_canonical(&report()).expect("ser");
    let sig = sign(&doc, entry::ENTRY_SIG_DOMAIN, &[&entry()]);
    let mut listing = PackListing {
        format: PACK_STREAM_FORMAT.into(),
        files: [
            "deployment.json",
            "deployment.json.sig",
            "trust.json",
            "trust.json.sig",
        ]
        .iter()
        .map(|p| StreamFile {
            path: (*p).into(),
            size: 10,
            sha256: "ab".repeat(32),
        })
        .collect(),
    };
    listing.files.push(StreamFile {
        path: "bundles/b0/bundle.json".into(),
        size: 5,
        sha256: "cd".repeat(32),
    });
    listing.files.sort_by(|a, b| a.path.cmp(&b.path));
    let with = |sel: u8, b: Vec<u8>| [vec![sel], b].concat();
    vec![
        ("report.bin", with(0, join(&[&doc, &sig]))),
        ("listing.bin", with(1, to_canonical(&listing).expect("ser"))),
        (
            "get.bin",
            with(2, wire::encode_request(Request::Pack, "depot")),
        ),
        (
            "post.bin",
            with(2, wire::encode_request(Request::Report(42), "depot")),
        ),
        ("response.bin", with(3, wire::encode_response(200, 7))),
    ]
}
