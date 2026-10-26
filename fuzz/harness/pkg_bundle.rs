//! Harness: bundle manifest, its signature set and the chain checks
//! (`robodr_pkg::bundle`, `::parity::plan`).
//!
//! Input: `bundle.json \0 bundle.sig`. Invariants beyond "no panic":
//!
//! * a bundle that parses is exactly its canonical encoding; every listed
//!   path classifies under the fixed grammar (no traversal is
//!   expressible); every RPK has its manifest and signature listed; the
//!   parity plan exists iff a parity section does, and covers every file
//!   exactly once;
//! * `bundle_hash` is deterministic and differs from the plain SHA-256;
//! * a bundle that verifies against the harness site carries the release
//!   quorum and a programme the site accepts;
//! * chain decisions follow the rules: from genesis only `bundle_seq` 1 is
//!   next; against a head `h`, `seq == h` is accepted only for the same
//!   hash, `seq < h` is a replay, `seq > h + 1` a gap, and `seq == h + 1`
//!   is next only when `prev_bundle_hash` is the head's hash.
//!
//! Shared via `#[path]` with `crates/robodr-pkg/tests/fuzz_smoke.rs`.
#![allow(dead_code)]

#[path = "pkg_common.rs"]
mod pkg_common;

use pkg_common::*;
use robodr_pkg::bundle::{
    self, bundle_hash, check_chain, classify, BundleManifest, ChainAnchor, ChainState, ChainStep,
    VerifiedBundle,
};
use robodr_pkg::common::{is_hex64, sha256_hex, to_canonical};
use robodr_pkg::sig::{Role, SignatureSet, Signers};
use robodr_pkg::Code;

pub fn run(data: &[u8]) {
    let parts = split(data, 2);
    let doc = parts[0];
    let h = bundle_hash(doc);
    assert!(is_hex64(&h));
    assert_ne!(h, sha256_hex(doc));
    if let Ok(b) = bundle::parse_bundle(doc) {
        check_bundle(&b, doc, &h);
    }
    if let Some(sig) = parts.get(1) {
        if let Ok(v) = bundle::verify_bundle_manifest(doc, sig, trust()) {
            assert!(v.signers.count(Role::Release) >= 2);
            assert!(trust().accepts_programme(&v.manifest.programme));
            for r in &v.manifest.rpks {
                assert_eq!(
                    trust().programme_of_package(&r.name),
                    Some(v.manifest.programme.as_str())
                );
            }
            assert_eq!(v.hash, h);
            let set = SignatureSet::parse(sig).expect("parses");
            assert_eq!(set.to_bytes().expect("ser"), *sig);
        }
    }
}

fn check_bundle(b: &BundleManifest, doc: &[u8], h: &str) {
    assert_eq!(to_canonical(b).expect("serialises"), doc);
    for f in &b.files {
        assert!(classify(&f.path).is_some(), "{}", f.path);
        assert!(!f.path.contains(".."));
        assert!(!f.path.starts_with('/'));
    }
    for r in &b.rpks {
        let under = b.files_under(&r.dir);
        assert!(under.contains_key("MANIFEST.json") && under.contains_key("MANIFEST.sig"));
    }
    match &b.parity {
        None => assert!(robodr_pkg::parity::plan(b).is_err()),
        Some(_) => {
            let groups = robodr_pkg::parity::plan(b).expect("validated parity plans");
            let mut seen = vec![0u8; b.files.len()];
            for g in &groups {
                for i in g.members() {
                    seen[i] += 1;
                }
            }
            assert!(
                seen.iter().all(|&n| n == 1),
                "every file in exactly one group"
            );
        }
    }
    // Chain rules against a few heads.
    let v = VerifiedBundle {
        manifest: b.clone(),
        hash: h.to_string(),
        signers: Signers::default(),
    };
    let seq = b.bundle_seq;
    let g = check_chain(&ChainAnchor::Genesis, &v);
    assert_eq!(g.is_ok(), seq == 1);
    for head_seq in [seq.saturating_sub(1).max(1), seq, seq + 1, 1] {
        for head_hash in [
            b.prev_bundle_hash
                .clone()
                .unwrap_or_else(|| "00".repeat(32)),
            h.to_string(),
        ] {
            let head = ChainState {
                format: bundle::CHAIN_FORMAT.into(),
                site: SITE.into(),
                programme: b.programme.clone(),
                bundle_seq: head_seq,
                bundle_hash: head_hash.clone(),
                trust_version: 1,
                trust_digest: "00".repeat(32),
            };
            let r = check_chain(&ChainAnchor::Head(head), &v);
            match r {
                Ok(ChainStep::AlreadyAccepted) => assert!(seq == head_seq && head_hash == h),
                Ok(ChainStep::Next) => {
                    assert_eq!(seq, head_seq + 1);
                    assert_eq!(b.prev_bundle_hash.as_deref(), Some(head_hash.as_str()));
                }
                Err(e) => match e.code {
                    Code::Replay => assert!(seq < head_seq),
                    Code::Equivocation => assert!(seq == head_seq && head_hash != h),
                    Code::ChainGap => assert!(seq > head_seq + 1),
                    Code::ChainBroken => assert_eq!(seq, head_seq + 1),
                    c => panic!("unexpected chain refusal {c:?}"),
                },
            }
        }
    }
}

/// Seeds: a one-RPK bundle with parity signed by the release quorum, and
/// a chained bundle 2 without parity signed by one key.
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    use robodr_pkg::bundle::*;
    use robodr_pkg::parity::{layout, parity_path, PARITY_SCHEME};
    let rel = release();
    let dir = "rpk_nav-stack_7_arm64";
    let c1 = sha256_hex(b"chunk-1");
    let c2 = sha256_hex(b"chunk-2");
    let mut files = vec![
        BundleFile {
            path: format!("{dir}/MANIFEST.json"),
            size: 900,
            sha256: sha256_hex(b"m"),
        },
        BundleFile {
            path: format!("{dir}/MANIFEST.sig"),
            size: 300,
            sha256: sha256_hex(b"s"),
        },
        BundleFile {
            path: format!("{dir}/chunks/{c1}"),
            size: 7,
            sha256: c1.clone(),
        },
        BundleFile {
            path: format!("{dir}/chunks/{c2}"),
            size: 7,
            sha256: c2.clone(),
        },
    ];
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let sizes: Vec<u64> = files.iter().map(|f| f.size).collect();
    let lay = layout(&sizes, 2, 2, 512).expect("layout");
    let mut all = files.clone();
    for (g, (_, len)) in lay.iter().enumerate() {
        for j in 1..=2 {
            all.push(BundleFile {
                path: parity_path(g + 1, j),
                size: *len,
                sha256: sha256_hex(&[g as u8, j as u8]),
            });
        }
    }
    all.sort_by(|a, b| a.path.cmp(&b.path));
    let b1 = BundleManifest {
        format: BUNDLE_FORMAT.into(),
        programme: PROGRAMME.into(),
        bundle_seq: 1,
        prev_bundle_hash: None,
        created_at: 1_790_000_000,
        rpks: vec![BundleRpk {
            dir: dir.into(),
            name: "nav-stack".into(),
            serial: 7,
            arch: robodr_pkg::rpk::Arch::Arm64,
            digest: sha256_hex(b"digest"),
        }],
        files: all,
        parity: Some(BundleParity {
            scheme: PARITY_SCHEME.into(),
            data_shards: 2,
            parity_shards: 2,
            shard_size: 512,
            groups: lay.len() as u32,
        }),
    };
    let d1 = to_canonical(&b1).expect("canonical");
    let s1 = sign(&d1, BUNDLE_SIG_DOMAIN, &[&rel[0], &rel[1]]);
    let mut b2 = b1.clone();
    b2.bundle_seq = 2;
    b2.prev_bundle_hash = Some(bundle_hash(&d1));
    b2.parity = None;
    b2.files = files;
    let d2 = to_canonical(&b2).expect("canonical");
    let s2 = sign(&d2, BUNDLE_SIG_DOMAIN, &[&rel[1]]);
    vec![
        ("seed-b1-parity-quorum.bin", join(&[&d1, &s1])),
        ("seed-b2-one-sig.bin", join(&[&d2, &s2])),
    ]
}
