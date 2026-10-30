//! Harness: RPK manifest + signature set (`robodr_pkg::rpk`, `::sig`).
//!
//! Input: `MANIFEST.json \0 MANIFEST.sig`. Invariants beyond "no panic":
//!
//! * a manifest that parses is exactly its canonical encoding, validates,
//!   and its directory name is a valid bundle RPK directory; every content
//!   file's chunk sizes add up to its size (less the per-chunk overhead
//!   for a sealed file, each of whose chunks is used once); the payload
//!   files are the content minus at most the SBOM; a sealed manifest has
//!   a seal and a public one none;
//! * `rpk_digest` is deterministic, 64 hex, never the plain SHA-256;
//! * a signature set that parses is its canonical encoding;
//! * a manifest that verifies against the harness site is signed by at
//!   least the release quorum of distinct keys and has the parsed digest;
//! * `verify_content` with a chunk source that returns nothing never
//!   accepts a manifest that has content bytes.
//!
//! Shared via `#[path]` with `crates/robodr-pkg/tests/fuzz_smoke.rs`.
#![allow(dead_code)]

#[path = "pkg_common.rs"]
mod pkg_common;

use pkg_common::*;
use robodr_pkg::common::{is_hex64, sha256_hex, to_canonical};
use robodr_pkg::rpk::{self, Manifest, MANIFEST_SIG_DOMAIN};
use robodr_pkg::sig::{Role, SignatureSet};
use robodr_pkg::{Code, Refusal};

pub fn run(data: &[u8]) {
    let parts = split(data, 2);
    let doc = parts[0];
    let sig = parts.get(1).copied();
    let d = rpk::rpk_digest(doc);
    assert!(is_hex64(&d));
    assert_eq!(d, rpk::rpk_digest(doc));
    assert_ne!(d, sha256_hex(doc));
    if let Ok(m) = rpk::parse_manifest(doc) {
        check_manifest(&m, doc);
    }
    let Some(sig) = sig else {
        return;
    };
    if let Ok(s) = SignatureSet::parse(sig) {
        assert_eq!(s.to_bytes().expect("serialises"), sig);
    }
    if let Ok(v) = rpk::verify_manifest(doc, sig, trust(), NOW) {
        assert!(v.signers.count(Role::Release) >= trust().file().quorum.release as usize);
        assert_eq!(v.digest, d);
        // Signed by the release keys of the programme owning the name.
        assert_eq!(
            trust().programme_of_package(&v.manifest.name),
            Some(v.programme.as_str())
        );
        // The signature really is over the domain-separated bytes.
        let set = SignatureSet::parse(sig).expect("verified set parses");
        assert!(set
            .check(trust(), &[Role::Release], MANIFEST_SIG_DOMAIN, doc)
            .is_ok());
    }
}

fn check_manifest(m: &Manifest, doc: &[u8]) {
    assert_eq!(to_canonical(m).expect("serialises"), doc);
    m.validate().expect("a parsed manifest validates");
    assert!(
        robodr_pkg::bundle::is_rpk_dir(&m.dir_name()),
        "{}",
        m.dir_name()
    );
    assert_eq!(m.is_sealed(), m.seal.is_some());
    for f in &m.content {
        let over = if m.is_sealed_file(f) {
            rpk::SEALED_CHUNK_OVERHEAD
        } else {
            0
        };
        let sum: u64 = f
            .chunks
            .iter()
            .map(|&i| m.chunks[i as usize].size - over)
            .sum();
        assert_eq!(sum, f.size);
    }
    if m.is_sealed() {
        let mut seen = std::collections::BTreeSet::new();
        for f in &m.content {
            for &i in &f.chunks {
                assert!(seen.insert(i), "a sealed RPK's chunk used twice");
            }
        }
    }
    let n = m.payload_files().count();
    assert!(n + 1 >= m.content.len() && n <= m.content.len());
    assert!(m.security_floor >= 1 && m.security_floor <= m.version.serial);
    let r = rpk::verify_content(m, &mut |_| Err(Refusal::new(Code::MissingFile, "none")));
    if m.content.iter().any(|f| f.size > 0) {
        assert!(r.is_err());
    }
}

/// Seeds: a two-file manifest signed by the release quorum, and an `.deb`
/// with an SBOM signed by one key (refused by quorum).
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    use robodr_pkg::rpk::*;
    let f = |p: &str, b: &[u8], mode: u32| (p.to_string(), b.to_vec(), mode);
    let mk = |kind: Kind, files: Vec<(String, Vec<u8>, u32)>, sbom: Option<&[u8]>| {
        let mut chunks: Vec<Chunk> = files
            .iter()
            .filter(|(_, b, _)| !b.is_empty())
            .map(|(_, b, _)| Chunk {
                sha256: sha256_hex(b),
                size: b.len() as u64,
            })
            .collect();
        chunks.sort_by(|a, b| a.sha256.cmp(&b.sha256));
        chunks.dedup();
        let mut content: Vec<ContentFile> = files
            .iter()
            .map(|(p, b, mode)| ContentFile {
                path: p.clone(),
                mode: *mode,
                size: b.len() as u64,
                sha256: sha256_hex(b),
                chunks: chunks
                    .iter()
                    .position(|c| c.sha256 == sha256_hex(b) && !b.is_empty())
                    .map(|i| vec![i as u32])
                    .unwrap_or_default(),
            })
            .collect();
        content.sort_by(|a, b| a.path.cmp(&b.path));
        Manifest {
            format: RPK_FORMAT.into(),
            name: "nav-stack".into(),
            version: Version {
                serial: 7,
                display: "1.7.0".into(),
            },
            kind,
            platform: "ugv-x1".into(),
            arch: Arch::Arm64,
            hw_compat: vec!["jetson-orin".into()],
            requires: vec![Dependency {
                name: "robodr-agentd".into(),
                min_serial: 3,
            }],
            conflicts: vec![],
            security_floor: 5,
            confidentiality: Confidentiality::Public,
            content,
            chunks,
            sbom: sbom.map(sha256_hex),
            install: Install {
                allow_maintainer_scripts: kind == Kind::Deb,
                requires_operator_present: false,
            },
            health: vec![
                HealthCheck::ServiceActive {
                    unit: "nav.service".into(),
                },
                HealthCheck::Probe {
                    argv: vec!["/usr/bin/nav-probe".into(), "--quick".into()],
                    user: "robodr-probe".into(),
                    timeout_s: 30,
                },
            ],
            expires_at: Some(1_900_000_000),
            seal: None,
        }
    };
    let rel = release();
    let files = mk(
        Kind::Files,
        vec![
            f("bin/nav", b"\x7fELF nav", 0o755),
            f("etc/nav.yaml", b"speed: 1\n", 0o644),
            f("empty", b"", 0o644),
        ],
        None,
    );
    let doc = to_canonical(&files).expect("canonical");
    let sig = sign(&doc, MANIFEST_SIG_DOMAIN, &[&rel[0], &rel[1]]);
    let sbom = br#"{"bomFormat":"CycloneDX","specVersion":"1.5"}"#;
    let deb = mk(
        Kind::Deb,
        vec![
            f("nav_1.7.0_arm64.deb", b"!<arch>\n", 0o644),
            f("sbom.cdx.json", sbom, 0o644),
        ],
        Some(sbom),
    );
    let ddoc = to_canonical(&deb).expect("canonical");
    let dsig = sign(&ddoc, MANIFEST_SIG_DOMAIN, &[&rel[0]]);
    // A sealed model: one sealed file (synthetic chunk hashes: the
    // parser judges sizes and structure, not ciphertext) and a clear SBOM.
    let mut sealed = mk(
        Kind::Model,
        vec![f("model.cdx.json", sbom, 0o644)],
        Some(sbom),
    );
    sealed.confidentiality = Confidentiality::Sealed;
    sealed.chunks.push(Chunk {
        sha256: "ee".repeat(32),
        size: 1000 + SEALED_CHUNK_OVERHEAD,
    });
    sealed.content.push(ContentFile {
        path: "weights.onnx".into(),
        mode: 0o640,
        size: 1000,
        sha256: "dd".repeat(32),
        chunks: vec![],
    });
    sealed.chunks.sort_by(|a, b| a.sha256.cmp(&b.sha256));
    let at = |h: &str, c: &[Chunk]| c.iter().position(|x| x.sha256 == h).map(|i| i as u32);
    let sbom_at = at(&sha256_hex(sbom), &sealed.chunks).into_iter().collect();
    let ee_at = at(&"ee".repeat(32), &sealed.chunks).into_iter().collect();
    sealed.content[0].chunks = sbom_at;
    sealed.content[1].chunks = ee_at;
    sealed.health.clear();
    sealed.seal = Some(Seal {
        scheme: SEAL_SCHEME.into(),
        seal_id: "aa".repeat(32),
        ck_commit: "bb".repeat(32),
        depot_wraps: vec![DepotWrap {
            recipient: format!("sha256:{}", "cc".repeat(32)),
            wrap: "01".repeat(105),
        }],
    });
    let sdoc = to_canonical(&sealed).expect("canonical");
    let ssig = sign(&sdoc, MANIFEST_SIG_DOMAIN, &[&rel[0], &rel[1]]);
    vec![
        ("seed-files-quorum.bin", join(&[&doc, &sig])),
        ("seed-deb-one-sig.bin", join(&[&ddoc, &dsig])),
        ("seed-sealed-model.bin", join(&[&sdoc, &ssig])),
    ]
}
