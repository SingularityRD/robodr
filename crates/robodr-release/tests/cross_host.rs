//! Sprint 13a exit criterion, end to end through the `robodr-release`
//! binary: a bundle built and signed on one host verifies on another.
//!
//! "Host A" (the connected side) generates keys, writes and root-signs the
//! site trust file, builds an RPK (a 9 MiB file: three 4 MiB chunks, plus
//! a CycloneDX SBOM), has two release keys sign it, assembles a bundle with
//! parity and has two release keys sign that. Only the bundle directory
//! and the trust file (with its signature) are copied to "host B" (another
//! directory tree; nothing else of A is reachable from it), which verifies
//! with nothing but the pinned root fingerprints, commits the chain head,
//! then accepts the next bundle, refuses a replay and a gap, and repairs a
//! damaged bundle from its parity. A third tree rebuilds the RPK and gets
//! the same bytes (reproducible builds).

mod common;

use common::{bytes, copy_tree, Tmp};
use robodr_blackbox::KeyFile;
use robodr_pkg::common::to_canonical;
use robodr_pkg::trust::{Quorum, TrustFile, TrustKey, TRUST_FORMAT};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_robodr-release");
const NOW: &str = "1790000000";

/// Run the binary; returns (exit code, stdout JSON or Null, stderr).
fn run(args: &[&str]) -> (i32, Value, String) {
    let o = Command::new(BIN).args(args).output().unwrap();
    let stdout = String::from_utf8(o.stdout).unwrap();
    let stderr = String::from_utf8(o.stderr).unwrap();
    let v = serde_json::from_str(&stdout).unwrap_or(Value::Null);
    (o.status.code().unwrap_or(-1), v, stderr)
}

fn ok(args: &[&str]) -> Value {
    let (c, v, e) = run(args);
    assert_eq!(c, 0, "{args:?} failed: {e}");
    v
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

struct HostA {
    dir: PathBuf,
    keys: PathBuf,
    pins: Vec<String>,
    trust: PathBuf,
}

fn keygen(h: &Path, id: &str) -> (PathBuf, String) {
    let p = h.join(format!("{id}.key"));
    let v = ok(&["keygen", "--out", s(&p), "--key-id", id]);
    let f = v["fingerprint"].as_str().unwrap().to_string();
    // `fingerprint` of the public file agrees.
    let v2 = ok(&["fingerprint", "--key", &format!("{}.pub", p.display())]);
    assert_eq!(v2["fingerprint"], f);
    (p, f)
}

fn trust_key(path: &Path, id: &str) -> TrustKey {
    let k = KeyFile::load_public(&PathBuf::from(format!("{}.pub", path.display()))).unwrap();
    TrustKey::new(id, &k.public_key().unwrap())
}

fn host_a(tmp: &Tmp) -> HostA {
    let dir = tmp.path().join("host-a");
    let keys = dir.join("keys");
    fs::create_dir_all(&keys).unwrap();
    let mut pins = Vec::new();
    for r in ["root-1", "root-2", "root-3"] {
        pins.push(keygen(&keys, r).1);
    }
    for r in ["rel-a", "rel-b", "rel-c", "depot-1", "op-1", "op-2"] {
        keygen(&keys, r);
    }
    let tk = |id: &str| trust_key(&keys.join(format!("{id}.key")), id);
    let t = TrustFile {
        format: TRUST_FORMAT.into(),
        site: "site-a".into(),
        version: 1,
        issued_at: 1_790_000_000,
        programmes: vec!["ugv-x1".into()],
        quorum: Quorum {
            root: 2,
            release: 2,
            operator_prod: 2,
            operator_lab: 1,
        },
        roots: ["root-1", "root-2", "root-3"]
            .iter()
            .map(|i| tk(i))
            .collect(),
        release_keys: ["rel-a", "rel-b", "rel-c"].iter().map(|i| tk(i)).collect(),
        depot_keys: vec![tk("depot-1")],
        operator_keys: vec![tk("op-1"), tk("op-2")],
        revoked_keys: vec![],
        revoked_rpks: vec![],
        floors: vec![],
    };
    let trust = dir.join("trust.json");
    fs::write(&trust, to_canonical(&t).unwrap()).unwrap();
    // One root is not enough; two are.
    ok(&[
        "sign",
        "--key",
        s(&keys.join("root-1.key")),
        "--target",
        s(&trust),
    ]);
    let mut v = vec!["verify", "trust", "--trust", s(&trust)];
    for p in &pins {
        v.extend(["--root", p]);
    }
    let (c, _, e) = run(&v);
    assert_eq!(c, 1);
    assert!(e.contains("refused (quorum_not_met)"), "{e}");
    ok(&[
        "sign",
        "--key",
        s(&keys.join("root-3.key")),
        "--target",
        s(&trust),
    ]);
    ok(&v);
    HostA {
        dir,
        keys,
        pins,
        trust,
    }
}

const SPEC: &str = r#"{
  "format": "robodr-rpk-spec/1",
  "name": "nav-stack",
  "version": {"serial": 7, "display": "1.7.0"},
  "kind": "files",
  "platform": "ugv-x1",
  "arch": "arm64",
  "security_floor": 5,
  "install": {"allow_maintainer_scripts": false, "requires_operator_present": false},
  "health": [{"check": "service_active", "unit": "nav.service"}],
  "sbom_path": "sbom.cdx.json"
}"#;

fn build_rpk(host: &Path, serial: u64, big: &[u8]) -> PathBuf {
    let pl = host.join(format!("payload-{serial}"));
    fs::create_dir_all(pl.join("bin")).unwrap();
    fs::write(pl.join("bin/nav"), big).unwrap();
    fs::write(
        pl.join("sbom.cdx.json"),
        br#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}"#,
    )
    .unwrap();
    let spec = host.join(format!("spec-{serial}.json"));
    fs::write(
        &spec,
        SPEC.replace("\"serial\": 7", &format!("\"serial\": {serial}")),
    )
    .unwrap();
    let out = host.join("out");
    fs::create_dir_all(&out).unwrap();
    let v = ok(&[
        "build",
        "rpk",
        "--spec",
        s(&spec),
        "--payload",
        s(&pl),
        "--out-dir",
        s(&out),
    ]);
    PathBuf::from(v["rpk"].as_str().unwrap())
}

fn release_sign(a: &HostA, target: &Path, ids: &[&str]) {
    for id in ids {
        ok(&[
            "sign",
            "--key",
            s(&a.keys.join(format!("{id}.key"))),
            "--target",
            s(target),
        ]);
    }
}

fn with_pins<'a>(mut v: Vec<&'a str>, pins: &'a [String]) -> Vec<&'a str> {
    for p in pins {
        v.extend(["--root", p.as_str()]);
    }
    v
}

#[test]
fn a_bundle_built_on_one_host_verifies_on_another() {
    let tmp = Tmp::new("xhost");
    let a = host_a(&tmp);
    let big = bytes(42, 9 * 1024 * 1024 + 123);

    // --- Host A: RPK, quorum signatures, bundle 1 with parity, signatures.
    let rpk = build_rpk(&a.dir, 7, &big);
    assert_eq!(fs::read_dir(rpk.join("chunks")).unwrap().count(), 4); // 3 + SBOM
    release_sign(&a, &rpk, &["rel-a", "rel-b"]);
    ok(&with_pins(
        vec![
            "verify",
            "rpk",
            "--dir",
            s(&rpk),
            "--trust",
            s(&a.trust),
            "--now",
            NOW,
        ],
        &a.pins,
    ));
    let b1 = a.dir.join("bundle-0001");
    let v = ok(&with_pins(
        vec![
            "build",
            "bundle",
            "--programme",
            "ugv-x1",
            "--seq",
            "1",
            "--rpk",
            s(&rpk),
            "--trust",
            s(&a.trust),
            "--parity",
            "2",
            "--parity-group",
            "4",
            "--shard-size",
            "65536",
            "--created-at",
            NOW,
            "--now",
            NOW,
            "--out",
            s(&b1),
        ],
        &a.pins,
    ));
    assert_eq!(v["parity"], true);
    release_sign(&a, &b1, &["rel-b", "rel-c"]);

    // --- Host B: only the bundle and the trust file cross.
    let hb = tmp.path().join("host-b");
    fs::create_dir_all(&hb).unwrap();
    copy_tree(&b1, &hb.join("media/bundle-0001"));
    fs::copy(&a.trust, hb.join("trust.json")).unwrap();
    fs::copy(
        format!("{}.sig", a.trust.display()),
        hb.join("trust.json.sig"),
    )
    .unwrap();
    let state = hb.join("chain-ugv-x1.json");
    let tb = hb.join("trust.json");
    let verify_b = |bundle: &Path, extra: &[&str]| {
        let mut v = vec![
            "verify",
            "bundle",
            "--dir",
            s(bundle),
            "--trust",
            s(&tb),
            "--now",
            NOW,
        ];
        v.extend_from_slice(extra);
        run(&with_pins(v, &a.pins))
    };
    // No chain mode: usage error. A missing state without --genesis too.
    assert_eq!(verify_b(&hb.join("media/bundle-0001"), &[]).0, 2);
    assert_eq!(
        verify_b(&hb.join("media/bundle-0001"), &["--state", s(&state)]).0,
        2
    );
    let (c, v, e) = verify_b(
        &hb.join("media/bundle-0001"),
        &["--state", s(&state), "--genesis", "--commit"],
    );
    assert_eq!(c, 0, "{e}");
    assert_eq!(v["chain"], "next");
    assert_eq!(v["state_committed"], true);
    assert_eq!(v["rpks"][0]["name"], "nav-stack");
    let h1 = v["bundle_hash"].as_str().unwrap().to_string();
    // Again: already accepted, state unchanged.
    let (c, v, _) = verify_b(
        &hb.join("media/bundle-0001"),
        &["--state", s(&state), "--commit"],
    );
    assert_eq!(c, 0);
    assert_eq!(v["chain"], "already_accepted");
    // Wrong pins: refused.
    let (c, _, e) = run(&[
        "verify",
        "bundle",
        "--dir",
        s(&hb.join("media/bundle-0001")),
        "--trust",
        s(&tb),
        "--genesis",
        "--root",
        &a.pins[0],
        "--root",
        &a.pins[1],
    ]);
    assert_eq!(c, 1);
    assert!(e.contains("refused (unknown_key)"), "{e}");

    // --- Host C: the same spec and payload give the same RPK bytes.
    let hc = tmp.path().join("host-c-elsewhere");
    fs::create_dir_all(&hc).unwrap();
    let rpk_c = build_rpk(&hc, 7, &big);
    assert_eq!(
        fs::read(rpk.join("MANIFEST.json")).unwrap(),
        fs::read(rpk_c.join("MANIFEST.json")).unwrap()
    );

    // --- Bundle 2 (chained with --prev-bundle), then replay and gap on B.
    let rpk8 = build_rpk(&a.dir, 8, &big[..1000]);
    release_sign(&a, &rpk8, &["rel-a", "rel-c"]);
    let b2 = a.dir.join("bundle-0002");
    ok(&with_pins(
        vec![
            "build",
            "bundle",
            "--programme",
            "ugv-x1",
            "--seq",
            "2",
            "--prev-bundle",
            s(&b1),
            "--rpk",
            s(&rpk8),
            "--trust",
            s(&a.trust),
            "--parity",
            "1",
            "--now",
            NOW,
            "--out",
            s(&b2),
        ],
        &a.pins,
    ));
    release_sign(&a, &b2, &["rel-a", "rel-b"]);
    let b3 = a.dir.join("bundle-0003");
    let h2 = {
        // Learn bundle 2's hash from a --after verification on A.
        let (c, v, e) = run(&with_pins(
            vec![
                "verify",
                "bundle",
                "--dir",
                s(&b2),
                "--trust",
                s(&a.trust),
                "--now",
                NOW,
                "--after",
                &format!("1:{h1}"),
            ],
            &a.pins,
        ));
        assert_eq!(c, 0, "{e}");
        v["bundle_hash"].as_str().unwrap().to_string()
    };
    ok(&with_pins(
        vec![
            "build",
            "bundle",
            "--programme",
            "ugv-x1",
            "--seq",
            "3",
            "--prev-hash",
            &h2,
            "--rpk",
            s(&rpk8),
            "--trust",
            s(&a.trust),
            "--now",
            NOW,
            "--out",
            s(&b3),
        ],
        &a.pins,
    ));
    release_sign(&a, &b3, &["rel-b", "rel-c"]);
    copy_tree(&b2, &hb.join("media/bundle-0002"));
    copy_tree(&b3, &hb.join("media/bundle-0003"));
    // Gap: 3 while B's head is 1.
    let (c, _, e) = verify_b(
        &hb.join("media/bundle-0003"),
        &["--state", s(&state), "--commit"],
    );
    assert_eq!(c, 1);
    assert!(e.contains("refused (chain_gap)"), "{e}");
    // Damage bundle 2 on B: verify refuses, repair rebuilds from parity.
    let chunk = fs::read_dir(hb.join("media/bundle-0002/rpk_nav-stack_8_arm64/chunks"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    fs::remove_file(&chunk).unwrap();
    let (c, _, e) = verify_b(&hb.join("media/bundle-0002"), &["--state", s(&state)]);
    assert_eq!(c, 1);
    assert!(e.contains("refused (missing_file)"), "{e}");
    let v = ok(&with_pins(
        vec![
            "repair",
            "--dir",
            s(&hb.join("media/bundle-0002")),
            "--trust",
            s(&tb),
        ],
        &a.pins,
    ));
    assert_eq!(v["rebuilt"].as_array().unwrap().len(), 1);
    let (c, v, e) = verify_b(
        &hb.join("media/bundle-0002"),
        &["--state", s(&state), "--commit"],
    );
    assert_eq!(c, 0, "{e}");
    assert_eq!(v["chain"], "next");
    // Replay of bundle 1 after 2.
    let (c, _, e) = verify_b(&hb.join("media/bundle-0001"), &["--state", s(&state)]);
    assert_eq!(c, 1);
    assert!(e.contains("refused (replay)"), "{e}");
    // And 3 is now next.
    let (c, v, e) = verify_b(
        &hb.join("media/bundle-0003"),
        &["--state", s(&state), "--commit"],
    );
    assert_eq!(c, 0, "{e}");
    assert_eq!(v["bundle_seq"], 3);
}

#[test]
fn cli_usage_and_version() {
    let (c, v, _) = run(&["--version"]);
    assert_eq!(c, 0);
    assert_eq!(v, Value::Null);
    assert_eq!(run(&["--help"]).0, 0);
    assert_eq!(run(&[]).0, 2);
    assert_eq!(run(&["frobnicate"]).0, 2);
    assert_eq!(run(&["verify"]).0, 2);
    assert_eq!(run(&["verify", "bundle", "--dir", "x"]).0, 2);
    assert_eq!(
        run(&["verify", "trust", "--trust", "x", "--root", "nope"]).0,
        2
    );
    assert_eq!(
        run(&["sign", "--key", "/nonexistent", "--target", "/nonexistent"]).0,
        1
    );
}
