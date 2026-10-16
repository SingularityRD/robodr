//! End-to-end tests of profile versioning and signing in the
//! `robodr-commission` binary: `keygen`, `lock --sign-key / --parent`,
//! `sign`, `verify-profile` (incl. anti-rollback state) and
//! `migrate-legacy`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use robodr_commission::{file_digest, sealed_text, to_json, AcceptedState};

const BIN: &str = env!("CARGO_BIN_EXE_robodr-commission");

fn example(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join(name)
}

fn tmpdir(tag: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "robodr-commission-sig-{}-{}-{tag}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN).args(args).output().expect("run binary")
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn sig_of(p: &Path) -> PathBuf {
    PathBuf::from(format!("{}.sig", p.display()))
}

/// keygen into `dir`, returning (key, trust).
fn keygen(dir: &Path, name: &str) -> (PathBuf, PathBuf) {
    let key = dir.join(format!("{name}.key"));
    let trust = dir.join(format!("{name}.trust.json"));
    let o = run(&[
        "keygen",
        "--out",
        s(&key),
        "--trust-out",
        s(&trust),
        "--key-id",
        name,
    ]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    (key, trust)
}

/// Learn the clean example and confirm its sign-off.
fn draft(dir: &Path) -> (PathBuf, PathBuf) {
    let p = dir.join("draft.json");
    let o = run(&[
        "learn",
        "--events",
        s(&example("clean-run.jsonl")),
        "--model",
        "ugv-demo-synthetic",
        "--out",
        s(&p),
        "--quiet",
    ]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let so = PathBuf::from(format!("{}.signoff.json", p.display()));
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&so).unwrap()).unwrap();
    v["operator"] = "Test Operator".into();
    for i in v["items"].as_array_mut().unwrap() {
        i["confirmed"] = true.into();
    }
    std::fs::write(&so, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    (p, so)
}

fn verify(profile: &Path, trust: &Path, extra: &[&str]) -> Output {
    let mut a = vec![
        "verify-profile",
        "--profile",
        s(profile),
        "--trusted-keys",
        s(trust),
    ];
    a.extend_from_slice(extra);
    run(&a)
}

fn report(o: &Output) -> serde_json::Value {
    serde_json::from_str(&out(o)).unwrap_or_else(|e| panic!("{e}: {}", out(o)))
}

#[test]
fn keygen_lock_sign_verify_round_trip() {
    let d = tmpdir("rt");
    let (key, trust) = keygen(&d, "oem-a");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    // keygen never overwrites.
    let o = run(&["keygen", "--out", s(&key), "--trust-out", s(&d.join("t2"))]);
    assert_eq!(code(&o), 2);
    assert!(!d.join("t2").exists());

    let (p, so) = draft(&d);
    let locked = d.join("locked.json");
    let o = run(&[
        "lock",
        "--in",
        s(&p),
        "--signoff",
        s(&so),
        "--out",
        s(&locked),
        "--platform",
        "ugv-x1",
        "--unit-id",
        "ugv-007",
        "--profile-version",
        "7",
        "--locked-at",
        "1790000000",
        "--sign-key",
        s(&key),
    ]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert!(sig_of(&locked).exists());
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&locked).unwrap()).unwrap();
    let m = &v["metadata"];
    assert_eq!(m["schema_version"], 1);
    assert_eq!(m["profile_version"], 7);
    assert_eq!(m["platform"], "ugv-x1");
    assert_eq!(m["unit_id"], "ugv-007");
    assert_eq!(m["locked_by"], "Test Operator");
    assert_eq!(m["locked_at"], 1_790_000_000u64);
    assert!(m["parent_digest"].is_null());

    let o = verify(&locked, &trust, &["--json"]);
    assert_eq!(code(&o), 0, "{}", out(&o));
    let r = report(&o);
    assert_eq!(r["trusted"], true);
    assert_eq!(r["profile_version"], 7);
    assert_eq!(r["signed_by"], "oem-a");
    let digest = file_digest(&std::fs::read(&locked).unwrap());
    assert_eq!(r["digest"], digest.as_str());
    // Platform / unit expectations.
    assert_eq!(
        code(&verify(
            &locked,
            &trust,
            &["--expect-platform", "ugv-x1", "--expect-unit", "ugv-007"]
        )),
        0
    );
    let o = verify(&locked, &trust, &["--expect-unit", "ugv-008"]);
    assert_eq!(code(&o), 1);
    assert!(out(&o).contains("REFUSED"), "{}", out(&o));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn wrong_key_tampered_and_missing_signature_are_refused() {
    let d = tmpdir("neg");
    let (key, trust) = keygen(&d, "oem-a");
    let (_, other_trust) = keygen(&d, "oem-b");
    let (p, so) = draft(&d);
    let locked = d.join("locked.json");
    let o = run(&[
        "lock",
        "--in",
        s(&p),
        "--signoff",
        s(&so),
        "--out",
        s(&locked),
        "--platform",
        "ugv",
        "--profile-version",
        "1",
        "--sign-key",
        s(&key),
    ]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    // Wrong trust anchors.
    let o = verify(&locked, &other_trust, &[]);
    assert_eq!(code(&o), 1);
    assert!(out(&o).contains("not a trusted profile key"), "{}", out(&o));
    // Tampered profile bytes (one extra space: same JSON value, different
    // bytes).
    let orig = std::fs::read_to_string(&locked).unwrap();
    std::fs::write(
        &locked,
        orig.replacen("\"locked\": true", "\"locked\":  true", 1),
    )
    .unwrap();
    let o = verify(&locked, &trust, &[]);
    assert_eq!(code(&o), 1, "{}", out(&o));
    // Tampered signature.
    std::fs::write(&locked, &orig).unwrap();
    let sig = std::fs::read_to_string(sig_of(&locked)).unwrap();
    let mut sv: serde_json::Value = serde_json::from_str(&sig).unwrap();
    let mut hex = sv["signature_hex"].as_str().unwrap().to_string();
    let flipped = if hex.ends_with('0') { "1" } else { "0" };
    hex.replace_range(hex.len() - 1.., flipped);
    sv["signature_hex"] = hex.into();
    std::fs::write(sig_of(&locked), to_json(&sv).unwrap()).unwrap();
    let o = verify(&locked, &trust, &[]);
    assert_eq!(code(&o), 1);
    assert!(out(&o).contains("does not verify"), "{}", out(&o));
    // Missing signature.
    std::fs::remove_file(sig_of(&locked)).unwrap();
    let o = verify(&locked, &trust, &[]);
    assert_eq!(code(&o), 1);
    assert!(out(&o).contains("no signature file"), "{}", out(&o));
    // `sign` restores it.
    let o = run(&["sign", "--profile", s(&locked), "--sign-key", s(&key)]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert_eq!(code(&verify(&locked, &trust, &[])), 0);
    // `sign` refuses drafts; trust file is required.
    let o = run(&["sign", "--profile", s(&p), "--sign-key", s(&key), "--force"]);
    assert_eq!(code(&o), 2);
    let o = run(&["verify-profile", "--profile", s(&locked)]);
    assert_eq!(code(&o), 2);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn lineage_parent_versions_and_rollback_state() {
    let d = tmpdir("lineage");
    let (key, trust) = keygen(&d, "oem-a");
    let (p, so) = draft(&d);
    let v1 = d.join("v1.json");
    let o = run(&[
        "lock",
        "--in",
        s(&p),
        "--signoff",
        s(&so),
        "--out",
        s(&v1),
        "--platform",
        "ugv",
        "--profile-version",
        "1",
        "--sign-key",
        s(&key),
    ]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let v1_digest = file_digest(&std::fs::read(&v1).unwrap());

    // Parent with a version that is not higher: usage error.
    let v2 = d.join("v2.json");
    let o = run(&[
        "lock",
        "--in",
        s(&p),
        "--signoff",
        s(&so),
        "--out",
        s(&v2),
        "--parent",
        s(&v1),
        "--profile-version",
        "1",
        "--sign-key",
        s(&key),
    ]);
    assert_eq!(code(&o), 2);
    assert!(err(&o).contains("must be higher"), "{}", err(&o));
    // Different platform than the parent: usage error.
    let o = run(&[
        "lock",
        "--in",
        s(&p),
        "--signoff",
        s(&so),
        "--out",
        s(&v2),
        "--parent",
        s(&v1),
        "--platform",
        "drone",
        "--sign-key",
        s(&key),
    ]);
    assert_eq!(code(&o), 2);
    // Neither parent nor platform/version.
    let o = run(&["lock", "--in", s(&p), "--signoff", s(&so), "--out", s(&v2)]);
    assert_eq!(code(&o), 2);
    assert!(err(&o).contains("required"), "{}", err(&o));
    assert!(!v2.exists());
    // Default: parent + 1, platform inherited, parent digest recorded; the
    // parent's own signature is checked when --trusted-keys is given.
    let o = run(&[
        "lock",
        "--in",
        s(&p),
        "--signoff",
        s(&so),
        "--out",
        s(&v2),
        "--parent",
        s(&v1),
        "--trusted-keys",
        s(&trust),
        "--sign-key",
        s(&key),
    ]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&v2).unwrap()).unwrap();
    assert_eq!(m["metadata"]["profile_version"], 2);
    assert_eq!(m["metadata"]["platform"], "ugv");
    assert_eq!(m["metadata"]["parent_digest"], v1_digest.as_str());
    let v2_digest = file_digest(&std::fs::read(&v2).unwrap());

    // Anti-rollback against a state that accepted v2.
    let state = d.join("state.json");
    let st = AcceptedState {
        format: robodr_commission::trust::STATE_FORMAT.into(),
        model: "ugv-demo-synthetic".into(),
        platform: "ugv".into(),
        unit_id: None,
        profile_version: 2,
        digest: v2_digest.clone(),
    };
    std::fs::write(&state, to_json(&st).unwrap()).unwrap();
    let before = std::fs::read(&state).unwrap();
    let o = verify(&v1, &trust, &["--state", s(&state), "--json"]);
    assert_eq!(code(&o), 1);
    assert!(report(&o)["refused"]
        .as_str()
        .unwrap()
        .contains("rollback refused"));
    let o = verify(
        &v1,
        &trust,
        &["--state", s(&state), "--allow-rollback", &v1_digest],
    );
    assert_eq!(code(&o), 0, "{}", out(&o));
    assert!(out(&o).contains("OperatorRollback"), "{}", out(&o));
    // The flag must be a digest, and naming another file does not help.
    let o = verify(
        &v1,
        &trust,
        &["--state", s(&state), "--allow-rollback", "1"],
    );
    assert_eq!(code(&o), 2);
    let o = verify(
        &v1,
        &trust,
        &["--state", s(&state), "--allow-rollback", &v2_digest],
    );
    assert_eq!(code(&o), 1);
    assert_eq!(code(&verify(&v2, &trust, &["--state", s(&state)])), 0);
    // verify-profile is read-only.
    assert_eq!(std::fs::read(&state).unwrap(), before);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn unsigned_lock_warns_and_legacy_migration() {
    let d = tmpdir("legacy");
    let (key, trust) = keygen(&d, "oem-a");
    let (p, so) = draft(&d);
    let unsigned = d.join("unsigned.json");
    let o = run(&[
        "lock",
        "--in",
        s(&p),
        "--signoff",
        s(&so),
        "--out",
        s(&unsigned),
        "--platform",
        "ugv",
        "--profile-version",
        "1",
    ]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert!(err(&o).contains("NOT signed"), "{}", err(&o));
    assert!(!sig_of(&unsigned).exists());

    // A legacy locked profile: sealed, no metadata.
    let mut prof: robodr_events::profile::Profile =
        serde_json::from_str(&std::fs::read_to_string(&unsigned).unwrap()).unwrap();
    prof.metadata = None;
    let legacy = d.join("legacy.json");
    let legacy_text = sealed_text(&prof).unwrap();
    std::fs::write(&legacy, &legacy_text).unwrap();
    let o = verify(&legacy, &trust, &[]);
    assert_eq!(code(&o), 1);
    assert!(out(&o).contains("migrate-legacy"), "{}", out(&o));
    // `sign` refuses a legacy profile.
    let o = run(&["sign", "--profile", s(&legacy), "--sign-key", s(&key)]);
    assert_eq!(code(&o), 2);

    let migrated = d.join("migrated.json");
    let o = run(&[
        "migrate-legacy",
        "--in",
        s(&legacy),
        "--out",
        s(&migrated),
        "--platform",
        "ugv",
        "--profile-version",
        "1",
        "--operator",
        "Migrating Operator",
        "--sign-key",
        s(&key),
    ]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let o = verify(&migrated, &trust, &["--json"]);
    assert_eq!(code(&o), 0, "{}", out(&o));
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&migrated).unwrap()).unwrap();
    assert_eq!(
        v["metadata"]["parent_digest"],
        file_digest(legacy_text.as_bytes()).as_str()
    );
    assert_eq!(v["metadata"]["locked_by"], "Migrating Operator");
    // Content unchanged.
    let mut back: robodr_events::profile::Profile = serde_json::from_value(v).unwrap();
    back.metadata = None;
    assert_eq!(back, prof);
    // Only legacy profiles migrate.
    let o = run(&[
        "migrate-legacy",
        "--in",
        s(&migrated),
        "--out",
        s(&d.join("again.json")),
        "--platform",
        "ugv",
        "--profile-version",
        "2",
        "--operator",
        "x",
        "--sign-key",
        s(&key),
    ]);
    assert_eq!(code(&o), 2);
    assert!(err(&o).contains("already has metadata"), "{}", err(&o));
    let o = run(&[
        "migrate-legacy",
        "--in",
        s(&p),
        "--out",
        s(&d.join("again.json")),
        "--platform",
        "ugv",
        "--profile-version",
        "2",
        "--operator",
        "x",
        "--sign-key",
        s(&key),
    ]);
    assert_eq!(code(&o), 2);
    let _ = std::fs::remove_dir_all(&d);
}
