//! Bound configuration (T11 / T12), the report renderer (T47) and the lab
//! chain (T48), end to end through the CLI: `poc-init` -> `learn` ->
//! `firewall-draft` -> `bind` -> sign-off -> `lock` -> `verify-profile`,
//! then what a loader decides for the bound files (`trust::bound`).

use robodr_commission::trust::bound::{
    bytes_digest, digest_for_role, verify_bindings, verify_bindings_report, BindingRefusal,
    ROLE_EXECUTOR_MOTION, ROLE_MOTION_FIREWALL, ROLE_RESPONSE_POLICY,
};
use robodr_commission::trust::TrustInputs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

const BIN: &str = env!("CARGO_BIN_EXE_robodr-commission");

fn tmpdir(tag: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "robodr-commission-bound-{}-{}-{tag}",
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

fn example(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join(name)
}

fn policy_text(validated: bool) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/response-policy.example.json");
    let t = std::fs::read_to_string(p).unwrap();
    t.replace(
        "\"oem_validated\": false",
        &format!("\"oem_validated\": {validated}"),
    )
}

const EXECUTOR: &str = r#"{"schema": "robodr-executor-config/v1", "network": {"management": []},
 "motion": {"nav2": {"oem_validated": true, "ros2": {"peer_ip": "10.0.0.2"}}}}"#;

struct Chain {
    d: PathBuf,
    poc: PathBuf,
    draft: PathBuf,
    report: PathBuf,
}

fn chain() -> Chain {
    let d = tmpdir("chain");
    let poc = d.join("poc");
    let o = run(&["poc-init", "--dir", s(&poc), "--operator", "alice"]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert!(err(&o).contains("LAB-ONLY TRUST CHAIN"), "{}", err(&o));
    let draft = d.join("draft.json");
    let report = d.join("report.json");
    let o = run(&[
        "learn",
        "--events",
        s(&example("clean-run.jsonl")),
        "--model",
        "ugv-demo-synthetic",
        "--out",
        s(&draft),
        "--report",
        s(&report),
        "--quiet",
    ]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    Chain {
        d,
        poc,
        draft,
        report,
    }
}

fn confirm(so: &Path, operator: &str) {
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(so).unwrap()).unwrap();
    v["operator"] = operator.into();
    for i in v["items"].as_array_mut().unwrap() {
        i["confirmed"] = true.into();
    }
    std::fs::write(so, serde_json::to_string_pretty(&v).unwrap()).unwrap();
}

/// bind -> confirm -> sign -> lock -> sign; returns the locked profile.
fn bind_and_lock(c: &Chain, binds: &[&str], version: &str) -> PathBuf {
    let bound = c.d.join(format!("bound-{version}.json"));
    let so = c.d.join(format!("bound-{version}.json.signoff.json"));
    let mut a = vec!["bind", "--in", s(&c.draft), "--out", s(&bound), "--signoff"];
    let learned = PathBuf::from(format!("{}.signoff.json", c.draft.display()));
    a.push(s(&learned));
    a.extend_from_slice(binds);
    let o = run(&a);
    assert_eq!(code(&o), 0, "{}", err(&o));
    confirm(&so, "alice [LAB-ONLY]");
    let ops = c.poc.join("operators.json");
    let o = run(&[
        "signoff",
        "--signoff",
        s(&so),
        "--sign-key",
        s(&c.poc.join("lab-only-operator.key")),
        "--operators",
        s(&ops),
    ]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let locked = c.d.join(format!("locked-{version}.json"));
    let o = run(&[
        "lock",
        "--in",
        s(&bound),
        "--signoff",
        s(&so),
        "--operators",
        s(&ops),
        "--out",
        s(&locked),
        "--platform",
        "ugv",
        "--profile-version",
        version,
        "--sign-key",
        s(&c.poc.join("lab-only-profile.key")),
    ]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    locked
}

fn inputs(c: &Chain) -> (PathBuf, PathBuf) {
    (
        c.poc.join("profile-trust.json"),
        c.poc.join("trust-roots.json"),
    )
}

#[test]
fn bound_policy_and_executor_motion_are_honoured_only_as_signed() {
    let c = chain();
    let pol = c.d.join("response-policy.json");
    std::fs::write(&pol, policy_text(true)).unwrap();
    let exe = c.d.join("executor.json");
    std::fs::write(&exe, EXECUTOR).unwrap();
    let locked = bind_and_lock(
        &c,
        &["--response-policy", s(&pol), "--executor-config", s(&exe)],
        "1",
    );
    let (tk, tr) = inputs(&c);
    let o = run(&[
        "verify-profile",
        "--profile",
        s(&locked),
        "--trusted-keys",
        s(&tk),
        "--trust-roots",
        s(&tr),
    ]);
    assert_eq!(code(&o), 0, "{}{}", out(&o), err(&o));
    assert!(
        out(&o).contains("binds response_policy sha256:"),
        "{}",
        out(&o)
    );
    assert!(
        out(&o).contains("binds executor_motion sha256:"),
        "{}",
        out(&o)
    );
    assert!(out(&o).contains("LAB-ONLY TRUST CHAIN"), "{}", out(&o));

    let ti = TrustInputs {
        trusted_keys: Some(&tk),
        trust_roots: Some(&tr),
        ..Default::default()
    };
    let pol_d = bytes_digest(policy_text(true).as_bytes());
    let exe_d = digest_for_role(ROLE_EXECUTOR_MOTION, EXECUTOR).unwrap();
    let r = verify_bindings(
        &locked,
        &ti,
        &[
            (ROLE_RESPONSE_POLICY, &pol_d),
            (ROLE_EXECUTOR_MOTION, &exe_d),
        ],
    );
    assert!(r.iter().all(Result::is_ok), "{r:?}");
    assert_eq!(r[0].as_ref().unwrap().locked_by, "alice [LAB-ONLY]");
    // Review (WP6): a loader without the trust evaluation (the executor)
    // learns the chain is lab-only, to print the banner.
    let rep = verify_bindings_report(&locked, &ti, &[(ROLE_RESPONSE_POLICY, &pol_d)]);
    assert!(rep.lab_only && rep.results[0].is_ok(), "{rep:?}");

    // A flipped flag (or any edit) under the same profile: mismatch.
    let edited = bytes_digest(policy_text(false).as_bytes());
    let r = verify_bindings(&locked, &ti, &[(ROLE_RESPONSE_POLICY, &edited)]);
    assert!(
        matches!(r[0], Err(BindingRefusal::Mismatch { .. })),
        "{r:?}"
    );
    // A role it does not bind.
    let r = verify_bindings(&locked, &ti, &[(ROLE_MOTION_FIREWALL, &pol_d)]);
    assert!(
        matches!(r[0], Err(BindingRefusal::NotBound { .. })),
        "{r:?}"
    );
    // A forged profile (one byte) is not trusted: nothing it binds holds.
    let mut t = std::fs::read_to_string(&locked).unwrap();
    t = t.replacen("\"model\"", " \"model\"", 1);
    let forged = c.d.join("forged.json");
    std::fs::write(&forged, t).unwrap();
    std::fs::copy(
        format!("{}.sig", locked.display()),
        format!("{}.sig", forged.display()),
    )
    .unwrap();
    let r = verify_bindings(&forged, &ti, &[(ROLE_RESPONSE_POLICY, &pol_d)]);
    assert!(
        matches!(r[0], Err(BindingRefusal::NoTrustedProfile { .. })),
        "{r:?}"
    );
    // The draft never binds.
    let r = verify_bindings(&c.draft, &ti, &[(ROLE_RESPONSE_POLICY, &pol_d)]);
    assert!(r[0].is_err());
    let _ = std::fs::remove_dir_all(&c.d);
}

/// Review (WP6): binding in steps with `--signoff` (the policy first, the
/// executor's motion section with the first run's list) kept only the
/// items of the last run, so `lock` refused the list (RequiredItemMissing).
#[test]
fn bind_in_steps_keeps_the_earlier_binding_items() {
    let c = chain();
    let pol = c.d.join("response-policy.json");
    std::fs::write(&pol, policy_text(true)).unwrap();
    let exe = c.d.join("executor.json");
    std::fs::write(&exe, EXECUTOR).unwrap();
    let learned = PathBuf::from(format!("{}.signoff.json", c.draft.display()));
    let b1 = c.d.join("b1.json");
    let o = run(&[
        "bind",
        "--in",
        s(&c.draft),
        "--out",
        s(&b1),
        "--signoff",
        s(&learned),
        "--response-policy",
        s(&pol),
    ]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let so1 = c.d.join("b1.json.signoff.json");
    let b2 = c.d.join("b2.json");
    let o = run(&[
        "bind",
        "--in",
        s(&b1),
        "--out",
        s(&b2),
        "--signoff",
        s(&so1),
        "--executor-config",
        s(&exe),
    ]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let so2 = c.d.join("b2.json.signoff.json");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&so2).unwrap()).unwrap();
    let subjects: Vec<&str> = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["kind"] == "bound_config")
        .map(|i| i["subject"].as_str().unwrap())
        .collect();
    assert_eq!(subjects.len(), 2, "{subjects:?}");
    assert!(subjects.iter().any(|s| s.starts_with("response_policy ")));
    assert!(subjects.iter().any(|s| s.starts_with("executor_motion ")));

    // Re-binding the same role replaces its item (no stale digest kept).
    std::fs::write(&pol, policy_text(false)).unwrap();
    let b3 = c.d.join("b3.json");
    let o = run(&[
        "bind",
        "--in",
        s(&b2),
        "--out",
        s(&b3),
        "--signoff",
        s(&so2),
        "--response-policy",
        s(&pol),
    ]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let so3 = c.d.join("b3.json.signoff.json");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&so3).unwrap()).unwrap();
    let pol_items: Vec<&str> = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["kind"] == "bound_config")
        .filter_map(|i| i["subject"].as_str())
        .filter(|s| s.starts_with("response_policy "))
        .collect();
    assert_eq!(
        pol_items,
        vec![format!(
            "response_policy {}",
            bytes_digest(policy_text(false).as_bytes())
        )]
    );

    // And the two-step list locks.
    confirm(&so3, "alice [LAB-ONLY]");
    let ops = c.poc.join("operators.json");
    let o = run(&[
        "signoff",
        "--signoff",
        s(&so3),
        "--sign-key",
        s(&c.poc.join("lab-only-operator.key")),
        "--operators",
        s(&ops),
    ]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    // report-html shows the .sig key ids as unverified unless given the
    // operators file, then as checked (review WP6).
    let html = c.d.join("r.html");
    let o = run(&[
        "report-html",
        "--report",
        s(&c.report),
        "--out",
        s(&html),
        "--signoff",
        s(&so3),
    ]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let h = std::fs::read_to_string(&html).unwrap();
    assert!(h.contains("UNVERIFIED"), "{h}");
    let o = run(&[
        "report-html",
        "--report",
        s(&c.report),
        "--out",
        s(&html),
        "--signoff",
        s(&so3),
        "--operators",
        s(&ops),
        "--force",
    ]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let h = std::fs::read_to_string(&html).unwrap();
    assert!(
        h.contains("signatures (verified against the operators file)"),
        "{h}"
    );
    assert!(
        h.contains("<span class=\"ok\">valid</span>: alice [LAB-ONLY]"),
        "{h}"
    );
    let o = run(&[
        "lock",
        "--in",
        s(&b3),
        "--signoff",
        s(&so3),
        "--operators",
        s(&ops),
        "--out",
        s(&c.d.join("locked.json")),
        "--platform",
        "ugv",
        "--profile-version",
        "1",
        "--sign-key",
        s(&c.poc.join("lab-only-profile.key")),
    ]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let _ = std::fs::remove_dir_all(&c.d);
}

#[test]
fn bind_refuses_invalid_files_and_locked_input() {
    let c = chain();
    let bad = c.d.join("bad-policy.json");
    std::fs::write(&bad, "{\"oem_validated\": true}").unwrap();
    let o = run(&[
        "bind",
        "--in",
        s(&c.draft),
        "--out",
        s(&c.d.join("b.json")),
        "--response-policy",
        s(&bad),
    ]);
    assert_eq!(code(&o), 2, "{}", err(&o));
    assert!(
        err(&o).contains("not a valid response_policy file"),
        "{}",
        err(&o)
    );
    assert!(!c.d.join("b.json").exists());
    // Nothing to bind.
    let o = run(&["bind", "--in", s(&c.draft), "--out", s(&c.d.join("b.json"))]);
    assert_eq!(code(&o), 2);
    // Not an executor configuration, or a `motion` that is not an object
    // (review WP6: only a digest was computed before).
    for bad_exe in [
        r#"{"motion": {"nav2": {"oem_validated": true}}}"#,
        r#"{"schema": "robodr-executor-config/v1", "motion": [1]}"#,
        r#"{"schema": "robodr-executor-config/v1", "motion": "x"}"#,
    ] {
        let exe = c.d.join("bad-executor.json");
        std::fs::write(&exe, bad_exe).unwrap();
        let o = run(&[
            "bind",
            "--in",
            s(&c.draft),
            "--out",
            s(&c.d.join("b.json")),
            "--executor-config",
            s(&exe),
        ]);
        assert_eq!(code(&o), 2, "{bad_exe}: {}", err(&o));
        assert!(
            err(&o).contains("not a valid executor_motion file"),
            "{}",
            err(&o)
        );
    }
    // A firewall file that does not compile against the draft.
    let fw = c.d.join("fw.json");
    std::fs::write(&fw, "{\"channels\": {}}").unwrap();
    let o = run(&[
        "bind",
        "--in",
        s(&c.draft),
        "--out",
        s(&c.d.join("b.json")),
        "--motion-firewall",
        s(&fw),
    ]);
    assert_eq!(code(&o), 2, "{}", err(&o));
    assert!(
        err(&o).contains("must compile against this draft"),
        "{}",
        err(&o)
    );
    let _ = std::fs::remove_dir_all(&c.d);
}

#[test]
fn bind_adds_one_motion_item_per_bound_file() {
    // Each binding is a sign-off item naming the exact digest, and a
    // motion item (motion_quorum applies; see the ops unit test).
    let c = chain();
    let pol = c.d.join("response-policy.json");
    std::fs::write(&pol, policy_text(true)).unwrap();
    let bound = c.d.join("bound.json");
    let learned = PathBuf::from(format!("{}.signoff.json", c.draft.display()));
    let o = run(&[
        "bind",
        "--in",
        s(&c.draft),
        "--out",
        s(&bound),
        "--signoff",
        s(&learned),
        "--response-policy",
        s(&pol),
    ]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let so = c.d.join("bound.json.signoff.json");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&so).unwrap()).unwrap();
    let bound_items: Vec<&serde_json::Value> = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["kind"] == "bound_config")
        .collect();
    assert_eq!(bound_items.len(), 1);
    assert!(bound_items[0]["reason"]
        .as_str()
        .unwrap()
        .contains("oem_validated: true"));
    let so_v = robodr_commission::Signoff::for_profile(
        &robodr_commission::parse_profile_text(&std::fs::read_to_string(&bound).unwrap()).unwrap(),
    );
    assert!(robodr_commission::signoff::motion_items(&so_v).any(|i| i.kind == "bound_config"));
    let _ = std::fs::remove_dir_all(&c.d);
}

#[test]
fn firewall_draft_binds_and_report_renders() {
    let c = chain();
    let fw = c.d.join("firewall.json");
    let o = run(&[
        "firewall-draft",
        "--in",
        s(&c.draft),
        "--report",
        s(&c.report),
        "--out",
        s(&fw),
        "--max-angular",
        "1.0",
        "--ceiling-linear",
        "0.8",
    ]);
    // Twist channels drafted; any non-Twist channel makes it incomplete.
    assert!(code(&o) == 0 || code(&o) == 1, "{}", err(&o));
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&fw).unwrap()).unwrap();
    assert!(!v["channels"].as_object().unwrap().is_empty(), "{v}");
    if code(&o) == 0 {
        let locked = bind_and_lock(&c, &["--motion-firewall", s(&fw)], "1");
        let (tk, tr) = inputs(&c);
        let ti = TrustInputs {
            trusted_keys: Some(&tk),
            trust_roots: Some(&tr),
            ..Default::default()
        };
        let d = bytes_digest(&std::fs::read(&fw).unwrap());
        let r = verify_bindings(&locked, &ti, &[(ROLE_MOTION_FIREWALL, &d)]);
        assert!(r[0].is_ok(), "{r:?}");
    } else {
        assert!(err(&o).contains("INCOMPLETE"), "{}", err(&o));
    }
    // Missing --max-angular is a usage error.
    let o = run(&[
        "firewall-draft",
        "--in",
        s(&c.draft),
        "--report",
        s(&c.report),
        "--out",
        s(&c.d.join("fw2.json")),
    ]);
    assert_eq!(code(&o), 2);

    let html = c.d.join("report.html");
    let learned = PathBuf::from(format!("{}.signoff.json", c.draft.display()));
    let o = run(&[
        "report-html",
        "--report",
        s(&c.report),
        "--out",
        s(&html),
        "--signoff",
        s(&learned),
        "--note",
        "site <A>",
    ]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let h = std::fs::read_to_string(&html).unwrap();
    assert!(h.starts_with("<!doctype html>"));
    assert!(h.contains("ugv-demo-synthetic"));
    assert!(h.contains("site &lt;A&gt;"));
    assert!(h.contains("unconfirmed sign-off item(s)"));
    // No clobber without --force.
    let o = run(&["report-html", "--report", s(&c.report), "--out", s(&html)]);
    assert_eq!(code(&o), 2);
    let _ = std::fs::remove_dir_all(&c.d);
}
