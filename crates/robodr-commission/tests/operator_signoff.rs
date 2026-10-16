//! End-to-end tests of the signed operator sign-off (`signoff --sign-key`,
//! `operators`, `lock --operators`, two-person rule), the output manifest
//! (`learn` / `signoff` write it last; `lock` / `check` refuse a torn set)
//! and discovery-server attribution (`learn --discovery-server`).

mod common;

use common::*;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

const BIN: &str = env!("CARGO_BIN_EXE_robodr-commission");

fn example(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join(name)
}

fn tmpdir(tag: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "robodr-commission-opsign-{}-{}-{tag}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Run the binary as is (no test signing wrapper).
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

fn path_plus(p: &Path, suffix: &str) -> PathBuf {
    PathBuf::from(format!("{}{suffix}", p.display()))
}

/// Learn the clean example into `dir` (with a report).
fn learn(dir: &Path) -> PathBuf {
    let p = dir.join("draft.json");
    let o = run(&[
        "learn",
        "--events",
        s(&example("clean-run.jsonl")),
        "--model",
        "ugv-demo-synthetic",
        "--out",
        s(&p),
        "--report",
        s(&dir.join("report.json")),
        "--quiet",
    ]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    p
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

/// keygen an operator key; returns (secret, public).
fn opkey(dir: &Path, name: &str) -> (PathBuf, PathBuf) {
    let key = dir.join(format!("{name}.key"));
    let o = run(&[
        "keygen",
        "--out",
        s(&key),
        "--trust-out",
        s(&dir.join(format!("{name}.trust.json"))),
        "--key-id",
        name,
    ]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    (key.clone(), path_plus(&key, ".pub"))
}

fn operators(dir: &Path, ops: &[(&str, &Path)], quorum: u32) -> PathBuf {
    let out = dir.join("operators.json");
    let mut a: Vec<String> = vec!["operators".into(), "--out".into(), s(&out).into()];
    for (n, p) in ops {
        a.push("--operator".into());
        a.push(format!("{n}={}", p.display()));
    }
    a.push("--motion-quorum".into());
    a.push(quorum.to_string());
    a.push("--force".into());
    let refs: Vec<&str> = a.iter().map(String::as_str).collect();
    let o = run(&refs);
    assert_eq!(code(&o), 0, "{}", err(&o));
    out
}

fn sign(so: &Path, key: &Path, extra: &[&str]) -> Output {
    let mut a = vec!["signoff", "--signoff", s(so), "--sign-key", s(key)];
    a.extend_from_slice(extra);
    run(&a)
}

fn lock(draft: &Path, so: &Path, ops: &Path, out: &Path, extra: &[&str]) -> Output {
    let mut a = vec![
        "lock",
        "--in",
        s(draft),
        "--signoff",
        s(so),
        "--operators",
        s(ops),
        "--out",
        s(out),
        "--platform",
        "ugv",
        "--profile-version",
        "1",
    ];
    a.extend_from_slice(extra);
    run(&a)
}

#[test]
fn signed_signoff_round_trip_and_two_person_rule() {
    let d = tmpdir("rt");
    let draft = learn(&d);
    let so = path_plus(&draft, ".signoff.json");
    assert!(path_plus(&draft, ".manifest.json").exists());
    let (alice, alice_pub) = opkey(&d, "alice");
    let (bob, bob_pub) = opkey(&d, "bob");
    let (mallory, _) = opkey(&d, "mallory");
    let ops1 = operators(&d, &[("Alice", &alice_pub), ("Bob", &bob_pub)], 1);
    let out = d.join("locked.json");

    // Unconfirmed: signing refused (exit 1), nothing written.
    let o = sign(&so, &alice, &[]);
    assert_eq!(code(&o), 1, "{}", err(&o));
    assert!(err(&o).contains("not confirmed"), "{}", err(&o));
    assert!(!path_plus(&so, ".sig").exists());

    confirm(&so, "Alice");
    // Confirmed but unsigned: lock refused, naming the missing signature.
    let o = lock(&draft, &so, &ops1, &out, &[]);
    assert_eq!(code(&o), 1, "{}", err(&o));
    assert!(
        err(&o).contains("no valid operator signature"),
        "{}",
        err(&o)
    );
    assert!(!out.exists());

    // A key outside the trust list: refused at sign time with --operators.
    let o = sign(&so, &mallory, &["--operators", s(&ops1)]);
    assert_eq!(code(&o), 1);
    assert!(err(&o).contains("not in the operators trust list"));
    // ...and by lock when signed without the check.
    assert_eq!(code(&sign(&so, &mallory, &[])), 0);
    let o = lock(&draft, &so, &ops1, &out, &[]);
    assert_eq!(code(&o), 1);
    assert!(
        err(&o).contains("not in the operators trust list"),
        "{}",
        err(&o)
    );
    std::fs::remove_file(path_plus(&so, ".sig")).unwrap();

    // Bob signs, but the list names Alice.
    assert_eq!(code(&sign(&so, &bob, &[])), 0);
    let o = lock(&draft, &so, &ops1, &out, &[]);
    assert_eq!(code(&o), 1);
    assert!(
        err(&o).contains("the named operator must sign"),
        "{}",
        err(&o)
    );
    // Alice adds her signature (with the draft preflight): locks.
    let o = sign(&so, &alice, &["--in", s(&draft), "--operators", s(&ops1)]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert!(err(&o).contains("2 signature(s)"), "{}", err(&o));
    // Signing twice with one key is an error.
    assert_eq!(code(&sign(&so, &alice, &[])), 2);
    let o = lock(&draft, &so, &ops1, &out, &[]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let locked: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(locked["metadata"]["locked_by"], "Alice");

    // Two-person rule: quorum 2 from the trust list or from the flag.
    let out2 = d.join("locked2.json");
    let ops2 = operators(&d, &[("Alice", &alice_pub), ("Bob", &bob_pub)], 2);
    let sig = path_plus(&so, ".sig");
    let both = std::fs::read(&sig).unwrap();
    std::fs::remove_file(&sig).unwrap();
    assert_eq!(code(&sign(&so, &alice, &[])), 0);
    let o = lock(&draft, &so, &ops2, &out2, &[]);
    assert_eq!(code(&o), 1);
    assert!(err(&o).contains("two-person rule"), "{}", err(&o));
    let o = lock(&draft, &so, &ops1, &out2, &["--motion-quorum", "2"]);
    assert_eq!(code(&o), 1);
    assert!(err(&o).contains("two-person rule"), "{}", err(&o));
    // Quorum above the number of operators: usage error.
    let o = lock(&draft, &so, &ops1, &out2, &["--motion-quorum", "3"]);
    assert_eq!(code(&o), 2);
    std::fs::write(&sig, both).unwrap();
    let o = lock(&draft, &so, &ops2, &out2, &[]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn edited_signoff_voids_signatures() {
    let d = tmpdir("edit");
    let draft = learn(&d);
    let so = path_plus(&draft, ".signoff.json");
    let (alice, alice_pub) = opkey(&d, "alice");
    let ops = operators(&d, &[("Alice", &alice_pub)], 1);
    confirm(&so, "Alice");
    assert_eq!(code(&sign(&so, &alice, &[])), 0);
    // Someone deletes an item and recomputes items_sha256 after signing.
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&so).unwrap()).unwrap();
    let mut s_: robodr_commission::Signoff = serde_json::from_value(v.clone()).unwrap();
    s_.items.retain(|i| i.kind != "motion_writer");
    let digest = s_.profile_sha256.clone();
    s_.rebind(digest);
    v = serde_json::to_value(&s_).unwrap();
    std::fs::write(&so, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    let out = d.join("locked.json");
    let o = lock(&draft, &so, &ops, &out, &[]);
    assert_eq!(code(&o), 1);
    let e = err(&o);
    assert!(e.contains("changed after signing"), "{e}");
    assert!(e.contains("not the one written with this draft"), "{e}");
    // Re-signing over the old signature file needs --force.
    let o = sign(&so, &alice, &[]);
    assert_eq!(code(&o), 2);
    assert!(err(&o).contains("--force"), "{}", err(&o));
    let o = sign(&so, &alice, &["--force"]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    // Signed now, but the manifest still catches the swapped list, and the
    // floor catches the missing motion review.
    let o = lock(&draft, &so, &ops, &out, &[]);
    assert_eq!(code(&o), 1);
    assert!(err(&o).contains("stale or foreign"), "{}", err(&o));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn torn_output_set_is_refused_by_lock_and_check() {
    let d = tmpdir("torn");
    let draft = learn(&d);
    let so = path_plus(&draft, ".signoff.json");
    let (alice, alice_pub) = opkey(&d, "alice");
    let ops = operators(&d, &[("Alice", &alice_pub)], 1);
    confirm(&so, "Alice");
    assert_eq!(code(&sign(&so, &alice, &[])), 0);
    let out = d.join("locked.json");
    let check = |p: &Path| {
        run(&[
            "check",
            "--profile",
            s(p),
            "--events",
            s(&example("clean-run.jsonl")),
        ])
    };
    assert_eq!(code(&check(&draft)), 0);

    // The report from another run (the operator reviewed a stale report).
    let report = d.join("report.json");
    let good_report = std::fs::read(&report).unwrap();
    std::fs::write(&report, b"{}\n").unwrap();
    let o = lock(&draft, &so, &ops, &out, &[]);
    assert_eq!(code(&o), 1);
    assert!(err(&o).contains("stale or edited report"), "{}", err(&o));
    let o = check(&draft);
    assert_eq!(code(&o), 2);
    assert!(err(&o).contains("output manifest"), "{}", err(&o));
    std::fs::write(&report, good_report).unwrap();

    // Manifest missing (power loss before it was written).
    let mp = path_plus(&draft, ".manifest.json");
    let m = std::fs::read(&mp).unwrap();
    std::fs::remove_file(&mp).unwrap();
    let o = lock(&draft, &so, &ops, &out, &[]);
    assert_eq!(code(&o), 1);
    assert!(err(&o).contains("no output manifest"), "{}", err(&o));
    // check notes it but still runs on a draft without a manifest.
    let o = check(&draft);
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert!(err(&o).contains("no output manifest"));
    // Explicit opt-out for drafts made before manifests existed.
    let o = lock(&draft, &so, &ops, &out, &["--no-manifest"]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    std::fs::remove_file(&out).unwrap();
    std::fs::remove_file(path_plus(&out, ".sig")).ok();
    std::fs::write(&mp, m).unwrap();
    let o = lock(&draft, &so, &ops, &out, &[]);
    assert_eq!(code(&o), 0, "{}", err(&o));

    // Re-learn over the set with --force: the manifest is rewritten last
    // and matches the new set.
    let o = run(&[
        "learn",
        "--events",
        s(&example("clean-run.jsonl")),
        "--model",
        "ugv-demo-synthetic",
        "--margin",
        "1.2",
        "--out",
        s(&draft),
        "--quiet",
        "--force",
    ]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let man: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&mp).unwrap()).unwrap();
    assert!(man["report"].is_null(), "no --report this time");
    assert_eq!(man["draft"]["path"], "draft.json");
    assert_eq!(code(&check(&draft)), 0);
    // learn without --force refuses an existing manifest too.
    let o = run(&[
        "learn",
        "--events",
        s(&example("clean-run.jsonl")),
        "--out",
        s(&d.join("other.json")),
        "--signoff",
        s(&d.join("other.so.json")),
        "--quiet",
    ]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    std::fs::remove_file(d.join("other.json")).unwrap();
    std::fs::remove_file(d.join("other.so.json")).unwrap();
    let o = run(&[
        "learn",
        "--events",
        s(&example("clean-run.jsonl")),
        "--out",
        s(&d.join("other.json")),
        "--signoff",
        s(&d.join("other.so.json")),
        "--quiet",
    ]);
    assert_eq!(code(&o), 2);
    assert!(err(&o).contains("manifest.json"), "{}", err(&o));
    assert!(!d.join("other.json").exists());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn signoff_list_mode_writes_a_manifest_for_merged_drafts() {
    let d = tmpdir("merged");
    let a = learn(&d);
    let m = d.join("merged.json");
    let o = run(&["merge", "--out", s(&m), s(&a)]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let so = d.join("merged.so.json");
    let o = run(&["signoff", "--in", s(&m), "--out", s(&so)]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert!(path_plus(&m, ".manifest.json").exists());
    // Again without --force: the manifest still matches, so it is kept.
    let o = run(&["signoff", "--in", s(&m), "--out", s(&d.join("so2.json"))]);
    assert_eq!(code(&o), 2);
    let (alice, alice_pub) = opkey(&d, "alice");
    let ops = operators(&d, &[("Alice", &alice_pub)], 1);
    confirm(&so, "Alice");
    assert_eq!(code(&sign(&so, &alice, &["--in", s(&m)])), 0);
    let out = d.join("locked.json");
    let o = lock(&m, &so, &ops, &out, &[]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    // Sign-mode flag misuse.
    let o = run(&[
        "signoff",
        "--in",
        s(&m),
        "--out",
        s(&so),
        "--operators",
        s(&ops),
    ]);
    assert_eq!(code(&o), 2);
    let o = sign(&so, &alice, &["--out", s(&d.join("x"))]);
    assert_eq!(code(&o), 2);
    // --in of another draft (the locked file): refused before signing.
    let o = sign(&so, &alice, &["--in", s(&out), "--force"]);
    assert_eq!(code(&o), 1, "{}", err(&o));
    assert!(err(&o).contains("does not belong"), "{}", err(&o));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn lock_and_operators_usage_errors() {
    let d = tmpdir("usage");
    let draft = learn(&d);
    let so = path_plus(&draft, ".signoff.json");
    let out = d.join("l.json");
    // --operators is required.
    let o = run(&[
        "lock",
        "--in",
        s(&draft),
        "--signoff",
        s(&so),
        "--out",
        s(&out),
        "--platform",
        "p",
        "--profile-version",
        "1",
    ]);
    assert_eq!(code(&o), 2);
    assert!(err(&o).contains("--operators"), "{}", err(&o));
    // A missing or world-writable operators list.
    let o = lock(&draft, &so, &d.join("nope.json"), &out, &[]);
    assert_eq!(code(&o), 2);
    let (_, alice_pub) = opkey(&d, "alice");
    let ops = operators(&d, &[("Alice", &alice_pub)], 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ops, std::fs::Permissions::from_mode(0o666)).unwrap();
        let o = lock(&draft, &so, &ops, &out, &[]);
        assert_eq!(code(&o), 2);
        assert!(err(&o).contains("group/others"), "{}", err(&o));
        std::fs::set_permissions(&ops, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let o = lock(&draft, &so, &ops, &out, &["--motion-quorum", "0"]);
    assert_eq!(code(&o), 2);
    // A malformed signature file is an input error.
    std::fs::write(path_plus(&so, ".sig"), "{").unwrap();
    let o = lock(&draft, &so, &ops, &out, &[]);
    assert_eq!(code(&o), 2);
    assert!(err(&o).contains("signature file"), "{}", err(&o));
    // operators: bad specs, a secret key file, quorum too high.
    let (alice_key, _) = (d.join("alice.key"), ());
    for args in [
        vec!["operators", "--out", "x.json"],
        vec!["operators", "--out", "x.json", "--operator", "noequals"],
        vec![
            "operators",
            "--out",
            "x.json",
            "--operator",
            &format!("A={}", s(&alice_key)),
        ],
        vec![
            "operators",
            "--out",
            "x.json",
            "--operator",
            &format!("A={}", s(&alice_pub)),
            "--motion-quorum",
            "2",
        ],
    ] {
        let a: Vec<&str> = args.iter().map(|x| &**x).collect();
        let o = run(&a);
        assert_eq!(code(&o), 2, "{args:?}: {}", err(&o));
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// A capture with a discovery server (prefix 0xc3 at 10.42.0.5) relaying
/// a copy of the talker's /rosout writer and a /relayed_only writer the
/// talker never announced itself.
fn relay_capture(dir: &Path) -> PathBuf {
    const SERVER: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 42, 0, 5);
    let (t, srv) = (prefix(0xa1), prefix(0xc3));
    let mut frames_ = talker_listener(false);
    let relayed: Vec<Vec<u8>> = ["rt/rosout", "rt/relayed_only"]
        .iter()
        .enumerate()
        .map(|(i, topic)| {
            let payload = sedp_payload(t, 0x7000 + i as u32, topic, "pkg::msg::dds_::T_", 0);
            rtps(srv, &[data(SEDP_PUB_WRITER, 500 + i as u32, &payload)])
        })
        .collect();
    frames_.extend(frames(SERVER, &relayed));
    let p = dir.join("relay.pcap");
    std::fs::write(&p, pcap(&frames_)).unwrap();
    p
}

/// Learn the relay capture; returns (sign-off, participants the report
/// attributes the `/relayed_only` writer to).
fn learn_relay(dir: &Path, cap: &Path, extra: &[&str]) -> (serde_json::Value, Vec<String>) {
    let out = dir.join("relay.json");
    let report = dir.join("relay.report.json");
    let mut a = vec![
        "learn",
        "--pcap",
        s(cap),
        "--min-duration",
        "0",
        "--out",
        s(&out),
        "--report",
        s(&report),
        "--quiet",
        "--force",
    ];
    a.extend_from_slice(extra);
    let o = run(&a);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let r: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report).unwrap()).unwrap();
    let so =
        serde_json::from_str(&std::fs::read_to_string(path_plus(&out, ".signoff.json")).unwrap())
            .unwrap();
    let owners = r["writer_topics"]["/relayed_only"]["participants"]
        .as_array()
        .map(|a| a.iter().map(|x| x.as_str().unwrap().to_string()).collect())
        .unwrap_or_default();
    (so, owners)
}

fn relay_items(so: &serde_json::Value) -> Vec<String> {
    so["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["kind"] == "endpoint_sender_mismatch")
        .map(|i| i["reason"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn discovery_server_relays_from_a_capture() {
    let d = tmpdir("relay");
    let cap = relay_capture(&d);
    let (talker, srv) = (hex(prefix(0xa1)), hex(prefix(0xc3)));
    // (The RTPS layer also attributes a relayed copy to its sender, as the
    // sensor does; what matters here is attribution to the talker.)
    // Unconfigured: the relay is a mismatch, nothing is attributed.
    let (so, owners) = learn_relay(&d, &cap, &[]);
    assert!(!owners.contains(&talker), "{owners:?}");
    let items = relay_items(&so);
    assert_eq!(items.len(), 1, "{items:?}");
    assert!(items[0].contains("GUID spoofing"));
    // Known server: the /rosout copy is attributed, /relayed_only is not.
    let (so, owners) = learn_relay(
        &d,
        &cap,
        &["--discovery-server", &format!("{srv}@10.42.0.5")],
    );
    assert!(!owners.contains(&talker), "{owners:?}");
    let items = relay_items(&so);
    assert_eq!(items.len(), 1, "{items:?}");
    assert!(items[0].contains("known discovery server"), "{}", items[0]);
    assert!(
        items[0].contains("never announced 1 of them"),
        "{}",
        items[0]
    );
    // Trusted server: the talker is accepted, so its relayed writer is
    // attributed to it and nothing is flagged.
    let (so, owners) = learn_relay(&d, &cap, &["--trusted-discovery-server", "10.42.0.5"]);
    assert!(owners.contains(&talker), "{owners:?}");
    assert!(relay_items(&so).is_empty(), "{:?}", relay_items(&so));
    // A server spec on another IP does not match.
    let (so, owners) = learn_relay(
        &d,
        &cap,
        &["--trusted-discovery-server", &format!("{srv}@10.42.0.6")],
    );
    assert!(!owners.contains(&talker));
    assert_eq!(relay_items(&so).len(), 1);
    // Invalid spec: usage error, nothing written.
    let o = run(&[
        "learn",
        "--pcap",
        s(&cap),
        "--out",
        s(&d.join("bad.json")),
        "--discovery-server",
        "not-a-server",
    ]);
    assert_eq!(code(&o), 2);
    assert!(err(&o).contains("--discovery-server"), "{}", err(&o));
    assert!(!d.join("bad.json").exists());
    let _ = std::fs::remove_dir_all(&d);
}
