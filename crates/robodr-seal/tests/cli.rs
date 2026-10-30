//! The `robodr-seal` binary: key generation, policy signing, usage errors
//! (always); provisioning, enrolment, policy install / commit, depot
//! rewrap, status and erase against a software TPM (`ROBODR_SWTPM=1`).

mod common;

use common::*;
use std::path::Path;
use std::process::Command;

fn seal(args: &[&str]) -> (i32, serde_json::Value, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_robodr-seal"))
        .args(args)
        .output()
        .unwrap();
    let out = serde_json::from_slice(&o.stdout).unwrap_or(serde_json::Value::Null);
    (
        o.status.code().unwrap_or(-1),
        out,
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn keys_policy_and_usage() {
    let d = tmp("cli-basic");
    let (c, v, e) = seal(&["keygen", "policy", "--out", s(&d.join("auth.key"))]);
    assert_eq!(c, 0, "{e}");
    assert_eq!(v["public"], s(&d.join("auth.key.pub")));
    let (c, v, e) = seal(&["keygen", "depot", "--out", s(&d.join("depot.key"))]);
    assert_eq!(c, 0, "{e}");
    assert!(v["fingerprint"].as_str().unwrap().starts_with("sha256:"));
    // Never overwrite a key.
    assert_eq!(
        seal(&["keygen", "depot", "--out", s(&d.join("depot.key"))]).0,
        1
    );
    let zero = "00".repeat(32);
    let (c, _, e) = seal(&[
        "policy",
        "sign",
        "--key",
        s(&d.join("auth.key")),
        "--platform",
        "ugv-x1",
        "--version",
        "1",
        "--pcr",
        &format!("0={zero}"),
        "--pcr",
        &format!("7={zero}"),
        "--out",
        s(&d.join("p.json")),
    ]);
    assert_eq!(c, 0, "{e}");
    let auth = robodr_seal::keys::policy_load_public(&d.join("auth.key.pub")).unwrap();
    robodr_seal::policy::verify(
        &std::fs::read(d.join("p.json")).unwrap(),
        &auth,
        "ugv-x1",
        robodr_seal::tpm::DEFAULT_FLOOR_NV,
    )
    .unwrap();
    // Usage errors exit 2; -h only alone.
    for bad in [
        vec!["policy", "sign", "-h"],
        vec!["keygen", "depot", "--out"],
        vec!["keygen", "depot", "--bogus", "x"],
        vec![
            "policy",
            "sign",
            "--pcr",
            "24=00",
            "--key",
            "k",
            "--platform",
            "p",
            "--version",
            "1",
            "--out",
            "o",
        ],
        vec!["status", "--seal-dir", "x", "--srk", "0x01000000"],
        vec!["frobnicate"],
    ] {
        assert_eq!(seal(&bad).0, 2, "{bad:?}");
    }
    assert_eq!(seal(&["--help"]).0, 0);
    assert_eq!(seal(&["--version"]).0, 0);
}

#[test]
fn unit_lifecycle_on_a_software_tpm() {
    if !swtpm_enabled("cli_lifecycle") {
        return;
    }
    let d = tmp("cli-tpm");
    let sw = SwTpm::start(&d.join("swtpm"));
    let tcti = sw.tcti();
    let wd = sw.work_dir();
    let t = ["--tcti", tcti.as_str(), "--work-dir", wd.to_str().unwrap()];
    let with = |args: &[&str]| -> Vec<String> {
        args.iter().chain(t.iter()).map(|x| x.to_string()).collect()
    };
    let run = |args: Vec<String>| {
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        seal(&a)
    };
    let auth = d.join("owner.auth");
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&auth)
            .unwrap();
        std::io::Write::write_all(&mut f, OWNER_AUTH).unwrap();
    }
    let prov = || with(&["provision", "--owner-auth-file", s(&auth)]);
    // Refused while the TPM's owner authorization is empty (review H1).
    let (c, _, e) = run(prov());
    assert_eq!(c, 1, "provisioned an unowned TPM");
    assert!(e.contains("owner and lockout authorizations"), "{e}");
    let (c, _, _) = run(with(&["provision"]));
    assert_eq!(c, 2, "--owner-auth-file is required");
    sw.take_ownership();
    let (c, v, e) = run(prov());
    assert_eq!(c, 0, "{e}");
    assert_eq!(v["defined_epoch"], true);
    let (c, v, _) = run(prov());
    assert_eq!(c, 0);
    assert_eq!(v["defined_epoch"], false, "idempotent");
    seal(&["keygen", "policy", "--out", s(&d.join("auth.key"))]);
    seal(&["keygen", "depot", "--out", s(&d.join("depot.key"))]);
    let sd = d.join("seal");
    let (c, rec, e) = run(with(&[
        "enroll",
        "--seal-dir",
        s(&sd),
        "--unit",
        "ugv-07",
        "--platform",
        "ugv-x1",
        "--policy-authority",
        s(&d.join("auth.key.pub")),
    ]));
    assert_eq!(c, 0, "{e}");
    assert_eq!(rec["mode"], "tpm");
    std::fs::write(d.join("unit.json"), serde_json::to_vec(&rec).unwrap()).unwrap();
    // Sign a policy for the TPM's current PCR values.
    let pcrs: Vec<String> = sw
        .pcrs(&[0, 7])
        .iter()
        .map(|(i, v)| format!("{i}={}", robodr_seal::to_hex(v)))
        .collect();
    let (c, _, e) = seal(&[
        "policy",
        "sign",
        "--key",
        s(&d.join("auth.key")),
        "--platform",
        "ugv-x1",
        "--version",
        "2",
        "--pcr",
        &pcrs[0],
        "--pcr",
        &pcrs[1],
        "--out",
        s(&d.join("p2.json")),
    ]);
    assert_eq!(c, 0, "{e}");
    let (c, _, e) = run(with(&[
        "policy",
        "install",
        "--seal-dir",
        s(&sd),
        "--policy",
        s(&d.join("p2.json")),
    ]));
    assert_eq!(c, 0, "{e}");
    let (c, v, e) = run(with(&["policy", "commit", "--seal-dir", s(&sd)]));
    assert_eq!(c, 0, "{e}");
    assert_eq!(v["committed"], 2);
    // Depot: rewrap a sealed RPK for the unit's record.
    let depot = robodr_seal::keys::x25519_load(&d.join("depot.key")).unwrap();
    let (rpk, m, digest) = sealed_rpk(
        &d.join("rel"),
        "nav-model",
        "ugv-x1",
        &[("w.bin", b"secret".to_vec())],
        &[depot.public()],
    );
    let (c, wk, e) = seal(&[
        "rewrap",
        "--depot-key",
        s(&d.join("depot.key")),
        "--rpk",
        s(&rpk),
        "--unit-record",
        s(&d.join("unit.json")),
    ]);
    assert_eq!(c, 0, "{e}");
    assert_eq!(wk["unit"], "ugv-07");
    assert_eq!(wk["rpk_digest"], digest.as_str());
    let unit = robodr_seal::unit::Unit::open(&sd, Some(sw.tpm())).unwrap();
    let w = robodr_seal::from_hex(wk["wrap"].as_str().unwrap()).unwrap();
    unit.unwrap_content_key(&w, &digest, m.seal.as_ref().unwrap())
        .unwrap();
    let (c, st, _) = run(with(&["status", "--seal-dir", s(&sd)]));
    assert_eq!(c, 0);
    assert_eq!(st["erased"], false);
    assert_eq!(st["policy_version"], 2);
    assert_eq!(st["floor_bits"], 3);
    let (c, rep, e) = run(with(&[
        "erase",
        "--seal-dir",
        s(&sd),
        "--trigger",
        "operator",
    ]));
    assert_eq!(c, 0, "{e}");
    assert!(rep["epoch_after"].as_u64() > rep["epoch_before"].as_u64());
    let (_, st, _) = run(with(&["status", "--seal-dir", s(&sd)]));
    assert_eq!(st["erased"], true);
    assert_eq!(
        unit.unwrap_content_key(&w, &digest, m.seal.as_ref().unwrap())
            .unwrap_err()
            .kind,
        robodr_seal::ErrorKind::Erased
    );
    // A bad trigger is refused.
    assert_eq!(
        run(with(&[
            "erase",
            "--seal-dir",
            s(&sd),
            "--trigger",
            "Bad Trigger"
        ]))
        .0,
        1
    );
}
