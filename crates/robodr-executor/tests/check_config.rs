//! `robodr-executor --check-config` as the binary runs it (review of T67):
//! a `soc.key_scopes` entry naming a key id no `soc.keys` key has (a typo
//! or a removed key) makes every key without an entry approve and revert
//! nothing, so the check fails with exit 2 and names the entry; the same
//! configuration with a matching entry, or none, passes.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};

const BIN: &str = env!("CARGO_BIN_EXE_robodr-executor");
const SOC_KEY_ID: &str = "soc:check:1";

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "robodr-executor-check-config-{}-{tag}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config")
}

/// The shipped example configuration with every path in `d`, one SOC key
/// (`SOC_KEY_ID`) and `key_scopes` as given.
fn setup(tag: &str, key_scopes: Value) -> PathBuf {
    let d = tmpdir(tag);
    let key = d.join("executor.key");
    let out = Command::new(BIN)
        .args(["keygen", "--out"])
        .arg(&key)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    std::fs::copy(
        root().join("response-policy.example.json"),
        d.join("policy.json"),
    )
    .unwrap();
    let soc = d.join("soc.pub");
    std::fs::write(
        &soc,
        robodr_executor::soc::testing::public_key_json(&[9; 32], SOC_KEY_ID),
    )
    .unwrap();
    std::fs::set_permissions(&soc, std::fs::Permissions::from_mode(0o644)).unwrap();
    let mut v: Value = serde_json::from_str(
        &std::fs::read_to_string(root().join("executor.example.json")).unwrap(),
    )
    .unwrap();
    v["key_file"] = key.to_str().unwrap().into();
    v["state_dir"] = d.join("state").to_str().unwrap().into();
    v["socket"] = d.join("executor.sock").to_str().unwrap().into();
    v["policy_path"] = d.join("policy.json").to_str().unwrap().into();
    v["soc"] = json!({"keys": [soc], "key_scopes": key_scopes});
    let cfg = d.join("executor.json");
    std::fs::write(&cfg, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    cfg
}

fn check(cfg: &Path) -> (Option<i32>, String) {
    let out = Command::new(BIN)
        .arg("--config")
        .arg(cfg)
        .arg("--check-config")
        .output()
        .unwrap();
    (
        out.status.code(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[test]
fn check_config_fails_on_a_key_scopes_entry_naming_no_soc_key() {
    let scope = json!({"actions": ["quarantine_node"], "max_ttl_s": 900});
    // No entry, and an entry for the loaded key: the check passes.
    for (tag, scopes) in [
        ("none", json!({})),
        ("match", json!({ SOC_KEY_ID: scope.clone() })),
    ] {
        let (code, text) = check(&setup(tag, scopes));
        assert_eq!(code, Some(0), "{tag}: {text}");
        assert!(text.contains("configuration ok"), "{tag}: {text}");
    }
    // A mistyped key id: exit 2, naming the entry and what it does.
    let (code, text) = check(&setup("typo", json!({ "soc:chek:1": scope })));
    assert_eq!(code, Some(2), "{text}");
    assert!(
        text.contains("\"soc:chek:1\"")
            && text.contains("key_scope_denied")
            && !text.contains("configuration ok"),
        "{text}"
    );
}
