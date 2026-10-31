//! T85: `robodr-blackbox backup create | verify | restore` round trip on a
//! unit tree laid out as the package lays it out, honouring OPERATIONS §14:
//! configuration and keys come back, evidence goes only to an archive
//! directory, and the §14.1 "never restore" state never comes back, not
//! even from an archive crafted to hold it.

mod common;

use common::TestDir;
use robodr_blackbox::backup::{self, RestoreOptions, MAGIC};
use robodr_blackbox::crypto::{sha256, to_hex, Sha256};
use std::path::Path;
use std::process::Command;

fn put(root: &Path, rel: &str, data: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, data).unwrap();
}

/// Every row of OPERATIONS §14.1, one file each.
const RESTORED: &[&str] = &[
    "etc/robodr/agentd.json",
    "etc/robodr/control-plane/soc-ca.pem",
    "etc/robodr/keys/agentd-blackbox.key",
    "etc/systemd/system/robodr-agentd.service.d/20-finding-key.conf",
    "etc/robodr-depot/depot.json",
    "etc/robodr-anchor-receiver/receiver.json",
    "var/lib/robodr-anchor-receiver/heads.json",
];
const EVIDENCE: &[&str] = &[
    "var/lib/robodr/blackbox/agentd/seg-0000000000000000.rbb",
    "var/lib/robodr/blackbox/pulsard/seg-0000000000000000.rbb",
    "var/lib/robodr/fleet/journal/j-1.json",
    "var/lib/robodr/archive/2026-10.tar",
    "var/lib/robodr/export/diode/batch-1.rbdiode",
    "var/lib/robodr/control-plane/agentd/exports/abc/bundle.rbbx",
    "var/lib/robodr/firewall-gw/events.jsonl",
    "var/lib/robodr/spool/agentd/acked/1.json",
    "var/lib/robodr/depot/depot.db",
];
const READY: &[&str] = &[
    "var/lib/robodr/spool/agentd/ready/7.json",
    "var/lib/robodr/spool/pulsard/ready/3.json",
];
/// §14.1 "Restore: no" (and not even backed up, mostly).
const NEVER: &[&str] = &[
    "var/lib/robodr/control-plane/agentd/replay.json",
    "var/lib/robodr/executor/journal.json",
    "var/lib/robodr/firewall-gw/writers.json",
    "var/lib/robodr/profile-state/state.json",
    "var/lib/robodr/profile-state-pulsard/state.json",
    "var/lib/robodr/releases/security-floor",
    "var/lib/robodr/fleet/enrollment.json",
    "var/lib/robodr/deliverd/floors.json",
    "var/lib/robodr-seal/sealed.blob",
    "var/lib/robodr/anchor/sidecar.json",
    "var/lib/robodr/export/spool-export/state.json",
    "var/lib/robodr/export/kafka-publish/state.json",
    "var/lib/robodr/export/uplink/state.json",
    "opt/robodr-delivered/pkg/bin",
];

fn unit(root: &Path) {
    for p in RESTORED.iter().chain(EVIDENCE).chain(READY).chain(NEVER) {
        put(root, p, &format!("content of {p}"));
    }
    put(root, "etc/passwd", "root:x:0:0");
    put(
        root,
        "etc/systemd/system/sshd.service.d/x.conf",
        "[Service]",
    );
}

fn archive(root: &Path, out: &Path, keys: bool) -> backup::CreateReport {
    let f = std::fs::File::create(out).unwrap();
    backup::create(root, std::io::BufWriter::new(f), keys).unwrap()
}

#[test]
fn round_trip_restores_config_and_never_restores_monotonic_state() {
    let d = TestDir::new("t85-rt");
    let src = d.sub("unit");
    unit(&src);
    let a = d.sub("backup.rbkup");
    let rep = archive(&src, &a, true);
    assert!(rep.files >= (RESTORED.len() + EVIDENCE.len() + READY.len()) as u64);
    // Backed up: no other unit's / system file.
    let entries = backup::verify(&mut std::fs::File::open(&a).unwrap()).unwrap();
    let names: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    assert!(!names.contains(&"etc/passwd"));
    assert!(!names.iter().any(|n| n.contains("sshd")));
    for p in NEVER.iter().filter(|p| {
        !p.starts_with("var/lib/robodr/export/") && !p.starts_with("var/lib/robodr/fleet/")
    }) {
        assert!(!names.contains(p), "{p} must not even be backed up");
    }

    // Restore onto a rebuilt unit (fresh root), evidence to an archive dir.
    let dst = d.sub("rebuilt");
    std::fs::create_dir_all(dst.join("var/lib/robodr/spool/agentd/ready")).unwrap();
    std::fs::create_dir_all(dst.join("var/lib/robodr/spool/pulsard/ready")).unwrap();
    let ev = d.sub("evidence");
    let rep = backup::restore(
        &a,
        &dst,
        &RestoreOptions {
            spool_ready: true,
            evidence_to: Some(ev.clone()),
            dry_run: false,
        },
    )
    .unwrap();
    for p in RESTORED.iter().chain(READY) {
        assert_eq!(
            std::fs::read_to_string(dst.join(p)).unwrap(),
            format!("content of {p}"),
            "{p}"
        );
    }
    for p in EVIDENCE {
        assert!(!dst.join(p).exists(), "evidence {p} restored into the unit");
        assert_eq!(
            std::fs::read_to_string(ev.join(p)).unwrap(),
            format!("content of {p}")
        );
    }
    for p in NEVER {
        assert!(!dst.join(p).exists(), "{p} restored");
        assert!(!ev.join(p).exists(), "{p} extracted as evidence");
    }
    // The exporter state that was backed up is named, with its reason.
    assert!(rep
        .refused
        .iter()
        .any(|(p, why)| p == "var/lib/robodr/export/uplink/state.json"
            && why.contains("exporter sequence state")));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = |p: &str| std::fs::metadata(dst.join(p)).unwrap().permissions().mode() & 0o7777;
        assert_eq!(m("etc/robodr/keys/agentd-blackbox.key"), 0o600);
        assert_eq!(m("etc/robodr/keys"), 0o700);
    }
}

#[test]
fn keys_only_with_include_keys_and_spool_and_evidence_only_on_request() {
    let d = TestDir::new("t85-opts");
    let src = d.sub("unit");
    unit(&src);
    let a = d.sub("backup.rbkup");
    let rep = archive(&src, &a, false);
    assert!(rep.skipped.iter().any(|(p, _)| p == "etc/robodr/keys"));
    let dst = d.sub("rebuilt");
    std::fs::create_dir_all(dst.join("var/lib/robodr/spool/agentd/ready")).unwrap();
    put(
        &dst,
        "var/lib/robodr/spool/pulsard/ready/99.json",
        "own finding",
    );
    let rep = backup::restore(&a, &dst, &RestoreOptions::default()).unwrap();
    assert!(!dst.join("etc/robodr/keys").exists());
    assert!(dst.join("etc/robodr/agentd.json").exists());
    for p in READY.iter().chain(EVIDENCE) {
        assert!(!dst.join(p).exists(), "{p}");
    }
    assert!(rep.evidence.is_empty());
    // --spool-ready, but pulsard's ready/ already holds a finding of the
    // rebuilt unit: only agentd's comes back.
    backup::restore(
        &a,
        &dst,
        &RestoreOptions {
            spool_ready: true,
            ..RestoreOptions::default()
        },
    )
    .unwrap();
    assert!(dst.join(READY[0]).exists());
    assert!(!dst.join(READY[1]).exists());
}

/// A raw archive with arbitrary entries (what an attacker or a hand-made
/// tar-to-rbkup conversion could hand the operator).
fn crafted(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    let mut h = Sha256::new();
    for (p, data) in entries {
        let hd = serde_json::to_vec(&serde_json::json!({
            "kind": "file", "path": p, "mode": 0o4755, "size": data.len(),
            "sha256": to_hex(&sha256(data)),
        }))
        .unwrap();
        let lp = (hd.len() as u32).to_be_bytes();
        h.update(&lp);
        h.update(&hd);
        out.extend_from_slice(&lp);
        out.extend_from_slice(&hd);
        out.extend_from_slice(data);
    }
    let end = serde_json::to_vec(&serde_json::json!({
        "kind": "end", "entries": entries.len(), "headers_sha256": to_hex(&h.finalize()),
    }))
    .unwrap();
    out.extend_from_slice(&(end.len() as u32).to_be_bytes());
    out.extend_from_slice(&end);
    out
}

#[test]
fn crafted_archives_cannot_roll_back_state_or_escape_the_root() {
    let d = TestDir::new("t85-crafted");
    let dst = d.sub("unit");
    std::fs::create_dir_all(dst.join("etc/robodr")).unwrap();
    std::fs::create_dir_all(dst.join("var/lib/robodr/releases")).unwrap();
    std::fs::write(dst.join("var/lib/robodr/releases/security-floor"), "7").unwrap();

    // A rollback of the security floor and the replay store: refused.
    let a = d.sub("rollback.rbkup");
    std::fs::write(
        &a,
        crafted(&[
            ("var/lib/robodr/releases/security-floor", b"1"),
            ("var/lib/robodr/control-plane/agentd/replay.json", b"{}"),
            ("etc/robodr/agentd.json", b"{\"ok\":1}"),
        ]),
    )
    .unwrap();
    let rep = backup::restore(&a, &dst, &RestoreOptions::default()).unwrap();
    assert_eq!(
        std::fs::read_to_string(dst.join("var/lib/robodr/releases/security-floor")).unwrap(),
        "7"
    );
    assert!(!dst.join("var/lib/robodr/control-plane").exists());
    assert_eq!(rep.restored, vec!["etc/robodr/agentd.json".to_string()]);
    assert_eq!(rep.refused.len(), 2);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(dst.join("etc/robodr/agentd.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(m & 0o7000, 0, "set-id bits are never restored");
    }

    // Path escapes are refused before anything is written.
    for bad in [
        "../outside",
        "/etc/robodr/x",
        "etc/robodr/../../x",
        "etc//robodr",
    ] {
        let a = d.sub("escape.rbkup");
        std::fs::write(
            &a,
            crafted(&[("etc/robodr/first.json", b"1"), (bad, b"pwned")]),
        )
        .unwrap();
        let e = backup::restore(&a, &dst, &RestoreOptions::default()).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData, "{bad}: {e}");
        assert!(!dst.join("etc/robodr/first.json").exists(), "{bad}");
        assert!(!d.sub("outside").exists());
    }

    // A symlink planted in the target tree is not followed.
    #[cfg(unix)]
    {
        let elsewhere = d.sub("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, dst.join("etc/robodr/control-plane")).unwrap();
        let a = d.sub("link.rbkup");
        std::fs::write(&a, crafted(&[("etc/robodr/control-plane/ca.pem", b"x")])).unwrap();
        let rep = backup::restore(&a, &dst, &RestoreOptions::default()).unwrap();
        assert!(rep.restored.is_empty());
        assert!(!elsewhere.join("ca.pem").exists());
    }

    // A flipped byte, a cut archive, an edited end record: nothing written.
    let good = crafted(&[("etc/robodr/new.json", b"0123456789")]);
    let mut flipped = good.clone();
    let i = flipped.len() - 60;
    flipped[i] ^= 1;
    let cut = good[..good.len() - 5].to_vec();
    for (tag, bytes) in [("flipped", flipped), ("cut", cut)] {
        let a = d.sub(tag);
        std::fs::write(&a, bytes).unwrap();
        assert!(
            backup::restore(&a, &dst, &RestoreOptions::default()).is_err(),
            "{tag}"
        );
        assert!(!dst.join("etc/robodr/new.json").exists(), "{tag}");
    }
}

#[test]
fn cli_round_trip() {
    let d = TestDir::new("t85-cli");
    let src = d.sub("unit");
    unit(&src);
    let bin = env!("CARGO_BIN_EXE_robodr-blackbox");
    let a = d.sub("b.rbkup");
    let o = Command::new(bin)
        .args(["backup", "create", "--root"])
        .arg(&src)
        .arg("--out")
        .arg(&a)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    // Never overwritten.
    let o2 = Command::new(bin)
        .args(["backup", "create", "--root"])
        .arg(&src)
        .arg("--out")
        .arg(&a)
        .output()
        .unwrap();
    assert_eq!(o2.status.code(), Some(2));
    let o = Command::new(bin)
        .args(["backup", "verify"])
        .arg(&a)
        .output()
        .unwrap();
    assert!(o.status.success());
    let dst = d.sub("rebuilt");
    std::fs::create_dir_all(&dst).unwrap();
    // Evidence into the unit's own state is refused.
    let o = Command::new(bin)
        .args(["backup", "restore"])
        .arg(&a)
        .arg("--root")
        .arg(&dst)
        .arg("--evidence-to")
        .arg(dst.join("var/lib/robodr/blackbox"))
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    let o = Command::new(bin)
        .args(["backup", "restore"])
        .arg(&a)
        .arg("--root")
        .arg(&dst)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains("restored: etc/robodr/agentd.json"), "{out}");
    assert!(
        out.contains("not restored: var/lib/robodr/export/uplink/state.json"),
        "{out}"
    );
    assert!(dst.join("etc/robodr/agentd.json").exists());
    // A damaged archive: exit 1, nothing restored.
    let mut b = std::fs::read(&a).unwrap();
    let n = b.len() / 2;
    b[n] ^= 0xff;
    let bad = d.sub("bad.rbkup");
    std::fs::write(&bad, b).unwrap();
    let o = Command::new(bin)
        .args(["backup", "verify"])
        .arg(&bad)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
}
