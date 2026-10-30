//! Sprint 14b exit criteria and adversarial tests (`docs/SECURE-DELIVERY.md`
//! §10), with software TPMs (`ROBODR_SWTPM=1`):
//!
//! * lease expiry blocks unseal after a reboot (`robot.seal.lease_expired`),
//!   a fresh lease from the depot opens again; a unit without a lease-gated
//!   UWK is refused at a site that uses leases;
//! * crypto-erase from a simulated tamper input: deferred while the robot
//!   moves fast (`robot.seal.erase_deferred`, also across a restart),
//!   executed when idle; trigger spoofing (another uid, a finding with the
//!   tamper rule id, a person's trigger on the platform socket) does
//!   nothing;
//! * floors in a TPM NV counter: migration from the 13b record, then a
//!   restored disk, a recreated counter and a deleted black box lock;
//! * the SOC sees the chain of findings through the existing diode path
//!   (spool exporter → diode pack → import).

mod common;

use common::*;
use robodr_depot::depot::{Depot, RolloutParams};
use robodr_pkg::common::to_canonical;
use robodr_pkg::deployment::{
    Deployment, Item, Rollout, Targets, DEPLOYMENT_FORMAT, DEPLOYMENT_SIG_DOMAIN,
};
use robodr_pkg::sig::SignatureSet;
use std::path::{Path, PathBuf};

/// The findings of `spool` as the SOC receives them: exported by the
/// spool exporter into diode batches, carried across, imported and
/// validated. Returns the rule ids.
fn through_diode(spool: &Path, unit: &str, root: &Path) -> Vec<String> {
    use robodr_diode::{ImportConfig, Importer, Keyring, PackConfig, Packer};
    let key = || Box::new(robodr_blackbox::HmacSha256Key::new("diode-1", &[5u8; 32]).unwrap());
    std::fs::create_dir_all(root.join("outbox")).unwrap();
    let pc = PackConfig::new(unit);
    let packer = Packer::open(
        &root.join("outbox"),
        &root.join("pack-state.json"),
        pc.clone(),
        key(),
    )
    .unwrap();
    let mut ex = robodr_export::spool_export::Exporter::open(
        robodr_export::spool_export::ExportConfig::for_packer(
            spool,
            root.join("export-state.json"),
            &pc,
        ),
        packer,
    )
    .unwrap();
    let now_ms = now() * 1000;
    let rep = ex.run_once(now_ms).unwrap();
    assert!(rep.rejected.is_empty(), "{:?}", rep.rejected);
    let inbox = root.join("high/inbox");
    std::fs::create_dir_all(&inbox).unwrap();
    for b in &rep.batches {
        let st = std::process::Command::new("cp")
            .arg("-a")
            .arg(root.join("outbox").join(&b.name))
            .arg(inbox.join(&b.name))
            .status()
            .unwrap();
        assert!(st.success());
    }
    let mut k = Keyring::new();
    k.add(unit, key()).unwrap();
    let mut imp = Importer::open(ImportConfig::under(&root.join("high")), k).unwrap();
    let r = imp.run(now_ms).unwrap();
    assert!(r.quarantined.is_empty(), "{:?}", r.quarantined);
    let mut ids = Vec::new();
    for a in &r.accepted {
        let t = std::fs::read_to_string(a.output.join(robodr_diode::unpack::RECORDS_FILE)).unwrap();
        for l in t.lines() {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            let env = robodr_ocsf::parse_and_validate(v["value"].as_str().unwrap()).unwrap();
            let j: serde_json::Value = serde_json::to_value(&env).unwrap();
            ids.push(j["entity_context"]["rule_id"].as_str().unwrap().to_string());
        }
    }
    ids
}

#[test]
fn lease_expiry_blocks_unseal_after_reboot() {
    if !swtpm_enabled("lease_exit") {
        return;
    }
    let mut site = Site::new("lease14b");
    let mut u = UnitH::new(&site, "bench-01", &site.ca, true);
    let plain = UnitH::new(&site, "bench-02", &site.ca, false);
    site.write_trust(&[("lab", &["bench-01", "bench-02"])]);
    u.anchor(&site);
    plain.anchor(&site);
    let cfg = site.depot_config(true, None);
    Depot::init(&cfg, &site.trust_path, now()).unwrap();
    let mut d = Depot::open(cfg, now()).unwrap();
    // A UWK without the site's lease key is refused here.
    let n: [u8; 32] = robodr_seal::from_hex(&d.enrol_begin("bench-02", now()).unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let req = plain.seal().enrol_request(&n).unwrap();
    let e = d
        .enrol_verify(&serde_json::to_vec(&req).unwrap(), now())
        .unwrap_err();
    assert!(e.0.contains("lease"), "{e}");
    enrol(&site, &mut d, &u);
    let m1 = site.sealed_model("nav-model", 1, b"ROBODR-TEST-14B-LEASED-MODEL-1");
    let b1 = site.bundle(1, None, std::slice::from_ref(&m1));
    let r1 = site.entry_report(&b1);
    d.import(&b1, &r1, now()).unwrap();
    let p = RolloutParams {
        soak_s: 0,
        ..Default::default()
    };
    let seq = d
        .rollout_create("m1", &[digest(&m1)], &["lab".into()], &p, now())
        .unwrap();
    assert!(d.deploy_approve(seq, &site.ops[0], now()).unwrap());
    let s = Served::start(d);
    u.connect(s.port);
    // No lease yet: the sealed item waits, robot.seal.lease_expired.
    robodr_deliverd::lan::pull(&u.cfg()).unwrap();
    let mut e = u.open();
    u.run(&mut e, 4);
    assert_eq!(u.current("runtime/model", "nav-model"), None);
    assert!(u.rules().contains(&"robot.seal.lease_expired".to_string()));
    // The report brings a lease; the model installs.
    assert!(robodr_deliverd::lan::report(&mut e).unwrap());
    u.run(&mut e, 8);
    assert_eq!(
        u.current("runtime/model", "nav-model").as_deref(),
        Some("1")
    );
    drop(e);
    // The TPM's clock passes the lease (an hour of TPM time), then a
    // reboot: nothing unseals, by the unit and in the TPM.
    let t = u.seal().tpm_time().unwrap();
    let o = u.sw.tool(
        "tpm2_setclock",
        &[
            "-c",
            "o",
            "-p",
            "file:-",
            &(t.clock + 3_700_000).to_string(),
        ],
        Some(seal::OWNER_AUTH),
    );
    assert!(o.ok(), "{}", o.error_line());
    u.sw.restart();
    let err = u.seal().probe().unwrap_err();
    assert_eq!(err.kind, robodr_seal::ErrorKind::LeaseExpired, "{err}");
    // A new release waits for a lease again...
    let m2 = site.sealed_model("nav-model", 2, b"ROBODR-TEST-14B-LEASED-MODEL-2");
    let b2 = site.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&m2));
    let r2 = site.entry_report(&b2);
    s.with(|d| d.import(&b2, &r2, now())).unwrap();
    let seq = s
        .with(|d| d.rollout_create("m2", &[digest(&m2)], &["lab".into()], &p, now()))
        .unwrap();
    assert!(s
        .with(|d| d.deploy_approve(seq, &site.ops[0], now()))
        .unwrap());
    robodr_deliverd::lan::pull(&u.cfg()).unwrap();
    let mut e = u.open();
    u.run(&mut e, 4);
    assert_eq!(
        u.current("runtime/model", "nav-model").as_deref(),
        Some("1")
    );
    // ... until the depot renews it from the unit's current TPM time.
    assert!(robodr_deliverd::lan::report(&mut e).unwrap());
    u.run(&mut e, 8);
    assert_eq!(
        u.current("runtime/model", "nav-model").as_deref(),
        Some("2")
    );
    let unit_id = e.config().unit.id.clone();
    drop(e);
    // A renewal by media: this lease runs out too; the unit's report goes
    // to the depot by media and the depot's media pack carries the new
    // lease with the deployment the unit already has (a pack it has seen):
    // the lease is still installed.
    let t = u.seal().tpm_time().unwrap();
    let o = u.sw.tool(
        "tpm2_setclock",
        &[
            "-c",
            "o",
            "-p",
            "file:-",
            &(t.clock + 3_700_000).to_string(),
        ],
        Some(seal::OWNER_AUTH),
    );
    assert!(o.ok(), "{}", o.error_line());
    u.sw.restart();
    let err = u.seal().probe().unwrap_err();
    assert_eq!(err.kind, robodr_seal::ErrorKind::LeaseExpired, "{err}");
    let e = u.open();
    let rep = e.unit_report().unwrap();
    drop(e);
    assert!(s
        .with(|d| d.accept_report(None, &rep, now()))
        .unwrap()
        .is_some());
    s.with(|d| d.write_pack(&unit_id, &u.dir.join("media").join("renewal")))
        .unwrap();
    let mut e = u.open();
    u.run(&mut e, 4);
    drop(e);
    u.seal().probe().unwrap();
    // The SOC sees the unit's chain through the diode, and the depot's.
    let ids = through_diode(
        &u.dir.join("spool"),
        "bench-01",
        &site.dir().join("soc-unit"),
    );
    for want in ["robot.seal.lease_expired", "robot.deliver.installed"] {
        assert!(ids.iter().any(|i| i == want), "{want} not in {ids:?}");
    }
    let ids = through_diode(
        &site.dir().join("depot-spool"),
        "depot-1",
        &site.dir().join("soc-depot"),
    );
    for want in ["robot.depot.enrolment_refused", "robot.depot.unit_enrolled"] {
        assert!(ids.iter().any(|i| i == want), "{want} not in {ids:?}");
    }
}

#[test]
fn erase_from_a_tamper_input_is_graded_by_safety_and_cannot_be_spoofed() {
    if !swtpm_enabled("erase_exit") {
        return;
    }
    let mut site = Site::new("erase14b");
    let mut u = UnitH::new(&site, "ugv-07", &site.ca, false);
    site.write_trust(&[("ring-1", &["ugv-07"])]);
    u.anchor(&site);
    let sock = u.dir.join("erase.sock");
    u.cfg_json["erase"] = serde_json::json!({"trigger_socket": sock, "feeder_uids": [4242]});
    let cfg = u.cfg();
    let trig = robodr_deliverd::erasex::TriggerSocket::bind(cfg.erase.as_ref().unwrap()).unwrap();
    let mut e = u.open();
    use robodr_deliverd::erasex::{send, Event};
    use robodr_responder::erase::EraseTrigger;
    // Spoofing 1: a process of another uid (the socket opened to it by
    // mistake): the kernel's peer credentials refuse it.
    {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::process::CommandExt;
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o666)).unwrap();
        let st = std::process::Command::new("python3")
            .arg("-c")
            .arg(format!(
                "import socket;s=socket.socket(socket.AF_UNIX);s.connect({:?});s.send(b'{{\"format\":\"robodr-erase-trigger/1\",\"trigger\":\"tamper\"}}\\n')",
                sock.display().to_string()
            ))
            .uid(65534)
            .gid(65534)
            .status()
            .unwrap();
        assert!(st.success());
        let evs = trig.poll();
        assert!(
            matches!(
                evs.as_slice(),
                [Event::Refused {
                    uid: Some(65534),
                    ..
                }]
            ),
            "{evs:?}"
        );
    }
    // Spoofing 2: a person's trigger on the platform socket.
    send(&sock, EraseTrigger::Operator).unwrap_or(());
    {
        use std::io::Write;
        let mut c = std::os::unix::net::UnixStream::connect(&sock).unwrap();
        c.write_all(b"{\"format\":\"robodr-erase-trigger/1\",\"trigger\":\"operator\"}\n")
            .unwrap();
    }
    assert!(trig
        .poll()
        .iter()
        .all(|e| matches!(e, Event::Refused { .. })));
    // Spoofing 3: a finding named robot.seal.tamper in the spool.
    let fake = u.dir.join("spool/ready/00000000000000099999.json");
    std::fs::write(&fake, br#"{"rule_id":"robot.seal.tamper"}"#).unwrap();
    u.run(&mut e, 2);
    std::fs::remove_file(&fake).unwrap();
    assert!(e.state().erase_pending.is_none());
    u.seal().probe().unwrap();
    // The tamper input while moving fast: planned, deferred.
    u.safety("moving_fast");
    send(&sock, EraseTrigger::Tamper).unwrap();
    let evs = trig.poll();
    let [Event::Trigger { trigger, .. }] = evs.as_slice() else {
        panic!("{evs:?}")
    };
    let r = e.erase_trigger(*trigger, 0).unwrap();
    assert!(r.starts_with("deferred"), "{r}");
    u.seal().probe().unwrap();
    // Still deferred after a restart of the agent.
    drop(e);
    let mut e = u.open();
    u.run(&mut e, 2);
    assert!(e.state().erase_pending.is_some());
    u.seal().probe().unwrap();
    // Idle: the erase runs.
    u.safety("idle");
    u.run(&mut e, 2);
    assert!(e.state().erase_pending.is_none());
    let err = u.seal().probe().unwrap_err();
    assert_eq!(err.kind, robodr_seal::ErrorKind::Erased);
    drop(e);
    let rules = u.rules();
    let pos = |r: &str| {
        rules
            .iter()
            .position(|x| x == r)
            .unwrap_or_else(|| panic!("{r}: {rules:?}"))
    };
    assert!(pos("robot.seal.tamper") < pos("robot.seal.erase_deferred"));
    assert!(pos("robot.seal.erase_deferred") < pos("robot.seal.erased"));
    assert_eq!(
        rules.iter().filter(|r| *r == "robot.seal.erased").count(),
        1
    );
    // The SOC side.
    let ids = through_diode(&u.dir.join("spool"), "ugv-07", &site.dir().join("soc"));
    for want in [
        "robot.seal.tamper",
        "robot.seal.erase_deferred",
        "robot.seal.erased",
    ] {
        assert!(ids.iter().any(|i| i == want), "{want} not in {ids:?}");
    }
}

/// A media pack for `u` (lab ring) with `rpks` from `bundles`, signed by
/// the depot key and one operator.
fn media_pack(site: &Site, u: &UnitH, name: &str, seq: u64, rpks: &[PathBuf], bundles: &[PathBuf]) {
    let mut items: Vec<Item> = rpks
        .iter()
        .map(|r| {
            let m =
                robodr_pkg::rpk::parse_manifest(&std::fs::read(r.join("MANIFEST.json")).unwrap())
                    .unwrap();
            Item {
                rpk_digest: digest(r),
                name: m.name,
                serial: m.version.serial,
            }
        })
        .collect();
    items.sort_by(|a, b| a.name.cmp(&b.name));
    let d = Deployment {
        format: DEPLOYMENT_FORMAT.into(),
        deployment_id: format!("dep-{seq}"),
        site: SITE.into(),
        deployment_seq: seq,
        created_at: now() - 60,
        targets: Targets {
            units: vec![u.id.clone()],
            groups: vec![],
        },
        ring: "lab".into(),
        items,
        not_before: now() - 60,
        expires_at: now() + 86400,
        rollout: Rollout {
            batch_size: 1,
            soak_s: 0,
            max_failures: 0,
        },
        maintenance_window: None,
        wrapped_keys: vec![],
    };
    let p = u.dir.join("media").join(name);
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(p.join("bundles")).unwrap();
    std::fs::copy(&site.trust_path, p.join("trust.json")).unwrap();
    std::fs::copy(
        robodr_release::ops::sig_path(&site.trust_path),
        p.join("trust.json.sig"),
    )
    .unwrap();
    let doc = to_canonical(&d).unwrap();
    std::fs::write(p.join("deployment.json"), &doc).unwrap();
    let mut s = SignatureSet::empty();
    s.add(&site.depot, DEPLOYMENT_SIG_DOMAIN, &doc).unwrap();
    s.add(&site.ops[0], DEPLOYMENT_SIG_DOMAIN, &doc).unwrap();
    std::fs::write(p.join("deployment.json.sig"), s.to_bytes().unwrap()).unwrap();
    for (i, b) in bundles.iter().enumerate() {
        let st = std::process::Command::new("cp")
            .arg("-a")
            .arg(b)
            .arg(p.join("bundles").join(format!("b{i}")))
            .status()
            .unwrap();
        assert!(st.success());
    }
}

fn copy_tree(from: &Path, to: &Path) {
    let _ = std::fs::remove_dir_all(to);
    let st = std::process::Command::new("cp")
        .arg("-a")
        .arg(from)
        .arg(to)
        .status()
        .unwrap();
    assert!(st.success());
}

#[test]
fn floors_in_a_tpm_nv_counter_survive_disk_rollback_and_counter_recreation() {
    if !swtpm_enabled("nv_floors") {
        return;
    }
    let mut site = Site::new("nvfloors");
    let mut u = UnitH::new(&site, "bench-01", &site.ca, false);
    site.write_trust(&[("lab", &["bench-01"])]);
    u.anchor(&site);
    std::fs::write(site.hw.join("nav-stack-ok"), b"ok").unwrap();
    // 13b: no anchor. v1 installed.
    let v1 = site.files_rpk("nav-stack", 1);
    let b1 = site.bundle(1, None, std::slice::from_ref(&v1));
    media_pack(
        &site,
        &u,
        "p1",
        1,
        std::slice::from_ref(&v1),
        std::slice::from_ref(&b1),
    );
    let mut e = u.open();
    u.run(&mut e, 8);
    assert_eq!(u.current("files", "nav-stack").as_deref(), Some("1"));
    drop(e);
    // Migration: the counter is defined (unwritten), the agent anchors its
    // 13b record on the next start.
    u.sw.tpm()
        .define_counter(0x0150_0042, seal::OWNER_AUTH)
        .unwrap();
    u.cfg_json["seal"]["anti_rollback_nv"] = "0x01500042".into();
    let e = u.open();
    assert!(e.state().locked.is_none());
    drop(e);
    let hw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(u.dir.join("blackbox/highwater.json")).unwrap())
            .unwrap();
    assert!(hw["doc"]["nv"].as_u64().is_some(), "{hw}");
    // The disk as it is now (an image an attacker keeps).
    let snap = u.dir.join("snapshot");
    std::fs::create_dir_all(&snap).unwrap();
    for d in ["state", "blackbox"] {
        copy_tree(&u.dir.join(d), &snap.join(d));
    }
    // v5 raises the floor to 5.
    let v5 = site.files_rpk_with_floor("nav-stack", 5, 5);
    let b2 = site.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&v5));
    media_pack(
        &site,
        &u,
        "p2",
        2,
        std::slice::from_ref(&v5),
        std::slice::from_ref(&b2),
    );
    let mut e = u.open();
    u.run(&mut e, 8);
    assert_eq!(u.current("files", "nav-stack").as_deref(), Some("5"));
    assert_eq!(e.state().floor("nav-stack"), 5);
    drop(e);
    // Restore the older disk (state, black box, record): locked.
    for d in ["state", "blackbox"] {
        copy_tree(&snap.join(d), &u.dir.join(d));
    }
    let e = u.open();
    let l = e.state().locked.clone().expect("locked");
    assert!(l.why.contains("NV counter"), "{}", l.why);
    drop(e);
    // Delete the black box and the state entirely: locked.
    for d in ["state", "blackbox"] {
        std::fs::remove_dir_all(u.dir.join(d)).unwrap();
        std::fs::create_dir_all(u.dir.join(d)).unwrap();
    }
    let e = u.open();
    assert!(e.state().locked.is_some(), "deleted black box and state");
    drop(e);
    // Undefine and define the counter again (owner authorization): locked.
    let o = u.sw.tool(
        "tpm2_nvundefine",
        &["0x01500042", "-C", "o", "-P", "file:-"],
        Some(seal::OWNER_AUTH),
    );
    assert!(o.ok());
    u.sw.tpm()
        .define_counter(0x0150_0042, seal::OWNER_AUTH)
        .unwrap();
    let e = u.open();
    assert!(e.state().locked.is_some(), "recreated counter");
}
