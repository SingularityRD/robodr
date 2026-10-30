//! Sprint 14a exit criteria (`docs/SECURE-DELIVERY.md` §10), with software
//! TPMs (`ROBODR_SWTPM=1`): four units (lab `bench-01`, canary `ugv-08`,
//! ring-1 `ugv-07` and `ugv-09`), each a swtpm manufactured with an EK
//! certificate, a seal directory and a delivery agent; one depot.
//!
//! * a bundle enters only with the entry station's passing report;
//! * every unit enrols with credential activation and two operators;
//! * a staged rollout lab → canary → ring-1, each stage approved by the
//!   quorum of its ring, delivered over mutual TLS (the unit's key in its
//!   TPM), advanced only after every unit reported healthy;
//! * a release that fails its health gate on the canary halts the rollout
//!   there: ring-1 never receives it;
//! * a sealed model assigned only to ugv-07 (and its canary) cannot be
//!   decrypted by a captured ugv-09, whatever it is given.

mod common;

use common::*;
use robodr_depot::db::{DeployState, RolloutState};
use robodr_depot::depot::{Depot, RolloutParams};

const MARKER: &[u8] = b"ROBODR-TEST-14A-MODEL-ONLY-FOR-UGV07-5e1f";

fn params() -> RolloutParams {
    RolloutParams {
        soak_s: 0,
        ..Default::default()
    }
}

/// Pull over the LAN, install, report: one unit's delivery round.
fn round(u: &UnitH) -> robodr_deliverd::Engine {
    robodr_deliverd::lan::pull(&u.cfg()).unwrap();
    // The agent's loop does not download an unchanged pack again.
    assert_eq!(
        robodr_deliverd::lan::pull_if_changed(&u.cfg()).unwrap(),
        None
    );
    let mut e = u.open();
    u.run(&mut e, 12);
    robodr_deliverd::lan::report(&mut e).unwrap();
    e
}

fn approve(s: &Served, site: &Site, seq: u64, n: usize) -> bool {
    let mut active = false;
    for op in &site.ops[..n] {
        active = s.with(|d| d.deploy_approve(seq, op, now())).unwrap();
    }
    active
}

#[test]
fn staged_rollout_halt_at_canary_and_captured_unit() {
    if !swtpm_enabled("exit_14a") {
        return;
    }
    let mut site = Site::new("exit14a");
    let mut units: Vec<UnitH> = Vec::new();
    for id in ["bench-01", "ugv-08", "ugv-07", "ugv-09"] {
        units.push(UnitH::new(&site, id, &site.ca, false));
    }
    site.write_trust(&[
        ("lab", &["bench-01"]),
        ("canary", &["ugv-08"]),
        ("ring-1", &["ugv-07", "ugv-09"]),
    ]);
    // The trust file lists the EK CA, which exists once a TPM was made.
    for u in &units {
        u.anchor(&site);
    }
    let cfg = site.depot_config(false, None);
    Depot::init(&cfg, &site.trust_path, now()).unwrap();
    let mut d = Depot::open(cfg, now()).unwrap();

    // Release 1: nav-stack v1 and the sealed model.
    std::fs::write(site.hw.join("nav-stack-ok"), b"sensor").unwrap();
    let v1 = site.files_rpk("nav-stack", 1);
    let model = site.sealed_model("nav-model", 1, MARKER);
    let b1 = site.bundle(1, None, &[v1.clone(), model.clone()]);
    // No report, a report for another bundle: refused; the right one: in.
    let none = b1.with_extension("missing.json");
    assert!(d.import(&b1, &none, now()).is_err());
    let r1 = site.entry_report(&b1);
    d.import(&b1, &r1, now()).unwrap();

    for u in &units {
        enrol(&site, &mut d, u);
    }
    let served = Served::start(d);
    for u in &mut units {
        u.connect(served.port);
    }
    let [lab, canary, ugv07, ugv09] = &units[..] else {
        unreachable!()
    };

    // Ring skipping is not expressible.
    for stages in [vec!["ring-1"], vec!["lab", "ring-1"], vec!["canary", "lab"]] {
        let st: Vec<String> = stages.iter().map(|s| s.to_string()).collect();
        assert!(served
            .with(|d| d.rollout_create("skip", &[digest(&v1)], &st, &params(), now()))
            .is_err());
    }
    // Rollout r1: lab -> canary -> ring-1.
    let st: Vec<String> = ["lab", "canary", "ring-1"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let seq = served
        .with(|d| d.rollout_create("r1", &[digest(&v1)], &st, &params(), now()))
        .unwrap();
    // Not approved: the unit gets nothing (404).
    assert!(robodr_deliverd::lan::pull(&lab.cfg()).is_err());
    // No advancing before the stage passed.
    assert!(served.with(|d| d.rollout_advance("r1", now())).is_err());
    assert!(approve(&served, &site, seq, 1), "lab: one operator");
    round(lab);
    assert_eq!(lab.current("files", "nav-stack").as_deref(), Some("1"));
    let seq = served
        .with(|d| d.rollout_advance("r1", now()))
        .unwrap()
        .unwrap();
    assert!(
        approve(&served, &site, seq, 1),
        "canary: one operator (trust ring)"
    );
    round(canary);
    let seq = served
        .with(|d| d.rollout_advance("r1", now()))
        .unwrap()
        .unwrap();
    // Production: one operator is not enough.
    assert!(!approve(&served, &site, seq, 1));
    assert!(robodr_deliverd::lan::pull(&ugv07.cfg()).is_err());
    assert!(served
        .with(|d| d.deploy_approve(seq, &site.ops[1], now()))
        .unwrap());
    round(ugv07);
    round(ugv09);
    for u in &units {
        assert_eq!(
            u.current("files", "nav-stack").as_deref(),
            Some("1"),
            "{}",
            u.id
        );
    }
    assert_eq!(
        served.with(|d| d.rollout_advance("r1", now())).unwrap(),
        None
    );

    // Release 2: v2, healthy on the lab unit, failing on the canary (its
    // health check's file is gone by the time the canary installs it).
    let v2 = site.files_rpk("nav-stack", 2);
    let b2 = site.bundle(2, Some(bundle_hash(&b1)), &[v2.clone()]);
    let r2 = site.entry_report(&b2);
    served.with(|d| d.import(&b2, &r2, now())).unwrap();
    let seq = served
        .with(|d| d.rollout_create("r2", &[digest(&v2)], &st, &params(), now()))
        .unwrap();
    approve(&served, &site, seq, 1);
    round(lab);
    assert_eq!(lab.current("files", "nav-stack").as_deref(), Some("2"));
    let seq = served
        .with(|d| d.rollout_advance("r2", now()))
        .unwrap()
        .unwrap();
    approve(&served, &site, seq, 1);
    std::fs::remove_file(site.hw.join("nav-stack-ok")).unwrap();
    let e = round(canary);
    assert_eq!(
        canary.current("files", "nav-stack").as_deref(),
        Some("1"),
        "the canary rolled back"
    );
    assert!(canary
        .rules()
        .contains(&"robot.deliver.health_failed".to_string()));
    drop(e);
    served.with(|d| {
        let r = &d.db.rollouts["r2"];
        assert_eq!(r.state, RolloutState::Halted, "{r:?}");
        assert_eq!(d.db.deployments[&seq].state, DeployState::Halted);
        assert!(d.rollout_advance("r2", now()).is_err());
        assert!(
            d.rollout_resume("r2", &[&site.ops[0]], now()).is_err(),
            "one operator cannot resume"
        );
    });
    assert!(spool_rules(&site.dir().join("depot-spool"))
        .contains(&"robot.depot.rollout_halted".to_string()));
    // Ring-1 never received v2: their pack is still r1's ring-1 stage.
    for u in [ugv07, ugv09] {
        round(u);
        assert_eq!(
            u.current("files", "nav-stack").as_deref(),
            Some("1"),
            "{}",
            u.id
        );
    }

    // The sealed model, for ugv-07 only (and its canary).
    let seq = served
        .with(|d| {
            d.rollout_create(
                "m1",
                &[digest(&model)],
                &["canary".to_string(), "ring-1".to_string()],
                &RolloutParams {
                    units: Some(vec!["ugv-08".into(), "ugv-07".into()]),
                    ..params()
                },
                now(),
            )
        })
        .unwrap();
    approve(&served, &site, seq, 1);
    round(canary);
    let seq = served
        .with(|d| d.rollout_advance("m1", now()))
        .unwrap()
        .unwrap();
    approve(&served, &site, seq, 2);
    round(ugv07);
    let w = std::fs::read(
        ugv07
            .dir
            .join("runtime/model/nav-model/current/weights.onnx"),
    )
    .unwrap();
    assert_eq!(w, MARKER);
    // ugv-09 over the LAN: still its own (r1) pack, no model, no wrap.
    round(ugv09);
    assert!(!ugv09.dir.join("runtime/model/nav-model").exists());
    // Captured ugv-09 with ugv-07's media pack (every wrap of the
    // deployment is in it): the pack is refused, and its TPM cannot
    // unwrap ugv-07's wrap either.
    let pack = ugv09.dir.join("media/stolen");
    served.with(|d| d.write_pack("ugv-07", &pack)).unwrap();
    let mut e = ugv09.open();
    ugv09.run(&mut e, 6);
    drop(e);
    assert!(!ugv09.dir.join("runtime/model/nav-model").exists());
    let dep: robodr_pkg::deployment::Deployment =
        serde_json::from_slice(&std::fs::read(pack.join("deployment.json")).unwrap()).unwrap();
    let wk = dep
        .wrapped_keys
        .iter()
        .find(|w| w.unit == "ugv-07")
        .unwrap();
    let m = robodr_pkg::rpk::parse_manifest(&std::fs::read(model.join("MANIFEST.json")).unwrap())
        .unwrap();
    let wrap = robodr_seal::from_hex(&wk.wrap).unwrap();
    assert!(ugv09
        .seal()
        .unwrap_content_key(&wrap, &digest(&model), m.seal.as_ref().unwrap())
        .is_err());
    assert!(!dep.wrapped_keys.iter().any(|w| w.unit == "ugv-09"));
    // No plaintext anywhere on ugv-09 (outside the stolen media).
    let hits = seal::files_containing(
        &[
            &ugv09.dir.join("state"),
            &ugv09.dir.join("runtime"),
            &ugv09.dir.join("blackbox"),
            &ugv09.dir.join("seal"),
        ],
        MARKER,
    );
    assert!(hits.is_empty(), "{hits:?}");
}
