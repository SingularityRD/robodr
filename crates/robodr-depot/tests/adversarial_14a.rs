//! Sprint 14a adversarial tests (`docs/SECURE-DELIVERY.md` §10, 14a):
//! forged and replayed entry reports, wrong quorum, ring skipping, a
//! rolled-back depot database, unit impersonation at enrolment (fake TPM,
//! non-resident key, AK of another TPM, rogue authority, stale nonce,
//! changed boot), mutual-TLS client confusion between units, report
//! replay. TPM tests need `ROBODR_SWTPM=1`.

mod common;

use common::*;
use robodr_depot::depot::{Depot, RolloutParams};
use std::io::{Read, Write};
use std::sync::Arc;

fn site_with(units: &[(&str, bool)], tag: &str) -> (Site, Vec<UnitH>) {
    let mut site = Site::new(tag);
    let mut us = Vec::new();
    for (id, rogue) in units {
        let ca = if *rogue { &site.rogue_ca } else { &site.ca };
        us.push(UnitH::new(&site, id, ca, false));
    }
    site.write_trust(&[
        ("lab", &["bench-01"]),
        ("canary", &["ugv-08"]),
        ("ring-1", &["ugv-07", "ugv-09"]),
    ]);
    for u in &us {
        u.anchor(&site);
    }
    (site, us)
}

fn depot(site: &Site) -> Depot {
    let cfg = site.depot_config(false, None);
    Depot::init(&cfg, &site.trust_path, now()).unwrap();
    Depot::open(cfg, now()).unwrap()
}

#[test]
fn forged_replayed_and_failing_entry_reports_are_refused() {
    if !swtpm_enabled("entry_reports") {
        return;
    }
    let (site, _u) = site_with(&[("bench-01", false)], "entry");
    let mut d = depot(&site);
    let r1 = site.files_rpk("nav-stack", 1);
    let b1 = site.bundle(1, None, std::slice::from_ref(&r1));
    let rep1 = site.entry_report(&b1);
    let r2 = site.files_rpk("nav-stack", 2);
    let b2 = site.bundle(2, Some(bundle_hash(&b1)), std::slice::from_ref(&r2));
    // Bundle 1's report replayed for bundle 2.
    let replay = b2.with_extension("replayed.json");
    std::fs::copy(&rep1, &replay).unwrap();
    std::fs::copy(
        robodr_release::ops::sig_path(&rep1),
        robodr_release::ops::sig_path(&replay),
    )
    .unwrap();
    // Bundle 2 before bundle 1 (a gap) with its own report: refused too.
    let rep2 = site.entry_report(&b2);
    assert!(d.import(&b2, &rep2, now()).is_err(), "gap");
    d.import(&b1, &rep1, now()).unwrap();
    assert!(d.import(&b2, &replay, now()).is_err(), "replayed report");
    // A report signed by an operator key (not an entry key).
    let st = site.site_trust();
    let scan = robodr_depot::entry::scan(&robodr_depot::entry::ScanInput {
        bundle: &b2,
        site: &st,
        station: "entry-1",
        vulndb: None,
        history: &site.dir().join("h2"),
        fail_on: robodr_pkg::entry::Severity::High,
        now: now(),
        lifetime_s: 3600,
    })
    .unwrap();
    let forged = b2.with_extension("forged.json");
    let (b, s) = robodr_depot::entry::sign(&scan, &site.ops[0]).unwrap();
    std::fs::write(&forged, b).unwrap();
    std::fs::write(robodr_release::ops::sig_path(&forged), s).unwrap();
    assert!(
        d.import(&b2, &forged, now()).is_err(),
        "operator-signed report"
    );
    // A failing scan: a vulnerability database listing a component of the
    // SBOM... (the RPK has none) -> the verdict is forced to fail instead.
    let mut failing = scan.clone();
    failing.verdict = robodr_pkg::entry::Verdict::Fail;
    let fp = b2.with_extension("failing.json");
    let (b, s) = robodr_depot::entry::sign(&failing, &site.entry).unwrap();
    std::fs::write(&fp, b).unwrap();
    std::fs::write(robodr_release::ops::sig_path(&fp), s).unwrap();
    assert!(d.import(&b2, &fp, now()).is_err(), "failing verdict");
    d.import(&b2, &rep2, now()).unwrap();
    let refused = spool_rules(&site.dir().join("depot-spool"))
        .iter()
        .filter(|r| *r == "robot.depot.import_refused")
        .count();
    assert_eq!(refused, 4);
}

#[test]
fn enrolment_impersonation_is_refused() {
    if !swtpm_enabled("impersonation") {
        return;
    }
    let (site, us) = site_with(
        &[
            ("bench-01", false),
            ("ugv-08", false),
            ("ugv-07", true),
            ("ugv-09", false),
        ],
        "imperson",
    );
    let mut d = depot(&site);
    let (a, b, rogue, u9) = (&us[0], &us[1], &us[2], &us[3]);
    let begin = |d: &mut Depot, u: &str| -> [u8; 32] {
        robodr_seal::from_hex(&d.enrol_begin(u, now()).unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    };
    // (1) Fake TPM: an EK certificate from a CA the trust file does not list.
    let n = begin(&mut d, "ugv-07");
    let req = rogue.seal().enrol_request(&n).unwrap();
    let e = d
        .enrol_verify(&serde_json::to_vec(&req).unwrap(), now())
        .unwrap_err();
    assert!(e.0.contains("EK certificate"), "{e}");
    // (2) A TPM without an EK certificate: the request without it.
    let n = begin(&mut d, "bench-01");
    let mut req = a.seal().enrol_request(&n).unwrap();
    req.tpm.as_mut().unwrap().ek_certificate = None;
    assert!(d
        .enrol_verify(&serde_json::to_vec(&req).unwrap(), now())
        .is_err());
    // (3) Stale nonce: a request made for an earlier enrol begin.
    let old = begin(&mut d, "bench-01");
    let req_old = a.seal().enrol_request(&old).unwrap();
    begin(&mut d, "bench-01");
    assert!(d
        .enrol_verify(&serde_json::to_vec(&req_old).unwrap(), now())
        .is_err());
    // (4) Non-resident / foreign key as UWK: B's certified UWK in A's request.
    let n = begin(&mut d, "bench-01");
    let mut req = a.seal().enrol_request(&n).unwrap();
    let rb = b.seal().enrol_request(&n).unwrap();
    req.tpm.as_mut().unwrap().uwk_public_area = rb.tpm.as_ref().unwrap().uwk_public_area.clone();
    let e = d
        .enrol_verify(&serde_json::to_vec(&req).unwrap(), now())
        .unwrap_err();
    assert!(e.0.contains("another object") || e.0.contains("uwk"), "{e}");
    // A UWK-shaped key that is not resident (userwithauth set, created in
    // A's TPM and certified by A's AK): the attributes refuse it.
    let n = begin(&mut d, "bench-01");
    let mut req = a.seal().enrol_request(&n).unwrap();
    let w = a.dir.join("weak");
    std::fs::create_dir_all(&w).unwrap();
    let pol = w.join("pol");
    std::fs::write(&pol, [0u8; 32]).unwrap();
    let o = a.sw.tool(
        "tpm2_create",
        &[
            "-C",
            "0x81000001",
            "-G",
            "ecc256:ecdh",
            "-a",
            "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|noda",
            "-L",
            pol.to_str().unwrap(),
            "-u",
            w.join("k.pub").to_str().unwrap(),
            "-r",
            w.join("k.priv").to_str().unwrap(),
        ],
        None,
    );
    assert!(o.ok(), "{}", o.error_line());
    let kp = std::fs::read(w.join("k.pub")).unwrap();
    let kr = std::fs::read(w.join("k.priv")).unwrap();
    let akp = std::fs::read(a.dir.join("seal/ak.pub")).unwrap();
    let akr = std::fs::read(a.dir.join("seal/ak.priv")).unwrap();
    let cert =
        a.sw.tpm()
            .certify_with_ak((&akp, &akr), &[("weak", &kp, &kr)])
            .unwrap();
    let t = req.tpm.as_mut().unwrap();
    t.uwk_public_area = robodr_seal::to_hex(&kp);
    t.uwk_certify = robodr_seal::enrol::SignedHex {
        attest: robodr_seal::to_hex(&cert[0].attest),
        sig: robodr_seal::to_hex(&cert[0].sig),
    };
    let p = robodr_seal::attest::parse_tpm2b_public(&kp).unwrap();
    req.record.uwk_public = robodr_seal::to_hex(&p.p256().unwrap());
    let e = d
        .enrol_verify(&serde_json::to_vec(&req).unwrap(), now())
        .unwrap_err();
    assert!(e.0.contains("attributes"), "{e}");
    // (5) AK of another TPM: A's EK with B's AK and B's certified keys.
    // The depot's challenge goes to A's EK for B's AK name: neither TPM
    // can answer it.
    let n = begin(&mut d, "ugv-08");
    let mut req = b.seal().enrol_request(&n).unwrap();
    let ra = a.seal().enrol_request(&n).unwrap();
    let ta = ra.tpm.unwrap();
    let t = req.tpm.as_mut().unwrap();
    t.ek_public = ta.ek_public;
    t.ek_certificate = ta.ek_certificate;
    let ch = d
        .enrol_verify(&serde_json::to_vec(&req).unwrap(), now())
        .unwrap()
        .unwrap();
    let c = robodr_seal::enrol::parse_challenge(&ch).unwrap();
    assert!(
        b.seal().enrol_activate(&c).is_err(),
        "B's TPM has another EK"
    );
    let mut c_a = c.clone();
    c_a.unit = "bench-01".into();
    assert!(
        a.seal().enrol_activate(&c_a).is_err(),
        "A's TPM has another AK"
    );
    // A guessed answer closes the enrolment.
    let resp = robodr_seal::enrol::EnrolResponse {
        format: robodr_seal::enrol::RESPONSE_FORMAT.into(),
        unit: "ugv-08".into(),
        nonce: c.nonce.clone(),
        secret: "00".repeat(32),
    };
    assert!(d
        .enrol_finish(&serde_json::to_vec(&resp).unwrap(), now())
        .is_err());
    assert!(d
        .enrol_finish(&serde_json::to_vec(&resp).unwrap(), now())
        .is_err());
    // (6) Changed boot measurements: the quote no longer matches the
    // signed policy.
    u9.sw.extend(7, [9u8; 32]);
    let n = begin(&mut d, "ugv-09");
    let req = u9.seal().enrol_request(&n).unwrap();
    let e = d
        .enrol_verify(&serde_json::to_vec(&req).unwrap(), now())
        .unwrap_err();
    assert!(e.0.contains("boot measurements"), "{e}");
    // (7) Operators: one is not enough, the same twice counts once, a
    // release key is not an operator.
    enrol_upto_activation(&mut d, a);
    assert!(!d.enrol_approve("bench-01", &site.ops[0], now()).unwrap());
    assert!(d.enrol_approve("bench-01", &site.ops[0], now()).is_err());
    assert!(d.enrol_approve("bench-01", &site.rel[0], now()).is_err());
    assert!(d.enrol_approve("bench-01", &site.ops[1], now()).unwrap());
    let refused = spool_rules(&site.dir().join("depot-spool"))
        .iter()
        .filter(|r| *r == "robot.depot.enrolment_refused")
        .count();
    assert!(refused >= 7, "{refused}");
}

fn enrol_upto_activation(d: &mut Depot, u: &UnitH) {
    let n: [u8; 32] = robodr_seal::from_hex(&d.enrol_begin(&u.id, now()).unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let req = u.seal().enrol_request(&n).unwrap();
    let ch = d
        .enrol_verify(&serde_json::to_vec(&req).unwrap(), now())
        .unwrap()
        .unwrap();
    let resp = u
        .seal()
        .enrol_activate(&robodr_seal::enrol::parse_challenge(&ch).unwrap())
        .unwrap();
    d.enrol_finish(&serde_json::to_vec(&resp).unwrap(), now())
        .unwrap();
}

#[test]
fn a_unit_enrolled_with_a_rogue_authority_is_refused() {
    if !swtpm_enabled("rogue_authority") {
        return;
    }
    let mut site = Site::new("rogueauth");
    let dir = site.dir().join("units/bench-01");
    site.ca.manufacture(&dir.join("tpm"));
    let sw = seal::SwTpm::start(&dir.join("tpm"));
    sw.provision();
    let rogue = robodr_seal::keys::PolicyKey::generate().unwrap();
    let u = robodr_seal::unit::Unit::enroll_tpm(
        &dir.join("seal"),
        "bench-01",
        PLATFORM,
        &rogue.public(),
        sw.tpm(),
    )
    .unwrap();
    let p = robodr_seal::policy::sign(
        &rogue,
        PLATFORM,
        1,
        &sw.pcrs(&PCRS),
        robodr_seal::tpm::DEFAULT_FLOOR_NV,
    )
    .unwrap();
    u.install_policy(&p).unwrap();
    site.write_trust(&[("lab", &["bench-01"])]);
    let mut d = depot(&site);
    let n: [u8; 32] = robodr_seal::from_hex(&d.enrol_begin("bench-01", now()).unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let req = u.enrol_request(&n).unwrap();
    let e = d
        .enrol_verify(&serde_json::to_vec(&req).unwrap(), now())
        .unwrap_err();
    assert!(e.0.contains("authority"), "{e}");
}

/// One raw request over mutual TLS with `cert` and a signer; status, body.
fn tls(
    port: u16,
    ca: &std::path::Path,
    cert: &std::path::Path,
    sign: Arc<robodr_blackbox::tls::ExternalSign>,
    req: &[u8],
) -> Result<(u16, Vec<u8>), String> {
    let c = robodr_blackbox::tls::load_client_with_signer(
        &robodr_blackbox::tls::ClientTlsFiles {
            ca_file: ca.to_path_buf(),
            cert_chain: Some(cert.to_path_buf()),
            key_file: None,
            server_name: Some("depot.site-a".into()),
            spki_sha256: vec![],
            crl_files: vec![],
        },
        sign,
    )?;
    let sock = std::net::TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    let _ = sock.set_read_timeout(Some(std::time::Duration::from_secs(30)));
    let conn = rustls::ClientConnection::new(c.config.clone(), c.name_for("depot.site-a")?)
        .map_err(|e| e.to_string())?;
    let mut s = rustls::StreamOwned::new(conn, sock);
    s.write_all(req)
        .map_err(|e| robodr_blackbox::tls::describe(&e))?;
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let end = robodr_pkg::wire::head_end(&out).ok_or("no response")?;
    let (st, _) = robodr_pkg::wire::parse_response(&out[..end]).map_err(|e| e.to_string())?;
    Ok((st, out[end..].to_vec()))
}

fn signer_of(u: &UnitH) -> Arc<robodr_blackbox::tls::ExternalSign> {
    let dir = u.dir.join("seal");
    let cfg = u.sw.cfg();
    Arc::new(move |dg: &[u8; 32]| {
        let t = robodr_seal::tpm::Tpm::new(cfg.clone(), Box::new(robodr_seal::cmd::System))
            .map_err(|e| e.to_string())?;
        robodr_seal::unit::Unit::open(&dir, Some(t))
            .and_then(|u| u.sign_digest(dg))
            .map_err(|e| e.to_string())
    })
}

#[test]
fn mtls_client_confusion_wrong_quorum_ring_skipping_and_report_replay() {
    if !swtpm_enabled("mtls_confusion") {
        return;
    }
    let (site, mut us) = site_with(
        &[
            ("bench-01", false),
            ("ugv-08", false),
            ("ugv-07", false),
            ("ugv-09", false),
        ],
        "mtls",
    );
    let mut d = depot(&site);
    let r1 = site.files_rpk("nav-stack", 1);
    std::fs::write(site.hw.join("nav-stack-ok"), b"ok").unwrap();
    let b1 = site.bundle(1, None, std::slice::from_ref(&r1));
    let rep = site.entry_report(&b1);
    d.import(&b1, &rep, now()).unwrap();
    for u in &us {
        enrol(&site, &mut d, u);
    }
    // Ring skipping: no rollout reaches ring-1 without lab/canary first,
    // and no stage advances before it passed.
    let st = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let p = RolloutParams {
        soak_s: 0,
        ..Default::default()
    };
    assert!(d
        .rollout_create("x", &[digest(&r1)], &st(&["ring-1"]), &p, now())
        .is_err());
    assert!(d
        .rollout_create(
            "x",
            &[digest(&r1)],
            &st(&["canary", "ring-1", "ring-1"]),
            &p,
            now()
        )
        .is_err());
    let seq = d
        .rollout_create("r1", &[digest(&r1)], &st(&["canary", "ring-1"]), &p, now())
        .unwrap();
    assert!(
        d.rollout_advance("r1", now()).is_err(),
        "not approved, not installed"
    );
    // Wrong quorum: the depot key, a release key, an entry key never count.
    assert!(d.deploy_approve(seq, &site.rel[0], now()).is_err());
    assert!(d.deploy_approve(seq, &site.entry, now()).is_err());
    assert!(d.deploy_approve(seq, &site.depot, now()).is_err());
    assert!(d.deploy_approve(seq, &site.ops[0], now()).unwrap());
    let s = Served::start(d);
    for u in &mut us {
        u.connect(s.port);
    }
    let ca = us[1].dir.join("depot/depot-ca.pem");
    // Slot exhaustion by trickling: a client that sends a TLS record
    // header and then one byte every 1.5 s would hold a connection slot
    // forever under a per-read timeout. The server closes it at the
    // request deadline (deadline_s = 8 here) however it trickles.
    {
        use std::io::{Read, Write};
        let t0 = std::time::Instant::now();
        let mut c = std::net::TcpStream::connect(("127.0.0.1", s.port)).unwrap();
        c.set_read_timeout(Some(std::time::Duration::from_millis(1500)))
            .unwrap();
        c.write_all(&[0x16, 0x03, 0x01, 0x02, 0x00]).unwrap();
        let closed_after = loop {
            assert!(
                t0.elapsed() < std::time::Duration::from_secs(20),
                "a trickling client outlived the request deadline"
            );
            let mut b = [0u8; 64];
            match c.read(&mut b) {
                Ok(0) => break t0.elapsed(),
                Ok(_) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => break t0.elapsed(),
            }
            if c.write_all(&[0]).is_err() {
                break t0.elapsed();
            }
        };
        assert!(
            closed_after < std::time::Duration::from_secs(12),
            "{closed_after:?}"
        );
    }
    // ugv-08's identity: its own pack only.
    let (st8, body8) = tls(
        s.port,
        &ca,
        &us[1].dir.join("depot/client.pem"),
        signer_of(&us[1]),
        &robodr_pkg::wire::encode_request(robodr_pkg::wire::Request::Pack, "x"),
    )
    .unwrap();
    assert_eq!(st8, 200);
    assert!(String::from_utf8_lossy(&body8).contains("deployment.json"));
    // ugv-07 has no active deployment yet: 404, never another unit's.
    let (st7, _) = tls(
        s.port,
        &ca,
        &us[2].dir.join("depot/client.pem"),
        signer_of(&us[2]),
        &robodr_pkg::wire::encode_request(robodr_pkg::wire::Request::Pack, "x"),
    )
    .unwrap();
    assert_eq!(st7, 404);
    // A request naming another unit is not part of the protocol.
    let (stx, _) = tls(
        s.port,
        &ca,
        &us[2].dir.join("depot/client.pem"),
        signer_of(&us[2]),
        b"GET /v1/pack?unit=ugv-08 HTTP/1.1\r\n\r\n",
    )
    .unwrap();
    assert_eq!(stx, 400);
    // ugv-08's certificate with ugv-07's TPM key: the handshake fails.
    assert!(tls(
        s.port,
        &ca,
        &us[1].dir.join("depot/client.pem"),
        signer_of(&us[2]),
        &robodr_pkg::wire::encode_request(robodr_pkg::wire::Request::Pack, "x")
    )
    .is_err());
    // A certificate of the depot CA for a key that is no enrolled unit's
    // (an attacker's own key, signed by a stolen CA key) gets 403.
    let k = robodr_seal::keys::PolicyKey::generate().unwrap();
    let ca_key = robodr_seal::keys::policy_load(&site.dir().join("keys/ca.key")).unwrap();
    let der = robodr_depot::x509::issue(
        &robodr_depot::x509::Params {
            issuer_cn: "site-a depot unit CA",
            subject_cn: "ugv-08",
            subject_public: &k.public(),
            serial: 99,
            not_before: now() - 60,
            not_after: now() + 3600,
            kind: robodr_depot::x509::Kind::Client,
        },
        &ca_key,
    )
    .unwrap();
    let fake = site.dir().join("fake.pem");
    std::fs::write(&fake, robodr_depot::x509::pem("CERTIFICATE", &der)).unwrap();
    let k2 = Arc::new(move |dg: &[u8; 32]| k.sign_digest(dg).map_err(|e| e.to_string()));
    let (stf, _) = tls(
        s.port,
        &ca,
        &fake,
        k2,
        &robodr_pkg::wire::encode_request(robodr_pkg::wire::Request::Pack, "x"),
    )
    .unwrap();
    assert_eq!(stf, 403);
    // Reports: ugv-07's report over ugv-08's connection is refused; a
    // report replayed is refused.
    robodr_deliverd::lan::pull(&us[1].cfg()).unwrap();
    let mut e8 = us[1].open();
    us[1].run(&mut e8, 10);
    let rep8 = e8.unit_report().unwrap();
    let e7 = us[2].open();
    let rep7 = e7.unit_report().unwrap();
    let post = |b: &[u8]| {
        let mut r =
            robodr_pkg::wire::encode_request(robodr_pkg::wire::Request::Report(b.len()), "x");
        r.extend_from_slice(b);
        r
    };
    let (st, _) = tls(
        s.port,
        &ca,
        &us[1].dir.join("depot/client.pem"),
        signer_of(&us[1]),
        &post(&rep7),
    )
    .unwrap();
    assert_eq!(st, 409, "another unit's report over this unit's connection");
    let (st, _) = tls(
        s.port,
        &ca,
        &us[1].dir.join("depot/client.pem"),
        signer_of(&us[1]),
        &post(&rep8),
    )
    .unwrap();
    assert_eq!(st, 200);
    let (st, _) = tls(
        s.port,
        &ca,
        &us[1].dir.join("depot/client.pem"),
        signer_of(&us[1]),
        &post(&rep8),
    )
    .unwrap();
    assert_eq!(st, 409, "replayed report");
    // Production stage: one operator does not activate it.
    let seq2 = s.with(|d| d.rollout_advance("r1", now())).unwrap().unwrap();
    assert!(!s
        .with(|d| d.deploy_approve(seq2, &site.ops[0], now()))
        .unwrap());
    assert!(robodr_deliverd::lan::pull(&us[2].cfg()).is_err());
    // Revoked: no more packs (403: no longer an enrolled identity).
    let (o1, o2) = (&site.ops[0], &site.ops[1]);
    assert!(
        s.with(|d| d.revoke("ugv-08", &[o1])).is_err(),
        "one operator"
    );
    s.with(|d| d.revoke("ugv-08", &[o1, o2])).unwrap();
    let (st, _) = tls(
        s.port,
        &ca,
        &us[1].dir.join("depot/client.pem"),
        signer_of(&us[1]),
        &robodr_pkg::wire::encode_request(robodr_pkg::wire::Request::Pack, "x"),
    )
    .unwrap();
    assert_eq!(st, 403);
}

#[test]
fn a_rolled_back_depot_database_locks_the_depot() {
    if !swtpm_enabled("db_rollback") {
        return;
    }
    let mut site = Site::new("dbrollback");
    let dsw = seal::SwTpm::start(&site.dir().join("depot-tpm"));
    dsw.take_ownership();
    dsw.tpm()
        .define_counter(0x0150_0050, seal::OWNER_AUTH)
        .unwrap();
    site.ca.manufacture(&site.dir().join("dummy-tpm"));
    site.write_trust(&[("lab", &["bench-01"])]);
    let cfg = site.depot_config(false, Some(dsw.tcti()));
    Depot::init(&cfg, &site.trust_path, now()).unwrap();
    let mut d = Depot::open(cfg.clone(), now()).unwrap();
    let r1 = site.files_rpk("nav-stack", 1);
    let b1 = site.bundle(1, None, std::slice::from_ref(&r1));
    let rep1 = site.entry_report(&b1);
    d.import(&b1, &rep1, now()).unwrap();
    let db = cfg.state_dir.join("depot.json");
    let old = std::fs::read(&db).unwrap();
    d.enrol_begin("bench-01", now()).unwrap();
    drop(d);
    // Restore the older database (a backup, a disk image): locked.
    std::fs::write(&db, &old).unwrap();
    let mut d = Depot::open(cfg.clone(), now()).unwrap();
    assert!(d.db.locked.is_some());
    assert!(d.enrol_begin("bench-01", now()).is_err());
    assert!(d.import(&b1, &rep1, now()).is_err());
    assert!(
        spool_rules(&site.dir().join("depot-spool")).contains(&"robot.depot.locked".to_string())
    );
    assert!(d.reanchor(7, &[&site.ops[0]]).is_err(), "one operator");
    d.reanchor(7, &[&site.ops[0], &site.ops[1]]).unwrap();
    assert_eq!(d.db.deployment_seq, 7);
    d.enrol_begin("bench-01", now()).unwrap();
    drop(d);
    // Deleting the database is a rollback too.
    std::fs::remove_file(&db).unwrap();
    let d = Depot::open(cfg.clone(), now()).unwrap();
    assert!(d.db.locked.is_some());
    drop(d);
    // So is recreating the counter (owner authorization).
    std::fs::write(&db, &old).unwrap();
    let o = dsw.tool(
        "tpm2_nvundefine",
        &["0x01500050", "-C", "o", "-P", "file:-"],
        Some(seal::OWNER_AUTH),
    );
    assert!(o.ok());
    dsw.tpm()
        .define_counter(0x0150_0050, seal::OWNER_AUTH)
        .unwrap();
    let d = Depot::open(cfg, now()).unwrap();
    assert!(d.db.locked.is_some(), "recreated counter");
    drop(d);
    let _ = std::fs::remove_dir_all(format!("/dev/shm/robodr-depot-it-{}", std::process::id()));
}
