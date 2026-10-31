//! The Kafka producer over TLS, mutual TLS and SASL/SCRAM against the
//! in-process fake cluster (`tests/common/mod.rs`: rustls server, the broker
//! side of SCRAM written from RFC 5802), with the test PKI of
//! `fixtures/tls/` (`gen.sh` there). The SCRAM client is also checked
//! against the RFC 7677 vector (`src/kafka/sasl.rs`) and, when a broker is
//! available, a real Apache Kafka (`tests/kafka_real_broker.rs`).
//!
//! Negative / adversarial: plain TCP refused unless explicitly allowed
//! (library and CLI), an untrusted CA, a wrong host name, an expired
//! certificate, a certificate without `serverAuth`, a pin mismatch, a
//! missing or foreign client certificate, downgrades in both directions, a
//! wrong password or user, an impostor broker that cannot prove it knows
//! the credential, a downgraded iteration count, a broker without the
//! mechanism, SASL over plain TCP, a revoked broker certificate (CRL), an
//! expired CRL. Nothing is delivered in any refused case.

mod common;

use common::*;
use robodr_blackbox::tls::{self, ClientTls, ClientTlsFiles, ServerTlsFiles};
use robodr_export::kafka::sasl::{Mechanism, SaslConfig};
use robodr_export::kafka::{Outcome, ProduceError, ProduceRecord, Producer, ProducerConfig};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

const PUBLISH: &str = env!("CARGO_BIN_EXE_robodr-kafka-publish");

/// A private copy of `fixtures/tls/` (keys 0600; git keeps 0644).
struct Pki(TempDir);

impl Pki {
    fn new() -> Self {
        let d = TempDir::new("kafka-pki");
        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/tls");
        for e in fs::read_dir(&src).unwrap() {
            let e = e.unwrap();
            let n = e.file_name().into_string().unwrap();
            if !(n.ends_with(".pem") || n.ends_with(".key")) {
                continue;
            }
            let to = d.path().join(&n);
            fs::copy(e.path(), &to).unwrap();
            let mode = if n.ends_with(".key") { 0o600 } else { 0o644 };
            fs::set_permissions(&to, fs::Permissions::from_mode(mode)).unwrap();
        }
        Pki(d)
    }
    fn p(&self, n: &str) -> PathBuf {
        self.0.path().join(n)
    }
    fn server(&self, leaf: &str, client_ca: bool) -> Arc<rustls::ServerConfig> {
        tls::load_server(&ServerTlsFiles {
            cert_chain: self.p(&format!("{leaf}.pem")),
            key_file: self.p(&format!("{leaf}.key")),
            client_ca: client_ca.then(|| self.p("ca.pem")),
            crl_files: Vec::new(),
        })
        .unwrap()
    }
    fn client(
        &self,
        ca: &str,
        cert: Option<&str>,
        name: Option<&str>,
        pins: &[String],
    ) -> ClientTls {
        tls::load_client(&ClientTlsFiles {
            ca_file: self.p(ca),
            cert_chain: cert.map(|c| self.p(&format!("{c}.pem"))),
            key_file: cert.map(|c| self.p(&format!("{c}.key"))),
            server_name: name.map(str::to_string),
            spki_sha256: pins.to_vec(),
            crl_files: Vec::new(),
        })
        .unwrap()
    }
    fn pin_of(&self, leaf: &str) -> String {
        let c = CertificateDer::from_pem_file(self.p(&format!("{leaf}.pem"))).unwrap();
        robodr_blackbox::crypto::to_hex(&tls::spki_sha256(&c).unwrap())
    }
}

fn base(c: &Cluster) -> ProducerConfig {
    let mut p = ProducerConfig::new(c.bootstrap());
    p.retries = 2;
    p.retry_backoff = Duration::from_millis(5);
    p.retry_backoff_max = Duration::from_millis(20);
    p.request_timeout = Duration::from_secs(5);
    p.connect_timeout = Duration::from_secs(2);
    p.produce_timeout_ms = 1_000;
    p.delivery_timeout = Duration::from_secs(20);
    p
}

fn with_tls(c: &Cluster, t: ClientTls) -> ProducerConfig {
    let mut p = base(c);
    p.tls = Some(t);
    p
}

fn recs(n: usize) -> Vec<(i32, ProduceRecord)> {
    (0..n)
        .map(|i| {
            (
                (i % 2) as i32,
                ProduceRecord {
                    key: Some(format!("k{i}").into_bytes()),
                    value: Some(format!("{i:06}tls").into_bytes()),
                    headers: vec![],
                    timestamp_ms: 1_790_000_000_000 + i as i64,
                },
            )
        })
        .collect()
}

fn send(cfg: ProducerConfig, n: usize) -> Result<usize, ProduceError> {
    let mut p = Producer::new(cfg)?;
    let o = p.send(TOPIC, &recs(n))?;
    Ok(o.iter()
        .filter(|x| matches!(x, Outcome::Delivered { .. }))
        .count())
}

fn tls_cluster(pki: &Pki, leaf: &str, client_ca: bool) -> Cluster {
    let cfg = pki.server(leaf, client_ca);
    Cluster::start_with(2, 2, move |s| s.tls = Some(cfg))
}

#[test]
fn tls_and_mutual_tls_deliver_to_every_broker() {
    let pki = Pki::new();
    let c = tls_cluster(&pki, "server", false);
    // Partition 1 is led by node 2: the advertised broker is verified too.
    c.state.lock().unwrap().leaders = vec![1, 2];
    assert_eq!(
        send(with_tls(&c, pki.client("ca.pem", None, None, &[])), 6),
        Ok(6)
    );
    assert_eq!(c.total(), 6);

    let c = tls_cluster(&pki, "server", true);
    c.state.lock().unwrap().leaders = vec![1, 2];
    let cfg = with_tls(&c, pki.client("ca.pem", Some("client"), None, &[]));
    assert_eq!(send(cfg, 4), Ok(4));
    assert_eq!(c.total(), 4);
    // Host name `localhost` is verified like an IP literal.
    let mut cfg = with_tls(&c, pki.client("ca.pem", Some("client"), None, &[]));
    cfg.bootstrap = vec![c.bootstrap()[0].replace("127.0.0.1", "localhost")];
    assert_eq!(send(cfg, 2), Ok(2));
}

#[test]
fn plain_tcp_is_refused_unless_explicitly_allowed() {
    let pki = Pki::new();
    let c = Cluster::start(1, 2);
    let e = Producer::new(base(&c)).err().unwrap().to_string();
    assert!(e.contains("plain TCP"), "{e}");
    let mut both = with_tls(&c, pki.client("ca.pem", None, None, &[]));
    both.allow_plaintext = true;
    assert!(Producer::new(both).is_err());
    let mut sasl_plain = base(&c);
    sasl_plain.allow_plaintext = true;
    sasl_plain.sasl = Some(SaslConfig::new(Mechanism::ScramSha256, "u", "p").unwrap());
    let e = Producer::new(sasl_plain).err().unwrap().to_string();
    assert!(e.contains("SASL needs TLS"), "{e}");
    let mut ok = base(&c);
    ok.allow_plaintext = true;
    assert_eq!(send(ok, 2), Ok(2));
}

#[test]
fn bad_broker_certificates_are_refused() {
    let pki = Pki::new();
    for leaf in ["other-server", "wrong-host", "expired", "client-only"] {
        let c = tls_cluster(&pki, leaf, false);
        let e = send(with_tls(&c, pki.client("ca.pem", None, None, &[])), 2).unwrap_err();
        assert!(
            matches!(e, ProduceError::RetriesExhausted(_)),
            "{leaf}: {e}"
        );
        assert!(e.to_string().contains("certificate"), "{leaf}: {e}");
        assert_eq!(c.total(), 0, "{leaf}");
    }
    // Trusting only another CA refuses the genuine broker.
    let c = tls_cluster(&pki, "server", false);
    assert!(send(with_tls(&c, pki.client("other-ca.pem", None, None, &[])), 1).is_err());
    assert_eq!(c.total(), 0);
}

#[test]
fn server_name_override_and_pins() {
    let pki = Pki::new();
    let c = tls_cluster(&pki, "wrong-host", false);
    let cfg = with_tls(&c, pki.client("ca.pem", None, Some("wrong.example"), &[]));
    assert_eq!(send(cfg, 1), Ok(1));
    let cfg = with_tls(&c, pki.client("ca.pem", None, Some("evil.example"), &[]));
    assert!(send(cfg, 1).is_err());

    let c = tls_cluster(&pki, "server", false);
    let good = pki.pin_of("server");
    let next = pki.pin_of("client");
    let cfg = with_tls(&c, pki.client("ca.pem", None, None, &[next.clone(), good]));
    assert_eq!(send(cfg, 1), Ok(1));
    let cfg = with_tls(&c, pki.client("ca.pem", None, None, &[next]));
    let e = send(cfg, 1).unwrap_err().to_string();
    assert!(e.contains("pin"), "{e}");
    assert_eq!(c.total(), 1);
}

#[test]
fn mutual_tls_refuses_missing_and_foreign_client_certificates() {
    let pki = Pki::new();
    let c = tls_cluster(&pki, "server", true);
    for cert in [None, Some("other-client")] {
        let e = send(with_tls(&c, pki.client("ca.pem", cert, None, &[])), 1);
        assert!(e.is_err(), "{cert:?}");
    }
    assert_eq!(c.total(), 0);
}

#[test]
fn no_downgrade_in_either_direction() {
    let pki = Pki::new();
    // A TLS producer against a plain listener (or a stripping proxy).
    let plain = Cluster::start(1, 2);
    let e = send(with_tls(&plain, pki.client("ca.pem", None, None, &[])), 1).unwrap_err();
    assert!(e.to_string().contains("TLS"), "{e}");
    assert_eq!(plain.total(), 0);
    assert!(
        plain.state.lock().unwrap().seen.is_empty(),
        "no Kafka request in clear"
    );
    // A plain producer against a TLS listener.
    let c = tls_cluster(&pki, "server", false);
    let mut cfg = base(&c);
    cfg.allow_plaintext = true;
    let e = send(cfg, 1).unwrap_err().to_string();
    assert!(e.contains("TLS"), "{e}");
    assert_eq!(c.total(), 0);
}

fn scram_cluster(pki: &Pki, srv: ScramServer) -> Cluster {
    let cfg = pki.server("server", false);
    Cluster::start_with(1, 2, move |s| {
        s.tls = Some(cfg);
        s.scram = Some(srv);
    })
}

fn scram_cfg(c: &Cluster, pki: &Pki, m: Mechanism, user: &str, pw: &str) -> ProducerConfig {
    let mut cfg = with_tls(c, pki.client("ca.pem", None, None, &[]));
    cfg.sasl = Some(SaslConfig::new(m, user, pw).unwrap());
    cfg
}

#[test]
fn scram_sha_256_and_512_over_tls() {
    let pki = Pki::new();
    for m in [Mechanism::ScramSha256, Mechanism::ScramSha512] {
        let c = scram_cluster(&pki, ScramServer::new(m, "robodr", "s3cret, =pw"));
        assert_eq!(
            send(scram_cfg(&c, &pki, m, "robodr", "s3cret, =pw"), 3),
            Ok(3)
        );
        let st = c.state.lock().unwrap();
        assert!(st.authenticated >= 1);
        assert_eq!(st.auth_failures, 0);
    }
}

#[test]
fn scram_failures_are_fatal_and_deliver_nothing() {
    let pki = Pki::new();
    let m = Mechanism::ScramSha256;
    let fatal = |c: &Cluster, cfg: ProducerConfig, want: &str| {
        let t = Instant::now();
        let e = send(cfg, 1).unwrap_err();
        assert!(matches!(e, ProduceError::Fatal { .. }), "{want}: {e}");
        assert!(e.to_string().contains(want), "{want}: {e}");
        assert!(t.elapsed() < Duration::from_secs(5), "not retried");
        assert_eq!(c.total(), 0);
    };
    let c = scram_cluster(&pki, ScramServer::new(m, "robodr", "right"));
    fatal(
        &c,
        scram_cfg(&c, &pki, m, "robodr", "wrong"),
        "SASL_AUTHENTICATION_FAILED",
    );
    fatal(
        &c,
        scram_cfg(&c, &pki, m, "nobody", "right"),
        "SASL_AUTHENTICATION_FAILED",
    );
    // The broker offers another mechanism only.
    let c = scram_cluster(
        &pki,
        ScramServer::new(Mechanism::ScramSha512, "robodr", "right"),
    );
    fatal(
        &c,
        scram_cfg(&c, &pki, m, "robodr", "right"),
        "refused the mechanism",
    );
    // An impostor broker (TLS-valid but without the credential) cannot
    // produce the server signature.
    let mut srv = ScramServer::new(m, "robodr", "right");
    srv.forge_server_signature = true;
    let c = scram_cluster(&pki, srv);
    fatal(
        &c,
        scram_cfg(&c, &pki, m, "robodr", "right"),
        "server signature",
    );
    // A downgraded iteration count.
    let mut srv = ScramServer::new(m, "robodr", "right");
    srv.iterations = 1024;
    let c = scram_cluster(&pki, srv);
    fatal(
        &c,
        scram_cfg(&c, &pki, m, "robodr", "right"),
        "iteration count",
    );
    // A SASL listener without SASL configured: closed after ApiVersions.
    let c = scram_cluster(&pki, ScramServer::new(m, "robodr", "right"));
    let e = send(with_tls(&c, pki.client("ca.pem", None, None, &[])), 1).unwrap_err();
    assert!(e.to_string().contains("SASL"), "{e}");
    assert_eq!(c.total(), 0);
    // A broker without the SASL APIs.
    let c = tls_cluster(&pki, "server", false);
    let e = send(scram_cfg(&c, &pki, m, "robodr", "right"), 1).unwrap_err();
    assert!(matches!(e, ProduceError::Unsupported(_)), "{e}");
}

#[test]
fn scram_sessions_are_renewed_before_the_broker_ends_them() {
    let pki = Pki::new();
    let m = Mechanism::ScramSha512;
    let mut srv = ScramServer::new(m, "robodr", "pw");
    srv.session_lifetime_ms = 250;
    let c = scram_cluster(&pki, srv);
    let mut p = Producer::new(scram_cfg(&c, &pki, m, "robodr", "pw")).unwrap();
    assert_eq!(p.send(TOPIC, &recs(1)).unwrap().len(), 1);
    let before = p.stats();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(p.send(TOPIC, &recs(1)).unwrap().len(), 1);
    let after = p.stats();
    assert!(after.connects > before.connects, "{after:?}");
    assert_eq!(after.io_errors, 0, "{after:?}");
    assert!(c.state.lock().unwrap().authenticated >= 2);
    assert_eq!(c.total(), 2);
}

fn spool_with(t: &TempDir, n: u64) -> PathBuf {
    use robodr_agent::FindingOutput;
    let spool = t.path().join("spool");
    let mut s = robodr_agentd::spool::Spool::open(&spool, 1 << 30, 1000).unwrap();
    for i in 0..n {
        let rec = robodr_ocsf::record(&finding(i), None).unwrap();
        s.write(
            &FindingOutput {
                topic: rec.topic,
                key: rec.key,
                partition: rec.partition,
                value: rec.value,
                headers: rec
                    .headers
                    .into_iter()
                    .map(|(k, v)| (k.into(), v))
                    .collect(),
            },
            robodr_agentd::SpoolClass::Normal,
        )
        .unwrap();
    }
    spool
}

#[test]
fn cli_requires_tls_or_an_explicit_plaintext_flag() {
    let pki = Pki::new();
    let t = TempDir::new("kafka-tls-cli");
    let spool = spool_with(&t, 2);
    let c = scram_cluster(
        &pki,
        ScramServer::new(Mechanism::ScramSha256, "robodr", "pw"),
    );
    let run = |extra: &[&str]| {
        Command::new(PUBLISH)
            .args(["--bootstrap", &c.bootstrap()[0], "--once"])
            .args(["--spool".as_ref(), spool.as_os_str()])
            .args(["--state-dir".as_ref(), t.path().join("soc").as_os_str()])
            .args(extra)
            .output()
            .unwrap()
    };
    let ca = pki.p("ca.pem");
    let ca = ca.to_str().unwrap();
    let pw = t.path().join("pw");
    fs::write(&pw, "pw\n").unwrap();
    fs::set_permissions(&pw, fs::Permissions::from_mode(0o644)).unwrap();
    let pw_s = pw.to_str().unwrap();
    let sasl = [
        "--sasl-mechanism",
        "SCRAM-SHA-256",
        "--sasl-username",
        "robodr",
        "--sasl-password-file",
        pw_s,
    ];
    for (args, want) in [
        (vec![], "plain TCP"),
        (vec!["--tls-ca", ca, "--allow-plaintext"], "both"),
        (vec!["--tls-cert", ca], "need --tls-ca"),
        (
            vec!["--allow-plaintext", "--sasl-mechanism", "SCRAM-SHA-256"],
            "together",
        ),
        (
            [&["--tls-ca", ca][..], &sasl[..]].concat(),
            "lets group/others access",
        ),
        (
            vec![
                "--tls-ca",
                ca,
                "--sasl-mechanism",
                "PLAIN",
                "--sasl-username",
                "u",
                "--sasl-password-file",
                pw_s,
            ],
            "",
        ),
    ] {
        let o = run(&args);
        let err = String::from_utf8_lossy(&o.stderr);
        assert_eq!(o.status.code(), Some(2), "{args:?}: {err}");
        assert!(err.contains(want), "{args:?}: {err}");
    }
    assert_eq!(c.total(), 0);
    fs::set_permissions(&pw, fs::Permissions::from_mode(0o600)).unwrap();
    let o = run(&[&["--tls-ca", ca][..], &sasl[..]].concat());
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(c.total(), 2);
}

/// Review F3: an on-path peer that answers the ClientHello with a TLS
/// record header and then one byte at a time held the producer for ever
/// (the socket timeout was armed once and rustls loops over reads):
/// connect, request and delivery deadlines were all defeated. The
/// handshake and every TLS request are now bounded as a whole.
#[test]
fn a_trickled_tls_handshake_cannot_outlast_the_deadlines() {
    use std::io::{Read, Write};
    let pki = Pki::new();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            std::thread::spawn(move || {
                let mut b = [0u8; 4096];
                let _ = s.read(&mut b); // ClientHello
                let _ = s.write_all(&[0x16, 0x03, 0x03, 0x40, 0x00]);
                for _ in 0..1000 {
                    std::thread::sleep(Duration::from_millis(100));
                    if s.write_all(&[0x02]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    let mut c = ProducerConfig::new(vec![addr.to_string()]);
    c.tls = Some(pki.client("ca.pem", None, None, &[]));
    c.connect_timeout = Duration::from_millis(300);
    c.request_timeout = Duration::from_millis(600);
    c.produce_timeout_ms = 300;
    c.delivery_timeout = Duration::from_millis(1500);
    c.retries = 0;
    let mut p = Producer::new(c).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let t0 = Instant::now();
    std::thread::spawn(move || {
        let _ = tx.send(p.partition_count(TOPIC).is_err());
    });
    let r = rx.recv_timeout(Duration::from_secs(8));
    assert_eq!(r, Ok(true), "still connecting after {:?}", t0.elapsed());
}

fn crl_client(pki: &Pki, crl: &str) -> ClientTls {
    tls::load_client(&ClientTlsFiles {
        ca_file: pki.p("crl-ca.pem"),
        crl_files: vec![pki.p(crl)],
        ..ClientTlsFiles::default()
    })
    .unwrap()
}

/// `crl_files` (`--tls-crl-file`): a revoked broker certificate is refused
/// and counted, its unrevoked sibling of the same CA delivers; an expired
/// CRL refuses every broker it covers (fail closed).
#[test]
fn crl_files_refuse_a_revoked_broker() {
    let pki = Pki::new();
    let c = tls_cluster(&pki, "crl-revoked-server", false);
    let t = crl_client(&pki, "crl-ca.crl.pem");
    let stats = t.crl.clone().unwrap();
    let e = send(with_tls(&c, t), 2).unwrap_err();
    assert!(e.to_string().contains("Revoked"), "{e}");
    assert_eq!(c.total(), 0);
    assert!(stats.status().revoked_rejections >= 1);
    // Without the CRL the same broker is trusted (the CRL did the refusing).
    let t = tls::load_client(&ClientTlsFiles {
        ca_file: pki.p("crl-ca.pem"),
        ..ClientTlsFiles::default()
    })
    .unwrap();
    assert_eq!(send(with_tls(&c, t), 2).unwrap(), 2);
    let c = tls_cluster(&pki, "crl-server", false);
    assert_eq!(
        send(with_tls(&c, crl_client(&pki, "crl-ca.crl.pem")), 2).unwrap(),
        2
    );
    // An expired CRL: nothing is delivered, even to the unrevoked broker.
    let c = tls_cluster(&pki, "crl-server", false);
    let t = crl_client(&pki, "crl-ca-expired.crl.pem");
    let stats = t.crl.clone().unwrap();
    let e = send(with_tls(&c, t), 2).unwrap_err();
    assert!(e.to_string().contains("ExpiredRevocationList"), "{e}");
    assert_eq!(c.total(), 0);
    assert!(stats.status().expired_crl_rejections >= 1);
}

#[test]
fn cli_tls_crl_file() {
    let pki = Pki::new();
    let t = TempDir::new("kafka-tls-crl-cli");
    let spool = spool_with(&t, 2);
    let run = |c: &Cluster, extra: &[&str]| {
        Command::new(PUBLISH)
            .args(["--bootstrap", &c.bootstrap()[0], "--once"])
            .args(["--spool".as_ref(), spool.as_os_str()])
            .args(["--state-dir".as_ref(), t.path().join("soc").as_os_str()])
            .args(extra)
            .output()
            .unwrap()
    };
    let (ca, crl) = (pki.p("crl-ca.pem"), pki.p("crl-ca.crl.pem"));
    let (ca, crl) = (ca.to_str().unwrap(), crl.to_str().unwrap());
    // Without --tls-ca it is a usage error.
    let c = tls_cluster(&pki, "crl-revoked-server", false);
    let o = run(&c, &["--tls-crl-file", crl]);
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("need --tls-ca"));
    // A revoked broker: nothing delivered.
    let o = run(&c, &["--tls-ca", ca, "--tls-crl-file", crl]);
    assert!(!o.status.success());
    assert_eq!(c.total(), 0);
    // An unrevoked one: delivered.
    let c = tls_cluster(&pki, "crl-server", false);
    let o = run(&c, &["--tls-ca", ca, "--tls-crl-file", crl]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(c.total(), 2);
}

/// T6: `--check` states when the client certificate and each CRL in use
/// expire, and fails on an expired one.
#[test]
fn cli_check_reports_credential_expiry() {
    let pki = Pki::new();
    let t = TempDir::new("kafka-tls-expiry");
    let spool = spool_with(&t, 1);
    fs::create_dir_all(t.path().join("soc")).unwrap();
    let check = |c: &Cluster, extra: &[&str]| {
        let o = Command::new(PUBLISH)
            .args(["--bootstrap", &c.bootstrap()[0], "--check"])
            .args(["--spool".as_ref(), spool.as_os_str()])
            .args(["--state-dir".as_ref(), t.path().join("soc").as_os_str()])
            .args(extra)
            .output()
            .unwrap();
        (
            o.status.code(),
            String::from_utf8_lossy(&o.stdout).into_owned(),
        )
    };
    let p = |n: &str| pki.p(n).to_str().unwrap().to_string();
    // Mutual TLS with a client certificate valid until 2125.
    let c = tls_cluster(&pki, "server", true);
    let (ca, cert, key) = (p("ca.pem"), p("client.pem"), p("client.key"));
    let (code, out) = check(
        &c,
        &["--tls-ca", &ca, "--tls-cert", &cert, "--tls-key", &key],
    );
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("ok   tls-cert expires in "), "{out}");
    // An expired client certificate (2001) fails the check.
    let (cert, key) = (p("expired.pem"), p("expired.key"));
    let (code, out) = check(
        &c,
        &["--tls-ca", &ca, "--tls-cert", &cert, "--tls-key", &key],
    );
    assert_eq!(code, Some(1), "{out}");
    assert!(out.contains("FAIL tls-cert expired "), "{out}");
    assert!(!out.contains("check passed"), "{out}");
    // A CRL in use: its nextUpdate (2125).
    let c = tls_cluster(&pki, "crl-server", false);
    let (ca, crl) = (p("crl-ca.pem"), p("crl-ca.crl.pem"));
    let (code, out) = check(&c, &["--tls-ca", &ca, "--tls-crl-file", &crl]);
    assert_eq!(code, Some(0), "{out}");
    assert!(
        out.lines()
            .any(|l| l.starts_with("ok   crl:") && l.contains(" expires in ")),
        "{out}"
    );
}
