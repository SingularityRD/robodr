//! `robodr-kafka-publish`: diode importer output (or a site spool) ->
//! Kafka (`--topic`, default `robodr.findings`). See `robodr_export::publish`.

// S10: this crate has no `unsafe` code and must stay that way.
#![forbid(unsafe_code)]

use robodr_diode::cli::{argv, is_version_request, parse_args_with_switches, Args};
use robodr_export::deadletter::{DEFAULT_ROTATION, MIN_ROTATION_BYTES};
use robodr_export::kafka::{Producer, ProducerConfig};
use robodr_export::retention;
use robodr_export::{PublishConfig, Publisher, Source};
use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "usage: robodr-kafka-publish --bootstrap HOST:PORT [--bootstrap ...] \
--state-dir DIR (--diode-out DIR | --spool DIR) [--topic T] [--chunk N] [--client-id S] \
[--request-timeout-ms N] [--produce-timeout-ms N] [--delivery-timeout-ms N] [--retries N] [--max-request-bytes N] \
[--interval-ms N] [--once] [--upgrade-data-source LABEL] [--no-idempotence] \
[--dead-letter-max-bytes N] [--dead-letter-keep N] [--dead-letter-max-age-s N] \
[--done-max-age-s N] [--done-max-count N] \
(--tls-ca FILE [--tls-cert FILE --tls-key FILE] [--tls-server-name NAME] [--tls-spki-sha256 HEX]... \
[--sasl-mechanism SCRAM-SHA-256|SCRAM-SHA-512 --sasl-username U --sasl-password-file FILE] \
| --allow-plaintext)\n\
Unsigned contract 1.x records are upgraded to contract 2.0 (data_source --upgrade-data-source, \
default robodr; topic --topic); signed ones are dead-lettered \
(\"legacy 1.x signed record: re-sign required\").\n\
TLS is required: every broker certificate is verified against --tls-ca (and the broker's \
host name, or --tls-server-name); --tls-cert/--tls-key add a client certificate (mutual TLS). \
Plain TCP only with an explicit --allow-plaintext (isolated network or a local TLS proxy).\n\
The producer is idempotent (InitProducerId, sequence numbers; a re-sent batch is dropped by the \
broker); --no-idempotence for brokers that refuse it (Kafka < 3.0 without the IDEMPOTENT_WRITE \
cluster ACL): at-least-once.\n\
Retention: dead-letter.jsonl rotates at --dead-letter-max-bytes (default 64 MiB, 0 = never) with \
--dead-letter-keep rotated files (default 4) and optionally --dead-letter-max-age-s; done/ markers \
older than --done-max-age-s (default 2592000 = 30 days, 0 = keep) or beyond --done-max-count are \
deleted once their batch has left the importer's out/. Nothing still needed for deduplication \
is deleted.";

struct Opts {
    producer: ProducerConfig,
    publish: PublishConfig,
    interval: Duration,
    once: bool,
}

fn opts(a: &Args) -> Result<Opts, String> {
    let bootstrap: Vec<String> = a.all("bootstrap").into_iter().map(str::to_string).collect();
    if bootstrap.is_empty() {
        return Err("--bootstrap is required".into());
    }
    let mut p = ProducerConfig::new(bootstrap);
    if let Some(c) = a.one("client-id")? {
        p.client_id = c.into();
    }
    if let Some(n) = a.num::<u64>("request-timeout-ms")? {
        p.request_timeout = Duration::from_millis(n);
    }
    if let Some(n) = a.num::<i32>("produce-timeout-ms")? {
        p.produce_timeout_ms = n;
    }
    if let Some(n) = a.num::<u64>("delivery-timeout-ms")? {
        p.delivery_timeout = Duration::from_millis(n);
    }
    if let Some(n) = a.num("retries")? {
        p.retries = n;
    }
    if let Some(n) = a.num("max-request-bytes")? {
        p.max_request_bytes = n;
    }
    p.idempotence = !a.flag("no-idempotence");
    security(a, &mut p)?;
    // Configuration errors (plain TCP not allowed, SASL without TLS, bad
    // bounds) are usage errors (exit 2), not retried at run time.
    Producer::new(p.clone()).map_err(|e| e.to_string())?;
    let source = match (a.one("diode-out")?, a.one("spool")?) {
        (Some(d), None) => Source::DiodeOut(d.into()),
        (None, Some(s)) => Source::Spool(s.into()),
        _ => return Err("exactly one of --diode-out / --spool is required".into()),
    };
    let mut c = PublishConfig::new(source, a.req("state-dir")?);
    if let Some(t) = a.one("topic")? {
        c.topic = t.into();
    }
    if let Some(n) = a.num("chunk")? {
        c.chunk_records = n;
    }
    if let Some(l) = a.one("upgrade-data-source")? {
        c.upgrade_data_source = l.into();
    }
    let mut rot = DEFAULT_ROTATION;
    match a.num::<u64>("dead-letter-max-bytes")? {
        Some(0) => c.dead_letter_rotation = None,
        Some(n) => rot.max_bytes = n,
        None => {}
    }
    if let Some(k) = a.num::<u32>("dead-letter-keep")? {
        if k == 0 {
            return Err("--dead-letter-keep must be >= 1".into());
        }
        rot.keep = k;
    }
    if c.dead_letter_rotation.is_some() {
        if !rot.is_valid() {
            return Err(format!(
                "--dead-letter-max-bytes must be 0 or >= {MIN_ROTATION_BYTES}"
            ));
        }
        c.dead_letter_rotation = Some(rot);
    }
    c.dead_letter_retention = retention::with_flags(
        c.dead_letter_retention,
        a.num("dead-letter-max-age-s")?,
        None,
        None,
    );
    c.done_retention = retention::with_flags(
        c.done_retention,
        a.num("done-max-age-s")?,
        a.num("done-max-count")?,
        None,
    );
    let interval: u64 = a.num("interval-ms")?.unwrap_or(2_000);
    if interval == 0 {
        return Err("--interval-ms must be > 0".into());
    }
    Ok(Opts {
        producer: p,
        publish: c,
        interval: Duration::from_millis(interval),
        once: a.flag("once"),
    })
}

/// `--tls-*`, `--sasl-*`, `--allow-plaintext` (checked again by
/// `Producer::new`: no TLS and no `--allow-plaintext` is refused).
fn security(a: &Args, p: &mut ProducerConfig) -> Result<(), String> {
    use robodr_blackbox::tls;
    use robodr_export::kafka::sasl::{Mechanism, SaslConfig};
    p.allow_plaintext = a.flag("allow-plaintext");
    let ca = a.one("tls-ca")?;
    let (cert, key) = (a.one("tls-cert")?, a.one("tls-key")?);
    let name = a.one("tls-server-name")?;
    let pins: Vec<String> = a
        .all("tls-spki-sha256")
        .into_iter()
        .map(str::to_string)
        .collect();
    match ca {
        Some(ca) => {
            if p.allow_plaintext {
                return Err("--tls-ca and --allow-plaintext are both given: remove one".into());
            }
            let t = tls::load_client(&tls::ClientTlsFiles {
                ca_file: ca.into(),
                cert_chain: cert.map(Into::into),
                key_file: key.map(Into::into),
                server_name: name.map(str::to_string),
                spki_sha256: pins,
            })
            .map_err(|e| format!("TLS: {e}"))?;
            p.tls = Some(t);
        }
        None if cert.is_some() || key.is_some() || name.is_some() || !pins.is_empty() => {
            return Err(
                "--tls-cert / --tls-key / --tls-server-name / --tls-spki-sha256 need \
                        --tls-ca"
                    .into(),
            )
        }
        None => {}
    }
    let mech = a.one("sasl-mechanism")?;
    let user = a.one("sasl-username")?;
    let pw_file = a.one("sasl-password-file")?;
    match (mech, user, pw_file) {
        (None, None, None) => {}
        (Some(m), Some(u), Some(f)) => {
            // `raw` is wiped when dropped; the password is borrowed from it
            // (no other copy) until SaslConfig takes its own (wiped on drop).
            let raw = tls::read_pem("--sasl-password-file", std::path::Path::new(f), true)?;
            let pw = std::str::from_utf8(&raw)
                .map_err(|_| "--sasl-password-file: not UTF-8".to_string())?
                .trim_end_matches(['\n', '\r']);
            p.sasl = Some(SaslConfig::new(Mechanism::parse(m)?, u, pw)?);
        }
        _ => {
            return Err("SASL needs --sasl-mechanism, --sasl-username and \
                        --sasl-password-file together"
                .into())
        }
    }
    Ok(())
}

fn run(o: &Opts) -> Result<(), String> {
    let producer = Producer::new(o.producer.clone()).map_err(|e| e.to_string())?;
    let mut p = Publisher::open(o.publish.clone(), producer).map_err(|e| e.to_string())?;
    loop {
        let r = p.run_once().map_err(|e| e.to_string())?;
        if r.published > 0
            || r.dead_lettered > 0
            || !r.batches_done.is_empty()
            || r.pruned_done.removed > 0
            || r.pruned_dead_letters.removed > 0
        {
            println!("{}", serde_json::to_string(&r).unwrap_or_default());
        }
        if o.once {
            return Ok(());
        }
        std::thread::sleep(o.interval);
    }
}

fn main() -> ExitCode {
    let v = match argv() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("robodr-kafka-publish: {e}");
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    if is_version_request(&v) {
        println!("robodr-kafka-publish {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    let parsed = parse_args_with_switches(
        v,
        &[
            "bootstrap",
            "state-dir",
            "diode-out",
            "spool",
            "topic",
            "chunk",
            "client-id",
            "request-timeout-ms",
            "produce-timeout-ms",
            "delivery-timeout-ms",
            "retries",
            "max-request-bytes",
            "interval-ms",
            "upgrade-data-source",
            "dead-letter-max-bytes",
            "dead-letter-keep",
            "dead-letter-max-age-s",
            "done-max-age-s",
            "done-max-count",
            "tls-ca",
            "tls-cert",
            "tls-key",
            "tls-server-name",
            "tls-spki-sha256",
            "sasl-mechanism",
            "sasl-username",
            "sasl-password-file",
        ],
        &["once", "allow-plaintext", "no-idempotence"],
    );
    let o = match parsed.and_then(|a| opts(&a)) {
        Ok(o) => o,
        Err(e) if e == "help" => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("robodr-kafka-publish: {e}");
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    loop {
        match run(&o) {
            Ok(()) => return ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("robodr-kafka-publish: {e}");
                if o.once {
                    return ExitCode::from(1);
                }
                std::thread::sleep(o.interval);
            }
        }
    }
}
