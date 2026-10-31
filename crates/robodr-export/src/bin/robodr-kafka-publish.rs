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
[--out-max-age-s N] [--out-max-count N] [--out-max-bytes N] \
[--rejected-max-age-s N] [--rejected-max-count N] [--rejected-max-bytes N] \
(--tls-ca FILE [--tls-cert FILE --tls-key FILE] [--tls-server-name NAME] [--tls-spki-sha256 HEX]... [--tls-crl-file FILE]... \
[--sasl-mechanism SCRAM-SHA-256|SCRAM-SHA-512 --sasl-username U --sasl-password-file FILE] \
| --allow-plaintext)\n\
Unsigned contract 1.x records are upgraded to contract 2.0 (data_source --upgrade-data-source, \
default robodr; topic --topic); signed ones are dead-lettered \
(\"legacy 1.x signed record: re-sign required\").\n\
TLS is required: every broker certificate is verified against --tls-ca (and the broker's \
host name, or --tls-server-name); --tls-cert/--tls-key add a client certificate (mutual TLS); \
--tls-crl-file (PEM or DER CRLs of the broker CAs) refuses a revoked broker certificate (an issuer \
without a CRL, an expired or unusable CRL refuse every broker; reloaded when the files change). \
Plain TCP only with an explicit --allow-plaintext (isolated network or a local TLS proxy).\n\
The producer is idempotent (InitProducerId, sequence numbers; a re-sent batch is dropped by the \
broker); --no-idempotence for brokers that refuse it (Kafka < 3.0 without the IDEMPOTENT_WRITE \
cluster ACL): at-least-once.\n\
Kafka refusing record timestamps (INVALID_TIMESTAMP) means this host's clock is off: the run \
fails with a hint and retries, nothing is dead-lettered; fix NTP.\n\
Retention: dead-letter.jsonl is one growing file by default and is never deleted (it may hold \
the only copy of findings Kafka refused). Opt in to rotation with --dead-letter-max-bytes N \
(>= 65536; 0 = never, the default), keeping --dead-letter-keep rotated files (default 4) and \
optionally bounded by --dead-letter-max-age-s; older rotated files are then DELETED (each \
deletion is logged with its entry count). done/ markers older than --done-max-age-s (default \
2592000 = 30 days, 0 = keep) or beyond --done-max-count are deleted once their batch has left \
the importer's out/. --out-max-age-s / --out-max-count / --out-max-bytes (diode source, \
default keep; only when this publisher is the sole consumer of out/) delete the out/ batch \
directories it has finished (aged by their done/ marker); --rejected-max-age-s / \
--rejected-max-count / --rejected-max-bytes (spool source, default keep) delete the oldest \
<spool>/rejected/ records. Nothing still needed for deduplication is deleted. The JSON report \
carries state_usage (entries and bytes of done/, dead letters, out/ or rejected/, measured at \
most once a minute). A spool file that \
cannot be read (I/O error after 3 attempts) is dead-lettered with the error and moved to \
<spool>/rejected/; the run goes on.";

/// `--out-max-*` (diode source only) and `--rejected-max-*` (spool source
/// only), `--reinject-max-*` when `reinject` (opt-in bounds, default keep).
fn source_bounds(
    a: &Args,
    diode: bool,
    reinject: bool,
) -> Result<[Option<retention::Retention>; 3], String> {
    let out = retention::bound_flags("out", |f| a.num(f))?;
    let rejected = retention::bound_flags("rejected", |f| a.num(f))?;
    let re = if reinject {
        retention::bound_flags("reinject", |f| a.num(f))?
    } else {
        None
    };
    if out.is_some() && !diode {
        return Err("--out-max-* bound the importer's out/: they need --diode-out".into());
    }
    if rejected.is_some() && diode {
        return Err("--rejected-max-* bound <spool>/rejected/: they need --spool".into());
    }
    Ok([out, rejected, re])
}

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
    // Rotation (and with it deletion of old dead letters) is opt-in: a dead
    // letter may be the only copy of a finding Kafka refused.
    let mut rot = DEFAULT_ROTATION;
    let max_bytes = a.num::<u64>("dead-letter-max-bytes")?.unwrap_or(0);
    let keep = a.num::<u32>("dead-letter-keep")?;
    if keep == Some(0) {
        return Err("--dead-letter-keep must be >= 1".into());
    }
    c.dead_letter_rotation = None;
    if max_bytes > 0 {
        rot.max_bytes = max_bytes;
        if let Some(k) = keep {
            rot.keep = k;
        }
        if !rot.is_valid() {
            return Err(format!(
                "--dead-letter-max-bytes must be 0 or >= {MIN_ROTATION_BYTES}"
            ));
        }
        c.dead_letter_rotation = Some(rot);
    } else if keep.is_some() {
        return Err(
            "--dead-letter-keep needs --dead-letter-max-bytes N (rotation is off by default)"
                .into(),
        );
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
    let [out, rejected, _] = source_bounds(a, matches!(c.source, Source::DiodeOut(_)), false)?;
    c.out_retention = out.unwrap_or(retention::Retention::UNBOUNDED);
    c.rejected_retention = rejected.unwrap_or(retention::Retention::UNBOUNDED);
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
    let crls: Vec<std::path::PathBuf> = a.all("tls-crl-file").into_iter().map(Into::into).collect();
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
                crl_files: crls,
            })
            .map_err(|e| format!("TLS: {e}"))?;
            p.tls = Some(t);
        }
        None if cert.is_some()
            || key.is_some()
            || name.is_some()
            || !pins.is_empty()
            || !crls.is_empty() =>
        {
            return Err(
                "--tls-cert / --tls-key / --tls-server-name / --tls-spki-sha256 / \
                        --tls-crl-file need --tls-ca"
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
            || r.pruned_out.removed > 0
            || r.pruned_rejected.removed > 0
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
            "out-max-age-s",
            "out-max-count",
            "out-max-bytes",
            "rejected-max-age-s",
            "rejected-max-count",
            "rejected-max-bytes",
            "tls-ca",
            "tls-cert",
            "tls-key",
            "tls-server-name",
            "tls-spki-sha256",
            "tls-crl-file",
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
