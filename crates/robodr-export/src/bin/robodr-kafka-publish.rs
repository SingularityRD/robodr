//! `robodr-kafka-publish`: diode importer output (or a site spool) ->
//! Kafka (`--topic`, default `robodr.findings`). See `robodr_export::publish`.

// S10: this crate has no `unsafe` code and must stay that way.
#![forbid(unsafe_code)]

use robodr_diode::cli::{argv, parse_args_with_switches, Args};
use robodr_export::kafka::{Producer, ProducerConfig};
use robodr_export::{PublishConfig, Publisher, Source};
use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "usage: robodr-kafka-publish --bootstrap HOST:PORT [--bootstrap ...] \
--state-dir DIR (--diode-out DIR | --spool DIR) [--topic T] [--chunk N] [--client-id S] \
[--request-timeout-ms N] [--produce-timeout-ms N] [--delivery-timeout-ms N] [--retries N] [--max-request-bytes N] \
[--interval-ms N] [--once] [--upgrade-data-source LABEL]\n\
Unsigned contract 1.x records are upgraded to contract 2.0 (data_source --upgrade-data-source, \
default robodr; topic --topic); signed ones are dead-lettered \
(\"legacy 1.x signed record: re-sign required\").\n\
No TLS/SASL: run on an isolated SOC network or through a local TLS proxy (stunnel).";

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

fn run(o: &Opts) -> Result<(), String> {
    let producer = Producer::new(o.producer.clone()).map_err(|e| e.to_string())?;
    let mut p = Publisher::open(o.publish.clone(), producer).map_err(|e| e.to_string())?;
    loop {
        let r = p.run_once().map_err(|e| e.to_string())?;
        if r.published > 0 || r.dead_lettered > 0 || !r.batches_done.is_empty() {
            println!("{}", serde_json::to_string(&r).unwrap_or_default());
        }
        if o.once {
            return Ok(());
        }
        std::thread::sleep(o.interval);
    }
}

fn main() -> ExitCode {
    let parsed = argv().and_then(|v| {
        parse_args_with_switches(
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
            ],
            &["once"],
        )
    });
    let o = match parsed.and_then(|a| opts(&a)) {
        Ok(o) => o,
        Err(e) => {
            if e != "help" {
                eprintln!("robodr-kafka-publish: {e}");
            }
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
