//! `robodr-uplink`: agentd spool (or diode importer output) -> AutoSecOps
//! ingest API (`docs/contracts/robodr.ingest-api.md`). See
//! `robodr_export::uplink` (delivery), `uplink::service` (the loop, status
//! file, backoff) and `uplink::reinject` (the `reinject` subcommand).

// S10: this crate has no `unsafe` code and must stay that way.
#![forbid(unsafe_code)]

use robodr_agentd::notify::Notifier;
use robodr_blackbox::sign_ed25519::Ed25519SigningKey;
use robodr_diode::cli::{argv, parse_args_with_switches, Args};
use robodr_export::deadletter::Rotation;
use robodr_export::uplink::http::{self, Endpoint, HttpsTransport, Timeouts};
use robodr_export::uplink::reinject::{self, ReinjectOptions};
use robodr_export::uplink::service::{self, Env, ServiceConfig};
use robodr_export::uplink::{self, RetryPolicy, StateLock, Uplink, UplinkConfig};
use robodr_export::Source;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

const USAGE: &str = "usage: robodr-uplink --url https://HOST[:PORT][/API-ROOT] --key-file FILE \
--ca-bundle PEM [--spki-sha256 HEX ...] --state-dir DIR (--spool DIR | --diode-out DIR) \
[--max-lines N] [--max-body-bytes N] [--connect-timeout-ms N] [--request-timeout-ms N] \
[--max-attempts N] [--backoff-base-ms N] [--backoff-max-ms N] [--refused-backoff-max-s N] \
[--exit-when-stuck-s N] [--dead-letter-max-bytes N] [--dead-letter-keep N] \
[--upgrade-data-source LABEL] [--upgrade-topic TOPIC] [--interval-ms N] [--once]\n\
       robodr-uplink reinject --state-dir DIR (--spool DIR | --diode-out DIR) \
--dead-letter FILE [--dead-letter FILE ...] [--codes CODE,CODE,...] [--dry-run]\n\
       robodr-uplink --version\n\
POSTs findings to {url}/robot-edr/v2/ingest (contract robodr.ingest v1), signed with the \
Ed25519 key file (registered on the server as an `uplink` or `relay` key).\n\
TLS is mandatory (CA bundle; optional SHA-256 SPKI pins: the server key must match one); plain http:// \
only to a loopback IP literal, without --ca-bundle.\n\
Status: <state-dir>/uplink-status.json and sd_notify STATUS=. One process per --state-dir (flock).\n\
reinject: re-queue dead-lettered records (default codes: unknown_robot, robot_mismatch, \
site_mismatch, missing_finding_signature, bad_finding_signature) under new batch ids; \
stop the service first.\n\
Exit: 0 done (--once, reinject), 1 runtime or configuration error, 2 usage, \
3 failing longer than --exit-when-stuck-s.";

const SERVICE_FLAGS: &[&str] = &[
    "url",
    "key-file",
    "ca-bundle",
    "spki-sha256",
    "state-dir",
    "spool",
    "diode-out",
    "max-lines",
    "max-body-bytes",
    "connect-timeout-ms",
    "request-timeout-ms",
    "max-attempts",
    "backoff-base-ms",
    "backoff-max-ms",
    "refused-backoff-max-s",
    "exit-when-stuck-s",
    "dead-letter-max-bytes",
    "dead-letter-keep",
    "upgrade-data-source",
    "upgrade-topic",
    "interval-ms",
];

const REINJECT_FLAGS: &[&str] = &[
    "state-dir",
    "spool",
    "diode-out",
    "dead-letter",
    "codes",
    "max-record-bytes",
];

struct Opts {
    url: Endpoint,
    key_file: String,
    ca_bundle: Option<String>,
    pins: Vec<[u8; 32]>,
    timeouts: Timeouts,
    cfg: UplinkConfig,
    service: ServiceConfig,
}

fn ms(a: &Args, flag: &str) -> Result<Option<Duration>, String> {
    match a.num::<u64>(flag)? {
        Some(0) => Err(format!("--{flag} must be > 0")),
        Some(n) => Ok(Some(Duration::from_millis(n))),
        None => Ok(None),
    }
}

fn secs(a: &Args, flag: &str) -> Result<Option<Duration>, String> {
    match a.num::<u64>(flag)? {
        Some(0) => Err(format!("--{flag} must be > 0")),
        Some(n) if n > 7 * 24 * 3600 => Err(format!("--{flag} must be at most 604800 (7 days)")),
        Some(n) => Ok(Some(Duration::from_secs(n))),
        None => Ok(None),
    }
}

fn source(a: &Args) -> Result<Source, String> {
    match (a.one("diode-out")?, a.one("spool")?) {
        (Some(d), None) => Ok(Source::DiodeOut(d.into())),
        (None, Some(s)) => Ok(Source::Spool(s.into())),
        _ => Err("exactly one of --diode-out / --spool is required".into()),
    }
}

fn opts(a: &Args) -> Result<Opts, String> {
    let url = Endpoint::parse(a.req("url")?)?;
    let ca_bundle = a.one("ca-bundle")?.map(str::to_string);
    let pins = a
        .all("spki-sha256")
        .into_iter()
        .map(http::parse_pin)
        .collect::<Result<Vec<_>, _>>()?;
    match (url.tls, ca_bundle.is_some()) {
        (true, false) => return Err("--ca-bundle is required for https://".into()),
        (false, true) => {
            return Err("--ca-bundle is meaningless for plain http:// (loopback only)".into())
        }
        _ => {}
    }
    if !url.tls && !pins.is_empty() {
        return Err("--spki-sha256 is meaningless for plain http://".into());
    }
    let mut timeouts = Timeouts::default();
    if let Some(d) = ms(a, "connect-timeout-ms")? {
        timeouts.connect = d;
    }
    if let Some(d) = ms(a, "request-timeout-ms")? {
        timeouts.request = d;
    }
    let mut cfg = UplinkConfig::new(source(a)?, a.req("state-dir")?);
    if let Some(n) = a.num("max-lines")? {
        cfg.max_lines = n;
    }
    if let Some(n) = a.num("max-body-bytes")? {
        cfg.max_body_bytes = n;
    }
    if let Some(l) = a.one("upgrade-data-source")? {
        cfg.upgrade_data_source = l.into();
    }
    if let Some(t) = a.one("upgrade-topic")? {
        cfg.upgrade_topic = t.into();
    }
    let mut retry = RetryPolicy::default();
    if let Some(n) = a.num("max-attempts")? {
        retry.max_attempts = n;
    }
    if let Some(d) = ms(a, "backoff-base-ms")? {
        retry.base = d;
    }
    if let Some(d) = ms(a, "backoff-max-ms")? {
        retry.max = d;
    }
    cfg.retry = retry;
    let mut rot = uplink::DEFAULT_DEAD_LETTER_ROTATION;
    match a.num::<u64>("dead-letter-max-bytes")? {
        Some(0) => cfg.dead_letter_rotation = None,
        Some(n) => rot.max_bytes = n,
        None => {}
    }
    if let Some(k) = a.num::<u32>("dead-letter-keep")? {
        if k == 0 {
            return Err("--dead-letter-keep must be >= 1".into());
        }
        rot.keep = k;
    }
    if cfg.dead_letter_rotation.is_some() {
        cfg.dead_letter_rotation = Some(Rotation { ..rot });
    }
    let interval = ms(a, "interval-ms")?.unwrap_or(Duration::from_secs(2));
    let service = ServiceConfig {
        interval,
        transient_backoff_max: retry.max,
        refused_backoff_max: secs(a, "refused-backoff-max-s")?
            .unwrap_or(ServiceConfig::default().refused_backoff_max),
        exit_when_stuck_after: secs(a, "exit-when-stuck-s")?,
        once: a.flag("once"),
    };
    Ok(Opts {
        url,
        key_file: a.req("key-file")?.to_string(),
        ca_bundle,
        pins,
        timeouts,
        cfg,
        service,
    })
}

/// Everything loaded once at start: key and TLS configuration.
struct Loaded {
    key: Ed25519SigningKey,
    tls: Option<rustls::ClientConfig>,
}

fn load(o: &Opts) -> Result<Loaded, String> {
    let key = uplink::load_sender_key(std::path::Path::new(&o.key_file))?;
    let tls = match &o.ca_bundle {
        Some(p) => {
            let roots = http::load_ca_bundle(std::path::Path::new(p))?;
            Some(http::client_config(roots, &o.pins)?)
        }
        None => None,
    };
    Ok(Loaded { key, tls })
}

fn random_u64() -> u64 {
    let mut b = [0u8; 8];
    robodr_blackbox::crypto::fill_random(&mut b)
        .map(|()| u64::from_le_bytes(b))
        .unwrap_or(0)
}

fn usage_exit(e: &str) -> ExitCode {
    if e != "help" {
        eprintln!("robodr-uplink: {e}");
    }
    eprintln!("{USAGE}");
    if e == "help" {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

fn main_reinject(args: Vec<String>) -> ExitCode {
    let parsed = parse_args_with_switches(args, REINJECT_FLAGS, &["dry-run"]).and_then(|a| {
        let codes: BTreeSet<String> = match a.one("codes")? {
            Some(c) => c
                .split(',')
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .map(|c| {
                    if uplink::wire::is_valid_code(c) {
                        Ok(c.to_string())
                    } else {
                        Err(format!("--codes: invalid code {c:?}"))
                    }
                })
                .collect::<Result<_, _>>()?,
            None => reinject::DEFAULT_CODES
                .iter()
                .map(|c| c.to_string())
                .collect(),
        };
        let dead_letters: Vec<PathBuf> = a
            .all("dead-letter")
            .into_iter()
            .map(PathBuf::from)
            .collect();
        if dead_letters.is_empty() {
            return Err("--dead-letter FILE is required (repeat it for rotated files)".into());
        }
        Ok(ReinjectOptions {
            state_dir: a.req("state-dir")?.into(),
            source: source(&a)?,
            dead_letters,
            codes,
            max_record_bytes: a.num("max-record-bytes")?.unwrap_or(1024 * 1024),
            dry_run: a.flag("dry-run"),
            now_ms: robodr_export::now_ms(),
        })
    });
    let o = match parsed {
        Ok(o) => o,
        Err(e) => return usage_exit(&e),
    };
    match reinject::reinject(&o) {
        Ok(r) => {
            println!("{}", serde_json::to_string(&r).unwrap_or_default());
            for u in &r.unavailable {
                eprintln!(
                    "robodr-uplink reinject: {} line {}: {}",
                    u.source, u.position, u.why
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("robodr-uplink reinject: {e}");
            ExitCode::from(1)
        }
    }
}

fn main() -> ExitCode {
    let v = match argv() {
        Ok(v) => v,
        Err(e) => return usage_exit(&e),
    };
    if v.len() == 1 && v[0] == "--version" {
        println!("robodr-uplink {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if v.first().map(String::as_str) == Some("reinject") {
        return main_reinject(v[1..].to_vec());
    }
    if v.iter().any(|a| a == "--max-retry-after-s") {
        return usage_exit(
            "--max-retry-after-s was removed: Retry-After is always honoured in full, up to \
             24 h (contract section 7)",
        );
    }
    let o = match parse_args_with_switches(v, SERVICE_FLAGS, &["once"])
        .and_then(|a| opts(&a))
        .and_then(|o| o.cfg.validate().map(|()| o).map_err(|e| e.to_string()))
    {
        Ok(o) => o,
        Err(e) => return usage_exit(&e),
    };
    let loaded = match load(&o) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("robodr-uplink: {e}");
            return ExitCode::from(1);
        }
    };
    // One process per state directory, for the whole lifetime (also between
    // runs): a second service, a --once or a reinject run fails clearly.
    let lock = match StateLock::acquire(&o.cfg.state_dir) {
        Ok(l) => Arc::new(l),
        Err(e) => {
            eprintln!("robodr-uplink: {e}");
            return ExitCode::from(1);
        }
    };
    eprintln!(
        "robodr-uplink: {} as {} ({})",
        o.url,
        loaded.key_id(),
        if o.pins.is_empty() {
            "CA bundle"
        } else {
            "CA bundle + SPKI pin"
        }
    );
    let notifier = Notifier::from_env();
    let open = || {
        let t = HttpsTransport::new(o.url.clone(), loaded.tls.clone(), o.timeouts)
            .map_err(uplink::UplinkError::Config)?;
        let mut seed = loaded.key.to_seed();
        let key = Ed25519SigningKey::from_seed_with_derived_id(&seed);
        robodr_blackbox::crypto::wipe(&mut seed);
        Uplink::open_locked(o.cfg.clone(), t, key, lock.clone())
    };
    let mut env = Env {
        now_ms: Box::new(robodr_export::now_ms),
        sleep: Box::new(std::thread::sleep),
        rng: Box::new(random_u64),
        notify: Box::new(|m| {
            notifier.notify(m);
        }),
        log: Box::new(|m| eprintln!("robodr-uplink: {m}")),
        report: Box::new(|r| println!("{}", serde_json::to_string(r).unwrap_or_default())),
        stop: Box::new(|| false),
    };
    ExitCode::from(service::run(&o.service, &o.cfg.state_dir, open, &mut env))
}

impl Loaded {
    fn key_id(&self) -> String {
        use robodr_blackbox::Signer;
        self.key.key_id().to_string()
    }
}
