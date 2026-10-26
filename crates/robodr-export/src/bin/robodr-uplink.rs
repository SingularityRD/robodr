//! `robodr-uplink`: agentd spool (or diode importer output) -> AutoSecOps
//! ingest API (`docs/contracts/robodr.ingest-api.md`). See
//! `robodr_export::uplink`.

use robodr_blackbox::sign_ed25519::Ed25519SigningKey;
use robodr_diode::cli::{argv, parse_args_with_switches, Args};
use robodr_export::uplink::http::{self, Endpoint, HttpsTransport, Timeouts};
use robodr_export::uplink::{self, backoff_delay, RetryPolicy, Uplink, UplinkConfig};
use robodr_export::Source;
use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "usage: robodr-uplink --url https://HOST[:PORT][/API-ROOT] --key-file FILE \
--ca-bundle PEM [--spki-sha256 HEX ...] --state-dir DIR (--spool DIR | --diode-out DIR) \
[--max-lines N] [--max-body-bytes N] [--connect-timeout-ms N] [--request-timeout-ms N] \
[--max-attempts N] [--backoff-base-ms N] [--backoff-max-ms N] [--max-retry-after-s N] \
[--upgrade-data-source LABEL] [--upgrade-topic TOPIC] [--interval-ms N] [--once] | --version\n\
POSTs findings to {url}/robot-edr/v2/ingest (contract robodr.ingest v1), signed with the \
Ed25519 key file (registered on the server as an `uplink` or `relay` key).\n\
TLS is mandatory (CA bundle; optional SHA-256 SPKI pins: the server key must match one); plain http:// \
only to a loopback IP literal, without --ca-bundle.\n\
Exit: 0 done (--once), 1 runtime or configuration error, 2 usage.";

struct Opts {
    url: Endpoint,
    key_file: String,
    ca_bundle: Option<String>,
    pins: Vec<[u8; 32]>,
    timeouts: Timeouts,
    cfg: UplinkConfig,
    interval: Duration,
    once: bool,
}

fn ms(a: &Args, flag: &str) -> Result<Option<Duration>, String> {
    match a.num::<u64>(flag)? {
        Some(0) => Err(format!("--{flag} must be > 0")),
        Some(n) => Ok(Some(Duration::from_millis(n))),
        None => Ok(None),
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
    let source = match (a.one("diode-out")?, a.one("spool")?) {
        (Some(d), None) => Source::DiodeOut(d.into()),
        (None, Some(s)) => Source::Spool(s.into()),
        _ => return Err("exactly one of --diode-out / --spool is required".into()),
    };
    let mut cfg = UplinkConfig::new(source, a.req("state-dir")?);
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
    if let Some(n) = a.num::<u64>("max-retry-after-s")? {
        retry.max_retry_after = Duration::from_secs(n);
    }
    cfg.retry = retry;
    let interval = ms(a, "interval-ms")?.unwrap_or(Duration::from_secs(2));
    Ok(Opts {
        url,
        key_file: a.req("key-file")?.to_string(),
        ca_bundle,
        pins,
        timeouts,
        cfg,
        interval,
        once: a.flag("once"),
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

/// Runs until an error (or once). `failures` is reset by every successful
/// run.
fn run(o: &Opts, l: &Loaded, failures: &mut u32) -> Result<(), String> {
    let t = HttpsTransport::new(o.url.clone(), l.tls.clone(), o.timeouts)?;
    let mut seed = l.key.to_seed();
    let key = Ed25519SigningKey::from_seed_with_derived_id(&seed);
    robodr_blackbox::crypto::wipe(&mut seed);
    let mut u = Uplink::open(o.cfg.clone(), t, key).map_err(|e| e.to_string())?;
    loop {
        let r = u.run_once().map_err(|e| e.to_string())?;
        *failures = 0;
        if !r.is_empty() {
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
        if v.len() == 1 && v[0] == "--version" {
            println!("robodr-uplink {}", env!("CARGO_PKG_VERSION"));
            return Err("version".into());
        }
        parse_args_with_switches(
            v,
            &[
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
                "max-retry-after-s",
                "upgrade-data-source",
                "upgrade-topic",
                "interval-ms",
            ],
            &["once"],
        )
    });
    let o = match parsed.and_then(|a| opts(&a)) {
        Ok(o) => o,
        Err(e) if e == "version" => return ExitCode::SUCCESS,
        Err(e) => {
            if e != "help" {
                eprintln!("robodr-uplink: {e}");
            }
            eprintln!("{USAGE}");
            return if e == "help" {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            };
        }
    };
    let loaded = match load(&o) {
        Ok(l) => l,
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
    // Consecutive failed runs back off exponentially (with jitter) from the
    // poll interval up to the retry cap, so a refusing server (401, 409) is
    // not hammered.
    let error_policy = RetryPolicy {
        max_attempts: u32::MAX,
        base: o.interval,
        max: o.cfg.retry.max.max(o.interval),
        max_retry_after: o.cfg.retry.max_retry_after,
    };
    let mut failures = 0u32;
    loop {
        match run(&o, &loaded, &mut failures) {
            Ok(()) => return ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("robodr-uplink: {e}");
                if o.once {
                    return ExitCode::from(1);
                }
                failures = failures.saturating_add(1);
                let mut b = [0u8; 8];
                let rand = robodr_blackbox::crypto::fill_random(&mut b)
                    .map(|()| u64::from_le_bytes(b))
                    .unwrap_or(0);
                std::thread::sleep(backoff_delay(&error_policy, failures, rand));
            }
        }
    }
}

impl Loaded {
    fn key_id(&self) -> String {
        use robodr_blackbox::Signer;
        self.key.key_id().to_string()
    }
}
