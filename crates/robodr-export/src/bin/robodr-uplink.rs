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
use robodr_export::{retention, Source};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

const USAGE: &str = "usage: robodr-uplink --url https://HOST[:PORT][/API-ROOT] --key-file FILE \
--ca-bundle PEM [--spki-sha256 HEX ...] [--crl-file CRL ...] --state-dir DIR (--spool DIR | --diode-out DIR) \
[--max-lines N] [--max-body-bytes N] [--connect-timeout-ms N] [--request-timeout-ms N] \
[--max-attempts N] [--backoff-base-ms N] [--backoff-max-ms N] [--refused-backoff-max-s N] \
[--exit-when-stuck-s N] [--dead-letter-max-bytes N] [--dead-letter-keep N] \
[--dead-letter-max-age-s N] [--done-max-age-s N] [--done-max-count N] \
[--out-max-age-s N] [--out-max-count N] [--out-max-bytes N] \
[--rejected-max-age-s N] [--rejected-max-count N] [--rejected-max-bytes N] \
[--reinject-max-age-s N] [--reinject-max-count N] [--reinject-max-bytes N] \
[--upgrade-data-source LABEL] [--upgrade-topic TOPIC] [--interval-ms N] [--once | --check]\n\
       robodr-uplink reinject --state-dir DIR (--spool DIR | --diode-out DIR) \
--dead-letter FILE [--dead-letter FILE ...] [--codes CODE,CODE,...] [--dry-run]\n\
       robodr-uplink --version\n\
POSTs findings to {url}/robot-edr/v2/ingest (contract robodr.ingest v1), signed with the \
Ed25519 key file (registered on the server as an `uplink` or `relay` key).\n\
TLS is mandatory (CA bundle; optional SHA-256 SPKI pins: the server key must match one; optional CRLs \
of the server's CAs, PEM or DER: a revoked server is refused, an issuer without a CRL or an expired \
or unusable CRL refuses every server, the files are reloaded when they change); plain http:// \
only to a loopback IP literal, without --ca-bundle.\n\
Status: <state-dir>/uplink-status.json and sd_notify STATUS=. One process per --state-dir (flock).\n\
--check (site acceptance): TLS (CA bundle, pins, CRLs), the ingest endpoint (an empty batch, \
refused with 400 empty_batch before authentication: no finding is sent) and, for a --spool \
(uplink) key, its registration (read-only fleet request); exit 0 passed, 1 failed. Takes no \
lock and writes nothing: runs next to the service.\n\
reinject: re-queue dead-lettered records (default codes: unknown_robot, robot_mismatch, \
site_mismatch, missing_finding_signature, bad_finding_signature) under new batch ids; \
stop the service first.\n\
Retention: rotated dead-letter files past --dead-letter-keep or older than --dead-letter-max-age-s, \
and done/ markers older than --done-max-age-s (default 2592000 = 30 days, 0 = keep) or beyond \
--done-max-count, are deleted once nothing in them is needed any more (records that may still be \
processed again; batches still in out/). Opt-in, default keep: --out-max-* (diode source; only \
when this uplink is the sole consumer of out/) delete the records of out/ batches it has finished \
(a tombstone with the manifest stays), \
--rejected-max-* (spool source) the oldest <spool>/rejected/ records, --reinject-max-* the \
records.jsonl of finished re-injection generations (their origin.jsonl ledger stays). \
uplink-status.json carries state_usage (entries and bytes of each, measured at most once a \
minute).\n\
Exit: 0 done (--once, reinject), 1 runtime or configuration error, 2 usage, \
3 failing longer than --exit-when-stuck-s.";

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

const SERVICE_FLAGS: &[&str] = &[
    "url",
    "key-file",
    "ca-bundle",
    "spki-sha256",
    "crl-file",
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
    "dead-letter-max-age-s",
    "done-max-age-s",
    "done-max-count",
    "out-max-age-s",
    "out-max-count",
    "out-max-bytes",
    "rejected-max-age-s",
    "rejected-max-count",
    "rejected-max-bytes",
    "reinject-max-age-s",
    "reinject-max-count",
    "reinject-max-bytes",
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
    crl_files: Vec<PathBuf>,
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

/// How the uplink authenticates the server, for the start line: plain
/// `http://` (loopback only) has no CA bundle and no pin (RESULTS D2).
fn transport_label(tls: bool, pinned: bool, crl: bool) -> String {
    let base = match (tls, pinned) {
        (false, _) => return "plain HTTP to loopback, no TLS".into(),
        (true, false) => "CA bundle",
        (true, true) => "CA bundle + SPKI pin",
    };
    if crl {
        format!("{base} + CRL")
    } else {
        base.into()
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
    let crl_files: Vec<PathBuf> = a.all("crl-file").into_iter().map(Into::into).collect();
    if !url.tls && !crl_files.is_empty() {
        return Err("--crl-file is meaningless for plain http://".into());
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
    cfg.dead_letter_retention = robodr_export::retention::with_flags(
        cfg.dead_letter_retention,
        a.num("dead-letter-max-age-s")?,
        None,
        None,
    );
    cfg.done_retention = robodr_export::retention::with_flags(
        cfg.done_retention,
        a.num("done-max-age-s")?,
        a.num("done-max-count")?,
        None,
    );
    let [out, rejected, re] = source_bounds(a, matches!(cfg.source, Source::DiodeOut(_)), true)?;
    cfg.out_retention = out.unwrap_or(retention::Retention::UNBOUNDED);
    cfg.rejected_retention = rejected.unwrap_or(retention::Retention::UNBOUNDED);
    cfg.reinject_retention = re.unwrap_or(retention::Retention::UNBOUNDED);
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
        crl_files,
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
            Some(http::client_config_with_crls(roots, &o.pins, &o.crl_files)?.0)
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
    if matches!(v.as_slice(), [only] if only == "--version") {
        println!(
            "{}",
            robodr_buildinfo::version_line("robodr-uplink", env!("CARGO_PKG_VERSION"))
        );
        return ExitCode::SUCCESS;
    }
    if let Some((_, rest)) = v.split_first().filter(|(first, _)| *first == "reinject") {
        return main_reinject(rest.to_vec());
    }
    if v.iter().any(|a| a == "--max-retry-after-s") {
        return usage_exit(
            "--max-retry-after-s was removed: Retry-After is always honoured in full, up to \
             24 h (contract section 7)",
        );
    }
    let mut check = false;
    let o = match parse_args_with_switches(v, SERVICE_FLAGS, &["once", "check"])
        .and_then(|a| {
            check = a.flag("check");
            if check && a.flag("once") {
                return Err("--check and --once are separate modes".into());
            }
            opts(&a)
        })
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
    if check {
        return run_check(&o, &loaded);
    }
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
        transport_label(o.url.tls, !o.pins.is_empty(), !o.crl_files.is_empty())
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

/// `--check`: TLS, the ingest endpoint and (uplink keys) the key's
/// registration, without sending a finding, taking the state lock or
/// writing anything (`robodr_export::uplink::check`).
fn run_check(o: &Opts, loaded: &Loaded) -> ExitCode {
    println!(
        "robodr-uplink --check: {} ({})",
        o.url,
        transport_label(o.url.tls, !o.pins.is_empty(), !o.crl_files.is_empty())
    );
    let source = match &o.cfg.source {
        Source::Spool(p) => ("--spool", p),
        Source::DiodeOut(p) => ("--diode-out", p),
    };
    for (what, p) in [("--state-dir", &o.cfg.state_dir), source] {
        if !p.is_dir() {
            println!("FAIL {what} {} is not a directory", p.display());
            return ExitCode::from(1);
        }
        println!("ok   {what} {}", p.display());
    }
    let mut t = match HttpsTransport::new(o.url.clone(), loaded.tls.clone(), o.timeouts) {
        Ok(t) => t,
        Err(e) => {
            println!("FAIL {e}");
            return ExitCode::from(1);
        }
    };
    let mut nonce = [0u8; 16];
    if let Err(e) = robodr_blackbox::crypto::fill_random(&mut nonce) {
        println!("FAIL random: {e}");
        return ExitCode::from(1);
    }
    let relay = matches!(o.cfg.source, Source::DiodeOut(_));
    let r = uplink::check::run(&mut t, &loaded.key, relay, robodr_export::now_ms(), nonce);
    for l in &r.lines {
        println!("{l}");
    }
    match r.outcome {
        uplink::check::Outcome::Ok => {
            println!("check passed");
            ExitCode::SUCCESS
        }
        uplink::check::Outcome::Failed(e) => {
            println!("FAIL {e}");
            ExitCode::from(1)
        }
    }
}

impl Loaded {
    fn key_id(&self) -> String {
        use robodr_blackbox::Signer;
        self.key.key_id().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::transport_label;

    #[test]
    fn plain_http_is_not_labelled_as_a_ca_bundle() {
        assert_eq!(
            transport_label(false, false, false),
            "plain HTTP to loopback, no TLS"
        );
        assert_eq!(transport_label(true, false, false), "CA bundle");
        assert_eq!(transport_label(true, true, false), "CA bundle + SPKI pin");
        assert_eq!(transport_label(true, false, true), "CA bundle + CRL");
    }
}
