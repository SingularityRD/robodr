//! `robodr-uplink` delivery logic against the reference consumer
//! (`tests/common/ingest.rs`) through an in-memory transport: batching,
//! batch ids, partial acceptance, dead letters, retries and backoff,
//! `413` splitting, refusals, and crash/restart at every step.

mod common;
#[path = "common/ingest.rs"]
mod ingest;

use common::*;
use ingest::{Consumer, MockTransport, Registry, Role, Script};
use robodr_agent::FindingOutput;
use robodr_agentd::spool::Spool;
use robodr_blackbox::sign_ed25519::Ed25519SigningKey;
use robodr_blackbox::Signer;
use robodr_export::uplink::wire;
use robodr_export::uplink::{FailPoint, RetryPolicy, Uplink, UplinkConfig, UplinkError};
use robodr_export::Source;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const SENDER_SEED: [u8; 32] = [0x51; 32];
const FINDING_SEED: [u8; 32] = [0x52; 32];
const OTHER_ROBOT: &str = "ugv-008";

fn sender() -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed_with_derived_id(&SENDER_SEED)
}

fn finding_key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed_with_derived_id(&FINDING_SEED)
}

fn registry(role: Role) -> Registry {
    let s = sender();
    let f = finding_key();
    Registry::default()
        .robot(UNIT, false)
        .robot(OTHER_ROBOT, false)
        .key(
            s.key_id(),
            role,
            (role == Role::Uplink).then_some(UNIT),
            s.public_key(),
        )
        .key(f.key_id(), Role::Finding, Some(UNIT), f.public_key())
}

type Shared = Arc<Mutex<Consumer>>;

struct Rig {
    _tmp: TempDir,
    spool: PathBuf,
    out: PathBuf,
    state: PathBuf,
    consumer: Shared,
    sleeps: Arc<Mutex<Vec<Duration>>>,
    clock: Arc<AtomicU64>,
}

impl Rig {
    fn new(tag: &str, role: Role) -> Self {
        let tmp = TempDir::new(tag);
        let p = tmp.path().to_path_buf();
        let r = Self {
            spool: p.join("spool"),
            out: p.join("out"),
            state: p.join("state"),
            consumer: Arc::new(Mutex::new(Consumer::new(registry(role)))),
            sleeps: Arc::new(Mutex::new(Vec::new())),
            clock: Arc::new(AtomicU64::new(NOW)),
            _tmp: tmp,
        };
        // An empty spool (agentd layout).
        drop(Spool::open(&r.spool, 1 << 30, 1_000_000).unwrap());
        fs::create_dir_all(&r.out).unwrap();
        r
    }

    fn output(rec: robodr_ocsf::Record) -> FindingOutput {
        FindingOutput {
            topic: rec.topic.to_string(),
            key: rec.key,
            partition: rec.partition,
            value: rec.value,
            headers: rec
                .headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        }
    }

    /// Spool findings `from..from+n` of `robot`, signed with the finding key
    /// if `signed`.
    fn spool(&self, robot: &str, from: u64, n: u64, signed: bool) {
        let mut s = Spool::open(&self.spool, 1 << 30, 1_000_000).unwrap();
        let fk = finding_key();
        for i in from..from + n {
            let mut rec = robodr_ocsf::record(&finding_for(robot, i), Some(12)).unwrap();
            if signed {
                robodr_ocsf::sign_record(&mut rec, &fk).unwrap();
            }
            s.write(&Self::output(rec), false).unwrap();
        }
    }

    fn spool_garbage(&self) {
        let n = self.ready().len() + self.acked().len() + self.rejected().len() + 1000;
        fs::write(
            self.spool.join("ready").join(format!("{n:020}.json")),
            b"{\"not\":\"a spool record\"}",
        )
        .unwrap();
    }

    fn files(&self, d: &str) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(self.spool.join(d))
            .map(|r| {
                r.map(|e| e.unwrap().file_name().into_string().unwrap())
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }
    fn ready(&self) -> Vec<String> {
        self.files("ready")
    }
    fn acked(&self) -> Vec<String> {
        self.files("acked")
    }
    fn rejected(&self) -> Vec<String> {
        self.files("rejected")
    }

    fn cfg(&self, source: Source) -> UplinkConfig {
        let mut c = UplinkConfig::new(source, &self.state);
        c.retry = RetryPolicy {
            max_attempts: 5,
            base: Duration::from_millis(100),
            max: Duration::from_secs(2),
            max_retry_after: Duration::from_secs(60),
        };
        c
    }

    fn spool_cfg(&self) -> UplinkConfig {
        self.cfg(Source::Spool(self.spool.clone()))
    }

    fn uplink_with(&self, cfg: UplinkConfig, fail_next: usize) -> Uplink<MockTransport> {
        let t = MockTransport {
            consumer: self.consumer.clone(),
            fail_next,
        };
        let clock = self.clock.clone();
        let sleeps = self.sleeps.clone();
        Uplink::open(cfg, t, sender())
            .unwrap()
            .with_clock(move || clock.fetch_add(1000, Ordering::SeqCst))
            .with_sleeper(move |d| sleeps.lock().unwrap().push(d))
            .with_rng(|| 0)
            .with_log(|_| {})
    }

    fn uplink(&self, cfg: UplinkConfig) -> Uplink<MockTransport> {
        self.uplink_with(cfg, 0)
    }

    fn c(&self) -> std::sync::MutexGuard<'_, Consumer> {
        self.consumer.lock().unwrap()
    }

    fn requests(&self) -> Vec<ingest::Seen> {
        self.c().seen.clone()
    }

    fn dead_letters(&self) -> Vec<serde_json::Value> {
        match fs::read_to_string(self.state.join("dead-letter.jsonl")) {
            Ok(s) => s
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}

fn hdr<'a>(s: &'a ingest::Seen, name: &str) -> &'a str {
    &s.headers.iter().find(|(k, _)| k == name).unwrap().1
}

fn line_count(body: &[u8]) -> usize {
    ingest::split_lines(body).len()
}

#[test]
fn spool_partial_acceptance_dead_letters_and_acks() {
    let r = Rig::new("partial", Role::Uplink);
    r.spool(UNIT, 0, 3, false);
    r.spool(OTHER_ROBOT, 0, 1, false); // robot_mismatch (uplink key of UNIT)
    r.spool_garbage(); // refused locally
    r.spool(UNIT, 3, 2, false);
    let mut u = r.uplink(r.spool_cfg());
    let rep = u.run_once().unwrap();
    assert_eq!(rep.batches, 1);
    assert_eq!(rep.lines_sent, 6);
    assert_eq!((rep.accepted, rep.created, rep.rejected), (5, 5, 1));
    assert_eq!(rep.dead_lettered_local, 1);
    assert!(r.ready().is_empty());
    assert_eq!(r.acked().len(), 5);
    assert_eq!(r.rejected().len(), 2);
    let dl = r.dead_letters();
    assert_eq!(dl.len(), 2);
    assert_eq!(dl[0]["code"], "local");
    assert_eq!(dl[1]["code"], "robot_mismatch");
    let pos = dl[1]["position"].as_u64().unwrap();
    assert!(r.rejected().contains(&format!("{pos:020}.json")));
    assert!(dl[1]["batch_id"].as_str().unwrap().starts_with("rdu1-"));
    assert!(dl[1]["record"].as_str().unwrap().contains(OTHER_ROBOT));
    assert_eq!(r.c().finding_count(), 5);
    // Nothing left: no request.
    let rep = u.run_once().unwrap();
    assert!(rep.is_empty(), "{rep:?}");
    assert_eq!(r.requests().len(), 1);
    let st = u.state();
    assert!(st.pending.is_none());
    assert_eq!(
        (st.sent_lines_total, st.accepted_total, st.rejected_total),
        (6, 5, 1)
    );
}

#[test]
fn request_headers_and_signature_follow_the_contract() {
    let r = Rig::new("headers", Role::Uplink);
    r.spool(UNIT, 0, 2, false);
    r.uplink(r.spool_cfg()).run_once().unwrap();
    let seen = r.requests();
    assert_eq!(seen.len(), 1);
    let s = &seen[0];
    assert_eq!(s.status, 200);
    let names: Vec<&str> = s.headers.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        names,
        [
            "Content-Type",
            "X-RoboDR-Key-Id",
            "X-RoboDR-Batch-Id",
            "X-RoboDR-Timestamp",
            "X-RoboDR-Signature"
        ]
    );
    assert_eq!(hdr(s, "Content-Type"), "application/x-ndjson");
    let kid = sender().key_id().to_string();
    assert_eq!(hdr(s, wire::H_KEY_ID), kid);
    let ts: u64 = hdr(s, wire::H_TIMESTAMP).parse().unwrap();
    assert_eq!(ts, NOW);
    assert!(wire::verify_batch(
        &sender().public_key(),
        &kid,
        hdr(s, wire::H_BATCH_ID),
        ts,
        &s.body,
        hdr(s, wire::H_SIGNATURE)
    ));
    // Body: one line per record, final LF, value verbatim, sig null.
    assert!(s.body.ends_with(b"\n"));
    let files = r.acked();
    for (l, f) in ingest::split_lines(&s.body).iter().zip(&files) {
        let v: serde_json::Value = serde_json::from_slice(l).unwrap();
        let rec: serde_json::Value =
            serde_json::from_slice(&fs::read(r.spool.join("acked").join(f)).unwrap()).unwrap();
        assert_eq!(v["value"], rec["value"]);
        assert!(v["sig"].is_null());
        assert_eq!(v.as_object().unwrap().len(), 2);
    }
}

#[test]
fn per_finding_signatures_are_carried_and_verify() {
    let r = Rig::new("sig", Role::Uplink);
    // UNIT requires signatures: a missing one would be refused.
    r.c().reg.robots.insert(UNIT.into(), true);
    r.spool(UNIT, 0, 3, true);
    let rep = r.uplink(r.spool_cfg()).run_once().unwrap();
    assert_eq!((rep.created, rep.rejected), (3, 0));
    let body = &r.requests()[0].body;
    for l in ingest::split_lines(body) {
        let v: serde_json::Value = serde_json::from_slice(l).unwrap();
        assert_eq!(v["sig"]["alg"], "ed25519");
        assert_eq!(v["sig"]["key_id"], finding_key().key_id());
    }
}

#[test]
fn batches_respect_line_and_byte_limits() {
    let r = Rig::new("limits", Role::Uplink);
    r.spool(UNIT, 0, 7, false);
    let mut cfg = r.spool_cfg();
    cfg.max_lines = 3;
    let rep = r.uplink(cfg).run_once().unwrap();
    assert_eq!(rep.batches, 3);
    let seen = r.requests();
    let sizes: Vec<usize> = seen.iter().map(|s| line_count(&s.body)).collect();
    assert_eq!(sizes, [3, 3, 1]);
    let ids: std::collections::BTreeSet<&str> =
        seen.iter().map(|s| hdr(s, wire::H_BATCH_ID)).collect();
    assert_eq!(ids.len(), 3, "distinct batch ids");
    assert_eq!(r.acked().len(), 7);

    // Byte limit: 1000 findings (~1.6 KB each) do not fit 1 MiB.
    let r = Rig::new("limits-bytes", Role::Uplink);
    r.spool(UNIT, 0, 1000, false);
    let mut cfg = r.spool_cfg();
    cfg.max_body_bytes = robodr_export::uplink::MIN_BODY_BYTES;
    let rep = r.uplink(cfg).run_once().unwrap();
    assert_eq!(rep.created, 1000);
    let seen = r.requests();
    assert!(seen.len() >= 2);
    for s in &seen {
        assert!(s.body.len() <= robodr_export::uplink::MIN_BODY_BYTES);
        assert!(line_count(&s.body) < 1000);
    }
    // A batch is cut only when the next line would not fit.
    let next = ingest::split_lines(&seen[1].body)[0].len() + 1;
    assert!(seen[0].body.len() + next > robodr_export::uplink::MIN_BODY_BYTES);
    assert_eq!(r.acked().len(), 1000);
}

#[test]
fn config_limits_are_enforced() {
    let r = Rig::new("cfg", Role::Uplink);
    for edit in [
        (|c: &mut UplinkConfig| c.max_lines = 0) as fn(&mut UplinkConfig),
        |c| c.max_lines = 1001,
        |c| c.max_body_bytes = wire::MAX_BODY_BYTES + 1,
        |c| c.max_body_bytes = robodr_export::uplink::MIN_BODY_BYTES - 1,
        |c| c.retry.max_attempts = 0,
        |c| c.upgrade_topic = "bad topic".into(),
    ] {
        let mut c = r.spool_cfg();
        edit(&mut c);
        let t = MockTransport {
            consumer: r.consumer.clone(),
            fail_next: 0,
        };
        assert!(matches!(
            Uplink::open(c, t, sender()),
            Err(UplinkError::Config(_))
        ));
    }
    // A key with a chosen (non-derived) id is refused: the contract names
    // keys by the derived id.
    let named = Ed25519SigningKey::from_seed("uplink-1", &SENDER_SEED).unwrap();
    let t = MockTransport {
        consumer: r.consumer.clone(),
        fail_next: 0,
    };
    assert!(matches!(
        Uplink::open(r.spool_cfg(), t, named),
        Err(UplinkError::Config(_))
    ));
}

#[test]
fn transport_errors_are_retried_with_the_same_batch_and_backoff() {
    let r = Rig::new("retry", Role::Uplink);
    r.spool(UNIT, 0, 2, false);
    let mut u = r.uplink_with(r.spool_cfg(), 2);
    let rep = u.run_once().unwrap();
    assert_eq!((rep.requests, rep.retries, rep.created), (3, 2, 2));
    // The two failed attempts never reached the consumer; the third did,
    // with a fresh timestamp. Backoff: [50, 100] ms then [100, 200] ms
    // (rng 0: the lower bound).
    let seen = r.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(hdr(&seen[0], wire::H_TIMESTAMP), (NOW + 2000).to_string());
    assert_eq!(
        *r.sleeps.lock().unwrap(),
        [Duration::from_millis(50), Duration::from_millis(100)]
    );
}

#[test]
fn server_errors_and_429_retry_with_same_batch_id_and_honour_retry_after() {
    let r = Rig::new("5xx", Role::Uplink);
    r.spool(UNIT, 0, 2, false);
    r.c().script.extend([
        Script::Status(503, None, "{\"code\":\"unavailable\"}".into()),
        Script::Status(500, None, "oops".into()),
        Script::Status(429, Some("7".into()), "{\"code\":\"rate_limited\"}".into()),
    ]);
    let rep = r.uplink(r.spool_cfg()).run_once().unwrap();
    assert_eq!((rep.requests, rep.retries, rep.created), (4, 3, 2));
    let seen = r.requests();
    assert_eq!(
        seen.iter().map(|s| s.status).collect::<Vec<_>>(),
        [503, 500, 429, 200]
    );
    let id = hdr(&seen[0], wire::H_BATCH_ID);
    let kid = sender().key_id().to_string();
    let mut stamps = Vec::new();
    for s in &seen {
        assert_eq!(hdr(s, wire::H_BATCH_ID), id, "same batch id");
        assert_eq!(s.body, seen[0].body, "same body");
        let ts: u64 = hdr(s, wire::H_TIMESTAMP).parse().unwrap();
        assert!(wire::verify_batch(
            &sender().public_key(),
            &kid,
            id,
            ts,
            &s.body,
            hdr(s, wire::H_SIGNATURE)
        ));
        stamps.push(ts);
    }
    assert!(
        stamps.windows(2).all(|w| w[0] < w[1]),
        "re-signed: {stamps:?}"
    );
    let sleeps = r.sleeps.lock().unwrap().clone();
    assert_eq!(sleeps.len(), 3);
    assert_eq!(sleeps[2], Duration::from_secs(7), "Retry-After honoured");
}

#[test]
fn attempts_exhausted_keep_the_batch_pending_with_its_id() {
    let r = Rig::new("giveup", Role::Uplink);
    r.spool(UNIT, 0, 2, false);
    for _ in 0..5 {
        r.c()
            .script
            .push_back(Script::Status(502, None, String::new()));
    }
    let mut u = r.uplink(r.spool_cfg());
    match u.run_once() {
        Err(UplinkError::GaveUp { attempts: 5, .. }) => {}
        other => panic!("{other:?}"),
    }
    assert_eq!(r.ready().len(), 2, "nothing acknowledged");
    let pending = u.state().pending.clone().unwrap();
    // The next run (server back) re-sends the same batch id.
    let rep = r.uplink(r.spool_cfg()).run_once().unwrap();
    assert_eq!(rep.resumed, 1);
    let seen = r.requests();
    assert_eq!(
        hdr(seen.last().unwrap(), wire::H_BATCH_ID),
        pending.batch_id
    );
    assert_eq!(r.acked().len(), 2);
}

#[test]
fn refusals_acknowledge_nothing() {
    for (status, code) in [
        (401, "bad_signature"),
        (400, "bad_header"),
        (409, "batch_id_reuse"),
        (415, "x"),
    ] {
        let r = Rig::new("refused", Role::Uplink);
        r.spool(UNIT, 0, 2, false);
        r.c().script.push_back(Script::Status(
            status,
            None,
            format!("{{\"code\":\"{code}\",\"detail\":\"d\"}}"),
        ));
        let mut u = r.uplink(r.spool_cfg());
        match u.run_once() {
            Err(UplinkError::Refused {
                status: s, code: c, ..
            }) => {
                assert_eq!((s, c.as_str()), (status, code));
            }
            other => panic!("{status}: {other:?}"),
        }
        assert_eq!(
            r.requests().len(),
            1,
            "{status}: not retried within the run"
        );
        assert_eq!(r.ready().len(), 2);
        assert!(r.dead_letters().is_empty());
        let id = u.state().pending.clone().unwrap().batch_id;
        let rep = r.uplink(r.spool_cfg()).run_once().unwrap();
        assert_eq!(rep.created, 2);
        assert_eq!(hdr(&r.requests()[1], wire::H_BATCH_ID), id);
    }
}

#[test]
fn malformed_200_acknowledges_nothing() {
    let r = Rig::new("bad200", Role::Uplink);
    r.spool(UNIT, 0, 2, false);
    let mut id = String::from("other");
    for body in [
        "{\"batch_id\":\"ID\",\"replayed\":false,\"accepted\":2,\"created\":2,\"updated\":0,\"duplicates\":0,\"rejected\":[]}",
        "not json",
        // Right batch id, but one line unaccounted for.
        "{\"batch_id\":\"ID\",\"replayed\":false,\"accepted\":1,\"created\":1,\"updated\":0,\"duplicates\":0,\"rejected\":[]}",
        // Right batch id, a rejected line outside the batch.
        "{\"batch_id\":\"ID\",\"replayed\":false,\"accepted\":2,\"created\":2,\"updated\":0,\"duplicates\":0,\"rejected\":[{\"line\":3,\"code\":\"x\"}]}",
    ] {
        r.c()
            .script
            .push_back(Script::Status(200, None, body.replace("ID", &id)));
        let mut u = r.uplink(r.spool_cfg());
        match u.run_once() {
            Err(UplinkError::Protocol(_)) => {}
            other => panic!("{other:?}"),
        }
        assert_eq!(r.ready().len(), 2);
        assert!(r.dead_letters().is_empty());
        id = u.state().pending.clone().unwrap().batch_id;
    }
}

#[test]
fn status_413_halves_the_batch_and_a_single_line_413_stops() {
    let r = Rig::new("413", Role::Uplink);
    r.spool(UNIT, 0, 5, false);
    r.c().max_lines = 2;
    let rep = r.uplink(r.spool_cfg()).run_once().unwrap();
    assert_eq!(rep.created, 5);
    assert_eq!(
        rep.split_413, 1,
        "5 lines: 413, then batches of at most 2: {rep:?}"
    );
    assert_eq!(rep.batches, 3);
    let seen = r.requests();
    for s in seen.iter().filter(|s| s.status == 200) {
        assert!(line_count(&s.body) <= 2);
    }
    assert_eq!(r.acked().len(), 5);

    let r = Rig::new("413-one", Role::Uplink);
    r.spool(UNIT, 0, 1, false);
    r.c()
        .script
        .push_back(Script::Status(413, None, String::new()));
    match r.uplink(r.spool_cfg()).run_once() {
        Err(UplinkError::Refused { status: 413, .. }) => {}
        other => panic!("{other:?}"),
    }
    assert_eq!(r.ready().len(), 1);
}

/// Crash after the pending batch was saved: the restart sends the same
/// batch id for the same records.
#[test]
fn crash_before_send_resends_same_batch_id() {
    let r = Rig::new("crash-pending", Role::Uplink);
    r.spool(UNIT, 0, 3, false);
    let mut cfg = r.spool_cfg();
    cfg.fail_point = Some(FailPoint::AfterPendingSaved);
    let mut u = r.uplink(cfg);
    assert!(matches!(u.run_once(), Err(UplinkError::Injected)));
    let id = u.state().pending.clone().unwrap().batch_id;
    assert!(r.requests().is_empty());
    // New records arrive meanwhile: the pending batch keeps its cut.
    r.spool(UNIT, 3, 2, false);
    let rep = r.uplink(r.spool_cfg()).run_once().unwrap();
    assert_eq!(rep.resumed, 1);
    let seen = r.requests();
    assert_eq!(hdr(&seen[0], wire::H_BATCH_ID), id);
    assert_eq!(line_count(&seen[0].body), 3);
    assert_eq!(r.acked().len(), 5);
    assert_eq!(r.c().finding_count(), 5);
}

/// Crash after the server processed the batch but before the result was
/// saved: the restart re-sends the same batch; the server answers with its
/// stored response (`replayed`) and nothing is processed twice.
#[test]
fn crash_after_response_is_replayed_not_reprocessed() {
    let r = Rig::new("crash-response", Role::Uplink);
    r.spool(UNIT, 0, 2, false);
    r.spool(OTHER_ROBOT, 0, 1, false);
    let mut cfg = r.spool_cfg();
    cfg.fail_point = Some(FailPoint::AfterResponse);
    assert!(matches!(
        r.uplink(cfg).run_once(),
        Err(UplinkError::Injected)
    ));
    assert_eq!(r.ready().len(), 3, "nothing acknowledged yet");
    let rep = r.uplink(r.spool_cfg()).run_once().unwrap();
    assert_eq!((rep.replayed, rep.created, rep.rejected), (1, 2, 1));
    let seen = r.requests();
    assert_eq!(seen.len(), 2);
    assert_eq!(
        hdr(&seen[0], wire::H_BATCH_ID),
        hdr(&seen[1], wire::H_BATCH_ID)
    );
    assert_eq!(r.c().event_count(), 2);
    assert_eq!(r.acked().len(), 2);
    assert_eq!(r.rejected().len(), 1);
    assert_eq!(r.dead_letters().len(), 1);
}

/// Crash after the result was saved, and after the first rename: the
/// restart finishes without a request and without duplicate dead letters.
#[test]
fn crash_while_acknowledging_finishes_without_resending() {
    for fp in [FailPoint::AfterResultSaved, FailPoint::AfterFirstAck] {
        let r = Rig::new("crash-ack", Role::Uplink);
        r.spool(OTHER_ROBOT, 0, 1, false); // rejected: first in the batch
        r.spool(UNIT, 0, 3, false);
        let mut cfg = r.spool_cfg();
        cfg.fail_point = Some(fp);
        assert!(matches!(
            r.uplink(cfg).run_once(),
            Err(UplinkError::Injected)
        ));
        let dl_before = r.dead_letters().len();
        let rep = r.uplink(r.spool_cfg()).run_once().unwrap();
        assert_eq!(rep.resumed, 1, "{fp:?}");
        assert_eq!(r.requests().len(), 1, "{fp:?}: no second request");
        assert!(r.ready().is_empty());
        assert_eq!(r.acked().len(), 3);
        assert_eq!(r.rejected().len(), 1);
        assert_eq!(
            r.dead_letters().len(),
            1,
            "{fp:?}: deduplicated ({dl_before})"
        );
    }
}

/// A pending batch whose input changed is dropped; the records are cut
/// again under a new id and the server reports repeats as duplicates.
#[test]
fn changed_input_drops_the_pending_batch() {
    let r = Rig::new("crash-changed", Role::Uplink);
    r.spool(UNIT, 0, 3, false);
    let mut cfg = r.spool_cfg();
    cfg.fail_point = Some(FailPoint::AfterPendingSaved);
    let mut u = r.uplink(cfg);
    assert!(matches!(u.run_once(), Err(UplinkError::Injected)));
    let id = u.state().pending.clone().unwrap().batch_id;
    let first = r.ready()[0].clone();
    fs::rename(
        r.spool.join("ready").join(&first),
        r.spool.join("acked").join(&first),
    )
    .unwrap();
    let rep = r.uplink(r.spool_cfg()).run_once().unwrap();
    assert_eq!(rep.pending_dropped, 1);
    let seen = r.requests();
    assert_eq!(seen.len(), 1);
    assert_ne!(hdr(&seen[0], wire::H_BATCH_ID), id);
    assert_eq!(rep.created, 2);
}

#[test]
fn state_belongs_to_one_source_kind() {
    let r = Rig::new("kind", Role::Uplink);
    r.spool(UNIT, 0, 1, false);
    let mut cfg = r.spool_cfg();
    cfg.fail_point = Some(FailPoint::AfterPendingSaved);
    assert!(r.uplink(cfg).run_once().is_err());
    let t = MockTransport {
        consumer: r.consumer.clone(),
        fail_next: 0,
    };
    assert!(matches!(
        Uplink::open(r.cfg(Source::DiodeOut(r.out.clone())), t, sender()),
        Err(UplinkError::State(_))
    ));
}

/// Write `out/<name>/records.jsonl` the way the diode importer does.
fn diode_batch(out: &Path, name: &str, robot: &str, from: u64, n: u64, garbage_at: Option<u64>) {
    let d = out.join(name);
    fs::create_dir_all(&d).unwrap();
    let mut s = String::new();
    for i in from..from + n {
        if garbage_at == Some(i) {
            s.push_str("{\"garbage\":true}\n");
            continue;
        }
        let rec = robodr_ocsf::record(&finding_for(robot, i), Some(12)).unwrap();
        let line = serde_json::json!({
            "topic": rec.topic, "partition": rec.partition, "key": rec.key,
            "headers": rec.headers, "value": rec.value,
            "diode": {"unit_id": robot, "batch_seq": 1, "batch_hash": "00", "line": i - from + 1},
        });
        s.push_str(&serde_json::to_string(&line).unwrap());
        s.push('\n');
    }
    fs::write(d.join("records.jsonl"), s).unwrap();
}

#[test]
fn diode_output_relay_with_offsets_and_done_markers() {
    let r = Rig::new("diode", Role::Relay);
    diode_batch(&r.out, "rdd_ugv-007_0000000000000001", UNIT, 0, 5, Some(2));
    diode_batch(
        &r.out,
        "rdd_ugv-008_0000000000000001",
        OTHER_ROBOT,
        0,
        3,
        None,
    );
    fs::create_dir_all(r.out.join(".staging-x")).unwrap();
    let mut cfg = r.cfg(Source::DiodeOut(r.out.clone()));
    cfg.max_lines = 2;
    let mut u = r.uplink(cfg.clone());
    let rep = u.run_once().unwrap();
    assert_eq!(rep.created, 7);
    assert_eq!(rep.dead_lettered_local, 1);
    assert_eq!(rep.batches_done.len(), 2);
    // Diode lines carry no per-finding signature.
    for s in r.requests() {
        for l in ingest::split_lines(&s.body) {
            let v: serde_json::Value = serde_json::from_slice(l).unwrap();
            assert!(v["sig"].is_null());
        }
    }
    let dl = r.dead_letters();
    assert_eq!(dl.len(), 1);
    assert_eq!(dl[0]["source"], "rdd_ugv-007_0000000000000001");
    assert_eq!(dl[0]["position"], 3);
    assert!(r.state.join("done/rdd_ugv-007_0000000000000001").exists());
    assert!(u.state().in_flight.is_empty());
    let n = r.requests().len();
    assert!(u.run_once().unwrap().is_empty());
    assert_eq!(r.requests().len(), n);

    // A new batch, crash after the result was saved: resumes at the offset.
    diode_batch(&r.out, "rdd_ugv-007_0000000000000002", UNIT, 10, 4, None);
    let mut c2 = cfg.clone();
    c2.fail_point = Some(FailPoint::AfterResultSaved);
    assert!(matches!(
        r.uplink(c2).run_once(),
        Err(UplinkError::Injected)
    ));
    let rep = r.uplink(cfg.clone()).run_once().unwrap();
    assert_eq!(rep.resumed, 1);
    assert_eq!(
        rep.created, 2,
        "only the second half is sent after the resume"
    );
    assert_eq!(r.c().finding_count(), 11);
}

#[test]
fn diode_crash_before_send_resends_same_batch_id() {
    let r = Rig::new("diode-crash", Role::Relay);
    diode_batch(&r.out, "rdd_ugv-007_0000000000000001", UNIT, 0, 3, Some(0));
    let mut cfg = r.cfg(Source::DiodeOut(r.out.clone()));
    cfg.fail_point = Some(FailPoint::AfterPendingSaved);
    let mut u = r.uplink(cfg);
    assert!(u.run_once().is_err());
    let p = u.state().pending.clone().unwrap();
    assert_eq!(p.positions, [2, 3]);
    assert_eq!(p.last, 3);
    let rep = r
        .uplink(r.cfg(Source::DiodeOut(r.out.clone())))
        .run_once()
        .unwrap();
    assert_eq!(rep.created, 2);
    assert_eq!(hdr(&r.requests()[0], wire::H_BATCH_ID), p.batch_id);
    assert_eq!(r.dead_letters().len(), 1, "local dead letter not repeated");
}

#[test]
fn sender_key_file_loading() {
    let tmp = TempDir::new("keyfile");
    let p = tmp.path().join("uplink.key");
    robodr_blackbox::KeyFile::ed25519_from_seed(&SENDER_SEED, None)
        .unwrap()
        .write_new(&p)
        .unwrap();
    let k = robodr_export::uplink::load_sender_key(&p).unwrap();
    assert_eq!(k.key_id(), sender().key_id());
    // A chosen key id, a public key file, an HMAC key: refused.
    let named = tmp.path().join("named.key");
    robodr_blackbox::KeyFile::ed25519_from_seed(&SENDER_SEED, Some("uplink-1"))
        .unwrap()
        .write_new(&named)
        .unwrap();
    assert!(robodr_export::uplink::load_sender_key(&named).is_err());
    let publ = tmp.path().join("pub.key");
    robodr_blackbox::KeyFile::ed25519_from_seed(&SENDER_SEED, None)
        .unwrap()
        .to_public()
        .unwrap()
        .write_new(&publ)
        .unwrap();
    assert!(robodr_export::uplink::load_sender_key(&publ).is_err());
    let hmac = tmp.path().join("hmac.key");
    robodr_blackbox::KeyFile::generate_hmac(None)
        .unwrap()
        .write_new(&hmac)
        .unwrap();
    assert!(robodr_export::uplink::load_sender_key(&hmac).is_err());
}
