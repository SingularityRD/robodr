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
            s.write(&Self::output(rec), robodr_agentd::SpoolClass::Normal)
                .unwrap();
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

/// Review finding: an I/O error (EACCES, EIO) reading one spool file failed
/// every run forever. Now it is quarantined after a bounded number of
/// attempts (local dead letter with the error, moved to rejected/) and the
/// rest is sent.
#[test]
fn unreadable_spool_file_is_quarantined_not_fatal() {
    let r = Rig::new("eio", Role::Uplink);
    r.spool(UNIT, 0, 3, false);
    let bad = r.ready()[1].clone();
    let mut u = r.uplink(r.spool_cfg());
    robodr_export::inject_read_errors(&bad, u32::MAX);
    let rep = u.run_once();
    robodr_export::inject_read_errors(&bad, 0);
    let rep = rep.unwrap();
    assert_eq!(
        (rep.accepted, rep.quarantined_unreadable),
        (2, 1),
        "{rep:?}"
    );
    assert_eq!(rep.dead_lettered_local, 1);
    assert!(r.ready().is_empty());
    assert_eq!(r.rejected(), vec![bad]);
    let dl = r.dead_letters();
    assert_eq!(dl.len(), 1);
    assert!(
        dl[0]["reason"]
            .as_str()
            .unwrap()
            .starts_with("unreadable (I/O error"),
        "{dl:?}"
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
    drop(u); // releases the state directory's lock
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
        drop(u);
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
    drop(u);
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
    drop(u);
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
    drop(u);

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
    drop(u);
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

/// A dead-letter file whose last line was torn by a crash: the fragment is
/// counted (report + log), the next entry is appended as a line of its own
/// and is found again when the file is reloaded (it used to be merged into
/// the fragment and silently skipped by the loader, so dedup lost it).
#[test]
fn torn_dead_letter_line_is_counted_and_does_not_hide_the_next_entry() {
    let r = Rig::new("torn-dl", Role::Uplink);
    fs::create_dir_all(&r.state).unwrap();
    fs::write(
        r.state.join("dead-letter.jsonl"),
        b"{\"source\":\"x\",\"position\":1}\n{\"source\":\"x\",\"pos",
    )
    .unwrap();
    r.spool(OTHER_ROBOT, 0, 1, false); // rejected: robot_mismatch
    let mut cfg = r.spool_cfg();
    cfg.fail_point = Some(FailPoint::AfterResultSaved);
    assert!(matches!(
        r.uplink(cfg).run_once(),
        Err(UplinkError::Injected)
    ));
    let rep = r.uplink(r.spool_cfg()).run_once().unwrap();
    assert_eq!(rep.resumed, 1);
    assert_eq!(rep.dead_letter_malformed, 1, "{rep:?}");
    let text = fs::read_to_string(r.state.join("dead-letter.jsonl")).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3, "{text}");
    assert_eq!(lines[1], "{\"source\":\"x\",\"pos");
    let dl: serde_json::Value = serde_json::from_str(lines[2]).unwrap();
    assert_eq!(dl["code"], "robot_mismatch");
    let mut reload =
        robodr_export::deadletter::DeadLetters::new(&r.state, "dead-letter.jsonl", None);
    let st = reload.stats().unwrap();
    assert_eq!((st.entries, st.malformed), (2, 1));
    assert!(reload
        .contains(
            dl["source"].as_str().unwrap(),
            dl["position"].as_u64().unwrap()
        )
        .unwrap());
}

// ---------------------------------------------------------------------------
// Review F1: Retry-After after the last attempt; F2: status, backoff, stuck;
// F8: state-directory lock, dead-letter rotation; re-injection.
// ---------------------------------------------------------------------------

use robodr_export::uplink::reinject::{self, ReinjectOptions};
use robodr_export::uplink::service::{self, Env, ServiceConfig, Status};

fn status_of(r: &Rig) -> Status {
    serde_json::from_slice(&fs::read(r.state.join(service::STATUS_FILE)).unwrap()).unwrap()
}

/// What a service run did (recorded by the test `Env`).
#[derive(Default)]
struct Recorded {
    sleeps: Vec<Duration>,
    notes: Vec<String>,
    logs: Vec<String>,
}

/// Run the service loop for `runs` iterations (then `stop`), the wall clock
/// advancing `step_ms` per reading.
fn run_service(r: &Rig, cfg: &ServiceConfig, runs: usize, step_ms: u64) -> (u8, Recorded) {
    run_service_with(r, cfg, runs, step_ms, Box::new(|_| Vec::new()))
}

/// [`run_service`] with the credentials the binary reads from its CRLs.
fn run_service_with(
    r: &Rig,
    cfg: &ServiceConfig,
    runs: usize,
    step_ms: u64,
    credentials: Box<dyn FnMut(u64) -> Vec<robodr_ocsf::CredentialExpiry>>,
) -> (u8, Recorded) {
    let rec = Arc::new(Mutex::new(Recorded::default()));
    let clock = Arc::new(AtomicU64::new(NOW));
    let mut left = runs;
    let (r1, r2, r3) = (rec.clone(), rec.clone(), rec.clone());
    let c = clock.clone();
    let mut env = Env {
        now_ms: Box::new(move || c.fetch_add(step_ms, Ordering::SeqCst)),
        sleep: Box::new(move |d| r1.lock().unwrap().sleeps.push(d)),
        rng: Box::new(|| 0),
        notify: Box::new(move |m| r2.lock().unwrap().notes.push(m.to_string())),
        log: Box::new(move |m| r3.lock().unwrap().logs.push(m.to_string())),
        report: Box::new(|_| {}),
        stop: Box::new(move || {
            left -= 1;
            left == 0
        }),
        credentials,
    };
    let code = service::run(cfg, &r.state, || Ok(r.uplink(r.spool_cfg())), &mut env);
    drop(env);
    let rec = Arc::try_unwrap(rec).ok().unwrap().into_inner().unwrap();
    (code, rec)
}

fn svc() -> ServiceConfig {
    ServiceConfig {
        interval: Duration::from_secs(2),
        transient_backoff_max: Duration::from_secs(60),
        refused_backoff_max: Duration::from_secs(900),
        exit_when_stuck_after: None,
        once: false,
    }
}

/// F1: a `429` with `Retry-After` on the run's last attempt: the error
/// carries it and the service waits at least that long before the next run
/// (it used to wait only its own backoff, ≤ 60 s). Over 24 h: 24 h.
#[test]
fn retry_after_on_the_last_attempt_is_honoured_by_the_service() {
    for (ra, want) in [("3600", 3600u64), ("999999999999", 24 * 3600)] {
        let r = Rig::new("ra-last", Role::Uplink);
        r.spool(UNIT, 0, 1, false);
        for _ in 0..5 {
            r.c().script.push_back(Script::Status(
                429,
                Some(ra.into()),
                "{\"code\":\"rate_limited\"}".into(),
            ));
        }
        match r.uplink(r.spool_cfg()).run_once() {
            Err(e @ UplinkError::GaveUp { .. }) => {
                assert_eq!(e.retry_after(), Some(Duration::from_secs(want)), "{ra}");
                assert!(e.is_transient());
            }
            other => panic!("{other:?}"),
        }
        // Within the run the retries waited Retry-After too.
        assert!(r
            .sleeps
            .lock()
            .unwrap()
            .iter()
            .all(|d| *d == Duration::from_secs(want)));
        for _ in 0..5 {
            r.c().script.push_back(Script::Status(
                429,
                Some(ra.into()),
                "{\"code\":\"rate_limited\"}".into(),
            ));
        }
        let (code, rec) = run_service(&r, &svc(), 1, 1000);
        assert_eq!(code, 0);
        assert_eq!(rec.sleeps, [Duration::from_secs(want)], "{ra}");
        let st = status_of(&r);
        assert_eq!(st.state, "retrying");
        assert_eq!(st.last_error.unwrap().retry_after_s, Some(want));
    }
}

/// Sales-readiness T6: the status file carries each CRL's `nextUpdate`
/// with the days left, and a CRL within 14 days is logged once per day
/// count, not every run.
#[test]
fn status_reports_crl_expiry_and_warns_once_a_day() {
    use robodr_blackbox::crl::{CrlInUse, CrlStatus};
    let day_ms = 86_400_000u64;
    // Valid for 3.5 more days at NOW; one day passes per run.
    let next_update_s = i64::try_from((NOW + 3 * day_ms + day_ms / 2) / 1000).unwrap();
    let crls = CrlStatus {
        in_use: vec![
            CrlInUse {
                issuer: "Site CA".into(),
                next_update: Some(next_update_s),
                ..CrlInUse::default()
            },
            CrlInUse {
                issuer: "No next update".into(),
                ..CrlInUse::default()
            },
        ],
        ..CrlStatus::default()
    };
    assert_eq!(service::crl_credentials(&crls, NOW).len(), 1);
    let r = Rig::new("crl-expiry", Role::Uplink);
    let (code, rec) = run_service_with(
        &r,
        &svc(),
        6,
        day_ms / 4,
        Box::new(move |now| service::crl_credentials(&crls, now)),
    );
    assert_eq!(code, 0);
    let st = status_of(&r);
    let c = st
        .credentials
        .first()
        .expect("credential in the status file");
    assert_eq!(c.name, "crl:Site CA");
    assert_eq!(c.expires_ms, u64::try_from(next_update_s).unwrap() * 1000);
    assert!(c.days_to_expiry <= 3, "{c:?}");
    let warns: Vec<_> = rec
        .logs
        .iter()
        .filter(|l| l.contains("crl:Site CA"))
        .collect();
    // Six runs over a day and a half: day counts 3 and 2 (maybe 1).
    assert!((2..=3).contains(&warns.len()), "{warns:?}");
    assert!(warns[0].contains("expires in 3 day(s)"), "{warns:?}");
    // A credential far from expiry is in the file but never logged.
    let r = Rig::new("crl-far", Role::Uplink);
    let far = CrlStatus {
        in_use: vec![CrlInUse {
            issuer: "Far CA".into(),
            next_update: Some(4_891_363_200),
            ..CrlInUse::default()
        }],
        ..CrlStatus::default()
    };
    let (_, rec) = run_service_with(
        &r,
        &svc(),
        2,
        1000,
        Box::new(move |now| service::crl_credentials(&far, now)),
    );
    assert_eq!(status_of(&r).credentials.len(), 1);
    assert!(!rec.logs.iter().any(|l| l.contains("Far CA")));
}

/// F2: refusals back off to the long cap; transient failures to the short
/// one; never below the poll interval.
#[test]
fn failure_backoff_classes() {
    let cfg = svc();
    let refused = UplinkError::Refused {
        status: 401,
        code: "unknown_key".into(),
        detail: String::new(),
    };
    let transient = UplinkError::GaveUp {
        attempts: 6,
        last: "HTTP 503".into(),
        retry_after: None,
    };
    for f in 1..40u32 {
        for rand in [0u64, u64::MAX, 12345] {
            let d = service::failure_delay(&cfg, f, &refused, rand);
            assert!(
                d >= Duration::from_secs(1) && d <= Duration::from_secs(900),
                "{f} {d:?}"
            );
            let t = service::failure_delay(&cfg, f, &transient, rand);
            assert!(t <= Duration::from_secs(60), "{f} {t:?}");
        }
    }
    // After ~10 refusals in a row the wait is at least half the cap.
    assert!(service::failure_delay(&cfg, 12, &refused, 0) >= Duration::from_secs(450));
    // At the cap, even the shortest jittered wait (half the cap) means at
    // most 192 refused requests a day (it was ~1440 at a 60 s cap).
    let shortest = service::failure_delay(&cfg, 30, &refused, 0);
    assert_eq!(shortest, Duration::from_secs(450));
    assert!(86_400 / shortest.as_secs() <= 192);
}

/// F2: a batch the server keeps refusing is visible: status file (state,
/// error, stuck_since, pending batch, failed runs, backlog), `STATUS=` and
/// a log line per run; the backoff grows; the streak survives a restart;
/// a later success clears it.
#[test]
fn a_refused_batch_is_visible_in_the_status_file_and_sd_notify() {
    let r = Rig::new("status", Role::Uplink);
    r.spool(UNIT, 0, 2, false);
    for _ in 0..3 {
        r.c().script.push_back(Script::Status(
            401,
            None,
            "{\"code\":\"unknown_key\",\"detail\":\"not registered\"}".into(),
        ));
    }
    let (code, rec) = run_service(&r, &svc(), 3, 1000);
    assert_eq!(code, 0);
    let st = status_of(&r);
    assert_eq!(st.format, service::STATUS_FORMAT);
    assert_eq!(st.state, "blocked");
    let e = st.last_error.clone().unwrap();
    assert_eq!(
        (e.kind.as_str(), e.status, e.code.as_deref()),
        ("refused", Some(401), Some("unknown_key"))
    );
    assert_eq!(st.consecutive_failures, 3);
    assert_eq!(st.pending_failed_runs, 3);
    let since = st.stuck_since_ms.unwrap();
    assert!((NOW..NOW + 10_000).contains(&since), "{since}");
    assert_eq!(st.snapshot.pending_lines, 2);
    assert!(st
        .snapshot
        .pending_batch_id
        .as_deref()
        .unwrap()
        .starts_with("rdu1-"));
    assert_eq!(st.snapshot.backlog.spool_ready, Some(2));
    assert!(st.last_success_at_ms.is_none());
    assert!(st.next_attempt_at_ms.is_some());
    assert_eq!(rec.sleeps.len(), 3);
    assert!(
        rec.sleeps.windows(2).all(|w| w[1] >= w[0]),
        "{:?}",
        rec.sleeps
    );
    assert_eq!(rec.notes.len(), 3);
    assert!(
        rec.notes[2].starts_with("STATUS=blocked"),
        "{}",
        rec.notes[2]
    );
    assert!(
        rec.notes[2].contains("HTTP 401 unknown_key"),
        "{}",
        rec.notes[2]
    );
    assert!(rec.logs.iter().any(|l| l.contains("401")));
    // Restart, still refused: the streak start and failed-run count carry
    // over (same pending batch).
    r.c().script.push_back(Script::Status(
        401,
        None,
        "{\"code\":\"unknown_key\"}".into(),
    ));
    let (_, _) = run_service(&r, &svc(), 1, 1000);
    let st2 = status_of(&r);
    assert_eq!(st2.stuck_since_ms, Some(since));
    assert_eq!(st2.pending_failed_runs, 4);
    // Fixed: delivered, streak cleared.
    let (_, rec) = run_service(&r, &svc(), 1, 1000);
    let st3 = status_of(&r);
    assert_eq!(st3.state, "ok");
    assert!(st3.stuck_since_ms.is_none() && st3.last_delivery_at_ms.is_some());
    assert_eq!(st3.snapshot.pending_batch_id, None);
    assert_eq!(st3.snapshot.backlog.spool_ready, Some(0));
    assert_eq!(st3.snapshot.accepted_total, 2);
    assert_eq!(rec.sleeps, [Duration::from_secs(2)], "poll interval");
    assert!(rec.notes[0].starts_with("STATUS=ok"));
}

/// F2: optional exit once failures lasted the configured time.
#[test]
fn exit_when_stuck() {
    let r = Rig::new("stuck-exit", Role::Uplink);
    r.spool(UNIT, 0, 1, false);
    for _ in 0..10 {
        r.c().script.push_back(Script::Status(
            400,
            None,
            "{\"code\":\"bad_header\"}".into(),
        ));
    }
    let mut cfg = svc();
    cfg.exit_when_stuck_after = Some(Duration::from_secs(60));
    // 30 s per clock reading: the third failure is 60 s into the streak.
    let (code, rec) = run_service(&r, &cfg, 100, 30_000);
    assert_eq!(code, service::EXIT_STUCK);
    assert!(rec.logs.iter().any(|l| l.contains("exiting with status 3")));
    assert_eq!(r.ready().len(), 1, "nothing acknowledged");
    // --once: one run, exit 1 on failure, status written.
    let mut once = svc();
    once.once = true;
    let (code, rec) = run_service(&r, &once, 100, 1000);
    assert_eq!(code, 1);
    assert!(rec.sleeps.is_empty());
    assert_eq!(status_of(&r).state, "blocked");
}

/// F8: one process per state directory.
#[test]
fn state_directory_is_locked() {
    let r = Rig::new("lock", Role::Uplink);
    let u = r.uplink(r.spool_cfg());
    let t = MockTransport {
        consumer: r.consumer.clone(),
        fail_next: 0,
    };
    match Uplink::open(r.spool_cfg(), t, sender()) {
        Err(e @ UplinkError::Locked(_)) => {
            assert!(
                e.to_string().contains("held by another robodr-uplink"),
                "{e}"
            );
        }
        other => panic!("{:?}", other.err()),
    }
    let o = reinject_opts(&r, Source::Spool(r.spool.clone()));
    assert!(matches!(
        reinject::reinject(&o),
        Err(UplinkError::Locked(_))
    ));
    // A lock of another directory is refused by open_locked.
    let other = Rig::new("lock-other", Role::Uplink);
    let l = Arc::new(robodr_export::uplink::StateLock::acquire(&other.state).unwrap());
    let t = MockTransport {
        consumer: r.consumer.clone(),
        fail_next: 0,
    };
    drop(u);
    assert!(matches!(
        Uplink::open_locked(r.spool_cfg(), t, sender(), l),
        Err(UplinkError::Config(_))
    ));
    // Released on drop.
    drop(r.uplink(r.spool_cfg()));
    let _again = r.uplink(r.spool_cfg());
}

/// F8: the uplink's dead-letter file rotates (keep N); deduplication and
/// re-injection read the rotated files too.
#[test]
fn dead_letters_rotate() {
    let r = Rig::new("dl-rotate", Role::Relay);
    r.c().reg.robots.remove(OTHER_ROBOT);
    r.spool(OTHER_ROBOT, 0, 120, false); // all unknown_robot
    let mut cfg = r.spool_cfg();
    let rot = robodr_export::deadletter::Rotation {
        max_bytes: robodr_export::uplink::MIN_DEAD_LETTER_BYTES,
        keep: 2,
    };
    cfg.dead_letter_rotation = Some(rot);
    let rep = r.uplink(cfg.clone()).run_once().unwrap();
    assert_eq!(rep.rejected, 120);
    // Files past `keep` were deleted after the run: their records left
    // ready/ (moved to rejected/), so no entry is needed any more.
    assert!(rep.pruned_dead_letters.removed >= 1, "{rep:?}");
    assert_eq!(rep.pruned_dead_letters.held, 0);
    let files = robodr_export::deadletter::files(&r.state, "dead-letter.jsonl").unwrap();
    let names: Vec<String> = files
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        names,
        [
            "dead-letter.jsonl.2",
            "dead-letter.jsonl.1",
            "dead-letter.jsonl"
        ]
    );
    for f in &files {
        assert!(fs::metadata(f).unwrap().len() <= rot.max_bytes);
    }
    let mut dl = robodr_export::deadletter::DeadLetters::new(&r.state, "dead-letter.jsonl", None);
    let st = dl.stats().unwrap();
    assert!(st.entries >= 3 && st.entries < 120, "{st:?}");
    assert_eq!(st.malformed, 0);
    // Re-injection over every kept file: the rotated-out entries are gone.
    r.c().reg.robots.insert(OTHER_ROBOT.into(), false);
    let mut o = reinject_opts(&r, Source::Spool(r.spool.clone()));
    o.dead_letters = files;
    let a = reinject::reinject(&o).unwrap();
    assert_eq!(a.queued, st.entries);
    // Invalid rotation settings are refused.
    for bad in [
        robodr_export::deadletter::Rotation {
            max_bytes: 10,
            keep: 1,
        },
        robodr_export::deadletter::Rotation {
            max_bytes: 1 << 20,
            keep: 0,
        },
    ] {
        let mut c = cfg.clone();
        c.dead_letter_rotation = Some(bad);
        let t = MockTransport {
            consumer: r.consumer.clone(),
            fail_next: 0,
        };
        assert!(matches!(
            Uplink::open(c, t, sender()),
            Err(UplinkError::Config(_))
        ));
    }
}

fn reinject_opts(r: &Rig, source: Source) -> ReinjectOptions {
    ReinjectOptions {
        state_dir: r.state.clone(),
        source,
        dead_letters: vec![r.state.join("dead-letter.jsonl")],
        codes: reinject::DEFAULT_CODES
            .iter()
            .map(|c| c.to_string())
            .collect(),
        max_record_bytes: 1024 * 1024,
        dry_run: false,
        now_ms: NOW,
    }
}

/// Re-injection (spool): rejected records are re-queued from `rejected/`,
/// sent under new batch ids, rejected again until the registration is
/// fixed, then accepted; every step is idempotent.
#[test]
fn reinject_spool_records_after_the_registration_is_fixed() {
    let r = Rig::new("reinject-spool", Role::Relay);
    r.c().reg.robots.remove(OTHER_ROBOT);
    r.spool(UNIT, 0, 2, false);
    r.spool(OTHER_ROBOT, 0, 2, false); // unknown_robot
    r.spool_garbage(); // local: not re-injected by default
    let rep = r.uplink(r.spool_cfg()).run_once().unwrap();
    assert_eq!(
        (rep.created, rep.rejected, rep.dead_lettered_local),
        (2, 2, 1)
    );
    let first_ids: Vec<String> = r
        .requests()
        .iter()
        .map(|s| hdr(s, wire::H_BATCH_ID).to_string())
        .collect();

    // Dry run: nothing written.
    let mut o = reinject_opts(&r, Source::Spool(r.spool.clone()));
    o.dry_run = true;
    let dry = reinject::reinject(&o).unwrap();
    assert_eq!((dry.queued, dry.other_code, dry.generation), (2, 1, None));
    assert!(!r.state.join("reinject").exists());

    // Not fixed yet: re-sent under a new batch id, rejected again.
    o.dry_run = false;
    let a = reinject::reinject(&o).unwrap();
    assert_eq!((a.queued, a.from_input, a.from_dead_letter), (2, 2, 0));
    let gen_a = a.generation.clone().unwrap();
    assert!(reinject::is_valid_generation(&gen_a));
    let again = reinject::reinject(&o).unwrap();
    assert_eq!(
        (again.queued, again.already_queued, again.generation),
        (0, 2, None),
        "idempotent"
    );
    let rep = r.uplink(r.spool_cfg()).run_once().unwrap();
    assert_eq!((rep.created, rep.rejected), (0, 2));
    assert_eq!(rep.reinjected_done, std::slice::from_ref(&gen_a));
    let id = hdr(r.requests().last().unwrap(), wire::H_BATCH_ID).to_string();
    assert!(!first_ids.contains(&id), "new batch id");
    let dl = r.dead_letters();
    let again_dl: Vec<&serde_json::Value> = dl
        .iter()
        .filter(|d| d["source"] == format!("reinject:{gen_a}"))
        .collect();
    assert_eq!(again_dl.len(), 2);
    assert_eq!(again_dl[0]["code"], "unknown_robot");
    assert!(r.state.join("reinject").join(&gen_a).join("done").exists());
    assert!(u_is_idle(&r));

    // Fixed: the second-round dead letters are re-injected (from the first
    // generation's lines) and accepted; the originals stay queued once.
    r.c().reg.robots.insert(OTHER_ROBOT.into(), false);
    let b = reinject::reinject(&o).unwrap();
    assert_eq!((b.queued, b.from_input, b.already_queued), (2, 2, 2));
    let rep = r.uplink(r.spool_cfg()).run_once().unwrap();
    assert_eq!((rep.created, rep.rejected), (2, 0));
    assert_eq!(r.c().finding_count(), 4);
    let ids: std::collections::BTreeSet<String> = r
        .requests()
        .iter()
        .map(|s| hdr(s, wire::H_BATCH_ID).to_string())
        .collect();
    assert_eq!(ids.len(), r.requests().len(), "every batch id is new");
    let none = reinject::reinject(&o).unwrap();
    assert_eq!((none.queued, none.already_queued), (0, 4));
    assert!(u_is_idle(&r));
    // The original spool files stay where they were.
    assert_eq!(r.rejected().len(), 3);
}

/// Nothing left to send: a run makes no request.
fn u_is_idle(r: &Rig) -> bool {
    let n = r.requests().len();
    let rep = r.uplink(r.spool_cfg()).run_once().unwrap();
    rep.is_empty() && r.requests().len() == n
}

/// Re-injection (diode): lines re-read from `records.jsonl`, or from the
/// dead letter's copy when the batch directory is gone; a crash after the
/// pending batch was saved re-sends the same (new) batch id.
#[test]
fn reinject_diode_records_and_resume_after_a_crash() {
    let r = Rig::new("reinject-diode", Role::Relay);
    r.c().reg.robots.remove(OTHER_ROBOT);
    diode_batch(
        &r.out,
        "rdd_ugv-008_0000000000000001",
        OTHER_ROBOT,
        0,
        2,
        None,
    );
    diode_batch(
        &r.out,
        "rdd_ugv-008_0000000000000002",
        OTHER_ROBOT,
        5,
        1,
        None,
    );
    let cfg = r.cfg(Source::DiodeOut(r.out.clone()));
    let rep = r.uplink(cfg.clone()).run_once().unwrap();
    assert_eq!(rep.rejected, 3);
    fs::remove_dir_all(r.out.join("rdd_ugv-008_0000000000000002")).unwrap();
    r.c().reg.robots.insert(OTHER_ROBOT.into(), false);
    let o = reinject_opts(&r, Source::DiodeOut(r.out.clone()));
    let a = reinject::reinject(&o).unwrap();
    assert_eq!((a.queued, a.from_input, a.from_dead_letter), (3, 2, 1));
    let mut crash = cfg.clone();
    crash.fail_point = Some(FailPoint::AfterPendingSaved);
    let mut u = r.uplink(crash);
    assert!(matches!(u.run_once(), Err(UplinkError::Injected)));
    let p = u.state().pending.clone().unwrap();
    drop(u);
    assert!(p.source.starts_with("reinject:rj-"), "{}", p.source);
    let n = r.requests().len();
    let rep = r.uplink(cfg.clone()).run_once().unwrap();
    assert_eq!((rep.resumed, rep.created), (1, 3));
    assert_eq!(hdr(&r.requests()[n], wire::H_BATCH_ID), p.batch_id);
    assert_eq!(r.c().finding_count(), 3);
    assert!(r.uplink(cfg).state().reinject.is_empty());
}

/// T83: the uplink's remaining state is bounded on request and measured.
/// By default `rejected/` and the re-injection generations are kept; with
/// bounds, the rejected records and the finished generation's
/// `records.jsonl` go, the generation's ledger (`origin.jsonl`, `done`)
/// stays, so re-injecting the same dead letters again queues nothing, and
/// a record rejected again after its generation was pruned is re-injected
/// from its dead letter's copy. The status snapshot carries the sizes.
#[test]
fn rejected_and_reinject_payloads_are_pruned_on_request_and_measured() {
    use robodr_export::retention::Retention;
    let r = Rig::new("t83-spool", Role::Relay);
    r.c().reg.robots.remove(OTHER_ROBOT);
    r.spool(UNIT, 0, 2, false);
    r.spool(OTHER_ROBOT, 0, 2, false); // unknown_robot
    r.spool_garbage();
    let mut u = r.uplink(r.spool_cfg());
    u.run_once().unwrap();
    let snap = u.snapshot().unwrap();
    let usage = snap.state_usage.clone().expect("measured");
    assert_eq!(usage.spool_rejected.map(|x| x.entries), Some(3));
    assert!(usage.spool_rejected.unwrap().bytes > 0);
    assert_eq!(usage.diode_out, None);
    assert_eq!(usage.dead_letters.entries, 1, "one dead-letter file");
    assert!(usage.dead_letters.bytes > 0);
    drop(u);
    let o = reinject_opts(&r, Source::Spool(r.spool.clone()));
    let gen = reinject::reinject(&o).unwrap().generation.unwrap();
    let rep = r.uplink(r.spool_cfg()).run_once().unwrap();
    assert_eq!(rep.reinjected_done, std::slice::from_ref(&gen));
    let gdir = r.state.join("reinject").join(&gen);
    // Default: kept.
    let rep = r.uplink(r.spool_cfg()).run_once().unwrap();
    assert_eq!(rep.pruned_rejected, Default::default());
    assert_eq!(rep.pruned_reinject, Default::default());
    assert_eq!(r.rejected().len(), 3);
    assert!(gdir.join("records.jsonl").exists());

    let mut cfg = r.spool_cfg();
    let none = Retention {
        max_count: Some(0),
        ..Default::default()
    };
    cfg.rejected_retention = none;
    cfg.reinject_retention = none;
    let mut u = r.uplink(cfg);
    let rep = u.run_once().unwrap();
    assert_eq!(rep.pruned_rejected.removed, 3, "{rep:?}");
    assert_eq!(rep.pruned_reinject.removed, 1, "{rep:?}");
    assert!(rep.pruned_reinject.removed_bytes > 0);
    assert!(r.rejected().is_empty());
    assert!(!gdir.join("records.jsonl").exists());
    assert!(gdir.join("origin.jsonl").exists() && gdir.join("done").exists());
    let snap = u.snapshot().unwrap();
    let usage = snap.state_usage.unwrap();
    assert_eq!(usage.reinject.map(|x| x.entries), Some(1));
    drop(u);
    // The ledger still knows the first round.
    let again = reinject::reinject(&o).unwrap();
    assert_eq!((again.queued, again.already_queued), (2, 2), "{again:?}");
    // The second round's dead letters (source reinject:<gen>) came from the
    // pruned generation: re-injected from the dead letters' own copies.
    assert_eq!(again.from_dead_letter, 2, "{again:?}");
}
