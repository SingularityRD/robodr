//! The std-only producer against the in-process fake cluster: success,
//! retriable errors, leader change, disconnects mid-request, oversized
//! records, fatal errors, timeouts and hostile responses.

mod common;

use common::*;
use robodr_export::kafka::proto;
use robodr_export::kafka::{Outcome, ProduceError, ProduceRecord, Producer, ProducerConfig};
use std::time::Duration;

fn cfg(c: &Cluster) -> ProducerConfig {
    let mut p = ProducerConfig::new(c.bootstrap());
    p.retry_backoff = Duration::from_millis(5);
    p.retry_backoff_max = Duration::from_millis(50);
    p.request_timeout = Duration::from_secs(5);
    p.produce_timeout_ms = 1_000;
    p.delivery_timeout = Duration::from_secs(30);
    p
}

fn rec(i: usize, size: usize) -> ProduceRecord {
    ProduceRecord {
        key: Some(format!("rf1-{i:032x}").into_bytes()),
        value: Some(format!("{i:06}{}", "x".repeat(size)).into_bytes()),
        headers: vec![
            ("content-type".into(), b"application/json".to_vec()),
            ("robot-id".into(), b"ugv-007".to_vec()),
        ],
        timestamp_ms: 1_790_000_000_000 + i as i64,
    }
}

fn recs(n: usize, partitions: i32) -> Vec<(i32, ProduceRecord)> {
    (0..n)
        .map(|i| ((i as i32) % partitions, rec(i, 10)))
        .collect()
}

fn delivered(o: &[Outcome]) -> usize {
    o.iter()
        .filter(|x| matches!(x, Outcome::Delivered { .. }))
        .count()
}

/// Values of one partition, in log order, as the record index.
fn order(c: &Cluster, p: i32) -> Vec<usize> {
    c.values(p)
        .iter()
        .map(|v| v[..6].parse().unwrap())
        .collect()
}

#[test]
fn success_preserves_order_headers_and_offsets() {
    let c = Cluster::start(1, 3);
    let mut p = Producer::new(cfg(&c)).unwrap();
    assert_eq!(p.partition_count(TOPIC).unwrap(), 3);
    let input = recs(100, 3);
    let out = p.send(TOPIC, &input).unwrap();
    assert_eq!(delivered(&out), 100);
    for part in 0..3 {
        let want: Vec<usize> = (0..100).filter(|i| (*i as i32) % 3 == part).collect();
        assert_eq!(order(&c, part), want, "partition {part} order");
    }
    // Offsets: consecutive per partition, starting at 0.
    for (i, o) in out.iter().enumerate() {
        let Outcome::Delivered { partition, offset } = o else {
            panic!()
        };
        assert_eq!(*partition, (i as i32) % 3);
        assert_eq!(*offset, (i / 3) as i64);
    }
    let all = c.all_records();
    let r = &all[0].1;
    assert_eq!(
        header(r, "content-type").as_deref(),
        Some("application/json")
    );
    assert_eq!(header(r, "robot-id").as_deref(), Some("ugv-007"));
    assert!(r.key.is_some());
    let st = c.state.lock().unwrap();
    assert!(st.acks_seen.iter().all(|a| *a == -1), "acks=all");
    // Negotiated: Produce v8, Metadata v8, ApiVersions v0.
    assert!(st.seen.contains(&(1, 0, 8)));
    assert!(st.seen.contains(&(1, 3, 8)));
    assert!(st.seen.contains(&(1, 18, 0)));
    // One request carried all three partitions.
    assert_eq!(st.produce_requests, 1);
    drop(st);
    // A second call reuses the connection and appends after.
    let out = p.send(TOPIC, &recs(3, 3)).unwrap();
    assert_eq!(
        out[0],
        Outcome::Delivered {
            partition: 0,
            offset: 34
        }
    );
}

#[test]
fn older_produce_version_is_negotiated() {
    let c = Cluster::start(1, 1);
    c.state.lock().unwrap().produce_max_version = 3;
    let mut p = Producer::new(cfg(&c)).unwrap();
    assert_eq!(delivered(&p.send(TOPIC, &recs(5, 1)).unwrap()), 5);
    assert!(c.state.lock().unwrap().seen.contains(&(1, 0, 3)));
}

#[test]
fn unsupported_broker_is_fatal() {
    let c = Cluster::start(1, 1);
    c.state.lock().unwrap().produce_max_version = 2;
    let mut p = Producer::new(cfg(&c)).unwrap();
    let e = p.send(TOPIC, &recs(1, 1)).unwrap_err();
    assert!(matches!(e, ProduceError::Unsupported(_)), "{e}");
    assert_eq!(c.total(), 0);
}

#[test]
fn retriable_errors_are_retried_without_duplicates() {
    let c = Cluster::start(1, 2);
    c.script([
        Action::Error(7),  // REQUEST_TIMED_OUT
        Action::Error(19), // NOT_ENOUGH_REPLICAS
        Action::Error(5),  // LEADER_NOT_AVAILABLE (refresh)
    ]);
    let mut p = Producer::new(cfg(&c)).unwrap();
    let out = p.send(TOPIC, &recs(10, 2)).unwrap();
    assert_eq!(delivered(&out), 10);
    assert_eq!(c.total(), 10, "nothing appended twice");
    assert!(p.stats().retries >= 3);
    assert_eq!(c.state.lock().unwrap().produce_requests, 4);
}

#[test]
fn leader_change_is_followed() {
    let c = Cluster::start(2, 2);
    c.script([Action::MoveLeader(2)]);
    let mut p = Producer::new(cfg(&c)).unwrap();
    let out = p.send(TOPIC, &recs(20, 2)).unwrap();
    assert_eq!(delivered(&out), 20);
    assert_eq!(c.total(), 20);
    let st = c.state.lock().unwrap();
    assert!(
        st.seen.contains(&(2, 0, 8)),
        "produce went to the new leader: {:?}",
        st.seen
    );
    assert!(p.stats().metadata_refreshes >= 2);
}

#[test]
fn stale_leader_answers_not_leader_then_new_leader_succeeds() {
    // Leadership moves behind the producer's back between two calls.
    let c = Cluster::start(2, 1);
    let mut p = Producer::new(cfg(&c)).unwrap();
    assert_eq!(delivered(&p.send(TOPIC, &recs(2, 1)).unwrap()), 2);
    c.state.lock().unwrap().leaders = vec![2];
    assert_eq!(delivered(&p.send(TOPIC, &recs(2, 1)).unwrap()), 2);
    assert_eq!(order(&c, 0), vec![0, 1, 0, 1]);
}

#[test]
fn disconnect_mid_request_is_at_least_once() {
    // Broker appends, then drops the connection before answering: the
    // client cannot know, re-sends, and the log holds a duplicate.
    let c = Cluster::start(1, 1);
    c.script([Action::DisconnectAfterAppend]);
    let mut p = Producer::new(cfg(&c)).unwrap();
    let out = p.send(TOPIC, &recs(3, 1)).unwrap();
    assert_eq!(delivered(&out), 3);
    assert_eq!(order(&c, 0), vec![0, 1, 2, 0, 1, 2]);
    assert!(p.stats().io_errors >= 1);
    assert!(p.stats().connects >= 2, "reconnected");

    // Dropped before appending: exactly once.
    let c = Cluster::start(1, 1);
    c.script([Action::DisconnectBeforeAppend, Action::PartialFrame]);
    let mut p = Producer::new(cfg(&c)).unwrap();
    let out = p.send(TOPIC, &recs(3, 1)).unwrap();
    assert_eq!(delivered(&out), 3);
    assert_eq!(order(&c, 0), vec![0, 1, 2]);
}

#[test]
fn hostile_or_silent_broker_times_out_and_recovers() {
    let c = Cluster::start(1, 1);
    c.script([Action::Garbage, Action::Hang]);
    let mut cf = cfg(&c);
    cf.request_timeout = Duration::from_millis(300);
    cf.produce_timeout_ms = 100;
    let mut p = Producer::new(cf).unwrap();
    let out = p.send(TOPIC, &recs(2, 1)).unwrap();
    assert_eq!(delivered(&out), 2);
    assert_eq!(c.total(), 2);
    assert!(p.stats().io_errors >= 2);
}

#[test]
fn oversized_records_are_isolated_and_rejected() {
    let c = Cluster::start(1, 1);
    c.state.lock().unwrap().max_value_bytes = 100;
    let mut p = Producer::new(cfg(&c)).unwrap();
    let mut input = recs(6, 1);
    input[3].1 = rec(3, 500); // too large for the broker
    let out = p.send(TOPIC, &input).unwrap();
    assert!(
        matches!(out[3], Outcome::Rejected { code: 10, .. }),
        "{:?}",
        out[3]
    );
    assert_eq!(delivered(&out), 5);
    assert_eq!(
        order(&c, 0),
        vec![0, 1, 2, 4, 5],
        "order kept around the hole"
    );

    // Client side: larger than max_request_bytes, never sent.
    let c = Cluster::start(1, 1);
    let mut cf = cfg(&c);
    cf.max_request_bytes = 8192;
    let mut p = Producer::new(cf).unwrap();
    let input = vec![(0, rec(0, 10)), (0, rec(1, 9000)), (0, rec(2, 10))];
    let out = p.send(TOPIC, &input).unwrap();
    assert!(matches!(out[1], Outcome::Rejected { code: 10, .. }));
    assert_eq!(order(&c, 0), vec![0, 2]);
}

#[test]
fn requests_are_split_to_respect_max_request_bytes() {
    let c = Cluster::start(1, 2);
    let mut cf = cfg(&c);
    cf.max_request_bytes = 8192;
    let mut p = Producer::new(cf).unwrap();
    let input: Vec<_> = (0..40).map(|i| ((i % 2) as i32, rec(i, 1000))).collect();
    let out = p.send(TOPIC, &input).unwrap();
    assert_eq!(delivered(&out), 40);
    assert!(c.state.lock().unwrap().produce_requests >= 5);
    assert_eq!(
        order(&c, 0),
        (0..40).filter(|i| i % 2 == 0).collect::<Vec<_>>()
    );
}

#[test]
fn fatal_error_stops() {
    let c = Cluster::start(1, 1);
    c.script([Action::Error(29)]); // TOPIC_AUTHORIZATION_FAILED
    let mut p = Producer::new(cfg(&c)).unwrap();
    let e = p.send(TOPIC, &recs(2, 1)).unwrap_err();
    assert!(matches!(e, ProduceError::Fatal { code: 29, .. }), "{e}");
}

#[test]
fn unknown_topic_and_exhausted_retries() {
    let c = Cluster::start(1, 1);
    let mut cf = cfg(&c);
    cf.retries = 2;
    let mut p = Producer::new(cf).unwrap();
    let e = p.partition_count("no-such-topic").unwrap_err();
    assert!(matches!(e, ProduceError::RetriesExhausted(_)), "{e}");

    c.script(std::iter::repeat_n(Action::Error(7), 10));
    let e = p.send(TOPIC, &recs(1, 1)).unwrap_err();
    assert!(matches!(e, ProduceError::RetriesExhausted(_)), "{e}");
    assert_eq!(c.total(), 0);
}

#[test]
fn partition_beyond_topic_is_retried_then_fails() {
    let c = Cluster::start(1, 1);
    let mut cf = cfg(&c);
    cf.retries = 1;
    let mut p = Producer::new(cf).unwrap();
    let e = p.send(TOPIC, &[(5, rec(0, 1))]).unwrap_err();
    assert!(matches!(e, ProduceError::RetriesExhausted(_)), "{e}");
}

/// Regression (found against Kafka 3.9.1): a batch that is only too large
/// as a whole (topic `max.message.bytes` below `max_request_bytes`, every
/// record fine on its own) used to switch the partition to one record per
/// request for the rest of the call. The batch is now halved until it fits.
#[test]
fn batch_too_large_as_a_whole_is_halved() {
    let c = Cluster::start(1, 1);
    // About 8 records of ~1 KB per batch.
    c.state.lock().unwrap().max_batch_bytes = 8 * 1100;
    let mut p = Producer::new(cfg(&c)).unwrap();
    let input: Vec<_> = (0..200).map(|i| (0, rec(i, 1000))).collect();
    let out = p.send(TOPIC, &input).unwrap();
    assert_eq!(delivered(&out), 200);
    assert_eq!(order(&c, 0), (0..200).collect::<Vec<_>>());
    let n = c.state.lock().unwrap().produce_requests;
    // 200 -> 100 -> 50 -> 25 -> 12 -> 6 refused/accepted, then 6 a time.
    assert!(n < 60, "{n} produce requests for 200 records");

    // Mixed: one record too large on its own among records that are too
    // large together. It is still isolated, everything else delivered in
    // order.
    let c = Cluster::start(1, 1);
    {
        let mut st = c.state.lock().unwrap();
        st.max_batch_bytes = 8 * 1100;
        st.max_value_bytes = 2000;
    }
    let mut p = Producer::new(cfg(&c)).unwrap();
    let mut input: Vec<_> = (0..60).map(|i| (0, rec(i, 1000))).collect();
    input[37].1 = rec(37, 5000);
    let out = p.send(TOPIC, &input).unwrap();
    assert!(matches!(out[37], Outcome::Rejected { code: 10, .. }));
    assert_eq!(delivered(&out), 59);
    let want: Vec<usize> = (0..60).filter(|i| *i != 37).collect();
    assert_eq!(order(&c, 0), want);
}

fn one_shot_server(f: impl Fn(std::net::TcpStream) + Send + 'static) -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            f(s);
        }
    });
    addr
}

fn read_request(s: &mut std::net::TcpStream) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut len = [0u8; 4];
    s.read_exact(&mut len).ok()?;
    let mut b = vec![0u8; i32::from_be_bytes(len) as usize];
    s.read_exact(&mut b).ok()?;
    Some(b)
}

/// Regression (found against Kafka 3.9.1): a plaintext request to a TLS
/// listener is answered with a TLS alert (`15 03 03 00 02 02 50`), which
/// was reported as "response frame size 352518912". The error now says
/// that the listener wants TLS.
#[test]
fn tls_listener_is_named_in_the_error() {
    let addr = one_shot_server(|mut s| {
        use std::io::Write;
        let _ = read_request(&mut s);
        let _ = s.write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x50]);
    });
    let mut cf = ProducerConfig::new(vec![addr]);
    cf.retries = 1;
    cf.retry_backoff = Duration::from_millis(1);
    let mut p = Producer::new(cf).unwrap();
    let e = p.partition_count(TOPIC).unwrap_err().to_string();
    assert!(e.contains("TLS") && e.contains("PLAINTEXT only"), "{e}");
}

/// Regression (found against Kafka 3.9.1): a SASL_PLAINTEXT listener
/// answers ApiVersions, then closes the connection on Metadata; the error
/// was a bare "broker closed the connection". It now names SASL.
#[test]
fn sasl_listener_is_named_in_the_error() {
    let addr = one_shot_server(|mut s| {
        use std::io::Write;
        let Some(f) = read_request(&mut s) else {
            return;
        };
        let (h, _) = proto::parse_request_header(&f).unwrap();
        assert_eq!(h.api_key, proto::API_VERSIONS);
        let body = proto::encode_api_versions_response(&proto::ApiVersionsResponse {
            error_code: 0,
            apis: vec![
                proto::ApiRange {
                    api_key: 0,
                    min: 0,
                    max: 11,
                },
                proto::ApiRange {
                    api_key: 3,
                    min: 0,
                    max: 12,
                },
            ],
        });
        let mut out = ((body.len() + 4) as i32).to_be_bytes().to_vec();
        out.extend_from_slice(&h.correlation_id.to_be_bytes());
        out.extend_from_slice(&body);
        let _ = s.write_all(&out);
        // Next request (Metadata): closed without an answer.
        let _ = read_request(&mut s);
    });
    let mut cf = ProducerConfig::new(vec![addr]);
    cf.retries = 1;
    cf.retry_backoff = Duration::from_millis(1);
    let mut p = Producer::new(cf).unwrap();
    let e = p.partition_count(TOPIC).unwrap_err().to_string();
    assert!(e.contains("SASL"), "{e}");
}

/// Regression (found against Kafka 3.9.1 with `connections.max.idle.ms`):
/// the broker closes idle connections; the producer used to discover that
/// only by a failed request (an I/O error, a metadata refresh and a retry
/// after backoff on every send after a quiet period, which is the normal
/// case for findings). Connections idle for `connections_max_idle` are now
/// closed before use.
#[test]
fn idle_connections_are_closed_before_the_broker_does() {
    let c = Cluster::start(1, 1);
    c.state.lock().unwrap().idle_close = Some(Duration::from_millis(150));
    // Client idle limit above the broker's: the stale connection fails
    // once, the record is still delivered exactly once.
    let mut p = Producer::new(cfg(&c)).unwrap();
    assert_eq!(delivered(&p.send(TOPIC, &recs(1, 1)).unwrap()), 1);
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(delivered(&p.send(TOPIC, &recs(1, 1)).unwrap()), 1);
    assert!(p.stats().io_errors >= 1, "{:?}", p.stats());
    assert_eq!(c.total(), 2);
    // Below the broker's: reconnects up front, no error, no retry.
    let mut cf = cfg(&c);
    cf.connections_max_idle = Duration::from_millis(50);
    let mut p = Producer::new(cf).unwrap();
    assert_eq!(delivered(&p.send(TOPIC, &recs(1, 1)).unwrap()), 1);
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(delivered(&p.send(TOPIC, &recs(1, 1)).unwrap()), 1);
    let st = p.stats();
    assert_eq!((st.io_errors, st.retries), (0, 0), "{st:?}");
    assert!(st.connects >= 3, "{st:?}");
    assert_eq!(c.total(), 4);
}
