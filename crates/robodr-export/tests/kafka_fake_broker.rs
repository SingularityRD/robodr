//! The std-only producer against the in-process fake cluster: success,
//! retriable errors, leader change, disconnects mid-request, oversized
//! records, fatal errors, timeouts and hostile responses.

mod common;

use common::*;
use robodr_export::kafka::{Outcome, ProduceError, ProduceRecord, Producer, ProducerConfig};
use std::time::Duration;

fn cfg(c: &Cluster) -> ProducerConfig {
    let mut p = ProducerConfig::new(c.bootstrap());
    p.retry_backoff = Duration::from_millis(5);
    p.retry_backoff_max = Duration::from_millis(50);
    p.request_timeout = Duration::from_secs(5);
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
