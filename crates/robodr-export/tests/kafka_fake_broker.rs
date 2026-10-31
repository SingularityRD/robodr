//! The std-only producer against the in-process fake cluster: success,
//! retriable errors, leader change, disconnects mid-request, oversized
//! records, fatal errors, timeouts and hostile responses.

mod common;

use common::*;
use robodr_export::kafka::proto;
use robodr_export::kafka::{
    IdempotentState, Outcome, ProduceError, ProduceRecord, Producer, ProducerConfig, SendJournal,
};
use std::time::Duration;

fn cfg(c: &Cluster) -> ProducerConfig {
    let mut p = ProducerConfig::new(c.bootstrap());
    p.allow_plaintext = true;
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
fn disconnect_mid_request_is_at_least_once_without_idempotence() {
    // Broker appends, then drops the connection before answering: the
    // client cannot know, re-sends, and the log holds a duplicate.
    let c = Cluster::start(1, 1);
    c.script([Action::DisconnectAfterAppend]);
    let mut cf = cfg(&c);
    cf.idempotence = false;
    let mut p = Producer::new(cf).unwrap();
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
    cf.allow_plaintext = true;
    cf.retries = 1;
    cf.retry_backoff = Duration::from_millis(1);
    let mut p = Producer::new(cf).unwrap();
    let e = p.partition_count(TOPIC).unwrap_err().to_string();
    assert!(e.contains("TLS record") && e.contains("CA file"), "{e}");
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
    cf.allow_plaintext = true;
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

// ------------------------------------------------------------ idempotence

/// `(partition, producer id, epoch, base sequence, records)` appended.
fn appended(c: &Cluster) -> Vec<(i32, i64, i16, i32, i32)> {
    c.state.lock().unwrap().appended.clone()
}

#[test]
fn idempotent_lost_ack_is_not_written_twice() {
    for dup_code in [false, true] {
        // The broker appends, then drops the connection: the client
        // re-sends the same batch (same sequence) and the broker answers
        // it as a duplicate (success with the original offset, or
        // DUPLICATE_SEQUENCE_NUMBER).
        let c = Cluster::start(1, 1);
        c.state.lock().unwrap().dup_error_code = dup_code;
        c.script([Action::DisconnectAfterAppend]);
        let mut p = Producer::new(cfg(&c)).unwrap();
        let out = p.send(TOPIC, &recs(3, 1)).unwrap();
        assert_eq!(delivered(&out), 3);
        assert_eq!(order(&c, 0), vec![0, 1, 2], "dup_code {dup_code}");
        assert_eq!(c.state.lock().unwrap().duplicates, 1);
        if dup_code {
            assert_eq!(p.stats().duplicates, 1);
            assert!(matches!(out[0], Outcome::Delivered { offset: -1, .. }));
        } else {
            assert_eq!(
                out[2],
                Outcome::Delivered {
                    partition: 0,
                    offset: 2
                }
            );
        }
        assert_eq!(appended(&c), vec![(0, 1000, 0, 0, 3)]);
        assert_eq!(c.init_pid_requests(), 1);
        // The next call continues the sequence.
        p.send(TOPIC, &recs(2, 1)).unwrap();
        assert_eq!(appended(&c)[1], (0, 1000, 0, 3, 2));
        assert_eq!(c.init_pid_requests(), 1, "one producer id per producer");
        assert_eq!(p.idempotent_state().unwrap().next(TOPIC, 0), 5);
    }
}

#[test]
fn sequences_are_per_partition_and_survive_leader_moves() {
    let c = Cluster::start(2, 3);
    c.script([Action::Ok, Action::MoveLeader(2)]);
    let mut p = Producer::new(cfg(&c)).unwrap();
    assert_eq!(delivered(&p.send(TOPIC, &recs(30, 3)).unwrap()), 30);
    // Refused by the old leader (nothing appended), re-sent to the new one
    // with the same sequences.
    assert_eq!(delivered(&p.send(TOPIC, &recs(6, 3)).unwrap()), 6);
    assert_eq!(c.total(), 36);
    let a = appended(&c);
    for part in 0..3 {
        let seqs: Vec<(i32, i32)> = a
            .iter()
            .filter(|x| x.0 == part)
            .map(|x| (x.3, x.4))
            .collect();
        assert_eq!(seqs, vec![(0, 10), (10, 2)], "partition {part}");
    }
    assert!(a.iter().all(|x| x.1 == 1000 && x.2 == 0));
}

/// OUT_OF_ORDER_SEQUENCE_NUMBER / UNKNOWN_PRODUCER_ID on a broker with
/// KIP-360 (InitProducerId v3+): the same producer id at the next epoch,
/// from sequence 0, without InitProducerId. INVALID_PRODUCER_EPOCH /
/// PRODUCER_FENCED (someone else is ahead on this id), and every error on
/// an older broker: a new producer id.
#[test]
fn sequence_errors_bump_the_epoch_or_reset_the_producer_id() {
    for max_v in [4i16, 3, 2, 1] {
        for code in [45i16, 59, 47, 90] {
            let c = Cluster::start(1, 1);
            c.state.lock().unwrap().init_pid_max_version = max_v;
            let mut p = Producer::new(cfg(&c)).unwrap();
            p.send(TOPIC, &recs(2, 1)).unwrap();
            c.script([Action::Error(code)]);
            let out = p.send(TOPIC, &recs(3, 1)).unwrap();
            let what = format!("code {code}, InitProducerId v{max_v}");
            assert_eq!(delivered(&out), 3, "{what}");
            assert_eq!(c.total(), 5, "nothing twice, nothing lost ({what})");
            let s = p.stats();
            if max_v >= 3 && (code == 45 || code == 59) {
                assert_eq!((s.epoch_bumps, s.producer_id_resets), (1, 0), "{what}");
                assert_eq!(c.init_pid_requests(), 1, "{what}");
                // The bumped epoch starts at sequence 0.
                assert_eq!(appended(&c)[1], (0, 1000, 1, 0, 3), "{what}");
                let st = p.idempotent_state().unwrap();
                assert_eq!((st.producer_id, st.producer_epoch), (1000, 1));
                assert_eq!(st.next(TOPIC, 0), 3);
            } else {
                assert_eq!((s.epoch_bumps, s.producer_id_resets), (0, 1), "{what}");
                assert_eq!(c.init_pid_requests(), 2, "{what}");
                // The new producer id starts at sequence 0.
                assert_eq!(appended(&c)[1], (0, 1001, 0, 0, 3), "{what}");
            }
        }
    }
}

/// KIP-360's gain: a batch of another partition whose acknowledgement was
/// lost when the epoch was bumped keeps its numbering, is re-sent under
/// the older epoch (that partition has not seen the new one) and is
/// deduplicated. A new producer id instead (an older broker) re-sends its
/// records as new ones: written twice.
#[test]
fn epoch_bump_keeps_other_partitions_batches_in_doubt_deduplicated() {
    for max_v in [4i16, 1] {
        let c = Cluster::start(2, 2);
        {
            let mut st = c.state.lock().unwrap();
            st.leaders = vec![1, 2];
            st.init_pid_max_version = max_v;
        }
        let mut p = Producer::new(cfg(&c)).unwrap();
        assert_eq!(delivered(&p.send(TOPIC, &recs(4, 2)).unwrap()), 4);
        // Partition 0 (node 1): appended, reply lost. Partition 1 (node
        // 2): out of order.
        c.script([Action::DisconnectAfterAppend, Action::Error(45)]);
        let out = p.send(TOPIC, &recs(6, 2)).unwrap();
        assert_eq!(delivered(&out), 6);
        let s = p.stats();
        if max_v >= 3 {
            assert_eq!(c.total(), 10, "nothing written twice");
            assert_eq!((s.epoch_bumps, s.producer_id_resets), (1, 0));
            assert_eq!(c.state.lock().unwrap().duplicates, 1);
            let a = appended(&c);
            // Partition 0: epoch 0 throughout; partition 1: epoch 1 from 0.
            assert!(a.contains(&(0, 1000, 0, 2, 3)), "{a:?}");
            assert!(a.contains(&(1, 1000, 1, 0, 3)), "{a:?}");
            // Partition 0 continues under the new epoch, from 0.
            assert_eq!(delivered(&p.send(TOPIC, &recs(2, 2)).unwrap()), 2);
            assert!(appended(&c).contains(&(0, 1000, 1, 0, 1)));
            assert_eq!(c.total(), 12);
        } else {
            assert_eq!(c.total(), 13, "the in-doubt batch is written twice");
            assert_eq!((s.epoch_bumps, s.producer_id_resets), (0, 1));
        }
    }
}

/// A broker that forgot the producer (`producer.id.expiration.ms`)
/// accepts its next batch with any sequence: no reset needed.
#[test]
fn expired_producer_continues() {
    let c = Cluster::start(1, 1);
    let mut p = Producer::new(cfg(&c)).unwrap();
    p.send(TOPIC, &recs(2, 1)).unwrap();
    c.forget_producers();
    p.send(TOPIC, &recs(2, 1)).unwrap();
    assert_eq!(c.total(), 4);
    assert_eq!(p.stats().producer_id_resets, 0);
    assert_eq!(appended(&c)[1], (0, 1000, 0, 2, 2));
}

#[test]
fn init_producer_id_refusals() {
    // No IDEMPOTENT_WRITE: fatal, with the remedy; nothing sent.
    let c = Cluster::start(1, 1);
    c.state.lock().unwrap().init_pid_error = Some(31);
    let mut p = Producer::new(cfg(&c)).unwrap();
    let e = p.send(TOPIC, &recs(1, 1)).unwrap_err();
    assert!(matches!(e, ProduceError::Fatal { code: 31, .. }), "{e}");
    let m = e.to_string();
    assert!(
        m.contains("IDEMPOTENT_WRITE") && m.contains("idempotence off"),
        "{m}"
    );
    assert_eq!(c.total(), 0);
    // Idempotence off: works, never asks for a producer id.
    let mut cf = cfg(&c);
    cf.idempotence = false;
    let mut p = Producer::new(cf).unwrap();
    assert_eq!(delivered(&p.send(TOPIC, &recs(2, 1)).unwrap()), 2);
    assert!(p.idempotent_state().is_none());
    assert_eq!(
        c.state.lock().unwrap().idempotent_batches,
        0,
        "producer id -1"
    );

    // A broker without InitProducerId: refused with the remedy.
    let c = Cluster::start(1, 1);
    c.state.lock().unwrap().init_pid_supported = false;
    let mut p = Producer::new(cfg(&c)).unwrap();
    let e = p.send(TOPIC, &recs(1, 1)).unwrap_err();
    assert!(matches!(e, ProduceError::Unsupported(_)), "{e}");
    assert!(e.to_string().contains("idempotence off"), "{e}");

    // A coordinator that is not ready yet: retried.
    let c = Cluster::start(1, 1);
    c.state.lock().unwrap().init_pid_error = Some(15);
    let c2 = c.clone();
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(30));
        c2.state.lock().unwrap().init_pid_error = None;
    });
    let mut p = Producer::new(cfg(&c)).unwrap();
    assert_eq!(delivered(&p.send(TOPIC, &recs(1, 1)).unwrap()), 1);
    t.join().unwrap();
    assert!(c.init_pid_requests() >= 2);
}

/// A batch too large as a whole is halved: the refused batch frees its
/// sequences, so the broker sees no gap and no reset happens.
#[test]
fn halving_reuses_the_refused_sequences() {
    let c = Cluster::start(1, 1);
    c.state.lock().unwrap().max_batch_bytes = 8 * 1100;
    let mut p = Producer::new(cfg(&c)).unwrap();
    let input: Vec<_> = (0..40).map(|i| (0, rec(i, 1000))).collect();
    assert_eq!(delivered(&p.send(TOPIC, &input).unwrap()), 40);
    assert_eq!(order(&c, 0), (0..40).collect::<Vec<_>>());
    assert_eq!(p.stats().producer_id_resets, 0);
    let mut next = 0;
    for (_, _, _, seq, n) in appended(&c) {
        assert_eq!(seq, next);
        next += n;
    }
    assert_eq!(next, 40);
}

/// Review finding: a batch whose reply was lost is re-sent; if the copy is
/// refused with a record-level error (Kafka validates records before it
/// looks for duplicates, e.g. after the topic's `max.message.bytes` was
/// lowered), the first copy may already be in the log. Its sequences must
/// not be handed to the next batch, which the broker would answer as a
/// duplicate: reported delivered, never written. The producer renumbers
/// instead (an epoch bump, or a new producer id on an older broker).
#[test]
fn record_error_on_a_resent_batch_never_reuses_its_sequences() {
    for (dup_code, max_v) in [(false, 4i16), (true, 4), (false, 1), (true, 1)] {
        let c = Cluster::start(1, 1);
        c.state.lock().unwrap().dup_error_code = dup_code;
        c.state.lock().unwrap().init_pid_max_version = max_v;
        // Appended, reply lost; the re-send is refused as a record.
        c.script([Action::DisconnectAfterAppend, Action::Error(10)]);
        let mut p = Producer::new(cfg(&c)).unwrap();
        let out = p.send(TOPIC, &[(0, rec(0, 10))]).unwrap();
        assert!(matches!(out[0], Outcome::Rejected { code: 10, .. }));
        assert_eq!(order(&c, 0), vec![0], "the first copy was appended");
        // The next record must really be written.
        let out = p.send(TOPIC, &[(0, rec(1, 10))]).unwrap();
        assert_eq!(delivered(&out), 1);
        assert_eq!(
            order(&c, 0),
            vec![0, 1],
            "record 1 reported delivered must be in the log (dup_code {dup_code})"
        );
        assert_eq!(c.state.lock().unwrap().duplicates, 0);
        if max_v >= 3 {
            assert_eq!(p.stats().epoch_bumps, 1);
            assert_eq!(c.init_pid_requests(), 1);
            assert_eq!(appended(&c)[1], (0, 1000, 1, 0, 1));
        } else {
            assert_eq!(p.stats().producer_id_resets, 1);
            assert_eq!(c.init_pid_requests(), 2);
            assert_eq!(appended(&c)[1], (0, 1001, 0, 0, 1));
        }
    }
}

/// The same for a re-sent batch that is halved: no later batch may reuse
/// the in-doubt sequences either.
#[test]
fn halving_a_resent_batch_renumbers() {
    for max_v in [4i16, 1] {
        let c = Cluster::start(1, 1);
        c.state.lock().unwrap().init_pid_max_version = max_v;
        c.script([Action::DisconnectAfterAppend, Action::Error(10)]);
        let mut p = Producer::new(cfg(&c)).unwrap();
        let out = p.send(TOPIC, &recs(4, 1)).unwrap();
        // Halved and sent under a new epoch / producer id: a duplicate of
        // what the first copy appended, never a loss.
        assert_eq!(delivered(&out), 4);
        assert_eq!(order(&c, 0), vec![0, 1, 2, 3, 0, 1, 2, 3]);
        let s = p.stats();
        assert_eq!(s.epoch_bumps + s.producer_id_resets, 1);
        assert_eq!(s.epoch_bumps, u64::from(max_v >= 3));
        let out = p.send(TOPIC, &recs(2, 1)).unwrap();
        assert_eq!(delivered(&out), 2);
        assert_eq!(c.total(), 10, "every record reported delivered is written");
    }
}

/// At the largest epoch no bump is possible: a new producer id.
#[test]
fn largest_epoch_resets_the_producer_id() {
    let c = Cluster::start(1, 1);
    let mut p = Producer::new(cfg(&c)).unwrap();
    p.restore_idempotent_state(IdempotentState {
        producer_id: 77,
        producer_epoch: i16::MAX,
        sequences: [(TOPIC.to_string(), [(0, 5)].into_iter().collect())]
            .into_iter()
            .collect(),
    });
    {
        // The broker holds producer 77 at the largest epoch, sequence 0.
        let mut st = c.state.lock().unwrap();
        st.producers.insert(
            (77, 0),
            ProducerEntry {
                epoch: i16::MAX,
                last_seq: 0,
                recent: Default::default(),
            },
        );
    }
    assert_eq!(delivered(&p.send(TOPIC, &recs(2, 1)).unwrap()), 2);
    let s = p.stats();
    assert_eq!((s.epoch_bumps, s.producer_id_resets), (0, 1));
    assert_eq!(appended(&c), vec![(0, 1000, 0, 0, 2)]);
}

/// A crash after an epoch bump while another partition's batch was in
/// doubt under the older epoch: the restarted producer re-sends it as it
/// was (same id, older epoch) and the broker drops the copy.
#[test]
fn restart_after_an_epoch_bump_resends_the_older_epochs_batch() {
    let c = Cluster::start(2, 2);
    c.state.lock().unwrap().leaders = vec![1, 2];
    let mut p = Producer::new(cfg(&c)).unwrap();
    assert_eq!(delivered(&p.send(TOPIC, &recs(4, 2)).unwrap()), 4);
    let state0 = p.idempotent_state().unwrap().clone();
    drop(p);
    // Partition 0: appended, reply lost; partition 1: out of order; then
    // the bumped batch of partition 1 is lost too, and the producer gives
    // up (a crash).
    c.script([
        Action::DisconnectAfterAppend,
        Action::Error(45),
        Action::DisconnectBeforeAppend,
        Action::DisconnectBeforeAppend,
    ]);
    let mut cf = cfg(&c);
    cf.retries = 1;
    let input = recs(6, 2);
    let saved: Saved = Default::default();
    let mut p = Producer::new(cf).unwrap();
    p.restore_idempotent_state(state0);
    assert!(p
        .send_journaled(TOPIC, &input, None, &mut saver(&saved))
        .is_err());
    assert_eq!(p.stats().epoch_bumps, 1);
    drop(p);
    let (state, journal) = saved.lock().unwrap().last().cloned().unwrap();
    assert_eq!(state.producer_epoch, 1, "the bump is stored");
    assert!(
        journal
            .batches
            .iter()
            .any(|b| b.partition == 0 && b.producer_epoch == 0 && b.offset.is_none()),
        "{journal:?}"
    );
    assert_eq!(c.total(), 7, "partition 0's batch is in the log");
    let mut p = Producer::new(cfg(&c)).unwrap();
    p.restore_idempotent_state(state);
    let out = p
        .send_journaled(TOPIC, &input, Some(&journal), &mut saver(&saved))
        .unwrap();
    assert_eq!(delivered(&out), 6);
    assert_eq!(c.total(), 10, "nothing written twice");
    assert_eq!(c.init_pid_requests(), 1);
}

/// Review finding: INVALID_TIMESTAMP means the publishing host's clock is
/// off (it stamps every record): retried, then the call fails with a hint;
/// no record is reported rejected.
#[test]
fn invalid_timestamp_is_never_blamed_on_a_record() {
    let c = Cluster::start(1, 1);
    {
        let mut st = c.state.lock().unwrap();
        st.timestamp_after_max_ms = Some(3_600_000);
        // `rec` stamps a fixed time; put the broker's clock 2 h behind it.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        st.clock_offset_ms = 1_790_000_000_000 - now - 7_200_000;
    }
    let mut cf = cfg(&c);
    cf.retries = 2;
    let mut p = Producer::new(cf).unwrap();
    let e = p.send(TOPIC, &recs(3, 1)).unwrap_err();
    let m = e.to_string();
    assert!(matches!(e, ProduceError::RetriesExhausted(_)), "{m}");
    assert!(
        m.contains("INVALID_TIMESTAMP") && m.contains("clock"),
        "{m}"
    );
    assert_eq!(p.stats().rejected, 0);
    assert_eq!(c.total(), 0);
    // Clock fixed: the same records go through.
    c.state.lock().unwrap().clock_offset_ms = 0;
    c.state.lock().unwrap().timestamp_after_max_ms = None;
    assert_eq!(delivered(&p.send(TOPIC, &recs(3, 1)).unwrap()), 3);
}

type Saved = std::sync::Arc<std::sync::Mutex<Vec<(IdempotentState, SendJournal)>>>;

fn saver(saved: &Saved) -> impl FnMut(&IdempotentState, &SendJournal) -> Result<(), String> + '_ {
    move |s, j| {
        saved.lock().unwrap().push((s.clone(), j.clone()));
        Ok(())
    }
}

/// A crash after the broker appended a batch but before its
/// acknowledgement arrived: the restarted producer restores the persisted
/// state and journal, re-sends the batch in doubt as it was, and the broker
/// drops the copy.
#[test]
fn restart_with_the_journal_does_not_duplicate() {
    let c = Cluster::start(1, 2);
    c.script([Action::DisconnectAfterAppend]);
    let mut cf = cfg(&c);
    cf.retries = 0;
    let input = recs(6, 2);
    let saved: Saved = Default::default();
    let mut p = Producer::new(cf).unwrap();
    let e = p
        .send_journaled(TOPIC, &input, None, &mut saver(&saved))
        .unwrap_err();
    assert!(matches!(e, ProduceError::RetriesExhausted(_)), "{e}");
    drop(p);
    assert_eq!(c.total(), 6, "appended, not acknowledged");
    let (state, journal) = saved.lock().unwrap().last().cloned().unwrap();
    assert_eq!(journal.batches.len(), 2);
    assert!(journal.batches.iter().all(|b| b.offset.is_none()));
    assert_eq!(state.next(TOPIC, 0), 3);

    let mut p = Producer::new(cfg(&c)).unwrap();
    p.restore_idempotent_state(state);
    let out = p
        .send_journaled(TOPIC, &input, Some(&journal), &mut saver(&saved))
        .unwrap();
    assert_eq!(delivered(&out), 6);
    assert_eq!(c.total(), 6, "the broker dropped both copies");
    assert_eq!(c.state.lock().unwrap().duplicates, 2);
    assert_eq!(
        c.init_pid_requests(),
        1,
        "the persisted producer id is reused"
    );
    assert_eq!(
        out[1],
        Outcome::Delivered {
            partition: 1,
            offset: 0
        }
    );

    // Without the journal the same records would be new ones: written
    // twice (what the journal prevents).
    let mut p = Producer::new(cfg(&c)).unwrap();
    p.restore_idempotent_state(saved.lock().unwrap().last().unwrap().0.clone());
    p.send(TOPIC, &input).unwrap();
    assert_eq!(c.total(), 12);
}

/// More than five batches per partition in one call (the broker only
/// remembers five): the journal marks the acknowledged ones, which a
/// restart reports without sending; only the last one is re-sent.
#[test]
fn restart_skips_acknowledged_batches() {
    let c = Cluster::start(1, 1);
    let mut cf = cfg(&c);
    cf.max_request_bytes = 8192;
    let input: Vec<_> = (0..40).map(|i| (0, rec(i, 1000))).collect();
    let saved: Saved = Default::default();
    let mut p = Producer::new(cf.clone()).unwrap();
    let out = p
        .send_journaled(TOPIC, &input, None, &mut saver(&saved))
        .unwrap();
    assert_eq!(delivered(&out), 40);
    let n = c.state.lock().unwrap().produce_requests;
    assert!(n > 5, "{n} requests");
    // The last journal stored: all but the last batch acknowledged.
    let (state, journal) = saved.lock().unwrap().last().cloned().unwrap();
    let in_doubt = journal
        .batches
        .iter()
        .filter(|b| b.offset.is_none())
        .count();
    assert_eq!((journal.batches.len() as u64, in_doubt), (n, 1));

    // "Crash" before the caller committed: replay with the journal.
    let mut p = Producer::new(cf).unwrap();
    p.restore_idempotent_state(state);
    let again = p
        .send_journaled(TOPIC, &input, Some(&journal), &mut saver(&saved))
        .unwrap();
    assert_eq!(again, out, "same outcomes, same offsets");
    assert_eq!(c.total(), 40);
    assert_eq!(p.stats().journal_acked, n - 1);
    assert_eq!(c.state.lock().unwrap().produce_requests, n + 1);
}

#[test]
fn unfitting_journals_are_ignored() {
    let c = Cluster::start(1, 2);
    let input = recs(4, 2);
    let mut p = Producer::new(cfg(&c)).unwrap();
    let saved: Saved = Default::default();
    p.send_journaled(TOPIC, &input, None, &mut saver(&saved))
        .unwrap();
    let (_, j) = saved.lock().unwrap().last().cloned().unwrap();
    // Another topic, an index out of range, another partition: the
    // records are sent as new ones (never lost).
    let mut other = j.clone();
    other.topic = "other".into();
    let mut range = j.clone();
    range.batches[0].records.push(99);
    let mut part = j.clone();
    part.batches[0].partition = 1 - part.batches[0].partition;
    for bad in [other, range, part] {
        let before = c.total();
        let out = p
            .send_journaled(TOPIC, &input, Some(&bad), &mut saver(&saved))
            .unwrap();
        assert_eq!(delivered(&out), 4);
        assert_eq!(c.total(), before + 4);
    }
    assert_eq!(p.stats().journal_acked, 0);
}

#[test]
fn a_journal_that_cannot_be_saved_stops_before_sending() {
    let c = Cluster::start(1, 1);
    let mut p = Producer::new(cfg(&c)).unwrap();
    let e = p
        .send_journaled(TOPIC, &recs(2, 1), None, &mut |_, _| {
            Err("disk full".to_string())
        })
        .unwrap_err();
    assert!(matches!(e, ProduceError::Journal(_)), "{e}");
    assert!(e.to_string().contains("disk full"));
    assert_eq!(c.state.lock().unwrap().produce_requests, 0);
    // The sequences were not used up: the next batch starts at 0.
    p.send(TOPIC, &recs(2, 1)).unwrap();
    assert_eq!(appended(&c), vec![(0, 1000, 0, 0, 2)]);
}

#[test]
fn sequence_numbers_wrap_like_kafka() {
    use robodr_export::kafka::client::increment_sequence;
    assert_eq!(increment_sequence(0, 5), 5);
    assert_eq!(increment_sequence(i32::MAX - 2, 2), i32::MAX);
    assert_eq!(increment_sequence(i32::MAX - 2, 3), 0);
    assert_eq!(increment_sequence(i32::MAX, 1), 0);
    assert_eq!(increment_sequence(i32::MAX, 10), 9);
    assert_eq!(inc_seq(i32::MAX, 10), 9);
}

/// Review finding (WP16): a batch numbered under an older epoch (another
/// partition's batch in doubt across an epoch bump) answered
/// INVALID_PRODUCER_EPOCH / PRODUCER_FENCED: someone else writes with this
/// producer id at a higher epoch (a cloned state directory). The producer
/// resets to a new producer id, as the module docs say, instead of going
/// on at the bumped epoch, where the other writer's batches could be
/// answered DUPLICATE_SEQUENCE_NUMBER (reported delivered, never written).
#[test]
fn fencing_of_an_older_epochs_batch_resets_the_producer_id() {
    for code in [47i16, 90] {
        let c = Cluster::start(2, 2);
        {
            let mut st = c.state.lock().unwrap();
            st.leaders = vec![1, 2];
            st.init_pid_max_version = 4;
        }
        let mut p = Producer::new(cfg(&c)).unwrap();
        assert_eq!(delivered(&p.send(TOPIC, &recs(4, 2)).unwrap()), 4);
        // Partition 0 (node 1): appended, reply lost. Partition 1 (node
        // 2): out of order (epoch bump). Partition 0's re-send under the
        // older epoch: fenced.
        c.script([
            Action::DisconnectAfterAppend,
            Action::Error(45),
            Action::Error(code),
        ]);
        let out = p.send(TOPIC, &recs(6, 2)).unwrap();
        assert_eq!(delivered(&out), 6, "code {code}");
        let s = p.stats();
        assert_eq!(s.epoch_bumps, 1, "code {code}");
        assert_eq!(s.producer_id_resets, 1, "code {code}: a new producer id");
        let st = p.idempotent_state().unwrap();
        assert_ne!(st.producer_id, 1000, "code {code}");
        assert_eq!(c.init_pid_requests(), 2, "code {code}");
        // Partition 0 continues under the new producer id.
        assert_eq!(delivered(&p.send(TOPIC, &recs(2, 2)).unwrap()), 2);
        assert!(
            appended(&c)
                .iter()
                .rfind(|a| a.0 == 0)
                .is_some_and(|a| a.1 != 1000),
            "{:?}",
            appended(&c)
        );
    }
}
