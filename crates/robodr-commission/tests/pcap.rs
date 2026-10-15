//! Learning from packet captures: pcap/pcapng -> robodr-capture ->
//! robodr-rtps (with DATA_FRAG reassembly) -> Learner, then lock and check
//! over the same capture.

mod common;

use common::*;
use robodr_commission::input::read_all;
use robodr_commission::{
    lock, Checker, EventSource, InputError, LearnConfig, Learner, PcapSource, WarningLevel,
};

fn learn_bytes(bytes: &[u8]) -> Learner {
    let mut l = Learner::new(LearnConfig {
        model: "talker-listener".into(),
        ..Default::default()
    })
    .unwrap();
    let mut src = PcapSource::new("mem.pcap", bytes).unwrap();
    l.ingest(&mut src).unwrap();
    l
}

fn has(l: &Learner, code: &str, subject: &str) -> bool {
    l.report()
        .warnings
        .iter()
        .any(|w| w.code == code && w.subject == subject)
}

#[test]
fn pcap_learn_lock_check_is_clean_and_reassembles_fragmented_sedp() {
    let bytes = pcap(&talker_listener(false));
    let l = learn_bytes(&bytes);
    let p = l.profile();
    let r = l.report();
    let (t, li) = (hex(prefix(0xa1)), hex(prefix(0xb2)));

    assert_eq!(
        p.participants.iter().cloned().collect::<Vec<_>>(),
        vec![t.clone(), li.clone()]
    );
    // /chatter only arrives as DATA_FRAG: learned means reassembled.
    assert!(p.writer_topics.contains("/chatter"), "{r}");
    assert!(p.writer_topics.contains("/rosout"));
    assert!(p.writer_topics.contains("/parameter_events"));
    assert!(!p
        .writer_topics
        .iter()
        .any(|t| t.starts_with("rq/") || t.starts_with("rr/")));
    for node in ["/talker", "/listener"] {
        for s in robodr_commission::PARAMETER_SERVICES {
            assert!(p.services.contains(&format!("{node}/{s}")), "{node}/{s}");
        }
    }
    assert_eq!(p.services.len(), 12);
    assert_eq!(p.actions.iter().collect::<Vec<_>>(), vec!["/dock"]);
    assert_eq!(
        p.raw_dds_topics.iter().collect::<Vec<_>>(),
        vec!["ros_discovery_info"]
    );
    assert!(p.reader_topics.is_empty());

    // Roles: the listener serves its parameters; the talker is a client.
    let gp = &r.services["/listener/get_parameters"];
    assert!(gp.servers.contains(&li) && gp.clients.contains(&t));
    assert!(r.actions["/dock"].servers.contains(&li));

    let c = r.runs[0].capture.as_ref().expect("capture diagnostics");
    assert!(c.discovery_data_frag >= 3);
    assert_eq!(c.discovery_frag_completed, 1);
    assert!(!c.discovery_reassembly_failed());
    assert_eq!(c.ip_reassembled, 1);
    assert_eq!(c.ip_reassembly_dropped, 0);
    assert_eq!(r.anomalies_total, 0, "{r}");
    assert!(has(&l, "fragmented_discovery_reassembled", "run0"));
    for code in [
        "missing_parameter_services",
        "incomplete_parameter_services",
        "fragmented_discovery_unreassembled",
        "reader_only_name",
        "raw_dds_topic",
    ] {
        assert!(!r.warnings.iter().any(|w| w.code == code), "{code}: {r}");
    }
    // Positions are frame ordinals.
    assert!(r.participants[&t].first_seen.position >= 1);

    // lock -> check over the same capture: zero deviations.
    let locked = lock(&p).unwrap();
    let mut chk = Checker::new(&locked);
    chk.ingest(&mut PcapSource::new("mem.pcap", &bytes[..]).unwrap())
        .unwrap();
    let rep = chk.finish();
    assert_eq!(rep.deviations_total, 0, "{rep}");
    assert!(rep.events > 40);

    // Learned with --learn-readers, the same capture is still clean.
    let mut l2 = Learner::new(LearnConfig {
        model: "m".into(),
        learn_readers: true,
        ..Default::default()
    })
    .unwrap();
    l2.ingest(&mut PcapSource::new("mem.pcap", &bytes[..]).unwrap())
        .unwrap();
    let p2 = lock(&l2.profile()).unwrap();
    assert!(p2.reader_topics.contains("/chatter"));
    let mut chk = Checker::new(&p2);
    chk.ingest(&mut PcapSource::new("mem.pcap", &bytes[..]).unwrap())
        .unwrap();
    assert_eq!(chk.finish().deviations_total, 0);
}

#[test]
fn pcapng_gives_the_same_profile() {
    let frames = talker_listener(false);
    let a = learn_bytes(&pcap(&frames)).profile();
    let b = learn_bytes(&pcapng(&frames)).profile();
    assert_eq!(a, b);
}

#[test]
fn lost_data_frag_is_reported_and_endpoint_missing() {
    let l = learn_bytes(&pcap(&talker_listener(true)));
    let p = l.profile();
    assert!(!p.writer_topics.contains("/chatter"));
    let r = l.report();
    let c = r.runs[0].capture.as_ref().unwrap();
    assert!(c.discovery_reassembly_failed());
    assert_eq!(c.discovery_frag_incomplete, 1);
    let w = r
        .warnings
        .iter()
        .find(|w| w.code == "fragmented_discovery_unreassembled")
        .expect("warning");
    assert_eq!(w.level, WarningLevel::Warn);
    assert!(w.message.contains("1 incomplete"), "{}", w.message);
}

#[test]
fn node_without_parameter_services_is_flagged() {
    let a = prefix(0xc3);
    let specs = vec!["W rt/rosout".to_string(), "W rt/telemetry".into()];
    let mut frames = frames(TALKER, &announce(a, &specs));
    // A second node with a partial parameter set (capture started late).
    let b = prefix(0xd4);
    let mut partial = ros_node("/late");
    partial.truncate(5 + 4); // rosout etc. + two of the six services
    frames.extend(common::frames(LISTENER, &announce(b, &partial)));
    let l = learn_bytes(&pcap(&frames));
    assert!(has(&l, "missing_parameter_services", &hex(a)));
    assert!(!has(&l, "missing_parameter_services", &hex(b)));
    assert!(has(&l, "incomplete_parameter_services", "/late"));
}

#[test]
fn corrupt_or_truncated_captures_are_errors() {
    assert!(matches!(
        PcapSource::new("x.pcap", &b"definitely not a capture"[..]),
        Err(InputError::Capture { .. })
    ));
    let mut bytes = pcap(&talker_listener(false));
    bytes.truncate(bytes.len() - 7);
    let mut src = PcapSource::new("t.pcap", &bytes[..]).unwrap();
    let err = read_all(&mut src).unwrap_err();
    assert!(matches!(err, InputError::Capture { .. }), "{err}");
    assert!(err.to_string().starts_with("t.pcap: "), "{err}");
    assert!(src.next_event().is_none());
}

#[test]
fn hostile_payloads_never_panic() {
    // Random-ish RTPS-looking garbage on the RTPS port: counted, not fatal.
    let mut x: u64 = 0x1234_5678;
    let mut dgrams = Vec::new();
    for len in [0usize, 3, 20, 21, 64, 300, 1400] {
        let mut d = b"RTPS".to_vec();
        for _ in 0..len {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            d.push(x as u8);
        }
        dgrams.push(d);
    }
    dgrams.push(b"not rtps".to_vec());
    let bytes = pcap(&frames(TALKER, &dgrams));
    let mut src = PcapSource::new("g.pcap", &bytes[..]).unwrap();
    let evs = read_all(&mut src).unwrap();
    let d = src.capture_diagnostics().unwrap();
    assert_eq!(d.frames, dgrams.len() as u64);
    // Whatever parsed is at most participant noise; nothing panicked.
    assert!(evs.len() <= dgrams.len() * 4);
}
