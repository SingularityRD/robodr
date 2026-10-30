//! Synthetic frames from the RFCs and the community clients' shapes.

use super::*;

pub(crate) mod build {
    //! Builders shared by the tests (and mirrored in the fuzz seeds).

    /// A STUN message (`class` bits from `t`), attributes TLV-padded, with
    /// an optional valid FINGERPRINT.
    pub fn stun(t: u16, attrs: &[(u16, &[u8])], fingerprint: bool) -> Vec<u8> {
        let mut body = Vec::new();
        for (ty, v) in attrs {
            body.extend_from_slice(&ty.to_be_bytes());
            body.extend_from_slice(&(v.len() as u16).to_be_bytes());
            body.extend_from_slice(v);
            while body.len() % 4 != 0 {
                body.push(0);
            }
        }
        let mut m = Vec::new();
        m.extend_from_slice(&t.to_be_bytes());
        let len = body.len() + if fingerprint { 8 } else { 0 };
        m.extend_from_slice(&(len as u16).to_be_bytes());
        m.extend_from_slice(&0x2112_A442u32.to_be_bytes());
        m.extend_from_slice(&[7u8; 12]);
        m.extend_from_slice(&body);
        if fingerprint {
            let crc = super::super::crc32_ieee(&m) ^ 0x5354_554e;
            m.extend_from_slice(&0x8028u16.to_be_bytes());
            m.extend_from_slice(&4u16.to_be_bytes());
            m.extend_from_slice(&crc.to_be_bytes());
        }
        m
    }

    /// ICE binding request from the controlling peer.
    pub fn binding_request(user: &str) -> Vec<u8> {
        stun(
            0x0001,
            &[
                (0x0006, user.as_bytes()),
                (0x0024, &[0, 0, 0, 1]),
                (0x802A, &[1; 8]),
                (0x0025, &[]),
                (0x0008, &[0; 20]),
            ],
            true,
        )
    }

    pub fn binding_success() -> Vec<u8> {
        stun(
            0x0101,
            &[
                (0x0020, &[0, 1, 0x30, 0x39, 1, 2, 3, 4]),
                (0x0008, &[0; 20]),
            ],
            true,
        )
    }

    /// A DTLS 1.2 record (`ty`, `epoch`) with `body`.
    pub fn dtls(ty: u8, epoch: u16, body: &[u8]) -> Vec<u8> {
        let mut r = vec![ty, 0xFE, 0xFD];
        r.extend_from_slice(&epoch.to_be_bytes());
        r.extend_from_slice(&[0, 0, 0, 0, 0, 1]);
        r.extend_from_slice(&(body.len() as u16).to_be_bytes());
        r.extend_from_slice(body);
        r
    }

    pub fn client_hello() -> Vec<u8> {
        dtls(22, 0, &[1, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 40])
    }

    pub fn server_hello() -> Vec<u8> {
        let mut d = dtls(22, 0, &[2, 0, 0, 38, 0, 0, 0, 0, 0, 0, 0, 38]);
        d.extend(dtls(22, 0, &[11, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1]));
        d
    }

    pub fn app_data() -> Vec<u8> {
        dtls(23, 1, &[0xAB; 48])
    }

    pub fn http(head: &str, body: &[u8]) -> Vec<u8> {
        let mut v = head.replace('\n', "\r\n").into_bytes();
        v.extend_from_slice(b"\r\n");
        v.extend_from_slice(body);
        v
    }

    pub const SDP: &str = "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n\
a=group:BUNDLE 0 1\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\nc=IN IP4 0.0.0.0\r\n\
a=ice-ufrag:AbCd\r\na=ice-pwd:secretsecretsecretsecret12\r\n\
a=fingerprint:sha-256 01:02:03\r\na=setup:actpass\r\n\
a=candidate:1 1 udp 2130706431 192.168.123.20 50000 typ host\r\n\
a=candidate:2 1 udp 1694498815 203.0.113.9 50001 typ srflx raddr 0.0.0.0 rport 0\r\n\
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";

    pub fn legacy_offer() -> Vec<u8> {
        let body = serde_json::json!({
            "id": "STA_localNetwork", "sdp": SDP, "type": "offer", "token": "tok-value-xyz"
        })
        .to_string();
        http(
            &format!(
                "POST /offer HTTP/1.1\nHost: 192.168.123.161:8081\nContent-Type: \
                 application/json\nContent-Length: {}\n",
                body.len()
            ),
            body.as_bytes(),
        )
    }

    pub fn base64(b: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for c in b.chunks(3) {
            let n = (u32::from(c[0]) << 16)
                | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
                | u32::from(*c.get(2).unwrap_or(&0));
            for i in 0..4 {
                if i <= c.len() {
                    s.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    s.push('=');
                }
            }
        }
        s
    }
}

use build::*;

const ROBOT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 123, 161));
const OPERATOR: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 123, 20));
const INTRUDER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 123, 66));
const MAC_OP: [u8; 6] = [2, 0, 0, 0, 0, 0x20];
const S: u64 = 1_000_000_000;
/// 2026-10-28 (a Wednesday) 12:00 UTC.
const NOON_WED: u64 = 1_793_188_800 * S;

fn pkt<'a>(
    t: u64,
    l4: L4,
    from: (IpAddr, u16),
    to: (IpAddr, u16),
    mac: Option<[u8; 6]>,
    payload: &'a [u8],
) -> FlowPacket<'a> {
    FlowPacket {
        wall_ns: NOON_WED + t,
        mono_ns: 10 * S + t,
        l4,
        src: from.0,
        src_port: from.1,
        dst: to.0,
        dst_port: to.1,
        src_mac: mac,
        payload,
    }
}

/// A full local session from `peer`: legacy offer, answer, ICE, DTLS,
/// SRTP. Returns every finding.
fn session(m: &mut WebRtcMonitor, peer: IpAddr, mac: Option<[u8; 6]>, t0: u64) -> Vec<Deviation> {
    let mut out = Vec::new();
    let offer = legacy_offer();
    let answer = http("HTTP/1.1 200 OK\nContent-Length: 2\n", b"{}");
    let req = binding_request("RoBo:AbCd");
    let ok = binding_success();
    let ch = client_hello();
    let sh = server_hello();
    let ad = app_data();
    let rtp = [0x80u8, 96, 0, 1, 0, 0, 0, 1, 0, 0, 0, 9, 1, 2, 3, 4];
    let steps: Vec<(L4, bool, u16, u16, &[u8])> = vec![
        (L4::Tcp, true, 51000, 8081, &offer),
        (L4::Tcp, false, 51000, 8081, &answer),
        (L4::Udp, true, 50000, 40000, &req),
        (L4::Udp, false, 50000, 40000, &ok),
        (L4::Udp, true, 50000, 40000, &ch),
        (L4::Udp, false, 50000, 40000, &sh),
        (L4::Udp, true, 50000, 40000, &ad),
        (L4::Udp, false, 50000, 40000, &ad),
        (L4::Udp, false, 50000, 40000, &rtp),
    ];
    for (i, (l4, inbound, pp, rp, payload)) in steps.into_iter().enumerate() {
        let t = t0 + i as u64 * 10_000_000;
        let p = if inbound {
            pkt(t, l4, (peer, pp), (ROBOT, rp), mac, payload)
        } else {
            pkt(t, l4, (ROBOT, rp), (peer, pp), None, payload)
        };
        out.extend(m.process(&p));
    }
    out
}

fn rules_of(d: &[Deviation]) -> Vec<(String, Severity)> {
    d.iter()
        .map(|d| (d.rule_str().to_string(), d.severity))
        .collect()
}

fn enabled() -> WebRtcOptions {
    WebRtcOptions {
        enabled: true,
        ..Default::default()
    }
}

#[test]
fn stun_parses_ice_checks_and_verifies_the_fingerprint() {
    let r = binding_request("RoBo:AbCd");
    let s = parse_stun(&r).unwrap();
    assert_eq!(
        (s.class, s.method),
        (StunClass::Request, stun_method::BINDING)
    );
    assert_eq!(s.username, Some("RoBo:AbCd"));
    assert!(s.ice_controlling && s.use_candidate && s.message_integrity);
    assert_eq!(s.fingerprint_ok, Some(true));
    let okb = binding_success();
    let ok = parse_stun(&okb).unwrap();
    assert_eq!(ok.class, StunClass::Success);
    // Class / method bit interleaving (RFC 8489 §5): Allocate request
    // 0x0003, ChannelBind success 0x0109, Data indication 0x0017.
    for (t, c, m) in [
        (0x0003, StunClass::Request, stun_method::ALLOCATE),
        (0x0109, StunClass::Success, stun_method::CHANNEL_BIND),
        (0x0017, StunClass::Indication, stun_method::DATA),
        (0x0111, StunClass::Error, stun_method::BINDING),
    ] {
        let b = stun(t, &[], false);
        let s = parse_stun(&b).unwrap();
        assert_eq!((s.class, s.method), (c, m), "{t:#x}");
    }
    // Adversarial: a flipped bit breaks the fingerprint; truncation,
    // a wrong cookie, a length not matching, a non-tiling attribute and
    // top bits set are not STUN.
    let mut bad = r.clone();
    bad[30] ^= 1;
    assert_eq!(parse_stun(&bad).unwrap().fingerprint_ok, Some(false));
    for n in 0..r.len() {
        assert!(parse_stun(&r[..n]).is_none(), "{n}");
    }
    let mut cookie = r.clone();
    cookie[4] ^= 1;
    assert!(parse_stun(&cookie).is_none());
    let mut long = r.clone();
    long.extend_from_slice(&[0; 4]);
    assert!(parse_stun(&long).is_none());
    let mut top = r.clone();
    top[0] |= 0x80;
    assert!(parse_stun(&top).is_none());
    let mut over = stun(0x0001, &[(0x0006, b"abcd")], false);
    over[22..24].copy_from_slice(&200u16.to_be_bytes());
    assert!(parse_stun(&over).is_none());
    // FINGERPRINT not last: refused.
    let mut fp_mid = stun(0x0001, &[(0x8028, &[0; 4]), (0x0006, b"ab")], false);
    let n = (fp_mid.len() - 20) as u16;
    fp_mid[2..4].copy_from_slice(&n.to_be_bytes());
    assert!(parse_stun(&fp_mid).is_none());
    // Non-UTF-8 username: no username, still STUN.
    let s = stun(0x0001, &[(0x0006, &[0xff, 0xfe])], false);
    assert_eq!(parse_stun(&s).unwrap().username, None);
}

#[test]
fn dtls_records_are_classified_from_headers_only() {
    let ch = parse_dtls(&client_hello()).unwrap();
    assert!(ch.client_hello && !ch.server_hello && !ch.encrypted);
    let sh = parse_dtls(&server_hello()).unwrap();
    assert!(sh.server_hello && sh.records == 2);
    let ad = parse_dtls(&app_data()).unwrap();
    assert!(ad.encrypted);
    // A handshake record in epoch 1 is encrypted (its type byte is
    // ciphertext): not a hello.
    let enc_hs = parse_dtls(&dtls(22, 1, &[1, 2, 3])).unwrap();
    assert!(!enc_hs.client_hello && enc_hs.encrypted);
    // Truncated first record / wrong version: not DTLS. A broken second
    // record: truncated, first kept.
    let c = client_hello();
    for n in 0..c.len() {
        assert!(parse_dtls(&c[..n]).is_none(), "{n}");
    }
    let mut v10 = c.clone();
    v10[2] = 0xFF;
    assert!(parse_dtls(&v10).is_some(), "DTLS 1.0 version FE FF");
    let mut tls = c.clone();
    tls[1] = 0x03;
    assert!(parse_dtls(&tls).is_none(), "TLS, not DTLS");
    let mut two = client_hello();
    two.extend_from_slice(&[22, 0xFE, 0xFD, 0]);
    let t = parse_dtls(&two).unwrap();
    assert!(t.client_hello && t.truncated && t.records == 1);
    assert!(matches!(classify_udp(&client_hello()), UdpClass::Dtls(_)));
    assert!(matches!(
        classify_udp(&binding_success()),
        UdpClass::Stun(_)
    ));
    assert_eq!(
        classify_udp(&[0x80, 96, 0, 1, 0, 0, 0, 1]),
        UdpClass::Rtp { rtcp: false }
    );
    assert_eq!(
        classify_udp(&[0x80, 200, 0, 1, 0, 0, 0, 1]),
        UdpClass::Rtp { rtcp: true }
    );
    assert_eq!(
        classify_udp(&[0x40, 0, 0, 4, 1, 2, 3, 4]),
        UdpClass::ChannelData
    );
    assert_eq!(classify_udp(&[0x40, 0, 0, 9, 1]), UdpClass::Other);
    assert_eq!(classify_udp(b"RTPS\x02\x01"), UdpClass::Other);
    assert_eq!(classify_udp(&[]), UdpClass::Other);
}

#[test]
fn signalling_is_classified_and_only_metadata_is_kept() {
    let offer = legacy_offer();
    let r = parse_http_request(&offer).unwrap();
    assert_eq!((r.method, r.path), ("POST", "/offer"));
    let m = classify_signalling(&r);
    assert_eq!(m.kind, SignallingKind::LegacyOffer);
    let sdp = m.sdp.as_ref().unwrap();
    assert_eq!(sdp.ice_ufrag.as_deref(), Some("AbCd"));
    assert_eq!(sdp.fingerprint_hash.as_deref(), Some("sha-256"));
    assert_eq!(
        sdp.candidates,
        vec![
            ("host".to_string(), "192.168.123.20".to_string()),
            ("srflx".to_string(), "203.0.113.9".to_string())
        ]
    );
    assert_eq!(
        sdp.media,
        vec!["video".to_string(), "application".to_string()]
    );
    // The token is reported by length only, the ICE password never.
    assert_eq!(m.token_len, Some(13));
    let shown = format!("{m:?}");
    assert!(!shown.contains("tok-value-xyz") && !shown.contains("secretsecret"));
    // A body split over segments: kind known, no SDP.
    let cut = &offer[..offer.len() - 10];
    let m = classify_signalling(&parse_http_request(cut).unwrap());
    assert_eq!(
        (m.kind, m.sdp.is_none()),
        (SignallingKind::LegacyOffer, true)
    );
    for (head, kind) in [
        (
            "POST /con_notify HTTP/1.1\nContent-Length: 0\n",
            SignallingKind::ConNotify,
        ),
        (
            "POST /con_ing_a1b2c3d4e5 HTTP/1.1\nContent-Length: 0\n",
            SignallingKind::ConIng,
        ),
        (
            "GET / HTTP/1.1\nUpgrade: websocket\nConnection: Upgrade\n",
            SignallingKind::WebSocket,
        ),
        ("GET /index.html HTTP/1.1\n", SignallingKind::OtherHttp),
    ] {
        let b = http(head, b"");
        assert_eq!(
            classify_signalling(&parse_http_request(&b).unwrap()).kind,
            kind,
            "{head}"
        );
    }
    // Not HTTP / incomplete head / control bytes: nothing.
    for bad in [
        &b"POST /offer HTTP/1.1\r\nHost: x\r\n"[..],
        b"post /offer HTTP/1.1\r\n\r\n",
        b"POST offer HTTP/1.1\r\n\r\n",
        b"POST /offer HTTP/2\r\n\r\n",
        b"POST /of\x01fer HTTP/1.1\r\n\r\n",
        b"",
    ] {
        assert!(parse_http_request(bad).is_none(), "{bad:?}");
    }
    let many: String = (0..80).map(|i| format!("X-{i}: y\n")).collect();
    assert!(parse_http_request(&http(&format!("GET / HTTP/1.1\n{many}"), b"")).is_none());
    // The robot's con_notify answer: member names and lengths only.
    let answer = base64(br#"{"data1":"PUBLICKEYPUBLICKEYPUBLICKEY0123456789","data2":2}"#);
    let members = con_notify_answer_members(answer.as_bytes()).unwrap();
    assert_eq!(members, vec![("data1".into(), 37), ("data2".into(), 0)]);
    assert!(con_notify_answer_members(b"!!!").is_none());
    assert!(con_notify_answer_members(base64(b"[1,2]").as_bytes()).is_none());
    assert_eq!(base64_decode(b"aGk=").unwrap(), b"hi");
    assert_eq!(base64_decode(b"aGk").unwrap(), b"hi");
    assert!(base64_decode(b"a").is_none());
    let resp = http("HTTP/1.1 200 OK\nContent-Length: 2\n", b"{}");
    assert_eq!(parse_http_response(&resp).unwrap().status, 200);
    assert!(parse_http_response(b"HTTP/1.1 2000 OK\r\n\r\n").is_none());
}

#[test]
fn ipv4_flows_decode_strictly() {
    let udp = robodr_capture::synth::ipv4_udp(
        Ipv4Addr::new(192, 168, 123, 20),
        Ipv4Addr::new(192, 168, 123, 161),
        50000,
        40000,
        b"abc",
    );
    let (l4, s, sp, d, dp, pl) = decode_ipv4(&udp).unwrap();
    assert_eq!((l4, sp, dp, pl), (L4::Udp, 50000, 40000, &b"abc"[..]));
    assert_eq!((IpAddr::V4(s), IpAddr::V4(d)), (OPERATOR, ROBOT));
    for n in 0..udp.len() {
        assert!(decode_ipv4(&udp[..n]).is_none() || n >= 28, "{n}");
    }
    let mut frag = udp.clone();
    frag[6] = 0x20; // MF
    assert!(decode_ipv4(&frag).is_none());
    // TCP with a 20-byte header.
    let mut tcp = udp.clone();
    tcp[9] = 6;
    let mut seg = vec![0u8; 20];
    seg[0..2].copy_from_slice(&51000u16.to_be_bytes());
    seg[2..4].copy_from_slice(&8081u16.to_be_bytes());
    seg[12] = 5 << 4;
    seg.extend_from_slice(b"GET");
    tcp.truncate(20);
    tcp.extend_from_slice(&seg);
    let total = tcp.len() as u16;
    tcp[2..4].copy_from_slice(&total.to_be_bytes());
    let (l4, _, sp, _, dp, pl) = decode_ipv4(&tcp).unwrap();
    assert_eq!((l4, sp, dp, pl), (L4::Tcp, 51000, 8081, &b"GET"[..]));
    tcp[32] = 4 << 4; // data offset < 5
    assert!(decode_ipv4(&tcp).is_none());
}

#[test]
fn deny_windows_parse_and_wrap_over_midnight() {
    let w = DenyWindow::parse("mon-fri 18:00-06:00").unwrap();
    assert_eq!((w.days, w.start_min, w.end_min), (0b0001_1111, 1080, 360));
    let h = 3_600 * S;
    assert!(!w.contains(NOON_WED));
    assert!(w.contains(NOON_WED + 7 * h)); // Wed 19:00
    assert!(w.contains(NOON_WED + 15 * h)); // Thu 03:00 (window of Wed)
                                            // Sat 03:00 belongs to Friday's window; Sun 03:00 to none.
    assert!(w.contains(NOON_WED + (2 * 24 + 15) * h));
    assert!(!w.contains(NOON_WED + (3 * 24 + 15) * h));
    assert!(!w.contains(NOON_WED + (4 * 24 + 15) * h));
    let every = DenyWindow::parse("11:30-12:30").unwrap();
    assert!(every.contains(NOON_WED) && every.days == 0);
    let wk = DenyWindow::parse("sat,sun 00:00-23:59").unwrap();
    assert_eq!(wk.days, 0b0110_0000);
    for bad in [
        "",
        "18:00",
        "25:00-01:00",
        "10:00-10:00",
        "xyz 01:00-02:00",
        "1:00-2:00",
    ] {
        assert!(DenyWindow::parse(bad).is_err(), "{bad}");
    }
}

#[test]
fn a_listed_controller_session_is_quiet_and_tracked() {
    let mut opts = enabled();
    opts.controllers.insert(OPERATOR, Some(MAC_OP));
    let mut m = WebRtcMonitor::new(opts);
    let f = session(&mut m, OPERATOR, Some(MAC_OP), 0);
    assert!(f.is_empty(), "{:?}", rules_of(&f));
    let s = m.session(&OPERATOR).unwrap();
    assert_eq!(s.state, SessionState::Established);
    assert_eq!(s.signalling, vec![SignallingKind::LegacyOffer]);
    assert!(s.answered && s.client_hello && s.server_hello);
    assert_eq!(
        s.flows.iter().copied().collect::<Vec<_>>(),
        vec![(50000, 40000)]
    );
    assert_eq!(
        s.flows_text(),
        "192.168.123.20:50000 <-> 192.168.123.161:40000"
    );
    assert_eq!(s.sdp.as_ref().unwrap().ice_ufrag.as_deref(), Some("AbCd"));
    assert_eq!(s.mac.as_deref(), Some("02:00:00:00:00:20"));
    assert_eq!(m.stats.sessions_established, 1);
    // Idle: the session ends.
    m.expire(10 * S + 31 * S);
    assert!(m.session(&OPERATOR).is_none());
    assert_eq!(m.stats.sessions_ended, 1);
}

#[test]
fn unexpected_controllers_raise_findings() {
    let mut opts = enabled();
    opts.controllers.insert(OPERATOR, Some(MAC_OP));
    let mut m = WebRtcMonitor::new(opts);
    let _ = session(&mut m, OPERATOR, Some(MAC_OP), 0);
    // An unlisted peer: attempt (High), then established (Critical), and
    // a second concurrent session.
    let f = session(&mut m, INTRUDER, Some([2, 0, 0, 0, 0, 0x66]), S);
    let r = rules_of(&f);
    assert!(
        r.contains(&(rules::UNKNOWN_CONTROLLER.into(), Severity::High)),
        "{r:?}"
    );
    assert!(
        r.contains(&(rules::UNKNOWN_CONTROLLER.into(), Severity::Critical)),
        "{r:?}"
    );
    assert!(
        r.contains(&(rules::CONCURRENT_SESSIONS.into(), Severity::High)),
        "{r:?}"
    );
    let crit = f.iter().find(|d| d.severity == Severity::Critical).unwrap();
    assert!(
        crit.detail
            .contains("192.168.123.66:50000 <-> 192.168.123.161:40000"),
        "{}",
        crit.detail
    );
    // Deduplicated: the same session again raises nothing new.
    assert!(session(&mut m, INTRUDER, None, 2 * S).is_empty());
    // The listed controller's IP from another MAC.
    let mut m2 = WebRtcMonitor::new(m.options().clone());
    let f = session(&mut m2, OPERATOR, Some([2, 0, 0, 0, 0, 0x99]), 0);
    let r = rules_of(&f);
    assert_eq!(
        r,
        vec![(rules::CONTROLLER_MAC_MISMATCH.into(), Severity::High)],
        "{r:?}"
    );
}

#[test]
fn learn_mode_reports_each_new_peer_once() {
    let mut m = WebRtcMonitor::new(enabled());
    let f = session(&mut m, OPERATOR, None, 0);
    assert_eq!(
        rules_of(&f),
        vec![(rules::NEW_PEER.into(), Severity::Medium)]
    );
    m.expire(u64::MAX);
    assert!(
        session(&mut m, OPERATOR, None, 100 * S).is_empty(),
        "known peer"
    );
}

#[test]
fn denied_window_media_without_signalling_and_relay() {
    let mut opts = enabled();
    opts.controllers.insert(OPERATOR, None);
    opts.deny_windows
        .push(DenyWindow::parse("11:00-13:00").unwrap());
    let mut m = WebRtcMonitor::new(opts.clone());
    let f = session(&mut m, OPERATOR, None, 0);
    let r = rules_of(&f);
    assert_eq!(
        r,
        vec![(rules::SESSION_IN_DENIED_WINDOW.into(), Severity::High)],
        "{r:?}"
    );
    // ICE + DTLS without signalling on the link.
    opts.deny_windows.clear();
    let mut m = WebRtcMonitor::new(opts.clone());
    let req = binding_request("RoBo:AbCd");
    let (ch, sh) = (client_hello(), server_hello());
    let mut f = Vec::new();
    for (inb, p) in [(true, &req), (true, &ch), (false, &sh)] {
        let p = if inb {
            pkt(0, L4::Udp, (OPERATOR, 50000), (ROBOT, 40000), None, p)
        } else {
            pkt(0, L4::Udp, (ROBOT, 40000), (OPERATOR, 50000), None, p)
        };
        f.extend(m.process(&p));
    }
    assert_eq!(
        rules_of(&f),
        vec![(rules::MEDIA_WITHOUT_SIGNALLING.into(), Severity::Medium)]
    );
    // The robot allocating on a TURN relay outside the local networks.
    let relay = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));
    let alloc = stun(0x0003, &[], true);
    let mut m = WebRtcMonitor::new(opts);
    let f = m.process(&pkt(
        0,
        L4::Udp,
        (ROBOT, 40001),
        (relay, 3478),
        None,
        &alloc,
    ));
    let r = rules_of(&f);
    assert!(
        r.contains(&(rules::RELAYED_SESSION.into(), Severity::Medium)),
        "{r:?}"
    );
    assert!(
        r.contains(&(rules::UNKNOWN_CONTROLLER.into(), Severity::High)),
        "{r:?}"
    );
    assert!(m.session(&relay).unwrap().relayed);
}

#[test]
fn unrelated_traffic_and_disabled_monitor_are_ignored() {
    let mut m = WebRtcMonitor::new(WebRtcOptions::default());
    let req = binding_request("a:b");
    assert!(m
        .process(&pkt(0, L4::Udp, (INTRUDER, 1), (ROBOT, 2), None, &req))
        .is_empty());
    assert_eq!(m.stats.packets, 0);
    let mut m = WebRtcMonitor::new(enabled());
    // Not to / from the robot; robot to robot; TCP on another port; SRTP
    // or an HTTP response from an unknown peer: nothing starts.
    let other = IpAddr::V4(Ipv4Addr::new(192, 168, 123, 30));
    assert!(m
        .process(&pkt(0, L4::Udp, (INTRUDER, 1), (other, 2), None, &req))
        .is_empty());
    assert!(m
        .process(&pkt(0, L4::Udp, (ROBOT, 1), (ROBOT, 2), None, &req))
        .is_empty());
    let get = http("GET / HTTP/1.1\n", b"");
    assert!(m
        .process(&pkt(0, L4::Tcp, (INTRUDER, 1), (ROBOT, 80), None, &get))
        .is_empty());
    let rtp = [0x80u8, 96, 0, 1, 0, 0, 0, 1, 0, 0, 0, 9];
    assert!(m
        .process(&pkt(0, L4::Udp, (ROBOT, 1), (INTRUDER, 2), None, &rtp))
        .is_empty());
    let resp = http("HTTP/1.1 200 OK\n", b"");
    assert!(m
        .process(&pkt(0, L4::Tcp, (ROBOT, 8081), (INTRUDER, 2), None, &resp))
        .is_empty());
    assert_eq!(m.sessions().count(), 0);
}

#[test]
fn memory_is_bounded_under_a_spoofed_peer_flood() {
    let mut opts = enabled();
    opts.controllers.insert(OPERATOR, None);
    let mut m = WebRtcMonitor::new(opts);
    let req = binding_request("x:y");
    let mut n = 0usize;
    for i in 0..5000u32 {
        let peer = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i));
        for d in m.process(&pkt(
            u64::from(i),
            L4::Udp,
            (peer, 5),
            (ROBOT, 6),
            None,
            &req,
        )) {
            assert!(d.rule_str().starts_with("robot.unitree.webrtc_"));
            n += 1;
        }
    }
    assert!(m.sessions().count() <= DEFAULT_MAX_PEERS);
    assert!(n <= MAX_REPORTED);
    assert!(m.stats.findings_suppressed > 0 && m.stats.peers_evicted > 0);
}

#[test]
fn parsers_never_panic_on_noise() {
    let mut x = 0x2545_f491_4f6c_dd1du64;
    let seeds = [
        binding_request("a:b"),
        client_hello(),
        legacy_offer(),
        app_data(),
    ];
    let mut m = WebRtcMonitor::new(enabled());
    for i in 0..20_000usize {
        let mut d = seeds[i % seeds.len()].clone();
        for _ in 0..(i % 7) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let at = (x as usize) % d.len().max(1);
            if let Some(b) = d.get_mut(at) {
                *b ^= (x >> 32) as u8;
            }
            if x.is_multiple_of(5) {
                d.truncate(at);
            }
        }
        let _ = classify_udp(&d);
        let _ = parse_http_request(&d);
        let _ = parse_http_response(&d);
        let _ = decode_ipv4(&d);
        let _ = con_notify_answer_members(&d);
        let l4 = if i % 2 == 0 { L4::Udp } else { L4::Tcp };
        let _ = m.process(&pkt(i as u64, l4, (INTRUDER, 1), (ROBOT, 8081), None, &d));
    }
}
