#!/usr/bin/env python3
"""Red-team, network side, against agentd rt-ugv-001 (capture rob-rt in
netns rdr-rob; attacker on gen-rt in netns rdr-gen).

usage: redteam_net.py RT_DIR AGENTD_PID STEP...   (steps: rogue spray malformed safety)
Prints, per step, the findings it added to the spool and the daemon's state.
"""
import json, os, random, socket, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcaplib, rtlib

rt, pid = sys.argv[1], int(sys.argv[2])
steps = sys.argv[3:]
F = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../fixtures/captures/ros2-jazzy/")
spool = os.path.join(rt, "spool")
s = rtlib.packet_socket(os.environ.get("RT_GEN_NS", "rdr-gen"), "gen-rt")
rogue_pcap, _ = pcaplib.read(F + "fastrtps_gz_rogue_cmd_vel.pcap")
base_pcap, _ = pcaplib.read(F + "fastrtps_gz_baseline.pcap")
profile = json.load(open(os.path.join(rt, "locked.json")))
known = {bytes.fromhex(p) for p in profile["participants"]}


def status():
    try:
        return json.load(open(os.path.join(spool, "status.json")))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def step(name, fn, settle=4):
    before = rtlib.spool_counts(spool); r0 = rtlib.rss_kib(pid); t0 = time.time()
    info = fn()
    time.sleep(settle)
    after = rtlib.spool_counts(spool)
    st = status()
    print(json.dumps({"step": name, "info": info, "new_findings": rtlib.diff(after, before),
                      "agentd_alive": rtlib.alive(pid), "rss_kib_before": r0,
                      "rss_kib_after": rtlib.rss_kib(pid) if rtlib.alive(pid) else None,
                      "state": st.get("state"), "safety_state": st.get("safety_state"),
                      "secs": round(time.time() - t0, 1)}), flush=True)
    return after


def replay(frames, speed=1.0):
    t0 = frames[0][0]; w0 = time.monotonic()
    for t, fr in frames:
        d = w0 + (t - t0) / speed - time.monotonic()
        if d > 0:
            time.sleep(d)
        s.send(fr)
    return {"frames": len(frames)}


def spdp_template():
    for _, fr in rogue_pcap:
        i, pre = rtlib.rtps_prefix(fr)
        if pre and pre not in known and fr[14 + 9] == 17:
            _, _, udp, _ = rtlib.split(fr)
            if struct_port(udp) == 7400:
                return fr
    raise SystemExit("no rogue SPDP frame")


def struct_port(udp):
    return int.from_bytes(udp[2:4], "big")


def rogue():
    # Baseline first (discovery of the robot's own participants), then the
    # lab rogue run: a foreign participant publishing /cmd_vel at 3 m/s.
    replay(base_pcap, speed=4.0)
    return replay(rogue_pcap, speed=1.0)


def spray():
    tpl = spdp_template()
    n = 3000
    frames = [rtlib.with_prefix(tpl, random.randbytes(12)) for _ in range(n)]
    frames = [rtlib.build(*rtlib.split(f)) for f in frames]
    t = time.time(); rtlib.send(s, frames, pps=1000)
    return {"spdp_frames": n, "distinct_guid_prefixes": n, "rate_pps": round(n / (time.time() - t))}


def malformed():
    tpl = spdp_template()
    eth, ip, udp, payload = rtlib.split(tpl)
    i = payload.find(b"RTPS")
    out = []
    # truncated RTPS headers
    out += [rtlib.build(eth, ip, udp, payload[: i + k]) for k in range(1, 20)] * 10
    # first submessage length past the datagram
    bad = bytearray(payload); bad[i + 22:i + 24] = b"\xff\xff"; out += [rtlib.build(eth, ip, udp, bytes(bad))] * 100
    # random bytes behind a valid RTPS header
    out += [rtlib.build(eth, ip, udp, payload[: i + 20] + random.randbytes(random.randint(1, 1400))) for _ in range(1000)]
    # submessage ids / flags randomised in place
    for _ in range(1000):
        b = bytearray(payload)
        for _ in range(8):
            j = random.randrange(i + 20, len(b)); b[j] = random.randrange(256)
        out.append(rtlib.build(eth, ip, udp, bytes(b)))
    rtlib.send(s, out, pps=2000)
    # oversized: 60 KiB RTPS datagrams, IP-fragmented, and an incomplete one
    big = payload[: i + 20] + random.randbytes(60_000)
    frags = []
    for k in range(20):
        frags += rtlib.fragments(eth, ip, udp, big, ident=0x5000 + k)
    frags += rtlib.fragments(eth, ip, udp, big, ident=0x6000)[:-1]  # never completed
    rtlib.send(s, frags, pps=2000)
    # a 64 KiB-1 non-RTPS UDP payload
    rtlib.send(s, rtlib.fragments(eth, ip, udp, random.randbytes(65_507), ident=0x7000), pps=2000)
    return {"malformed_frames": len(out), "oversized_fragments": len(frags) + 45}


def safety():
    # Robot's own traffic first so SEDP announced /odom (gz_bridge @10.77.10.10).
    replay(base_pcap[: len(base_pcap) // 2], speed=4.0)
    spoof = []
    for t, fr in base_pcap[len(base_pcap) // 2:]:
        eth, ip, udp, payload = rtlib.split(fr)
        if socket.inet_ntoa(ip[12:16]) == "10.77.10.10" and b"RTPS" in payload:
            spoof.append((t, rtlib.build(eth, ip, udp, payload, src="10.99.3.66")))
    info = replay(spoof, speed=1.0)
    # The safety socket from an unprivileged user (mode 0600: refused).
    sock = os.path.join(rt, "safety.sock")
    r = subprocess.run(["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", "python3", "-c",
                        f"import socket;c=socket.socket(socket.AF_UNIX);c.connect({sock!r});"
                        "c.sendall(b'{\"state\":\"idle\"}\\n')"], capture_output=True, text=True)
    info["unprivileged_socket"] = (r.stderr.strip().splitlines() or ["ok"])[-1]
    # Root, malformed and unknown-state lines (counted, never applied).
    c = socket.socket(socket.AF_UNIX); c.connect(sock)
    c.sendall(b'{"state":"idle","extra":1}\n{"state":"teleport"}\nnot json\n'); c.close()
    info["root_bad_lines"] = 3
    return info


for name in steps:
    step(name, globals()[name], settle=6 if name != "spray" else 8)
