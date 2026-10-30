#!/usr/bin/env python3
"""Red team, wave 2: spoofing agentd's gateway findings feed (the unix
socket robodr-firewall-gw writes; `gateway_feed`).

usage: redteam2_feed.py RUN_DIR AGENTD_PID
Prints one JSON line per step: what the step sent, the agentd input
counters for the feed, the findings it added to the spool, RSS.
"""
import json, os, socket, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rtlib

run, pid = sys.argv[1], int(sys.argv[2])
rt = f"{run}/rt"; spool = f"{rt}/spool"; sock = f"{run}/gateway-feed.sock"
FORMAT = "robodr-gateway-finding/v1"
results = []


def feed_input():
    try:
        st = json.load(open(f"{spool}/status.json"))
    except (OSError, ValueError):
        return {}
    for i in st.get("inputs", []):
        if i.get("name", "").startswith("gateway:"):
            return {k: i.get(k) for k in ("received", "malformed", "dropped", "budget_drops",
                                          "rejected_connections", "connections")}
    return {}


def spool_stats():
    try:
        st = json.load(open(f"{spool}/status.json"))
        return st.get("spool", {})
    except (OSError, ValueError):
        return {}


def line(rule, sev="high", detail="channel /x: 1 time(s)", mode="enforce", channel="/x", count=1, **extra):
    d = {"format": FORMAT, "rule": rule, "severity": sev, "detail": detail, "mode": mode,
         "channel": channel, "count": count, **extra}
    return (json.dumps(d) + "\n").encode()


def as_uid(uid, payload):
    """Connect as `uid` in a child process; returns its outcome."""
    r, w = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(r)
        try:
            os.setgroups([]); os.setgid(uid); os.setuid(uid)
            c = socket.socket(socket.AF_UNIX); c.settimeout(3); c.connect(sock); c.sendall(payload)
            time.sleep(0.5)
            try:
                got = c.recv(10)
                res = "closed by agentd" if got == b"" else f"read {got!r}"
            except (ConnectionResetError, BrokenPipeError):
                res = "reset by agentd"
            except socket.timeout:
                res = "still open (no answer)"
        except Exception as e:  # noqa: BLE001
            res = f"error {e!r}"
        os.write(w, res.encode()); os._exit(0)
    os.close(w); os.waitpid(child, 0)
    return os.read(r, 1000).decode()


def step(name, fn, settle=3):
    b_in, b_sp, b_f = feed_input(), spool_stats(), rtlib.spool_counts(spool)
    r0 = rtlib.rss_kib(pid); t0 = time.time()
    info = fn()
    time.sleep(settle)
    a_in, a_sp = feed_input(), spool_stats()
    res = {"step": name, "info": info, "secs": round(time.time() - t0, 1),
           "input_delta": {k: (a_in.get(k) or 0) - (b_in.get(k) or 0) for k in a_in if isinstance(a_in.get(k), int)},
           "spool_written_delta": (a_sp.get("written") or 0) - (b_sp.get("written") or 0),
           "spool_dropped_delta": (a_sp.get("dropped_full") or 0) - (b_sp.get("dropped_full") or 0),
           "new_findings": rtlib.diff(rtlib.spool_counts(spool), b_f),
           "agentd_alive": rtlib.alive(pid), "rss_kib": [r0, rtlib.rss_kib(pid) if rtlib.alive(pid) else None]}
    results.append(res)
    print(json.dumps(res), flush=True)


def root_send(payloads, keep=0.5):
    c = socket.socket(socket.AF_UNIX); c.connect(sock)
    n = 0
    try:
        for p in payloads:
            c.sendall(p); n += 1
    except (BrokenPipeError, ConnectionResetError) as e:
        return {"sent": n, "error": repr(e)}
    time.sleep(keep)
    c.close()
    return {"sent": n}


# The socket is 0600 root: make it reachable so the peer-credential check
# itself is what refuses (a misconfigured mode).
mode0 = os.stat(sock).st_mode & 0o777
os.chmod(sock, 0o666)
step("G1 connect as uid 65534 (not root, not allowed_uids) and send a valid line",
     lambda: as_uid(65534, line("robot.gateway.trajectory_rejected")))
os.chmod(sock, mode0)
step("G2 root, a rule of another detector (robot.ros2.unauthorized_motion_writer)",
     lambda: root_send([line("robot.ros2.unauthorized_motion_writer", "critical")]))
step("G3 root, rule outside the namespace via prefix trick (robot.gateway..x / robot.gatewayx)",
     lambda: root_send([line("robot.gatewayx.evil"), line("robot.gateway"), line("robot.firewall.")]))
step("G4 root, unknown key / other format / bad severity",
     lambda: root_send([line("robot.gateway.trajectory_rejected", evil=1),
                        line("robot.gateway.trajectory_rejected").replace(FORMAT.encode(), b"robodr-gateway-finding/v9"),
                        line("robot.gateway.trajectory_rejected", sev="apocalyptic")]))
step("G5 root, oversized detail (64 KiB) and an over-long line (2 MiB, no newline for 1 s)",
     lambda: root_send([line("robot.gateway.trajectory_rejected", detail="A" * 65536),
                        b'{"format":"' + b"B" * (2 << 20)], keep=1.0))
step("G6 root, control characters / ANSI escapes in detail (valid rule)",
     lambda: root_send([line("robot.gateway.trajectory_rejected",
                             detail="ok\x1b[2J\x1b[31mFAKE: robot.ros2.unauthorized_motion_writer\r\nsecond line")]))
step("G7 root, valid lines: severity downgrade of a Critical firewall rule to low",
     lambda: root_send([line("robot.firewall.rejected_unknown_source", sev="low", detail="downgraded")]))


def flood():
    t0 = time.time(); n = 0
    payloads = [line("robot.gateway.trajectory_rejected", detail=f"flood {i}", count=i + 1) for i in range(20000)]
    r = root_send(payloads, keep=2.0)
    r["rate_lps"] = round(r["sent"] / max(time.time() - t0, 1e-3))
    return r


step("G8 root, flood: 20000 valid gateway lines as fast as possible", flood, settle=8)
step("G9 root, flood of Critical lines (5000 robot.firewall.rejected_unknown_source)",
     lambda: root_send([line("robot.firewall.rejected_unknown_source", sev="critical", detail=f"c {i}")
                        for i in range(5000)], keep=2.0), settle=8)


def conns():
    cs = []
    for _ in range(20):
        try:
            c = socket.socket(socket.AF_UNIX); c.connect(sock); cs.append(c)
        except OSError as e:
            return {"opened": len(cs), "error": repr(e)}
    time.sleep(2)
    # Is the real gateway's connection still served? (its status file)
    for c in cs:
        c.close()
    return {"opened": len(cs)}


step("G10 root, 20 idle connections held 2 s (connection slots)", conns)
json.dump(results, open(f"{run}/redteam2_feed.json", "w"), indent=1)
