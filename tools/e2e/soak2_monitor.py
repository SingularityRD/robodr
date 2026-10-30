#!/usr/bin/env python3
"""Per-interval metrics of the wave-2 soak -> JSON lines.

usage: soak2_monitor.py RUN_DIR OUT.jsonl INTERVAL_S NAME=PIDFILE ...

Per process: RSS (KiB), CPU % over the interval, threads, open fds.
Robot side: agentd spool (ready / acked files, bytes), black box bytes,
agentd status.json counters, the gateway's status.json counters and
latency, the anchor receiver's held seq / alerts, Kafka log bytes and the
publisher's state. Stops when every agentd / gateway process is gone.
"""
import json, os, subprocess, sys, time

run, out, interval = sys.argv[1], sys.argv[2], float(sys.argv[3])
procs = dict(a.split("=", 1) for a in sys.argv[4:])
HZ = os.sysconf("SC_CLK_TCK")
B = os.environ.get("ROBODR_BIN", "/home/user/wt/target-soak/release")


def pid_of(pf):
    try:
        return int(open(pf).read().strip())
    except (OSError, ValueError):
        return None


def proc(pid):
    try:
        st = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
        status = {l.split(":")[0]: l.split(":", 1)[1].strip() for l in open(f"/proc/{pid}/status")}
        return {"rss_kib": int(status["VmRSS"].split()[0]), "threads": int(status["Threads"]),
                "fds": len(os.listdir(f"/proc/{pid}/fd")), "ticks": int(st[11]) + int(st[12])}
    except (OSError, KeyError, IndexError, ValueError):
        return None


def du(d):
    t = n = 0
    for root, _, files in os.walk(d):
        for f in files:
            try:
                t += os.path.getsize(os.path.join(root, f)); n += 1
            except OSError:
                pass
    return t, n


def count(d):
    try:
        return len(os.listdir(d))
    except OSError:
        return 0


def jload(p):
    try:
        return json.load(open(p))
    except (OSError, ValueError):
        return None


def pick(d, keys):
    return {k: d.get(k) for k in keys} if isinstance(d, dict) else None


prev = {}
f = open(out, "a")
t0 = time.time(); tprev = time.monotonic()
while True:
    time.sleep(interval)
    now = time.monotonic(); dt = now - tprev; tprev = now
    row = {"t": round(time.time(), 1), "elapsed_s": int(time.time() - t0), "procs": {}}
    alive = False
    for name, pf in procs.items():
        pid = pid_of(pf); p = proc(pid) if pid else None
        if p:
            if name.startswith(("agentd", "gateway")):
                alive = True
            last = prev.get(name)
            p["cpu_pct"] = round(100 * (p["ticks"] - last[1]) / HZ / dt, 2) if last and last[0] == pid else None
            prev[name] = (pid, p["ticks"])
        row["procs"][name] = p
    ugv = f"{run}/ugv"
    sb, sn = du(f"{ugv}/spool")
    row["spool"] = {"ready": count(f"{ugv}/spool/ready"), "acked": count(f"{ugv}/spool/acked"),
                    "bytes": sb, "files": sn}
    row["blackbox_bytes"] = du(f"{ugv}/blackbox")[0]
    st = jload(f"{ugv}/spool/status.json")
    if isinstance(st, dict):
        row["agentd_status"] = {k: st.get(k) for k in ("health", "findings", "spool", "blackbox", "daemon",
                                                         "drops", "inputs", "gateway_feed", "executor")
                                if k in st}
    gs = jload(f"{run}/gw/status.json")
    if isinstance(gs, dict):
        g = gs.get("gateway", {})
        row["gateway"] = {**pick(g, ("packets", "passed", "modified", "limited", "substituted", "suppressed",
                                     "late", "replays", "sn_jumps", "trajectory_refused",
                                     "restriction_capped", "rewrite_failed", "undecidable")),
                          "latency": gs.get("latency_recv_to_verdict_ns"),
                          "feed": gs.get("findings_feed"), "findings_total": gs.get("findings_total"),
                          "restriction": gs.get("restriction") is not None,
                          "firewall": pick(gs.get("firewall"), ("faults", "rejected", "limited", "passed"))}
        row["gw_events_bytes"] = os.path.getsize(f"{run}/gw/events.jsonl") if os.path.exists(
            f"{run}/gw/events.jsonl") else 0
    r = subprocess.run([f"{B}/robodr-anchor-receiver", "status", "--config", f"{run}/anchor-rx/receiver.json"],
                       capture_output=True, text=True, timeout=20)
    row["anchor_rx"] = (r.stdout or r.stderr).strip()[-400:]
    row["pressure"] = {}
    for res in ("cpu", "io", "memory"):
        try:
            some = open(f"/proc/pressure/{res}").readline().split()
            row["pressure"][res] = float(some[2].split("=")[1])  # avg60 of "some"
        except (OSError, IndexError, ValueError):
            pass
    row["loadavg"] = open("/proc/loadavg").read().split()[:3]
    row["kafka_log_bytes"] = du(f"{run}/kafka/data")[0]
    row["kafka_publish_state"] = jload(f"{run}/kpub-state/progress.json")
    f.write(json.dumps(row) + "\n"); f.flush()
    if not alive:
        break
