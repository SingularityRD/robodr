#!/usr/bin/env python3
"""Per-minute soak metrics -> CSV.

usage: soak_monitor.py OUT.csv INTERVAL_S NAME=ROBOT_ID:AGENTD_PID:SPOOL:BLACKBOX:UPLINK_STATE:UPLINK_PID ...

Columns per robot: agentd RSS (KiB), agentd CPU % over the interval, uplink
RSS, spool ready/acked file counts, black-box bytes, uplink state, accepted
total, spool backlog, and from the AutoSecOps DB (docker exec aso-test-pg):
distinct findings, summed occurrences and cases for the robot.
"""
import csv, json, os, subprocess, sys, time

out, interval = sys.argv[1], float(sys.argv[2])
robots = []
for spec in sys.argv[3:]:
    name, rest = spec.split("=", 1)
    rid, pid, spool, bb, ust, upid = rest.split(":")
    robots.append(dict(name=name, rid=rid, pid=int(pid), spool=spool, bb=bb, ust=ust, upid=int(upid)))
HZ = os.sysconf("SC_CLK_TCK")


def proc(pid):
    try:
        st = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
        rss = next(int(l.split()[1]) for l in open(f"/proc/{pid}/status") if l.startswith("VmRSS"))
        return rss, int(st[11]) + int(st[12])
    except (FileNotFoundError, ProcessLookupError, StopIteration):
        return None, None


def count(d):
    try:
        return len(os.listdir(d))
    except FileNotFoundError:
        return 0


def du(d):
    t = 0
    for root, _, files in os.walk(d):
        for f in files:
            try:
                t += os.path.getsize(os.path.join(root, f))
            except FileNotFoundError:
                pass
    return t


def db():
    q = ("select robot_id, count(*), coalesce(sum(occurrence_count),0), count(distinct case_id) "
         "from robot_finding group by robot_id")
    r = subprocess.run(["docker", "exec", "aso-test-pg", "psql", "-U", "postgres", "-d", "robodr_e2e",
                        "-At", "-F", ",", "-c", q], capture_output=True, text=True)
    res = {}
    for line in r.stdout.splitlines():
        rid, n, occ, cases = line.split(",")
        res[rid] = (int(n), int(occ), int(cases))
    return res


fields = ["t", "elapsed_s"]
for r in robots:
    n = r["name"]
    fields += [f"{n}_rss_kib", f"{n}_cpu_pct", f"{n}_uplink_rss_kib", f"{n}_spool_ready", f"{n}_spool_acked",
               f"{n}_blackbox_bytes", f"{n}_uplink_state", f"{n}_accepted_total", f"{n}_backlog",
               f"{n}_db_findings", f"{n}_db_occurrences", f"{n}_db_cases"]
new = not os.path.exists(out)
f = open(out, "a", newline=""); w = csv.DictWriter(f, fields)
if new:
    w.writeheader()
prev = {r["name"]: proc(r["pid"])[1] for r in robots}
t0 = time.time(); tprev = time.monotonic()
while True:
    time.sleep(interval)
    now = time.monotonic(); dt = now - tprev; tprev = now
    d = db(); row = {"t": int(time.time()), "elapsed_s": int(time.time() - t0)}
    alive = False
    for r in robots:
        n = r["name"]; rss, cpu = proc(r["pid"]); urss, _ = proc(r["upid"])
        alive |= rss is not None
        try:
            us = json.load(open(os.path.join(r["ust"], "uplink-status.json")))
        except (FileNotFoundError, json.JSONDecodeError):
            us = {}
        row.update({
            f"{n}_rss_kib": rss, f"{n}_cpu_pct": None if cpu is None or prev[n] is None
            else round(100 * (cpu - prev[n]) / HZ / dt, 2),
            f"{n}_uplink_rss_kib": urss,
            f"{n}_spool_ready": count(os.path.join(r["spool"], "ready")),
            f"{n}_spool_acked": count(os.path.join(r["spool"], "acked")),
            f"{n}_blackbox_bytes": du(r["bb"]), f"{n}_uplink_state": us.get("state"),
            f"{n}_accepted_total": us.get("accepted_total"),
            f"{n}_backlog": (us.get("backlog") or {}).get("spool_ready"),
            f"{n}_db_findings": d.get(r["rid"], (0, 0, 0))[0],
            f"{n}_db_occurrences": d.get(r["rid"], (0, 0, 0))[1],
            f"{n}_db_cases": d.get(r["rid"], (0, 0, 0))[2],
        })
        prev[n] = cpu
    w.writerow(row); f.flush()
    if not alive:
        break
