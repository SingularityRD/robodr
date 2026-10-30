#!/usr/bin/env python3
"""Summarise a wave-2 soak run (soak2.sh) -> JSON on stdout.

usage: soak2_report.py RUN_DIR [INJECT_WINDOW_S]

* processes: RSS first / last / max and a least-squares slope (KiB/h) over
  the second half (leak check), mean CPU %;
* agentd findings by rule, split into those inside an injection window
  (rogue replay start .. + INJECT_WINDOW_S, default 120) and outside
  (clean traffic: false-positive candidates), per hour;
* gateway findings (events file) likewise against the generator's
  injection times (window 10 s);
* gateway / generator counters and latency, SOC timings, restriction
  round trips, spool / black box / Kafka growth, anchor receiver, crashes.
"""
import collections, json, os, sys

run = sys.argv[1]
win = float(sys.argv[2]) if len(sys.argv) > 2 else 120.0
L = f"{run}/logs"


def jl(p):
    out = []
    try:
        for l in open(p):
            try:
                out.append(json.loads(l))
            except ValueError:
                pass
    except OSError:
        pass
    return out


def slope(xs, ys):
    n = len(xs)
    if n < 3:
        return None
    mx, my = sum(xs) / n, sum(ys) / n
    d = sum((x - mx) ** 2 for x in xs)
    return None if d == 0 else sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / d


m = jl(f"{L}/metrics.jsonl")
rep = {"samples": len(m), "duration_s": m[-1]["elapsed_s"] if m else 0}
procs = {}
for name in (m[0]["procs"] if m else {}):
    pts = [(r["elapsed_s"], r["procs"][name]["rss_kib"]) for r in m if r["procs"].get(name)]
    cpu = [r["procs"][name]["cpu_pct"] for r in m if r["procs"].get(name) and r["procs"][name].get("cpu_pct") is not None]
    fds = [r["procs"][name]["fds"] for r in m if r["procs"].get(name)]
    half = pts[len(pts) // 2:]
    s = slope([p[0] / 3600 for p in half], [p[1] for p in half])
    procs[name] = {"rss_first": pts[0][1] if pts else None, "rss_last": pts[-1][1] if pts else None,
                   "rss_max": max(p[1] for p in pts) if pts else None,
                   "rss_slope_kib_per_h_2nd_half": round(s, 1) if s is not None else None,
                   "cpu_mean_pct": round(sum(cpu) / len(cpu), 2) if cpu else None,
                   "cpu_max_pct": max(cpu) if cpu else None,
                   "fds_first_last": [fds[0], fds[-1]] if fds else None,
                   "samples_alive": len(pts)}
rep["procs"] = procs
if m:
    rep["pressure_cpu_avg60_mean"] = round(sum(r["pressure"].get("cpu", 0) for r in m) / len(m), 1)
    rep["pressure_cpu_avg60_max"] = max(r["pressure"].get("cpu", 0) for r in m)
    rep["spool"] = {"first": m[0]["spool"], "last": m[-1]["spool"],
                    "max_ready": max(r["spool"]["ready"] for r in m)}
    rep["blackbox_bytes"] = [m[0]["blackbox_bytes"], m[-1]["blackbox_bytes"]]
    rep["kafka_log_bytes"] = [m[0].get("kafka_log_bytes"), m[-1].get("kafka_log_bytes")]
    try:
        rep["kafka_publish"] = json.load(open(f"{run}/kpub-state/progress.json"))
    except (OSError, ValueError):
        pass
    rep["gateway_last"] = m[-1].get("gateway")
    rep["agentd_last"] = m[-1].get("agentd_status")
    rep["anchor_rx_last"] = m[-1].get("anchor_rx")
    rep["late_per_sample"] = [r["gateway"]["late"] for r in m if r.get("gateway")][::10]

# agentd findings vs. injection windows
inj = [float(l.split()[0]) for l in open(f"{L}/gen-ugv.events") if " inject " in l] if os.path.exists(
    f"{L}/gen-ugv.events") else []
inside, outside = collections.Counter(), collections.Counter()
outside_samples = collections.defaultdict(list)
spool = f"{run}/ugv/spool"
for sub in ("ready", "acked"):
    d = f"{spool}/{sub}"
    for n in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        try:
            v = json.loads(json.load(open(f"{d}/{n}"))["value"])
        except (OSError, ValueError, KeyError):
            continue
        t = v["ocsf"]["time"] / 1000
        rule = v["ocsf"]["finding_info"]["analytic"]["uid"]
        key = (rule, v["severity"])
        if any(i <= t <= i + win for i in inj):
            inside[key] += 1
        else:
            outside[key] += 1
            if len(outside_samples[rule]) < 2:
                outside_samples[rule].append(v.get("entity_context", {}).get("detail", {}).get("value", "")[:240])
hours = rep["duration_s"] / 3600 or 1
rep["agentd_findings"] = {
    "injections": len(inj), "window_s": win,
    "in_injection_windows": {f"{k[0]} ({k[1]})": c for k, c in inside.most_common()},
    "outside_windows": {f"{k[0]} ({k[1]})": c for k, c in outside.most_common()},
    "outside_per_hour": round(sum(outside.values()) / hours, 1),
    "outside_samples": outside_samples,
}

# gateway findings vs. generator injections
gt = jl(f"{L}/gw-traffic.jsonl")
ginj = [g["t"] for g in gt if "inject" in g]
ev = jl(f"{run}/gw/events.jsonl")
gc = collections.Counter(); gclean = collections.Counter()
for e in ev:
    d = e.get("detail", "")
    head = d[d.find("("):d.find(")") + 1] if "(" in d else ""
    gc[(e["rule"], head)] += 1
rep["gateway_events"] = {f"{k[0]} {k[1]}": c for k, c in gc.most_common()}
rep["gateway_injections"] = len(ginj)
mins = [g for g in gt if "elapsed_s" in g]
if mins:
    last = mins[-1]
    rep["generator_last"] = {k: last.get(k) for k in ("elapsed_s", "lowcmd", "sport", "trajectory", "lost",
                                                       "foreign_datagrams_received", "latency_total")}
    rep["generator_latency_minutes_p99_us"] = [g["latency_minute"]["p99_us"] for g in mins if g.get("latency_minute")]
    rep["generator_alerts"] = [g for g in gt if "alert" in g][:5]

# SOC
soc = jl(f"{L}/soc.jsonl")
st = [s for s in soc if s.get("kind") == "status"]
ok = sorted(s["ms"] for s in st if s.get("status") == 200)
rep["soc"] = {"status_calls": len(st), "ok": len(ok),
              "non_200": collections.Counter(str(s.get("status") or s.get("error")) for s in st if s.get("status") != 200),
              "ms_p50": ok[len(ok) // 2] if ok else None, "ms_max": ok[-1] if ok else None,
              "safety_states": collections.Counter(s.get("safety") for s in st),
              "restrict": [{k: s.get(k) for k in ("kind", "n", "status", "gateway_restriction_after_5s",
                                                    "gateway_restriction_after_ttl")}
                           | {"req_status": (s.get("answer") or {}).get("status")} for s in soc
                           if s.get("kind", "").startswith("restrict")]}
# crashes / restarts
crash = {}
for n in os.listdir(L):
    if n.endswith(".log"):
        txt = open(f"{L}/{n}", errors="replace").read()
        crash[n] = {"panic": txt.count("panicked"), "abort": txt.count("SIGABRT") + txt.count("Aborted"),
                    "error_lines": sum(1 for l in txt.splitlines() if "error" in l.lower())}
rep["logs"] = crash
print(json.dumps(rep, indent=1, default=str))
