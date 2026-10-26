#!/usr/bin/env python3
"""Summarise soak metrics.csv: RSS trend (least squares, KiB/h), CPU, spool,
uplink, findings and black-box growth per robot.
usage: soak_report.py metrics.csv NAME [NAME...]"""
import csv, sys

rows = list(csv.DictReader(open(sys.argv[1])))


def num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def slope(xs, ys):
    n = len(xs); mx = sum(xs) / n; my = sum(ys) / n
    d = sum((x - mx) ** 2 for x in xs)
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / d if d else 0.0


print(f"samples: {len(rows)}, duration {int(rows[-1]['elapsed_s']) / 60:.1f} min (monitor), interval 60 s")
for n in sys.argv[2:]:
    r = [x for x in rows if num(x[f"{n}_rss_kib"]) is not None]
    t = [num(x["elapsed_s"]) / 3600 for x in r]
    rss = [num(x[f"{n}_rss_kib"]) for x in r]
    cpu = [num(x[f"{n}_cpu_pct"]) for x in r if num(x[f"{n}_cpu_pct"]) is not None]
    bb = [num(x[f"{n}_blackbox_bytes"]) for x in r]
    half = len(r) // 2
    print(f"\n[{n}]")
    print(f"  agentd RSS KiB: first {rss[0]:.0f} last {rss[-1]:.0f} min {min(rss):.0f} max {max(rss):.0f}; "
          f"trend {slope(t, rss):+.1f} KiB/h (all), {slope(t[half:], rss[half:]):+.1f} KiB/h (2nd half)")
    print(f"  agentd CPU %: mean {sum(cpu) / len(cpu):.2f} max {max(cpu):.2f}")
    urss = [num(x[f"{n}_uplink_rss_kib"]) for x in r if num(x[f"{n}_uplink_rss_kib"])]
    print(f"  uplink RSS KiB: first {urss[0]:.0f} last {urss[-1]:.0f} max {max(urss):.0f}")
    ready = [num(x[f"{n}_spool_ready"]) for x in r]
    print(f"  spool ready (backlog) max {max(ready):.0f}, last {ready[-1]:.0f}; acked last {r[-1][f'{n}_spool_acked']}")
    states = {}
    for x in r:
        states[x[f"{n}_uplink_state"]] = states.get(x[f"{n}_uplink_state"], 0) + 1
    print(f"  uplink state samples: {states}; accepted_total last {r[-1][f'{n}_accepted_total']}")
    print(f"  black box: {bb[0] / 1e6:.2f} -> {bb[-1] / 1e6:.2f} MB, {slope(t, bb) / 1e6:.2f} MB/h")
    print(f"  AutoSecOps: findings {r[-1][f'{n}_db_findings']}, occurrences {r[-1][f'{n}_db_occurrences']}, "
          f"cases {r[-1][f'{n}_db_cases']}")
    occ = [int(num(x[f"{n}_db_occurrences"])) for x in r]
    steps = [(int(num(r[i]['elapsed_s'])) // 60, occ[i] - occ[i - 1]) for i in range(1, len(r)) if occ[i] != occ[i - 1]]
    print(f"  occurrence increments (minute, +n): {steps[:80]}")
