#!/usr/bin/env python3
"""RoboDR vs a Pulsar-only deployment, per attack scenario (gap T65).

Reproducible: run `demo/run.sh`, then
`docker compose -f demo/docker-compose.yml run --rm -T robot /demo/scripts/compare.sh`
(RoboDR side: every robodr-attack-sim scenario from two attacker placements,
each scenario alone in its own capture, replayed through its own
robodr-agentd run and scored on its own spool), then

    tools/e2e/compare_pulsar_only.py demo/state/compare > tools/e2e/COMPARISON-pulsar-only.md

**RoboDR column**: measured. The rule ids robodr-agentd reported in that
scenario's own run (a scenario counts as detected when any of its evidence
ids below was reported there; no run sees another scenario's traffic, so
no scenario is credited with another one's findings). EVIDENCE is mirrored
in crates/robodr-attack-sim/tests/agentd_e2e.rs, which pins it for both
placements and checks that none of these ids fire on the clean carrier.

**Pulsar-only column**: a best case, computed from what Pulsar can observe.
Pulsar is a host sensor: its events (vendor/pulsar
crates/pulsar-core/src/event.rs, `Payload`) are process, file and socket
events of the robot computer. The only per-datagram network event is
`Receive {source, destination, len, is_tcp}`: addresses and a length, no
payload bytes (the script reads the enum and fails if that changes). Its
rules engine evaluates each event on its own (no counts or time windows).
So the best Pulsar-only rules for these scenarios are, generously:

* P1 "datagram from an address that is not in the baseline": every source
  address seen in the baseline capture is allowed (an `IN` list on
  `payload.source.ip`);
* P2 "datagram shorter than an RTPS header" (`payload.len < 20`).

Both are evaluated here on the same attack capture, counting only datagrams
a process on the robot computer receives (sent to a robot address or to the
SPDP multicast group; the Unitree low-level port 192.168.123.10:8007 belongs
to the robot's motor controller, not to the Linux host Pulsar runs on).
Pulsar never ran in this comparison: the column is what it could see at
most, which is the fair bound for a host-only product.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import pcaplib  # noqa: E402

BASELINE = os.path.join(ROOT, "fixtures/captures/ros2-jazzy/fastrtps_baseline.pcap")
PULSAR_EVENT = os.path.join(ROOT, "vendor/pulsar/crates/pulsar-core/src/event.rs")
SPDP_GROUP = ipaddress.ip_address("239.255.0.1")

# Any of these reported = the scenario was detected (expected ids first).
EVIDENCE = {
    "rogue-participant": ["robot.ros2.unknown_participant", "robot.ros2.identity_instances_exceeded"],
    "guid-spray": ["robot.ros2.discovery_flood", "robot.ros2.unknown_participant"],
    "malformed-rtps": ["robot.rtps.malformed_discovery", "robot.rtps.discovery_not_inspected"],
    "cmd-vel-envelope": ["robot.motion.linear_over_envelope", "robot.firewall.rejected_over_hard_limit"],
    "lowcmd-torque": ["robot.unitree.legacy_unknown_sender", "robot.firewall.joint_torque_out_of_envelope",
                      "robot.motion.unprofiled_channel", "robot.firewall.rejected_unknown_channel"],
}

CANNOT = {
    "rogue-participant": "that a DDS participant joined, its GUID, that it is not in the profile; from an allowed host nothing at all",
    "guid-spray": "the number of distinct participants (all from one address); no rate rule exists in a per-event engine",
    "malformed-rtps": "malformed RTPS of normal length (random bodies, bad submessage lengths, mutations, fragments)",
    "cmd-vel-envelope": "anything: same host, port and length as the operator; the speed is in the payload",
    "lowcmd-torque": "anything on the robot computer: the frames go to the motor controller; the torque is in the payload",
}


def pulsar_receive_fields():
    with open(PULSAR_EVENT, encoding="utf-8") as fh:
        src = fh.read()
    m = re.search(r"pub enum Payload \{(.*?)\n\}", src, re.S)
    if not m:
        raise SystemExit(f"{PULSAR_EVENT}: Payload enum not found")
    body = m.group(1)
    r = re.search(r"\n    Receive \{(.*?)\n    \}", body, re.S)
    if not r:
        raise SystemExit("Pulsar Payload has no Receive event: revisit this comparison")
    fields = re.findall(r"^\s+([a-z_]+):", r.group(1), re.M)
    if set(fields) - {"source", "destination", "len", "is_tcp"}:
        raise SystemExit(f"Pulsar Receive now has {fields}: revisit this comparison")
    events = re.findall(r"^    ([A-Z][A-Za-z]+)\b", body, re.M)
    try:
        rev = subprocess.run(["git", "-C", os.path.join(ROOT, "vendor/pulsar"), "rev-parse", "HEAD"],
                             capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        rev = "unknown"
    return fields, events, rev


def datagrams(path):
    frames, linktype = pcaplib.read(path)
    if linktype != 1:
        raise SystemExit(f"{path}: Ethernet captures only")
    out = []
    for t, f in frames:
        if len(f) < 34 or f[12:14] != b"\x08\x00":
            continue
        ihl = (f[14] & 0x0F) * 4
        if f[23] != 17:
            continue
        frag = struct.unpack("!H", f[20:22])[0]
        src = ipaddress.ip_address(socket.inet_ntoa(f[26:30]))
        dst = ipaddress.ip_address(socket.inet_ntoa(f[30:34]))
        if frag & 0x1FFF:  # not the first fragment: no UDP header
            continue
        udp = f[14 + ihl:]
        if len(udp) < 8:
            continue
        dport = struct.unpack("!H", udp[2:4])[0]
        ulen = struct.unpack("!H", udp[4:6])[0] - 8
        out.append((t, src, dst, dport, ulen))
    return out


def windows(plan, t0):
    """(scenario, start, end) from robodr-attack-sim's pcap plan."""
    sc = plan["scenarios"]
    starts = [(s["scenario"], t0 + s["start_offset_s"]) for s in sc]
    # cmd-vel-envelope rewrites traffic from its start to the end: it overlaps
    # the staggered scenarios, so it is handled on its own below.
    staged = sorted([x for x in starts if x[0] != "cmd-vel-envelope"], key=lambda x: x[1])
    out = []
    for i, (name, s) in enumerate(staged):
        e = staged[i + 1][1] if i + 1 < len(staged) else float("inf")
        out.append((name, s, e))
    return out


def evaluate(base, attack, plan):
    """P1/P2 over one scenario's own capture, from the attack's start on."""
    allowed = {d[1] for d in base}
    robot_addrs = {d[2] for d in base if not d[2].is_multicast}
    t0 = attack[0][0]
    res = {}
    for name, s, e in windows(plan, t0):
        win = [d for d in attack if s <= d[0] < e]
        received = [d for d in win if d[2] in robot_addrs or d[2] == SPDP_GROUP]
        # Only datagrams that are not part of the baseline traffic pattern
        # can be the attack's; P1/P2 hit counts are over all received.
        p1 = sum(1 for d in received if d[1] not in allowed)
        p2 = sum(1 for d in received if d[4] < 20)
        res[name] = {"received": len(received), "p1": p1, "p2": p2}
    # cmd-vel-envelope: same packets as the baseline, rewritten in place.
    res["cmd-vel-envelope"] = {"received": None, "p1": 0, "p2": 0}
    return res


def robodr(score):
    """(rule id -> count, whether the scenario's own expected ids were all present)."""
    seen = {}
    for s in score["scenarios"]:
        for e in s["expected"]:
            seen[e["rule_id"]] = e["count"]
    for o in score["other_rule_ids"]:
        seen[o["rule_id"]] = o["count"]
    return seen, score.get("pass") is True


def main(argv):
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    d = argv[1]
    fields, events, rev = pulsar_receive_fields()
    base = datagrams(BASELINE)
    rows = []
    for placement in ("foreign", "insider"):
        for sc in EVIDENCE:
            run = os.path.join(d, f"{placement}-{sc}")
            with open(f"{run}-plan.json", encoding="utf-8") as fh:
                plan = json.load(fh)
            if [s["scenario"] for s in plan["scenarios"]] != [sc]:
                raise SystemExit(f"{run}-plan.json: not a run of {sc} alone; rerun demo/scripts/compare.sh")
            with open(f"{run}-score.json", encoding="utf-8") as fh:
                seen, own = robodr(json.load(fh))
            attack = datagrams(f"{run}.pcap")
            p = evaluate(base, attack, plan)[sc]
            ev = [(r, seen[r]) for r in EVIDENCE[sc] if seen.get(r)]
            hits = []
            if p["p1"]:
                hits.append(f"P1 x{p['p1']}")
            if p["p2"]:
                hits.append(f"P2 x{p['p2']}")
            rows.append((placement, sc, ev, hits, p, own))
    print("<!-- GENERATED by tools/e2e/compare_pulsar_only.py; see its docstring to reproduce. -->")
    print("# RoboDR vs Pulsar-only: attack scenarios\n")
    print(f"Pulsar source: `vendor/pulsar` at `{rev}`; its `Receive` event carries "
          f"`{', '.join(fields)}` (no payload). Events: {', '.join(events)}.\n")
    print("Attacker placements: **foreign** = a new host on the robot network (10.77.10.66); "
          "**insider** = the operator's own host (10.77.10.21), e.g. a compromised teleop laptop.\n")
    print("Each scenario runs alone in its own capture per placement, through its own robodr-agentd "
          "run, scored on its own spool: a RoboDR count is for that scenario only. A scenario counts "
          "as detected when one of its evidence ids (below; `EVIDENCE` in the script) fired in its "
          "own run; `crates/robodr-attack-sim/tests/agentd_e2e.rs` pins that for both placements and "
          "that none of these ids fire on the clean baseline. \"own id missing\" marks a run where "
          "the scenario's own expected id (`robodr-attack-sim list`) did not fire and the detection "
          "comes from another evidence id.\n")
    print("| Placement | Scenario | RoboDR (measured, rule id x count) | Pulsar-only best case (P1 unknown source, P2 short datagram) | What Pulsar-only cannot tell |")
    print("|---|---|---|---|---|")
    for placement, sc, ev, hits, p, own in rows:
        r = "; ".join(f"`{i}` x{n}" for i, n in ev) or "**not detected**"
        if ev and not own:
            r += " (own id missing)"
        if sc == "lowcmd-torque":
            pl = "**not visible** (frames go to the motor controller)"
        elif sc == "cmd-vel-envelope":
            pl = "**not visible** (identical addresses, ports and lengths)"
        else:
            pl = ", ".join(hits) or "**nothing**"
            pl += f" of {p['received']} datagrams received"
        print(f"| {placement} | {sc} | {r} | {pl} | {CANNOT[sc]} |")
    det_r = sum(1 for row in rows if row[2])
    det_p = sum(1 for row in rows if row[3] and row[1] not in ("lowcmd-torque", "cmd-vel-envelope"))
    print(f"\nDetected: RoboDR {det_r}/{len(rows)}, Pulsar-only best case {det_p}/{len(rows)} "
          "(a P1/P2 hit counts as detected, although it says only \"a datagram from X\" or "
          "\"a short datagram\", not what happened).\n")
    print("Where Pulsar-only is strong and RoboDR builds on it: host activity on the robot "
          "computer (shells, SROS 2 key reads, package installs, service tampering). RoboDR "
          "ships its rule pack for Pulsar (`rules/robodr/`, 86 rules) and correlates those "
          "host detections with the network ones (`robot.correlate.*`); those scenarios are "
          "not in this table (tools/e2e/redteam2.sh; they need Pulsar running on a real "
          "kernel, gap T27).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
