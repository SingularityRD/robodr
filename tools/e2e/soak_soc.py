#!/usr/bin/env python3
"""Periodic SOC traffic during the soak (AutoSecOps venv python).

usage: soak_soc.py RUN_DIR OUT.jsonl SECONDS [RESTRICT_EVERY_S]

Every 60 s: GET the robot snapshot over mutual TLS (latency, status,
safety state, mode). Every RESTRICT_EVERY_S (default 900): a SOC-signed
restrict_motion (max_linear_speed 0.2, ttl 180 s) that the executor
carries out through the gateway adapter (restriction file ->
robodr-firewall-gw); checks the gateway's status shows the restriction
within 5 s and none after the TTL, and records the request's state.
Every 4th round also an evidence inventory GET.
"""
import asyncio, json, os, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import soclib

run, out, secs = sys.argv[1], sys.argv[2], float(sys.argv[3])
every = float(sys.argv[4]) if len(sys.argv) > 4 else 900
fd = open(out, "a")
soc = soclib.Soc(run, "soak-ugv-001")


def log(**kw):
    kw["t"] = round(time.time(), 3)
    fd.write(json.dumps(kw) + "\n"); fd.flush()


def gw_restriction():
    try:
        return json.load(open(f"{run}/gw/status.json")).get("restriction")
    except (OSError, ValueError):
        return "unreadable"


async def snapshot(tag="status"):
    t = time.monotonic()
    try:
        st, b = await soc.get()
    except Exception as e:  # noqa: BLE001 - recorded as a failure
        log(kind=tag, error=repr(e)[:300], ms=round((time.monotonic() - t) * 1000, 1))
        return
    ms = round((time.monotonic() - t) * 1000, 1)
    s = b.get("safety_state", {}) if isinstance(b, dict) else {}
    log(kind=tag, status=st, ms=ms, mode=b.get("mode") if isinstance(b, dict) else None,
        health=b.get("health") if isinstance(b, dict) else None, safety=s.get("state"))


async def restrict(n):
    t = time.monotonic()
    rid, st, b = await soc.post_action("restrict_motion", {"max_linear_speed": 0.2}, ttl=180)
    ms = round((time.monotonic() - t) * 1000, 1)
    await asyncio.sleep(5)
    applied = gw_restriction()
    log(kind="restrict_motion", n=n, rid=rid, status=st, ms=ms, answer=soclib.short(b),
        gateway_restriction_after_5s=applied is not None and applied != "unreadable")
    await asyncio.sleep(200)
    st2, b2 = await soc.get("action-requests", rid)
    lifted = gw_restriction()
    log(kind="restrict_motion_after_ttl", n=n, rid=rid, status=st2, answer=soclib.short(b2),
        gateway_restriction_after_ttl=lifted)


async def main():
    t0 = time.monotonic(); n = 0
    next_restrict = t0 + 120
    tasks = []
    while time.monotonic() - t0 < secs:
        await snapshot()
        if n % 4 == 3:
            t = time.monotonic()
            try:
                st, b = await soc.get("evidence")
                log(kind="evidence_inventory", status=st, ms=round((time.monotonic() - t) * 1000, 1))
            except Exception as e:  # noqa: BLE001
                log(kind="evidence_inventory", error=repr(e)[:300])
        if time.monotonic() >= next_restrict:
            tasks.append(asyncio.create_task(restrict(len(tasks) + 1)))
            next_restrict += every
        n += 1
        await asyncio.sleep(60)
    for t in tasks:
        await t


asyncio.run(main())
