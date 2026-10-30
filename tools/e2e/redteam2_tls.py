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
agentd's anchor counters (status.json), the receiver's held seq and a
mutual-TLS handshake with the unit's client certificate
(RUN/tls/anchor/client.pem, as agentd's head anchor uses; added
2026-10-30 for W2-4: the counters alone do not show whether a unit gets a
slot).

Environment: RT_SRC_BASE (first attacker source, default 127.0.0.10);
RT_FAST_HELLO=1: each attacker connection sends a complete ClientHello at
once (Python ssl, no client certificate) and then nothing, instead of
trickling (the strongest pre-authentication squatter: it ranks as
progressing until the server's progress floor or deadline cuts it).
"""
import asyncio, json, os, socket, ssl, subprocess, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

run, target, nsrc, per, secs = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), float(sys.argv[5])
port = 8788 if target == "cp" else 7462
B = os.environ.get("ROBODR_BIN", "/home/user/wt/target-soak/release")
HELLO = bytes.fromhex("160301020001" "0001fc0303") + os.urandom(32)
stop = threading.Event()
stats = {"opened": 0, "refused": 0, "cut": 0, "bytes": 0}
lock = threading.Lock()


FAST = os.environ.get("RT_FAST_HELLO") == "1"


def client_hello():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    out = ssl.MemoryBIO()
    obj = ctx.wrap_bio(ssl.MemoryBIO(), out)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return out.read()


def hold(s):
    """Send a full ClientHello, then read until the server cuts us."""
    s.sendall(client_hello())
    with lock:
        stats["bytes"] += 1
    s.settimeout(1.0)
    while not stop.is_set():
        try:
            if not s.recv(4096):
                raise OSError("closed")
        except socket.timeout:
            continue


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
            if FAST:
                hold(s)
            for b in ([] if FAST else HELLO):
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


base = os.environ.get("RT_SRC_BASE", "127.0.0.10").rsplit(".", 1)
src = lambda i: f"{base[0]}.{int(base[1]) + i}"  # noqa: E731 (stays below .255)
threads = [threading.Thread(target=attacker, args=(src(i),), daemon=True)
           for i in range(nsrc) for _ in range(per)]


def unit_handshake():
    """A mutual-TLS handshake with the unit's certificate (the slot a head
    anchor exchange needs); ok within 5 s."""
    t = time.monotonic()
    ctx = ssl.create_default_context(cafile=f"{run}/tls/anchor/ca.pem")
    ctx.load_cert_chain(f"{run}/tls/anchor/client.pem", f"{run}/tls/anchor/client.key")
    ctx.check_hostname = False
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            with ctx.wrap_socket(s) as t2:
                t2.do_handshake()
        return {"tls_ok": True, "ms": round((time.monotonic() - t) * 1000)}
    except (OSError, ssl.SSLError) as e:
        return {"tls_ok": False, "error": type(e).__name__, "ms": round((time.monotonic() - t) * 1000)}


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
        a = anchor_view()
        a.update(unit_handshake())
        return a

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
        ok = [s for s in samples if s.get("tls_ok")]
        out["during"] = {"probes": len(samples), "unit_tls_ok": len(ok),
                         "errors": sorted({s.get("error") for s in samples if not s.get("tls_ok")})}
    print(json.dumps(out))
    out["fast_hello"] = FAST
    tag = "_fast" if FAST else ""
    json.dump(out, open(f"{run}/redteam2_tls_{target}_{nsrc}x{per}{tag}.json", "w"), indent=1)


asyncio.run(main())
