#!/usr/bin/env python3
"""Red team, wave 2: control plane v2 -> agentd -> executor (motion
adapters) -> robodr-firewall-gw, against rt-ugv-001 (agentd mTLS on
127.0.0.1:8788 in netns rdr-rob; run inside it with the AutoSecOps venv
python). Requests are signed with AutoSecOps's own SOC client code.

usage: redteam2_cp.py RUN_DIR [STEP...]
steps: forge (R5 family), approvers (two-person rule / approver
aliasing), restrict (restrict_motion through the gateway adapter and
tampering with the restriction file), executor (forged envelopes /
orders on the executor socket). Default: all.
"""
import asyncio, hashlib, hmac, json, os, secrets, socket, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import soclib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

run = sys.argv[1]
steps = sys.argv[2:] or ["forge", "approvers", "restrict", "executor"]
rt = f"{run}/rt"
soc = soclib.Soc(run, "rt-ugv-001", url="https://127.0.0.1:8788")
soc_rt_pub = json.load(open(f"{rt}/finding.key.pub"))
results = []


def record(name, expect, status, body, ok, **extra):
    results.append({"test": name, "expected": expect, "status": status, "ok": bool(ok),
                    "answer": soclib.short(body), **extra})
    print(json.dumps(results[-1]), flush=True)


def nft():
    return subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True).stdout


def gw_status():
    try:
        return json.load(open(f"{run}/gw/status.json"))
    except (OSError, ValueError):
        return {}


async def wait_state(rid, want, secs=10):
    b = {}
    for _ in range(int(secs * 4)):
        st, b = await soc.get("action-requests", rid)
        if isinstance(b, dict) and b.get("status") in want:
            return st, b
        await asyncio.sleep(0.25)
    return st, b


async def forge():
    tgt = soc.target("action-requests")
    rid, body = soc.action("record_evidence")
    valid = soc.raw("POST", tgt, body)
    st, b = await soc.send(valid)
    record("R5-0 valid SOC-signed record_evidence (positive control)", "200/201", st, b, st in (200, 201))
    st, b = await soc.send(valid)
    record("R5 exact replay of the valid request bytes", "401 replayed_nonce", st, b, st == 401)
    atk = Ed25519PrivateKey.generate()
    rid2, body2 = soc.action("record_evidence")
    st, b = await soc.send(soc.raw("POST", tgt, body2, key=atk))
    record("R5b SOC key id, signed by another key", "401", st, b, st == 401)
    st, b = await soc.send(soc.raw("POST", tgt, body2, key=atk, key_id="ed25519:0000000000000000"))
    record("R5c unknown key id", "401", st, b, st == 401)
    rid3, body3 = soc.action("record_evidence", reason="altered")
    st, b = await soc.send(soc.raw("POST", tgt, body3, sign_body=body2))
    record("R5d body altered after signing", "401", st, b, st == 401)
    st, b = await soc.send(soc.raw("POST", tgt, body2, ts=int(time.time()) - 3600))
    record("R5e valid signature, timestamp 1 h old", "401", st, b, st == 401)
    st, b = await soc.send(soc.raw("POST", tgt, body2, ts=int(time.time()) + 3600))
    record("R5e2 valid signature, timestamp 1 h in the future", "401", st, b, st == 401)
    other = soclib.cp._robot_target("ugv-other", "action-requests")
    st, b = await soc.send(soc.raw("POST", other, body2))
    record("R5f request addressed to another robot id", "refused", st, b, st in (401, 403, 404))


async def approvers():
    """Two-person rule on safe_pause (the nav2 adapter has no peer here:
    a request that passes the approval gate ends `failed` at the adapter,
    one that does not is refused before it)."""
    cases = [
        ("A0 two distinct approvers (positive control: passes the gate)", ["bob@soc", "carol@soc"], "analyst@soc", "gate"),
        ("A1 same person, different case", ["bob@soc", "BOB@SOC"], "analyst@soc", "refuse"),
        ("A2 requester listed as an approver", ["analyst@soc", "bob@soc"], "analyst@soc", "refuse"),
        ("A3 requester in another case", ["Analyst@SOC", "bob@soc"], "analyst@soc", "refuse"),
        ("A4 exact duplicate", ["bob@soc", "bob@soc"], "analyst@soc", "refuse"),
        ("A5 only one approver", ["bob@soc"], "analyst@soc", "refuse"),
        ("A6 Cyrillic homoglyph (bоb)", ["bob@soc", "bоb@soc"], "analyst@soc", "refuse"),
        ("A7 zero-width space suffix", ["bob@soc", "bob@soc​"], "analyst@soc", "refuse"),
        ("A8 leading space", ["bob@soc", " bob@soc"], "analyst@soc", "refuse"),
        ("A9 five approvers (max 4)", ["a1", "a2", "a3", "a4", "a5"], "analyst@soc", "refuse"),
        ("A10 requester padded with spaces, approver = trimmed requester",
         ["analyst@soc", "bob@soc"], "  analyst@soc  ", "refuse"),
        ("A11 empty approver name", ["", "bob@soc"], "analyst@soc", "refuse"),
        ("A12 plus-addressed aliases of one mailbox", ["bob+1@soc", "bob+2@soc"], "analyst@soc", "gate"),
        ("A13 fullwidth Latin (ｂｏｂ)", ["bob@soc", "ｂｏｂ@soc"], "analyst@soc", "refuse"),
    ]
    for name, appr, req, want in cases:
        for _ in range(5):
            rid, st, b = await soc.post_action("safe_pause", approved_by=appr, requested_by=req)
            if st != 429:
                break
            await asyncio.sleep(3)
        if st in (200, 201, 202) and isinstance(b, dict):
            st2, b2 = await wait_state(rid, {"failed", "verified", "refused", "applied", "rejected"}, 8)
        else:
            st2, b2 = st, b
        txt = json.dumps(b2)
        passed_gate = "approval" not in txt and st in (200, 201, 202) and not (
            isinstance(b2, dict) and b2.get("status") == "refused" and "approv" in txt)
        ok = passed_gate if want == "gate" else not passed_gate
        record(name, "passes the approval gate" if want == "gate" else "refused (approval / invalid_field)",
               st, b2, ok, approved_by=appr, requested_by=req,
               detail=(b2.get("refusal") or b2.get("detail") or b2.get("outcome")) if isinstance(b2, dict) else None)
        await asyncio.sleep(2.5)


async def restrict():
    path = f"{run}/restrict/restriction.json"
    rid, st, b = await soc.post_action("restrict_motion", {"max_linear_speed": 0.2}, ttl=60)
    st2, b2 = await wait_state(rid, {"verified", "failed", "refused"}, 10)
    g = gw_status()
    record("M0 restrict_motion through the gateway adapter (positive control)", "verified, gateway shows it",
           st2, b2, isinstance(b2, dict) and b2.get("status") == "verified" and g.get("restriction") is not None,
           gateway_restriction=g.get("restriction"))
    # Tamper 1: delete the restriction file behind the executor's back.
    try:
        os.unlink(path)
    except OSError:
        pass
    await asyncio.sleep(14)  # > executor verify_interval_s (10)
    g = gw_status()
    st3, b3 = await soc.get("action-requests", rid)
    record("M1 restriction file deleted behind the executor (drift)", "re-applied or reported",
           st3, b3, g.get("restriction") is not None or (isinstance(b3, dict) and b3.get("status") != "verified"),
           gateway_restriction_after=g.get("restriction"), file_exists=os.path.exists(path))
    # Tamper 2: a group/world-writable restriction file and a symlink.
    for label, make in [
        ("M2 world-writable restriction file", "ww"),
        ("M3 restriction file replaced by a symlink", "link"),
    ]:
        tmp = f"{run}/restrict/evil.json"
        doc = {"format": "robodr-gw-restriction/v1", "id": "evil", "max_linear_speed": 0.05,
               "expires_unix_ms": int(time.time() * 1000) + 600000}
        open(tmp, "w").write(json.dumps(doc))
        try:
            os.unlink(path)
        except OSError:
            pass
        if make == "ww":
            os.chmod(tmp, 0o666); os.rename(tmp, path)
        else:
            os.symlink(tmp, path)
        await asyncio.sleep(1.5)
        g = gw_status()
        r = g.get("restriction")
        record(label, "ignored (restriction_error)", None, "", not (r and r.get("id") == "evil"),
               gateway_restriction=r, restriction_error=g.get("restriction_error"))
        for p in (path, tmp):
            try:
                os.unlink(p)
            except OSError:
                pass
    await asyncio.sleep(12)
    st4, b4 = await soc.get("action-requests", rid)
    record("M4 state after the tampering", "reported", st4, b4, True, gateway_restriction=gw_status().get("restriction"))


def envelope(msg, key):
    ts = int(time.time() * 1000); nonce = secrets.token_hex(16)
    mac = hmac.new(key, b"robodr-executor/1\x00" + str(ts).encode() + b"\x00" + nonce.encode()
                   + b"\x00\x00" + msg.encode(), hashlib.sha256).hexdigest()
    return json.dumps({"v": "robodr-executor/1", "ts": ts, "nonce": nonce, "reply_to": "",
                       "msg": msg, "mac": mac}).encode() + b"\n"


def exchange(line):
    c = socket.socket(socket.AF_UNIX); c.settimeout(5); c.connect(f"{rt}/executor.sock"); c.sendall(line)
    try:
        data = c.recv(65536)
    except (socket.timeout, ConnectionResetError) as e:
        data = repr(e).encode()
    c.close()
    return data.decode(errors="replace")[:400]


async def executor():
    key = bytes.fromhex(open(f"{rt}/executor.key").read().strip())
    n0 = nft()
    ans = exchange(envelope('{"op":"ping"}', os.urandom(32)))
    record("R6a executor envelope with a wrong HMAC key", "refused / closed", None, ans, "pong" not in ans)
    base = {"judged_state": "idle",
            "context": {"platform": "ugv", "morphology": "wheeled_mobile", "phase": "parked",
                        "connectivity": "connected", "control": "autonomous",
                        "operator_present": True, "profile_locked": True},
            "plan_morphology": "wheeled_mobile", "human_approved": True,
            "origin": {"kind": "control_plane", "key_id": soc.sk["key_id"], "requested_by": "x"},
            "issued_ms": int(time.time() * 1000)}
    for name, extra in [
        ("R6b HMAC-valid isolate_network claiming SOC approval, no signed request",
         {"id": "forged-1", "action": "isolate_network", "target": {"kind": "none"}, "ttl_s": 60}),
        ("R6f HMAC-valid safe_pause claiming two approvers, no signed request",
         {"id": "forged-2", "action": "safe_pause", "target": {"kind": "none"},
          "approved_by": ["bob@soc", "carol@soc"]}),
        ("R6g HMAC-valid restrict_motion naming a gateway restriction, no signed request",
         {"id": "forged-3", "action": "restrict_motion", "ttl_s": 60,
          "target": {"kind": "motion", "max_linear_speed": 0.1}}),
    ]:
        order = {**base, **extra}
        ans = exchange(envelope(json.dumps({"op": "submit", "order": order}), key))
        restr = (gw_status().get("restriction") or {}).get("id")
        record(name, "refused (or closed unanswered), nothing applied", None, ans,
               ("refused" in ans or ans == "") and "verified" not in ans and nft() == n0
               and restr != extra["id"], gateway_restriction_id=restr)
    # Replay of a captured, valid envelope (same nonce) on the socket.
    line = envelope('{"op":"ping"}', key)
    a1 = exchange(line); a2 = exchange(line)
    record("R6h replayed executor envelope (same nonce)", "second refused", None, a2,
           "pong" in a1 and "pong" not in a2, first=a1[:120])


async def contain():
    """R6c / R6e: isolate_network (TTL) and quarantine_node of a live rogue
    participant (the lab rogue capture replayed from netns rt-gen)."""
    rid, st, b = await soc.post_action("isolate_network", ttl=45)
    st2, b2 = await wait_state(rid, {"verified", "failed", "refused"}, 10)
    rules = nft()
    record("R6c isolate_network, ttl 45 s (positive control)", "verified; management, uplink, motion path kept",
           st2, b2, isinstance(b2, dict) and b2.get("status") == "verified" and "table inet robodr" in rules,
           keeps_mgmt="10.99.1.0/24" in rules, keeps_uplink="7462" in rules,
           keeps_motion="10.77.10.10" in rules)
    await asyncio.sleep(55)
    st3, b3 = await soc.get("action-requests", rid)
    record("R6c' after the TTL", "reverted, table gone", st3, b3,
           isinstance(b3, dict) and b3.get("status") in ("reverted", "expired") and "table inet robodr" not in nft())
    # The rogue: baseline then the rogue capture, live, from rt-gen.
    import pcaplib, rtlib
    F = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../fixtures/captures/ros2-jazzy/")
    rogue, _ = pcaplib.read(F + "fastrtps_gz_rogue_cmd_vel.pcap")
    base, _ = pcaplib.read(F + "fastrtps_gz_baseline.pcap")
    known = {bytes.fromhex(p) for p in json.load(open(f"{rt}/locked.json"))["participants"]}
    guid = None
    for _, fr in rogue:
        _, pre = rtlib.rtps_prefix(fr)
        if pre and pre not in known:
            guid = pre.hex(); break
    sock = rtlib.packet_socket("rt-gen", "gen-rt")

    def play(frames, speed):
        t0 = frames[0][0]; w0 = time.monotonic()
        for t, fr in frames:
            d = w0 + (t - t0) / speed - time.monotonic()
            if d > 0:
                time.sleep(d)
            sock.send(fr)
    await asyncio.to_thread(play, base, 4.0)
    task = asyncio.create_task(asyncio.to_thread(play, rogue, 1.0))
    await asyncio.sleep(12)
    rid, st, b = await soc.post_action("quarantine_node", {"participant_guid": guid})
    st4, b4 = await wait_state(rid, {"verified", "failed", "refused"}, 10)
    rules = nft()
    record("R6e quarantine_node of the live rogue participant", "verified with locators / addresses",
           st4, b4, isinstance(b4, dict) and b4.get("status") == "verified",
           guid=guid, containment=(b4.get("containment") if isinstance(b4, dict) else None),
           quarantine=(b4.get("state", {}).get("quarantine") if isinstance(b4, dict) else None),
           nft_mentions_rogue_address="10.77.10." in rules or "quarantine" in rules)
    await task
    st5, b5 = await soc.send(soc.raw("POST", soc.target("action-requests", rid, "revert"),
                                     soclib.cp.body_bytes({"reason": "red team done", "requested_by": "analyst@soc"})))
    record("R6e' revert of the quarantine", "reverted", st5, b5, st5 in (200, 201, 202))


async def main():
    for s in steps:
        await {"forge": forge, "approvers": approvers, "restrict": restrict, "executor": executor,
               "contain": contain}[s]()


asyncio.run(main())
json.dump(results, open(f"{run}/redteam2_cp.json", "w"), indent=1)
print("FAILED:", [r["test"] for r in results if not r["ok"]])
