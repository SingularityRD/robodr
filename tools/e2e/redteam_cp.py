#!/usr/bin/env python3
"""Red-team, control plane v2 + executor v1, against rt-ugv-001 (agentd
mTLS listener 127.0.0.1:8787 inside netns rdr-rob). Requests are built
with AutoSecOps's own SOC client code (robodr_control_plane), so the
positive control is exactly what a SOC sends.

usage (AutoSecOps venv python): redteam_cp.py RT_DIR CP_TLS SOC_KEY PARTICIPANT_GUID
"""
import asyncio, hashlib, hmac, json, os, secrets, subprocess, sys, time, socket

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rtlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from autosecops_registry._internal import secrets as rsecrets
from autosecops_registry.integrations import robodr_control_plane as cp

rt, tls, soc_key, guid = sys.argv[1:5]
rtlib.netns("rdr-rob")
sk = json.load(open(soc_key))
fk = json.load(open(os.path.join(rt, "finding.key.pub")))
rsecrets.set_context({"ROBODR_SOC_KEY_ID": sk["key_id"], "ROBODR_SOC_SECRET_HEX": sk["secret_hex"],
                      "ROBODR_SOC_CLIENT_CERT_PEM": open(f"{tls}/soc.pem").read(),
                      "ROBODR_SOC_CLIENT_KEY_PEM": open(f"{tls}/soc.key").read()})
robot = cp._robot(base_url="https://127.0.0.1:8787", robot_id="rt-ugv-001",
                  robot_ca_pem=open(f"{tls}/robot-ca.pem").read(), robot_spki_sha256=None,
                  answer_public_key_hex=fk["public_hex"], answer_key_id=fk["key_id"])
SOC = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sk["secret_hex"]))
results = []


def nft():
    r = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True)
    return r.stdout


def raw_request(method, target, body, key=SOC, key_id=None, ts=None, nonce=None, sign_body=None):
    key_id = key_id or sk["key_id"]; ts = ts or int(time.time()); nonce = nonce or secrets.token_urlsafe(24)
    sig = key.sign(cp.signing_message(method, target, robot.robot_id, key_id, ts, nonce,
                                      body if sign_body is None else sign_body)).hex()
    return cp.request_bytes(method=method, target=target, host=robot.host_header, key_id=key_id,
                            timestamp=ts, nonce=nonce, signature_hex=sig, body=body)


async def send(req):
    a = await cp._exchange(robot, req, max_body=cp.MAX_ANSWER_BYTES)
    try:
        body = json.loads(a.body)
    except ValueError:
        body = a.body[:200].decode(errors="replace")
    return a.status, body


def record(name, expect, status, body, ok, extra=None):
    results.append({"test": name, "expected": expect, "status": status, "ok": ok,
                    "answer": body if isinstance(body, str) else {k: body.get(k) for k in
                              ("code", "detail", "status", "state", "executed", "request_id", "error") if k in body},
                    **(extra or {})})
    print(json.dumps(results[-1]), flush=True)


async def main():
    target = cp._robot_target(robot.robot_id, "action-requests")
    action = os.environ.get("CP_ACTION", "quarantine_node")
    rid = f"{action}:rt-ugv-001:{secrets.token_hex(6)}"
    doc = {"request_id": rid, "action": action, "parameters": {"participant_guid": guid},
           "reason": "red-team positive control", "requested_by": "redteam@soc",
           "source": "redteam", "authority": "request"}
    if action == "isolate_network":
        doc["parameters"] = {}; doc["ttl_seconds"] = 120
    body = cp.body_bytes(doc)
    nft0 = nft()
    valid = raw_request("POST", target, body)
    st, b = await send(valid)
    await asyncio.sleep(3)
    nft1 = nft()
    record(f"CP0 valid SOC-signed {action} (positive control)", "accepted, executor applies nft",
           st, b, st in (200, 201, 202), {"nft_tables_before": nft0.count("table "),
                                          "nft_tables_after": nft1.count("table "),
                                          "nft_mentions_guid_or_quarantine": ("quarantine" in nft1) or (guid[:8] in nft1)})
    st, b = await send(valid)
    record("CP1 exact replay of the valid request bytes", "401 replay", st, b, st == 401)
    attacker = Ed25519PrivateKey.generate()
    body2 = body.replace(rid.encode(), (rid + "x").encode())
    st, b = await send(raw_request("POST", target, body2, key=attacker))
    record("CP2 forged: SOC key id, signed by another key", "401", st, b, st == 401)
    st, b = await send(raw_request("POST", target, body2, key=attacker, key_id="ed25519:0000000000000000"))
    record("CP3 forged: unknown key id", "401", st, b, st == 401)
    st, b = await send(raw_request("POST", target, body2, sign_body=body))
    record("CP4 body altered after signing", "401", st, b, st == 401)
    st, b = await send(raw_request("POST", target, body2, ts=int(time.time()) - 3600))
    record("CP5 stale timestamp (1 h old), valid signature", "401", st, b, st == 401)
    other = cp._robot_target("ugv-other", "action-requests")
    st, b = await send(raw_request("POST", other, body2))
    record("CP6 request for another robot id", "refused (401/404)", st, b, st in (401, 403, 404))
    await asyncio.sleep(1)
    nft2 = nft()
    record("CP7 no nft change from CP1-CP6", "ruleset unchanged since CP0", None, "", nft2 == nft1)
    return rid


import threading


def feed_idle():
    # The safety PLC gateway's role: a fresh "idle" every 200 ms (root, 0600 socket).
    c = socket.socket(socket.AF_UNIX); c.connect(os.path.join(rt, "safety.sock"))
    while True:
        c.sendall(b'{"state":"idle"}\n'); time.sleep(0.2)


if os.environ.get("FEED_IDLE") == "1":
    threading.Thread(target=feed_idle, daemon=True).start(); time.sleep(2)
rid = asyncio.run(main())

# --- executor socket, bypassing agentd -------------------------------------
sock = os.path.join(rt, "executor.sock")
KEY = bytes.fromhex(open(os.path.join(rt, "executor.key")).read().strip())


def envelope(msg, key):
    ts = int(time.time() * 1000); nonce = secrets.token_hex(16)
    mac = hmac.new(key, b"robodr-executor/1\x00" + str(ts).encode() + b"\x00" + nonce.encode()
                   + b"\x00\x00" + msg.encode(), hashlib.sha256).hexdigest()
    return json.dumps({"v": "robodr-executor/1", "ts": ts, "nonce": nonce, "reply_to": "",
                       "msg": msg, "mac": mac}).encode() + b"\n"


def exchange(line):
    c = socket.socket(socket.AF_UNIX); c.settimeout(5); c.connect(sock); c.sendall(line)
    try:
        data = c.recv(65536)
    except (socket.timeout, ConnectionResetError) as e:
        data = repr(e).encode()
    c.close()
    return data.decode(errors="replace")[:300]


nft_a = nft()
ans = exchange(envelope('{"op":"ping"}', os.urandom(32)))
record("EX1 executor envelope with a wrong HMAC key", "refused / closed", None, ans, "pong" not in ans)
# A forged order from a (hypothetically) compromised agentd holding the HMAC
# key: claims a SOC approval but carries no SOC-signed request.
order = {"id": "forged-1", "action": "isolate_network", "target": {"kind": "none"}, "ttl_s": 60,
         "judged_state": "idle",
         "context": {"platform": "ugv", "morphology": "wheeled_mobile", "phase": "parked",
                     "connectivity": "connected", "control": "autonomous",
                     "operator_present": True, "profile_locked": True},
         "plan_morphology": "wheeled_mobile", "human_approved": True,
         "origin": {"kind": "control_plane", "key_id": sk["key_id"], "requested_by": "x"},
         "issued_ms": int(time.time() * 1000)}
ans = exchange(envelope(json.dumps({"op": "submit", "order": order}), KEY))
record("EX2 HMAC-valid submit, human_approved without a SOC-signed request", "refused, no nft change",
       None, ans, "applied" not in ans and nft() == nft_a)
print("NFT_AFTER_ALL:", nft().count("table "), "tables")
json.dump(results, open(os.path.join(rt, "redteam_cp.json"), "w"), indent=1)
