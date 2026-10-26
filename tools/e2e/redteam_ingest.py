#!/usr/bin/env python3
"""Red-team the ingest API with forged / replayed / oversized batches.
usage (AutoSecOps venv python): redteam_ingest.py INGEST_URL UPLINK_KEY SPOOL_DIR AUDIT_FILE"""
import hashlib, json, os, struct, sys, time, uuid
import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

url, keyf, spool, audit = sys.argv[1:5]


def kid(sk):
    pub = sk.public_key().public_bytes_raw()
    return "ed25519:" + hashlib.sha256(b"robodr-blackbox/ed25519-key-id/v1\x00" + pub).digest()[:8].hex()


real = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(json.load(open(keyf))["secret_hex"]))


def post(sk, body, batch=None, key_id=None, ts=None, ctype="application/x-ndjson"):
    key_id = key_id or kid(sk); batch = batch or f"rt-{uuid.uuid4().hex[:16]}"
    ts = ts if ts is not None else int(time.time() * 1000)
    msg = (b"robodr-ingest/batch/v1\x00" + struct.pack(">I", len(key_id)) + key_id.encode()
           + struct.pack(">I", len(batch)) + batch.encode() + struct.pack(">Q", ts)
           + hashlib.sha256(body).digest())
    h = {"Content-Type": ctype, "X-RoboDR-Key-Id": key_id, "X-RoboDR-Batch-Id": batch,
         "X-RoboDR-Timestamp": str(ts), "X-RoboDR-Signature": sk.sign(msg).hex()}
    r = requests.post(url, data=body, headers=h, timeout=30)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:200]


names = sorted(os.listdir(os.path.join(spool, "acked")))[:3]
lines = []
for n in names:
    rec = json.load(open(os.path.join(spool, "acked", n)))
    sig = dict(rec["headers"]).get("robodr-finding-sig")
    lines.append(json.dumps({"value": rec["value"], "sig": json.loads(sig) if sig else None},
                            separators=(",", ":")).encode())
body = b"\n".join(lines) + b"\n"
n0 = sum(1 for _ in open(audit))
out = []
attacker = Ed25519PrivateKey.generate()
out.append(("IN1 batch signed by an unregistered key", "401 unknown_key", *post(attacker, body)))
out.append(("IN2 claims the robot's uplink key id, signed by attacker", "401 bad_signature",
            *post(attacker, body, key_id=kid(real))))
out.append(("IN3 genuine key, timestamp 10 min old (captured-and-delayed)", "401 stale_timestamp",
            *post(real, body, ts=int(time.time() * 1000) - 600_000)))
b = f"rt-replay-{uuid.uuid4().hex[:8]}"
s1 = post(real, body, batch=b); s2 = post(real, body, batch=b)
out.append(("IN4 same signed batch twice", "2nd replayed:true, no new effects", s2[0],
            {"first": {k: s1[1].get(k) for k in ("replayed", "accepted", "created", "updated", "duplicates")},
             "second": {k: s2[1].get(k) for k in ("replayed", "accepted", "created", "updated", "duplicates")}}))
out.append(("IN5 5 MiB body (cap 4 MiB)", "413", *post(real, b"x" * (5 * 1024 * 1024))))
out.append(("IN6 wrong content type", "415", *post(real, body, ctype="application/json")))
out.append(("IN7 malformed NDJSON lines in a signed batch", "200 with per-line rejections",
            *post(real, b'{"value":"{not json","sig":null}\nnot even json\n')))
time.sleep(2)
new = [l for l in open(audit).read().splitlines()[n0:] if "FAILURE" in l]
for name, exp, st, js in out:
    print(json.dumps({"test": name, "expected": exp, "status": st, "answer": js}))
print(json.dumps({"audit_failure_events_written": len(new),
                  "reasons": [json.loads(l.split("\t", 1)[1]).get("data", {}).get("failure_reason") for l in new]}))
