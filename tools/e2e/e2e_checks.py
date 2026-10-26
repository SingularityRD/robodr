#!/usr/bin/env python3
"""E2E assertions against a live AutoSecOps API after robodr-uplink delivered
the agentd spool (run with the AutoSecOps venv python).

usage: e2e_checks.py STATE ROBOT_DIR ROBOT2_DIR AUDIT_FILE INGEST_URL CA_PEM

  ROBOT_DIR   robot 1 (fleet-enrolled): spool-orig/ (pristine copy of the
              spool uplink delivered), keys/uplink.key
  ROBOT2_DIR  robot 2 (registered by hand): spool/ with its own findings
Prints one PASS/FAIL line per assertion and exits 1 on any FAIL.
"""
import hashlib, json, os, struct, sys, time, uuid
import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aso_client import Aso

state, r1, r2, audit_file, ingest_url, ca = sys.argv[1:7]
aso = Aso(state)
fails = 0


def check(name, ok, detail=""):
    global fails
    fails += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def spool_lines(spool):
    out = []
    for sub in ("acked", "ready"):
        p = os.path.join(spool, sub)
        for n in sorted(os.listdir(p)) if os.path.isdir(p) else []:
            rec = json.load(open(os.path.join(p, n)))
            sig = dict(rec["headers"]).get("robodr-finding-sig")
            out.append((rec["value"], json.loads(sig) if sig else None))
    return out


def wire(lines):
    return b"".join(json.dumps({"value": v, "sig": s}, separators=(",", ":")).encode() + b"\n"
                    for v, s in lines)


class Key:
    def __init__(self, path=None):
        if path:
            d = json.load(open(path))
            self.sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(d["secret_hex"]))
        else:
            self.sk = Ed25519PrivateKey.generate()
        pub = self.sk.public_key().public_bytes_raw()
        self.key_id = "ed25519:" + hashlib.sha256(
            b"robodr-blackbox/ed25519-key-id/v1\x00" + pub).digest()[:8].hex()


def post(key, batch_id, body, key_id=None, ts=None):
    kid = key_id or key.key_id
    ts = ts or int(time.time() * 1000)
    msg = (b"robodr-ingest/batch/v1\x00" + struct.pack(">I", len(kid)) + kid.encode()
           + struct.pack(">I", len(batch_id)) + batch_id.encode() + struct.pack(">Q", ts)
           + hashlib.sha256(body).digest())
    h = {"Content-Type": "application/x-ndjson", "X-RoboDR-Key-Id": kid,
         "X-RoboDR-Batch-Id": batch_id, "X-RoboDR-Timestamp": str(ts),
         "X-RoboDR-Signature": key.sk.sign(msg).hex()}
    return requests.post(ingest_url, data=body, headers=h, verify=ca, timeout=30)


def cases():
    return aso.get("/cases", params={"limit": 200})["items"]


def audit_lines():
    try:
        return [l.split("\t", 1) for l in open(audit_file).read().splitlines()]
    except FileNotFoundError:
        return []


# --- A1 cases, tag, severity and fields -----------------------------------
lines1 = spool_lines(os.path.join(r1, "spool-orig"))
by_id = {}
for v, _ in lines1:
    f = json.loads(v)
    by_id[f["external_id"]] = f
cs = cases()
robodr_cases = [c for c in cs if any(t["ref"] == "robodr" for t in c["tags"])]
check("A1 one case per distinct finding, all tagged robodr",
      len(robodr_cases) == len(by_id) == len(cs),
      f"spool={len(lines1)} lines, {len(by_id)} distinct findings; cases={len(cs)}, robodr-tagged={len(robodr_cases)}")
bad = []
for c in robodr_cases:
    d = aso.get(f"/cases/{c['id']}")
    fv = {f["id"]: f["value"] for f in d["fields"]}
    ext = next((e for e in by_id if f"`{e}`" in d["description"]), None)
    f = by_id.get(ext)
    if f is None:
        bad.append((c["short_id"], "no matching finding")); continue
    want = f["severity"]
    rule = f["ocsf"]["finding_info"]["analytic"]["uid"]
    if (c["severity"], c["priority"]) != (want, want) or fv.get("robot_id") != "lab-ugv-001" \
            or fv.get("rule_id") != rule or fv.get("site") != "lab":
        bad.append((c["short_id"], c["severity"], want, fv.get("rule_id"), rule))
check("A2 case severity/priority = finding severity; robot_id, site, rule_id fields",
      not bad, f"{len(robodr_cases)} cases checked" + (f"; mismatches {bad}" if bad else ""))

# --- A3 dedup: same findings again under a new batch id --------------------
up1 = Key(os.path.join(r1, "keys/uplink.key"))
n_before = len(cs)
r = post(up1, f"e2e-dedup-{uuid.uuid4().hex[:12]}", wire(lines1[:100]))
j = r.json()
check("A3 re-sent findings are duplicates, no new case",
      r.status_code == 200 and j["duplicates"] == 100 and j["created"] == 0
      and len(cases()) == n_before,
      f"HTTP {r.status_code} accepted={j.get('accepted')} created={j.get('created')} "
      f"updated={j.get('updated')} duplicates={j.get('duplicates')}; cases {n_before}->{len(cases())}")

# --- A4 replay: same batch id, same body -> stored response ---------------
bid = f"e2e-replay-{uuid.uuid4().hex[:12]}"
body = wire(lines1[100:110])
a = post(up1, bid, body); b = post(up1, bid, body)
check("A4 same batch id + body -> replayed:true, same counts",
      a.status_code == b.status_code == 200 and a.json()["replayed"] is False
      and b.json()["replayed"] is True
      and {k: v for k, v in a.json().items() if k != "replayed"}
      == {k: v for k, v in b.json().items() if k != "replayed"},
      f"1st replayed={a.json().get('replayed')} 2nd HTTP {b.status_code} replayed={b.json().get('replayed')}")
c_ = post(up1, bid, wire(lines1[110:111]))
check("A5 same batch id, other body -> 409 batch_id_reuse",
      c_.status_code == 409 and c_.json().get("code") == "batch_id_reuse",
      f"HTTP {c_.status_code} {c_.text[:120]}")

# --- A6/A7 wrong keys -> 401 + audit --------------------------------------
n_audit = len(audit_lines())
rogue = Key()
r = post(rogue, f"e2e-rogue-{uuid.uuid4().hex[:12]}", wire(lines1[:1]))
r_bad = post(rogue, f"e2e-forged-{uuid.uuid4().hex[:12]}", wire(lines1[:1]), key_id=up1.key_id)
time.sleep(2)
new = audit_lines()[n_audit:]
fail_events = [(p, json.loads(b)) for p, b in new if '"robot' in b and "FAILURE" in b]
check("A6 batch signed by an unregistered key -> 401 unknown_key",
      r.status_code == 401 and r.json().get("code") == "unknown_key", f"HTTP {r.status_code} {r.text[:100]}")
check("A7 batch claiming the uplink key id, signed by another key -> 401 bad_signature",
      r_bad.status_code == 401 and r_bad.json().get("code") == "bad_signature",
      f"HTTP {r_bad.status_code} {r_bad.text[:100]}")
check("A8 both 401s audited (actor ROBOT, status FAILURE, reason, client IP)",
      len(fail_events) >= 2,
      "; ".join(f"{p}: actor={e['actor_type']} action={e['action']} status={e['status']} "
                f"ip={e['ip_address']} data={e.get('data')}" for p, e in fail_events) or f"new audit lines: {new}")

# --- A9 finding for another robot -> robot_mismatch -----------------------
lines2 = spool_lines(os.path.join(r2, "spool"))
r = post(up1, f"e2e-mismatch-{uuid.uuid4().hex[:12]}", wire(lines2[:1] + lines1[:1]))
j = r.json()
codes = [x.get("code") for x in j.get("rejected", [])]
check("A9 robot-2 finding in robot-1's uplink batch -> line rejected robot_mismatch, rest accepted",
      r.status_code == 200 and codes == ["robot_mismatch"] and j["accepted"] == 1,
      f"HTTP {r.status_code} rejected={j.get('rejected')} accepted={j.get('accepted')}")

# --- A10 tampered finding value (per-finding signature) -------------------
v, s = lines1[0]
# Same JSON content, other bytes (one space): only the signature can tell.
tampered = v.replace('"contract_version":', '"contract_version": ', 1)
r = post(up1, f"e2e-tamper-{uuid.uuid4().hex[:12]}", wire([(tampered, s)]))
check("A10 finding bytes altered after signing (content-equal) -> bad_finding_signature",
      r.status_code == 200 and [x.get("code") for x in r.json().get("rejected", [])] == ["bad_finding_signature"],
      f"rejected={r.json().get('rejected')}")
print(f"\n{fails} failure(s)")
sys.exit(1 if fails else 0)
