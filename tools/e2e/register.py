#!/usr/bin/env python3
"""Register a robot in AutoSecOps and give it keys.

  register.py STATE ROBOT_DIR ROBOT_ID fleet  [--soc-url URL] [--ca-bundle PEM]
      Preferred path: robot created through the management API, SOC fleet key
      generated + activated, single-use token issued, then `robodr-enroll`
      on the unit generates and registers the uplink/finding/black-box keys.
  register.py STATE ROBOT_DIR ROBOT_ID manual
      Robot + uplink + finding keys through POST /robot-edr/robots and /keys
      (keys made with robodr-blackbox keygen in ROBOT_DIR).
Run with the AutoSecOps venv python. Writes ROBOT_DIR/registration.json.
"""
import argparse, json, os, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aso_client import Aso, pub_hex

B = os.environ.get("ROBODR_BIN", "/home/user/robodr/target/release")
ap = argparse.ArgumentParser()
ap.add_argument("state"); ap.add_argument("dir"); ap.add_argument("robot_id")
ap.add_argument("mode", choices=["fleet", "manual"])
ap.add_argument("--site", default="lab")
ap.add_argument("--soc-url", default="http://127.0.0.1:8000/api")
ap.add_argument("--ca-bundle")
ap.add_argument("--require-finding-signature", action="store_true")
a = ap.parse_args()
d = os.path.abspath(a.dir)
aso = Aso(a.state)

existing = [r for r in aso.get("/robot-edr/robots", params={"limit": 200})["items"]
            if r["robot_id"] == a.robot_id]
robot = existing[0] if existing else aso.post("/robot-edr/robots", {"robot_id": a.robot_id, "site": a.site,
                                        "model": "lab-ugv", "morphology": "ugv",
                                        "require_finding_signature": a.require_finding_signature})
print("robot", robot["id"], robot["robot_id"])
reg = {"robot": robot}

def keygen(path, kid=None):
    # Sender keys must keep the derived ed25519:<16 hex> id (robodr-uplink refuses others).
    extra = ["--key-id", kid] if kid else []
    subprocess.run([f"{B}/robodr-blackbox", "keygen", "--out", path, *extra],
                   check=True, stdout=subprocess.DEVNULL)

if a.mode == "manual":
    up = f"{d}/uplink.key"
    if not os.path.exists(up):
        keygen(up)
    have = {k["public_key"] for k in aso.get("/robot-edr/keys", params={"limit": 200})["items"]}
    if pub_hex(up + ".pub") not in have:
        reg["uplink_key"] = aso.post("/robot-edr/keys", {
            "role": "uplink", "robot_id": a.robot_id, "public_key": pub_hex(up + ".pub")})
    if pub_hex(f"{d}/finding.key.pub") not in have:
        reg["finding_key"] = aso.post("/robot-edr/keys", {
            "role": "finding", "robot_id": a.robot_id,
            "public_key": pub_hex(f"{d}/finding.key.pub"), "key_id": f"finding-{a.robot_id}"})
    reg["uplink_key_file"] = up
else:
    keys = aso.get("/robot-edr/fleet/soc-keys")
    fleet = [k for k in keys if k["kind"] == "fleet" and k["status"] == "active"]
    if not fleet:
        k = aso.post("/robot-edr/fleet/soc-keys", {"kind": "fleet"})
        if k["status"] != "active":
            k = aso.post(f"/robot-edr/fleet/soc-keys/{k['id']}/activate")
        fleet = [k]
    soc = fleet[0]
    print("SOC fleet key", soc["key_id"], soc["status"])
    keyd = f"{d}/fleet-etc"; os.makedirs(keyd, mode=0o755, exist_ok=True)
    open(f"{keyd}/fleet-soc.pub", "w").write(soc["public_key_file"])
    # Approval key: offline, operator-held; only its public half goes on the unit.
    if not os.path.exists(f"{keyd}/approval.key"):
        keygen(f"{keyd}/approval.key", "soc-approval")
    for f in ("fleet-soc.pub", "approval.key.pub"):
        os.chmod(f"{keyd}/{f}", 0o644)
    kd = f"{d}/keys"; os.makedirs(kd, mode=0o700, exist_ok=True)
    tok = aso.post(f"/robot-edr/robots/{robot['id']}/fleet/tokens", {"validity_hours": 1})
    tf = f"{d}/token.txt"
    fd = os.open(tf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, tok["token"].encode()); os.close(fd)
    print("token issued", tok["token_id"], "(token itself not printed)")
    sd = f"{d}/fleet-state"; os.makedirs(sd, mode=0o700, exist_ok=True)
    cfg = {"format": "robodr-fleet-config/v1", "state_dir": sd,
           "agentd_config": f"{d}/agentd.json",
           "soc": {"url": a.soc_url, "ca_bundle": a.ca_bundle, "spki_sha256": [],
                   "keys": [f"{keyd}/fleet-soc.pub"],
                   "approval_keys": [f"{keyd}/approval.key.pub"]},
           "workspace": aso.ws,
           "keys": {"uplink": f"{kd}/uplink.key", "finding": f"{kd}/finding.key",
                    "blackbox": f"{kd}/blackbox.key"}}
    if a.ca_bundle is None:
        del cfg["soc"]["ca_bundle"]
    json.dump(cfg, open(f"{d}/fleet.json", "w"), indent=2)
    r = subprocess.run([f"{B}/robodr-enroll", "--config", f"{d}/fleet.json",
                        "--token-file", tf], capture_output=True, text=True)
    print(r.stdout + r.stderr)
    os.unlink(tf)
    if r.returncode != 0:
        sys.exit(f"robodr-enroll failed rc={r.returncode}")
    reg["uplink_key_file"] = f"{kd}/uplink.key"
    reg["fleet_status"] = aso.get(f"/robot-edr/robots/{robot['id']}/fleet")
json.dump(reg, open(f"{d}/registration.json", "w"), indent=2)
