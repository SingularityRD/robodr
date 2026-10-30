"""SOC side of the control plane v2 for the soak / red team: requests are
built and signed with AutoSecOps's own SOC client code
(`autosecops_registry.integrations.robodr_control_plane`), so a positive
control is exactly what a SOC sends. Run with the AutoSecOps venv python.
TEST KEYS ONLY."""
import json, os, secrets, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from autosecops_registry._internal import secrets as rsecrets
from autosecops_registry.integrations import robodr_control_plane as cp


class Soc:
    def __init__(self, run, robot_id, url="https://127.0.0.1:8787", sub=None):
        tls = f"{run}/tls"
        self.sk = json.load(open(f"{run}/soc.key"))
        sub = sub or ("rt" if robot_id.startswith("rt-") else "ugv")
        fk = json.load(open(f"{run}/{sub}/finding.key.pub"))
        rsecrets.set_context({"ROBODR_SOC_KEY_ID": self.sk["key_id"],
                              "ROBODR_SOC_SECRET_HEX": self.sk["secret_hex"],
                              "ROBODR_SOC_CLIENT_CERT_PEM": open(f"{tls}/soc.pem").read(),
                              "ROBODR_SOC_CLIENT_KEY_PEM": open(f"{tls}/soc.key").read()})
        self.robot = cp._robot(base_url=url, robot_id=robot_id,
                               robot_ca_pem=open(f"{tls}/robot-ca.pem").read(), robot_spki_sha256=None,
                               answer_public_key_hex=fk["public_hex"], answer_key_id=fk["key_id"])
        self.key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(self.sk["secret_hex"]))
        self.robot_id = robot_id

    def raw(self, method, target, body, key=None, key_id=None, ts=None, nonce=None, sign_body=None):
        key = key or self.key
        key_id = key_id or self.sk["key_id"]
        ts = ts or int(time.time())
        nonce = nonce or secrets.token_urlsafe(24)
        sig = key.sign(cp.signing_message(method, target, self.robot_id, key_id, ts, nonce,
                                          body if sign_body is None else sign_body)).hex()
        return cp.request_bytes(method=method, target=target, host=self.robot.host_header, key_id=key_id,
                                timestamp=ts, nonce=nonce, signature_hex=sig, body=body)

    async def send(self, req):
        a = await cp._exchange(self.robot, req, max_body=cp.MAX_ANSWER_BYTES)
        try:
            body = json.loads(a.body)
        except ValueError:
            body = a.body[:300].decode(errors="replace")
        return a.status, body

    def target(self, *rest):
        return cp._robot_target(self.robot_id, *rest)

    def action(self, action, parameters=None, ttl=None, approved_by=None, requested_by="analyst@soc",
               reason="soak"):
        rid = f"{action}:{self.robot_id}:{secrets.token_hex(6)}"
        doc = {"request_id": rid, "action": action, "parameters": parameters or {},
               "reason": reason, "requested_by": requested_by, "source": "soak", "authority": "request"}
        if ttl is not None:
            doc["ttl_seconds"] = ttl
        if approved_by is not None:
            doc["approved_by"] = approved_by
        return rid, cp.body_bytes(doc)

    async def post_action(self, *a, **kw):
        rid, body = self.action(*a, **kw)
        st, b = await self.send(self.raw("POST", self.target("action-requests"), body))
        return rid, st, b

    async def get(self, *rest):
        return await self.send(self.raw("GET", self.target(*rest), b""))


def short(b):
    if isinstance(b, str):
        return b[:200]
    keep = ("code", "detail", "status", "state", "executed", "request_id", "error", "outcome", "reason",
            "in_force", "containment", "refusal", "refused")
    return {k: b.get(k) for k in keep if k in b}
