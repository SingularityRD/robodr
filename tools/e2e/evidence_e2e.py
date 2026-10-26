#!/usr/bin/env python3
"""Evidence E2E: drive the AutoSecOps registry actions (production code path)
against a live agentd control plane v2 (mutual TLS), storing a verified
evidence report on the case through the action gateway (/internal SDK path).

usage (AutoSecOps venv python, env from aso.env):
  evidence_e2e.py STATE ROBOT_DIR CP_TLS_DIR SOC_KEY GW_SOCK RULE_ID [BASE_URL]

The executor token is minted with autosecops.auth.executor_tokens (the same
service key as the running API/gateway), as the executor does per run.
"""
import asyncio, json, os, sys, uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aso_client import Aso

state, rdir, tls, soc_key, gw_sock, rule = sys.argv[1:7]
base_url = sys.argv[7] if len(sys.argv) > 7 else "https://127.0.0.1:8787"

from autosecops.auth.executor_tokens import mint_executor_token  # noqa: E402
from autosecops_registry import context as rctx  # noqa: E402
from autosecops_registry._internal import secrets as rsecrets  # noqa: E402
from autosecops_registry.integrations import robodr_control_plane as cp  # noqa: E402

aso = Aso(state)
# The finding (from the pristine spool) and its case.
finding = None
for sub in ("ready",):
    d = os.path.join(rdir, "spool-orig", sub)
    for n in sorted(os.listdir(d)):
        f = json.loads(json.load(open(os.path.join(d, n)))["value"])
        if f["ocsf"]["finding_info"]["analytic"]["uid"] == rule:
            finding = f; break
assert finding, rule
case = next(c for c in aso.get("/cases", params={"limit": 200})["items"]
            if c["summary"] and finding["title"] in c["summary"])
print(f"finding {finding['finding_id']} ({rule}, {len(finding['evidence_links'])} evidence links) "
      f"-> case {case['short_id']} {case['id']}")

sk = json.load(open(soc_key))
fk = json.load(open(os.path.join(rdir, "keys/finding.key.pub")))
rsecrets.set_context({
    "ROBODR_SOC_KEY_ID": sk["key_id"], "ROBODR_SOC_SECRET_HEX": sk["secret_hex"],
    "ROBODR_SOC_CLIENT_CERT_PEM": open(f"{tls}/soc.pem").read(),
    "ROBODR_SOC_CLIENT_KEY_PEM": open(f"{tls}/soc.key").read(),
})
wf_id = "wf-" + uuid.uuid4().hex
# A workflow run started by the operator carries the operator's user id;
# the gateway derives the run's scopes (robot:read, case access) from it.
me = aso.s.get(f"{aso.B}/users/me").json()
token = mint_executor_token(workspace_id=uuid.UUID(aso.ws), user_id=uuid.UUID(me["id"]),
                            wf_id=wf_id, wf_exec_id=f"{wf_id}:exec-e2e")
os.environ.update({"TRACECAT__ACTION_GATEWAY_SOCKET": gw_sock,
                   "TRACECAT__EXECUTOR_TOKEN": token, "TRACECAT__WORKSPACE_ID": aso.ws,
                   "TRACECAT__WORKFLOW_ID": wf_id, "TRACECAT__RUN_ID": "run-e2e"})
rctx.set_context(rctx.RegistryContext.from_env())

common = dict(base_url=base_url, robot_id=finding["entity_context"]["robot"]["id"],
              robot_ca_pem=open(f"{tls}/robot-ca.pem").read(),
              answer_public_key_hex=fk["public_hex"], answer_key_id=fk["key_id"])
sel = dict(finding_id=finding["finding_id"], evidence_links=finding["evidence_links"])
export_id = "e2e-" + uuid.uuid4().hex[:12]


async def main():
    snap = await cp.get_robot(**common)
    print("get_robot:", json.dumps(snap)[:300])
    inv = await cp.list_evidence(**common)
    print("list_evidence:", json.dumps(inv)[:300])
    created = await cp.create_evidence_export(**common, export_id=export_id,
                                              requested_by="e2e-operator", reason="E2E evidence", **sel)
    print("create_evidence_export:", json.dumps(created)[:400])
    dl = await cp.download_evidence_export(**common, export_id=export_id,
                                           case_id=case["id"], **sel)
    print("download_evidence_export: verified =", dl["verified"], "stored =", json.dumps(dl["stored"])[:400])
    print("verification:", json.dumps(dl["verification"])[:800])
    return dl

dl = asyncio.run(main())
print(json.dumps({"case_id": case["id"], "export_id": export_id, "verified": dl["verified"]}))
