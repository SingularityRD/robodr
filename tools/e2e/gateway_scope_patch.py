"""Action-gateway launcher that adds `robot:read` to the executor's service
scopes IN PROCESS ONLY (no repo change), to prove the rest of the evidence
path once the AutoSecOps defect is fixed: WORKSPACE_OPERATIONAL_SCOPES
(autosecops/authz/scopes.py) lacks `robot:read`, which every route of
autosecops/robot_edr/evidence_router.py requires, so the shipped gateway
answers 403 insufficient_scope to download_evidence_export.

usage: uvicorn --factory gateway_scope_patch:create_app --uds SOCK
"""
from autosecops.authz import scopes

for sid, s in list(scopes.SERVICE_PRINCIPAL_SCOPES.items()):
    scopes.SERVICE_PRINCIPAL_SCOPES[sid] = s | {"robot:read"}

from autosecops.executor.action_gateway.app import create_app  # noqa: E402,F401
