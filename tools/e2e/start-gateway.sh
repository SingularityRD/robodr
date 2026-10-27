#!/usr/bin/env bash
# Start the AutoSecOps action gateway on a unix socket for the evidence E2E.
# usage: start-gateway.sh ENV_FILE SOCK LOG [patched]
#   patched: gateway_scope_patch:create_app (adds robot:read in process; see that file)
set -euo pipefail
envf=$1; sock=$2; log=$3; mode=${4:-}
cd "${ASO_DIR:-/home/user/autosecops1}"
set -a; . "$envf"; set +a
rm -f "$sock"
app=autosecops.executor.action_gateway.app:create_app
if [ "$mode" = patched ]; then
  export PYTHONPATH="$(dirname "$(readlink -f "$0")")${PYTHONPATH:+:$PYTHONPATH}"
  app=gateway_scope_patch:create_app
fi
exec uv run --frozen python -m uvicorn "$app" --factory --uds "$sock" >"$log" 2>&1
