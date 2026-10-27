#!/usr/bin/env bash
# Start the AutoSecOps API (uvicorn, no Caddy) for the RoboDR E2E harness.
# usage: start-aso-api.sh ENV_FILE LOG_FILE [PORT] [extra uvicorn args...]
# FastAPI takes root_path from TRACECAT__API_ROOT_PATH=/api, so request targets
# look like the stock Caddy deployment (/api/robot-edr/v2/...). Do not pass
# uvicorn --root-path as well (it would double the prefix).
set -euo pipefail
envf=$1; log=$2; port=${3:-8000}; shift 3 || shift $#
cd "${ASO_DIR:-/home/user/autosecops1}"
set -a; . "$envf"; set +a
exec uv run --frozen python -m uvicorn autosecops.api.app:app \
  --host 127.0.0.1 --port "$port" "$@" >"$log" 2>&1
