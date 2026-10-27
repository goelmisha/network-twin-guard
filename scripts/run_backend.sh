#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Start the FastAPI backend.
#
# Works with or without the lab deployed: when Docker is unavailable the
# platform runs in model-only mode and says so on /api/v1/health.
#
# Usage:  scripts/run_backend.sh [--reload]
# ---------------------------------------------------------------------------
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${TWIN_PYTHON:-${REPO_ROOT}/.venv/bin/python}"

if [[ ! -x "${PYTHON}" ]]; then
  echo "error: virtualenv not found at ${PYTHON}" >&2
  echo "       create it first:  scripts/setup_env.sh" >&2
  exit 1
fi

HOST="${TWIN_API_HOST:-0.0.0.0}"
PORT="${TWIN_API_PORT:-8000}"
RELOAD_FLAG=""
if [[ "${1:-}" == "--reload" ]]; then
  RELOAD_FLAG="--reload"
fi

echo "[backend] serving on http://${HOST}:${PORT} (docs at /docs)"
exec "${PYTHON}" -m uvicorn app.main:app \
  --app-dir "${REPO_ROOT}/backend" \
  --host "${HOST}" \
  --port "${PORT}" \
  ${RELOAD_FLAG}
