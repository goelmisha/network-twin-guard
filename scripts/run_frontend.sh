#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Start the Streamlit validation dashboard.
#
# The dashboard talks to the backend over HTTP; make sure the backend is running
# first (scripts/run_backend.sh). Override the API location with TWIN_API_BASE_URL.
#
# Usage:  scripts/run_frontend.sh
# ---------------------------------------------------------------------------
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${TWIN_PYTHON:-${REPO_ROOT}/.venv/bin/python}"

if [[ ! -x "${PYTHON}" ]]; then
  echo "error: virtualenv not found at ${PYTHON}" >&2
  echo "       create it first:  scripts/setup_env.sh" >&2
  exit 1
fi

export TWIN_API_BASE_URL="${TWIN_API_BASE_URL:-http://localhost:8000}"
UI_PORT="${TWIN_UI_PORT:-8501}"
UI_HOST="${TWIN_UI_HOST:-0.0.0.0}"

# Use the loopback address in the banner: 0.0.0.0 is a bind address, not a
# browseable URL.
BROWSE_HOST="${UI_HOST}"
if [[ "${BROWSE_HOST}" == "0.0.0.0" ]]; then
  BROWSE_HOST="localhost"
fi

echo "[frontend] API base URL: ${TWIN_API_BASE_URL}"
echo "[frontend] dashboard:   http://${BROWSE_HOST}:${UI_PORT}"
exec "${PYTHON}" -m streamlit run "${REPO_ROOT}/frontend/app.py" \
  --server.port "${UI_PORT}" \
  --server.address "${UI_HOST}" \
  --server.headless true
