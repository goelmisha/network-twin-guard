#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# One-command deployment of the branch-office digital twin.
#
#   1. validates config/model.yaml against corporate-twin.yml
#   2. renders per-node bootstrap scripts (addressing, routes, iptables)
#   3. builds the Alpine node image if it is missing
#   4. deploys the lab with containerlab
#
# Usage:  scripts/deploy.sh
# ---------------------------------------------------------------------------
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

PYTHON="${TWIN_PYTHON:-${REPO_ROOT}/.venv/bin/python}"
if [[ ! -x "${PYTHON}" ]]; then
  PYTHON="$(command -v python3)"
fi

if ! command -v containerlab >/dev/null 2>&1; then
  echo "error: containerlab is not installed." >&2
  echo "       install: curl -sL https://containerlab.dev/setup | sudo -E bash -s 'all'" >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "error: the Docker daemon is not reachable." >&2
  exit 1
fi

echo "[deploy] (1/4) validating the model and rendering bootstrap scripts"
"${PYTHON}" scripts/render_policies.py

echo "[deploy] (2/4) ensuring the node image exists"
if ! docker image inspect "${TWIN_HOST_IMAGE:-twin-host:latest}" >/dev/null 2>&1; then
  "${REPO_ROOT}/scripts/build_images.sh"
else
  echo "  ${TWIN_HOST_IMAGE:-twin-host:latest} already present"
fi

echo "[deploy] (3/4) deploying the topology"
containerlab deploy -t "${REPO_ROOT}/corporate-twin.yml"

echo "[deploy] (4/4) verifying node reachability"
containerlab inspect -t "${REPO_ROOT}/corporate-twin.yml" || true

echo
echo "[deploy] lab is up. Start the platform with:"
echo "  scripts/run_backend.sh    # http://localhost:8000/docs"
echo "  scripts/run_frontend.sh   # http://localhost:8501"
