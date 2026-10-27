#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Create the project virtualenv and install all dependencies.
#
# Uses `uv` when available (much faster, and it picks prebuilt arm64 wheels),
# falling back to the standard library venv module.
#
# The interpreter is taken from `python3` on PATH. Export TWIN_PYTHON_VERSION to
# pin a specific version, e.g. TWIN_PYTHON_VERSION=3.12 scripts/setup_env.sh
#
# Usage:  scripts/setup_env.sh
# ---------------------------------------------------------------------------
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

VENV="${REPO_ROOT}/.venv"

# Pin an interpreter only when explicitly requested. Defaulting to a hard-coded
# version would make `uv` silently download a second CPython on machines that
# already have a suitable one (and fail outright when offline).
PYTHON_SPEC="${TWIN_PYTHON_VERSION:-}"

if command -v uv >/dev/null 2>&1; then
  echo "[setup] using uv"
  if [[ -z "${PYTHON_SPEC}" ]]; then
    # Pass a version rather than a filesystem path: uv resolves versions through
    # its own interpreter discovery, which copes with builds (e.g. some Homebrew
    # installs) that report an empty platform.mac_ver() and are rejected when
    # handed over as an explicit path.
    PYTHON_SPEC="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || true)"
  fi
  if [[ -n "${PYTHON_SPEC}" ]]; then
    uv venv --python "${PYTHON_SPEC}" "${VENV}"
  else
    uv venv "${VENV}"
  fi
  uv pip install --python "${VENV}/bin/python" \
    -r backend/requirements.txt \
    -r frontend/requirements.txt \
    -r requirements-dev.txt
else
  echo "[setup] using python3 -m venv"
  python3 -m venv "${VENV}"
  "${VENV}/bin/python" -m pip install --upgrade pip
  "${VENV}/bin/pip" install \
    -r backend/requirements.txt \
    -r frontend/requirements.txt \
    -r requirements-dev.txt
fi

echo
echo "[setup] done. Virtualenv: ${VENV}"
echo "  backend :  scripts/run_backend.sh"
echo "  frontend:  scripts/run_frontend.sh"
