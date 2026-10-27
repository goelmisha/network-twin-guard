#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Destroy the digital twin lab and remove its virtual wiring.
#
# Usage:  scripts/teardown.sh
# ---------------------------------------------------------------------------
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v containerlab >/dev/null 2>&1; then
  echo "error: containerlab is not installed." >&2
  exit 1
fi

echo "[teardown] destroying lab from ${REPO_ROOT}/corporate-twin.yml"
containerlab destroy -t "${REPO_ROOT}/corporate-twin.yml" --cleanup

echo "[teardown] done. The backend keeps working in model-only mode."
