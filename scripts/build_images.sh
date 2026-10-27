#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Build the lightweight Alpine node image used by every twin container.
#
# Safe to re-run: the build is cached. On a Raspberry Pi 5 this takes roughly a
# minute on first run.
# ---------------------------------------------------------------------------
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${TWIN_HOST_IMAGE:-twin-host:latest}"

echo "[build_images] building ${IMAGE} for $(uname -m)"
docker build \
  --tag "${IMAGE}" \
  --file "${REPO_ROOT}/docker/twin-host.Dockerfile" \
  "${REPO_ROOT}/docker"

echo "[build_images] done: ${IMAGE}"
docker image inspect "${IMAGE}" --format '  size: {{.Size}} bytes  arch: {{.Architecture}}'
