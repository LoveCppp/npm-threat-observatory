#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "${ROOT_DIR}"

podman compose down || true
podman ps -a --format '{{.Names}}' | grep '^analysis-' | xargs -r podman rm -f
podman volume prune -f || true

if podman machine inspect podman-machine-default >/dev/null 2>&1; then
  podman machine stop podman-machine-default || true
  podman machine start podman-machine-default
fi

podman compose up -d
