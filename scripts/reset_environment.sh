#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: Docker is not installed or not on PATH." >&2
  exit 1
fi

echo "Stopping lab and deleting runtime volume..."
docker compose down --volumes --remove-orphans

echo "Starting from clean runtime state..."
bash scripts/start_environment.sh
