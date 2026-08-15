#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: Docker is not installed or not on PATH." >&2
  exit 1
fi

docker compose config -q
docker compose up -d --build

echo
echo "Waiting for services to become healthy..."
for _ in $(seq 1 30); do
  app_status="$(docker inspect --format='{{.State.Health.Status}}' fyp-vulnerable-store 2>/dev/null || true)"
  exec_status="$(docker inspect --format='{{.State.Health.Status}}' fyp-controlled-executor 2>/dev/null || true)"

  if [[ "$app_status" == "healthy" && "$exec_status" == "healthy" ]]; then
    echo "Environment is healthy."
    echo "Dummy app: http://127.0.0.1:8000"
    exit 0
  fi

  sleep 2
done

echo "ERROR: services did not become healthy in time." >&2
docker compose ps
exit 1
