#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

docker compose config -q

app_status="$(docker inspect --format='{{.State.Health.Status}}' fyp-vulnerable-store)"
exec_status="$(docker inspect --format='{{.State.Health.Status}}' fyp-controlled-executor)"

if [[ "$app_status" != "healthy" ]]; then
  echo "ERROR: vulnerable-store is not healthy: $app_status" >&2
  exit 1
fi

if [[ "$exec_status" != "healthy" ]]; then
  echo "ERROR: controlled-executor is not healthy: $exec_status" >&2
  exit 1
fi

echo "PASS: both services are healthy."

docker compose exec -T controlled-executor   python -m infrastructure.executor.isolation_probe

echo "PASS: Docker lab isolation checks completed."
