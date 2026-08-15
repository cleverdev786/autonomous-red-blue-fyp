#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

docker compose config -q

for test_id in \
  sqli-login-bypass-001 \
  xss-reflection-001 \
  path-traversal-private-file-001
do
  echo
  echo "===== $test_id ====="
  docker compose exec -T controlled-executor \
    python -m infrastructure.executor.run_registered_test \
    --test-id "$test_id" \
    --attempt-number 1
done

echo
echo "PASS: all three registered security tests produced deterministic evidence."
