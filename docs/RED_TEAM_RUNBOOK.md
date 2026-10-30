# MARS Red Team operator runbook

This runbook operates the model-free Red Team release against the repository's deliberately vulnerable local application. It does not authorize testing any other target.

## Safety boundary

- The only enabled target is `vulnerable-store` from `config/targets/vulnerable-store.json`.
- The only supported vulnerability classes are SQL injection, reflected XSS, and path traversal.
- The only executable tests are the three registered IDs in `config/security_tests/`.
- Do not substitute a hostname, URL, Compose project, test ID, payload, or container.
- Do not expose the vulnerable application or ZAP API beyond loopback/internal Docker networks.
- ZAP observations are never confirmed findings by themselves.

## Prerequisites

- Linux with Docker Engine and Docker Compose
- Python 3.11 or newer and the repository `.venv`
- Node.js only when rebuilding the React application
- A checkout of this repository with no unreviewed changes to target or test registries

Install development dependencies once:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
cd dashboard/frontend
npm ci
npm run build
```

## Start and stop the complete local stack

Double-click `MARS Dashboard.desktop`, or run:

```bash
./launch-mars.sh
```

The launcher validates Python dependencies, builds/starts the two services in `compose.yaml`, waits for their health checks, starts `backend.app:app` on `127.0.0.1:8090`, and opens `http://127.0.0.1:8090/dashboard/`. The services are:

- `fyp-vulnerable-store`: synthetic vulnerable application, loopback port 8000
- `fyp-controlled-executor`: internal registered-test executor with no published port
- MARS FastAPI/React application: loopback port 8090

ZAP is deliberately excluded from normal startup because it is an on-demand, approval-gated tool.

Stop the stack using the desktop entry's **Stop MARS services** action, or:

```bash
./stop-mars.sh
```

Shutdown sends `TERM` only to the PID recorded by the MARS launcher after verifying its working directory and command line. It then runs Compose `down --remove-orphans` for `compose.yaml`. The named application volume is preserved.

## Operator credential

Red write operations are disabled unless the backend starts with `MARS_RED_OPERATOR_TOKEN` set to an operator-controlled value of at least 32 characters. There is no default credential in the repository. Generate a temporary local token without committing it:

```bash
export MARS_RED_OPERATOR_TOKEN="$(.venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(32))')"
./launch-mars.sh
```

Enter that same value in the dashboard when prompted. It remains in React memory only. The API additionally requires an allowed local Origin, a server-issued CSRF token, JSON content, and unique request IDs. Never put the token in Git, a URL, screenshots, logs, or evidence exports.

## Standard profile

`config/red_standard.json` is server-authoritative:

| Limit | Value |
| --- | ---: |
| HTTP requests | 24 |
| Crawl requests | 12 |
| Registered tests | 3 |
| Runtime | 180 seconds |
| Parallel operations | 1 |
| Crawl depth | 2 |
| Automatic retries | 0 |
| CPU | 0.5 core |
| Memory | 512 MiB |

The browser cannot increase these values. A timeout or ambiguous execution is retained as inconclusive and is not silently replayed.

## Run an assessment

1. Open **Red Team** in the dashboard.
2. Supply the operator token.
3. Select the registered `vulnerable-store` target and Manual or Autonomous mode.
4. Review the fixed target, three classes, methods, and Standard budget.
5. Create the draft, authorize it explicitly, then start it.

Manual mode runs Reconnaissance, Planning, Execution, and Verification through separate controls. Rerunning reconnaissance makes the earlier plan stale; plan again before execution.

Autonomous mode progresses through the same four deterministic workers and policy checks. Its mode and authorization are fixed for the active assessment. **Stop** remains available and cancels queued work without deleting evidence.

An assessment marked `completed_with_limitations` is not a claim that the target is safe. Inspect coverage gaps, suspected observations, and unavailable authenticated routes.

## Reproduce the acceptance workflow

The acceptance fixture uses the standalone `compose.isolated.yaml` project. It has independent container, network, image, and volume identities and publishes no host port. Do not combine it with `compose.yaml` as an override.

```bash
docker compose -f compose.isolated.yaml config -q
docker compose -f compose.isolated.yaml up -d --no-build --wait
MARS_RUN_T34_E2E=1 \
MARS_T34_EXPORT=/tmp/mars-red-t34-acceptance.json \
.venv/bin/pytest -q tests/integration/test_red_t34_e2e.py
```

The fixture invokes each registered test once in the controlled executor, then verifies Manual and Autonomous orchestration, findings, gaps, receipts, hashes, rerun history, and cancellation. Review the sanitized JSON artifact; it intentionally contains no response bodies or credentials.

Run the adversarial restart/cancellation exercise separately:

```bash
MARS_RUN_T35_OPERATIONAL=1 \
MARS_T35_EXPORT=/tmp/mars-red-t35-operational.json \
.venv/bin/pytest -q tests/integration/test_red_t35_operational.py
```

This restarts only the controlled executor and fails if unrelated containers change.

## ZAP boundary

The opt-in image is OWASP ZAP 2.17.0 for Linux/amd64, digest-pinned in `compose.zap.yaml` to `sha256:0075662e5c287cf0a68caebabbfea872e5dc461912ad6d7345fa02a290d0ccb6`.

ZAP is short-lived, non-root, read-only, capability-dropped, resource-limited, and attached only to an internal target-gate network. Its API binds to container loopback and is not published. The only active rule admitted by the release is reflected-XSS rule `40012` against the registered GET search endpoint, through the two-request gate. Broad spiders, full active scans, arbitrary rules, redirects, and external targets are denied.

Do not start ZAP manually to bypass the application workflow. `compose.zap.yaml` is an implementation boundary, not blanket scanner authorization.

## State, evidence, and privacy

- MARS workspace state defaults to `~/.local/state/mars/workspace.sqlite3`.
- Launcher state and logs are under `${XDG_STATE_HOME:-~/.local/state}/sentinel-fyp/`.
- Red evidence stores hashes, provenance, bounded sanitized excerpts, receipts, findings, gaps, and timeline events.
- Raw credentials and unsafe filesystem paths are excluded from Red evidence and the UI timeline.
- `/tmp/mars-red-t34-acceptance.json` and `/tmp/mars-red-t35-operational.json` are disposable acceptance exports; regenerate them when needed.
- Preserve historical research datasets and experiment evidence. Red acceptance does not requalify the M20 model experiment or authorize M21.

## Reset the vulnerable lab

Normal stop/start preserves the named volume. A reset deletes synthetic lab state and therefore requires deliberate operator intent:

```bash
bash scripts/reset_environment.sh
```

That script runs `docker compose down --volumes --remove-orphans` for the default registered lab and recreates it. It must never be pointed at another Compose project. Capture required evidence before resetting.

For the standalone acceptance lab, stop without data deletion using:

```bash
docker compose -f compose.isolated.yaml down --remove-orphans
```

Do not add `--volumes` unless you explicitly intend to discard only that isolated lab's synthetic runtime state.

## Troubleshooting

Check service state:

```bash
docker compose -f compose.yaml ps
curl --fail http://127.0.0.1:8090/api/console/status
```

Check the dashboard log:

```bash
tail -n 100 "${XDG_STATE_HOME:-$HOME/.local/state}/sentinel-fyp/operator.log"
```

Common failures:

- **Docker unavailable:** start Docker, then rerun the launcher. The complete stack now fails closed instead of opening a partial UI.
- **Container unhealthy:** inspect `docker compose logs`; do not remove volumes as a first response.
- **Operator unconfigured (503):** stop MARS, set a new token of at least 32 characters, and relaunch.
- **Unauthorized/CSRF failure:** use the same in-memory token, local dashboard origin, and a fresh CSRF challenge/request ID.
- **Stale plan:** rerun Planning after Reconnaissance.
- **Port 8090 occupied:** stop the known process safely; do not kill an unrelated PID. The stop script refuses processes it cannot identify as MARS.
- **ZAP unavailable:** leave it unavailable unless the specific workflow has approval. Registered controlled tests remain the confirmation authority.

## Rollback

These changes require no database migration. To roll back the local runtime, stop MARS, check out the prior reviewed revision, rebuild the frontend if its assets changed, and relaunch. Preserve evidence and named Docker volumes unless a separately approved reset is required.
