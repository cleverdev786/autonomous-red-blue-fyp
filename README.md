# MARS: Autonomous Multi-Agent Red–Blue Framework

MARS is a Final Year Project for controlled web-application vulnerability detection and remediation research. The current development release includes a model-free, deterministic four-worker Red Team, a FastAPI backend, a React dashboard, durable SQLite state/evidence, and a hardened local Docker lab.

## Current status

Red Team roadmap tasks T01–T36 are implemented and verified on the `development` branch. The release supports Manual and Autonomous assessments of the repository's deliberately vulnerable `vulnerable-store` for:

- SQL injection;
- reflected cross-site scripting;
- directory/path traversal.

This does not authorize testing public, external, production, or otherwise unapproved systems. It is not a claim that arbitrary applications are safe.

The historical M20 Q6_K DEVELOPMENT feasibility result remains `INELIGIBLE`. No final RQ1/RQ2/RQ3 experiment has been authorized or run, and M21 remains blocked pending a separate research-design decision.

See [PROGRESS.md](PROGRESS.md), the [Red Team operator runbook](docs/RED_TEAM_RUNBOOK.md), and the [acceptance report](docs/RED_TEAM_ACCEPTANCE_REPORT.md).

## Quick start

### Requirements

- Linux
- Python 3.11 or newer
- Docker Engine with Docker Compose
- Node.js for rebuilding the dashboard

### Install

```bash
git clone <YOUR_REPOSITORY_URL>
cd autonomous-red-blue-fyp

python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e ".[dev]"

cd dashboard/frontend
npm ci
npm run build
cd ../..
```

### Launch everything

Double-click **MARS Dashboard.desktop**, or run:

```bash
./launch-mars.sh
```

The launcher builds and starts the complete registered Docker lab, waits for both containers to become healthy, starts the MARS application on `127.0.0.1:8090`, and opens:

```text
http://127.0.0.1:8090/dashboard/
```

Normal startup includes:

- `fyp-vulnerable-store` on loopback port 8000;
- `fyp-controlled-executor` on the internal Docker network;
- FastAPI and the built React application on loopback port 8090.

OWASP ZAP is intentionally not a permanent service. Its digest-pinned 2.17.0 container is started only by an approved, bounded workflow.

### Stop everything

Use the desktop entry's **Stop MARS services** action, or run:

```bash
./stop-mars.sh
```

The stop script verifies the launcher-managed backend PID before sending `TERM`, stops only the registered Compose project, and preserves the named Docker volume.

## Red operator token

There is no default operator credential. Red write operations fail closed unless `MARS_RED_OPERATOR_TOKEN` is set to a local value of at least 32 characters before startup:

```bash
export MARS_RED_OPERATOR_TOKEN="$(.venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(32))')"
./launch-mars.sh
```

Enter the same token in the dashboard. Do not commit or place it in URLs, logs, screenshots, or evidence.

## How the Red Team works

The Red Team uses four independent deterministic Python workers coordinated by one Central Orchestrator:

1. **Reconnaissance** records scoped endpoint candidates.
2. **Planning** selects every applicable vetted test within the fixed Standard budget and records coverage gaps.
3. **Execution** runs only server-validated approved operations through registered adapters.
4. **Verification** applies deterministic evidence oracles and distinguishes confirmed, suspected, not-confirmed, and inconclusive outcomes.

Manual and Autonomous modes use the same policy, queue, workers, evidence, and findings. Autonomous execution still requires one explicit, immutable operator authorization. Cancellation preserves evidence and does not silently replay uncertain work.

The Standard profile permits at most 24 HTTP requests, 12 crawl requests, three tests, 180 seconds, one parallel operation, depth two, zero automatic retries, 0.5 CPU core, and 512 MiB memory.

## Verification

Python checks:

```bash
.venv/bin/pytest -q
git ls-files -m -o --exclude-standard -- '*.py' | xargs -r .venv/bin/ruff check
```

Frontend checks:

```bash
cd dashboard/frontend
npm test
npm run build
```

Compose checks:

```bash
docker compose -f compose.yaml config -q
docker compose -f compose.isolated.yaml config -q
docker compose -f compose.yaml -f compose.zap.yaml --profile zap config -q
```

Opt-in live Red acceptance uses only the isolated authorized lab:

```bash
docker compose -f compose.isolated.yaml up -d --no-build --wait
MARS_RUN_T34_E2E=1 \
MARS_T34_EXPORT=/tmp/mars-red-t34-acceptance.json \
.venv/bin/pytest -q tests/integration/test_red_t34_e2e.py

MARS_RUN_T35_OPERATIONAL=1 \
MARS_T35_EXPORT=/tmp/mars-red-t35-operational.json \
.venv/bin/pytest -q tests/integration/test_red_t35_operational.py
```

These commands execute real registered tests against synthetic local data. Review the runbook before running them.

## Architecture

```text
React dashboard
      |
FastAPI operator/read APIs
      |
Central Orchestrator ── immutable authorization / policy / queue / journal
      |
Recon ── Planning ── Controlled Execution ── Verification
      |
SQLite state + protected evidence + pending data-only Blue handoff
      |
Hardened internal Docker lab and optional confined ZAP job
```

Security boundaries:

- localhost-only dashboard and vulnerable-app port;
- internal, non-attachable Docker networks;
- read-only containers with dropped capabilities and `no-new-privileges`;
- no Docker socket, host network, privileged container, arbitrary shell, or arbitrary target import;
- CSRF, local-origin, bearer-token, idempotency, immutable authorization, and server-side scope checks for effectful Red APIs;
- evidence hashing, provenance, redaction, and denial of unsafe artifact paths.

## Repository layout

| Path | Purpose |
| --- | --- |
| `agents/red/` | deterministic Red worker roles |
| `orchestrator/` | policy-owned workflows and queue coordination |
| `services/` | trusted execution, state, evidence, and API services |
| `schemas/` | Pydantic contracts and persisted DTOs |
| `dashboard/` | FastAPI implementation and React application |
| `config/` | registered target, test templates, and Standard budget |
| `infrastructure/` | controlled executor and ZAP gate entrypoints |
| `dummy_apps/` | deliberately vulnerable synthetic application |
| `tests/` | unit, integration, negative-path, and opt-in live checks |
| `docs/` | architecture, operations, evidence, and historical research records |
| `tasks/` | current Red Team plan and completed task tracker |

`compose.yaml` is the normal registered local lab. `compose.isolated.yaml` is a complete standalone acceptance lab with separate identities and no published host port; do not combine it with the base file. `compose.zap.yaml` is an opt-in profile, not a normal startup service.

## Data and reset safety

Normal stop/start preserves runtime data. `scripts/reset_environment.sh` intentionally deletes and recreates the default lab's synthetic volume. Capture evidence first and never retarget the script at another Compose project.

Never modify or rerun frozen historical experiments to improve their outcome. Development Red acceptance artifacts under `/tmp` are disposable and distinct from research datasets.

## Further documentation

- [Red Team operator runbook](docs/RED_TEAM_RUNBOOK.md)
- [Red Team acceptance report](docs/RED_TEAM_ACCEPTANCE_REPORT.md)
- [Operator console notes](docs/OPERATOR_CONSOLE.md)
- [Docker lab guide](docs/DOCKER_LAB.md)
- [Current Red Team task tracker](tasks/todo.md)
- [Historical M20 feasibility decision](docs/M20_DEVELOPMENT_FEASIBILITY.md)
