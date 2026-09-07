# Autonomous Multi-Agent Red-Blue Framework

Final Year Project:

**AN AUTONOMOUS MULTI-AGENT RED-BLUE FRAMEWORK FOR WEB APPLICATION VULNERABILITY DETECTION AND REMEDIATION**

## Current Status

**Milestone 16 — Dashboard and Scoring: TECHNICALLY VERIFIED; deterministic scoring, read-only dashboard, authoritative automated/runtime verification, and the NullPool concurrency correction PASS; final staged Git review and commit PENDING.**

Milestones 1–15 are permanently complete. Milestone 15 is committed at `b1572cf`. Milestone 16 adds deterministic versioned `red-blue-v1` Red/Blue game scoring and a local React + Vite dashboard backed by a GET-only FastAPI API. The scorer runs explicitly offline/post-run from stored evidence; the dashboard never calculates or persists scores. Canonical `ScoreResult` artifacts carry component observations, penalties, selected patch attempt, attributed policy-event IDs, final score/version, and a SHA-256-linked `score_records.evidence_reference`. Scores remain separate from research metrics; RQ2 is `not_applicable`, and incomplete runs are `ineligible_incomplete` with no final score rows.

The dashboard opens an existing SQLite research DB with URI `mode=ro`, `PRAGMA query_only=ON`, and explicit SQLAlchemy `NullPool`. It provides Overview, Runs, Run Detail, Findings, Patch Verification, Metrics, and Audit views without attack, patch, Git, Docker, shell, environment-reset, experiment-control, or score-recalculation authority. Generated/model/diff/audit text is bounded and rendered inertly. Authoritative verification passes at 271 tests; a corrected 240-request concurrent dashboard runtime produced 240 HTTP 200 responses, zero closed-database/request exceptions, unchanged DB SHA-256 and row counts, and no persistent SQLite write sidecars. The production-only npm audit reports zero vulnerabilities; two development/build advisories remain recorded without an automatic or forced upgrade. Final RQ experiments have not been run and Milestone 17 remains locked.

Milestone 16 scoring summary:

```text
Red = clamp(100*C - 5*min(D_R,4) - 25*min(P_R,2), 0, 100)

Blue diagnosis/localization: 10 classification + 10 source file + 10 function/route
Blue best single patch attempt: 5 syntax + 5 startup + 10 functional
                                + 20 security + 25 original replay + 5 regression
Blue = clamp(component points - 5*min(D_B,3) - 25*min(P_B,2), 0, 100)
```

See `docs/DASHBOARD_SCORING.md` for the exact evidence authority, policy attribution, persistence rules, dashboard boundaries, and verification record.

## Approved Scope

The MVP is limited to a deliberately vulnerable local dummy application and three controlled vulnerability categories:

1. SQL Injection
2. Cross-Site Scripting (XSS)
3. Directory / Path Traversal

The framework must not scan or test real websites, public IP addresses, external servers, private organizations, production systems, or unauthorized targets.

## Core Design Rule

LLMs may recommend actions.

Deterministic project services decide whether those actions are allowed and perform sensitive operations.

LLM agents will not receive unrestricted shell, network, Docker, Git, or host-filesystem access.

## Requirements

Recommended:

- Python 3.11–3.14
- Git
- Docker / Docker Compose (required in later milestones)
- Node.js (required for the React + Vite dashboard build/preview)

## Linux Setup

```bash
git clone <YOUR_REPOSITORY_URL>
cd autonomous-red-blue-fyp

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -e ".[dev]"

pytest
```

## Windows PowerShell Setup

```powershell
git clone <YOUR_REPOSITORY_URL>
Set-Location autonomous-red-blue-fyp

py -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
pip install -e ".[dev]"

pytest
```

If PowerShell blocks virtual-environment activation, use an appropriate local execution-policy setting according to your machine/university policy instead of disabling security controls globally.

## Basic Verification

Python verification:

```bash
python -m compileall -q \
  agents orchestrator schemas services llm dummy_apps infrastructure security_tests dashboard
python -m pytest -q -p no:cacheprovider
```

Dashboard frontend build:

```bash
cd dashboard/frontend
npm install --no-package-lock
npm run build
```

Current Milestone 16 authoritative baseline:

```text
Full development-laptop suite: 271 passed, 1 non-failing Starlette warning
Focused scoring/dashboard/metric gate: 21 passed, 1 non-failing Starlette warning
SQLAlchemy schema: exactly 20 tables
React/Vite production build: PASS
Perfect scoring fixture: Red 100 / Blue 100
Score evidence integrity and same-version idempotency: PASS
Changed same-version evidence rejection: PASS
RQ2 not_applicable / RUNNING ineligible_incomplete: PASS
Read-only dashboard: mode=ro + PRAGMA query_only=ON + NullPool
Manual seven-view presentation/safety verification: PASS
Concurrent corrected dashboard runtime: 240/240 HTTP 200, 0 exceptions
Concurrent-read DB SHA-256 and all table row counts: unchanged
Core CLI/orchestrator independent of dashboard package: PASS
npm audit --omit=dev: 0 production vulnerabilities
Permanent data/fyp.db: absent
Final RQ experiments: NOT RUN
```

Milestone 15 is permanently complete at `b1572cf`; its stale pre-commit README wording has been corrected here. Milestone 16 is technically verified, with only the final staged Git review and M16 commit pending.

## Configuration

The repository uses environment variables for runtime configuration.

Copy `.env.example` only as a reference. The current foundation does not automatically load `.env` files.

Initial variables:

```text
FYP_ENV=development
FYP_DATA_DIR=./data
FYP_DATABASE_URL=sqlite:///./data/fyp.db
```

Never commit real API keys or passwords.

Cloud-model credentials will be added only when a provider integration is implemented.

## Repository Layout

```text
.
├── agents/              # untrusted typed Red/Blue reasoning roles
├── config/              # trusted human-controlled registries
├── data/                # generated/local data placeholders
├── dashboard/           # read-only FastAPI API + React/Vite presentation UI
├── docs/                # architecture, research and milestone documentation
├── dummy_apps/          # deliberately vulnerable local applications
├── infrastructure/      # Docker/runtime entry points and probes
├── llm/                 # provider-neutral LLM interfaces/providers
├── orchestrator/        # workflow coordination and policy-driven flows
├── schemas/             # cross-module Pydantic contracts/enums
├── scripts/             # human-operated setup/reset/verification scripts
├── security_tests/      # fixed deterministic registered security tests
├── services/            # trusted deterministic services
├── storage/             # local SQLAlchemy research evidence store
├── experiments/         # observational run recording and deterministic metrics
├── tests/               # repository-level automated tests
├── PROGRESS.md
├── README.md
├── HANDOFF.md
├── pyproject.toml
└── compose.yaml
```

The top-level `agents/` package is the frozen Phase 1 untrusted reasoning layer. It is distinct from `llm/` provider mechanics, `orchestrator/` coordination, and deterministic `services/`.

## Development Order

The immediate order is:

1. Repository foundation
2. Core schemas and configuration
3. Dummy application baseline
4. Controlled vulnerability scenarios
5. Docker isolation and reset
6. Target registry and policy engine
7. Deterministic security-test harness
8. Red Team MVP
9. Structured logging and Blue Team
10. Patching, Git, and verification
11. Experiments and dashboard

See `docs/phase-1/MILESTONES.md` for the complete plan.

## Tests First

A milestone is not complete because code exists.

Use:

**DESIGN → IMPLEMENT → TEST → VERIFY → DOCUMENT → COMMIT**

## Important Safety Notes

- Use synthetic data only.
- Do not expose the future vulnerable app publicly.
- Do not mount the Docker socket into attack or verification containers.
- Do not provide LLM agents a general shell tool.
- Do not automatically merge generated patches.
- Keep experiment failures; they are valid research data.

## Current Dummy Application

The baseline app lives at:

```text
dummy_apps/vulnerable_store/
```

Run it locally from the repository root:

```bash
python -m dummy_apps.vulnerable_store.app.reset
uvicorn dummy_apps.vulnerable_store.app.main:app --host 127.0.0.1 --port 8000
```

Seeded synthetic users:

```text
student1 / demo-pass-1
student2 / demo-pass-2
```

## Controlled Scenario Routes

```text
POST /scenarios/sql-injection/login
GET  /scenarios/xss/search
GET  /scenarios/path-traversal/read
```

The baseline routes remain available for regression testing.

The path-traversal scenario is additionally bounded by a synthetic scenario-file sandbox so it cannot traverse into arbitrary host files.

## Docker Lab

Start on a machine with Docker:

Linux:

```bash
bash scripts/start_environment.sh
bash scripts/verify_docker_isolation.sh
```

Windows PowerShell:

```powershell
.\scripts\start_environment.ps1
.\scripts\verify_docker_isolation.ps1
```

The dummy app is published only at:

```text
http://127.0.0.1:8000
```

The controlled executor has no published port and uses only the externally
isolated `security-lab` Docker network.

See `docs/DOCKER_LAB.md`.

## Policy Layer

Trusted registry configuration:

```text
config/targets/
config/security_tests/
```

Deterministic authorization:

```text
services/target_registry.py
orchestrator/policy_engine.py
orchestrator/limits.py
```

Unknown targets, destinations, endpoints, methods, test IDs, privileged paths,
invalid workflow transitions, and exhausted budgets fail closed.

See `docs/POLICY_ENGINE.md`.

## Controlled Security-Test Harness

Registered implementations:

```text
security_tests/
```

Executor:

```text
services/controlled_executor.py
```

The executor builds local requests only from trusted registry/configuration and
fixed templates. It does not accept raw URLs or free-form payloads.

Runtime verification:

```bash
bash scripts/reset_environment.sh
bash scripts/verify_docker_isolation.sh
bash scripts/verify_registered_tests.sh
```

See `docs/SECURITY_TEST_HARNESS.md`.

## Next Task

**Complete the Milestone 16 final staged Git review and commit.**

Stage only the verified M16 implementation plus this documentation finalization, prove the exact staged file scope, run `git diff --cached --check`, review the scoring/dashboard/documentation diffs, and commit only after all staged Git gates pass. Do not begin Milestone 17 and do not run final RQ experiments until the M16 commit is confirmed.
