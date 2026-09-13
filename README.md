# Autonomous Multi-Agent Red-Blue Framework

Final Year Project:

**AN AUTONOMOUS MULTI-AGENT RED-BLUE FRAMEWORK FOR WEB APPLICATION VULNERABILITY DETECTION AND REMEDIATION**

## Current Status

**Milestone 19 - RQ3 Structured Feedback Retry: IMPLEMENTED, TESTED, and RUNTIME VERIFIED locally; documentation finalization in progress.**

Milestones 1-18 are permanently complete. Milestone 18 is committed at `aa58d89` (`aa58d8941cdca6cf371090b62236104e6967ff60`) as `Complete Milestone 18 frozen RQ2 classification dataset`.

Milestone 19 implements the optional secondary RQ3 comparison between `RetryFeedbackMode.NONE` and `RetryFeedbackMode.STRUCTURED`. RQ3 retry begins only after a deterministic verified `REJECTED` patch attempt with baseline restoration and remaining shared budget. `ACCEPTED`, `FAILED`, and `POLICY_BLOCKED` remain terminal and do not automatically retry. The retry path reuses the original Blue analysis/source context, the stored baseline commit, and one shared `RunLimitTracker`; it does not rerun Blue analysis or reset attempt/model/runtime budgets.

Structured feedback is derived internally from only the immediately previous attempt (`N-1 -> N`) using typed verification evidence. Raw stdout/stderr, pytest output, traceback text, shell output, unrestricted exception text, and unrestricted patch diffs are not forwarded to the model. Under the current evidence model, `regression_failure_ids` remains empty; `original_replay_succeeded` means the original exploit replay completed without timeout and exploit evidence was observed.

The primary RQ3 second-attempt acceptance denominator is **all actual second attempts**, including `ACCEPTED`, `REJECTED`, `POLICY_BLOCKED`, `FAILED`, and genuinely interrupted/incomplete attempts. These outcomes remain separate in reporting. `repeated_failure_rate` means second-attempt `REJECTED` divided by all actual second attempts. Any evaluable-only acceptance rate is secondary and cannot replace the primary denominator.

Development-laptop TEST evidence: 56 focused M19 tests passed; 222 affected M12-M18 regression tests passed; the complete suite passed 313 tests with only the existing non-failing Starlette deprecation warning. Runtime VERIFY used disposable DEVELOPMENT research storage and disposable Git evidence only. It proved the actual `REJECTED -> PATCH_GENERATING` transition, real baseline restoration, shared budgets, NONE/STRUCTURED treatment separation, safe feedback linkage, begun-retry persistence, `NULL / NOT_REPORTED` token/cost telemetry, five-way second-attempt outcome retention, exactly 20 SQLAlchemy tables, unchanged M18 RQ2 dataset hashes, and zero actual `FINAL_EVALUATION` experiments.

The permanent M18 RQ2 dataset remains frozen and unchanged:

```text
inputs.jsonl        9a7db4522d96c2a4d27b6f131bd145c6fd38b7614e0ccbbef8ab7dbf4cc5c6f5
ground_truth.jsonl 376cac8cbf7963aa0630f0a2437f555d56861c945beda2a0ffdb63f47391781f
manifest.json       8131e0ad2a40a6963fe9f405445352ce8af287f6ab41297f80ebba0735e31345
```

No real RQ1/RQ2/RQ3 final experiment has been run. M20 remains locked pending explicit approval after M19 documentation, staged review, and commit.

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

Permanent Milestone 17 authoritative baseline:

```text
Full development-laptop suite: 286 passed, 1 non-failing Starlette warning
Focused M17/integration gate: 113 passed, 1 non-failing Starlette warning
SQLAlchemy schema: exactly 20 tables
Experience history limit: 20 terminal RQ1 records per trusted strategy
Experience ordering: completed_at DESC, started_at DESC, run_id ASC
Missing Blue score: preserved as None and excluded from reward average
DISABLED: zero experience lookup
FROZEN_IDENTICAL: supplied snapshot only
ENABLED_EXPLORATORY: bounded live history
Policy denial overrides historical reward: PASS
Unregistered strategy rejection: PASS
Canonical SelectionDecision artifact/hash validation: PASS
Paired RQ1 configs differ only by Blue architecture: PASS
Single-agent provider roles: BLUE_SINGLE_AGENT x4
Multi-agent provider roles: monitoring / triage / code analysis / patch generation
Equivalent normalized inputs and patch output: PASS
Shared branch-flow and verification interfaces: PASS
proposed_security_test remains optional: PASS
Controlled runtime DBs: development configurations only
Runtime evidence path: /tmp/fyp-m17-runtime
M17 source files byte-identical before/after runtime: PASS
Git status and branch/ref state unchanged: PASS
Permanent data/fyp.db: absent
Final RQ experiments: NOT RUN
```

Milestone 16 is permanently complete at `927746e`. Milestone 17 is permanently complete at `25ebfdb` (`25ebfdbee1c6ca310c073c21fca3b81603e366ab`).

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

**Perform the exact final staged Git review for Milestone 18.**

Stage only the verified M18 implementation, the exact promoted `rq2-classification` / `v1` dataset artifacts, and this documentation finalization. Prove the exact staged path scope and dataset SHA-256 values, run staged whitespace/integrity checks and the final regression gate, and commit only after every staged Git gate passes. Do not run Rule/LLM/Hybrid classification, final experiments, or begin Milestone 19 before the M18 commit is confirmed.
