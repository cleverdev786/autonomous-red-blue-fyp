# Autonomous Multi-Agent Red-Blue Framework

Final Year Project:

**AN AUTONOMOUS MULTI-AGENT RED-BLUE FRAMEWORK FOR WEB APPLICATION VULNERABILITY DETECTION AND REMEDIATION**

## Current Status

**Milestone 17 - Experience Memory + RQ1 Single-Agent Baseline: TECHNICALLY VERIFIED; bounded deterministic experience selection, controlled RQ1 single-versus-multi architecture verification, authoritative automated/runtime checks, and repository-integrity checks PASS; final staged Git review and commit PENDING.**

Milestones 1–16 are permanently complete. Milestone 16 is committed at `927746e` (`927746e41eca43bb4221dbdd9784ec47f4208cee`) as `Complete Milestone 16 dashboard and scoring`.

Milestone 17 adds a bounded read-only `ExperienceStore` over existing canonical research evidence, not a second memory database. Each trusted strategy can contribute at most 20 newest terminal RQ1 outcomes, ordered deterministically by completion time, start time, and run ID. Missing Blue scores remain unknown (`None`) and are excluded from reward averages rather than treated as zero. `SelectionPolicy` may rank only registered strategies that also pass policy approval. Policy denial always wins over historical reward. No reinforcement learning, online learning, random exploration, self-modification, or new execution authority is added.

Experience modes are `DISABLED`, `FROZEN_IDENTICAL`, and `ENABLED_EXPLORATORY`. Final primary RQ1/RQ2 evaluations require `DISABLED`. Selection decisions are stored as canonical `selection_decision` artifacts through the existing research artifact store, so the SQLAlchemy schema remains exactly 20 tables.

The RQ1 baseline compares one general-purpose Blue persona against the existing specialist architecture. Every single-agent reasoning call uses `AgentRole.BLUE_SINGLE_AGENT`; the multi-agent condition retains `BLUE_MONITORING`, `BLUE_TRIAGE`, `BLUE_CODE_ANALYSIS`, and `BLUE_PATCH_GENERATION`. The RQ1 runner derives the condition from stored `ExperimentConfiguration`, and paired configs may differ only by `config_id` and `blue_team_mode`. Both conditions use equivalent normalized inputs and the same existing downstream patch-generation, branch/Git-isolation, verification, and research-storage interfaces. `proposed_security_test` remains optional, and the final RQ1 classification mode is not frozen until M20.

Authoritative development-laptop verification passes at 286 tests. Controlled disposable runtime verification confirmed the 20-record bound, stable ordering, missing-score behavior, all three experience modes, policy override, canonical `SelectionDecision` persistence, single-agent role consistency, specialized multi-agent roles, paired-input equivalence, shared downstream interfaces/storage, development-only configurations, and repository immutability. No final RQ experiment has been run. Milestone 18 remains locked until the M17 commit is confirmed.

See `docs/EXPERIENCE_MEMORY_RQ1.md` for the exact M17 architecture, safety boundary, experiment-control rules, and verification record. Milestone 16 scoring/dashboard details remain in `docs/DASHBOARD_SCORING.md`.

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

Current Milestone 17 authoritative baseline:

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

Milestone 16 is permanently complete at `927746e`. Milestone 17 is technically verified, with only the final staged Git review and M17 commit pending.

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

**Complete the Milestone 17 final staged Git review and commit.**

Stage only the verified M17 implementation plus this documentation finalization, prove the exact staged file scope, run `git diff --cached --check`, review the experience/RQ1/documentation diffs, and commit only after all staged Git gates pass. Do not begin Milestone 18 and do not run final RQ experiments until the M17 commit is confirmed.
