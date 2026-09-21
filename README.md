# Autonomous Multi-Agent Red-Blue Framework

Final Year Project:

**AN AUTONOMOUS MULTI-AGENT RED-BLUE FRAMEWORK FOR WEB APPLICATION VULNERABILITY DETECTION AND REMEDIATION**

## Current Status

**Milestone 20 - Experiment Freeze / DEVELOPMENT Feasibility Candidate Selection: Candidate Set v4 repository support has passed IMPLEMENT, focused TEST, and VERIFY. The v4 DOCUMENT checkpoint is updated locally; C4 live zero-generation readiness has not been run.**

Milestones 1-19 are permanently complete. Milestone 19 is committed at `8a62232` (`8a62232e256699cc6a5e385cbb6267a4a06ae01c`) as `Complete Milestone 19 structured feedback retry`. Milestone 20 work is on branch `m20-work`; the preserved pre-v4 WIP checkpoint is `1b67c0c` (`1b67c0caee99e469ec1ab66818cb7c4cbb1668d6`).

The frozen `feasibility-v1` protocol remains unchanged: eight synthetic DEVELOPMENT fixtures, evaluator truth separated from candidate-visible inputs, four fixed role prompts/response schemas, `F2 = 30`, `F3 = 45`, and `75` logical calls per candidate. Generation settings remain `context=8192`, `max_output=4096`, `temperature=0.7`, `top_p=0.8`, `top_k=20`, `seed=null`, non-streaming, zero automatic retries, tools disabled, grounding disabled, and a 600-second request timeout.

Candidate-set history remains explicit and immutable:

```text
v1: L1/L2 failed semantic feasibility; C1 was quota-confounded; no candidate selected.
v2: L3 readiness PASS; L4 readiness PASS; C2 NOT READY because observed RPD 20 < 75.
v3: bounded 3-provider × 2-model documentation screen ended V3-DISCOVERY-NONE; v3 was never instantiated in repository assets.
v4: exact L3 + exact L4 + C4 gemini-3.1-flash-lite (zero_cost_cloud).
```

For C4, static schema readiness is resolved as `C4_SCHEMA_READINESS = PASS` under the already-frozen interpretation: the exact schemas remain unchanged, provider-native enforcement of every annotation keyword was never required, and deterministic local Pydantic validation remains authoritative. No provider-specialized schema transform was introduced.

The approved v4 repository-support patch SHA-256 is:

```text
7494fbabd6d708302283e36cdcdbeeecec5e8fa71c3f848bd2cfb1e012bca10b
```

Focused v2+v4 TEST passed `20/20`. VERIFY confirmed the exact 10-file implementation scope, v4 descriptor bundle SHA-256 `6c7c83445d002a7b6b38c69933f826d472a51ff42a36aa2892f75db947d0455d`, exact L3/L4 identity carry-forward from v2 except for the explicit descriptor version, frozen v1/v2 repository-byte preservation, frozen feasibility-v1 hash/schedule equivalence, v3 remaining uninstantiated, zero provider/generation request literals, and no v4 global-readiness execution path.

The approved C4 quota design is `15 RPM / 250K TPM / 500 RPD`; the already-frozen 20% headroom derivation is therefore `12 effective RPM / 200K effective TPM / 5-second fixed pacing`. This is representation only: **C4 zero-generation readiness has not been executed, provider requests remain 0, generation requests remain 0, no v4 global barrier has been implemented/evaluated, and no F2/F3 feasibility generation has begun.**

The permanent M18 RQ2 dataset remains frozen and unchanged:

```text
inputs.jsonl        9a7db4522d96c2a4d27b6f131bd145c6fd38b7614e0ccbbef8ab7dbf4cc5c6f5
ground_truth.jsonl 376cac8cbf7963aa0630f0a2437f555d56861c945beda2a0ffdb63f47391781f
manifest.json       8131e0ad2a40a6963fe9f405445352ce8af287f6ab41297f80ebba0735e31345
```

No real RQ1/RQ2/RQ3 final experiment has been run. C4 readiness, any v4 global barrier, B5/RQ1-K/RQ3 derivation, M21, and final experiments remain locked behind explicit later gates.

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

**Review and approve the Milestone 20 Candidate Set v4 DOCUMENT diff before any staging or commit.**

After documentation approval, perform only the exact staged Git review for the verified v4 implementation + documentation checkpoint. Preserve all v1/v2/v3 evidence including `V3-DISCOVERY-NONE`, prove the staged path scope and frozen protocol hashes, run staged whitespace/integrity checks, and commit only after that staged gate is explicitly approved. Do not run C4 zero-generation readiness, make provider calls, implement/evaluate a v4 global barrier, execute F2/F3, derive B5/RQ1-K/RQ3, begin M21, or run final experiments.
