# Autonomous Multi-Agent Red-Blue Framework

Final Year Project:

**AN AUTONOMOUS MULTI-AGENT RED-BLUE FRAMEWORK FOR WEB APPLICATION VULNERABILITY DETECTION AND REMEDIATION**

## Current Status

**Milestone 20 DEVELOPMENT feasibility execution is terminally closed with no eligible candidate. The final experiment freeze is not established, and M21 remains blocked.**

Milestones 1-19 are permanently complete. Milestone 20 work remains on branch `m20-work`. The frozen `feasibility-v1` protocol remained unchanged throughout DEVELOPMENT feasibility: eight synthetic fixtures, evaluator truth separated from candidate-visible inputs, four fixed role prompts/response schemas, `F2 = 30`, `F3 = 45`, and `75` logical calls per official candidate exposure. Generation settings remained `context=8192`, `max_output=4096`, `temperature=0.7`, `top_p=0.8`, `top_k=20`, `seed=null`, non-streaming, zero automatic retries, tools disabled, grounding disabled, and a 600-second request timeout.

Candidate-set history remains explicit and immutable:

```text
v1: L1/L2 failed semantic feasibility; C1 was quota-confounded; no candidate selected.
v2: L3/L4 zero-generation readiness PASS; C2 NOT READY because observed RPD 20 < 75.
v3: bounded documentation-only discovery ended V3-DISCOVERY-NONE; v3 was never instantiated.
v4: L3 + L4 + C4 completed the frozen DEVELOPMENT feasibility cycle; all were INELIGIBLE.
```

A post-v4 specialist feasibility experiment fine-tuned `Qwen/Qwen2.5-Coder-3B-Instruct`. Q4_K_M showed a representation-dependent registered-test-selection regression; F16, Q8 and Q6_K restored the affected SQL selector behavior. Final Q6_K artifact SHA-256:

```text
07bcec4047a457766a92c9737fd0ac8045e328ccf703baf43768c2ea962bf7a9
```

Q6_K achieved artifact-specific CPU `PILOT_GO` only under a predeclared one-time infrastructure-recovery amendment. The original timeout remains preserved and is not rewritten as a clean pilot pass.

The sealed Q6_K official frozen DEVELOPMENT feasibility-v1 exposure completed `75/75` logical requests with zero provider failures and zero retries. Classification, source/function localization, registered-test selection, benign handling, stability and local-resource gates passed, but frozen patch verification accepted only `2/6` F2 patches and did not cover every vulnerability class. The official selector decision is:

```text
Q6_K DEVELOPMENT feasibility-v1: INELIGIBLE
```

The official 75-call exposure must not be rerun to improve the result. This was a DEVELOPMENT feasibility gate, not an RQ1/RQ2/RQ3 final evaluation. The training corpus excluded the frozen feasibility-v1 fixture/truth records themselves, while the training design was knowingly informed by the frozen DEVELOPMENT task interface, fixture structure, schemas and verifier-compatible remediation idioms.

See [`docs/M20_DEVELOPMENT_FEASIBILITY.md`](docs/M20_DEVELOPMENT_FEASIBILITY.md) for the authoritative M20 evidence and decision narrative.

The permanent M18 RQ2 dataset remains frozen and unchanged:

```text
inputs.jsonl        9a7db4522d96c2a4d27b6f131bd145c6fd38b7614e0ccbbef8ab7dbf4cc5c6f5
ground_truth.jsonl 376cac8cbf7963aa0630f0a2437f555d56861c945beda2a0ffdb63f47391781f
manifest.json       8131e0ad2a40a6963fe9f405445352ce8af287f6ab41297f80ebba0735e31345
```

No real RQ1/RQ2/RQ3 final experiment has been run. No final experiment configuration is admitted from this feasibility cycle, and M21 remains locked pending an explicit pre-final-evaluation design decision.

## Integrated Development Branch (2026-10-09)

**Active local branch:** `integration/r4c4f-primary-20261009`. The original
FYP code and four approved R3/R4 development commits are consolidated in this
repository. Historical M20 and recovery branches remain intact; the project
was **not** rebuilt from scratch.

Two Docker Compose files are intentional:

- `compose.yaml` is the original/default lab: image
  `fyp-red-blue-lab:local`, host port `127.0.0.1:8000`.
- `compose.isolated.yaml` is a **standalone** isolated lab configuration, with
  independent image, containers, network and volume, host port
  `127.0.0.1:18080`, and unchanged container port 8000.

`services/isolated_compose_mock_adapter.py` is **mock-only**. It does not call
Docker and is not wired into the original live execution pipeline. Modern
source filenames describe module responsibilities; historical evidence schema
version strings are retained for compatibility.

The primary repository passed 337 focused and 755 complete offline tests
before renaming (one benign warning). The renamed source must pass the tests
again. M20 Q6_K remains INELIGIBLE and M21 final experiments BLOCKED.

See [Current development guide](docs/CURRENT_DEVELOPMENT_GUIDE.md).

## Remediation Compatibility Recovery (2026-10-09)

The additive remediation decision/outcome compatibility layer is verified on the separate `recovery/remediation-outcome-compat-20261009` branch. It introduces safe no-patch finalization and RQ1 development-mode compatibility without changing legacy patch artifacts or the 20-table database. Focused verification passed (123 tests); the full Python 3.12 suite passed (418 tests, one non-failing deprecation warning). No remediation compiler or model inference is included. See [Recovery compatibility verification](docs/REMEDIATION_COMPATIBILITY_RECOVERY.md) for exact scope, test commands, evidence hashes, limitations and next gates. This is **not** a final experiment freeze or an M20 qualification change.

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
├── compose.yaml           # default, original Docker configuration
└── compose.isolated.yaml  # isolated, standalone configuration
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

**Safety:** the legacy startup commands below select `compose.yaml` and
existing fixed image/container names. They do not select
`compose.isolated.yaml`. Do not run them on a shared/active daemon without
separate authorization and ownership checks. The isolated adapter is
mock-only, not a Docker runtime.


Legacy default lab, only when specifically authorized:

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

The isolated configuration uses loopback `127.0.0.1:18080` instead.
It is a complete alternative file, **not** a YAML overlay to combine using
multiple `-f` flags. Its normalized runtime configuration still needs an
independent read-only verification before any Docker mutation.

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

## Historical Next Task (superseded 2026-10-09)

**Review and approve the Milestone 20 Candidate Set v4 DOCUMENT diff before any staging or commit.**

After documentation approval, perform only the exact staged Git review for the verified v4 implementation + documentation checkpoint. Preserve all v1/v2/v3 evidence including `V3-DISCOVERY-NONE`, prove the staged path scope and frozen protocol hashes, run staged whitespace/integrity checks, and commit only after that staged gate is explicitly approved. Do not run C4 zero-generation readiness, make provider calls, implement/evaluate a v4 global barrier, execute F2/F3, derive B5/RQ1-K/RQ3, begin M21, or run final experiments.


## Current Next Steps (2026-10-09)

1. Verify renamed source with focused and full offline tests, then publish
   the integration branch **only** (no `main` merge).
2. Separately validate isolated Docker configuration and port 18080
   read-only before any build/start/cleanup.
3. Complete bounded genuine Red runtime capture and three registered
   vulnerability verification scenarios under separate approval.
4. Resolve M20 model/protocol eligibility in parallel, then conduct frozen
   final RQ1/RQ2, analyze and finish the report, demo and viva.
