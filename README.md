# Autonomous Multi-Agent Red-Blue Framework

Final Year Project:

**AN AUTONOMOUS MULTI-AGENT RED-BLUE FRAMEWORK FOR WEB APPLICATION VULNERABILITY DETECTION AND REMEDIATION**

## Current Status

**Milestone 14 — Patch Verification Pipeline: TECHNICALLY VERIFIED; authoritative automated and controlled Docker/Git runtime verification PASS; final staged Git review and commit PENDING.**

Milestones 1–13 are complete. Milestone 13 is permanently committed at `7d883b8`. Milestone 14 provides deterministic patch-policy/Git-integrity revalidation, isolated syntax/import and startup checks, controlled-executor-only functional/security/original-replay verification, a frozen trusted regression allowlist, deterministic accept/reject decisions, accepted-only local patch-branch commits, and safe baseline restoration. Raw generated tests are syntax-checked only and never executed or used for acceptance. The complete development-laptop automated and Docker/Git runtime gates now pass after a two-file deterministic Path Traversal fixture correction that preserved the existing sandbox-escape safety response without weakening verification. No automatic retry, merge, push, experiment storage, or Milestone 15 work is included.

Current Milestone 14 verification baseline:

```text
Python compilation: PASS
Authoritative full suite after Path Traversal fixture correction: 230 passed, 1 warning
Focused patch-generation tests after correction: 21 passed
Focused Milestone 14 verification tests after correction: 21 passed
Trusted verification policy: PASS
Controlled Docker/Git runtime verification: PASS (2026-08-27)
SQLi / XSS / Path Traversal accepted-remediation cases: PASS
Insecure / functional-regression / syntax rejection cases: PASS
Git-drift POLICY_BLOCKED case: PASS
Raw generated-test non-execution: PASS
Permanent repository stayed main @ 7d883b8; 24/24 scope checksums unchanged: PASS
Milestone 13 commit: PASS (`7d883b8`)
```

The Milestone 12 agent never writes directly to disk. Source edits are restricted to the validated Milestone 11 `CodeFinding` file; proposed exact-text anchors must be grounded in the bounded source context; generated-test paths are derived by the trusted service; and final prepared patches remain in memory only.

Milestone 13 materializes `PreparedPatch` artifacts only on deterministic isolated local branches. Milestone 14 verifies those branches through deterministic services and the isolated Docker lab. Automatic retries, merge, remote publication, persistent experiment execution, real cloud LLM providers, and the dashboard remain locked for later milestones.

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
- Node.js (required later for the React dashboard)

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

Run:

```bash
python -m compileall -q \
  agents orchestrator schemas services llm dummy_apps infrastructure security_tests
python -m pytest -q -p no:cacheprovider
```

Current implementation baseline:

```text
Python compilation: PASS
Milestone 14 authoritative pytest after correction: 230 passed, 1 warning
Milestone 14 focused verification tests: 21 passed
Milestone 14 controlled Docker/Git runtime verification: PASS (2026-08-27)
Milestone 14 permanent repository integrity: PASS — main @ 7d883b8, 24/24 scope checksums unchanged
Milestone 13 commit: PASS (`7d883b8`)
Milestone 12 commit: PASS (`ff17026`)
```

Milestone 14 is technically verified. Final documentation/staged Git review and the Milestone 14 commit remain pending.

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
├── docs/                # architecture, research and milestone documentation
├── dummy_apps/          # deliberately vulnerable local applications
├── infrastructure/      # Docker/runtime entry points and probes
├── llm/                 # provider-neutral LLM interfaces/providers
├── orchestrator/        # workflow coordination and policy-driven flows
├── schemas/             # cross-module Pydantic contracts/enums
├── scripts/             # human-operated setup/reset/verification scripts
├── security_tests/      # fixed deterministic registered security tests
├── services/            # trusted deterministic services
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

**Complete the Milestone 14 documentation finalization and final staged Git review.**

Stage exactly the verified 24-file Milestone 14 scope, inspect the staged implementation/correction/documentation diffs, and commit only after `git diff --cached --check` and the exact staged-path comparison pass. Do not merge or push any generated patch branch and do not begin Milestone 15 until the Milestone 14 commit is confirmed.
