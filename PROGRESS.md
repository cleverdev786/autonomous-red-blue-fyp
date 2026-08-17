# PROGRESS

## Project
**An Autonomous Multi-Agent Red-Blue Framework for Web Application Vulnerability Detection and Remediation**

## Current Milestone
**Milestone 8 — Red Team MVP**

## Status
**IN PROGRESS — local implementation and automated verification passed; Docker runtime verification PENDING**

## Completed Milestones
- [x] Phase 1 foundation
- [x] Threat model
- [x] Milestone 1 — Repository Foundation
- [x] Milestone 2 — Core Schemas
- [x] Milestone 3 — Dummy Application Baseline
- [x] Milestone 4 — Vulnerability Scenarios
- [x] Milestone 5 — Docker Isolation and Reset — runtime verified
- [x] Milestone 6 — Target Registry and Policy Engine
- [x] Milestone 7 — Deterministic Security-Test Harness — runtime verified
- [ ] Milestone 8 — Red Team MVP — Docker runtime verification pending

## Milestone 7 Verified Baseline

Milestone 7 remains closed. The existing controlled executor:

- accepts registered test ID plus attempt number only;
- derives target, destination, endpoint, method, parameters, timeout, and evidence rules from trusted code/configuration;
- blocks arbitrary URL/hostname/port/method/payload/file/command authority;
- does not follow redirects;
- enforces request/attempt/runtime budgets;
- returns bounded structured execution evidence.

Recorded Milestone 7 automated baseline:

```text
77 passed
```

Recorded Milestone 7 development-machine runtime verification:

```text
PASS: both services are healthy.
PASS: controlled-executor can reach vulnerable-store on the lab network.
PASS: public internet is blocked from controlled-executor.
PASS: Docker lab isolation checks completed.
PASS: all three registered security tests produced deterministic evidence.
```

## Milestone 8 Implemented Locally

### Agent/Provider Separation

New architectural layer:

```text
agents/
├── base.py
└── red/
    ├── reconnaissance.py
    ├── attack_planner.py
    └── attack_verifier.py
```

Responsibilities remain separated:

```text
agents/base.py
= common typed agent reasoning contract

llm/interface.py
= provider-neutral structured-generation contract
```

Agents do not own provider, HTTP, executor, Docker, Git, or shell authority.

### Reconnaissance Boundary

`ReconnaissanceService` exposes to the Reconnaissance Agent only:

- target ID;
- endpoint IDs;
- allowed HTTP methods;
- declared input-field names.

Reconnaissance does not receive registered test IDs, vulnerability categories, test mappings, registered parameter names, request/evidence-rule IDs, payloads, target hostname/port, source paths, or scenario ground truth.

### Separate Planning Catalog

The Attack Planner separately receives a restricted catalog containing only:

- `test_id`;
- vulnerability class;
- registered `endpoint_id`;
- allowed parameter names;
- safe description.

It produces the existing typed `AttackPlan`. The orchestrator deterministically validates the selection and calls `PolicyEngine.validate_security_test()` before execution.

### Red Team Flow

```text
READY
→ RECONNAISSANCE
→ ATTACK_PLANNING
→ ATTACK_EXECUTING
→ ATTACK_VERIFYING
```

Outcome:

```text
confirmed + valid deterministic evidence
ATTACK_VERIFYING → BLUE_MONITORING

unconfirmed / missing / invalid deterministic evidence
ATTACK_VERIFYING → REJECTED
```

Every transition uses `PolicyEngine.validate_state_transition()`.

`BLUE_MONITORING` is a handoff state only. No Blue Team implementation executes in Milestone 8.

The existing retry transition back to attack planning is intentionally unused by this single-attempt MVP.

### Model-Call Budget

A successful flow requires exactly three authorized provider calls:

1. reconnaissance;
2. attack planning;
3. attack verification.

Before each call:

1. policy validates model-call budget;
2. `RunLimitTracker` consumes one call only after authorization;
3. provider runs;
4. returned output is Pydantic-validated.

### Execution Boundary

`ControlledExecutor` remains unchanged and remains the only component that performs the registered HTTP sequence.

Only the planner-produced, deterministically approved:

```text
AttackPlan.test_id
attempt_number
```

reach `ControlledExecutor.execute_registered_test()`.

### Verification Integrity

The orchestrator enforces:

- execution target/test IDs match the plan;
- verifier target/test IDs match the plan;
- cited evidence IDs exist in deterministic executor evidence;
- confirmation requires cited deterministic evidence;
- empty evidence cannot become confirmed;
- timed-out execution cannot become confirmed;
- incomplete execution cannot become confirmed;
- agent-generated text cannot manufacture evidence.

### Runtime Verification Entry Point

```text
infrastructure/executor/run_red_team_mvp.py
```

This is a **Milestone 8 runtime-verification entry point only**.

Its `--test-id` argument configures the deterministic `MockProvider` planning fixture. It does not pass that CLI value directly to `ControlledExecutor`.

Runtime path:

```text
CLI fixture
→ MockProvider
→ Reconnaissance Agent
→ ReconnaissanceResult
→ Attack Planner
→ AttackPlan.test_id
→ deterministic validation
→ ControlledExecutor
```

Running this complete mock flow inside `controlled-executor` for Milestone 8 does not relocate future production orchestration/LLM-provider responsibilities into that container.

## Milestone 8 Automated Verification Result

Commands run locally against the attached repository snapshot:

```bash
python -m compileall -q \
  agents orchestrator schemas services llm dummy_apps infrastructure security_tests

python -m pytest -q -p no:cacheprovider

git diff --check
```

Observed results:

```text
Python compilation: PASS
Pytest: 96 passed in 0.81s
git diff --check: PASS
```

Automated coverage includes:

- restricted reconnaissance context;
- separate restricted planning catalog;
- typed agent/provider separation;
- all three registered scenarios through the full mock Red Team flow in-process;
- exact three-call successful model budget;
- model-call denial before provider invocation/extra consumption;
- unknown/out-of-catalog plan rejection before executor invocation;
- endpoint/class/parameter plan mismatch rejection;
- malformed provider output rejected by Pydantic;
- execution target/test identity mismatch rejection;
- empty evidence rejection;
- timeout rejection;
- incomplete execution rejection;
- invented evidence-ID rejection;
- confirmation-without-evidence-citation rejection;
- runtime helper planner path (no direct helper call to executor execution method).

## Milestone 8 Docker Runtime Gate

**PASS — development-laptop runtime verification completed on 2026-08-17.**

Observed development-machine results:

```text
Python compile check: PASS (exit code 0)
Pytest: 96 passed, 1 warning in 2.36s
Docker clean reset/rebuild: PASS
Docker isolation verification: PASS
Public internet blocked from controlled-executor: PASS

Red Team runtime — sqli-login-bypass-001: PASS
Red Team runtime — xss-reflection-001: PASS
Red Team runtime — path-traversal-private-file-001: PASS

Final workflow state for all three confirmed runs: blue_monitoring
git diff --check: PASS
```

For every registered runtime scenario:

- reconnaissance described the approved endpoint surface;
- the mock provider configured the planner fixture;
- `AttackPlan.test_id` visibly contained the selected registered test before execution;
- execution completed without timeout;
- deterministic executor evidence was present;
- verification cited evidence IDs present in `TestExecutionResult`;
- verification was confirmed;
- the final workflow state was `blue_monitoring`;
- no Blue Team behavior executed.

The single pytest warning is an upstream Starlette/FastAPI TestClient deprecation warning from the virtual environment and did not fail the test suite.

## Milestone 8 Completion Criteria Status

- [x] Frozen top-level `agents/` layer implemented
- [x] Agent and provider abstractions remain separate
- [x] Narrow reconnaissance context implemented
- [x] Separate restricted planning catalog implemented
- [x] Existing Red Team schemas reused
- [x] Planner output deterministically validated
- [x] Existing policy engine reused unchanged
- [x] Existing run-limit tracker reused unchanged
- [x] Existing controlled executor reused unchanged
- [x] Existing registered security tests/config reused unchanged
- [x] Exactly three authorized provider calls for a successful flow
- [x] Verification integrity enforced deterministically
- [x] `BLUE_MONITORING` handoff implemented without Blue behavior
- [x] Full compile check passed
- [x] Full pytest suite passed — 96 tests
- [x] `git diff --check` passed
- [x] Docker image rebuild/reset verification on development laptop
- [x] Docker isolation re-verification on development laptop
- [x] Full Red Team runtime flow for SQL Injection
- [x] Full Red Team runtime flow for XSS
- [x] Full Red Team runtime flow for Path Traversal
- [ ] Final Git diff/status review after runtime verification
- [ ] Milestone 8 commit

## Still Locked

Do not implement until the appropriate later milestone:

- Blue Team agents/monitoring/triage;
- code-analysis agents;
- patch generation/retry;
- Git patch branches/automation;
- patch application and verification pipeline;
- experiment runner;
- RQ1/RQ2/RQ3 execution framework;
- research dashboard/React UI;
- experience/reward-guided selection;
- real external/cloud LLM provider integration;
- new vulnerability classes;
- new registered security-test payloads;
- crawler/scanner behavior;
- generic HTTP executor.

## Next Gate

**Final Milestone 8 Git diff/status review and commit.**

Implementation, automated verification, and Docker/runtime verification are complete. Do not begin the next milestone until the final Git review is clean and the Milestone 8 commit is created.

## Last Updated
2026-08-17
