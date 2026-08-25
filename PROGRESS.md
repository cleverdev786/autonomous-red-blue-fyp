# PROGRESS

## Project
**An Autonomous Multi-Agent Red-Blue Framework for Web Application Vulnerability Detection and Remediation**

## Current Milestone
**Milestone 11 — Blue Team Triage and Code Analysis**

## Status

**TECHNICALLY VERIFIED — implementation, automated verification, and development-laptop runtime verification PASS; final staged Git review and commit PENDING.**

Milestones 1–10 are complete. The post-Milestone-10 documentation cleanup is permanently committed at `2da2048`. Milestone 11 implementation, automated verification, and development-laptop runtime verification now pass in the current working tree. Final staged Git review and the milestone commit remain pending; Milestone 12 stays locked.

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
- [x] Milestone 8 — Red Team MVP — runtime verified and committed (`aee2213`)
- [x] Milestone 9 — Structured Logging and Audit System — runtime verified and committed (`4058143`)
- [x] Milestone 10 — Rule-Based Detection Baseline — runtime verified and committed (`5c494ba`)

## Milestone 7 Verified Baseline

Milestone 7 remains closed. The existing controlled executor:

- at Milestone 7 closure, accepted registered test ID plus attempt number only;
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

Milestone 9 subsequently adds only opaque `run_id` correlation and executor-generated `request_id` evidence. This does not add arbitrary HTTP/header authority or change registered security-test behavior.

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
- [x] Final Git diff/status review after runtime verification
- [x] Milestone 8 commit — `aee2213 Complete Milestone 8 Red Team MVP`

## Milestone 9 Implemented Locally

### Structured Application Evidence

The vulnerable store now emits Pydantic-validated JSON-line application events for:

- HTTP requests;
- validation observations;
- database observations;
- file-access observations;
- application errors.

Every structured application event includes opaque `run_id` and `request_id` correlation. Structural fields are generated separately from the bounded `attributes` mapping, and caller-supplied attributes cannot overwrite `schema_version`, IDs, timestamp, event type, component, route, method, or status. Sensitive attribute names such as password/token/authorization/cookie/secret/environment values are discarded.

Blue-facing events use neutral route names (`login`, `search`, `file_read`, etc.) and do not expose registered `test_id`, vulnerability class, registry endpoint IDs, raw scenario paths, request/evidence-rule IDs, source ground truth, or scenario ground truth.

### Correlation Boundary

`ControlledExecutor.execute_registered_test()` now additionally accepts an opaque `run_id`. It deterministically generates each `request_id` and passes only those fixed correlation values through `HttpTransport`. `HttpxTransport` constructs the two fixed internal correlation headers. No arbitrary header mapping was introduced.

Deterministic execution evidence now carries:

```text
RedTeamRunResult.run_id
TestExecutionResult.run_id
HttpExchangeEvidence.request_id
```

This creates a traceable run → execution → exchange → application-event chain without changing registered test selection, destinations, methods, payloads, or evidence rules.

### LogReader

`services/log_reader.py` reads only registry-approved `TargetDefinition.log_sources`. It has no Docker/subprocess capability. It validates application events, ignores ordinary runtime noise, safely counts malformed claimed structured events, de-duplicates event IDs, and returns only the exact requested run.

Docker stdout acquisition remains a human/runtime verification responsibility for Milestone 9. No Compose bind mount or Docker socket capability was added.

### Audit Service

`services/audit_service.py` writes append-oriented typed audit records under the fixed project-local runtime path `data/audit/audit.jsonl`. `RedTeamFlow` records current policy-sensitive actions, model-call authorization/results, workflow transitions, registered-test authorization, and controlled-execution outcomes. Blocked and successful actions are retained. Agents cannot create audit records directly.

Audit records remain separate from Blue/RQ2 application-classification input.

## Milestone 9 Automated Verification Result

Commands run against the Milestone 8 committed baseline plus the Milestone 9 implementation:

```bash
python3 -m compileall -q \
  agents orchestrator schemas services llm dummy_apps infrastructure security_tests

python3 -m pytest -q -p no:cacheprovider

git diff --check
```

Observed results:

```text
Python compilation: PASS
Pytest: 108 passed
git diff --check: PASS
```

Automated coverage includes the structural-field overwrite invariant, sensitive-field filtering, JSON-line integrity, neutral route names, all required application event categories, error logging, executor/application request correlation, exact run isolation, duplicate/malformed handling, absence of Docker authority in `LogReader`, append-oriented audit filtering, successful sensitive-operation auditing, blocked model-call auditing, and all Milestone 1–8 regressions.

## Milestone 9 Runtime Gate

**PASS — development-laptop runtime verification completed on 2026-08-18.**

Observed results:

```text
Python compile check: PASS (exit code 0)
Pytest: 108 passed, 1 warning in 3.00s
git diff --check: PASS

Docker clean reset/rebuild: PASS
Docker isolation verification: PASS
Public internet blocked from controlled-executor: PASS
Milestone 7 registered-test regression: PASS

m9-run-001 / SQL Injection correlated Red Team flow: PASS
m9-run-002 / XSS correlated Red Team flow: PASS
m9-run-003 / Path Traversal correlated Red Team flow: PASS
Final workflow state for all three runs: blue_monitoring

LogReader exact run isolation: PASS
Executor/application request-ID correlation: PASS
Required Milestone 9 runtime event categories: PASS
Forbidden registry/ground-truth structural metadata check: PASS

Audit runtime verification: PASS
14 audit records per run
3 successful model calls per run
registered-test authorization recorded
successful controlled execution recorded

Final Docker isolation re-check: PASS
```

Runtime evidence also confirmed:

- each execution carried the expected opaque `run_id`;
- each deterministic HTTP exchange carried a distinct executor-generated `request_id`;
- application logs contained the matching request IDs for the exact run;
- all three executions completed without timeout and retained deterministic evidence;
- structured application logs used neutral route names and did not expose scenario paths or registry/ground-truth structural fields;
- audit history was separated from Blue-facing application evidence;
- the controlled executor remained unable to access the public internet.

The single pytest warning is an upstream Starlette/FastAPI TestClient deprecation warning from the virtual environment and did not fail the test suite.

## Milestone 10 Completed

### Deterministic Rule-Only RQ2 Baseline

`services/rule_engine.py` now implements the deterministic Rule Only classification condition for RQ2 using only the existing Milestone 9 normalized evidence contract:

```text
LogReadResult
→ RuleEngine
→ TriageResult
```

No new event/classification schema was introduced. The implementation reuses `ApplicationLogEvent`, `LogReadResult`, `ClassificationLabel`, and `TriageResult` exactly as frozen by earlier milestones.

The engine supports the fixed labels `sql_injection`, `xss`, `path_traversal`, `benign`, and `unknown`. It uses generic observable signatures rather than exact registered-test IDs/payload equality, does not use neutral route names as vulnerability labels, returns `unknown` for conflicting signatures rather than applying arbitrary class precedence, and fails closed on mixed-run normalized input.

The service imports no LLM, agent, Red Team, audit, orchestrator, scenario-ground-truth, or registered-security-test module. It has no network, Docker, shell, filesystem, Git, model, or execution authority.

### Research-Validity Boundary

Milestone 10 classification input excludes scenario/test IDs, vulnerability ground truth, Red execution evidence, audit records, raw scenario routes, and source ground truth. Neutral route names cannot determine classification. This keeps the rule-only condition compatible with the same normalized evidence contract that later LLM-only and hybrid RQ2 conditions must receive.

Formal experiment persistence remains locked for its later milestone. Milestone 10 produces the existing JSON-serializable `TriageResult`; development runtime outputs may be retained only as local ignored artifacts.

## Milestone 10 Automated Verification Result

Commands executed against permanent Milestone 9 baseline `4058143` plus the Milestone 10 implementation:

```bash
python3 -m compileall -q \
  agents orchestrator schemas services llm dummy_apps infrastructure security_tests

python3 -m pytest -q -p no:cacheprovider

git diff --check
```

Observed results:

```text
Python compilation: PASS (exit code 0)
Pytest: 133 passed, 1 warning in 3.17s
git diff --check: PASS
```

Focused Milestone 10 tests cover all three supported vulnerability labels, generalized signatures, benign false-positive cases, route-name non-leakage, empty/conflicting `unknown` behavior, mixed-run rejection, deterministic event-order handling, evidence-ID integrity, and forbidden dependency/import boundaries.

## Milestone 10 Runtime Gate

**PASS — development-laptop runtime verification completed on 2026-08-19.**

Observed results:

```text
Python compile check: PASS (exit code 0)
Pytest: 133 passed, 1 warning in 3.17s
git diff --check: PASS

Docker clean reset/rebuild: PASS
Docker isolation verification: PASS
Public internet blocked from controlled-executor: PASS

m10-attack-001: sql_injection PASS
m10-attack-002: xss PASS
m10-attack-003: path_traversal PASS

m10-benign-001: benign PASS
m10-benign-002: benign PASS
m10-benign-003: benign PASS

Six classification JSON artifacts retained: PASS
Rule-only runtime loaded no LLM/agent modules: PASS
Final Docker isolation re-check: PASS
Final git diff --check: PASS
```

Runtime evidence confirmed that all three approved attack classes were classified correctly from Milestone 9 structured application events, all three representative normal baseline runs remained `benign`, supporting attack evidence IDs referenced actual normalized application events, and the rule-only path completed without loading LLM or agent modules. Six development classification artifacts were retained under ignored `data/m10-results/` paths.

### Docker host-port environment note

During benign runtime generation, the current Docker Engine/runtime accepted the Compose-requested binding in `HostConfig.PortBindings` but did not establish the live host mapping on the lab's `internal: true` bridge (`NetworkSettings.Ports` reported `8000/tcp: null`). The application remained healthy and reachable inside the isolated lab.

This was treated as a development-environment Docker runtime/networking issue, not a Milestone 10 code failure. No repository Docker configuration, network topology, or isolation control was weakened. Human-operated benign verification requests were issued from inside `vulnerable-store` to its own loopback interface, preserving the approved architecture and safety boundary.

The existing Starlette/FastAPI TestClient deprecation warning remained non-failing and did not affect the 133-test result.

Milestone 10 runtime verification is closed. The milestone was finalized and permanently committed at `5c494ba` (`5c494bab1ffe579cc22eab092764c5dc4101e8d8`) after the final Git review. The post-Milestone-10 documentation consistency cleanup was then committed at `2da2048`, which closed that gate and unlocked Milestone 11.

## Milestone 11 Implemented and Runtime-Verified Locally

Implemented components:

```text
agents/blue/__init__.py
agents/blue/monitoring.py
agents/blue/triage.py
agents/blue/code_analysis.py
orchestrator/blue_team_flow.py
services/source_reader.py
tests/test_blue_team_mvp.py
docs/BLUE_TEAM_TRIAGE_CODE_ANALYSIS.md
```

Extended existing components:

```text
schemas/blue_team.py
schemas/__init__.py
llm/mock_provider.py
README.md
PROGRESS.md
```

Milestone 11 preserves one comparable RQ2 input/output boundary:

```text
LogReadResult + ClassificationMode -> TriageResult
```

The three classification modes are now operational in code:

```text
rule_only -> existing RuleEngine -> TriageResult
llm_only  -> TriageAgent -> TriageResult
hybrid    -> RuleEngine evidence + TriageAgent -> TriageResult
```

`rule_only` classification still makes zero model/provider calls. `MonitoringAgent` exists for the specialized Blue Team architecture but is deliberately kept outside the RQ2 classification path so it cannot add a hidden reasoning stage to LLM-only/hybrid comparisons.

The new deterministic `SourceReader` is policy-controlled and further restricts Blue-visible source to bounded Python snippets under:

```text
dummy_apps/vulnerable_store/app/
```

Scenario ground-truth files, tests, secret-like files, out-of-root paths, and non-Python source are not exposed. Source selection uses only neutral route names from normalized logs. `CodeFinding` outputs are deterministically checked against the exact supplied snippets and line ranges.

### Milestone 11 Automated Verification Result

Implementation-workspace commands:

```bash
python -m compileall -q \
  agents orchestrator schemas services llm dummy_apps infrastructure security_tests

python -m pytest -q -p no:cacheprovider
```

Observed results:

```text
Python compilation: PASS
Pytest: 153 passed
Focused Milestone 11 tests: 20 passed
```

The optional Ruff check was unavailable in the implementation workspace because the Ruff module was not installed there. No dependency or project configuration was changed to work around that environment limitation.

Permanent-repository pre-runtime verification was then repeated on the development laptop:

```text
Python compilation: PASS
Full pytest suite: 153 passed, 1 warning in 3.29s
Focused Milestone 11 suite: 20 passed in 0.44s
git diff --check: PASS
```

The single warning remained the existing non-failing Starlette/FastAPI TestClient deprecation warning.

### Milestone 11 Runtime Gate

**PASS — development-laptop runtime verification completed successfully on 2026-08-25.**

Observed runtime evidence:

```text
Clean Docker reset/rebuild: PASS
Initial Docker isolation verification: PASS
Registered security-test regression: PASS
Correlated SQLi Red run: confirmed; final_state=blue_monitoring
Correlated XSS Red run: confirmed; final_state=blue_monitoring
Correlated Path Traversal Red run: confirmed; final_state=blue_monitoring
Structured-log correlation: 4 matching events for each opaque runtime run ID
Normalized Blue log read: 4 events per run; malformed=0; duplicates=0
rule_only classifications: SQLi / XSS / Path Traversal PASS
hybrid classifications: SQLi / XSS / Path Traversal PASS
llm_only deterministic mock classifications: SQLi / XSS / Path Traversal PASS
SQLi localization: scenario_routes.py :: vulnerable_login
XSS localization: scenario_routes.py :: vulnerable_search
Path Traversal localization: scenario_routes.py :: vulnerable_file_read
Standalone MonitoringAgent smoke verification: PASS
Scenario ground-truth source read blocked and audited: PASS
Final Docker isolation re-check: PASS
Public internet remained blocked from controlled-executor: PASS
git diff --check after runtime verification: PASS
```

The runtime verification used the existing isolated local lab and deterministic mock provider. It did not add a cloud provider, weaken Docker/network controls, expose scenario ground truth, or grant agents new execution/filesystem authority.

Milestone 11 is technically verified. Do not mark it formally complete until the complete staged Git review passes and the milestone commit is created and verified.

## Still Locked

Do not implement until the appropriate later milestone:

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

**Milestone 11 final staged Git review and commit.**

Implementation, the 153-test regression suite, the 20-test focused Milestone 11 suite, development-laptop runtime verification, registered-test regression, source-ground-truth blocking, and final Docker isolation verification have passed. The remaining gate is a complete staged review of all Milestone 11 tracked and newly added files.

Do not begin Milestone 12 until that staged review passes and the Milestone 11 commit is created and verified.

## Last Updated

2026-08-25
