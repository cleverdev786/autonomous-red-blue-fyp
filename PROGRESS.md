# PROGRESS

## Project
**An Autonomous Multi-Agent Red-Blue Framework for Web Application Vulnerability Detection and Remediation**

## Current Milestone
**Milestone 17 - Experience Memory + RQ1 Single-Agent Baseline**

## Status

**TECHNICALLY VERIFIED - bounded deterministic experience selection, the RQ1 single-agent baseline, authoritative development-laptop automated verification, controlled disposable runtime verification, and repository-integrity checks all PASS; final staged Git review and commit remain PENDING.**

Milestones 1–16 are permanently complete. Milestone 16 is committed at `927746e` (`927746e41eca43bb4221dbdd9784ec47f4208cee`) as `Complete Milestone 16 dashboard and scoring`. Milestone 17 adds a bounded read-only experience projection over existing M15/M16 research evidence, a deterministic selector that can choose only registered and policy-approved strategies, and the RQ1 single-agent comparison condition. Experience does not add new targets, endpoints, tools, paths, permissions, limits, Git/Docker/network authority, or other capabilities. The single-agent condition uses `AgentRole.BLUE_SINGLE_AGENT` for every reasoning call while the multi-agent condition retains the existing specialist roles. Both conditions derive their mode from stored `ExperimentConfiguration`, use equivalent normalized inputs, and converge into the same existing patch, Git-isolation, verification, and research-storage path. Final RQ1/RQ2 evaluations keep experience disabled. Final RQ experiments have not been run. Milestone 18 remains locked until the M17 commit is confirmed.

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
- [x] Milestone 11 — Blue Team Triage and Code Analysis — runtime verified and committed (`a3421a2`)
- [x] Milestone 12 — Patch Generation and Patch Policy — runtime verified and committed (`ff17026`)
- [x] Milestone 13 — Git Automation and Patch Branch Isolation — runtime verified and committed (`7d883b8`)
- [x] Milestone 14 — Patch Verification Pipeline — runtime verified and committed (`cf45fc2`)
- [x] Milestone 15 — Experiment Storage and Metrics — runtime verified and committed (`b1572cf`)
- [x] Milestone 16 — Dashboard and Scoring — runtime verified and committed (`927746e`)

## Milestone 17 Technically Verified

Milestone 17 implements the Phase-1 experience-memory boundary and the RQ1 single-agent baseline without changing the verified M1-M16 Blue flow, patch-generation flow, verification pipeline, scoring implementation, dashboard, or storage models.

### Experience memory and deterministic selection

`services/experience_store.py` reads prior terminal RQ1 outcomes from the existing research database through `ResearchReadRepository`. It does not create a second mutable memory database and does not read evaluator ground-truth classification tables. The bounded history rule is:

```text
MAX_EXPERIENCE_RECORDS_PER_STRATEGY = 20
ordering = completed_at DESC, started_at DESC, run_id ASC
ordering version = completed_started_run-v1
score version = red-blue-v1
```

Each `ExperienceSummary` contains only a small outcome projection: source run, scenario, trusted strategy ID, terminal status, optional Blue score, patch acceptance, regression flag, policy-block count, duplicate-patch count, and attempt count. A missing Blue score remains `None`; it is not converted to zero and is excluded from reward averages.

`orchestrator/selection_policy.py` ranks only caller-registered strategies that also pass `PolicyEngine.validate_strategy_selection()`. Policy denial always overrides historical reward. No random exploration, reinforcement learning, online learning, model training, or self-modification is implemented. Ranking is deterministic: higher mean Blue score, higher patch acceptance, lower regression rate, fewer policy blocks, fewer duplicate patches, lower mean attempt count, then lexical strategy ID as the final tie-break.

The three experience modes are:

```text
DISABLED
  no experience lookup; use the configured trusted strategy

FROZEN_IDENTICAL
  use only the supplied immutable snapshot

ENABLED_EXPLORATORY
  read the current bounded history for development/exploratory use
```

Final primary RQ1/RQ2 configurations require `ExperienceMode.DISABLED`. Selection decisions are stored as canonical typed `selection_decision` result artifacts with SHA-256 integrity through the existing artifact store. No SQLAlchemy table was added; the schema remains exactly 20 tables.

### RQ1 single-agent baseline

`experiments/rq1_runner.py` derives `blue_team_mode` from the stored `ExperimentConfiguration`; `run()` has no second independent mode argument. `validate_rq1_configuration_pair()` requires the paired RQ1 conditions to differ only by `config_id` and `blue_team_mode`.

The single-agent condition uses one general-purpose `SingleGeneralBlueAgent` persona across monitoring, triage/classification, code analysis, and patch proposal. Every provider call uses `AgentRole.BLUE_SINGLE_AGENT`. Stage-specific schemas and input adapters are allowed, but they do not create specialist identities. The multi-agent condition keeps the existing roles:

```text
BLUE_MONITORING
BLUE_TRIAGE
BLUE_CODE_ANALYSIS
BLUE_PATCH_GENERATION
```

Both conditions explicitly run monitoring and then reuse the existing typed Blue/Patch contracts. The single-agent adapters inherit the existing `BlueTeamFlow.run` and `PatchGenerationFlow.run` behavior, and both RQ1 conditions use the same downstream patch-branch, Git-isolation, verification, and research-storage interfaces. `proposed_security_test` remains optional. M17 does not freeze the final RQ1 classification mode; that remains an M20 experiment-freeze decision. `RULE_ONLY` is rejected only for the single-agent RQ1 execution because that condition must include classification by the general Blue agent.

### Authoritative automated and controlled runtime verification

```text
Focused M17/integration gate: 113 passed, 1 non-failing Starlette warning
Full development-laptop suite: 286 passed, 1 non-failing Starlette warning
SQLAlchemy schema: exactly 20 tables
Protected M1-M16 flow files changed by M17: none
Permanent data/fyp.db: absent
M17 working scope during VERIFY: exactly 14 files, unstaged

Experience runtime:
  history bounded to 20 per strategy: PASS
  stable deterministic ordering: PASS
  missing Blue score remains None: PASS
  missing score excluded from mean reward: PASS
  read-only experience lookup changed no DB rows: PASS
  read-only experience lookup changed no DB bytes: PASS
  DISABLED performs zero live lookup: PASS
  FROZEN_IDENTICAL uses supplied snapshot only: PASS
  ENABLED_EXPLORATORY uses bounded live history: PASS
  policy denial overrides superior reward: PASS
  unregistered strategy rejected: PASS
  canonical SelectionDecision persisted/hash revalidated: PASS
  no FINAL_EVALUATION configuration created: PASS

Paired RQ1 runtime:
  paired configs differ only by Blue architecture: PASS
  stored configuration derives condition: PASS
  single-agent calls = BLUE_SINGLE_AGENT x4: PASS
  multi-agent roles remain specialized: PASS
  equivalent normalized inputs: PASS
  equivalent normalized patch output: PASS
  proposed_security_test optional: PASS
  same downstream branch-flow object: PASS
  same verification-pipeline object: PASS
  same research DB/storage path: PASS
  same canonical artifact stages stored: PASS
  development configurations only: PASS

Repository integrity after runtime VERIFY:
  all 14 M17 files byte-identical to pre-runtime state: PASS
  Git working-tree status unchanged: PASS
  branch/ref state unchanged: PASS
  nothing staged: PASS
  HEAD remained permanent M16: PASS
  permanent data/fyp.db remained absent: PASS
  runtime evidence stayed under /tmp/fyp-m17-runtime: PASS
```

The controlled RQ1 runtime uses development fixtures and shared recording adapters to prove M17 architecture and condition isolation. It intentionally does not repeat the full M13/M14 Git/Docker remediation campaign because M17 does not modify those subsystems. No final RQ experiment was run.

See `docs/EXPERIENCE_MEMORY_RQ1.md`.

## Milestone 16 Permanent Baseline

Milestone 16 is permanently complete at `927746e` (`927746e41eca43bb4221dbdd9784ec47f4208cee`). It defines scoring version `red-blue-v1`. Scoring is an explicit offline/post-run operation implemented in `orchestrator/scoring.py`; dashboard GET requests never calculate or persist scores. The scorer consumes stored terminal evidence, evaluator-only truth where a score component requires correctness evaluation, and the exact frozen policy-attribution map. LLM opinion is never score authority.

Red score:

```text
C   = 1 only for a canonical RedTeamRunResult that revalidates the trusted
      Milestone 8 confirmation semantics; otherwise 0
D_R = repeated registered Red test uses after the first use
P_R = Red-attributable blocked policy events from the frozen red-blue-v1 map

Red = clamp(100*C - 5*min(D_R, 4) - 25*min(P_R, 2), 0, 100)
```

Blue score:

```text
classification correctness          10
source-file localization            10
function/route localization         10

best single patch attempt only:
  syntax_import                      5
  application_startup                5
  functional                        10
  security                          20
  original_replay                   25
  regression                         5
                                     --
                                     70

Blue = clamp(
    diagnosis/localization points
  + best one-attempt verification points
  - 5*min(D_B, 3)
  - 25*min(P_B, 2),
  0,
  100
)
```

Patch-stage points are never combined across attempts. Duplicate Blue attempts are repeated prepared-diff SHA-256 values. RQ2 runs return `not_applicable`; CREATED/RUNNING runs return `ineligible_incomplete`; neither case creates score rows.

Each persisted score has an immutable canonical typed `ScoreResult` artifact in existing `result_artifacts`. `score_records.evidence_reference` resolves to that artifact plus its SHA-256 digest. `(run_id, score_type, scoring_version)` is unique. Identical same-version rescoring is an idempotent no-op; changed evidence or an inconsistent score under the same version fails rather than overwriting history. Formula changes therefore require a new scoring version. Research metric code remains independent of score rows.

The dashboard consists of `dashboard/api/` and `dashboard/frontend/`. The frontend uses the frozen React + Vite Phase-1 architecture. The FastAPI API reads an already-existing SQLite database only; it never initializes or creates the research DB. The corrected database engine uses SQLite URI `mode=ro`, `PRAGMA query_only=ON`, and `NullPool`, eliminating the intermittent cross-thread closed-connection failure found during runtime verification while preserving genuine read-only access.

Minimum verified views are Overview, Runs, Run Detail, Findings, Patch Verification, Metrics, and Audit. Stored generated/model/diff/audit text is bounded and displayed as inert escaped text. Manual runtime verification confirmed literal `<script>...</script>` fixture strings did not execute and no unsafe operation/recalculation controls are exposed. CLI/orchestrator scoring was also verified from a copy where the dashboard package was absent.

Authoritative automated and runtime result:

```text
Python full development-laptop suite: 271 passed, 1 non-failing Starlette warning
Focused scoring/dashboard/metric gate: 21 passed, 1 non-failing Starlette warning
SQLAlchemy schema: PASS — exactly 20 tables
Scoring perfect-run: Red 100 / Blue 100
Penalty-run: Red 70 / Blue 70
RQ2 score applicability: not_applicable; score rows = 0
RUNNING score applicability: ineligible_incomplete; score rows = 0
Canonical ScoreResult evidence/hash resolution: PASS
Identical same-version rescore: PASS — DB SHA-256 unchanged
Changed same-version evidence rejection: PASS — existing score rows/artifacts unchanged
Dashboard genuine SQLite read-only/query-only enforcement: PASS
Dashboard GET-only/API safety boundary: PASS
Manual seven-view React presentation/safety verification: PASS
NullPool correction: PASS
Concurrent dashboard runtime: 240 attempted / 240 responses / 240 HTTP 200 / 0 exceptions
Corrected API log: no 500, ProgrammingError, traceback, or closed-database error
Concurrent-read research DB SHA-256: unchanged
All 20 table row counts after concurrent reads: unchanged
Total score rows after dashboard reads: unchanged (4)
RQ2 score rows after dashboard reads: 0
Persistent SQLite WAL/SHM/journal sidecars: none
Core CLI/orchestrator without dashboard package: PASS
Permanent data/fyp.db: absent
Permanent agent-patch branches: none
VERIFY implementation scope: exactly 27 files, byte-identical to post-correction baseline
npm audit --omit=dev: 0 production vulnerabilities
Full npm audit: 2 development/build advisories (1 moderate esbuild, 1 high Vite); recorded, not auto-fixed
```

The npm findings are a non-blocking development/build dependency warning for this local read-oriented dashboard because the production-only audit is clean. No `npm audit fix` or forced dependency upgrade was applied during M16 verification.

See `docs/DASHBOARD_SCORING.md`.

## Milestone 15 Permanent Baseline

Milestone 15 is permanently complete at `b1572cf`. It added the frozen `storage/` and `experiments/` packages without changing agent or verification authority. Research results are recorded as canonical typed artifacts plus normalized SQLAlchemy rows. RQ1/RQ3 remain scenario-scoped; RQ2 is dataset-scoped with classifier-visible items separated from evaluation-only labels. Failed, rejected, policy-blocked and interrupted runs/attempts remain first-class records.

Research metrics are recomputed from raw records. Score rows remain separate from metric code; M16 now supplies the deterministic game-score layer without changing those research metrics. Missing model token/cost telemetry remains explicitly `not_reported` rather than being fabricated as zero. The existing audit JSONL remains authoritative; storage records only a digest/summary and bounded policy-event references.

Milestone 15 authoritative closure baseline remains:

```text
Full development-laptop suite at M15 closure: 257 passed, 1 warning
SQLAlchemy schema: exactly 20 tables
Controlled file-backed SQLite runtime: PASS (2026-08-29)
Canonical artifact reopen/hash verification: PASS — 27/27
RQ1/RQ2/RQ3/Red metric recomputation: PASS
Normal Application Task Success derivation: PASS — 9/17 synthetic checks
Audit separation and bounded policy references: PASS
Unknown token/cost telemetry remains NULL/not_reported: PASS
Score-record independence from research metrics: PASS
Permanent data/fyp.db: absent before and after runtime
Permanent commit: b1572cf
```

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

Milestone 11 is permanently complete and committed at `a3421a2` (`a3421a29ad5c8bcc70cdc53cc3f4dd6890792235`). The repository was clean after commit verification, which unlocked Milestone 12.

## Milestone 12 Implemented Locally

Implemented components:

```text
agents/blue/patch_generation.py
orchestrator/patch_generation_flow.py
services/patch_service.py
tests/test_patch_generation.py
docs/PATCH_GENERATION_POLICY.md
```

Extended trusted schemas/config/policy and deterministic mock support:

```text
schemas/patches.py
schemas/targets.py
schemas/__init__.py
orchestrator/policy_engine.py
llm/mock_provider.py
config/targets/vulnerable-store.json
tests/test_schemas.py
tests/test_policy_engine.py
README.md
PROGRESS.md
```

Milestone 12 now implements:

```text
BlueTeamAnalysisResult
→ grounded bounded patch context
→ PatchGenerationAgent
→ PatchProposal
→ deterministic path/grounding/size validation
→ in-memory PreparedPatch + unified diff
→ PATCH_VALIDATING
```

Important boundaries remain enforced:

- source edits are restricted to the exact validated `CodeFinding.file_path`;
- proposed edits use exact `original_content` → `replacement_content` grounding;
- original anchors must be supplied to the model, unique in the current file, and non-overlapping;
- generated-test destinations are derived by the trusted Patch Service, not selected by the LLM;
- patch paths are restricted to approved writable roots and `.py` files;
- human-controlled target configuration limits files, insertions, deletions, and total diff bytes;
- the Patch Service creates only an in-memory unified diff and hashes;
- no source/test patch is written to disk;
- no Git branch, patch application, patched test execution, or patch acceptance is implemented.

### Milestone 12 Automated Verification Result

Implementation-workspace commands:

```bash
python -m compileall -q \
  agents orchestrator schemas services llm dummy_apps infrastructure security_tests

python -m pytest -q -p no:cacheprovider

python -m pytest -q -p no:cacheprovider tests/test_patch_generation.py
```

Observed results:

```text
Python compilation: PASS
Full pytest suite: 180 passed
Focused Milestone 12 tests: 20 passed
```

Automated coverage confirms grounded in-memory patch preparation for SQL Injection, XSS, and Path Traversal; no-disk-write behavior; service-derived optional generated-test paths; patch/model budget enforcement before provider invocation; protected-path and non-Python blocking; patch-size enforcement; retry-feedback input separation; and audit evidence for successful/blocked preparation.

### Milestone 12 Host-Side Runtime Verification

Development-laptop runtime verification completed successfully on 2026-08-25 against the permanent repository while `main` remained at Milestone 11 commit `a3421a2`. The verification exercised the real Milestone 12 orchestration and deterministic patch service without applying generated patches.

Observed pre-runtime state:

```text
Branch: main
HEAD: a3421a2
Generated-test destination absent: PASS
Milestone 12 Git-visible implementation scope: unchanged
```

Observed prepared-patch results:

```text
m12-runtime-sqli: files=1, inserted=7, deleted=4, bytes=958
diff_sha256=66269f75a26c4350d79b2dac654c47285e1d6a42f967ee4af9cbd9a88af3bfb5

m12-runtime-xss: files=1, inserted=2, deleted=1, bytes=606
diff_sha256=a86c1f805bd497e2610f5c65088a32d3387af0ad407ac8eeb57e9b93410483c0

m12-runtime-path: files=1, inserted=9, deleted=0, bytes=964
diff_sha256=c0c0e531670dd9bfcf1fb7db5c759d649e8b2aee25685f147629a0008d88fa6c
```

Additional runtime safety/policy checks:

```text
Optional generated security test remained in memory only: PASS
orchestrator/policy_engine.py patch path blocked: PASS
.env patch path blocked: PASS
mandatory baseline test patch path blocked: PASS
oversized patch blocked by configured policy: PASS
ungrounded exact-text proposal blocked and audited: PASS
scenario_routes.py SHA-256 unchanged after runtime checks: PASS
generated security test not written: PASS
branch remained main: PASS
HEAD remained a3421a2: PASS
git diff --check after runtime verification: PASS
final changed/untracked scope remained exactly the 16 Milestone 12 paths: PASS
```

The runtime gate therefore confirms that Milestone 12 prepares policy-approved patches strictly in memory and fails closed for protected, oversized, or ungrounded proposals without modifying the vulnerable source tree or beginning Git automation/patch verification.

Milestone 12 is permanently complete and committed at `ff17026` (`ff17026216e7f8cb4bfb7cbed2da6047414ef522`). The repository was clean after post-commit verification, which unlocked Milestone 13.

## Milestone 13 Technically Verified

Implemented components:

```text
config/git-policy.json
schemas/git.py
services/git_service.py
orchestrator/patch_branch_flow.py
tests/test_git_service.py
docs/GIT_PATCH_BRANCH_ISOLATION.md
```

Extended schema exports and project status/test coverage:

```text
schemas/__init__.py
tests/test_schemas.py
README.md
PROGRESS.md
```

Milestone 13 now implements:

```text
PatchGenerationResult / PreparedPatch
→ clean configured baseline validation
→ deterministic agent-patch/<run_id>/attempt-<n> branch
→ PreparedPatch integrity/freshness/path preflight
→ exact-path write + replacement hash verification
→ bounded staged Git diff evidence
→ PATCH_APPLYING
```

Important boundaries:

- the baseline branch is validated clean before branch creation;
- branch creation is completed before the first generated file write;
- the service consumes only `PreparedPatch`, never raw LLM patch output;
- source/replacement/diff hashes are revalidated before application;
- patch paths are rechecked through the deterministic Patch Policy;
- only prepared paths are written/staged;
- application failures roll back only known prepared paths;
- baseline restoration refuses to erase unrelated dirty files;
- patch branches are retained rather than automatically deleted;
- local patch commits require an explicit trusted `PatchDecision.ACCEPTED`;
- no push, force-push, merge, pull, fetch, or arbitrary Git-command interface exists;
- the normal Milestone 13 flow does not commit, merge, verify, or accept a patch.

### Milestone 13 Authoritative Automated Verification

Permanent development-laptop verification with the project's installed GitPython dependency observed:

```text
GitPython: 3.1.59
Python compilation: PASS
Full pytest suite: 203 passed, 1 warning in 11.06s
Focused Milestone 13 Git tests: 19 passed in 4.53s
Schema tests: 17 passed in 0.21s
git diff --check: PASS
Prohibited Git API grep: PASS (no matches)
Destructive reset/clean grep: PASS (no matches)
Final branch: main
Final HEAD: ff17026
Final changed/untracked scope: exactly the 10 Milestone 13 paths
```

The single pytest warning is the existing Starlette/FastAPI TestClient deprecation warning and did not fail the suite. The authoritative laptop result supersedes the implementation-workspace GitPython compatibility-shim result for milestone closure.

### Milestone 13 Controlled Host-Side Git Runtime Verification

Controlled runtime verification was performed on 2026-08-26 using disposable `/tmp` clones of the clean Milestone 12 baseline while the permanent repository supplied the current Milestone 13 Python implementation. No generated patch branch or patch write was created in the permanent repository.

Observed runtime results:

```text
permanent baseline before runtime: main @ ff17026216e7f8cb4bfb7cbed2da6047414ef522
disposable clones started clean on main @ ff17026: PASS
PreparedPatch materialized only on agent-patch/m13-runtime-xss/attempt-1: PASS
baseline main remained ff17026: PASS
native Git diff SHA-256 generated: f767123700a56fd9320174e35f0b5624ba283675a21b792538429f07c9396035
exact-path restoration returned the disposable repository to clean main: PASS
patch-attempt branch retained for evidence: PASS
generated security test existed only on the disposable patch branch: PASS
generated security test removed by exact-path restoration: PASS
dirty baseline blocked: PASS
wrong expected baseline SHA blocked: PASS
deterministic branch collision blocked: PASS
direct PreparedPatch materialization on main blocked: PASS
PatchDecision.REJECTED could not create a commit: PASS
explicit PatchDecision.ACCEPTED created local patch-branch commit 3d149c001c02df1dccae9bc38961adf3ad041499: PASS
accepted commit did not move main: PASS
permanent scenario_routes.py SHA-256 unchanged: PASS
permanent branch refs unchanged: PASS
permanent repository stayed main @ ff17026: PASS
final permanent changed/untracked scope remained exactly the 10 Milestone 13 paths: PASS
git diff --check after runtime verification: PASS
```

The disposable accepted-commit clone retained a local `origin` pointing to the permanent repository because it was created with `git clone`; no push or remote mutation was performed. Milestone 13 runtime verification therefore confirms branch-per-attempt isolation, baseline protection, exact-path restoration, fail-closed Git preconditions, and accepted-only local commit capability without modifying the permanent baseline.

## Milestone 14 Implemented Locally

Milestone 14 now follows the frozen deterministic order:

```text
patch policy → path/Git integrity → syntax/import → startup/isolation
→ functional → relevant registered security test → original Red replay
→ trusted regression allowlist → deterministic ACCEPTED/REJECTED
```

Safety boundaries implemented in the working tree:

- no LLM participates in verification;
- live HTTP verification originates only inside `controlled-executor`;
- `EnvironmentService` exposes fixed Docker lifecycle/isolation operations only;
- `TestRunner` exposes named deterministic checks only;
- raw generated tests are compiled for syntax but never imported/executed and never influence acceptance;
- policy/Git-integrity failures map to `POLICY_BLOCKED`;
- trusted infrastructure/runner failures map to `FAILED`;
- syntax/startup/functional/security/replay/regression patch failures map to `REJECTED`;
- accepted patches use the existing accepted-only local Git commit capability;
- Docker cleanup and exact-path baseline restoration are always attempted;
- automatic retry, merge and push do not exist in the Milestone 14 flow.

Implementation and authoritative automated evidence:

```text
Implementation-workspace compilation: PASS
Implementation-workspace full suite after Path Traversal fixture correction: 209 passed, 1 GitPython-only skip
Authoritative development-laptop GitPython: 3.1.59
Authoritative development-laptop compilation: PASS
Authoritative development-laptop full suite after correction: 230 passed, 1 warning in 5.67s
Focused patch-generation tests after correction: 21 passed in 0.55s
Focused Milestone 14 verification tests after correction: 21 passed
Earlier authoritative M14 pre-runtime schema tests: 20 passed
Earlier authoritative M14 pre-runtime GitService tests: 21 passed
Earlier authoritative M14 verification + schema tests: 41 passed
git diff --check: PASS
```

The warning is the existing non-failing Starlette/FastAPI TestClient deprecation warning. The two-file correction is restricted to `llm/mock_provider.py` and `tests/test_patch_generation.py`; it preserves the existing `scenario_root` sandbox-escape guard before the new `intended_public_root` containment guard and does not weaken the Milestone 14 regression policy.

### Milestone 14 Controlled Host-Side Docker/Git Runtime Verification

**PASS — complete corrected runtime verification completed successfully on 2026-08-27.**

The first runtime attempt correctly rejected the deterministic Path Traversal patch because it changed the trusted sandbox-escape response from `"Scenario sandbox escape blocked"` to `"Path traversal blocked"`. The regression suite therefore caught a real compatibility regression. The deterministic fixture was corrected without changing the verifier or regression allowlist, all automated gates were rerun, and the complete runtime gate was then repeated from scratch.

The corrected disposable runtime baseline was:

```text
ee535c199907556c6797d375c42f3ec458dfae3e
```

Observed corrected runtime results:

```text
Vulnerable baseline SQL Injection evidence confirmed: PASS
Vulnerable baseline XSS evidence confirmed: PASS
Vulnerable baseline Path Traversal evidence confirmed: PASS
SQLi remediation ACCEPTED on isolated branch: a8e0d1a93ede0e2dd0270cc55c82774291ed717a
XSS remediation with hostile generated-test guard ACCEPTED: 3961b3035683e6dd06b38c4db5087f7d0674a612
Path Traversal remediation ACCEPTED after fixture correction: de2ad5647b903646e0c576d123cda3e7169b10d3
Raw generated test compiled but was never executed or collected: PASS
Policy-valid insecure XSS patch rejected by security + original replay: PASS
Security-fixing but behavior-breaking XSS patch rejected by functional/regression: PASS
Invalid Python patch rejected at syntax/import before application startup: PASS
Staged Git drift POLICY_BLOCKED before Docker verification stages: PASS
All seven disposable case repositories restored to clean main at ee535c1: PASS
Accepted commits retained only on local agent-patch branches: PASS
Rejected/POLICY_BLOCKED attempts created no accepted remediation commit: PASS
Docker lab fully cleaned after runtime verification: PASS
Permanent scenario_routes.py SHA-256 unchanged: PASS
All 24 permanent Milestone 14/correction files byte-identical before/after: PASS (24/24)
Permanent branch refs unchanged: PASS
Permanent porcelain status before/after identical: PASS
Permanent generated XSS test absent: PASS
Permanent repository remained main @ 7d883b8 with no agent-patch branch: PASS
git diff --check after runtime verification: PASS
Final Git-visible scope remained exactly 24 Milestone 14/correction paths: PASS
```

No merge or push was performed. Milestone 14 is technically verified; documentation finalization, exact staged-scope review, and the milestone commit remain pending.

See `docs/PATCH_VERIFICATION_PIPELINE.md`.

## Still Locked

Do not implement until the appropriate later milestone:

- Milestone 18 — RQ2 Frozen Classification Dataset;
- Milestone 19 — RQ3 Structured Feedback Retry;
- Milestone 20 — Experiment Freeze;
- Milestone 21 — Final Controlled Experiments;
- Milestone 22 — Results Analysis;
- automatic merge or remote Git publication;
- unrestricted HTTP, Docker, shell, filesystem, database, or Git authority for LLM agents;
- new vulnerability classes or real/public/production targets.

Final RQ experiments remain unrun. M16 scores remain separate from RQ metrics; M17 may use the stored Blue `red-blue-v1` score only as one bounded development/exploratory selection signal, while final RQ1/RQ2 evaluations keep experience disabled.

## Next Gate

**Perform the exact final staged Git review for Milestone 17 and commit only after the staged implementation/documentation scope is proven correct.**

Milestone 17 is technically verified with commit pending. Review the complete M17 implementation plus this documentation finalization, prove the exact staged path scope, run staged whitespace/safety checks and the final regression gate, and commit only after every staged Git gate passes. Do not begin Milestone 18 and do not run final RQ experiments before the M17 commit is confirmed.

## Last Updated

2026-09-09
