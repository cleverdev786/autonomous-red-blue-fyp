# MARS Red Team | Implementation checklist

**Source:** [`tasks/plan.md`](plan.md), frozen requirements from the approved design interview (2026-10-26).
**Current state:** All tasks are **unchecked**. These are planned implementation and verification tasks, not completed work.
**Use:** Execute in numeric order. Check a task only after **all** criteria and its verification pass. Do not begin an actual implementation without explicit separate authorization.
**Task size:** S/M focused slices, typically 1–5 files, not entire subsystems. Paths below are indicative until T01 verifies the current branch.

## Universal gate for each task

- [ ] Working tree inspected, pre-existing changes preserved and relevant source read before editing.
- [ ] New/changed logic has at least one focused test plus a denial/exception case where appropriate.
- [ ] Tests/build for touched layer pass; Docker safety and audit truthfulness checked whenever relevant.
- [ ] Reviewable commit and updated documentation after the task is fully verified (only with authorized implementation).

## Phase A: Audit and contracts

Do not start Docker tools or alter working code before the existing branch, tests and interfaces are understood.

### T01: Audit current Red Team and pin baseline

- [x] **T01 fully implemented and verified**

**Outcome:** Produce a short actual-code inventory and retain all unrelated changes; establish current behavior before changing it.
**Depends on:** none. **Size:** S. **Likely touched:** `agents/red/; orchestrator/red_team_flow.py; services/; dashboard/frontend/src/; tests/`.

**Acceptance criteria:**
- [x] Current git branch/status, Docker target health, existing registered tests, preview-only APIs, model hooks and actual executor path are documented from live code.
- [x] Existing unit and frontend checks are run or specific pre-existing failures are recorded without modifying source.
- [x] Old research/evaluation outputs and unrelated working-tree changes remain untouched.
- [x] **Verification:** `git status -sb`; targeted `.venv/bin/python -m pytest` discovery; `cd dashboard/frontend && npm test && npm run build`.

### T02: Freeze the model-free Red Agent contract

- [x] **T02 fully implemented and verified**

**Outcome:** Define the deterministic responsibilities and output schemas for all four workers and identify optional LLM paths to exclude.
**Depends on:** T01. **Size:** M. **Likely touched:** `schemas/red_team.py; agents/red/*; tests/test_red_agent_contracts.py`.

**Acceptance criteria:**
- [x] Recon, Plan, Execute and Verify contracts have typed inputs, outputs, error/status models and scope references.
- [x] Required Red Team path makes no model-provider call; old optional paths are isolated or explicitly deprecated without breaking unrelated features.
- [x] Contract tests fail on malformed or out-of-scope agent outputs.
- [x] **Verification:** Unit test malformed schema, missing required scope and a provider stub that raises if called.

### Checkpoint A.2: release gate after T02

- [x] Agent contracts: deterministic inputs/outputs checked.
- [x] Record passing command, output location and reviewer/commit reference.

**Checkpoint A.2 evidence:** `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_red_agent_contracts.py tests/test_red_team_mvp.py tests/test_policy_engine.py tests/test_registered_assessment_plan.py tests/test_controlled_executor.py tests/test_operator_console.py tests/test_docker_isolation_config.py tests/test_mars_red_preflight.py` (128 passed, 1 existing deprecation warning); review basis: T02 scope diff and fail-closed contract tests; commit: `0b60ad5`.

### T03: Define Standard assessment policy

- [x] **T03 fully implemented and verified**

**Outcome:** Represent the single authorized vulnerable-store target, three vulnerability classes, allowed HTTP methods and strictly bounded test budgets.
**Depends on:** T01,T02. **Size:** M. **Likely touched:** `config/targets/vulnerable-store.json; orchestrator/policy_engine.py; schemas/red_team.py; tests/test_red_policy.py`.

**Acceptance criteria:**
- [x] Immutable assessment authorization includes target fingerprint, allowed destination/method, SQLi/XSS/traversal, crawl/request/time/concurrency limits.
- [x] An unknown target, vulnerability class, method or exhausted budget is denied before an operation is issued.
- [x] Standard is the only testing profile; no Quick/Thorough placeholders.
- [x] **Verification:** Policy unit tests for valid target, forbidden host/method/class and each exhausted budget; inspect config bounds.

**T03 verification evidence:** `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_red_policy.py` (18 passed); Standard bounds in `config/red_standard.json`. Snapshot/check are contract-only and do not grant tool dispatch permission (T07/T08). Commit: `e47bea4`.

### T04: Specify persisted states and API DTOs

- [x] **T04 fully implemented and verified**

**Outcome:** Finalize the minimal state machine and mapping among candidates, plans, operations, evidence, findings and coverage gaps.
**Depends on:** T02,T03. **Size:** S. **Likely touched:** `schemas/red_team.py; dashboard/api/console.py (contracts only); tests/test_red_schema_contracts.py`.

**Acceptance criteria:**
- [x] Assessment, stage, finding and gap statuses have explicit transition rules and separate workflow-completion/coverage fields.
- [x] Each operation references one immutable plan version and authorization fingerprint; confirmation cannot be inferred from a ZAP alert.
- [x] JSON contract fixtures can be decoded and rejected on invalid transitions/references.
- [x] **Verification:** Schema tests serialize all states, reject illegal transitions and compare representative API payloads.

**T04 verification evidence:** `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_red_schema_contracts.py tests/test_red_policy.py tests/test_red_agent_contracts.py tests/test_red_team_mvp.py tests/test_policy_engine.py tests/test_registered_assessment_plan.py tests/test_controlled_executor.py tests/test_operator_console.py tests/test_docker_isolation_config.py tests/test_mars_red_preflight.py` (167 passed, one pre-existing Starlette/httpx warning). DTO test uses an in-process FastAPI response fixture, not a live Red endpoint. Actual persistence and dispatch remain out of scope.

### Checkpoint A.4: release gate after T04

- [x] Baseline and scope: contract review complete.
- [x] Record passing command, output location and reviewer/commit reference.

**Checkpoint A.4 evidence:** 167 focused Python tests passed; reviewed state/plan/receipt DTO scope and fail-closed transitions; T04 commit `2153d13`.

## Phase B: Persistence, security and approval

Lay the server-side state/evidence/authorization foundation; make rejection behavior testable.

### T05: Persist assessment and plan versions

- [x] **T05 fully implemented and verified**

**Outcome:** Add minimal SQLite persistence for assessments, stages, candidates, plans, operations and immutable authorization snapshots.
**Depends on:** T04. **Size:** M. **Likely touched:** `existing SQLite persistence layer; schemas/red_team.py; migrations or schema initialization; tests/test_red_store.py`.

**Acceptance criteria:**
- [x] Creating, reading and restarting preserves assessment identity, plan version, stage status and authorization.
- [x] Prior plan versions are retained; staleness is explicit and older records are never overwritten.
- [x] Foreign references and uniqueness/idempotency constraints are enforced.
- [x] **Verification:** Temp-database tests create an assessment, reopen storage, verify version history and reject duplicate requests.

**T05 verification evidence:** `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_red_store.py` (8 passed); all persistence tests use isolated temporary SQLite databases. T05 has no effectful API or scan path. Commit reference: the commit containing this record.

### T06: Persist append-only timeline and evidence metadata

- [x] **T06 fully implemented and verified**

**Outcome:** Create a small event/evidence storage seam backed by existing SQLite/file conventions.
**Depends on:** T05. **Size:** M. **Likely touched:** `existing persistence layer; services/red_evidence_store.py (if needed); tests/test_red_evidence_store.py`.

**Acceptance criteria:**
- [x] Timeline stores actor, action, outcome and timestamp; evidence stores hash, target fingerprint, operation ID, content type and safe bounded location.
- [x] Events/evidence remain accessible after a restart or failed/cancelled assessment.
- [x] Raw credentials and sensitive request bodies are redacted; unsafe artifact paths cannot be read.
- [x] **Verification:** Tests for event ordering, hash integrity, read permissions, log redaction and restart durability.

**T06 verification:** `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_red_evidence_store.py` (8 passed). Event/evidence data are append-only and scope-bound, with redacted structured JSON and SHA-256 verification. The old unreferenced Milestone-8 Red Team MVP document was deleted. No external scan performed. Commit reference: the commit containing this checkpoint.

### Checkpoint B.6: release gate after T06

- [x] Durability: versioning and evidence journal pass.
- [x] Record passing command, output location and reviewer/commit reference.

**Checkpoint B.6 review:** T05 versioned SQLite persistence and T06 append-only evidence/receipt records confirmed after restart, hash tampering and path traversal denied; tests under `tests/test_red_store.py` and `tests/test_red_evidence_store.py`. Commit reference: the commit containing this checkpoint.

### T07: Enforce trusted operation admission

- [x] **T07 fully implemented and verified**

**Outcome:** Move final authorization into a shared service independent of agent reasoning, and reject untrusted scanner recommendations.
**Depends on:** T03,T04,T05. **Size:** M. **Likely touched:** `orchestrator/policy_engine.py; services/controlled_executor.py; tests/test_red_admission.py`.

**Acceptance criteria:**
- [x] Every operation is revalidated against target/method/port/redirect/budget, current plan and immutable authorization, not browser claims.
- [x] Plan, policy and target fingerprints must match; unknown command/tool names never reach execution.
- [x] Unsafe redirects, URL tricks and stale plans fail closed with auditable denial events.
- [x] **Verification:** Negative tests for localhost/metadata/external destination, encoded URL, redirects, stale plan, tampered operation and budget violation.

**T07 commit gate:** Scoped review of schema, persisted plan/authorization cross-checks, negative admission tests and journal-denial behavior complete; commit reference: the commit containing this checkpoint.

**T07 verification:** `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_red_admission.py` (31 passed). `services/red_admission.py` rechecks persisted scope, newest approved plan, registered candidate/test/method/parameters, exact canonical URL, pinned private Docker-lab IP set, no redirects, and the Standard budget snapshot. Policy outcomes are journaled under the trusted assessment scope. **T07 is pre-dispatch only:** it does not execute a tool, reserve budgets atomically, or add an effectful API; binding it to runtime dispatch remains for later tasks.

### T08: Protect state-changing Red API operations

- [x] **T08 fully implemented and verified**

**Outcome:** Extend existing FastAPI console protections for explicit operator authorization, CSRF/anti-replay and validated command semantics.
**Depends on:** T05,T07. **Size:** M. **Likely touched:** `dashboard/api/console.py; schemas/red_team.py; tests/test_red_api_security.py`.

**Acceptance criteria:**
- [x] Effectful Red routes are authorized and protected against cross-origin/CSRF/duplicate submissions; same-origin alone is not used as permission.
- [x] No API accepts raw Docker flags, unrestricted network URLs, shell commands, arbitrary ZAP scripts or direct evidence filesystem paths.
- [x] Rejections have consistent machine-readable status and do not mutate queued work.
- [x] **Verification:** FastAPI TestClient tests: missing auth, wrong origin/CSRF, replay, malformed payload and legitimate operator request.

**T08 verification:** `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_red_api_security.py tests/test_red_admission.py tests/test_red_evidence_store.py tests/test_red_store.py tests/test_red_schema_contracts.py tests/test_red_policy.py tests/test_red_agent_contracts.py tests/test_red_team_mvp.py tests/test_policy_engine.py tests/test_registered_assessment_plan.py tests/test_controlled_executor.py tests/test_operator_console.py tests/test_docker_isolation_config.py tests/test_mars_red_preflight.py` (235 passed, one pre-existing Starlette/httpx warning). The only new effectful Red route persists operator *review intent* under authenticated, CSRF-checked, origin-bound, replay-rejected controls. No test dispatch, operator-approval grant, queue mutation, or network activity is enabled by T08. Commit reference: the commit containing this T08 checkpoint.

### Checkpoint B.8: release gate after T08

- [x] Policy admission and API protections pass.
- [x] Record passing command, output location and reviewer/commit reference.

**Checkpoint B.8 evidence:** T07's read-only admission scope/deny audit and T08's guarded review-intent API passed a combined 235-test focused regression suite; commit reference: the commit containing this checkpoint. No execution endpoints are enabled.

## Phase C: Docker-isolated ZAP reconnaissance

Introduce the scanner safely, then let the Recon Agent produce policy-classified endpoint candidates.

### T09: Add confined on-demand ZAP Compose job

- [x] **T09 fully implemented and verified**

**Outcome:** Prepare official version/digest-pinned ZAP behind isolated lab-network access, without starting unrestricted scans.
**Depends on:** T01,T03,T07. **Size:** M. **Likely touched:** `compose.yaml; config/zap/* (if needed); tests/test_zap_compose_policy.py`.

**Acceptance criteria:**
- [x] Scanner can reach only the explicitly registered Docker lab target with no host network, exposed public ZAP API, Docker socket or privileged mode.
- [x] CPU/memory/pid/time limits and a vetted image digest are recorded; lifecycle is on-demand, not permanently running.
- [x] Compose topology/isolation checks verify no unintended changes to existing lab services.
- [x] **Verification:** `docker compose config`; static isolation checks; controlled service startup/shutdown/health test only against the lab.

**T09 final verification:** Official ZAP 2.17.0 linux/amd64 image digest `sha256:0075662e5c287cf0a68caebabbfea872e5dc461912ad6d7345fa02a290d0ccb6` verified using `docker image inspect`. `docker compose -f compose.yaml -f compose.zap.yaml --profile zap config --quiet` passed; `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_zap_compose_policy.py` (7 passed). Runtime smoke test: `docker compose ... up -d --no-deps --no-build zap`, attached only the registered `fyp-vulnerable-store` to the temporary internal `fyp-red-blue-lab_zap-target` network, confirmed healthy ZAP preflight, membership exactly two containers, HTTP GET `http://vulnerable-store:8000/health` returned baseline health, public IP `1.1.1.1:80` TCP connect denied (errno 101), and read-only/unprivileged/PID limits verified. ZAP container and temporary network stopped and deleted; normal lab unchanged. No actual ZAP crawl, active scan, or public API was started.

### T10: Build bounded ZAP adapter

- [x] **T10 fully implemented and verified**

**Outcome:** Implement a narrow Python adapter for passive mapping and safe approved API actions rather than free-form scanner access.
**Depends on:** T07,T09. **Size:** M. **Likely touched:** `services/zap_adapter.py (new only if needed); schemas/red_team.py; tests/test_zap_adapter.py`.

**Acceptance criteria:**
- [x] Adapter accepts only registered target ID, documented limited operations and explicit request/depth/duration budgets.
- [x] Redirect/host constraints and ZAP API responses are independently validated; errors/timeouts are structured.
- [x] No external URLs, arbitrary scripting, broad active-scan configuration or shell execution are exposed.
- [x] **Verification:** Mock adapter tests for discovery, malformed output, timeouts, redirects and unapproved commands; lab-only smoke test.

**T10 partial verification:** `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_zap_adapter.py` (36 passed). Fixed allowlist: passive `core/view/urls` and single registered-GET `core/action/accessUrl` with `followRedirects=false`, Standard policy snapshot and duration/depth/request bounds, canonical target-origin checks and sanitized path-only observations. No generic scripts, scanner configuration, arbitrary URL, active spider or shell access. **Live ZAP 2.17.0 API smoke:** pinned container on internal lab only, authenticated API bound to container loopback with no published port, passive view returned empty before seeding; real registered GET /health via ZapAdapter.seed completed, and next passive view rejected an off-scope URL (fail-closed). Isolated ZAP container/network removed afterward. **No active scan.** Adapter remains an injected-transport pre-dispatch contract; runtime dispatcher integration and atomic counters are future gates.

### Checkpoint C.10: release gate after T10

- [x] ZAP isolation and narrow adapter pass.
- [x] Record passing command, output location and reviewer/commit reference.

**Checkpoint C.10 evidence:** T10 adapter mock tests and existing Red regressions; live ZAP 2.17.0 loopback-only preflight reached registered /health and rejected untrusted passive URLs; commit reference: the T10 commit containing this checkpoint.

### T11: Make Recon Agent produce endpoint candidates

- [x] **T11 fully implemented and verified**

**Outcome:** Wire approved ZAP crawling/passive observations into deterministic endpoint normalization/deduplication and policy classification.
**Depends on:** T04,T06,T10. **Size:** M. **Likely touched:** `agents/red/reconnaissance.py; services/reconnaissance_service.py; tests/test_red_recon_candidates.py`.

**Acceptance criteria:**
- [x] Agent outputs normalized method/path/parameter candidates with discovered/source timestamps, target identity and admission status.
- [x] New routes remain candidates until policy admits operations; protected/authentication-only areas generate coverage limitations.
- [x] Deterministic reruns produce stable candidate identities and major-step events.
- [x] **Verification:** Unit test mixed ZAP observations/duplicates/unknown methods and real lab crawl candidate output.

**T11 verification:** `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_red_recon_candidates.py` (13 passed). Deterministic scoped candidate classification, SHA-256 identities, stable reruns, idempotent persistence across later observation timestamps, authentication and unsupported-route limitations, bounded registered GET seeding with preflight budget checks, forged-scope rejection, and append-only started/completed events. **Real Docker-lab verification:** pinned ZAP 2.17.0 inside the opt-in isolated network with authenticated container-loopback API; bounded registered GET observations of `/health` and `/documents` produced two candidate-only records, both persisted to a temporary assessment SQLite store with two durable Red journal events. ZAP container and temporary network were removed, original MARS services stayed healthy. No unrestricted spider, active scan, execution approval, or dispatch was enabled. Commit reference: the commit containing this T11 checkpoint.

### T12: Expose read-only reconnaissance preview

- [x] **T12 fully implemented and verified**

**Outcome:** Provide a server-backed way to inspect current endpoint candidates and unsupported/rejected routes before executing tests.
**Depends on:** T05,T06,T11. **Size:** S. **Likely touched:** `dashboard/api/console.py; schemas/red_team.py; tests/test_red_recon_api.py`.

**Acceptance criteria:**
- [x] Read-only API returns scoped candidates, source, method, policy status and limitations for one assessment.
- [x] A preview never creates an execution receipt or falsely reports a test as run.
- [x] Invalid assessment IDs or unauthorized evidence access are rejected.
- [x] **Verification:** API tests for populated/empty preview and no execution-side effects.

**T12 verification:** `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_red_recon_api.py tests/test_red_recon_candidates.py` (24 passed). The authenticated GET projects stored candidates through the frozen assessment method scope and target fingerprint, reports registered/unsupported status and limitations, labels itself `read_only_preview` with execution disabled, rejects missing/invalid credentials, untrusted origins, registry drift and malformed/unknown assessment IDs, opens existing SQLite state in read-only mode, does not create a missing database, and leaves existing SQLite bytes unchanged. The broader unaffected Red persistence/policy/recon regression passed 96 tests; 20 additional Red schema tests passed with one legacy TestClient case deselected because the installed Starlette 1.7.0 test client requires unavailable `httpx2`. Proof/output location: `tests/test_red_recon_api.py`, `tests/test_red_recon_candidates.py`, and this tracker entry. Review reference: parallel EngineeringSuite standards and T12-spec review on 2026-10-28, with required findings resolved. Commit reference: `development` HEAD with subject `feat(red): expose scoped reconnaissance preview (T12)`. No Docker or scanner was used.

### Checkpoint C.12: release gate after T12

- [x] Candidate discovery and no-execution preview pass.
- [x] Record passing command, output location and reviewer/commit reference.

## Phase D: Rule-based Attack Planning

Select all applicable bounded approved tests and preserve plan lineage without LLMs.

### T13: Convert registered tests to approved template descriptors

- [x] **T13 fully implemented and verified**

**Outcome:** Represent existing SQLi login, reflected XSS and path traversal tests as vetted, parameter-bound descriptors.
**Depends on:** T03,T04,T11. **Size:** M. **Likely touched:** `config/security_tests/; services/registered_assessment_plan.py; schemas/red_team.py; tests/test_red_templates.py`.

**Acceptance criteria:**
- [x] Existing three registered test IDs retain current meanings and have explicit target/path/method/parameter applicability, oracle and resource cost.
- [x] Templates may bind documented parameters but cannot introduce arbitrary payloads or commands.
- [x] Unknown classes and incompatible parameters are rejected or recorded as unsupported.
- [x] **Verification:** Template schema tests and compatibility tests against the three existing registered cases.

**T13 verification:** `tests/test_red_templates.py` validates the three trusted descriptors, rejects arbitrary payload/command fields and fails closed on unknown classes or incompatible endpoint parameters. The descriptor projection is read-only and does not dispatch a provider, HTTP request, scanner or shell operation.

### T14: Select all applicable approved tests within budget

- [x] **T14 fully implemented and verified**

**Outcome:** Implement deterministic rule matching of candidates to vetted templates, stable operation ordering and Standard cost accounting.
**Depends on:** T11,T13. **Size:** M. **Likely touched:** `agents/red/attack_planner.py; services/registered_assessment_plan.py; tests/test_red_planner_rules.py`.

**Acceptance criteria:**
- [x] Every applicable authorized template instance is selected until an explicit budget is reached; selection is reproducible without LLM calls.
- [x] Missing template, blocked scope and exhausted budget each produce a typed coverage gap and recommendation when relevant.
- [x] The planner cannot alter target scope, upgrade methods or invent a scanner/shell operation.
- [x] **Verification:** Fixture tests for all-applicable matching, stable ordering, budget edges, unmatched endpoints and LLM-stub raising.

**T14 verification:** `tests/test_red_planner_rules.py` proves stable all-applicable matching, Standard test/request/runtime cost accounting, typed recommendations for coverage gaps, exact scope/method/class preservation and a provider-free deterministic planner.

### T15: Version plans and invalidate dependent work

- [x] **T15 fully implemented and verified**

**Outcome:** Ensure reconnaissance reruns create a new surface revision, mark previously dependent plans stale and block execution until replanning.
**Depends on:** T05,T07,T14. **Size:** M. **Likely touched:** `orchestrator/red_team_flow.py; persistence layer; tests/test_red_plan_staleness.py`.

**Acceptance criteria:**
- [x] New surface snapshot invalidates dependent execution eligibility, not historical evidence.
- [x] Stale-plan execution is denied in both manual and autonomous paths; prior version remains viewable.
- [x] New approved plan has an immutable digest including scope, candidates and templates.
- [x] **Verification:** State/DB tests for rerun Recon → stale old plan → denied execution → refreshed plan accepted.

**T15 verification:** `tests/test_red_plan_staleness.py` records immutable surface revisions, stales and blocks dependent unrun work, denies the old plan through the existing trusted admission gate in Manual and Autonomous modes, preserves plan history and admits a newly digested plan.

### Checkpoint D.15: release gate after T15

- [x] Template selection, budget gaps and stale-plan tests pass.
- [x] Record passing command, output location and reviewer/commit reference.

**Checkpoint D.15 evidence:** `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_red_templates.py tests/test_red_planner_rules.py tests/test_red_plan_staleness.py tests/test_red_recon_candidates.py tests/test_red_store.py tests/test_red_admission.py tests/test_red_evidence_store.py tests/test_red_schema_contracts.py tests/test_red_policy.py tests/test_red_agent_contracts.py tests/test_red_team_mvp.py::test_reconnaissance_and_planning_views_are_separate_and_narrow -k 'not fastapi_response_model_matches_expected_contract'` (118 passed, 1 deselected, one existing Starlette/httpx deprecation warning). Review basis: scoped T13-T15 diff, fail-closed planner/store/admission tests and no execution/provider path; commit reference: the commit containing this checkpoint.

## Phase E: Controlled execution and verification

Demonstrate real, bounded SQLi/XSS/path-traversal testing with reliable evidence.

### T16: Wire real controlled HTTP reproductions

- [x] **T16 fully implemented and verified**

**Outcome:** Adapt the existing controlled executor to accept policy-admitted operation references and return actual lab receipts.
**Depends on:** T07,T13,T15. **Size:** M. **Likely touched:** `services/controlled_executor.py; services/isolated_compose_executor.py; tests/test_red_real_execution.py`.

**Acceptance criteria:**
- [x] Existing SQLi/XSS/traversal registered reproductions invoke the real approved lab target, not previews or mock-only transport.
- [x] Operation returns actual method/target fingerprint, timing, evidence IDs and bounded error classification.
- [x] Attempts outside allowed identity, class, method or budget are blocked before network calls.
- [x] **Verification:** Focused real Docker smoke cases for three test IDs plus blocked-host negative test; unit coverage for errors.

**T16 verification:** `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_red_real_execution.py` (8 passed). The persisted-operation admission gate is rechecked immediately before the fixed registered executor and returns a bounded receipt containing the trusted target fingerprint, method, vulnerability class, timing, evidence IDs and structured error class. Identity, vulnerability-class, method, external-host and request-budget denials made zero transport calls. **Real Docker lab smoke:** the already-running healthy isolated `vulnerable-store` and `controlled-executor` services ran the fixed `run_verification_test` entry point for `sqli-login-bypass-001`, `xss-reflection-001` and `path-traversal-private-file-001`; all three completed with two requests and their expected deterministic evidence IDs. No preview, arbitrary URL, redirect, scanner, container reset or data reset was used.

### T17: Permit individually approved targeted ZAP tests

- [x] **T17 fully implemented and verified**

**Outcome:** Add explicit named ZAP targeted operations where they provide verified value for SQLi, XSS or traversal, no broad active scans.
**Depends on:** T07,T10,T14,T16. **Size:** M. **Likely touched:** `services/zap_adapter.py; services/controlled_executor.py; tests/test_red_zap_active.py`.

**Acceptance criteria:**
- [x] Only specific vetted scanner rule/endpoint/method combinations can run; agent-selected arbitrary ZAP rules are denied.
- [x] Any ZAP alert is stored as a suspected observation pending separate controlled verification.
- [x] Full-site active-scan flags and uncontrolled requests cannot be sent from the Red API or executor.
- [x] **Verification:** Mock/ZAP-lab tests for approved targeted operation, denied full scan and alert classification.

**T17 verification:** The only active operation is reflected-XSS rule `40012` against the registered GET search endpoint with recursion disabled. The opt-in ZAP network now resolves the target name only to a dedicated two-request proxy; the real target has no ZAP-network attachment, redirects are not followed, the gate must be fresh, and all ZAP/gate calls share the approved hard deadline. Generic rules, URLs, full-site flags, stale gates, zero-request scans and over-budget results fail closed. Alerts are append-only sanitized `suspected` observations and can never confirm a finding. `PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -q -p no:cacheprovider tests/test_red_zap_active.py tests/test_zap_request_gate.py` passed 10 tests; the broader E.18 command below covers the adapter and Compose policy as well. No unrestricted or external scan ran.

### T18: Restore clean target state when tests interfere

- [x] **T18 fully implemented and verified**

**Outcome:** Build safe, target-owned reset/recreate operations around existing trusted Compose controls and fingerprint verification.
**Depends on:** T03,T06,T09,T16. **Size:** M. **Likely touched:** `services/isolated_compose_executor.py; compose.yaml; tests/test_red_reset.py`.

**Acceptance criteria:**
- [x] Before interfering tests, the orchestrator can establish a known clean disposable state; restart alone is not assumed to clear persistent data.
- [x] Evidence is committed before reset, and reset cannot affect unrelated projects/volumes.
- [x] Unknown clean-state outcomes block further sensitive operations or mark them inconclusive.
- [x] **Verification:** Integration test for state mutation → reset → baseline state restored; unrelated container untouched.

**T18 verification:** The reset gate first validates hash-bound execution evidence and exact Git, daemon, image, project, network, container and volume ownership. It writes an append-only intent before mutation, dispatches only to the already inspected application container ID, recreates the target-owned SQLite schema and file trees, checks the complete expected SQLite object/row and file manifest, runs the fixed functional suite, and rechecks Docker identity. Any unknown result is durably recorded as `inconclusive` and blocks replay. Focused offline tests (including an unexpected table and files) passed 50 cases. **Real Docker lab check:** one synthetic product row changed the persisted count from 3 to 4; the fixed target reset returned it to 3, removed the row, and all eight functional checks passed. Before/after inventory contained the same two healthy project container IDs (`15c734300bc0`, `7cffcc6cbcd5`); no unrelated live container existed to snapshot, while the implementation and injected-runner tests prove the mutating command can name only the admitted application container ID and never a project, volume, teardown or prune action.

### Checkpoint E.18: release gate after T18

- [x] Controlled execution, ZAP targeting and state reset pass.
- [x] Record passing command, output location and reviewer/commit reference.

**Checkpoint E.18 evidence:** `PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -q -p no:cacheprovider tests/test_red_real_execution.py tests/test_red_zap_active.py tests/test_zap_adapter.py tests/test_zap_compose_policy.py tests/test_zap_request_gate.py tests/test_red_target_reset.py tests/test_isolated_compose_executor.py dummy_apps/vulnerable_store/tests/test_baseline.py::test_reset_restores_known_database_state tests/test_red_templates.py tests/test_red_planner_rules.py tests/test_red_plan_staleness.py tests/test_red_recon_candidates.py tests/test_red_store.py tests/test_red_admission.py tests/test_red_evidence_store.py tests/test_red_schema_contracts.py tests/test_red_policy.py tests/test_red_agent_contracts.py tests/test_red_team_mvp.py::test_reconnaissance_and_planning_views_are_separate_and_narrow -k 'not fastapi_response_model_matches_expected_contract'` passed 252 tests with 1 deselected and one existing Starlette/httpx deprecation warning. A final post-review T17 run passed 10 tests; Ruff and `git diff --check` passed. EngineeringSuite security/code review found no remaining T18 issue and its final T17 deadline/zero-request findings were fixed and re-tested. Commit reference: the commit containing this checkpoint.

### T19: Capture and normalize actual evidence receipts

- [x] **T19 fully implemented and verified**

**Outcome:** Persist independently identifiable HTTP and ZAP observations with hashes and reliable provenance, without secrets.
**Depends on:** T06,T16,T17. **Size:** M. **Likely touched:** `services/controlled_executor.py; evidence store; tests/test_red_evidence_receipts.py`.

**Acceptance criteria:**
- [x] Receipts link execution operation, plan revision, test case, target revision, runtime timestamp and hashed bounded raw response.
- [x] ZAP alerts and controlled reproduction are separate source types; a scanner alert cannot become a confirmed finding through serialization.
- [x] Failures, timeouts and cancellations retain immutable partial receipts and redacted summaries.
- [x] **Verification:** Tests verify integrity mismatch detection, source type and secrecy; replay one real lab receipt.

**T19 verification:** Admitted controlled HTTP execution now records an atomic, secret-free receipt and evidence artifact; ZAP records explicit suspected/not-observed observations; partial outcomes remain durable. Focused tests and the opt-in live Docker receipt replay passed.

### T20: Independently verify supported vulnerabilities

- [x] **T20 fully implemented and verified**

**Outcome:** Implement explicit deterministic result oracles for SQLi, reflected XSS and path traversal against actual reproducible receipts.
**Depends on:** T13,T16,T19. **Size:** M. **Likely touched:** `agents/red/attack_verifier.py; schemas/red_team.py; tests/test_red_verification.py`.

**Acceptance criteria:**
- [x] Confirmed requires independently validated matching evidence from an approved controlled reproduction; another scanner is not mandatory.
- [x] False positive, timeout, unsupported oracle and only-ZAP-alert paths yield not_confirmed/suspected/inconclusive accurately.
- [x] Finding includes severity, category, route, provenance, reproduction scope and verifiable evidence reference.
- [x] **Verification:** Positive and negative fixture tests for each class; no evidence → never confirmed; run real lab replay.

**T20 verification:** Verification requires a persisted approved operation, receipt, intact evidence artifact, exact registered exchange sequence and matching raw-result hash before a trusted deterministic oracle can confirm SQLi, XSS or traversal. Scanner-only alerts remain suspected and no-alert observations are inconclusive. Positive, negative, tamper, unsupported, timeout and live-replay tests passed.

### T21: Calculate truthful assessment coverage and completion

- [x] **T21 fully implemented and verified**

**Outcome:** Aggregate per-test and per-candidate results into verified findings, suspect observations, untested gaps and workflow completion.
**Depends on:** T14,T18,T20. **Size:** M. **Likely touched:** `services/red_assessment_summary.py (if necessary); schemas/red_team.py; tests/test_red_coverage.py`.

**Acceptance criteria:**
- [x] Eligible approved test instance denominator, completed/blocked/skipped and observed-uncovered counts are computed and explicit.
- [x] Each confirmed finding automatically creates one durable, idempotent pending-handoff record for future Blue Team use; no Blue worker executes.
- [x] `completed_with_limitations` is used when material untested/uncertain coverage remains; no zero-finding = safe inference.
- [x] Warnings about unauthenticated-only coverage and unsupported vulnerability classes are visible in summary data.
- [x] **Verification:** Fixture tests for full/partial coverage, budget cutoff, unsupported route and mixed confirmed/suspected/failed outcomes.

**T21 verification:** Coverage and completion are derived from the canonical persisted candidates, operations, receipts, findings and durable coverage gaps. Confirmed findings create idempotent data-only pending handoffs; no Blue worker runs. Full, partial, budget, unsupported, blocked and mixed-outcome fixtures passed.

### Checkpoint E.21: release gate after T21

- [x] Independent evidence verification and coverage rollup pass.
- [x] Record passing command, output location and reviewer/commit reference.

**Checkpoint E.21 evidence:** `PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -q -p no:cacheprovider tests/test_red_evidence_receipts.py tests/test_red_verification.py tests/test_red_coverage.py tests/test_red_evidence_store.py -k 'not fastapi_response_model_matches_expected_contract'` passed 31 tests. The broader Red regression passed 276 tests with 1 deselected and one existing Starlette/httpx deprecation warning; the opt-in live Docker receipt replay passed 1 test. Ruff, `docker compose config -q`, `git diff --check`, registered live SQLi/XSS/traversal checks and all 8 controlled-executor functional checks passed. EngineeringSuite security and correctness review found no remaining actionable defect. Commit reference: the commit containing this checkpoint.

## Phase F: Central Orchestrator and mode execution

Coordinate Manual and Autonomous assessments, scheduling, cancellation and recovery.

### T22: Build the Central Orchestrator stage state machine

- [x] **T22 fully implemented and verified**

**Outcome:** Evolve existing red_team_flow into model-free manager with trusted stages and one durable per-assessment source of truth.
**Depends on:** T04,T06,T15,T21. **Size:** M. **Likely touched:** `orchestrator/red_team_flow.py; schemas/red_team.py; tests/test_red_orchestrator_states.py`.

**Acceptance criteria:**
- [x] Only legal transitions dispatch agents; every transition has a typed event and persists before/after a worker operation.
- [x] Manual stage independence and autonomous dependency order share the same agent implementation/policy.
- [x] Restarting the coordinator does not imply successful completion of interrupted work.
- [x] **Verification:** State-machine tests for normal path, blocked prerequisites, restart and unexpected stage errors.

**T22 verification:** `RedStageCoordinator` dispatches the four typed model-free workers through one prerequisite policy for Manual and Autonomous modes. Stage state and typed events commit atomically in the assessment SQLite database; the transition transaction rechecks the assessment is running. A successful stage requires its canonical surface, plan/operations/gaps, receipt/evidence or finding/gap output to be durable and scope-bound. Simulated interruption remains `running` after coordinator restart and cannot be redispatched as success. Nine focused state-machine tests, the 75-test persistence/contract regression, and the 285-test broad Red regression passed with 1 deselected test and one existing Starlette/httpx deprecation warning. Ruff and `git diff --check` passed; EngineeringSuite review found no remaining actionable defect.

### T23: Add simple resource-aware assessment queue

- [x] **T23 fully implemented and verified**

**Outcome:** Use existing Python/SQLite facilities to serialize heavy Docker work and support queued assessments without additional message brokers.
**Depends on:** T05,T09,T22. **Size:** M. **Likely touched:** `orchestrator/red_team_flow.py; persistence layer; tests/test_red_queue.py`.

**Acceptance criteria:**
- [x] Two assessments cannot run conflicting operations on one target instance simultaneously; heavy ZAP jobs obey resource budget.
- [x] Queue order, statuses and requests survive process restarts where feasible without double execution.
- [x] No Celery, Redis or new scheduler service is added for a single-machine lab without demonstrated need.
- [x] **Verification:** Queue concurrency tests with two jobs; kill/restart worker test; inspect CPU/memory bounds in Docker smoke.

**T23 verification:** `PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -q -p no:cacheprovider tests/test_red_queue.py tests/test_red_orchestrator_states.py` passed 22 tests. SQLite `BEGIN IMMEDIATE` claims preserve FIFO order and one durable lease, serialize heavy work per target, bind denormalized columns to typed payloads, retain interrupted leases without silent redelivery, and enforce frozen per-job plus aggregate HTTP/runtime/ZAP crawl budgets. A 163-test model-free Red regression passed with one pre-existing Starlette/httpx warning. Ruff, both base and ZAP-profile Compose validation, and `git diff --check` passed. Docker inspection confirmed existing controlled-executor limits of 0.25 CPU/128 MiB, vulnerable-store limits of 0.5 CPU/256 MiB, and rendered ZAP limits of 0.5 CPU/512 MiB; the existing lab containers were stopped, so they were not restarted because the vulnerable-store entrypoint resets scenario data. No broker, scanner, container execution, recovery policy or T24 behavior was added.

### Checkpoint F.23: release gate after T23

- [x] Orchestrator and scheduling tests pass.
- [x] Record passing command, output location and reviewer/commit reference.

**Checkpoint F.23 evidence:** Queue/orchestrator output is recorded in `tests/test_red_queue.py` and `tests/test_red_orchestrator_states.py` (22 passed); the broader regression passed 163 tests. EngineeringSuite TDD, Ponytail, security and code-review findings were resolved, including fail-closed persisted-row provenance and aggregate ZAP crawl-budget enforcement. Commit reference: the commit containing this checkpoint.

### T24: Implement prompt cancellation and safe recovery

- [ ] **T24 fully implemented and verified**

**Outcome:** Stop scheduling on cancellation; manage bounded idempotent retries, unknown outcomes and preserved evidence.
**Depends on:** T06,T18,T22,T23. **Size:** M. **Likely touched:** `orchestrator/red_team_flow.py; services/controlled_executor.py; tests/test_red_cancel_retry.py`.

**Acceptance criteria:**
- [ ] Stop revokes pending tasks, requests in-flight cancellation and records honest completed/interrupted operation state.
- [ ] Only safe retryable operations are repeated within a configured limit; uncertain active attack status becomes inconclusive.
- [ ] Previously captured evidence and plan history remain retrievable after cancel/fail/restart.
- [ ] **Verification:** Tests cancel before start, during ZAP/HTTP action, duplicate cancel, timeout and post-restart recovery.

### T25: Implement authorized Manual and Autonomous dispatch

- [ ] **T25 fully implemented and verified**

**Outcome:** Use one approved assessment snapshot to run either user-selected stages or sequential autonomous Red operations.
**Depends on:** T07,T15,T22,T23,T24. **Size:** M. **Likely touched:** `orchestrator/red_team_flow.py; tests/test_red_modes.py; existing API controller seam`.

**Acceptance criteria:**
- [ ] Autonomous requires explicit operator authorization once per target/scope/profile and completes within that authorization.
- [ ] Manual executes individual stages only when prerequisites are current, preserving independent reruns and old plans.
- [ ] Mode is immutable while assessment nonterminal; cancellation remains available and no page-load auto-execution exists.
- [ ] **Verification:** One complete lab assessment in each mode and negative tests for no authorization, stale plan and mid-run mode change.

### Checkpoint F.25: release gate after T25

- [ ] Safe stop/recovery and both modes pass.
- [ ] Record passing command, output location and reviewer/commit reference.

## Phase G: FastAPI and React assessment experience

Build server-backed dashboard, controls, timeline and findings without inventing data.

### T26: Expose Red read APIs for dashboard and workspaces

- [ ] **T26 fully implemented and verified**

**Outcome:** Provide stable, typed, paginated target/summary/assessment/events/findings/coverage reads using existing console conventions.
**Depends on:** T05,T06,T21,T22. **Size:** M. **Likely touched:** `dashboard/api/console.py; schemas/red_team.py; tests/test_red_read_api.py`.

**Acceptance criteria:**
- [ ] Global and selected-target filters agree across counts, findings, assessment index and history.
- [ ] Event responses summarize major worker steps rather than full technical trace or secrets.
- [ ] Empty/loading/failed data have predictable response semantics and preview-only results cannot appear as executed.
- [ ] **Verification:** TestClient tests for filters, pagination, nonexistent ID, no findings, stale plan and cancellation state.

### T27: Expose Red write APIs for authorized commands

- [ ] **T27 fully implemented and verified**

**Outcome:** Add create draft, authorize/start, manual stage run/rerun and cancel endpoints atop the trusted supervisor.
**Depends on:** T08,T25,T26. **Size:** M. **Likely touched:** `dashboard/api/console.py; schemas/red_team.py; tests/test_red_write_api.py`.

**Acceptance criteria:**
- [ ] Server validates operator identity/CSRF/idempotency, immutable authorization and legal stage prerequisites on every call.
- [ ] Creating a draft cannot execute; duplicate start/manual/cancel requests cannot repeat active attacks.
- [ ] HTTP conflicts/errors explain locked mode, stale plan, budget exhaustion or blocked operation without side effects.
- [ ] **Verification:** API integration tests for full draft→authorize→start and manual commands, plus CSRF, replay and forged scope.

### Checkpoint G.27: release gate after T27

- [ ] Read/write APIs including authorization tests pass.
- [ ] Record passing command, output location and reviewer/commit reference.

### T28: Build dashboard metrics and assessment index

- [ ] **T28 fully implemented and verified**

**Outcome:** Replace Red placeholder with a dashboard showing four real metrics, target/status filters and assessment history.
**Depends on:** T26. **Size:** M. **Likely touched:** `dashboard/frontend/src/App.tsx or Red panel; dashboard/frontend/src/api.ts; dashboard/frontend/src/product.css; frontend tests`.

**Acceptance criteria:**
- [ ] Four primary metrics are verified findings, tested/eligible endpoints, active/queued assessments and agent health/activity.
- [ ] All Targets / Selected Target and status filters update metrics, findings totals and history consistently.
- [ ] Existing theme, navigation, empty states and real backend data are preserved; no fake counters.
- [ ] **Verification:** `cd dashboard/frontend && npm test && npm run build`; browser dark/light/mobile dashboard review.

### T29: Build New Assessment and remembered mode selection

- [ ] **T29 fully implemented and verified**

**Outcome:** Add deliberate assessment creation with target, Standard budget summary, scope review, operator authorization and mode preference.
**Depends on:** T27,T28. **Size:** M. **Likely touched:** `dashboard/frontend/src/App.tsx or Red assessment form; dashboard/frontend/src/api.ts; frontend tests`.

**Acceptance criteria:**
- [ ] Manual/Autonomous preference is remembered but no assessment starts on selection or page load.
- [ ] New Assessment explicitly authorizes fixed target/classes/budgets before start, and mode is locked during the active run.
- [ ] Error or rejected authorization returns clear feedback; stop/cancel remains accessible.
- [ ] **Verification:** Frontend tests for remembered mode and lock; browser confirm no network execution before explicit approval.

### T30: Build four Manual agent control panels

- [ ] **T30 fully implemented and verified**

**Outcome:** Render compact Recon, Plan, Execute and Verify worker cards, server-authoritative statuses and safe Run/Rerun/Inspect.
**Depends on:** T27,T29. **Size:** M. **Likely touched:** `dashboard/frontend/src/App.tsx or Red agent cards; dashboard/frontend/src/api.ts; frontend tests`.

**Acceptance criteria:**
- [ ] Each card displays current status, last action, task count, failure state and independently valid manual controls.
- [ ] Invalid stage action is disabled with explanation; rerun recon makes old plan visibly stale.
- [ ] Inspect opens existing stage history without leaking raw payloads or requiring LLM data.
- [ ] **Verification:** Frontend state tests and browser run of each eligible manual stage including stale-plan block.

### Checkpoint G.30: release gate after T30

- [ ] Dashboard, creation and manual panels usable.
- [ ] Record passing command, output location and reviewer/commit reference.

### T31: Build Autonomous live assessment timeline

- [ ] **T31 fully implemented and verified**

**Outcome:** Make selected assessments open a dedicated workspace with current stage, progress, major events and a usable Stop action.
**Depends on:** T26,T27,T29. **Size:** M. **Likely touched:** `dashboard/frontend/src/App.tsx or Red workspace; dashboard/frontend/src/api.ts; frontend tests`.

**Acceptance criteria:**
- [ ] One Red dashboard stays navigable while different assessment detail workspaces are available.
- [ ] Timeline displays major stage actions, timestamps and statuses via bounded polling; mode selector stays locked until terminal.
- [ ] Cancel/failed/blocked/queued states render accurately without fake progress or unbounded polling.
- [ ] **Verification:** Frontend tests for polling/mode-lock/stop and browser live assessment with queued and terminal paths.

### T32: Add findings table and evidence detail panel

- [ ] **T32 fully implemented and verified**

**Outcome:** Show verification outcomes, severity/category/target, a detail inspector, coverage gaps and Reports/Blue-handoff placeholders only where real data exists.
**Depends on:** T20,T21,T26,T31. **Size:** M. **Likely touched:** `dashboard/frontend/src/App.tsx or Red finding components; dashboard/frontend/src/api.ts; frontend tests`.

**Acceptance criteria:**
- [ ] Findings table differentiates confirmed, suspected, not confirmed and inconclusive; gaps are disclosed separately.
- [ ] Clicking a finding opens validated evidence/provenance and reproduction/coverage context; no raw secrets or harmful HTML injection.
- [ ] Full export links to existing Reports only if implemented; future Blue handoff is labeled pending and performs no Blue workflow.
- [ ] **Verification:** Frontend tests for filters/evidence and escaping; browser inspect confirmed/suspected/gap result states.

### T33: Polish accessibility, errors and responsive behavior

- [ ] **T33 fully implemented and verified**

**Outcome:** Finish real UX states without creating a new design system or extra dependencies.
**Depends on:** T28,T29,T30,T31,T32. **Size:** M. **Likely touched:** `dashboard/frontend/src/product.css; Red components; frontend tests`.

**Acceptance criteria:**
- [ ] Keyboard access, focus, disabled explanations, contrast and readable table/controls work across dark/light themes.
- [ ] Loading, empty, offline, blocked, timeout and cancelled states are distinct and honest.
- [ ] Mobile/narrow layouts retain critical stop, authorization and agent controls.
- [ ] **Verification:** Run frontend tests/build; browser manual review at desktop/tablet/mobile in both themes.

### Checkpoint G.33: release gate after T33

- [ ] Autonomous timeline, findings, responsive/accessibility checks pass.
- [ ] Record passing command, output location and reviewer/commit reference.

## Phase H: End-to-end acceptance and handoff

Prove functionality, security and reproducibility; finish runbook and research reporting.

### T34: Prove true end-to-end SQLi/XSS/traversal workflow

- [ ] **T34 fully implemented and verified**

**Outcome:** Perform controlled tests on the authorized Docker lab and compare observations, plan, execution and independent verification across Manual and Autonomous flows.
**Depends on:** T25,T27,T32. **Size:** M. **Likely touched:** `tests/integration/ (or existing end-to-end directory); fixtures; test documentation`.

**Acceptance criteria:**
- [ ] The three registered classes produce reproducible actual Docker evidence and appropriate findings, not mocked execution claims.
- [ ] One Manual stage rerun and one Autonomous assessment prove stable plans, timeline, queue and stop behavior.
- [ ] Suspected-only observations, unavailable authenticated routes and missing-template gaps are correctly reported.
- [ ] **Verification:** Run focused Python integration suite and frontend build; inspect evidence receipts/target hashes in exported fixture.

### T35: Run adversarial security and operational regression

- [ ] **T35 fully implemented and verified**

**Outcome:** Exercise denial paths and cleanup to prove autonomy stays within allowed execution authority.
**Depends on:** T34. **Size:** M. **Likely touched:** `security tests; compose policy tests; API tests; test runbook`.

**Acceptance criteria:**
- [ ] Out-of-scope host/redirect/method/test, forged request, stale plan, unapproved ZAP scan and Docker privilege attempts are rejected.
- [ ] Interrupt/restart, exhaustion and state restore do not delete evidence, double-execute or touch unrelated containers.
- [ ] All applicable Python/React tests and Compose configuration validation pass with results recorded.
- [ ] **Verification:** Execute negative-path CI commands, `docker compose config`, targeted permission tests and a bounded cancel/restart lab exercise.

### T36: Finalize documentation, reproducibility and review

- [ ] **T36 fully implemented and verified**

**Outcome:** Produce operator runbook, acceptance report and FYP-ready model-free agent explanation; prepare merge only after approval.
**Depends on:** T34,T35. **Size:** S. **Likely touched:** `docs/RED_TEAM_RUNBOOK.md (new); tasks/plan.md; tasks/todo.md; existing project docs`.

**Acceptance criteria:**
- [ ] Runbook documents isolated startup/shutdown, Standard budgets, target limitations, approvals, reset, ZAP version, privacy and troubleshooting.
- [ ] Assessment demo records actual metrics (coverage, confirmed/suspected/gaps, agent tasks, duration and tool invocations) without invented values.
- [ ] Checkpoint list is complete, old research artifacts unchanged, review diff and test output available; Git push only under separate implementation authorization.
- [ ] **Verification:** Independent reviewer can follow runbook to reproduce permitted SQLi/XSS/traversal flow and audit evidence; `git diff --check`, status and test logs.

### Checkpoint H.36: release gate after T36

- [ ] End-to-end evidence, adversarial safety and runbook complete.
- [ ] Record passing command, output location and reviewer/commit reference.

## Final release acceptance (do not mark until proven)

- [ ] No Red Team LLM/model provider call is required in Manual or Autonomous execution.
- [ ] One orchestrated workflow uses four independent deterministic workers and trusted policy enforcement.
- [ ] OWASP ZAP is Docker-isolated, scoped, on demand and supports only approved actions.
- [ ] Three supported classes are demonstrated with real lab evidence and independent verification.
- [ ] Agent planning is all-applicable within bounded Standard profile and records coverage gaps.
- [ ] Manual mode supports each stage, stale-plan blocking and preserved history.
- [ ] Autonomous mode respects explicit authorization, fixed mode per run and cancellation.
- [ ] Red dashboard, live workspace, findings panel and truthful metrics work in both themes and on mobile.
- [ ] Scope-bypass, SSRF/redirect, CSRF/replay, bad tool input, wrong Docker project and reset negative tests pass.
- [ ] Blue Team execution, imported application UI, authenticated crawling, extra classes and other deferred work are not accidentally included.
- [ ] Final acceptance and reviewer signoff before calling the release implemented.
