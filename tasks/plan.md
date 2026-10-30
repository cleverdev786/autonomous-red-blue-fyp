# MARS Red Team | Final implementation plan

**Decision baseline:** 2026-10-26, rounds 1–10 including Q51–Q54.  
**Implementation status:** T01–T36 implemented, verified and committed on `development`; push is handed off to the repository owner.
**Primary tracker:** [`tasks/todo.md`](todo.md). Check tasks in order, including the checkpoint gates.  
**Supersedes:** the preliminary Red Team plan committed as `c03b0de`. Task-level implementation and evidence are recorded in `tasks/todo.md`; operating instructions and measured acceptance results are in `docs/RED_TEAM_RUNBOOK.md` and `docs/RED_TEAM_ACCEPTANCE_REPORT.md`.

## 1. Objective and release boundary

Deliver a **model-free, rule-based, four-agent Red Team** operated through the existing MARS React/FastAPI dashboard, coordinated by **one Central Orchestrator**, and demonstrated against the **existing authorized Docker vulnerable-store lab**. Deliver a complete Manual and Autonomous assessment journey, actual ZAP-assisted discovery, approved targeted security checks, independent confirmation, truthful coverage reporting and preserved evidence. Support SQL injection (SQLi), reflected XSS and path/directory traversal **only** in this release.

**Acceptance principle:** A finished workflow is not a declaration of application safety. Every confirmed vulnerability requires an allowed controlled reproduction plus independent deterministic evidence validation. Every unsupported eligible candidate becomes a recorded coverage gap, not a pass.

### In scope now

- Four independent, role-specific Python agents: Reconnaissance, Attack Planning, Controlled Test Execution, Attack Verification.
- One Python Central Orchestrator as an assessment supervisor: policy, lifecycle, dependency graph, resource-aware queue, event history, cancellation and safe recovery. Red implementation only; a later Blue Team can connect through structured records.
- Existing Docker lab as the sole enabled target initially. Design target identifiers and authorization boundaries generically but **do not implement user target import or generic Docker management**.
- OWASP ZAP in a confined, on-demand **Red Team Docker tool container**, for scope-limited crawling/passive observations and explicitly approved targeted testing; existing Python HTTP/controlled executor for reproducible checks.
- Three vulnerability categories, approved adaptable templates, all applicable permitted tests within the **Standard** resource budget, and coverage gaps for missing, blocked or exhausted checks.
- Persistent, versioned assessment state, plan provenance, agent activity, evidence receipts and findings. Candidate endpoint versus approved operation versus verified finding are distinct concepts.
- Dashboard-first UI; global/selected-target filtering; four metrics; four compact manual agent panels; dedicated live autonomous assessment workspace with major-step timeline; a findings table with detail panel.
- Permission to execute is per assessment and fixes target, attack classes, allowed methods and budgets; Autonomous stays automatic **only within that prior authorization**.

### Explicitly deferred / excluded

- LLMs, model providers, structured generation calls, ML decision engines or model-backed agent judgement for Red Team.
- Blue Team work: ModSecurity/OWASP CRS, Semgrep, patch generation, deployment, fix verification, and Blue Team UI. Red Team may produce an automatically created, durable **pending handoff record**, but does not run Blue operations.
- Importing the user's Docker Compose application through UI; supporting arbitrary repositories, source-to-container automation, additional target catalogues in the release UI.
- Authenticated crawling, credentials management, state-changing discovery unless a later policy explicitly enables it; more vulnerability classes.
- Other scanners, general-purpose attack frameworks, arbitrary agent shell commands, Docker socket exposure, permanent ZAP daemon, multiple LLMs, Celery/Kubernetes/microservices, extra testing-intensity profiles, speculative agent scoring.
- Modifying original FYP research artefacts or old empirical/evaluation records.

## 2. Existing repository foundations to reuse (last inspected 2026-10-26)

These paths describe the previously inspected `development` branch, not claims about a live inspection in this session:

| Existing component | Reuse or corrective action |
| --- | --- |
| `agents/red/reconnaissance.py`, `attack_planner.py`, `attack_verifier.py` | Keep agent boundaries; replace/disable LLM-dependent decisions on the required path; avoid duplicate agents. |
| `orchestrator/red_team_flow.py`, `orchestrator/policy_engine.py` | Reuse orchestration entry point/policy concepts; evolve to a durable, rule-based supervisor rather than adding another application. |
| `services/reconnaissance_service.py`, `controlled_executor.py`, `isolated_compose_executor.py` | Reuse bounded HTTP, registered test and isolated execution mechanisms. Audit their real-versus-preview semantics before extending. |
| `services/registered_assessment_plan.py` | Read-only preview explicitly has `execution_enabled=False`; preserve truthful labeling, never mistake it for an executed run. |
| `schemas/red_team.py` | Extend typed records and validation instead of parallel payload schemas. |
| `config/targets/vulnerable-store.json`, `config/security_tests/` | Initial scope and three existing registered tests: `sqli-login-bypass-001`, `xss-reflection-001`, `path-traversal-private-file-001`. |
| `compose.yaml` and existing lab image | Existing isolated target and controlled executor foundation. Extend minimally for a tightly confined ZAP job. |
| `dashboard/api/console.py` | Existing FastAPI API, local-origin protection and assessment read paths. Add authorization for effectful operations; local-origin check alone is not sufficient. |
| `dashboard/frontend/src/App.tsx`, `routes.ts`, `api.ts`, `product.css` | Replace Red Team placeholder using current MARS theme, routing and client conventions. No separate UI system. |
| Existing SQLite/FastAPI/Pydantic/httpx/pytest/React dependencies | Prefer these before adding dependencies; stdlib for bounded task scheduling where sufficient. |

**Nonnegotiable first step:** reconcile this inventory against the current working tree and tests. Preserve user changes. Do not remove prior safety gates or fake an execution through the read-only plan endpoint.

## 3. Architecture and responsibility contracts

```text
MARS React UI
  Dashboard / assessment index / four worker panels / live workspace
                |
        FastAPI Red API (auth + validated input)
                |
     CENTRAL ORCHESTRATOR [Python, shared MARS service]
     - authorize assessment snapshot (target/methods/classes/budget)
     - queue, journal, transitions, retries, stop, evidence IDs
     - validate work proposed by agents; never accept tool output as policy
                |
    +-----------+-------------+----------------+---------------+
    |                         |                |               |
  Recon Agent             Planning Agent   Execution Agent   Verification Agent
  ZAP safe mapping        deterministic    controlled HTTP   deterministic
  policy-aware            rule/template    + approved ZAP    evidence validators
  endpoint candidates     matching         operations        and results
    +-----------+-------------+----------------+---------------+
                |
      SQLite records + protected evidence store
      candidates / plans / actions / results / gaps / event timeline
                |
     pending Blue handoff descriptor (data contract ONLY, later)

Isolation: authorized vulnerable-store container <-> allowlisted scanner/executor
No Docker socket, privileged mode, host network or external target access for agents.
```

### Agent interfaces, distinct authorities

- **Recon Agent:** input `assessment_scope`, `target_fingerprint`, budget; selects approved ZAP discovery operations; output deduplicated `EndpointCandidate` records (`method`, normalized path, observed params, source, timestamp, candidate policy decision). Discovery does not authorize execution.
- **Planning Agent:** input approved candidates, test-template catalogue, prior attempt state, remaining budget; deterministically evaluates applicability, produces **all eligible** registered/approved test instances, a plan version and `CoverageGap` records. Endpoint and method decisions are rechecked by a separate execution authority. No free-form commands or payload generation.
- **Execution Agent:** accepts only a **trusted-server-validated** `ApprovedOperation` reference against an immutable authorization snapshot; chooses an allowlisted adapter (`controlled_http`, approved targeted ZAP operation); returns receipts and bounded raw evidence. No arbitrary tool arguments, network destinations, or shell.
- **Verification Agent:** examines the approved operation, target revision, response/test evidence and predefined oracle; produces `confirmed`, `not_confirmed`, `suspected`, `inconclusive`, or `not_tested` as appropriate. A ZAP alert alone is **suspected**, not confirmed. Reproducible positive controlled evidence meeting a separate deterministic oracle can be confirmed; independent does not mean a second scanner is mandatory.
- **Central Orchestrator:** owns permissions, consistency, state transitions, idempotency, scheduling and journal. It is a deterministic manager, **not an LLM agent** or a replacement for specialized workers. A rejected operation is a policy event, not a failed exploit.

### Typed persisted core concepts

`TargetRegistration` (existing lab only); `Assessment` (target, mode, Standard profile, authorization snapshot, target fingerprint, completion, coverage); `AgentStageRun`; `EndpointCandidate`; `PlanVersion`; `ApprovedOperation`; `ExecutionReceipt`; `EvidenceArtifact` (hash, provenance, content type, scope, access policy); `Finding`; `CoverageGap`; `TimelineEvent`; `PendingHandoff` (data only; created idempotently for each confirmed finding, never launches Blue).

Persist identifiers and linkages (`assessment_id`, `target_id`, `plan_version`, `operation_id`, `evidence_id`, target image/config fingerprint, timestamps). **Do not store raw secrets in the UI timeline.** External tools and model-like strings are untrusted input. Bind execution to the approved scope and current plan, not to frontend fields alone.

### Status taxonomy and correctness

- Assessment lifecycle: `created → awaiting_authorization → queued → running → completed | completed_with_limitations | failed | cancelled | blocked`. Include `pausing/stop_requested` internally if needed. `completed` means supported work finished; `completed_with_limitations` means material gaps/unresolved observations remain. Distinguish terminal from active states for UI mode lock.
- Stage: `not_started | ready | queued | running | succeeded | failed | blocked | cancelled | stale`. A rerun of Recon marks dependent plan versions **stale**; no stale plan may execute; the old plan and results remain audit history.
- Findings/evidence: separate `suspected`, `confirmed`, `not_confirmed`, `inconclusive` and `not_tested/coverage_gap`. Do not classify a test timeout as `not_confirmed`.
- Coverage: report explicit denominator `eligible approved test instances`, executed/completed/blocked/skipped counts and observed-candidate gaps. Do not count unsupported untested routes as passes. Method, authenticated-route and missing-template limitations are displayed truthfully.

### Manual and Autonomous behavior

- Both modes use **the same policy, agent implementations, job queue, findings and evidence**; only dispatch is different.
- **Manual:** four compact panels with `Run`, `Rerun`, `Inspect`. Each action runs the selected stage against its valid prerequisites. Recon may run independently; planning needs a current recon snapshot; execution needs a non-stale approved plan; verification needs existing compatible receipts. Disable invalid controls with a concise explanation.
- **Autonomous:** operator selects the authorized target, Standard profile and allowed SQLi/XSS/traversal scope and explicitly starts one assessment. Agents progress automatically **within approval**. Out-of-scope operations are blocked for review, never silently authorized. Use live timeline, stage status and stop action.
- Preferred mode is remembered in browser settings, **but never triggers an assessment on page load**. The mode selector is **locked while that assessment is active**, and unlocks only when it reaches a terminal state. Active assessment retains its originally captured mode. Stop/cancel action remains available regardless of the mode lock.
- Separate assessment workspaces coexist with dashboard index, status filtering and resource-aware scheduling. No two active destructive operations against one target instance. A queued assessment never silently modifies a currently running target.
- Stop scheduling promptly, revoke queue entries, request in-flight cancellation where technically possible, preserve all evidence and accurately distinguish interrupted from completed actions. Safe retries are bounded and idempotent; ambiguous outcomes remain inconclusive, **not auto-replayed**.

## 4. Docker, ZAP and verification rules

1. **Start from the existing Compose lab.** Register the current authorized target ID and specific service/network/host/port/method scope. Restrict runtime to approved Docker assets and project name. Do not take arbitrary Compose definitions from HTTP clients.
2. **ZAP integration:** use a vetted **digest-pinned** official ZAP container, resource limits, read-only/nonroot profile where feasible and an isolated lab-only network. No host networking, Docker socket, privileged operation, or unrestricted external egress. Prefer a short-lived job/profile; never leave an exposed, unauthenticated ZAP API on a reachable network. Add an allowlist/denylist for ZAP discovery and redirects, explicit budgets, and safe crawling behavior. Check image compatibility with the target's network before any live scans.
3. **Approved active ZAP tests:** if applicable to one of the three vulnerability classes, admit specific ZAP operations through the same target policy and run budget as Python tests. Do not blanket-enable ZAP's unrestricted active scanner or claim it is non-invasive. Keep ZAP alerts as observations until separately confirmed.
4. **Registered reproductions:** reuse the existing `controlled_executor.py`, registered test IDs and integrity checks to validate real, Docker-isolated HTTP behavior. Migrate to adaptable *vetted templates* with explicit parameter and method constraints only when the current tests support this safely. Avoid misleading preview/assessments or in-process mocks.
5. **State restore:** tests that interfere must run against a verified clean snapshot or recreated disposable target instance. `docker restart` alone does not reset persistent databases or volumes. Store evidence before restoring state. Never remove unrelated host containers/volumes.
6. **Scope enforcement:** normalize and revalidate host, IP, port, method, redirect destination and parameter for every tool operation. Refuse nonallowlisted destinations and fail closed on DNS rebinding or network redirection. No credentials/authenticated discovery in v1.
7. **Resources:** Standard profile as explicit configurable-but-bounded numbers for wall-clock, requests, tests, depth, CPU, memory, parallelism and retries. Numbers selected in code/config must be verified against actual laptop capacities; no hard-coded theoretical promises. Resource-aware queue can be a simple durable Python/SQLite worker, no Celery until load warrants it.

## 5. Backend/UI contract for first implementation

Contract names are a **proposed direction**, finalized in T05/T22 before implementation, not currently functioning endpoints:

| Endpoint | Purpose | Constraints |
| --- | --- | --- |
| `GET /api/red/targets` | Registered targets and compatibility/limitations | Existing approved Docker lab only |
| `GET /api/red/assessments?target_id=&status=` | Dashboard index and filtered history | Pagination, stable ordering |
| `GET /api/red/summary?target_id=` | Four primary metrics + coverage indicators | Same global/per-target filtering as findings |
| `POST /api/red/assessments` | Create a *draft* assessment | No execution on creation |
| `POST /api/red/assessments/{id}/authorize` | Record immutable scope and operator approval | Authentication/CSRF/anti-replay; state gate |
| `POST /api/red/assessments/{id}/start` | Enqueue authorized assessment | Idempotency key; captured mode |
| `POST /api/red/assessments/{id}/stages/{stage}/run` | Manual stage command | Same trusted policy; valid prerequisites |
| `POST /api/red/assessments/{id}/cancel` | Stop queue and request active cancellation | Honest termination state; no evidence deletion |
| `GET /api/red/assessments/{id}` | Stage status, coverage, plan version, summary | Server-authoritative states |
| `GET /api/red/assessments/{id}/events` | Major-step timeline; polling initially | No secrets/verbose payload dumps |
| `GET /api/red/assessments/{id}/findings` | Compact table, verification states, gap counts | Paginated/filterable |
| `GET /api/red/findings/{id}` | Detail, references, evidence metadata | Evidence access gated and sanitized |

**API rules:** Model-free server behavior, Pydantic at boundaries; explicit authorization snapshot; controlled payload shapes; anti-CSRF or equivalent operator authorization for effectful endpoints (origin alone is not enough); idempotency for start/cancel/run; no client-supplied shell or ZAP commands; safe report/evidence retrieval. Prefer simple event polling initially over sockets. No separate microservice per agent.

### User interface information architecture

```text
Red Team (/dashboard/red-team)
  Header: Red Team, target filter, remembered Manual | Autonomous mode (locked if active)
  Four top-level metrics: verified findings | endpoints tested/eligible |
                          active/queued assessments | agent health/activity
  Assessment list: target, mode, status, progress, last run, findings, limitations
  New Assessment: existing target -> Standard policy review -> explicit authorize/start
  Selected assessment workspace:
      [Recon] [Planning] [Execution] [Verification]  four compact worker cards
      Manual: per-card Run / Rerun / Inspect (with prerequisites)
      Autonomous: current worker + four-stage live timeline + stop
      Events: major step, timestamp, status, selected tool / high-level decision
      Findings: compact table (severity, class, target, verification, evidence)
      Click finding: detail panel, reproduction provenance, export/report pointer
  Filters: All Targets / Selected Target, status, vulnerability type, confirmation
```

Use existing MARS dark/light palettes, React routing, CSS and responsive conventions. Show actual server states, deliberate empty/error/loading screens and accessible disabled explanations; no fabricated counters. `Reports` owns full reports. A verified finding may expose a **future Blue handoff state** without launching Blue Team. The orchestrator summary may appear in existing Overview, not a separate page.

## 6. Execution order, dependencies and checkpoint gates

Each task in [`tasks/todo.md`](todo.md) is one focused, verifiable slice; the task list holds **all individual acceptance checkboxes**, likely files and verification. The sequence is deliberately foundation-first but vertically integrated at each meaningful cut.

| Phase | Tasks | Exit gate |
| --- | --- | --- |
| A: Baseline and contracts | T01–T04 | Accurate baseline, deterministic schema, target/scope contract |
| B: Persistence and policy | T05–T08 | Durable state/evidence, denied operations demonstrably rejected |
| C: Docker + ZAP reconnaissance | T09–T12 | Scoped discoveries become policy-classified endpoint candidates |
| D: Planning | T13–T15 | Adaptable vetted tests, bounded all-applicable selection, stale plans |
| E: Real execution and verification | T16–T21 | Real evidence for SQLi/XSS/traversal, independent result oracle, truthful gaps |
| F: Orchestration | T22–T25 | Manual/auto state machine, queue, cancellation, safe recovery |
| G: API and UI | T26–T33 | Validated effectful API and usable Red dashboard/workspaces |
| H: Acceptance and release | T34–T36 | E2E demonstration, security negative tests, operating docs |

**Critical path:** T01 → T02 → T03 → T04 → T05/T06/T07 → T08 → T09 → T10 → T11 → T12 → T13 → T14 → T15 → T16 → T17 → T18 → T19 → T20 → T21 → T22 → T23 → T24 → T25 → T26 → T27 → T28 → T29 → T30 → T31 → T32 → T33 → T34 → T35 → T36. Only independent tests/docs can be parallelized after their contracts exist.

### Definition of done applied to EVERY task

- The actual repository behavior has been inspected; no unrelated changes or unsafe file deletions.
- One focused test or clear negative-path proof demonstrates the new behavior. Build/lint/unit tests run for touched layers.
- No mock or read-only preview is claimed as a live assessment. Evidence produced by a real authorized Docker test is distinctly recorded.
- Permissions, Docker limits, error handling and security regressions are reviewed whenever a task changes a boundary.
- The task checklist is checked only after its acceptance criteria and verification pass; checkpoint gates remain unchecked until proven.
- A small, reviewable commit per verified task/checkpoint on the approved development branch. **Planning this work does not authorize code changes or pushes.**

## 7. Test and demonstration matrix

| Scenario | Expected outcome | Must prove |
| --- | --- | --- |
| Registered `vulnerable-store` with eligible SQLi, XSS, path-traversal templates | Real controlled executions, independently verified findings or honest not-confirmed result | End-to-end tool evidence; no fake result |
| ZAP finds a new in-scope endpoint | `candidate`, assessed by method/target policy before planning | No automatic scope expansion |
| ZAP yields a suspicious alert but reproduction fails | `suspected` or `not_confirmed` according to evidence, **not confirmed** | Separate ZAP observations/oracle |
| No vetted template matches | Coverage gap and recommended template addition | No unapproved payload/command |
| Test budget reached | Remaining eligible tests listed as not tested | Correct numerator/denominator |
| Manual rerun reconnaissance | Existing plan becomes stale; execution disabled until replanned | Historical records preserved |
| Autonomous run with one approval | Steps progress without further routine prompts | Target/classes/budget never grow |
| Toggle during active run | Disabled; stop stays available | Mode captured per assessment |
| Operator cancels | Queued actions revoked, in-flight abort requested, evidence kept | No silent partial success |
| Executor or ZAP times out | Safe bounded retry only if idempotent; uncertain action inconclusive | No automatic blind replay |
| State-changing test sequence | Verified clean target state between interfering operations | Evidence collected before reset |
| Redirect/crafted URI targets host, metadata IP or external site | Rejected before network operation and after redirects | No SSRF/scope bypass |
| Attempted Docker privileges/host mounts/untested project import | Refused | No general Docker provisioning surface |
| Read-only preview endpoints | Marked preview/not executed | No false positive evidence |
| No authenticated crawl | Compatibility/coverage limitation shown | No assertion protected routes were tested |

## 8. Risk register and resolution

| Risk | Severity | Mitigation / proof |
| --- | --- | --- |
| Optional LLM hooks produce nondeterministic or unverified Red decisions | High | Required path is model-free; no provider call in critical-path tests; optional legacy functions are isolated or deprecated. |
| Agent autonomy mistaken for execution permission | Critical | Policy service validates every operation and redirect against immutable operator-approved snapshot. |
| ZAP active test exceeds approved target or scanner API exposed | Critical | Dedicated isolated network, targeted rules only, pinned build, default-deny egress, permission checks, no host API bind. |
| Container resets destroy unrelated data | Critical | Restrict to named disposable lab assets; verify ownership labels and volume scope. |
| Test state contamination | High | Reset/recreate only where needed; verify clean-state fingerprint; preserve evidence first. |
| Tool alerts or preview output treated as confirmed | High | Separate observations from independent reproduction receipts and verification oracle. |
| Manual rerun executes stale plan | High | Immutable plan versions and stale state gate in both API and worker. |
| False sense of full coverage | High | Eligible test denominator, explicit gaps, unsupported classes and authentication limitations. |
| Browser or tool output injects unauthorized actions | High | Authenticated effectful API, CSRF/anti-replay, Pydantic validation, sanitized evidence, no arbitrary commands. |
| Laptop resource pressure | Medium | One heavy run per target, Standard bounded budgets, on-demand scanner and queue. |
| UI duplicates features or disturbs MARS theme | Medium | Reuse existing nav, routes, API client and CSS tokens. |
| Premature Blue/import features expand scope | Medium | Explicit deferrals; only data contract for future handoff. |

## 9. Architecture review: Standards axis vs. specification axis

**Review method:** This is a pre-implementation architecture/specification review, not a `git diff <ref>...HEAD` code review. The development laptop was offline during this planning session, and a fixed diff base was not given; therefore no claim of executing the `/review` skill's two parallel code-diff subreviews is made.

**Standards / engineering-quality findings:** Avoid duplicate agents or new microservices; do not add model providers; reuse existing Pydantic/httpx/SQLite/React conventions; make safety gates server-owned. Do not add scanner/container dependencies before a measured functional need and isolated test. Critical open implementation verification: latest repo inspection, actual command coverage of the current controlled executor, and ZAP topology/isolation suitability.

**Spec-fit findings resolved:** Original proposal focused too narrowly on static catalogues; now includes ZAP endpoint candidates and approved adaptable templates. Model hooks are not a core dependency. Blue tool placement corrected. Imported applications, authenticated discovery and more profiles explicitly deferred. Four-panel Manual UX, dedicated Autonomous timeline, mode lock, durable gaps and evidence agreed. All Q51–Q54 recommendations incorporated.

**No unanswered requirements are blocking task planning.** Where exact operational limits depend on measurements, T04/T09 must select conservative defaults and prove them under Docker rather than request further product decisions.

## 10. Release approval gate

Implementation and technical verification through T36 are complete. T34 and T35 passed against the authorized isolated Docker target with reproducible sanitized evidence, and the release checkpoint is committed. Push is delegated to the repository owner and was not performed by Codex. This does not authorize deployment, arbitrary target testing, or final research experiments.
