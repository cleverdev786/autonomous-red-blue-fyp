# Plan: MARS Red Team (frontend + backend, tool-assisted, local-first)

**Status:** PROPOSED FOR REVIEW, **NOT IMPLEMENTED** (2026-10-26).
**Scope:** MARS React/Vite `/dashboard/red-team` + existing FastAPI service + existing typed RedTeamFlow, policy engine, registries and isolated Docker lab. No external targets, internet discovery or install in this planning pass.
**Research:** [docs/RED_TEAM_TOOL_RESEARCH_2026-10-26.md](../docs/RED_TEAM_TOOL_RESEARCH_2026-10-26.md).
**Task tracker:** `tasks/todo.md`; no external tracker designated or prior incomplete `tasks/plan.md` found.

## Design principle

**Four stages, not four autonomous microservices**. Keep the trusted engine and one MARS UI; treat LLM output and scanner reports as untrusted suggestions. Work without a local model or cloud API; model-enabled reasoning is explicitly optional and never receives networking/Docker authority.

```text
MARS / Red Team (React)
   | choose registered target, inspection mode, inspect results
   v
FastAPI /api/red/* (origin + scope validation; read-only until explicit execution)
   | run_id, bounded events/receipts and snapshots
   v
Trusted Red workflow coordinator + policy and budgets
   +--> 1. RECON        registered surface -> optional *passive* tool observations
   +--> 2. PLAN         registered test selection / validated optional LLM advice
   +--> 3. EXECUTE      explicit operator gate -> controlled-executor on internal Docker lab
   +--> 4. VERIFY       deterministic registry/evidence check -> optional verifier explanation
   v
Immutable operational receipts, run state and link to Findings/Reports
   `-- confirmed and authorized -> existing Blue Team handoff (separate workflow)
```

The user **never** provides an arbitrary host, port, shell command, script, payload or file path. The browser selects IDs from the backend's approved registries. Backend rechecks on every step. No auto-start on page load. Existing historical research evidence remains untouched.

## What the four stages actually do

| Stage | Existing implementation to reuse | Future backend boundary | What the user sees |
|---|---|---|---|
| **1. Reconnaissance Agent** | `ReconnaissanceService` + `ReconnaissanceAgent` + `TargetRegistry` | Read-only, allowlisted target/endpoint metadata; optional bounded passive ZAP context later. Explicitly distinguish registry facts from scanner observations | Authorized target, endpoint/method/input fields, source + timestamp, any scope refusals; optional model summary |
| **2. Attack Planning Agent** | `AttackPlanningAgent`, `AttackPlanningCatalog`, `AttackPlan`, `PolicyEngine` | Deterministic offline choice from known registered tests; optional model recommendation validated against catalog; plan is **not** execution permission | Test ID and mapped endpoint, vulnerability type, bounded expected requests, policy/rationale, state "ready for approval" or "blocked" |
| **3. Controlled Test Execution** | **Existing trusted `ControlledExecutor`** and `security_tests/*` behind Docker isolation | Privileged *trust* boundary but **not a model agent**. Only a registered test ID, opaque run ID, allowed attempt; fixed request sequence, timeouts, circuit breaker, no arbitrary network | Explicit Start/Cancel gate, real progress/event receipt, request-count, HTTP result, timeout/blocked/error; no raw attack payload editing |
| **4. Attack Verification Agent** | `AttackVerificationAgent`, `RedTeamFlow` evidence identity validation, `TestExecutionResult` | Deterministic evidence validity/identity and eligibility first; optional model narrative second, cannot invent IDs or change verdict | confirmed / not confirmed / inconclusive / policy blocked, supporting evidence IDs, bounded sanitized exchanges, Blue handoff eligibility |

`RedTeamFlow` currently uses three model calls for the reasoning roles; it is **not** a production-ready model-independent UI job endpoint. The existing `services/tool_driven_workflow.py` is a separate offline SQLi/XSS/traversal sandbox demonstration and is **not** a substitute for general live Docker execution. Preserve this distinction in UI labels.

### Proposed API contract (not implemented)

- `GET /api/red/targets`: registered local target summaries and which stages are supported. Read-only; never accept arbitrary URL query for network requests.
- `GET /api/red/targets/{target_id}/surface`: the bounded recon metadata plus provenance `registry` (and future `passive_scan` observations that are *not* authoritative).
- `POST /api/red/plans`: `{target_id, mode, registered_test_id?}` where `mode` is `offline_registered | assisted`; return `plan_id`, selected registered test, expected budgets, policy status, no execution. Offline selection may be explicit operator choice rather than opaque heuristic.
- `POST /api/red/runs`: `{plan_id, confirmation_token}` from an explicit, reviewed operator confirmation. Backend re-resolves policy and the target/test identities; responds `202` with opaque `run_id`, never raw command output. The confirmation token must be server-issued, short-lived, single-use, and bound to the exact immutable plan, target and scope. Do not use this endpoint until a real authenticated/authorized local-operator policy is designed; same-origin alone is not authorization.
- `GET /api/red/runs/{run_id}`: small snapshot containing `phase`, `state`, `reason_code`, `started_at`, `request_count`, `attempt_number`, `evidence_refs`; sanitized event log; never overclaim success. Bounded polling is sufficient before SSE/WebSocket is justified.
- `POST /api/red/runs/{run_id}/cancel`: best-effort cancellation with clear `cancel_requested` and eventual `cancelled`/unknown outcome. Never claim the process stopped before confirmed.
- `GET /api/red/runs/{run_id}/evidence`: sanitized, bounded evidence with hash/provenance; only retained, authorized runs. No raw secrets, credential response bodies or host paths.

Proposed run states: `draft`, `scope_reviewed`, `awaiting_execution_approval`, `queued`, `reconciling`, `executing`, `verifying`, `confirmed`, `not_confirmed`, `inconclusive`, `blocked`, `failed`, `cancel_requested`, `cancelled`. Define one canonical typed state model and map existing `WorkflowState` rather than shadow it with inconsistent strings. There is **no** silently automatic retry of an uncertain execution.

### Frontend, within existing MARS theme

One `/dashboard/red-team` page, no separate app or sidebar change. Desktop: narrow left **registered target/plan** rail and large right **four-stage timeline**, with a persistent evidence/replay drawer; mobile stacks the controls above the timeline. Default state shows scope and what has **not** run. Stages expand for **actual** data only:

1. **Target & scope:** registered `vulnerable-store` only, endpoint list, allowed methods, local Docker status, offline/assisted mode, request cap.
2. **Recon:** table of approved endpoints; optional passive observation badges with explicit provenance.
3. **Attack plan:** registered tests with descriptive labels, policy decision, projected budgets; operator reviews plan before it can execute.
4. **Execution and verification:** explicit local-lab start gate; current event state, evidence table, immutable verdict; link a confirmed result into existing Findings and/or Blue Team handoff.

Use existing `api.ts` typed request/validation convention, `ui.tsx` components, `tokens.css`, `product.css`, and the React route already defined. No fabricated region counts, throughput scores, "AI confidence" claims or unsupported security findings. Errors, no Docker, no model, no DB, blocked and timeouts get distinct useful empty states. No infinite animation or new frontend dependencies.

## Docker and Python dependencies: decision and sequencing

**Day 1 minimum:** existing `fyp-red-blue-lab:local` with `vulnerable-store` + `controlled-executor`; existing Python `httpx`, `pydantic`, `FastAPI`, `SQLAlchemy`; **zero extra installs**. A Docker image is not an agent: tools connect through a tightly typed adapter and trusted operation.

**Optional expansion after a working vertical slice:**
- **ZAP** official stable image as a short-lived separate tool runner, no API port published to the host, restricted to the approved Docker service and URL paths, passive/targeted requests only at first; limit scan time, CPU/RAM and request count, mount results to a dedicated location. Discovered URLs remain unapproved candidates. It does not run inside the existing `controlled-executor`.
- **Semgrep** official image, read-only mount of the approved source tree, local pinned rules, JSON output, disable optional metrics, no model/payload authority. Scans source code, not remote HTTP endpoints. It may enrich recon and Blue localization but cannot trigger attacks.
- **Bandit** optional `pip` extra *only* if a Python-specific AST report adds value beyond Semgrep; keep it out of the runtime attack image unless required.
- **Nuclei** optional only if additional registered non-overlapping vulnerability classes or applications justify it. Use specific reviewed templates, no updates or external OAST/interactsh, egress denied, very low request/concurrency caps. **Not** part of the minimum installation.

Do **not** install or bundle Kali, Metasploit, Nmap/Amass/Subfinder or sqlmap by default. For the current three synthetic HTTP checks these add more scope, packaging weight and duplicated capability than value. Do not run active ZAP scans on the development laptop outside the disposable synthetic target.

When adopting any image: choose official publisher; pin immutable sha256 digest and version/rules manifest; verify architecture/licensing, dependencies and memory; enforce `read_only`, `cap_drop: [ALL]`, no-new-privileges, rootless process, dedicated volumes, no Docker socket, no host networking, no internet, fixed runner command and resource/time caps. The current 7.6 GiB laptop cannot be assumed to support model inference plus every scanner simultaneously.

## Ordered vertical tasks (each should fit one focused implementation session)

### Phase 0. Contract and authority (foundation)
**T1.** Define canonical Red phase, verdict, plan and evidence contracts. Decide how these extend existing `schemas/red_team.py` / `WorkflowState`; no duplicate enum islands. **Acceptance:** malformed/untrusted target IDs, wrong evidence IDs, missing run state, invented verdicts and arbitrary URLs fail validation. **Verify:** focused typed-schema tests and `pytest -q`. **Likely files:** `schemas/red_team.py`, `schemas/common.py`, `tests/test_red_team_contracts.py`. **Depends:** none.
**T2.** Define the local operator execution permission model and event/persistence ownership. Keep operation receipt storage separate from research archives; authenticated operator checks before effectful APIs. **Acceptance:** same-origin alone cannot authorize execution; one plan identity cannot dispatch twice; restart/cancel exposes uncertain status faithfully. **Verify:** boundary misuse tests and storage tests. **Likely files:** `services/*red_workflow*.py`, `orchestrator/policy_engine.py`, `tests/test_red_execution_admission.py`. **Depends:** T1.
**Checkpoint:** contract + permission boundary reviewed **before** any execution endpoint is added.

### Phase 1. Safe read-only UI slice
**T3.** Expose bounded registry/recon data to `GET /api/red/targets` + `surface` using existing `ReconnaissanceService` (no scanning yet). **Acceptance:** shows only trusted registered target/endpoints; unknown target rejected; no network call/model call. **Verify:** FastAPI TestClient + `tests/test_mars_red_preflight.py`. **Likely files:** `dashboard/api/console.py` or narrow router, `services/reconnaissance_service.py`, `tests/test_red_api.py`. **Depends:** T1.
**T4.** Replace Red Team placeholder page with target/scope and read-only four-stage timeline. **Acceptance:** no auto execution, responsive, accessible, distinct unavailable/loading/blocked states; no fake run results. **Verify:** frontend `npm test`, `npm run build`, Firefox light/dark/mobile. **Likely files:** `dashboard/frontend/src/App.tsx`, `dashboard/frontend/src/api.ts`, `dashboard/frontend/src/red/RedTeamPanel.tsx`, `dashboard/frontend/src/product.css`. **Depends:** T3.
**Checkpoint:** user can inspect all approved scope without starting any attack, even offline/model unavailable.

### Phase 2. Registered planning (no execution side effects)
**T5.** Add a bounded plan preview from existing catalog + `PolicyEngine`; optional assisted recommendation must validate to registered ID/endpoint/method/parameter set. **Acceptance:** unknown tests/parameter mutation blocked, local fallback works without LLM, does not dispatch HTTP. **Verify:** `tests/test_registered_assessment_plan.py`, new plan API tests. **Likely files:** `services/registered_assessment_plan.py`, narrow API router, `tests/test_red_plan_preview.py`. **Depends:** T2–T4.
**Checkpoint:** a human can inspect and explicitly approve a stable, policy-admissible plan.

### Phase 3. Controlled Docker execution and hard stop
**T6.** Wire the reviewed plan to the existing registered `ControlledExecutor` in the approved isolated Docker executor, **not** a model sandbox. Add strict one-job-at-a-time coordination if needed; don't bring a queue dependency prematurely. **Acceptance:** only approved three test IDs; origin/auth/confirmation gate, request/time/attempt budgets, no redirect/ejected DNS, cancel/timeout with honest results, no host socket exposed to UI/model. **Verify:** executor policy tests and an explicitly admitted synthetic Docker smoke run with intact source/hash/network safeguards. **Likely files:** dedicated `services/red_job_runner.py`, narrow API router, `tests/test_red_job_runner.py`, integration test. **Depends:** T5 and reviewed admission.
**Checkpoint:** explicit operator action triggers one registered test inside lab, not scans against arbitrary hosts.

### Phase 4. Independent verification, receipts and handoff
**T7.** Normalize executor evidence into an immutable operational receipt with policy provenance. The verifier agent may narrate evidence but cannot create it or upgrade `inconclusive` to `confirmed`. **Acceptance:** identities, request counts, completion and hashes checked; timeout/empty evidence => not confirmed or inconclusive; sanitized evidence persists and can be opened in MARS. **Verify:** `tests/test_red_team_mvp.py`, `tests/test_executor_evidence_capture.py`, new evidence contract tests and UI render tests. **Likely files:** `orchestrator/red_team_flow.py`, `services/executor_evidence_capture.py`, `dashboard/frontend/src/red/RedTeamPanel.tsx`, tests. **Depends:** T6.
**Checkpoint:** end-to-end Red registered test and evidence linked to Findings/Reports, with honest Blue handoff eligibility.

### Phase 5. Tool extensions, only if justified by actual gaps
**T8.** Prototype ZAP **passive-only** registered-source HTTP observation on a throwaway synthetic app; compare discovered signals with known registered evidence. **Acceptance:** fixed allowlisted URLs, enforced offline image pin/rules, no unapproved requests/active scans, bounded JSON receipt and image resource caps. **Verify:** Compose network/egress check, a repeatable sandbox integration test. **Files:** optional Compose profile, tool adapter, test, reviewed config. **Depends:** T7 and explicit decision to adopt.
**T9.** Prototype Semgrep **local-rule read-only** source scanning only if source-pattern detection yields additional verified useful signal. **Acceptance:** JSON matches tied to source SHA and reviewed rules; no automatic test dispatch, code modification or cloud sync. **Verify:** scanned fixture source + negative controls. **Files:** adapter, local rule pack, fixture tests; Compose profile if Docker runner chosen. **Depends:** T7 and evidence of need.
**Checkpoint:** optional tools must show additional confirmed usefulness, otherwise remain excluded.

### Phase 6. Whole-system review
**T10.** Test full authorized path in both offline and assisted modes; reject any empty, inconsistent or unapproved evidence; verify CPU/RAM with models loaded and unloaded; verify shutdown and rollback without changed host source. **Acceptance:** no untested install, complete user-visible lifecycle and every claim traceable to a local receipt. **Verify:** `pytest -q -p no:cacheprovider`, `npm test`, `npm run build`, scoped Docker smoke tests and manual browser accessibility review. **Depends:** T7 and only adopted optional tools.

## Adversarial critique: reasons to NOT proceed automatically

- **"Four agents" is an organizational description, not justification for four LLMs/containers.** Four independent inference sessions would multiply latency/failures with no new test coverage. Reuse the existing three reasoning roles, keep execution deterministic; consider zero model calls as default.
- **"Reconnaissance" may be misunderstood as internet discovery.** For the current local synthetic app the registry is the authorized surface; expansion to a second containerized test app needs an approved target manifest and new regression fixtures first.
- **Tool reports are probabilistic leads.** A Semgrep warning or ZAP passive alert is not proof of exploitability. Don't show an attack as "verified" unless a controlled test produced the expected actual evidence.
- **"Start" cannot be behind only a same-origin middleware.** Before exposing a Docker-triggering endpoint from a browser, establish operator authentication/authorization, CSRF protections, scope binding and exact action confirmation. This is the highest-risk blocker.
- **ZAP is Java-heavy and the laptop is modest.** A simultaneous model server, ZAP, Semgrep and Docker target may strain 7.6 GiB RAM. Prefer sequential ephemeral jobs or keep extras disabled by default.
- **Avoid shipping extra Docker containers merely to make an architecture diagram look richer.** The current two-container lab is the smallest valid execution base. Candidate images exist upstream but are **not** pulled yet.
- **Avoid silently conflating real Docker trials with the in-process offline sandbox.** User-facing labels, receipts and results must declare their execution source.

## Decisions to approve before implementation

1. **Initial scope:** only the registered local vulnerable-store target (recommended), or additional explicitly approved dockerized teaching targets with new manifests/tests? **Default: existing target only.**
2. **Model policy:** offline-first with optional local model suggestions (recommended), or model-required flow? **Default: offline-first.**
3. **Active scanner policy:** no ZAP/Nuclei active scanning until isolated-target registration and independent approval (recommended). **Default: no active external scanner.**
4. **Operator identity:** local single-user access is not itself an authorization scheme. **Block T6** until execution permission and browser-to-Docker trust boundary are agreed.
5. **Evidence retention:** operation receipts in a new local MARS operational store with opt-in export; no writes to frozen research artifacts. **Default: preserve historical files.**

**Stop condition:** This is a plan, not authorization to run tests, pull images, modify services, install Python dependencies, or implement the page.
