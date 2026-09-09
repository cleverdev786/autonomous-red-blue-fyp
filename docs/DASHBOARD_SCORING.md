# Milestone 16 — Dashboard and Scoring

## Status

Milestone 16 is **permanently complete** at `927746e41eca43bb4221dbdd9784ec47f4208cee` (`927746e`) as `Complete Milestone 16 dashboard and scoring`.

Permanent prerequisite checkpoint:

```text
Milestone 15 commit:
b1572cfa0cb4289035684a19194811848a930efe

Short SHA:
b1572cf

Commit:
Complete Milestone 15 experiment storage and metrics
```

Milestone 16 adds two capabilities only:

1. deterministic, versioned Red/Blue game-style scoring derived from stored post-run evidence;
2. a local read-oriented dashboard for experiment visibility and demonstration.

It does not implement Milestone 17 or later experiment conditions.

---

## 1. Scoring Authority

Scoring version:

```text
red-blue-v1
```

The sole formula authority is:

```text
orchestrator/scoring.py
```

Scoring is explicit and offline/post-run. The CLI entry point is:

```bash
python -m orchestrator.scoring \
  --database <existing-sqlite-file> \
  --run-id <run-id>
```

The scorer does not call an LLM and does not perform HTTP, Git, Docker, shell, patch, or environment actions. Dashboard GET routes never calculate or persist scores.

The scorer uses stored terminal evidence. Ground-truth-dependent correctness components are post-run evaluation only; evaluator truth is not exposed to Red/Blue agents, patch generation, or verification.

Research metrics remain separate from game scores. Existing RQ1/RQ2/RQ3/Red/normal-application metric functions do not use score rows as metric authority.

---

## 2. Score Applicability

Scenario-scoped terminal runs may be scored after execution.

The scorer treats these stored terminal statuses as eligible for post-run evaluation:

```text
ACCEPTED
REJECTED
FAILED
POLICY_BLOCKED
COMPLETED
```

RQ2 is dataset-scoped and does not receive artificial Red/Blue game scores:

```text
applicability = not_applicable
score rows = 0
```

Incomplete runs do not receive premature final scores:

```text
CREATED / RUNNING
applicability = ineligible_incomplete
score rows = 0
```

---

## 3. Red Team Score — `red-blue-v1`

Define:

```text
C = 1 only when a stored canonical RedTeamRunResult revalidates the trusted
    Milestone 8 confirmation semantics; otherwise 0

D_R = repeated use of the same registered Red test_id after its first use
      in the run

P_R = blocked policy-event references attributed to Red by the exact v1 map
```

Formula:

```text
Red Score =
clamp(
    100*C
  - 5*min(D_R, 4)
  - 25*min(P_R, 2),
  0,
  100
)
```

A raw stored `confirmed=True` flag is not sufficient by itself. The scorer revalidates the canonical Red result against the trusted confirmation conditions, including plan/execution/verification identity consistency, completed non-timeout execution, deterministic evidence presence, valid cited evidence IDs, and final Red flow state.

Duplicate penalty:

```text
5 points each
maximum counted duplicates = 4
maximum duplicate deduction = 20
```

Red policy penalty map:

```text
registered_test_authorization + unknown_test
registered_test_authorization + test_target_mismatch
registered_test_authorization + test_endpoint_mismatch
```

Other blocked-policy references are neutral to the Red v1 score unless a future scoring version explicitly changes the attribution map.

---

## 4. Blue Team Score — `red-blue-v1`

Diagnosis/localization components:

```text
correct classification                10
correct vulnerable source file        10
correct vulnerable function/route     10
                                      --
                                      30
```

For each patch attempt `i`, verification points are:

```text
syntax_import          5
application_startup    5
functional            10
security              20
original_replay       25
regression             5
                      --
                      70
```

Exactly one best patch attempt is selected. Verification stages from different attempts are never combined. The highest verification-point attempt wins; deterministic tie-breaking prefers the lower attempt number and then the lower stored attempt row ID.

Define:

```text
D_B = repeated prepared_diff_sha256 values after their first occurrence
P_B = blocked policy-event references attributed to Blue by the exact v1 map
```

Formula:

```text
Blue Score =
clamp(
    classification/localization points
  + selected one-attempt verification points
  - 5*min(D_B, 3)
  - 25*min(P_B, 2),
  0,
  100
)
```

There is no separate ACCEPTED bonus because ACCEPTED already depends on the mandatory deterministic verification stages.

Duplicate penalty:

```text
5 points each
maximum counted duplicates = 3
maximum duplicate deduction = 15
```

Blue policy penalty map:

```text
source_read + source_path_not_allowed
source_read + protected_path
source_read + symlink_escape
patch_path_validation + patch_path_not_allowed
patch_path_validation + protected_path
patch_size_validation + patch_too_large
```

All other policy events are score-neutral by default in `red-blue-v1`, including unrelated infrastructure/Git/environment events.

---

## 5. Canonical Score Evidence and Immutability

Every persisted score has a typed canonical `ScoreResult` artifact using the existing `result_artifacts` table.

The artifact records bounded deterministic evidence including:

```text
run_id
score_type
scoring_version
component observations and evidence IDs
penalty observations and evidence IDs
selected patch attempt
attributed policy-event IDs
subtotal
total penalty
final score
```

The score artifact intentionally does not copy unnecessary raw evaluator ground truth.

`score_records.evidence_reference` resolves to the canonical artifact and its SHA-256 digest:

```text
result_artifact:<artifact-id>:sha256:<payload-sha256>
```

The score identity is unique on:

```text
(run_id, score_type, scoring_version)
```

Persistence semantics are immutable:

```text
same version + identical score/evidence
→ idempotent no-op

same version + inconsistent score
→ fail

same version + changed evidence
→ fail

formula/evidence-rule change
→ requires a new scoring_version
```

This prevents silent rewriting of historical score evidence.

---

## 6. Dashboard Architecture

Required structure:

```text
dashboard/
├── api/
└── frontend/
```

Frontend architecture:

```text
React + Vite
```

API implementation:

```text
FastAPI
```

Storage source:

```text
existing SQLite / SQLAlchemy research database
```

The dashboard is optional. Existing CLI/orchestrator code was verified to operate from an isolated copy where the `dashboard` package was absent.

---

## 7. Genuine Read-Only SQLite Boundary

The dashboard API accepts only an already-existing database file. It does not initialize or create the research database.

The connection uses:

```text
SQLite file URI mode=ro
PRAGMA query_only=ON
PRAGMA foreign_keys=ON
SQLAlchemy NullPool
```

The final `NullPool` configuration is important. The first runtime implementation used the custom SQLite creator with SQLAlchemy's implicit `SingletonThreadPool`. Under concurrent synchronous FastAPI GETs this produced an intermittent:

```text
sqlite3.ProgrammingError: Cannot operate on a closed database
```

The smallest corrective change set explicit `NullPool`, giving dashboard sessions independent short-lived read-only connections while preserving `mode=ro` and `query_only=ON`.

The corrected concurrent runtime completed without reproducing the failure.

---

## 8. Dashboard API Boundary

Implemented API routes are GET-only:

```text
GET /api/health
GET /api/overview
GET /api/runs
GET /api/runs/{run_id}
GET /api/runs/{run_id}/findings
GET /api/runs/{run_id}/patch-verification
GET /api/runs/{run_id}/scores
GET /api/runs/{run_id}/audit
GET /api/metrics/rq1
GET /api/metrics/rq2
GET /api/metrics/rq3
GET /api/metrics/red
GET /api/metrics/normal-application
```

The dashboard has no route or service authority for:

```text
attack execution
arbitrary HTTP
patch generation/application
score calculation/recalculation
experiment start/cancel
Git operations
Docker/environment control
shell execution
research-outcome mutation
raw local-file browsing
```

A POST to the dashboard API is not an execution path. The runtime gate explicitly verified mutation routes are absent.

---

## 9. Frontend Views and Presentation Safety

Verified views:

```text
Overview
Runs
Run Detail
Findings
Patch Verification
Metrics
Audit
```

The UI includes successful, rejected, policy-blocked, failed, and incomplete/running evidence rather than hiding unsuccessful runs.

Stored generated content is treated only as inert data. Bounded excerpts include patch/diff, model/stage, and audit text. Normal React escaping is used; there is no intentional executable rendering path for stored content.

Manual runtime fixtures included literal strings such as:

```text
<script>alert('diff')</script>
<script>alert('audit')</script>
<script>alert('model')</script>
```

They displayed as text without alert/script execution, redirect, or HTML injection.

The manually inspected UI exposed no controls for attack execution, patch application, Git, Docker, shell, environment reset, experiment execution, or score recalculation.

---

## 10. Authoritative Verification Record

Final development-laptop automated results after the NullPool correction:

```text
Focused scoring/dashboard/experiment-metric gate:
21 passed, 1 non-failing Starlette TestClient deprecation warning

Full Python suite:
271 passed, 1 non-failing Starlette TestClient deprecation warning
```

Frontend:

```text
React/Vite production build: PASS
```

Deterministic scoring runtime:

```text
perfect-run Red: 100
perfect-run Blue: 100
selected patch attempt: 1

penalty-run Red: 70
penalty-run Blue: 70

RQ2: not_applicable, zero score rows
RUNNING: ineligible_incomplete, zero score rows

canonical ScoreResult artifacts/references/hash verification: PASS
identical same-version rescore: idempotent; DB SHA-256 unchanged
changed same-version evidence: rejected; existing score rows/artifacts unchanged
```

Dashboard/runtime safety:

```text
missing DB rejected without file creation: PASS
SQLite direct INSERT through dashboard connection rejected: PASS
GET endpoints: PASS
POST mutation attempt: rejected
unrestricted artifact endpoint: absent
manual seven-view UI verification: PASS
escaped hostile <script> fixture rendering: PASS
unsafe control buttons: absent
```

Corrected concurrent runtime:

```text
pool class: sqlalchemy.pool.impl.NullPool
PRAGMA query_only: 1
requests attempted: 240
responses received: 240
HTTP 200: 240
exceptions: 0
closed-database failures: 0
HTTP 500: 0
server tracebacks/ProgrammingError in corrected API log: 0
```

Research-database integrity after concurrent GETs:

```text
DB SHA-256 before/after: identical
all 20 SQLAlchemy table row counts: unchanged
total score rows: unchanged at 4
RQ2 score rows: 0
runtime.db-wal: absent
runtime.db-shm: absent
runtime.db-journal: absent
```

Repository/architecture closure:

```text
core orchestrator imported from dashboard-free isolated copy: PASS
isolated idempotent scorer: Red 100 / Blue 100; DB unchanged
permanent data/fyp.db: absent
permanent agent-patch branches: none
M16 VERIFY implementation scope: exactly 27 files
all 27 implementation files byte-identical to post-correction baseline during closure
SQLAlchemy table count: 20
```

---

## 11. npm Audit Classification

A non-destructive audit was run from a disposable copy of the frontend package manifest.

Full dependency tree:

```text
1 moderate
1 high

esbuild: moderate, transitive
vite: high, direct
```

Production-only dependency tree:

```text
0 vulnerabilities
```

Classification:

```text
non-blocking development/build dependency warning
```

No `npm audit fix` or `npm audit fix --force` was performed. The advisories are recorded for later dependency maintenance instead of changing an already verified milestone automatically.

---

## 12. Research and Safety Boundaries Preserved

Milestone 16 does not change the frozen vulnerability scope:

```text
SQL Injection
XSS
Path Traversal
```

It does not broaden testing beyond the self-created local deliberately vulnerable application.

It preserves:

```text
LLMs as untrusted recommenders
policy-controlled sensitive actions
ground-truth separation
failed/incomplete evidence retention
research metrics separate from scores
operational audit separate from research DB
explicit unknown model telemetry semantics
no automatic patch merge/push
```

This document remains the permanent M16 scoring/dashboard record. M17 is documented separately in `docs/EXPERIENCE_MEMORY_RQ1.md`. The following remain later milestones:

```text
M18 - RQ2 Frozen Classification Dataset
M19 - RQ3 Structured Feedback Retry
M20 - Experiment Freeze
M21 - Final Controlled Experiments
M22 - Results Analysis
```

---

## 13. Permanent Gate Record

```text
DESIGN       PASS
IMPLEMENT    PASS
TEST         PASS
VERIFY       PASS
DOCUMENT     PASS
COMMIT       PASS - 927746e41eca43bb4221dbdd9784ec47f4208cee
```

Milestone 16 is permanently closed. M17 builds on this checkpoint without changing the frozen M16 scoring formulas or dashboard authority boundaries.
