# MARS Backend

**Canonical Python ASGI entrypoint:** `backend.app:app`

From the repository root, in the existing virtual environment:

```bash
.venv/bin/python -m uvicorn backend.app:app --host 127.0.0.1 --port 8090
```

The backend is already implemented. This package provides a discoverable and
stable entrypoint without copying backend logic or introducing a second server.

## Where the backend code currently lives

| Responsibility | Existing authoritative location |
|---|---|
| FastAPI app factory, route mounting and compatibility | `dashboard/api/console.py` |
| MARS assessment drafts, job states and preflight | `dashboard/api/mars_plans.py` |
| Operator/model management APIs | `dashboard/api/operator_service.py` |
| Read-only historical run API | `dashboard/api/main.py`, `read_service.py` |
| Deterministic registered executor | `services/controlled_executor.py` |
| Isolated Docker execution verification | `services/isolated_compose_executor.py` |
| Durable single-attempt safety store | `services/mars_dispatch_intent.py` |
| Externally admitted SQLi job handoff | `services/job_dispatch.py` |
| Receipt evidence reconciliation | `services/receipt_record.py` |
| Independently bound SQLi patch preview | `services/blue_preview.py` |
| Captured Red to model input | `services/blue_input.py` |
| Explicit local Q8 job classification | `services/blue_classify.py` |
| Model-selected source localization | `services/blue_localize.py` |
| Red/Blue workflow orchestration | `orchestrator/`, `agents/` |
| Persistent local MARS workspace | `~/.local/state/mars/workspace.sqlite3` |
| React web application | `dashboard/frontend/` |

## Boundaries

A backend package is not a new authorization mechanism. No new execution
permission is conferred by this entrypoint. The existing `/api/mars/jobs/{id}/start`
route intentionally refuses launch. The admitted development-only SQLi handoff is
instead explicitly invoked with `python -m services.job_dispatch`,
using `--help` to inspect its required arguments. It accepts an existing
scope-reviewed MARS job, an independently reviewed external admission file and
SHA-256, and an external evidence directory. Its case/run identifier must be
`mars-` followed by the job UUID without hyphens. It reuses the isolated
executor's Git, Docker and source checks, then commits exactly one durable
attempt intent before delegation. A failed or uncertain dispatch is **never
retried automatically**.

**This is not independent admission itself.** Do not invoke the real worker
without separately reviewed Docker/source pins and permitted synthetic runtime.
A returned executor receipt must match the saved external receipt bytes,
registered SQLi observation (when present), and durable admission reference
before one audited receipt summary is persisted. The React Assessments view can
read `GET /api/mars/jobs/{id}/execution`, which distinguishes
`not_dispatched`, `outcome_unknown`, and `receipt_recorded` with the actual
reported outcome. The durable intent stays unknown to forbid unsafe retries.
The SQLi development-only patch preview can be recorded with
`python -m services.blue_preview --help`, supplying the existing job database,
pinned source checkout, archived evidence directory, admission path and its
independently obtained SHA-256, plus the independently obtained receipt SHA-256.
It requires a confirmed, matching archived registered Red result and reruns
the repository's existing archived Red evidence verifier **without Docker**.
Only then does it invoke the existing deterministic trusted patch compiler
in an ephemeral source copy; no source file is changed or patched.

`GET /api/mars/jobs/{id}/proposal` and the React Assessments View proposal
show the resulting diff with explicit `model_decision_used=false`,
`patch_applied=false`, `security_replayed=false`, and
`final_research_qualified=false`. This is a source-grounded deterministic
development proposal, **not** a model-generated Blue classification or repair
acceptance.

### Local Q8 classification of independently bound Red observations

`services.blue_input` reconstructs the registered SQLi pair using the
**frozen registered request definitions** and **actual archived response
excerpts**. The original HTTP request bodies were not captured, so this is
a documented reconstruction, not a raw HTTP trace. Classification and source
localization prompt inputs contain no exploit evaluator truth.

The Assessments view includes **Classify with Q8** and **View Blue result**.
The former calls `POST /api/mars/jobs/{id}/classify` (local-origin only).
The server must have an actually loaded, SHA-verified C08B Q8 model and its
independently validated external C12 prompt package. It also needs five
operator-controlled environment variables, configured before server startup:

- `MARS_SOURCE_ROOT`: exact registered archived source checkout
- `MARS_EVIDENCE_DIR`: external registered Red case directory
- `MARS_ADMISSION_PATH`: independently reviewed admission file
- `MARS_ADMISSION_SHA256`: externally pinned admission digest
- `MARS_RECEIPT_SHA256`: externally pinned case receipt digest

The browser cannot supply paths or pins, and classification never launches
Docker. Model request/response bytes are saved in the existing external,
append-only Q8 evidence location. One classified job allows one attempt only;
an interrupted inference is shown as `outcome_unknown`, never silently
retried. The model's **actual label** is retained, even if benign, unknown,
or wrong. All Q8 decisions remain development-only and
**cannot authorize source analysis or patch application**.

### Model-selected SQLi source localization

A saved, actual Q8 `sql_injection` prediction can be followed with
`POST /api/mars/jobs/{id}/localize`. A non-SQLi or unknown/benign label
cannot enter this path. The same five server-side independently pinned Red
inputs are required as for classification. The worker **revalidates** the raw
archived Q8 classification and the independently bound Red observation before
using the **manifest-verified, existing C12 localization prompt**. It sends
only the captured HTTP pair and exact trusted numbered source snippets.

The model selects `function_or_route`, `sink_line`, `root_cause` and
`confidence`, validated by the existing compact-source schema, executable
source-line verifier, bound source registry and Blue analysis adapter. Raw
model responses remain in separate, external append-only evidence, with
SHA-256 fingerprints for the localization input and raw model response. A failed
or interrupted localization stays `outcome_unknown` and cannot auto-retry.
`GET /api/mars/jobs/{id}/localization` and Assessments **View source
finding** display the recorded selection. The UI only offers **Localize
with Q8** after a recorded SQLi prediction is displayed and Q8 is ready.
No browser-supplied paths, new Docker dispatch, Git mutation, patch authority
or research admission have been added.

Next: preserve this source-checked, model-selected Blue analysis for
isolated Git branch patch preparation, legitimate regressions and registered
security replay. The deterministic compiler preview remains separate from
Q8's model-selection provenance. The protected baseline and disabled HTTP Red
execution endpoint remain unchanged.

Legacy ASGI imports such as `dashboard.api.console:app` continue to work.
A future physical migration of the API modules should be done separately with
endpoint and package compatibility coverage, not through duplicated code.
