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
No Blue/patch verification is connected yet, and this does not qualify an
RQ1/RQ2 research result.

Legacy ASGI imports such as `dashboard.api.console:app` continue to work.
A future physical migration of the API modules should be done separately with
endpoint and package compatibility coverage, not through duplicated code.
