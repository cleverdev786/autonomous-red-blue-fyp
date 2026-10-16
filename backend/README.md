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
| Red/Blue workflow orchestration | `orchestrator/`, `agents/` |
| Persistent local MARS workspace | `~/.local/state/mars/workspace.sqlite3` |
| React web application | `dashboard/frontend/` |

## Boundaries

A backend package is not a new authorization mechanism. No new execution
permission is conferred by this entrypoint. The existing `/api/mars/jobs/{id}/start`
route intentionally refuses launch. The offline verified executor needs a clean,
independently pinned source, an externally approved runtime admission and
separate explicit permission before real Docker or security testing.

Legacy ASGI imports such as `dashboard.api.console:app` continue to work.
A future physical migration of the API modules should be done separately with
endpoint and package compatibility coverage, not through duplicated code.
