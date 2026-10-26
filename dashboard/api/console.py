"""Standalone localhost demonstration console over the existing FYP services.

Run with: python -m dashboard.api.console
The dashboard's original read-only API remains unchanged and is reused if an
existing experiment database is configured. No final trials are launched here.
"""

from __future__ import annotations

import json
import subprocess
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from dashboard.api.config import DashboardDatabaseError, resolve_database_path
from dashboard.api.main import create_app
from dashboard.api.mars_plans import register_mars_plans
from dashboard.api.operator_service import (
    DemoRequest,
    LocalStart,
    OperatorError,
    ProbeRequest,
    manager,
    prepare_preview,
    probe_capability,
    scenario_catalog,
)
from dashboard.api.q8_development_service import (
    Q8Demonstration,
    q8_development_status,
    run_q8_development_classification,
)
from services.evidence_review import (
    review_archived_assessment,
    review_pinned_patched_replay,
    review_pinned_phase5_replays,
    review_pinned_registered_red,
)
from services.registered_assessment_plan import (
    AssessmentPlanBlocked,
    registered_catalog,
)

ALLOWED_ORIGINS = {
    "http://127.0.0.1:8090",
    "http://localhost:8090",
    "http://127.0.0.1:5173",
    "http://localhost:5173",
}
REACT_DIST = Path(__file__).resolve().parents[1] / "frontend" / "dist"



class ReactRouteFiles(StaticFiles):
    """Only extension-free React routes receive the SPA shell on a 404."""

    async def get_response(self, path: str, scope: dict) -> Response:
        try:
            response = await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code != 404:
                raise
            response = None
        if response is not None and response.status_code != 404:
            return response
        # Missing assets must remain 404; never return HTML as JavaScript or CSS.
        segments = path.strip("/").split("/")
        if (scope.get("method") not in {"GET", "HEAD"}
                or not all(segment and segment.replace("-", "").replace("_", "").isalnum() for segment in segments)
                or segments[0] == "assets"
                or any("." in segment for segment in segments)):
            raise HTTPException(status_code=404)
        return FileResponse(
            Path(self.directory) / "index.html", media_type="text/html",
            headers={"Cache-Control": "no-store"},
        )

def require_local_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if origin and origin not in ALLOWED_ORIGINS:
        raise HTTPException(status_code=403, detail="Only the local console can change model state")


def to_http_error(exc: OperatorError) -> HTTPException:
    return HTTPException(status_code=400, detail=str(exc))


def create_console_app(database_path: str | Path | None = None, *,
                       mars_workspace_db: str | Path | None = None) -> FastAPI:
    """Construct the console even when no historical experiment DB exists."""
    try:
        resolved = resolve_database_path(database_path)
    except DashboardDatabaseError:
        resolved = None
    if resolved is not None:
        app = create_app(resolved)
    else:
        app = FastAPI(
            title="Red–Blue Operator Console", docs_url=None, redoc_url=None, openapi_url=None
        )

        @app.get("/api/overview")
        def empty_overview() -> dict:
            return {
                "total_runs": 0,
                "status_counts": {},
                "research_question_counts": {},
                "recent_runs": [],
            }

        @app.get("/api/runs")
        def empty_runs() -> list:
            return []

        @app.get("/api/health")
        def healthy() -> dict:
            return {"status": "ok", "database_read_only": True, "database_available": False}

    app.add_middleware(
        TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "testserver"]
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=sorted(ALLOWED_ORIGINS),
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
        allow_credentials=False,
    )
    router = APIRouter(prefix="/api/console")

    @router.get("/status")
    def status() -> dict:
        return {
            "project": "Autonomous Red–Blue Framework",
            "target": "vulnerable-store",
            "execution_mode": "development preview",
            "model": manager.status(),
            "experiment_db": resolved is not None,
            "rq1_final_runs_verified_here": None,
            "rq2_final_observations_verified_here": None,
            "research_notice": "No final research evidence is generated by this console.",
            "experience_mode": "DISABLED",
        }

    @router.get("/scenarios")
    def scenarios() -> list[dict]:
        return scenario_catalog()

    @router.post("/preview", dependencies=[Depends(require_local_origin)])
    def preview(data: DemoRequest) -> dict:
        try:
            return prepare_preview(data.scenario)
        except OperatorError as exc:
            raise to_http_error(exc) from exc

    @router.post("/workflows/offline", dependencies=[Depends(require_local_origin)])
    def registered_offline_workflow(data: DemoRequest) -> dict:
        """Run registered Red/Blue HTTP tests in an isolated worker, no model or live patch."""
        if data.scenario not in ("sql", "xss", "traversal"):
            raise HTTPException(status_code=422, detail="Unregistered local scenario")
        try:
            output = subprocess.run(
                [sys.executable, "-m", "services.tool_driven_workflow", data.scenario],
                cwd=str(Path(__file__).resolve().parents[2]),
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise HTTPException(status_code=503, detail="Offline worker unavailable") from exc
        if output.returncode != 0 or len(output.stdout) > 65536:
            raise HTTPException(status_code=503, detail="Offline rule workflow did not pass")
        try:
            receipt = json.loads(output.stdout)
        except ValueError as exc:
            raise HTTPException(status_code=503, detail="Offline worker returned no valid receipt") from exc
        if (receipt.get("scenario") != data.scenario
                or receipt.get("result") != "sandbox_verified"
                or receipt.get("model_used") is not False
                or receipt.get("live_source_modified") is not False):
            raise HTTPException(status_code=503, detail="Offline worker receipt rejected")
        return receipt

    @router.get("/models/local")
    def local_models() -> dict:
        return {
            "models": manager.list_local(),
            "active": manager.status(),
            "model_directory_configured": manager.directory() is not None,
            "providers": ["openai", "groq", "together"],
        }

    @router.post("/models/load", dependencies=[Depends(require_local_origin)])
    def load_model(data: LocalStart) -> dict:
        try:
            return manager.start(data)
        except OperatorError as exc:
            raise to_http_error(exc) from exc

    @router.post("/models/unload", dependencies=[Depends(require_local_origin)])
    def unload_model() -> dict:
        try:
            return manager.stop()
        except OperatorError as exc:
            raise to_http_error(exc) from exc

    @router.post("/models/probe", dependencies=[Depends(require_local_origin)])
    async def probe(data: ProbeRequest) -> dict:
        try:
            return await probe_capability(data)
        except OperatorError as exc:
            raise to_http_error(exc) from exc

    @router.get("/assessment/registry")
    def assessment_registry() -> dict:
        try:
            return registered_catalog(Path(__file__).resolve().parents[2])
        except AssessmentPlanBlocked as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @router.get("/assessment/review")
    def assessment_review(response: Response) -> dict:
        """Review externally pinned archives only; this endpoint never dispatches tests."""
        response.headers["Cache-Control"] = "no-store"
        return review_archived_assessment(root=Path(__file__).resolve().parents[2])

    @router.get("/assessment/registered-red")
    def registered_red_review(response: Response) -> dict:
        """Read-only, operator-pinned Red archive; never grants model or patch authority."""
        response.headers["Cache-Control"] = "no-store"
        return review_pinned_registered_red(root=Path(__file__).resolve().parents[2])

    @router.get("/assessment/patched-replay")
    def patched_replay_review(response: Response) -> dict:
        """Review operator-pinned archived replay; never dispatch tests."""
        response.headers["Cache-Control"] = "no-store"
        return review_pinned_patched_replay(root=Path(__file__).resolve().parents[2])

    @router.get("/assessment/phase5-replays")
    def phase5_replay_review(response: Response) -> dict:
        """Read-only pinned XSS and traversal development replay verification."""
        response.headers["Cache-Control"] = "no-store"
        return review_pinned_phase5_replays(root=Path(__file__).resolve().parents[2])

    @router.get("/assessment/export")
    def export_development_evidence() -> JSONResponse:
        """Portable status summary only; no raw evidence, paths or research acceptance."""
        root = Path(__file__).resolve().parents[2]
        red = review_pinned_registered_red(root=root)
        blue = review_archived_assessment(root=root)
        sql = review_pinned_patched_replay(root=root)
        phase5 = review_pinned_phase5_replays(root=root)
        data = {
            "schema_version": "sentinel-development-evidence-summary-v1",
            "scope": "author_reviewed_development_only",
            "archives": {
                "registered_red": {
                    "status": red["status"],
                    "test_id": red["registered_test_id"],
                    "run_id": red["red_run_id"],
                    "exploit_confirmed": red["exploit_confirmed"],
                },
                "q8_post_hoc_blue": {
                    "status": blue["status"],
                    "test_id": blue["registered_test_id"],
                    "red_run_id": blue["red_run_id"],
                    "classification": (
                        blue["model_decision"]["classification"]
                        if blue.get("model_decision") else None
                    ),
                },
                "patched_sqli": {
                    "status": sql["status"],
                    "run_id": sql["run_id"],
                    "exploit_confirmed": sql["exploit_confirmed"],
                    "legitimate_function_verified": (
                        sql["legitimate_login_verified"] is True
                        and sql["search_file_verified"] is True
                    ),
                },
                "patched_xss_traversal": {
                    "status": phase5["status"],
                    "replay_count": phase5["replay_count"],
                    "registered_runs": {
                        key: result["run_id"]
                        for key, result in phase5["results"].items()
                        if key in ("xss", "traversal")
                    },
                    "patched_docker_functional_verified": (
                        phase5["patched_docker_functional_verified"] is True
                    ),
                },
            },
            "final_research_qualified": False,
            "model_directed_original_red_proven": False,
            "original_live_repo_patch_state_independently_verified": False,
        }
        return JSONResponse(
            data,
            headers={
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "Content-Disposition": 'attachment; filename="sentinel-development-evidence.json"',
            },
        )

    @router.get("/q8/status")
    def q8_status() -> dict:
        return q8_development_status()

    @router.post("/q8/classify", dependencies=[Depends(require_local_origin)])
    def q8_classify(data: Q8Demonstration) -> dict:
        try:
            return run_q8_development_classification(data)
        except OperatorError as exc:
            raise to_http_error(exc) from exc

    app.include_router(router)
    # MARS user-authored draft plans live outside Git and outside the frozen research DB.
    workspace_path = Path(mars_workspace_db) if mars_workspace_db is not None else (
        Path.home() / ".local" / "state" / "mars" / "workspace.sqlite3"
    )
    app.include_router(register_mars_plans(
        root=Path(__file__).resolve().parents[2],
        database=workspace_path,
        require_origin=require_local_origin,
    ))

    # ponytail: built files only; rebuild with npm when React changes.
    # No second server, API proxy or package install is needed for deployment.
    if (REACT_DIST / "index.html").is_file():
        app.mount("/dashboard", ReactRouteFiles(directory=REACT_DIST, html=True))
    else:
        @app.get("/dashboard/")
        def react_build_missing(response: Response) -> dict:
            response.status_code = 503
            return {"detail": "Build the React dashboard: cd dashboard/frontend && npm run build"}

    # Old bookmarks go to the same MARS app; no second UI is mounted.
    @app.get("/research-dashboard")
    @app.get("/research-dashboard/{rest:path}")
    def old_react_dashboard_redirect(request: Request) -> RedirectResponse:
        suffix = request.url.path.removeprefix("/research-dashboard")
        destination = "/dashboard" + (suffix or "/")
        if request.url.query:
            destination += "?" + request.url.query
        return RedirectResponse(destination, status_code=307)

    @app.get("/", include_in_schema=False)
    def index() -> RedirectResponse:
        return RedirectResponse("/dashboard/", status_code=307)

    @asynccontextmanager
    async def console_lifespan(_app: FastAPI):
        try:
            yield
        finally:
            manager.stop()

    app.router.lifespan_context = console_lifespan

    return app


app = create_console_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "dashboard.api.console:app", host="127.0.0.1", port=8090, reload=False, access_log=False
    )
