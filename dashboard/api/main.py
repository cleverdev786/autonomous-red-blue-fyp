"""FastAPI application factory for the read-only Milestone 16 dashboard."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from dashboard.api.config import (
    create_read_only_engine,
    make_read_only_session_factory,
    resolve_database_path,
)
from dashboard.api.read_service import DashboardNotFoundError, DashboardReadService
from dashboard.api.schemas import (
    AuditView,
    FindingView,
    HealthView,
    OverviewView,
    PatchVerificationView,
    RunDetailView,
    RunListItem,
    RunScoresView,
)


def create_app(database_path: str | Path | None = None) -> FastAPI:
    """Create a dashboard bound to an already-existing read-only SQLite database."""
    resolved = resolve_database_path(database_path)
    engine = create_read_only_engine(resolved)
    service = DashboardReadService(make_read_only_session_factory(engine))

    app = FastAPI(
        title="FYP Red-Blue Dashboard",
        version="m16",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.database_path = resolved
    app.state.database_engine = engine
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://127.0.0.1:5173",
            "http://localhost:5173",
            "http://127.0.0.1:4173",
            "http://localhost:4173",
        ],
        allow_credentials=False,
        allow_methods=["GET"],
        allow_headers=["Accept", "Content-Type"],
    )

    @app.get("/api/health", response_model=HealthView)
    def health() -> HealthView:
        service.ping()
        return HealthView(status="ok", database_read_only=True)

    @app.get("/api/overview", response_model=OverviewView)
    def overview() -> OverviewView:
        return service.overview()

    @app.get("/api/runs", response_model=tuple[RunListItem, ...])
    def runs(
        status: str | None = None,
        research_question: str | None = None,
        limit: int = Query(default=100, ge=1, le=200),
    ) -> tuple[RunListItem, ...]:
        return service.runs(
            status=status,
            research_question=research_question,
            limit=limit,
        )

    @app.get("/api/runs/{run_id}", response_model=RunDetailView)
    def run_detail(run_id: str) -> RunDetailView:
        try:
            return service.run_detail(run_id)
        except DashboardNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/runs/{run_id}/findings", response_model=FindingView)
    def findings(run_id: str) -> FindingView:
        try:
            return service.findings(run_id)
        except DashboardNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/runs/{run_id}/patch-verification", response_model=PatchVerificationView)
    def patch_verification(run_id: str) -> PatchVerificationView:
        try:
            return service.patch_verification(run_id)
        except DashboardNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/runs/{run_id}/scores", response_model=RunScoresView)
    def scores(run_id: str) -> RunScoresView:
        try:
            return service.scores(run_id)
        except DashboardNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/runs/{run_id}/audit", response_model=AuditView)
    def audit(run_id: str) -> AuditView:
        try:
            return service.audit(run_id)
        except DashboardNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/metrics/rq1")
    def rq1_metrics(final_only: bool = True) -> dict:
        return service.rq1_metrics(final_only=final_only)

    @app.get("/api/metrics/rq2")
    def rq2_metrics(final_only: bool = True) -> dict:
        return service.rq2_metrics(final_only=final_only)

    @app.get("/api/metrics/rq3")
    def rq3_metrics(final_only: bool = True) -> dict:
        return service.rq3_metrics(final_only=final_only)

    @app.get("/api/metrics/red")
    def red_metrics(final_only: bool = True) -> dict:
        return service.red_metrics(final_only=final_only)

    @app.get("/api/metrics/normal-application")
    def normal_metrics(final_only: bool = True) -> dict:
        return service.normal_metrics(final_only=final_only)

    return app
