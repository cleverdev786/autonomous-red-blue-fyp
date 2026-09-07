"""Milestone 16 read-only dashboard API and bounded-presentation tests."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.pool import NullPool

from dashboard.api.config import DashboardDatabaseError
from dashboard.api.main import create_app
from schemas.common import ResearchQuestion, RunStatus, RunType
from schemas.experiments import ExperimentConfiguration, ModelConfiguration
from schemas.scoring import (
    ScoreComponentObservation,
    ScoreResult,
    ScoreType,
)
from storage.database import create_database_engine, initialize_database, make_session_factory
from storage.models import (
    Base,
    AuditRunManifestRow,
    ExperimentRunRow,
    PatchAttemptRow,
    PolicyEventReferenceRow,
    ResultArtifactRow,
    ScoreRecordRow,
    VerificationStageRow,
)
from storage.repositories import ExperimentWriteRepository, ScoreRepository


BASE = "f" * 40
NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _config(config_id: str, rq: ResearchQuestion) -> ExperimentConfiguration:
    return ExperimentConfiguration(
        config_id=config_id,
        run_type=RunType.DEVELOPMENT,
        research_question=rq,
        scenario_ids=("scenario-xss",) if rq != ResearchQuestion.RQ2 else (),
        dataset_id="dataset-rq2" if rq == ResearchQuestion.RQ2 else None,
        repetitions=10,
        model=ModelConfiguration(provider="mock", model_name="fixture"),
    )


def _seed_database(tmp_path: Path):
    database = tmp_path / "dashboard.db"
    engine = create_database_engine(f"sqlite:///{database}", project_root=tmp_path)
    initialize_database(engine)
    factory = make_session_factory(engine)
    write = ExperimentWriteRepository(factory)

    rq1 = _config("cfg-rq1-dashboard", ResearchQuestion.RQ1)
    write.create_configuration(rq1)
    statuses = (
        ("accepted-run", RunStatus.ACCEPTED),
        ("rejected-run", RunStatus.REJECTED),
        ("blocked-run", RunStatus.POLICY_BLOCKED),
        ("failed-run", RunStatus.FAILED),
    )
    for index, (run_id, status) in enumerate(statuses, start=1):
        write.create_run(
            run_id=run_id,
            config_id=rq1.config_id,
            repetition_index=index,
            baseline_commit=BASE,
            scenario_id="scenario-xss",
            started_at=NOW,
        )
        write.mark_running(run_id)
        write.finalize_run(
            run_id,
            status=status,
            completed_at=NOW,
            system_error_code="fixture" if status == RunStatus.FAILED else None,
            system_error_summary="<script>stored failure text</script>" if status == RunStatus.FAILED else None,
        )
    write.create_run(
        run_id="running-run",
        config_id=rq1.config_id,
        repetition_index=5,
        baseline_commit=BASE,
        scenario_id="scenario-xss",
        started_at=NOW,
    )
    write.mark_running("running-run")

    rq2 = _config("cfg-rq2-dashboard", ResearchQuestion.RQ2)
    write.create_configuration(rq2)
    write.create_run(
        run_id="rq2-run",
        config_id=rq2.config_id,
        repetition_index=1,
        baseline_commit=BASE,
        dataset_id="dataset-rq2",
        started_at=NOW,
    )
    write.mark_running("rq2-run")
    write.finalize_run("rq2-run", status=RunStatus.COMPLETED, completed_at=NOW)

    raw_diff = "\n".join(
        ["diff --git a/file.py b/file.py", "+<script>alert('diff')</script>"]
        + [f"+line-{index}" for index in range(400)]
    )
    payload = json.dumps(
        {"prepared_patch": {"unified_diff": raw_diff}},
        sort_keys=True,
        separators=(",", ":"),
    )
    with factory() as session:
        artifact = ResultArtifactRow(
            run_id="accepted-run",
            attempt_number=1,
            artifact_type="patch_generation_result",
            schema_name="PatchGenerationResult",
            schema_version="1.0",
            payload_json=payload,
            payload_sha256=hashlib.sha256(payload.encode()).hexdigest(),
            created_at=NOW,
        )
        session.add(artifact)
        session.flush()
        attempt = PatchAttemptRow(
            run_id="accepted-run",
            attempt_number=1,
            prepared_patch_artifact_id=artifact.artifact_id,
            prepared_diff_sha256="a" * 64,
            files_changed=1,
            inserted_lines=401,
            deleted_lines=0,
            total_diff_bytes=len(raw_diff.encode()),
            changed_paths_json=json.dumps(["file.py"]),
            final_state="accepted",
            patch_decision="accepted",
        )
        session.add(attempt)
        session.flush()
        session.add(
            VerificationStageRow(
                patch_attempt_id=attempt.id,
                stage_id="functional",
                sequence_number=1,
                required=True,
                passed=True,
                duration_ms=1,
                details="<script>alert('stage')</script>",
            )
        )
        session.add(
            AuditRunManifestRow(
                run_id="accepted-run",
                audit_source="/tmp/inert-audit.jsonl",
                event_count=1,
                blocked_count=1,
                failed_count=0,
                first_event_id="policy-1",
                last_event_id="policy-1",
                canonical_run_audit_sha256="b" * 64,
            )
        )
        session.add(
            PolicyEventReferenceRow(
                run_id="accepted-run",
                audit_event_id="policy-1",
                operation="patch_size_validation",
                policy_decision="blocked",
                policy_reason="patch_too_large",
                execution_status="blocked",
            )
        )
        session.commit()

    ScoreRepository(factory).record_score(
        ScoreResult(
            run_id="accepted-run",
            score_type=ScoreType.BLUE,
            scoring_version="red-blue-v1",
            components=(
                ScoreComponentObservation(
                    component_id="fixture",
                    observed=True,
                    points_possible=100,
                    points_awarded=100,
                    evidence_ids=("verification_stage:1",),
                ),
            ),
            penalties=(),
            subtotal=100,
            total_penalty=0,
            final_score=100,
        )
    )
    engine.dispose()
    return database, factory


def test_dashboard_requires_existing_database_and_never_initializes_missing_path(tmp_path: Path) -> None:
    missing = tmp_path / "missing.db"
    with pytest.raises(DashboardDatabaseError):
        create_app(missing)
    assert not missing.exists()


def test_dashboard_get_surface_is_read_only_and_keeps_all_outcomes_visible(tmp_path: Path) -> None:
    database, factory = _seed_database(tmp_path)
    before_hash = hashlib.sha256(database.read_bytes()).hexdigest()
    with factory() as session:
        before_scores = session.scalar(select(func.count()).select_from(ScoreRecordRow))

    app = create_app(database)
    api_methods = {
        method
        for route in app.routes
        if getattr(route, "path", "").startswith("/api/")
        for method in getattr(route, "methods", set())
    }
    assert api_methods == {"GET"}

    with TestClient(app) as client:
        assert client.get("/api/health").json() == {
            "status": "ok",
            "database_read_only": True,
        }
        overview = client.get("/api/overview").json()
        assert overview["status_counts"] == {
            "accepted": 1,
            "completed": 1,
            "failed": 1,
            "policy_blocked": 1,
            "rejected": 1,
            "running": 1,
        }
        runs = client.get("/api/runs").json()
        assert {item["status"] for item in runs} == {
            "accepted", "completed", "failed", "policy_blocked", "rejected", "running"
        }
        assert client.post("/api/runs").status_code == 405
        assert client.get("/api/artifacts/1").status_code == 404

    with app.state.database_engine.connect() as connection:
        with pytest.raises(DBAPIError):
            connection.execute(
                text("INSERT INTO score_records (run_id, score_type, score_value, scoring_version, evidence_reference) VALUES ('accepted-run','red',1,'x','x')")
            )

    app.state.database_engine.dispose()
    after_hash = hashlib.sha256(database.read_bytes()).hexdigest()
    assert after_hash == before_hash
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(ScoreRecordRow)) == before_scores


def test_dashboard_reads_stored_score_evidence_without_recalculation_and_rq2_is_na(tmp_path: Path) -> None:
    database, factory = _seed_database(tmp_path)
    app = create_app(database)
    with TestClient(app) as client:
        score = client.get("/api/runs/accepted-run/scores").json()
        assert score["applicability"] == "scored"
        assert len(score["scores"]) == 1
        assert score["scores"][0]["evidence_integrity"] is True
        assert score["scores"][0]["breakdown"]["final_score"] == 100

        rq2 = client.get("/api/runs/rq2-run/scores").json()
        assert rq2 == {"run_id": "rq2-run", "applicability": "not_applicable", "scores": []}

    app.state.database_engine.dispose()
    with factory() as session:
        assert session.scalar(
            select(func.count()).select_from(ScoreRecordRow).where(ScoreRecordRow.run_id == "rq2-run")
        ) == 0


def test_dashboard_bounds_patch_text_and_returns_generated_text_as_inert_strings(tmp_path: Path) -> None:
    database, _ = _seed_database(tmp_path)
    app = create_app(database)
    with TestClient(app) as client:
        patch = client.get("/api/runs/accepted-run/patch-verification").json()
        attempt = patch["attempts"][0]
        assert attempt["diff_truncated"] is True
        assert len(attempt["diff_excerpt"]) <= 12_000
        assert len(attempt["diff_excerpt"].splitlines()) <= 240
        assert "<script>alert('diff')</script>" in attempt["diff_excerpt"]
        assert attempt["stages"][0]["details"] == "<script>alert('stage')</script>"
    app.state.database_engine.dispose()

    frontend = (Path(__file__).parents[1] / "dashboard/frontend/src/App.tsx").read_text()
    assert "dangerouslySetInnerHTML" not in frontend
    assert "<pre className=\"diff\">{attempt.diff_excerpt}</pre>" in frontend


def _table_row_counts(factory) -> dict[str, int]:
    with factory() as session:
        return {
            table.name: int(
                session.scalar(
                    select(func.count()).select_from(table)
                )
                or 0
            )
            for table in Base.metadata.sorted_tables
        }


def test_dashboard_concurrent_reads_use_null_pool_and_never_mutate_database(
    tmp_path: Path,
) -> None:
    database, factory = _seed_database(tmp_path)
    before_hash = hashlib.sha256(database.read_bytes()).hexdigest()
    before_counts = _table_row_counts(factory)

    with factory() as session:
        before_score_rows = int(
            session.scalar(
                select(func.count()).select_from(ScoreRecordRow)
            )
            or 0
        )
        before_rq2_score_rows = int(
            session.scalar(
                select(func.count())
                .select_from(ScoreRecordRow)
                .where(ScoreRecordRow.run_id == "rq2-run")
            )
            or 0
        )

    app = create_app(database)
    assert isinstance(app.state.database_engine.pool, NullPool)

    paths = (
        "/api/health",
        "/api/overview",
        "/api/runs",
        "/api/runs/accepted-run",
        "/api/runs/accepted-run/findings",
        "/api/runs/accepted-run/patch-verification",
        "/api/runs/accepted-run/scores",
        "/api/runs/accepted-run/audit",
        "/api/runs/rq2-run",
        "/api/runs/rq2-run/scores",
        "/api/metrics/rq1",
        "/api/metrics/rq2",
        "/api/metrics/rq3",
        "/api/metrics/red",
        "/api/metrics/normal-application",
    )

    async def _exercise_parallel_reads() -> list[tuple[str, int, str]]:
        transport = httpx.ASGITransport(
            app=app,
            raise_app_exceptions=False,
        )
        semaphore = asyncio.Semaphore(24)

        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://dashboard.test",
            timeout=10.0,
        ) as client:

            async def _read(index: int) -> tuple[str, int, str]:
                path = paths[index % len(paths)]
                async with semaphore:
                    response = await client.get(path)
                return path, response.status_code, response.text[:500]

            return list(
                await asyncio.gather(
                    *(_read(index) for index in range(240))
                )
            )

    responses = asyncio.run(_exercise_parallel_reads())
    failures = [
        (path, status, body)
        for path, status, body in responses
        if status != 200
    ]
    assert failures == []

    app.state.database_engine.dispose()

    after_hash = hashlib.sha256(database.read_bytes()).hexdigest()
    after_counts = _table_row_counts(factory)

    with factory() as session:
        after_score_rows = int(
            session.scalar(
                select(func.count()).select_from(ScoreRecordRow)
            )
            or 0
        )
        after_rq2_score_rows = int(
            session.scalar(
                select(func.count())
                .select_from(ScoreRecordRow)
                .where(ScoreRecordRow.run_id == "rq2-run")
            )
            or 0
        )

    assert after_hash == before_hash
    assert after_counts == before_counts
    assert after_score_rows == before_score_rows
    assert after_rq2_score_rows == before_rq2_score_rows == 0
