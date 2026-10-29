"""T26 authenticated Red dashboard read APIs."""

import asyncio
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from dashboard.api.console import create_console_app
from orchestrator.policy_engine import StandardRedPolicy
from schemas.red_team import RedEndpointCandidate
from schemas.red_team_state import (
    AssessmentDTO,
    CoverageDTO,
    CoverageGapDTO,
    FindingDTO,
    OperationDTO,
    PlanVersionDTO,
    ReceiptDTO,
    StageDTO,
)
from services.red_assessment_store import RedAssessmentStore
from services.red_evidence_store import RedEvidenceStore
from services.target_registry import TargetRegistry

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "http://127.0.0.1:8090"
TOKEN = "test-operator-credential-at-least-32-bytes"
NOW = datetime(2026, 10, 29, 8, tzinfo=UTC)


def _authorization(assessment_id: str):
    registry = TargetRegistry.from_directories(
        targets_dir=ROOT / "config/targets",
        security_tests_dir=ROOT / "config/security_tests",
    )
    return StandardRedPolicy(
        registry=registry,
        budget_file=ROOT / "config/red_standard.json",
    ).freeze(
        assessment_id=assessment_id,
        approval_id=f"approval-{assessment_id}",
        target_id="vulnerable-store",
    )


@pytest.fixture
def site(tmp_path, monkeypatch):
    monkeypatch.setenv("MARS_RED_OPERATOR_TOKEN", TOKEN)
    state_db = tmp_path / "red.sqlite3"
    store = RedAssessmentStore(state_db)
    active = _authorization("as-active")
    cancelled = _authorization("as-cancelled")
    store.create(
        AssessmentDTO(
            scope=active.scope,
            mode="autonomous",
            status="running",
            workflow_complete=False,
            coverage=CoverageDTO(),
        ),
        active,
        request_id="create-active",
    )
    store.create(
        AssessmentDTO(
            scope=cancelled.scope,
            mode="manual",
            status="cancelled",
            workflow_complete=True,
            coverage=CoverageDTO(),
        ),
        cancelled,
        request_id="create-cancelled",
    )
    candidate = RedEndpointCandidate(
        candidate_id="candidate-xss",
        method="GET",
        path="/scenarios/xss/search",
        parameter_names=("q",),
        source="registered",
        observed_at=NOW,
    )
    store.add_candidate("as-active", candidate)
    store.add_candidate("as-cancelled", candidate.model_copy(update={
        "candidate_id": "candidate-preview-only",
    }))
    store.add_plan(PlanVersionDTO(
        scope=active.scope,
        plan_version="plan-current",
        surface_revision="surface-current",
        status="approved",
    ))
    store.add_operation(OperationDTO(
        scope=active.scope,
        operation_id="operation-xss",
        plan_version="plan-current",
        candidate_id=candidate.candidate_id,
        test_id="xss-reflection-001",
        status="approved",
    ))
    store.set_stage(StageDTO(
        scope=active.scope,
        stage="reconnaissance",
        status="ready",
    ))
    journal = RedEvidenceStore(store, Path(str(state_db) + ".evidence"))
    journal._record_verified_finding(FindingDTO(
        scope=active.scope,
        finding_id="finding-xss",
        operation_id="operation-xss",
        status="suspected",
        severity="medium",
        category="xss",
        route="/scenarios/xss/search",
    ))
    receipt = ReceiptDTO(
        scope=active.scope,
        receipt_id="receipt-inconclusive",
        operation_id="operation-xss",
        plan_version="plan-current",
        test_id="xss-reflection-001",
        run_id="run-inconclusive",
        target_revision=active.scope.target_fingerprint,
        recorded_at=NOW,
        source="controlled_http",
        status="failed",
        request_count=0,
        raw_response_sha256="a" * 64,
        evidence_id="evidence-inconclusive",
    )
    artifact = journal.add_receipt_with_evidence(
        receipt,
        data={"status": "failed", "reason_code": "transport-error"},
    )
    journal._record_verified_finding(FindingDTO(
        scope=active.scope,
        finding_id="finding-inconclusive",
        operation_id="operation-xss",
        status="inconclusive",
        evidence_receipt_ids=(receipt.receipt_id,),
        severity="medium",
        category="xss",
        route="/scenarios/xss/search",
        provenance="controlled_http",
        reproduction_scope="registered_local_lab",
        evidence_id=artifact.evidence_id,
    ))
    journal.record_coverage_gaps(active.scope, (CoverageGapDTO(
        scope=active.scope,
        gap_id="gap-auth",
        reason="authentication_required",
        candidate_id=candidate.candidate_id,
        recommendation="Authenticated discovery is outside this release.",
    ),))
    journal.append_event(
        active.scope,
        "event-recon",
        actor="red-orchestrator",
        action="stage-transition",
        outcome="running",
        details={
            "stage": "reconnaissance",
            "status": "running",
            "authorization": "must-not-be-returned",
        },
        occurred_at=NOW,
    )
    app = create_console_app(
        database_path=tmp_path / "missing-research.db",
        mars_workspace_db=tmp_path / "mars.db",
        red_state_db=state_db,
    )
    return app, state_db, active.scope, cancelled.scope


def _headers():
    return {"Authorization": f"Bearer {TOKEN}", "Origin": ORIGIN}


def _get(app, path: str):
    async def request():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            return await client.get(path, headers=_headers())

    return asyncio.run(request())


def test_targets_and_assessment_index_are_typed_filtered_and_paginated(site):
    app, state_db, active, _ = site
    before = state_db.read_bytes()

    targets = _get(app, "/api/red/targets")
    assessments = _get(
        app,
        "/api/red/assessments?target_id=vulnerable-store&status=running&limit=1&offset=0",
    )
    second_page = _get(app, "/api/red/assessments?limit=1&offset=1")

    assert targets.status_code == assessments.status_code == 200
    assert targets.json() == {
        "items": [{
            "target_id": "vulnerable-store",
            "compatibility": "supported",
            "supported_classes": ["path_traversal", "sql_injection", "xss"],
            "limitations": ["unauthenticated_only"],
        }],
        "pagination": {"offset": 0, "limit": 50, "total": 1},
    }
    assert assessments.json() == {
        "items": [{
            "assessment_id": "as-active",
            "target_id": "vulnerable-store",
            "mode": "autonomous",
            "profile": "standard",
            "status": "running",
            "workflow_complete": False,
            "coverage": CoverageDTO().model_dump(mode="json"),
            "current_plan_version": "plan-current",
            "current_surface_revision": None,
            "stage_statuses": {"reconnaissance": "ready"},
        }],
        "pagination": {"offset": 0, "limit": 1, "total": 1},
    }
    assert assessments.json()["items"][0]["assessment_id"] == active.assessment_id
    assert second_page.json()["items"][0]["assessment_id"] == "as-active"
    assert second_page.json()["pagination"] == {"offset": 1, "limit": 1, "total": 2}
    assert targets.headers["cache-control"] == "no-store"
    assert assessments.headers["cache-control"] == "no-store"
    assert state_db.read_bytes() == before


def test_workspace_events_findings_and_coverage_are_safe_read_projections(site):
    app, state_db, active, _ = site
    before = state_db.read_bytes()

    workspace = _get(app, "/api/red/assessments/as-active")
    events = _get(app, "/api/red/assessments/as-active/events?limit=10")
    findings = _get(app, "/api/red/assessments/as-active/findings?limit=1")
    coverage = _get(app, "/api/red/assessments/as-active/coverage")

    assert workspace.status_code == events.status_code == findings.status_code == 200
    assert coverage.status_code == 200
    assert workspace.json()["assessment"]["assessment_id"] == "as-active"
    assert workspace.json()["stages"] == [{
        "scope": active.model_dump(mode="json"),
        "stage": "reconnaissance",
        "status": "ready",
        "plan_version": None,
    }]
    assert workspace.json()["plans"][0]["plan_version"] == "plan-current"
    assert workspace.json()["candidate_count"] == 1
    assert workspace.json()["planned_operation_count"] == 1
    assert workspace.json()["finding_counts"] == {
        "suspected": 1,
        "confirmed": 0,
        "not_confirmed": 0,
        "inconclusive": 1,
    }
    assert workspace.json()["coverage_gap_count"] == 1
    assert events.json() == {
        "items": [{
            "event_id": "event-recon",
            "action": "stage-transition",
            "status": "running",
            "stage": "reconnaissance",
            "occurred_at": "2026-10-29T08:00:00Z",
        }],
        "pagination": {"offset": 0, "limit": 10, "total": 1},
    }
    assert "authorization" not in events.text
    assert "must-not-be-returned" not in events.text
    assert findings.json() == {
        "items": [{
            "finding_id": "finding-xss",
            "assessment_id": "as-active",
            "target_id": "vulnerable-store",
            "status": "suspected",
            "severity": "medium",
            "category": "xss",
            "route": "/scenarios/xss/search",
            "provenance": None,
            "reproduction_scope": None,
            "has_evidence": False,
        }],
        "pagination": {"offset": 0, "limit": 1, "total": 2},
        "coverage_gap_count": 1,
    }
    assert coverage.json() == {
        "assessment_id": "as-active",
        "target_id": "vulnerable-store",
        "coverage": CoverageDTO().model_dump(mode="json"),
        "gaps": [{
            "scope": active.model_dump(mode="json"),
            "gap_id": "gap-auth",
            "status": "open",
            "surface_revision": None,
            "reason": "authentication_required",
            "candidate_id": "candidate-xss",
            "test_id": None,
            "recommendation": "Authenticated discovery is outside this release.",
        }],
        "warnings": [
            "unauthenticated_only_coverage",
            "incomplete_or_uncertain_coverage",
        ],
    }
    assert state_db.read_bytes() == before


def test_summary_and_empty_cancelled_reads_use_the_same_target_filter(site):
    app, state_db, _, _ = site
    before = state_db.read_bytes()

    summary = _get(app, "/api/red/summary?target_id=vulnerable-store")
    empty_findings = _get(app, "/api/red/assessments/as-cancelled/findings")
    cancelled = _get(app, "/api/red/assessments?status=cancelled")

    assert summary.status_code == empty_findings.status_code == cancelled.status_code == 200
    assert summary.json() == {
        "target_id": "vulnerable-store",
        "assessment_count": 2,
        "confirmed_findings": 0,
        "suspected_findings": 1,
        "tested": 0,
        "eligible": 0,
        "active_assessments": 1,
        "queued_assessments": 0,
        "active_stages": 0,
        "coverage_gaps": 1,
    }
    assert empty_findings.json() == {
        "items": [],
        "pagination": {"offset": 0, "limit": 50, "total": 0},
        "coverage_gap_count": 0,
    }
    cancelled_workspace = _get(app, "/api/red/assessments/as-cancelled")
    assert cancelled_workspace.json()["candidate_count"] == 1
    assert cancelled_workspace.json()["planned_operation_count"] == 0
    assert cancelled_workspace.json()["finding_counts"] == {
        "suspected": 0,
        "confirmed": 0,
        "not_confirmed": 0,
        "inconclusive": 0,
    }
    assert cancelled.json()["pagination"]["total"] == 1
    assert cancelled.json()["items"][0]["status"] == "cancelled"
    assert state_db.read_bytes() == before


def test_global_findings_filter_and_nonzero_pagination_are_stable(site):
    app, state_db, _, _ = site
    before = state_db.read_bytes()

    response = _get(
        app,
        "/api/red/findings?target_id=vulnerable-store&offset=1&limit=1",
    )

    assert response.status_code == 200
    assert response.json() == {
        "items": [{
            "finding_id": "finding-inconclusive",
            "assessment_id": "as-active",
            "target_id": "vulnerable-store",
            "status": "inconclusive",
            "severity": "medium",
            "category": "xss",
            "route": "/scenarios/xss/search",
            "provenance": "controlled_http",
            "reproduction_scope": "registered_local_lab",
            "has_evidence": True,
        }],
        "pagination": {"offset": 1, "limit": 1, "total": 2},
        "coverage_gap_count": 1,
    }
    suspected = _get(app, "/api/red/findings?status=suspected")
    assert suspected.json()["pagination"]["total"] == 1
    assert suspected.json()["items"][0]["finding_id"] == "finding-xss"
    categorized = _get(app, "/api/red/findings?category=xss&severity=medium")
    assert categorized.json()["pagination"]["total"] == 2
    assert state_db.read_bytes() == before


def test_assessment_findings_support_filters_and_reject_invalid_values(site):
    app, state_db, _, _ = site
    before = state_db.read_bytes()

    filtered = _get(
        app,
        "/api/red/assessments/as-active/findings?status=inconclusive&category=xss",
    )
    invalid = _get(app, "/api/red/assessments/as-active/findings?severity=urgent")

    assert filtered.status_code == 200
    assert filtered.json()["pagination"]["total"] == 1
    assert filtered.json()["items"][0]["finding_id"] == "finding-inconclusive"
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "invalid_filter"
    assert state_db.read_bytes() == before


def test_finding_detail_returns_sanitized_evidence_metadata_only(site):
    app, state_db, _, _ = site
    before = state_db.read_bytes()

    response = _get(app, "/api/red/findings/finding-inconclusive")

    assert response.status_code == 200
    body = response.json()
    assert body["finding"]["finding_id"] == "finding-inconclusive"
    assert body["operation_id"] == "operation-xss"
    assert body["plan_version"] == "plan-current"
    assert body["test_id"] == "xss-reflection-001"
    assert body["evidence"] == [{
        "evidence_id": "evidence-inconclusive",
        "receipt_id": "receipt-inconclusive",
        "operation_id": "operation-xss",
        "sha256": body["evidence"][0]["sha256"],
        "content_type": "application/json",
    }]
    assert len(body["evidence"][0]["sha256"]) == 64
    assert "storage_ref" not in response.text
    assert "transport-error" not in response.text
    assert state_db.read_bytes() == before


def test_stale_plan_is_visible_but_not_reported_as_current(site):
    app, state_db, _, _ = site
    store = RedAssessmentStore(state_db)
    snapshot, _ = store.load("as-active")
    blocked = snapshot.operations[0].model_copy(update={"status": "blocked"})
    with store._connect() as db:
        db.execute(
            "UPDATE red_operations SET payload=? WHERE assessment_id=? AND operation_id=?",
            (blocked.model_dump_json(), "as-active", blocked.operation_id),
        )
    store.set_plan_stale("as-active", "plan-current")

    response = _get(app, "/api/red/assessments/as-active")

    assert response.status_code == 200
    assert response.json()["assessment"]["current_plan_version"] is None
    assert response.json()["plans"][0]["status"] == "stale"


@pytest.mark.parametrize(
    ("path", "code"),
    [
        ("/api/red/assessments/not-found", "assessment_not_found"),
        ("/api/red/assessments/not-found/events", "assessment_not_found"),
        ("/api/red/assessments/not-found/findings", "assessment_not_found"),
        ("/api/red/assessments/not-found/coverage", "assessment_not_found"),
        ("/api/red/findings/not-found", "finding_not_found"),
    ],
)
def test_unknown_read_resource_is_not_disclosed(site, path, code):
    app, state_db, _, _ = site
    before = state_db.read_bytes()

    response = _get(app, path)

    assert response.status_code == 404
    assert response.json()["error"]["code"] == code
    assert state_db.read_bytes() == before


def test_filters_and_authentication_fail_closed_without_side_effects(site):
    app, state_db, _, _ = site
    before = state_db.read_bytes()

    bad_status = _get(app, "/api/red/assessments?status=pretend-success")
    missing_target = _get(app, "/api/red/summary?target_id=unknown-target")

    async def unauthenticated():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            return await client.get("/api/red/summary")

    denied = asyncio.run(unauthenticated())
    assert bad_status.status_code == 422
    assert bad_status.json()["error"]["code"] == "invalid_filter"
    assert missing_target.status_code == 404
    assert missing_target.json()["error"]["code"] == "target_not_found"
    assert denied.status_code == 401
    assert denied.json()["error"]["code"] == "unauthorized"
    assert state_db.read_bytes() == before


def test_missing_state_database_is_not_created_by_reads(tmp_path, monkeypatch):
    monkeypatch.setenv("MARS_RED_OPERATOR_TOKEN", TOKEN)
    missing = tmp_path / "missing-red.sqlite3"
    app = create_console_app(
        database_path=tmp_path / "missing-research.db",
        mars_workspace_db=tmp_path / "mars.db",
        red_state_db=missing,
    )

    response = _get(app, "/api/red/assessments")

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "storage_unavailable"
    assert not missing.exists()
