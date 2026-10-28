"""T12 authenticated, read-only reconnaissance preview API."""

import asyncio
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from dashboard.api.console import create_console_app
from orchestrator.policy_engine import StandardRedPolicy
from schemas.red_team import RedEndpointCandidate
from schemas.red_team_state import AssessmentDTO, CoverageDTO
from services.red_assessment_store import RedAssessmentStore
from services.red_evidence_store import RedEvidenceStore
from services.target_registry import TargetRegistry, UnknownTargetError

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "http://127.0.0.1:8090"
TOKEN = "test-operator-credential-at-least-32-bytes"


def _authorization(assessment_id: str, *, allowed_methods=None):
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
        allowed_methods=allowed_methods,
    )


@pytest.fixture
def site(tmp_path, monkeypatch):
    monkeypatch.setenv("MARS_RED_OPERATOR_TOKEN", TOKEN)
    state_db = tmp_path / "red.sqlite3"
    store = RedAssessmentStore(state_db)
    populated = _authorization("as-populated")
    empty = _authorization("as-empty")
    get_only = _authorization("as-get-only", allowed_methods={"GET"})
    for authorization in (populated, empty, get_only):
        store.create(
            AssessmentDTO(
                scope=authorization.scope,
                mode="manual",
                status="running",
                workflow_complete=False,
                coverage=CoverageDTO(),
            ),
            authorization,
            request_id=f"create-{authorization.scope.assessment_id}",
        )
    observed_at = datetime(2026, 10, 28, tzinfo=UTC)
    store.add_candidate(
        "as-populated",
        RedEndpointCandidate(
            candidate_id="candidate-health",
            method="GET",
            path="/health",
            source="zap",
            observed_at=observed_at,
        ),
    )
    store.add_candidate(
        "as-get-only",
        RedEndpointCandidate(
            candidate_id="candidate-login",
            method="POST",
            path="/login",
            parameter_names=("username",),
            source="zap",
            observed_at=observed_at,
        ),
    )
    store.add_candidate(
        "as-populated",
        RedEndpointCandidate(
            candidate_id="candidate-admin",
            method="GET",
            path="/admin/panel",
            source="zap",
            observed_at=observed_at,
        ),
    )
    journal = RedEvidenceStore(store, tmp_path / "evidence")
    journal.append_event(
        populated.scope,
        "recon-completed-1",
        actor="red_reconnaissance",
        action="recon_completed",
        outcome="observed",
        details={"stage": "reconnaissance", "status": "completed"},
        occurred_at=observed_at,
    )
    app = create_console_app(
        database_path=tmp_path / "missing-research.db",
        mars_workspace_db=tmp_path / "mars.db",
        red_state_db=state_db,
    )
    return app, state_db, populated.scope, empty.scope, get_only.scope


def _headers(**overrides):
    headers = {"Authorization": f"Bearer {TOKEN}", "Origin": ORIGIN}
    headers.update(overrides)
    return headers


def _database_bytes(path: Path) -> bytes:
    return path.read_bytes()


def _get(app, path: str, *, headers: dict[str, str]):
    async def request():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.get(path, headers=headers)

    return asyncio.run(request())


def test_populated_preview_is_scoped_and_has_no_execution_side_effects(site):
    app, state_db, scope, _, _ = site
    before = _database_bytes(state_db)

    response = _get(
        app,
        "/api/red/operator/assessments/as-populated/reconnaissance-preview",
        headers=_headers(),
    )

    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {
        "scope": scope.model_dump(mode="json"),
        "effect": "read_only_preview",
        "execution_enabled": False,
        "candidates": [
            {
                "candidate": {
                    "candidate_id": "candidate-health",
                    "method": "GET",
                    "path": "/health",
                    "parameter_names": [],
                    "source": "zap",
                    "observed_at": "2026-10-28T00:00:00Z",
                },
                "policy_status": "candidate_only",
                "registered_endpoint_id": "health",
            },
            {
                "candidate": {
                    "candidate_id": "candidate-admin",
                    "method": "GET",
                    "path": "/admin/panel",
                    "parameter_names": [],
                    "source": "zap",
                    "observed_at": "2026-10-28T00:00:00Z",
                },
                "policy_status": "unsupported",
                "registered_endpoint_id": None,
            },
        ],
        "limitations": [{"path": "/admin/panel", "reason": "authentication_required"}],
    }
    assert _database_bytes(state_db) == before


def test_empty_preview_is_explicit_and_read_only(site):
    app, state_db, _, scope, _ = site
    before = _database_bytes(state_db)

    response = _get(
        app,
        "/api/red/operator/assessments/as-empty/reconnaissance-preview",
        headers=_headers(),
    )

    assert response.status_code == 200, response.text
    assert response.json() == {
        "scope": scope.model_dump(mode="json"),
        "effect": "read_only_preview",
        "execution_enabled": False,
        "candidates": [],
        "limitations": [],
    }
    assert _database_bytes(state_db) == before


def test_preview_applies_frozen_assessment_method_scope(site):
    app, state_db, _, _, scope = site
    before = _database_bytes(state_db)

    response = _get(
        app,
        "/api/red/operator/assessments/as-get-only/reconnaissance-preview",
        headers=_headers(),
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["scope"] == scope.model_dump(mode="json")
    assert body["candidates"][0]["policy_status"] == "unsupported"
    assert body["candidates"][0]["registered_endpoint_id"] is None
    assert body["limitations"] == [{"path": "/login", "reason": "method_out_of_scope"}]
    assert _database_bytes(state_db) == before


@pytest.mark.parametrize(
    "headers,expected,code",
    [
        ({}, 401, "unauthorized"),
        ({"Authorization": "Bearer invalid", "Origin": ORIGIN}, 401, "unauthorized"),
        (
            {"Authorization": f"Bearer {TOKEN}", "Origin": "https://evil.example"},
            403,
            "invalid_origin",
        ),
    ],
)
def test_preview_access_fails_closed_without_trusted_operator(site, headers, expected, code):
    app, state_db, _, _, _ = site
    before = _database_bytes(state_db)

    response = _get(
        app,
        "/api/red/operator/assessments/as-populated/reconnaissance-preview",
        headers=headers,
    )

    assert response.status_code == expected
    assert response.json()["error"]["code"] == code
    assert _database_bytes(state_db) == before


@pytest.mark.parametrize("assessment_id", ["unknown-assessment", "bad$id"])
def test_invalid_or_unknown_assessment_is_not_disclosed(site, assessment_id):
    app, state_db, _, _, _ = site
    before = _database_bytes(state_db)

    response = _get(
        app,
        f"/api/red/operator/assessments/{assessment_id}/reconnaissance-preview",
        headers=_headers(),
    )

    assert response.status_code == 404
    assert response.json()["error"] == {
        "code": "assessment_not_found",
        "message": "Assessment is unavailable.",
    }
    assert _database_bytes(state_db) == before


def test_unconfigured_operator_cannot_read_preview(site, monkeypatch):
    _, state_db, _, _, _ = site
    monkeypatch.delenv("MARS_RED_OPERATOR_TOKEN")
    app = create_console_app(
        database_path=state_db.with_name("missing.db"),
        mars_workspace_db=state_db.with_name("mars-other.db"),
        red_state_db=state_db,
    )
    response = _get(
        app,
        "/api/red/operator/assessments/as-populated/reconnaissance-preview",
        headers=_headers(),
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "operator_unconfigured"


def test_missing_state_database_is_not_created_by_preview(site, tmp_path):
    _, _, _, _, _ = site
    missing = tmp_path / "missing-red.sqlite3"
    app = create_console_app(
        database_path=tmp_path / "missing-research.db",
        mars_workspace_db=tmp_path / "mars-other.db",
        red_state_db=missing,
    )

    response = _get(
        app,
        "/api/red/operator/assessments/as-populated/reconnaissance-preview",
        headers=_headers(),
    )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "storage_unavailable"
    assert not missing.exists()


def test_registry_drift_fails_closed_without_mutation(site, monkeypatch):
    app, state_db, _, _, _ = site
    before = _database_bytes(state_db)

    def unavailable(_registry, _target_id):
        raise UnknownTargetError("target removed")

    monkeypatch.setattr(TargetRegistry, "get_target", unavailable)
    response = _get(
        app,
        "/api/red/operator/assessments/as-populated/reconnaissance-preview",
        headers=_headers(),
    )

    assert response.status_code == 503
    assert response.json()["error"] == {
        "code": "storage_unavailable",
        "message": "Preview could not be loaded.",
    }
    assert _database_bytes(state_db) == before
