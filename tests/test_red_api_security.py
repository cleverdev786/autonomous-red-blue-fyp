"""T08 protected Red operator action contracts. No dispatch or real scan."""

from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dashboard.api.console import create_console_app
from orchestrator.policy_engine import StandardRedPolicy
from schemas.red_team import RedEndpointCandidate
from schemas.red_team_state import AssessmentDTO, CoverageDTO, OperationDTO, PlanVersionDTO
from services.red_assessment_store import RedAssessmentStore
from services.red_evidence_store import RedEvidenceStore
from services.target_registry import TargetRegistry

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "http://127.0.0.1:8090"
TOKEN = "test-operator-credential-at-least-32-bytes"
BODY = {
    "assessment_id": "as-1", "plan_version": "plan-1",
    "operation_id": "op-1", "request_id": "review-intent-1",
    "action": "request_review",
}


@pytest.fixture
def site(tmp_path, monkeypatch):
    monkeypatch.setenv("MARS_RED_OPERATOR_TOKEN", TOKEN)
    path = tmp_path / "red.sqlite3"
    registry = TargetRegistry.from_directories(
        targets_dir=ROOT / "config/targets",
        security_tests_dir=ROOT / "config/security_tests",
    )
    auth = StandardRedPolicy(
        registry=registry, budget_file=ROOT / "config/red_standard.json",
    ).freeze(assessment_id="as-1", approval_id="trusted-approval-1",
             target_id="vulnerable-store")
    store = RedAssessmentStore(path)
    store.create(
        AssessmentDTO(scope=auth.scope, mode="manual", status="running",
                      workflow_complete=False, coverage=CoverageDTO()),
        auth, request_id="assessment-creation-1",
    )
    store.add_candidate("as-1", RedEndpointCandidate(
        candidate_id="candidate-1", method="GET", path="/scenarios/xss/search",
        source="registered", observed_at=datetime(2026, 10, 27, tzinfo=timezone.utc),
    ))
    store.add_plan(PlanVersionDTO(
        scope=auth.scope, plan_version="plan-1", surface_revision="surface-1",
        status="approved",
    ))
    store.add_operation(OperationDTO(
        scope=auth.scope, operation_id="op-1", plan_version="plan-1",
        candidate_id="candidate-1", test_id="xss-reflection-001", status="proposed",
    ))
    app = create_console_app(database_path=tmp_path / "missing-research.db",
                             mars_workspace_db=tmp_path / "mars.db", red_state_db=path)
    with TestClient(app) as client:
        yield client, store, auth.scope, path


def auth_headers():
    return {"Authorization": f"Bearer {TOKEN}", "Origin": ORIGIN}


def csrf(client):
    result = client.get("/api/red/operator/csrf", headers=auth_headers())
    assert result.status_code == 200, result.text
    assert result.headers["cache-control"] == "no-store"
    return result.json()["csrf_token"]


def submit(client, body=None, *, headers=None):
    provided = {**auth_headers(), "X-Red-CSRF": csrf(client)}
    provided.update(headers or {})
    return client.post("/api/red/operator/reviews", headers=provided,
                       json=BODY if body is None else body)


def test_missing_operator_auth_and_unconfigured_secret_fails_closed(site, monkeypatch):
    client, store, scope, path = site
    assert client.get("/api/red/operator/csrf").status_code == 401
    response = client.post("/api/red/operator/reviews", headers={"Origin": ORIGIN}, json=BODY)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"
    assert RedEvidenceStore(store, Path(str(path) + ".evidence")).list_events(scope) == []
    monkeypatch.delenv("MARS_RED_OPERATOR_TOKEN")
    app = create_console_app(database_path=path.with_name("missing.db"),
                             mars_workspace_db=path.with_name("other-mars.db"), red_state_db=path)
    with TestClient(app) as disabled:
        assert disabled.get("/api/red/operator/csrf", headers=auth_headers()).status_code == 503


@pytest.mark.parametrize("headers,expected", [
    ({"Origin": "https://evil.example"}, 403),
    ({"Origin": ""}, 403),
    ({"Origin": "null"}, 403),
    ({"X-Red-CSRF": "forged"}, 403),
    ({"Authorization": "Bearer invalid"}, 401),
])
def test_wrong_origin_csrf_or_auth_denied_without_mutation(site, headers, expected):
    client, store, scope, path = site
    response = submit(client, headers=headers)
    assert response.status_code == expected, response.text
    assert response.json()["error"]["code"]
    assert RedEvidenceStore(store, Path(str(path) + ".evidence")).list_events(scope) == []


def test_legitimate_operator_review_persists_without_scheduling(site):
    client, store, scope, path = site
    response = submit(client)
    assert response.status_code == 202, response.text
    assert response.json() == {
        "status": "recorded", "request_id": "review-intent-1",
        "effect": "review_only",
    }
    events = RedEvidenceStore(store, Path(str(path) + ".evidence")).list_events(scope)
    assert len(events) == 1
    assert events[0]["actor"] == "operator"
    assert events[0]["action"] == "operator_review_requested"
    assert events[0]["outcome"] == "recorded"
    snapshot, _ = store.load("as-1")
    assert snapshot.operations[0].status == "proposed"


def test_replay_same_key_denied_even_after_restart(site):
    client, store, scope, path = site
    assert submit(client).status_code == 202
    retry = submit(client)
    assert retry.status_code == 409
    assert retry.json()["error"]["code"] == "duplicate_request"
    app = create_console_app(database_path=path.with_name("missing.db"),
                             mars_workspace_db=path.with_name("other-mars.db"), red_state_db=path)
    with TestClient(app) as reopened:
        assert submit(reopened).status_code == 409
    assert len(RedEvidenceStore(store, Path(str(path) + ".evidence")).list_events(scope)) == 1


@pytest.mark.parametrize("bad", [
    {**BODY, "shell": "rm -rf /"}, {**BODY, "docker_flags": ["--privileged"]},
    {**BODY, "url": "http://evil.test/"}, {**BODY, "zap_script": "script"},
    {**BODY, "evidence_path": "../../secret"},
    {**BODY, "action": "start_scan"},
    {**BODY, "request_id": "../escape"},
    {**BODY, "plan_version": "other-plan"},
    {**BODY, "operation_id": "foreign"},
])
def test_malformed_and_unauthorized_action_cannot_modify_queue(site, bad):
    client, store, scope, path = site
    response = submit(client, bad)
    assert response.status_code in {409, 422}, response.text
    assert response.json()["error"]["code"]
    assert not RedEvidenceStore(store, Path(str(path) + ".evidence")).list_events(scope)
    snapshot, _ = store.load("as-1")
    assert snapshot.operations[0].status == "proposed"


def test_json_required_and_cross_origin_challenge_blocked(site):
    client, store, scope, path = site
    assert client.get("/api/red/operator/csrf", headers={
        "Authorization": f"Bearer {TOKEN}", "Origin": "https://foreign.test"
    }).status_code == 403
    headers = {**auth_headers(), "X-Red-CSRF": csrf(client),
               "Content-Type": "text/plain"}
    response = client.post("/api/red/operator/reviews", headers=headers,
                           content=b'{"action":"request_review"}')
    assert response.status_code == 415
    assert response.json()["error"]["code"] == "invalid_content_type"



def test_missing_csrf_and_origin_are_denied(site):
    client, store, scope, path = site
    without_csrf = client.post(
        "/api/red/operator/reviews",
        headers=auth_headers(),
        json=BODY,
    )
    assert without_csrf.status_code == 403
    assert without_csrf.json()["error"]["code"] == "invalid_csrf"
    no_origin = client.post(
        "/api/red/operator/reviews",
        headers={"Authorization": f"Bearer {TOKEN}", "X-Red-CSRF": csrf(client)},
        json=BODY,
    )
    assert no_origin.status_code == 403
    assert no_origin.json()["error"]["code"] == "invalid_origin"
    assert RedEvidenceStore(store, Path(str(path) + ".evidence")).list_events(scope) == []


def test_invalid_json_and_large_body_do_not_write_events(site):
    client, store, scope, path = site
    headers = {**auth_headers(), "X-Red-CSRF": csrf(client), "Content-Type": "application/json"}
    bad = client.post("/api/red/operator/reviews", headers=headers,
                      content=b"{invalid json")
    assert bad.status_code == 422
    assert bad.json()["error"]["code"] == "invalid_request"
    huge = client.post(
        "/api/red/operator/reviews", headers=headers,
        content=b'{"junk":"' + b'x' * 3000 + b'"}',
    )
    assert huge.status_code == 413
    assert huge.json()["error"]["code"] == "oversized_request"
    assert RedEvidenceStore(store, Path(str(path) + ".evidence")).list_events(scope) == []


def test_short_operator_secret_is_disabled(site, monkeypatch):
    _, _, _, path = site
    monkeypatch.setenv("MARS_RED_OPERATOR_TOKEN", "short-unsafe-value")
    app = create_console_app(database_path=path.with_name("none.db"),
                             mars_workspace_db=path.with_name("alt.db"), red_state_db=path)
    with TestClient(app) as client:
        response = client.get("/api/red/operator/csrf", headers=auth_headers())
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "operator_unconfigured"
