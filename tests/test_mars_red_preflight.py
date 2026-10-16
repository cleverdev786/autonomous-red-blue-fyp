"""W3-A preflight must be read-only and never enable dispatch."""
from fastapi.testclient import TestClient
from dashboard.api.console import create_console_app


def client_with_job(tmp_path):
    api = create_console_app(database_path="/missing/research.sqlite",
                             mars_workspace_db=tmp_path / "mars.sqlite3")
    return TestClient(api)


def prepare(client):
    plan = client.post("/api/mars/plans", json={"name":"Registered SQLi", "scenario":"sql"}).json()
    created = client.post("/api/mars/jobs", json={"plan_id":plan["id"]})
    assert created.status_code == 201
    return created.json()


def test_preflight_requires_review_and_independent_external_admission(tmp_path):
    with client_with_job(tmp_path) as c:
        job = prepare(c)
        url = f'/api/mars/jobs/{job["id"]}/preflight'
        before = c.get(f'/api/mars/jobs/{job["id"]}/events').json()
        pending = c.get(url)
        assert pending.status_code == 200
        p = pending.json()
        assert p["schema_version"] == "mars-red-preflight-v1"
        assert p["job_id"] == job["id"]
        assert p["registered_test_id"] == "sqli-login-bypass-001"
        assert p["scope_sha256"] == job["scope_sha256"]
        assert p["can_dispatch"] is False
        assert p["scope_current"] is True
        assert p["checks"]["job_scope_reviewed"] is False
        assert p["checks"]["registered_scope_current"] is True
        assert p["checks"]["independent_admission_verified"] is False
        assert p["checks"]["isolated_runtime_verified"] is False
        assert p["checks"]["runner_enabled"] is False
        assert c.get(f'/api/mars/jobs/{job["id"]}/events').json() == before
        c.post(f'/api/mars/jobs/{job["id"]}/review', json={})
        reviewed = c.get(url).json()
        assert reviewed["checks"]["job_scope_reviewed"] is True
        assert reviewed["can_dispatch"] is False
        assert c.post(f'/api/mars/jobs/{job["id"]}/start', json={}).status_code == 409
        c.post(f'/api/mars/jobs/{job["id"]}/cancel', json={})
        cancelled = c.get(url).json()
        assert cancelled["checks"]["job_scope_reviewed"] is False
        assert cancelled["can_dispatch"] is False


def test_preflight_rejects_missing_id_and_blocks_drift(tmp_path, monkeypatch):
    with client_with_job(tmp_path) as c:
        assert c.get("/api/mars/jobs/00000000-0000-4000-8000-000000000001/preflight").status_code == 404
        assert c.get("/api/mars/jobs/bad-id/preflight").status_code == 422
        job = prepare(c)
        import dashboard.api.mars_plans as workspace
        monkeypatch.setattr(workspace, "registered_catalog", lambda _: {
            "target_id":"vulnerable-store","registered_assessments":[]
        })
        p = c.get(f'/api/mars/jobs/{job["id"]}/preflight').json()
        assert p["scope_current"] is False
        assert p["checks"]["registered_scope_current"] is False
        assert p["can_dispatch"] is False
        assert c.get(f'/api/mars/jobs/{job["id"]}').json()["state"] == "awaiting_review"
