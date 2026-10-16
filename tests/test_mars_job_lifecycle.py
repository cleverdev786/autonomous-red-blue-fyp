"""W2 MARS jobs: lifecycle and event history without security execution."""
from fastapi.testclient import TestClient
from dashboard.api.console import create_console_app


def app(tmp_path):
    return create_console_app(
        database_path="/not/connected/research.db",
        mars_workspace_db=tmp_path / "workspace.sqlite3",
    )


def create_plan(client, name="Registered SQLi"):
    response = client.post("/api/mars/plans", json={"name": name, "scenario": "sql"})
    assert response.status_code == 201, response.text
    return response.json()


def test_job_review_cancel_persist_and_audit(tmp_path):
    api = app(tmp_path)
    with TestClient(api) as client:
        plan = create_plan(client)
        res = client.post("/api/mars/jobs", json={"plan_id": plan["id"]})
        assert res.status_code == 201, res.text
        job = res.json()
        assert job["id"] and job["plan_id"] == plan["id"]
        assert job["state"] == "awaiting_review"
        assert job["target_id"] == "vulnerable-store"
        assert job["registered_test_id"] == "sqli-login-bypass-001"
        assert job["endpoint_path"] and job["max_requests"] >= 1
        assert job["timeout_seconds"] > 0
        assert job["execution_authorized"] is False
        assert job["executed"] is False and job["final_research_qualified"] is False
        assert len(job["scope_sha256"]) == 64
        assert client.get("/api/mars/jobs").json()[0]["id"] == job["id"]
        assert client.get(f'/api/mars/jobs/{job["id"]}').json() == job
        assert [e["event"] for e in client.get(f'/api/mars/jobs/{job["id"]}/events').json()] == ["created"]
        assert client.post("/api/mars/jobs", json={"plan_id": plan["id"]}).status_code == 409
        assert client.delete(f'/api/mars/plans/{plan["id"]}').status_code == 409

        assert client.post(f'/api/mars/jobs/{job["id"]}/start', json={}).status_code == 409
        reviewed = client.post(f'/api/mars/jobs/{job["id"]}/review', json={})
        assert reviewed.status_code == 200, reviewed.text
        assert reviewed.json()["state"] == "scope_reviewed"
        assert reviewed.json()["execution_authorized"] is False
        assert client.post(f'/api/mars/jobs/{job["id"]}/review', json={}).status_code == 409
        assert client.post(f'/api/mars/jobs/{job["id"]}/start', json={}).status_code == 409
    with TestClient(app(tmp_path)) as reopened:
        assert reopened.get(f'/api/mars/jobs/{job["id"]}').json()["state"] == "scope_reviewed"
        cancelled = reopened.post(f'/api/mars/jobs/{job["id"]}/cancel', json={})
        assert cancelled.status_code == 200
        assert cancelled.json()["state"] == "cancelled"
        events = reopened.get(f'/api/mars/jobs/{job["id"]}/events').json()
        assert [e["event"] for e in events] == ["created", "scope_reviewed", "cancelled"]
        assert [e["sequence"] for e in events] == [1, 2, 3]
        assert all(len(e["occurred_at"]) >= 20 for e in events)
        assert reopened.post(f'/api/mars/jobs/{job["id"]}/cancel', json={}).status_code == 200
        assert reopened.get(f'/api/mars/jobs/{job["id"]}/events').json() == events
        assert reopened.post(f'/api/mars/jobs/{job["id"]}/review', json={}).status_code == 409
        assert reopened.post(f'/api/mars/jobs/{job["id"]}/start', json={}).status_code == 409


def test_job_rejects_unsafe_inputs_and_foreign_origin(tmp_path):
    with TestClient(app(tmp_path)) as client:
        plan = create_plan(client)
        for body in [
            {"plan_id": "nonexistent"},
            {"plan_id": plan["id"], "target_url": "https://bad.example"},
            {"plan_id": plan["id"], "execute": True},
            {"plan_id": plan["id"], "max_requests": 1000000},
        ]:
            response = client.post("/api/mars/jobs", json=body)
            assert response.status_code in (404, 422), (body, response.text)
        for path in ["/api/mars/jobs", "/api/mars/jobs/anything/review",
                     "/api/mars/jobs/anything/cancel"]:
            assert client.post(path, json={"plan_id": plan["id"]},
                               headers={"Origin": "https://evil.example"}).status_code == 403
        assert client.get("/api/mars/jobs/anything").status_code == 422
        assert client.get("/api/mars/jobs/anything/events").status_code == 422
        assert client.get("/api/mars/jobs").json() == []


def test_job_scope_review_rechecks_registry(tmp_path, monkeypatch):
    with TestClient(app(tmp_path)) as client:
        plan = create_plan(client)
        job = client.post("/api/mars/jobs", json={"plan_id":plan["id"]}).json()
        import dashboard.api.mars_plans as workspace
        monkeypatch.setattr(workspace, "registered_catalog", lambda _: {
            "target_id": "vulnerable-store", "registered_assessments": [],
        })
        response = client.post(f'/api/mars/jobs/{job["id"]}/review', json={})
        assert response.status_code == 409
        assert client.get(f'/api/mars/jobs/{job["id"]}').json()["state"] == "awaiting_review"
        assert len(client.get(f'/api/mars/jobs/{job["id"]}/events').json()) == 1
