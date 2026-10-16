"""W3-B1 execution-request export never grants execution authority."""
import hashlib
import json

from fastapi.testclient import TestClient
from dashboard.api.console import create_console_app


def client(tmp_path):
    return TestClient(create_console_app(
        database_path="/nonexistent/research.db",
        mars_workspace_db=tmp_path / "workspace.sqlite3",
    ))


def make_job(c, scenario="sql"):
    draft = c.post("/api/mars/plans", json={
        "name": "Review " + scenario, "scenario": scenario,
    })
    assert draft.status_code == 201, draft.text
    job = c.post("/api/mars/jobs", json={"plan_id": draft.json()["id"]})
    assert job.status_code == 201, job.text
    return job.json()


def test_execution_request_requires_review_and_remains_unapproved(tmp_path):
    with client(tmp_path) as c:
        job = make_job(c)
        url = f'/api/mars/jobs/{job["id"]}/execution-request'
        before = c.get(f'/api/mars/jobs/{job["id"]}/events').json()
        assert c.get(url).status_code == 409
        assert c.post(f'/api/mars/jobs/{job["id"]}/review', json={}).status_code == 200
        events = c.get(f'/api/mars/jobs/{job["id"]}/events').json()
        res = c.get(url)
        assert res.status_code == 200
        assert "attachment" in res.headers["content-disposition"]
        packet = res.json()
        assert packet["schema_version"] == "mars-execution-request-v1"
        assert packet["purpose"] == "independent_admission_review"
        assert packet["job_id"] == job["id"]
        assert packet["plan_id"] == job["plan_id"]
        assert packet["target_id"] == "vulnerable-store"
        assert packet["registered_test_id"] == "sqli-login-bypass-001"
        assert packet["scenario_id"] == "sqli-login-001"
        assert packet["scope_sha256"] == job["scope_sha256"]
        scope_fields = ("target_id", "endpoint_id", "registered_test_id", "method",
                        "endpoint_path", "max_requests", "timeout_seconds", "route")
        digest = hashlib.sha256(json.dumps(
            {key: packet[key] for key in scope_fields},
            sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest()
        assert digest == packet["scope_sha256"]
        assert packet["endpoint_path"] == job["endpoint_path"]
        assert packet["max_requests"] == job["max_requests"]
        assert packet["timeout_seconds"] == job["timeout_seconds"]
        assert packet["admission_granted"] is False
        assert packet["execution_authorized"] is False
        assert packet["final_research_qualified"] is False
        assert "source_head" not in packet
        assert "docker_container_id" not in packet
        assert c.get(url).json() == packet  # idempotent GET
        assert c.get(f'/api/mars/jobs/{job["id"]}/events').json() == events
        assert before != events
        assert c.post(f'/api/mars/jobs/{job["id"]}/start', json={}).status_code == 409
        assert c.post(f'/api/mars/jobs/{job["id"]}/cancel', json={}).status_code == 200
        assert c.get(url).status_code == 409


def test_execution_request_rejects_stale_registry_and_orphan(tmp_path, monkeypatch):
    with client(tmp_path) as c:
        job = make_job(c, "xss")
        url = f'/api/mars/jobs/{job["id"]}/execution-request'
        assert c.post(f'/api/mars/jobs/{job["id"]}/review', json={}).status_code == 200
        packet = c.get(url).json()
        assert packet["scenario_id"] == "xss-search-001"
        import dashboard.api.mars_plans as plans
        monkeypatch.setattr(plans, "registered_catalog", lambda _: {
            "target_id": "vulnerable-store", "registered_assessments": [],
        })
        response = c.get(url)
        assert response.status_code == 409
        assert c.get(f'/api/mars/jobs/{job["id"]}').json()["state"] == "scope_reviewed"
        assert c.get(f'/api/mars/jobs/{job["id"]}/events').json()[-1]["event"] == "scope_reviewed"
        assert c.get("/api/mars/jobs/00000000-0000-4000-8000-000000000001/execution-request").status_code == 404


def test_execution_request_rejects_deleted_draft(tmp_path):
    with client(tmp_path) as c:
        job = make_job(c, "traversal")
        assert c.post(f'/api/mars/jobs/{job["id"]}/review', json={}).status_code == 200
        # Simulate pre-existing orphaned data without permitting a normal deletion.
        import sqlite3
        with sqlite3.connect(tmp_path / "workspace.sqlite3") as db:
            db.execute("DELETE FROM plans WHERE id=?", (job["plan_id"],))
        assert c.get(f'/api/mars/jobs/{job["id"]}/execution-request').status_code == 409



def test_execution_request_refuses_mutated_job_fields(tmp_path):
    with client(tmp_path) as c:
        job = make_job(c)
        assert c.post(f'/api/mars/jobs/{job["id"]}/review', json={}).status_code == 200
        import sqlite3
        with sqlite3.connect(tmp_path / "workspace.sqlite3") as db:
            db.execute("UPDATE jobs SET endpoint_path='/other' WHERE id=?", (job["id"],))
        assert c.get(f'/api/mars/jobs/{job["id"]}/execution-request').status_code == 409
        assert c.post(f'/api/mars/jobs/{job["id"]}/start', json={}).status_code == 409
