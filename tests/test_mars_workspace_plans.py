"""MARS draft lifecycle. Never executes a target or modifies research records."""
from fastapi.testclient import TestClient
from dashboard.api.console import create_console_app


def test_draft_plan_create_list_delete_and_reopen(tmp_path):
    storage = tmp_path / "mars_workspace.sqlite3"
    with TestClient(create_console_app(database_path="/does/not/exist.sqlite",
                                       mars_workspace_db=storage)) as client:
        assert client.get("/api/mars/plans").json() == []
        created = client.post("/api/mars/plans",
                              json={"name":"SQLi baseline review", "scenario":"sql"})
        assert created.status_code == 201, created.text
        item = created.json()
        assert item["name"] == "SQLi baseline review"
        assert item["scenario"] == "sql"
        assert item["registered_test_id"] == "sqli-login-bypass-001"
        assert item["target_id"] == "vulnerable-store"
        assert item["status"] == "draft"
        assert item["executed"] is False
        assert item["execution_enabled"] is False
        assert item["final_research_qualified"] is False
        assert client.get("/api/mars/plans").json()[0]["id"] == item["id"]
        assert client.get(f'/api/mars/plans/{item["id"]}').json()["name"] == item["name"]
    with TestClient(create_console_app(database_path="/does/not/exist.sqlite",
                                       mars_workspace_db=storage)) as reopened:
        assert reopened.get("/api/mars/plans").json()[0]["id"] == item["id"]
        deleted = reopened.delete(f'/api/mars/plans/{item["id"]}')
        assert deleted.status_code == 204
        assert reopened.get("/api/mars/plans").json() == []
        assert reopened.get(f'/api/mars/plans/{item["id"]}').status_code == 404


def test_plans_reject_unregistered_and_mutation_attacks(tmp_path):
    with TestClient(create_console_app(database_path="/not/a/database.sqlite",
                                       mars_workspace_db=tmp_path/"plans.sqlite3")) as client:
        for body in [
            {"name":"external", "scenario":"https://example.com"},
            {"name":"out of scope", "scenario":"sql", "target":"external"},
            {"name":"", "scenario":"sql"},
            {"name":"X"*100, "scenario":"xss"},
            {"name":"ok", "scenario":"traversal", "run_test":True},
        ]:
            assert client.post("/api/mars/plans",json=body).status_code == 422
        foreign={"Origin":"https://evil.example"}
        assert client.post("/api/mars/plans",json={"name":"a test", "scenario":"sql"},headers=foreign).status_code == 403
        assert client.delete("/api/mars/plans/does-not-exist",headers=foreign).status_code == 403
        assert client.delete("/api/mars/plans/not-found").status_code == 404
        assert client.get("/api/mars/plans").json() == []
