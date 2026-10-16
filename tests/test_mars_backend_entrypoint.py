"""Stable MARS backend import and compatibility contract."""
from pathlib import Path

from fastapi.testclient import TestClient


def test_backend_package_resolves_same_live_fastapi_application():
    from backend.app import app
    from dashboard.api.console import app as existing

    assert app is existing


def test_backend_factory_preserves_existing_routes_and_mars_jobs(tmp_path):
    from backend.app import create_app

    app = create_app(
        database_path=tmp_path / "unconfigured-research.sqlite3",
        mars_workspace_db=tmp_path / "workspace.sqlite3",
    )
    with TestClient(app) as client:
        assert client.get("/api/mars/plans").json() == []
        assert client.get("/api/mars/jobs").json() == []
        assert client.get("/dashboard/").status_code in (200, 503)
        assert client.get("/").status_code == 200
        assert client.get("/research-dashboard/", follow_redirects=False).status_code == 307
        # A canonical entrypoint cannot relax the existing dispatch gate.
        assert client.post("/api/mars/jobs/00000000-0000-4000-8000-000000000001/start",
                           json={}).status_code == 404
