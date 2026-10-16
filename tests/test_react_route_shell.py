"""M10: React deep links never impersonate missing bundled assets."""
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from dashboard.api.console import ReactRouteFiles, create_console_app


def test_spa_deep_links_and_asset_misses(tmp_path: Path) -> None:
    (tmp_path / "index.html").write_text("<html>MARS test shell</html>")
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "app.js").write_text("console.log('ok')")
    app = FastAPI()
    app.mount("/dashboard", ReactRouteFiles(directory=tmp_path, html=True))
    with TestClient(app) as client:
        for route in ("/assessments", "/findings", "/remediation", "/reports/metrics", "/system", "/not-a-route"):
            response = client.get("/dashboard" + route)
            assert response.status_code == 200, route
            assert "MARS test shell" in response.text
            assert response.headers["content-type"].startswith("text/html")
        assert client.get("/dashboard/assets/app.js").status_code == 200
        for asset in ("/assets/missing.js", "/assets/missing.css", "/favicon.ico", "/assets/missing"):
            response = client.get("/dashboard" + asset)
            assert response.status_code == 404
            assert "MARS test shell" not in response.text


def test_legacy_console_keeps_root_and_api() -> None:
    with TestClient(create_console_app()) as client:
        root = client.get("/")
        assert root.status_code == 200
        assert "Sentinel" in root.text
        status = client.get("/api/console/status")
        assert status.status_code == 200
        assert status.json()["experience_mode"] == "DISABLED"


def test_old_research_url_redirects_without_second_dashboard() -> None:
    with TestClient(create_console_app(), follow_redirects=False) as client:
        for old, expected in (
            ("/research-dashboard", "/dashboard/"),
            ("/research-dashboard/", "/dashboard/"),
            ("/research-dashboard/reports/metrics?view=all", "/dashboard/reports/metrics?view=all"),
        ):
            response = client.get(old)
            assert response.status_code in (307, 308)
            assert response.headers["location"] == expected
