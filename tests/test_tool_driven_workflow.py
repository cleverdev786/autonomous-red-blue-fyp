"""Offline operational Red/Blue smoke: registered attacks -> deterministic patch -> replay."""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dashboard.api.console import create_console_app
from services.tool_driven_workflow import OfflineWorkflowBlocked, run_offline_cycle

ROOT = Path(__file__).resolve().parents[1]

@pytest.mark.parametrize("scenario", ("sql", "xss", "traversal"))
def test_real_registered_baseline_and_patched_replay_in_isolated_sandbox(scenario):
    protected = ROOT / "dummy_apps/vulnerable_store/app/scenario_routes.py"
    before = protected.read_bytes()
    result = run_offline_cycle(scenario, project_root=ROOT)
    assert result["scenario"] == scenario
    assert result["registered_red_confirmed"] is True
    assert result["patched_security_test_passed"] is True
    assert result["baseline_control_passed"] is True
    assert result["patched_control_passed"] is True
    assert result["normal_application_passed"] is True
    assert result["patch_prepared"] is True
    assert result["source_location_verified"] is True
    assert result["result"] == "sandbox_verified"
    assert result["model_used"] is False
    assert result["live_source_modified"] is False
    assert result["docker_replayed"] is False
    assert protected.read_bytes() == before

@pytest.mark.parametrize("bad", ("", "unknown", "../foo", "http://somewhere"))
def test_unknown_scenario_never_executes(bad):
    with pytest.raises(OfflineWorkflowBlocked):
        run_offline_cycle(bad, project_root=ROOT)

def test_api_rejects_arbitrary_scenario_and_other_origin():
    with TestClient(create_console_app()) as client:
        response = client.post("/api/console/workflows/offline", json={"scenario":"../foo"})
        assert response.status_code == 422
        response = client.post("/api/console/workflows/offline", json={"scenario":"sql"},
                               headers={"Origin":"https://example.com"})
        assert response.status_code == 403

def test_api_runs_registered_offline_cycle():
    with TestClient(create_console_app()) as client:
        response = client.post("/api/console/workflows/offline", json={"scenario":"sql"})
    assert response.status_code == 200, response.text
    assert response.json()["result"] == "sandbox_verified"

def test_tampered_source_is_refused_before_any_security_request(tmp_path):
    source = tmp_path / "dummy_apps/vulnerable_store/app/scenario_routes.py"
    source.parent.mkdir(parents=True)
    source.write_bytes((ROOT / "dummy_apps/vulnerable_store/app/scenario_routes.py").read_bytes() + b"\n# drift")
    with pytest.raises(OfflineWorkflowBlocked, match="source_snapshot_not_trusted"):
        run_offline_cycle("sql", project_root=tmp_path)


def test_symlinked_source_is_never_followed(tmp_path):
    target = ROOT / "dummy_apps/vulnerable_store/app/scenario_routes.py"
    source = tmp_path / "dummy_apps/vulnerable_store/app/scenario_routes.py"
    source.parent.mkdir(parents=True)
    source.symlink_to(target)
    with pytest.raises(OfflineWorkflowBlocked, match="source_snapshot_not_trusted"):
        run_offline_cycle("xss", project_root=tmp_path)
