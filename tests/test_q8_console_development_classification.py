"""Q8/C12 real-controller behavior with mocked model transport, no model run."""
from __future__ import annotations

import importlib
import json

import pytest
from fastapi.testclient import TestClient

from dashboard.api.q8_development_service import (
    Q8Demonstration,
    _frozen_system,
    run_q8_development_classification,
)
from services.q8_c12_development_bridge import MODEL_SHA256

ui = importlib.import_module("dashboard.api.console")
service = importlib.import_module("dashboard.api.q8_development_service")


def test_external_c12_classifier_system_is_integrity_pinned():
    system = _frozen_system()
    assert "two HTTP observations" in system
    assert "do not infer a vulnerability" in system


def test_console_q8_status_reports_disabled_research_and_source(monkeypatch):
    monkeypatch.setattr(service.manager, "status", lambda: {"state": "unloaded"})
    with TestClient(ui.create_console_app(database_path="/nonexistent/dev.sqlite")) as client:
        data = client.get("/api/console/q8/status").json()
        assert data["status"] == "not_ready"
        assert data["registered_tests_enabled"] is False
        assert data["patch_preparation_enabled"] is False
        assert data["source_localization_enabled"] is False
        assert data["final_research_qualified"] is False
        assert len(data["examples"]) == 4


def test_wrong_origin_rejected_without_inference(monkeypatch):
    called = []
    monkeypatch.setattr(ui, "run_q8_development_classification", lambda _: called.append("CALLED"))
    with TestClient(ui.create_console_app(database_path="/nonexistent/dev.sqlite")) as client:
        response = client.post("/api/console/q8/classify",
                               json={"example": "ordinary_search"},
                               headers={"Origin": "https://untrusted.example"})
        assert response.status_code == 403
        assert called == []


@pytest.mark.parametrize("payload", [
    {"example": "external"},
    {"example": "ordinary_search", "command": "run_test"},
    {"example": 42},
])
def test_ui_rejects_invalid_case_or_extra_control_fields(payload):
    with TestClient(ui.create_console_app(database_path="/nonexistent/dev.sqlite")) as client:
        assert client.post("/api/console/q8/classify",json=payload).status_code == 422


def test_rejects_unloaded_model_before_any_network_call(monkeypatch):
    monkeypatch.setattr(service.manager, "probe_busy", lambda: False)
    monkeypatch.setattr(service.manager, "finish_probe", lambda: None)
    monkeypatch.setattr(service.manager, "status", lambda: {"state": "unloaded"})
    monkeypatch.setattr(service, "_raw_completion",lambda *a: pytest.fail("network must not be attempted"))
    with pytest.raises(service.OperatorError, match="Load the verified"):
        run_q8_development_classification(Q8Demonstration(example="ordinary_search"))


def test_rejects_concurrent_operation_before_model_access(monkeypatch):
    monkeypatch.setattr(service.manager, "probe_busy", lambda: True)
    monkeypatch.setattr(service.manager, "status", lambda: pytest.fail("busy must deny"))
    with pytest.raises(service.OperatorError, match="Another model inference"):
        run_q8_development_classification(Q8Demonstration(example="ordinary_search"))


def _fake_ready(monkeypatch):
    monkeypatch.setattr(service.manager, "probe_busy", lambda: False)
    releases = []
    monkeypatch.setattr(service.manager, "finish_probe", lambda: releases.append(True))
    monkeypatch.setattr(service.manager, "status",
        lambda: {"state":"running","sha256":MODEL_SHA256,
                 "filename":"c08b-nf4-effective-Q8_0.gguf","port":18476})
    return releases


def test_model_classification_validated_and_raw_evidence_saved(monkeypatch,tmp_path):
    releases=_fake_ready(monkeypatch)
    monkeypatch.setattr(service, "_frozen_system",lambda: "two HTTP observations, benign restraint")
    monkeypatch.setattr(service, "_call_evidence_directory",lambda: tmp_path)
    sent=[]
    def returned(port,prompt):
        sent.append(prompt)
        return {"content":json.dumps({"classification":"benign","confidence":0.8,
                                      "reason":"No successful injection behavior."}),
                "truncated":False}
    monkeypatch.setattr(service,"_raw_completion",returned)
    result=run_q8_development_classification(Q8Demonstration(example="ordinary_search"))
    assert result["result"]["decision"]["classification"]=="benign"
    assert result["result"]["preliminary_blue_action"]=="no_action"
    assert result["assessment_plan"]["operational_verdict"]=="benign_unverified_requires_trusted_safe_evidence"
    assert result["assessment_plan"]["registered_test_id"] is None
    assert result["assessment_plan"]["evidence_policy_result"]=="trusted_safe_evidence_required"
    assert result["assessment_plan"]["registered_test_execution_authorized"] is False
    assert len(result["assessment_plan"]["stages"])==8
    assert result["source_analysis_authorized"] is False
    assert result["patch_prepared"] is False
    assert result["synthetic_observations_only"] is True
    assert result["model_not_independently_qualified"] is True
    assert result["registered_test_executed"] is False
    assert result["evidence_id"]==tmp_path.name
    assert len(releases)==1
    assert len(sent)==1 and "ground_truth" not in sent[0] and "expected" not in sent[0]
    for name in ("q8-input.json","q8-raw-completion.json","q8-gateway.json","q8-assessment-plan.json"):
        assert (tmp_path/name).exists()
        assert (tmp_path/name).stat().st_mode & 0o777 == 0o600


def test_schema_failure_keeps_raw_response_and_releases_slot(monkeypatch,tmp_path):
    releases=_fake_ready(monkeypatch)
    monkeypatch.setattr(service,"_call_evidence_directory",lambda:tmp_path)
    monkeypatch.setattr(service,"_frozen_system",lambda:"two HTTP observations")
    monkeypatch.setattr(service,"_raw_completion",
        lambda *_: {"content":json.dumps({"classification":"benign","confidence":0.5,
                            "reason":"ok","run_shell":True}),"truncated":False})
    with pytest.raises(service.OperatorError,match="typed validation"):
        run_q8_development_classification(Q8Demonstration(example="ordinary_search"))
    assert (tmp_path/"q8-raw-completion.json").is_file()
    assert (tmp_path/"q8-gateway.json").is_file()
    assert releases==[True]


def test_q8_backend_preserved_without_sentinel_dashboard():
    with TestClient(ui.create_console_app(database_path="/nonexistent/dev.sqlite"),
                    follow_redirects=False) as client:
        root = client.get("/")
        assert root.status_code == 307
        assert root.headers["location"] == "/dashboard/"
        assert client.get("/console.js").status_code == 404
        assert client.get("/api/console/q8/status").status_code == 200
        assert client.get("/api/console/status").status_code == 200
