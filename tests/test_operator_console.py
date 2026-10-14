"""Sandbox-only console acceptance. No Docker, model weights or live Red dispatch."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from dashboard.api.console import create_console_app
from dashboard.api.operator_service import (
    OperatorError,
    ProbeRequest,
    _checked_local_path,
    _reject_bad_name,
    manager,
)
from services.trusted_remediation_compiler import EXPECTED_SOURCE_SHA256


@pytest.fixture
def client():
    app = create_console_app(database_path="/this/does/not/exist.sqlite")
    with TestClient(app) as instance:
        yield instance


def test_console_start_without_database(client):
    assert client.get("/").status_code == 200
    assert client.get("/console.css").status_code == 200
    assert client.get("/console.js").status_code == 200
    assert "Sentinel" in client.get("/").text
    assert client.get("/api/overview").json()["total_runs"] == 0
    assert client.get("/api/runs").json() == []
    state = client.get("/api/console/status").json()
    assert state["experiment_db"] is False
    assert state["experience_mode"] == "DISABLED"
    assert state["rq1_final_runs_verified_here"] is None


def test_only_three_registered_synthetic_targets(client):
    scenarios = client.get("/api/console/scenarios").json()
    assert [item["id"] for item in scenarios] == ["sql", "xss", "traversal"]
    assert {x["registered_test"] for x in scenarios} == {
        "sqli-login-bypass-001",
        "xss-reflection-001",
        "path-traversal-private-file-001",
    }


@pytest.mark.parametrize("name", ["sql", "xss", "traversal"])
def test_existing_compiler_prepares_one_source_only_without_execution(client, name):
    result = client.post("/api/console/preview", json={"scenario": name})
    assert result.status_code == 200
    value = result.json()
    assert value["prepared"] is True
    assert value["applied"] is False and value["verified"] is False
    assert value["final_research"] is False
    assert value["source_sha256"] == EXPECTED_SOURCE_SHA256
    assert len(value["prepared_diff_sha256"]) == 64
    assert value["diff_preview"].startswith("---")
    assert value["steps"][-1]["status"] == "not executed"


def test_rejects_unregistered_scenario_and_unknown_fields(client):
    assert client.post("/api/console/preview", json={"scenario": "external"}).status_code == 422
    assert (
        client.post("/api/console/preview", json={"scenario": "sql", "shell": "rm"}).status_code
        == 422
    )


def test_mutation_denies_foreign_origin(client):
    headers = {"Origin": "https://example.org"}
    assert (
        client.post("/api/console/preview", json={"scenario": "sql"}, headers=headers).status_code
        == 403
    )
    assert client.post("/api/console/models/unload", json={}, headers=headers).status_code == 403


def test_model_paths_allow_only_listed_regular_gguf(tmp_path):
    model = tmp_path / "specialist.gguf"
    model.write_bytes(b"synthetic")
    assert _checked_local_path(tmp_path, "specialist.gguf") == model
    alias = tmp_path / "alias.gguf"
    alias.symlink_to(model)
    for value in (
        "../specialist.gguf",
        "/etc/passwd",
        "subdir/model.gguf",
        "alias.gguf",
        "model.safetensors",
    ):
        with pytest.raises(OperatorError):
            _checked_local_path(tmp_path, value)
    for value in ("; rm -rf ~", "../../model", "wrong model", ""):
        with pytest.raises(OperatorError):
            _reject_bad_name(value)


def test_local_launch_rejects_missing_configuration_without_process(client, monkeypatch):
    monkeypatch.delenv("FYP_MODEL_DIRECTORY", raising=False)
    response = client.post(
        "/api/console/models/load", json={"filename": "some.gguf", "model_name": "specialist"}
    )
    assert response.status_code == 400
    assert "FYP_MODEL_DIRECTORY" in response.json()["detail"]


def test_api_provider_rejects_arbitrary_url_or_missing_key(client):
    bad = client.post(
        "/api/console/models/probe",
        json={"source": "api", "model_name": "my-model", "provider": "http://127.0.0.1"},
    )
    assert bad.status_code == 400
    assert (
        client.post(
            "/api/console/models/probe",
            json={"source": "api", "model_name": "model-1", "provider": "openai"},
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/console/models/probe",
            json={
                "source": "api",
                "model_name": "bad name",
                "provider": "openai",
                "api_key": "secret",
            },
        ).status_code
        == 400
    )


def test_capability_check_is_bounded_and_only_classification(monkeypatch, tmp_path):
    import dashboard.api.operator_service as service

    monkeypatch.setenv("FYP_CONSOLE_EVIDENCE_DIR", str(tmp_path / "external-evidence"))
    requests = []

    def response(request):
        requests.append(request)
        assert request.url.host == "api.openai.com"
        assert request.headers["authorization"] == "Bearer synthetic-secret"
        body = json.loads(request.content)
        assert body["stream"] is False
        assert body["response_format"]["type"] == "json_schema"
        assert "ground_truth" not in json.dumps(body)
        expected = [
            ("sql_injection", "vulnerable_login", "sqli-login-bypass-001"),
            ("xss", "vulnerable_search", "xss-reflection-001"),
            ("path_traversal", "vulnerable_file_read", "path-traversal-private-file-001"),
            ("benign", None, None),
        ]
        cls, function, test_id = expected[len(requests) - 1]
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "content": json.dumps(
                                {
                                    "classification": cls,
                                    "confidence": 0.9,
                                    "reason": "synthetic",
                                    "file_path": "dummy_apps/vulnerable_store/app/scenario_routes.py"
                                    if function
                                    else None,
                                    "function_or_route": function,
                                    "registered_test_id": test_id,
                                    "no_action": cls == "benign",
                                }
                            )
                        },
                    }
                ]
            },
        )

    monkeypatch.setattr(
        service,
        "_no_external_redirects",
        lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(response), follow_redirects=False, trust_env=False
        ),
    )
    result = asyncio.run(
        service.probe_capability(
            ProbeRequest(
                source="api",
                model_name="valid-model",
                provider="openai",
                api_key="synthetic-secret",
            )
        )
    )
    assert len(requests) == 4
    assert result["capable_for_demo"] is True
    assert result["final_research_eligible"] is False
    assert "synthetic-secret" not in json.dumps(result)
    evidence = Path(result["evidence_directory"])
    assert evidence.is_dir()
    assert len(list(evidence.glob("call-*-request.json"))) == 4
    assert len(list(evidence.glob("call-*-response.raw"))) == 4
    assert len(list(evidence.glob("call-*-receipt.json"))) == 4
    for number in range(1, 5):
        name = f"call-{number:02d}"
        receipt = json.loads((evidence / f"{name}-receipt.json").read_text())
        assert (
            receipt["request_sha256"]
            == __import__("hashlib")
            .sha256((evidence / f"{name}-request.json").read_bytes())
            .hexdigest()
        )
        assert (
            receipt["response_sha256"]
            == __import__("hashlib")
            .sha256((evidence / f"{name}-response.raw").read_bytes())
            .hexdigest()
        )
        assert receipt["automatic_retries"] == 0
        assert receipt["usage_status"] == "NOT_REPORTED"
    assert "synthetic-secret" not in "".join(x.read_text() for x in evidence.iterdir())


def test_capability_check_preserves_bad_schema_failure(monkeypatch, tmp_path):
    import dashboard.api.operator_service as service

    monkeypatch.setenv("FYP_CONSOLE_EVIDENCE_DIR", str(tmp_path / "external-evidence"))
    calls = []

    def response(request):
        calls.append(request)
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "content": '{"classification":"xss","confidence":0.6,"reason":"a","extra":"invalid"}'
                        },
                    }
                ]
            },
        )

    monkeypatch.setattr(
        service,
        "_no_external_redirects",
        lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(response), follow_redirects=False, trust_env=False
        ),
    )
    result = asyncio.run(
        service.probe_capability(
            ProbeRequest(
                source="api",
                model_name="valid-model",
                provider="openai",
                api_key="synthetic-secret",
            )
        )
    )
    assert len(calls) == 4
    assert result["capable_for_demo"] is False
    assert all(row["status"] == "fail" for row in result["results"])


def test_no_model_key_or_state_in_existing_config(client):
    manager.stop()
    local = client.get("/api/console/models/local").json()
    assert local["active"]["final_research_ready"] is False
    assert set(local["providers"]) == {"openai", "groq", "together"}


def test_live_browser_boot_script_avoids_window_top_collision(client):
    """Regression: Window.top is unforgeable in Chromium/Firefox browser globals."""
    page = client.get("/")
    assert page.status_code == 200
    assert "console.js?v=4" in page.text
    assert "Workspace could not initialize" in page.text
    assert page.headers["cache-control"] == "no-store"
    script = client.get("/console.js")
    assert script.status_code == 200
    assert script.headers["cache-control"] == "no-store"
    assert "function top(" not in script.text
    assert "function pageIntro(" in script.text
    assert "AbortController" in script.text
    css = client.get("/console.css")
    assert css.headers["cache-control"] == "no-store"
    assert "fonts.googleapis.com" not in css.text
