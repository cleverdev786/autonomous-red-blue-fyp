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
    response = client.get("/")
    assert response.status_code == 200
    assert "MARS" in response.text
    assert client.get("/console.css").status_code == 404
    assert client.get("/console.js").status_code == 404
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


def test_root_opens_mars_instead_of_sentinel(client):
    from fastapi.testclient import TestClient
    with TestClient(create_console_app(), follow_redirects=False) as http:
        response = http.get("/")
        assert response.status_code == 307
        assert response.headers["location"] == "/dashboard/"
        assert http.get("/console.js").status_code == 404
        assert http.get("/console.css").status_code == 404


def test_react_dashboard_static_mount_and_missing_build(tmp_path, monkeypatch):
    """A React build is inert same-origin content; the operator console survives its absence."""
    from fastapi.testclient import TestClient

    from dashboard.api import console

    built = tmp_path / "dist"
    (built / "assets").mkdir(parents=True)
    (built / "index.html").write_text('<html><body><div id="root"></div></body></html>')
    (built / "assets" / "app.js").write_text('console.log("read-only build");')
    monkeypatch.setattr(console, "REACT_DIST", built)
    with TestClient(console.create_console_app(database_path="/nonexistent/react-demo.sqlite")) as client:
        assert client.get("/").status_code == 200
        home = client.get("/dashboard/")
        assert home.status_code == 200 and 'id="root"' in home.text
        asset = client.get("/dashboard/assets/app.js")
        assert asset.status_code == 200 and "read-only build" in asset.text
        assert client.post("/dashboard/").status_code == 405
        assert client.get("/dashboard/../../.env").status_code in (404, 405)
        with TestClient(console.create_console_app(database_path="/nonexistent/react-demo.sqlite"),
                        follow_redirects=False) as no_redirect:
            assert no_redirect.get("/").headers["location"] == "/dashboard/"

    monkeypatch.setattr(console, "REACT_DIST", tmp_path / "missing")
    with TestClient(console.create_console_app(database_path="/nonexistent/react-demo.sqlite")) as client:
        with TestClient(console.create_console_app(database_path="/nonexistent/react-demo.sqlite"),
                        follow_redirects=False) as no_redirect:
            assert no_redirect.get("/").headers["location"] == "/dashboard/"
        missing = client.get("/dashboard/")
        assert missing.status_code == 503
        assert "npm run build" in missing.json()["detail"]


def test_model_unload_scope_failure_is_controlled_http_error(client, monkeypatch):
    """A failed scope stop cannot be reported as an unloaded model."""
    from dashboard.api import console

    def refuse_stop():
        raise OperatorError("Could not confirm the model scope stopped")

    with monkeypatch.context() as patches:
        patches.setattr(console.manager, "stop", refuse_stop)
        response = client.post("/api/console/models/unload", json={})
        assert response.status_code == 400
        assert "Could not confirm" in response.json()["detail"]


def test_downloadable_evidence_summary_redacts_raw_records(client, monkeypatch):
    """Export summarizes pinned reviews without leaking source data or authorization."""
    from dashboard.api import console

    canary = "PRIVATE_SOURCE_AND_MODEL_RESPONSE_DO_NOT_EXPORT"
    monkeypatch.setattr(
        console, "review_pinned_registered_red",
        lambda root: {
            "status": "verified_archived_red", "registered_test_id": "sqli-login-bypass-001",
            "red_run_id": "baseline-01", "exploit_confirmed": True, "raw_response": canary,
        },
    )
    monkeypatch.setattr(
        console, "review_archived_assessment",
        lambda root: {
            "status": "evidence_bound", "registered_test_id": "sqli-login-bypass-001",
            "red_run_id": "baseline-01",
            "model_decision": {"classification": "sql_injection", "reason": canary},
            "local_source_path": canary,
        },
    )
    monkeypatch.setattr(
        console, "review_pinned_patched_replay",
        lambda root: {
            "status": "verified_archived_patched_replay", "run_id": "patched-01",
            "exploit_confirmed": False, "legitimate_login_verified": True,
            "search_file_verified": True, "docker_secret": canary,
        },
    )
    monkeypatch.setattr(
        console, "review_pinned_phase5_replays",
        lambda root: {
            "status": "verified_archived_phase5_replays", "replay_count": 2,
            "results": {"xss": {"run_id": "xss-patched"}, "traversal": {"run_id": "trav-patched"}},
            "patched_docker_functional_verified": False, "raw_request_body": canary,
        },
    )

    response = client.get("/api/console/assessment/export")
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Content-Disposition"].startswith("attachment;")
    assert response.json()["schema_version"] == "sentinel-development-evidence-summary-v1"
    assert response.json()["archives"]["registered_red"]["exploit_confirmed"] is True
    assert response.json()["archives"]["patched_xss_traversal"]["patched_docker_functional_verified"] is False
    assert response.json()["final_research_qualified"] is False
    assert canary not in response.text
    assert client.post("/api/console/assessment/export").status_code == 405


def test_mars_frontend_accessibility_sources_remain_available():
    root = Path(__file__).resolve().parents[1]
    app = (root / "dashboard/frontend/src/App.tsx").read_text()
    css = (root / "dashboard/frontend/src/styles.css").read_text()
    assert 'className="skip-to-content"' in app
    assert 'id="main-content" tabIndex={-1}' in app
    assert ":focus-visible" in css or ":focus-visible" in (
        root / "dashboard/frontend/src/product.css"
    ).read_text()
    assert "/api/console/assessment/export" in app
    assert "Run offline Red → Blue verification" in app


def test_evidence_export_without_approvals_does_not_claim_success(client, monkeypatch):
    for key in (
        "FYP_REGISTERED_RED_DISPLAY_PATH", "FYP_REGISTERED_RED_DISPLAY_SHA256",
        "FYP_ASSESSMENT_APPROVAL_PATH", "FYP_ASSESSMENT_APPROVAL_SHA256",
        "FYP_PATCHED_REPLAY_APPROVAL_PATH", "FYP_PATCHED_REPLAY_APPROVAL_SHA256",
        "FYP_PHASE5_REPLAY_APPROVAL_PATH", "FYP_PHASE5_REPLAY_APPROVAL_SHA256",
    ):
        monkeypatch.delenv(key, raising=False)
    payload = client.get("/api/console/assessment/export").json()
    assert all(record["status"] != "verified_archived_red"
               for record in payload["archives"].values())
    assert all(record["status"] not in (
        "evidence_bound", "verified_archived_patched_replay",
        "verified_archived_phase5_replays",
    ) for record in payload["archives"].values())
    assert payload["final_research_qualified"] is False
