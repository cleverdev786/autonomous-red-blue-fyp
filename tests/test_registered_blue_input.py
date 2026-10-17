"""Real-receipt-bound, read-only model input for XSS and traversal.

No actual Docker or model calls occur in these tests.
"""
from hashlib import sha256
from uuid import UUID

import pytest

from test_isolated_compose_executor import configured
from test_mars_dispatch_intent import seeded_job
from services.mars_dispatch_intent import reserve_once
from services.receipt_record import record_receipt

pytest_plugins = ("test_isolated_compose_executor",)


@pytest.fixture(params=[
    ("xss", "xss-search-001", "xss-reflection-001", "/xss/search", "q"),
    ("traversal", "path-traversal-read-001",
     "path-traversal-private-file-001", "/path-traversal/read", "path"),
])
def bound_case(tmp_path, environment, request):
    scenario, scenario_id, test_id, route, parameter = request.param
    database, job = seeded_job(tmp_path, scenario=scenario)
    root, external, admission_file, pin, registry = environment
    case = "mars-" + UUID(job["id"]).hex
    pin = pin.model_copy(update={
        "case_id": case, "run_id": case, "scenario_id": scenario_id,
    })
    admission_file.write_bytes(pin.canonical_bytes())
    digest = sha256(pin.canonical_bytes()).hexdigest()
    reserve_once(database, job["id"], job["scope_sha256"], digest)
    runner, _calls, dispatches, _payload = configured(
        (root, external, admission_file, pin, registry), scenario=scenario_id,
    )
    receipt = runner.run_registered()
    assert receipt.outcome == "baseline_exploit_confirmed"
    assert len(dispatches) == 1
    stored = record_receipt(database, job["id"], external / "evidence", receipt)
    arguments = {
        "database": database, "job_id": job["id"], "source_root": root,
        "evidence_dir": external / "evidence" / case,
        "admission_path": admission_file, "admission_sha256": digest,
        "receipt_sha256": stored["receipt_sha256"],
    }
    return arguments, scenario_id, test_id, route, parameter


def test_non_sql_model_input_uses_only_registered_requests_and_actual_responses(bound_case):
    from services.blue_input import build_registered_blue_input

    args, scenario_id, test_id, route, parameter = bound_case
    result = build_registered_blue_input(**args)
    assert result["scenario_id"] == scenario_id
    assert result["registered_test_id"] == test_id
    assert result["model_executed"] is False
    assert result["source_analysis_authorized"] is False
    assert result["patch_prepared"] is False
    pair = result["classification_request"]["input"]
    assert pair["route"] == route
    assert len(pair["observations"]) == 2
    assert all(row["method"] == "GET" for row in pair["observations"])
    assert all(set(row["parameters"]) == {parameter} for row in pair["observations"])
    assert pair["observations"][0]["status_code"] == 200
    assert pair["observations"][1]["status_code"] == 200
    assert result["localization_request"]["input"]["source_sha256"]
    assert "numbered_candidate_functions" in result["localization_request"]["input"]


@pytest.mark.parametrize("alter", ["admission", "receipt", "source", "raw"])
def test_non_sql_input_rejects_changed_provenance(bound_case, alter):
    from services.blue_input import BlueInputBlocked, build_registered_blue_input

    args, *_ = bound_case
    args = dict(args)
    if alter == "admission":
        args["admission_sha256"] = "f" * 64
    elif alter == "receipt":
        args["receipt_sha256"] = "f" * 64
    elif alter == "source":
        p = args["source_root"] / "services/controlled_executor.py"
        p.write_bytes(p.read_bytes() + b"\n# drift")
    else:
        (args["evidence_dir"] / "stdout.raw").unlink()
    with pytest.raises(BlueInputBlocked):
        build_registered_blue_input(**args)


def test_sql_only_classification_input_stays_blocked_for_non_sql(bound_case):
    from services.blue_input import BlueInputBlocked, build_blue_input

    args, *_ = bound_case
    with pytest.raises(BlueInputBlocked):
        build_blue_input(**args)


def _mock_non_sql_model(monkeypatch, tmp_path, output, *, source_line=84):
    import json
    import dashboard.api.q8_development_service as q8

    state = {
        "state": "running", "sha256": q8.MODEL_SHA256,
        "filename": "c08b-nf4-effective-Q8_0.gguf", "port": 18083,
    }
    monkeypatch.setattr(q8.manager, "probe_busy", lambda: False)
    monkeypatch.setattr(q8.manager, "finish_probe", lambda: None)
    monkeypatch.setattr(q8.manager, "status", lambda: state)
    monkeypatch.setattr(q8, "_frozen_system", lambda: "test-only frozen contract")
    monkeypatch.setattr(q8, "development_localization_prompt", lambda _: "source-prompt")
    archive = tmp_path / "external-model-record"
    archive.mkdir()
    monkeypatch.setattr(q8, "_call_evidence_directory", lambda: archive)
    calls = []
    def complete(_port, prompt):
        calls.append(prompt)
        if len(calls) == 1:
            selected = output
        else:
            selected = {
                "function_or_route": (
                    "vulnerable_search" if source_line == 84
                    else "vulnerable_file_read"
                ),
                "sink_line": source_line,
                "root_cause": "Untrusted input reaches the registered unsafe sink.",
                "confidence": 0.93,
            }
        return {"truncated": False, "content": json.dumps(selected)}
    monkeypatch.setattr(q8, "_raw_completion", complete)
    return archive, calls


def test_non_sql_model_probe_records_grounded_source_but_no_repair_authority(
    bound_case, monkeypatch, tmp_path,
):
    from services.blue_non_sql_probe import (
        probe_bound_non_sql_job, read_non_sql_probe, BlueNonSqlProbeBlocked,
    )
    import sqlite3

    args, scenario, *_ = bound_case
    expected = "xss" if scenario == "xss-search-001" else "path_traversal"
    archive, calls = _mock_non_sql_model(
        monkeypatch, tmp_path,
        {"classification": expected, "confidence": 0.96,
         "reason": "The registered attack response exposes a vulnerable outcome."},
        source_line=84 if expected == "xss" else 104,
    )
    result = probe_bound_non_sql_job(**args)
    assert len(calls) == 2
    assert result["status"] == "recorded"
    assert result["classification"] == expected
    assert result["model_evidence_id"] == archive.name
    assert result["source_localization_verified"] is True
    assert result["model_independently_qualified"] is False
    assert result["patch_preparation_authorized"] is False
    assert result["patch_applied"] is False
    assert result["security_replayed"] is False
    assert result["final_research_qualified"] is False
    assert (archive / "q8-nonsql-raw.json").is_file()
    assert (archive / "q8-nonsql-localization-raw.json").is_file()
    with sqlite3.connect(args["database"]) as conn:
        assert read_non_sql_probe(conn, args["job_id"]) == result
    with pytest.raises(BlueNonSqlProbeBlocked, match="already"):
        probe_bound_non_sql_job(**args)
    assert len(calls) == 2


def test_non_sql_model_misclassification_does_not_trigger_localization(
    bound_case, monkeypatch, tmp_path,
):
    from services.blue_non_sql_probe import probe_bound_non_sql_job

    args, *_ = bound_case
    archive, calls = _mock_non_sql_model(
        monkeypatch, tmp_path,
        {"classification": "benign", "confidence": 0.75,
         "reason": "Incorrectly believes the registered exploit is safe."},
    )
    result = probe_bound_non_sql_job(**args)
    assert result["status"] == "recorded"
    assert result["classification"] == "benign"
    assert result["source_localization_verified"] is False
    assert result["localization_reason"] == "model_class_mismatch"
    assert len(calls) == 1
    assert not (archive / "q8-nonsql-localization-raw.json").exists()
    assert result["patch_preparation_authorized"] is False


def test_non_sql_probe_keeps_unknown_intent_after_invalid_model_reply(
    bound_case, monkeypatch, tmp_path,
):
    import sqlite3
    from services.blue_non_sql_probe import (
        probe_bound_non_sql_job, read_non_sql_probe, BlueNonSqlProbeBlocked,
    )
    import dashboard.api.q8_development_service as q8

    args, *_ = bound_case
    archive, calls = _mock_non_sql_model(
        monkeypatch, tmp_path, {"classification": "xss"},
    )
    monkeypatch.setattr(
        q8, "_raw_completion",
        lambda *_: {"truncated": False, "content": "not-json"},
    )
    with pytest.raises(BlueNonSqlProbeBlocked):
        probe_bound_non_sql_job(**args)
    with sqlite3.connect(args["database"]) as conn:
        assert read_non_sql_probe(conn, args["job_id"])["status"] == "outcome_unknown"
    assert (archive / "q8-nonsql-raw.json").exists()
    with pytest.raises(BlueNonSqlProbeBlocked, match="already"):
        probe_bound_non_sql_job(**args)


def test_non_sql_model_wrong_source_fails_closed_with_raw_archive(
    bound_case, monkeypatch, tmp_path,
):
    import sqlite3
    from services.blue_non_sql_probe import (
        probe_bound_non_sql_job, read_non_sql_probe, BlueNonSqlProbeBlocked,
    )

    args, scenario, *_ = bound_case
    label = "xss" if scenario == "xss-search-001" else "path_traversal"
    archive, calls = _mock_non_sql_model(
        monkeypatch, tmp_path,
        {"classification": label, "confidence": 0.97,
         "reason": "The observed response contains the registered unsafe effect."},
        source_line=83 if label == "xss" else 103,
    )
    with pytest.raises(BlueNonSqlProbeBlocked):
        probe_bound_non_sql_job(**args)
    assert len(calls) == 2
    assert (archive / "q8-nonsql-raw.json").exists()
    assert (archive / "q8-nonsql-localization-raw.json").exists()
    assert not (archive / "q8-nonsql-localization-checked.json").exists()
    with sqlite3.connect(args["database"]) as conn:
        assert read_non_sql_probe(conn, args["job_id"])["status"] == "outcome_unknown"
    with pytest.raises(BlueNonSqlProbeBlocked, match="already"):
        probe_bound_non_sql_job(**args)


def test_non_sql_model_probe_readonly_job_api(bound_case, monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    from dashboard.api.console import create_console_app
    from services.blue_non_sql_probe import probe_bound_non_sql_job

    args, scenario, *_ = bound_case
    label = "xss" if scenario == "xss-search-001" else "path_traversal"
    _mock_non_sql_model(
        monkeypatch, tmp_path,
        {"classification": label, "confidence": 0.92,
         "reason": "Registered response includes the unsafe effect."},
        source_line=84 if label == "xss" else 104,
    )
    with TestClient(create_console_app(
        database_path="/absent/research.sqlite", mars_workspace_db=args["database"],
    )) as client:
        path = f"/api/mars/jobs/{args['job_id']}/non-sql-model-probe"
        before = client.get(path)
        assert before.status_code == 200
        assert before.json()["status"] == "not_requested"
        result = probe_bound_non_sql_job(**args)
        after = client.get(path)
        assert after.status_code == 200
        assert after.json() == result
        assert after.json()["patch_preparation_authorized"] is False
        assert client.post(path, json={}).status_code == 405
