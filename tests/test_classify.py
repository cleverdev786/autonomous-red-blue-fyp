"""Inert local Q8 classification integration: genuine Red-derived input, no Docker."""
import json

import pytest
from fastapi.testclient import TestClient

from dashboard.api.console import create_console_app
from test_isolated_compose_executor import environment
from test_preview import reviewed_archive


def configure_model(monkeypatch, tmp_path, label="sql_injection"):
    import dashboard.api.q8_development_service as q8
    from services.q8_c12_development_bridge import MODEL_SHA256

    calls = []
    evidence = tmp_path / "model-evidence"
    evidence.mkdir()
    monkeypatch.setattr(q8.manager, "probe_busy", lambda: False)
    monkeypatch.setattr(q8.manager, "finish_probe", lambda: calls.append("released"))
    monkeypatch.setattr(q8.manager, "status", lambda: {
        "state": "running", "sha256": MODEL_SHA256,
        "filename": "c08b-nf4-effective-Q8_0.gguf", "port": 18083,
    })
    monkeypatch.setattr(q8, "_frozen_system", lambda: "Classify two HTTP observations with JSON.")
    monkeypatch.setattr(q8, "_call_evidence_directory", lambda: evidence)

    def model_call(port, prompt):
        calls.append((port, prompt))
        return {"content": json.dumps({
            "classification": label, "confidence": 0.8, "reason":
            "Registered controlled responses show a suspicious login transition.",
        }), "truncated": False}

    monkeypatch.setattr(q8, "_raw_completion", model_call)
    return calls, evidence


def read_result(db, job_id):
    with TestClient(create_console_app(
        database_path="/absent/research.sqlite", mars_workspace_db=db,
    )) as client:
        response = client.get(f"/api/mars/jobs/{job_id}/classification")
    assert response.status_code == 200, response.text
    return response.json()


def test_unrequested_job_does_not_claim_model_classification(tmp_path):
    from test_mars_dispatch_intent import seeded_job
    db, job = seeded_job(tmp_path)
    assert read_result(db, job["id"])["status"] == "not_requested"


def test_verified_bound_sql_input_is_actually_submitted_to_q8(
    reviewed_archive, monkeypatch, tmp_path
):
    from services.blue_classify import classify_bound_job
    db, job, pins = reviewed_archive
    calls, evidence = configure_model(monkeypatch, tmp_path)
    response = classify_bound_job(database=db, job_id=job["id"], **pins)
    assert response["status"] == "recorded"
    assert response["classification"] == "sql_injection"
    assert response["model_origin"] == "q8_0_cpu_model"
    assert response["model_independently_qualified"] is False
    assert response["patch_preparation_authorized"] is False
    assert response["final_research_qualified"] is False
    assert read_result(db, job["id"]) == response
    assert len(calls) == 2 and calls[1] == "released"
    assert calls[0][0] == 18083
    assert "student1" in calls[0][1] and "' OR 1=1 --" in calls[0][1]
    assert "ground_truth" not in calls[0][1]
    assert "exploit_confirmed" not in calls[0][1]
    for file in ("q8-input.json", "q8-raw-completion.json", "q8-gateway.json",
                 "q8-assessment-plan.json"):
        assert (evidence / file).is_file()
    assert json.loads((evidence / "q8-input.json").read_text())["input"]["route"] == "/sql-injection/login"
    from hashlib import sha256
    assert response["model_input_sha256"] == sha256(
        (evidence / "q8-input.json").read_bytes()
    ).hexdigest()
    assert response["model_raw_sha256"] == sha256(
        (evidence / "q8-raw-completion.json").read_bytes()
    ).hexdigest()
    assert response["model_evidence_id"] == evidence.name



@pytest.mark.parametrize("label", ["benign", "unknown", "xss"])
def test_model_answer_is_preserved_not_corrected_to_sqli(
    reviewed_archive, monkeypatch, tmp_path, label
):
    from services.blue_classify import classify_bound_job
    db, job, pins = reviewed_archive
    configure_model(monkeypatch, tmp_path, label=label)
    result = classify_bound_job(database=db, job_id=job["id"], **pins)
    assert result["classification"] == label
    assert result["patch_preparation_authorized"] is False


def test_no_model_available_never_returns_a_fake_result(
    reviewed_archive, monkeypatch
):
    from services.blue_classify import BlueClassifyBlocked, classify_bound_job
    import dashboard.api.q8_development_service as q8
    db, job, pins = reviewed_archive
    monkeypatch.setattr(q8.manager, "status", lambda: {"state": "unloaded"})
    with pytest.raises(BlueClassifyBlocked):
        classify_bound_job(database=db, job_id=job["id"], **pins)
    assert read_result(db, job["id"])["status"] == "not_requested"


def test_identical_job_is_not_classified_twice(reviewed_archive, monkeypatch, tmp_path):
    from services.blue_classify import BlueClassifyBlocked, classify_bound_job
    db, job, pins = reviewed_archive
    calls, _ = configure_model(monkeypatch, tmp_path)
    classify_bound_job(database=db, job_id=job["id"], **pins)
    with pytest.raises(BlueClassifyBlocked, match="already"):
        classify_bound_job(database=db, job_id=job["id"], **pins)
    assert sum(isinstance(c, tuple) for c in calls) == 1


def test_tampered_red_evidence_never_calls_model(
    reviewed_archive, monkeypatch, tmp_path
):
    from services.blue_classify import BlueClassifyBlocked, classify_bound_job
    db, job, pins = reviewed_archive
    calls, _ = configure_model(monkeypatch, tmp_path)
    pins["receipt_sha256"] = "e" * 64
    with pytest.raises(BlueClassifyBlocked):
        classify_bound_job(database=db, job_id=job["id"], **pins)
    assert not calls


def test_invalid_model_json_is_not_recorded_as_success(
    reviewed_archive, monkeypatch, tmp_path
):
    from services.blue_classify import BlueClassifyBlocked, classify_bound_job
    import dashboard.api.q8_development_service as q8
    db, job, pins = reviewed_archive
    _calls, evidence = configure_model(monkeypatch, tmp_path)
    monkeypatch.setattr(q8, "_raw_completion", lambda *_: {
        "content": '{"classification":"invalid"}', "truncated": False,
    })
    with pytest.raises(BlueClassifyBlocked):
        classify_bound_job(database=db, job_id=job["id"], **pins)
    assert (evidence / "q8-raw-completion.json").is_file()
    assert read_result(db, job["id"])["status"] != "recorded"


def test_browser_cannot_choose_evidence_paths_or_trigger_unconfigured_q8(
    reviewed_archive, monkeypatch
):
    db, job, _pins = reviewed_archive
    for key in ("MARS_SOURCE_ROOT", "MARS_EVIDENCE_DIR", "MARS_ADMISSION_PATH",
                "MARS_ADMISSION_SHA256", "MARS_RECEIPT_SHA256"):
        monkeypatch.delenv(key, raising=False)
    with TestClient(create_console_app(
        database_path="/absent/research.sqlite", mars_workspace_db=db,
    )) as client:
        route = f"/api/mars/jobs/{job['id']}/classify"
        assert client.post(route, json={}).status_code == 409
        assert client.post(route, json={"evidence_dir":"/tmp/evil"}).status_code == 422
    assert read_result(db, job["id"])["status"] == "not_requested"


def test_explicit_local_classify_route_uses_operator_pins(
    reviewed_archive, monkeypatch, tmp_path
):
    db, job, pins = reviewed_archive
    calls, _ = configure_model(monkeypatch, tmp_path)
    for name, value in (
        ("MARS_SOURCE_ROOT", pins["source_root"]),
        ("MARS_EVIDENCE_DIR", pins["evidence_dir"]),
        ("MARS_ADMISSION_PATH", pins["admission_path"]),
        ("MARS_ADMISSION_SHA256", pins["admission_sha256"]),
        ("MARS_RECEIPT_SHA256", pins["receipt_sha256"]),
    ):
        monkeypatch.setenv(name, str(value))
    with TestClient(create_console_app(
        database_path="/absent/research.sqlite", mars_workspace_db=db,
    )) as client:
        response = client.post(f"/api/mars/jobs/{job['id']}/classify", json={})
        assert response.status_code == 200, response.text
        assert response.json()["classification"] == "sql_injection"
        assert response.json()["patch_preparation_authorized"] is False
        events = client.get(f"/api/mars/jobs/{job['id']}/events").json()
        assert events[-1]["event"] == "model_classification_recorded"
    assert sum(isinstance(c, tuple) for c in calls) == 1


def test_failed_inference_has_unknown_state_and_no_automatic_retry(
    reviewed_archive, monkeypatch, tmp_path
):
    from services.blue_classify import BlueClassifyBlocked, classify_bound_job
    import dashboard.api.q8_development_service as q8
    db, job, pins = reviewed_archive
    calls, _ = configure_model(monkeypatch, tmp_path)
    monkeypatch.setattr(q8, "_raw_completion", lambda *_: (_ for _ in ()).throw(
        q8.OperatorError("simulated local model crash")
    ))
    with pytest.raises(BlueClassifyBlocked):
        classify_bound_job(database=db, job_id=job["id"], **pins)
    assert read_result(db, job["id"])["status"] == "outcome_unknown"
    with pytest.raises(BlueClassifyBlocked, match="already"):
        classify_bound_job(database=db, job_id=job["id"], **pins)


@pytest.mark.parametrize("which", ["receipt", "job"])
def test_model_result_cannot_attach_after_saved_evidence_changes(
    reviewed_archive, monkeypatch, tmp_path, which
):
    from services.blue_classify import BlueClassifyBlocked, classify_bound_job
    import dashboard.api.q8_development_service as q8
    import sqlite3
    db, job, pins = reviewed_archive
    configure_model(monkeypatch, tmp_path)

    def model_reply(port, prompt):
        with sqlite3.connect(db) as conn:
            if which == "receipt":
                conn.execute("UPDATE execution_receipts SET receipt_sha256=? WHERE job_id=?",
                             ("f" * 64, job["id"]))
            else:
                conn.execute("UPDATE jobs SET state='awaiting_review' WHERE id=?",
                             (job["id"],))
        return {"content": json.dumps({
            "classification": "sql_injection", "confidence": 0.91,
            "reason": "The login control and injection results differ.",
        }), "truncated": False}

    monkeypatch.setattr(q8, "_raw_completion", model_reply)
    with pytest.raises(BlueClassifyBlocked):
        classify_bound_job(database=db, job_id=job["id"], **pins)
    assert read_result(db, job["id"])["status"] == "outcome_unknown"
