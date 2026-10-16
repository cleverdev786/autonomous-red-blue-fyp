"""Offline checks for model-selected SQLi source localization on bound Red evidence."""
import json
from hashlib import sha256
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dashboard.api.console import create_console_app
from test_classify import configure_model
from test_isolated_compose_executor import environment
from test_preview import reviewed_archive


def classified(reviewed_archive, monkeypatch, tmp_path, label="sql_injection"):
    from services.blue_classify import classify_bound_job
    db, job, pins = reviewed_archive
    monkeypatch.setenv("FYP_CONSOLE_EVIDENCE_DIR", str(tmp_path))
    calls, evidence = configure_model(monkeypatch, tmp_path, label=label)
    model = classify_bound_job(database=db, job_id=job["id"], **pins)
    import dashboard.api.q8_development_service as q8
    monkeypatch.setattr(
        q8, "_frozen_system",
        lambda role="classification": ("Model source localization" if
            role == "source_localization" else "Model classification"),
    )
    return db, job, pins, model, calls, evidence


def result_for(db, job):
    with TestClient(create_console_app(
        database_path="/absent/research.sqlite", mars_workspace_db=db,
    )) as client:
        r = client.get(f"/api/mars/jobs/{job['id']}/localization")
    assert r.status_code == 200, r.text
    return r.json()


def localization_reply(port, prompt):
    assert "candidate_function_names" in prompt
    assert "student1" in prompt
    assert "ground_truth" not in prompt
    return {"content": json.dumps({
        "function_or_route": "vulnerable_login",
        "sink_line": 53,
        "root_cause": "Login SQL query uses untrusted username in an interpolated string.",
        "confidence": 0.83,
    }), "truncated": False}


def test_unrequested_job_has_no_localization(tmp_path):
    from test_mars_dispatch_intent import seeded_job
    db, job = seeded_job(tmp_path)
    assert result_for(db, job)["status"] == "not_requested"


def test_model_localization_produces_typed_source_finding_and_audit(
    reviewed_archive, monkeypatch, tmp_path
):
    from services.blue_localize import localize_bound_job
    import dashboard.api.q8_development_service as q8

    db, job, pins, model, calls, evidence = classified(
        reviewed_archive, monkeypatch, tmp_path,
    )
    monkeypatch.setattr(q8, "_raw_completion", localization_reply)
    output = localize_bound_job(database=db, job_id=job["id"], **pins)
    assert output["status"] == "recorded"
    assert output["model_origin"] == "q8_0_cpu_model"
    assert output["classification"] == "sql_injection"
    assert output["function_or_route"] == "vulnerable_login"
    assert output["sink_line"] == 53
    assert output["source_file"] == "dummy_apps/vulnerable_store/app/scenario_routes.py"
    assert len(output["source_sha256"]) == 64
    assert len(output["blue_analysis_sha256"]) == 64
    assert output["source_analysis_completed"] is True
    assert output["patch_preparation_authorized"] is False
    assert output["patch_applied"] is False
    assert output["final_research_qualified"] is False
    assert result_for(db, job) == output
    loc_evidence = tmp_path / output["localization_evidence_id"]
    assert json.loads((loc_evidence / "q8-localization-input.json").read_text())["role"] == "source_localization"
    assert json.loads((loc_evidence / "q8-localization-gateway.json").read_text())["result"]["sink_line"] == 53
    assert output["localization_input_sha256"] == sha256(
        (loc_evidence / "q8-localization-input.json").read_bytes()
    ).hexdigest()
    assert output["localization_raw_sha256"] == sha256(
        (loc_evidence / "q8-localization-raw.json").read_bytes()
    ).hexdigest()
    with TestClient(create_console_app(
        database_path="/absent/research.sqlite", mars_workspace_db=db,
    )) as client:
        events = client.get(f"/api/mars/jobs/{job['id']}/events").json()
    assert events[-1]["event"] == "model_source_localized"


@pytest.mark.parametrize("wrong_label", ["benign", "unknown", "xss"])
def test_non_sqli_prediction_never_starts_localization(
    reviewed_archive, monkeypatch, tmp_path, wrong_label
):
    from services.blue_localize import BlueLocalizeBlocked, localize_bound_job
    db, job, pins, model, calls, evidence = classified(
        reviewed_archive, monkeypatch, tmp_path, label=wrong_label,
    )
    with pytest.raises(BlueLocalizeBlocked):
        localize_bound_job(database=db, job_id=job["id"], **pins)
    assert result_for(db, job)["status"] == "not_requested"


@pytest.mark.parametrize("mutate", ["model_raw", "model_input", "red_receipt"])
def test_changed_provenance_never_reaches_localization_model(
    reviewed_archive, monkeypatch, tmp_path, mutate
):
    from services.blue_localize import BlueLocalizeBlocked, localize_bound_job
    import dashboard.api.q8_development_service as q8
    db, job, pins, model, calls, evidence = classified(
        reviewed_archive, monkeypatch, tmp_path,
    )
    if mutate == "model_raw":
        (evidence / "q8-raw-completion.json").write_text("{}")
    elif mutate == "model_input":
        (evidence / "q8-input.json").write_text("{}")
    else:
        pins["receipt_sha256"] = "e" * 64
    monkeypatch.setattr(q8, "_raw_completion", lambda *_: pytest.fail("model must not run"))
    with pytest.raises(BlueLocalizeBlocked):
        localize_bound_job(database=db, job_id=job["id"], **pins)
    assert result_for(db, job)["status"] == "not_requested"


@pytest.mark.parametrize("selection", [
    {"function_or_route":"vulnerable_file_read","sink_line":99,
     "root_cause":"Incorrect source function for login", "confidence":0.9},
    {"function_or_route":"vulnerable_login","sink_line":45,
     "root_cause":"Comment, not the executable sink", "confidence":0.9},
])
def test_wrong_model_source_selection_is_saved_raw_but_not_accepted(
    reviewed_archive, monkeypatch, tmp_path, selection
):
    from services.blue_localize import BlueLocalizeBlocked, localize_bound_job
    import dashboard.api.q8_development_service as q8
    db, job, pins, model, calls, evidence = classified(
        reviewed_archive, monkeypatch, tmp_path,
    )
    monkeypatch.setattr(q8, "_raw_completion", lambda *_: {
        "content": json.dumps(selection), "truncated": False
    })
    with pytest.raises(BlueLocalizeBlocked):
        localize_bound_job(database=db, job_id=job["id"], **pins)
    assert result_for(db, job)["status"] == "outcome_unknown"
    assert list(tmp_path.glob("*/q8-localization-raw.json"))


def test_localization_attempt_cannot_be_repeated(
    reviewed_archive, monkeypatch, tmp_path
):
    from services.blue_localize import BlueLocalizeBlocked, localize_bound_job
    import dashboard.api.q8_development_service as q8
    db, job, pins, model, calls, evidence = classified(
        reviewed_archive, monkeypatch, tmp_path,
    )
    monkeypatch.setattr(q8, "_raw_completion", localization_reply)
    first = localize_bound_job(database=db, job_id=job["id"], **pins)
    with pytest.raises(BlueLocalizeBlocked, match="already"):
        localize_bound_job(database=db, job_id=job["id"], **pins)
    assert result_for(db, job) == first


def test_localization_without_verified_model_does_not_reserve_attempt(
    reviewed_archive, monkeypatch, tmp_path
):
    from services.blue_localize import BlueLocalizeBlocked, localize_bound_job
    import dashboard.api.q8_development_service as q8
    db, job, pins, model, calls, evidence = classified(
        reviewed_archive, monkeypatch, tmp_path,
    )
    monkeypatch.setattr(q8.manager, "status", lambda: {"state":"unloaded"})
    with pytest.raises(BlueLocalizeBlocked):
        localize_bound_job(database=db, job_id=job["id"], **pins)
    assert result_for(db, job)["status"] == "not_requested"


def test_localization_api_refuses_browser_evidence_paths(
    reviewed_archive, monkeypatch
):
    db, job, pins = reviewed_archive
    for name in ("MARS_SOURCE_ROOT", "MARS_EVIDENCE_DIR", "MARS_ADMISSION_PATH",
                 "MARS_ADMISSION_SHA256", "MARS_RECEIPT_SHA256"):
        monkeypatch.delenv(name, raising=False)
    with TestClient(create_console_app(
        database_path="/absent/research.sqlite", mars_workspace_db=db,
    )) as client:
        endpoint = f"/api/mars/jobs/{job['id']}/localize"
        assert client.post(endpoint, json={}).status_code == 409
        assert client.post(endpoint, json={"source_root": "/tmp/arbitrary"}).status_code == 422
    assert result_for(db, job)["status"] == "not_requested"


def test_localization_api_uses_server_pins_and_records_model_result(
    reviewed_archive, monkeypatch, tmp_path
):
    import dashboard.api.q8_development_service as q8
    db, job, pins, model, _calls, evidence = classified(
        reviewed_archive, monkeypatch, tmp_path,
    )
    monkeypatch.setattr(q8, "_raw_completion", localization_reply)
    for key, param in (
        ("MARS_SOURCE_ROOT", "source_root"),
        ("MARS_EVIDENCE_DIR", "evidence_dir"),
        ("MARS_ADMISSION_PATH", "admission_path"),
        ("MARS_ADMISSION_SHA256", "admission_sha256"),
        ("MARS_RECEIPT_SHA256", "receipt_sha256"),
    ):
        monkeypatch.setenv(key, str(pins[param]))
    with TestClient(create_console_app(
        database_path="/absent/research.sqlite", mars_workspace_db=db,
    )) as client:
        response = client.post(f"/api/mars/jobs/{job['id']}/localize", json={})
    assert response.status_code == 200, response.text
    assert response.json()["function_or_route"] == "vulnerable_login"


@pytest.mark.parametrize("tamper", ["job", "model", "red"])
def test_changed_provenance_during_model_inference_is_rejected(
    reviewed_archive, monkeypatch, tmp_path, tamper
):
    from services.blue_localize import BlueLocalizeBlocked, localize_bound_job
    import dashboard.api.q8_development_service as q8
    import sqlite3
    db, job, pins, model, _calls, evidence = classified(
        reviewed_archive, monkeypatch, tmp_path,
    )

    def modify_then_complete(port, prompt):
        if tamper == "job":
            with sqlite3.connect(db) as conn:
                conn.execute("UPDATE jobs SET max_requests=max_requests+1 WHERE id=?", (job["id"],))
        elif tamper == "model":
            (evidence / "q8-raw-completion.json").write_text("{}")
        else:
            file = pins["evidence_dir"] / "stdout.raw"
            file.write_bytes(file.read_bytes() + b"changed")
        return localization_reply(port, prompt)

    monkeypatch.setattr(q8, "_raw_completion", modify_then_complete)
    with pytest.raises(BlueLocalizeBlocked):
        localize_bound_job(database=db, job_id=job["id"], **pins)
    assert result_for(db, job)["status"] == "outcome_unknown"


def test_verified_external_localization_prompt_is_not_classification_prompt():
    import dashboard.api.q8_development_service as q8
    classification = q8._frozen_system()
    localization = q8._frozen_system("source_localization")
    assert "two HTTP observations" in classification
    assert "THREE competing route functions" in localization
    assert localization != classification
