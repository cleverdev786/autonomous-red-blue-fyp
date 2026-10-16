"""Blue receives the captured registered Red exchanges, not evaluator truth."""
from hashlib import sha256
import sqlite3
import pytest

from test_preview import reviewed_archive
from test_isolated_compose_executor import environment


def test_verified_sqli_receipt_becomes_two_model_inputs(reviewed_archive):
    from services.blue_input import build_blue_input
    db, job, pins = reviewed_archive
    before = db.stat().st_size
    result = build_blue_input(database=db, job_id=job["id"], **pins)
    assert result["job_id"] == job["id"]
    assert result["red_receipt_sha256"] == pins["receipt_sha256"]
    assert result["origin"] == "registered_steps_plus_captured_responses"
    assert result["model_executed"] is False
    assert result["source_analysis_authorized"] is False
    assert result["patch_prepared"] is False
    pair = result["classification_request"]["input"]
    assert result["classification_request"]["role"] == "classification"
    assert pair["route"] == "/sql-injection/login"
    rows = pair["observations"]
    assert len(rows) == 2
    assert rows[0]["parameters"]["username"] == "student1"
    assert rows[1]["parameters"]["username"] == "' OR 1=1 --"
    assert rows[0]["status_code"] == 401 and rows[1]["status_code"] == 200
    assert all(set(row) == {"method", "parameters", "status_code", "response_excerpt"} for row in rows)
    assert all("ground_truth" not in str(row) and "exploit_confirmed" not in str(row) for row in rows)
    assert result["localization_request"]["role"] == "source_localization"
    assert result["localization_request"]["input"]["observations"] == rows
    assert db.stat().st_size == before


@pytest.mark.parametrize("tamper", ["receipt", "admission", "stdout", "source", "job_scope"])
def test_model_input_refuses_changed_provenance(reviewed_archive, tamper):
    from services.blue_input import BlueInputBlocked, build_blue_input
    db, job, pins = reviewed_archive
    pins = dict(pins)
    if tamper == "receipt":
        pins["receipt_sha256"] = "f" * 64
    elif tamper == "admission":
        pins["admission_sha256"] = "f" * 64
    elif tamper == "stdout":
        p = pins["evidence_dir"] / "stdout.raw"
        p.write_bytes(p.read_bytes() + b"x")
    elif tamper == "source":
        p = pins["source_root"] / "dummy_apps/vulnerable_store/app/scenario_routes.py"
        p.write_bytes(p.read_bytes() + b"#changed")
    elif tamper == "job_scope":
        with sqlite3.connect(db) as conn:
            conn.execute("UPDATE jobs SET max_requests=max_requests+1 WHERE id=?", (job["id"],))
    with pytest.raises(BlueInputBlocked):
        build_blue_input(database=db, job_id=job["id"], **pins)


def test_build_input_never_calls_model_or_subprocess(reviewed_archive, monkeypatch):
    from services.blue_input import build_blue_input
    import subprocess
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: pytest.fail("subprocess not allowed"))
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: pytest.fail("Popen not allowed"))
    db, job, pins = reviewed_archive
    assert build_blue_input(database=db, job_id=job["id"], **pins)["model_executed"] is False
