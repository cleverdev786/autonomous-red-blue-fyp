"""Prepare a development-only patch from independently pinned Red evidence.

The test uses the repository's actual registered executor implementation with
a simulated command runner. It never calls Docker or changes source.
"""
from hashlib import sha256
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from dashboard.api.console import create_console_app
from services.mars_dispatch_intent import read_intent, reserve_once
from services.receipt_record import record_receipt
from test_isolated_compose_executor import configured, environment
from test_mars_dispatch_intent import seeded_job


@pytest.fixture
def reviewed_archive(tmp_path, environment, monkeypatch):
    import subprocess
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("no real subprocess"))
    db, job = seeded_job(tmp_path)
    root, external, manifest, pin, registry = environment
    case_id = "mars-" + UUID(job["id"]).hex
    pin = pin.model_copy(update={"case_id": case_id, "run_id": case_id})
    manifest.write_bytes(pin.canonical_bytes())
    digest = sha256(pin.canonical_bytes()).hexdigest()
    reserve_once(db, job["id"], job["scope_sha256"], digest)
    runner, _calls, dispatched, _payload = configured(
        (root, external, manifest, pin, registry)
    )
    receipt = runner.run_registered()
    assert receipt.outcome == "baseline_exploit_confirmed"
    assert len(dispatched) == 1
    stored = record_receipt(db, job["id"], external / "evidence", receipt)
    return db, job, {
        "source_root": root,
        "evidence_dir": external / "evidence" / case_id,
        "admission_path": manifest,
        "admission_sha256": digest,
        "receipt_sha256": stored["receipt_sha256"],
    }


def get_proposal(db, job_id):
    with TestClient(create_console_app(
        database_path="/absent/research.sqlite", mars_workspace_db=db
    )) as client:
        answer = client.get(f"/api/mars/jobs/{job_id}/proposal")
        assert answer.status_code == 200, answer.text
        return answer.json()


def test_missing_proposal_never_implies_patch_prepared(tmp_path):
    db, job = seeded_job(tmp_path)
    assert get_proposal(db, job["id"])["status"] == "not_prepared"


def test_bound_sqli_evidence_prepares_actual_compiler_diff_without_applying(
    reviewed_archive
):
    from services.blue_preview import prepare_blue_preview
    db, job, inputs = reviewed_archive
    output = prepare_blue_preview(database=db, job_id=job["id"], **inputs)
    assert output["status"] == "prepared"
    assert output["origin"] == "trusted_deterministic_builder"
    assert output["model_decision_used"] is False
    assert output["patch_applied"] is False
    assert output["security_replayed"] is False
    assert output["final_research_qualified"] is False
    assert "WHERE username = :username" in output["diff_preview"]
    assert get_proposal(db, job["id"]) == output
    assert read_intent(db, job["id"])["state"] == "outcome_unknown"
    with TestClient(create_console_app(
        database_path="/absent/research.sqlite", mars_workspace_db=db,
    )) as client:
        events = client.get(f"/api/mars/jobs/{job['id']}/events").json()
    assert [item["event"] for item in events] == [
        "created", "scope_reviewed", "dispatch_intent_recorded",
        "execution_receipt_recorded", "deterministic_patch_prepared",
    ]


@pytest.mark.parametrize("which", ["admission", "receipt", "source", "missing"])
def test_unbound_or_tampered_evidence_cannot_prepare_patch(reviewed_archive, which):
    from services.blue_preview import BluePreviewBlocked, prepare_blue_preview
    db, job, inputs = reviewed_archive
    inputs = dict(inputs)
    if which == "admission":
        inputs["admission_sha256"] = "f" * 64
    elif which == "receipt":
        inputs["receipt_sha256"] = "f" * 64
    elif which == "source":
        p = inputs["source_root"] / "services/controlled_executor.py"
        p.write_bytes(p.read_bytes() + b"\n# changed")
    else:
        (inputs["evidence_dir"] / "stdout.raw").unlink()
    with pytest.raises(BluePreviewBlocked):
        prepare_blue_preview(database=db, job_id=job["id"], **inputs)
    assert get_proposal(db, job["id"])["status"] == "not_prepared"


def test_duplicate_preparation_fails_closed(reviewed_archive):
    from services.blue_preview import BluePreviewBlocked, prepare_blue_preview
    db, job, inputs = reviewed_archive
    before = prepare_blue_preview(database=db, job_id=job["id"], **inputs)
    with pytest.raises(BluePreviewBlocked, match="already"):
        prepare_blue_preview(database=db, job_id=job["id"], **inputs)
    assert get_proposal(db, job["id"]) == before


def test_changed_registered_scope_cannot_prepare_preview(reviewed_archive):
    import sqlite3
    from services.blue_preview import BluePreviewBlocked, prepare_blue_preview

    db, job, inputs = reviewed_archive
    with sqlite3.connect(db) as conn:
        conn.execute(
            "UPDATE jobs SET max_requests=max_requests+1 WHERE id=?",
            (job["id"],),
        )
    with pytest.raises(BluePreviewBlocked):
        prepare_blue_preview(database=db, job_id=job["id"], **inputs)
    assert get_proposal(db, job["id"])["status"] == "not_prepared"
