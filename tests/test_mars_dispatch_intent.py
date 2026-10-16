"""W3-B2 tests the durable intent seam without running a Red executor.

Seam: reserve_once/read_intent are Python-only storage operations. A future
independently admitted worker must verify the external admission and source
pins before calling this seam. No HTTP execution endpoint is enabled.
"""
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256

import pytest
from fastapi.testclient import TestClient

from dashboard.api.console import create_console_app
from services.mars_dispatch_intent import (
    DispatchIntentBlocked, read_intent, reserve_once,
)

ADMISSION_DIGEST = sha256(b"external-reviewed-admission-test-fixture").hexdigest()


def seeded_job(tmp_path, reviewed=True):
    database = tmp_path / "mars.sqlite3"
    with TestClient(create_console_app(
        database_path="/absent/research.sqlite",
        mars_workspace_db=database,
    )) as client:
        plan = client.post("/api/mars/plans",
                           json={"name": "Registered SQLi review", "scenario": "sql"}).json()
        result = client.post("/api/mars/jobs", json={"plan_id": plan["id"]})
        assert result.status_code == 201, result.text
        job = result.json()
        if reviewed:
            assert client.post(f'/api/mars/jobs/{job["id"]}/review', json={}).status_code == 200
    return database, job


def test_reservation_is_durable_and_never_retries_after_unknown_outcome(tmp_path):
    database, job = seeded_job(tmp_path)
    ticket = reserve_once(database, job["id"], job["scope_sha256"], ADMISSION_DIGEST)
    assert ticket["state"] == "outcome_unknown"
    assert ticket["attempt"] == 1
    assert ticket["job_id"] == job["id"]
    assert ticket["admission_sha256"] == ADMISSION_DIGEST
    assert read_intent(database, job["id"]) == ticket

    # Simulate a crash after persistent intent but before a worker can
    # report an outcome. This must never be interpreted as safe to retry.
    calls = []
    def inert_runner():
        calls.append("invoked")
        raise RuntimeError("simulated crash")
    with pytest.raises(RuntimeError, match="simulated crash"):
        inert_runner()
    with pytest.raises(DispatchIntentBlocked, match="already recorded"):
        reserve_once(database, job["id"], job["scope_sha256"], ADMISSION_DIGEST)
    assert calls == ["invoked"]
    assert read_intent(database, job["id"]) == ticket

    with TestClient(create_console_app(
        database_path="/absent/research.sqlite", mars_workspace_db=database,
    )) as client:
        events = client.get(f'/api/mars/jobs/{job["id"]}/events').json()
        assert [e["event"] for e in events] == [
            "created", "scope_reviewed", "dispatch_intent_recorded",
        ]
        # Cancellation cannot falsely imply no command may have started.
        assert client.post(f'/api/mars/jobs/{job["id"]}/cancel', json={}).status_code == 409
        assert client.post(f'/api/mars/jobs/{job["id"]}/start', json={}).status_code == 409
        assert client.get(f'/api/mars/jobs/{job["id"]}/execution-request').status_code == 409


def test_one_concurrent_claim_wins_and_all_others_refuse(tmp_path):
    database, job = seeded_job(tmp_path)
    def attempt(_):
        try:
            return reserve_once(database, job["id"], job["scope_sha256"], ADMISSION_DIGEST)
        except DispatchIntentBlocked:
            return None
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(attempt, range(5)))
    assert sum(x is not None for x in results) == 1
    assert read_intent(database, job["id"]) == next(x for x in results if x)
    with TestClient(create_console_app(
        database_path="/absent/research.sqlite", mars_workspace_db=database,
    )) as client:
        events = client.get(f'/api/mars/jobs/{job["id"]}/events').json()
        assert sum(x["event"] == "dispatch_intent_recorded" for x in events) == 1


def test_invalid_admission_and_scope_never_record_intent(tmp_path):
    database, job = seeded_job(tmp_path)
    for scope, digest in [
        ("0"*64, ADMISSION_DIGEST),
        (job["scope_sha256"], "bad-digest"),
        (job["scope_sha256"], "0"*64),
    ]:
        with pytest.raises(DispatchIntentBlocked):
            reserve_once(database, job["id"], scope, digest)
    assert read_intent(database, job["id"]) is None
    with TestClient(create_console_app(
        database_path="/absent/research.sqlite", mars_workspace_db=database,
    )) as client:
        assert [e["event"] for e in client.get(
            f'/api/mars/jobs/{job["id"]}/events').json()] == [
                "created", "scope_reviewed",
        ]


def test_unreviewed_cancelled_and_unknown_jobs_refuse_claim(tmp_path):
    database, job = seeded_job(tmp_path, reviewed=False)
    with pytest.raises(DispatchIntentBlocked):
        reserve_once(database, job["id"], job["scope_sha256"], ADMISSION_DIGEST)
    with TestClient(create_console_app(
        database_path="/absent/research.sqlite", mars_workspace_db=database,
    )) as client:
        assert client.post(f'/api/mars/jobs/{job["id"]}/cancel', json={}).status_code == 200
    with pytest.raises(DispatchIntentBlocked):
        reserve_once(database, job["id"], job["scope_sha256"], ADMISSION_DIGEST)
    with pytest.raises(DispatchIntentBlocked):
        reserve_once(database, "00000000-0000-4000-8000-000000000001",
                     job["scope_sha256"], ADMISSION_DIGEST)
    assert read_intent(database, job["id"]) is None


def test_missing_workspace_cannot_be_silently_created(tmp_path):
    path = tmp_path / "not-previously-created.sqlite3"
    with pytest.raises(DispatchIntentBlocked):
        reserve_once(path, "00000000-0000-4000-8000-000000000001",
                     "a"*64, ADMISSION_DIGEST)
    assert not path.exists()



def test_intent_and_audit_event_roll_back_together(tmp_path):
    import sqlite3
    database, job = seeded_job(tmp_path)
    # Simulate an unavailable audit journal during an otherwise valid reservation.
    with sqlite3.connect(database) as conn:
        conn.execute("DROP TABLE job_events")
    with pytest.raises(sqlite3.OperationalError):
        reserve_once(database, job["id"], job["scope_sha256"], ADMISSION_DIGEST)
    assert read_intent(database, job["id"]) is None
