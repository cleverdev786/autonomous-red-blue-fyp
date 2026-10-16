"""Inert integration tests for independently admitted MARS -> existing Docker seam.

No Docker command or security test is run by these tests.
"""
from hashlib import sha256
from uuid import UUID

import pytest

from services.mars_dispatch_intent import DispatchIntentBlocked, read_intent
from services.isolated_compose_executor import RealExecutionAdmission
from test_isolated_compose_executor import environment
from test_mars_dispatch_intent import seeded_job


def approved_inputs(tmp_path, environment, job):
    root, external, manifest, pin, _registry = environment
    name = "mars-" + UUID(job["id"]).hex
    pin = pin.model_copy(update={"run_id": name, "case_id": name})
    manifest.write_bytes(pin.canonical_bytes())
    return dict(
        database=tmp_path / "mars.sqlite3",
        source_root=root,
        evidence_root=external / "evidence",
        admission_path=manifest,
        admission_sha256=sha256(pin.canonical_bytes()).hexdigest(),
        job_id=job["id"],
    ), pin


def fake_executor(monkeypatch, *, fail=False):
    import services.mars_admitted_dispatch as worker
    calls = []

    class InertExecutor:
        def __init__(self, **kwargs):
            calls.append(("created", kwargs))

        def _source_snapshot(self):
            calls.append(("source_checked",))

        def _runtime_snapshot(self):
            calls.append(("runtime_checked",))

        def run_registered(self):
            calls.append(("run_registered",))
            if fail:
                raise RuntimeError("simulated uncertain external outcome")
            return "inert-receipt-only"

    monkeypatch.setattr(worker, "IsolatedDockerExecutor", InertExecutor)
    return calls


def test_reviewed_sqli_job_reaches_existing_executor_once(tmp_path, environment, monkeypatch):
    from services.mars_admitted_dispatch import dispatch_reviewed_job
    db, job = seeded_job(tmp_path)
    args, pin = approved_inputs(tmp_path, environment, job)
    calls = fake_executor(monkeypatch)
    assert dispatch_reviewed_job(**args) == "inert-receipt-only"
    assert [c[0] for c in calls] == ["created", "source_checked", "runtime_checked", "run_registered"]
    intent = read_intent(db, job["id"])
    assert intent["state"] == "outcome_unknown"
    assert intent["admission_sha256"] == args["admission_sha256"]
    with pytest.raises(DispatchIntentBlocked, match="already recorded"):
        dispatch_reviewed_job(**args)
    assert [c[0] for c in calls] == ["created", "source_checked", "runtime_checked", "run_registered", "created", "source_checked", "runtime_checked"]


@pytest.mark.parametrize("change", ["scenario", "run_id", "admission_hash", "saved_scope"])
def test_mismatched_pins_or_scope_never_dispatch(
    tmp_path, environment, monkeypatch, change
):
    from services.mars_admitted_dispatch import dispatch_reviewed_job, AdmittedDispatchBlocked
    db, job = seeded_job(tmp_path)
    args, pin = approved_inputs(tmp_path, environment, job)
    if change in ("scenario", "run_id"):
        value = "xss-search-001" if change == "scenario" else "wrong-run-id"
        pin = pin.model_copy(update={"scenario_id" if change == "scenario" else change: value})
        args["admission_path"].write_bytes(pin.canonical_bytes())
        args["admission_sha256"] = sha256(pin.canonical_bytes()).hexdigest()
    elif change == "admission_hash":
        args["admission_sha256"] = "f"*64
    else:
        import sqlite3
        with sqlite3.connect(db) as con:
            con.execute("UPDATE jobs SET endpoint_path='/wrong' WHERE id=?", (job["id"],))
    calls = fake_executor(monkeypatch)
    with pytest.raises((AdmittedDispatchBlocked, RuntimeError, ValueError)):
        dispatch_reviewed_job(**args)
    assert calls == []
    assert read_intent(db, job["id"]) is None


def test_unknown_outcome_is_never_retried(tmp_path, environment, monkeypatch):
    from services.mars_admitted_dispatch import dispatch_reviewed_job
    db, job = seeded_job(tmp_path)
    args, _ = approved_inputs(tmp_path, environment, job)
    calls = fake_executor(monkeypatch, fail=True)
    with pytest.raises(RuntimeError, match="uncertain"):
        dispatch_reviewed_job(**args)
    assert read_intent(db, job["id"])["state"] == "outcome_unknown"
    with pytest.raises(DispatchIntentBlocked, match="already recorded"):
        dispatch_reviewed_job(**args)
    assert sum(c[0] == "run_registered" for c in calls) == 1


def test_missing_scope_review_refuses_before_executor(tmp_path, environment, monkeypatch):
    from services.mars_admitted_dispatch import dispatch_reviewed_job, AdmittedDispatchBlocked
    db, job = seeded_job(tmp_path, reviewed=False)
    args, _ = approved_inputs(tmp_path, environment, job)
    calls = fake_executor(monkeypatch)
    with pytest.raises(AdmittedDispatchBlocked, match="reviewed"):
        dispatch_reviewed_job(**args)
    assert calls == []
    assert read_intent(db, job["id"]) is None


def test_failed_runtime_preflight_must_not_consume_attempt(tmp_path, environment, monkeypatch):
    from services.mars_admitted_dispatch import dispatch_reviewed_job
    import services.mars_admitted_dispatch as worker
    db, job = seeded_job(tmp_path)
    args, _ = approved_inputs(tmp_path, environment, job)
    calls = []

    class RefusedRuntime:
        def __init__(self, **kwargs):
            pass

        def _source_snapshot(self):
            calls.append("source_ok")

        def _runtime_snapshot(self):
            calls.append("runtime_refused")
            raise RuntimeError("runtime identity failed")

        def run_registered(self):
            pytest.fail("No test must be dispatched after refused runtime")

    monkeypatch.setattr(worker, "IsolatedDockerExecutor", RefusedRuntime)
    with pytest.raises(RuntimeError, match="runtime identity failed"):
        dispatch_reviewed_job(**args)
    assert calls == ["source_ok", "runtime_refused"]
    assert read_intent(db, job["id"]) is None


def test_sql_job_cannot_be_rebound_to_registered_xss_route(
    tmp_path, environment, monkeypatch
):
    from services.mars_admitted_dispatch import dispatch_reviewed_job, AdmittedDispatchBlocked
    from services.registered_assessment_plan import registered_catalog
    import sqlite3
    import json
    db, job = seeded_job(tmp_path)
    args, _ = approved_inputs(tmp_path, environment, job)
    scope = next(r for r in registered_catalog(args["source_root"])["registered_assessments"]
                 if r["route"] == "/xss/search")
    digest = sha256(json.dumps(
        {k: scope[k] for k in ("target_id", "endpoint_id", "registered_test_id",
                              "method", "endpoint_path", "max_requests",
                              "timeout_seconds", "route")},
        sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE plans SET route=?, registered_test_id=? WHERE id=?",
                     (scope["route"], scope["registered_test_id"], job["plan_id"]))
        conn.execute(
            "UPDATE jobs SET route=?, registered_test_id=?, method=?, endpoint_path=?,"
            "max_requests=?, timeout_seconds=?, scope_sha256=? WHERE id=?",
            (scope["route"], scope["registered_test_id"], scope["method"],
             scope["endpoint_path"], scope["max_requests"],
             scope["timeout_seconds"], digest, job["id"]),
        )
    calls = fake_executor(monkeypatch)
    with pytest.raises(AdmittedDispatchBlocked):
        dispatch_reviewed_job(**args)
    assert calls == []
    assert read_intent(db, job["id"]) is None
