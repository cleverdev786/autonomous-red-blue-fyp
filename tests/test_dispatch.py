"""Inert integration tests for independently admitted MARS -> existing Docker seam.

No Docker command or security test is run by these tests.
"""
from hashlib import sha256
from uuid import UUID

import pytest
from test_mars_dispatch_intent import seeded_job

pytest_plugins = ("test_isolated_compose_executor",)
from services.isolated_compose_executor import (
    RealExecutionReceipt,
    load_real_admission,
)
from services.mars_dispatch_intent import DispatchIntentBlocked, read_intent


def approved_inputs(tmp_path, environment, job):
    root, external, manifest, pin, _registry = environment
    name = "mars-" + UUID(job["id"]).hex
    pin = pin.model_copy(update={"run_id": name, "case_id": name})
    manifest.write_bytes(pin.canonical_bytes())
    return {
        "database": tmp_path / "mars.sqlite3",
        "source_root": root,
        "evidence_root": external / "evidence",
        "admission_path": manifest,
        "admission_sha256": sha256(pin.canonical_bytes()).hexdigest(),
        "job_id": job["id"],
    }, pin


def fake_executor(monkeypatch, *, fail=False):
    import services.job_dispatch as worker
    calls = []

    class InertExecutor:
        def __init__(self, **kwargs):
            calls.append(("created", kwargs))
            self.kwargs = kwargs

        def _source_snapshot(self):
            calls.append(("source_checked",))

        def _runtime_snapshot(self):
            calls.append(("runtime_checked",))

        def run_registered(self):
            calls.append(("run_registered",))
            if fail:
                raise RuntimeError("simulated uncertain external outcome")
            pin = load_real_admission(
                self.kwargs["source_root"], self.kwargs["admission_path"],
                self.kwargs["admission_sha256"],
            )
            from pathlib import Path
            receipt = RealExecutionReceipt(
                case_id=pin.case_id, run_id=pin.run_id, scenario_id=pin.scenario_id,
                source_head=pin.source_head, source_tree=pin.source_tree,
                daemon_id=pin.daemon_id, image_id=pin.image_id,
                app_container_id=pin.app_container_id,
                executor_container_id=pin.executor_container_id,
                admission_sha256=self.kwargs["admission_sha256"],
                dispatch_argv=("inert",), stdout_sha256=sha256(b"").hexdigest(),
                stderr_sha256=sha256(b"").hexdigest(), returncode=-1,
                timed_out=False, outcome="executor_failed", reason="inert test failure",
            )
            case = Path(self.kwargs["evidence_root"]) / pin.case_id
            case.mkdir()
            (case / "receipt.json").write_bytes(
                (receipt.model_dump_json(indent=2) + "\n").encode()
            )
            return receipt

    monkeypatch.setattr(worker, "IsolatedDockerExecutor", InertExecutor)
    return calls


def test_reviewed_sqli_job_reaches_existing_executor_once(tmp_path, environment, monkeypatch):
    from services.job_dispatch import dispatch_reviewed_job
    db, job = seeded_job(tmp_path)
    args, _pin = approved_inputs(tmp_path, environment, job)
    calls = fake_executor(monkeypatch)
    assert dispatch_reviewed_job(**args).outcome == "executor_failed"
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
    from services.job_dispatch import AdmittedDispatchBlocked, dispatch_reviewed_job
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
    from services.job_dispatch import dispatch_reviewed_job
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
    from services.job_dispatch import AdmittedDispatchBlocked, dispatch_reviewed_job
    db, job = seeded_job(tmp_path, reviewed=False)
    args, _ = approved_inputs(tmp_path, environment, job)
    calls = fake_executor(monkeypatch)
    with pytest.raises(AdmittedDispatchBlocked, match="reviewed"):
        dispatch_reviewed_job(**args)
    assert calls == []
    assert read_intent(db, job["id"]) is None


def test_failed_runtime_preflight_must_not_consume_attempt(tmp_path, environment, monkeypatch):
    import services.job_dispatch as worker
    from services.job_dispatch import dispatch_reviewed_job
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
    import json
    import sqlite3

    from services.job_dispatch import AdmittedDispatchBlocked, dispatch_reviewed_job
    from services.registered_assessment_plan import registered_catalog
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


@pytest.mark.parametrize(("scenario","scenario_id"), [
    ("xss", "xss-search-001"),
    ("traversal", "path-traversal-read-001"),
])
def test_other_reviewed_scenarios_reach_registered_executor_only_once(
    tmp_path, environment, monkeypatch, scenario, scenario_id
):
    from services.job_dispatch import dispatch_reviewed_job
    db, job = seeded_job(tmp_path, scenario=scenario)
    args, pin = approved_inputs(tmp_path, environment, job)
    pin = pin.model_copy(update={"scenario_id": scenario_id})
    args["admission_path"].write_bytes(pin.canonical_bytes())
    args["admission_sha256"] = sha256(pin.canonical_bytes()).hexdigest()
    calls = fake_executor(monkeypatch)
    assert dispatch_reviewed_job(**args).scenario_id == scenario_id
    assert [call[0] for call in calls] == [
        "created", "source_checked", "runtime_checked", "run_registered",
    ]
    assert read_intent(db, job["id"])["state"] == "outcome_unknown"
    with pytest.raises(DispatchIntentBlocked, match="already recorded"):
        dispatch_reviewed_job(**args)
    assert sum(call[0] == "run_registered" for call in calls) == 1


@pytest.mark.parametrize(("scenario","wrong_scenario_id"), [
    ("xss", "sqli-login-001"),
    ("traversal", "xss-search-001"),
])
def test_other_scenarios_refuse_mismatched_external_admission_without_intent(
    tmp_path, environment, monkeypatch, scenario, wrong_scenario_id
):
    from services.job_dispatch import AdmittedDispatchBlocked, dispatch_reviewed_job
    db, job = seeded_job(tmp_path, scenario=scenario)
    args, pin = approved_inputs(tmp_path, environment, job)
    pin = pin.model_copy(update={"scenario_id": wrong_scenario_id})
    args["admission_path"].write_bytes(pin.canonical_bytes())
    args["admission_sha256"] = sha256(pin.canonical_bytes()).hexdigest()
    calls = fake_executor(monkeypatch)
    with pytest.raises(AdmittedDispatchBlocked):
        dispatch_reviewed_job(**args)
    assert calls == []
    assert read_intent(db, job["id"]) is None


@pytest.mark.parametrize(("scenario", "scenario_id"), [
    ("xss", "xss-search-001"),
    ("traversal", "path-traversal-read-001"),
])
def test_non_sql_red_job_does_not_unlock_sql_blue_gate(
    tmp_path, environment, scenario, scenario_id
):
    from services.job_dispatch import AdmittedDispatchBlocked, _reviewed_sql_scope
    db, job = seeded_job(tmp_path, scenario=scenario)
    with pytest.raises(AdmittedDispatchBlocked, match="SQLi"):
        _reviewed_sql_scope(db, job["id"], environment[0])
