"""Receipt reconciliation uses synthetic bytes only, never Docker execution."""
from hashlib import sha256
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from test_mars_dispatch_intent import seeded_job

pytest_plugins = ("test_isolated_compose_executor",)
from dashboard.api.console import create_console_app
from services.isolated_compose_executor import RealExecutionReceipt
from services.mars_dispatch_intent import read_intent, reserve_once

DIGEST = sha256(b"independent-admission-fixture").hexdigest()


def receipt_for(job):
    case = "mars-" + UUID(job["id"]).hex
    return RealExecutionReceipt(
        case_id=case, run_id=case, scenario_id="sqli-login-001",
        source_head="1" * 40, source_tree="2" * 40,
        daemon_id="test-daemon", image_id="sha256:" + "a" * 64,
        app_container_id="b" * 64, executor_container_id="c" * 64,
        admission_sha256=DIGEST, dispatch_argv=("docker", "exec", "inert"),
        stdout_sha256=sha256(b"").hexdigest(),
        stderr_sha256=sha256(b"").hexdigest(), returncode=1,
        timed_out=False, outcome="executor_failed",
        reason="synthetic process returned nonzero",
    )


def admission_setup(tmp_path):
    database, job = seeded_job(tmp_path)
    reserve_once(database, job["id"], job["scope_sha256"], DIGEST)
    evidence = tmp_path / "separate-evidence"
    case = evidence / ("mars-" + UUID(job["id"]).hex)
    case.mkdir(parents=True)
    receipt = receipt_for(job)
    (case / "receipt.json").write_bytes(
        (receipt.model_dump_json(indent=2) + "\n").encode()
    )
    return database, job, evidence, receipt


def read_api(database, job_id):
    with TestClient(create_console_app(
        database_path="/absent/research.sqlite", mars_workspace_db=database,
    )) as client:
        response = client.get(f"/api/mars/jobs/{job_id}/execution")
        assert response.status_code == 200, response.text
        return response.json()


def test_unattempted_and_unreconciled_job_are_not_claimed_completed(tmp_path):
    db, job = seeded_job(tmp_path)
    assert read_api(db, job["id"])["status"] == "not_dispatched"
    reserve_once(db, job["id"], job["scope_sha256"], DIGEST)
    assert read_api(db, job["id"])["status"] == "outcome_unknown"


def test_worker_recorded_failure_is_visible_without_claiming_success(tmp_path):
    from services.receipt_record import record_receipt
    db, job, evidence, receipt = admission_setup(tmp_path)
    recorded = record_receipt(db, job["id"], evidence, receipt)
    assert recorded["status"] == "receipt_recorded"
    assert recorded["outcome"] == "executor_failed"
    assert recorded["scope"] == "development_only_not_final_research"
    assert recorded["receipt_sha256"] == sha256(
        (receipt.model_dump_json(indent=2) + "\n").encode()
    ).hexdigest()
    shown = read_api(db, job["id"])
    assert shown == recorded
    assert read_intent(db, job["id"])["state"] == "outcome_unknown"
    with TestClient(create_console_app(
        database_path="/absent/research.sqlite", mars_workspace_db=db,
    )) as client:
        events = client.get(f"/api/mars/jobs/{job['id']}/events").json()
    assert [row["event"] for row in events] == [
        "created", "scope_reviewed", "dispatch_intent_recorded", "execution_receipt_recorded",
    ]


@pytest.mark.parametrize("tamper", ["receipt_content", "admission", "case", "observation"])
def test_no_forged_or_inconsistent_receipt_may_enter_workspace(tmp_path, tamper):
    from services.receipt_record import ReceiptBlocked, record_receipt
    db, job, evidence, receipt = admission_setup(tmp_path)
    path = evidence / receipt.case_id / "receipt.json"
    if tamper == "receipt_content":
        path.write_bytes(path.read_bytes().replace(b"executor_failed", b"provenance_failed"))
    elif tamper == "admission":
        receipt = receipt.model_copy(update={"admission_sha256": "f" * 64})
    elif tamper == "case":
        receipt = receipt.model_copy(update={"case_id": "other-case", "run_id": "other-run"})
    else:
        receipt = receipt.model_copy(update={
            "outcome": "baseline_exploit_confirmed", "observation_sha256": "f" * 64,
        })
    with pytest.raises(ReceiptBlocked):
        record_receipt(db, job["id"], evidence, receipt)
    assert read_api(db, job["id"])["status"] == "outcome_unknown"


def test_recording_is_write_once_even_when_facts_change(tmp_path):
    from services.receipt_record import ReceiptBlocked, record_receipt
    db, job, evidence, receipt = admission_setup(tmp_path)
    before = record_receipt(db, job["id"], evidence, receipt)
    with pytest.raises(ReceiptBlocked, match="already"):
        record_receipt(db, job["id"], evidence, receipt)
    assert read_api(db, job["id"]) == before


def test_symlink_receipt_file_is_refused(tmp_path):
    from services.receipt_record import ReceiptBlocked, record_receipt
    db, job, evidence, receipt = admission_setup(tmp_path)
    path = evidence / receipt.case_id / "receipt.json"
    moved = path.with_suffix(".txt")
    path.rename(moved)
    path.symlink_to(moved)
    with pytest.raises(ReceiptBlocked):
        record_receipt(db, job["id"], evidence, receipt)
    assert read_api(db, job["id"])["status"] == "outcome_unknown"


def test_matched_hash_does_not_make_invalid_observation_trustworthy(tmp_path):
    from services.receipt_record import ReceiptBlocked, record_receipt
    db, job, evidence, receipt = admission_setup(tmp_path)
    invalid = b'{"unsupported":"fabricated exploit"}'
    receipt = receipt.model_copy(update={
        "outcome": "baseline_exploit_confirmed",
        "observation_sha256": sha256(invalid).hexdigest(),
    })
    case = evidence / receipt.case_id
    (case / "observation.json").write_bytes(invalid)
    (case / "receipt.json").write_bytes(
        (receipt.model_dump_json(indent=2) + "\n").encode()
    )
    with pytest.raises(ReceiptBlocked):
        record_receipt(db, job["id"], evidence, receipt)
    assert read_api(db, job["id"])["status"] == "outcome_unknown"


def test_inert_registered_sqli_executor_receipt_reaches_job_api(
    tmp_path, environment, monkeypatch
):
    """Uses the real executor code with an injected process runner, never Docker."""
    import subprocess

    from test_isolated_compose_executor import configured

    from services.receipt_record import record_receipt

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail(
        "Real subprocess is forbidden in this test"
    ))
    db, job = seeded_job(tmp_path)
    root, external, manifest, pin, registry = environment
    case = "mars-" + UUID(job["id"]).hex
    pin = pin.model_copy(update={"case_id": case, "run_id": case})
    manifest.write_bytes(pin.canonical_bytes())
    admission = sha256(pin.canonical_bytes()).hexdigest()
    reserve_once(db, job["id"], job["scope_sha256"], admission)

    seam, _calls, dispatches, _payload = configured(
        (root, external, manifest, pin, registry)
    )
    receipt = seam.run_registered()
    assert receipt.outcome == "baseline_exploit_confirmed"
    assert receipt.observation_sha256 is not None
    assert len(dispatches) == 1

    stored = record_receipt(db, job["id"], external / "evidence", receipt)
    assert stored["status"] == "receipt_recorded"
    assert stored["outcome"] == "baseline_exploit_confirmed"
    assert stored["observation_sha256"] == receipt.observation_sha256
    assert read_api(db, job["id"]) == stored
    assert read_intent(db, job["id"])["state"] == "outcome_unknown"


@pytest.mark.parametrize(("scenario","scenario_id"), [
    ("xss", "xss-search-001"),
    ("traversal", "path-traversal-read-001"),
])
def test_other_registered_scenarios_store_inert_receipt_once(
    tmp_path, scenario, scenario_id
):
    from services.receipt_record import ReceiptBlocked, record_receipt
    db, job = seeded_job(tmp_path, scenario=scenario)
    reserve_once(db, job["id"], job["scope_sha256"], DIGEST)
    evidence = tmp_path / "external"
    case_id = "mars-" + UUID(job["id"]).hex
    folder = evidence / case_id
    folder.mkdir(parents=True)
    receipt = receipt_for(job).model_copy(update={"scenario_id": scenario_id})
    (folder / "receipt.json").write_bytes(
        (receipt.model_dump_json(indent=2) + "\n").encode()
    )
    result = record_receipt(db, job["id"], evidence, receipt)
    assert result["status"] == "receipt_recorded"
    assert result["outcome"] == "executor_failed"
    assert read_api(db, job["id"]) == result
    with pytest.raises(ReceiptBlocked):
        record_receipt(db, job["id"], evidence, receipt)


@pytest.mark.parametrize(("scenario","wrong_scenario"), [
    ("xss", "sqli-login-001"),
    ("traversal", "xss-search-001"),
])
def test_wrong_scenario_receipt_never_associates_with_reviewed_job(
    tmp_path, scenario, wrong_scenario
):
    from services.receipt_record import ReceiptBlocked, record_receipt
    db, job = seeded_job(tmp_path, scenario=scenario)
    reserve_once(db, job["id"], job["scope_sha256"], DIGEST)
    evidence = tmp_path / "external"
    case_id = "mars-" + UUID(job["id"]).hex
    folder = evidence / case_id
    folder.mkdir(parents=True)
    receipt = receipt_for(job).model_copy(update={"scenario_id": wrong_scenario})
    (folder / "receipt.json").write_bytes(
        (receipt.model_dump_json(indent=2) + "\n").encode()
    )
    with pytest.raises(ReceiptBlocked):
        record_receipt(db, job["id"], evidence, receipt)
    assert read_api(db, job["id"])["status"] == "outcome_unknown"


@pytest.mark.parametrize(("scenario", "scenario_id"), [
    ("xss", "xss-search-001"),
    ("traversal", "path-traversal-read-001"),
])
def test_accepted_non_sql_registered_observation_is_published_once(
    tmp_path, environment, scenario, scenario_id
):
    from test_isolated_compose_executor import configured

    from services.receipt_record import record_receipt

    database, job = seeded_job(tmp_path, scenario=scenario)
    root, external, manifest, pin, registry = environment
    case_id = "mars-" + UUID(job["id"]).hex
    pin = pin.model_copy(update={
        "case_id": case_id, "run_id": case_id, "scenario_id": scenario_id,
    })
    manifest.write_bytes(pin.canonical_bytes())
    admission = sha256(pin.canonical_bytes()).hexdigest()
    reserve_once(database, job["id"], job["scope_sha256"], admission)
    executor, _calls, dispatches, _payload = configured(
        (root, external, manifest, pin, registry), scenario=scenario_id,
    )
    receipt = executor.run_registered()
    assert receipt.scenario_id == scenario_id
    assert receipt.outcome == "baseline_exploit_confirmed"
    assert receipt.observation_sha256
    assert len(dispatches) == 1
    saved = record_receipt(database, job["id"], external / "evidence", receipt)
    assert saved["outcome"] == "baseline_exploit_confirmed"
    assert read_api(database, job["id"]) == saved


def test_receipt_refuses_scope_changed_after_dispatch_intent(tmp_path):
    import sqlite3

    from services.receipt_record import ReceiptBlocked, record_receipt

    database, job, evidence, receipt = admission_setup(tmp_path)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE jobs SET scope_sha256=? WHERE id=?",
            ("f" * 64, job["id"]),
        )
    with pytest.raises(ReceiptBlocked, match="matching reviewed job"):
        record_receipt(database, job["id"], evidence, receipt)
    assert read_api(database, job["id"])["status"] == "outcome_unknown"
