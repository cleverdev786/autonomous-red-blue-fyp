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
