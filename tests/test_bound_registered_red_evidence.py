"""Archived Docker provenance binding: fully offline injected executor fixtures."""
from __future__ import annotations

from dataclasses import replace
from hashlib import sha256

import pytest
from test_isolated_compose_executor import configured
from test_isolated_compose_executor import environment as upstream_environment

from schemas.common import ClassificationLabel
from schemas.rq2_dataset import RQ2ClassificationDecision
from security_tests.registry import SecurityTestRegistry
from services.bound_registered_red_evidence import (
    BoundRedEvidenceError,
    verify_archived_registered_red,
)
from services.model_driven_decision_gate import (
    BlueNextAction,
    authorize_bound_source_analysis,
    run_archived_evidence_gate,
)


@pytest.fixture
def environment(tmp_path):
    return upstream_environment.__wrapped__(tmp_path)


TRIALS = (
    ("sqli-login-001", ClassificationLabel.SQL_INJECTION, "scenario-sqli-login"),
    ("xss-search-001", ClassificationLabel.XSS, "scenario-xss-search"),
    (
        "path-traversal-read-001",
        ClassificationLabel.PATH_TRAVERSAL,
        "scenario-path-traversal-read",
    ),
)


def triage(label):
    return RQ2ClassificationDecision(
        classification=label, confidence=0.91, reason="Model-only decision."
    )


def archive(environment, *, scenario="sqli-login-001"):
    seam, calls, dispatches, _ = configured(environment, scenario=scenario)
    receipt = seam.run_registered()
    case = seam.evidence / receipt.case_id
    root, _, manifest, pin, registry = environment
    digest = sha256((case / "receipt.json").read_bytes()).hexdigest()
    context = {
        "source_root": root,
        "dispatch_root": root,
        "evidence_dir": case,
        "admission_path": manifest,
        "admission_sha256": sha256(manifest.read_bytes()).hexdigest(),
        "receipt_sha256": digest,
        "registry": registry,
        "implementations": SecurityTestRegistry.default(),
    }
    return context, receipt, calls, dispatches, pin


@pytest.mark.parametrize(("scenario", "label", "endpoint"), TRIALS)
def test_existing_executor_bytes_verify_without_redispatch(
    environment, scenario, label, endpoint
):
    context, receipt, calls, dispatches, _ = archive(
        environment, scenario=scenario
    )
    assert len(dispatches) == 1
    before_calls = len(calls)
    verified = verify_archived_registered_red(**context)
    assert len(calls) == before_calls
    assert len(dispatches) == 1
    assert verified.run_id == receipt.run_id
    assert verified.receipt_sha256 == context["receipt_sha256"]
    assert verified.observation.exploit_confirmed
    assert verified.endpoint_id == endpoint
    assert verified.vulnerability_class == label.value
    gate = authorize_bound_source_analysis(
        decision=triage(label),
        selected_test_id=verified.test_id,
        target_id="vulnerable-store",
        trusted_endpoint_id=endpoint,
        trusted_run_id=verified.run_id,
        evidence=verified,
        registry=context["registry"],
    )
    assert gate.action == BlueNextAction.SOURCE_ANALYSIS


@pytest.mark.parametrize("file_name", (
    "receipt.json",
    "stdout.raw",
    "stderr.raw",
    "observation.json",
    "dispatch-intent.json",
))
def test_single_byte_archive_tamper_is_rejected(environment, file_name):
    context, _, _, _, _ = archive(environment)
    with (context["evidence_dir"] / file_name).open("ab") as f:
        f.write(b"\n")
    with pytest.raises(BoundRedEvidenceError):
        verify_archived_registered_red(**context)


def test_source_checkout_drift_rejected_before_observation_binding(environment):
    context, _, _, _, _ = archive(environment)
    source_file = context["source_root"] / "services/controlled_executor.py"
    source_file.write_bytes(source_file.read_bytes() + b"\\n# archive changed\\n")
    with pytest.raises(BoundRedEvidenceError, match="checkout source SHA"):
        verify_archived_registered_red(**context)


def test_external_admission_digest_is_mandatory(environment):
    context, _, _, _, _ = archive(environment)
    context["admission_sha256"] = "0" * 64
    with pytest.raises(BoundRedEvidenceError):
        verify_archived_registered_red(**context)


def test_external_receipt_digest_is_mandatory(environment):
    context, _, _, _, _ = archive(environment)
    context["receipt_sha256"] = "0" * 64
    with pytest.raises(BoundRedEvidenceError, match="receipt"):
        verify_archived_registered_red(**context)


def test_dispatch_root_and_command_must_match_independent_root(environment, tmp_path):
    context, _, _, _, _ = archive(environment)
    context["dispatch_root"] = tmp_path
    with pytest.raises(BoundRedEvidenceError):
        verify_archived_registered_red(**context)


@pytest.mark.parametrize(("scenario", "label", "endpoint"), TRIALS)
def test_existing_archived_provenance_controller_obeys_predicted_label(
    environment, scenario, label, endpoint
):
    context, receipt, _calls, dispatches, _ = archive(
        environment, scenario=scenario
    )
    bound = verify_archived_registered_red(**context)
    recorded = []
    def selection():
        recorded.append("select")
        return bound.test_id
    def load(test_id):
        recorded.append("load:" + test_id)
        return verify_archived_registered_red(**context)
    result = run_archived_evidence_gate(
        decision=triage(label),
        target_id="vulnerable-store",
        trusted_endpoint_id=endpoint,
        trusted_run_id=receipt.run_id,
        registry=context["registry"],
        select_test=selection,
        load_bound_evidence=load,
    )
    assert result.triage.action == BlueNextAction.SELECT_REGISTERED_TEST
    assert result.final.action == BlueNextAction.SOURCE_ANALYSIS
    assert result.test_selection_calls == result.archived_evidence_load_calls == 1
    assert recorded == ["select", "load:" + bound.test_id]
    assert len(dispatches) == 1


@pytest.mark.parametrize(("prediction", "expected"), (
    (ClassificationLabel.BENIGN, BlueNextAction.NO_ACTION),
    (ClassificationLabel.UNKNOWN, BlueNextAction.MANUAL_REVIEW),
))
def test_nonattack_never_reads_archived_evidence_or_selects_test(
    environment, prediction, expected
):
    context, receipt, _, dispatches, _ = archive(environment)
    def fail_selection():
        raise AssertionError("no test-selection callback allowed")
    def fail_read(_):
        raise AssertionError("no evidence read allowed")
    result = run_archived_evidence_gate(
        decision=triage(prediction),
        target_id="vulnerable-store",
        trusted_endpoint_id="scenario-sqli-login",
        trusted_run_id=receipt.run_id,
        registry=context["registry"],
        select_test=fail_selection,
        load_bound_evidence=fail_read,
    )
    assert result.final.action == expected
    assert result.test_selection_calls == result.archived_evidence_load_calls == 0
    assert len(dispatches) == 1


@pytest.mark.parametrize(("fault", "expected_calls"), (
    ("wrong_test", 0),
    ("missing_archive", 1),
    ("wrong_run", 1),
    ("wrong_class", 1),
    ("archive_failure", 1),
))
def test_bound_controller_denies_mismatches_or_missing_archive_without_retry(
    environment, fault, expected_calls
):
    context, receipt, _calls, dispatches, _ = archive(environment)
    verified = verify_archived_registered_red(**context)
    selected = (
        "xss-reflection-001" if fault == "wrong_test" else verified.test_id
    )
    log = []
    def select():
        log.append("select")
        return selected
    def load(_):
        log.append("load")
        if fault == "archive_failure":
            raise BoundRedEvidenceError("unverifiable archive")
        if fault == "missing_archive":
            return None
        if fault == "wrong_run":
            return replace(verified, run_id="unrelated")
        if fault == "wrong_class":
            return replace(verified, vulnerability_class="xss")
        return verified
    gate = run_archived_evidence_gate(
        decision=triage(ClassificationLabel.SQL_INJECTION),
        target_id="vulnerable-store",
        trusted_endpoint_id="scenario-sqli-login",
        trusted_run_id=receipt.run_id,
        registry=context["registry"],
        select_test=select,
        load_bound_evidence=load,
    )
    assert gate.final.action == BlueNextAction.WITHHOLD_REPAIR
    assert gate.test_selection_calls == 1
    assert gate.archived_evidence_load_calls == expected_calls
    assert log.count("select") == 1
    assert log.count("load") == expected_calls
    assert len(dispatches) == 1


def test_offline_receipt_does_not_grant_patch_application_or_new_red_authorship(
    environment,
):
    context, receipt, _, _, _ = archive(environment)
    assert receipt.agent_red_plan_authored is False
    assert receipt.model_calls == 0
    assert receipt.scope == "development_only_not_final_research"
    bound = verify_archived_registered_red(**context)
    assert bound.evidence_scope == "archived_development_provenance"
    assert bound.observation.research_final_result is False
    assert bound.observation.agent_red_plan_authored is False
