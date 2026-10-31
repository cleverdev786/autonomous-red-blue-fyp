"""Model-only routing and trusted Red provenance: pure, offline, fail-closed."""
from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from schemas.common import ClassificationLabel, VulnerabilityClass, WorkflowState
from schemas.red_team import (
    AttackPlan,
    AttackVerification,
    EvidenceItem,
    ReconnaissanceResult,
    RedTeamRunResult,
)
from schemas.red_team import (
    TestExecutionResult as ExecutionResult,
)
from schemas.rq2_dataset import RQ2ClassificationDecision
from services.model_driven_decision_gate import (
    BlueNextAction,
    authorize_registered_test,
    authorize_source_analysis,
    route_model_triage,
    run_prospective_gate,
)
from services.target_registry import TargetRegistry

ROOT = Path(__file__).resolve().parents[1]
TARGET = "vulnerable-store"
RUN_ID = "gate4-dev-run"
CASES = (
    (ClassificationLabel.SQL_INJECTION, VulnerabilityClass.SQL_INJECTION,
     "sqli-login-bypass-001", "scenario-sqli-login"),
    (ClassificationLabel.XSS, VulnerabilityClass.XSS,
     "xss-reflection-001", "scenario-xss-search"),
    (ClassificationLabel.PATH_TRAVERSAL, VulnerabilityClass.PATH_TRAVERSAL,
     "path-traversal-private-file-001", "scenario-path-traversal-read"),
)


@pytest.fixture
def registry():
    return TargetRegistry.from_directories(
        targets_dir=ROOT / "config/targets",
        security_tests_dir=ROOT / "config/security_tests",
    )


def model(label: ClassificationLabel):
    return RQ2ClassificationDecision(
        classification=label, confidence=0.9,
        reason="Synthetic typed Q6 decision. No evaluator truth.",
    )


def red_result(category, selected_test, endpoint_id):
    evidence = EvidenceItem(
        evidence_id="trusted-evidence-001",
        evidence_type="registered_observation",
        summary="Trusted registered executor confirmed synthetic exploit.",
    )
    return RedTeamRunResult(
        run_id=RUN_ID, target_id=TARGET, attempt_number=1,
        reconnaissance=ReconnaissanceResult(
            target_id=TARGET, candidate_endpoints=(),
            rationale="Trusted registered surface.",
        ),
        attack_plan=AttackPlan(
            target_id=TARGET, test_id=selected_test, endpoint_id=endpoint_id,
            vulnerability_class=category, rationale="Registered test selection.",
        ),
        execution=ExecutionResult(
            run_id=RUN_ID, target_id=TARGET, test_id=selected_test,
            attempt_number=1, request_count=2, completed=True,
            status_code=200, evidence=(evidence,), duration_ms=20,
        ),
        verification=AttackVerification(
            target_id=TARGET, test_id=selected_test, confirmed=True,
            confidence=1, evidence_ids=(evidence.evidence_id,),
            reason="Independent registered evaluator confirmed exploit.",
        ),
        final_state=WorkflowState.BLUE_MONITORING,
    )


@pytest.mark.parametrize(("classification", "expected"), (
    (ClassificationLabel.BENIGN, BlueNextAction.NO_ACTION),
    (ClassificationLabel.UNKNOWN, BlueNextAction.MANUAL_REVIEW),
    (ClassificationLabel.SQL_INJECTION, BlueNextAction.SELECT_REGISTERED_TEST),
    (ClassificationLabel.XSS, BlueNextAction.SELECT_REGISTERED_TEST),
    (ClassificationLabel.PATH_TRAVERSAL, BlueNextAction.SELECT_REGISTERED_TEST),
))
def test_model_prediction_alone_selects_first_branch(classification, expected):
    actual = route_model_triage(decision=model(classification))
    assert actual.action == expected
    assert not actual.may_prepare_patch


def test_evaluator_truth_cannot_be_passed_to_any_gate():
    forbidden = {
        "ground_truth", "expected_class", "is_benign",
        "malicious_expected", "evaluator", "truth", "correct_label",
    }
    for function in (route_model_triage, authorize_registered_test, authorize_source_analysis):
        assert not set(inspect.signature(function).parameters).intersection(forbidden)


@pytest.mark.parametrize(("case_id", "prediction"), (
    ("benign_login_near_miss", ClassificationLabel.SQL_INJECTION),
    ("benign_normal_search", ClassificationLabel.UNKNOWN),
    ("benign_public_file", ClassificationLabel.PATH_TRAVERSAL),
))
def test_historical_false_positives_are_not_silently_changed_into_no_action(
    case_id, prediction
):
    verdict = route_model_triage(decision=model(prediction))
    assert verdict.action != BlueNextAction.NO_ACTION, case_id
    assert not verdict.may_prepare_patch


@pytest.mark.parametrize(("classification", "category", "test", "endpoint"), CASES)
def test_verified_red_allows_only_source_analysis(
    registry, classification, category, test, endpoint
):
    selected = authorize_registered_test(
        decision=model(classification), selected_test_id=test,
        target_id=TARGET, trusted_endpoint_id=endpoint, registry=registry,
    )
    assert selected.action == BlueNextAction.SELECT_REGISTERED_TEST
    assert not selected.may_prepare_patch
    result = authorize_source_analysis(
        decision=model(classification), selected_test_id=test,
        target_id=TARGET, trusted_endpoint_id=endpoint,
        trusted_run_id=RUN_ID, red=red_result(category, test, endpoint),
        registry=registry,
    )
    assert result.action == BlueNextAction.SOURCE_ANALYSIS
    assert result.may_prepare_patch


@pytest.mark.parametrize("label", (ClassificationLabel.BENIGN, ClassificationLabel.UNKNOWN))
def test_non_actionable_prediction_cannot_dispatch_or_patch(registry, label):
    kw = {
        "decision": model(label), "selected_test_id": CASES[0][2],
        "target_id": TARGET, "trusted_endpoint_id": CASES[0][3],
        "registry": registry,
    }
    assert authorize_registered_test(**kw).action == BlueNextAction.WITHHOLD_REPAIR
    assert authorize_source_analysis(
        **kw, trusted_run_id=RUN_ID, red=red_result(*CASES[0][1:]),
    ).action == BlueNextAction.WITHHOLD_REPAIR


@pytest.mark.parametrize("fault", ("unregistered", "wrong_class", "wrong_route", "missing"))
def test_untrusted_or_wrong_registered_selection_is_rejected(registry, fault):
    label, _, test, endpoint = CASES[0]
    if fault == "unregistered":
        test = "not-registered"
    if fault == "wrong_class":
        test = CASES[1][2]
    if fault == "wrong_route":
        endpoint = CASES[1][3]
    if fault == "missing":
        endpoint = "absent"
    verdict = authorize_registered_test(
        decision=model(label), selected_test_id=test,
        target_id=TARGET, trusted_endpoint_id=endpoint, registry=registry,
    )
    assert verdict.action == BlueNextAction.WITHHOLD_REPAIR


@pytest.mark.parametrize("fault", (
    "missing_red", "wrong_run", "wrong_test", "wrong_endpoint",
    "wrong_classification", "incomplete", "timed_out",
    "no_evidence", "unconfirmed", "wrong_evidence_id", "wrong_target",
))
def test_unbound_or_unconfirmed_red_evidence_is_rejected(registry, fault):
    label, category, test, endpoint = CASES[0]
    red = red_result(category, test, endpoint)
    if fault == "missing_red":
        red = None
    elif fault == "wrong_run":
        red = red.model_copy(update={"run_id": "other"})
    elif fault == "wrong_test":
        red = red.model_copy(update={
            "execution": red.execution.model_copy(update={"test_id": CASES[1][2]})
        })
    elif fault == "wrong_endpoint":
        red = red.model_copy(update={
            "attack_plan": red.attack_plan.model_copy(
                update={"endpoint_id": CASES[1][3]})
        })
    elif fault == "wrong_classification":
        red = red.model_copy(update={
            "attack_plan": red.attack_plan.model_copy(
                update={"vulnerability_class": VulnerabilityClass.XSS})
        })
    elif fault == "incomplete":
        red = red.model_copy(update={
            "execution": red.execution.model_copy(update={"completed": False})
        })
    elif fault == "timed_out":
        red = red.model_copy(update={
            "execution": red.execution.model_copy(update={"timed_out": True})
        })
    elif fault == "no_evidence":
        red = red.model_copy(update={
            "execution": red.execution.model_copy(update={"evidence": ()})
        })
    elif fault == "unconfirmed":
        red = red.model_copy(update={
            "verification": red.verification.model_copy(update={"confirmed": False})
        })
    elif fault == "wrong_evidence_id":
        red = red.model_copy(update={
            "verification": red.verification.model_copy(
                update={"evidence_ids": ("forged",)})
        })
    elif fault == "wrong_target":
        red = red.model_copy(update={"target_id": "wrong"})
    outcome = authorize_source_analysis(
        decision=model(label), selected_test_id=test, target_id=TARGET,
        trusted_endpoint_id=endpoint, trusted_run_id=RUN_ID,
        red=red, registry=registry,
    )
    assert outcome.action == BlueNextAction.WITHHOLD_REPAIR
    assert not outcome.may_prepare_patch


@pytest.mark.parametrize(("prediction", "expected"), (
    (ClassificationLabel.BENIGN, BlueNextAction.NO_ACTION),
    (ClassificationLabel.UNKNOWN, BlueNextAction.MANUAL_REVIEW),
))
def test_prospective_controller_skips_downstream_on_nonattacks(
    registry, prediction, expected
):
    def never_select():
        raise AssertionError("selection must not run")
    def never_execute(_):
        raise AssertionError("Red execution must not run")
    receipt = run_prospective_gate(
        decision=model(prediction), target_id=TARGET,
        trusted_endpoint_id=CASES[0][3], trusted_run_id=RUN_ID,
        registry=registry, select_test=never_select,
        execute_registered=never_execute,
    )
    assert receipt.final.action == expected
    assert receipt.test_selection_calls == receipt.registered_execution_calls == 0


def test_prospective_controller_orders_selection_then_red(registry):
    _, category, test, endpoint = CASES[0]
    calls = []
    def select():
        calls.append("selection")
        return test
    def red(chosen):
        calls.append("registered")
        return red_result(category, chosen, endpoint)
    receipt = run_prospective_gate(
        decision=model(ClassificationLabel.SQL_INJECTION), target_id=TARGET,
        trusted_endpoint_id=endpoint, trusted_run_id=RUN_ID,
        registry=registry, select_test=select, execute_registered=red,
    )
    assert calls == ["selection", "registered"]
    assert receipt.test_selection_calls == receipt.registered_execution_calls == 1
    assert receipt.final.action == BlueNextAction.SOURCE_ANALYSIS


@pytest.mark.parametrize(("fault", "expected_exec", "reason"), (
    ("bad_test", 0, "selection_context_mismatch"),
    ("no_red", 1, "no_verified_red_evidence"),
    ("select_throws", 0, "test_selection_failed"),
    ("red_throws", 1, "registered_execution_failed"),
))
def test_prospective_controller_blocks_without_retries(
    registry, fault, expected_exec, reason
):
    _, category, test, endpoint = CASES[0]
    calls = []
    def select():
        calls.append("selection")
        if fault == "select_throws":
            raise RuntimeError("model failure")
        return CASES[1][2] if fault == "bad_test" else test
    def red(chosen):
        calls.append("registered")
        if fault == "red_throws":
            raise RuntimeError("executor failure")
        return None if fault == "no_red" else red_result(category, chosen, endpoint)
    receipt = run_prospective_gate(
        decision=model(ClassificationLabel.SQL_INJECTION), target_id=TARGET,
        trusted_endpoint_id=endpoint, trusted_run_id=RUN_ID,
        registry=registry, select_test=select, execute_registered=red,
    )
    assert calls.count("selection") == 1
    assert calls.count("registered") == expected_exec
    assert receipt.final.action == BlueNextAction.WITHHOLD_REPAIR
    assert receipt.final.reason_code == reason


def test_false_positive_still_triggers_selection_but_not_unconfirmed_patch(registry):
    _, _, test, endpoint = CASES[0]
    calls = []
    def select():
        calls.append("selected")
        return test
    def no_verified_red(_):
        calls.append("executed")
    receipt = run_prospective_gate(
        decision=model(ClassificationLabel.SQL_INJECTION), target_id=TARGET,
        trusted_endpoint_id=endpoint, trusted_run_id=RUN_ID,
        registry=registry, select_test=select, execute_registered=no_verified_red,
    )
    assert calls == ["selected", "executed"]
    assert receipt.triage.action == BlueNextAction.SELECT_REGISTERED_TEST
    assert receipt.final.action == BlueNextAction.WITHHOLD_REPAIR
    assert not receipt.final.may_prepare_patch
