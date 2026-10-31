"""T02: model-free Red worker contracts, not the legacy provider workflow."""

import pytest
from pydantic import ValidationError

from agents.red.contracts import validate_worker_result
from schemas.red_team import (
    ExecutionWork,
    ExecutionWorkResult,
    PlanningWork,
    PlanningWorkResult,
    ReconnaissanceWork,
    ReconnaissanceWorkResult,
    RedScopeReference,
    RedEndpointCandidate,
    RedWorkerError,
    VerificationWork,
    VerificationWorkResult,
)


@pytest.fixture
def scope():
    return RedScopeReference(
        assessment_id="assessment-001",
        target_id="vulnerable-store",
        target_fingerprint="a" * 64,
        authorization_fingerprint="b" * 64,
    )


def test_four_stage_contracts_roundtrip_without_model_provider(scope, monkeypatch):
    class ProviderMustNotRun:
        def generate_structured(self, **_kwargs):
            raise AssertionError("a Red v1 contract must not call a model")

    monkeypatch.setattr(
        "llm.mock_provider.MockProvider.generate_structured",
        ProviderMustNotRun.generate_structured,
    )
    fixtures = [
        (ReconnaissanceWork(scope=scope), ReconnaissanceWorkResult(scope=scope)),
        (
            PlanningWork(scope=scope, surface_revision="surface-001"),
            PlanningWorkResult(scope=scope, plan_version="plan-001"),
        ),
        (
            ExecutionWork(scope=scope, plan_version="plan-001", operation_id="op-001"),
            ExecutionWorkResult(scope=scope, plan_version="plan-001",
                                operation_id="op-001", receipt_ids=("receipt-001",)),
        ),
        (
            VerificationWork(scope=scope, plan_version="plan-001",
                             operation_id="op-001", receipt_ids=("receipt-001",),
                             oracle_id="oracle-001"),
            VerificationWorkResult(scope=scope, plan_version="plan-001",
                                   operation_id="op-001", outcome="confirmed",
                                   evidence_receipt_ids=("receipt-001",)),
        ),
    ]
    for task, result in fixtures:
        serialized_task = type(task).model_validate_json(task.model_dump_json())
        serialized_result = type(result).model_validate_json(result.model_dump_json())
        assert validate_worker_result(serialized_task, serialized_result) == result


def test_reject_forged_scope_and_wrong_stage(scope):
    task = ReconnaissanceWork(scope=scope)
    other = scope.model_copy(update={"target_id": "external-target"})
    with pytest.raises(ValueError, match="scope"):
        validate_worker_result(task, ReconnaissanceWorkResult(scope=other))
    with pytest.raises(ValueError, match="stage"):
        validate_worker_result(task, PlanningWorkResult(scope=scope, plan_version="p1"))


def test_reject_malformed_scope_and_unknown_fields(scope):
    with pytest.raises(ValidationError):
        RedScopeReference.model_validate(
            {**scope.model_dump(), "target_fingerprint": "untrusted"}
        )
    with pytest.raises(ValidationError):
        ReconnaissanceWork.model_validate({"stage": "reconnaissance"})
    with pytest.raises(ValidationError):
        ReconnaissanceWork.model_validate({**ReconnaissanceWork(scope=scope).model_dump(),
                                          "arbitrary_shell": "echo bad"})


def test_require_operation_and_receipt_provenance(scope):
    task = ExecutionWork(scope=scope, plan_version="plan-001", operation_id="op-001")
    with pytest.raises(ValidationError):
        ExecutionWorkResult(scope=scope, plan_version="plan-001",
                            operation_id="op-001", receipt_ids=())
    with pytest.raises(ValueError, match="operation"):
        validate_worker_result(
            task, ExecutionWorkResult(scope=scope, plan_version="plan-001",
                                      operation_id="different-op",
                                      receipt_ids=("receipt-001",)),
        )
    with pytest.raises(ValueError, match="plan"):
        validate_worker_result(
            task, ExecutionWorkResult(scope=scope, plan_version="old-plan",
                                      operation_id="op-001", receipt_ids=("receipt-001",)),
        )


def test_unproven_verification_cannot_be_confirmed(scope):
    task = VerificationWork(scope=scope, plan_version="p1",
                            operation_id="op1", receipt_ids=("receipt-001",),
                            oracle_id="oracle-001")
    with pytest.raises(ValidationError):
        VerificationWorkResult(scope=scope, plan_version="p1", operation_id="op1",
                               outcome="confirmed")
    with pytest.raises(ValueError, match="receipt"):
        validate_worker_result(
            task,
            VerificationWorkResult(scope=scope, plan_version="p1",
                                   operation_id="op1", outcome="confirmed",
                                   evidence_receipt_ids=("forged",)),
        )


def test_discovery_candidate_cannot_be_external_url_or_masquerade_as_operation(scope):
    from datetime import datetime, timezone
    values = dict(
        candidate_id="candidate-001", method="GET",
        path="/scenarios/xss/search", parameter_names=("q",),
        source="zap", observed_at=datetime.now(timezone.utc),
    )
    candidate = RedEndpointCandidate(**values)
    task = PlanningWork(scope=scope, surface_revision="s1", candidates=(candidate,))
    assert task.candidates[0].path == "/scenarios/xss/search"
    for bad in ("http://example.org/", "//example.org/", "\\example.org/"):
        with pytest.raises(ValidationError):
            RedEndpointCandidate(**{**values, "path": bad})
    with pytest.raises(ValidationError):
        RedEndpointCandidate(**{**values, "shell_command": "ls"})


def test_failure_requires_structured_error(scope):
    with pytest.raises(ValidationError):
        ReconnaissanceWorkResult(scope=scope, status="failed")
    result = ReconnaissanceWorkResult(
        scope=scope, status="blocked",
        error=RedWorkerError(code="scope_blocked", message="Target not approved"),
    )
    assert validate_worker_result(ReconnaissanceWork(scope=scope), result) == result
