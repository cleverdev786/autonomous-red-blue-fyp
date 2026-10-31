"""T16 policy-admitted controlled HTTP execution."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from orchestrator.limits import RunLimitTracker
from orchestrator.policy_engine import PolicyEngine, StandardRedPolicy
from schemas.common import HttpMethod
from schemas.experiments import ExperimentLimits
from schemas.red_team import RedEndpointCandidate, RedPolicyUsage
from schemas.red_team_state import (
    AssessmentDTO,
    CoverageDTO,
    OperationDTO,
    PlanVersionDTO,
)
from security_tests.registry import SecurityTestRegistry
from services.controlled_executor import (
    ControlledExecutionBlocked,
    ControlledExecutor,
    PolicyAdmittedExecutor,
    TransportRequestError,
    TransportResponse,
    TransportTimeoutError,
)
from services.red_admission import AdmissionRequest, TrustedRedAdmission
from services.red_assessment_store import RedAssessmentStore
from services.red_evidence_store import RedEvidenceStore
from services.target_registry import TargetRegistry

ROOT = Path(__file__).resolve().parents[1]
IP = "172.19.0.7"


class XssTransport:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def send(self, **kwargs) -> TransportResponse:
        self.calls.append(kwargs)
        marker = kwargs["query_params"]["q"]
        return TransportResponse(
            status_code=200,
            text=f"Search term: {marker}",
            headers={},
        )


def build_execution_env(
    tmp_path: Path,
    *,
    allowed_classes: set[str] | None = None,
):
    registry = TargetRegistry.from_directories(
        targets_dir=ROOT / "config/targets",
        security_tests_dir=ROOT / "config/security_tests",
    )
    policy = StandardRedPolicy(
        registry=registry,
        budget_file=ROOT / "config/red_standard.json",
    )
    authorization = policy.freeze(
        assessment_id="as-1",
        approval_id="operator-review-1",
        target_id="vulnerable-store",
        allowed_classes=allowed_classes,
    )
    store = RedAssessmentStore(tmp_path / "red.sqlite3")
    store.create(
        AssessmentDTO(
            scope=authorization.scope,
            mode="manual",
            status="running",
            workflow_complete=False,
            coverage=CoverageDTO(),
        ),
        authorization,
        request_id="request-1",
    )
    store.add_candidate(
        "as-1",
        RedEndpointCandidate(
            candidate_id="candidate-xss",
            method="GET",
            path="/scenarios/xss/search",
            parameter_names=("q",),
            source="registered",
            observed_at=datetime(2026, 10, 28, tzinfo=UTC),
        ),
    )
    store.add_plan(
        PlanVersionDTO(
            scope=authorization.scope,
            plan_version="plan-1",
            surface_revision="surface-1",
            status="approved",
        )
    )
    store.add_operation(
        OperationDTO(
            scope=authorization.scope,
            operation_id="op-xss",
            plan_version="plan-1",
            candidate_id="candidate-xss",
            test_id="xss-reflection-001",
            status="approved",
        )
    )
    journal = RedEvidenceStore(store, tmp_path / "evidence")
    admission = TrustedRedAdmission(
        store=store,
        journal=journal,
        policy=policy,
        pinned_ips=frozenset({IP}),
        resolver=lambda _: (IP,),
    )
    transport = XssTransport()
    executor = ControlledExecutor(
        target_registry=registry,
        test_registry=SecurityTestRegistry.default(),
        policy_engine=PolicyEngine(registry=registry, project_root=ROOT),
        limits=RunLimitTracker(
            ExperimentLimits(
                max_model_calls=1,
                max_attack_attempts=3,
                max_patch_attempts=1,
                max_http_requests=24,
                max_runtime_seconds=180,
            )
        ),
        transport=transport,
    )
    request = AdmissionRequest(
        scope=authorization.scope,
        operation_id="op-xss",
        plan_version="plan-1",
        tool="controlled_http",
        method="GET",
        url="http://vulnerable-store:8000/scenarios/xss/search",
    )
    return PolicyAdmittedExecutor(admission=admission, executor=executor), request, transport


@pytest.fixture
def execution_env(tmp_path: Path):
    return build_execution_env(tmp_path)


def test_admitted_operation_returns_actual_scoped_receipt(execution_env) -> None:
    dispatcher, request, transport = execution_env

    receipt = dispatcher.execute(
        request=request,
        usage=RedPolicyUsage(),
        attempt_number=1,
        run_id="run-xss-1",
    )

    assert receipt.operation_id == "op-xss"
    assert receipt.plan_version == "plan-1"
    assert receipt.test_id == "xss-reflection-001"
    assert receipt.method == "GET"
    assert receipt.target_fingerprint == request.scope.target_fingerprint
    assert receipt.status == "completed"
    assert receipt.error_class is None
    assert receipt.request_count == 2
    assert receipt.evidence_ids == ("xss-unescaped-reflection-observed",)
    assert len(transport.calls) == 2
    persisted = dispatcher.admission.journal.list_receipts(request.scope)
    assert len(persisted) == 1
    assert persisted[0].receipt_id == receipt.receipt_id
    assert persisted[0].test_id == receipt.test_id


@pytest.mark.parametrize(
    ("changes", "usage"),
    [
        ({"operation_id": "unknown"}, RedPolicyUsage()),
        ({"method": HttpMethod.POST}, RedPolicyUsage()),
        ({"url": "http://external.test/scenarios/xss/search"}, RedPolicyUsage()),
        ({}, RedPolicyUsage(http_requests=23)),
    ],
)
def test_denied_identity_method_target_or_budget_never_reaches_transport(
    execution_env,
    changes,
    usage,
) -> None:
    dispatcher, request, transport = execution_env

    with pytest.raises(ControlledExecutionBlocked):
        dispatcher.execute(
            request=request.model_copy(update=changes),
            usage=usage,
            attempt_number=1,
            run_id="run-xss-1",
        )

    assert transport.calls == []


def test_unapproved_vulnerability_class_never_reaches_transport(tmp_path: Path) -> None:
    dispatcher, request, transport = build_execution_env(
        tmp_path,
        allowed_classes={"sql_injection"},
    )

    with pytest.raises(ControlledExecutionBlocked):
        dispatcher.execute(
            request=request,
            usage=RedPolicyUsage(),
            attempt_number=1,
            run_id="run-xss-1",
        )

    assert transport.calls == []


@pytest.mark.parametrize(
    ("error", "expected_status", "expected_class"),
    [
        (TransportTimeoutError("timeout"), "timeout", "request-timeout"),
        (TransportRequestError("unavailable"), "failed", "transport-error"),
    ],
)
def test_transport_failures_return_bounded_error_receipts(
    execution_env,
    error,
    expected_status,
    expected_class,
) -> None:
    dispatcher, request, transport = execution_env

    def fail(**kwargs):
        transport.calls.append(kwargs)
        raise error

    transport.send = fail
    receipt = dispatcher.execute(
        request=request,
        usage=RedPolicyUsage(),
        attempt_number=1,
        run_id="run-xss-error",
    )

    assert receipt.status == expected_status
    assert receipt.error_class == expected_class
    assert receipt.evidence_ids == ()
    assert len(transport.calls) == 1
    persisted = dispatcher.admission.journal.list_receipts(request.scope)
    assert persisted[0].status == expected_status
    assert persisted[0].request_count == 1
