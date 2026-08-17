"""Milestone 8 Red Team MVP architecture and workflow tests."""

from __future__ import annotations

import inspect
from pathlib import Path
from typing import Any, Mapping

import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel, ValidationError

from agents.red import AttackPlanningAgent, AttackVerificationAgent, ReconnaissanceAgent
from dummy_apps.vulnerable_store.app.config import StoreSettings
from dummy_apps.vulnerable_store.app.main import create_app
from infrastructure.executor.run_red_team_mvp import run_red_team_mvp
from llm.mock_provider import MockProvider
from orchestrator.limits import RunLimitTracker
from orchestrator.policy_engine import PolicyEngine
from orchestrator.red_team_flow import RedTeamFlow, RedTeamFlowError, RedTeamPolicyBlocked
from schemas.common import AgentRole, VulnerabilityClass, WorkflowState
from schemas.experiments import ExperimentLimits
from schemas.red_team import (
    AttackPlan,
    AttackVerification,
    EvidenceItem,
    TestExecutionResult as ExecutionResult,
)
from security_tests.registry import SecurityTestRegistry
from services.controlled_executor import ControlledExecutor, HttpTransport
from services.reconnaissance_service import ReconnaissanceService
from services.target_registry import TargetRegistry
from tests.test_controlled_executor import ClientTransportAdapter


ROOT = Path(__file__).resolve().parents[1]
TARGET_ID = "vulnerable-store"


@pytest.fixture
def registry() -> TargetRegistry:
    return TargetRegistry.from_directories(
        targets_dir=ROOT / "config" / "targets",
        security_tests_dir=ROOT / "config" / "security_tests",
    )


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    settings = StoreSettings(
        database_url=f"sqlite:///{(tmp_path / 'store.db').as_posix()}",
        seed_files_dir=tmp_path / "seed-files",
        scenario_files_dir=tmp_path / "scenario-files",
    )
    app = create_app(settings, reset_on_start=True)
    with TestClient(app) as test_client:
        yield test_client


class CapturingMockProvider(MockProvider):
    """Mock provider that retains the bounded inputs each role received."""

    def __init__(self, *, planned_test_id: str) -> None:
        super().__init__(planned_test_id=planned_test_id)
        self.inputs: list[tuple[AgentRole, Mapping[str, Any]]] = []

    def generate_structured(self, **kwargs):
        self.inputs.append((kwargs["role"], kwargs["input_data"]))
        return super().generate_structured(**kwargs)


class ScriptedProvider:
    """Delegate to MockProvider except for explicitly overridden role outputs."""

    def __init__(
        self,
        *,
        planned_test_id: str,
        overrides: Mapping[AgentRole, Mapping[str, Any]],
    ) -> None:
        self.delegate = MockProvider(planned_test_id=planned_test_id)
        self.overrides = dict(overrides)
        self.call_roles: list[AgentRole] = []

    def generate_structured(
        self,
        *,
        role: AgentRole,
        input_data: Mapping[str, Any],
        response_model: type[BaseModel],
    ):
        self.call_roles.append(role)
        if role in self.overrides:
            return self.overrides[role]
        return self.delegate.generate_structured(
            role=role,
            input_data=input_data,
            response_model=response_model,
        )


class StaticExecutor:
    """Small executor double for integrity-only tests; it performs no I/O."""

    def __init__(self, result: ExecutionResult) -> None:
        self.result = result
        self.calls: list[tuple[str, int]] = []

    def execute_registered_test(
        self,
        *,
        test_id: str,
        attempt_number: int,
    ) -> ExecutionResult:
        self.calls.append((test_id, attempt_number))
        return self.result


class RecordingPolicyEngine(PolicyEngine):
    """Record state-transition requests while retaining real policy behavior."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.transitions: list[tuple[WorkflowState, WorkflowState]] = []

    def validate_state_transition(self, *, current, requested):
        self.transitions.append((current, requested))
        return super().validate_state_transition(
            current=current,
            requested=requested,
        )


def build_flow(
    *,
    registry: TargetRegistry,
    provider,
    transport: HttpTransport | None = None,
    executor=None,
    max_model_calls: int = 3,
    policy_engine: PolicyEngine | None = None,
):
    policy = policy_engine or PolicyEngine(registry=registry, project_root=ROOT)
    limits = RunLimitTracker(
        ExperimentLimits(
            max_model_calls=max_model_calls,
            max_attack_attempts=1,
            max_patch_attempts=1,
            max_http_requests=10,
            max_runtime_seconds=60,
        )
    )
    if executor is None:
        if transport is None:
            raise ValueError("transport is required when executor is not supplied")
        executor = ControlledExecutor(
            target_registry=registry,
            test_registry=SecurityTestRegistry.default(),
            policy_engine=policy,
            limits=limits,
            transport=transport,
        )
    flow = RedTeamFlow(
        target_registry=registry,
        policy_engine=policy,
        limits=limits,
        executor=executor,
        provider=provider,
    )
    return flow, limits


def successful_execution(test_id: str) -> ExecutionResult:
    return ExecutionResult(
        target_id=TARGET_ID,
        test_id=test_id,
        attempt_number=1,
        request_count=1,
        completed=True,
        timed_out=False,
        status_code=200,
        evidence=(
            EvidenceItem(
                evidence_id="deterministic-evidence",
                evidence_type="test-observation",
                summary="Synthetic deterministic evidence for flow-integrity testing.",
            ),
        ),
        exchanges=(),
        duration_ms=1,
    )


def test_reconnaissance_and_planning_views_are_separate_and_narrow(
    registry: TargetRegistry,
) -> None:
    service = ReconnaissanceService(registry=registry)

    reconnaissance = service.build_reconnaissance_context(target_id=TARGET_ID)
    reconnaissance_dump = reconnaissance.model_dump(mode="json")
    assert set(reconnaissance_dump) == {"target_id", "endpoints"}
    for endpoint in reconnaissance_dump["endpoints"]:
        assert set(endpoint) == {"endpoint_id", "allowed_methods", "input_fields"}

    serialized_recon = reconnaissance.model_dump_json()
    for forbidden in (
        "test_id",
        "vulnerability_class",
        "allowed_parameter_names",
        "request_template_id",
        "success_evidence_rule_id",
        "hostname",
        "port",
        "source_root",
    ):
        assert forbidden not in serialized_recon

    catalog = service.build_attack_planning_catalog(target_id=TARGET_ID)
    catalog_dump = catalog.model_dump(mode="json")
    assert set(catalog_dump) == {"target_id", "options"}
    for option in catalog_dump["options"]:
        assert set(option) == {
            "test_id",
            "vulnerability_class",
            "endpoint_id",
            "allowed_parameter_names",
            "safe_description",
        }

    serialized_catalog = catalog.model_dump_json()
    for forbidden in (
        "request_template_id",
        "success_evidence_rule_id",
        "hostname",
        "port",
        "source_root",
        "writable_patch_roots",
    ):
        assert forbidden not in serialized_catalog


def test_agent_and_provider_contracts_remain_separate() -> None:
    for agent in (
        ReconnaissanceAgent(),
        AttackPlanningAgent(),
        AttackVerificationAgent(),
    ):
        assert not hasattr(agent, "provider")
        assert issubclass(agent.output_model, BaseModel)


@pytest.mark.parametrize(
    "test_id",
    [
        "sqli-login-bypass-001",
        "xss-reflection-001",
        "path-traversal-private-file-001",
    ],
)
def test_full_red_team_flow_reaches_blue_handoff_for_registered_scenarios(
    registry: TargetRegistry,
    client: TestClient,
    test_id: str,
) -> None:
    provider = CapturingMockProvider(planned_test_id=test_id)
    transport = ClientTransportAdapter(client)
    policy = RecordingPolicyEngine(registry=registry, project_root=ROOT)
    flow, limits = build_flow(
        registry=registry,
        provider=provider,
        transport=transport,
        policy_engine=policy,
    )

    result = flow.run(target_id=TARGET_ID, attempt_number=1)

    assert result.final_state == WorkflowState.BLUE_MONITORING
    assert result.attack_plan.test_id == test_id
    assert result.execution.test_id == result.attack_plan.test_id
    assert result.verification is not None
    assert result.verification.confirmed is True
    assert limits.snapshot().model_calls == 3
    assert provider.call_roles == (
        AgentRole.RED_RECONNAISSANCE,
        AgentRole.RED_ATTACK_PLANNER,
        AgentRole.RED_ATTACK_VERIFIER,
    )
    assert policy.transitions == [
        (WorkflowState.READY, WorkflowState.RECONNAISSANCE),
        (WorkflowState.RECONNAISSANCE, WorkflowState.ATTACK_PLANNING),
        (WorkflowState.ATTACK_PLANNING, WorkflowState.ATTACK_EXECUTING),
        (WorkflowState.ATTACK_EXECUTING, WorkflowState.ATTACK_VERIFYING),
        (WorkflowState.ATTACK_VERIFYING, WorkflowState.BLUE_MONITORING),
    ]

    recon_role, recon_input = provider.inputs[0]
    assert recon_role == AgentRole.RED_RECONNAISSANCE
    assert set(recon_input) == {"target_id", "endpoints"}
    assert "test_id" not in str(recon_input)

    planner_role, planner_input = provider.inputs[1]
    assert planner_role == AgentRole.RED_ATTACK_PLANNER
    assert set(planner_input) == {"reconnaissance", "planning_catalog"}


def test_attack_plan_outside_catalog_fails_before_executor(
    registry: TargetRegistry,
) -> None:
    selected = registry.get_security_test("xss-reflection-001")
    provider = ScriptedProvider(
        planned_test_id=selected.test_id,
        overrides={
            AgentRole.RED_ATTACK_PLANNER: {
                "target_id": TARGET_ID,
                "test_id": "unregistered-test",
                "endpoint_id": selected.endpoint_id,
                "vulnerability_class": selected.vulnerability_class.value,
                "parameter_choices": {},
                "rationale": "Attempt to select something outside the catalog.",
            }
        },
    )
    executor = StaticExecutor(successful_execution(selected.test_id))
    flow, _ = build_flow(
        registry=registry,
        provider=provider,
        executor=executor,
    )

    with pytest.raises(RedTeamFlowError, match="outside the restricted catalog"):
        flow.run(target_id=TARGET_ID)

    assert executor.calls == []


@pytest.mark.parametrize(
    "plan_changes, expected_message",
    [
        (
            {"endpoint_id": "scenario-sqli-login"},
            "endpoint does not match registered test metadata",
        ),
        (
            {"vulnerability_class": VulnerabilityClass.SQL_INJECTION.value},
            "vulnerability class does not match registered metadata",
        ),
        (
            {"parameter_choices": {"not-registered": "value"}},
            "unregistered parameter name",
        ),
    ],
)
def test_attack_plan_metadata_mismatch_fails_closed(
    registry: TargetRegistry,
    plan_changes: Mapping[str, Any],
    expected_message: str,
) -> None:
    selected = registry.get_security_test("xss-reflection-001")
    plan = {
        "target_id": TARGET_ID,
        "test_id": selected.test_id,
        "endpoint_id": selected.endpoint_id,
        "vulnerability_class": selected.vulnerability_class.value,
        "parameter_choices": {},
        "rationale": "Synthetic malformed planner output.",
    }
    plan.update(plan_changes)
    provider = ScriptedProvider(
        planned_test_id=selected.test_id,
        overrides={AgentRole.RED_ATTACK_PLANNER: plan},
    )
    executor = StaticExecutor(successful_execution(selected.test_id))
    flow, _ = build_flow(
        registry=registry,
        provider=provider,
        executor=executor,
    )

    with pytest.raises(RedTeamFlowError, match=expected_message):
        flow.run(target_id=TARGET_ID)

    assert executor.calls == []


def test_malformed_agent_output_is_rejected_by_pydantic(
    registry: TargetRegistry,
) -> None:
    provider = ScriptedProvider(
        planned_test_id="xss-reflection-001",
        overrides={
            AgentRole.RED_RECONNAISSANCE: {
                "target_id": TARGET_ID,
                "candidate_endpoints": [],
                "rationale": "Malformed because an extra field is forbidden.",
                "arbitrary_url": "https://example.com",
            }
        },
    )
    executor = StaticExecutor(successful_execution("xss-reflection-001"))
    flow, limits = build_flow(
        registry=registry,
        provider=provider,
        executor=executor,
    )

    with pytest.raises(ValidationError):
        flow.run(target_id=TARGET_ID)

    assert limits.snapshot().model_calls == 1
    assert executor.calls == []


def test_model_call_budget_blocks_before_provider_invocation_and_consumption(
    registry: TargetRegistry,
) -> None:
    provider = MockProvider(planned_test_id="xss-reflection-001")
    executor = StaticExecutor(successful_execution("xss-reflection-001"))
    flow, limits = build_flow(
        registry=registry,
        provider=provider,
        executor=executor,
        max_model_calls=2,
    )

    with pytest.raises(RedTeamPolicyBlocked) as exc:
        flow.run(target_id=TARGET_ID)

    assert exc.value.decision.reason_code.value == "model_call_limit_reached"
    assert limits.snapshot().model_calls == 2
    assert provider.call_roles == (
        AgentRole.RED_RECONNAISSANCE,
        AgentRole.RED_ATTACK_PLANNER,
    )
    assert executor.calls == [("xss-reflection-001", 1)]


@pytest.mark.parametrize("mismatch_kind", ["target", "test"])
def test_execution_identity_mismatch_transitions_to_rejected_without_verifier(
    registry: TargetRegistry,
    mismatch_kind: str,
) -> None:
    selected = "xss-reflection-001"
    valid = successful_execution(selected)
    if mismatch_kind == "target":
        mismatched = valid.model_copy(update={"target_id": "other-target"})
    else:
        mismatched = valid.model_copy(update={"test_id": "sqli-login-bypass-001"})

    provider = MockProvider(planned_test_id=selected)
    executor = StaticExecutor(mismatched)
    policy = RecordingPolicyEngine(registry=registry, project_root=ROOT)
    flow, limits = build_flow(
        registry=registry,
        provider=provider,
        executor=executor,
        policy_engine=policy,
    )

    result = flow.run(target_id=TARGET_ID)

    assert result.final_state == WorkflowState.REJECTED
    assert result.verification is None
    assert limits.snapshot().model_calls == 2
    assert provider.call_roles == (
        AgentRole.RED_RECONNAISSANCE,
        AgentRole.RED_ATTACK_PLANNER,
    )
    assert policy.transitions[-1] == (
        WorkflowState.ATTACK_VERIFYING,
        WorkflowState.REJECTED,
    )


@pytest.mark.parametrize(
    "execution, verification_override",
    [
        (
            ExecutionResult(
                target_id=TARGET_ID,
                test_id="xss-reflection-001",
                attempt_number=1,
                request_count=1,
                completed=True,
                timed_out=False,
                status_code=200,
                evidence=(),
                exchanges=(),
                duration_ms=1,
                error_code="evidence-not-observed",
            ),
            {
                "target_id": TARGET_ID,
                "test_id": "xss-reflection-001",
                "confirmed": True,
                "confidence": 1.0,
                "evidence_ids": (),
                "reason": "Agent text claims evidence that does not exist.",
            },
        ),
        (
            ExecutionResult(
                target_id=TARGET_ID,
                test_id="xss-reflection-001",
                attempt_number=1,
                request_count=1,
                completed=False,
                timed_out=True,
                status_code=None,
                evidence=(),
                exchanges=(),
                duration_ms=1,
                error_code="request-timeout",
            ),
            {
                "target_id": TARGET_ID,
                "test_id": "xss-reflection-001",
                "confirmed": True,
                "confidence": 1.0,
                "evidence_ids": (),
                "reason": "A timeout cannot be promoted to confirmation.",
            },
        ),
        (
            successful_execution("xss-reflection-001").model_copy(
                update={
                    "completed": False,
                    "timed_out": False,
                    "error_code": "incomplete-execution",
                }
            ),
            {
                "target_id": TARGET_ID,
                "test_id": "xss-reflection-001",
                "confirmed": True,
                "confidence": 1.0,
                "evidence_ids": ("deterministic-evidence",),
                "reason": "Incomplete execution cannot be promoted to confirmation.",
            },
        ),
        (
            successful_execution("xss-reflection-001"),
            {
                "target_id": TARGET_ID,
                "test_id": "xss-reflection-001",
                "confirmed": True,
                "confidence": 1.0,
                "evidence_ids": ("invented-evidence",),
                "reason": "The cited evidence identifier was invented.",
            },
        ),
        (
            successful_execution("xss-reflection-001"),
            {
                "target_id": TARGET_ID,
                "test_id": "xss-reflection-001",
                "confirmed": True,
                "confidence": 1.0,
                "evidence_ids": (),
                "reason": "Confirmation without citing deterministic evidence.",
            },
        ),
    ],
)
def test_verification_integrity_forces_rejection(
    registry: TargetRegistry,
    execution: ExecutionResult,
    verification_override: Mapping[str, Any],
) -> None:
    provider = ScriptedProvider(
        planned_test_id="xss-reflection-001",
        overrides={AgentRole.RED_ATTACK_VERIFIER: verification_override},
    )
    executor = StaticExecutor(execution)
    flow, limits = build_flow(
        registry=registry,
        provider=provider,
        executor=executor,
    )

    result = flow.run(target_id=TARGET_ID)

    assert result.final_state == WorkflowState.REJECTED
    assert result.verification is not None
    assert limits.snapshot().model_calls == 3


def test_runtime_helper_uses_planner_path_not_direct_cli_to_executor(
    registry: TargetRegistry,
    client: TestClient,
) -> None:
    source = inspect.getsource(run_red_team_mvp)
    assert ".execute_registered_test(" not in source

    result = run_red_team_mvp(
        project_root=ROOT,
        target_registry=registry,
        planned_test_id="xss-reflection-001",
        attempt_number=1,
        transport=ClientTransportAdapter(client),
    )

    assert result.attack_plan.test_id == "xss-reflection-001"
    assert result.execution.test_id == result.attack_plan.test_id
    assert result.final_state == WorkflowState.BLUE_MONITORING
