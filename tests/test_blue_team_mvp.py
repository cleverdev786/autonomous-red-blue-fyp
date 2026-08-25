"""Milestone 11 Blue Team triage, source-reader, and code-analysis tests."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from llm.mock_provider import MockProvider
from orchestrator.blue_team_flow import (
    BlueTeamFlow,
    BlueTeamFlowError,
    BlueTeamPolicyBlocked,
)
from orchestrator.limits import RunLimitTracker
from orchestrator.policy_engine import PolicyEngine
from schemas.blue_team import CodeFinding, TriageResult
from schemas.common import AgentRole, ClassificationLabel, PolicyReasonCode, WorkflowState
from schemas.experiments import ClassificationMode, ExperimentLimits
from schemas.logging import ApplicationEventType, ApplicationLogEvent, LogReadResult
from services.audit_service import AuditService
from services.rule_engine import RuleEngine
from services.source_reader import SourceReadBlocked, SourceReader
from services.target_registry import TargetRegistry


ROOT = Path(__file__).resolve().parents[1]
TARGET_ID = "vulnerable-store"
NOW = datetime(2026, 8, 25, 7, 30, tzinfo=UTC)


@pytest.fixture
def registry() -> TargetRegistry:
    return TargetRegistry.from_directories(
        targets_dir=ROOT / "config" / "targets",
        security_tests_dir=ROOT / "config" / "security_tests",
    )


def _event(
    event_id: str,
    *,
    run_id: str = "blue-run-001",
    route_name: str = "search",
    event_type: ApplicationEventType = ApplicationEventType.VALIDATION_EVENT,
    attributes: dict[str, object] | None = None,
) -> ApplicationLogEvent:
    return ApplicationLogEvent(
        schema_version="1.0",
        event_id=event_id,
        timestamp=NOW,
        run_id=run_id,
        request_id=f"req-{event_id}",
        event_type=event_type,
        component="vulnerable-store",
        route_name=route_name,
        method="GET",
        status_code=200,
        attributes=attributes or {},
    )


def _logs(
    *events: ApplicationLogEvent,
    run_id: str = "blue-run-001",
) -> LogReadResult:
    return LogReadResult(
        target_id=TARGET_ID,
        run_id=run_id,
        events=tuple(events),
    )


def _flow(
    *,
    registry: TargetRegistry,
    tmp_path: Path,
    provider,
    limits: ExperimentLimits | None = None,
) -> BlueTeamFlow:
    policy = PolicyEngine(registry=registry, project_root=ROOT)
    return BlueTeamFlow(
        target_registry=registry,
        policy_engine=policy,
        limits=RunLimitTracker(limits or ExperimentLimits()),
        provider=provider,
        audit_service=AuditService(project_root=tmp_path),
        project_root=ROOT,
    )


def _source_reader(
    *,
    registry: TargetRegistry,
    tmp_path: Path,
) -> SourceReader:
    policy = PolicyEngine(registry=registry, project_root=ROOT)
    return SourceReader(
        registry=registry,
        policy_engine=policy,
        audit_service=AuditService(project_root=tmp_path),
        project_root=ROOT,
    )


class CapturingProvider:
    def __init__(self, delegate: MockProvider) -> None:
        self.delegate = delegate
        self.inputs: dict[AgentRole, Mapping[str, Any]] = {}

    def generate_structured(
        self,
        *,
        role: AgentRole,
        input_data: Mapping[str, Any],
        response_model: type[BaseModel],
    ):
        self.inputs[role] = input_data
        return self.delegate.generate_structured(
            role=role,
            input_data=input_data,
            response_model=response_model,
        )


class InventedEvidenceProvider:
    def generate_structured(
        self,
        *,
        role: AgentRole,
        input_data: Mapping[str, Any],
        response_model: type[BaseModel],
    ):
        assert role == AgentRole.BLUE_TRIAGE
        logs = LogReadResult.model_validate(input_data["logs"])
        return {
            "run_id": logs.run_id,
            "is_suspicious": True,
            "classification": "xss",
            "confidence": 1.0,
            "supporting_event_ids": ["evt-invented"],
            "reason": "Deliberately invalid fixture.",
        }


class WrongFindingProvider:
    def __init__(self) -> None:
        self.delegate = MockProvider(blue_classification=ClassificationLabel.XSS)

    def generate_structured(
        self,
        *,
        role: AgentRole,
        input_data: Mapping[str, Any],
        response_model: type[BaseModel],
    ):
        if role == AgentRole.BLUE_CODE_ANALYSIS:
            triage = TriageResult.model_validate(input_data["triage"])
            return {
                "run_id": triage.run_id,
                "file_path": "orchestrator/policy_engine.py",
                "function_or_route": "forged",
                "root_cause": "Deliberately invalid fixture.",
                "supporting_lines": [{"start_line": 1, "end_line": 1}],
                "confidence": 1.0,
            }
        return self.delegate.generate_structured(
            role=role,
            input_data=input_data,
            response_model=response_model,
        )


def test_triage_schema_rejects_label_outside_frozen_set() -> None:
    with pytest.raises(ValidationError):
        TriageResult.model_validate(
            {
                "run_id": "blue-run-001",
                "is_suspicious": True,
                "classification": "command_injection",
                "confidence": 1.0,
                "supporting_event_ids": ["evt-1"],
                "reason": "Not an approved RQ2 label.",
            }
        )


def test_source_reader_allows_bounded_application_python_source(
    registry: TargetRegistry,
    tmp_path: Path,
) -> None:
    snippet = _source_reader(registry=registry, tmp_path=tmp_path).read_file(
        run_id="source-run",
        target_id=TARGET_ID,
        relative_path="dummy_apps/vulnerable_store/app/scenario_routes.py",
        start_line=37,
        max_lines=20,
    )

    assert snippet.file_path.endswith("app/scenario_routes.py")
    assert snippet.start_line == 37
    assert snippet.end_line <= 56
    assert "vulnerable_login" in snippet.content


@pytest.mark.parametrize(
    ("relative_path", "reason"),
    [
        ("orchestrator/policy_engine.py", PolicyReasonCode.SOURCE_PATH_NOT_ALLOWED),
        ("dummy_apps/vulnerable_store/.env", PolicyReasonCode.PROTECTED_PATH),
        (
            "dummy_apps/vulnerable_store/scenarios/xss-search-001.json",
            PolicyReasonCode.SOURCE_PATH_NOT_ALLOWED,
        ),
        (
            "dummy_apps/vulnerable_store/tests/test_baseline.py",
            PolicyReasonCode.SOURCE_PATH_NOT_ALLOWED,
        ),
    ],
)
def test_source_reader_blocks_outside_app_ground_truth_and_secret_paths(
    registry: TargetRegistry,
    tmp_path: Path,
    relative_path: str,
    reason: PolicyReasonCode,
) -> None:
    reader = _source_reader(registry=registry, tmp_path=tmp_path)
    with pytest.raises(SourceReadBlocked) as exc_info:
        reader.read_file(
            run_id="blocked-source-run",
            target_id=TARGET_ID,
            relative_path=relative_path,
        )
    assert exc_info.value.reason_code == reason

    audit = AuditService(project_root=tmp_path).read_run(run_id="blocked-source-run")
    assert audit
    assert audit[-1].operation == "source_read"
    assert audit[-1].execution_status.value == "blocked"


def test_source_reader_relevant_selection_never_returns_ground_truth_files(
    registry: TargetRegistry,
    tmp_path: Path,
) -> None:
    result = _source_reader(registry=registry, tmp_path=tmp_path).read_relevant(
        run_id="relevant-source-run",
        target_id=TARGET_ID,
        route_names=("search",),
    )

    assert result.snippets
    assert any(item.file_path.endswith("app/scenario_routes.py") for item in result.snippets)
    for snippet in result.snippets:
        assert snippet.file_path.startswith("dummy_apps/vulnerable_store/app/")
        assert snippet.file_path.endswith(".py")
        assert "/scenarios/" not in snippet.file_path
        assert len(snippet.content) <= 6000


def test_rule_only_reuses_existing_rule_engine_and_makes_zero_provider_calls(
    registry: TargetRegistry,
    tmp_path: Path,
) -> None:
    logs = _logs(_event("evt-xss", attributes={"value": "<script>run()</script>"}))
    provider = MockProvider(blue_classification=ClassificationLabel.BENIGN)
    flow = _flow(registry=registry, tmp_path=tmp_path, provider=provider)

    result = flow.classify(logs=logs, mode=ClassificationMode.RULE_ONLY)

    assert result == RuleEngine().classify(logs)
    assert result.classification == ClassificationLabel.XSS
    assert provider.call_roles == ()
    assert flow.limits.snapshot().model_calls == 0


def test_llm_only_does_not_invoke_rule_engine(
    registry: TargetRegistry,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    logs = _logs(_event("evt-llm", attributes={"value": "unfamiliar evidence"}))
    provider = MockProvider(blue_classification=ClassificationLabel.XSS)
    flow = _flow(registry=registry, tmp_path=tmp_path, provider=provider)

    def fail_if_called(*args, **kwargs):
        raise AssertionError("RuleEngine must not run in llm_only mode")

    monkeypatch.setattr(flow.rule_engine, "classify", fail_if_called)
    result = flow.classify(logs=logs, mode=ClassificationMode.LLM_ONLY)

    assert result.classification == ClassificationLabel.XSS
    assert provider.call_roles == (AgentRole.BLUE_TRIAGE,)


def test_hybrid_passes_rule_result_as_evidence_to_triage_agent(
    registry: TargetRegistry,
    tmp_path: Path,
) -> None:
    logs = _logs(_event("evt-hybrid", attributes={"requested_path": "../private.txt"}))
    delegate = MockProvider()
    provider = CapturingProvider(delegate)
    flow = _flow(registry=registry, tmp_path=tmp_path, provider=provider)

    result = flow.classify(logs=logs, mode=ClassificationMode.HYBRID)

    assert result.classification == ClassificationLabel.PATH_TRAVERSAL
    triage_input = provider.inputs[AgentRole.BLUE_TRIAGE]
    assert "rule_result" in triage_input
    assert triage_input["rule_result"]["classification"] == "path_traversal"
    assert triage_input["logs"] == logs.model_dump(mode="json")


def test_all_three_modes_return_same_triage_contract(
    registry: TargetRegistry,
    tmp_path: Path,
) -> None:
    logs = _logs(_event("evt-shared", attributes={"value": "<script>run()</script>"}))

    outputs = []
    for mode in ClassificationMode:
        provider = MockProvider(blue_classification=ClassificationLabel.XSS)
        flow = _flow(registry=registry, tmp_path=tmp_path / mode.value, provider=provider)
        outputs.append(flow.classify(logs=logs, mode=mode))

    assert all(isinstance(output, TriageResult) for output in outputs)
    assert {output.classification for output in outputs} == {ClassificationLabel.XSS}
    assert {tuple(output.model_dump().keys()) for output in outputs} == {
        tuple(outputs[0].model_dump().keys())
    }


def test_triage_rejects_invented_supporting_event_id(
    registry: TargetRegistry,
    tmp_path: Path,
) -> None:
    logs = _logs(_event("evt-real"))
    flow = _flow(registry=registry, tmp_path=tmp_path, provider=InventedEvidenceProvider())

    with pytest.raises(BlueTeamFlowError, match="unknown supporting event ID"):
        flow.classify(logs=logs, mode=ClassificationMode.LLM_ONLY)


def test_monitoring_agent_is_available_but_not_required_by_rq2_classifier(
    registry: TargetRegistry,
    tmp_path: Path,
) -> None:
    logs = _logs(_event("evt-monitor"))
    provider = MockProvider(blue_classification=ClassificationLabel.XSS)
    flow = _flow(registry=registry, tmp_path=tmp_path, provider=provider)

    result = flow.monitor(logs)

    assert result.event_ids == ("evt-monitor",)
    assert result.suspicious_event_ids == ("evt-monitor",)
    assert provider.call_roles == (AgentRole.BLUE_MONITORING,)


def test_model_budget_blocks_before_llm_provider_invocation(
    registry: TargetRegistry,
    tmp_path: Path,
) -> None:
    provider = MockProvider(blue_classification=ClassificationLabel.XSS)
    flow = _flow(
        registry=registry,
        tmp_path=tmp_path,
        provider=provider,
        limits=ExperimentLimits(max_model_calls=1),
    )
    flow.limits.consume_model_calls()

    with pytest.raises(BlueTeamPolicyBlocked) as exc_info:
        flow.classify(logs=_logs(_event("evt-budget")), mode=ClassificationMode.LLM_ONLY)

    assert exc_info.value.decision.reason_code == PolicyReasonCode.MODEL_CALL_LIMIT_REACHED
    assert provider.call_roles == ()


@pytest.mark.parametrize(
    ("classification", "route_name", "attributes", "expected_function"),
    [
        (
            ClassificationLabel.SQL_INJECTION,
            "login",
            {"username": "guest' OR 1=1 --"},
            "vulnerable_login",
        ),
        (
            ClassificationLabel.XSS,
            "search",
            {"value": "<script>run()</script>"},
            "vulnerable_search",
        ),
        (
            ClassificationLabel.PATH_TRAVERSAL,
            "file_read",
            {"requested_path": "../private.txt"},
            "vulnerable_file_read",
        ),
    ],
)
def test_full_supported_flows_move_from_logs_to_grounded_code_finding(
    registry: TargetRegistry,
    tmp_path: Path,
    classification: ClassificationLabel,
    route_name: str,
    attributes: dict[str, object],
    expected_function: str,
) -> None:
    logs = _logs(
        _event(
            f"evt-{classification.value}",
            route_name=route_name,
            attributes=attributes,
        )
    )
    provider = MockProvider(blue_classification=classification)
    flow = _flow(registry=registry, tmp_path=tmp_path, provider=provider)

    result = flow.run(logs=logs, mode=ClassificationMode.LLM_ONLY)

    assert result.triage.classification == classification
    assert result.code_finding is not None
    assert result.code_finding.file_path == (
        "dummy_apps/vulnerable_store/app/scenario_routes.py"
    )
    assert result.code_finding.function_or_route == expected_function
    assert result.code_finding.supporting_lines
    assert result.final_state == WorkflowState.CODE_ANALYSIS
    assert provider.call_roles == (
        AgentRole.BLUE_TRIAGE,
        AgentRole.BLUE_CODE_ANALYSIS,
    )


def test_benign_rule_only_flow_stops_after_triage_without_model_call(
    registry: TargetRegistry,
    tmp_path: Path,
) -> None:
    logs = _logs(_event("evt-benign", route_name="search", attributes={"value": "notebook"}))
    provider = MockProvider(blue_classification=ClassificationLabel.XSS)
    flow = _flow(registry=registry, tmp_path=tmp_path, provider=provider)

    result = flow.run(logs=logs, mode=ClassificationMode.RULE_ONLY)

    assert result.triage.classification == ClassificationLabel.BENIGN
    assert result.code_finding is None
    assert result.final_state == WorkflowState.TRIAGE
    assert provider.call_roles == ()


def test_code_finding_cannot_cite_file_not_supplied_by_source_reader(
    registry: TargetRegistry,
    tmp_path: Path,
) -> None:
    logs = _logs(
        _event(
            "evt-wrong-file",
            route_name="search",
            attributes={"value": "<script>run()</script>"},
        )
    )
    flow = _flow(registry=registry, tmp_path=tmp_path, provider=WrongFindingProvider())
    triage = flow.classify(logs=logs, mode=ClassificationMode.LLM_ONLY)

    with pytest.raises(BlueTeamFlowError, match="file not supplied"):
        flow.analyze_code(logs=logs, triage=triage)


def test_mock_code_analysis_uses_only_supplied_source_context_module() -> None:
    source = Path(ROOT / "llm" / "mock_provider.py").read_text(encoding="utf-8")
    assert "schemas.scenarios" not in source
    assert "security_tests" not in source
    assert "dummy_apps.vulnerable_store.scenarios" not in source
