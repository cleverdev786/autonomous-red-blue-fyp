"""Milestone 9 structured logging, correlation, LogReader, and audit tests."""

from __future__ import annotations

from datetime import UTC, datetime
import inspect
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dummy_apps.vulnerable_store.app.config import StoreSettings
from dummy_apps.vulnerable_store.app.main import create_app
from dummy_apps.vulnerable_store.app.structured_logging import (
    emit_structured_event,
    request_logging_context,
)
from llm.mock_provider import MockProvider
from orchestrator.limits import RunLimitTracker
from orchestrator.policy_engine import PolicyEngine
from orchestrator.red_team_flow import RedTeamFlow, RedTeamPolicyBlocked
from schemas.common import PolicyReasonCode, WorkflowState
from schemas.experiments import ExperimentLimits
from schemas.logging import (
    ApplicationEventType,
    ApplicationLogEvent,
    AuditExecutionStatus,
    AuditPolicyDecision,
)
from security_tests.registry import SecurityTestRegistry
from services.audit_service import AuditService
from services.controlled_executor import ControlledExecutor, HttpTransport
from services.log_reader import LogReader
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
def app_settings(tmp_path: Path) -> StoreSettings:
    return StoreSettings(
        database_url=f"sqlite:///{(tmp_path / 'store.db').as_posix()}",
        seed_files_dir=tmp_path / "seed-files",
        scenario_files_dir=tmp_path / "scenario-files",
    )


def _parse_application_events(output: str) -> tuple[ApplicationLogEvent, ...]:
    events: list[ApplicationLogEvent] = []
    for line in output.splitlines():
        try:
            decoded = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(decoded, dict) or decoded.get("schema_version") != "1.0":
            continue
        events.append(ApplicationLogEvent.model_validate(decoded))
    return tuple(events)


def _event(*, event_id: str, run_id: str, request_id: str) -> ApplicationLogEvent:
    return ApplicationLogEvent(
        schema_version="1.0",
        event_id=event_id,
        timestamp=datetime.now(UTC),
        run_id=run_id,
        request_id=request_id,
        event_type=ApplicationEventType.HTTP_REQUEST,
        component="vulnerable-store",
        route_name="search",
        method="GET",
        status_code=200,
        attributes={},
    )


def test_structural_fields_cannot_be_overridden_by_caller_attributes(capsys) -> None:
    with request_logging_context(
        run_id="trusted-run",
        request_id="trusted-request",
        method="POST",
        route_name="login",
    ):
        event = emit_structured_event(
            event_type=ApplicationEventType.DATABASE_EVENT,
            status_code=201,
            attributes={
                "schema_version": "evil",
                "event_id": "evil",
                "timestamp": "evil",
                "run_id": "evil-run",
                "request_id": "evil-request",
                "event_type": "application_error",
                "component": "evil-component",
                "route_name": "evil-route",
                "method": "DELETE",
                "status_code": 599,
                "username": "student1",
                "password": "must-never-appear",
                "api_token": "must-never-appear",
                "environment": "must-never-appear",
            },
        )

    assert event.schema_version == "1.0"
    assert event.run_id == "trusted-run"
    assert event.request_id == "trusted-request"
    assert event.event_type == ApplicationEventType.DATABASE_EVENT
    assert event.component == "vulnerable-store"
    assert event.route_name == "login"
    assert event.method == "POST"
    assert event.status_code == 201
    assert event.attributes == {"username": "student1"}

    emitted = capsys.readouterr().out.strip()
    parsed = ApplicationLogEvent.model_validate_json(emitted)
    assert parsed == event
    assert "must-never-appear" not in emitted


def test_newline_and_quote_heavy_attribute_remains_one_json_line(capsys) -> None:
    value = 'line-one\n"quoted"\n{still-data}'
    with request_logging_context(
        run_id="run-json",
        request_id="req-json",
        method="GET",
        route_name="search",
    ):
        emit_structured_event(
            event_type=ApplicationEventType.VALIDATION_EVENT,
            attributes={"value": value},
        )

    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 1
    event = ApplicationLogEvent.model_validate_json(lines[0])
    assert event.attributes["value"] == value


def test_scenario_logs_use_neutral_route_names_and_no_registry_ground_truth(
    app_settings: StoreSettings,
    capsys,
) -> None:
    app = create_app(app_settings, reset_on_start=True)
    with TestClient(app) as client:
        response = client.get(
            "/scenarios/xss/search",
            params={"q": "<script>alert(1)</script>"},
            headers={
                "X-FYP-Run-ID": "neutral-run",
                "X-FYP-Request-ID": "neutral-request",
            },
        )
    assert response.status_code == 200

    output = capsys.readouterr().out
    events = _parse_application_events(output)
    selected = [event for event in events if event.run_id == "neutral-run"]
    assert selected
    assert {event.route_name for event in selected} == {"search"}
    assert {event.request_id for event in selected} == {"neutral-request"}

    serialized = "\n".join(event.model_dump_json() for event in selected)
    assert "/scenarios/" not in serialized
    assert "endpoint_id" not in serialized
    assert "test_id" not in serialized
    assert "vulnerability_class" not in serialized


def test_required_application_event_categories_are_emitted(
    app_settings: StoreSettings,
    capsys,
) -> None:
    app = create_app(app_settings, reset_on_start=True)
    with TestClient(app) as client:
        headers = {
            "X-FYP-Run-ID": "category-run",
            "X-FYP-Request-ID": "req-db",
        }
        client.post(
            "/scenarios/sql-injection/login",
            json={"username": "student1", "password": "demo-pass-1"},
            headers=headers,
        )
        client.get(
            "/scenarios/xss/search",
            params={"q": "notebook"},
            headers={**headers, "X-FYP-Request-ID": "req-validation"},
        )
        client.get(
            "/scenarios/path-traversal/read",
            params={"path": "guide.txt"},
            headers={**headers, "X-FYP-Request-ID": "req-file"},
        )
        client.get(
            "/scenarios/path-traversal/read",
            headers={**headers, "X-FYP-Request-ID": "req-invalid"},
        )

    events = [
        event
        for event in _parse_application_events(capsys.readouterr().out)
        if event.run_id == "category-run"
    ]
    event_types = {event.event_type for event in events}
    assert ApplicationEventType.HTTP_REQUEST in event_types
    assert ApplicationEventType.VALIDATION_EVENT in event_types
    assert ApplicationEventType.DATABASE_EVENT in event_types
    assert ApplicationEventType.FILE_ACCESS_EVENT in event_types


def test_unhandled_application_error_is_structured_without_raw_path(
    app_settings: StoreSettings,
    capsys,
) -> None:
    app = create_app(app_settings, reset_on_start=True)

    @app.get("/boom")
    def boom() -> None:
        raise RuntimeError("synthetic failure")

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get(
            "/boom",
            headers={
                "X-FYP-Run-ID": "error-run",
                "X-FYP-Request-ID": "error-request",
            },
        )
    assert response.status_code == 500

    events = [
        event
        for event in _parse_application_events(capsys.readouterr().out)
        if event.run_id == "error-run"
    ]
    error_events = [
        event
        for event in events
        if event.event_type == ApplicationEventType.APPLICATION_ERROR
    ]
    assert len(error_events) == 1
    assert error_events[0].route_name == "other"
    assert error_events[0].error_type == "RuntimeError"
    assert "/boom" not in error_events[0].model_dump_json()


def test_executor_request_ids_correlate_with_application_logs(
    registry: TargetRegistry,
    app_settings: StoreSettings,
    capsys,
) -> None:
    app = create_app(app_settings, reset_on_start=True)
    with TestClient(app) as client:
        transport = ClientTransportAdapter(client)
        policy = PolicyEngine(registry=registry, project_root=ROOT)
        limits = RunLimitTracker(
            ExperimentLimits(
                max_model_calls=1,
                max_attack_attempts=1,
                max_patch_attempts=1,
                max_http_requests=10,
                max_runtime_seconds=60,
            )
        )
        executor = ControlledExecutor(
            target_registry=registry,
            test_registry=SecurityTestRegistry.default(),
            policy_engine=policy,
            limits=limits,
            transport=transport,
        )
        result = executor.execute_registered_test(
            test_id="xss-reflection-001",
            attempt_number=1,
            run_id="correlation-run",
        )

    assert result.run_id == "correlation-run"
    request_ids = {exchange.request_id for exchange in result.exchanges}
    assert len(request_ids) == 2

    events = [
        event
        for event in _parse_application_events(capsys.readouterr().out)
        if event.run_id == "correlation-run"
    ]
    assert events
    assert {event.request_id for event in events} == request_ids


def test_executor_transport_exposes_fixed_correlation_not_generic_headers() -> None:
    parameters = inspect.signature(HttpTransport.send).parameters
    assert "run_id" in parameters
    assert "request_id" in parameters
    assert "headers" not in parameters

    executor_parameters = inspect.signature(
        ControlledExecutor.execute_registered_test
    ).parameters
    assert set(executor_parameters) == {
        "self",
        "test_id",
        "attempt_number",
        "run_id",
    }


def test_log_reader_isolates_run_deduplicates_and_handles_malformed_lines(
    registry: TargetRegistry,
    tmp_path: Path,
) -> None:
    source = tmp_path / "data/logs/vulnerable-store.jsonl"
    source.parent.mkdir(parents=True)
    run_one = _event(event_id="evt-one", run_id="run-one", request_id="req-one")
    run_two = _event(event_id="evt-two", run_id="run-two", request_id="req-two")
    source.write_text(
        "\n".join(
            [
                "INFO: uvicorn noise",
                "{broken-json",
                json.dumps({"message": "ordinary json noise"}),
                run_one.model_dump_json(),
                run_one.model_dump_json(),
                run_two.model_dump_json(),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    reader = LogReader(registry=registry, project_root=tmp_path)
    result = reader.read_run(target_id=TARGET_ID, run_id="run-one")

    assert [event.event_id for event in result.events] == ["evt-one"]
    assert result.ignored_line_count == 2
    assert result.malformed_line_count == 1
    assert result.duplicate_event_count == 1
    assert set(inspect.signature(LogReader.read_run).parameters) == {
        "self",
        "target_id",
        "run_id",
    }


def test_audit_service_appends_and_filters_exact_run(tmp_path: Path) -> None:
    audit = AuditService(project_root=tmp_path)
    audit.record(
        run_id="audit-run-one",
        component="red_team_flow",
        actor_type="orchestrator",
        operation="controlled_execution",
        target="xss-reflection-001",
        policy_decision=AuditPolicyDecision.NOT_APPLICABLE,
        execution_status=AuditExecutionStatus.SUCCEEDED,
        evidence_reference="evidence-one",
    )
    audit.record(
        run_id="audit-run-two",
        component="red_team_flow",
        actor_type="orchestrator",
        operation="controlled_execution",
        target="sqli-login-bypass-001",
        policy_decision=AuditPolicyDecision.NOT_APPLICABLE,
        execution_status=AuditExecutionStatus.FAILED,
        error_code="synthetic-error",
    )

    assert len(audit.path.read_text(encoding="utf-8").splitlines()) == 2
    run_one = audit.read_run(run_id="audit-run-one")
    assert len(run_one) == 1
    assert run_one[0].execution_status == AuditExecutionStatus.SUCCEEDED
    assert run_one[0].evidence_reference == "evidence-one"


def _build_audited_flow(
    *,
    registry: TargetRegistry,
    client: TestClient,
    audit: AuditService,
    max_model_calls: int,
) -> tuple[RedTeamFlow, RunLimitTracker]:
    policy = PolicyEngine(registry=registry, project_root=ROOT)
    limits = RunLimitTracker(
        ExperimentLimits(
            max_model_calls=max_model_calls,
            max_attack_attempts=1,
            max_patch_attempts=1,
            max_http_requests=10,
            max_runtime_seconds=60,
        )
    )
    executor = ControlledExecutor(
        target_registry=registry,
        test_registry=SecurityTestRegistry.default(),
        policy_engine=policy,
        limits=limits,
        transport=ClientTransportAdapter(client),
    )
    flow = RedTeamFlow(
        target_registry=registry,
        policy_engine=policy,
        limits=limits,
        executor=executor,
        provider=MockProvider(planned_test_id="xss-reflection-001"),
        audit_service=audit,
    )
    return flow, limits


def test_successful_sensitive_execution_produces_audit_history(
    registry: TargetRegistry,
    app_settings: StoreSettings,
    tmp_path: Path,
) -> None:
    app = create_app(app_settings, reset_on_start=True)
    audit = AuditService(project_root=tmp_path / "audit-success")
    with TestClient(app) as client:
        flow, limits = _build_audited_flow(
            registry=registry,
            client=client,
            audit=audit,
            max_model_calls=3,
        )
        result = flow.run(
            run_id="audit-flow-success",
            target_id=TARGET_ID,
            attempt_number=1,
        )

    assert result.final_state == WorkflowState.BLUE_MONITORING
    assert limits.snapshot().model_calls == 3
    events = audit.read_run(run_id="audit-flow-success")
    assert sum(
        event.operation == "model_call"
        and event.execution_status == AuditExecutionStatus.SUCCEEDED
        for event in events
    ) == 3
    assert any(
        event.operation == "registered_test_authorization"
        and event.policy_decision == AuditPolicyDecision.ALLOWED
        for event in events
    )
    assert any(
        event.operation == "controlled_execution"
        and event.execution_status == AuditExecutionStatus.SUCCEEDED
        and event.evidence_reference == "xss-unescaped-reflection-observed"
        for event in events
    )


def test_blocked_policy_action_is_audited_before_provider_invocation(
    registry: TargetRegistry,
    app_settings: StoreSettings,
    tmp_path: Path,
) -> None:
    app = create_app(app_settings, reset_on_start=True)
    audit = AuditService(project_root=tmp_path / "audit-blocked")
    with TestClient(app) as client:
        flow, limits = _build_audited_flow(
            registry=registry,
            client=client,
            audit=audit,
            max_model_calls=2,
        )
        with pytest.raises(RedTeamPolicyBlocked):
            flow.run(
                run_id="audit-flow-blocked",
                target_id=TARGET_ID,
                attempt_number=1,
            )

    assert limits.snapshot().model_calls == 2
    events = audit.read_run(run_id="audit-flow-blocked")
    assert any(
        event.operation == "model_call_authorization"
        and event.policy_decision == AuditPolicyDecision.BLOCKED
        and event.policy_reason == PolicyReasonCode.MODEL_CALL_LIMIT_REACHED
        and event.execution_status == AuditExecutionStatus.BLOCKED
        for event in events
    )


def test_log_reader_contains_no_docker_or_subprocess_authority() -> None:
    source = inspect.getsource(LogReader).lower()
    assert "docker" not in source
    assert "subprocess" not in source
