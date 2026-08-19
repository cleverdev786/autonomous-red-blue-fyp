"""Milestone 10 deterministic rule-only RQ2 baseline tests."""

from __future__ import annotations

from datetime import UTC, datetime
import inspect

import pytest

from schemas.blue_team import TriageResult
from schemas.common import ClassificationLabel
from schemas.logging import ApplicationEventType, ApplicationLogEvent, LogReadResult
from services.rule_engine import RuleEngine, RuleEngineInputError


NOW = datetime(2026, 8, 19, 8, 0, tzinfo=UTC)


def _event(
    event_id: str,
    *,
    run_id: str = "rule-run-001",
    route_name: str = "other",
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


def _logs(*events: ApplicationLogEvent, run_id: str = "rule-run-001") -> LogReadResult:
    return LogReadResult(
        target_id="vulnerable-store",
        run_id=run_id,
        events=tuple(events),
    )


def test_sql_injection_signature_classifies_to_existing_triage_contract() -> None:
    result = RuleEngine().classify(
        _logs(
            _event(
                "evt-sqli",
                event_type=ApplicationEventType.DATABASE_EVENT,
                attributes={"username": "guest' OR 1=1 --"},
            )
        )
    )

    assert isinstance(result, TriageResult)
    assert result.classification == ClassificationLabel.SQL_INJECTION
    assert result.is_suspicious is True
    assert result.confidence == 1.0
    assert result.supporting_event_ids == ("evt-sqli",)


def test_sql_injection_union_select_generalizes_beyond_registered_payload() -> None:
    result = RuleEngine().classify(
        _logs(_event("evt-union", attributes={"value": "x' UNION SELECT name FROM items"}))
    )
    assert result.classification == ClassificationLabel.SQL_INJECTION


def test_xss_script_signature_classifies() -> None:
    result = RuleEngine().classify(
        _logs(_event("evt-xss", attributes={"value": "<script>alert(1)</script>"}))
    )
    assert result.classification == ClassificationLabel.XSS
    assert result.supporting_event_ids == ("evt-xss",)


def test_xss_event_handler_generalizes_beyond_script_tag() -> None:
    result = RuleEngine().classify(
        _logs(_event("evt-handler", attributes={"value": '<img src=x onerror="run()">'}))
    )
    assert result.classification == ClassificationLabel.XSS


def test_xss_javascript_uri_is_detected() -> None:
    result = RuleEngine().classify(
        _logs(_event("evt-js-uri", attributes={"value": "javascript:run()"}))
    )
    assert result.classification == ClassificationLabel.XSS


def test_path_traversal_signature_classifies() -> None:
    result = RuleEngine().classify(
        _logs(
            _event(
                "evt-path",
                event_type=ApplicationEventType.FILE_ACCESS_EVENT,
                attributes={"requested_path": "../private/note.txt"},
            )
        )
    )
    assert result.classification == ClassificationLabel.PATH_TRAVERSAL
    assert result.supporting_event_ids == ("evt-path",)


def test_encoded_path_traversal_generalizes() -> None:
    result = RuleEngine().classify(
        _logs(_event("evt-encoded", attributes={"requested_path": "%252e%252e/private.txt"}))
    )
    assert result.classification == ClassificationLabel.PATH_TRAVERSAL


def test_windows_style_path_traversal_is_detected() -> None:
    result = RuleEngine().classify(
        _logs(_event("evt-windows", attributes={"file_path": r"..\private\note.txt"}))
    )
    assert result.classification == ClassificationLabel.PATH_TRAVERSAL


@pytest.mark.parametrize(
    "attributes",
    [
        {"username": "o'reilly"},
        {"value": "I <3 deterministic tests"},
        {"requested_path": "report..txt"},
        {"requested_path": "public/reports/2026.txt"},
        {"query": "union membership selection"},
    ],
)
def test_representative_benign_values_remain_benign(attributes: dict[str, object]) -> None:
    result = RuleEngine().classify(_logs(_event("evt-benign", attributes=attributes)))
    assert result.classification == ClassificationLabel.BENIGN
    assert result.is_suspicious is False
    assert result.confidence == 1.0
    assert result.supporting_event_ids == ()


@pytest.mark.parametrize("route_name", ["login", "search", "file_read"])
def test_neutral_route_name_alone_never_determines_vulnerability(route_name: str) -> None:
    result = RuleEngine().classify(_logs(_event("evt-route", route_name=route_name)))
    assert result.classification == ClassificationLabel.BENIGN


def test_path_syntax_in_non_path_attribute_does_not_trigger_traversal() -> None:
    result = RuleEngine().classify(
        _logs(_event("evt-text", attributes={"message": "see ../archive for context"}))
    )
    assert result.classification == ClassificationLabel.BENIGN


def test_empty_normalized_run_returns_unknown() -> None:
    result = RuleEngine().classify(_logs())
    assert result.classification == ClassificationLabel.UNKNOWN
    assert result.is_suspicious is False
    assert result.confidence == 0.0
    assert result.supporting_event_ids == ()


def test_conflicting_supported_signatures_return_unknown_without_precedence() -> None:
    result = RuleEngine().classify(
        _logs(
            _event("evt-sqli", attributes={"username": "x' OR 1=1 --"}),
            _event("evt-xss", attributes={"value": "<script>run()</script>"}),
        )
    )
    assert result.classification == ClassificationLabel.UNKNOWN
    assert result.is_suspicious is True
    assert result.confidence == 0.0
    assert result.supporting_event_ids == ("evt-sqli", "evt-xss")


def test_mixed_run_events_fail_closed() -> None:
    logs = _logs(_event("evt-other-run", run_id="different-run"))
    with pytest.raises(RuleEngineInputError, match="must all match"):
        RuleEngine().classify(logs)


def test_event_order_does_not_change_result() -> None:
    first = _event("evt-b", attributes={"value": "<script>run()</script>"})
    second = _event("evt-a", attributes={"value": "<script>again()</script>"})

    result_a = RuleEngine().classify(_logs(first, second))
    result_b = RuleEngine().classify(_logs(second, first))

    assert result_a == result_b
    assert result_a.supporting_event_ids == ("evt-a", "evt-b")


def test_repeated_classification_is_deterministic() -> None:
    logs = _logs(_event("evt-repeat", attributes={"requested_path": "../private.txt"}))
    assert RuleEngine().classify(logs) == RuleEngine().classify(logs)


def test_every_supporting_event_id_exists_in_input() -> None:
    logs = _logs(
        _event("evt-match", attributes={"value": "<script>run()</script>"}),
        _event("evt-clean", attributes={"value": "normal search"}),
    )
    result = RuleEngine().classify(logs)
    input_ids = {event.event_id for event in logs.events}
    assert set(result.supporting_event_ids).issubset(input_ids)


def test_rule_engine_has_no_llm_agent_red_audit_or_execution_imports() -> None:
    source = inspect.getsource(__import__("services.rule_engine", fromlist=["RuleEngine"]))
    forbidden_import_fragments = (
        "from llm",
        "import llm",
        "from agents",
        "import agents",
        "from security_tests",
        "from orchestrator",
        "from services.audit_service",
        "from schemas.red_team",
        "from schemas.scenarios",
    )
    for fragment in forbidden_import_fragments:
        assert fragment not in source


def test_rule_engine_does_not_use_route_name_in_detection_logic() -> None:
    source = inspect.getsource(RuleEngine)
    assert "route_name" not in source
