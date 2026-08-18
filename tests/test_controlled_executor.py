"""Milestone 7 deterministic security-test harness tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import pytest
from fastapi.testclient import TestClient

from dummy_apps.vulnerable_store.app.config import StoreSettings
from dummy_apps.vulnerable_store.app.main import create_app
from orchestrator.limits import RunLimitTracker
from orchestrator.policy_engine import PolicyEngine
from schemas.common import PolicyReasonCode
from schemas.experiments import ExperimentLimits
from security_tests.base import RegisteredSecurityTest, RequestStep
from security_tests.registry import (
    SecurityTestImplementationError,
    SecurityTestRegistry,
)
from services.controlled_executor import (
    ControlledExecutionBlocked,
    ControlledExecutor,
    HttpTransport,
    TransportResponse,
    TransportTimeoutError,
)
from services.target_registry import TargetRegistry


ROOT = Path(__file__).resolve().parents[1]
RUN_ID = "test-run-001"


class ClientTransportAdapter:
    """Adapter letting unit tests exercise the executor without external network."""

    def __init__(self, client: TestClient) -> None:
        self.client = client
        self.calls: list[tuple[str, str]] = []

    def send(
        self,
        *,
        method: str,
        url: str,
        query_params: Mapping[str, str],
        json_body: Mapping[str, Any] | None,
        timeout_seconds: int,
        run_id: str,
        request_id: str,
    ) -> TransportResponse:
        self.calls.append((method, url))
        # Only the path/query from the registry-built URL is used by TestClient.
        from urllib.parse import urlsplit

        parts = urlsplit(url)
        response = self.client.request(
            method,
            parts.path,
            params=dict(query_params),
            json=dict(json_body) if json_body is not None else None,
            headers={
                "X-FYP-Run-ID": run_id,
                "X-FYP-Request-ID": request_id,
            },
            follow_redirects=False,
        )
        return TransportResponse(
            status_code=response.status_code,
            text=response.text,
            headers=dict(response.headers),
        )


class RedirectTransport:
    def __init__(self) -> None:
        self.call_count = 0

    def send(self, **kwargs) -> TransportResponse:
        self.call_count += 1
        return TransportResponse(
            status_code=302,
            text="redirect",
            headers={"location": "http://example.com/"},
        )


class TimeoutTransport:
    def send(self, **kwargs) -> TransportResponse:
        raise TransportTimeoutError("synthetic timeout")


class RecordingTransport:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def send(self, **kwargs) -> TransportResponse:
        self.calls.append(kwargs)
        return TransportResponse(
            status_code=200,
            text="no evidence",
            headers={},
        )


class UnknownParameterTest(RegisteredSecurityTest):
    test_id = "xss-reflection-001"

    def build_steps(self) -> tuple[RequestStep, ...]:
        from schemas.common import HttpMethod

        return (
            RequestStep(
                step_id="bad",
                endpoint_id="scenario-xss-search",
                method=HttpMethod.GET,
                query_params={"q": "safe", "url": "http://example.com"},
            ),
        )

    def evaluate(self, exchanges):
        return ()


@pytest.fixture
def app_settings(tmp_path: Path) -> StoreSettings:
    return StoreSettings(
        database_url=f"sqlite:///{(tmp_path / 'store.db').as_posix()}",
        seed_files_dir=tmp_path / "seed-files",
        scenario_files_dir=tmp_path / "scenario-files",
    )


@pytest.fixture
def client(app_settings: StoreSettings) -> TestClient:
    app = create_app(app_settings, reset_on_start=True)
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def registry() -> TargetRegistry:
    return TargetRegistry.from_directories(
        targets_dir=ROOT / "config" / "targets",
        security_tests_dir=ROOT / "config" / "security_tests",
    )


def build_executor(
    *,
    registry: TargetRegistry,
    transport: HttpTransport,
    test_registry: SecurityTestRegistry | None = None,
    max_http_requests: int = 10,
) -> ControlledExecutor:
    policy = PolicyEngine(registry=registry, project_root=ROOT)
    limits = RunLimitTracker(
        ExperimentLimits(
            max_model_calls=1,
            max_attack_attempts=3,
            max_patch_attempts=1,
            max_http_requests=max_http_requests,
            max_runtime_seconds=60,
        )
    )
    return ControlledExecutor(
        target_registry=registry,
        test_registry=test_registry or SecurityTestRegistry.default(),
        policy_engine=policy,
        limits=limits,
        transport=transport,
    )


@pytest.mark.parametrize(
    ("test_id", "expected_evidence_id"),
    [
        ("sqli-login-bypass-001", "sqli-auth-bypass-observed"),
        ("xss-reflection-001", "xss-unescaped-reflection-observed"),
        (
            "path-traversal-private-file-001",
            "path-traversal-private-file-observed",
        ),
    ],
)
def test_registered_tests_produce_deterministic_evidence(
    client: TestClient,
    registry: TargetRegistry,
    test_id: str,
    expected_evidence_id: str,
) -> None:
    transport = ClientTransportAdapter(client)
    executor = build_executor(registry=registry, transport=transport)

    result = executor.execute_registered_test(
        test_id=test_id,
        attempt_number=1,
        run_id=RUN_ID,
    )

    assert result.completed is True
    assert result.timed_out is False
    assert result.error_code is None
    assert result.request_count == 2
    assert len(result.exchanges) == 2
    assert [item.evidence_id for item in result.evidence] == [
        expected_evidence_id
    ]

    for _, url in transport.calls:
        assert url.startswith("http://vulnerable-store:8000/")
        assert "example.com" not in url


def test_unknown_test_is_blocked_before_transport(
    client: TestClient,
    registry: TargetRegistry,
) -> None:
    transport = ClientTransportAdapter(client)
    executor = build_executor(registry=registry, transport=transport)

    with pytest.raises(ControlledExecutionBlocked) as exc:
        executor.execute_registered_test(
            test_id="unregistered-test",
            attempt_number=1,
            run_id=RUN_ID,
        )

    assert exc.value.decision.reason_code == PolicyReasonCode.UNKNOWN_TEST
    assert transport.calls == []


def test_http_budget_blocks_before_any_request_when_too_small(
    registry: TargetRegistry,
) -> None:
    transport = RecordingTransport()
    executor = build_executor(
        registry=registry,
        transport=transport,
        max_http_requests=1,
    )

    # The first step is allowed and consumes the single request budget.
    # The second request is blocked before transport.
    with pytest.raises(ControlledExecutionBlocked) as exc:
        executor.execute_registered_test(
            test_id="xss-reflection-001",
            attempt_number=1,
            run_id=RUN_ID,
        )

    assert exc.value.decision.reason_code == PolicyReasonCode.REQUEST_LIMIT_REACHED
    assert len(transport.calls) == 1


def test_external_redirect_is_never_followed(
    registry: TargetRegistry,
) -> None:
    transport = RedirectTransport()
    executor = build_executor(registry=registry, transport=transport)

    result = executor.execute_registered_test(
        test_id="xss-reflection-001",
        attempt_number=1,
        run_id=RUN_ID,
    )

    assert result.completed is False
    assert result.error_code == "redirect-blocked"
    assert result.request_count == 1
    assert result.exchanges[0].redirect_location == "http://example.com/"
    assert transport.call_count == 1


def test_timeout_returns_structured_failure(
    registry: TargetRegistry,
) -> None:
    executor = build_executor(
        registry=registry,
        transport=TimeoutTransport(),
    )

    result = executor.execute_registered_test(
        test_id="xss-reflection-001",
        attempt_number=1,
        run_id=RUN_ID,
    )

    assert result.completed is False
    assert result.timed_out is True
    assert result.error_code == "request-timeout"
    assert result.request_count == 1


def test_test_implementation_cannot_add_unregistered_parameter(
    registry: TargetRegistry,
) -> None:
    transport = RecordingTransport()
    custom_registry = SecurityTestRegistry(
        (
            # Keep all three IDs present so registry integrity passes.
            UnknownParameterTest(),
            SecurityTestRegistry.default().get("sqli-login-bypass-001"),
            SecurityTestRegistry.default().get(
                "path-traversal-private-file-001"
            ),
        )
    )
    executor = build_executor(
        registry=registry,
        transport=transport,
        test_registry=custom_registry,
    )

    with pytest.raises(ControlledExecutionBlocked) as exc:
        executor.execute_registered_test(
            test_id="xss-reflection-001",
            attempt_number=1,
            run_id=RUN_ID,
        )

    assert exc.value.decision.reason_code == PolicyReasonCode.PROHIBITED_OPERATION
    assert transport.calls == []


def test_code_registry_must_exactly_match_metadata_registry(
    registry: TargetRegistry,
) -> None:
    incomplete = SecurityTestRegistry(
        (SecurityTestRegistry.default().get("xss-reflection-001"),)
    )

    with pytest.raises(SecurityTestImplementationError):
        incomplete.validate_against_target_registry(registry)
