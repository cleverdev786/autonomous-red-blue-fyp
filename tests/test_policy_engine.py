"""Fail-closed policy-engine tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from orchestrator.limits import RunLimitTracker
from orchestrator.policy_engine import PolicyEngine
from schemas.common import (
    HttpMethod,
    PolicyReasonCode,
    WorkflowState,
)
from schemas.experiments import ExperimentLimits
from services.target_registry import TargetRegistry


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def registry() -> TargetRegistry:
    return TargetRegistry.from_directories(
        targets_dir=ROOT / "config" / "targets",
        security_tests_dir=ROOT / "config" / "security_tests",
    )


@pytest.fixture
def policy(registry: TargetRegistry) -> PolicyEngine:
    return PolicyEngine(registry=registry, project_root=ROOT)


def test_registered_target_is_allowed(policy: PolicyEngine) -> None:
    decision = policy.validate_target("vulnerable-store")
    assert decision.allowed is True


def test_unregistered_target_is_blocked(policy: PolicyEngine) -> None:
    decision = policy.validate_target("example.com")

    assert decision.allowed is False
    assert decision.reason_code == PolicyReasonCode.UNKNOWN_TARGET


@pytest.mark.parametrize(
    ("scheme", "hostname", "port", "reason"),
    [
        ("https", "vulnerable-store", 8000, PolicyReasonCode.SCHEME_NOT_ALLOWED),
        ("http", "example.com", 8000, PolicyReasonCode.HOST_NOT_ALLOWED),
        ("http", "127.0.0.1", 8000, PolicyReasonCode.HOST_NOT_ALLOWED),
        ("http", "vulnerable-store", 22, PolicyReasonCode.PORT_NOT_ALLOWED),
    ],
)
def test_network_destination_must_match_registered_target(
    policy: PolicyEngine,
    scheme: str,
    hostname: str,
    port: int,
    reason: PolicyReasonCode,
) -> None:
    decision = policy.validate_network_destination(
        target_id="vulnerable-store",
        scheme=scheme,
        hostname=hostname,
        port=port,
    )

    assert decision.allowed is False
    assert decision.reason_code == reason


def test_registered_network_destination_is_allowed(policy: PolicyEngine) -> None:
    decision = policy.validate_network_destination(
        target_id="vulnerable-store",
        scheme="http",
        hostname="vulnerable-store",
        port=8000,
    )
    assert decision.allowed is True


def test_unknown_endpoint_is_blocked(policy: PolicyEngine) -> None:
    decision = policy.validate_endpoint(
        target_id="vulnerable-store",
        endpoint_id="admin-panel",
    )

    assert decision.allowed is False
    assert decision.reason_code == PolicyReasonCode.UNKNOWN_ENDPOINT


def test_wrong_http_method_is_blocked(policy: PolicyEngine) -> None:
    decision = policy.validate_http_method(
        target_id="vulnerable-store",
        endpoint_id="scenario-xss-search",
        method=HttpMethod.POST,
    )

    assert decision.allowed is False
    assert decision.reason_code == PolicyReasonCode.METHOD_NOT_ALLOWED


def test_registered_test_is_allowed_only_on_its_endpoint(policy: PolicyEngine) -> None:
    allowed = policy.validate_security_test(
        target_id="vulnerable-store",
        test_id="xss-reflection-001",
        endpoint_id="scenario-xss-search",
    )
    blocked = policy.validate_security_test(
        target_id="vulnerable-store",
        test_id="xss-reflection-001",
        endpoint_id="scenario-sqli-login",
    )

    assert allowed.allowed is True
    assert blocked.allowed is False
    assert blocked.reason_code == PolicyReasonCode.TEST_ENDPOINT_MISMATCH


def test_unknown_test_is_blocked(policy: PolicyEngine) -> None:
    decision = policy.validate_security_test(
        target_id="vulnerable-store",
        test_id="arbitrary-new-test",
    )

    assert decision.allowed is False
    assert decision.reason_code == PolicyReasonCode.UNKNOWN_TEST


def test_source_read_inside_registered_root_is_allowed(policy: PolicyEngine) -> None:
    decision = policy.validate_source_read(
        target_id="vulnerable-store",
        relative_path="dummy_apps/vulnerable_store/app/scenario_routes.py",
    )
    assert decision.allowed is True


@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "../outside.txt",
        "dummy_apps/vulnerable_store/../../orchestrator/policy_engine.py",
        "orchestrator/policy_engine.py",
    ],
)
def test_source_read_outside_root_is_blocked(
    policy: PolicyEngine,
    path: str,
) -> None:
    decision = policy.validate_source_read(
        target_id="vulnerable-store",
        relative_path=path,
    )

    assert decision.allowed is False


def test_source_read_blocks_env_file_inside_source_root(
    policy: PolicyEngine,
    tmp_path: Path,
) -> None:
    # Protection is based on requested path even if the file does not exist.
    decision = policy.validate_source_read(
        target_id="vulnerable-store",
        relative_path="dummy_apps/vulnerable_store/.env",
    )

    assert decision.allowed is False
    assert decision.reason_code == PolicyReasonCode.PROTECTED_PATH


def test_patch_path_allows_vulnerable_source_file(policy: PolicyEngine) -> None:
    decision = policy.validate_patch_path(
        target_id="vulnerable-store",
        relative_path="dummy_apps/vulnerable_store/app/scenario_routes.py",
    )
    assert decision.allowed is True


@pytest.mark.parametrize(
    "path",
    [
        "orchestrator/policy_engine.py",
        "config/targets/vulnerable-store.json",
        "compose.yaml",
        "pyproject.toml",
        "dummy_apps/vulnerable_store/tests/test_baseline.py",
        "../outside.py",
    ],
)
def test_patch_path_blocks_protected_or_outside_files(
    policy: PolicyEngine,
    path: str,
) -> None:
    decision = policy.validate_patch_path(
        target_id="vulnerable-store",
        relative_path=path,
    )

    assert decision.allowed is False


def test_generated_test_path_is_allowed(policy: PolicyEngine) -> None:
    decision = policy.validate_patch_path(
        target_id="vulnerable-store",
        relative_path=(
            "dummy_apps/vulnerable_store/tests/generated/"
            "test_generated_security.py"
        ),
    )
    assert decision.allowed is True


@pytest.mark.skipif(
    not hasattr(os, "symlink"),
    reason="symlink support unavailable",
)
def test_existing_symlink_escape_is_blocked(
    registry: TargetRegistry,
    tmp_path: Path,
) -> None:
    project_root = tmp_path / "repo"
    allowed_root = project_root / "dummy_apps" / "vulnerable_store"
    app_root = allowed_root / "app"
    outside_root = tmp_path / "outside"
    app_root.mkdir(parents=True)
    outside_root.mkdir()
    (outside_root / "secret.txt").write_text("synthetic", encoding="utf-8")
    (app_root / "escape").symlink_to(outside_root, target_is_directory=True)

    policy = PolicyEngine(registry=registry, project_root=project_root)
    decision = policy.validate_source_read(
        target_id="vulnerable-store",
        relative_path=(
            "dummy_apps/vulnerable_store/app/escape/secret.txt"
        ),
    )

    assert decision.allowed is False
    assert decision.reason_code == PolicyReasonCode.SOURCE_PATH_NOT_ALLOWED


def test_valid_state_transition_is_allowed(policy: PolicyEngine) -> None:
    decision = policy.validate_state_transition(
        current=WorkflowState.ATTACK_PLANNING,
        requested=WorkflowState.ATTACK_EXECUTING,
    )
    assert decision.allowed is True


def test_invalid_state_transition_is_blocked(policy: PolicyEngine) -> None:
    decision = policy.validate_state_transition(
        current=WorkflowState.CREATED,
        requested=WorkflowState.PATCH_APPLYING,
    )

    assert decision.allowed is False
    assert decision.reason_code == PolicyReasonCode.INVALID_STATE


def test_policy_block_transition_is_allowed_from_active_state(
    policy: PolicyEngine,
) -> None:
    decision = policy.validate_state_transition(
        current=WorkflowState.CODE_ANALYSIS,
        requested=WorkflowState.POLICY_BLOCKED,
    )
    assert decision.allowed is True


def test_terminal_state_cannot_resume(policy: PolicyEngine) -> None:
    decision = policy.validate_state_transition(
        current=WorkflowState.COMPLETED,
        requested=WorkflowState.RECONNAISSANCE,
    )
    assert decision.allowed is False


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def make_tracker(clock: FakeClock | None = None) -> RunLimitTracker:
    return RunLimitTracker(
        ExperimentLimits(
            max_model_calls=1,
            max_attack_attempts=1,
            max_patch_attempts=1,
            max_http_requests=2,
            max_runtime_seconds=5,
        ),
        clock=clock or FakeClock(),
    )


def test_http_budget_is_blocked_after_limit(policy: PolicyEngine) -> None:
    tracker = make_tracker()
    tracker.consume_http_requests(2)

    decision = policy.validate_http_request_budget(tracker)

    assert decision.allowed is False
    assert decision.reason_code == PolicyReasonCode.REQUEST_LIMIT_REACHED


def test_attack_attempt_budget_is_blocked_after_limit(
    policy: PolicyEngine,
) -> None:
    tracker = make_tracker()
    tracker.consume_attack_attempts()

    decision = policy.validate_attack_attempt_budget(tracker)

    assert decision.allowed is False
    assert decision.reason_code == PolicyReasonCode.ATTEMPT_LIMIT_REACHED


def test_runtime_expiry_blocks_future_budget(policy: PolicyEngine) -> None:
    clock = FakeClock()
    tracker = make_tracker(clock)
    clock.advance(5)

    decision = policy.validate_model_call_budget(tracker)

    assert decision.allowed is False
    assert decision.reason_code == PolicyReasonCode.TIME_LIMIT_REACHED
