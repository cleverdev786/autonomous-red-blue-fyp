"""Tests for the trusted target/security-test registry."""

from __future__ import annotations

from pathlib import Path

import pytest

from schemas.common import HttpMethod, VulnerabilityClass
from schemas.targets import EndpointDefinition, SecurityTestDefinition, TargetDefinition
from services.target_registry import (
    RegistryConfigurationError,
    TargetRegistry,
    UnknownSecurityTestError,
    UnknownTargetError,
)


ROOT = Path(__file__).resolve().parents[1]


def load_project_registry() -> TargetRegistry:
    return TargetRegistry.from_directories(
        targets_dir=ROOT / "config" / "targets",
        security_tests_dir=ROOT / "config" / "security_tests",
    )


def test_project_registry_loads_and_cross_references_validate() -> None:
    registry = load_project_registry()

    targets = registry.list_targets()
    tests = registry.list_security_tests()

    assert [target.target_id for target in targets] == ["vulnerable-store"]
    assert {item.test_id for item in tests} == {
        "sqli-login-bypass-001",
        "xss-reflection-001",
        "path-traversal-private-file-001",
    }


def test_registry_returns_known_target_and_test() -> None:
    registry = load_project_registry()

    target = registry.get_target("vulnerable-store")
    security_test = registry.get_security_test("xss-reflection-001")

    assert target.hostname == "vulnerable-store"
    assert security_test.vulnerability_class == VulnerabilityClass.XSS


def test_registry_fails_closed_for_unknown_ids() -> None:
    registry = load_project_registry()

    with pytest.raises(UnknownTargetError):
        registry.get_target("example.com")

    with pytest.raises(UnknownSecurityTestError):
        registry.get_security_test("arbitrary-test")


def test_registry_rejects_duplicate_target_id() -> None:
    endpoint = EndpointDefinition(
        endpoint_id="health",
        path="/health",
        allowed_methods=(HttpMethod.GET,),
    )
    target = TargetDefinition(
        target_id="duplicate-target",
        container_name="duplicate-target",
        hostname="duplicate-target",
        port=8000,
        endpoints=(endpoint,),
        allowed_test_ids=("test-001",),
        source_root="dummy_apps/app",
        writable_patch_roots=("dummy_apps/app",),
        log_sources=("data/log.jsonl",),
        reset_operation_id="reset-target",
    )
    security_test = SecurityTestDefinition(
        test_id="test-001",
        vulnerability_class=VulnerabilityClass.XSS,
        target_id="duplicate-target",
        endpoint_id="health",
        method=HttpMethod.GET,
        request_template_id="template-001",
        success_evidence_rule_id="evidence-001",
        description="Synthetic test definition.",
    )

    with pytest.raises(RegistryConfigurationError):
        TargetRegistry(
            targets=(target, target),
            security_tests=(security_test,),
        )


def test_registry_rejects_test_not_in_target_allowlist() -> None:
    endpoint = EndpointDefinition(
        endpoint_id="search",
        path="/search",
        allowed_methods=(HttpMethod.GET,),
        input_fields=("q",),
    )
    target = TargetDefinition(
        target_id="target-one",
        container_name="target-one",
        hostname="target-one",
        port=8000,
        endpoints=(endpoint,),
        allowed_test_ids=("allowed-test",),
        source_root="dummy_apps/app",
        writable_patch_roots=("dummy_apps/app",),
        log_sources=("data/log.jsonl",),
        reset_operation_id="reset-target",
    )
    allowed_test = SecurityTestDefinition(
        test_id="allowed-test",
        vulnerability_class=VulnerabilityClass.XSS,
        target_id="target-one",
        endpoint_id="search",
        method=HttpMethod.GET,
        allowed_parameter_names=("q",),
        request_template_id="template-allowed",
        success_evidence_rule_id="evidence-allowed",
        description="Allowed synthetic test.",
    )
    hidden_test = SecurityTestDefinition(
        test_id="hidden-test",
        vulnerability_class=VulnerabilityClass.XSS,
        target_id="target-one",
        endpoint_id="search",
        method=HttpMethod.GET,
        allowed_parameter_names=("q",),
        request_template_id="template-hidden",
        success_evidence_rule_id="evidence-hidden",
        description="This test is not present in target allowed_test_ids.",
    )

    with pytest.raises(RegistryConfigurationError):
        TargetRegistry(
            targets=(target,),
            security_tests=(allowed_test, hidden_test),
        )
