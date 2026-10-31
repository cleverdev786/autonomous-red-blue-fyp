"""Vetted registered-test descriptors for deterministic Red planning."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from schemas.red_team import RegisteredTestOption
from schemas.targets import SecurityTestDefinition
from services.reconnaissance_service import ReconnaissanceService
from services.target_registry import RegistryConfigurationError, TargetRegistry

ROOT = Path(__file__).resolve().parents[1]


def load_registry() -> TargetRegistry:
    return TargetRegistry.from_directories(
        targets_dir=ROOT / "config" / "targets",
        security_tests_dir=ROOT / "config" / "security_tests",
    )


@pytest.mark.parametrize(
    ("test_id", "path", "method", "parameters", "oracle_id"),
    (
        (
            "sqli-login-bypass-001",
            "/scenarios/sql-injection/login",
            "POST",
            ("username", "password"),
            "auth-bypass-evidence-001",
        ),
        (
            "xss-reflection-001",
            "/scenarios/xss/search",
            "GET",
            ("q",),
            "unescaped-reflection-evidence-001",
        ),
        (
            "path-traversal-private-file-001",
            "/scenarios/path-traversal/read",
            "GET",
            ("path",),
            "synthetic-private-file-evidence-001",
        ),
    ),
)
def test_registered_templates_preserve_approved_scope_and_cost(
    test_id: str,
    path: str,
    method: str,
    parameters: tuple[str, ...],
    oracle_id: str,
) -> None:
    catalog = ReconnaissanceService(registry=load_registry()).build_attack_planning_catalog(
        target_id="vulnerable-store"
    )

    template = next(option for option in catalog.options if option.test_id == test_id)

    assert template.target_id == "vulnerable-store"
    assert template.path == path
    assert template.method.value == method
    assert template.allowed_parameter_names == parameters
    assert template.oracle_id == oracle_id
    assert template.resource_cost.max_requests == 2
    assert template.resource_cost.timeout_seconds == 5


@pytest.mark.parametrize(
    ("field", "value"),
    (("payload", "<script>alert(1)</script>"), ("command", "sh -c id")),
)
def test_template_descriptors_reject_payloads_and_commands(
    field: str,
    value: str,
) -> None:
    with pytest.raises(ValidationError):
        RegisteredTestOption.model_validate(
            {
                "test_id": "xss-reflection-001",
                "target_id": "vulnerable-store",
                "vulnerability_class": "xss",
                "endpoint_id": "scenario-xss-search",
                "path": "/scenarios/xss/search",
                "method": "GET",
                "allowed_parameter_names": ["q"],
                "request_template_id": "xss-reflection-template-001",
                "oracle_id": "unescaped-reflection-evidence-001",
                "resource_cost": {"max_requests": 2, "timeout_seconds": 5},
                "safe_description": "Controlled reflected XSS scenario.",
                field: value,
            }
        )


def test_registry_rejects_unknown_class_and_incompatible_parameters() -> None:
    with pytest.raises(ValidationError):
        SecurityTestDefinition.model_validate(
            {
                "test_id": "unsupported-class",
                "vulnerability_class": "command_injection",
                "target_id": "vulnerable-store",
                "endpoint_id": "scenario-xss-search",
                "method": "GET",
                "request_template_id": "unsupported-template",
                "success_evidence_rule_id": "unsupported-oracle",
                "description": "Unsupported test class.",
            }
        )

    registry = load_registry()
    incompatible = registry.get_security_test("xss-reflection-001").model_copy(
        update={"allowed_parameter_names": ("unregistered",)}
    )
    tests = tuple(
        incompatible if test.test_id == incompatible.test_id else test
        for test in registry.list_security_tests()
    )

    with pytest.raises(RegistryConfigurationError, match="contains parameters"):
        TargetRegistry(targets=registry.list_targets(), security_tests=tests)
