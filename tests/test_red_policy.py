"""T03: fail-closed Standard assessment policy; no requests or scans."""

from pathlib import Path
import pytest
from pydantic import ValidationError

from orchestrator.policy_engine import StandardRedPolicy
from schemas.common import HttpMethod, VulnerabilityClass
from schemas.red_team import RedPolicyOperation, RedPolicyUsage, RedStandardBudget
from services.target_registry import TargetRegistry

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def policy():
    registry = TargetRegistry.from_directories(
        targets_dir=ROOT / "config/targets",
        security_tests_dir=ROOT / "config/security_tests",
    )
    return StandardRedPolicy(registry=registry, budget_file=ROOT / "config/red_standard.json")


def freeze(policy, *, methods=None, classes=None):
    return policy.freeze(
        assessment_id="assessment-1",
        approval_id="review-1",
        target_id="vulnerable-store",
        allowed_methods=methods,
        allowed_classes=classes,
    )


def operation(snapshot, **changes):
    payload = dict(
        scope=snapshot.scope,
        kind="test",
        scheme="http", hostname="vulnerable-store", port=8000,
        method="POST", endpoint_id="scenario-sqli-login",
        test_id="sqli-login-bypass-001",
        vulnerability_class="sql_injection",
        requests=1,
    )
    payload.update(changes)
    return RedPolicyOperation(**payload)


def test_standard_only_frozen_and_json_roundtrip(policy):
    snap = freeze(policy)
    assert snap.budget.profile == "standard"
    assert snap.scope.target_id == "vulnerable-store"
    assert (snap.scheme, snap.hostname, snap.port) == ("http", "vulnerable-store", 8000)
    assert snap.scope.authorization_fingerprint != snap.scope.target_fingerprint
    assert snap.allowed_classes == frozenset(VulnerabilityClass)
    assert snap.allowed_methods == frozenset({HttpMethod.GET, HttpMethod.POST})
    assert type(snap).model_validate_json(snap.model_dump_json()) == snap
    assert policy.check(snap, operation(snap), RedPolicyUsage()).allowed
    with pytest.raises(ValidationError):
        RedStandardBudget(profile="quick")
    with pytest.raises(ValidationError):
        RedStandardBudget(max_http_requests=999999)


def test_no_external_target_and_no_unapproved_methods_or_classes(policy):
    with pytest.raises(ValueError, match="target"):
        policy.freeze(assessment_id="x", approval_id="review-1", target_id="external")
    with pytest.raises(ValueError, match="class"):
        freeze(policy, classes={"remote_code_execution"})
    with pytest.raises(ValueError, match="method"):
        freeze(policy, methods={"DELETE"})
    snap = freeze(policy, methods={HttpMethod.GET}, classes={VulnerabilityClass.XSS})
    assert not policy.check(snap, operation(snap), RedPolicyUsage()).allowed
    xss = operation(snap, method="GET", test_id="xss-reflection-001",
                    endpoint_id="scenario-xss-search", vulnerability_class="xss")
    assert policy.check(snap, xss, RedPolicyUsage()).allowed
    assert not policy.check(snap, operation(snap, method="PUT"), RedPolicyUsage()).allowed
    assert not policy.check(snap, operation(snap, vulnerability_class="xss"), RedPolicyUsage()).allowed


@pytest.mark.parametrize("change", [
    {"hostname": "evil.example"}, {"port": 8080},
    {"test_id": "unregistered"}, {"endpoint_id": "health"},
    {"method": "GET"}, {"vulnerability_class": "xss"},
])
def test_off_scope_operations_denied_before_dispatch(policy, change):
    snap = freeze(policy)
    assert not policy.check(snap, operation(snap, **change), RedPolicyUsage()).allowed


def test_unexpected_scheme_rejected_at_schema_boundary(policy):
    snap = freeze(policy)
    with pytest.raises(ValidationError):
        operation(snap, scheme="https")


def test_authorization_cannot_be_mutated_in_place(policy):
    snap = freeze(policy)
    with pytest.raises(ValidationError):
        snap.approval_id = "forged"


def test_stale_and_forged_authorization_fingerprint_denied(policy):
    snap = freeze(policy)
    wrong_scope = snap.scope.model_copy(update={"authorization_fingerprint": "1" * 64})
    assert not policy.check(snap, operation(snap, scope=wrong_scope), RedPolicyUsage()).allowed
    forged = snap.model_copy(update={"allowed_methods": frozenset({HttpMethod.PUT})})
    assert not policy.check(forged, operation(snap), RedPolicyUsage()).allowed
    forged_destination = snap.model_copy(update={"hostname": "external.example"})
    assert not policy.check(forged_destination, operation(snap), RedPolicyUsage()).allowed
    stale = snap.model_copy(update={
        "scope": snap.scope.model_copy(update={"target_fingerprint": "a" * 64})
    })
    assert not policy.check(stale, operation(stale), RedPolicyUsage()).allowed


@pytest.mark.parametrize("used", [
    {"http_requests": 24}, {"tests_started": 3}, {"elapsed_seconds": 180},
    {"active_operations": 1},
])
def test_exhausted_test_budgets_denied(policy, used):
    snap = freeze(policy)
    assert not policy.check(snap, operation(snap), RedPolicyUsage(**used)).allowed


def test_crawl_limits_depth_and_retry_denied(policy):
    snap = freeze(policy)
    crawl = operation(snap, kind="crawl", method="GET", test_id=None,
                      vulnerability_class=None, endpoint_id="baseline-search")
    assert policy.check(snap, crawl, RedPolicyUsage()).allowed
    assert not policy.check(snap, crawl, RedPolicyUsage(crawl_requests=12)).allowed
    assert not policy.check(snap, operation(snap, kind="crawl", method="GET",
                                            test_id=None, vulnerability_class=None,
                                            endpoint_id="baseline-search", depth=3),
                            RedPolicyUsage()).allowed
    assert not policy.check(snap, operation(snap, retry_number=1), RedPolicyUsage()).allowed


def test_malformed_requests_or_unknown_fields_rejected(policy):
    snap = freeze(policy)
    with pytest.raises(ValidationError):
        RedPolicyOperation.model_validate({**operation(snap).model_dump(),
                                           "shell_command": "curl internet"})
    with pytest.raises(ValidationError):
        RedPolicyUsage(http_requests=-1)
    with pytest.raises(ValidationError):
        RedPolicyOperation.model_validate({**operation(snap).model_dump(), "scope": None})


def test_budget_config_rejects_unbounded_limits_and_quick_profile(policy, tmp_path):
    path = tmp_path / "budget.json"
    path.write_text('{"profile":"quick"}')
    with pytest.raises(ValidationError):
        StandardRedPolicy(registry=policy.registry, budget_file=path)
    path.write_text('{"profile":"standard","max_parallel_operations":2}')
    with pytest.raises(ValidationError):
        StandardRedPolicy(registry=policy.registry, budget_file=path)
