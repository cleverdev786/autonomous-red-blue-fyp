"""T17 individually approved targeted ZAP operations."""

from pathlib import Path

import pytest

from orchestrator.policy_engine import StandardRedPolicy
from schemas.red_team import RedPolicyUsage
from services.target_registry import TargetRegistry
from services.zap_adapter import (
    FixedTargetedZapRunner,
    TargetedZapRunResult,
    ZapAdapter,
    ZapAdapterDenied,
    ZapAlert,
    ZapBudget,
    ZapObservationStore,
)

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def policy_and_auth():
    registry = TargetRegistry.from_directories(
        targets_dir=ROOT / "config/targets",
        security_tests_dir=ROOT / "config/security_tests",
    )
    policy = StandardRedPolicy(
        registry=registry,
        budget_file=ROOT / "config/red_standard.json",
    )
    authorization = policy.freeze(
        assessment_id="assessment-1",
        approval_id="review-1",
        target_id="vulnerable-store",
    )
    return policy, authorization


def test_named_xss_operation_uses_one_fixed_rule_and_exact_endpoint(
    policy_and_auth,
) -> None:
    policy, authorization = policy_and_auth
    adapter = ZapAdapter(
        policy=policy,
        request_json=lambda *_: pytest.fail("preparation must not call ZAP"),
    )

    result = adapter.prepare_targeted_scan(
        authorization,
        test_id="xss-reflection-001",
        budget=ZapBudget(max_urls=2, max_depth=1, duration_seconds=30),
        usage=RedPolicyUsage(),
    )

    assert result.test_id == "xss-reflection-001"
    assert result.scanner_id == "40012"
    assert result.endpoint_id == "scenario-xss-search"
    assert result.method == "GET"
    assert result.url == "http://vulnerable-store:8000/scenarios/xss/search?q=notebook"
    assert result.scan_policy_name == "mars-xss-reflection-001"
    assert result.recurse is False
    assert result.in_scope_only is True
    assert result.request_limit == 2
    assert result.status == "prepared_not_executed"


def test_arbitrary_rule_or_full_site_flags_cannot_reach_zap(policy_and_auth) -> None:
    policy, authorization = policy_and_auth
    adapter = ZapAdapter(
        policy=policy,
        request_json=lambda *_: pytest.fail("ZAP API must not be called"),
    )
    budget = ZapBudget(max_urls=2, max_depth=1, duration_seconds=30)

    with pytest.raises(ZapAdapterDenied, match="targeted_test_denied"):
        adapter.prepare_targeted_scan(
            authorization,
            test_id="agent-selected-rule-99999",
            budget=budget,
            usage=RedPolicyUsage(),
        )
    with pytest.raises(TypeError):
        adapter.prepare_targeted_scan(
            authorization,
            test_id="xss-reflection-001",
            budget=budget,
            usage=RedPolicyUsage(),
            scanner_id="99999",
            recurse=True,
        )


def test_targeted_scan_duration_budget_fails_closed_without_zap(policy_and_auth) -> None:
    policy, authorization = policy_and_auth
    adapter = ZapAdapter(
        policy=policy,
        request_json=lambda *_: pytest.fail("ZAP API must not be called"),
    )

    with pytest.raises(ZapAdapterDenied, match="targeted_test_denied"):
        adapter.prepare_targeted_scan(
            authorization,
            test_id="xss-reflection-001",
            budget=ZapBudget(max_urls=2, max_depth=1, duration_seconds=30),
            usage=RedPolicyUsage(elapsed_seconds=160),
        )


def test_targeted_alert_is_persisted_only_as_suspected(policy_and_auth) -> None:
    policy, authorization = policy_and_auth
    calls = []
    stored = []
    adapter = ZapAdapter(
        policy=policy,
        request_json=lambda *_: pytest.fail("generic ZAP API must not be called"),
        run_targeted=lambda operation: (
            calls.append(operation)
            or TargetedZapRunResult(
                request_count=2,
                duration_seconds=4,
                alerts=(
                    ZapAlert(
                        scanner_id="40012",
                        url=operation.url,
                        name="Cross Site Scripting (Reflected)",
                    ),
                ),
            )
        ),
        store_suspected=stored.append,
    )

    observation = adapter.run_targeted_scan(
        authorization,
        test_id="xss-reflection-001",
        budget=ZapBudget(max_urls=2, max_depth=1, duration_seconds=30),
        usage=RedPolicyUsage(),
    )

    assert len(calls) == 1
    assert calls[0].recurse is False and calls[0].in_scope_only is True
    assert observation.status == "suspected"
    assert observation.confirmed is False
    assert observation.request_count == 2
    assert stored == [observation]


def test_fixed_runner_uses_only_one_rule_and_durable_suspected_store(
    policy_and_auth, tmp_path,
) -> None:
    policy, authorization = policy_and_auth
    calls = []

    def zap_json(route, params, timeout):
        calls.append((route, dict(params), timeout))
        if route.endswith("/scan/"):
            return {"scan": "7"}
        if route.endswith("/status/"):
            return {"status": "100"}
        if route.endswith("/alerts/"):
            return {"alerts": [{
                "pluginId": "40012",
                "url": "http://vulnerable-store:8000/scenarios/xss/search?q=notebook",
                "name": "Cross Site Scripting (Reflected)",
            }]}
        return {}

    store = ZapObservationStore(tmp_path / "zap-observations")
    gate_counts = iter((0, 2))
    runner = FixedTargetedZapRunner(
        request_json=zap_json,
        gate_status=lambda _timeout: {"forwarded": next(gate_counts), "limit": 2},
    )
    adapter = ZapAdapter(
        policy=policy,
        request_json=lambda *_: pytest.fail("generic API path used"),
        run_targeted=runner,
        store_suspected=store.save,
    )

    observation = adapter.run_targeted_scan(
        authorization,
        test_id="xss-reflection-001",
        budget=ZapBudget(max_urls=2, max_depth=1, duration_seconds=30),
        usage=RedPolicyUsage(),
    )

    assert store.read(authorization.scope, "xss-reflection-001") == observation
    assert calls[0][0].endswith("deleteAllAlerts/")
    assert calls[1][0].endswith("disableAllScanners/")
    assert calls[2][1] == {"ids": "40012"}
    scan = calls[3]
    assert scan[0].endswith("/scan/")
    assert scan[1] == {
        "url": "http://vulnerable-store:8000/scenarios/xss/search?q=notebook",
        "recurse": "false",
        "inScopeOnly": "true",
        "method": "GET",
    }
    assert all("full" not in route.lower() for route, _params, _timeout in calls)


def test_targeted_runner_over_budget_or_mismatched_alert_fails_closed(
    policy_and_auth,
) -> None:
    policy, authorization = policy_and_auth
    stored = []

    def execute(operation):
        return TargetedZapRunResult(
            request_count=3,
            duration_seconds=1,
            alerts=(ZapAlert(
                scanner_id="40012",
                url=operation.url,
                name="Cross Site Scripting (Reflected)",
            ),),
        )

    adapter = ZapAdapter(
        policy=policy,
        request_json=lambda *_: pytest.fail("generic ZAP API must not be called"),
        run_targeted=execute,
        store_suspected=stored.append,
    )
    with pytest.raises(ZapAdapterDenied, match="targeted_result_denied"):
        adapter.run_targeted_scan(
            authorization,
            test_id="xss-reflection-001",
            budget=ZapBudget(max_urls=2, max_depth=1, duration_seconds=30),
            usage=RedPolicyUsage(),
        )
    assert stored == []


def test_fixed_runner_enforces_deadline_before_any_zap_call(policy_and_auth) -> None:
    policy, authorization = policy_and_auth
    operation = ZapAdapter(
        policy=policy, request_json=lambda *_: pytest.fail("unexpected generic call"),
    ).prepare_targeted_scan(
        authorization,
        test_id="xss-reflection-001",
        budget=ZapBudget(max_urls=2, max_depth=1, duration_seconds=1),
        usage=RedPolicyUsage(),
    )
    moments = iter((0.0, 2.0))
    runner = FixedTargetedZapRunner(
        request_json=lambda *_: pytest.fail("deadline must block before ZAP"),
        gate_status=lambda _timeout: {"forwarded": 0, "limit": 2},
        monotonic=lambda: next(moments),
    )

    with pytest.raises(ZapAdapterDenied, match="targeted_runner_failed"):
        runner(operation)
