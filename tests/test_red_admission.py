"""T07 trusted admission boundary. Tests never send HTTP or run Docker."""

from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from schemas.common import HttpMethod

from orchestrator.policy_engine import StandardRedPolicy
from schemas.red_team import RedEndpointCandidate, RedPolicyUsage
from schemas.red_team_state import AssessmentDTO, CoverageDTO, OperationDTO, PlanVersionDTO
from services.red_admission import AdmissionRequest, TrustedRedAdmission
from services.red_assessment_store import RedAssessmentStore
from services.red_evidence_store import RedEvidenceStore
from services.target_registry import TargetRegistry


ROOT = Path(__file__).resolve().parents[1]
URL = "http://vulnerable-store:8000/scenarios/xss/search"
IP = "172.19.0.7"


@pytest.fixture
def env(tmp_path):
    registry = TargetRegistry.from_directories(
        targets_dir=ROOT / "config/targets",
        security_tests_dir=ROOT / "config/security_tests",
    )
    policy = StandardRedPolicy(
        registry=registry, budget_file=ROOT / "config/red_standard.json",
    )
    auth = policy.freeze(
        assessment_id="as-1", approval_id="operator-review-1", target_id="vulnerable-store"
    )
    store = RedAssessmentStore(tmp_path / "red.sqlite3")
    store.create(
        AssessmentDTO(scope=auth.scope, mode="manual", status="running",
                      workflow_complete=False, coverage=CoverageDTO()),
        auth, request_id="req-1",
    )
    store.add_candidate(
        "as-1", RedEndpointCandidate(
            candidate_id="candidate-1", method="GET",
            path="/scenarios/xss/search", source="registered",
            observed_at=datetime(2026, 10, 27, tzinfo=timezone.utc),
        ),
    )
    store.add_plan(
        PlanVersionDTO(scope=auth.scope, plan_version="plan-1",
                       surface_revision="surface-1", status="approved")
    )
    store.add_operation(
        OperationDTO(scope=auth.scope, operation_id="op-1", plan_version="plan-1",
                     candidate_id="candidate-1", test_id="xss-reflection-001",
                     status="approved")
    )
    journal = RedEvidenceStore(store, tmp_path / "artifacts")
    admission = TrustedRedAdmission(
        store=store, journal=journal, policy=policy,
        pinned_ips=frozenset({IP}), resolver=lambda _: (IP,),
    )
    request = AdmissionRequest(
        scope=auth.scope, operation_id="op-1", plan_version="plan-1",
        tool="controlled_http", method="GET", url=URL,
    )
    return admission, request, journal, store, auth


def test_matching_saved_operation_is_admitted_without_dispatch(env):
    admission, request, journal, *_ = env
    decision = admission.check(request, usage=RedPolicyUsage())
    assert decision.allowed
    assert [item["action"] for item in journal.list_events(request.scope)] == ["operation_admitted"]


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8000/scenarios/xss/search",
    "http://169.254.169.254/latest/meta-data",
    "http://external.test:8000/scenarios/xss/search",
    "http://vulnerable-store.evil.test:8000/scenarios/xss/search",
    "http://vulnerable-store:8001/scenarios/xss/search",
    "https://vulnerable-store:8000/scenarios/xss/search",
    "http://vulnerable-store:8000/%73cenarios/xss/search",
    "http://vulnerable-store:8000/scenarios/xss/../xss/search",
    "http://vulnerable-store:8000/scenarios/xss/search?next=//evil.test",
    "http://vulnerable-store:8000/scenarios/xss/search#fragment",
    "http://user@vulnerable-store:8000/scenarios/xss/search",
    "http://vulnerable-store:8000\\@evil.test/scenarios/xss/search",
])
def test_untrusted_urls_never_admitted(env, url):
    admission, request, journal, *_ = env
    result = admission.check(request.model_copy(update={"url": url}), RedPolicyUsage())
    assert not result.allowed
    assert journal.list_events(request.scope)[-1]["outcome"] == "denied"


@pytest.mark.parametrize("changes", [
    {"tool": "shell"}, {"tool": "zap_active_all"}, {"method": HttpMethod.POST},
    {"plan_version": "unknown"}, {"operation_id": "unknown"},
    {"redirect_url": "http://evil.test/"},
    {"redirect_url": URL},
])
def test_unapproved_tool_method_plan_and_redirect_are_denied(env, changes):
    admission, request, *_ = env
    assert not admission.check(
        request.model_copy(update=changes), RedPolicyUsage()
    ).allowed


def test_fingerprint_and_current_plan_are_required(env):
    admission, request, journal, store, auth = env
    altered_scope = request.scope.model_copy(update={
        "authorization_fingerprint": "f" * 64,
    })
    assert not admission.check(
        request.model_copy(update={"scope": altered_scope}), RedPolicyUsage()
    ).allowed
    assert journal.list_events(auth.scope)[-1]["action"] == "operation_blocked"
    store.add_plan(
        PlanVersionDTO(scope=auth.scope, plan_version="plan-2",
                       surface_revision="surface-2", status="approved")
    )
    assert not admission.check(request, RedPolicyUsage()).allowed
    assert journal.list_events(auth.scope)[-1]["outcome"] == "denied"


@pytest.mark.parametrize("usage", [
    RedPolicyUsage(http_requests=24),
    RedPolicyUsage(tests_started=3),
    RedPolicyUsage(elapsed_seconds=180),
    RedPolicyUsage(active_operations=1),
])
def test_each_exhausted_budget_denied(env, usage):
    admission, request, *_ = env
    assert not admission.check(request, usage).allowed


def test_dns_rebinding_or_unsafe_ip_fails_closed(env):
    _, request, journal, store, _ = env
    policy = env[0].policy
    for result in [
        ("172.19.0.8",), ("127.0.0.1",), ("169.254.169.254",),
        ("8.8.8.8",), (), (IP, "8.8.8.8"),
    ]:
        gate = TrustedRedAdmission(
            store=store, journal=journal, policy=policy,
            pinned_ips=frozenset({IP}), resolver=lambda _, result=result: result,
        )
        assert not gate.check(request, RedPolicyUsage()).allowed
    no_pin = TrustedRedAdmission(
        store=store, journal=journal, policy=policy,
        pinned_ips=frozenset(), resolver=lambda _: (IP,),
    )
    assert not no_pin.check(request, RedPolicyUsage()).allowed


def test_browser_cannot_supply_shell_payload_or_arbitrary_tool_arguments(env):
    _, request, *_ = env
    with pytest.raises(ValidationError):
        AdmissionRequest.model_validate({
            **request.model_dump(), "command": "docker run --privileged",
        })
    with pytest.raises(ValidationError):
        AdmissionRequest.model_validate({
            **request.model_dump(), "args": ["--host-network"],
        })


def test_saved_operation_not_matching_vetted_candidate_is_denied(env):
    admission, request, journal, store, auth = env
    store.add_candidate("as-1", RedEndpointCandidate(
        candidate_id="bad-route", method="GET", path="/health", source="zap",
        observed_at=datetime(2026, 10, 27, tzinfo=timezone.utc),
    ))
    store.add_operation(OperationDTO(
        scope=auth.scope, operation_id="op-bad", plan_version="plan-1",
        candidate_id="bad-route", test_id="xss-reflection-001", status="approved",
    ))
    assert not admission.check(
        request.model_copy(update={"operation_id": "op-bad"}), RedPolicyUsage()
    ).allowed
    assert journal.list_events(auth.scope)[-1]["outcome"] == "denied"


def test_audit_unavailable_fails_closed(env, monkeypatch):
    admission, request, journal, *_ = env
    def unavailable(*_args, **_kwargs):
        raise RuntimeError("journal offline")
    monkeypatch.setattr(journal, "append_event", unavailable)
    assert not admission.check(request, RedPolicyUsage()).allowed



def test_unapproved_candidate_parameter_is_denied(env):
    admission, request, journal, store, auth = env
    store.add_candidate("as-1", RedEndpointCandidate(
        candidate_id="c-extra", method="GET", path="/scenarios/xss/search",
        parameter_names=("q", "admin_token"), source="zap",
        observed_at=datetime(2026, 10, 27, tzinfo=timezone.utc),
    ))
    store.add_operation(OperationDTO(
        scope=auth.scope, operation_id="op-extra", plan_version="plan-1",
        candidate_id="c-extra", test_id="xss-reflection-001", status="approved",
    ))
    result = admission.check(
        request.model_copy(update={"operation_id": "op-extra"}), RedPolicyUsage(),
    )
    assert not result.allowed
    assert journal.list_events(auth.scope)[-1]["outcome"] == "denied"


def test_stored_unapproved_operation_cannot_be_admitted(env):
    admission, request, journal, store, auth = env
    store.add_operation(OperationDTO(
        scope=auth.scope, operation_id="op-draft", plan_version="plan-1",
        candidate_id="candidate-1", test_id="xss-reflection-001", status="proposed",
    ))
    result = admission.check(
        request.model_copy(update={"operation_id": "op-draft"}), RedPolicyUsage(),
    )
    assert not result.allowed
    assert journal.list_events(auth.scope)[-1]["action"] == "operation_blocked"
