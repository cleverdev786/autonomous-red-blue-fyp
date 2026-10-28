"""T11 deterministic observation mapping; no HTTP or ZAP runtime required."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from agents.red.reconnaissance import ReconnaissanceAgent
from services.reconnaissance_service import ReconnaissanceService, ZapObservation
from services.target_registry import TargetRegistry, UnknownTargetError

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 28, tzinfo=UTC)


@pytest.fixture
def service():
    registry = TargetRegistry.from_directories(
        targets_dir=ROOT / "config/targets", security_tests_dir=ROOT / "config/security_tests"
    )
    return ReconnaissanceService(registry=registry)


def obs(path, method="GET", names=()):
    return ZapObservation(path=path, method=method, parameter_names=names)


def test_registered_observation_is_only_candidate_not_admitted(service):
    result = service.map_zap_observations(
        target_id="vulnerable-store",
        observations=[obs("/scenarios/xss/search", names=("q",))],
        observed_at=NOW,
    )
    assert result.target_id == "vulnerable-store"
    assert len(result.candidates) == 1
    entry = result.candidates[0]
    assert entry.candidate.path == "/scenarios/xss/search"
    assert entry.candidate.method == "GET"
    assert entry.candidate.parameter_names == ("q",)
    assert entry.candidate.source == "zap"
    assert entry.candidate.observed_at == NOW
    assert entry.admission_status == "candidate_only"
    assert entry.registered_endpoint_id == "scenario-xss-search"
    assert len(result.events) == 2
    assert result.events[0].action == "recon_started"
    assert result.events[1].action == "recon_completed"


def test_deterministic_dedup_and_stable_ids_independent_of_input_order(service):
    items = [
        obs("/health"),
        obs("/scenarios/xss/search", names=("q",)),
        obs("/health"),
        obs("/scenarios/xss/search", names=("q",)),
    ]
    one = service.map_zap_observations(
        target_id="vulnerable-store", observations=items, observed_at=NOW
    )
    two = service.map_zap_observations(
        target_id="vulnerable-store", observations=list(reversed(items)), observed_at=NOW
    )
    assert one == two
    assert len(one.candidates) == 2
    assert len({x.candidate.candidate_id for x in one.candidates}) == 2


def test_unregistered_route_remains_candidate_and_coverage_gap(service):
    result = service.map_zap_observations(
        target_id="vulnerable-store", observations=[obs("/surprise")], observed_at=NOW
    )
    assert result.candidates[0].admission_status == "unsupported"
    assert result.limitations[0].reason == "no_template"


def test_authentication_only_route_marked_as_limitation(service):
    result = service.map_zap_observations(
        target_id="vulnerable-store", observations=[obs("/admin/login")], observed_at=NOW
    )
    assert result.candidates[0].admission_status == "unsupported"
    assert result.limitations[0].reason == "authentication_required"


def test_unknown_method_is_not_executable(service):
    result = service.map_zap_observations(
        target_id="vulnerable-store", observations=[obs("/health", "PUT")], observed_at=NOW
    )
    assert not result.candidates
    assert result.limitations[0].reason == "method_out_of_scope"


def test_invalid_paths_and_parameter_tricks_fail_closed(service):
    for value in (
        "http://evil.test/",
        "//evil.test",
        "/../secrets",
        "/%2e%2e/admin",
        "/safe\\evil",
        "/admin?token=foo",
    ):
        with pytest.raises(ValueError):
            service.map_zap_observations(
                target_id="vulnerable-store", observations=[obs(value)], observed_at=NOW
            )
    with pytest.raises(ValueError):
        service.map_zap_observations(
            target_id="vulnerable-store",
            observations=[obs("/health", names=("__proto__",))],
            observed_at=NOW,
        )


def test_unregistered_target_rejected(service):
    with pytest.raises(UnknownTargetError):
        service.map_zap_observations(
            target_id="external", observations=[obs("/health")], observed_at=NOW
        )


def test_agent_deterministic_bridge_never_executes(service):
    result = ReconnaissanceAgent.map_observations(
        service=service,
        target_id="vulnerable-store",
        observations=[obs("/health")],
        observed_at=NOW,
    )
    assert result.candidates[0].candidate.path == "/health"


def test_seeded_registered_recon_inherits_standard_budget(service, monkeypatch):
    from orchestrator.policy_engine import StandardRedPolicy
    from schemas.red_team import RedPolicyUsage
    from services.zap_adapter import ZapBudget

    registry = service.registry
    policy = StandardRedPolicy(registry=registry, budget_file=ROOT / "config/red_standard.json")
    auth = policy.freeze(
        assessment_id="as-1", approval_id="approved-1", target_id="vulnerable-store"
    )
    seen = []

    class FakeZap:
        def seed(self, authorization, *, target_id, endpoint_id, budget, usage):
            assert authorization == auth and target_id == "vulnerable-store"
            seen.append((endpoint_id, usage.http_requests, usage.crawl_requests))
            return True

    result = service.collect_registered_zap(
        adapter=FakeZap(),
        authorization=auth,
        endpoint_ids=("health", "baseline-search", "health"),
        budget=ZapBudget(max_urls=4, max_depth=1, duration_seconds=10),
        usage=RedPolicyUsage(),
        observed_at=NOW,
    )
    assert seen == [("health", 0, 0), ("baseline-search", 1, 1)]
    assert {entry.candidate.path for entry in result.candidates} == {"/health", "/search"}
    assert all(entry.admission_status == "candidate_only" for entry in result.candidates)


def test_seeded_recon_disallows_unknown_or_non_get_before_zap_call(service):
    from orchestrator.policy_engine import StandardRedPolicy
    from schemas.red_team import RedPolicyUsage
    from services.zap_adapter import ZapBudget

    auth = StandardRedPolicy(
        registry=service.registry, budget_file=ROOT / "config/red_standard.json"
    ).freeze(assessment_id="as-1", approval_id="approval-1", target_id="vulnerable-store")

    class NotCalled:
        def seed(self, *args, **kwargs):
            pytest.fail("must not reach ZAP")

    for ids in [("scenario-sqli-login",), ("unknown-endpoint",), ("health",) * 13]:
        with pytest.raises(ValueError):
            service.collect_registered_zap(
                adapter=NotCalled(),
                authorization=auth,
                endpoint_ids=ids,
                budget=ZapBudget(max_urls=4, max_depth=1, duration_seconds=10),
                usage=RedPolicyUsage(),
                observed_at=NOW,
            )


def test_persist_candidate_and_major_step_events_idempotently(service, tmp_path):
    from orchestrator.policy_engine import StandardRedPolicy
    from schemas.red_team_state import AssessmentDTO, CoverageDTO
    from services.red_assessment_store import RedAssessmentStore
    from services.red_evidence_store import RedEvidenceStore

    policy = StandardRedPolicy(
        registry=service.registry, budget_file=ROOT / "config/red_standard.json"
    )
    auth = policy.freeze(
        assessment_id="as-1", approval_id="approval-1", target_id="vulnerable-store"
    )
    store = RedAssessmentStore(tmp_path / "assessments.db")
    store.create(
        AssessmentDTO(
            scope=auth.scope,
            mode="manual",
            status="running",
            workflow_complete=False,
            coverage=CoverageDTO(),
        ),
        auth,
        request_id="creation-1",
    )
    journal = RedEvidenceStore(store, tmp_path / "evidence")
    mapping = service.map_zap_observations(
        target_id="vulnerable-store",
        observations=[
            obs("/health"),
            obs("/admin/login"),
            obs("/health"),
        ],
        observed_at=NOW,
    )
    service.persist_mapping(mapping=mapping, scope=auth.scope, store=store, journal=journal)
    service.persist_mapping(mapping=mapping, scope=auth.scope, store=store, journal=journal)
    restored, _ = RedAssessmentStore(store.path).load("as-1")
    assert len(restored.candidates) == 2
    assert {c.path for c in restored.candidates} == {"/health", "/admin/login"}
    events = journal.list_events(auth.scope)
    assert [event["action"] for event in events] == ["recon_started", "recon_completed"]
    assert all(event["actor"] == "red_reconnaissance" for event in events)
    assert all(event["details"]["stage"] == "reconnaissance" for event in events)
    assert not restored.operations
    assert not restored.plans

    # A later reconnaissance of the same surface retains its stable candidate
    # identities and first-observed timestamp, but writes a new event pair.
    later = NOW.replace(day=29)
    new_mapping = service.map_zap_observations(
        target_id="vulnerable-store",
        observations=[obs("/health"), obs("/admin/login")],
        observed_at=later,
    )
    assert {entry.candidate.candidate_id for entry in new_mapping.candidates} == {
        item.candidate_id for item in restored.candidates
    }
    service.persist_mapping(mapping=new_mapping, scope=auth.scope, store=store, journal=journal)
    assert len(RedAssessmentStore(store.path).load("as-1")[0].candidates) == 2
    assert [e["action"] for e in journal.list_events(auth.scope)] == [
        "recon_started",
        "recon_completed",
        "recon_started",
        "recon_completed",
    ]


def test_persist_denies_tampered_scope_without_writes(service, tmp_path):
    from orchestrator.policy_engine import StandardRedPolicy
    from schemas.red_team_state import AssessmentDTO, CoverageDTO
    from services.red_assessment_store import RedAssessmentStore
    from services.red_evidence_store import RedEvidenceStore

    auth = StandardRedPolicy(
        registry=service.registry, budget_file=ROOT / "config/red_standard.json"
    ).freeze(assessment_id="as-1", approval_id="approval-1", target_id="vulnerable-store")
    store = RedAssessmentStore(tmp_path / "assessments.db")
    store.create(
        AssessmentDTO(
            scope=auth.scope,
            mode="manual",
            status="running",
            workflow_complete=False,
            coverage=CoverageDTO(),
        ),
        auth,
        request_id="creation-1",
    )
    journal = RedEvidenceStore(store, tmp_path / "evidence")
    mapping = service.map_zap_observations(
        target_id="vulnerable-store", observations=[obs("/health")], observed_at=NOW
    )
    forged = auth.scope.model_copy(update={"authorization_fingerprint": "f" * 64})
    with pytest.raises(ValueError):
        service.persist_mapping(mapping=mapping, scope=forged, store=store, journal=journal)
    assert not store.load("as-1")[0].candidates
    assert not journal.list_events(auth.scope)


def test_seeded_recon_rejects_total_remaining_budget_before_any_get(service):
    from orchestrator.policy_engine import StandardRedPolicy
    from schemas.red_team import RedPolicyUsage
    from services.zap_adapter import ZapBudget

    authorization = StandardRedPolicy(
        registry=service.registry, budget_file=ROOT / "config/red_standard.json"
    ).freeze(assessment_id="as-1", approval_id="approved-1", target_id="vulnerable-store")

    class ForbiddenZap:
        def seed(self, *args, **kwargs):
            pytest.fail("no partial reconnaissance requests when batch budget is exceeded")

    with pytest.raises(ValueError, match="budget"):
        service.collect_registered_zap(
            adapter=ForbiddenZap(),
            authorization=authorization,
            endpoint_ids=("health", "baseline-documents"),
            budget=ZapBudget(max_urls=4, max_depth=1, duration_seconds=10),
            usage=RedPolicyUsage(crawl_requests=11, http_requests=23),
            observed_at=NOW,
        )
