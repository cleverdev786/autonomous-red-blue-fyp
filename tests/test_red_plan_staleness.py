"""T15 surface revision and stale-plan persistence rules."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from agents.red.attack_planner import DeterministicAttackPlanner
from orchestrator.policy_engine import StandardRedPolicy
from schemas.red_team import PlanningWork, RedEndpointCandidate, RedPolicyUsage
from schemas.red_team_state import AssessmentDTO, CoverageDTO, PlanVersionDTO
from services.reconnaissance_service import ReconnaissanceService
from services.red_admission import AdmissionRequest, TrustedRedAdmission
from services.red_assessment_store import RedAssessmentStore, StoreConflict
from services.red_evidence_store import RedEvidenceStore
from services.target_registry import TargetRegistry

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 28, tzinfo=UTC)
IP = "172.19.0.7"


@pytest.mark.parametrize("mode", ["manual", "autonomous"])
def test_recon_rerun_stales_old_plan_and_refreshed_plan_is_admissible(
    tmp_path: Path,
    mode: str,
) -> None:
    registry = TargetRegistry.from_directories(
        targets_dir=ROOT / "config/targets",
        security_tests_dir=ROOT / "config/security_tests",
    )
    policy = StandardRedPolicy(
        registry=registry,
        budget_file=ROOT / "config/red_standard.json",
    )
    authorization = policy.freeze(
        assessment_id="as-1",
        approval_id="approval-1",
        target_id="vulnerable-store",
    )
    store = RedAssessmentStore(tmp_path / "red.sqlite3")
    store.create(
        AssessmentDTO(
            scope=authorization.scope,
            mode=mode,
            status="running",
            workflow_complete=False,
            coverage=CoverageDTO(),
        ),
        authorization,
        request_id="request-1",
    )
    candidate = RedEndpointCandidate(
        candidate_id="candidate-xss",
        method="GET",
        path="/scenarios/xss/search",
        parameter_names=("q",),
        source="zap",
        observed_at=NOW,
    )
    store.add_candidate("as-1", candidate)
    first_surface = store.record_surface(
        authorization.scope,
        candidates=(candidate,),
        observed_at=NOW,
    )
    with pytest.raises(StoreConflict, match="digest"):
        store.add_plan(
            PlanVersionDTO(
                scope=authorization.scope,
                plan_version="undigested-plan",
                surface_revision=first_surface.surface_revision,
                status="approved",
            )
        )

    catalog = ReconnaissanceService(registry=registry).build_attack_planning_catalog(
        target_id="vulnerable-store"
    )
    planner = DeterministicAttackPlanner()
    first = planner.plan(
        work=PlanningWork(
            scope=authorization.scope,
            surface_revision=first_surface.surface_revision,
            candidates=(candidate,),
            vetted_test_ids=tuple(option.test_id for option in catalog.options),
        ),
        catalog=catalog,
        authorization=authorization,
    )
    store.add_plan(first.plan)
    approved = first.operations[0].model_copy(update={"status": "approved"})
    store.add_operation(approved)

    journal = RedEvidenceStore(store, tmp_path / "artifacts")
    admission = TrustedRedAdmission(
        store=store,
        journal=journal,
        policy=policy,
        pinned_ips=frozenset({IP}),
        resolver=lambda _: (IP,),
    )
    request = AdmissionRequest(
        scope=authorization.scope,
        operation_id=approved.operation_id,
        plan_version=first.plan.plan_version,
        tool="controlled_http",
        method="GET",
        url="http://vulnerable-store:8000/scenarios/xss/search",
    )
    assert admission.check(request, RedPolicyUsage()).allowed

    second_surface = store.record_surface(
        authorization.scope,
        candidates=(candidate,),
        observed_at=NOW.replace(day=29),
    )
    assert second_surface.surface_revision != first_surface.surface_revision
    denied = admission.check(request, RedPolicyUsage())
    assert not denied.allowed

    stale_snapshot, _ = store.load("as-1")
    assert stale_snapshot.plans[0].status == "stale"
    assert stale_snapshot.operations[0].status == "blocked"

    refreshed = planner.plan(
        work=PlanningWork(
            scope=authorization.scope,
            surface_revision=second_surface.surface_revision,
            candidates=(candidate,),
            vetted_test_ids=tuple(option.test_id for option in catalog.options),
        ),
        catalog=catalog,
        authorization=authorization,
    )
    assert refreshed.plan.plan_digest != first.plan.plan_digest
    store.add_plan(refreshed.plan)
    refreshed_operation = refreshed.operations[0].model_copy(update={"status": "approved"})
    store.add_operation(refreshed_operation)
    refreshed_request = request.model_copy(
        update={
            "operation_id": refreshed_operation.operation_id,
            "plan_version": refreshed.plan.plan_version,
        }
    )
    assert admission.check(refreshed_request, RedPolicyUsage()).allowed

    final_snapshot, _ = store.load("as-1")
    assert [plan.status for plan in final_snapshot.plans] == ["stale", "approved"]
