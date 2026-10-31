"""T14 deterministic registered-template planning rules."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from agents.red.attack_planner import DeterministicAttackPlanner
from orchestrator.policy_engine import StandardRedPolicy
from schemas.red_team import PlanningWork, RedEndpointCandidate
from services.reconnaissance_service import ReconnaissanceService
from services.target_registry import TargetRegistry

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 28, tzinfo=UTC)


def planning_inputs(*, allowed_classes=None, allowed_methods=None):
    registry = TargetRegistry.from_directories(
        targets_dir=ROOT / "config/targets",
        security_tests_dir=ROOT / "config/security_tests",
    )
    authorization = StandardRedPolicy(
        registry=registry,
        budget_file=ROOT / "config/red_standard.json",
    ).freeze(
        assessment_id="as-1",
        approval_id="approval-1",
        target_id="vulnerable-store",
        allowed_classes=allowed_classes,
        allowed_methods=allowed_methods,
    )
    catalog = ReconnaissanceService(registry=registry).build_attack_planning_catalog(
        target_id="vulnerable-store"
    )
    candidates = (
        RedEndpointCandidate(
            candidate_id="candidate-traversal",
            method="GET",
            path="/scenarios/path-traversal/read",
            parameter_names=("path",),
            source="zap",
            observed_at=NOW,
        ),
        RedEndpointCandidate(
            candidate_id="candidate-xss",
            method="GET",
            path="/scenarios/xss/search",
            parameter_names=("q",),
            source="zap",
            observed_at=NOW,
        ),
        RedEndpointCandidate(
            candidate_id="candidate-sqli",
            method="POST",
            path="/scenarios/sql-injection/login",
            parameter_names=("username", "password"),
            source="registered",
            observed_at=NOW,
        ),
    )
    work = PlanningWork(
        scope=authorization.scope,
        surface_revision="surface-1",
        candidates=candidates,
        vetted_test_ids=tuple(option.test_id for option in catalog.options),
    )
    return DeterministicAttackPlanner(), work, catalog, authorization


def test_selects_every_applicable_template_in_stable_order_without_provider() -> None:
    planner, work, catalog, authorization = planning_inputs()

    forward = planner.plan(work=work, catalog=catalog, authorization=authorization)
    reverse = planner.plan(
        work=work.model_copy(update={"candidates": tuple(reversed(work.candidates))}),
        catalog=catalog,
        authorization=authorization,
    )

    assert forward == reverse
    assert [operation.test_id for operation in forward.operations] == [
        "path-traversal-private-file-001",
        "sqli-login-bypass-001",
        "xss-reflection-001",
    ]
    assert not forward.coverage_gaps
    assert forward.plan.status == "approved"
    assert len(forward.plan.plan_digest or "") == 64
    assert not hasattr(planner, "provider")


def test_plan_digest_binds_candidates_and_templates() -> None:
    planner, work, catalog, authorization = planning_inputs()
    baseline = planner.plan(work=work, catalog=catalog, authorization=authorization)
    changed_candidate = work.candidates[0].model_copy(update={"source": "registered"})
    changed_work = work.model_copy(update={"candidates": (changed_candidate, *work.candidates[1:])})
    changed_template = catalog.options[0].model_copy(
        update={"safe_description": "Reviewed descriptor revision."}
    )
    changed_catalog = catalog.model_copy(
        update={"options": (changed_template, *catalog.options[1:])}
    )

    assert (
        planner.plan(
            work=changed_work,
            catalog=catalog,
            authorization=authorization,
        ).plan.plan_digest
        != baseline.plan.plan_digest
    )
    assert (
        planner.plan(
            work=work,
            catalog=changed_catalog,
            authorization=authorization,
        ).plan.plan_digest
        != baseline.plan.plan_digest
    )


def test_budget_and_unsupported_candidates_produce_typed_gaps() -> None:
    planner, work, catalog, authorization = planning_inputs()
    duplicate_xss = work.candidates[1].model_copy(update={"candidate_id": "candidate-xss-second"})
    unknown = RedEndpointCandidate(
        candidate_id="candidate-unknown",
        method="GET",
        path="/unregistered",
        source="zap",
        observed_at=NOW,
    )
    work = work.model_copy(update={"candidates": (*work.candidates, duplicate_xss, unknown)})

    result = planner.plan(work=work, catalog=catalog, authorization=authorization)

    assert len(result.operations) == 3
    assert {gap.reason for gap in result.coverage_gaps} == {
        "budget_exhausted",
        "no_template",
    }
    assert all(gap.recommendation for gap in result.coverage_gaps)


def test_scope_restrictions_create_gaps_and_cannot_upgrade_method_or_target() -> None:
    planner, work, catalog, authorization = planning_inputs(
        allowed_classes={"sql_injection", "path_traversal", "xss"},
        allowed_methods={"GET"},
    )
    result = planner.plan(work=work, catalog=catalog, authorization=authorization)

    assert [operation.test_id for operation in result.operations] == [
        "path-traversal-private-file-001",
        "xss-reflection-001",
    ]
    assert {gap.reason for gap in result.coverage_gaps} == {"method_out_of_scope"}
    assert all(operation.scope == authorization.scope for operation in result.operations)

    forged = work.model_copy(
        update={
            "scope": work.scope.model_copy(update={"target_id": "external"}),
        }
    )
    try:
        planner.plan(work=forged, catalog=catalog, authorization=authorization)
    except ValueError as exc:
        assert "scope" in str(exc)
    else:
        raise AssertionError("forged target scope must be rejected")


def test_unavailable_authenticated_route_has_a_specific_gap() -> None:
    planner, work, catalog, authorization = planning_inputs()
    candidate = work.candidates[0].model_copy(
        update={
            "candidate_id": "candidate-admin",
            "path": "/admin/panel",
            "parameter_names": (),
        }
    )

    result = planner.plan(
        work=work.model_copy(update={"candidates": (candidate,)}),
        catalog=catalog,
        authorization=authorization,
    )

    assert result.operations == ()
    assert result.coverage_gaps[0].reason == "authentication_required"
