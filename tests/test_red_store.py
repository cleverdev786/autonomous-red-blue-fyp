"""T05 SQLite persistence: immutable approval and versioned Red records."""

from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
import sqlite3

import pytest

from orchestrator.policy_engine import StandardRedPolicy
from schemas.red_team import RedEndpointCandidate
from schemas.red_team_state import (
    AssessmentDTO, CoverageDTO, OperationDTO, PlanVersionDTO, StageDTO,
)
from services.red_assessment_store import RedAssessmentStore, StoreConflict
from services.target_registry import TargetRegistry

from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def records(tmp_path):
    registry = TargetRegistry.from_directories(
        targets_dir=ROOT / "config/targets", security_tests_dir=ROOT / "config/security_tests",
    )
    auth = StandardRedPolicy(
        registry=registry, budget_file=ROOT / "config/red_standard.json",
    ).freeze(
        assessment_id="as-1", approval_id="approval-1", target_id="vulnerable-store",
    )
    assessment = AssessmentDTO(
        scope=auth.scope, mode="manual", status="created",
        workflow_complete=False, coverage=CoverageDTO(),
    )
    candidate = RedEndpointCandidate(
        candidate_id="c-1", method="GET", path="/scenarios/xss/search",
        parameter_names=("q",), source="registered",
        observed_at=datetime(2026, 10, 27, tzinfo=timezone.utc),
    )
    plan = PlanVersionDTO(
        scope=auth.scope, plan_version="plan-1", surface_revision="surface-1",
        status="approved",
    )
    op = OperationDTO(
        scope=auth.scope, operation_id="op-1", plan_version="plan-1",
        candidate_id="c-1", test_id="xss-reflection-001", status="proposed",
    )
    return tmp_path / "red.sqlite3", auth, assessment, candidate, plan, op


def test_restart_restores_identity_auth_and_stages(records):
    path, auth, assessment, candidate, plan, operation = records
    store = RedAssessmentStore(path)
    assert store.create(assessment, auth, request_id="request-1") == "as-1"
    store.add_candidate(assessment.scope.assessment_id, candidate)
    store.add_plan(plan)
    store.set_stage(StageDTO(scope=auth.scope, stage="reconnaissance", status="ready"))
    store.set_stage(StageDTO(scope=auth.scope, stage="reconnaissance", status="queued"))
    store.set_stage(StageDTO(scope=auth.scope, stage="reconnaissance", status="running"))
    store.add_operation(operation)

    restored, saved_auth = RedAssessmentStore(path).load("as-1")
    assert restored.assessment == assessment
    assert saved_auth == auth
    assert restored.stages[0].status.value == "running"
    assert restored.plans == (plan,)
    assert restored.candidates == (candidate,)
    assert restored.operations == (operation,)


def test_prior_versions_are_retained_and_stale_cannot_be_executed(records):
    path, auth, assessment, candidate, plan, operation = records
    db = RedAssessmentStore(path)
    db.create(assessment, auth, request_id="req-1")
    db.add_candidate("as-1", candidate)
    db.add_plan(plan)
    db.add_operation(operation)
    db.set_plan_stale("as-1", "plan-1")
    new_plan = plan.model_copy(update={"plan_version": "plan-2",
                                       "surface_revision": "surface-2"})
    db.add_plan(new_plan)
    snapshot, _ = RedAssessmentStore(path).load("as-1")
    assert {x.plan_version: x.status for x in snapshot.plans} == {
        "plan-1": "stale", "plan-2": "approved",
    }
    assert snapshot.operations[0].plan_version == "plan-1"
    with pytest.raises(StoreConflict, match="stale"):
        db.add_operation(operation.model_copy(update={
            "operation_id": "op-2",
        }))
    with pytest.raises(StoreConflict, match="immutable"):
        db.add_plan(plan.model_copy(update={"surface_revision": "altered"}))


def test_retry_is_idempotent_only_for_identical_request(records):
    path, auth, assessment, *_ = records
    db = RedAssessmentStore(path)
    assert db.create(assessment, auth, request_id="same-request") == "as-1"
    assert db.create(assessment, auth, request_id="same-request") == "as-1"
    other = assessment.model_copy(update={"mode": "autonomous"})
    with pytest.raises(StoreConflict, match="idempotency"):
        db.create(other, auth, request_id="same-request")
    with pytest.raises(StoreConflict, match="already"):
        db.create(assessment, auth, request_id="different-request")
    with pytest.raises(StoreConflict, match="authorization"):
        db.create(assessment, auth.model_copy(update={"approval_id": "altered"}),
                  request_id="same-request")


def test_reject_orphan_refs_and_cross_assessment_scope(records):
    path, auth, assessment, candidate, plan, operation = records
    db = RedAssessmentStore(path)
    with pytest.raises(StoreConflict, match="assessment"):
        db.add_plan(plan)
    db.create(assessment, auth, request_id="req-1")
    with pytest.raises(StoreConflict, match="plan"):
        db.add_operation(operation)
    db.add_candidate("as-1", candidate)
    with pytest.raises(StoreConflict, match="plan"):
        db.add_operation(operation)
    wrong = plan.model_copy(update={
        "scope": auth.scope.model_copy(update={"authorization_fingerprint": "f" * 64})
    })
    with pytest.raises(StoreConflict, match="scope"):
        db.add_plan(wrong)
    db.add_plan(plan)
    with pytest.raises(StoreConflict, match="candidate"):
        db.add_operation(operation.model_copy(update={"candidate_id": "not-registered"}))
    db.add_operation(operation)
    with pytest.raises(StoreConflict, match="duplicate"):
        db.add_operation(operation)
    with pytest.raises(StoreConflict, match="duplicate"):
        db.add_candidate("as-1", candidate)


def test_stage_transition_and_unknown_plan_fail_closed(records):
    path, auth, assessment, candidate, plan, operation = records
    db = RedAssessmentStore(path)
    db.create(assessment, auth, request_id="req-1")
    with pytest.raises(StoreConflict, match="transition"):
        db.set_stage(StageDTO(scope=auth.scope, stage="planning", status="running"))
    with pytest.raises(StoreConflict, match="plan"):
        db.set_stage(StageDTO(scope=auth.scope, stage="planning", status="ready",
                              plan_version="missing"))
    db.add_plan(plan)
    db.set_stage(StageDTO(scope=auth.scope, stage="planning", status="ready",
                          plan_version="plan-1"))
    with pytest.raises(StoreConflict, match="transition"):
        db.set_stage(StageDTO(scope=auth.scope, stage="planning", status="succeeded",
                              plan_version="plan-1"))


def test_commit_is_atomic_and_keeps_existing_project_db_out_of_scope(records):
    path, auth, assessment, candidate, plan, operation = records
    db = RedAssessmentStore(path)
    db.create(assessment, auth, request_id="req-1")
    db.add_candidate("as-1", candidate)
    db.add_plan(plan)
    # Direct SQL cannot bypass composite foreign keys.
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO red_operations"
                "(assessment_id, operation_id, plan_version, candidate_id, payload)"
                " VALUES (?,?,?,?,?)",
                ("as-1", "bad-op", "nonexistent", "c-1", operation.model_dump_json()),
            )
    saved, _ = RedAssessmentStore(path).load("as-1")
    assert saved.operations == ()



def test_concurrent_identical_retry_keeps_one_assessment(records):
    path, auth, assessment, *_ = records
    RedAssessmentStore(path)

    def attempt(_):
        return RedAssessmentStore(path).create(
            assessment, auth, request_id="stable-intent",
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(attempt, range(2))) == ["as-1", "as-1"]
    restored, _ = RedAssessmentStore(path).load("as-1")
    assert restored.assessment.scope.assessment_id == "as-1"


def test_authorization_must_match_scope_before_write(records):
    path, auth, assessment, *_ = records
    db = RedAssessmentStore(path)
    unauthorized = auth.model_copy(update={
        "scope": auth.scope.model_copy(update={"authorization_fingerprint": "f" * 64})
    })
    with pytest.raises(StoreConflict, match="authorization"):
        db.create(assessment, unauthorized, request_id="bad-request")
    with pytest.raises(StoreConflict, match="assessment"):
        db.load("as-1")
