"""T22 model-free Red stage coordinator state-machine tests."""

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest

from orchestrator.policy_engine import StandardRedPolicy
from orchestrator.red_team_flow import (
    RedStageBlocked,
    RedStageCoordinator,
    RedStageExecutionError,
)
from schemas.red_team import (
    ExecutionWork,
    ExecutionWorkResult,
    PlanningWork,
    PlanningWorkResult,
    ReconnaissanceWork,
    ReconnaissanceWorkResult,
    RedEndpointCandidate,
    VerificationWork,
    VerificationWorkResult,
)
from schemas.red_team_state import (
    AssessmentDTO,
    AssessmentState,
    CoverageDTO,
    CoverageGapDTO,
    FindingDTO,
    OperationDTO,
    PlanVersionDTO,
    ReceiptDTO,
    StageDTO,
    StageState,
    StageTransitionEventDTO,
)
from services.red_assessment_store import RedAssessmentStore
from services.red_evidence_store import EvidenceDenied, RedEvidenceStore
from services.target_registry import TargetRegistry

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 28, 18, tzinfo=UTC)


def build_environment(tmp_path, *, mode="autonomous", workers=None):
    registry = TargetRegistry.from_directories(
        targets_dir=ROOT / "config/targets",
        security_tests_dir=ROOT / "config/security_tests",
    )
    authorization = StandardRedPolicy(
        registry=registry, budget_file=ROOT / "config/red_standard.json",
    ).freeze(
        assessment_id=f"as-t22-{mode}",
        approval_id=f"approval-t22-{mode}",
        target_id="vulnerable-store",
    )
    store = RedAssessmentStore(tmp_path / f"{mode}.sqlite3")
    store.create(
        AssessmentDTO(
            scope=authorization.scope,
            mode=mode,
            status="running",
            workflow_complete=False,
            coverage=CoverageDTO(),
        ),
        authorization,
        request_id=f"request-t22-{mode}",
    )
    candidate = RedEndpointCandidate(
        candidate_id="candidate-xss",
        method="GET",
        path="/scenarios/xss/search",
        parameter_names=("q",),
        source="registered",
        observed_at=NOW,
    )
    store.add_candidate(authorization.scope.assessment_id, candidate)
    surface = store.record_surface(
        authorization.scope, candidates=(candidate,), observed_at=NOW,
    )
    plan = PlanVersionDTO(
        scope=authorization.scope,
        plan_version="plan-t22",
        surface_revision=surface.surface_revision,
        status="approved",
        plan_digest="c" * 64,
    )
    store.add_plan(plan)
    operation = OperationDTO(
        scope=authorization.scope,
        operation_id="operation-t22",
        plan_version=plan.plan_version,
        candidate_id=candidate.candidate_id,
        test_id="xss-reflection-001",
        status="approved",
    )
    store.add_operation(operation)
    journal = RedEvidenceStore(store, tmp_path / f"{mode}-evidence")
    receipt = ReceiptDTO(
        scope=authorization.scope,
        receipt_id="receipt-t22",
        operation_id=operation.operation_id,
        plan_version=plan.plan_version,
        test_id=operation.test_id,
        run_id="run-t22",
        target_revision=authorization.scope.target_fingerprint,
        recorded_at=NOW,
        source="controlled_http",
        status="completed",
        request_count=0,
        exchanges=(),
        raw_response_sha256=hashlib.sha256(b"t22").hexdigest(),
        evidence_id="evidence-t22",
    )
    journal.add_receipt_with_evidence(
        receipt,
        data={
            "operation_id": operation.operation_id,
            "test_id": operation.test_id,
            "status": "completed",
        },
    )
    journal._record_verified_finding(
        FindingDTO(
            scope=authorization.scope,
            finding_id="finding-t22",
            operation_id=operation.operation_id,
            status="inconclusive",
            oracle_id="unescaped-reflection-evidence-001",
            evidence_receipt_ids=(receipt.receipt_id,),
        )
    )
    tasks = (
        ReconnaissanceWork(scope=authorization.scope),
        PlanningWork(
            scope=authorization.scope,
            surface_revision=surface.surface_revision,
            candidates=(candidate,),
            vetted_test_ids=(operation.test_id,),
        ),
        ExecutionWork(
            scope=authorization.scope,
            plan_version=plan.plan_version,
            operation_id=operation.operation_id,
        ),
        VerificationWork(
            scope=authorization.scope,
            plan_version=plan.plan_version,
            operation_id=operation.operation_id,
            receipt_ids=(receipt.receipt_id,),
            oracle_id="unescaped-reflection-evidence-001",
        ),
    )
    default_workers = {
        "reconnaissance": lambda task: ReconnaissanceWorkResult(
            scope=task.scope, candidates=(candidate,),
        ),
        "planning": lambda task: PlanningWorkResult(
            scope=task.scope,
            plan_version=plan.plan_version,
            operation_ids=(operation.operation_id,),
        ),
        "execution": lambda task: ExecutionWorkResult(
            scope=task.scope,
            plan_version=task.plan_version,
            operation_id=task.operation_id,
            receipt_ids=(receipt.receipt_id,),
        ),
        "verification": lambda task: VerificationWorkResult(
            scope=task.scope,
            plan_version=task.plan_version,
            operation_id=task.operation_id,
            outcome="inconclusive",
            evidence_receipt_ids=(receipt.receipt_id,),
        ),
    }
    coordinator = RedStageCoordinator(
        journal=journal,
        workers=workers or default_workers,
        clock=lambda: NOW,
    )
    return coordinator, journal, tasks, default_workers


def test_autonomous_normal_path_persists_typed_before_and_after_events(tmp_path):
    coordinator, journal, tasks, _ = build_environment(tmp_path)

    results = coordinator.run_autonomous(tasks)

    assert tuple(result.stage for result in results) == (
        "reconnaissance", "planning", "execution", "verification",
    )
    snapshot, _ = journal.store.load(tasks[0].scope.assessment_id)
    assert {stage.stage: stage.status for stage in snapshot.stages} == {
        "reconnaissance": StageState.SUCCEEDED,
        "planning": StageState.SUCCEEDED,
        "execution": StageState.SUCCEEDED,
        "verification": StageState.SUCCEEDED,
    }
    events = journal.list_stage_events(tasks[0].scope)
    assert len(events) == 16
    assert all(event.phase == "before_worker" for event in events[:3])
    assert events[3].phase == "after_worker"
    assert [event.status for event in events[:4]] == [
        StageState.READY,
        StageState.QUEUED,
        StageState.RUNNING,
        StageState.SUCCEEDED,
    ]


def test_manual_stage_uses_same_workers_and_blocks_missing_prerequisite(tmp_path):
    calls = []
    coordinator, journal, tasks, workers = build_environment(tmp_path, mode="manual")
    wrapped = {
        name: (lambda task, name=name: (calls.append(name), workers[name](task))[1])
        for name in workers
    }
    coordinator = RedStageCoordinator(journal=journal, workers=wrapped, clock=lambda: NOW)

    with pytest.raises(RedStageBlocked, match="reconnaissance"):
        coordinator.run_manual(tasks[1])
    assert calls == []
    snapshot, _ = journal.store.load(tasks[0].scope.assessment_id)
    assert snapshot.stages[0].status == StageState.BLOCKED

    coordinator.run_manual(tasks[0])
    altered = tasks[1].model_copy(update={
        "candidates": (
            tasks[1].candidates[0].model_copy(update={"path": "/altered"}),
        ),
    })
    with pytest.raises(RedStageBlocked, match="persisted reconnaissance surface"):
        coordinator.run_manual(altered)
    coordinator.run_manual(tasks[1])
    assert calls == ["reconnaissance", "planning"]


def test_restart_preserves_interrupted_running_stage_without_redispatch(tmp_path):
    calls = []

    def interrupted(task):
        calls.append(task.stage)
        raise KeyboardInterrupt("simulated process stop")

    _, journal, tasks, workers = build_environment(tmp_path, mode="manual")
    coordinator = RedStageCoordinator(
        journal=journal,
        workers={**workers, "reconnaissance": interrupted},
        clock=lambda: NOW,
    )
    with pytest.raises(KeyboardInterrupt, match="process stop"):
        coordinator.run_manual(tasks[0])

    restored = RedStageCoordinator(
        journal=RedEvidenceStore(
            RedAssessmentStore(journal.store.path), journal.evidence_root,
        ),
        workers={
            **workers,
            "reconnaissance": lambda _task: pytest.fail("must not redispatch"),
        },
        clock=lambda: NOW,
    )
    with pytest.raises(RedStageBlocked, match="interrupted"):
        restored.run_manual(tasks[0])
    snapshot, _ = restored.journal.store.load(tasks[0].scope.assessment_id)
    assert snapshot.stages[0].status == StageState.RUNNING
    assert calls == ["reconnaissance"]


def test_unexpected_worker_error_is_persisted_as_failed(tmp_path):
    coordinator, journal, tasks, workers = build_environment(tmp_path, mode="manual")

    def fail(_task):
        raise RuntimeError("unsafe worker detail")

    coordinator = RedStageCoordinator(
        journal=journal,
        workers={**workers, "reconnaissance": fail},
        clock=lambda: NOW,
    )
    with pytest.raises(RedStageExecutionError, match="reconnaissance worker failed"):
        coordinator.run_manual(tasks[0])

    snapshot, _ = journal.store.load(tasks[0].scope.assessment_id)
    assert snapshot.stages[0].status == StageState.FAILED
    events = journal.list_stage_events(tasks[0].scope)
    assert events[-1].status == StageState.FAILED
    assert events[-1].phase == "after_worker"
    assert "unsafe worker detail" not in str(journal.list_events(tasks[0].scope))


def test_success_without_durable_worker_output_is_failed(tmp_path):
    coordinator, journal, tasks, workers = build_environment(tmp_path, mode="manual")
    missing = tasks[0].model_copy()
    unpersisted = tasks[1].candidates[0].model_copy(update={
        "candidate_id": "candidate-unpersisted",
    })
    coordinator = RedStageCoordinator(
        journal=journal,
        workers={
            **workers,
            "reconnaissance": lambda task: ReconnaissanceWorkResult(
                scope=task.scope, candidates=(unpersisted,),
            ),
        },
        clock=lambda: NOW,
    )

    with pytest.raises(RedStageExecutionError, match="did not persist"):
        coordinator.run_manual(missing)
    snapshot, _ = journal.store.load(missing.scope.assessment_id)
    assert snapshot.stages[0].status == StageState.FAILED


def test_transition_rechecks_running_assessment_atomically(tmp_path):
    _, journal, tasks, _ = build_environment(tmp_path, mode="manual")
    snapshot, _ = journal.store.load(tasks[0].scope.assessment_id)
    cancelled = snapshot.assessment.model_copy(update={
        "status": AssessmentState.CANCELLED, "workflow_complete": True,
    })
    with journal.store._connect() as db:
        db.execute(
            "UPDATE red_assessments SET assessment_json=? WHERE assessment_id=?",
            (cancelled.model_dump_json(), tasks[0].scope.assessment_id),
        )
    stage = StageDTO(
        scope=tasks[0].scope,
        stage="reconnaissance",
        status="ready",
    )
    event = StageTransitionEventDTO(
        scope=tasks[0].scope,
        event_id="event-terminal-denied",
        stage="reconnaissance",
        previous_status="not_started",
        status="ready",
        phase="before_worker",
        occurred_at=NOW,
    )

    with pytest.raises(EvidenceDenied, match="running assessment"):
        journal.transition_stage(stage, event)
    restored, _ = journal.store.load(tasks[0].scope.assessment_id)
    assert restored.stages == ()


def test_planning_success_requires_durable_coverage_gaps(tmp_path):
    _, journal, tasks, workers = build_environment(tmp_path, mode="manual")
    coordinator = RedStageCoordinator(
        journal=journal,
        workers={
            **workers,
            "planning": lambda task: PlanningWorkResult(
                scope=task.scope,
                plan_version="plan-t22",
                operation_ids=("operation-t22",),
                coverage_gap_ids=("gap-missing",),
            ),
        },
        clock=lambda: NOW,
    )
    coordinator.run_manual(tasks[0])

    with pytest.raises(RedStageExecutionError, match="coverage-gap"):
        coordinator.run_manual(tasks[1])


def test_verification_success_is_bound_to_requested_oracle(tmp_path):
    coordinator, _, tasks, _ = build_environment(tmp_path, mode="manual")
    for task in tasks[:3]:
        coordinator.run_manual(task)
    changed_oracle = tasks[3].model_copy(update={"oracle_id": "different-oracle"})

    with pytest.raises(RedStageExecutionError, match="finding output"):
        coordinator.run_manual(changed_oracle)


def test_not_tested_requires_open_gap_for_same_test(tmp_path):
    _, journal, tasks, workers = build_environment(tmp_path, mode="manual")
    journal.record_coverage_gaps(
        tasks[0].scope,
        (
            CoverageGapDTO(
                scope=tasks[0].scope,
                gap_id="gap-unrelated-test",
                reason="not_tested",
                candidate_id="candidate-xss",
                test_id="sqli-login-bypass-001",
            ),
        ),
    )
    coordinator = RedStageCoordinator(
        journal=journal,
        workers={
            **workers,
            "verification": lambda task: VerificationWorkResult(
                scope=task.scope,
                plan_version=task.plan_version,
                operation_id=task.operation_id,
                outcome="not_tested",
            ),
        },
        clock=lambda: NOW,
    )
    for task in tasks[:3]:
        coordinator.run_manual(task)

    with pytest.raises(RedStageExecutionError, match="coverage gap"):
        coordinator.run_manual(tasks[3])
