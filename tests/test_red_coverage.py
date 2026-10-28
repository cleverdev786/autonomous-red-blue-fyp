"""T21 truthful coverage rollup and durable data-only handoff."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from agents.red.attack_verifier import DeterministicAttackVerifier
from schemas.red_team import TestExecutionResult as ExecutionResult
from schemas.red_team_state import CoverageGapDTO
from services.red_assessment_summary import RedAssessmentSummarizer
from services.red_evidence_receipts import RedEvidenceRecorder
from services.target_registry import TargetRegistry
from services.zap_adapter import ZapTargetedObservation
from tests.test_red_real_execution import build_execution_env

ROOT = Path(__file__).resolve().parents[1]


def _registry():
    return TargetRegistry.from_directories(
        targets_dir=ROOT / "config/targets",
        security_tests_dir=ROOT / "config/security_tests",
    )


def test_full_coverage_completes_and_creates_one_idempotent_pending_handoff(tmp_path):
    dispatcher, request, _ = build_execution_env(tmp_path)
    result = dispatcher.executor.execute_registered_test(
        test_id="xss-reflection-001", attempt_number=1, run_id="run-summary"
    )
    journal = dispatcher.admission.journal
    receipt = RedEvidenceRecorder(journal).record_controlled(
        scope=request.scope, operation_id=request.operation_id,
        plan_version=request.plan_version,
        target_revision=request.scope.target_fingerprint, result=result,
        recorded_at=datetime(2026, 10, 28, 13, tzinfo=UTC),
    )
    finding = DeterministicAttackVerifier(_registry(), journal=journal).verify(
        receipt, result
    )
    snapshot, _ = journal.store.load(request.scope.assessment_id)
    summarizer = RedAssessmentSummarizer(journal)

    first = summarizer.summarize(
        scope=request.scope, operations=snapshot.operations,
        receipts=(receipt,), findings=(finding,),
    )
    second = summarizer.summarize(
        scope=request.scope, operations=snapshot.operations,
        receipts=(receipt,), findings=(finding,),
    )

    assert first.status == "completed"
    assert first.coverage.completed == first.coverage.eligible == 1
    assert first.pending_handoffs == second.pending_handoffs
    assert len(journal.list_pending_handoffs(request.scope)) == 1
    assert first.pending_handoffs[0].data_only is True


def test_budget_cutoff_and_unsupported_route_complete_with_visible_limitations(tmp_path):
    dispatcher, request, _ = build_execution_env(tmp_path)
    journal = dispatcher.admission.journal
    snapshot, _ = journal.store.load(request.scope.assessment_id)
    gap = CoverageGapDTO(
        scope=request.scope, gap_id="gap-unsupported", reason="unsupported_class",
        candidate_id="candidate-xss", recommendation="No registered safe template.",
    )
    budget_gap = CoverageGapDTO(
        scope=request.scope, gap_id="gap-budget", reason="budget_exhausted",
        candidate_id="candidate-xss", test_id="xss-reflection-001",
        recommendation="Resume only under a newly approved budget.",
    )
    journal.record_coverage_gaps(request.scope, (gap, budget_gap))

    with pytest.raises(ValueError, match="coverage-gap"):
        RedAssessmentSummarizer(journal).summarize(
            scope=request.scope, operations=snapshot.operations,
            receipts=(), findings=(), coverage_gaps=(),
        )

    summary = RedAssessmentSummarizer(journal).summarize(
        scope=request.scope, operations=snapshot.operations, receipts=(), findings=(),
        coverage_gaps=(gap, budget_gap),
    )

    assert summary.status == "completed_with_limitations"
    assert summary.coverage.eligible == 1
    assert summary.coverage.skipped == 1
    assert summary.coverage.completed == 0
    assert "unauthenticated_only_coverage" in summary.warnings
    assert "unsupported_vulnerability_classes" in summary.warnings
    assert "incomplete_or_uncertain_coverage" in summary.warnings


def test_timeout_is_executed_but_inconclusive_not_completed_or_safe(tmp_path):
    dispatcher, request, _ = build_execution_env(tmp_path)
    journal = dispatcher.admission.journal
    result = ExecutionResult(
        run_id="run-timeout", target_id="vulnerable-store",
        test_id="xss-reflection-001", attempt_number=1, request_count=0,
        completed=False, timed_out=True, duration_ms=5000,
        error_code="request-timeout",
    )
    receipt = RedEvidenceRecorder(journal).record_controlled(
        scope=request.scope, operation_id=request.operation_id,
        plan_version=request.plan_version,
        target_revision=request.scope.target_fingerprint, result=result,
        recorded_at=datetime(2026, 10, 28, 13, tzinfo=UTC),
    )
    finding = DeterministicAttackVerifier(_registry(), journal=journal).verify(
        receipt, result
    )
    snapshot, _ = journal.store.load(request.scope.assessment_id)

    summary = RedAssessmentSummarizer(journal).summarize(
        scope=request.scope, operations=snapshot.operations,
        receipts=(receipt,), findings=(finding,),
    )

    assert summary.status == "completed_with_limitations"
    assert summary.coverage.executed == 1
    assert summary.coverage.completed == 0
    assert summary.coverage.unresolved_observations == 1
    assert summary.pending_handoffs == ()


def test_blocked_operation_is_explicitly_accounted_for(tmp_path):
    dispatcher, request, _ = build_execution_env(tmp_path)
    journal = dispatcher.admission.journal
    snapshot, _ = journal.store.load(request.scope.assessment_id)
    blocked = snapshot.operations[0].model_copy(update={"status": "blocked"})
    with journal.store._connect() as db:
        db.execute(
            "UPDATE red_operations SET payload=? WHERE assessment_id=? AND operation_id=?",
            (blocked.model_dump_json(), request.scope.assessment_id, blocked.operation_id),
        )

    summary = RedAssessmentSummarizer(journal).summarize(
        scope=request.scope, operations=(blocked,), receipts=(), findings=(),
    )

    assert summary.status == "completed_with_limitations"
    assert summary.coverage.blocked == 1
    assert summary.coverage.skipped == 0


def test_summary_rejects_an_omitted_persisted_operation(tmp_path):
    dispatcher, request, _ = build_execution_env(tmp_path)
    journal = dispatcher.admission.journal

    with pytest.raises(ValueError, match="complete persisted operation"):
        RedAssessmentSummarizer(journal).summarize(
            scope=request.scope, operations=(), receipts=(), findings=(),
        )


def test_mixed_confirmed_suspected_and_failed_results_remain_limited(tmp_path):
    dispatcher, request, _ = build_execution_env(tmp_path)
    journal = dispatcher.admission.journal
    recorder = RedEvidenceRecorder(journal)
    result = dispatcher.executor.execute_registered_test(
        test_id="xss-reflection-001", attempt_number=1, run_id="run-mixed"
    )
    controlled = recorder.record_controlled(
        scope=request.scope, operation_id=request.operation_id,
        plan_version=request.plan_version,
        target_revision=request.scope.target_fingerprint, result=result,
        recorded_at=datetime(2026, 10, 28, 14, tzinfo=UTC),
    )
    zap = recorder.record_zap(
        observation=ZapTargetedObservation(
            scope=request.scope, test_id="xss-reflection-001", scanner_id="40012",
            endpoint_id="scenario-xss-search", status="suspected", confirmed=False,
            request_count=2, duration_seconds=1, alert_count=1,
        ),
        operation_id=request.operation_id, plan_version=request.plan_version,
        target_revision=request.scope.target_fingerprint,
        recorded_at=datetime(2026, 10, 28, 14, 1, tzinfo=UTC),
    )
    failed = recorder.record_partial(
        scope=request.scope, operation_id=request.operation_id,
        plan_version=request.plan_version, test_id="xss-reflection-001",
        target_revision=request.scope.target_fingerprint, status="failed",
        summary="transport-error",
        recorded_at=datetime(2026, 10, 28, 14, 2, tzinfo=UTC),
    )
    verifier = DeterministicAttackVerifier(_registry(), journal=journal)
    findings = (
        verifier.verify(controlled, result),
        verifier.verify(zap, None),
        verifier.verify(failed, None),
    )
    snapshot, _ = journal.store.load(request.scope.assessment_id)

    summary = RedAssessmentSummarizer(journal).summarize(
        scope=request.scope, operations=snapshot.operations,
        receipts=(controlled, zap, failed), findings=findings,
    )

    assert summary.status == "completed_with_limitations"
    assert summary.coverage.completed == 1
    assert summary.coverage.unresolved_observations == 2
    assert len(summary.pending_handoffs) == 1
