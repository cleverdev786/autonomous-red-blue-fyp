"""T19 normalized, immutable Red evidence receipts."""

from datetime import UTC, datetime

import pytest

from schemas.red_team import TestExecutionResult as ExecutionResult
from schemas.red_team_state import FindingDTO
from services.red_evidence_receipts import RedEvidenceRecorder
from services.red_evidence_store import EvidenceDenied
from services.zap_adapter import ZapTargetedObservation
from tests.test_red_real_execution import build_execution_env


def test_controlled_receipt_hashes_raw_result_without_persisting_response(tmp_path):
    dispatcher, request, _ = build_execution_env(tmp_path)
    result = dispatcher.executor.execute_registered_test(
        test_id="xss-reflection-001", attempt_number=1, run_id="run-t19"
    )
    recorder = RedEvidenceRecorder(dispatcher.admission.journal)

    receipt = recorder.record_controlled(
        scope=request.scope,
        operation_id=request.operation_id,
        plan_version=request.plan_version,
        target_revision=request.scope.target_fingerprint,
        result=result,
        recorded_at=datetime(2026, 10, 28, 12, tzinfo=UTC),
    )

    assert receipt.test_id == "xss-reflection-001"
    assert receipt.source == "controlled_http"
    assert receipt.recorded_at.tzinfo is not None
    assert len(receipt.raw_response_sha256) == 64
    raw = dispatcher.admission.journal.read_evidence(request.scope, receipt.evidence_id)
    assert b"fyp_xss_marker" not in raw
    assert b"body_excerpt" not in raw


def test_partial_timeout_and_cancellation_are_durable_and_redacted(tmp_path):
    dispatcher, request, _ = build_execution_env(tmp_path)
    recorder = RedEvidenceRecorder(dispatcher.admission.journal)
    timed_out = ExecutionResult(
        run_id="run-timeout", target_id="vulnerable-store",
        test_id="xss-reflection-001", attempt_number=1, request_count=0,
        completed=False, timed_out=True, duration_ms=5000,
        error_code="request-timeout",
    )
    timeout_receipt = recorder.record_controlled(
        scope=request.scope, operation_id=request.operation_id,
        plan_version=request.plan_version,
        target_revision=request.scope.target_fingerprint, result=timed_out,
        recorded_at=datetime(2026, 10, 28, 12, tzinfo=UTC),
    )
    cancelled = recorder.record_partial(
        scope=request.scope, operation_id=request.operation_id,
        plan_version=request.plan_version, test_id="xss-reflection-001",
        target_revision=request.scope.target_fingerprint, status="cancelled",
        summary="operator cancellation; Authorization: Bearer do-not-store",
        recorded_at=datetime(2026, 10, 28, 12, 1, tzinfo=UTC),
    )

    assert [item.status for item in recorder.list_receipts(request.scope)] == [
        "timeout", "cancelled"
    ]
    assert b"do-not-store" not in dispatcher.admission.journal.read_evidence(
        request.scope, cancelled.evidence_id
    )
    assert timeout_receipt.raw_response_sha256


def test_receipt_integrity_mismatch_is_detected(tmp_path):
    dispatcher, request, _ = build_execution_env(tmp_path)
    result = dispatcher.executor.execute_registered_test(
        test_id="xss-reflection-001", attempt_number=1, run_id="run-integrity"
    )
    receipt = RedEvidenceRecorder(dispatcher.admission.journal).record_controlled(
        scope=request.scope, operation_id=request.operation_id,
        plan_version=request.plan_version,
        target_revision=request.scope.target_fingerprint, result=result,
        recorded_at=datetime(2026, 10, 28, 12, tzinfo=UTC),
    )
    changed = result.model_copy(update={"duration_ms": result.duration_ms + 1})

    with pytest.raises(EvidenceDenied, match="integrity"):
        RedEvidenceRecorder.verify_result_integrity(receipt, changed)


def test_zap_observation_remains_a_separate_non_confirming_source(tmp_path):
    dispatcher, request, _ = build_execution_env(tmp_path)
    observation = ZapTargetedObservation(
        scope=request.scope, test_id="xss-reflection-001", scanner_id="40012",
        endpoint_id="scenario-xss-search", status="suspected", confirmed=False,
        request_count=2, duration_seconds=1, alert_count=1,
    )
    receipt = RedEvidenceRecorder(dispatcher.admission.journal).record_zap(
        observation=observation, operation_id=request.operation_id,
        plan_version=request.plan_version,
        target_revision=request.scope.target_fingerprint,
        recorded_at=datetime(2026, 10, 28, 12, tzinfo=UTC),
    )

    assert receipt.source == "zap"
    assert receipt.status == "completed"

    forged = FindingDTO(
        scope=request.scope, finding_id="finding-forged-zap",
        operation_id=request.operation_id, status="confirmed",
        oracle_id="unescaped-reflection-evidence-001",
        evidence_receipt_ids=(receipt.receipt_id,), severity="medium",
        category="xss", route="/scenarios/xss/search",
        provenance="controlled_http", reproduction_scope="registered_local_lab",
        evidence_id=receipt.evidence_id,
    )
    with pytest.raises(EvidenceDenied, match="controlled receipt"):
        dispatcher.admission.journal._record_verified_finding(forged)


def test_receipt_and_artifact_commit_atomically_on_file_conflict(tmp_path):
    dispatcher, request, _ = build_execution_env(tmp_path)
    result = dispatcher.executor.execute_registered_test(
        test_id="xss-reflection-001", attempt_number=1, run_id="run-atomic"
    )
    recorder = RedEvidenceRecorder(dispatcher.admission.journal)
    recorded_at = datetime(2026, 10, 28, 15, tzinfo=UTC)
    receipt = recorder.record_controlled(
        scope=request.scope, operation_id=request.operation_id,
        plan_version=request.plan_version,
        target_revision=request.scope.target_fingerprint, result=result,
        recorded_at=recorded_at,
    )
    assert recorder.list_receipts(request.scope) == (receipt,)

    with pytest.raises(EvidenceDenied):
        recorder.record_controlled(
            scope=request.scope, operation_id=request.operation_id,
            plan_version=request.plan_version,
            target_revision=request.scope.target_fingerprint, result=result,
            recorded_at=recorded_at,
        )
    assert recorder.list_receipts(request.scope) == (receipt,)
