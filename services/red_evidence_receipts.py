"""Normalize actual Red observations into secret-free immutable receipts (T19)."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime

from schemas.red_team import RedScopeReference, TestExecutionResult
from schemas.red_team_state import ReceiptDTO, ReceiptExchangeDTO
from services.red_evidence_store import EvidenceDenied, RedEvidenceStore
from services.zap_adapter import ZapTargetedObservation

_MAX_RAW_RESULT = 16_384


def _canonical_result(result: TestExecutionResult) -> bytes:
    raw = json.dumps(
        result.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if len(raw) > _MAX_RAW_RESULT:
        raise EvidenceDenied("bounded raw response exceeds size limit")
    return raw


class RedEvidenceRecorder:
    """Write provenance and hashes, never response bodies or request secrets."""

    def __init__(self, journal: RedEvidenceStore) -> None:
        self.journal = journal

    def record_controlled(
        self,
        *,
        scope: RedScopeReference,
        operation_id: str,
        plan_version: str,
        target_revision: str,
        result: TestExecutionResult,
        recorded_at: datetime,
    ) -> ReceiptDTO:
        raw = _canonical_result(result)
        status = (
            "cancelled"
            if result.error_code == "cancellation-requested"
            else "timeout" if result.timed_out
            else "completed" if result.completed else "failed"
        )
        exchanges = tuple(
            ReceiptExchangeDTO(
                step_id=item.step_id,
                endpoint_id=item.endpoint_id,
                method=item.method,
                status_code=item.status_code,
                body_sha256=hashlib.sha256(item.body_excerpt.encode()).hexdigest(),
                body_length=len(item.body_excerpt),
            )
            for item in result.exchanges
        )
        return self._record(
            scope=scope,
            operation_id=operation_id,
            plan_version=plan_version,
            test_id=result.test_id,
            run_id=result.run_id,
            target_revision=target_revision,
            recorded_at=recorded_at,
            source="controlled_http",
            status=status,
            request_count=result.request_count,
            exchanges=exchanges,
            raw_response_sha256=hashlib.sha256(raw).hexdigest(),
            summary=result.error_code or status,
        )

    def record_partial(
        self,
        *,
        scope: RedScopeReference,
        operation_id: str,
        plan_version: str,
        test_id: str,
        target_revision: str,
        status: str,
        summary: str,
        recorded_at: datetime,
    ) -> ReceiptDTO:
        if status not in {"failed", "blocked", "cancelled", "timeout"}:
            raise EvidenceDenied("partial receipt requires a non-success status")
        bounded = summary[:100].encode("utf-8")
        return self._record(
            scope=scope,
            operation_id=operation_id,
            plan_version=plan_version,
            test_id=test_id,
            run_id=f"partial-{hashlib.sha256(summary.encode()).hexdigest()[:16]}",
            target_revision=target_revision,
            recorded_at=recorded_at,
            source="controlled_http",
            status=status,
            request_count=0,
            exchanges=(),
            raw_response_sha256=hashlib.sha256(bounded).hexdigest(),
            summary=status,
        )

    def record_zap(
        self,
        *,
        observation: ZapTargetedObservation,
        operation_id: str,
        plan_version: str,
        target_revision: str,
        recorded_at: datetime,
    ) -> ReceiptDTO:
        raw = json.dumps(
            observation.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return self._record(
            scope=observation.scope,
            operation_id=operation_id,
            plan_version=plan_version,
            test_id=observation.test_id,
            run_id=(
                f"zap-{hashlib.sha256(observation.model_dump_json().encode()).hexdigest()[:16]}"
            ),
            target_revision=target_revision,
            recorded_at=recorded_at,
            source="zap",
            observation_status=observation.status,
            status="completed",
            request_count=observation.request_count,
            exchanges=(),
            raw_response_sha256=hashlib.sha256(raw).hexdigest(),
            summary=observation.status,
        )

    def _record(
        self,
        *,
        scope: RedScopeReference,
        operation_id: str,
        plan_version: str,
        test_id: str,
        run_id: str,
        target_revision: str,
        recorded_at: datetime,
        source: str,
        observation_status: str | None = None,
        status: str,
        request_count: int,
        exchanges: tuple[ReceiptExchangeDTO, ...],
        raw_response_sha256: str,
        summary: str,
    ) -> ReceiptDTO:
        material = (
            f"{scope.authorization_fingerprint}:{operation_id}:{plan_version}:"
            f"{test_id}:{source}:{recorded_at.isoformat()}:{raw_response_sha256}"
        ).encode()
        suffix = hashlib.sha256(material).hexdigest()[:24]
        receipt = ReceiptDTO(
            scope=scope,
            receipt_id=f"receipt-{suffix}",
            operation_id=operation_id,
            plan_version=plan_version,
            test_id=test_id,
            run_id=run_id,
            target_revision=target_revision,
            recorded_at=recorded_at,
            source=source,
            observation_status=observation_status,
            status=status,
            request_count=request_count,
            exchanges=exchanges,
            raw_response_sha256=raw_response_sha256,
            evidence_id=f"evidence-{suffix}",
        )
        self.journal.add_receipt_with_evidence(
            receipt,
            data={
                "operation_id": operation_id,
                "test_id": test_id,
                "status": status,
                "reason_code": summary,
            },
        )
        return receipt

    def list_receipts(self, scope: RedScopeReference) -> tuple[ReceiptDTO, ...]:
        return self.journal.list_receipts(scope)

    @staticmethod
    def verify_result_integrity(
        receipt: ReceiptDTO, result: TestExecutionResult
    ) -> None:
        actual = hashlib.sha256(_canonical_result(result)).hexdigest()
        if actual != receipt.raw_response_sha256:
            raise EvidenceDenied("receipt integrity verification failed")
        if receipt.test_id != result.test_id or receipt.scope.target_id != result.target_id:
            raise EvidenceDenied("receipt result identity mismatch")
