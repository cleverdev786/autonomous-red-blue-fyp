"""Fail-closed recovery of abandoned Red queue leases (T24)."""

from __future__ import annotations

from datetime import datetime
from hashlib import sha256

from schemas.red_queue import QueueJobDTO
from schemas.red_team import ExecutionWork, RedScopeReference
from schemas.red_team_state import FindingDTO, FindingState, StageState
from services.red_assessment_queue import RedAssessmentQueue
from services.red_evidence_receipts import RedEvidenceRecorder
from services.red_evidence_store import RedEvidenceStore


class RedAssessmentRecovery:
    """Reconcile durable output after a crash; never guess by replaying work."""

    def __init__(
        self,
        *,
        queue: RedAssessmentQueue,
        journal: RedEvidenceStore,
    ) -> None:
        if queue.store.path.resolve() != journal.store.path.resolve():
            raise ValueError("queue and recovery journal must share one database")
        self.queue = queue
        self.journal = journal
        self.recorder = RedEvidenceRecorder(journal)

    def recover(
        self,
        scope: RedScopeReference,
        *,
        recovered_at: datetime,
    ) -> tuple[QueueJobDTO, ...]:
        """Resolve abandoned leases using receipts, otherwise mark uncertainty."""
        recovered = []
        for job in self.queue.list_jobs(scope):
            if job.status != "running":
                continue
            cancellation = job.cancellation_requested_at is not None
            completed = False
            if isinstance(job.work, ExecutionWork):
                receipts = tuple(
                    receipt
                    for receipt in self.journal.list_receipts(scope)
                    if receipt.operation_id == job.work.operation_id
                    and job.claimed_at is not None
                    and receipt.recorded_at >= job.claimed_at
                )
                completed = any(receipt.status == "completed" for receipt in receipts)
                if not completed:
                    receipt = (
                        receipts[-1]
                        if receipts
                        else self.recorder.record_partial(
                            scope=scope,
                            operation_id=job.work.operation_id,
                            plan_version=job.work.plan_version,
                            test_id=self._test_id(job.work),
                            target_revision=scope.target_fingerprint,
                            status="cancelled" if cancellation else "failed",
                            summary="interrupted operation outcome unknown",
                            recorded_at=recovered_at,
                        )
                    )
                    finding = FindingDTO(
                        scope=scope,
                        finding_id="finding-" + sha256(
                            f"recovery:{receipt.receipt_id}".encode()
                        ).hexdigest()[:24],
                        operation_id=job.work.operation_id,
                        status=FindingState.INCONCLUSIVE,
                        evidence_receipt_ids=(receipt.receipt_id,),
                    )
                    self.journal._record_verified_finding(finding)
            status = (
                "completed" if completed
                else "cancelled" if cancellation else "failed"
            )
            stage_status = (
                StageState.SUCCEEDED if completed
                else StageState.CANCELLED if cancellation else StageState.FAILED
            )
            recovered.append(self.queue.recover_job(
                job_id=job.job_id,
                status=status,
                stage_status=stage_status,
                recovered_at=recovered_at,
            ))
        return tuple(recovered)

    def _test_id(self, work: ExecutionWork) -> str:
        snapshot, _ = self.queue.store.load(work.scope.assessment_id)
        operation = next(
            item for item in snapshot.operations
            if item.operation_id == work.operation_id
        )
        if operation.test_id is None:
            raise ValueError("execution recovery requires a registered test")
        return operation.test_id
