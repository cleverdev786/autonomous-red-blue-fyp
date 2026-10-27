"""Red v1 typed stage contract validation; no provider or execution dispatch."""

from __future__ import annotations

from schemas.red_team import (
    ExecutionWork,
    ExecutionWorkResult,
    PlanningWork,
    PlanningWorkResult,
    ReconnaissanceWork,
    ReconnaissanceWorkResult,
    VerificationWork,
    VerificationWorkResult,
)

RedWork = ReconnaissanceWork | PlanningWork | ExecutionWork | VerificationWork
RedWorkResult = (
    ReconnaissanceWorkResult
    | PlanningWorkResult
    | ExecutionWorkResult
    | VerificationWorkResult
)


def validate_worker_result(task: RedWork, result: RedWorkResult) -> RedWorkResult:
    """Validate stage identity and scope references; policy admission is separate."""

    pairs = {
        ReconnaissanceWork: ReconnaissanceWorkResult,
        PlanningWork: PlanningWorkResult,
        ExecutionWork: ExecutionWorkResult,
        VerificationWork: VerificationWorkResult,
    }
    expected = pairs.get(type(task))
    if expected is None or type(result) is not expected:
        raise ValueError("worker stage/result mismatch")
    if result.scope != task.scope:
        raise ValueError("worker scope differs from authorized task reference")
    if isinstance(task, (ExecutionWork, VerificationWork)):
        if task.plan_version != result.plan_version:
            raise ValueError("worker plan version mismatch")
        if task.operation_id != result.operation_id:
            raise ValueError("worker operation reference mismatch")
    if isinstance(task, VerificationWork) and not set(
        result.evidence_receipt_ids
    ).issubset(task.receipt_ids):
        raise ValueError("verification references a receipt outside its task")
    return result
