"""Interpret registered controlled-executor results for Blue verification."""

from __future__ import annotations

from schemas.red_team import TestExecutionResult
from schemas.verification import VerificationStageResult


def security_stage_result(*, stage_id: str, execution: TestExecutionResult) -> VerificationStageResult:
    """Pass only when execution completed and exploit evidence is absent."""
    passed = execution.completed and not execution.timed_out and not execution.evidence
    if passed:
        details = f"Registered test {execution.test_id!r} completed with no exploit evidence."
    elif execution.evidence:
        details = f"Registered test {execution.test_id!r} still produced exploit evidence."
    elif execution.error_code:
        details = (
            f"Registered test {execution.test_id!r} did not complete cleanly: "
            f"{execution.error_code}."
        )
    else:
        details = f"Registered test {execution.test_id!r} did not complete cleanly."
    return VerificationStageResult(
        stage_id=stage_id,
        required=True,
        passed=passed,
        duration_ms=execution.duration_ms,
        details=details,
        test_execution=execution,
    )
