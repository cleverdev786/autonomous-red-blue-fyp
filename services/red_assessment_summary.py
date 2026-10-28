"""Truthful Red assessment coverage, completion, and data-only handoff (T21)."""

from __future__ import annotations

from schemas.red_team import RedScopeReference
from schemas.red_team_state import (
    CoverageDTO,
    CoverageGapDTO,
    FindingDTO,
    FindingState,
    OperationDTO,
    ReceiptDTO,
    RedAssessmentSummaryDTO,
)
from services.red_evidence_store import RedEvidenceStore


class RedAssessmentSummarizer:
    def __init__(self, journal: RedEvidenceStore) -> None:
        self.journal = journal

    def summarize(
        self,
        *,
        scope: RedScopeReference,
        operations: tuple[OperationDTO, ...],
        receipts: tuple[ReceiptDTO, ...],
        findings: tuple[FindingDTO, ...],
        coverage_gaps: tuple[CoverageGapDTO, ...] = (),
    ) -> RedAssessmentSummaryDTO:
        for group in (operations, receipts, findings, coverage_gaps):
            if any(item.scope != scope for item in group):
                raise ValueError("summary input scope mismatch")
        snapshot, _ = self.journal.store.load(scope.assessment_id)
        if operations != snapshot.operations:
            raise ValueError("summary requires the complete persisted operation set")
        if receipts != self.journal.list_receipts(scope):
            raise ValueError("summary requires the complete persisted receipt set")
        if coverage_gaps != self.journal.list_coverage_gaps(scope):
            raise ValueError("summary requires the complete persisted coverage-gap set")
        persisted_findings = self.journal.list_findings(scope)
        if any(item not in findings for item in persisted_findings):
            raise ValueError("summary cannot omit a persisted finding")
        eligible_operations = tuple(
            item
            for item in operations
            if item.test_id is not None and item.status != "proposed"
        )
        receipt_ops = {item.operation_id for item in receipts}
        terminal_finding_ops = {
            item.operation_id for item in findings
            if item.status in {FindingState.CONFIRMED, FindingState.NOT_CONFIRMED}
        }
        executed = len({item.operation_id for item in eligible_operations} & receipt_ops)
        completed = len({item.operation_id for item in eligible_operations} & terminal_finding_ops)
        blocked = sum(
            item.operation_id not in receipt_ops and item.status == "blocked"
            for item in eligible_operations
        )
        skipped = len(eligible_operations) - executed - blocked
        open_gaps = tuple(item for item in coverage_gaps if item.status.value == "open")
        explicitly_gapped = {
            item.candidate_id for item in open_gaps if item.candidate_id is not None
        }
        planned_candidates = {item.candidate_id for item in eligible_operations}
        uncovered_candidates = {
            item.candidate_id for item in snapshot.candidates
        } - planned_candidates - explicitly_gapped
        unresolved = sum(
            item.status in {FindingState.SUSPECTED, FindingState.INCONCLUSIVE}
            for item in findings
        )
        coverage = CoverageDTO(
            eligible=len(eligible_operations), executed=executed, completed=completed,
            blocked=blocked, skipped=skipped,
            observed_candidate_gaps=len(open_gaps) + len(uncovered_candidates),
            unresolved_observations=unresolved,
        )
        warnings = []
        warnings.append("unauthenticated_only_coverage")
        if any(item.reason == "unsupported_class" for item in open_gaps):
            warnings.append("unsupported_vulnerability_classes")
        if not coverage.coverage_complete:
            warnings.append("incomplete_or_uncertain_coverage")

        assessment = self.journal.finalize_assessment(scope, coverage, findings)
        handoffs = self.journal.list_pending_handoffs(scope)
        return RedAssessmentSummaryDTO(
            scope=scope,
            status=assessment.status.value,
            coverage=coverage,
            findings=findings,
            coverage_gaps=coverage_gaps,
            pending_handoffs=handoffs,
            warnings=tuple(warnings),
        )
