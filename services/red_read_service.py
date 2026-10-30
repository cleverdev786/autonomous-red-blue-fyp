"""Read-only projections for the Red dashboard and assessment workspaces."""

from __future__ import annotations

from schemas.red_team import RedStandardBudget
from schemas.red_team_state import (
    AssessmentState,
    FindingDTO,
    FindingState,
    GapState,
    RedAssessmentDetailDTO,
    RedAssessmentListItemDTO,
    RedAssessmentPageDTO,
    RedAssessmentWorkspaceDTO,
    RedCoverageReadDTO,
    RedDashboardSummaryDTO,
    RedEventPageDTO,
    RedEventReadDTO,
    RedEvidenceMetadataReadDTO,
    RedFindingDetailDTO,
    RedFindingPageDTO,
    RedFindingReadDTO,
    RedOperationReadDTO,
    RedPaginationDTO,
    RedTargetPageDTO,
    RedTargetReadDTO,
    StageDTO,
    StageState,
)
from services.red_assessment_store import RedAssessmentStore
from services.red_evidence_store import RedEvidenceStore
from services.target_registry import TargetRegistry


class RedReadNotFound(LookupError):
    """A requested Red read resource does not exist in the authorized store."""


class RedReadConflict(ValueError):
    """A supposedly global identifier is ambiguous across assessment scopes."""


class RedReadService:
    """Build API DTOs from validated persisted state without dispatch authority."""

    def __init__(
        self,
        store: RedAssessmentStore,
        registry: TargetRegistry,
        standard_budget: RedStandardBudget,
    ) -> None:
        if not store.read_only:
            raise ValueError("Red dashboard reads require a read-only store")
        self.store = store
        self.registry = registry
        self.standard_budget = standard_budget
        self.journal = RedEvidenceStore(
            store,
            store.path.with_name(store.path.name + ".evidence"),
        )

    def targets(self, *, offset: int, limit: int) -> RedTargetPageDTO:
        targets = self.registry.list_targets()
        items = tuple(
            RedTargetReadDTO(
                target_id=target.target_id,
                supported_classes=tuple(sorted({
                    self.registry.get_security_test(test_id).vulnerability_class.value
                    for test_id in target.allowed_test_ids
                })),
                standard_budget=self.standard_budget,
            )
            for target in targets[offset:offset + limit]
        )
        return RedTargetPageDTO(
            items=items,
            pagination=RedPaginationDTO(
                offset=offset,
                limit=limit,
                total=len(targets),
            ),
        )

    def assessments(
        self,
        *,
        target_id: str | None,
        status: str | None = None,
        offset: int,
        limit: int,
    ) -> RedAssessmentPageDTO:
        if target_id is not None:
            self.registry.get_target(target_id)
        snapshots, total = self.store.list_assessments(
            target_id=target_id,
            status=status,
            offset=offset,
            limit=limit,
        )
        return RedAssessmentPageDTO(
            items=tuple(self._assessment_item(snapshot) for snapshot in snapshots),
            pagination=RedPaginationDTO(offset=offset, limit=limit, total=total),
        )

    def workspace(self, assessment_id: str) -> RedAssessmentWorkspaceDTO:
        snapshot, _ = self.store.load(assessment_id)
        stages = self._projected_stages(snapshot)
        findings = self.journal.list_findings(snapshot.assessment.scope)
        gaps = self.journal.list_coverage_gaps(snapshot.assessment.scope)
        counts = {state: 0 for state in FindingState}
        for finding in findings:
            counts[finding.status] += 1
        return RedAssessmentWorkspaceDTO(
            assessment=self._assessment_item(snapshot, stages=stages),
            stages=stages,
            plans=snapshot.plans,
            operations=tuple(RedOperationReadDTO(
                operation_id=item.operation_id, plan_version=item.plan_version,
                test_id=item.test_id, status=item.status,
            ) for item in snapshot.operations),
            candidate_count=len(snapshot.candidates),
            planned_operation_count=len(snapshot.operations),
            finding_counts=counts,
            coverage_gap_count=sum(gap.status == GapState.OPEN for gap in gaps),
        )

    def events(
        self,
        assessment_id: str,
        *,
        offset: int,
        limit: int,
    ) -> RedEventPageDTO:
        snapshot, _ = self.store.load(assessment_id)
        rows = self.journal.list_events(snapshot.assessment.scope)
        major_actions = {
            "assessment-authorization",
            "assessment-cancellation",
            "stage-transition",
            "recon_started",
            "recon_completed",
        }
        events = []
        for row in rows:
            if row["action"] not in major_actions:
                continue
            stage = row["details"].get("stage")
            if stage not in {
                "reconnaissance", "planning", "execution", "verification",
            }:
                stage = None
            events.append(RedEventReadDTO(
                event_id=row["event_id"],
                action=row["action"],
                status=row["outcome"],
                stage=stage,
                occurred_at=row["occurred_at"],
            ))
        return RedEventPageDTO(
            items=tuple(events[offset:offset + limit]),
            pagination=RedPaginationDTO(
                offset=offset,
                limit=limit,
                total=len(events),
            ),
        )

    def findings(
        self,
        assessment_id: str,
        *,
        status: str | None,
        category: str | None,
        severity: str | None,
        offset: int,
        limit: int,
    ) -> RedFindingPageDTO:
        self.store.load(assessment_id)
        findings, total = self.journal.list_findings_page(
            assessment_id=assessment_id,
            status=status,
            category=category,
            severity=severity,
            offset=offset,
            limit=limit,
        )
        return RedFindingPageDTO(
            items=tuple(self._finding_item(item) for item in findings),
            pagination=RedPaginationDTO(
                offset=offset,
                limit=limit,
                total=total,
            ),
            coverage_gap_count=self.journal.count_open_coverage_gaps(
                assessment_id=assessment_id,
            ),
        )

    def all_findings(
        self,
        *,
        target_id: str | None,
        status: str | None,
        category: str | None,
        severity: str | None,
        offset: int,
        limit: int,
    ) -> RedFindingPageDTO:
        if target_id is not None:
            self.registry.get_target(target_id)
        findings, total = self.journal.list_findings_page(
            target_id=target_id,
            status=status,
            category=category,
            severity=severity,
            offset=offset,
            limit=limit,
        )
        return RedFindingPageDTO(
            items=tuple(self._finding_item(finding) for finding in findings),
            pagination=RedPaginationDTO(
                offset=offset,
                limit=limit,
                total=total,
            ),
            coverage_gap_count=self.journal.count_open_coverage_gaps(
                target_id=target_id,
            ),
        )

    def finding_detail(self, finding_id: str) -> RedFindingDetailDTO:
        snapshots, _ = self.store.list_assessments(offset=0, limit=None)
        matches: list[tuple[RedAssessmentDetailDTO, FindingDTO]] = []
        for snapshot in snapshots:
            matches.extend(
                (snapshot, finding)
                for finding in self.journal.list_findings(snapshot.assessment.scope)
                if finding.finding_id == finding_id
            )
        if not matches:
            raise RedReadNotFound("finding not found")
        if len(matches) != 1:
            raise RedReadConflict("finding identifier is ambiguous")
        snapshot, finding = matches[0]
        operation = next(
            (
                item
                for item in snapshot.operations
                if item.operation_id == finding.operation_id
            ),
            None,
        )
        if operation is None:
            raise ValueError("finding references an unavailable operation")
        evidence = tuple(
            RedEvidenceMetadataReadDTO(
                evidence_id=artifact.evidence_id,
                receipt_id=artifact.receipt_id,
                operation_id=artifact.operation_id,
                sha256=artifact.sha256,
                content_type=artifact.content_type,
            )
            for artifact in self.journal.list_evidence(finding.scope)
            if (
                artifact.evidence_id == finding.evidence_id
                or artifact.receipt_id in finding.evidence_receipt_ids
            )
        )
        return RedFindingDetailDTO(
            finding=self._finding_item(finding),
            operation_id=finding.operation_id,
            plan_version=operation.plan_version,
            test_id=operation.test_id,
            oracle_id=finding.oracle_id,
            evidence_receipt_ids=finding.evidence_receipt_ids,
            evidence=evidence,
        )

    def coverage(self, assessment_id: str) -> RedCoverageReadDTO:
        snapshot, _ = self.store.load(assessment_id)
        assessment = snapshot.assessment
        gaps = self.journal.list_coverage_gaps(assessment.scope)
        warnings = ["unauthenticated_only_coverage"]
        if any(gap.reason == "unsupported_class" for gap in gaps):
            warnings.append("unsupported_vulnerability_classes")
        if not assessment.coverage.coverage_complete:
            warnings.append("incomplete_or_uncertain_coverage")
        return RedCoverageReadDTO(
            assessment_id=assessment.scope.assessment_id,
            target_id=assessment.scope.target_id,
            coverage=assessment.coverage,
            gaps=gaps,
            warnings=tuple(warnings),
        )

    def summary(
        self,
        *,
        target_id: str | None,
        status: str | None = None,
    ) -> RedDashboardSummaryDTO:
        if target_id is not None:
            self.registry.get_target(target_id)
        snapshots, total = self.store.list_assessments(
            target_id=target_id,
            status=status,
            offset=0,
            limit=None,
        )
        findings = tuple(
            finding
            for snapshot in snapshots
            for finding in self.journal.list_findings(snapshot.assessment.scope)
        )
        gaps = tuple(
            gap
            for snapshot in snapshots
            for gap in self.journal.list_coverage_gaps(snapshot.assessment.scope)
        )
        return RedDashboardSummaryDTO(
            target_id=target_id,
            assessment_count=total,
            confirmed_findings=sum(
                finding.status == FindingState.CONFIRMED for finding in findings
            ),
            suspected_findings=sum(
                finding.status == FindingState.SUSPECTED for finding in findings
            ),
            tested=sum(snapshot.assessment.coverage.executed for snapshot in snapshots),
            eligible=sum(snapshot.assessment.coverage.eligible for snapshot in snapshots),
            active_assessments=sum(
                snapshot.assessment.status in {
                    AssessmentState.QUEUED,
                    AssessmentState.RUNNING,
                }
                for snapshot in snapshots
            ),
            queued_assessments=sum(
                snapshot.assessment.status == AssessmentState.QUEUED
                for snapshot in snapshots
            ),
            active_stages=sum(
                stage.status in {StageState.QUEUED, StageState.RUNNING}
                for snapshot in snapshots
                for stage in self._projected_stages(snapshot)
            ),
            coverage_gaps=sum(gap.status == GapState.OPEN for gap in gaps),
        )

    def _assessment_item(
        self,
        snapshot: RedAssessmentDetailDTO,
        *,
        stages: tuple[StageDTO, ...] | None = None,
    ) -> RedAssessmentListItemDTO:
        assessment = snapshot.assessment
        current_plan = next(
            (plan for plan in reversed(snapshot.plans) if plan.status != "stale"),
            None,
        )
        current_surface = snapshot.surfaces[-1] if snapshot.surfaces else None
        return RedAssessmentListItemDTO(
            assessment_id=assessment.scope.assessment_id,
            target_id=assessment.scope.target_id,
            mode=assessment.mode,
            profile=assessment.profile,
            status=assessment.status,
            workflow_complete=assessment.workflow_complete,
            coverage=assessment.coverage,
            current_plan_version=(
                current_plan.plan_version if current_plan is not None else None
            ),
            current_surface_revision=(
                current_surface.surface_revision if current_surface is not None else None
            ),
            stage_statuses={
                stage.stage: stage.status
                for stage in stages or self._projected_stages(snapshot)
            },
        )

    def _projected_stages(
        self,
        snapshot: RedAssessmentDetailDTO,
    ) -> tuple[StageDTO, ...]:
        """Overlay durable active queue state without mutating the read model."""
        projected = {stage.stage: stage for stage in snapshot.stages}
        with self.store._connect() as db:
            table = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='red_queue_jobs'"
            ).fetchone()
            if table is None:
                return snapshot.stages
            rows = db.execute(
                """SELECT stage,status FROM red_queue_jobs
                   WHERE assessment_id=? AND status IN ('queued','running')
                   ORDER BY sequence""",
                (snapshot.assessment.scope.assessment_id,),
            ).fetchall()
        for row in rows:
            stage = row["stage"]
            status = StageState(row["status"])
            current = projected.get(stage)
            projected[stage] = (
                current.model_copy(update={"status": status})
                if current is not None else StageDTO(
                    scope=snapshot.assessment.scope,
                    stage=stage,
                    status=status,
                )
            )
        order = {stage: index for index, stage in enumerate(
            ("reconnaissance", "planning", "execution", "verification")
        )}
        return tuple(sorted(projected.values(), key=lambda item: order[item.stage]))

    @staticmethod
    def _finding_item(finding: FindingDTO) -> RedFindingReadDTO:
        return RedFindingReadDTO(
            finding_id=finding.finding_id,
            assessment_id=finding.scope.assessment_id,
            target_id=finding.scope.target_id,
            status=finding.status,
            severity=finding.severity,
            category=finding.category,
            route=finding.route,
            provenance=finding.provenance,
            reproduction_scope=finding.reproduction_scope,
            has_evidence=finding.evidence_id is not None,
        )
