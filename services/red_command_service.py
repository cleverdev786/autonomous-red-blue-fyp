"""Trusted server-side construction for authenticated Red operator commands."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from agents.red.contracts import RedWork
from orchestrator.policy_engine import StandardRedPolicy
from orchestrator.red_team_flow import RedQueuedStageRunner, RedStageCoordinator
from schemas.red_queue import QueueResourceDTO
from schemas.red_team import (
    ExecutionWork,
    PlanningWork,
    ReconnaissanceWork,
    VerificationWork,
)
from schemas.red_team_state import (
    AssessmentDTO,
    AssessmentState,
    CoverageDTO,
    RedAssessmentDetailDTO,
    RedCommandReceiptDTO,
)
from services.red_assessment_queue import RedAssessmentQueue
from services.red_assessment_store import RedAssessmentStore, StoreConflict
from services.red_assessment_supervisor import (
    RedAssessmentSupervisor,
    RedDispatchDenied,
)
from services.red_evidence_store import RedEvidenceStore
from services.target_registry import TargetRegistry


def _api_never_runs_workers(_task: RedWork):
    raise RuntimeError("operator API only queues work")


class RedCommandService:
    """Translate bounded commands into trusted policy, scope, task and resource DTOs."""

    def __init__(
        self,
        *,
        state_db: Path,
        registry: TargetRegistry,
        budget_file: Path,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.state_db = Path(state_db)
        self.registry = registry
        self.policy = StandardRedPolicy(registry=registry, budget_file=budget_file)
        self.clock = clock

    def create(
        self,
        *,
        request_id: str,
        target_id: str,
        mode: str,
        approval_id: str,
    ) -> RedCommandReceiptDTO:
        assessment_id = "assessment-" + sha256(request_id.encode()).hexdigest()[:24]
        authorization = self.policy.freeze(
            assessment_id=assessment_id,
            approval_id=approval_id,
            target_id=target_id,
        )
        assessment = AssessmentDTO(
            scope=authorization.scope,
            mode=mode,
            status=AssessmentState.AWAITING_AUTHORIZATION,
            workflow_complete=False,
            coverage=CoverageDTO(),
        )
        store = RedAssessmentStore(self.state_db)
        RedEvidenceStore(store, self.state_db.with_name(
            self.state_db.name + ".evidence"
        ))
        stored_id = store.create(
            assessment,
            authorization,
            request_id=request_id,
        )
        return RedCommandReceiptDTO(
            assessment_id=stored_id,
            request_id=request_id,
            status="awaiting_authorization",
        )

    def authorize(
        self,
        assessment_id: str,
        *,
        request_id: str,
        approval_id: str,
    ) -> RedCommandReceiptDTO:
        snapshot, _ = self._load(assessment_id)
        self._supervisor().authorize(
            snapshot.assessment.scope,
            approval_id=approval_id,
            command_id=request_id,
            authorized_at=self.clock(),
        )
        return RedCommandReceiptDTO(
            assessment_id=assessment_id,
            request_id=request_id,
            status="queued",
        )

    def start(self, assessment_id: str, *, request_id: str) -> RedCommandReceiptDTO:
        snapshot, _ = self._load(assessment_id)
        if snapshot.assessment.mode != "autonomous":
            raise RedDispatchDenied("assessment mode is immutable")
        task = self._reconnaissance(snapshot)
        job = self._supervisor().enqueue_autonomous_start(
            task,
            command_id=request_id,
            resource=QueueResourceDTO(resource_class="light"),
            enqueued_at=self.clock(),
        )
        return RedCommandReceiptDTO(
            assessment_id=assessment_id,
            request_id=request_id,
            status="queued",
            job_ids=(job.job_id,),
        )

    def run_stage(
        self,
        assessment_id: str,
        stage: str,
        *,
        request_id: str,
        operation_id: str | None,
    ) -> RedCommandReceiptDTO:
        snapshot, _ = self._load(assessment_id)
        if snapshot.assessment.mode != "manual":
            raise RedDispatchDenied("assessment mode is immutable")
        task, resource = self._stage_task(snapshot, stage, operation_id)
        job = self._supervisor().enqueue_manual(
            task,
            command_id=request_id,
            resource=resource,
            enqueued_at=self.clock(),
        )
        return RedCommandReceiptDTO(
            assessment_id=assessment_id,
            request_id=request_id,
            status="queued",
            job_ids=(job.job_id,),
        )

    def cancel(self, assessment_id: str, *, request_id: str) -> RedCommandReceiptDTO:
        snapshot, _ = self._load(assessment_id)
        supervisor = self._supervisor()
        if snapshot.assessment.status in {
            AssessmentState.AWAITING_AUTHORIZATION,
            AssessmentState.CANCELLED,
        }:
            jobs = supervisor.queue.request_cancellation(
                snapshot.assessment.scope,
                cancellation_id=request_id,
                requested_at=self.clock(),
            )
        else:
            jobs = supervisor.cancel(
                snapshot.assessment.scope,
                cancellation_id=request_id,
                requested_at=self.clock(),
            )
        updated, _ = self._load(assessment_id)
        status = (
            "cancelled"
            if updated.assessment.status == AssessmentState.CANCELLED
            else "cancellation_requested"
        )
        return RedCommandReceiptDTO(
            assessment_id=assessment_id,
            request_id=request_id,
            status=status,
            job_ids=tuple(job.job_id for job in jobs),
        )

    def _load(self, assessment_id: str):
        if not self.state_db.is_file():
            raise StoreConflict("unknown assessment")
        return RedAssessmentStore(self.state_db).load(assessment_id)

    def _supervisor(self) -> RedAssessmentSupervisor:
        store = RedAssessmentStore(self.state_db)
        journal = RedEvidenceStore(store, self.state_db.with_name(
            self.state_db.name + ".evidence"
        ))
        queue = RedAssessmentQueue(store)
        coordinator = RedStageCoordinator(
            journal=journal,
            workers={
                stage: _api_never_runs_workers
                for stage in ("reconnaissance", "planning", "execution", "verification")
            },
            clock=self.clock,
        )
        return RedAssessmentSupervisor(
            queue=queue,
            registry=self.registry,
            runner=RedQueuedStageRunner(
                queue=queue,
                coordinator=coordinator,
                clock=self.clock,
            ),
        )

    def _reconnaissance(self, snapshot: RedAssessmentDetailDTO) -> ReconnaissanceWork:
        target = self.registry.get_target(snapshot.assessment.scope.target_id)
        return ReconnaissanceWork(
            scope=snapshot.assessment.scope,
            authorized_seed_endpoint_ids=tuple(
                endpoint.endpoint_id for endpoint in target.endpoints
            ),
        )

    def _stage_task(
        self,
        snapshot: RedAssessmentDetailDTO,
        stage: str,
        operation_id: str | None,
    ) -> tuple[RedWork, QueueResourceDTO]:
        if stage == "reconnaissance":
            if operation_id is not None:
                raise RedDispatchDenied("reconnaissance does not accept an operation")
            return self._reconnaissance(snapshot), QueueResourceDTO(resource_class="light")
        if stage == "planning":
            if operation_id is not None or not snapshot.surfaces:
                raise RedDispatchDenied("planning requires the current reconnaissance surface")
            surface = snapshot.surfaces[-1]
            candidates = {item.candidate_id: item for item in snapshot.candidates}
            target = self.registry.get_target(snapshot.assessment.scope.target_id)
            return PlanningWork(
                scope=snapshot.assessment.scope,
                surface_revision=surface.surface_revision,
                candidates=tuple(candidates[item] for item in surface.candidate_ids),
                vetted_test_ids=target.allowed_test_ids,
            ), QueueResourceDTO(resource_class="light")
        operation = self._operation(snapshot, operation_id)
        if stage == "execution":
            test = self.registry.get_security_test(operation.test_id)
            return ExecutionWork(
                scope=snapshot.assessment.scope,
                plan_version=operation.plan_version,
                operation_id=operation.operation_id,
            ), QueueResourceDTO(
                resource_class="docker",
                requests=test.max_requests,
                runtime_seconds=test.timeout_seconds,
                cpu_cores=0.5,
                memory_mb=512,
            )
        if stage == "verification":
            journal = RedEvidenceStore(
                RedAssessmentStore(self.state_db),
                self.state_db.with_name(self.state_db.name + ".evidence"),
            )
            receipts = tuple(
                item.receipt_id
                for item in journal.list_receipts(snapshot.assessment.scope)
                if item.operation_id == operation.operation_id
            )
            if not receipts:
                raise RedDispatchDenied(
                    "verification requires persisted receipts for its operation"
                )
            test = self.registry.get_security_test(operation.test_id)
            return VerificationWork(
                scope=snapshot.assessment.scope,
                plan_version=operation.plan_version,
                operation_id=operation.operation_id,
                receipt_ids=receipts,
                oracle_id=test.success_evidence_rule_id,
            ), QueueResourceDTO(resource_class="light")
        raise RedDispatchDenied("unknown Red stage")

    @staticmethod
    def _operation(snapshot: RedAssessmentDetailDTO, operation_id: str | None):
        active_plan = next(
            (item for item in reversed(snapshot.plans) if item.status == "approved"),
            None,
        )
        operations = tuple(
            item for item in snapshot.operations
            if active_plan is not None
            and item.plan_version == active_plan.plan_version
            and item.status == "approved"
            and (operation_id is None or item.operation_id == operation_id)
        )
        if len(operations) != 1:
            raise RedDispatchDenied("execution requires one approved operation on the active plan")
        return operations[0]
