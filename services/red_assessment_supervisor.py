"""Authorized Manual and Autonomous dispatch over the shared Red queue (T25)."""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import datetime
from hashlib import sha256

from pydantic import TypeAdapter

from agents.red.contracts import RedWork, RedWorkResult
from orchestrator.red_team_flow import RedQueuedStageRunner, RedStageBlocked
from schemas.common import Identifier
from schemas.red_queue import QueueJobDTO, QueueResourceDTO
from schemas.red_team import (
    ExecutionWork,
    PlanningWork,
    RedScopeReference,
    VerificationWork,
)
from schemas.red_team_state import (
    AssessmentDTO,
    AssessmentState,
    require_assessment_transition,
)
from services.red_assessment_queue import QueueDenied, RedAssessmentQueue
from services.red_assessment_summary import RedAssessmentSummarizer
from services.target_registry import TargetRegistry

_STAGES = ("reconnaissance", "planning", "execution", "verification")


class RedDispatchDenied(ValueError):
    """Authorization or dispatch state denied a Red command."""


class RedAssessmentSupervisor:
    """One model-free dispatch boundary shared by both assessment modes."""

    def __init__(
        self,
        *,
        queue: RedAssessmentQueue,
        runner: RedQueuedStageRunner,
        registry: TargetRegistry | None = None,
    ) -> None:
        if queue.store.path.resolve() != runner.queue.store.path.resolve():
            raise ValueError("supervisor queue and runner must share one database")
        self.queue = queue
        self.runner = runner
        self.registry = registry
        self.journal = runner.coordinator.journal
        self.summarizer = RedAssessmentSummarizer(self.journal)
        with self.queue.store._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS red_dispatch_authorizations (
                assessment_id TEXT PRIMARY KEY,
                command_id TEXT NOT NULL UNIQUE,
                approval_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                authorization_fingerprint TEXT NOT NULL,
                profile TEXT NOT NULL CHECK(profile='standard'),
                mode TEXT NOT NULL CHECK(mode IN ('manual','autonomous')),
                authorized_at TEXT NOT NULL,
                FOREIGN KEY (assessment_id)
                    REFERENCES red_assessments(assessment_id)
            )""")

    @staticmethod
    def _identifier(value: str) -> str:
        return TypeAdapter(Identifier).validate_python(value)

    @staticmethod
    def _aware(value: datetime) -> None:
        if value.tzinfo is None:
            raise RedDispatchDenied("dispatch timestamp requires timezone")

    def authorize(
        self,
        scope: RedScopeReference,
        *,
        approval_id: str,
        command_id: str,
        authorized_at: datetime,
    ) -> AssessmentDTO:
        """Record one explicit approval for the immutable assessment snapshot."""
        approval_id = self._identifier(approval_id)
        command_id = self._identifier(command_id)
        self._aware(authorized_at)
        with self.queue.store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self.queue.store._require_scope(db, scope)
            assessment, authorization = self.queue.store._load_assessment(
                db, scope.assessment_id
            )
            existing = db.execute(
                """SELECT * FROM red_dispatch_authorizations
                   WHERE assessment_id=?""",
                (scope.assessment_id,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["command_id"] != command_id
                    or existing["approval_id"] != approval_id
                    or existing["target_id"] != scope.target_id
                    or existing["authorization_fingerprint"]
                    != scope.authorization_fingerprint
                    or existing["profile"] != assessment.profile
                    or existing["mode"] != assessment.mode
                ):
                    raise RedDispatchDenied("assessment authorization is immutable")
                return assessment
            if (
                authorization.scope != scope
                or authorization.approval_id != approval_id
                or assessment.status != AssessmentState.AWAITING_AUTHORIZATION
            ):
                raise RedDispatchDenied("explicit operator authorization required")
            require_assessment_transition(
                assessment.status, AssessmentState.QUEUED
            )
            queued = AssessmentDTO.model_validate(assessment.model_copy(update={
                "status": AssessmentState.QUEUED,
                "workflow_complete": False,
            }))
            db.execute(
                """INSERT INTO red_dispatch_authorizations
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    scope.assessment_id,
                    command_id,
                    approval_id,
                    scope.target_id,
                    scope.authorization_fingerprint,
                    assessment.profile,
                    assessment.mode,
                    authorized_at.isoformat(),
                ),
            )
            db.execute(
                """UPDATE red_assessments SET assessment_json=?
                   WHERE assessment_id=?""",
                (queued.model_dump_json(), scope.assessment_id),
            )
            event_id = "event-" + sha256(
                f"authorize:{scope.assessment_id}:{command_id}".encode()
            ).hexdigest()[:24]
            db.execute(
                """INSERT INTO red_events
                   (assessment_id,event_id,actor,action,outcome,occurred_at,details)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    scope.assessment_id,
                    event_id,
                    "operator",
                    "assessment-authorization",
                    "approved",
                    authorized_at.isoformat(),
                    json.dumps({
                        "mode": assessment.mode,
                        "profile": assessment.profile,
                        "target_id": scope.target_id,
                    }, sort_keys=True),
                ),
            )
            return queued

    def enqueue_manual(
        self,
        task: RedWork,
        *,
        command_id: str,
        resource: QueueResourceDTO,
        enqueued_at: datetime,
    ) -> QueueJobDTO:
        command_id = self._identifier(command_id)
        self._require_authorized(task.scope, "manual")
        job_id = self._job_id(command_id, task.stage)
        existing = self._existing_jobs(((job_id, task, resource),))
        if existing is not None:
            return existing[0]
        try:
            self.runner.coordinator.validate_for_queue(task, "manual")
            return self.queue.enqueue_operator(
                job_id=job_id,
                work=task,
                resource=resource,
                enqueued_at=enqueued_at,
            )
        except (QueueDenied, RedStageBlocked) as exc:
            raise RedDispatchDenied(str(exc)) from exc

    def enqueue_autonomous(
        self,
        tasks: Sequence[RedWork],
        *,
        command_id: str,
        resources: Sequence[QueueResourceDTO],
        enqueued_at: datetime,
    ) -> tuple[QueueJobDTO, ...]:
        command_id = self._identifier(command_id)
        work = tuple(tasks)
        reservations = tuple(resources)
        if (
            len(work) != len(_STAGES)
            or tuple(task.stage for task in work) != _STAGES
            or any(task.scope != work[0].scope for task in work)
            or len(reservations) != len(work)
        ):
            raise RedDispatchDenied(
                "autonomous dispatch requires one ordered four-stage workload"
            )
        self._require_authorized(work[0].scope, "autonomous")
        entries = tuple(
            (self._job_id(command_id, task.stage), task, resource)
            for task, resource in zip(work, reservations, strict=True)
        )
        existing = self._existing_jobs(entries)
        if existing is not None:
            return existing
        try:
            self.runner.coordinator.validate_for_queue(work[0], "autonomous")
            return self.queue.enqueue_many(tuple(
                (
                    job_id,
                    task,
                    resource,
                    enqueued_at,
                )
                for job_id, task, resource in entries
            ))
        except (QueueDenied, RedStageBlocked) as exc:
            raise RedDispatchDenied(str(exc)) from exc

    def enqueue_autonomous_start(
        self,
        task: RedWork,
        *,
        command_id: str,
        resource: QueueResourceDTO,
        enqueued_at: datetime,
    ) -> QueueJobDTO:
        """Start an autonomous assessment with its dependency-free first stage."""
        if task.stage != "reconnaissance":
            raise RedDispatchDenied("autonomous start requires reconnaissance")
        command_id = self._identifier(command_id)
        self._require_authorized(task.scope, "autonomous")
        job_id = self._job_id(command_id, task.stage)
        existing = self._existing_jobs(((job_id, task, resource),))
        if existing is not None:
            return existing[0]
        try:
            self.runner.coordinator.validate_for_queue(task, "autonomous")
            return self.queue.enqueue_progressive_start(
                command_id=command_id,
                job_id=job_id,
                work=task,
                resource=resource,
                enqueued_at=enqueued_at,
            )
        except (QueueDenied, RedStageBlocked) as exc:
            raise RedDispatchDenied(str(exc)) from exc

    def run_next(
        self,
        *,
        worker_id: str,
        claimed_at: datetime,
    ) -> RedWorkResult | None:
        self._resume_progressive_autonomous()
        try:
            result = self.runner.run_next(
                worker_id=worker_id, claimed_at=claimed_at,
            )
        except Exception:
            self._resume_progressive_autonomous()
            raise
        self._resume_progressive_autonomous()
        if (
            result is not None
            and result.stage == "verification"
            and self.queue.progressive_command(result.scope) is None
        ):
            self._finalize(result.scope)
        return result

    def _resume_progressive_autonomous(self) -> None:
        """Reconcile every progressive dispatch independently of global queue traffic."""
        for assessment_id in self.queue.progressive_assessment_ids():
            snapshot, _ = self.queue.store.load(assessment_id)
            if snapshot.assessment.status not in {
                AssessmentState.QUEUED,
                AssessmentState.RUNNING,
            }:
                continue
            self._reconcile_progressive_autonomous(snapshot.assessment.scope)

    def cancel(
        self,
        scope: RedScopeReference,
        *,
        cancellation_id: str,
        requested_at: datetime,
    ) -> tuple[QueueJobDTO, ...]:
        self._require_authorized(scope, None)
        try:
            return self.queue.request_cancellation(
                scope,
                cancellation_id=cancellation_id,
                requested_at=requested_at,
            )
        except QueueDenied as exc:
            raise RedDispatchDenied(str(exc)) from exc

    def change_mode(self, scope: RedScopeReference, mode: str) -> None:
        snapshot, _ = self.queue.store.load(scope.assessment_id)
        if snapshot.assessment.scope != scope or snapshot.assessment.mode != mode:
            raise RedDispatchDenied("assessment mode is immutable")

    def _require_authorized(
        self,
        scope: RedScopeReference,
        mode: str | None,
    ) -> None:
        snapshot, authorization = self.queue.store.load(scope.assessment_id)
        with self.queue.store._connect() as db:
            row = db.execute(
                """SELECT * FROM red_dispatch_authorizations
                   WHERE assessment_id=?""",
                (scope.assessment_id,),
            ).fetchone()
        if (
            row is None
            or snapshot.assessment.scope != scope
            or authorization.scope != scope
            or row["approval_id"] != authorization.approval_id
            or row["target_id"] != scope.target_id
            or row["authorization_fingerprint"]
            != scope.authorization_fingerprint
            or row["profile"] != snapshot.assessment.profile
            or row["mode"] != snapshot.assessment.mode
            or mode is not None and snapshot.assessment.mode != mode
        ):
            raise RedDispatchDenied("explicit operator authorization required")

    def _existing_jobs(
        self,
        entries: Sequence[tuple[str, RedWork, QueueResourceDTO]],
    ) -> tuple[QueueJobDTO, ...] | None:
        jobs = {
            job.job_id: job
            for job in self.queue.list_jobs(entries[0][1].scope)
        }
        found = tuple(jobs.get(job_id) for job_id, _task, _resource in entries)
        if not any(found):
            return None
        if any(job is None for job in found):
            raise RedDispatchDenied("command has an incomplete queue record")
        existing = tuple(job for job in found if job is not None)
        if any(
            job.work != task or job.resource != resource
            for job, (_job_id, task, resource) in zip(existing, entries, strict=True)
        ):
            raise RedDispatchDenied("command identity conflict")
        return existing

    def _finalize(
        self,
        scope: RedScopeReference,
        required_stages: Sequence[str] = _STAGES,
    ) -> None:
        snapshot, _ = self.queue.store.load(scope.assessment_id)
        if snapshot.assessment.status != AssessmentState.RUNNING:
            return
        stages = {item.stage: item.status.value for item in snapshot.stages}
        if any(stages.get(stage) != "succeeded" for stage in required_stages):
            return
        self.summarizer.summarize(
            scope=scope,
            operations=snapshot.operations,
            receipts=self.journal.list_receipts(scope),
            findings=self.journal.list_findings(scope),
            coverage_gaps=self.journal.list_coverage_gaps(scope),
        )

    def _reconcile_progressive_autonomous(
        self, scope: RedScopeReference,
    ) -> None:
        command_id = self.queue.progressive_command(scope)
        if command_id is None:
            return
        if self.registry is None:
            raise RedDispatchDenied(
                "progressive autonomous dispatch requires the target registry"
            )
        snapshot, authorization = self.queue.store.load(scope.assessment_id)
        jobs = self.queue.list_jobs(scope)
        if any(job.status == "failed" for job in jobs):
            self.queue.finalize_progressive_failure(scope)
            return

        reconnaissance = self._progressive_job(
            jobs, self._job_id(command_id, "reconnaissance"),
        )
        if reconnaissance is None or reconnaissance.status in {"queued", "running"}:
            return
        if reconnaissance.status != "completed":
            return

        if not snapshot.surfaces:
            raise RedDispatchDenied("planning requires the current reconnaissance surface")
        surface = snapshot.surfaces[-1]
        candidates = {item.candidate_id: item for item in snapshot.candidates}
        target = self.registry.get_target(scope.target_id)
        planning = PlanningWork(
            scope=scope,
            surface_revision=surface.surface_revision,
            candidates=tuple(candidates[item] for item in surface.candidate_ids),
            vetted_test_ids=target.allowed_test_ids,
        )
        planning_job = self._ensure_progressive_job(
            command_id, planning, QueueResourceDTO(resource_class="light"), jobs,
        )
        if planning_job.status != "completed":
            return

        snapshot, authorization = self.queue.store.load(scope.assessment_id)
        plan = next(
            (item for item in reversed(snapshot.plans) if item.status == "approved"),
            None,
        )
        operations = tuple(
            item for item in snapshot.operations
            if plan is not None
            and item.plan_version == plan.plan_version
            and item.status == "approved"
        )
        if plan is None:
            raise RedDispatchDenied(
                "autonomous dispatch requires an approved operation on the active plan"
            )
        if not operations:
            self._finalize(scope, ("reconnaissance", "planning"))
            return
        jobs = self.queue.list_jobs(scope)
        receipts = self.journal.list_receipts(scope)
        for operation in operations:
            test = self.registry.get_security_test(operation.test_id)
            execution = ExecutionWork(
                scope=scope,
                plan_version=operation.plan_version,
                operation_id=operation.operation_id,
            )
            execution_job = self._ensure_progressive_job(
                command_id,
                execution,
                QueueResourceDTO(
                    resource_class="docker",
                    requests=test.max_requests,
                    runtime_seconds=test.timeout_seconds,
                    cpu_cores=authorization.budget.max_cpu_cores,
                    memory_mb=authorization.budget.max_memory_mb,
                ),
                jobs,
            )
            if execution_job.status != "completed":
                return
            operation_receipts = tuple(
                item.receipt_id for item in receipts
                if item.operation_id == operation.operation_id
            )
            if not operation_receipts:
                raise RedDispatchDenied(
                    "verification requires persisted receipts for its operation"
                )
            verification = VerificationWork(
                scope=scope,
                plan_version=operation.plan_version,
                operation_id=operation.operation_id,
                receipt_ids=operation_receipts,
                oracle_id=test.success_evidence_rule_id,
            )
            verification_job = self._ensure_progressive_job(
                command_id,
                verification,
                QueueResourceDTO(resource_class="light"),
                jobs,
            )
            if verification_job.status != "completed":
                return
        self._finalize(scope)

    def _ensure_progressive_job(
        self,
        command_id: str,
        task: RedWork,
        resource: QueueResourceDTO,
        jobs: Sequence[QueueJobDTO],
    ) -> QueueJobDTO:
        operation_id = (
            task.operation_id
            if isinstance(task, (ExecutionWork, VerificationWork)) else None
        )
        job_id = self._job_id(command_id, task.stage, operation_id)
        existing = self._progressive_job(jobs, job_id)
        if existing is not None:
            if existing.work != task or existing.resource != resource:
                raise RedDispatchDenied("command identity conflict")
            return existing
        self.runner.coordinator.validate_for_queue(task, "autonomous")
        try:
            return self.queue.enqueue_operator(
                job_id=job_id,
                work=task,
                resource=resource,
                enqueued_at=self.runner.clock(),
            )
        except QueueDenied as exc:
            raise RedDispatchDenied(str(exc)) from exc

    @staticmethod
    def _progressive_job(
        jobs: Sequence[QueueJobDTO], job_id: str,
    ) -> QueueJobDTO | None:
        return next((job for job in jobs if job.job_id == job_id), None)

    @staticmethod
    def _job_id(
        command_id: str, stage: str, operation_id: str | None = None,
    ) -> str:
        identity = f"{command_id}:{stage}"
        if operation_id is not None:
            identity += f":{operation_id}"
        digest = sha256(identity.encode()).hexdigest()[:24]
        return f"job-{digest}"
