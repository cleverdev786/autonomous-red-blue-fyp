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
from schemas.red_team import RedScopeReference
from schemas.red_team_state import (
    AssessmentDTO,
    AssessmentState,
    require_assessment_transition,
)
from services.red_assessment_queue import QueueDenied, RedAssessmentQueue
from services.red_assessment_summary import RedAssessmentSummarizer

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
    ) -> None:
        if queue.store.path.resolve() != runner.queue.store.path.resolve():
            raise ValueError("supervisor queue and runner must share one database")
        self.queue = queue
        self.runner = runner
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
        try:
            self.runner.coordinator.validate_for_queue(task, "manual")
            return self.queue.enqueue(
                job_id=self._job_id(command_id, task.stage),
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
        try:
            self.runner.coordinator.validate_for_queue(work[0], "autonomous")
            return self.queue.enqueue_many(tuple(
                (
                    self._job_id(command_id, task.stage),
                    task,
                    resource,
                    enqueued_at,
                )
                for task, resource in zip(work, reservations, strict=True)
            ))
        except (QueueDenied, RedStageBlocked) as exc:
            raise RedDispatchDenied(str(exc)) from exc

    def run_next(
        self,
        *,
        worker_id: str,
        claimed_at: datetime,
    ) -> RedWorkResult | None:
        result = self.runner.run_next(
            worker_id=worker_id, claimed_at=claimed_at,
        )
        if result is not None and result.stage == "verification":
            self._finalize(result.scope)
        return result

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

    def _finalize(self, scope: RedScopeReference) -> None:
        snapshot, _ = self.queue.store.load(scope.assessment_id)
        if snapshot.assessment.status != AssessmentState.RUNNING:
            return
        stages = {item.stage: item.status.value for item in snapshot.stages}
        if any(stages.get(stage) != "succeeded" for stage in _STAGES):
            return
        self.summarizer.summarize(
            scope=scope,
            operations=snapshot.operations,
            receipts=self.journal.list_receipts(scope),
            findings=self.journal.list_findings(scope),
            coverage_gaps=self.journal.list_coverage_gaps(scope),
        )

    @staticmethod
    def _job_id(command_id: str, stage: str) -> str:
        digest = sha256(f"{command_id}:{stage}".encode()).hexdigest()[:24]
        return f"job-{digest}"
