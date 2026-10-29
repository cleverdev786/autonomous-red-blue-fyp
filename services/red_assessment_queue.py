"""SQLite FIFO queue and per-target resource leases for Red assessments (T23)."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from datetime import datetime
from hashlib import sha256
from uuid import uuid4

from pydantic import TypeAdapter

from schemas.common import Identifier
from schemas.red_queue import QueuedRedWork, QueueJobDTO, QueueResourceDTO
from schemas.red_team import ExecutionWork, RedScopeReference, RedStandardBudget
from schemas.red_team_state import (
    AssessmentDTO,
    AssessmentState,
    OperationDTO,
    StageDTO,
    StageState,
    require_assessment_transition,
    require_stage_transition,
)
from services.red_assessment_store import RedAssessmentStore, StoreConflict


class QueueDenied(ValueError):
    """A queue request, claim, or lease completion failed closed."""


class RedAssessmentQueue:
    """Small durable queue; running leases are never silently reclaimed."""

    def __init__(self, store: RedAssessmentStore) -> None:
        self.store = store
        with self.store._connect() as db:
            existing = db.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='red_queue_jobs'"
            ).fetchone()
            if existing is not None and "'cancelled'" not in existing["sql"]:
                db.execute("ALTER TABLE red_queue_jobs RENAME TO red_queue_jobs_t23")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS red_queue_jobs (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL UNIQUE,
                    assessment_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    resource_class TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(
                        status IN ('queued','running','completed','failed','cancelled')
                    ),
                    work_json TEXT NOT NULL,
                    resource_json TEXT NOT NULL,
                    enqueued_at TEXT NOT NULL,
                    claimed_at TEXT,
                    finished_at TEXT,
                    worker_id TEXT,
                    lease_id TEXT,
                    cancellation_id TEXT,
                    cancellation_requested_at TEXT,
                    FOREIGN KEY (assessment_id)
                        REFERENCES red_assessments(assessment_id)
                );
                CREATE TABLE IF NOT EXISTS red_queue_cancellations (
                    assessment_id TEXT PRIMARY KEY,
                    cancellation_id TEXT NOT NULL UNIQUE,
                    requested_at TEXT NOT NULL,
                    finalized_at TEXT,
                    FOREIGN KEY (assessment_id)
                        REFERENCES red_assessments(assessment_id)
                );
            """)
            legacy = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='red_queue_jobs_t23'"
            ).fetchone()
            if legacy is not None:
                db.execute(
                    """INSERT INTO red_queue_jobs
                       (sequence,job_id,assessment_id,target_id,stage,resource_class,
                        status,work_json,resource_json,enqueued_at,claimed_at,
                        finished_at,worker_id,lease_id)
                       SELECT sequence,job_id,assessment_id,target_id,stage,resource_class,
                              status,work_json,resource_json,enqueued_at,claimed_at,
                              finished_at,worker_id,lease_id
                       FROM red_queue_jobs_t23"""
                )
                db.execute("DROP TABLE red_queue_jobs_t23")
            db.executescript("""
                CREATE INDEX IF NOT EXISTS red_queue_status_sequence
                    ON red_queue_jobs(status, sequence);
                CREATE INDEX IF NOT EXISTS red_queue_target_status
                    ON red_queue_jobs(target_id, status, resource_class);
            """)

    @staticmethod
    def _aware(value: datetime, field: str) -> None:
        if value.tzinfo is None:
            raise QueueDenied(f"{field} requires timezone")

    @staticmethod
    def _job(row: sqlite3.Row) -> QueueJobDTO:
        job = QueueJobDTO(
            sequence=row["sequence"],
            job_id=row["job_id"],
            work=json.loads(row["work_json"]),
            resource=json.loads(row["resource_json"]),
            status=row["status"],
            enqueued_at=datetime.fromisoformat(row["enqueued_at"]),
            claimed_at=(
                datetime.fromisoformat(row["claimed_at"])
                if row["claimed_at"] is not None else None
            ),
            finished_at=(
                datetime.fromisoformat(row["finished_at"])
                if row["finished_at"] is not None else None
            ),
            worker_id=row["worker_id"],
            lease_id=row["lease_id"],
            cancellation_id=row["cancellation_id"],
            cancellation_requested_at=(
                datetime.fromisoformat(row["cancellation_requested_at"])
                if row["cancellation_requested_at"] is not None else None
            ),
        )
        if (
            row["assessment_id"] != job.work.scope.assessment_id
            or row["target_id"] != job.work.scope.target_id
            or row["stage"] != job.work.stage
            or row["resource_class"] != job.resource.resource_class
        ):
            raise QueueDenied("queue row provenance mismatch")
        return job

    def enqueue(
        self,
        *,
        job_id: str,
        work: QueuedRedWork,
        resource: QueueResourceDTO,
        enqueued_at: datetime,
    ) -> QueueJobDTO:
        return self.enqueue_many(((job_id, work, resource, enqueued_at),))[0]

    def enqueue_many(
        self,
        entries: Sequence[
            tuple[str, QueuedRedWork, QueueResourceDTO, datetime]
        ],
    ) -> tuple[QueueJobDTO, ...]:
        """Persist one dispatch atomically so partial workflows cannot escape."""
        validated = tuple(self._validate_enqueue(*entry) for entry in entries)
        if not validated:
            raise QueueDenied("queue dispatch requires work")
        with self.store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            return tuple(
                self._enqueue(db, job_id, work, resource, enqueued_at, budget)
                for job_id, work, resource, enqueued_at, budget in validated
            )

    def _validate_enqueue(
        self,
        job_id: str,
        work: QueuedRedWork,
        resource: QueueResourceDTO,
        enqueued_at: datetime,
    ) -> tuple[
        str, QueuedRedWork, QueueResourceDTO, datetime, RedStandardBudget
    ]:
        TypeAdapter(Identifier).validate_python(job_id)
        self._aware(enqueued_at, "enqueue timestamp")
        try:
            work = TypeAdapter(QueuedRedWork).validate_json(work.model_dump_json())
            resource = QueueResourceDTO.model_validate_json(
                resource.model_dump_json()
            )
        except (AttributeError, ValueError) as exc:
            raise QueueDenied("queue payload is invalid") from exc
        snapshot, authorization = self.store.load(work.scope.assessment_id)
        if snapshot.assessment.scope != work.scope or authorization.scope != work.scope:
            raise QueueDenied("queue work scope differs from authorization")
        if snapshot.assessment.status not in {
            AssessmentState.QUEUED, AssessmentState.RUNNING,
        }:
            raise QueueDenied("assessment is not queueable")
        if isinstance(work, ExecutionWork) != (resource.resource_class != "light"):
            raise QueueDenied("queue resource class does not match work stage")
        budget = authorization.budget
        request_limit = (
            budget.max_crawl_requests
            if resource.resource_class == "zap"
            else budget.max_http_requests
        )
        if resource.resource_class != "light" and (
            resource.requests > request_limit
            or resource.runtime_seconds > budget.max_runtime_seconds
            or resource.cpu_cores > budget.max_cpu_cores
            or resource.memory_mb > budget.max_memory_mb
        ):
            raise QueueDenied("queue resource budget exceeds authorization")
        return job_id, work, resource, enqueued_at, budget

    def _enqueue(
        self,
        db: sqlite3.Connection,
        job_id: str,
        work: QueuedRedWork,
        resource: QueueResourceDTO,
        enqueued_at: datetime,
        budget: RedStandardBudget,
    ) -> QueueJobDTO:
        work_json = work.model_dump_json()
        resource_json = resource.model_dump_json()
        self.store._require_scope(db, work.scope)
        persisted, _ = self.store._load_assessment(db, work.scope.assessment_id)
        if persisted.status not in {
            AssessmentState.QUEUED, AssessmentState.RUNNING,
        }:
            raise QueueDenied("assessment is not queueable")
        existing = db.execute(
            "SELECT * FROM red_queue_jobs WHERE job_id=?", (job_id,),
        ).fetchone()
        if existing is not None:
            job = self._job(existing)
            if (
                job.work != work
                or job.resource != resource
                or job.enqueued_at != enqueued_at
            ):
                raise QueueDenied("queue job identity conflict")
            return job
        if db.execute(
            """SELECT 1 FROM red_queue_cancellations
               WHERE assessment_id=?""",
            (work.scope.assessment_id,),
        ).fetchone() is not None:
            raise QueueDenied("cancelled assessment cannot accept queue work")
        if resource.resource_class != "light":
            persisted_jobs = tuple(
                self._job(row)
                for row in db.execute("SELECT * FROM red_queue_jobs").fetchall()
            )
            reservations = tuple(
                job
                for job in persisted_jobs
                if job.work.scope.assessment_id == work.scope.assessment_id
                and job.resource.resource_class != "light"
            )
            request_total = sum(job.resource.requests for job in reservations)
            zap_request_total = sum(
                job.resource.requests
                for job in reservations
                if job.resource.resource_class == "zap"
            )
            runtime_total = sum(job.resource.runtime_seconds for job in reservations)
            if (
                len(reservations) + 1 > budget.max_tests
                or request_total + resource.requests > budget.max_http_requests
                or (
                    resource.resource_class == "zap"
                    and zap_request_total + resource.requests
                    > budget.max_crawl_requests
                )
                or runtime_total + resource.runtime_seconds
                > budget.max_runtime_seconds
            ):
                raise QueueDenied("assessment queue budget is exhausted")
        try:
            cursor = db.execute(
                """INSERT INTO red_queue_jobs
                   (job_id,assessment_id,target_id,stage,resource_class,status,
                    work_json,resource_json,enqueued_at)
                   VALUES (?,?,?,?,?,'queued',?,?,?)""",
                (
                    job_id,
                    work.scope.assessment_id,
                    work.scope.target_id,
                    work.stage,
                    resource.resource_class,
                    work_json,
                    resource_json,
                    enqueued_at.isoformat(),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise QueueDenied("queue job could not be persisted") from exc
        row = db.execute(
            "SELECT * FROM red_queue_jobs WHERE sequence=?", (cursor.lastrowid,),
        ).fetchone()
        return self._job(row)

    def claim_next(
        self, *, worker_id: str, claimed_at: datetime
    ) -> QueueJobDTO | None:
        TypeAdapter(Identifier).validate_python(worker_id)
        self._aware(claimed_at, "claim timestamp")
        lease_id = f"lease-{uuid4().hex}"
        with self.store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            queued = db.execute(
                "SELECT * FROM red_queue_jobs WHERE status='queued' ORDER BY sequence",
            ).fetchall()
            active_jobs = tuple(
                self._job(row)
                for row in db.execute(
                    "SELECT * FROM red_queue_jobs WHERE status='running'"
                ).fetchall()
            )
            selected = None
            for row in queued:
                job = self._job(row)
                if db.execute(
                    """SELECT 1 FROM red_queue_cancellations
                       WHERE assessment_id=?""",
                    (job.work.scope.assessment_id,),
                ).fetchone() is not None:
                    continue
                assessment, _ = self.store._load_assessment(
                    db, job.work.scope.assessment_id
                )
                if assessment.status not in {
                    AssessmentState.QUEUED, AssessmentState.RUNNING,
                }:
                    continue
                if any(
                    active.work.scope.assessment_id
                    == job.work.scope.assessment_id
                    for active in active_jobs
                ):
                    continue
                if (
                    job.resource.resource_class != "light"
                    and any(
                        active.resource.resource_class != "light"
                        and active.work.scope.target_id == job.work.scope.target_id
                        for active in active_jobs
                    )
                ):
                    continue
                selected = row
                break
            if selected is None:
                return None
            if claimed_at < datetime.fromisoformat(selected["enqueued_at"]):
                raise QueueDenied("queue claim cannot precede enqueue")
            assessment, _ = self.store._load_assessment(
                db, selected["assessment_id"]
            )
            if assessment.status == AssessmentState.QUEUED:
                require_assessment_transition(
                    assessment.status, AssessmentState.RUNNING
                )
                running = AssessmentDTO.model_validate(
                    assessment.model_copy(update={"status": AssessmentState.RUNNING})
                )
                db.execute(
                    """UPDATE red_assessments SET assessment_json=?
                       WHERE assessment_id=?""",
                    (running.model_dump_json(), selected["assessment_id"]),
                )
            updated = db.execute(
                """UPDATE red_queue_jobs
                   SET status='running',claimed_at=?,worker_id=?,lease_id=?
                   WHERE sequence=? AND status='queued'""",
                (
                    claimed_at.isoformat(),
                    worker_id,
                    lease_id,
                    selected["sequence"],
                ),
            )
            if updated.rowcount != 1:
                raise QueueDenied("queue claim lost atomic ownership")
            row = db.execute(
                "SELECT * FROM red_queue_jobs WHERE sequence=?",
                (selected["sequence"],),
            ).fetchone()
            return self._job(row)

    def finish(
        self,
        *,
        job_id: str,
        lease_id: str,
        worker_id: str,
        status: str,
        finished_at: datetime,
    ) -> QueueJobDTO:
        if status not in {"completed", "failed", "cancelled"}:
            raise QueueDenied("invalid terminal queue status")
        for value in (job_id, lease_id, worker_id):
            TypeAdapter(Identifier).validate_python(value)
        self._aware(finished_at, "finish timestamp")
        with self.store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM red_queue_jobs WHERE job_id=?", (job_id,),
            ).fetchone()
            if (
                row is None
                or row["status"] != "running"
                or row["lease_id"] != lease_id
                or row["worker_id"] != worker_id
            ):
                raise QueueDenied("queue completion requires the active lease")
            if status == "cancelled" and row["cancellation_id"] is None:
                raise QueueDenied("queue cancellation requires a cancellation request")
            if finished_at < datetime.fromisoformat(row["claimed_at"]):
                raise QueueDenied("queue completion cannot precede claim")
            db.execute(
                """UPDATE red_queue_jobs SET status=?,finished_at=?
                   WHERE job_id=?""",
                (status, finished_at.isoformat(), job_id),
            )
            completed = db.execute(
                "SELECT * FROM red_queue_jobs WHERE job_id=?", (job_id,),
            ).fetchone()
            job = self._job(completed)
            cancellation = db.execute(
                """SELECT cancellation_id FROM red_queue_cancellations
                   WHERE assessment_id=?""",
                (job.work.scope.assessment_id,),
            ).fetchone()
            remaining = db.execute(
                """SELECT 1 FROM red_queue_jobs WHERE assessment_id=?
                   AND status='running' LIMIT 1""",
                (job.work.scope.assessment_id,),
            ).fetchone()
            if cancellation is not None and remaining is None:
                self._cancel_active_stages(
                    db,
                    job.work.scope,
                    cancellation["cancellation_id"],
                    finished_at,
                )
                self._finalize_cancellation(db, job.work.scope, finished_at)
            return job

    def request_cancellation(
        self,
        scope: RedScopeReference,
        *,
        cancellation_id: str,
        requested_at: datetime,
    ) -> tuple[QueueJobDTO, ...]:
        """Revoke queued work and durably signal an active worker, idempotently."""
        TypeAdapter(Identifier).validate_python(cancellation_id)
        self._aware(requested_at, "cancellation timestamp")
        with self.store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self.store._require_scope(db, scope)
            assessment, _ = self.store._load_assessment(db, scope.assessment_id)
            existing = db.execute(
                "SELECT * FROM red_queue_cancellations WHERE assessment_id=?",
                (scope.assessment_id,),
            ).fetchone()
            if existing is not None:
                if existing["cancellation_id"] != cancellation_id:
                    raise QueueDenied("assessment already has another cancellation request")
                rows = db.execute(
                    """SELECT * FROM red_queue_jobs WHERE assessment_id=?
                       ORDER BY sequence""",
                    (scope.assessment_id,),
                ).fetchall()
                return tuple(self._job(row) for row in rows)
            if assessment.status not in {AssessmentState.QUEUED, AssessmentState.RUNNING}:
                raise QueueDenied("assessment is not cancellable")
            db.execute(
                "INSERT INTO red_queue_cancellations VALUES (?,?,?,NULL)",
                (scope.assessment_id, cancellation_id, requested_at.isoformat()),
            )
            event_id = "event-" + sha256(
                f"cancel:{scope.assessment_id}:{cancellation_id}".encode()
            ).hexdigest()[:24]
            db.execute(
                """INSERT INTO red_events
                   (assessment_id,event_id,actor,action,outcome,occurred_at,details)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    scope.assessment_id,
                    event_id,
                    "operator",
                    "assessment-cancellation",
                    "requested",
                    requested_at.isoformat(),
                    "{}",
                ),
            )
            rows = db.execute(
                """SELECT * FROM red_queue_jobs WHERE assessment_id=?
                   AND status IN ('queued','running') ORDER BY sequence""",
                (scope.assessment_id,),
            ).fetchall()
            for row in rows:
                job = self._job(row)
                if requested_at < job.enqueued_at:
                    raise QueueDenied("queue cancellation cannot precede enqueue")
                status = "cancelled" if job.status == "queued" else "running"
                db.execute(
                    """UPDATE red_queue_jobs
                       SET status=?,finished_at=?,cancellation_id=?,
                           cancellation_requested_at=? WHERE sequence=?""",
                    (
                        status,
                        requested_at.isoformat() if status == "cancelled" else None,
                        cancellation_id,
                        requested_at.isoformat(),
                        job.sequence,
                    ),
                )
            active = db.execute(
                """SELECT 1 FROM red_queue_jobs WHERE assessment_id=?
                   AND status='running' LIMIT 1""",
                (scope.assessment_id,),
            ).fetchone()
            if active is None:
                self._cancel_active_stages(db, scope, cancellation_id, requested_at)
                self._finalize_cancellation(db, scope, requested_at)
            updated = db.execute(
                """SELECT * FROM red_queue_jobs WHERE assessment_id=?
                   ORDER BY sequence""",
                (scope.assessment_id,),
            ).fetchall()
            return tuple(self._job(row) for row in updated)

    def cancellation_requested(self, *, job_id: str, lease_id: str) -> bool:
        for value in (job_id, lease_id):
            TypeAdapter(Identifier).validate_python(value)
        with self.store._connect() as db:
            row = db.execute(
                """SELECT cancellation_requested_at FROM red_queue_jobs
                   WHERE job_id=? AND lease_id=? AND status='running'""",
                (job_id, lease_id),
            ).fetchone()
        return row is not None and row["cancellation_requested_at"] is not None

    def recover_job(
        self,
        *,
        job_id: str,
        status: str,
        stage_status: StageState,
        recovered_at: datetime,
    ) -> QueueJobDTO:
        """Resolve one abandoned lease without ever redispatching its work."""
        TypeAdapter(Identifier).validate_python(job_id)
        self._aware(recovered_at, "recovery timestamp")
        if status not in {"completed", "failed", "cancelled"}:
            raise QueueDenied("invalid recovery status")
        with self.store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM red_queue_jobs WHERE job_id=?", (job_id,),
            ).fetchone()
            if row is None or row["status"] != "running":
                raise QueueDenied("recovery requires an abandoned running lease")
            job = self._job(row)
            if recovered_at < job.claimed_at:
                raise QueueDenied("recovery cannot precede claim")
            if status == "cancelled" and job.cancellation_id is None:
                raise QueueDenied("cancelled recovery requires a cancellation request")
            stage_row = db.execute(
                """SELECT payload FROM red_stages
                   WHERE assessment_id=? AND stage=?""",
                (job.work.scope.assessment_id, job.work.stage),
            ).fetchone()
            if stage_row is not None:
                stage = StageDTO.model_validate_json(stage_row["payload"])
                if stage.status == StageState.RUNNING:
                    require_stage_transition(stage.status, stage_status)
                    recovered = stage.model_copy(update={"status": stage_status})
                    db.execute(
                        """UPDATE red_stages SET payload=?
                           WHERE assessment_id=? AND stage=?""",
                        (
                            recovered.model_dump_json(),
                            job.work.scope.assessment_id,
                            job.work.stage,
                        ),
                    )
                    event_id = "event-" + sha256(
                        f"recover:{job.job_id}:{stage_status.value}".encode()
                    ).hexdigest()[:24]
                    self._append_stage_event(
                        db, job.work.scope, event_id, job.work.stage,
                        stage.status, stage_status, recovered_at,
                    )
            db.execute(
                """UPDATE red_queue_jobs SET status=?,finished_at=?
                   WHERE job_id=?""",
                (status, recovered_at.isoformat(), job_id),
            )
            if isinstance(job.work, ExecutionWork):
                operation_row = db.execute(
                    """SELECT payload FROM red_operations
                       WHERE assessment_id=? AND operation_id=?""",
                    (job.work.scope.assessment_id, job.work.operation_id),
                ).fetchone()
                if operation_row is not None:
                    operation = OperationDTO.model_validate_json(
                        operation_row["payload"]
                    )
                    operation_status = (
                        "completed" if status == "completed"
                        else "cancelled" if status == "cancelled" else "blocked"
                    )
                    updated_operation = operation.model_copy(
                        update={"status": operation_status}
                    )
                    db.execute(
                        """UPDATE red_operations SET payload=?
                           WHERE assessment_id=? AND operation_id=?""",
                        (
                            updated_operation.model_dump_json(),
                            job.work.scope.assessment_id,
                            job.work.operation_id,
                        ),
                    )
            remaining = db.execute(
                """SELECT 1 FROM red_queue_jobs WHERE assessment_id=?
                   AND status='running' LIMIT 1""",
                (job.work.scope.assessment_id,),
            ).fetchone()
            cancellation = db.execute(
                """SELECT 1 FROM red_queue_cancellations
                   WHERE assessment_id=?""",
                (job.work.scope.assessment_id,),
            ).fetchone()
            if remaining is None and cancellation is not None:
                self._finalize_cancellation(db, job.work.scope, recovered_at)
            elif remaining is None and status == "failed":
                current, _ = self.store._load_assessment(
                    db, job.work.scope.assessment_id
                )
                require_assessment_transition(current.status, AssessmentState.FAILED)
                failed = AssessmentDTO.model_validate(current.model_copy(update={
                    "status": AssessmentState.FAILED,
                    "workflow_complete": True,
                }))
                db.execute(
                    """UPDATE red_assessments SET assessment_json=?
                       WHERE assessment_id=?""",
                    (failed.model_dump_json(), job.work.scope.assessment_id),
                )
            recovered_row = db.execute(
                "SELECT * FROM red_queue_jobs WHERE job_id=?", (job_id,),
            ).fetchone()
            return self._job(recovered_row)

    def _cancel_active_stages(
        self,
        db: sqlite3.Connection,
        scope: RedScopeReference,
        cancellation_id: str,
        occurred_at: datetime,
    ) -> None:
        rows = db.execute(
            "SELECT stage,plan_version,payload FROM red_stages WHERE assessment_id=?",
            (scope.assessment_id,),
        ).fetchall()
        for row in rows:
            stage = StageDTO.model_validate_json(row["payload"])
            if stage.status not in {
                StageState.READY, StageState.QUEUED, StageState.RUNNING,
            }:
                continue
            cancelled = stage.model_copy(update={"status": StageState.CANCELLED})
            event_id = "event-" + sha256(
                f"{cancellation_id}:{stage.stage}".encode()
            ).hexdigest()[:24]
            db.execute(
                """UPDATE red_stages SET payload=?
                   WHERE assessment_id=? AND stage=?""",
                (cancelled.model_dump_json(), scope.assessment_id, stage.stage),
            )
            self._append_stage_event(
                db, scope, event_id, stage.stage, stage.status,
                StageState.CANCELLED, occurred_at,
            )

    @staticmethod
    def _append_stage_event(
        db: sqlite3.Connection,
        scope: RedScopeReference,
        event_id: str,
        stage: str,
        previous: StageState,
        status: StageState,
        occurred_at: datetime,
    ) -> None:
        details = json.dumps({
            "stage": stage,
            "previous_status": previous.value,
            "status": status.value,
            "phase": "recovery",
        }, sort_keys=True)
        db.execute(
            """INSERT OR IGNORE INTO red_events
               (assessment_id,event_id,actor,action,outcome,occurred_at,details)
               VALUES (?,?,?,?,?,?,?)""",
            (
                scope.assessment_id, event_id, "red-orchestrator",
                "stage-transition", status.value, occurred_at.isoformat(), details,
            ),
        )

    def _finalize_cancellation(
        self,
        db: sqlite3.Connection,
        scope: RedScopeReference,
        finalized_at: datetime,
    ) -> None:
        current, _ = self.store._load_assessment(db, scope.assessment_id)
        if current.status == AssessmentState.CANCELLED:
            return
        require_assessment_transition(current.status, AssessmentState.CANCELLED)
        cancelled = AssessmentDTO.model_validate(current.model_copy(update={
            "status": AssessmentState.CANCELLED,
            "workflow_complete": True,
        }))
        db.execute(
            "UPDATE red_assessments SET assessment_json=? WHERE assessment_id=?",
            (cancelled.model_dump_json(), scope.assessment_id),
        )
        db.execute(
            """UPDATE red_queue_cancellations SET finalized_at=?
               WHERE assessment_id=?""",
            (finalized_at.isoformat(), scope.assessment_id),
        )

    def list_jobs(self, scope) -> tuple[QueueJobDTO, ...]:
        try:
            with self.store._connect() as db:
                self.store._require_scope(db, scope)
                rows = db.execute(
                    """SELECT * FROM red_queue_jobs WHERE assessment_id=?
                       ORDER BY sequence""",
                    (scope.assessment_id,),
                ).fetchall()
        except StoreConflict as exc:
            raise QueueDenied("queue scope denied") from exc
        return tuple(self._job(row) for row in rows)
