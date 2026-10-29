"""SQLite FIFO queue and per-target resource leases for Red assessments (T23)."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from uuid import uuid4

from pydantic import TypeAdapter

from schemas.common import Identifier
from schemas.red_queue import QueuedRedWork, QueueJobDTO, QueueResourceDTO
from schemas.red_team import ExecutionWork
from schemas.red_team_state import (
    AssessmentDTO,
    AssessmentState,
    require_assessment_transition,
)
from services.red_assessment_store import RedAssessmentStore, StoreConflict


class QueueDenied(ValueError):
    """A queue request, claim, or lease completion failed closed."""


class RedAssessmentQueue:
    """Small durable queue; running leases are never silently reclaimed."""

    def __init__(self, store: RedAssessmentStore) -> None:
        self.store = store
        with self.store._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS red_queue_jobs (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL UNIQUE,
                    assessment_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    resource_class TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(
                        status IN ('queued','running','completed','failed')
                    ),
                    work_json TEXT NOT NULL,
                    resource_json TEXT NOT NULL,
                    enqueued_at TEXT NOT NULL,
                    claimed_at TEXT,
                    finished_at TEXT,
                    worker_id TEXT,
                    lease_id TEXT,
                    FOREIGN KEY (assessment_id)
                        REFERENCES red_assessments(assessment_id)
                );
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

        work_json = work.model_dump_json()
        resource_json = resource.model_dump_json()
        with self.store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self.store._require_scope(db, work.scope)
            persisted, _ = self.store._load_assessment(
                db, work.scope.assessment_id
            )
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
                runtime_total = sum(
                    job.resource.runtime_seconds for job in reservations
                )
                if (
                    len(reservations) + 1 > budget.max_tests
                    or request_total + resource.requests
                    > budget.max_http_requests
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
                "SELECT * FROM red_queue_jobs WHERE sequence=?",
                (cursor.lastrowid,),
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
        if status not in {"completed", "failed"}:
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
            return self._job(completed)

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
