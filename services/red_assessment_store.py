"""T05 versioned Red assessment storage, isolated from historical MARS data.

No tool execution, network access, or approval issuance occurs in this module.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing, contextmanager
from datetime import datetime
from hashlib import sha256
from pathlib import Path

from pydantic import TypeAdapter

from schemas.common import Identifier
from schemas.red_team import RedEndpointCandidate, RedScopeReference, RedStandardAuthorization
from schemas.red_team_state import (
    AssessmentDTO,
    OperationDTO,
    PlanVersionDTO,
    RedAssessmentDetailDTO,
    StageDTO,
    StageState,
    SurfaceRevisionDTO,
    require_stage_transition,
)


class StoreConflict(ValueError):
    """A duplicate, invalid transition or untrusted relationship was rejected."""


_ID = TypeAdapter(Identifier)


class RedAssessmentStore:
    """Small SQLite seam with immutable identity/approval and append-only plans."""

    def __init__(self, path: Path, *, read_only: bool = False) -> None:
        self.path = Path(path)
        self.read_only = read_only
        if read_only:
            return
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS red_assessments (
                    assessment_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL UNIQUE,
                    assessment_json TEXT NOT NULL,
                    authorization_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS red_candidates (
                    assessment_id TEXT NOT NULL,
                    candidate_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (assessment_id, candidate_id),
                    FOREIGN KEY (assessment_id) REFERENCES red_assessments(assessment_id)
                );
                CREATE TABLE IF NOT EXISTS red_surfaces (
                    assessment_id TEXT NOT NULL,
                    surface_revision TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (assessment_id, surface_revision),
                    FOREIGN KEY (assessment_id) REFERENCES red_assessments(assessment_id)
                );
                CREATE TABLE IF NOT EXISTS red_plans (
                    assessment_id TEXT NOT NULL,
                    plan_version TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('draft', 'approved', 'stale')),
                    PRIMARY KEY (assessment_id, plan_version),
                    FOREIGN KEY (assessment_id) REFERENCES red_assessments(assessment_id)
                );
                CREATE TABLE IF NOT EXISTS red_stages (
                    assessment_id TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    plan_version TEXT,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (assessment_id, stage),
                    FOREIGN KEY (assessment_id) REFERENCES red_assessments(assessment_id),
                    FOREIGN KEY (assessment_id, plan_version)
                        REFERENCES red_plans(assessment_id, plan_version)
                );
                CREATE TABLE IF NOT EXISTS red_operations (
                    assessment_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    plan_version TEXT NOT NULL,
                    candidate_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (assessment_id, operation_id),
                    FOREIGN KEY (assessment_id, plan_version)
                        REFERENCES red_plans(assessment_id, plan_version),
                    FOREIGN KEY (assessment_id, candidate_id)
                        REFERENCES red_candidates(assessment_id, candidate_id)
                );
            """)

    @contextmanager
    def _connect(self):
        database = f"{self.path.resolve().as_uri()}?mode=ro" if self.read_only else self.path
        with closing(sqlite3.connect(database, timeout=5, uri=self.read_only)) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys = ON")
            with db:
                yield db

    @staticmethod
    def _load_assessment(db, assessment_id: str) -> tuple[AssessmentDTO, RedStandardAuthorization]:
        row = db.execute(
            "SELECT assessment_json, authorization_json FROM red_assessments WHERE assessment_id=?",
            (assessment_id,),
        ).fetchone()
        if row is None:
            raise StoreConflict("unknown assessment")
        return (
            AssessmentDTO.model_validate_json(row["assessment_json"]),
            RedStandardAuthorization.model_validate_json(row["authorization_json"]),
        )

    def _require_scope(self, db, scope: RedScopeReference) -> None:
        stored, authorization = self._load_assessment(db, scope.assessment_id)
        if stored.scope != scope or authorization.scope != scope:
            raise StoreConflict("scope or authorization fingerprint mismatch")

    def create(
        self,
        assessment: AssessmentDTO,
        authorization: RedStandardAuthorization,
        *,
        request_id: str,
    ) -> str:
        key = _ID.validate_python(request_id)
        if authorization.scope != assessment.scope:
            raise StoreConflict("authorization must match assessment scope")
        if assessment.profile != authorization.budget.profile:
            raise StoreConflict("authorization profile mismatch")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")  # serialize idempotency checks across callers
            previous = db.execute(
                "SELECT assessment_id, assessment_json, authorization_json FROM red_assessments WHERE request_id=?",
                (key,),
            ).fetchone()
            if previous is not None:
                if RedStandardAuthorization.model_validate_json(
                    previous["authorization_json"]
                ) != authorization:
                    raise StoreConflict("authorization snapshot differs from existing request")
                saved = AssessmentDTO.model_validate_json(previous["assessment_json"])
                if (
                    saved.scope != assessment.scope
                    or saved.mode != assessment.mode
                    or saved.profile != assessment.profile
                ):
                    raise StoreConflict("idempotency request reused with a different assessment")
                return previous["assessment_id"]
            try:
                db.execute(
                    "INSERT INTO red_assessments VALUES (?,?,?,?)",
                    (assessment.scope.assessment_id, key,
                     assessment.model_dump_json(), authorization.model_dump_json()),
                )
            except sqlite3.IntegrityError as exc:
                raise StoreConflict("assessment already exists or request key is in use") from exc
        return assessment.scope.assessment_id

    def add_candidate(self, assessment_id: str, candidate: RedEndpointCandidate) -> None:
        with self._connect() as db:
            self._load_assessment(db, assessment_id)
            try:
                db.execute(
                    "INSERT INTO red_candidates VALUES (?,?,?)",
                    (assessment_id, candidate.candidate_id, candidate.model_dump_json()),
                )
            except sqlite3.IntegrityError as exc:
                raise StoreConflict("duplicate candidate") from exc

    def add_plan(self, plan: PlanVersionDTO) -> None:
        with self._connect() as db:
            self._require_scope(db, plan.scope)
            latest_surface = db.execute(
                "SELECT surface_revision FROM red_surfaces WHERE assessment_id=? ORDER BY rowid DESC LIMIT 1",
                (plan.scope.assessment_id,),
            ).fetchone()
            if latest_surface is not None and latest_surface["surface_revision"] != plan.surface_revision:
                raise StoreConflict("plan references a stale surface revision")
            if latest_surface is not None and plan.status == "approved" and plan.plan_digest is None:
                raise StoreConflict("approved current-surface plan requires a digest")
            exists = db.execute(
                "SELECT 1 FROM red_plans WHERE assessment_id=? AND plan_version=?",
                (plan.scope.assessment_id, plan.plan_version),
            ).fetchone()
            if exists:
                raise StoreConflict("plan versions are immutable")
            db.execute(
                "INSERT INTO red_plans VALUES (?,?,?,?)",
                (plan.scope.assessment_id, plan.plan_version, plan.model_dump_json(), plan.status),
            )

    def record_surface(
        self,
        scope: RedScopeReference,
        *,
        candidates: tuple[RedEndpointCandidate, ...],
        observed_at: datetime,
    ) -> SurfaceRevisionDTO:
        """Persist one immutable surface and invalidate dependent unrun work."""
        if observed_at.tzinfo is None:
            raise StoreConflict("surface timestamp must be timezone-aware")
        ordered = tuple(sorted(candidates, key=lambda item: item.candidate_id))
        body = {
            "scope": scope.model_dump(mode="json"),
            "observed_at": observed_at.isoformat(),
            "candidates": [item.model_dump(mode="json") for item in ordered],
        }
        digest = sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        surface = SurfaceRevisionDTO(
            scope=scope,
            surface_revision=f"surface-{digest[:20]}",
            snapshot_digest=digest,
            candidate_ids=tuple(item.candidate_id for item in ordered),
            observed_at=observed_at,
        )
        with self._connect() as db:
            self._require_scope(db, scope)
            for candidate in ordered:
                row = db.execute(
                    "SELECT payload FROM red_candidates WHERE assessment_id=? AND candidate_id=?",
                    (scope.assessment_id, candidate.candidate_id),
                ).fetchone()
                saved = (
                    RedEndpointCandidate.model_validate_json(row["payload"])
                    if row is not None else None
                )
                if saved is None or saved.model_dump(exclude={"observed_at"}) != (
                    candidate.model_dump(exclude={"observed_at"})
                ):
                    raise StoreConflict("surface references unknown or altered candidate")
            existing = db.execute(
                "SELECT payload FROM red_surfaces WHERE assessment_id=? AND surface_revision=?",
                (scope.assessment_id, surface.surface_revision),
            ).fetchone()
            if existing is not None:
                if SurfaceRevisionDTO.model_validate_json(existing["payload"]) != surface:
                    raise StoreConflict("surface revision collision")
                return surface

            running = db.execute(
                """SELECT 1 FROM red_operations
                   WHERE assessment_id=? AND json_extract(payload, '$.status')='running' LIMIT 1""",
                (scope.assessment_id,),
            ).fetchone()
            if running is not None:
                raise StoreConflict("cannot revise surface while an operation is running")
            db.execute(
                "INSERT INTO red_surfaces VALUES (?,?,?)",
                (scope.assessment_id, surface.surface_revision, surface.model_dump_json()),
            )
            db.execute(
                """UPDATE red_plans SET status='stale'
                   WHERE assessment_id=? AND status IN ('draft','approved')
                     AND json_extract(payload, '$.surface_revision') != ?""",
                (scope.assessment_id, surface.surface_revision),
            )
            operation_rows = db.execute(
                "SELECT operation_id, payload FROM red_operations WHERE assessment_id=?",
                (scope.assessment_id,),
            ).fetchall()
            for row in operation_rows:
                operation = OperationDTO.model_validate_json(row["payload"])
                if operation.status in {"proposed", "approved"}:
                    blocked = operation.model_copy(update={"status": "blocked"})
                    db.execute(
                        "UPDATE red_operations SET payload=? WHERE assessment_id=? AND operation_id=?",
                        (blocked.model_dump_json(), scope.assessment_id, operation.operation_id),
                    )
        return surface

    def set_plan_stale(self, assessment_id: str, plan_version: str) -> None:
        with self._connect() as db:
            row = db.execute(
                "SELECT status FROM red_plans WHERE assessment_id=? AND plan_version=?",
                (assessment_id, plan_version),
            ).fetchone()
            if row is None or row["status"] != "approved":
                raise StoreConflict("only an approved plan can become stale")
            active = db.execute(
                """SELECT 1 FROM red_operations
                   WHERE assessment_id=? AND plan_version=? AND
                     json_extract(payload, '$.status') IN ('approved','running') LIMIT 1""",
                (assessment_id, plan_version),
            ).fetchone()
            if active:
                raise StoreConflict("cannot stale a plan with active operations")
            db.execute(
                "UPDATE red_plans SET status='stale' WHERE assessment_id=? AND plan_version=?",
                (assessment_id, plan_version),
            )

    def set_stage(self, stage: StageDTO) -> None:
        with self._connect() as db:
            self._require_scope(db, stage.scope)
            row = db.execute(
                "SELECT payload FROM red_stages WHERE assessment_id=? AND stage=?",
                (stage.scope.assessment_id, stage.stage),
            ).fetchone()
            before = StageDTO.model_validate_json(row["payload"]).status if row else StageState.NOT_STARTED
            try:
                require_stage_transition(before, stage.status)
            except ValueError as exc:
                raise StoreConflict("invalid stage transition") from exc
            if stage.plan_version is not None:
                exists = db.execute(
                    "SELECT 1 FROM red_plans WHERE assessment_id=? AND plan_version=?",
                    (stage.scope.assessment_id, stage.plan_version),
                ).fetchone()
                if not exists:
                    raise StoreConflict("stage references unknown plan")
            db.execute(
                """INSERT INTO red_stages (assessment_id, stage, plan_version, payload)
                   VALUES (?,?,?,?)
                   ON CONFLICT(assessment_id,stage) DO UPDATE SET
                       plan_version=excluded.plan_version, payload=excluded.payload""",
                (stage.scope.assessment_id, stage.stage,
                 stage.plan_version, stage.model_dump_json()),
            )

    def add_operation(self, operation: OperationDTO) -> None:
        with self._connect() as db:
            self._require_scope(db, operation.scope)
            exists = db.execute(
                "SELECT status FROM red_plans WHERE assessment_id=? AND plan_version=?",
                (operation.scope.assessment_id, operation.plan_version),
            ).fetchone()
            if exists is None:
                raise StoreConflict("operation references unknown plan")
            if exists["status"] != "approved":
                raise StoreConflict("operation references stale or unapproved plan")
            candidate = db.execute(
                "SELECT 1 FROM red_candidates WHERE assessment_id=? AND candidate_id=?",
                (operation.scope.assessment_id, operation.candidate_id),
            ).fetchone()
            if candidate is None:
                raise StoreConflict("operation references unknown candidate")
            try:
                db.execute(
                    "INSERT INTO red_operations VALUES (?,?,?,?,?)",
                    (operation.scope.assessment_id, operation.operation_id,
                     operation.plan_version, operation.candidate_id,
                     operation.model_dump_json()),
                )
            except sqlite3.IntegrityError as exc:
                raise StoreConflict("duplicate operation") from exc

    def load(self, assessment_id: str) -> tuple[RedAssessmentDetailDTO, RedStandardAuthorization]:
        _ID.validate_python(assessment_id)
        with self._connect() as db:
            db.execute("BEGIN")  # consistent snapshot across related records
            assessment, authorization = self._load_assessment(db, assessment_id)

            def rows(table: str):
                # Private constants only; never interpolate caller-supplied table names.
                assert table in {
                    "red_candidates", "red_surfaces", "red_plans", "red_stages", "red_operations"
                }
                return db.execute(
                    f"SELECT * FROM {table} WHERE assessment_id=? ORDER BY rowid",
                    (assessment_id,),
                ).fetchall()

            plans = [
                PlanVersionDTO.model_validate_json(row["payload"]).model_copy(
                    update={"status": row["status"]}
                )
                for row in rows("red_plans")
            ]
            snapshot = RedAssessmentDetailDTO(
                assessment=assessment,
                candidates=tuple(
                    RedEndpointCandidate.model_validate_json(row["payload"])
                    for row in rows("red_candidates")
                ),
                surfaces=tuple(
                    SurfaceRevisionDTO.model_validate_json(row["payload"])
                    for row in rows("red_surfaces")
                ),
                plans=tuple(plans),
                stages=tuple(
                    StageDTO.model_validate_json(row["payload"])
                    for row in rows("red_stages")
                ),
                operations=tuple(
                    OperationDTO.model_validate_json(row["payload"])
                    for row in rows("red_operations")
                ),
            )
            return snapshot, authorization

    def list_assessments(
        self,
        *,
        target_id: str | None = None,
        status: str | None = None,
        offset: int = 0,
        limit: int | None = 50,
    ) -> tuple[tuple[RedAssessmentDetailDTO, ...], int]:
        """Return validated assessment snapshots in newest-first creation order."""
        clauses = []
        parameters: list[object] = []
        if target_id is not None:
            clauses.append("json_extract(assessment_json, '$.scope.target_id')=?")
            parameters.append(target_id)
        if status is not None:
            clauses.append("json_extract(assessment_json, '$.status')=?")
            parameters.append(status)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self._connect() as db:
            total = db.execute(
                "SELECT COUNT(*) FROM red_assessments" + where,
                parameters,
            ).fetchone()[0]
            query = (
                "SELECT assessment_id FROM red_assessments"
                + where
                + " ORDER BY rowid DESC"
            )
            page_parameters = [*parameters]
            if limit is not None:
                query += " LIMIT ? OFFSET ?"
                page_parameters.extend((limit, offset))
            elif offset:
                query += " LIMIT -1 OFFSET ?"
                page_parameters.append(offset)
            rows = db.execute(query, page_parameters).fetchall()
        return tuple(self.load(row["assessment_id"])[0] for row in rows), total
