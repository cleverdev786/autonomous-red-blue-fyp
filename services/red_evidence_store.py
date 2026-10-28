"""Append-only, scope-bound Red timeline and redacted evidence files (T06).

Use only from trusted backend code. HTTP operator authentication is a later gate.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

from pydantic import TypeAdapter, ValidationError

from schemas.common import Identifier
from schemas.red_team import RedScopeReference
from schemas.red_team_state import (
    AssessmentDTO,
    AssessmentState,
    CoverageDTO,
    CoverageGapDTO,
    EvidenceArtifactDTO,
    FindingDTO,
    FindingState,
    OperationDTO,
    PendingHandoffDTO,
    ReceiptDTO,
    StageDTO,
    StageState,
    StageTransitionEventDTO,
    require_assessment_transition,
    require_stage_transition,
)
from services.red_assessment_store import RedAssessmentStore, StoreConflict


class EvidenceDenied(ValueError):
    """Invalid provenance, unsafe access, duplicate receipt or corrupted content."""


_SAFE_DETAIL_KEYS = frozenset(
    {"stage", "reason_code", "operation_id", "status", "test_id",
     "endpoint_id", "method", "status_code", "oracle_id",
     "previous_status", "phase"}
)
_SAFE_VALUE = re.compile(r"^[a-zA-Z0-9_.-]{1,100}$")
_SECRET_HINT = re.compile(
    r"(?:password|passwd|secret|bearer|token|authorization|cookie|credential|api[_-]?key)",
    re.IGNORECASE,
)


def _sanitized(details: Mapping[str, object]) -> dict[str, object]:
    clean: dict[str, object] = {}
    for key, value in details.items():
        if not isinstance(key, str) or len(key) > 100:
            raise EvidenceDenied("invalid field name")
        if (key in _SAFE_DETAIL_KEYS
                and ((type(value) is int and 0 <= value <= 999)
                     or (isinstance(value, str)
                         and _SAFE_VALUE.fullmatch(value)
                         and not _SECRET_HINT.search(value)))):
            clean[key] = value
        else:
            clean[key] = "[REDACTED]"
    return clean


class RedEvidenceStore:
    """Reuses the T05 SQLite DB; keeps evidence bytes in a separate bounded root."""

    def __init__(self, store: RedAssessmentStore, evidence_root: Path) -> None:
        self.store = store
        self.evidence_root = Path(evidence_root).resolve()
        self.evidence_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.store._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS red_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    assessment_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    details TEXT NOT NULL,
                    UNIQUE(assessment_id, event_id),
                    FOREIGN KEY(assessment_id) REFERENCES red_assessments(assessment_id)
                );
                CREATE TABLE IF NOT EXISTS red_receipts (
                    assessment_id TEXT NOT NULL,
                    receipt_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    plan_version TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (assessment_id, receipt_id),
                    FOREIGN KEY (assessment_id, operation_id)
                        REFERENCES red_operations(assessment_id, operation_id)
                );
                CREATE TABLE IF NOT EXISTS red_evidence (
                    assessment_id TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    receipt_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    content_type TEXT NOT NULL,
                    storage_ref TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    PRIMARY KEY (assessment_id, evidence_id),
                    FOREIGN KEY (assessment_id, receipt_id)
                        REFERENCES red_receipts(assessment_id, receipt_id)
                );
                CREATE TABLE IF NOT EXISTS red_findings (
                    assessment_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (assessment_id, finding_id),
                    FOREIGN KEY(assessment_id) REFERENCES red_assessments(assessment_id)
                );
                CREATE TABLE IF NOT EXISTS red_pending_handoffs (
                    assessment_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (assessment_id, finding_id),
                    FOREIGN KEY(assessment_id, finding_id)
                        REFERENCES red_findings(assessment_id, finding_id)
                );
                CREATE TABLE IF NOT EXISTS red_coverage_gaps (
                    assessment_id TEXT NOT NULL,
                    gap_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (assessment_id, gap_id),
                    FOREIGN KEY(assessment_id) REFERENCES red_assessments(assessment_id)
                );
                CREATE TRIGGER IF NOT EXISTS red_events_no_update
                    BEFORE UPDATE ON red_events BEGIN SELECT RAISE(ABORT, 'append-only'); END;
                CREATE TRIGGER IF NOT EXISTS red_events_no_delete
                    BEFORE DELETE ON red_events BEGIN SELECT RAISE(ABORT, 'append-only'); END;
                CREATE TRIGGER IF NOT EXISTS red_receipts_no_update
                    BEFORE UPDATE ON red_receipts BEGIN SELECT RAISE(ABORT, 'append-only'); END;
                CREATE TRIGGER IF NOT EXISTS red_receipts_no_delete
                    BEFORE DELETE ON red_receipts BEGIN SELECT RAISE(ABORT, 'append-only'); END;
                CREATE TRIGGER IF NOT EXISTS red_evidence_no_update
                    BEFORE UPDATE ON red_evidence BEGIN SELECT RAISE(ABORT, 'append-only'); END;
                CREATE TRIGGER IF NOT EXISTS red_evidence_no_delete
                    BEFORE DELETE ON red_evidence BEGIN SELECT RAISE(ABORT, 'append-only'); END;
                CREATE TRIGGER IF NOT EXISTS red_findings_no_update
                    BEFORE UPDATE ON red_findings BEGIN SELECT RAISE(ABORT, 'append-only'); END;
                CREATE TRIGGER IF NOT EXISTS red_findings_no_delete
                    BEFORE DELETE ON red_findings BEGIN SELECT RAISE(ABORT, 'append-only'); END;
                CREATE TRIGGER IF NOT EXISTS red_pending_handoffs_no_update
                    BEFORE UPDATE ON red_pending_handoffs BEGIN SELECT RAISE(ABORT, 'append-only'); END;
                CREATE TRIGGER IF NOT EXISTS red_pending_handoffs_no_delete
                    BEFORE DELETE ON red_pending_handoffs BEGIN SELECT RAISE(ABORT, 'append-only'); END;
                CREATE TRIGGER IF NOT EXISTS red_coverage_gaps_no_update
                    BEFORE UPDATE ON red_coverage_gaps BEGIN SELECT RAISE(ABORT, 'append-only'); END;
                CREATE TRIGGER IF NOT EXISTS red_coverage_gaps_no_delete
                    BEFORE DELETE ON red_coverage_gaps BEGIN SELECT RAISE(ABORT, 'append-only'); END;
            """)

    def _require_scope(self, db: sqlite3.Connection, scope: RedScopeReference) -> None:
        try:
            self.store._require_scope(db, scope)
        except StoreConflict as exc:
            raise EvidenceDenied("assessment scope denied") from exc

    def add_receipt(self, receipt: ReceiptDTO) -> None:
        with self.store._connect() as db:
            self._require_scope(db, receipt.scope)
            op = db.execute(
                "SELECT payload FROM red_operations WHERE assessment_id=? AND operation_id=?",
                (receipt.scope.assessment_id, receipt.operation_id),
            ).fetchone()
            operation = (
                OperationDTO.model_validate_json(op["payload"]) if op is not None else None
            )
            if (
                operation is None
                or operation.plan_version != receipt.plan_version
                or operation.test_id != receipt.test_id
                or receipt.target_revision != receipt.scope.target_fingerprint
            ):
                raise EvidenceDenied("receipt references unknown operation or plan")
            try:
                db.execute(
                    "INSERT INTO red_receipts VALUES (?,?,?,?,?)",
                    (receipt.scope.assessment_id, receipt.receipt_id,
                     receipt.operation_id, receipt.plan_version, receipt.model_dump_json()),
                )
            except sqlite3.IntegrityError as exc:
                raise EvidenceDenied("duplicate receipt") from exc

    def add_receipt_with_evidence(
        self,
        receipt: ReceiptDTO,
        *,
        data: Mapping[str, object],
    ) -> EvidenceArtifactDTO:
        """Commit one receipt and its secret-free artifact as a single DB unit."""
        raw = json.dumps(data, ensure_ascii=True)
        if len(raw) > 16_384:
            raise EvidenceDenied("evidence exceeds size limit")
        content = json.dumps(
            _sanitized(data), sort_keys=True, separators=(",", ":")
        ).encode()
        digest = hashlib.sha256(content).hexdigest()
        relative = f"{receipt.scope.assessment_id}/{receipt.evidence_id}.json"
        directory = self.evidence_root / receipt.scope.assessment_id
        location = directory / f"{receipt.evidence_id}.json"
        artifact = EvidenceArtifactDTO(
            scope=receipt.scope,
            evidence_id=receipt.evidence_id,
            receipt_id=receipt.receipt_id,
            operation_id=receipt.operation_id,
            sha256=digest,
            content_type="application/json",
            storage_ref=relative,
        )
        created = False
        try:
            with self.store._connect() as db:
                self._require_scope(db, receipt.scope)
                row = db.execute(
                    "SELECT payload FROM red_operations WHERE assessment_id=? AND operation_id=?",
                    (receipt.scope.assessment_id, receipt.operation_id),
                ).fetchone()
                operation = (
                    OperationDTO.model_validate_json(row["payload"])
                    if row is not None else None
                )
                if (
                    operation is None
                    or operation.plan_version != receipt.plan_version
                    or operation.test_id != receipt.test_id
                    or receipt.target_revision != receipt.scope.target_fingerprint
                ):
                    raise EvidenceDenied("receipt references unknown operation or plan")
                directory.mkdir(mode=0o700, exist_ok=True)
                if directory.is_symlink() or directory.resolve() != directory:
                    raise EvidenceDenied("unsafe evidence directory")
                descriptor = os.open(
                    location,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                )
                created = True
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(content)
                    handle.flush()
                    os.fsync(handle.fileno())
                db.execute(
                    "INSERT INTO red_receipts VALUES (?,?,?,?,?)",
                    (
                        receipt.scope.assessment_id,
                        receipt.receipt_id,
                        receipt.operation_id,
                        receipt.plan_version,
                        receipt.model_dump_json(),
                    ),
                )
                db.execute(
                    "INSERT INTO red_evidence VALUES (?,?,?,?,?,?,?,?)",
                    (
                        receipt.scope.assessment_id,
                        receipt.evidence_id,
                        receipt.receipt_id,
                        receipt.operation_id,
                        digest,
                        artifact.content_type,
                        relative,
                        artifact.model_dump_json(),
                    ),
                )
        except (OSError, sqlite3.IntegrityError, sqlite3.DatabaseError) as exc:
            if created:
                location.unlink(missing_ok=True)
            raise EvidenceDenied("duplicate or unwritable receipt evidence") from exc
        except Exception:
            if created:
                location.unlink(missing_ok=True)
            raise
        return artifact

    def list_receipts(self, scope: RedScopeReference) -> tuple[ReceiptDTO, ...]:
        with self.store._connect() as db:
            self._require_scope(db, scope)
            rows = db.execute(
                "SELECT payload FROM red_receipts WHERE assessment_id=? ORDER BY rowid",
                (scope.assessment_id,),
            ).fetchall()
            try:
                return tuple(
                    ReceiptDTO.model_validate_json(row["payload"]) for row in rows
                )
            except ValidationError as exc:
                raise EvidenceDenied(
                    "legacy receipt is preserved but non-confirming; migration required"
                ) from exc

    def _record_verified_finding(self, finding: FindingDTO) -> None:
        """Internal verifier sink; callers cannot promote observations here."""
        with self.store._connect() as db:
            self._require_scope(db, finding.scope)
            self._add_finding(db, finding)

    @staticmethod
    def _add_finding(db: sqlite3.Connection, finding: FindingDTO) -> None:
        receipt_ids = set(finding.evidence_receipt_ids)
        referenced_receipts: list[ReceiptDTO] = []
        if receipt_ids:
            rows = db.execute(
                "SELECT payload FROM red_receipts WHERE assessment_id=?",
                (finding.scope.assessment_id,),
            ).fetchall()
            parsed = [ReceiptDTO.model_validate_json(row["payload"]) for row in rows]
            related = {
                item.receipt_id
                for item in parsed
                if item.operation_id == finding.operation_id
            }
            if not receipt_ids.issubset(related):
                raise EvidenceDenied("finding references unrelated receipt")
            referenced_receipts = [
                item for item in parsed if item.receipt_id in receipt_ids
            ]
        if finding.status in {FindingState.CONFIRMED, FindingState.NOT_CONFIRMED} and (
            not referenced_receipts
            or any(
                item.source != "controlled_http" or item.status != "completed"
                for item in referenced_receipts
            )
            or finding.provenance != "controlled_http"
            or finding.reproduction_scope != "registered_local_lab"
            or finding.evidence_id
            not in {item.evidence_id for item in referenced_receipts}
        ):
            raise EvidenceDenied("terminal finding requires controlled receipt evidence")
        if (
            finding.status == FindingState.SUSPECTED
            and finding.provenance == "zap"
            and (
                not referenced_receipts
                or any(item.source != "zap" for item in referenced_receipts)
            )
        ):
            raise EvidenceDenied("ZAP suspicion requires a ZAP receipt")
        existing = db.execute(
            "SELECT payload FROM red_findings WHERE assessment_id=? AND finding_id=?",
            (finding.scope.assessment_id, finding.finding_id),
        ).fetchone()
        if existing is not None:
            if FindingDTO.model_validate_json(existing["payload"]) != finding:
                raise EvidenceDenied("finding identity conflict")
            return
        db.execute(
            "INSERT INTO red_findings VALUES (?,?,?)",
            (finding.scope.assessment_id, finding.finding_id, finding.model_dump_json()),
        )

    def list_findings(self, scope: RedScopeReference) -> tuple[FindingDTO, ...]:
        with self.store._connect() as db:
            self._require_scope(db, scope)
            rows = db.execute(
                "SELECT payload FROM red_findings WHERE assessment_id=? ORDER BY rowid",
                (scope.assessment_id,),
            ).fetchall()
            return tuple(FindingDTO.model_validate_json(row["payload"]) for row in rows)

    def ensure_pending_handoff(self, finding: FindingDTO) -> PendingHandoffDTO:
        if finding.status != FindingState.CONFIRMED:
            raise EvidenceDenied("pending handoff requires a confirmed finding")
        handoff = PendingHandoffDTO(scope=finding.scope, finding_id=finding.finding_id)
        with self.store._connect() as db:
            self._require_scope(db, finding.scope)
            self._ensure_pending_handoff(db, finding, handoff)
        return handoff

    @staticmethod
    def _ensure_pending_handoff(
        db: sqlite3.Connection,
        finding: FindingDTO,
        handoff: PendingHandoffDTO,
    ) -> None:
        row = db.execute(
            "SELECT payload FROM red_findings WHERE assessment_id=? AND finding_id=?",
            (finding.scope.assessment_id, finding.finding_id),
        ).fetchone()
        if row is None or FindingDTO.model_validate_json(row["payload"]) != finding:
            raise EvidenceDenied("pending handoff requires the persisted finding")
        db.execute(
            "INSERT OR IGNORE INTO red_pending_handoffs VALUES (?,?,?)",
            (finding.scope.assessment_id, finding.finding_id, handoff.model_dump_json()),
        )

    def finalize_assessment(
        self,
        scope: RedScopeReference,
        coverage: CoverageDTO,
        findings: tuple[FindingDTO, ...],
    ) -> AssessmentDTO:
        """Atomically persist findings/handoffs and the terminal coverage state."""
        status = (
            AssessmentState.COMPLETED
            if coverage.coverage_complete
            else AssessmentState.COMPLETED_WITH_LIMITATIONS
        )
        with self.store._connect() as db:
            self._require_scope(db, scope)
            current, _ = self.store._load_assessment(db, scope.assessment_id)
            completed = AssessmentDTO.model_validate(
                current.model_copy(
                    update={
                        "status": status,
                        "workflow_complete": True,
                        "coverage": coverage,
                    }
                )
            )
            if current != completed:
                try:
                    require_assessment_transition(current.status, status)
                except ValueError as exc:
                    raise EvidenceDenied(
                        "assessment cannot be completed from its current state"
                    ) from exc
            persisted = tuple(
                FindingDTO.model_validate_json(row["payload"])
                for row in db.execute(
                    "SELECT payload FROM red_findings WHERE assessment_id=? ORDER BY rowid",
                    (scope.assessment_id,),
                ).fetchall()
            )
            if persisted != findings:
                raise EvidenceDenied(
                    "assessment finalization requires the complete verified finding set"
                )
            for finding in persisted:
                if finding.status == FindingState.CONFIRMED:
                    handoff = PendingHandoffDTO(
                        scope=finding.scope, finding_id=finding.finding_id
                    )
                    self._ensure_pending_handoff(db, finding, handoff)
            if current != completed:
                db.execute(
                    "UPDATE red_assessments SET assessment_json=? WHERE assessment_id=?",
                    (completed.model_dump_json(), scope.assessment_id),
                )
        return completed

    def list_pending_handoffs(
        self, scope: RedScopeReference
    ) -> tuple[PendingHandoffDTO, ...]:
        with self.store._connect() as db:
            self._require_scope(db, scope)
            rows = db.execute(
                "SELECT payload FROM red_pending_handoffs WHERE assessment_id=? ORDER BY rowid",
                (scope.assessment_id,),
            ).fetchall()
            return tuple(PendingHandoffDTO.model_validate_json(row["payload"]) for row in rows)

    def record_coverage_gaps(
        self,
        scope: RedScopeReference,
        gaps: tuple[CoverageGapDTO, ...],
    ) -> None:
        if any(item.scope != scope for item in gaps):
            raise EvidenceDenied("coverage gap scope mismatch")
        with self.store._connect() as db:
            self._require_scope(db, scope)
            for gap in gaps:
                existing = db.execute(
                    "SELECT payload FROM red_coverage_gaps WHERE assessment_id=? AND gap_id=?",
                    (scope.assessment_id, gap.gap_id),
                ).fetchone()
                if existing is not None:
                    if CoverageGapDTO.model_validate_json(existing["payload"]) != gap:
                        raise EvidenceDenied("coverage gap identity conflict")
                    continue
                db.execute(
                    "INSERT INTO red_coverage_gaps VALUES (?,?,?)",
                    (scope.assessment_id, gap.gap_id, gap.model_dump_json()),
                )

    def list_coverage_gaps(
        self, scope: RedScopeReference
    ) -> tuple[CoverageGapDTO, ...]:
        with self.store._connect() as db:
            self._require_scope(db, scope)
            rows = db.execute(
                "SELECT payload FROM red_coverage_gaps WHERE assessment_id=? ORDER BY rowid",
                (scope.assessment_id,),
            ).fetchall()
            return tuple(
                CoverageGapDTO.model_validate_json(row["payload"]) for row in rows
            )

    def append_event(
        self,
        scope: RedScopeReference,
        event_id: str,
        *,
        actor: str,
        action: str,
        outcome: str,
        details: Mapping[str, object] | None = None,
        occurred_at: datetime | None = None,
    ) -> None:
        identifier = TypeAdapter(Identifier)
        for value in (event_id, actor, action, outcome):
            identifier.validate_python(value)
        timestamp = occurred_at or datetime.now(UTC)
        if timestamp.tzinfo is None:
            raise EvidenceDenied("event timestamp requires timezone")
        raw = json.dumps(details or {}, ensure_ascii=True)
        if len(raw) > 16_384:
            raise EvidenceDenied("event metadata exceeds size limit")
        filtered = json.dumps(_sanitized(details or {}), sort_keys=True)
        with self.store._connect() as db:
            self._require_scope(db, scope)
            try:
                db.execute(
                    "INSERT INTO red_events"
                    "(assessment_id,event_id,actor,action,outcome,occurred_at,details)"
                    " VALUES (?,?,?,?,?,?,?)",
                    (scope.assessment_id, event_id, actor, action,
                     outcome, timestamp.isoformat(), filtered),
                )
            except sqlite3.IntegrityError as exc:
                raise EvidenceDenied("duplicate event") from exc

    def transition_stage(
        self,
        stage: StageDTO,
        event: StageTransitionEventDTO,
    ) -> None:
        """Atomically persist one legal stage state and its typed timeline event."""
        if (
            event.scope != stage.scope
            or event.stage != stage.stage
            or event.status != stage.status
        ):
            raise EvidenceDenied("stage transition event mismatch")
        with self.store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._require_scope(db, stage.scope)
            assessment, _ = self.store._load_assessment(
                db, stage.scope.assessment_id
            )
            if assessment.status != AssessmentState.RUNNING:
                raise EvidenceDenied("stage transition requires a running assessment")
            row = db.execute(
                "SELECT payload FROM red_stages WHERE assessment_id=? AND stage=?",
                (stage.scope.assessment_id, stage.stage),
            ).fetchone()
            previous = (
                StageDTO.model_validate_json(row["payload"]).status
                if row is not None
                else StageState.NOT_STARTED
            )
            if event.previous_status != previous:
                raise EvidenceDenied("stage transition does not match persisted state")
            try:
                require_stage_transition(previous, stage.status)
            except ValueError as exc:
                raise EvidenceDenied("invalid stage transition") from exc
            if stage.plan_version is not None:
                plan = db.execute(
                    "SELECT 1 FROM red_plans WHERE assessment_id=? AND plan_version=?",
                    (stage.scope.assessment_id, stage.plan_version),
                ).fetchone()
                if plan is None:
                    raise EvidenceDenied("stage references unknown plan")
            details = json.dumps(
                {
                    "stage": stage.stage,
                    "previous_status": previous.value,
                    "status": stage.status.value,
                    "phase": event.phase,
                },
                sort_keys=True,
            )
            try:
                db.execute(
                    """INSERT INTO red_stages (assessment_id,stage,plan_version,payload)
                       VALUES (?,?,?,?)
                       ON CONFLICT(assessment_id,stage) DO UPDATE SET
                           plan_version=excluded.plan_version,payload=excluded.payload""",
                    (
                        stage.scope.assessment_id,
                        stage.stage,
                        stage.plan_version,
                        stage.model_dump_json(),
                    ),
                )
                db.execute(
                    """INSERT INTO red_events
                       (assessment_id,event_id,actor,action,outcome,occurred_at,details)
                       VALUES (?,?,?,?,?,?,?)""",
                    (
                        stage.scope.assessment_id,
                        event.event_id,
                        "red-orchestrator",
                        "stage-transition",
                        stage.status.value,
                        event.occurred_at.isoformat(),
                        details,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise EvidenceDenied("duplicate stage transition event") from exc

    def list_stage_events(
        self, scope: RedScopeReference
    ) -> tuple[StageTransitionEventDTO, ...]:
        with self.store._connect() as db:
            self._require_scope(db, scope)
            rows = db.execute(
                """SELECT event_id,occurred_at,details FROM red_events
                   WHERE assessment_id=? AND action='stage-transition'
                   ORDER BY sequence""",
                (scope.assessment_id,),
            ).fetchall()
        events = []
        for row in rows:
            details = json.loads(row["details"])
            events.append(
                StageTransitionEventDTO(
                    scope=scope,
                    event_id=row["event_id"],
                    stage=details["stage"],
                    previous_status=details["previous_status"],
                    status=details["status"],
                    phase=details["phase"],
                    occurred_at=datetime.fromisoformat(row["occurred_at"]),
                )
            )
        return tuple(events)

    def list_events(self, scope: RedScopeReference) -> list[dict]:
        with self.store._connect() as db:
            self._require_scope(db, scope)
            rows = db.execute(
                "SELECT event_id,actor,action,outcome,occurred_at,details"
                " FROM red_events WHERE assessment_id=? ORDER BY sequence",
                (scope.assessment_id,),
            ).fetchall()
            return [
                {**dict(row), "details": json.loads(row["details"])}
                for row in rows
            ]

    def write_evidence(
        self,
        scope: RedScopeReference,
        evidence_id: str,
        *,
        receipt_id: str,
        data: Mapping[str, object],
    ) -> EvidenceArtifactDTO:
        TypeAdapter(Identifier).validate_python(evidence_id)
        if not isinstance(data, Mapping):
            raise EvidenceDenied("evidence must be structured metadata")
        try:
            raw = json.dumps(data, ensure_ascii=True)
        except (TypeError, ValueError) as exc:
            raise EvidenceDenied("unsupported evidence content") from exc
        if len(raw) > 16_384:
            raise EvidenceDenied("evidence exceeds size limit")
        content = json.dumps(_sanitized(data), sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha256(content).hexdigest()
        relative = f"{scope.assessment_id}/{evidence_id}.json"
        directory = self.evidence_root / scope.assessment_id
        location = directory / f"{evidence_id}.json"
        with self.store._connect() as db:
            self._require_scope(db, scope)
            row = db.execute(
                "SELECT operation_id FROM red_receipts WHERE assessment_id=? AND receipt_id=?",
                (scope.assessment_id, receipt_id),
            ).fetchone()
            if row is None:
                raise EvidenceDenied("unknown receipt")
            artifact = EvidenceArtifactDTO(
                scope=scope, evidence_id=evidence_id, receipt_id=receipt_id,
                operation_id=row["operation_id"], sha256=digest,
                content_type="application/json", storage_ref=relative,
            )
            if db.execute(
                "SELECT 1 FROM red_evidence WHERE assessment_id=? AND evidence_id=?",
                (scope.assessment_id, evidence_id),
            ).fetchone():
                raise EvidenceDenied("duplicate evidence")
            directory.mkdir(mode=0o700, exist_ok=True)
            if directory.is_symlink() or directory.resolve() != directory:
                raise EvidenceDenied("unsafe evidence directory")
            created = False
            try:
                fd = os.open(location, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                created = True
                with os.fdopen(fd, "wb") as handle:
                    handle.write(content)
                    handle.flush()
                    os.fsync(handle.fileno())
                db.execute(
                    "INSERT INTO red_evidence VALUES (?,?,?,?,?,?,?,?)",
                    (scope.assessment_id, evidence_id, receipt_id, row["operation_id"],
                     digest, artifact.content_type, relative, artifact.model_dump_json()),
                )
            except (OSError, sqlite3.DatabaseError) as exc:
                if created:
                    location.unlink(missing_ok=True)
                raise EvidenceDenied("duplicate or unwritable evidence") from exc
        return artifact

    def list_evidence(self, scope: RedScopeReference) -> tuple[EvidenceArtifactDTO, ...]:
        """Read metadata after restart without accessing raw file bytes."""
        with self.store._connect() as db:
            self._require_scope(db, scope)
            rows = db.execute(
                "SELECT metadata_json FROM red_evidence WHERE assessment_id=? ORDER BY rowid",
                (scope.assessment_id,),
            ).fetchall()
            return tuple(EvidenceArtifactDTO.model_validate_json(row["metadata_json"])
                         for row in rows)

    def read_evidence(self, scope: RedScopeReference, evidence_id: str) -> bytes:
        TypeAdapter(Identifier).validate_python(evidence_id)
        with self.store._connect() as db:
            self._require_scope(db, scope)
            row = db.execute(
                "SELECT metadata_json FROM red_evidence WHERE assessment_id=? AND evidence_id=?",
                (scope.assessment_id, evidence_id),
            ).fetchone()
            if row is None:
                raise EvidenceDenied("unknown evidence")
            try:
                artifact = EvidenceArtifactDTO.model_validate_json(row["metadata_json"])
                if artifact.scope != scope:
                    raise EvidenceDenied("evidence scope mismatch")
                location = self.evidence_root / artifact.storage_ref
                if location.is_symlink() or not location.resolve(strict=True).is_relative_to(self.evidence_root):
                    raise EvidenceDenied("unsafe evidence path")
                fd = os.open(location, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(fd, "rb") as handle:
                    content = handle.read(16_385)
            except (OSError, ValueError, ValidationError) as exc:
                raise EvidenceDenied("unsafe or unavailable evidence path") from exc
            if hashlib.sha256(content).hexdigest() != artifact.sha256:
                raise EvidenceDenied("evidence integrity verification failed")
            return content
