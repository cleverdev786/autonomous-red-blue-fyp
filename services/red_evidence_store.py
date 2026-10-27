"""Append-only, scope-bound Red timeline and redacted evidence files (T06).

Use only from trusted backend code. HTTP operator authentication is a later gate.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from schemas.common import Identifier
from pydantic import TypeAdapter, ValidationError
from schemas.red_team import RedScopeReference
from schemas.red_team_state import EvidenceArtifactDTO, ReceiptDTO
from services.red_assessment_store import RedAssessmentStore, StoreConflict


class EvidenceDenied(ValueError):
    """Invalid provenance, unsafe access, duplicate receipt or corrupted content."""


_SAFE_DETAIL_KEYS = frozenset(
    {"stage", "reason_code", "operation_id", "status", "test_id",
     "endpoint_id", "method", "status_code", "oracle_id"}
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
                "SELECT plan_version FROM red_operations WHERE assessment_id=? AND operation_id=?",
                (receipt.scope.assessment_id, receipt.operation_id),
            ).fetchone()
            if op is None or op["plan_version"] != receipt.plan_version:
                raise EvidenceDenied("receipt references unknown operation or plan")
            try:
                db.execute(
                    "INSERT INTO red_receipts VALUES (?,?,?,?,?)",
                    (receipt.scope.assessment_id, receipt.receipt_id,
                     receipt.operation_id, receipt.plan_version, receipt.model_dump_json()),
                )
            except sqlite3.IntegrityError as exc:
                raise EvidenceDenied("duplicate receipt") from exc

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
        timestamp = occurred_at or datetime.now(timezone.utc)
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
