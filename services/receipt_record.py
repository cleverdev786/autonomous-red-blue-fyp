"""Write-once link from isolated executor receipts to an audited workspace job.

No execution, automatic retry, or research qualification is performed here.
"""
from __future__ import annotations

import os
import sqlite3
import stat
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from urllib.parse import quote
from uuid import UUID

from schemas.registered_red_observation import DeterministicRedObservation
from services.isolated_compose_executor import RealExecutionReceipt

SCOPE = "development_only_not_final_research"


class ReceiptBlocked(RuntimeError):
    """Untrusted, duplicate or unassociated evidence must not be published."""


def ensure_receipt_table(conn: sqlite3.Connection) -> None:
    conn.execute("""CREATE TABLE IF NOT EXISTS execution_receipts (
        job_id TEXT PRIMARY KEY,
        admission_sha256 TEXT NOT NULL,
        receipt_sha256 TEXT NOT NULL,
        observation_sha256 TEXT,
        run_id TEXT NOT NULL,
        case_id TEXT NOT NULL,
        outcome TEXT NOT NULL,
        reason TEXT NOT NULL,
        recorded_at TEXT NOT NULL
    )""")


def read_receipt(conn: sqlite3.Connection, job_id: str) -> dict:
    """Read only a verified receipt summary or an explicit unknown status."""
    canonical = str(UUID(job_id))
    ensure_receipt_table(conn)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM execution_receipts WHERE job_id=?", (canonical,)
    ).fetchone()
    if row is not None:
        return {
            "job_id": canonical, "status": "receipt_recorded", "scope": SCOPE,
            **{key: row[key] for key in (
                "admission_sha256", "receipt_sha256", "observation_sha256",
                "run_id", "case_id", "outcome", "reason", "recorded_at",
            )},
        }
    intent = conn.execute(
        "SELECT 1 FROM dispatch_intents WHERE job_id=?", (canonical,)
    ).fetchone()
    return {
        "job_id": canonical, "status": "outcome_unknown" if intent else "not_dispatched",
        "scope": SCOPE,
    }


def _bytes_new_file(path: Path, limit: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ReceiptBlocked("Evidence file missing or symlinked")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_size > limit:
            raise ReceiptBlocked("Evidence file type or size refused")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ReceiptBlocked("Evidence file exceeded limit")
        return data
    finally:
        os.close(fd)


def record_receipt(
    database: Path, job_id: str, evidence_root: Path, receipt: RealExecutionReceipt
) -> dict:
    """Persist one result only after matching its external bytes and admission intent."""
    canonical = str(UUID(job_id))
    if not isinstance(receipt, RealExecutionReceipt):
        raise ReceiptBlocked("An actual typed isolated executor receipt is required")
    case_id = "mars-" + UUID(canonical).hex
    if (receipt.case_id != case_id or receipt.run_id != case_id
            or receipt.scenario_id != "sqli-login-001"):
        raise ReceiptBlocked("Receipt does not belong to this registered SQLi job")
    evidence_root = Path(evidence_root)
    case = evidence_root / case_id
    if (evidence_root.is_symlink() or not evidence_root.is_dir()
            or case.is_symlink() or not case.is_dir()):
        raise ReceiptBlocked("External evidence directory is missing or symlinked")
    raw = _bytes_new_file(case / "receipt.json", 16_384)
    if raw != (receipt.model_dump_json(indent=2) + "\n").encode():
        raise ReceiptBlocked("Stored receipt bytes disagree with executor return")
    if receipt.outcome in ("baseline_exploit_confirmed", "baseline_exploit_not_observed"):
        if receipt.observation_sha256 is None:
            raise ReceiptBlocked("A confirmed baseline outcome requires an observation")
    if receipt.observation_sha256:
        raw_observation = _bytes_new_file(case / "observation.json", 1_048_576)
        if sha256(raw_observation).hexdigest() != receipt.observation_sha256:
            raise ReceiptBlocked("Observation fingerprint mismatch")
        try:
            observed = DeterministicRedObservation.model_validate_json(raw_observation)
        except ValueError as exc:
            raise ReceiptBlocked("Registered observation schema invalid") from exc
        if (observed.scenario_id != receipt.scenario_id
                or observed.registered_test_id != "sqli-login-bypass-001"
                or observed.phase != "vulnerable_baseline"
                or observed.evidence_scope != "reported_controlled_executor"
                or observed.execution.run_id != receipt.run_id
                or observed.execution.attempt_number != 1):
            raise ReceiptBlocked("Observation is not from this registered execution")
        expected = ("inconclusive" if not observed.test_completed
                    else "baseline_exploit_confirmed" if observed.exploit_confirmed
                    else "baseline_exploit_not_observed")
        if receipt.outcome != expected:
            raise ReceiptBlocked("Receipt outcome contradicts registered observation")
    database = Path(database)
    if database.is_symlink() or not database.is_file():
        raise ReceiptBlocked("Existing workspace required")
    with sqlite3.connect(
        "file:" + quote(str(database.absolute())) + "?mode=rw", uri=True, timeout=5,
    ) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("BEGIN IMMEDIATE")
        ensure_receipt_table(conn)
        job = conn.execute(
            "SELECT state,scenario,registered_test_id FROM jobs WHERE id=?", (canonical,)
        ).fetchone()
        intent = conn.execute(
            "SELECT admission_sha256 FROM dispatch_intents WHERE job_id=?",
            (canonical,),
        ).fetchone()
        if (job is None or job["state"] != "scope_reviewed"
                or job["scenario"] != "sql"
                or job["registered_test_id"] != "sqli-login-bypass-001"
                or intent is None
                or intent["admission_sha256"] != receipt.admission_sha256):
            raise ReceiptBlocked("No matching reviewed job and durable admission intent")
        now = datetime.now(timezone.utc).isoformat()
        try:
            conn.execute(
                "INSERT INTO execution_receipts "
                "(job_id,admission_sha256,receipt_sha256,observation_sha256,"
                "run_id,case_id,outcome,reason,recorded_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (canonical, receipt.admission_sha256, sha256(raw).hexdigest(),
                 receipt.observation_sha256, receipt.run_id, receipt.case_id,
                 receipt.outcome, receipt.reason, now),
            )
        except sqlite3.IntegrityError as exc:
            raise ReceiptBlocked("A receipt is already recorded; never overwrite") from exc
        sequence = conn.execute(
            "SELECT COALESCE(MAX(sequence),0)+1 FROM job_events WHERE job_id=?",
            (canonical,),
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO job_events (job_id,sequence,event,occurred_at) "
            "VALUES (?,?,?,?)",
            (canonical, sequence, "execution_receipt_recorded", now),
        )
        return read_receipt(conn, canonical)
