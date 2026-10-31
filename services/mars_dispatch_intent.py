"""Durable single-attempt claim primitive for a future externally admitted Red worker.

This is NOT a dispatcher and does NOT verify independent admission. The future
W3 worker must verify clean Git pins, the admission, runtime and registry before
calling reserve_once. No HTTP endpoint exposes this primitive.

Once reserved, the outcome is UNKNOWN until separate independently evidenced
reconciliation. Never release a reservation or automatically retry it.
"""
from __future__ import annotations

import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
from uuid import UUID


class DispatchIntentBlocked(RuntimeError):
    """The attempt cannot be safely claimed."""


def ensure_intent_table(conn: sqlite3.Connection) -> None:
    conn.execute("""CREATE TABLE IF NOT EXISTS dispatch_intents (
        job_id TEXT PRIMARY KEY,
        attempt INTEGER NOT NULL CHECK (attempt = 1),
        scope_sha256 TEXT NOT NULL,
        admission_sha256 TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state = 'outcome_unknown'),
        recorded_at TEXT NOT NULL
    )""")


@contextmanager
def _open_existing(database: Path):
    database = Path(database)
    if database.is_symlink() or not database.is_file():
        raise DispatchIntentBlocked("Existing workspace database required")
    # mode=rw prevents accidental creation of a new workspace.
    conn = sqlite3.connect("file:" + quote(str(database.absolute())) + "?mode=rw",
                           uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _fingerprint(value: str) -> bool:
    return (isinstance(value, str)
            and re.fullmatch(r"[0-9a-f]{64}", value) is not None
            and value != "0" * 64)


def reserve_once(database: Path, job_id: str, scope_sha256: str,
                 admission_sha256: str) -> dict:
    """Atomically write an UNKNOWN intent before any future external command.

    admission_sha256 is only a *reference* to an external pinned admission.
    Checking that admission's authenticity belongs to the separate worker gate.
    """
    try:
        canonical_id = str(UUID(str(job_id)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise DispatchIntentBlocked("Invalid job identifier") from exc
    if not _fingerprint(scope_sha256) or not _fingerprint(admission_sha256):
        raise DispatchIntentBlocked("Valid scope and admission fingerprints required")
    with _open_existing(Path(database)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        ensure_intent_table(conn)
        row = conn.execute(
            "SELECT state, scope_sha256 FROM jobs WHERE id=?", (canonical_id,),
        ).fetchone()
        if row is None or row["state"] != "scope_reviewed":
            raise DispatchIntentBlocked("Scope-reviewed job required")
        if row["scope_sha256"] != scope_sha256:
            raise DispatchIntentBlocked("Saved job fingerprint mismatch")
        # Unique PRIMARY KEY and BEGIN IMMEDIATE provide an across-process
        # first-writer-wins claim. No retries, lease expiry, or reset path.
        timestamp = datetime.now(timezone.utc).isoformat()
        try:
            conn.execute(
                "INSERT INTO dispatch_intents "
                "(job_id,attempt,scope_sha256,admission_sha256,state,recorded_at) "
                "VALUES (?,1,?,?,'outcome_unknown',?)",
                (canonical_id, scope_sha256, admission_sha256, timestamp),
            )
        except sqlite3.IntegrityError as exc:
            raise DispatchIntentBlocked("Dispatch intent already recorded; never retry") from exc
        next_sequence = conn.execute(
            "SELECT COALESCE(MAX(sequence),0)+1 FROM job_events WHERE job_id=?",
            (canonical_id,),
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO job_events (job_id,sequence,event,occurred_at) "
            "VALUES (?,?,?,?)",
            (canonical_id, next_sequence, "dispatch_intent_recorded", timestamp),
        )
    return read_intent(database, canonical_id)


def read_intent(database: Path, job_id: str) -> dict | None:
    """Read the durable unknown-outcome marker; never change it."""
    try:
        canonical_id = str(UUID(str(job_id)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise DispatchIntentBlocked("Invalid job identifier") from exc
    with _open_existing(Path(database)) as conn:
        found = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='dispatch_intents'",
        ).fetchone()
        if not found:
            return None
        record = conn.execute(
            "SELECT job_id,attempt,scope_sha256,admission_sha256,state,recorded_at "
            "FROM dispatch_intents WHERE job_id=?", (canonical_id,),
        ).fetchone()
        return dict(record) if record else None
