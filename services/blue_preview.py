"""Read-only Blue patch preview from externally pinned registered Red evidence.

A deterministic scenario mapping is NOT an agent's classification or a
research-qualified detection. This module never dispatches, applies, or replays.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from hashlib import sha256
from pathlib import Path
from urllib.parse import quote
from uuid import UUID

from security_tests.registry import SecurityTestRegistry
from services.bound_registered_red_evidence import (
    BoundRedEvidenceError, verify_archived_registered_red,
)
from services.target_registry import TargetRegistry
from services.job_dispatch import AdmittedDispatchBlocked, _reviewed_sql_scope


class BluePreviewBlocked(RuntimeError):
    """No trusted source-grounded development preview may be recorded."""


def ensure_preview_table(conn: sqlite3.Connection) -> None:
    conn.execute("""CREATE TABLE IF NOT EXISTS blue_previews (
        job_id TEXT PRIMARY KEY,
        receipt_sha256 TEXT NOT NULL,
        prepared_json TEXT NOT NULL
    )""")


def read_blue_preview(conn: sqlite3.Connection, job_id: str) -> dict:
    ensure_preview_table(conn)
    row = conn.execute(
        "SELECT prepared_json FROM blue_previews WHERE job_id=?", (str(UUID(job_id)),)
    ).fetchone()
    return json.loads(row[0]) if row else {
        "job_id": str(UUID(job_id)), "status": "not_prepared",
        "model_decision_used": False, "patch_applied": False,
        "security_replayed": False, "final_research_qualified": False,
    }


def prepare_blue_preview(
    *, database: Path, job_id: str, source_root: Path, evidence_dir: Path,
    admission_path: Path, admission_sha256: str, receipt_sha256: str,
) -> dict:
    """Prepare one write-once compiler diff after independent archive validation."""
    canonical = str(UUID(job_id))
    source_root, evidence_dir, admission_path = map(
        Path, (source_root, evidence_dir, admission_path)
    )
    database = Path(database)
    if database.is_symlink() or not database.is_file():
        raise BluePreviewBlocked("Existing workspace database required")
    try:
        with sqlite3.connect(
            "file:" + quote(str(database.absolute())) + "?mode=rw",
            uri=True, timeout=5,
        ) as conn:
            conn.row_factory = sqlite3.Row
            ensure_preview_table(conn)
            job = conn.execute(
                "SELECT state,scenario,route,registered_test_id FROM jobs WHERE id=?",
                (canonical,),
            ).fetchone()
            intent = conn.execute(
                "SELECT admission_sha256 FROM dispatch_intents WHERE job_id=?",
                (canonical,),
            ).fetchone()
            receipt = conn.execute(
                "SELECT receipt_sha256,outcome FROM execution_receipts WHERE job_id=?",
                (canonical,),
            ).fetchone()
            existing = conn.execute(
                "SELECT 1 FROM blue_previews WHERE job_id=?", (canonical,),
            ).fetchone()
        if existing:
            raise BluePreviewBlocked("A Blue preview is already recorded")
        if (job is None or job["state"] != "scope_reviewed"
                or job["scenario"] != "sql" or job["route"] != "/sql-injection/login"
                or job["registered_test_id"] != "sqli-login-bypass-001"
                or intent is None or receipt is None
                or intent["admission_sha256"] != admission_sha256
                or receipt["receipt_sha256"] != receipt_sha256
                or receipt["outcome"] != "baseline_exploit_confirmed"):
            raise BluePreviewBlocked("A confirmed, receipt-matched SQLi job is required")
        # The original, scope-reviewed SQLi plan must still exactly match the
        # trusted registry. Receipt identity alone does not protect against
        # later changes to saved job limits or target scope.
        _reviewed_sql_scope(database, canonical, source_root)
        registry = TargetRegistry.from_directories(
            targets_dir=source_root / "config/targets",
            security_tests_dir=source_root / "config/security_tests",
        )
        bound = verify_archived_registered_red(
            source_root=source_root, dispatch_root=source_root,
            evidence_dir=evidence_dir, admission_path=admission_path,
            admission_sha256=admission_sha256, receipt_sha256=receipt_sha256,
            registry=registry, implementations=SecurityTestRegistry.default(),
        )
        expected_run = "mars-" + UUID(canonical).hex
        if (bound.run_id != expected_run or bound.case_id != expected_run
                or bound.test_id != "sqli-login-bypass-001"
                or bound.observation.exploit_confirmed is not True):
            raise BluePreviewBlocked("Pinned evidence does not belong to this SQLi job")

        # This existing compiler takes a trusted scenario template as input,
        # not a model-generated classification. It works in a temporary copy.
        from dashboard.api.operator_service import prepare_preview
        proposal = prepare_preview("sql")
        if (proposal["prepared"] is not True
                or proposal["applied"] is not False
                or proposal["verified"] is not False
                or not proposal["prepared_diff_sha256"]
                or not proposal["diff_preview"]):
            raise BluePreviewBlocked("Existing trusted compiler did not prepare a diff")
        result = {
            "job_id": canonical, "status": "prepared",
            "origin": "trusted_deterministic_builder", "model_decision_used": False,
            "red_run_id": bound.run_id, "red_receipt_sha256": receipt_sha256,
            "registered_test_id": bound.test_id,
            "source_file": "dummy_apps/vulnerable_store/app/scenario_routes.py",
            "diff_sha256": proposal["prepared_diff_sha256"],
            "diff_preview": proposal["diff_preview"],
            "patch_applied": False, "security_replayed": False,
            "final_research_qualified": False,
            "note": ("Registered Red evidence was independently revalidated. "
                     "Source mapping is deterministic, not an AI Blue decision. "
                     "The proposed patch is not applied or security-replayed."),
        }
        serialized = json.dumps(result, sort_keys=True, separators=(",", ":"))
        with sqlite3.connect(
            "file:" + quote(str(database.absolute())) + "?mode=rw",
            uri=True, timeout=5,
        ) as conn:
            conn.execute("BEGIN IMMEDIATE")
            ensure_preview_table(conn)
            current = conn.execute(
                "SELECT receipt_sha256,outcome FROM execution_receipts WHERE job_id=?",
                (canonical,),
            ).fetchone()
            if current != (receipt_sha256, "baseline_exploit_confirmed"):
                raise BluePreviewBlocked("Recorded Red evidence changed during preparation")
            try:
                conn.execute(
                    "INSERT INTO blue_previews(job_id,receipt_sha256,prepared_json) VALUES (?,?,?)",
                    (canonical, receipt_sha256, serialized),
                )
            except sqlite3.IntegrityError as exc:
                raise BluePreviewBlocked("A Blue preview is already recorded") from exc
            sequence = conn.execute(
                "SELECT COALESCE(MAX(sequence),0)+1 FROM job_events WHERE job_id=?",
                (canonical,),
            ).fetchone()[0]
            from datetime import datetime, timezone
            conn.execute(
                "INSERT INTO job_events(job_id,sequence,event,occurred_at) VALUES (?,?,?,?)",
                (canonical, sequence, "deterministic_patch_prepared",
                 datetime.now(timezone.utc).isoformat()),
            )
        return result
    except BluePreviewBlocked:
        raise
    except (BoundRedEvidenceError, AdmittedDispatchBlocked,
            OSError, ValueError, KeyError, sqlite3.Error) as exc:
        raise BluePreviewBlocked("Red evidence or trusted compiler was rejected") from exc


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare a deterministic SQLi patch preview from independently pinned Red evidence"
    )
    for name in ("database", "source-root", "evidence-dir", "admission-path"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("job-id", "admission-sha256", "receipt-sha256"):
        parser.add_argument("--" + name, required=True)
    args = vars(parser.parse_args())
    params = {key.replace("-", "_"): value for key, value in args.items()}
    print(json.dumps(prepare_blue_preview(**params), indent=2))


if __name__ == "__main__":
    main()
