"""Derive Q8 classification and source-localization inputs from bound Red HTTP exchanges.

Read only. No model inference, Red dispatch, patch authority, or evaluator truth.
The request parameters originate from the frozen registered test definitions;
the captured executor contains responses but not original HTTP request bodies.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from urllib.parse import quote
from uuid import UUID

from security_tests.registry import SecurityTestRegistry
from services.bound_registered_red_evidence import (
    BoundRedEvidenceError, verify_archived_registered_red,
)
from services.job_dispatch import AdmittedDispatchBlocked, _reviewed_sql_scope
from services.q8_c12_development_bridge import (
    Q8DevelopmentBlocked, classification_request, localization_request,
)
from services.target_registry import TargetRegistry


class BlueInputBlocked(RuntimeError):
    """Recorded SQLi evidence is not safe to present as observed model input."""


def build_blue_input(
    *, database: Path, job_id: str, source_root: Path, evidence_dir: Path,
    admission_path: Path, admission_sha256: str, receipt_sha256: str,
) -> dict:
    canonical = str(UUID(job_id))
    database, source_root = Path(database), Path(source_root)
    evidence_dir, admission_path = Path(evidence_dir), Path(admission_path)
    if database.is_symlink() or not database.is_file():
        raise BlueInputBlocked("Existing MARS workspace required")
    try:
        _reviewed_sql_scope(database, canonical, source_root)
        with sqlite3.connect(
            "file:" + quote(str(database.absolute())) + "?mode=ro",
            uri=True, timeout=5,
        ) as conn:
            conn.row_factory = sqlite3.Row
            intent = conn.execute(
                "SELECT admission_sha256 FROM dispatch_intents WHERE job_id=?",
                (canonical,),
            ).fetchone()
            receipt = conn.execute(
                "SELECT receipt_sha256,outcome FROM execution_receipts WHERE job_id=?",
                (canonical,),
            ).fetchone()
        if (intent is None or receipt is None
                or intent["admission_sha256"] != admission_sha256
                or receipt["receipt_sha256"] != receipt_sha256
                or receipt["outcome"] != "baseline_exploit_confirmed"):
            raise BlueInputBlocked("Matching successful and recorded Red receipt required")
        registry = TargetRegistry.from_directories(
            targets_dir=source_root / "config" / "targets",
            security_tests_dir=source_root / "config" / "security_tests",
        )
        tests = SecurityTestRegistry.default()
        bound = verify_archived_registered_red(
            source_root=source_root, dispatch_root=source_root,
            evidence_dir=evidence_dir, admission_path=admission_path,
            admission_sha256=admission_sha256, receipt_sha256=receipt_sha256,
            registry=registry, implementations=tests,
        )
        expected_run = "mars-" + UUID(canonical).hex
        if (bound.run_id != expected_run or bound.case_id != expected_run
                or bound.test_id != "sqli-login-bypass-001"
                or bound.endpoint_id != "scenario-sqli-login"):
            raise BlueInputBlocked("Red provenance belongs to another job or test")

        # Reconstruct only request parameters declared by trusted registered steps.
        steps = tests.get(bound.test_id).build_steps()
        responses = bound.observation.execution.exchanges
        if len(steps) != 2 or len(responses) != 2:
            raise BlueInputBlocked("Two matching registered HTTP exchanges required")
        rows = []
        for step, observed in zip(steps, responses, strict=True):
            method = getattr(step.method, "value", step.method)
            if (step.step_id != observed.step_id
                    or step.endpoint_id != observed.endpoint_id
                    or method != observed.method or step.json_body is None):
                raise BlueInputBlocked("Captured step identity mismatch")
            rows.append({
                "method": method, "parameters": dict(step.json_body),
                "response_excerpt": observed.body_excerpt,
                "status_code": observed.status_code,
            })
        pair = {"route": "/sql-injection/login", "observations": rows}
        classification = classification_request(pair)
        localization = localization_request(pair=pair, project_root=source_root)
        return {
            "job_id": canonical,
            "red_run_id": bound.run_id,
            "red_receipt_sha256": receipt_sha256,
            "origin": "registered_steps_plus_captured_responses",
            "original_http_request_bodies_captured": False,
            "classification_request": classification,
            "localization_request": localization,
            "model_executed": False,
            "source_analysis_authorized": False,
            "patch_prepared": False,
            "final_research_qualified": False,
        }
    except BlueInputBlocked:
        raise
    except (
        AdmittedDispatchBlocked, BoundRedEvidenceError, Q8DevelopmentBlocked,
        OSError, ValueError, KeyError, TypeError, sqlite3.Error,
    ) as exc:
        raise BlueInputBlocked("Registered Red evidence could not be bound to model input") from exc


def main() -> None:
    parser = argparse.ArgumentParser(description="Export recorded SQLi observations to Q8 request schemas")
    for name in ("database", "source-root", "evidence-dir", "admission-path"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("job-id", "admission-sha256", "receipt-sha256"):
        parser.add_argument("--" + name, required=True)
    print(json.dumps(build_blue_input(**vars(parser.parse_args())), indent=2))


if __name__ == "__main__":
    main()
