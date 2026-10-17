"""Connect one reviewed registered MARS job to the independently admitted Red runner.

This is a local engineering entrypoint, not a web endpoint or research approval.
It never creates an admission, starts Docker, resets a target, or retries a test.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path
from urllib.parse import quote
from uuid import UUID

from schemas.registered_red_observation import REGISTERED
from security_tests.registry import SecurityTestRegistry
from services.isolated_compose_executor import (
    IsolatedDockerExecutor,
    load_real_admission,
)
from services.mars_dispatch_intent import reserve_once
from services.receipt_record import record_receipt
from services.registered_assessment_plan import SCENARIO_IDENTITIES, registered_catalog
from services.target_registry import TargetRegistry


class AdmittedDispatchBlocked(RuntimeError):
    """The job or independently approved admission is not an exact match."""


def _reviewed_registered_scope(database: Path, job_id: str, root: Path) -> tuple[str, str]:
    if database.is_symlink() or not database.is_file():
        raise AdmittedDispatchBlocked("Existing, non-symlink workspace required")
    with sqlite3.connect(
        "file:" + quote(str(database.absolute())) + "?mode=ro", uri=True,
    ) as conn:
        conn.row_factory = sqlite3.Row
        job = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if job is None or job["state"] != "scope_reviewed":
            raise AdmittedDispatchBlocked("A reviewed, registered job is required")
        identity = SCENARIO_IDENTITIES.get(job["scenario"])
        if (identity is None or job["route"] != identity[0]
                or job["registered_test_id"] != REGISTERED[identity[1]][0]
                or job["target_id"] != "vulnerable-store"):
            raise AdmittedDispatchBlocked("Registered scenario identity mismatch")
        plan = conn.execute("SELECT * FROM plans WHERE id=?", (job["plan_id"],)).fetchone()
    if plan is None or any(plan[key] != job[key] for key in (
        "name", "scenario", "target_id", "registered_test_id", "route"
    )):
        raise AdmittedDispatchBlocked("Saved plan and job no longer agree")
    catalog = registered_catalog(root)
    matching = [r for r in catalog["registered_assessments"]
                if r["route"] == job["route"] and r["trusted_registry_verified"]
                and not r["execution_enabled"]]
    if len(matching) != 1:
        raise AdmittedDispatchBlocked("Trusted scenario mapping is not unique")
    scope = matching[0]
    fields = ("target_id", "registered_test_id", "route", "method",
              "endpoint_path", "max_requests", "timeout_seconds")
    if any(job[key] != scope[key] for key in fields):
        raise AdmittedDispatchBlocked("Saved job differs from current trusted registry")
    expected = hashlib.sha256(json.dumps(
        {key: scope[key] for key in ("target_id", "endpoint_id", "registered_test_id",
          "method", "endpoint_path", "max_requests", "timeout_seconds", "route")},
        sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()
    if expected != job["scope_sha256"]:
        raise AdmittedDispatchBlocked("Scope fingerprint mismatch")
    return expected, identity[1]


def _reviewed_sql_scope(database: Path, job_id: str, root: Path) -> str:
    """Keep the existing SQLi-only Blue authority separate from Red dispatch."""
    digest, scenario_id = _reviewed_registered_scope(database, job_id, root)
    if scenario_id != "sqli-login-001":
        raise AdmittedDispatchBlocked("A reviewed, registered SQLi job is required")
    return digest


def dispatch_reviewed_job(
    *, database: Path, source_root: Path, evidence_root: Path,
    admission_path: Path, admission_sha256: str, job_id: str,
):
    """One explicit operator invocation; unknown external effects are never retried.

    External reviewers must separately pin the admission file and its SHA256.
    Source and runtime are checked BEFORE the durable attempt reservation and
    again by the existing executor after reservation.
    """
    canonical_id = str(UUID(job_id))
    database, source_root = Path(database), Path(source_root)
    scope_hash, expected_scenario = _reviewed_registered_scope(
        database, canonical_id, source_root,
    )
    pin = load_real_admission(source_root, Path(admission_path), admission_sha256)
    expected_identity = "mars-" + UUID(canonical_id).hex
    if (pin.run_id != expected_identity or pin.case_id != expected_identity
            or pin.scenario_id != expected_scenario):
        raise AdmittedDispatchBlocked("Admission not pinned to this registered job")
    registry = TargetRegistry.from_directories(
        targets_dir=source_root / "config" / "targets",
        security_tests_dir=source_root / "config" / "security_tests",
    )
    seam = IsolatedDockerExecutor(
        source_root=source_root, evidence_root=Path(evidence_root),
        admission_path=Path(admission_path), admission_sha256=admission_sha256,
        registry=registry, implementations=SecurityTestRegistry.default(),
    )
    # Reuse existing pin checks, not a second Docker verification engine.
    seam._source_snapshot()
    seam._runtime_snapshot()
    reserve_once(database, canonical_id, scope_hash, admission_sha256)
    receipt = seam.run_registered()
    record_receipt(database, canonical_id, Path(evidence_root), receipt)
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description="Run one externally admitted registered MARS Red job")
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--admission-path", required=True, type=Path)
    parser.add_argument("--admission-sha256", required=True)
    parser.add_argument("--job-id", required=True)
    args = parser.parse_args()
    receipt = dispatch_reviewed_job(**vars(args))
    print(receipt.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
