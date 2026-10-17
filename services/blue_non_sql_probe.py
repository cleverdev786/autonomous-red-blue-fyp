"""One-shot, read-only Q8 development evidence for registered XSS/traversal Red.

Model classification and independently source-checked localization are recorded
without granting patch, test dispatch, automatic repair, or research authority.
Each attempt reserves a durable unknown intent before any inference.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from urllib.parse import quote
from uuid import UUID

import dashboard.api.q8_development_service as q8
from services.blue_input import BlueInputBlocked, build_registered_blue_input
from services.q8_c12_development_bridge import (
    Q8DevelopmentBlocked, archive_gateway_reply, classification_receipt,
    localization_receipt,
)

EXPECTED_CLASSES = {
    "xss-search-001": "xss",
    "path-traversal-read-001": "path_traversal",
}


class BlueNonSqlProbeBlocked(RuntimeError):
    """Model evidence cannot be safely recorded or was previously attempted."""


def ensure_non_sql_probe_table(conn: sqlite3.Connection) -> None:
    conn.execute("""CREATE TABLE IF NOT EXISTS blue_non_sql_probes (
        job_id TEXT PRIMARY KEY,
        status TEXT NOT NULL CHECK(status IN ('outcome_unknown','recorded')),
        result_json TEXT
    )""")


def read_non_sql_probe(conn: sqlite3.Connection, job_id: str) -> dict:
    canonical = str(UUID(job_id))
    ensure_non_sql_probe_table(conn)
    row = conn.execute(
        "SELECT status,result_json FROM blue_non_sql_probes WHERE job_id=?",
        (canonical,),
    ).fetchone()
    if row is None:
        return {"job_id": canonical, "status": "not_requested"}
    if row[0] != "recorded":
        return {"job_id": canonical, "status": "outcome_unknown"}
    return json.loads(row[1])


def _verified_raw(port: int, prompt: str, archive: Path, filename: str,
                  source_root: Path) -> dict:
    raw = q8._raw_completion(port, prompt)
    archive_gateway_reply(
        evidence_dir=archive, filename=filename, reply=raw,
        project_root=source_root,
    )
    if (raw.get("truncated") is not False
            or type(raw.get("content")) is not str
            or len(raw["content"]) > 8192):
        raise BlueNonSqlProbeBlocked("Unusable raw response; one-shot evidence retained")
    try:
        output = json.loads(raw["content"])
    except ValueError as exc:
        raise BlueNonSqlProbeBlocked("Model returned non-JSON; raw evidence retained") from exc
    if type(output) is not dict:
        raise BlueNonSqlProbeBlocked("Model output must be one JSON object")
    return output


def probe_bound_non_sql_job(
    *, database: Path, job_id: str, source_root: Path, evidence_dir: Path,
    admission_path: Path, admission_sha256: str, receipt_sha256: str,
) -> dict:
    """Issue at most two local model calls; no automatic repair or replay."""
    canonical = str(UUID(job_id))
    database, source_root = Path(database), Path(source_root)
    arguments = dict(
        database=database, job_id=canonical, source_root=source_root,
        evidence_dir=Path(evidence_dir), admission_path=Path(admission_path),
        admission_sha256=admission_sha256, receipt_sha256=receipt_sha256,
    )
    try:
        prepared = build_registered_blue_input(**arguments)
    except BlueInputBlocked as exc:
        raise BlueNonSqlProbeBlocked("Verified registered non-SQL Red required") from exc
    if q8.manager.probe_busy():
        raise BlueNonSqlProbeBlocked("Local model already busy")
    try:
        state = q8.manager.status()
        if (state.get("state") != "running"
                or state.get("sha256") != q8.MODEL_SHA256
                or state.get("filename") != "c08b-nf4-effective-Q8_0.gguf"):
            raise BlueNonSqlProbeBlocked("Exact approved development Q8 not running")
        system = q8._frozen_system()
        pair = prepared["classification_request"]["input"]
        user = json.dumps(pair, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        prompt = (
            "<|im_start|>system\n" + system + "<|im_end|>\n"
            "<|im_start|>user\n" + user + "<|im_end|>\n"
            "<|im_start|>assistant\n"
        )
        # Durable intent must exist BEFORE any model call. Unknown outcomes
        # cannot be retried, overwritten or interpreted as a harmless refusal.
        uri = "file:" + quote(str(database.absolute())) + "?mode=rw"
        with sqlite3.connect(uri, uri=True, timeout=5) as conn:
            conn.execute("BEGIN IMMEDIATE")
            ensure_non_sql_probe_table(conn)
            try:
                conn.execute(
                    "INSERT INTO blue_non_sql_probes(job_id,status) "
                    "VALUES (?,'outcome_unknown')", (canonical,),
                )
            except sqlite3.IntegrityError as exc:
                raise BlueNonSqlProbeBlocked("A non-SQL model probe was already attempted") from exc

        archive = q8._call_evidence_directory()
        archive_gateway_reply(
            evidence_dir=archive, filename="q8-nonsql-input.json",
            reply=prepared, project_root=source_root,
        )
        archive_gateway_reply(
            evidence_dir=archive, filename="q8-nonsql-prompt.json",
            reply={"profile": "q8-c12-registered-pair-readonly-v1", "prompt": prompt},
            project_root=source_root,
        )
        output = _verified_raw(
            state["port"], prompt, archive, "q8-nonsql-raw.json", source_root,
        )
        decision = classification_receipt(
            pair=pair,
            gateway_reply={"role": "classification", "result": output,
                           "origin": "q8_0_cpu_model", "executed_tests": False},
        )
        archive_gateway_reply(
            evidence_dir=archive, filename="q8-nonsql-decision.json",
            reply=decision, project_root=source_root,
        )
        label = decision["decision"]["classification"]
        model_match = (
            label == EXPECTED_CLASSES[prepared["scenario_id"]]
            and decision["preliminary_blue_action"] == "select_registered_test"
        )
        verified = False
        localization_reason = "model_class_mismatch"
        selected_line = None
        selection = None
        if model_match:
            localization_request = prepared["localization_request"]
            localization_prompt = q8.development_localization_prompt(
                localization_request["input"],
            )
            archive_gateway_reply(
                evidence_dir=archive, filename="q8-nonsql-localization-input.json",
                reply=localization_request, project_root=source_root,
            )
            archive_gateway_reply(
                evidence_dir=archive, filename="q8-nonsql-localization-prompt.json",
                reply={"profile": q8.LOCALIZATION_PROMPT_PROFILE,
                       "prompt": localization_prompt},
                project_root=source_root,
            )
            suggested = _verified_raw(
                state["port"], localization_prompt, archive,
                "q8-nonsql-localization-raw.json", source_root,
            )
            localized = localization_receipt(
                request=localization_request,
                gateway_reply={"role": "source_localization", "result": suggested,
                               "origin": "q8_0_cpu_model", "executed_tests": False},
                project_root=source_root,
            )
            archive_gateway_reply(
                evidence_dir=archive, filename="q8-nonsql-localization-checked.json",
                reply=localized, project_root=source_root,
            )
            verified = True
            localization_reason = "source_hash_ast_and_sink_verified"
            selected_line = localized["verified_sink_line"]
            selection = localized["selection"]
        after = q8.manager.status()
        if (after.get("state") != "running"
                or after.get("sha256") != state["sha256"]
                or after.get("filename") != state["filename"]):
            raise BlueNonSqlProbeBlocked("Model session changed during inference")
        if build_registered_blue_input(**arguments) != prepared:
            raise BlueNonSqlProbeBlocked("Pinned Red/source context changed during inference")
        result = {
            "job_id": canonical, "status": "recorded",
            "scenario_id": prepared["scenario_id"],
            "registered_test_id": prepared["registered_test_id"],
            "red_receipt_sha256": receipt_sha256,
            "model_origin": "q8_0_cpu_model", "model_sha256": state["sha256"],
            "model_evidence_id": archive.name,
            "model_raw_sha256": sha256((archive / "q8-nonsql-raw.json").read_bytes()).hexdigest(),
            "model_input_sha256": sha256((archive / "q8-nonsql-input.json").read_bytes()).hexdigest(),
            "model_prompt_sha256": sha256((archive / "q8-nonsql-prompt.json").read_bytes()).hexdigest(),
            "localization_raw_sha256": (
                sha256((archive / "q8-nonsql-localization-raw.json").read_bytes()).hexdigest()
                if verified else None
            ),
            "source_file": "dummy_apps/vulnerable_store/app/scenario_routes.py",
            "source_sha256": prepared["localization_request"]["input"]["source_sha256"],
            "classification": label, "confidence": decision["decision"]["confidence"],
            "reason": decision["decision"]["reason"],
            "source_localization_verified": verified,
            "localization_reason": localization_reason,
            "model_selected_sink_line": selected_line, "model_source_selection": selection,
            "model_independently_qualified": False,
            "source_analysis_authorized": False,
            "patch_preparation_authorized": False, "patch_applied": False,
            "security_replayed": False, "final_research_qualified": False,
        }
        with sqlite3.connect(uri, uri=True, timeout=5) as conn:
            conn.execute("BEGIN IMMEDIATE")
            scenario_name = (
                "xss" if prepared["scenario_id"] == "xss-search-001"
                else "traversal"
            )
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
            if (job != (
                    "scope_reviewed", scenario_name, pair["route"],
                    prepared["registered_test_id"]
                ) or intent != (admission_sha256,)
                    or receipt != (receipt_sha256, "baseline_exploit_confirmed")):
                raise BlueNonSqlProbeBlocked("Bound scope or Red receipt changed before commit")
            count = conn.execute(
                "UPDATE blue_non_sql_probes SET status='recorded',result_json=? "
                "WHERE job_id=? AND status='outcome_unknown'",
                (json.dumps(result, sort_keys=True, separators=(",", ":")), canonical),
            ).rowcount
            if count != 1:
                raise BlueNonSqlProbeBlocked("Model probe intent was changed")
            sequence = conn.execute(
                "SELECT COALESCE(MAX(sequence),0)+1 FROM job_events WHERE job_id=?",
                (canonical,),
            ).fetchone()[0]
            conn.execute(
                "INSERT INTO job_events(job_id,sequence,event,occurred_at) VALUES (?,?,?,?)",
                (canonical, sequence, "non_sql_model_probe_recorded",
                 datetime.now(UTC).isoformat()),
            )
        return result
    except BlueNonSqlProbeBlocked:
        raise
    except (BlueInputBlocked, Q8DevelopmentBlocked, q8.OperatorError,
            OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
        raise BlueNonSqlProbeBlocked("Non-SQL model or source evidence rejected") from exc
    finally:
        q8.manager.finish_probe()


def main() -> None:
    """Explicit operator CLI; never invoked by a dashboard start endpoint."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Record one unqualified, read-only Q8 model probe on pinned XSS/traversal Red",
    )
    for name in ("database", "source-root", "evidence-dir", "admission-path"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("job-id", "admission-sha256", "receipt-sha256"):
        parser.add_argument("--" + name, required=True)
    print(json.dumps(
        probe_bound_non_sql_job(**vars(parser.parse_args())),
        sort_keys=True, indent=2,
    ))


if __name__ == "__main__":
    main()
