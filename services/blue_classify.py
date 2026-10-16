"""One genuine Q8 model classification of independently bound registered SQLi evidence.

Only callable in the process hosting the approved Q8 model session. The model
cannot dispatch a test, choose patch content, or qualify scientific findings.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from urllib.parse import quote
from uuid import UUID

import dashboard.api.q8_development_service as q8
from services.blue_input import BlueInputBlocked, build_blue_input
from services.job_dispatch import AdmittedDispatchBlocked, _reviewed_sql_scope
from services.q8_c12_development_bridge import (
    Q8DevelopmentBlocked, archive_gateway_reply, classification_receipt,
)
from services.registered_assessment_plan import (
    AssessmentPlanBlocked, plan_from_model_receipt,
)


class BlueClassifyBlocked(RuntimeError):
    """Q8 was not available or inference evidence cannot be accepted."""


def ensure_classify_table(conn: sqlite3.Connection) -> None:
    conn.execute("""CREATE TABLE IF NOT EXISTS blue_decisions (
        job_id TEXT PRIMARY KEY,
        status TEXT NOT NULL CHECK(status IN ('outcome_unknown','recorded')),
        result_json TEXT
    )""")


def read_blue_decision(conn: sqlite3.Connection, job_id: str) -> dict:
    canonical = str(UUID(job_id))
    ensure_classify_table(conn)
    row = conn.execute(
        "SELECT status,result_json FROM blue_decisions WHERE job_id=?", (canonical,)
    ).fetchone()
    if row is None:
        return {"job_id": canonical, "status": "not_requested"}
    if row[0] != "recorded":
        return {"job_id": canonical, "status": "outcome_unknown"}
    return json.loads(row[1])


def classify_bound_job(
    *, database: Path, job_id: str, source_root: Path, evidence_dir: Path,
    admission_path: Path, admission_sha256: str, receipt_sha256: str,
) -> dict:
    """Perform at most one local Q8 call for one independently bound SQLi job."""
    canonical = str(UUID(job_id))
    try:
        request = build_blue_input(
            database=database, job_id=canonical, source_root=source_root,
            evidence_dir=evidence_dir, admission_path=admission_path,
            admission_sha256=admission_sha256, receipt_sha256=receipt_sha256,
        )
    except BlueInputBlocked as exc:
        raise BlueClassifyBlocked("Registered Red-to-model input was rejected") from exc
    if q8.manager.probe_busy():
        raise BlueClassifyBlocked("A local Q8 inference is already in progress")
    try:
        state = q8.manager.status()
        if (state.get("state") != "running"
                or state.get("sha256") != q8.MODEL_SHA256
                or state.get("filename") != "c08b-nf4-effective-Q8_0.gguf"):
            raise BlueClassifyBlocked("Verified local Q8 model is not running")
        system = q8._frozen_system()
        pair = request["classification_request"]["input"]
        user = json.dumps(pair, separators=(",", ":"), ensure_ascii=False)
        prompt = (
            "<|im_start|>system\n" + system + "<|im_end|>\n"
            "<|im_start|>user\n" + user + "<|im_end|>\n<|im_start|>assistant\n"
        )

        # Reserve once BEFORE sending a request to the model. Interrupted
        # inference remains unknown and is never silently retried/cherry-picked.
        database = Path(database)
        with sqlite3.connect(
            "file:" + quote(str(database.absolute())) + "?mode=rw", uri=True, timeout=5,
        ) as conn:
            conn.execute("BEGIN IMMEDIATE")
            ensure_classify_table(conn)
            try:
                conn.execute(
                    "INSERT INTO blue_decisions(job_id,status) VALUES (?,'outcome_unknown')",
                    (canonical,),
                )
            except sqlite3.IntegrityError as exc:
                raise BlueClassifyBlocked("A Q8 classification is already attempted") from exc

        # All model artifacts are external, append-only, and retain raw failure.
        archive = q8._call_evidence_directory()
        archive_gateway_reply(
            evidence_dir=archive, filename="q8-input.json",
            reply=request["classification_request"], project_root=source_root,
        )
        raw = q8._raw_completion(state["port"], prompt)
        archive_gateway_reply(
            evidence_dir=archive, filename="q8-raw-completion.json",
            reply=raw, project_root=source_root,
        )
        if raw.get("truncated") is not False or type(raw.get("content")) is not str:
            raise BlueClassifyBlocked("Q8 raw completion is missing or truncated")
        if len(raw["content"]) > 8192:
            raise BlueClassifyBlocked("Q8 response is oversized")
        try:
            selected = json.loads(raw["content"])
        except ValueError as exc:
            raise BlueClassifyBlocked("Model returned invalid JSON; raw completion saved") from exc
        reply = {
            "role": "classification", "result": selected,
            "origin": "q8_0_cpu_model", "executed_tests": False,
        }
        archive_gateway_reply(
            evidence_dir=archive, filename="q8-gateway.json",
            reply=reply, project_root=source_root,
        )
        decision = classification_receipt(pair=pair, gateway_reply=reply)
        assessment = plan_from_model_receipt(
            root=Path(source_root), pair=pair, receipt=decision,
        )
        archive_gateway_reply(
            evidence_dir=archive, filename="q8-assessment-plan.json",
            reply=assessment, project_root=source_root,
        )
        after = q8.manager.status()
        if (after.get("state") != "running"
                or after.get("sha256") != q8.MODEL_SHA256
                or after.get("filename") != state.get("filename")):
            raise BlueClassifyBlocked("Q8 session changed during inference")
        result = {
            "job_id": canonical, "status": "recorded",
            "classification": decision["decision"]["classification"],
            "confidence": decision["decision"]["confidence"],
            "reason": decision["decision"]["reason"],
            "model_origin": "q8_0_cpu_model",
            "model_sha256": state["sha256"],
            "model_input_origin": request["origin"],
            "model_evidence_id": archive.name,
            "model_input_sha256": sha256(
                (archive / "q8-input.json").read_bytes()
            ).hexdigest(),
            "model_raw_sha256": sha256(
                (archive / "q8-raw-completion.json").read_bytes()
            ).hexdigest(),
            "preliminary_action": decision["preliminary_blue_action"],
            "model_independently_qualified": False,
            "source_analysis_authorized": False,
            "patch_preparation_authorized": False,
            "final_research_qualified": False,
        }
        # The model call may take minutes. Revalidate the immutable job scope
        # and exact recorded admission/receipt under the commit lock.
        scope_hash = _reviewed_sql_scope(database, canonical, Path(source_root))
        with sqlite3.connect(
            "file:" + quote(str(database.absolute())) + "?mode=rw", uri=True, timeout=5,
        ) as conn:
            conn.execute("BEGIN IMMEDIATE")
            current_job = conn.execute(
                "SELECT state,scenario,route,registered_test_id,scope_sha256 "
                "FROM jobs WHERE id=?", (canonical,),
            ).fetchone()
            current_intent = conn.execute(
                "SELECT admission_sha256 FROM dispatch_intents WHERE job_id=?",
                (canonical,),
            ).fetchone()
            current_receipt = conn.execute(
                "SELECT receipt_sha256,outcome FROM execution_receipts WHERE job_id=?",
                (canonical,),
            ).fetchone()
            if (current_job is None or current_job != (
                    "scope_reviewed", "sql", "/sql-injection/login",
                    "sqli-login-bypass-001", scope_hash
                ) or current_intent != (admission_sha256,)
                    or current_receipt != (receipt_sha256, "baseline_exploit_confirmed")):
                raise BlueClassifyBlocked("Saved job or Red provenance changed during Q8 inference")
            count = conn.execute(
                "UPDATE blue_decisions SET status='recorded',result_json=? "
                "WHERE job_id=? AND status='outcome_unknown'",
                (json.dumps(result, sort_keys=True, separators=(",", ":")), canonical),
            ).rowcount
            if count != 1:
                raise BlueClassifyBlocked("Model result could not be linked to the pending job")
            next_sequence = conn.execute(
                "SELECT COALESCE(MAX(sequence),0)+1 FROM job_events WHERE job_id=?",
                (canonical,),
            ).fetchone()[0]
            conn.execute(
                "INSERT INTO job_events(job_id,sequence,event,occurred_at) VALUES (?,?,?,?)",
                (canonical, next_sequence, "model_classification_recorded",
                 datetime.now(timezone.utc).isoformat()),
            )
        return result
    except BlueClassifyBlocked:
        raise
    except (Q8DevelopmentBlocked, AssessmentPlanBlocked, AdmittedDispatchBlocked,
            OSError, ValueError, KeyError, TypeError, sqlite3.Error, q8.OperatorError) as exc:
        raise BlueClassifyBlocked("Q8 model classification could not be accepted") from exc
    finally:
        q8.manager.finish_probe()
