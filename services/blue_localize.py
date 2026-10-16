"""One model-selected, source-checked SQLi localization of independently bound Red evidence.

Development only: no Docker, Git mutation, patch authority or research qualification.
The frozen C12 source-selection contract validates Q8's own function/sink choice.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from urllib.parse import quote
from uuid import UUID

import dashboard.api.q8_development_service as q8
from schemas.blue_team import TriageResult
from schemas.common import ClassificationLabel
from schemas.rq2_dataset import RQ2ClassificationDecision
from security_tests.registry import SecurityTestRegistry
from services.blue_input import BlueInputBlocked, build_blue_input
from services.bound_registered_red_evidence import verify_archived_registered_red
from services.compact_source_selection import (
    CompactSourceSelection,
    build_verified_analysis,
    load_trusted_source_window,
)
from services.job_dispatch import AdmittedDispatchBlocked, _reviewed_sql_scope
from services.model_driven_decision_gate import (
    BlueNextAction,
    authorize_bound_source_analysis,
)
from services.q8_c12_development_bridge import (
    Q8DevelopmentBlocked,
    archive_gateway_reply,
    classification_receipt,
    localization_receipt,
)
from services.registered_assessment_plan import plan_from_model_receipt
from services.target_registry import TargetRegistry


class BlueLocalizeBlocked(RuntimeError):
    """No model-sourced localization can be accepted for this job."""


def ensure_localize_table(conn: sqlite3.Connection) -> None:
    conn.execute("""CREATE TABLE IF NOT EXISTS blue_localizations (
        job_id TEXT PRIMARY KEY,
        status TEXT NOT NULL CHECK(status IN ('outcome_unknown','recorded')),
        result_json TEXT
    )""")


def read_blue_localization(conn: sqlite3.Connection, job_id: str) -> dict:
    canonical = str(UUID(job_id))
    ensure_localize_table(conn)
    row = conn.execute(
        "SELECT status,result_json FROM blue_localizations WHERE job_id=?",
        (canonical,),
    ).fetchone()
    if row is None:
        return {"job_id": canonical, "status": "not_requested"}
    if row[0] != "recorded":
        return {"job_id": canonical, "status": "outcome_unknown"}
    return json.loads(row[1])


def _archived_file(directory: Path, filename: str, expected_sha: str | None,
                   max_bytes: int) -> dict:
    path = directory / filename
    if (path.is_symlink() or not path.is_file() or
            any(parent.is_symlink() for parent in path.parents) or
            path.stat().st_size > max_bytes):
        raise BlueLocalizeBlocked("Model archive is missing, symlinked or oversized")
    raw = path.read_bytes()
    if (len(raw) > max_bytes or
            (expected_sha is not None and sha256(raw).hexdigest() != expected_sha)):
        raise BlueLocalizeBlocked("Model evidence fingerprint changed")
    data = json.loads(raw)
    if type(data) is not dict:
        raise BlueLocalizeBlocked("Model evidence is not a JSON object")
    return data


def _trusted_classification(saved: dict, request: dict, root: Path) -> RQ2ClassificationDecision:
    """Re-evaluate the saved Q8 request/completion against actual Red input."""
    if (saved["status"] != "recorded" or saved["classification"] != "sql_injection" or
            saved["preliminary_action"] != "select_registered_test" or
            saved["model_sha256"] != q8.MODEL_SHA256 or
            saved["model_origin"] != "q8_0_cpu_model" or
            saved["model_input_origin"] != "registered_steps_plus_captured_responses" or
            not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", saved["model_evidence_id"])):
        raise BlueLocalizeBlocked("Recorded Q8 decision is not actionable SQLi")
    parent = Path(os.environ.get(
        "FYP_CONSOLE_EVIDENCE_DIR",
        str(Path.home() / ".local/state/sentinel-fyp/capability-evidence"),
    )).expanduser()
    archive = parent / saved["model_evidence_id"]
    if (parent.is_symlink() or archive.is_symlink() or not archive.is_dir() or
            root.resolve() == archive.resolve() or
            root.resolve() in archive.resolve().parents):
        raise BlueLocalizeBlocked("Archived model evidence must be external and regular")
    model_input = _archived_file(
        archive, "q8-input.json", saved["model_input_sha256"], 16384,
    )
    raw = _archived_file(
        archive, "q8-raw-completion.json", saved["model_raw_sha256"], 262144,
    )
    if (model_input != request["classification_request"] or
            raw.get("truncated") is not False or type(raw.get("content")) is not str):
        raise BlueLocalizeBlocked("Q8 request or raw completion mismatch")
    response = json.loads(raw["content"])
    gateway = _archived_file(archive, "q8-gateway.json", None, 16384)
    if (gateway != {"role": "classification", "result": response,
                    "origin": "q8_0_cpu_model", "executed_tests": False}):
        raise BlueLocalizeBlocked("Saved Q8 gateway changed its raw answer")
    checked = classification_receipt(
        pair=request["classification_request"]["input"], gateway_reply=gateway,
    )
    original_plan = plan_from_model_receipt(
        root=root, pair=request["classification_request"]["input"], receipt=checked,
    )
    if _archived_file(archive, "q8-assessment-plan.json", None, 32768) != original_plan:
        raise BlueLocalizeBlocked("Saved Q8 assessment plan is inconsistent")
    if (checked["decision"]["classification"] != saved["classification"] or
            checked["decision"]["confidence"] != saved["confidence"] or
            checked["decision"]["reason"] != saved["reason"] or
            checked["preliminary_blue_action"] != saved["preliminary_action"]):
        raise BlueLocalizeBlocked("Q8 database decision does not match raw inference")
    return RQ2ClassificationDecision.model_validate(checked["decision"])


def localize_bound_job(
    *, database: Path, job_id: str, source_root: Path, evidence_dir: Path,
    admission_path: Path, admission_sha256: str, receipt_sha256: str,
) -> dict:
    canonical = str(UUID(job_id))
    database, source_root = Path(database), Path(source_root)
    try:
        prepared = build_blue_input(
            database=database, job_id=canonical, source_root=source_root,
            evidence_dir=evidence_dir, admission_path=admission_path,
            admission_sha256=admission_sha256, receipt_sha256=receipt_sha256,
        )
        uri = "file:" + quote(str(database.absolute())) + "?mode=rw"
        with sqlite3.connect(uri, uri=True, timeout=5) as conn:
            decision_row = conn.execute(
                "SELECT status,result_json FROM blue_decisions WHERE job_id=?",
                (canonical,),
            ).fetchone()
            if not decision_row or decision_row[0] != "recorded":
                raise BlueLocalizeBlocked("A recorded Q8 classification is required")
            saved = json.loads(decision_row[1])
        decision = _trusted_classification(saved, prepared, source_root)
        registry = TargetRegistry.from_directories(
            targets_dir=source_root / "config/targets",
            security_tests_dir=source_root / "config/security_tests",
        )
        bound = verify_archived_registered_red(
            source_root=source_root, dispatch_root=source_root,
            evidence_dir=Path(evidence_dir), admission_path=Path(admission_path),
            admission_sha256=admission_sha256, receipt_sha256=receipt_sha256,
            registry=registry, implementations=SecurityTestRegistry.default(),
        )
        gate = authorize_bound_source_analysis(
            decision=decision, selected_test_id="sqli-login-bypass-001",
            target_id="vulnerable-store", trusted_endpoint_id="scenario-sqli-login",
            trusted_run_id=prepared["red_run_id"], evidence=bound, registry=registry,
        )
        if gate.action != BlueNextAction.SOURCE_ANALYSIS:
            raise BlueLocalizeBlocked("Model decision and verified Red evidence disagree")

        if q8.manager.probe_busy():
            raise BlueLocalizeBlocked("A model inference is already in progress")
        try:
            state = q8.manager.status()
            if (state.get("state") != "running" or
                    state.get("sha256") != q8.MODEL_SHA256 or
                    state.get("filename") != "c08b-nf4-effective-Q8_0.gguf"):
                raise BlueLocalizeBlocked("Verified Q8 model is not running")
            localization_request = prepared["localization_request"]
            prompt = q8.development_localization_prompt(localization_request["input"])
            # Persist one intent before inference so no crash prompts a silent retry.
            with sqlite3.connect(uri, uri=True, timeout=5) as conn:
                conn.execute("BEGIN IMMEDIATE")
                ensure_localize_table(conn)
                try:
                    conn.execute(
                        "INSERT INTO blue_localizations(job_id,status) VALUES (?,'outcome_unknown')",
                        (canonical,),
                    )
                except sqlite3.IntegrityError as exc:
                    raise BlueLocalizeBlocked("A source localization was already attempted") from exc
            archive = q8._call_evidence_directory()
            archive_gateway_reply(
                evidence_dir=archive, filename="q8-localization-input.json",
                reply=localization_request, project_root=source_root,
            )
            archive_gateway_reply(
                evidence_dir=archive, filename="q8-localization-prompt.json",
                reply={"profile": q8.LOCALIZATION_PROMPT_PROFILE, "prompt": prompt},
                project_root=source_root,
            )
            raw = q8._raw_completion(state["port"], prompt)
            archive_gateway_reply(
                evidence_dir=archive, filename="q8-localization-raw.json",
                reply=raw, project_root=source_root,
            )
            if raw.get("truncated") is not False or type(raw.get("content")) is not str:
                raise BlueLocalizeBlocked("Q8 localization was truncated or invalid")
            if len(raw["content"]) > 8192:
                raise BlueLocalizeBlocked("Q8 localization response too large")
            output = json.loads(raw["content"])
            gateway = {
                "role": "source_localization", "result": output,
                "origin": "q8_0_cpu_model", "executed_tests": False,
            }
            archive_gateway_reply(
                evidence_dir=archive, filename="q8-localization-gateway.json",
                reply=gateway, project_root=source_root,
            )
            localized = localization_receipt(
                request=localization_request, gateway_reply=gateway,
                project_root=source_root,
            )
            selection = CompactSourceSelection.model_validate(localized["selection"])
            window = load_trusted_source_window(
                project_root=source_root, start_line=38, end_line=56,
            )
            analysis = build_verified_analysis(
                project_root=source_root, trusted_run_id=bound.run_id,
                triage=TriageResult(
                    run_id=bound.run_id, is_suspicious=True,
                    classification=ClassificationLabel.SQL_INJECTION,
                    confidence=decision.confidence, reason=decision.reason,
                ),
                selection=selection, window=window,
            )
            after = q8.manager.status()
            if (after.get("state") != "running" or
                    after.get("sha256") != state["sha256"] or
                    after.get("filename") != state["filename"]):
                raise BlueLocalizeBlocked("Q8 model session changed during localization")
            result = {
                "job_id": canonical, "status": "recorded",
                "classification": decision.classification.value,
                "model_origin": "q8_0_cpu_model",
                "function_or_route": selection.function_or_route,
                "sink_line": selection.sink_line,
                "root_cause": selection.root_cause,
                "confidence": selection.confidence,
                "source_file": localized["source_relative_path"],
                "source_sha256": localized["source_sha256"],
                "blue_analysis_sha256": sha256(
                    json.dumps(analysis.model_dump(mode="json"),
                               sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest(),
                "red_receipt_sha256": receipt_sha256,
                "localization_evidence_id": archive.name,
                "localization_prompt_profile": q8.LOCALIZATION_PROMPT_PROFILE,
                "localization_prompt_sha256": sha256(
                    (archive / "q8-localization-prompt.json").read_bytes()
                ).hexdigest(),
                "localization_input_sha256": sha256(
                    (archive / "q8-localization-input.json").read_bytes()
                ).hexdigest(),
                "localization_raw_sha256": sha256(
                    (archive / "q8-localization-raw.json").read_bytes()
                ).hexdigest(),
                "source_analysis_completed": True,
                "patch_preparation_authorized": False,
                "patch_applied": False,
                "final_research_qualified": False,
            }
            # Q8 inference can take minutes. Recheck both external archives and
            # the independently pinned Red observation before DB commit.
            if build_blue_input(
                database=database, job_id=canonical, source_root=source_root,
                evidence_dir=evidence_dir, admission_path=admission_path,
                admission_sha256=admission_sha256, receipt_sha256=receipt_sha256,
            ) != prepared:
                raise BlueLocalizeBlocked("Red-derived source evidence changed")
            if _trusted_classification(saved, prepared, source_root) != decision:
                raise BlueLocalizeBlocked("Archived model classification changed")
            scope_hash = _reviewed_sql_scope(database, canonical, source_root)
            with sqlite3.connect(uri, uri=True, timeout=5) as conn:
                conn.execute("BEGIN IMMEDIATE")
                job = conn.execute(
                    "SELECT state,scenario,route,registered_test_id,scope_sha256 "
                    "FROM jobs WHERE id=?", (canonical,),
                ).fetchone()
                admission = conn.execute(
                    "SELECT admission_sha256 FROM dispatch_intents WHERE job_id=?",
                    (canonical,),
                ).fetchone()
                receipt = conn.execute(
                    "SELECT receipt_sha256,outcome FROM execution_receipts WHERE job_id=?",
                    (canonical,),
                ).fetchone()
                current = conn.execute(
                    "SELECT status,result_json FROM blue_decisions WHERE job_id=?",
                    (canonical,),
                ).fetchone()
                if (job != ("scope_reviewed","sql","/sql-injection/login",
                            "sqli-login-bypass-001",scope_hash) or
                        admission != (admission_sha256,) or
                        receipt != (receipt_sha256, "baseline_exploit_confirmed") or
                        current != decision_row):
                    raise BlueLocalizeBlocked("Job or model evidence changed while localizing")
                updated = conn.execute(
                    "UPDATE blue_localizations SET status='recorded',result_json=? "
                    "WHERE job_id=? AND status='outcome_unknown'",
                    (json.dumps(result, sort_keys=True), canonical),
                ).rowcount
                if updated != 1:
                    raise BlueLocalizeBlocked("Localization intent was changed")
                seq = conn.execute(
                    "SELECT COALESCE(MAX(sequence),0)+1 FROM job_events WHERE job_id=?",
                    (canonical,),
                ).fetchone()[0]
                conn.execute(
                    "INSERT INTO job_events(job_id,sequence,event,occurred_at) VALUES (?,?,?,?)",
                    (canonical, seq, "model_source_localized",
                     datetime.now(timezone.utc).isoformat()),
                )
            return result
        finally:
            q8.manager.finish_probe()
    except BlueLocalizeBlocked:
        raise
    except (BlueInputBlocked, AdmittedDispatchBlocked, Q8DevelopmentBlocked,
            OSError, ValueError, KeyError, TypeError, sqlite3.Error,
            q8.OperatorError) as exc:
        raise BlueLocalizeBlocked("Q8 localization evidence or model output rejected") from exc
