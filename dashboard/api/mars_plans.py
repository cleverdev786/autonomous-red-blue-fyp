"""MARS draft assessment workspace, independent of frozen experiment databases.

Drafts have no execution authority. Scope is copied only from the trusted registry.
"""
from __future__ import annotations

import sqlite3
import hashlib
import json
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from services.registered_assessment_plan import AssessmentPlanBlocked, registered_catalog
from schemas.registered_red_observation import REGISTERED
from services.mars_dispatch_intent import ensure_intent_table
from services.receipt_record import ensure_receipt_table, read_receipt
from services.blue_preview import ensure_preview_table, read_blue_preview
from services.blue_classify import ensure_classify_table, read_blue_decision, classify_bound_job, BlueClassifyBlocked

SCENARIO_ROUTES = {
    "sql": "/sql-injection/login",
    "xss": "/xss/search",
    "traversal": "/path-traversal/read",
}


class DraftRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=3, max_length=80)
    scenario: Literal["sql", "xss", "traversal"]




class JobRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    plan_id: UUID


class EmptyAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

def register_mars_plans(*, root: Path, database: Path, require_origin):
    router = APIRouter(prefix="/api/mars", tags=["MARS workspace"])

    @contextmanager
    def connect():
        database.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(database, timeout=5)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("""CREATE TABLE IF NOT EXISTS plans (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, scenario TEXT NOT NULL,
                target_id TEXT NOT NULL, registered_test_id TEXT NOT NULL,
                route TEXT NOT NULL, created_at TEXT NOT NULL
            )""")
            conn.execute("""CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY, plan_id TEXT NOT NULL, state TEXT NOT NULL,
                name TEXT NOT NULL, scenario TEXT NOT NULL, target_id TEXT NOT NULL,
                registered_test_id TEXT NOT NULL, route TEXT NOT NULL,
                method TEXT NOT NULL, endpoint_path TEXT NOT NULL,
                max_requests INTEGER NOT NULL, timeout_seconds INTEGER NOT NULL,
                scope_sha256 TEXT NOT NULL, created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )""")
            conn.execute("""CREATE UNIQUE INDEX IF NOT EXISTS unique_active_plan_job
                ON jobs(plan_id) WHERE state IN ('awaiting_review', 'scope_reviewed')""")
            conn.execute("""CREATE TABLE IF NOT EXISTS job_events (
                job_id TEXT NOT NULL, sequence INTEGER NOT NULL,
                event TEXT NOT NULL, occurred_at TEXT NOT NULL,
                PRIMARY KEY(job_id, sequence)
            )""")
            ensure_intent_table(conn)
            ensure_receipt_table(conn)
            ensure_preview_table(conn)
            ensure_classify_table(conn)
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def present(row):
        return {
            "id": row["id"], "name": row["name"], "scenario": row["scenario"],
            "target_id": row["target_id"], "registered_test_id": row["registered_test_id"],
            "route": row["route"], "created_at": row["created_at"],
            "status": "draft", "execution_enabled": False, "executed": False,
            "final_research_qualified": False,
        }

    @router.get("/plans")
    def list_plans() -> list[dict]:
        with connect() as conn:
            return [present(row) for row in conn.execute(
                "SELECT * FROM plans ORDER BY created_at DESC, id DESC LIMIT 500"
            ).fetchall()]

    @router.get("/plans/{plan_id}")
    def get_plan(plan_id: str) -> dict:
        with connect() as conn:
            row = conn.execute("SELECT * FROM plans WHERE id = ?", (plan_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Draft not found")
        return present(row)

    @router.post("/plans", status_code=201, dependencies=[Depends(require_origin)])
    def create_plan(request: DraftRequest) -> dict:
        try:
            registry = registered_catalog(root)
        except AssessmentPlanBlocked as exc:
            raise HTTPException(503, "Trusted assessment registry unavailable") from exc
        matched = [row for row in registry["registered_assessments"]
                   if row["route"] == SCENARIO_ROUTES[request.scenario]
                   and row["target_id"] == registry["target_id"]
                   and row["trusted_registry_verified"] is True
                   and row["execution_enabled"] is False]
        if len(matched) != 1:
            raise HTTPException(409, "Registered scenario not uniquely grounded")
        entry = matched[0]
        values = (
            str(uuid4()), request.name, request.scenario, entry["target_id"],
            entry["registered_test_id"], entry["route"],
            datetime.now(timezone.utc).isoformat(),
        )
        with connect() as conn:
            # Serialize the limit check and insert under concurrent local requests.
            conn.execute("BEGIN IMMEDIATE")
            if conn.execute("SELECT COUNT(*) FROM plans").fetchone()[0] >= 500:
                raise HTTPException(409, "Draft limit reached")
            conn.execute(
                "INSERT INTO plans (id,name,scenario,target_id,registered_test_id,route,created_at) "
                "VALUES (?,?,?,?,?,?,?)", values
            )
        return present(dict(zip(
            ("id", "name", "scenario", "target_id", "registered_test_id", "route", "created_at"),
            values,
        )))

    @router.delete("/plans/{plan_id}", status_code=204, dependencies=[Depends(require_origin)])
    def delete_plan(plan_id: str) -> Response:
        with connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if conn.execute(
                "SELECT 1 FROM jobs WHERE plan_id=? AND state IN ('awaiting_review','scope_reviewed')",
                (plan_id,),
            ).fetchone():
                raise HTTPException(409, "Cancel active assessment jobs before deleting the plan")
            cursor = conn.execute("DELETE FROM plans WHERE id = ?", (plan_id,))
            if cursor.rowcount == 0:
                raise HTTPException(404, "Draft not found")
        return Response(status_code=204)

    # Jobs are a planning lifecycle, deliberately not a dispatch/execution API.
    def display_job(row):
        return {
            **{key: row[key] for key in (
                "id", "plan_id", "name", "scenario", "target_id", "registered_test_id",
                "route", "method", "endpoint_path", "max_requests", "timeout_seconds",
                "scope_sha256", "created_at", "updated_at", "state",
            )},
            "execution_authorized": False, "executed": False,
            "final_research_qualified": False,
        }

    def trusted_scope(plan):
        try:
            registry = registered_catalog(root)
        except AssessmentPlanBlocked as exc:
            raise HTTPException(503, "Trusted registry unavailable") from exc
        matches = [item for item in registry["registered_assessments"]
                   if item["target_id"] == plan["target_id"]
                   and item["route"] == plan["route"]
                   and item["registered_test_id"] == plan["registered_test_id"]
                   and item["trusted_registry_verified"] is True
                   and item["execution_enabled"] is False
                   and item["max_requests"] > 0
                   and item["timeout_seconds"] > 0]
        if len(matches) != 1 or registry["target_id"] != plan["target_id"]:
            raise HTTPException(409, "Plan no longer matches trusted registry")
        return matches[0]

    def receipt_hash(item):
        scope = {key: item[key] for key in (
            "target_id", "endpoint_id", "registered_test_id", "method",
            "endpoint_path", "max_requests", "timeout_seconds", "route",
        )}
        return hashlib.sha256(json.dumps(scope, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def current_job(conn, job_id):
        row = conn.execute("SELECT * FROM jobs WHERE id=?", (str(job_id),)).fetchone()
        if row is None:
            raise HTTPException(404, "Job not found")
        return row

    @router.get("/jobs")
    def list_jobs() -> list[dict]:
        with connect() as conn:
            return [display_job(row) for row in conn.execute(
                "SELECT * FROM jobs ORDER BY created_at DESC, id DESC LIMIT 500"
            ).fetchall()]

    @router.get("/jobs/{job_id}")
    def get_job(job_id: UUID) -> dict:
        with connect() as conn:
            return display_job(current_job(conn, job_id))

    @router.get("/jobs/{job_id}/execution")
    def job_execution(job_id: UUID) -> dict:
        with connect() as conn:
            current_job(conn, job_id)
            return read_receipt(conn, str(job_id))

    @router.get("/jobs/{job_id}/proposal")
    def job_proposal(job_id: UUID) -> dict:
        with connect() as conn:
            current_job(conn, job_id)
            return read_blue_preview(conn, str(job_id))

    @router.get("/jobs/{job_id}/classification")
    def get_job_classification(job_id: UUID) -> dict:
        with connect() as conn:
            current_job(conn, job_id)
            return read_blue_decision(conn, str(job_id))

    @router.post("/jobs/{job_id}/classify", dependencies=[Depends(require_origin)])
    def classify_job(job_id: UUID, request: EmptyAction) -> dict:
        # Operator-controlled paths and independent fingerprints are server
        # configuration only. Never accept source/evidence paths from browsers.
        import os
        names = ("MARS_SOURCE_ROOT", "MARS_EVIDENCE_DIR", "MARS_ADMISSION_PATH",
                 "MARS_ADMISSION_SHA256", "MARS_RECEIPT_SHA256")
        values = [os.environ.get(name) for name in names]
        if any(not value for value in values):
            raise HTTPException(409, "Independent evidence pins are not configured")
        with connect() as conn:
            current_job(conn, job_id)
        try:
            return classify_bound_job(
                database=database, job_id=str(job_id),
                source_root=Path(values[0]), evidence_dir=Path(values[1]),
                admission_path=Path(values[2]), admission_sha256=values[3],
                receipt_sha256=values[4],
            )
        except BlueClassifyBlocked as exc:
            raise HTTPException(409, str(exc)) from exc

    @router.get("/jobs/{job_id}/events")
    def job_events(job_id: UUID) -> list[dict]:
        with connect() as conn:
            current_job(conn, job_id)
            return [dict(row) for row in conn.execute(
                "SELECT sequence, event, occurred_at FROM job_events "
                "WHERE job_id=? ORDER BY sequence", (str(job_id),)
            ).fetchall()]

    @router.post("/jobs", status_code=201, dependencies=[Depends(require_origin)])
    def create_job(request: JobRequest) -> dict:
        with connect() as conn:
            plan = conn.execute("SELECT * FROM plans WHERE id=?", (str(request.plan_id),)).fetchone()
            if plan is None:
                raise HTTPException(404, "Plan not found")
            item = trusted_scope(plan)
            now = datetime.now(timezone.utc).isoformat()
            values = (str(uuid4()), str(request.plan_id), "awaiting_review", plan["name"],
                      plan["scenario"], item["target_id"], item["registered_test_id"],
                      item["route"], item["method"], item["endpoint_path"],
                      item["max_requests"], item["timeout_seconds"], receipt_hash(item), now, now)
            conn.execute("BEGIN IMMEDIATE")
            if conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] >= 500:
                raise HTTPException(409, "Job limit reached")
            try:
                conn.execute(
                    "INSERT INTO jobs (id,plan_id,state,name,scenario,target_id,registered_test_id,"
                    "route,method,endpoint_path,max_requests,timeout_seconds,scope_sha256,"
                    "created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", values)
            except sqlite3.IntegrityError as exc:
                raise HTTPException(409, "An active job already exists for this plan") from exc
            conn.execute("INSERT INTO job_events (job_id,sequence,event,occurred_at) "
                         "VALUES (?,1,'created',?)", (values[0], now))
            return display_job(current_job(conn, values[0]))

    def change_job(job_id: UUID, action: str):
        with connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = current_job(conn, job_id)
            if action == "cancel" and conn.execute(
                "SELECT 1 FROM dispatch_intents WHERE job_id=?", (str(job_id),),
            ).fetchone():
                raise HTTPException(
                    409, "Dispatch outcome is unknown; cancellation cannot guarantee a stop",
                )
            if action == "cancel" and row["state"] == "cancelled":
                return display_job(row)
            if action == "review" and row["state"] != "awaiting_review":
                raise HTTPException(409, "Job cannot be reviewed in its current state")
            if action == "cancel" and row["state"] not in ("awaiting_review", "scope_reviewed"):
                raise HTTPException(409, "Job cannot be cancelled in its current state")
            if action == "review":
                # A local scope review is not independent scientific or execution approval.
                plan = conn.execute("SELECT * FROM plans WHERE id=?", (row["plan_id"],)).fetchone()
                if plan is None:
                    raise HTTPException(409, "Original plan is unavailable")
                scope = trusted_scope(plan)
                if receipt_hash(scope) != row["scope_sha256"]:
                    raise HTTPException(409, "Trusted scope changed since job preparation")
            state = "scope_reviewed" if action == "review" else "cancelled"
            now = datetime.now(timezone.utc).isoformat()
            conn.execute("UPDATE jobs SET state=?,updated_at=? WHERE id=?", (state, now, str(job_id)))
            sequence = conn.execute("SELECT COALESCE(MAX(sequence),0)+1 FROM job_events "
                                    "WHERE job_id=?", (str(job_id),)).fetchone()[0]
            conn.execute("INSERT INTO job_events (job_id,sequence,event,occurred_at) "
                         "VALUES (?,?,?,?)", (str(job_id), sequence, state, now))
            return display_job(current_job(conn, job_id))

    @router.post("/jobs/{job_id}/review", dependencies=[Depends(require_origin)])
    def review_job(job_id: UUID, request: EmptyAction) -> dict:
        return change_job(job_id, "review")

    @router.post("/jobs/{job_id}/cancel", dependencies=[Depends(require_origin)])
    def cancel_job(job_id: UUID, request: EmptyAction) -> dict:
        return change_job(job_id, "cancel")

    @router.get("/jobs/{job_id}/preflight")
    def red_preflight(job_id: UUID) -> dict:
        """Inspect registration and state only. No filesystem admission or Docker probe.

        An independently pinned admission and actual isolated-runtime verification
        belong to W3 dispatch, not this view. This endpoint can never grant them.
        """
        with connect() as conn:
            job = current_job(conn, job_id)
            plan = conn.execute("SELECT * FROM plans WHERE id=?", (job["plan_id"],)).fetchone()
        scope_current = False
        if plan is not None:
            try:
                scope_current = receipt_hash(trusted_scope(plan)) == job["scope_sha256"]
            except HTTPException:
                # Unavailable/changed registry can only block readiness.
                pass
        checks = {
            "job_scope_reviewed": job["state"] == "scope_reviewed",
            "registered_scope_current": scope_current,
            "independent_admission_verified": False,
            "isolated_runtime_verified": False,
            "runner_enabled": False,
        }
        return {
            "schema_version": "mars-red-preflight-v1",
            "job_id": job["id"],
            "registered_test_id": job["registered_test_id"],
            "scope_sha256": job["scope_sha256"],
            "scope_current": scope_current,
            "checks": checks,
            "can_dispatch": False,
            "note": "No independent execution admission or runtime check was performed.",
        }

    @router.get("/jobs/{job_id}/execution-request")
    def export_execution_request(job_id: UUID) -> JSONResponse:
        """Reviewer input only. It is NOT an isolated executor admission."""
        with connect() as conn:
            job = current_job(conn, job_id)
            if job["state"] != "scope_reviewed":
                raise HTTPException(409, "Scope must be reviewed before requesting admission")
            if conn.execute(
                "SELECT 1 FROM dispatch_intents WHERE job_id=?", (str(job_id),),
            ).fetchone():
                raise HTTPException(409, "Uncertain prior intent; another review request is blocked")
            plan = conn.execute("SELECT * FROM plans WHERE id=?", (job["plan_id"],)).fetchone()
        if plan is None:
            raise HTTPException(409, "Original plan is unavailable")
        scope = trusted_scope(plan)
        if (receipt_hash(scope) != job["scope_sha256"] or
                any(job[key] != scope[key] for key in (
                    "target_id", "registered_test_id", "route", "method",
                    "endpoint_path", "max_requests", "timeout_seconds",
                ))):
            raise HTTPException(409, "Saved job scope no longer matches the registry")
        scenario_ids = [scenario for scenario, registered in REGISTERED.items()
                        if registered[0] == job["registered_test_id"]]
        if len(scenario_ids) != 1:
            raise HTTPException(409, "No unique isolated scenario mapping exists")
        packet = {
            "schema_version": "mars-execution-request-v1",
            "purpose": "independent_admission_review",
            "job_id": job["id"], "plan_id": job["plan_id"],
            "scenario_id": scenario_ids[0],
            "target_id": job["target_id"],
            "registered_test_id": job["registered_test_id"],
            "route": scope["route"], "endpoint_id": scope["endpoint_id"],
            "method": job["method"], "endpoint_path": job["endpoint_path"],
            "max_requests": job["max_requests"],
            "timeout_seconds": job["timeout_seconds"],
            "scope_sha256": job["scope_sha256"],
            "admission_granted": False,
            "execution_authorized": False,
            "final_research_qualified": False,
        }
        return JSONResponse(packet, headers={
            "Content-Disposition": f'attachment; filename="mars-execution-request-{job_id}.json"',
            "Cache-Control": "no-store",
        })

    @router.post("/jobs/{job_id}/start", dependencies=[Depends(require_origin)])
    def start_job_not_enabled(job_id: UUID, request: EmptyAction) -> dict:
        # No executor is attached in W2. Do not accidentally imply a running job.
        with connect() as conn:
            current_job(conn, job_id)
        raise HTTPException(409, "Execution unavailable: a separately authorized runner is required")

    return router
