"""T08: authenticated, replay-protected operator review intent API.

Records a review request only. Does not approve, queue, dispatch or execute Red work.
No secret is generated, printed or persisted by the application.
"""
from __future__ import annotations

import os
import secrets
import sqlite3
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, ValidationError

from schemas.common import Identifier
from services.red_assessment_store import RedAssessmentStore, StoreConflict
from services.red_evidence_store import RedEvidenceStore, EvidenceDenied


class ReviewIntent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    assessment_id: Identifier
    plan_version: Identifier
    operation_id: Identifier
    request_id: Identifier
    action: Literal["request_review"]


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message}},
        headers={"Cache-Control": "no-store"},
    )


def register_red_operator(*, state_db: Path, allowed_origins: frozenset[str]) -> APIRouter:
    router = APIRouter(prefix="/api/red/operator", tags=["Red operator"])
    secret = os.getenv("MARS_RED_OPERATOR_TOKEN")
    csrf_token = secrets.token_urlsafe(32)

    def authorize(request: Request, *, mutation: bool) -> JSONResponse | None:
        if not secret or len(secret) < 32:
            return _error(503, "operator_unconfigured", "Red operator access is disabled.")
        bearer = request.headers.get("authorization", "")
        if not secrets.compare_digest(bearer, "Bearer " + secret):
            return _error(401, "unauthorized", "Valid operator authorization is required.")
        origin = request.headers.get("origin")
        if origin is not None and origin not in allowed_origins:
            return _error(403, "invalid_origin", "Origin is not approved.")
        if mutation:
            if origin not in allowed_origins:
                return _error(403, "invalid_origin", "Explicit trusted origin is required.")
            submitted = request.headers.get("x-red-csrf", "")
            if not secrets.compare_digest(submitted, csrf_token):
                return _error(403, "invalid_csrf", "CSRF token is missing or invalid.")
        return None

    @router.get("/csrf")
    def challenge(request: Request):
        blocked = authorize(request, mutation=False)
        if blocked is not None:
            return blocked
        return JSONResponse(
            {"csrf_token": csrf_token},
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )

    @router.post("/reviews")
    async def record_review(request: Request):
        blocked = authorize(request, mutation=True)
        if blocked is not None:
            return blocked
        if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            return _error(415, "invalid_content_type", "JSON content type required.")

        chunks: list[bytes] = []
        total = 0
        async for chunk in request.stream():
            total += len(chunk)
            if total > 2048:
                return _error(413, "oversized_request", "Review request is too large.")
            chunks.append(chunk)
        try:
            data = ReviewIntent.model_validate_json(b"".join(chunks))
        except ValidationError:
            return _error(422, "invalid_request", "Review request fields are invalid.")

        try:
            store = RedAssessmentStore(state_db)
            snapshot, authorization = store.load(data.assessment_id)
            if snapshot.assessment.status.value != "running":
                return _error(409, "invalid_state", "Assessment is not running.")
            if (not snapshot.plans or snapshot.plans[-1].plan_version != data.plan_version
                    or snapshot.plans[-1].status != "approved"):
                return _error(409, "stale_plan", "Plan is stale or not current.")
            operation = next(
                (item for item in snapshot.operations if item.operation_id == data.operation_id), None
            )
            if (operation is None or operation.plan_version != data.plan_version
                    or operation.status != "proposed" or operation.scope != authorization.scope):
                return _error(409, "invalid_operation", "Review requires a proposed registered operation.")
            journal = RedEvidenceStore(store, Path(str(state_db) + ".evidence"))
            journal.append_event(
                authorization.scope, data.request_id,
                actor="operator", action="operator_review_requested",
                outcome="recorded", details={"operation_id": data.operation_id},
            )
        except StoreConflict:
            return _error(404, "assessment_not_found", "Assessment is unavailable.")
        except EvidenceDenied as exc:
            if str(exc) == "duplicate event":
                return _error(409, "duplicate_request", "Review request ID already exists.")
            return _error(503, "journal_unavailable", "Review request could not be recorded.")
        except (OSError, ValueError, sqlite3.DatabaseError):
            return _error(503, "storage_unavailable", "Review request could not be recorded.")
        return JSONResponse(
            status_code=202,
            content={"status": "recorded", "request_id": data.request_id,
                     "effect": "review_only"},
            headers={"Cache-Control": "no-store"},
        )

    return router
