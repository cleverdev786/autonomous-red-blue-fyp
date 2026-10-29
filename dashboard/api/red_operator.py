"""Authenticated Red preview and replay-protected operator review APIs.

Reads stored reconnaissance or records a review request. Does not dispatch Red work.
No secret is generated, printed or persisted by the application.
"""
from __future__ import annotations

import os
import secrets
import sqlite3
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, TypeAdapter, ValidationError

from schemas.common import Identifier
from schemas.red_team_state import (
    AssessmentState,
    FindingState,
    RedAssessmentPageDTO,
    RedAssessmentWorkspaceDTO,
    RedCommandReceiptDTO,
    RedCoverageReadDTO,
    RedDashboardSummaryDTO,
    RedEventPageDTO,
    RedFindingDetailDTO,
    RedFindingPageDTO,
    RedTargetPageDTO,
)
from services.reconnaissance_service import ReconnaissanceService
from services.red_assessment_store import RedAssessmentStore, StoreConflict
from services.red_assessment_supervisor import RedDispatchDenied
from services.red_command_service import RedCommandService
from services.red_evidence_store import EvidenceDenied, RedEvidenceStore
from services.red_read_service import (
    RedReadConflict,
    RedReadNotFound,
    RedReadService,
)
from services.target_registry import TargetRegistry, TargetRegistryError

_IDENTIFIER = TypeAdapter(Identifier)


class ReviewIntent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    assessment_id: Identifier
    plan_version: Identifier
    operation_id: Identifier
    request_id: Identifier
    action: Literal["request_review"]


class CreateAssessmentCommand(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: Identifier
    target_id: Identifier
    mode: Literal["manual", "autonomous"]
    approval_id: Identifier


class AuthorizeAssessmentCommand(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: Identifier
    approval_id: Identifier


class AssessmentCommand(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: Identifier


class StageCommand(AssessmentCommand):
    operation_id: Identifier | None = None


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message}},
        headers={"Cache-Control": "no-store"},
    )


def register_red_operator(
    *,
    state_db: Path,
    allowed_origins: frozenset[str],
    registry: TargetRegistry,
) -> APIRouter:
    router = APIRouter(prefix="/api/red", tags=["Red"])
    secret = os.getenv("MARS_RED_OPERATOR_TOKEN")
    csrf_token = secrets.token_urlsafe(32)
    command_service = RedCommandService(
        state_db=state_db,
        registry=registry,
        budget_file=Path(__file__).resolve().parents[2] / "config/red_standard.json",
    )

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

    def read_service() -> RedReadService:
        return RedReadService(
            RedAssessmentStore(state_db, read_only=True),
            registry,
            command_service.policy.budget,
        )

    def ok(data) -> JSONResponse:
        return JSONResponse(
            data.model_dump(mode="json"),
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )

    async def command_body(request: Request, model):
        content_type = request.headers.get("content-type", "")
        if content_type.split(";", 1)[0].strip().lower() != "application/json":
            return None, _error(415, "invalid_content_type", "JSON content type required.")
        chunks: list[bytes] = []
        total = 0
        async for chunk in request.stream():
            total += len(chunk)
            if total > 2048:
                return None, _error(413, "oversized_request", "Command is too large.")
            chunks.append(chunk)
        try:
            return model.model_validate_json(b"".join(chunks)), None
        except (ValidationError, ValueError):
            return None, _error(422, "invalid_request", "Command fields are invalid.")

    def command_ok(data: RedCommandReceiptDTO, status_code: int = 202) -> JSONResponse:
        return JSONResponse(
            status_code=status_code,
            content=data.model_dump(mode="json"),
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )

    def command_conflict(exc: RedDispatchDenied) -> JSONResponse:
        message = str(exc)
        if "mode" in message or "autonomous" in message:
            code, explanation = "locked_mode", "Assessment mode is locked."
        elif "budget" in message:
            code, explanation = "budget_exhausted", "Authorized resource budget is exhausted."
        elif "stale" in message or "active plan" in message or "approved operation" in message:
            code, explanation = "stale_plan", "The approved plan is stale or unavailable."
        elif "active work" in message or "already" in message:
            code, explanation = "active_operation", "The assessment stage already has active work."
        elif "authorization" in message:
            code, explanation = "authorization_required", "Explicit authorization is required."
        elif "requires" in message:
            code, explanation = "blocked_operation", "Command prerequisites are not satisfied."
        else:
            code, explanation = (
                "command_conflict",
                "Command conflicts with the persisted assessment state.",
            )
        return _error(409, code, explanation)

    async def authenticated_command(request: Request, model):
        blocked = authorize(request, mutation=True)
        if blocked is not None:
            return None, blocked
        return await command_body(request, model)

    @router.post("/assessments", response_model=RedCommandReceiptDTO, status_code=201)
    async def create_assessment(request: Request) -> JSONResponse:
        data, blocked = await authenticated_command(request, CreateAssessmentCommand)
        if blocked is not None:
            return blocked
        try:
            return command_ok(command_service.create(
                request_id=data.request_id,
                target_id=data.target_id,
                mode=data.mode,
                approval_id=data.approval_id,
            ), 201)
        except StoreConflict:
            return _error(409, "idempotency_conflict", "Request ID is already in use.")
        except TargetRegistryError:
            return _error(404, "target_not_found", "Target is unavailable.")
        except (OSError, ValueError, sqlite3.DatabaseError):
            return _error(503, "storage_unavailable", "Assessment draft could not be created.")

    @router.post(
        "/assessments/{assessment_id}/authorize",
        response_model=RedCommandReceiptDTO,
        status_code=202,
    )
    async def authorize_assessment(assessment_id: str, request: Request) -> JSONResponse:
        data, blocked = await authenticated_command(request, AuthorizeAssessmentCommand)
        if blocked is not None:
            return blocked
        if not valid_identifier(assessment_id):
            return _error(404, "assessment_not_found", "Assessment is unavailable.")
        try:
            return command_ok(command_service.authorize(
                assessment_id,
                request_id=data.request_id,
                approval_id=data.approval_id,
            ))
        except StoreConflict:
            return _error(404, "assessment_not_found", "Assessment is unavailable.")
        except RedDispatchDenied as exc:
            return command_conflict(exc)
        except (OSError, ValueError, sqlite3.DatabaseError):
            return _error(503, "storage_unavailable", "Authorization could not be recorded.")

    @router.post(
        "/assessments/{assessment_id}/start",
        response_model=RedCommandReceiptDTO,
        status_code=202,
    )
    async def start_assessment(assessment_id: str, request: Request) -> JSONResponse:
        data, blocked = await authenticated_command(request, AssessmentCommand)
        if blocked is not None:
            return blocked
        if not valid_identifier(assessment_id):
            return _error(404, "assessment_not_found", "Assessment is unavailable.")
        try:
            return command_ok(command_service.start(
                assessment_id,
                request_id=data.request_id,
            ))
        except StoreConflict:
            return _error(404, "assessment_not_found", "Assessment is unavailable.")
        except RedDispatchDenied as exc:
            return command_conflict(exc)
        except (OSError, ValueError, sqlite3.DatabaseError):
            return _error(503, "storage_unavailable", "Assessment could not be started.")

    @router.post(
        "/assessments/{assessment_id}/stages/{stage}/run",
        response_model=RedCommandReceiptDTO,
        status_code=202,
    )
    async def run_stage(assessment_id: str, stage: str, request: Request) -> JSONResponse:
        data, blocked = await authenticated_command(request, StageCommand)
        if blocked is not None:
            return blocked
        if not valid_identifier(assessment_id) or stage not in {
            "reconnaissance", "planning", "execution", "verification",
        }:
            return _error(404, "assessment_or_stage_not_found", "Assessment stage is unavailable.")
        try:
            return command_ok(command_service.run_stage(
                assessment_id,
                stage,
                request_id=data.request_id,
                operation_id=data.operation_id,
            ))
        except StoreConflict:
            return _error(404, "assessment_not_found", "Assessment is unavailable.")
        except RedDispatchDenied as exc:
            return command_conflict(exc)
        except (OSError, ValueError, sqlite3.DatabaseError):
            return _error(503, "storage_unavailable", "Stage could not be queued.")

    @router.post(
        "/assessments/{assessment_id}/cancel",
        response_model=RedCommandReceiptDTO,
        status_code=202,
    )
    async def cancel_assessment(assessment_id: str, request: Request) -> JSONResponse:
        data, blocked = await authenticated_command(request, AssessmentCommand)
        if blocked is not None:
            return blocked
        if not valid_identifier(assessment_id):
            return _error(404, "assessment_not_found", "Assessment is unavailable.")
        try:
            return command_ok(command_service.cancel(
                assessment_id,
                request_id=data.request_id,
            ))
        except StoreConflict:
            return _error(404, "assessment_not_found", "Assessment is unavailable.")
        except RedDispatchDenied as exc:
            return command_conflict(exc)
        except (OSError, ValueError, sqlite3.DatabaseError):
            return _error(503, "storage_unavailable", "Cancellation could not be recorded.")

    @router.get("/targets", response_model=RedTargetPageDTO)
    async def targets(
        request: Request,
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=50, ge=1, le=200),
    ) -> JSONResponse:
        blocked = authorize(request, mutation=False)
        if blocked is not None:
            return blocked
        try:
            return ok(read_service().targets(offset=offset, limit=limit))
        except (OSError, ValidationError, ValueError, sqlite3.DatabaseError):
            return _error(503, "storage_unavailable", "Red targets could not be loaded.")

    @router.get("/assessments", response_model=RedAssessmentPageDTO)
    async def assessments(
        request: Request,
        target_id: str | None = None,
        status: str | None = None,
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=50, ge=1, le=200),
    ) -> JSONResponse:
        blocked = authorize(request, mutation=False)
        if blocked is not None:
            return blocked
        if status is not None:
            try:
                AssessmentState(status)
            except ValueError:
                return _error(422, "invalid_filter", "Assessment status is invalid.")
        if target_id is not None:
            try:
                _IDENTIFIER.validate_python(target_id)
            except ValidationError:
                return _error(404, "target_not_found", "Target is unavailable.")
        try:
            return ok(read_service().assessments(
                target_id=target_id,
                status=status,
                offset=offset,
                limit=limit,
            ))
        except TargetRegistryError:
            return _error(404, "target_not_found", "Target is unavailable.")
        except (OSError, ValidationError, ValueError, sqlite3.DatabaseError):
            return _error(503, "storage_unavailable", "Assessments could not be loaded.")

    @router.get("/findings", response_model=RedFindingPageDTO)
    async def findings(
        request: Request,
        target_id: str | None = None,
        status: str | None = None,
        category: str | None = None,
        severity: str | None = None,
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=50, ge=1, le=200),
    ) -> JSONResponse:
        blocked = authorize(request, mutation=False)
        if blocked is not None:
            return blocked
        try:
            if target_id is not None:
                _IDENTIFIER.validate_python(target_id)
            if category is not None:
                _IDENTIFIER.validate_python(category)
            if status is not None:
                FindingState(status)
            if severity is not None and severity not in {
                "informational", "low", "medium", "high", "critical",
            }:
                raise ValueError("invalid severity")
        except (ValidationError, ValueError):
            return _error(422, "invalid_filter", "Finding filters are invalid.")
        try:
            return ok(read_service().all_findings(
                target_id=target_id,
                status=status,
                category=category,
                severity=severity,
                offset=offset,
                limit=limit,
            ))
        except TargetRegistryError:
            return _error(404, "target_not_found", "Target is unavailable.")
        except (OSError, ValidationError, ValueError, sqlite3.DatabaseError):
            return _error(503, "storage_unavailable", "Findings could not be loaded.")

    @router.get("/findings/{finding_id}", response_model=RedFindingDetailDTO)
    async def finding_detail(finding_id: str, request: Request) -> JSONResponse:
        blocked = authorize(request, mutation=False)
        if blocked is not None:
            return blocked
        if not valid_identifier(finding_id):
            return _error(404, "finding_not_found", "Finding is unavailable.")
        try:
            return ok(read_service().finding_detail(finding_id))
        except RedReadNotFound:
            return _error(404, "finding_not_found", "Finding is unavailable.")
        except RedReadConflict:
            return _error(409, "ambiguous_finding", "Finding identifier is ambiguous.")
        except (OSError, ValidationError, ValueError, sqlite3.DatabaseError):
            return _error(503, "storage_unavailable", "Finding could not be loaded.")

    def valid_identifier(value: str) -> bool:
        try:
            _IDENTIFIER.validate_python(value)
        except ValidationError:
            return False
        return True

    def read_failure(exc: Exception, message: str) -> JSONResponse:
        if isinstance(exc, StoreConflict):
            return _error(404, "assessment_not_found", "Assessment is unavailable.")
        return _error(503, "storage_unavailable", message)

    @router.get("/summary", response_model=RedDashboardSummaryDTO)
    async def summary(
        request: Request,
        target_id: str | None = None,
        status: str | None = None,
    ) -> JSONResponse:
        blocked = authorize(request, mutation=False)
        if blocked is not None:
            return blocked
        if target_id is not None:
            try:
                _IDENTIFIER.validate_python(target_id)
            except ValidationError:
                return _error(404, "target_not_found", "Target is unavailable.")
        if status is not None:
            try:
                AssessmentState(status)
            except ValueError:
                return _error(422, "invalid_filter", "Assessment status is invalid.")
        try:
            return ok(read_service().summary(target_id=target_id, status=status))
        except TargetRegistryError:
            return _error(404, "target_not_found", "Target is unavailable.")
        except (OSError, ValidationError, ValueError, sqlite3.DatabaseError):
            return _error(503, "storage_unavailable", "Red summary could not be loaded.")

    @router.get(
        "/assessments/{assessment_id}",
        response_model=RedAssessmentWorkspaceDTO,
    )
    async def assessment_workspace(
        assessment_id: str,
        request: Request,
    ) -> JSONResponse:
        blocked = authorize(request, mutation=False)
        if blocked is not None:
            return blocked
        if not valid_identifier(assessment_id):
            return _error(404, "assessment_not_found", "Assessment is unavailable.")
        try:
            return ok(read_service().workspace(assessment_id))
        except (StoreConflict, OSError, ValidationError, ValueError, sqlite3.DatabaseError) as exc:
            return read_failure(exc, "Assessment could not be loaded.")

    @router.get(
        "/assessments/{assessment_id}/events",
        response_model=RedEventPageDTO,
    )
    async def assessment_events(
        assessment_id: str,
        request: Request,
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=50, ge=1, le=200),
    ) -> JSONResponse:
        blocked = authorize(request, mutation=False)
        if blocked is not None:
            return blocked
        if not valid_identifier(assessment_id):
            return _error(404, "assessment_not_found", "Assessment is unavailable.")
        try:
            return ok(read_service().events(
                assessment_id,
                offset=offset,
                limit=limit,
            ))
        except (StoreConflict, OSError, ValidationError, ValueError, sqlite3.DatabaseError) as exc:
            return read_failure(exc, "Assessment events could not be loaded.")

    @router.get(
        "/assessments/{assessment_id}/findings",
        response_model=RedFindingPageDTO,
    )
    async def assessment_findings(
        assessment_id: str,
        request: Request,
        status: str | None = None,
        category: str | None = None,
        severity: str | None = None,
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=50, ge=1, le=200),
    ) -> JSONResponse:
        blocked = authorize(request, mutation=False)
        if blocked is not None:
            return blocked
        if not valid_identifier(assessment_id):
            return _error(404, "assessment_not_found", "Assessment is unavailable.")
        try:
            if category is not None:
                _IDENTIFIER.validate_python(category)
            if status is not None:
                FindingState(status)
            if severity is not None and severity not in {
                "informational", "low", "medium", "high", "critical",
            }:
                raise ValueError("invalid severity")
        except (ValidationError, ValueError):
            return _error(422, "invalid_filter", "Finding filters are invalid.")
        try:
            return ok(read_service().findings(
                assessment_id,
                status=status,
                category=category,
                severity=severity,
                offset=offset,
                limit=limit,
            ))
        except (StoreConflict, OSError, ValidationError, ValueError, sqlite3.DatabaseError) as exc:
            return read_failure(exc, "Assessment findings could not be loaded.")

    @router.get(
        "/assessments/{assessment_id}/coverage",
        response_model=RedCoverageReadDTO,
    )
    async def assessment_coverage(
        assessment_id: str,
        request: Request,
    ) -> JSONResponse:
        blocked = authorize(request, mutation=False)
        if blocked is not None:
            return blocked
        if not valid_identifier(assessment_id):
            return _error(404, "assessment_not_found", "Assessment is unavailable.")
        try:
            return ok(read_service().coverage(assessment_id))
        except (StoreConflict, OSError, ValidationError, ValueError, sqlite3.DatabaseError) as exc:
            return read_failure(exc, "Assessment coverage could not be loaded.")

    @router.get("/operator/csrf")
    async def challenge(request: Request):
        blocked = authorize(request, mutation=False)
        if blocked is not None:
            return blocked
        return JSONResponse(
            {"csrf_token": csrf_token},
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )

    @router.get("/operator/assessments/{assessment_id}/reconnaissance-preview")
    async def reconnaissance_preview(assessment_id: str, request: Request) -> JSONResponse:
        blocked = authorize(request, mutation=False)
        if blocked is not None:
            return blocked
        try:
            _IDENTIFIER.validate_python(assessment_id)
        except ValidationError:
            return _error(404, "assessment_not_found", "Assessment is unavailable.")
        try:
            snapshot, authorization = RedAssessmentStore(
                state_db, read_only=True
            ).load(assessment_id)
            preview = ReconnaissanceService(registry=registry).build_preview(
                authorization=authorization,
                candidates=snapshot.candidates,
            )
        except StoreConflict:
            return _error(404, "assessment_not_found", "Assessment is unavailable.")
        except (
            OSError,
            TargetRegistryError,
            ValidationError,
            ValueError,
            sqlite3.DatabaseError,
        ):
            return _error(503, "storage_unavailable", "Preview could not be loaded.")
        return JSONResponse(
            preview.model_dump(mode="json"),
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )

    @router.post("/operator/reviews")
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
