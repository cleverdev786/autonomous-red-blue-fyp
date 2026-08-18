"""Typed structured application logging and audit contracts."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import TypeAlias

from pydantic import BaseModel, ConfigDict, Field

from schemas.common import Identifier, NonEmptyText, PolicyReasonCode


class ApplicationEventType(str, Enum):
    """Observable application event categories required by Milestone 9."""

    HTTP_REQUEST = "http_request"
    VALIDATION_EVENT = "validation_event"
    DATABASE_EVENT = "database_event"
    FILE_ACCESS_EVENT = "file_access_event"
    APPLICATION_ERROR = "application_error"


class AuditPolicyDecision(str, Enum):
    """Deterministic policy outcome recorded by the audit service."""

    ALLOWED = "allowed"
    BLOCKED = "blocked"
    NOT_APPLICABLE = "not_applicable"


class AuditExecutionStatus(str, Enum):
    """Execution state for one audited sensitive operation."""

    AUTHORIZED = "authorized"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"


LogAttributeValue: TypeAlias = str | int | float | bool | None


class ApplicationLogEvent(BaseModel):
    """Normalized Blue-facing application observation with run correlation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(pattern=r"^1\.0$")
    event_id: Identifier
    timestamp: datetime
    run_id: Identifier
    request_id: Identifier
    event_type: ApplicationEventType
    component: Identifier
    route_name: Identifier
    method: str = Field(min_length=1, max_length=10)
    status_code: int | None = Field(default=None, ge=100, le=599)
    attributes: dict[Identifier, LogAttributeValue] = Field(
        default_factory=dict,
        max_length=20,
    )
    error_type: Identifier | None = None


class LogReadResult(BaseModel):
    """Validated application events and bounded parser diagnostics for one run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_id: Identifier
    run_id: Identifier
    events: tuple[ApplicationLogEvent, ...] = ()
    ignored_line_count: int = Field(default=0, ge=0)
    malformed_line_count: int = Field(default=0, ge=0)
    duplicate_event_count: int = Field(default=0, ge=0)


class AuditEvent(BaseModel):
    """Append-oriented record for one trusted sensitive operation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: Identifier
    timestamp: datetime
    run_id: Identifier
    component: Identifier
    actor_type: Identifier
    operation: Identifier
    target: NonEmptyText
    policy_decision: AuditPolicyDecision
    policy_reason: PolicyReasonCode | None = None
    execution_status: AuditExecutionStatus
    duration_ms: int = Field(default=0, ge=0)
    evidence_reference: str | None = Field(default=None, max_length=1000)
    error_code: Identifier | None = None
