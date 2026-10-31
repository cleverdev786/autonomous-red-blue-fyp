"""Typed T23 contracts for the local SQLite Red assessment queue."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from schemas.common import Identifier
from schemas.red_team import (
    ExecutionWork,
    PlanningWork,
    ReconnaissanceWork,
    VerificationWork,
)

QueuedRedWork = Annotated[
    ReconnaissanceWork | PlanningWork | ExecutionWork | VerificationWork,
    Field(discriminator="stage"),
]


class QueueResourceDTO(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    resource_class: Literal["light", "docker", "zap"]
    requests: int = Field(default=0, ge=0, le=100)
    runtime_seconds: int = Field(default=0, ge=0, le=3600)
    cpu_cores: float = Field(default=0, ge=0, le=8)
    memory_mb: int = Field(default=0, ge=0, le=8192)

    @model_validator(mode="after")
    def resource_shape_matches_class(self):
        values = (
            self.requests,
            self.runtime_seconds,
            self.cpu_cores,
            self.memory_mb,
        )
        if self.resource_class == "light" and any(values):
            raise ValueError("light queue work cannot reserve Docker resources")
        if self.resource_class != "light" and any(value <= 0 for value in values):
            raise ValueError("heavy queue work requires bounded resources")
        return self


class QueueJobDTO(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    sequence: int = Field(ge=1)
    job_id: Identifier
    work: QueuedRedWork
    resource: QueueResourceDTO
    status: Literal["queued", "running", "completed", "failed", "cancelled"]
    enqueued_at: datetime
    claimed_at: datetime | None = None
    finished_at: datetime | None = None
    worker_id: Identifier | None = None
    lease_id: Identifier | None = None
    cancellation_id: Identifier | None = None
    cancellation_requested_at: datetime | None = None

    @field_validator(
        "enqueued_at", "claimed_at", "finished_at", "cancellation_requested_at"
    )
    @classmethod
    def timestamp_is_aware(cls, value):
        if value is not None and value.tzinfo is None:
            raise ValueError("queue timestamps require timezone")
        return value

    @model_validator(mode="after")
    def lifecycle_is_consistent(self):
        lease = (self.claimed_at, self.worker_id, self.lease_id)
        cancellation = (self.cancellation_id, self.cancellation_requested_at)
        if any(value is None for value in cancellation) != all(
            value is None for value in cancellation
        ):
            raise ValueError("queue cancellation metadata must be complete")
        if self.status == "queued" and any(
            value is not None for value in (*lease, self.finished_at, *cancellation)
        ):
            raise ValueError("queued work cannot have a lease")
        if self.status == "running" and (
            any(value is None for value in lease) or self.finished_at is not None
        ):
            raise ValueError("running work requires one active lease")
        if self.status in {"completed", "failed"} and (
            any(value is None for value in (*lease, self.finished_at))
        ):
            raise ValueError("terminal work requires its completed lease")
        if self.status == "cancelled" and (
            self.finished_at is None
            or any(value is None for value in cancellation)
            or (self.claimed_at is None) != (self.worker_id is None)
            or (self.claimed_at is None) != (self.lease_id is None)
        ):
            raise ValueError("cancelled work requires its cancellation record")
        if self.claimed_at is not None and self.claimed_at < self.enqueued_at:
            raise ValueError("queue claim cannot precede enqueue")
        if (
            self.finished_at is not None
            and self.claimed_at is not None
            and self.finished_at < self.claimed_at
        ):
            raise ValueError("queue completion cannot precede claim")
        if (
            self.cancellation_requested_at is not None
            and self.cancellation_requested_at < self.enqueued_at
        ):
            raise ValueError("queue cancellation cannot precede enqueue")
        return self
