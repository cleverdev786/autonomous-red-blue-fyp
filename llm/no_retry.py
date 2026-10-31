"""Milestone 20 Part-B no-hidden-retry contracts and accounting helpers."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from schemas.common import RunStatus


class NoHiddenRetryError(RuntimeError):
    """Raised when a provider cannot satisfy one-dispatch-per-logical-call semantics."""


class DispatchAccountingState(str, Enum):
    NOT_DISPATCHED = "not_dispatched"
    FAILED = "failed"
    COMPLETED = "completed"


class ProviderRetryCapability(BaseModel):
    """Trusted adapter declaration of provider/SDK retry behavior."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    automatic_retries_disabled: bool
    configured_max_retries: int | None = Field(default=None, ge=0)
    actual_request_count_observable: bool = False


class ModelDispatchAccounting(BaseModel):
    """One logical-call accounting decision independent of any provider SDK."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    state: DispatchAccountingState
    budget_units: int = Field(ge=0, le=1)
    agent_call_required: bool
    agent_call_status: RunStatus | None = None
    downstream_semantic_valid: bool | None = None


def validate_no_hidden_retry_capability(capability: ProviderRetryCapability) -> None:
    """Require an adapter configuration that guarantees zero automatic retries."""
    if not capability.automatic_retries_disabled:
        raise NoHiddenRetryError("automatic provider/runtime retries must be disabled")
    if capability.configured_max_retries not in {None, 0}:
        raise NoHiddenRetryError("configured_max_retries must be zero or not applicable")


def require_single_actual_request(*, actual_request_count: int | None) -> None:
    """Fail a call when an observable provider reports more than one actual request."""
    if actual_request_count is None:
        return
    if actual_request_count != 1:
        raise NoHiddenRetryError("one logical model call must dispatch exactly one request")


def account_model_dispatch(
    *,
    dispatched: bool,
    provider_response_received: bool = False,
    schema_valid: bool = False,
    semantic_valid: bool | None = None,
) -> ModelDispatchAccounting:
    """Apply the frozen no-hidden-retry call-accounting semantics.

    Semantic rejection occurs downstream from a successfully completed inference,
    so a schema-valid response is recorded as COMPLETED even when semantic_valid is false.
    """
    if not dispatched:
        return ModelDispatchAccounting(
            state=DispatchAccountingState.NOT_DISPATCHED,
            budget_units=0,
            agent_call_required=False,
        )

    if not provider_response_received or not schema_valid:
        return ModelDispatchAccounting(
            state=DispatchAccountingState.FAILED,
            budget_units=1,
            agent_call_required=True,
            agent_call_status=RunStatus.FAILED,
            downstream_semantic_valid=None,
        )

    return ModelDispatchAccounting(
        state=DispatchAccountingState.COMPLETED,
        budget_units=1,
        agent_call_required=True,
        agent_call_status=RunStatus.COMPLETED,
        downstream_semantic_valid=semantic_valid,
    )
