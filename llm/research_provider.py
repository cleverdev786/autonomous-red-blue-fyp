"""Provider binding and reusable research-call observation.

This wrapper never grants model authority. It observes already-authorized calls
and can either persist call evidence immediately or leave it pending so a caller
can attach a classification observation ID first.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
import hashlib
import time
from typing import Any

from schemas.common import AgentRole, RunStatus
from schemas.experiment_results import AgentCallRecord
from schemas.experiments import ModelConfiguration, ProviderDescriptor
from llm.interface import (
    StructuredGenerationProvider,
    StructuredModelT,
    take_provider_usage,
    validate_provider_binding,
)
from storage.repositories import ExperimentWriteRepository


class ResearchProviderError(RuntimeError):
    """Raised when research-call recording cannot preserve call identity."""


LinkageResolver = Callable[[AgentRole, Mapping[str, Any]], dict[str, int | None]]


def _default_linkage(role: AgentRole, input_data: Mapping[str, Any]) -> dict[str, int | None]:
    attempt = input_data.get("attempt_number")
    patch_attempt = (
        attempt
        if role in {AgentRole.BLUE_PATCH_GENERATION, AgentRole.BLUE_SINGLE_AGENT}
        and isinstance(attempt, int)
        and attempt >= 1
        else None
    )
    return {
        "classification_observation_id": None,
        "patch_attempt_number": patch_attempt,
        "red_attempt_number": None,
    }


class ResearchRecordingProvider:
    """Record one AgentCallRecord for every delegated structured model call."""

    def __init__(
        self,
        *,
        delegate: StructuredGenerationProvider,
        run_id: str,
        model_configuration: ModelConfiguration,
        first_sequence_number: int = 1,
        write_repository: ExperimentWriteRepository | None = None,
        linkage_resolver: LinkageResolver = _default_linkage,
        require_verified_binding: bool = False,
    ) -> None:
        if first_sequence_number < 1:
            raise ResearchProviderError("first_sequence_number must be >= 1")
        self.delegate = delegate
        self.run_id = run_id
        self.model_configuration = model_configuration
        self.write_repository = write_repository
        self.linkage_resolver = linkage_resolver
        self._next_sequence_number = first_sequence_number
        self._pending: list[AgentCallRecord] = []
        self._descriptor = validate_provider_binding(
            provider=delegate,
            expected=model_configuration,
            require_final_capable=require_verified_binding,
        )

    @property
    def descriptor(self) -> ProviderDescriptor:
        return self._descriptor.model_copy(update={"research_recording": True})

    def generate_structured(
        self,
        *,
        role: AgentRole,
        input_data: Mapping[str, Any],
        response_model: type[StructuredModelT],
    ) -> Mapping[str, Any] | StructuredModelT:
        sequence = self._next_sequence_number
        self._next_sequence_number += 1
        started = time.monotonic()
        status = RunStatus.COMPLETED
        try:
            result = self.delegate.generate_structured(
                role=role,
                input_data=input_data,
                response_model=response_model,
            )
            return response_model.model_validate(result)
        except Exception:
            status = RunStatus.FAILED
            raise
        finally:
            usage = take_provider_usage(self.delegate)
            linkage = self.linkage_resolver(role, input_data)
            call = AgentCallRecord(
                call_id=self._call_id(sequence=sequence, role=role),
                agent_role=role,
                sequence_number=sequence,
                provider=self._descriptor.provider,
                model_name=self._descriptor.model_name,
                duration_ms=max(0, int((time.monotonic() - started) * 1000)),
                result_status=status,
                classification_observation_id=linkage.get("classification_observation_id"),
                patch_attempt_number=linkage.get("patch_attempt_number"),
                red_attempt_number=linkage.get("red_attempt_number"),
                input_tokens=usage.input_tokens,
                output_tokens=usage.output_tokens,
                token_usage_status=usage.token_usage_status,
                estimated_cost=usage.estimated_cost,
                cost_status=usage.cost_status,
                currency=usage.currency,
                pricing_version=usage.pricing_version,
            )
            if self.write_repository is None:
                self._pending.append(call)
            else:
                self.write_repository.record_agent_call(self.run_id, call)

    def pop_pending_call(self) -> AgentCallRecord:
        if not self._pending:
            raise ResearchProviderError("no pending provider call is available")
        return self._pending.pop(0)

    def drain_pending_calls(self) -> tuple[AgentCallRecord, ...]:
        calls = tuple(self._pending)
        self._pending.clear()
        return calls

    def _call_id(self, *, sequence: int, role: AgentRole) -> str:
        digest = hashlib.sha256(self.run_id.encode("utf-8")).hexdigest()[:12]
        return f"model-{sequence}-{role.value}-{digest}"
