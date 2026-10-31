"""Provider-neutral contract for structured model generation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel

from schemas.common import AgentRole
from schemas.experiment_results import ProviderCallUsage
from schemas.experiments import ModelConfiguration, ProviderDescriptor


StructuredModelT = TypeVar("StructuredModelT", bound=BaseModel)


class ProviderBindingError(RuntimeError):
    """Raised when the injected provider does not match the frozen model config."""


@runtime_checkable
class StructuredGenerationProvider(Protocol):
    """Return structured data for one already-authorized agent reasoning call."""

    @property
    def descriptor(self) -> ProviderDescriptor:
        """Describe the actual provider/model/settings used for generation."""

    def generate_structured(
        self,
        *,
        role: AgentRole,
        input_data: Mapping[str, Any],
        response_model: type[StructuredModelT],
    ) -> Mapping[str, Any] | StructuredModelT:
        """Generate one structured response without authorizing any action."""


@runtime_checkable
class ProviderUsageReporter(Protocol):
    """Optional provider capability for explicit token/cost telemetry."""

    def take_last_usage(self) -> ProviderCallUsage:
        """Return and clear telemetry for the most recently completed call."""


def resolve_provider_descriptor(
    provider: object,
    *,
    fallback: ModelConfiguration | None = None,
) -> ProviderDescriptor:
    """Resolve actual adapter identity; development-only fallbacks are unverified."""
    raw = getattr(provider, "descriptor", None)
    if raw is not None:
        return ProviderDescriptor.model_validate(raw)
    if fallback is None:
        raise ProviderBindingError("provider does not expose a verified descriptor")
    return ProviderDescriptor(
        provider=fallback.provider,
        model_name=fallback.model_name,
        temperature=fallback.temperature,
        max_output_tokens=fallback.max_output_tokens,
        seed=fallback.seed,
        final_capable=False,
        identity_verified=False,
    )


def validate_provider_binding(
    *,
    provider: object,
    expected: ModelConfiguration,
    require_final_capable: bool = False,
) -> ProviderDescriptor:
    descriptor = resolve_provider_descriptor(provider, fallback=expected)
    mismatches: list[str] = []
    for field in ("provider", "model_name", "temperature", "max_output_tokens", "seed"):
        if getattr(descriptor, field) != getattr(expected, field):
            mismatches.append(field)
    if mismatches:
        raise ProviderBindingError(
            "provider descriptor differs from experiment model configuration: "
            + ", ".join(mismatches)
        )
    if require_final_capable and (not descriptor.identity_verified or not descriptor.final_capable):
        raise ProviderBindingError(
            "final evaluation requires a verified provider adapter marked final_capable"
        )
    return descriptor


def take_provider_usage(provider: object) -> ProviderCallUsage:
    """Return explicit usage or preserve missing telemetry as NOT_REPORTED."""
    if isinstance(provider, ProviderUsageReporter):
        try:
            return ProviderCallUsage.model_validate(provider.take_last_usage())
        except Exception:
            return ProviderCallUsage()
    return ProviderCallUsage()


def require_research_recording_for_final_capable(provider: object) -> None:
    """Reject raw final-capable adapters at model-calling orchestration boundaries."""
    raw = getattr(provider, "descriptor", None)
    if raw is None:
        return
    descriptor = ProviderDescriptor.model_validate(raw)
    if descriptor.final_capable and not descriptor.research_recording:
        raise ProviderBindingError(
            "final-capable providers must be wrapped by ResearchRecordingProvider "
            "before entering a model-calling flow"
        )
