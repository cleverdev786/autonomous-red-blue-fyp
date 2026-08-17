"""Provider-neutral contract for structured model generation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, TypeVar

from pydantic import BaseModel

from schemas.common import AgentRole


StructuredModelT = TypeVar("StructuredModelT", bound=BaseModel)


class StructuredGenerationProvider(Protocol):
    """Return structured data for one already-authorized agent reasoning call."""

    def generate_structured(
        self,
        *,
        role: AgentRole,
        input_data: Mapping[str, Any],
        response_model: type[StructuredModelT],
    ) -> Mapping[str, Any] | StructuredModelT:
        """Generate one structured response without authorizing any action."""
