"""Common typed contract for untrusted agent reasoning roles."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Generic, TypeVar

from pydantic import BaseModel

from schemas.common import AgentRole


OutputModelT = TypeVar("OutputModelT", bound=BaseModel)


class TypedReasoningAgent(Generic[OutputModelT]):
    """Describe one reasoning role and validate its typed result.

    Agents prepare bounded provider input and own the expected domain output
    type. They do not authorize actions or invoke providers themselves; the
    orchestrator performs provider calls only after deterministic budget checks.
    """

    role: AgentRole
    output_model: type[OutputModelT]

    def validate_output(
        self,
        raw_output: Mapping[str, Any] | BaseModel,
    ) -> OutputModelT:
        """Validate one provider response against the agent's output schema."""
        return self.output_model.model_validate(raw_output)
