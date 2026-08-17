"""Red Team reconnaissance reasoning over approved attack-surface metadata."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agents.base import TypedReasoningAgent
from schemas.common import AgentRole
from schemas.red_team import ReconnaissanceResult, RestrictedReconnaissanceContext


class ReconnaissanceAgent(TypedReasoningAgent[ReconnaissanceResult]):
    """Describe the approved target surface without attack-strategy metadata."""

    role = AgentRole.RED_RECONNAISSANCE
    output_model = ReconnaissanceResult

    @staticmethod
    def prepare_input(
        context: RestrictedReconnaissanceContext,
    ) -> Mapping[str, Any]:
        return context.model_dump(mode="json")
