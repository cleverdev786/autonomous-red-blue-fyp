"""Red Team reconnaissance reasoning over approved attack-surface metadata."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any

from agents.base import TypedReasoningAgent
from schemas.common import AgentRole
from schemas.red_team import ReconnaissanceResult, RestrictedReconnaissanceContext
from services.reconnaissance_service import ReconMapping, ReconnaissanceService, ZapObservation


class ReconnaissanceAgent(TypedReasoningAgent[ReconnaissanceResult]):
    """Describe the approved target surface without attack-strategy metadata."""

    @staticmethod
    def map_observations(
        *,
        service: ReconnaissanceService,
        target_id: str,
        observations: Iterable[ZapObservation],
        observed_at: datetime,
    ) -> ReconMapping:
        """Deterministic mapping; observations cannot issue execution approval."""
        return service.map_zap_observations(
            target_id=target_id,
            observations=observations,
            observed_at=observed_at,
        )

    role = AgentRole.RED_RECONNAISSANCE
    output_model = ReconnaissanceResult

    @staticmethod
    def prepare_input(
        context: RestrictedReconnaissanceContext,
    ) -> Mapping[str, Any]:
        return context.model_dump(mode="json")
