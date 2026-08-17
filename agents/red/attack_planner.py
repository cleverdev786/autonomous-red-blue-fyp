"""Red Team planning that may select only a registered test option."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agents.base import TypedReasoningAgent
from schemas.common import AgentRole
from schemas.red_team import AttackPlan, AttackPlanningCatalog, ReconnaissanceResult


class AttackPlanningAgent(TypedReasoningAgent[AttackPlan]):
    """Recommend one already-approved registered security-test ID."""

    role = AgentRole.RED_ATTACK_PLANNER
    output_model = AttackPlan

    @staticmethod
    def prepare_input(
        *,
        reconnaissance: ReconnaissanceResult,
        catalog: AttackPlanningCatalog,
    ) -> Mapping[str, Any]:
        return {
            "reconnaissance": reconnaissance.model_dump(mode="json"),
            "planning_catalog": catalog.model_dump(mode="json"),
        }
