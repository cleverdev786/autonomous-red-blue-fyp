"""Red Team advisory interpretation of deterministic execution evidence."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agents.base import TypedReasoningAgent
from schemas.common import AgentRole
from schemas.red_team import AttackPlan, AttackVerification, TestExecutionResult


class AttackVerificationAgent(TypedReasoningAgent[AttackVerification]):
    """Interpret bounded executor evidence without creating new evidence."""

    role = AgentRole.RED_ATTACK_VERIFIER
    output_model = AttackVerification

    @staticmethod
    def prepare_input(
        *,
        plan: AttackPlan,
        execution: TestExecutionResult,
    ) -> Mapping[str, Any]:
        return {
            "attack_plan": plan.model_dump(mode="json"),
            "execution_result": execution.model_dump(mode="json"),
        }
