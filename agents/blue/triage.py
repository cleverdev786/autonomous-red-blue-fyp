"""Blue Team classification over one normalized application-log run."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agents.base import TypedReasoningAgent
from schemas.blue_team import TriageResult
from schemas.common import AgentRole, ClassificationLabel
from schemas.logging import LogReadResult


class TriageAgent(TypedReasoningAgent[TriageResult]):
    """Return one classification constrained to the frozen RQ2 label set."""

    role = AgentRole.BLUE_TRIAGE
    output_model = TriageResult

    @staticmethod
    def prepare_input(
        *,
        logs: LogReadResult,
        rule_result: TriageResult | None = None,
    ) -> Mapping[str, Any]:
        payload: dict[str, Any] = {
            "logs": logs.model_dump(mode="json"),
            "allowed_labels": [label.value for label in ClassificationLabel],
        }
        if rule_result is not None:
            payload["rule_result"] = rule_result.model_dump(mode="json")
        return payload
