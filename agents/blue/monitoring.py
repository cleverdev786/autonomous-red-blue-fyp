"""Blue Team monitoring over normalized structured application events."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agents.base import TypedReasoningAgent
from schemas.blue_team import MonitoringResult
from schemas.common import AgentRole
from schemas.logging import LogReadResult


class MonitoringAgent(TypedReasoningAgent[MonitoringResult]):
    """Select suspicious normalized events without receiving execution authority."""

    role = AgentRole.BLUE_MONITORING
    output_model = MonitoringResult

    @staticmethod
    def prepare_input(logs: LogReadResult) -> Mapping[str, Any]:
        return {"logs": logs.model_dump(mode="json")}
