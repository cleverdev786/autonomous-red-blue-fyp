"""Blue Team source-code analysis over bounded approved source snippets."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from agents.base import TypedReasoningAgent
from schemas.blue_team import CodeFinding, SourceReadResult, TriageResult
from schemas.common import AgentRole
from schemas.logging import ApplicationLogEvent


class CodeAnalysisAgent(TypedReasoningAgent[CodeFinding]):
    """Localize a probable root cause without direct filesystem authority."""

    role = AgentRole.BLUE_CODE_ANALYSIS
    output_model = CodeFinding

    @staticmethod
    def prepare_input(
        *,
        triage: TriageResult,
        supporting_events: Sequence[ApplicationLogEvent],
        source_context: SourceReadResult,
    ) -> Mapping[str, Any]:
        return {
            "triage": triage.model_dump(mode="json"),
            "supporting_events": [
                event.model_dump(mode="json") for event in supporting_events
            ],
            "source_context": source_context.model_dump(mode="json"),
        }
