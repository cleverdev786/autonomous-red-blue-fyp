"""Blue Team patch proposal generation over bounded grounded source context."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agents.base import TypedReasoningAgent
from schemas.blue_team import CodeFinding, SourceReadResult, TriageResult
from schemas.common import AgentRole
from schemas.patches import PatchProposal, PatchRetryFeedback


class PatchGenerationAgent(TypedReasoningAgent[PatchProposal]):
    """Recommend exact-text edits without direct filesystem or Git authority."""

    role = AgentRole.BLUE_PATCH_GENERATION
    output_model = PatchProposal

    @staticmethod
    def prepare_input(
        *,
        triage: TriageResult,
        code_finding: CodeFinding,
        source_context: SourceReadResult,
        attempt_number: int,
        patch_constraints: Mapping[str, Any],
        retry_feedback: PatchRetryFeedback | None = None,
    ) -> Mapping[str, Any]:
        payload: dict[str, Any] = {
            "triage": triage.model_dump(mode="json"),
            "code_finding": code_finding.model_dump(mode="json"),
            "source_context": source_context.model_dump(mode="json"),
            "attempt_number": attempt_number,
            "patch_constraints": dict(patch_constraints),
        }
        if retry_feedback is not None:
            payload["retry_feedback"] = retry_feedback.model_dump(mode="json")
        return payload
