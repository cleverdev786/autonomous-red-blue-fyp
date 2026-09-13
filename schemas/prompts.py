"""Versioned model-visible prompt assets for experiment freezing."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from schemas.common import AgentRole, Identifier


class PromptAsset(BaseModel):
    """One immutable role prompt whose file bytes are frozen separately."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    prompt_id: Identifier
    version: Identifier
    role: AgentRole
    system_prompt: str = Field(min_length=1, max_length=12_000)
