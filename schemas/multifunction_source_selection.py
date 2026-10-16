"""Bounded DEVELOPMENT candidate multifunction source selection, not a patch.

All nine synthetically approved candidate functions, including the six safe
distractors, are schema-permitted. This does NOT tell Q6 which is vulnerable.
The source/task registry must separately validate family, route, source and
line identities, and this response is never Docker or patch authority.
"""
from __future__ import annotations

from typing import Literal, get_args

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CandidateMultifunctionSourceSelection(BaseModel):
    """Four model-authored fields with no paths, shell, URLs, or patch text."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    function_or_route: Literal[
        "lookup_public_beam", "calibration_beam", "read_beam",
        "caption_view", "preview_caption", "ticker_caption",
        "read_public_coil", "record_view", "coil_metadata",
    ]
    sink_line: int = Field(ge=1, le=200)
    root_cause: str = Field(min_length=8, max_length=200)
    confidence: float = Field(ge=0.0, le=1.0)

    @field_validator("root_cause")
    @classmethod
    def root_cause_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("root_cause cannot be blank")
        return value


ALLOWED_FUNCTION_NAMES = frozenset(
    get_args(CandidateMultifunctionSourceSelection.model_fields[
        "function_or_route"
    ].annotation)
)
