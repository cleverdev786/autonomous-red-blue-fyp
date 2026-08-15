"""Structured Blue Team monitoring, triage, and code-analysis outputs."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from schemas.common import (
    ClassificationLabel,
    Confidence,
    Identifier,
    NonEmptyText,
    RelativeProjectPath,
)


class MonitoringResult(BaseModel):
    """Normalized evidence selection for the current experiment run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: Identifier
    event_ids: tuple[Identifier, ...] = ()
    suspicious_event_ids: tuple[Identifier, ...] = ()
    summary: NonEmptyText


class TriageResult(BaseModel):
    """Classification constrained to the frozen RQ2 label set."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: Identifier
    is_suspicious: bool
    classification: ClassificationLabel
    confidence: Confidence
    supporting_event_ids: tuple[Identifier, ...] = ()
    reason: NonEmptyText


class SourceLineRange(BaseModel):
    """Bounded source location reference used for evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)

    def model_post_init(self, __context) -> None:
        if self.end_line < self.start_line:
            raise ValueError("end_line must be greater than or equal to start_line")


class CodeFinding(BaseModel):
    """Probable vulnerable code location and root cause."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: Identifier
    file_path: RelativeProjectPath
    function_or_route: NonEmptyText
    root_cause: NonEmptyText
    supporting_lines: tuple[SourceLineRange, ...] = ()
    confidence: Confidence
