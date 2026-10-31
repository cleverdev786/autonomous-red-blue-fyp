"""Versioned DEVELOPMENT-only Q6 compact source selection and trusted adapter.

Model supplies a suggestion, never trusted run/file identity or patch contents.
The source is an exact approved synthetic snapshot. No filesystem writes.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from schemas.blue_team import (
    BlueTeamAnalysisResult,
    CodeFinding,
    SourceLineRange,
    TriageResult,
)
from schemas.common import ClassificationLabel, WorkflowState
from schemas.experiments import ClassificationMode
from services.trusted_remediation_compiler import EXPECTED_SOURCE_SHA256, SOURCE, TARGET

SCHEMA_VERSION = "q6-compact-source-development-v1"
# Independently fixed source windows, chosen by trusted application orchestration,
# not by model-generated file paths. A window is not evaluator-only ground truth.
WINDOWS = ((38, 56), (77, 89), (92, 109))


class CompactSourceSelection(BaseModel):
    """Four short model-chosen fields. No injected run ID or file path."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    function_or_route: Literal[
        "vulnerable_login", "vulnerable_search", "vulnerable_file_read"
    ]
    sink_line: int = Field(ge=1, le=200)
    root_cause: str = Field(min_length=8, max_length=200)
    confidence: float = Field(ge=0.0, le=1.0)

    @field_validator("root_cause")
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("root cause must not be blank")
        return value


@dataclass(frozen=True)
class TrustedSourceWindow:
    start_line: int
    end_line: int
    numbered_source: str
    source_sha256: str


def load_trusted_source_window(
    *, project_root: Path, start_line: int, end_line: int
) -> TrustedSourceWindow:
    """Read only one approved excerpt of the exact untouched lab source."""
    if (start_line, end_line) not in WINDOWS:
        raise ValueError("source window is not approved")
    path = project_root / SOURCE
    if path.is_symlink() or not path.is_file():
        raise ValueError("source must be a regular, nonsymlink file")
    source_bytes = path.read_bytes()
    digest = sha256(source_bytes).hexdigest()
    if digest != EXPECTED_SOURCE_SHA256:
        raise ValueError("source hash changed")
    source_lines = source_bytes.decode("utf-8").splitlines()
    if end_line > len(source_lines):
        raise ValueError("source window outside file")
    numbered = "\n".join(
        f"{index}: {source_lines[index - 1]}"
        for index in range(start_line, end_line + 1)
    )
    return TrustedSourceWindow(start_line, end_line, numbered, digest)


def build_verified_analysis(
    *,
    project_root: Path,
    trusted_run_id: str,
    triage: TriageResult,
    selection: CompactSourceSelection,
    window: TrustedSourceWindow,
) -> BlueTeamAnalysisResult:
    """Validate model-selected location and attach only trusted identities.

    This does not call a model, select a registered test, or apply a patch.
    The deterministic compiler independently verifies class, sink, and AST.
    """
    if triage.run_id != trusted_run_id or not triage.is_suspicious:
        raise ValueError("triage and trusted run do not match")
    if triage.classification not in (
        ClassificationLabel.SQL_INJECTION,
        ClassificationLabel.XSS,
        ClassificationLabel.PATH_TRAVERSAL,
    ):
        raise ValueError("no actionable vulnerability class")
    fresh = load_trusted_source_window(
        project_root=project_root, start_line=window.start_line, end_line=window.end_line
    )
    if fresh != window:
        raise ValueError("source window has changed")
    if not (window.start_line <= selection.sink_line <= window.end_line):
        raise ValueError("selected sink line is outside the trusted excerpt")
    source = (project_root / SOURCE).read_text(encoding="utf-8")
    tree = ast.parse(source)
    routers = [
        n for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == "build_scenario_router"
    ]
    if len(routers) != 1:
        raise ValueError("source router AST mismatch")
    functions = [
        n for n in routers[0].body
        if isinstance(n, ast.FunctionDef) and n.name == selection.function_or_route
    ]
    if len(functions) != 1:
        raise ValueError("model selected missing or ambiguous function")
    if not (functions[0].lineno <= selection.sink_line <= functions[0].end_lineno):
        raise ValueError("selected line is not inside selected function")
    finding = CodeFinding(
        run_id=trusted_run_id,
        file_path=SOURCE,
        function_or_route=selection.function_or_route,
        root_cause=selection.root_cause,
        supporting_lines=(
            SourceLineRange(start_line=selection.sink_line, end_line=selection.sink_line),
        ),
        confidence=selection.confidence,
    )
    return BlueTeamAnalysisResult(
        run_id=trusted_run_id,
        target_id=TARGET,
        classification_mode=ClassificationMode.LLM_ONLY,
        triage=triage,
        code_finding=finding,
        final_state=WorkflowState.CODE_ANALYSIS,
    )
