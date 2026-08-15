"""Ground-truth records for deliberately vulnerable local scenarios."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from schemas.common import HttpMethod, Identifier, NonEmptyText, RelativeProjectPath, VulnerabilityClass


class ScenarioGroundTruth(BaseModel):
    """Frozen truth used for verification and later research evaluation.

    Ground-truth objects must not be included in model-visible prompts during
    final experiments unless a specific experiment explicitly requires it.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario_id: Identifier
    test_id: Identifier
    vulnerability_class: VulnerabilityClass
    endpoint: str = Field(min_length=1, max_length=300)
    method: HttpMethod
    input_field: Identifier
    vulnerable_source_file: RelativeProjectPath
    vulnerable_function: Identifier
    root_cause: NonEmptyText
    expected_evidence: NonEmptyText
    secure_behavior: NonEmptyText
    normal_behavior: NonEmptyText
    baseline_ref: Identifier
    reset_operation_id: Identifier
