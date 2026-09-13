"""Typed contracts for the Milestone 18 frozen RQ2 classification dataset.

These schemas separate classifier-visible, run-neutral normalized event content
from evaluator-only capture provenance and ground truth.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from schemas.common import ClassificationLabel, Identifier
from schemas.logging import ApplicationEventType, ApplicationLogEvent, LogAttributeValue


class RQ2SourceKind(str, Enum):
    """Registered request-step role used only by trusted dataset generation."""

    CONTROL = "control"
    ATTACK = "attack"


class RQ2ClassifierEvent(BaseModel):
    """Small run-neutral projection of existing ``ApplicationLogEvent`` semantics."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(pattern=r"^1\.0$")
    event_type: ApplicationEventType
    component: Identifier
    route_name: Identifier
    method: str = Field(min_length=1, max_length=10)
    status_code: int | None = Field(default=None, ge=100, le=599)
    attributes: dict[Identifier, LogAttributeValue] = Field(default_factory=dict, max_length=20)
    error_type: Identifier | None = None

    @classmethod
    def from_application_event(cls, event: ApplicationLogEvent) -> "RQ2ClassifierEvent":
        """Strip volatile runtime correlation without changing normalized semantics."""
        return cls(
            schema_version=event.schema_version,
            event_type=event.event_type,
            component=event.component,
            route_name=event.route_name,
            method=event.method,
            status_code=event.status_code,
            attributes=event.attributes,
            error_type=event.error_type,
        )


class RQ2ClassificationDecision(BaseModel):
    """Run-neutral classifier response used by the dedicated RQ2 evaluator."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    classification: ClassificationLabel
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str = Field(min_length=1, max_length=2000)


class RQ2CapturedObservation(BaseModel):
    """Evaluator-only runtime capture consumed by the deterministic dataset builder."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_test_id: Identifier
    source_step_id: Identifier
    source_repetition: int = Field(ge=1, le=10)
    source_kind: RQ2SourceKind
    event: ApplicationLogEvent


class RQ2DatasetInputItem(BaseModel):
    """One classifier-safe frozen item plus reproducibility hashes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: Identifier
    classifier_input_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    semantic_input_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    normalized_event: RQ2ClassifierEvent


class RQ2GroundTruthItem(BaseModel):
    """Evaluator-only label and provenance for one frozen classifier item."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: Identifier
    ground_truth_label: ClassificationLabel
    source_test_id: Identifier
    source_step_id: Identifier
    source_repetition: int = Field(ge=1, le=10)
    source_kind: RQ2SourceKind
    source_target_id: Identifier
    source_endpoint_id: Identifier
    source_run_id: Identifier
    source_request_id: Identifier
    source_event_id: Identifier
    source_notes: str = Field(min_length=1, max_length=1000)

    @field_validator("ground_truth_label")
    @classmethod
    def reject_unknown_truth(cls, value: ClassificationLabel) -> ClassificationLabel:
        if value == ClassificationLabel.UNKNOWN:
            raise ValueError("M18 v1 does not permit unknown as ground truth")
        return value


class RQ2DuplicationAudit(BaseModel):
    """Dataset-level audit of repeated controlled observations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    total_events: int = Field(ge=0)
    unique_event_ids: int = Field(ge=0)
    unique_classifier_input_hashes: int = Field(ge=0)
    unique_semantic_input_hashes: int = Field(ge=0)
    repetition_group_sizes: dict[str, int] = Field(default_factory=dict)


class RQ2DatasetManifest(BaseModel):
    """Integrity and provenance manifest for one frozen RQ2 dataset version."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(pattern=r"^1\.0$")
    dataset_id: Identifier
    dataset_version: Identifier
    source_framework_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    generated_at: datetime
    generation_method: Identifier
    item_count: int = Field(ge=1)
    repetitions_per_test: int = Field(ge=1)
    source_test_ids: tuple[Identifier, ...] = Field(min_length=1)
    expected_class_counts: dict[ClassificationLabel, int]
    inputs_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ground_truth_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    duplication_audit: RQ2DuplicationAudit
