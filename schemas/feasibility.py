"""Milestone 20 Part-B DEVELOPMENT-only feasibility contracts.

These schemas deliberately separate model-visible synthetic fixture inputs from
truth/evaluation records. They are not final-evaluation configuration objects.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from schemas.common import (
    ClassificationLabel,
    HttpMethod,
    Identifier,
    PatchDecision,
    RelativeProjectPath,
    VulnerabilityClass,
)


_SHA256 = r"^[0-9a-f]{64}$"


class ProviderCandidateCategory(str, Enum):
    """Predeclared three-way provider/model feasibility slots."""

    REALISTIC_LOCAL = "realistic_local"
    SMALLER_LOCAL = "smaller_local"
    ZERO_COST_CLOUD = "zero_cost_cloud"


class SyntheticSourceFile(BaseModel):
    """One bounded source file visible to a feasibility candidate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    file_path: RelativeProjectPath
    content: str = Field(min_length=1, max_length=20_000)


class SyntheticRegisteredTest(BaseModel):
    """Bounded registered-test option visible to Red planning."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    test_id: Identifier
    endpoint_id: Identifier
    vulnerability_class: VulnerabilityClass
    safe_description: str = Field(min_length=1, max_length=1000)


class SyntheticFixtureInput(BaseModel):
    """Model-visible DEVELOPMENT fixture with no evaluator truth fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fixture_id: Identifier
    fixture_version: Identifier
    target_id: Identifier
    endpoint_id: Identifier
    method: HttpMethod
    input_fields: tuple[Identifier, ...] = ()
    normalized_event: dict[str, JsonValue] = Field(default_factory=dict)
    source_files: tuple[SyntheticSourceFile, ...] = Field(min_length=1, max_length=8)
    registered_tests: tuple[SyntheticRegisteredTest, ...] = Field(min_length=1, max_length=12)

    @model_validator(mode="after")
    def unique_visible_catalog(self) -> "SyntheticFixtureInput":
        paths = [item.file_path for item in self.source_files]
        tests = [item.test_id for item in self.registered_tests]
        if len(paths) != len(set(paths)):
            raise ValueError("synthetic source file paths must be unique")
        if len(tests) != len(set(tests)):
            raise ValueError("synthetic registered test IDs must be unique")
        return self


class SyntheticFixtureTruth(BaseModel):
    """Evaluator-only truth for one synthetic DEVELOPMENT fixture."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fixture_id: Identifier
    fixture_version: Identifier
    expected_classification: ClassificationLabel
    expected_vulnerability_class: VulnerabilityClass | None = None
    expected_source_file: RelativeProjectPath | None = None
    expected_function_or_route: Identifier | None = None
    expected_registered_test_id: Identifier | None = None
    expected_pre_patch_attack_confirmed: bool
    expected_patch_decision: PatchDecision | None = None

    @model_validator(mode="after")
    def truth_shape_matches_fixture_type(self) -> "SyntheticFixtureTruth":
        if self.expected_classification == ClassificationLabel.BENIGN:
            if self.expected_vulnerability_class is not None:
                raise ValueError("benign truth cannot declare a vulnerability class")
            if any(
                value is not None
                for value in (
                    self.expected_source_file,
                    self.expected_function_or_route,
                    self.expected_registered_test_id,
                    self.expected_patch_decision,
                )
            ):
                raise ValueError("benign truth cannot declare attack/localization/patch truth")
            if self.expected_pre_patch_attack_confirmed:
                raise ValueError("benign fixture cannot require confirmed pre-patch attack")
            return self

        mapping = {
            ClassificationLabel.SQL_INJECTION: VulnerabilityClass.SQL_INJECTION,
            ClassificationLabel.XSS: VulnerabilityClass.XSS,
            ClassificationLabel.PATH_TRAVERSAL: VulnerabilityClass.PATH_TRAVERSAL,
        }
        expected_vulnerability = mapping.get(self.expected_classification)
        if expected_vulnerability is None:
            raise ValueError("synthetic truth may use only approved malicious labels or benign")
        if self.expected_vulnerability_class != expected_vulnerability:
            raise ValueError("classification and vulnerability-class truth must agree")
        if any(
            value is None
            for value in (
                self.expected_source_file,
                self.expected_function_or_route,
                self.expected_registered_test_id,
                self.expected_patch_decision,
            )
        ):
            raise ValueError("malicious truth requires source/function/test/patch truth")
        if not self.expected_pre_patch_attack_confirmed:
            raise ValueError("malicious fixture requires confirmed pre-patch attack truth")
        if self.expected_patch_decision != PatchDecision.ACCEPTED:
            raise ValueError(
                "all malicious feasibility fixtures must be deterministically patchable"
            )
        return self


class SyntheticFixtureInputManifest(BaseModel):
    """Candidate-visible manifest for the hashed synthetic input bundle."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fixture_set_id: Identifier
    fixture_set_version: Identifier
    fixture_ids: tuple[Identifier, ...] = Field(min_length=1)
    input_bundle_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def fixture_ids_are_unique(self) -> "SyntheticFixtureInputManifest":
        if len(self.fixture_ids) != len(set(self.fixture_ids)):
            raise ValueError("synthetic input manifest fixture IDs must be unique")
        return self


class SyntheticFixtureTruthManifest(BaseModel):
    """Evaluator-only manifest for the separate hashed truth bundle."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fixture_set_id: Identifier
    fixture_set_version: Identifier
    fixture_ids: tuple[Identifier, ...] = Field(min_length=1)
    truth_bundle_sha256: str = Field(pattern=_SHA256)
    evaluator_only: Literal[True] = True

    @model_validator(mode="after")
    def fixture_ids_are_unique(self) -> "SyntheticFixtureTruthManifest":
        if len(self.fixture_ids) != len(set(self.fixture_ids)):
            raise ValueError("synthetic truth manifest fixture IDs must be unique")
        return self


class SyntheticFixtureObservation(BaseModel):
    """One candidate observation evaluated against truth outside model execution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fixture_id: Identifier
    repetition_index: int = Field(default=1, ge=1, le=100)
    schema_valid: bool
    predicted_classification: ClassificationLabel | None = None
    predicted_source_file: RelativeProjectPath | None = None
    predicted_function_or_route: Identifier | None = None
    selected_registered_test_id: Identifier | None = None
    patch_decision: PatchDecision | None = None
    policy_violation: bool = False
    unauthorized_path: bool = False
    duration_ms: int = Field(default=0, ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)


class SemanticFeasibilitySummary(BaseModel):
    """Predefined F2 semantic-threshold evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    malicious_total: int = Field(ge=0)
    benign_total: int = Field(ge=0)
    schema_valid_count: int = Field(ge=0)
    malicious_class_correct: int = Field(ge=0)
    benign_class_correct: int = Field(ge=0)
    benign_no_action_correct: int = Field(ge=0)
    malicious_classes_with_correct_example: frozenset[VulnerabilityClass] = frozenset()
    source_file_exact: int = Field(ge=0)
    function_route_exact: int = Field(ge=0)
    registered_test_exact: int = Field(ge=0)
    accepted_patches: int = Field(ge=0)
    classes_with_accepted_patch: frozenset[VulnerabilityClass] = frozenset()
    policy_violation_count: int = Field(ge=0)
    unauthorized_path_count: int = Field(ge=0)
    passed: bool
    failure_reasons: tuple[str, ...] = ()


class StabilityFeasibilitySummary(BaseModel):
    """Predefined F3 repeated-observation stability evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    observation_count: int = Field(ge=0)
    fixture_count: int = Field(ge=0)
    schema_valid_count: int = Field(ge=0)
    classification_correct_count: int = Field(ge=0)
    malicious_localization_pass_count: int = Field(ge=0)
    policy_violation_count: int = Field(ge=0)
    unauthorized_path_count: int = Field(ge=0)
    passed: bool
    failure_reasons: tuple[str, ...] = ()


class ProviderCandidateSpec(BaseModel):
    """One unresolved feasibility candidate; no concrete candidates are instantiated here."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_id: Identifier
    category: ProviderCandidateCategory
    provider_identity: str = Field(min_length=1, max_length=200)
    model_identity: str = Field(min_length=1, max_length=300)
    artifact_sha256: str | None = Field(default=None, pattern=_SHA256)
    runtime_identity: str = Field(min_length=1, max_length=300)


class ProviderIntegrationEvidence(BaseModel):
    """Hard F1 integration evidence used by the candidate gate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    identity_verified: bool
    structured_output_supported: bool
    research_recording_compatible: bool
    automatic_retries_disabled: bool
    actual_request_count_observable: bool
    unrestricted_tools_disabled: bool
    load_or_connect_succeeded: bool
    zero_cost_verified: bool | None = None


class LocalResourceEvidence(BaseModel):
    """Machine-pressure evidence for one local candidate feasibility run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    baseline_mem_available_bytes: int = Field(ge=0)
    minimum_mem_available_bytes: int = Field(ge=0)
    baseline_swap_used_bytes: int = Field(ge=0)
    peak_swap_used_bytes: int = Field(ge=0)
    max_invocation_duration_ms: int = Field(ge=0)
    oom_kill: bool = False
    model_server_crash: bool = False
    machine_freeze: bool = False
    manual_restart_required: bool = False


class ProviderCandidateDecision(BaseModel):
    """One candidate's immutable pass/fail decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate: ProviderCandidateSpec
    hard_pass: bool
    semantic_pass: bool
    stability_pass: bool
    resource_pass: bool
    eligible: bool
    failure_reasons: tuple[str, ...] = ()


class FeasibilityCallMeasurement(BaseModel):
    """Token/time observation used only to derive later frozen settings."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    measurement_id: Identifier
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    duration_ms: int = Field(ge=0)
    schema_valid: bool
    semantically_usable: bool


class ProviderFeasibilityEvidence(BaseModel):
    """Persistable DEVELOPMENT-only evidence for one candidate gate execution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate: ProviderCandidateSpec
    integration: ProviderIntegrationEvidence
    semantic: SemanticFeasibilitySummary
    stability: StabilityFeasibilitySummary
    local_resource: LocalResourceEvidence | None = None
    measurements: tuple[FeasibilityCallMeasurement, ...] = ()
    development_only: Literal[True] = True

    @model_validator(mode="after")
    def local_candidates_require_resource_evidence(self) -> "ProviderFeasibilityEvidence":
        if self.candidate.category != ProviderCandidateCategory.ZERO_COST_CLOUD:
            if self.local_resource is None:
                raise ValueError("local feasibility candidates require local resource evidence")
        return self


class DerivedCapacity(BaseModel):
    """Deterministically derived context/output selection evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    observed_maximum: int = Field(ge=0)
    required_capacity: int = Field(ge=1)
    selected_capacity: int = Field(ge=1)


class DerivedRuntimeLimit(BaseModel):
    """Deterministically derived whole-minute experiment runtime ceiling."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    basis_ms: int = Field(ge=0)
    projected_ms: int = Field(ge=0)
    selected_runtime_seconds: int = Field(ge=60)
