"""M20 DEVELOPMENT feasibility-gate preparation contracts.

These contracts are deliberately separate from final-evaluation configuration.
They describe synthetic evaluator truth, concrete candidate slots, and the
predeclared F1-F4 DEVELOPMENT execution plan only.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from schemas.common import (
    ClassificationLabel,
    Identifier,
    PatchDecision,
    RelativeProjectPath,
    RunType,
)
from schemas.feasibility import ProviderCandidateSpec, SyntheticFixtureTruth
from schemas.feasibility_role_calls import FeasibilityGenerationSettings


_SHA256 = r"^[0-9a-f]{64}$"


class SyntheticVerificationProfile(str, Enum):
    """Deterministic static-verification profile for one synthetic fixture."""

    SQL_PARAMETERIZED = "sql_parameterized"
    HTML_ESCAPED = "html_escaped"
    PATH_CONTAINED = "path_contained"
    BENIGN_NO_ACTION = "benign_no_action"


class SyntheticVerificationExpectation(BaseModel):
    """Evaluator-only expectations used without executing generated source."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    profile: SyntheticVerificationProfile
    target_function: Identifier | None = None
    expected_parameters: tuple[Identifier, ...] = ()
    allowed_import_roots: tuple[Identifier, ...] = ()
    tainted_parameter: Identifier | None = None
    sql_placeholder: str | None = Field(default=None, max_length=8)
    path_root_name: Identifier | None = None
    required_check_ids: tuple[Identifier, ...] = (
        "patch-policy",
        "syntax-startup",
        "normal-functional",
        "registered-security-test",
        "original-replay",
        "regression",
    )

    @model_validator(mode="after")
    def profile_fields_are_complete(self) -> "SyntheticVerificationExpectation":
        if len(self.required_check_ids) != len(set(self.required_check_ids)):
            raise ValueError("synthetic verification check IDs must be unique")
        if self.profile == SyntheticVerificationProfile.BENIGN_NO_ACTION:
            if any(
                value is not None
                for value in (
                    self.target_function,
                    self.tainted_parameter,
                    self.sql_placeholder,
                    self.path_root_name,
                )
            ):
                raise ValueError("benign verification cannot define patch-target fields")
            if self.expected_parameters:
                raise ValueError("benign verification cannot define patch parameters")
            return self
        if self.target_function is None or not self.expected_parameters:
            raise ValueError("malicious verification requires target function and parameters")
        if self.profile == SyntheticVerificationProfile.SQL_PARAMETERIZED:
            if self.sql_placeholder is None:
                raise ValueError("SQL verification requires a placeholder")
        elif self.profile == SyntheticVerificationProfile.HTML_ESCAPED:
            if self.tainted_parameter is None:
                raise ValueError("XSS verification requires a tainted parameter")
        elif self.profile == SyntheticVerificationProfile.PATH_CONTAINED:
            if self.tainted_parameter is None or self.path_root_name is None:
                raise ValueError("path verification requires tainted parameter and root name")
        return self


class SyntheticEvaluatorTruthRecord(BaseModel):
    """Evaluator-only truth plus deterministic verification expectations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    truth: SyntheticFixtureTruth
    verification: SyntheticVerificationExpectation

    @model_validator(mode="after")
    def profile_matches_truth(self) -> "SyntheticEvaluatorTruthRecord":
        benign = self.truth.expected_classification == ClassificationLabel.BENIGN
        if benign != (self.verification.profile == SyntheticVerificationProfile.BENIGN_NO_ACTION):
            raise ValueError("truth classification and verification profile disagree")
        return self


class FeasibilityRuntimeKind(str, Enum):
    LOCAL_LLAMA_CPP = "local_llama_cpp"
    CLOUD_HTTP = "cloud_http"


class FeasibilityCandidateDescriptor(BaseModel):
    """Concrete but unselected DEVELOPMENT candidate slot."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    descriptor_version: Literal["v1", "v2", "v4"] = "v1"
    feasibility_only: Literal[True] = True
    spec: ProviderCandidateSpec
    runtime_kind: FeasibilityRuntimeKind
    source_uri: str = Field(min_length=1, max_length=1000)
    revision: str | None = Field(default=None, max_length=200)
    artifact_file: str | None = Field(default=None, max_length=300)
    artifact_size_label: str | None = Field(default=None, max_length=100)
    runtime_source_uri: str | None = Field(default=None, max_length=1000)
    runtime_version: str = Field(min_length=1, max_length=200)
    runtime_commit: str | None = Field(default=None, max_length=100)
    backend: str = Field(min_length=1, max_length=100)
    gpu_offload_layers: int | None = Field(default=None, ge=0)
    parallel_slots: int = Field(default=1, ge=1, le=8)
    bind_host: str | None = Field(default=None, max_length=100)
    api_model_id: str | None = Field(default=None, max_length=300)
    api_route: str | None = Field(default=None, max_length=1000)
    zero_cost_required: bool = False
    free_tier_reverify_before_run: bool = False
    tools_enabled: Literal[False] = False
    grounding_enabled: Literal[False] = False
    automatic_retries: Literal[0] = 0
    unresolved_settings: tuple[Identifier, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def runtime_fields_match_category(self) -> "FeasibilityCandidateDescriptor":
        if self.runtime_kind == FeasibilityRuntimeKind.LOCAL_LLAMA_CPP:
            if self.spec.artifact_sha256 is None:
                raise ValueError("local candidate requires an artifact SHA-256")
            if not self.revision or not self.artifact_file or not self.runtime_source_uri:
                raise ValueError("local candidate requires revision/artifact/runtime source")
            if self.gpu_offload_layers != 0:
                raise ValueError("initial scored local runtime must use zero GPU offload")
            if self.bind_host != "127.0.0.1":
                raise ValueError("local feasibility server must bind to 127.0.0.1")
            if self.api_model_id is not None or self.api_route is not None:
                raise ValueError("local candidate cannot define a cloud API model/route")
            if self.zero_cost_required or self.free_tier_reverify_before_run:
                raise ValueError("local candidate cannot require cloud free-tier verification")
        else:
            if self.spec.artifact_sha256 is not None:
                raise ValueError("cloud candidate cannot define a local artifact SHA-256")
            if self.artifact_file is not None or self.revision is not None:
                raise ValueError("cloud candidate cannot define local artifact metadata")
            if not self.api_model_id or not self.api_route:
                raise ValueError("cloud candidate requires model ID and API route")
            if not self.zero_cost_required or not self.free_tier_reverify_before_run:
                raise ValueError("cloud candidate must fail closed on zero-cost availability")
        if len(self.unresolved_settings) != len(set(self.unresolved_settings)):
            raise ValueError("unresolved candidate settings must be unique")
        return self


class FeasibilityCandidateManifest(BaseModel):
    """Hash-bound manifest for the three concrete but unselected candidate slots."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest_id: Identifier
    manifest_version: Identifier
    candidate_ids: tuple[Identifier, ...] = Field(min_length=3, max_length=3)
    descriptor_bundle_sha256: str = Field(pattern=_SHA256)
    final_selection_made: Literal[False] = False

    @model_validator(mode="after")
    def exactly_three_unique_candidates(self) -> "FeasibilityCandidateManifest":
        if len(set(self.candidate_ids)) != 3:
            raise ValueError("candidate manifest requires three unique candidate IDs")
        return self


class SyntheticCandidateResponse(BaseModel):
    """Provider-neutral DEVELOPMENT response consumed by the deterministic harness."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fixture_id: Identifier
    repetition_index: int = Field(default=1, ge=1, le=3)
    schema_valid: bool
    predicted_classification: ClassificationLabel | None = None
    predicted_source_file: RelativeProjectPath | None = None
    predicted_function_or_route: Identifier | None = None
    selected_registered_test_id: Identifier | None = None
    replacement_file_path: RelativeProjectPath | None = None
    replacement_source: str | None = Field(default=None, max_length=20_000)
    policy_violation: bool = False
    actual_request_count: int | None = Field(default=None, ge=0, le=20)
    duration_ms: int = Field(default=0, ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def replacement_fields_are_paired(self) -> "SyntheticCandidateResponse":
        if (self.replacement_file_path is None) != (self.replacement_source is None):
            raise ValueError("replacement file path and source must be supplied together")
        return self


class SyntheticPatchVerificationEvidence(BaseModel):
    """Deterministic patch-verification evidence for one synthetic response."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fixture_id: Identifier
    patch_verification_attempted: bool
    patch_policy_pass: bool
    syntax_startup_pass: bool
    normal_functional_pass: bool
    registered_security_test_pass: bool
    original_replay_pass: bool
    regression_pass: bool
    patch_decision: PatchDecision | None = None
    failure_reasons: tuple[str, ...] = ()


class FeasibilityStage(str, Enum):
    F1_INTEGRATION = "f1_integration"
    F2_SEMANTIC = "f2_semantic"
    F3_STABILITY = "f3_stability"
    F4_RESOURCE = "f4_resource"


class FeasibilityGateExecutionPlan(BaseModel):
    """Predeclared DEVELOPMENT-only F1-F4 orchestration plan."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_id: Identifier
    run_type: Literal[RunType.DEVELOPMENT] = RunType.DEVELOPMENT
    fixture_set_id: Identifier
    fixture_set_version: Identifier
    candidate_manifest_id: Identifier
    candidate_ids: tuple[Identifier, Identifier, Identifier]
    prompt_manifest_id: Identifier
    prompt_set_id: Identifier
    prompt_set_version: Identifier
    generation_settings: FeasibilityGenerationSettings
    generation_settings_sha256: str = Field(pattern=_SHA256)
    f2_fixture_ids: tuple[Identifier, ...] = Field(min_length=8, max_length=8)
    f2_patch_fixture_ids: tuple[Identifier, ...] = Field(min_length=6, max_length=6)
    f3_fixture_ids: tuple[Identifier, ...] = Field(min_length=4, max_length=4)
    f3_patch_fixture_ids: tuple[Identifier, ...] = Field(min_length=3, max_length=3)
    f2_logical_call_slots: Literal[30] = 30
    f3_logical_call_slots: Literal[45] = 45
    logical_call_slots_per_candidate: Literal[75] = 75
    stages: tuple[FeasibilityStage, ...] = (
        FeasibilityStage.F1_INTEGRATION,
        FeasibilityStage.F2_SEMANTIC,
        FeasibilityStage.F3_STABILITY,
        FeasibilityStage.F4_RESOURCE,
    )
    provider_selection_deferred: Literal[True] = True
    final_setting_derivation_deferred: Literal[True] = True
    final_evaluation_forbidden: Literal[True] = True

    @model_validator(mode="after")
    def validate_fixed_shapes(self) -> "FeasibilityGateExecutionPlan":
        if len(set(self.candidate_ids)) != 3:
            raise ValueError("feasibility plan requires three unique candidates")
        if len(set(self.f2_fixture_ids)) != 8:
            raise ValueError("F2 requires eight unique fixtures")
        if len(set(self.f3_fixture_ids)) != 4:
            raise ValueError("F3 requires four unique fixtures")
        if not set(self.f3_fixture_ids).issubset(self.f2_fixture_ids):
            raise ValueError("F3 fixtures must be drawn from the F2 fixture set")
        if len(set(self.f2_patch_fixture_ids)) != 6:
            raise ValueError("F2 patch schedule requires six unique fixtures")
        if not set(self.f2_patch_fixture_ids).issubset(self.f2_fixture_ids):
            raise ValueError("F2 patch fixtures must be drawn from the F2 fixture set")
        if len(set(self.f3_patch_fixture_ids)) != 3:
            raise ValueError("F3 patch schedule requires three unique fixtures")
        if not set(self.f3_patch_fixture_ids).issubset(self.f3_fixture_ids):
            raise ValueError("F3 patch fixtures must be drawn from the F3 fixture set")
        if self.stages != (
            FeasibilityStage.F1_INTEGRATION,
            FeasibilityStage.F2_SEMANTIC,
            FeasibilityStage.F3_STABILITY,
            FeasibilityStage.F4_RESOURCE,
        ):
            raise ValueError("feasibility stages must remain in fixed F1-F4 order")
        return self
