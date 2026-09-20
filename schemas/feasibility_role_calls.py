"""Role-separated M20 DEVELOPMENT feasibility-call contracts.

These schemas freeze the four zero-shot role outputs, common DEVELOPMENT
settings, prompt manifest references, and one-call evidence semantics. They are
not final-evaluation configuration and never contain evaluator truth.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from schemas.common import AgentRole, ClassificationLabel, Identifier, RelativeProjectPath


_SHA256 = r"^[0-9a-f]{64}$"


class FeasibilityRoleTask(str, Enum):
    """The four independent model capabilities measured in DEVELOPMENT feasibility."""

    TEST_SELECTION = "test-selection"
    CLASSIFICATION = "classification"
    SOURCE_ANALYSIS = "source-analysis"
    PATCH_GENERATION = "patch-generation"


class FeasibilityCallPhase(str, Enum):
    F2 = "f2"
    F3 = "f3"


class FeasibilityRoleCallResultStatus(str, Enum):
    COMPLETED = "completed"
    FAILED = "failed"
    INCOMPLETE = "incomplete"


class FeasibilityRoleCallDispatchStatus(str, Enum):
    DISPATCHED = "dispatched"
    NOT_DISPATCHED = "not_dispatched"


class FeasibilityRoleFailureKind(str, Enum):
    TRANSPORT_ERROR = "transport_error"
    TIMEOUT = "timeout"
    RATE_LIMIT = "rate_limit"
    SERVER_ERROR = "server_error"
    REFUSAL = "refusal"
    EMPTY_RESPONSE = "empty_response"
    SCHEMA_INVALID = "schema_invalid"
    SEMANTIC_INVALID = "semantic_invalid"
    TRUNCATED = "truncated"
    HIDDEN_RETRY = "hidden_retry"
    CATASTROPHIC_RUNTIME = "catastrophic_runtime"
    PROTOCOL_VIOLATION = "protocol_violation"


class FeasibilityGenerationSettings(BaseModel):
    """Common DEVELOPMENT-only settings shared by L1, L2, and C1."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    context_window: Literal[8192] = 8192
    max_output_tokens: Literal[4096] = 4096
    temperature: Literal[0.7] = 0.7
    top_p: Literal[0.8] = 0.8
    top_k: Literal[20] = 20
    seed: None = None
    streaming: Literal[False] = False
    automatic_retries: Literal[0] = 0
    tools_enabled: Literal[False] = False
    grounding_enabled: Literal[False] = False
    request_timeout_seconds: Literal[600] = 600


class FeasibilityTestSelectionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    fixture_id: Identifier
    selected_registered_test_id: Identifier | None = None


class FeasibilityClassificationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    fixture_id: Identifier
    predicted_classification: ClassificationLabel


class FeasibilitySourceAnalysisResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    fixture_id: Identifier
    predicted_source_file: RelativeProjectPath | None = None
    predicted_function_or_route: Identifier | None = None


class FeasibilityPatchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    fixture_id: Identifier
    replacement_file_path: RelativeProjectPath | None = None
    replacement_source: str | None = Field(default=None, max_length=20_000)

    @model_validator(mode="after")
    def replacement_fields_are_paired(self) -> "FeasibilityPatchResponse":
        if (self.replacement_file_path is None) != (self.replacement_source is None):
            raise ValueError("replacement file path and source must be supplied together")
        return self


class FeasibilityPromptReference(BaseModel):
    """File/hash binding for one DEVELOPMENT role prompt and its response schema."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    prompt_id: Identifier
    version: Identifier
    role: AgentRole
    task: FeasibilityRoleTask
    path: RelativeProjectPath
    file_sha256: str = Field(pattern=_SHA256)
    response_schema_id: Identifier
    response_schema_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def task_role_matches(self) -> "FeasibilityPromptReference":
        expected = role_for_task(self.task)
        if self.role != expected:
            raise ValueError("feasibility prompt task is bound to the wrong AgentRole")
        return self


class FeasibilityPromptManifest(BaseModel):
    """Hash-frozen DEVELOPMENT-only prompt set."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest_id: Identifier
    prompt_set_id: Identifier
    version: Identifier
    references: tuple[FeasibilityPromptReference, ...] = Field(min_length=4, max_length=4)
    prompt_bundle_sha256: str = Field(pattern=_SHA256)
    development_only: Literal[True] = True
    final_evaluation_forbidden: Literal[True] = True

    @model_validator(mode="after")
    def exactly_four_unique_tasks(self) -> "FeasibilityPromptManifest":
        if {item.task for item in self.references} != set(FeasibilityRoleTask):
            raise ValueError("prompt manifest requires exactly one reference per role task")
        if len({item.prompt_id for item in self.references}) != 4:
            raise ValueError("feasibility prompt IDs must be unique")
        if len({item.path for item in self.references}) != 4:
            raise ValueError("feasibility prompt paths must be unique")
        return self


class FeasibilityRoleCallSlot(BaseModel):
    """One predetermined logical provider slot; candidate identity is added out-of-band."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    phase: FeasibilityCallPhase
    fixture_id: Identifier
    repetition_index: int = Field(ge=1, le=3)
    task: FeasibilityRoleTask
    agent_role: AgentRole

    @model_validator(mode="after")
    def slot_shape_is_fixed(self) -> "FeasibilityRoleCallSlot":
        if self.agent_role != role_for_task(self.task):
            raise ValueError("role-call slot task/role mapping differs from frozen design")
        if self.phase == FeasibilityCallPhase.F2 and self.repetition_index != 1:
            raise ValueError("F2 role-call slots must use repetition 1")
        return self


class FeasibilityRoleCallTransportResult(BaseModel):
    """One adapter invocation result before trusted JSON/schema validation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    actual_request_count: int = Field(ge=1, le=20)
    raw_response_text: str | None = Field(default=None, max_length=100_000)
    duration_ms: int = Field(default=0, ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    failure_kind: FeasibilityRoleFailureKind | None = None
    catastrophic: bool = False

    @model_validator(mode="after")
    def failure_shape_is_consistent(self) -> "FeasibilityRoleCallTransportResult":
        if self.raw_response_text is None and self.failure_kind is None:
            raise ValueError("missing provider response requires an explicit failure kind")
        if self.catastrophic and self.failure_kind is None:
            raise ValueError("catastrophic transport results require a failure kind")
        return self


class FeasibilityRoleCallRecord(BaseModel):
    """Immutable evidence for one predetermined role-call slot."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    call_id: Identifier
    candidate_id: Identifier
    phase: FeasibilityCallPhase
    fixture_id: Identifier
    repetition_index: int = Field(ge=1, le=3)
    task: FeasibilityRoleTask
    agent_role: AgentRole
    prompt_id: Identifier
    prompt_version: Identifier
    system_prompt_sha256: str = Field(pattern=_SHA256)
    canonical_user_payload_sha256: str = Field(pattern=_SHA256)
    response_schema_id: Identifier
    response_schema_sha256: str = Field(pattern=_SHA256)
    generation_settings_sha256: str = Field(pattern=_SHA256)
    provider: str = Field(min_length=1, max_length=200)
    model_name: str = Field(min_length=1, max_length=500)
    dispatch_status: FeasibilityRoleCallDispatchStatus
    actual_request_count: int = Field(ge=0, le=20)
    duration_ms: int = Field(default=0, ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    raw_response_sha256: str | None = Field(default=None, pattern=_SHA256)
    parsed_response: dict[str, JsonValue] | None = None
    result_status: FeasibilityRoleCallResultStatus
    failure_kind: FeasibilityRoleFailureKind | None = None

    @model_validator(mode="after")
    def evidence_shape_is_consistent(self) -> "FeasibilityRoleCallRecord":
        if self.agent_role != role_for_task(self.task):
            raise ValueError("role-call record task/role mapping differs from frozen design")
        if self.dispatch_status == FeasibilityRoleCallDispatchStatus.NOT_DISPATCHED:
            if self.actual_request_count != 0:
                raise ValueError("not-dispatched slots must report zero provider requests")
            if self.result_status != FeasibilityRoleCallResultStatus.INCOMPLETE:
                raise ValueError("not-dispatched slots must remain INCOMPLETE")
            if self.raw_response_sha256 is not None or self.parsed_response is not None:
                raise ValueError("not-dispatched slots cannot contain provider output")
            return self
        if self.actual_request_count < 1:
            raise ValueError("dispatched role calls require at least one actual request")
        if self.result_status == FeasibilityRoleCallResultStatus.COMPLETED:
            if self.actual_request_count != 1:
                raise ValueError("completed role calls require exactly one provider request")
            if self.failure_kind is not None:
                raise ValueError("completed role calls cannot have a failure kind")
            if self.raw_response_sha256 is None or self.parsed_response is None:
                raise ValueError("completed role calls require raw and parsed response evidence")
        elif self.result_status == FeasibilityRoleCallResultStatus.FAILED:
            if self.failure_kind is None:
                raise ValueError("failed role calls require a failure kind")
        else:
            raise ValueError("dispatched role calls cannot be INCOMPLETE")
        return self


def role_for_task(task: FeasibilityRoleTask) -> AgentRole:
    """Bind DEVELOPMENT tasks to existing architecture roles; no synthetic roles exist."""
    return {
        FeasibilityRoleTask.TEST_SELECTION: AgentRole.RED_ATTACK_PLANNER,
        FeasibilityRoleTask.CLASSIFICATION: AgentRole.BLUE_TRIAGE,
        FeasibilityRoleTask.SOURCE_ANALYSIS: AgentRole.BLUE_CODE_ANALYSIS,
        FeasibilityRoleTask.PATCH_GENERATION: AgentRole.BLUE_PATCH_GENERATION,
    }[task]


class FeasibilityRawRoleResponse(BaseModel):
    """Raw provider response retained separately from the normalized call record."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    call_id: Identifier
    sha256: str = Field(pattern=_SHA256)
    raw_response_text: str = Field(max_length=100_000)

    @model_validator(mode="after")
    def raw_hash_matches(self) -> "FeasibilityRawRoleResponse":
        import hashlib

        actual = hashlib.sha256(self.raw_response_text.encode("utf-8")).hexdigest()
        if actual != self.sha256:
            raise ValueError("raw response SHA-256 does not match retained bytes")
        return self
