"""Zero-inference readiness and evidence-protection contracts for M20 candidate sets."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from schemas.common import Identifier

_SHA256 = r"^[0-9a-f]{64}$"


class EvidenceFileDigest(BaseModel):
    """Immutable digest for one file in an external DEVELOPMENT evidence tree."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    relative_path: str = Field(min_length=1, max_length=1000)
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=_SHA256)


class RoundEvidenceProtectionManifest(BaseModel):
    """Hash-bound snapshot of a completed immutable feasibility round."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest_version: Literal["v1"] = "v1"
    round_id: Identifier
    candidate_ids: tuple[Identifier, Identifier, Identifier]
    file_count: int = Field(ge=1)
    files: tuple[EvidenceFileDigest, ...] = Field(min_length=1)
    bundle_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_file_set(self) -> "RoundEvidenceProtectionManifest":
        paths = tuple(item.relative_path for item in self.files)
        if len(paths) != len(set(paths)):
            raise ValueError("evidence-protection manifest paths must be unique")
        if tuple(sorted(paths)) != paths:
            raise ValueError("evidence-protection manifest paths must be sorted")
        if self.file_count != len(self.files):
            raise ValueError("evidence-protection file count does not match file entries")
        if len(set(self.candidate_ids)) != 3:
            raise ValueError("evidence-protection manifest requires three unique candidates")
        return self


class FrozenContractEvidence(BaseModel):
    """Hashes proving one readiness record is bound to the frozen v1 protocol."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fixture_input_bundle_sha256: str = Field(pattern=_SHA256)
    evaluator_truth_bundle_sha256: str = Field(pattern=_SHA256)
    prompt_bundle_sha256: str = Field(pattern=_SHA256)
    generation_settings_sha256: str = Field(pattern=_SHA256)
    selector_file_sha256: str = Field(pattern=_SHA256)
    response_schema_sha256: tuple[str, str, str, str]
    f2_logical_call_slots: Literal[30] = 30
    f3_logical_call_slots: Literal[45] = 45
    logical_call_slots_per_candidate: Literal[75] = 75

    @model_validator(mode="after")
    def response_hashes_are_sha256(self) -> "FrozenContractEvidence":
        import re

        if any(re.fullmatch(_SHA256, value) is None for value in self.response_schema_sha256):
            raise ValueError("all response-schema hashes must be SHA-256 values")
        return self


class LocalZeroInferenceReadiness(BaseModel):
    """Zero-generation readiness evidence for one pinned local GGUF candidate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_id: Identifier
    candidate_set_version: Literal["v2"] = "v2"
    candidate_descriptor_sha256: str = Field(pattern=_SHA256)
    artifact_sha256: str = Field(pattern=_SHA256)
    artifact_size_bytes: int = Field(gt=0)
    artifact_checksum_verified: bool
    runtime_version: str = Field(min_length=1, max_length=200)
    runtime_commit: str = Field(min_length=1, max_length=100)
    backend: Literal["cpu-x86_64"] = "cpu-x86_64"
    bind_host: Literal["127.0.0.1"] = "127.0.0.1"
    gpu_offload_layers: Literal[0] = 0
    parallel_slots: Literal[1] = 1
    context_window: Literal[8192] = 8192
    model_architecture_recognized: bool
    model_load_succeeded: bool
    health_endpoint_succeeded: bool
    identity_observed: bool
    structured_output_supported: bool
    application_messages_preserved: bool
    license_terms_accepted: bool = False
    automatic_retries_disabled: bool
    actual_request_count_observable: bool
    tools_disabled: bool
    grounding_disabled: bool
    prior_attempt_absent: bool
    oom_during_load: bool = False
    server_crash_during_load: bool = False
    machine_freeze_during_load: bool = False
    baseline_mem_available_bytes: int = Field(gt=0)
    baseline_swap_used_bytes: int = Field(ge=0)
    generation_requests_made: Literal[0] = 0
    frozen_contract: FrozenContractEvidence


class CloudQuotaSnapshot(BaseModel):
    """Trusted account/project quota snapshot captured before the first cloud request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    captured_at_utc: str = Field(min_length=1, max_length=100)
    source_reference: str = Field(min_length=1, max_length=1000)
    account_project_specific_verified: bool
    quota_current_verified: bool
    requests_per_minute: int = Field(gt=0)
    tokens_per_minute: int = Field(gt=0)
    requests_per_day: int = Field(gt=0)
    tokens_per_day: int | None = Field(default=None, gt=0)


class CloudPacingPlan(BaseModel):
    """Precomputed fixed pacing for a 75-slot cloud feasibility attempt."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_count: Literal[75] = 75
    headroom_percent: Literal[20] = 20
    effective_requests_per_minute: int = Field(gt=0)
    effective_tokens_per_minute: int = Field(gt=0)
    total_input_upper_bound_tokens: int = Field(gt=0)
    total_output_upper_bound_tokens: int = Field(gt=0)
    daily_required_tokens: int = Field(gt=0)
    maximum_request_input_upper_bound_tokens: int = Field(gt=0)
    maximum_request_total_upper_bound_tokens: int = Field(gt=0)
    fixed_interval_seconds: float = Field(gt=0)


class CloudZeroInferenceReadiness(BaseModel):
    """Zero-request readiness evidence for the v2 zero-cost cloud candidate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_id: Identifier
    candidate_set_version: Literal["v2"] = "v2"
    candidate_descriptor_sha256: str = Field(pattern=_SHA256)
    api_model_id: str = Field(min_length=1, max_length=300)
    api_route: str = Field(min_length=1, max_length=1000)
    model_active: bool
    stable_endpoint_supported: bool
    free_tier_active: bool
    zero_cost_input_verified: bool
    zero_cost_output_verified: bool
    paid_billing_fallback_authorized: bool
    structured_output_supported: bool
    frozen_response_schemas_accepted: bool
    temperature_accepted: bool
    top_p_accepted: bool
    top_k_accepted: bool
    max_output_tokens_accepted: bool
    tools_disabled: bool
    grounding_disabled: bool
    automatic_retries_disabled: bool
    actual_request_count_observable: bool
    prior_attempt_absent: bool
    generation_requests_made: Literal[0] = 0
    quota: CloudQuotaSnapshot
    pacing: CloudPacingPlan
    frozen_contract: FrozenContractEvidence


class LocalReadinessCarryForwardReferenceV4(BaseModel):
    """Immutable v4 reference to one unchanged v2 local readiness evidence package."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_id: Identifier
    candidate_set_version: Literal["v4"] = "v4"
    source_candidate_set_version: Literal["v2"] = "v2"
    source_readiness_reference: str = Field(min_length=1, max_length=1000)
    source_readiness_bundle_sha256: str = Field(pattern=_SHA256)
    source_inspection_reference: str = Field(min_length=1, max_length=1000)
    source_inspection_bundle_sha256: str = Field(pattern=_SHA256)
    source_candidate_descriptor_sha256: str = Field(pattern=_SHA256)
    target_candidate_descriptor_sha256: str = Field(pattern=_SHA256)
    source_readiness_passed: bool
    source_evidence_immutable_verified: bool
    identity_equivalent_verified: bool
    source_generation_requests_made: Literal[0] = 0
    frozen_contract: FrozenContractEvidence


class CloudZeroGenerationReadinessV4(BaseModel):
    """Zero-provider-request readiness evidence for the v4 C4 cloud candidate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_id: Identifier
    candidate_set_version: Literal["v4"] = "v4"
    candidate_descriptor_sha256: str = Field(pattern=_SHA256)
    api_model_id: str = Field(min_length=1, max_length=300)
    api_route: str = Field(min_length=1, max_length=1000)
    model_active: bool
    stable_endpoint_supported: bool
    free_tier_active: bool
    zero_cost_input_verified: bool
    zero_cost_output_verified: bool
    paid_billing_fallback_authorized: bool
    structured_output_supported: bool
    c4_schema_readiness: Literal["PASS"] = "PASS"
    frozen_response_schemas_accepted: bool
    temperature_accepted: bool
    top_p_accepted: bool
    top_k_accepted: bool
    max_output_tokens_accepted: bool
    streaming_disabled: bool
    tools_disabled: bool
    grounding_disabled: bool
    automatic_retries_disabled: bool
    actual_request_count_observable: bool
    thinking_config_omitted: bool
    prior_attempt_absent: bool
    provider_requests_made: Literal[0] = 0
    generation_requests_made: Literal[0] = 0
    quota: CloudQuotaSnapshot
    pacing: CloudPacingPlan
    frozen_contract: FrozenContractEvidence


class GlobalReadinessDecision(BaseModel):
    """Fail-closed all-candidates barrier evaluated before Round-2 inference."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_set_version: Literal["v2"] = "v2"
    candidate_ids: tuple[Identifier, Identifier, Identifier]
    ready: bool
    failure_reasons: tuple[str, ...] = ()
    total_generation_requests_made: Literal[0] = 0
