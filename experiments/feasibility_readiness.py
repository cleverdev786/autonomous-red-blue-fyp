"""Fail-closed zero-inference readiness for M20 DEVELOPMENT candidate sets."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

from experiments.feasibility_assets import LoadedFeasibilityAssets
from experiments.feasibility_role_calls import (
    build_role_call_slots,
    canonical_model_sha256,
    generation_settings_sha256,
    prepare_role_call,
    response_schema_sha256,
)
from schemas.feasibility_gate import FeasibilityCandidateDescriptor, FeasibilityRuntimeKind
from schemas.feasibility_readiness import (
    CloudPacingPlan,
    CloudQuotaSnapshot,
    CloudZeroGenerationReadinessV4,
    CloudZeroInferenceReadiness,
    EvidenceFileDigest,
    FrozenContractEvidence,
    GlobalReadinessDecision,
    LocalReadinessCarryForwardReferenceV4,
    LocalZeroInferenceReadiness,
    RoundEvidenceProtectionManifest,
)
from schemas.feasibility_role_calls import FeasibilityRoleTask


class FeasibilityReadinessError(ValueError):
    """Raised when immutable evidence or zero-inference readiness is invalid."""


ROUND1_CANDIDATE_IDS = (
    "l1-qwen3-8b-q4-k-m",
    "l2-qwen3-4b-q4-k-m",
    "c1-gemini-3.5-flash-lite",
)
ROUND2_CANDIDATE_IDS = (
    "l3-qwen2.5-coder-7b-instruct-q4-k-m",
    "l4-gemma3-12b-it-q4-k-m",
    "c2-gemini-2.5-flash-lite-free",
)
V4_CANDIDATE_IDS = (
    "l3-qwen2.5-coder-7b-instruct-q4-k-m",
    "l4-gemma3-12b-it-q4-k-m",
    "c4-gemini-3.1-flash-lite-free",
)
V4_C4_CANDIDATE_ID = "c4-gemini-3.1-flash-lite-free"
V4_C4_API_MODEL_ID = "gemini-3.1-flash-lite"
V4_C4_API_ROUTE = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "gemini-3.1-flash-lite:generateContent"
)
V4_C4_OBSERVED_RPM = 15
V4_C4_OBSERVED_TPM = 250_000
V4_C4_OBSERVED_RPD = 500
V4_C4_EFFECTIVE_RPM = 12
V4_C4_EFFECTIVE_TPM = 200_000
V4_C4_FIXED_INTERVAL_SECONDS = 5.0
FROZEN_SELECTOR_FILE_SHA256 = (
    "2fcc1b5cf83ea36ff74b7b27c1fdfee8420ee13cd579735b269500568992151a"
)
LICENSE_ACCEPTANCE_REQUIRED = frozenset({"l4-gemma3-12b-it-q4-k-m"})


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha256(value: object) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_round_evidence_protection_manifest(
    *,
    evidence_root: Path,
    round_id: str,
    candidate_ids: tuple[str, str, str] = ROUND1_CANDIDATE_IDS,
) -> RoundEvidenceProtectionManifest:
    """Hash every regular evidence file for a completed round without rewriting it."""
    root = evidence_root.resolve(strict=True)
    rows: list[EvidenceFileDigest] = []
    for candidate_id in candidate_ids:
        candidate_root = root / candidate_id
        if not candidate_root.is_dir():
            raise FeasibilityReadinessError(
                f"missing completed-round candidate evidence directory: {candidate_id}"
            )
        for path in sorted(candidate_root.rglob("*")):
            if path.is_symlink():
                raise FeasibilityReadinessError("evidence-protection manifest forbids symlinks")
            if not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            rows.append(
                EvidenceFileDigest(
                    relative_path=relative,
                    size_bytes=path.stat().st_size,
                    sha256=_sha256_file(path),
                )
            )
    rows.sort(key=lambda item: item.relative_path)
    if not rows:
        raise FeasibilityReadinessError("completed-round evidence manifest cannot be empty")
    bundle = _canonical_sha256([item.model_dump(mode="json") for item in rows])
    return RoundEvidenceProtectionManifest(
        round_id=round_id,
        candidate_ids=candidate_ids,
        file_count=len(rows),
        files=tuple(rows),
        bundle_sha256=bundle,
    )


def verify_round_evidence_protection_manifest(
    *, evidence_root: Path, manifest: RoundEvidenceProtectionManifest
) -> None:
    """Require exact path, size, and SHA equality with a previously frozen round."""
    actual = build_round_evidence_protection_manifest(
        evidence_root=evidence_root,
        round_id=manifest.round_id,
        candidate_ids=manifest.candidate_ids,
    )
    if actual != manifest:
        raise FeasibilityReadinessError("completed-round evidence protection manifest mismatch")


def derive_cloud_pacing(
    *,
    quota: CloudQuotaSnapshot,
    request_input_byte_lengths: tuple[int, ...],
    max_output_tokens: int,
) -> CloudPacingPlan:
    """Derive fixed 20%-headroom pacing before dispatch using conservative byte/token bounds."""
    if len(request_input_byte_lengths) != 75:
        raise FeasibilityReadinessError("cloud pacing requires exactly 75 frozen request inputs")
    if any(value <= 0 for value in request_input_byte_lengths):
        raise FeasibilityReadinessError("cloud request input byte lengths must be positive")
    if max_output_tokens <= 0:
        raise FeasibilityReadinessError("cloud max_output_tokens must be positive")
    if not quota.account_project_specific_verified or not quota.quota_current_verified:
        raise FeasibilityReadinessError("cloud quota must be current account/project-specific evidence")
    if quota.requests_per_day < 75:
        raise FeasibilityReadinessError("cloud requests-per-day quota is insufficient for 75 slots")

    effective_rpm = math.floor(quota.requests_per_minute * 0.80)
    effective_tpm = math.floor(quota.tokens_per_minute * 0.80)
    if effective_rpm < 1 or effective_tpm < 1:
        raise FeasibilityReadinessError("cloud quota is too small after 20% headroom")

    total_input = sum(request_input_byte_lengths)
    total_output = 75 * max_output_tokens
    daily_required = total_input + total_output
    if quota.tokens_per_day is not None and quota.tokens_per_day < daily_required:
        raise FeasibilityReadinessError("cloud tokens-per-day quota is insufficient")

    max_input = max(request_input_byte_lengths)
    max_total = max_input + max_output_tokens
    by_rpm = 60.0 / effective_rpm
    by_tpm = 60.0 * max_total / effective_tpm
    interval = max(by_rpm, by_tpm)
    return CloudPacingPlan(
        effective_requests_per_minute=effective_rpm,
        effective_tokens_per_minute=effective_tpm,
        total_input_upper_bound_tokens=total_input,
        total_output_upper_bound_tokens=total_output,
        daily_required_tokens=daily_required,
        maximum_request_input_upper_bound_tokens=max_input,
        maximum_request_total_upper_bound_tokens=max_total,
        fixed_interval_seconds=interval,
    )


def expected_frozen_contract(
    *, assets: LoadedFeasibilityAssets, selector_file: Path
) -> FrozenContractEvidence:
    """Build the exact frozen protocol identity against which v2 readiness is checked."""
    selector_sha = _sha256_file(selector_file)
    if selector_sha != FROZEN_SELECTOR_FILE_SHA256:
        raise FeasibilityReadinessError("frozen feasibility selector/threshold file changed")
    schema_hashes = tuple(response_schema_sha256(task) for task in FeasibilityRoleTask)
    return FrozenContractEvidence(
        fixture_input_bundle_sha256=assets.input_manifest.input_bundle_sha256,
        evaluator_truth_bundle_sha256=assets.truth_manifest.truth_bundle_sha256,
        prompt_bundle_sha256=assets.prompt_manifest.prompt_bundle_sha256,
        generation_settings_sha256=generation_settings_sha256(
            assets.execution_plan.generation_settings
        ),
        selector_file_sha256=selector_sha,
        response_schema_sha256=schema_hashes,
        f2_logical_call_slots=assets.execution_plan.f2_logical_call_slots,
        f3_logical_call_slots=assets.execution_plan.f3_logical_call_slots,
        logical_call_slots_per_candidate=assets.execution_plan.logical_call_slots_per_candidate,
    )



def frozen_cloud_request_input_byte_lengths(
    assets: LoadedFeasibilityAssets,
) -> tuple[int, ...]:
    """Return the frozen conservative model-visible byte bounds for all 75 slots."""
    fixture_map = {item.fixture_id: item for item in assets.inputs}
    lengths: list[int] = []
    for slot in build_role_call_slots(assets.execution_plan):
        call = prepare_role_call(
            slot=slot,
            fixture=fixture_map[slot.fixture_id],
            prompt=assets.prompts_by_task[slot.task],
            generation_settings=assets.execution_plan.generation_settings,
        )
        lengths.append(
            len(call.prompt.system_prompt.encode("utf-8"))
            + len(call.canonical_user_payload.encode("utf-8"))
        )
    return tuple(lengths)


def _descriptor_identity_without_version(
    descriptor: FeasibilityCandidateDescriptor,
) -> dict[str, object]:
    payload = descriptor.model_dump(mode="json")
    payload.pop("descriptor_version")
    return payload


def validate_v4_local_carry_forward_reference(
    *,
    assets: LoadedFeasibilityAssets,
    selector_file: Path,
    source_descriptor: FeasibilityCandidateDescriptor,
    reference: LocalReadinessCarryForwardReferenceV4,
) -> None:
    """Validate a v4 pointer to immutable v2 L3/L4 readiness evidence without relabeling it."""
    if assets.candidate_manifest.manifest_version != "v4":
        raise FeasibilityReadinessError("local carry-forward requires candidate-set v4 assets")
    if assets.candidate_manifest.candidate_ids != V4_CANDIDATE_IDS:
        raise FeasibilityReadinessError("v4 candidate IDs differ from the approved set")
    if reference.candidate_id not in V4_CANDIDATE_IDS[:2]:
        raise FeasibilityReadinessError("v4 carry-forward may reference only unchanged L3/L4")
    target = next(
        (item for item in assets.candidates if item.spec.candidate_id == reference.candidate_id),
        None,
    )
    if target is None:
        raise FeasibilityReadinessError("v4 carry-forward target descriptor is missing")
    if source_descriptor.spec.candidate_id != reference.candidate_id:
        raise FeasibilityReadinessError("v2 source descriptor candidate identity differs")
    if source_descriptor.descriptor_version != "v2" or target.descriptor_version != "v4":
        raise FeasibilityReadinessError("carry-forward must point from v2 readiness to v4")
    if reference.source_candidate_descriptor_sha256 != canonical_model_sha256(source_descriptor):
        raise FeasibilityReadinessError("v2 source descriptor SHA mismatch")
    if reference.target_candidate_descriptor_sha256 != canonical_model_sha256(target):
        raise FeasibilityReadinessError("v4 target descriptor SHA mismatch")
    source_identity = _descriptor_identity_without_version(source_descriptor)
    target_identity = _descriptor_identity_without_version(target)
    if source_identity != target_identity:
        raise FeasibilityReadinessError("v4 local descriptor differs from v2 beyond version tag")
    expected_contract = expected_frozen_contract(assets=assets, selector_file=selector_file)
    if reference.frozen_contract != expected_contract:
        raise FeasibilityReadinessError("carry-forward frozen protocol hashes differ")
    if not reference.source_readiness_passed:
        raise FeasibilityReadinessError("source v2 readiness did not pass")
    if not reference.source_evidence_immutable_verified:
        raise FeasibilityReadinessError("source v2 evidence immutability is not verified")
    if not reference.identity_equivalent_verified:
        raise FeasibilityReadinessError(
            "v2/v4 local candidate identity equivalence is not verified"
        )


def validate_v4_c4_zero_generation_readiness(
    *,
    assets: LoadedFeasibilityAssets,
    selector_file: Path,
    evidence: CloudZeroGenerationReadinessV4,
) -> None:
    """Fail closed on C4 zero-provider-request readiness; never dispatch model inference."""
    if assets.candidate_manifest.manifest_version != "v4":
        raise FeasibilityReadinessError("C4 readiness requires candidate-set v4 assets")
    if assets.candidate_manifest.candidate_ids != V4_CANDIDATE_IDS:
        raise FeasibilityReadinessError("v4 candidate IDs differ from the approved set")
    if evidence.candidate_id != V4_C4_CANDIDATE_ID:
        raise FeasibilityReadinessError("C4 readiness candidate identity differs")
    descriptor = next(
        (item for item in assets.candidates if item.spec.candidate_id == evidence.candidate_id),
        None,
    )
    if descriptor is None or descriptor.runtime_kind != FeasibilityRuntimeKind.CLOUD_HTTP:
        raise FeasibilityReadinessError("C4 readiness is not bound to the v4 cloud descriptor")
    if evidence.candidate_descriptor_sha256 != canonical_model_sha256(descriptor):
        raise FeasibilityReadinessError("C4 candidate descriptor SHA mismatch")
    if evidence.api_model_id != V4_C4_API_MODEL_ID or descriptor.api_model_id != V4_C4_API_MODEL_ID:
        raise FeasibilityReadinessError("C4 API model identity differs")
    if evidence.api_route != V4_C4_API_ROUTE or descriptor.api_route != V4_C4_API_ROUTE:
        raise FeasibilityReadinessError("C4 API route differs")

    expected_contract = expected_frozen_contract(assets=assets, selector_file=selector_file)
    if evidence.frozen_contract != expected_contract:
        raise FeasibilityReadinessError("C4 frozen protocol hashes differ")

    checks = {
        "model active": evidence.model_active,
        "stable endpoint": evidence.stable_endpoint_supported,
        "free tier": evidence.free_tier_active,
        "zero-cost input": evidence.zero_cost_input_verified,
        "zero-cost output": evidence.zero_cost_output_verified,
        "structured output": evidence.structured_output_supported,
        "frozen schemas": evidence.frozen_response_schemas_accepted,
        "temperature setting": evidence.temperature_accepted,
        "top-p setting": evidence.top_p_accepted,
        "top-k setting": evidence.top_k_accepted,
        "max-output-tokens setting": evidence.max_output_tokens_accepted,
        "non-streaming": evidence.streaming_disabled,
        "tools disabled": evidence.tools_disabled,
        "grounding disabled": evidence.grounding_disabled,
        "automatic retries": evidence.automatic_retries_disabled,
        "request counting": evidence.actual_request_count_observable,
        "thinkingConfig omitted": evidence.thinking_config_omitted,
        "prior attempt absent": evidence.prior_attempt_absent,
    }
    failed = [name for name, passed in checks.items() if not passed]
    if failed:
        raise FeasibilityReadinessError("C4 readiness failed: " + ", ".join(failed))
    if evidence.paid_billing_fallback_authorized:
        raise FeasibilityReadinessError("C4 paid billing fallback is authorized")

    quota = evidence.quota
    if not quota.account_project_specific_verified or not quota.quota_current_verified:
        raise FeasibilityReadinessError("C4 quota is not current account/project-specific evidence")
    if (
        quota.requests_per_minute != V4_C4_OBSERVED_RPM
        or quota.tokens_per_minute != V4_C4_OBSERVED_TPM
        or quota.requests_per_day != V4_C4_OBSERVED_RPD
    ):
        raise FeasibilityReadinessError(
            "C4 observed project quota differs from approved readiness design"
        )

    lengths = frozen_cloud_request_input_byte_lengths(assets)
    expected_pacing = derive_cloud_pacing(
        quota=quota,
        request_input_byte_lengths=lengths,
        max_output_tokens=assets.execution_plan.generation_settings.max_output_tokens,
    )
    if evidence.pacing != expected_pacing:
        raise FeasibilityReadinessError("C4 fixed pacing differs from frozen quota derivation")
    if (
        expected_pacing.effective_requests_per_minute != V4_C4_EFFECTIVE_RPM
        or expected_pacing.effective_tokens_per_minute != V4_C4_EFFECTIVE_TPM
        or expected_pacing.fixed_interval_seconds != V4_C4_FIXED_INTERVAL_SECONDS
    ):
        raise FeasibilityReadinessError("C4 approved 12-RPM/5-second pacing is not reproduced")

def evaluate_global_round2_readiness(
    *,
    assets: LoadedFeasibilityAssets,
    selector_file: Path,
    local_evidence: tuple[LocalZeroInferenceReadiness, LocalZeroInferenceReadiness],
    cloud_evidence: CloudZeroInferenceReadiness,
    cloud_request_input_byte_lengths: tuple[int, ...],
    round1_evidence_protected: bool,
) -> GlobalReadinessDecision:
    """Require all three candidate slots ready before any Round-2 generation can begin."""
    failures: list[str] = []
    if not round1_evidence_protected:
        failures.append("Round-1 evidence protection manifest is not verified")
    expected_ids = assets.candidate_manifest.candidate_ids
    if assets.candidate_manifest.manifest_version != "v2":
        failures.append("candidate manifest is not v2")
    if expected_ids != ROUND2_CANDIDATE_IDS:
        failures.append("v2 candidate IDs differ from the precommitted set")

    expected_contract = expected_frozen_contract(assets=assets, selector_file=selector_file)
    descriptors = {item.spec.candidate_id: item for item in assets.candidates}
    evidence_by_id = {item.candidate_id: item for item in local_evidence}
    evidence_by_id[cloud_evidence.candidate_id] = cloud_evidence
    if set(evidence_by_id) != set(expected_ids):
        failures.append("readiness evidence does not cover exactly the three v2 candidates")

    for candidate_id in expected_ids:
        evidence = evidence_by_id.get(candidate_id)
        descriptor = descriptors.get(candidate_id)
        if evidence is None or descriptor is None:
            continue
        if evidence.candidate_descriptor_sha256 != canonical_model_sha256(descriptor):
            failures.append(f"{candidate_id}: candidate descriptor SHA mismatch")
        if evidence.frozen_contract != expected_contract:
            failures.append(f"{candidate_id}: frozen protocol hashes differ")
        if evidence.generation_requests_made != 0:
            failures.append(f"{candidate_id}: readiness made a generation request")

    for evidence in local_evidence:
        descriptor = descriptors.get(evidence.candidate_id)
        if descriptor is None or descriptor.runtime_kind != FeasibilityRuntimeKind.LOCAL_LLAMA_CPP:
            failures.append(f"{evidence.candidate_id}: local readiness bound to non-local descriptor")
            continue
        checks = {
            "artifact checksum": evidence.artifact_checksum_verified,
            "model architecture": evidence.model_architecture_recognized,
            "model load": evidence.model_load_succeeded,
            "health endpoint": evidence.health_endpoint_succeeded,
            "identity observation": evidence.identity_observed,
            "structured output": evidence.structured_output_supported,
            "application messages": evidence.application_messages_preserved,
            "automatic retries": evidence.automatic_retries_disabled,
            "request counting": evidence.actual_request_count_observable,
            "tools disabled": evidence.tools_disabled,
            "grounding disabled": evidence.grounding_disabled,
            "prior attempt absent": evidence.prior_attempt_absent,
        }
        for name, passed in checks.items():
            if not passed:
                failures.append(f"{evidence.candidate_id}: {name} readiness failed")
        if evidence.oom_during_load or evidence.server_crash_during_load or evidence.machine_freeze_during_load:
            failures.append(f"{evidence.candidate_id}: unsafe local model load")
        if evidence.artifact_sha256 != descriptor.spec.artifact_sha256:
            failures.append(f"{evidence.candidate_id}: artifact SHA differs from descriptor")
        if evidence.runtime_version != descriptor.runtime_version:
            failures.append(f"{evidence.candidate_id}: runtime version differs")
        if evidence.runtime_commit != descriptor.runtime_commit:
            failures.append(f"{evidence.candidate_id}: runtime commit differs")
        if evidence.backend != descriptor.backend or evidence.bind_host != descriptor.bind_host:
            failures.append(f"{evidence.candidate_id}: local backend/bind differs")
        if evidence.gpu_offload_layers != descriptor.gpu_offload_layers:
            failures.append(f"{evidence.candidate_id}: GPU-offload setting differs")
        if evidence.parallel_slots != descriptor.parallel_slots:
            failures.append(f"{evidence.candidate_id}: parallel-slot setting differs")
        if evidence.context_window != assets.execution_plan.generation_settings.context_window:
            failures.append(f"{evidence.candidate_id}: context setting differs")
        if evidence.candidate_id in LICENSE_ACCEPTANCE_REQUIRED and not evidence.license_terms_accepted:
            failures.append(f"{evidence.candidate_id}: required model license terms not accepted")

    cloud_descriptor = descriptors.get(cloud_evidence.candidate_id)
    if cloud_descriptor is None or cloud_descriptor.runtime_kind != FeasibilityRuntimeKind.CLOUD_HTTP:
        failures.append(f"{cloud_evidence.candidate_id}: cloud readiness bound to non-cloud descriptor")
    else:
        cloud_checks = {
            "model active": cloud_evidence.model_active,
            "stable endpoint": cloud_evidence.stable_endpoint_supported,
            "free tier": cloud_evidence.free_tier_active,
            "zero-cost input": cloud_evidence.zero_cost_input_verified,
            "zero-cost output": cloud_evidence.zero_cost_output_verified,
            "structured output": cloud_evidence.structured_output_supported,
            "frozen schemas": cloud_evidence.frozen_response_schemas_accepted,
            "temperature setting": cloud_evidence.temperature_accepted,
            "top-p setting": cloud_evidence.top_p_accepted,
            "top-k setting": cloud_evidence.top_k_accepted,
            "max-output-tokens setting": cloud_evidence.max_output_tokens_accepted,
            "tools disabled": cloud_evidence.tools_disabled,
            "grounding disabled": cloud_evidence.grounding_disabled,
            "automatic retries": cloud_evidence.automatic_retries_disabled,
            "request counting": cloud_evidence.actual_request_count_observable,
            "prior attempt absent": cloud_evidence.prior_attempt_absent,
        }
        for name, passed in cloud_checks.items():
            if not passed:
                failures.append(f"{cloud_evidence.candidate_id}: {name} readiness failed")
        if cloud_evidence.paid_billing_fallback_authorized:
            failures.append(f"{cloud_evidence.candidate_id}: paid billing fallback is authorized")
        if cloud_evidence.api_model_id != cloud_descriptor.api_model_id:
            failures.append(f"{cloud_evidence.candidate_id}: API model differs from descriptor")
        if cloud_evidence.api_route != cloud_descriptor.api_route:
            failures.append(f"{cloud_evidence.candidate_id}: API route differs from descriptor")
        try:
            expected_pacing = derive_cloud_pacing(
                quota=cloud_evidence.quota,
                request_input_byte_lengths=cloud_request_input_byte_lengths,
                max_output_tokens=assets.execution_plan.generation_settings.max_output_tokens,
            )
        except FeasibilityReadinessError as exc:
            failures.append(f"{cloud_evidence.candidate_id}: {exc}")
        else:
            if cloud_evidence.pacing != expected_pacing:
                failures.append(f"{cloud_evidence.candidate_id}: fixed pacing differs from quota derivation")

    return GlobalReadinessDecision(
        candidate_ids=expected_ids,
        ready=not failures,
        failure_reasons=tuple(failures),
        total_generation_requests_made=0,
    )


def require_global_round2_readiness(decision: GlobalReadinessDecision) -> None:
    """Block every Round-2 generation path unless the zero-inference barrier passed."""
    if not decision.ready or decision.total_generation_requests_made != 0:
        reasons = "; ".join(decision.failure_reasons) or "readiness barrier did not pass"
        raise FeasibilityReadinessError("Round-2 inference blocked: " + reasons)
