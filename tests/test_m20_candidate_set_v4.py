"""Candidate-set v4 representation and zero-provider-request C4 readiness support."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from pydantic import ValidationError

from experiments.feasibility_assets import FeasibilityAssetError, load_feasibility_assets
from experiments.feasibility_readiness import (
    V4_C4_API_MODEL_ID,
    V4_C4_API_ROUTE,
    V4_C4_CANDIDATE_ID,
    V4_CANDIDATE_IDS,
    FeasibilityReadinessError,
    derive_cloud_pacing,
    expected_frozen_contract,
    frozen_cloud_request_input_byte_lengths,
    validate_v4_c4_zero_generation_readiness,
    validate_v4_local_carry_forward_reference,
)
from experiments.feasibility_role_calls import canonical_model_sha256
from schemas.feasibility import ProviderCandidateCategory
from schemas.feasibility_readiness import (
    CloudQuotaSnapshot,
    CloudZeroGenerationReadinessV4,
    LocalReadinessCarryForwardReferenceV4,
)

ASSET_ROOT = Path("experiments/development_assets")
SELECTOR_FILE = Path("experiments/feasibility.py")

V2_ASSET_HASHES = {
    "candidates/v2/c2-gemini-2.5-flash-lite-free.json": (
        "69cccb9ce49fbdf6483dd6317a160d498573eb2d36499e1a6aebcce48037f98c"
    ),
    "candidates/v2/l3-qwen2.5-coder-7b-instruct-q4-k-m.json": (
        "05d250db176f6e9509039899810bb3e7faab26442d475a431da6eb6f974f0564"
    ),
    "candidates/v2/l4-gemma3-12b-it-q4-k-m.json": (
        "7d16240531126aabddc76243ed236f0eb0ae2a2d27c76fe8912c7ffb7967a573"
    ),
    "candidates/v2/manifest.json": (
        "4d688ab2970bfc2180d92ec9ae2b4e979f8934929621d55574e34865de1d0e92"
    ),
    "execution-plan-v2.json": (
        "5d8c0f30b89cf5fab008b919b797794391e2c85cf76a52f0d08f89ca75bbc09f"
    ),
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _v4_assets():
    return load_feasibility_assets(ASSET_ROOT, candidate_set_version="v4")


def _c4_readiness():
    assets = _v4_assets()
    contract = expected_frozen_contract(assets=assets, selector_file=SELECTOR_FILE)
    descriptor = next(
        item for item in assets.candidates if item.spec.candidate_id == V4_C4_CANDIDATE_ID
    )
    quota = CloudQuotaSnapshot(
        captured_at_utc="2026-09-21T00:00:00Z",
        source_reference="signed-in-project-quota-view",
        account_project_specific_verified=True,
        quota_current_verified=True,
        requests_per_minute=15,
        tokens_per_minute=250_000,
        requests_per_day=500,
        tokens_per_day=None,
    )
    lengths = frozen_cloud_request_input_byte_lengths(assets)
    pacing = derive_cloud_pacing(
        quota=quota,
        request_input_byte_lengths=lengths,
        max_output_tokens=assets.execution_plan.generation_settings.max_output_tokens,
    )
    evidence = CloudZeroGenerationReadinessV4(
        candidate_id=V4_C4_CANDIDATE_ID,
        candidate_descriptor_sha256=canonical_model_sha256(descriptor),
        api_model_id=V4_C4_API_MODEL_ID,
        api_route=V4_C4_API_ROUTE,
        model_active=True,
        stable_endpoint_supported=True,
        free_tier_active=True,
        zero_cost_input_verified=True,
        zero_cost_output_verified=True,
        paid_billing_fallback_authorized=False,
        structured_output_supported=True,
        c4_schema_readiness="PASS",
        frozen_response_schemas_accepted=True,
        temperature_accepted=True,
        top_p_accepted=True,
        top_k_accepted=True,
        max_output_tokens_accepted=True,
        streaming_disabled=True,
        tools_disabled=True,
        grounding_disabled=True,
        automatic_retries_disabled=True,
        actual_request_count_observable=True,
        thinking_config_omitted=True,
        prior_attempt_absent=True,
        provider_requests_made=0,
        generation_requests_made=0,
        quota=quota,
        pacing=pacing,
        frozen_contract=contract,
    )
    return assets, evidence


def test_v4_manifest_binds_exact_l3_l4_and_c4_without_selecting_final_provider() -> None:
    assets = _v4_assets()
    assert assets.candidate_manifest.manifest_version == "v4"
    assert assets.candidate_manifest.candidate_ids == V4_CANDIDATE_IDS
    assert assets.candidate_manifest.descriptor_bundle_sha256 == (
        "6c7c83445d002a7b6b38c69933f826d472a51ff42a36aa2892f75db947d0455d"
    )
    assert assets.candidate_manifest.final_selection_made is False

    by_category = {item.spec.category: item for item in assets.candidates}
    assert (
        by_category[ProviderCandidateCategory.SMALLER_LOCAL].spec.candidate_id
        == V4_CANDIDATE_IDS[0]
    )
    assert (
        by_category[ProviderCandidateCategory.REALISTIC_LOCAL].spec.candidate_id
        == V4_CANDIDATE_IDS[1]
    )
    cloud = by_category[ProviderCandidateCategory.ZERO_COST_CLOUD]
    assert cloud.spec.candidate_id == V4_C4_CANDIDATE_ID
    assert cloud.api_model_id == V4_C4_API_MODEL_ID
    assert cloud.api_route == V4_C4_API_ROUTE
    assert cloud.zero_cost_required is True
    assert cloud.free_tier_reverify_before_run is True
    assert cloud.automatic_retries == 0
    assert cloud.tools_enabled is False
    assert cloud.grounding_enabled is False


def test_v4_l3_l4_descriptors_are_v2_identity_exact_except_version_tag() -> None:
    v2 = load_feasibility_assets(ASSET_ROOT, candidate_set_version="v2")
    v4 = _v4_assets()
    for candidate_id in V4_CANDIDATE_IDS[:2]:
        source = next(item for item in v2.candidates if item.spec.candidate_id == candidate_id)
        target = next(item for item in v4.candidates if item.spec.candidate_id == candidate_id)
        source_payload = source.model_dump(mode="json")
        target_payload = target.model_dump(mode="json")
        assert source_payload.pop("descriptor_version") == "v2"
        assert target_payload.pop("descriptor_version") == "v4"
        assert target_payload == source_payload


def test_v4_changes_only_candidate_binding_not_frozen_feasibility_v1_protocol() -> None:
    v2 = load_feasibility_assets(ASSET_ROOT, candidate_set_version="v2")
    v4 = _v4_assets()
    assert v4.input_manifest == v2.input_manifest
    assert v4.truth_manifest == v2.truth_manifest
    assert v4.prompt_manifest == v2.prompt_manifest
    assert v4.inputs == v2.inputs
    assert v4.truth_records == v2.truth_records
    assert v4.prompts == v2.prompts

    left = v2.execution_plan.model_dump(mode="json")
    right = v4.execution_plan.model_dump(mode="json")
    assert left.pop("plan_id") == "m20-feasibility-gate-v2"
    assert right.pop("plan_id") == "m20-feasibility-gate-v4"
    left.pop("candidate_ids")
    right.pop("candidate_ids")
    assert right == left

    assert expected_frozen_contract(
        assets=v4, selector_file=SELECTOR_FILE
    ) == expected_frozen_contract(assets=v2, selector_file=SELECTOR_FILE)


def test_v3_remains_uninstantiated_and_existing_v2_assets_are_byte_unchanged() -> None:
    with pytest.raises(FeasibilityAssetError, match="unsupported"):
        load_feasibility_assets(ASSET_ROOT, candidate_set_version="v3")
    for relative, expected in V2_ASSET_HASHES.items():
        assert _sha256(ASSET_ROOT / relative) == expected


def test_v4_carry_forward_references_v2_evidence_without_relabeling_it() -> None:
    v2 = load_feasibility_assets(ASSET_ROOT, candidate_set_version="v2")
    v4 = _v4_assets()
    contract = expected_frozen_contract(assets=v4, selector_file=SELECTOR_FILE)

    for candidate_id in V4_CANDIDATE_IDS[:2]:
        source = next(item for item in v2.candidates if item.spec.candidate_id == candidate_id)
        target = next(item for item in v4.candidates if item.spec.candidate_id == candidate_id)
        reference = LocalReadinessCarryForwardReferenceV4(
            candidate_id=candidate_id,
            source_readiness_reference=f"external/v2/{candidate_id}/readiness",
            source_readiness_bundle_sha256="1" * 64,
            source_inspection_reference=f"external/v2/{candidate_id}/inspection",
            source_inspection_bundle_sha256="2" * 64,
            source_candidate_descriptor_sha256=canonical_model_sha256(source),
            target_candidate_descriptor_sha256=canonical_model_sha256(target),
            source_readiness_passed=True,
            source_evidence_immutable_verified=True,
            identity_equivalent_verified=True,
            source_generation_requests_made=0,
            frozen_contract=contract,
        )
        assert reference.source_candidate_set_version == "v2"
        assert reference.candidate_set_version == "v4"
        validate_v4_local_carry_forward_reference(
            assets=v4,
            selector_file=SELECTOR_FILE,
            source_descriptor=source,
            reference=reference,
        )

        broken = reference.model_copy(update={"identity_equivalent_verified": False})
        with pytest.raises(FeasibilityReadinessError, match="identity equivalence"):
            validate_v4_local_carry_forward_reference(
                assets=v4,
                selector_file=SELECTOR_FILE,
                source_descriptor=source,
                reference=broken,
            )


def test_c4_frozen_request_bounds_and_pacing_are_exact() -> None:
    assets, evidence = _c4_readiness()
    lengths = frozen_cloud_request_input_byte_lengths(assets)
    assert len(lengths) == 75
    assert sum(lengths) == 171_687
    assert min(lengths) == 2_100
    assert max(lengths) == 2_466

    assert evidence.quota.requests_per_minute == 15
    assert evidence.quota.tokens_per_minute == 250_000
    assert evidence.quota.requests_per_day == 500
    assert evidence.quota.tokens_per_day is None
    assert evidence.pacing.effective_requests_per_minute == 12
    assert evidence.pacing.effective_tokens_per_minute == 200_000
    assert evidence.pacing.total_input_upper_bound_tokens == 171_687
    assert evidence.pacing.total_output_upper_bound_tokens == 307_200
    assert evidence.pacing.daily_required_tokens == 478_887
    assert evidence.pacing.maximum_request_input_upper_bound_tokens == 2_466
    assert evidence.pacing.maximum_request_total_upper_bound_tokens == 6_562
    assert evidence.pacing.fixed_interval_seconds == 5.0


def test_c4_zero_generation_readiness_accepts_only_frozen_static_contract() -> None:
    assets, evidence = _c4_readiness()
    assert evidence.c4_schema_readiness == "PASS"
    assert evidence.provider_requests_made == 0
    assert evidence.generation_requests_made == 0
    assert evidence.thinking_config_omitted is True
    validate_v4_c4_zero_generation_readiness(
        assets=assets,
        selector_file=SELECTOR_FILE,
        evidence=evidence,
    )

    for update, match in (
        ({"thinking_config_omitted": False}, "thinkingConfig omitted"),
        ({"frozen_response_schemas_accepted": False}, "frozen schemas"),
        ({"streaming_disabled": False}, "non-streaming"),
    ):
        bad = evidence.model_copy(update=update)
        with pytest.raises(FeasibilityReadinessError, match=match):
            validate_v4_c4_zero_generation_readiness(
                assets=assets,
                selector_file=SELECTOR_FILE,
                evidence=bad,
            )


def test_c4_zero_generation_readiness_rejects_quota_or_pacing_drift() -> None:
    assets, evidence = _c4_readiness()
    bad_quota = evidence.quota.model_copy(update={"requests_per_minute": 14})
    with pytest.raises(FeasibilityReadinessError, match="observed project quota"):
        validate_v4_c4_zero_generation_readiness(
            assets=assets,
            selector_file=SELECTOR_FILE,
            evidence=evidence.model_copy(update={"quota": bad_quota}),
        )

    bad_pacing = evidence.pacing.model_copy(update={"fixed_interval_seconds": 6.0})
    with pytest.raises(FeasibilityReadinessError, match="fixed pacing"):
        validate_v4_c4_zero_generation_readiness(
            assets=assets,
            selector_file=SELECTOR_FILE,
            evidence=evidence.model_copy(update={"pacing": bad_pacing}),
        )


def test_v4_readiness_schema_forbids_any_provider_or_generation_request() -> None:
    _, evidence = _c4_readiness()
    payload = evidence.model_dump(mode="json")
    payload["provider_requests_made"] = 1
    with pytest.raises(ValidationError):
        CloudZeroGenerationReadinessV4.model_validate(payload)
    payload = evidence.model_dump(mode="json")
    payload["generation_requests_made"] = 1
    with pytest.raises(ValidationError):
        CloudZeroGenerationReadinessV4.model_validate(payload)
