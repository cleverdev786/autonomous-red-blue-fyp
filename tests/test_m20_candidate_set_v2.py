"""Candidate-set v2 identity, evidence protection, quota, and zero-inference readiness tests."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from experiments.feasibility_assets import FeasibilityAssetError, load_feasibility_assets
from experiments.feasibility_readiness import (
    FROZEN_SELECTOR_FILE_SHA256,
    ROUND2_CANDIDATE_IDS,
    FeasibilityReadinessError,
    build_round_evidence_protection_manifest,
    derive_cloud_pacing,
    evaluate_global_round2_readiness,
    expected_frozen_contract,
    require_global_round2_readiness,
    verify_round_evidence_protection_manifest,
)
from experiments.feasibility_role_calls import canonical_model_sha256
from schemas.feasibility import ProviderCandidateCategory
from schemas.feasibility_readiness import (
    CloudQuotaSnapshot,
    CloudZeroInferenceReadiness,
    LocalZeroInferenceReadiness,
)

ASSET_ROOT = Path("experiments/development_assets")
SELECTOR_FILE = Path("experiments/feasibility.py")


def test_v1_assets_remain_default_and_exactly_bound_to_round1_candidates() -> None:
    assets = load_feasibility_assets(ASSET_ROOT)
    assert assets.candidate_manifest.manifest_version == "v1"
    assert assets.candidate_manifest.descriptor_bundle_sha256 == (
        "26c4387067c9ecb01c921b0efc4055ec123b5023321b891a1252e8dde58c5de3"
    )
    assert assets.execution_plan.plan_id == "m20-feasibility-gate-v1"
    assert assets.execution_plan.candidate_ids == (
        "l1-qwen3-8b-q4-k-m",
        "l2-qwen3-4b-q4-k-m",
        "c1-gemini-3.5-flash-lite",
    )


def test_v2_manifest_binds_exact_precommitted_l3_l4_c2_identities() -> None:
    assets = load_feasibility_assets(ASSET_ROOT, candidate_set_version="v2")
    assert assets.candidate_manifest.manifest_version == "v2"
    assert assets.candidate_manifest.candidate_ids == ROUND2_CANDIDATE_IDS
    assert assets.candidate_manifest.descriptor_bundle_sha256 == (
        "0721a0f1a9dcb169949a70eceb832339df2999ec0933315cd7410dfe04f02917"
    )
    by_category = {item.spec.category: item for item in assets.candidates}

    smaller = by_category[ProviderCandidateCategory.SMALLER_LOCAL]
    assert smaller.spec.candidate_id == "l3-qwen2.5-coder-7b-instruct-q4-k-m"
    assert smaller.revision == "13fb94bfda8c8cf22497dc57b78f391a9acb426a"
    assert smaller.artifact_file == "qwen2.5-coder-7b-instruct-q4_k_m.gguf"
    assert smaller.spec.artifact_sha256 == (
        "509287f78cb4d4cf6b3843734733b914b2c158e43e22a7f4bf5e963800894d3c"
    )

    realistic = by_category[ProviderCandidateCategory.REALISTIC_LOCAL]
    assert realistic.spec.candidate_id == "l4-gemma3-12b-it-q4-k-m"
    assert realistic.revision == "1f36e7e20445fa79c97638eddb29ebffd975ab2f"
    assert realistic.artifact_file == "gemma-3-12b-it-Q4_K_M.gguf"
    assert realistic.spec.artifact_sha256 == (
        "7bb69bff3f48a7b642355d64a90e481182a7794707b3133890646b1efa778ff5"
    )

    cloud = by_category[ProviderCandidateCategory.ZERO_COST_CLOUD]
    assert cloud.spec.candidate_id == "c2-gemini-2.5-flash-lite-free"
    assert cloud.api_model_id == "gemini-2.5-flash-lite"
    assert cloud.api_route.endswith("/gemini-2.5-flash-lite:generateContent")
    assert cloud.zero_cost_required is True
    assert cloud.free_tier_reverify_before_run is True


def test_v2_plan_changes_only_candidate_binding_not_frozen_protocol() -> None:
    v1 = load_feasibility_assets(ASSET_ROOT)
    v2 = load_feasibility_assets(ASSET_ROOT, candidate_set_version="v2")
    assert v2.execution_plan.plan_id == "m20-feasibility-gate-v2"
    assert v2.execution_plan.candidate_ids == ROUND2_CANDIDATE_IDS
    assert v2.input_manifest == v1.input_manifest
    assert v2.truth_manifest == v1.truth_manifest
    assert v2.prompt_manifest == v1.prompt_manifest
    assert v2.inputs == v1.inputs
    assert v2.truth_records == v1.truth_records
    assert v2.prompts == v1.prompts
    left = v1.execution_plan.model_dump(mode="json")
    right = v2.execution_plan.model_dump(mode="json")
    left.pop("plan_id")
    left.pop("candidate_ids")
    right.pop("plan_id")
    right.pop("candidate_ids")
    assert right == left


def test_loader_requires_explicit_supported_candidate_set_version() -> None:
    with pytest.raises(FeasibilityAssetError, match="unsupported"):
        load_feasibility_assets(ASSET_ROOT, candidate_set_version="v3")


def test_round1_evidence_protection_detects_any_file_change(tmp_path: Path) -> None:
    root = tmp_path / "round1"
    ids = ("l1", "l2", "c1")
    for index, candidate_id in enumerate(ids, start=1):
        folder = root / candidate_id
        folder.mkdir(parents=True)
        (folder / "candidate-summary.json").write_text(f"candidate-{index}\n")
        (folder / "role-calls.jsonl").write_text(f"call-{index}\n")
    manifest = build_round_evidence_protection_manifest(
        evidence_root=root,
        round_id="m20-development-feasibility-round-1",
        candidate_ids=ids,
    )
    assert manifest.file_count == 6
    verify_round_evidence_protection_manifest(evidence_root=root, manifest=manifest)
    (root / "l2" / "role-calls.jsonl").write_text("tampered\n")
    with pytest.raises(FeasibilityReadinessError, match="manifest mismatch"):
        verify_round_evidence_protection_manifest(evidence_root=root, manifest=manifest)


def test_cloud_pacing_is_fixed_with_20_percent_headroom_and_daily_proof() -> None:
    quota = CloudQuotaSnapshot(
        captured_at_utc="2026-09-20T09:00:00Z",
        source_reference="trusted-project-rate-limits-view",
        account_project_specific_verified=True,
        quota_current_verified=True,
        requests_per_minute=100,
        tokens_per_minute=1_000_000,
        requests_per_day=1000,
        tokens_per_day=1_000_000,
    )
    plan = derive_cloud_pacing(
        quota=quota,
        request_input_byte_lengths=tuple(2000 for _ in range(75)),
        max_output_tokens=4096,
    )
    assert plan.effective_requests_per_minute == 80
    assert plan.effective_tokens_per_minute == 800_000
    assert plan.total_input_upper_bound_tokens == 150_000
    assert plan.total_output_upper_bound_tokens == 307_200
    assert plan.daily_required_tokens == 457_200
    assert plan.fixed_interval_seconds == pytest.approx(0.75)


def test_cloud_pacing_fails_closed_when_rpd_or_tpd_cannot_cover_full_schedule() -> None:
    lengths = tuple(2000 for _ in range(75))
    insufficient_rpd = CloudQuotaSnapshot(
        captured_at_utc="2026-09-20T09:00:00Z",
        source_reference="trusted-project-rate-limits-view",
        account_project_specific_verified=True,
        quota_current_verified=True,
        requests_per_minute=100,
        tokens_per_minute=1_000_000,
        requests_per_day=74,
    )
    with pytest.raises(FeasibilityReadinessError, match="requests-per-day"):
        derive_cloud_pacing(
            quota=insufficient_rpd,
            request_input_byte_lengths=lengths,
            max_output_tokens=4096,
        )
    insufficient_tpd = insufficient_rpd.model_copy(
        update={"requests_per_day": 1000, "tokens_per_day": 457_199}
    )
    with pytest.raises(FeasibilityReadinessError, match="tokens-per-day"):
        derive_cloud_pacing(
            quota=insufficient_tpd,
            request_input_byte_lengths=lengths,
            max_output_tokens=4096,
        )


def _perfect_readiness():
    assets = load_feasibility_assets(ASSET_ROOT, candidate_set_version="v2")
    contract = expected_frozen_contract(assets=assets, selector_file=SELECTOR_FILE)
    descriptors = {item.spec.candidate_id: item for item in assets.candidates}

    local_rows = []
    for candidate_id in ROUND2_CANDIDATE_IDS[:2]:
        descriptor = descriptors[candidate_id]
        local_rows.append(
            LocalZeroInferenceReadiness(
                candidate_id=candidate_id,
                candidate_descriptor_sha256=canonical_model_sha256(descriptor),
                artifact_sha256=descriptor.spec.artifact_sha256,
                artifact_size_bytes=5_000_000_000,
                artifact_checksum_verified=True,
                runtime_version=descriptor.runtime_version,
                runtime_commit=descriptor.runtime_commit,
                model_architecture_recognized=True,
                model_load_succeeded=True,
                health_endpoint_succeeded=True,
                identity_observed=True,
                structured_output_supported=True,
                application_messages_preserved=True,
                license_terms_accepted=True,
                automatic_retries_disabled=True,
                actual_request_count_observable=True,
                tools_disabled=True,
                grounding_disabled=True,
                prior_attempt_absent=True,
                baseline_mem_available_bytes=10_000_000_000,
                baseline_swap_used_bytes=0,
                frozen_contract=contract,
            )
        )

    quota = CloudQuotaSnapshot(
        captured_at_utc="2026-09-20T09:00:00Z",
        source_reference="trusted-project-rate-limits-view",
        account_project_specific_verified=True,
        quota_current_verified=True,
        requests_per_minute=100,
        tokens_per_minute=1_000_000,
        requests_per_day=1000,
        tokens_per_day=1_000_000,
    )
    lengths = tuple(2000 for _ in range(75))
    pacing = derive_cloud_pacing(
        quota=quota,
        request_input_byte_lengths=lengths,
        max_output_tokens=assets.execution_plan.generation_settings.max_output_tokens,
    )
    cloud_descriptor = descriptors[ROUND2_CANDIDATE_IDS[2]]
    cloud = CloudZeroInferenceReadiness(
        candidate_id=cloud_descriptor.spec.candidate_id,
        candidate_descriptor_sha256=canonical_model_sha256(cloud_descriptor),
        api_model_id=cloud_descriptor.api_model_id,
        api_route=cloud_descriptor.api_route,
        model_active=True,
        stable_endpoint_supported=True,
        free_tier_active=True,
        zero_cost_input_verified=True,
        zero_cost_output_verified=True,
        paid_billing_fallback_authorized=False,
        structured_output_supported=True,
        frozen_response_schemas_accepted=True,
        temperature_accepted=True,
        top_p_accepted=True,
        top_k_accepted=True,
        max_output_tokens_accepted=True,
        tools_disabled=True,
        grounding_disabled=True,
        automatic_retries_disabled=True,
        actual_request_count_observable=True,
        prior_attempt_absent=True,
        quota=quota,
        pacing=pacing,
        frozen_contract=contract,
    )
    return assets, tuple(local_rows), cloud, lengths


def test_global_readiness_requires_all_three_candidates_ready_before_generation() -> None:
    assets, local_rows, cloud, lengths = _perfect_readiness()
    decision = evaluate_global_round2_readiness(
        assets=assets,
        selector_file=SELECTOR_FILE,
        local_evidence=local_rows,
        cloud_evidence=cloud,
        cloud_request_input_byte_lengths=lengths,
        round1_evidence_protected=True,
    )
    assert decision.ready is True
    assert decision.failure_reasons == ()
    assert decision.total_generation_requests_made == 0
    require_global_round2_readiness(decision)

    bad_l4 = local_rows[1].model_copy(update={"license_terms_accepted": False})
    blocked = evaluate_global_round2_readiness(
        assets=assets,
        selector_file=SELECTOR_FILE,
        local_evidence=(local_rows[0], bad_l4),
        cloud_evidence=cloud,
        cloud_request_input_byte_lengths=lengths,
        round1_evidence_protected=True,
    )
    assert blocked.ready is False
    assert any("license terms" in reason for reason in blocked.failure_reasons)
    assert blocked.total_generation_requests_made == 0
    with pytest.raises(FeasibilityReadinessError, match="Round-2 inference blocked"):
        require_global_round2_readiness(blocked)



def test_global_readiness_blocks_when_round1_evidence_manifest_is_not_verified() -> None:
    assets, local_rows, cloud, lengths = _perfect_readiness()
    decision = evaluate_global_round2_readiness(
        assets=assets,
        selector_file=SELECTOR_FILE,
        local_evidence=local_rows,
        cloud_evidence=cloud,
        cloud_request_input_byte_lengths=lengths,
        round1_evidence_protected=False,
    )
    assert decision.ready is False
    assert any("Round-1 evidence" in reason for reason in decision.failure_reasons)

def test_global_readiness_rejects_descriptor_or_pacing_drift() -> None:
    assets, local_rows, cloud, lengths = _perfect_readiness()
    bad_local = local_rows[0].model_copy(update={"candidate_descriptor_sha256": "0" * 64})
    bad_pacing = cloud.pacing.model_copy(
        update={"fixed_interval_seconds": cloud.pacing.fixed_interval_seconds + 1.0}
    )
    bad_cloud = cloud.model_copy(update={"pacing": bad_pacing})
    decision = evaluate_global_round2_readiness(
        assets=assets,
        selector_file=SELECTOR_FILE,
        local_evidence=(bad_local, local_rows[1]),
        cloud_evidence=bad_cloud,
        cloud_request_input_byte_lengths=lengths,
        round1_evidence_protected=True,
    )
    assert decision.ready is False
    assert any("descriptor SHA" in reason for reason in decision.failure_reasons)
    assert any("fixed pacing" in reason for reason in decision.failure_reasons)


def test_frozen_selector_file_hash_stays_exact() -> None:
    assert hashlib.sha256(SELECTOR_FILE.read_bytes()).hexdigest() == FROZEN_SELECTOR_FILE_SHA256
