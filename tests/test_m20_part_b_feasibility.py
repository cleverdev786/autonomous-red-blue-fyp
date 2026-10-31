"""Assistant-side tests for M20 Part-B feasibility and no-hidden-retry infrastructure."""

from __future__ import annotations

import pytest

from experiments.feasibility import (
    FeasibilityInputRepository,
    FeasibilityProtocolError,
    derive_context_window,
    derive_output_ceiling,
    derive_rq1_runtime_limit,
    derive_rq2_runtime_limit,
    evaluate_local_resource_feasibility,
    evaluate_provider_candidate,
    evaluate_semantic_feasibility,
    evaluate_stability_feasibility,
    select_provider_candidate,
    validate_synthetic_fixture_package,
)
from llm.no_retry import (
    DispatchAccountingState,
    NoHiddenRetryError,
    ProviderRetryCapability,
    account_model_dispatch,
    require_single_actual_request,
    validate_no_hidden_retry_capability,
)
from schemas.common import (
    ClassificationLabel,
    HttpMethod,
    PatchDecision,
    RunStatus,
    VulnerabilityClass,
)
from schemas.feasibility import (
    FeasibilityCallMeasurement,
    LocalResourceEvidence,
    ProviderCandidateCategory,
    ProviderCandidateSpec,
    ProviderFeasibilityEvidence,
    ProviderIntegrationEvidence,
    SyntheticFixtureInput,
    SyntheticFixtureInputManifest,
    SyntheticFixtureObservation,
    SyntheticFixtureTruth,
    SyntheticFixtureTruthManifest,
    SyntheticRegisteredTest,
    SyntheticSourceFile,
)


CLASSES = (
    ClassificationLabel.SQL_INJECTION,
    ClassificationLabel.SQL_INJECTION,
    ClassificationLabel.XSS,
    ClassificationLabel.XSS,
    ClassificationLabel.PATH_TRAVERSAL,
    ClassificationLabel.PATH_TRAVERSAL,
    ClassificationLabel.BENIGN,
    ClassificationLabel.BENIGN,
)


def _vulnerability(label: ClassificationLabel) -> VulnerabilityClass | None:
    return {
        ClassificationLabel.SQL_INJECTION: VulnerabilityClass.SQL_INJECTION,
        ClassificationLabel.XSS: VulnerabilityClass.XSS,
        ClassificationLabel.PATH_TRAVERSAL: VulnerabilityClass.PATH_TRAVERSAL,
    }.get(label)


def _fixture_package():
    inputs = []
    truths = []
    for index, label in enumerate(CLASSES, start=1):
        fixture_id = f"fixture-{index}"
        vulnerability = _vulnerability(label)
        input_item = SyntheticFixtureInput(
            fixture_id=fixture_id,
            fixture_version="v1",
            target_id="synthetic-target",
            endpoint_id=f"endpoint-{index}",
            method=HttpMethod.GET,
            input_fields=("value",),
            normalized_event={"event_id": f"event-{index}", "value": f"sample-{index}"},
            source_files=(
                SyntheticSourceFile(
                    file_path=f"synthetic/app/module_{index}.py",
                    content=f"def route_{index}():\n    return 'fixture'\n",
                ),
            ),
            registered_tests=(
                SyntheticRegisteredTest(
                    test_id=f"synthetic-test-{index}",
                    endpoint_id=f"endpoint-{index}",
                    vulnerability_class=vulnerability or VulnerabilityClass.XSS,
                    safe_description="Synthetic bounded DEVELOPMENT test option.",
                ),
            ),
        )
        if vulnerability is None:
            truth = SyntheticFixtureTruth(
                fixture_id=fixture_id,
                fixture_version="v1",
                expected_classification=ClassificationLabel.BENIGN,
                expected_pre_patch_attack_confirmed=False,
            )
        else:
            truth = SyntheticFixtureTruth(
                fixture_id=fixture_id,
                fixture_version="v1",
                expected_classification=label,
                expected_vulnerability_class=vulnerability,
                expected_source_file=f"synthetic/app/module_{index}.py",
                expected_function_or_route=f"route_{index}",
                expected_registered_test_id=f"synthetic-test-{index}",
                expected_pre_patch_attack_confirmed=True,
                expected_patch_decision=PatchDecision.ACCEPTED,
            )
        inputs.append(input_item)
        truths.append(truth)
    return tuple(inputs), tuple(truths)


def _perfect_observation(truth: SyntheticFixtureTruth, *, repetition: int = 1):
    benign = truth.expected_classification == ClassificationLabel.BENIGN
    return SyntheticFixtureObservation(
        fixture_id=truth.fixture_id,
        repetition_index=repetition,
        schema_valid=True,
        predicted_classification=truth.expected_classification,
        predicted_source_file=None if benign else truth.expected_source_file,
        predicted_function_or_route=None if benign else truth.expected_function_or_route,
        selected_registered_test_id=None if benign else truth.expected_registered_test_id,
        patch_decision=None if benign else PatchDecision.ACCEPTED,
        duration_ms=100,
        input_tokens=200,
        output_tokens=80,
    )


def test_input_and_truth_manifests_remain_separate_and_truth_is_evaluator_only() -> None:
    inputs, truths = _fixture_package()
    fixture_ids = tuple(item.fixture_id for item in inputs)
    input_manifest = SyntheticFixtureInputManifest(
        fixture_set_id="m20-feasibility-fixtures",
        fixture_set_version="v1",
        fixture_ids=fixture_ids,
        input_bundle_sha256="1" * 64,
    )
    truth_manifest = SyntheticFixtureTruthManifest(
        fixture_set_id="m20-feasibility-fixtures",
        fixture_set_version="v1",
        fixture_ids=tuple(item.fixture_id for item in truths),
        truth_bundle_sha256="2" * 64,
    )
    assert "truth_bundle_sha256" not in input_manifest.model_dump()
    assert truth_manifest.evaluator_only is True


def test_fixture_contracts_are_truth_isolated_and_validate_exact_v1_shape() -> None:
    inputs, truths = _fixture_package()
    validate_synthetic_fixture_package(inputs=inputs, truths=truths)
    execution = FeasibilityInputRepository(inputs)
    assert len(execution.all()) == 8
    assert execution.get("fixture-1").fixture_id == "fixture-1"
    assert not hasattr(execution, "truth")
    assert not hasattr(execution, "get_truth")
    assert "expected_classification" not in execution.get("fixture-1").model_dump()

    bad_truths = truths[:-1]
    with pytest.raises(FeasibilityProtocolError, match="exactly eight"):
        validate_synthetic_fixture_package(inputs=inputs, truths=bad_truths)


def test_semantic_gate_passes_exact_predefined_threshold_contract() -> None:
    _, truths = _fixture_package()
    observations = tuple(_perfect_observation(truth) for truth in truths)
    summary = evaluate_semantic_feasibility(truths=truths, observations=observations)
    assert summary.passed
    assert summary.malicious_class_correct == 6
    assert summary.benign_class_correct == 2
    assert summary.benign_no_action_correct == 2
    assert summary.source_file_exact == 6
    assert summary.function_route_exact == 6
    assert summary.registered_test_exact == 6
    assert summary.accepted_patches == 6


def test_semantic_gate_rejects_schema_valid_benign_action_and_class_coverage_failures() -> None:
    _, truths = _fixture_package()
    rows = [_perfect_observation(truth) for truth in truths]
    rows[0] = rows[0].model_copy(update={"predicted_classification": ClassificationLabel.BENIGN})
    rows[1] = rows[1].model_copy(update={"predicted_classification": ClassificationLabel.BENIGN})
    rows[6] = rows[6].model_copy(
        update={
            "predicted_source_file": "synthetic/app/module_6.py",
            "selected_registered_test_id": "synthetic-test-6",
            "patch_decision": PatchDecision.ACCEPTED,
        }
    )
    summary = evaluate_semantic_feasibility(truths=truths, observations=tuple(rows))
    assert not summary.passed
    assert VulnerabilityClass.SQL_INJECTION not in summary.malicious_classes_with_correct_example
    assert summary.benign_no_action_correct == 1


def test_stability_gate_requires_four_fixed_fixture_classes_and_three_repetitions() -> None:
    _, truths = _fixture_package()
    chosen = (truths[0], truths[2], truths[4], truths[6])
    observations = tuple(
        _perfect_observation(truth, repetition=repetition)
        for truth in chosen
        for repetition in (1, 2, 3)
    )
    summary = evaluate_stability_feasibility(truths=truths, observations=observations)
    assert summary.passed
    assert summary.observation_count == 12
    assert summary.classification_correct_count == 12
    assert summary.malicious_localization_pass_count == 3


def _candidate(category: ProviderCandidateCategory, suffix: str) -> ProviderCandidateSpec:
    return ProviderCandidateSpec(
        candidate_id=f"candidate-{suffix}",
        category=category,
        provider_identity=f"provider-{suffix}",
        model_identity=f"model-{suffix}",
        runtime_identity=f"runtime-{suffix}",
    )


def _passing_summaries():
    _, truths = _fixture_package()
    semantic = evaluate_semantic_feasibility(
        truths=truths,
        observations=tuple(_perfect_observation(truth) for truth in truths),
    )
    chosen = (truths[0], truths[2], truths[4], truths[6])
    stability = evaluate_stability_feasibility(
        truths=truths,
        observations=tuple(
            _perfect_observation(truth, repetition=repetition)
            for truth in chosen
            for repetition in (1, 2, 3)
        ),
    )
    return semantic, stability


def _integration(*, cloud: bool = False) -> ProviderIntegrationEvidence:
    return ProviderIntegrationEvidence(
        identity_verified=True,
        structured_output_supported=True,
        research_recording_compatible=True,
        automatic_retries_disabled=True,
        actual_request_count_observable=True,
        unrestricted_tools_disabled=True,
        load_or_connect_succeeded=True,
        zero_cost_verified=True if cloud else None,
    )


def test_candidate_selection_uses_minimum_sufficient_hierarchy_not_score_ranking() -> None:
    semantic, stability = _passing_summaries()
    realistic = evaluate_provider_candidate(
        candidate=_candidate(ProviderCandidateCategory.REALISTIC_LOCAL, "l1"),
        integration=_integration(),
        semantic=semantic,
        stability=stability,
        resource_pass=True,
    )
    smaller = evaluate_provider_candidate(
        candidate=_candidate(ProviderCandidateCategory.SMALLER_LOCAL, "l2"),
        integration=_integration(),
        semantic=semantic,
        stability=stability,
        resource_pass=True,
    )
    cloud = evaluate_provider_candidate(
        candidate=_candidate(ProviderCandidateCategory.ZERO_COST_CLOUD, "c1"),
        integration=_integration(cloud=True),
        semantic=semantic,
        stability=stability,
        resource_pass=True,
    )
    assert select_provider_candidate((realistic, smaller, cloud)).candidate.category == (
        ProviderCandidateCategory.SMALLER_LOCAL
    )

    smaller_failed = smaller.model_copy(update={"resource_pass": False, "eligible": False})
    assert select_provider_candidate((realistic, smaller_failed, cloud)).candidate.category == (
        ProviderCandidateCategory.REALISTIC_LOCAL
    )

    realistic_failed = realistic.model_copy(update={"eligible": False, "resource_pass": False})
    selected_cloud = select_provider_candidate((realistic_failed, smaller_failed, cloud))
    assert selected_cloud.candidate.category == ProviderCandidateCategory.ZERO_COST_CLOUD


def test_provider_feasibility_evidence_is_development_only_and_requires_local_resources() -> None:
    semantic, stability = _passing_summaries()
    local = _candidate(ProviderCandidateCategory.SMALLER_LOCAL, "evidence")
    resource = LocalResourceEvidence(
        baseline_mem_available_bytes=8 * 1024**3,
        minimum_mem_available_bytes=2 * 1024**3,
        baseline_swap_used_bytes=0,
        peak_swap_used_bytes=0,
        max_invocation_duration_ms=1000,
    )
    evidence = ProviderFeasibilityEvidence(
        candidate=local,
        integration=_integration(),
        semantic=semantic,
        stability=stability,
        local_resource=resource,
    )
    assert evidence.development_only is True
    with pytest.raises(ValueError, match="require local resource"):
        ProviderFeasibilityEvidence(
            candidate=local,
            integration=_integration(),
            semantic=semantic,
            stability=stability,
        )


def test_local_resource_gate_and_capacity_runtime_derivations_are_deterministic() -> None:
    resource = LocalResourceEvidence(
        baseline_mem_available_bytes=8 * 1024**3,
        minimum_mem_available_bytes=2 * 1024**3,
        baseline_swap_used_bytes=0,
        peak_swap_used_bytes=1024**3,
        max_invocation_duration_ms=9 * 60 * 1000,
    )
    assert evaluate_local_resource_feasibility(resource) == (True, ())
    failed, reasons = evaluate_local_resource_feasibility(
        resource.model_copy(
            update={
                "minimum_mem_available_bytes": 512 * 1024**2,
                "peak_swap_used_bytes": 3 * 1024**3,
            }
        )
    )
    assert not failed
    assert len(reasons) == 2

    measurements = (
        FeasibilityCallMeasurement(
            measurement_id="m1",
            input_tokens=5000,
            output_tokens=1000,
            duration_ms=1000,
            schema_valid=True,
            semantically_usable=True,
        ),
        FeasibilityCallMeasurement(
            measurement_id="m2",
            input_tokens=4000,
            output_tokens=500,
            duration_ms=900,
            schema_valid=True,
            semantically_usable=True,
        ),
    )
    output = derive_output_ceiling(
        measurements=measurements,
        supported_capacities=(1024, 2048, 4096),
    )
    assert output.observed_maximum == 1000
    assert output.required_capacity == 1256
    assert output.selected_capacity == 2048

    context = derive_context_window(
        measurements=measurements,
        output_ceiling=output.selected_capacity,
        supported_capacities=(4096, 8192, 16384),
    )
    assert context.required_capacity == 7560
    assert context.selected_capacity == 8192

    rq1 = derive_rq1_runtime_limit((120_000, 350_000))
    assert rq1.projected_ms == 700_000
    assert rq1.selected_runtime_seconds == 720

    rq2 = derive_rq2_runtime_limit(
        classification_latencies_ms=(1000,) * 20,
        deterministic_overhead_ms=10_000,
    )
    assert rq2.basis_ms == 1000
    assert rq2.projected_ms == 140_000
    assert rq2.selected_runtime_seconds == 180


def test_no_hidden_retry_accounting_distinguishes_dispatch_schema_and_semantic_failure() -> None:
    validate_no_hidden_retry_capability(
        ProviderRetryCapability(
            automatic_retries_disabled=True,
            configured_max_retries=0,
            actual_request_count_observable=True,
        )
    )
    with pytest.raises(NoHiddenRetryError):
        validate_no_hidden_retry_capability(
            ProviderRetryCapability(automatic_retries_disabled=False)
        )
    with pytest.raises(NoHiddenRetryError):
        require_single_actual_request(actual_request_count=2)

    blocked = account_model_dispatch(dispatched=False)
    assert blocked.state == DispatchAccountingState.NOT_DISPATCHED
    assert blocked.budget_units == 0
    assert not blocked.agent_call_required

    transport_failure = account_model_dispatch(dispatched=True)
    assert transport_failure.state == DispatchAccountingState.FAILED
    assert transport_failure.budget_units == 1
    assert transport_failure.agent_call_status == RunStatus.FAILED

    schema_failure = account_model_dispatch(
        dispatched=True,
        provider_response_received=True,
        schema_valid=False,
    )
    assert schema_failure.agent_call_status == RunStatus.FAILED

    semantic_failure = account_model_dispatch(
        dispatched=True,
        provider_response_received=True,
        schema_valid=True,
        semantic_valid=False,
    )
    assert semantic_failure.state == DispatchAccountingState.COMPLETED
    assert semantic_failure.agent_call_status == RunStatus.COMPLETED
    assert semantic_failure.downstream_semantic_valid is False
