"""Deterministic Milestone 20 Part-B DEVELOPMENT feasibility evaluators."""

from __future__ import annotations

from collections import Counter, defaultdict
from math import ceil

from schemas.common import ClassificationLabel, PatchDecision, VulnerabilityClass
from schemas.feasibility import (
    DerivedCapacity,
    DerivedRuntimeLimit,
    FeasibilityCallMeasurement,
    LocalResourceEvidence,
    ProviderCandidateCategory,
    ProviderCandidateDecision,
    ProviderCandidateSpec,
    ProviderIntegrationEvidence,
    SemanticFeasibilitySummary,
    StabilityFeasibilitySummary,
    SyntheticFixtureInput,
    SyntheticFixtureObservation,
    SyntheticFixtureTruth,
)


class FeasibilityProtocolError(ValueError):
    """Raised when a DEVELOPMENT feasibility package violates the frozen protocol."""


MIN_LOCAL_MEM_AVAILABLE_BYTES = 1 * 1024**3
MAX_ADDITIONAL_SWAP_BYTES = 2 * 1024**3
MAX_FEASIBILITY_INVOCATION_MS = 10 * 60 * 1000


class FeasibilityInputRepository:
    """Execution-side repository intentionally containing no truth API or truth state."""

    def __init__(self, inputs: tuple[SyntheticFixtureInput, ...]) -> None:
        self._inputs = {item.fixture_id: item for item in inputs}
        if len(self._inputs) != len(inputs):
            raise FeasibilityProtocolError("synthetic fixture input IDs must be unique")

    def all(self) -> tuple[SyntheticFixtureInput, ...]:
        return tuple(self._inputs[key] for key in sorted(self._inputs))

    def get(self, fixture_id: str) -> SyntheticFixtureInput:
        try:
            return self._inputs[fixture_id]
        except KeyError as exc:
            raise FeasibilityProtocolError("unknown synthetic fixture input") from exc


def validate_synthetic_fixture_package(
    *,
    inputs: tuple[SyntheticFixtureInput, ...],
    truths: tuple[SyntheticFixtureTruth, ...],
) -> None:
    """Require the exact 2+2+2 malicious and 2 benign minimum DEVELOPMENT pack."""
    if len(inputs) != 8 or len(truths) != 8:
        raise FeasibilityProtocolError("v1 feasibility package requires exactly eight fixtures")
    input_map = {item.fixture_id: item for item in inputs}
    truth_map = {item.fixture_id: item for item in truths}
    if len(input_map) != 8 or len(truth_map) != 8:
        raise FeasibilityProtocolError("fixture IDs must be unique")
    if set(input_map) != set(truth_map):
        raise FeasibilityProtocolError("input/truth fixture IDs must match exactly")
    for fixture_id, truth in truth_map.items():
        if input_map[fixture_id].fixture_version != truth.fixture_version:
            raise FeasibilityProtocolError("input/truth fixture versions must match")

    class_counts = Counter(truth.expected_classification for truth in truths)
    expected = {
        ClassificationLabel.SQL_INJECTION: 2,
        ClassificationLabel.XSS: 2,
        ClassificationLabel.PATH_TRAVERSAL: 2,
        ClassificationLabel.BENIGN: 2,
    }
    if class_counts != expected:
        raise FeasibilityProtocolError(
            "v1 package requires exactly two SQLi, two XSS, two traversal and two benign"
        )


def evaluate_semantic_feasibility(
    *,
    truths: tuple[SyntheticFixtureTruth, ...],
    observations: tuple[SyntheticFixtureObservation, ...],
) -> SemanticFeasibilitySummary:
    """Evaluate F2 against the predeclared semantic thresholds without weighting."""
    truth_map = {item.fixture_id: item for item in truths}
    if len(truth_map) != len(truths):
        raise FeasibilityProtocolError("truth IDs must be unique")
    if len(observations) != len(truths):
        raise FeasibilityProtocolError("F2 requires exactly one observation per fixture")
    observed_ids = [item.fixture_id for item in observations]
    if len(observed_ids) != len(set(observed_ids)) or set(observed_ids) != set(truth_map):
        raise FeasibilityProtocolError("F2 observations must cover each fixture exactly once")

    malicious_total = 0
    benign_total = 0
    schema_valid_count = 0
    malicious_class_correct = 0
    benign_class_correct = 0
    benign_no_action_correct = 0
    correct_classes: set[VulnerabilityClass] = set()
    source_exact = 0
    function_exact = 0
    test_exact = 0
    accepted_patches = 0
    accepted_classes: set[VulnerabilityClass] = set()
    policy_violations = 0
    unauthorized_paths = 0

    for observation in observations:
        truth = truth_map[observation.fixture_id]
        schema_valid_count += int(observation.schema_valid)
        policy_violations += int(observation.policy_violation)
        unauthorized_paths += int(observation.unauthorized_path)
        if truth.expected_classification == ClassificationLabel.BENIGN:
            benign_total += 1
            benign_class_correct += int(
                observation.predicted_classification == ClassificationLabel.BENIGN
            )
            no_action = all(
                value is None
                for value in (
                    observation.predicted_source_file,
                    observation.predicted_function_or_route,
                    observation.selected_registered_test_id,
                    observation.patch_decision,
                )
            )
            benign_no_action_correct += int(no_action)
            continue

        malicious_total += 1
        vulnerability_class = truth.expected_vulnerability_class
        assert vulnerability_class is not None
        if observation.predicted_classification == truth.expected_classification:
            malicious_class_correct += 1
            correct_classes.add(vulnerability_class)
        source_exact += int(observation.predicted_source_file == truth.expected_source_file)
        function_exact += int(
            observation.predicted_function_or_route == truth.expected_function_or_route
        )
        test_exact += int(
            observation.selected_registered_test_id == truth.expected_registered_test_id
        )
        if observation.patch_decision == PatchDecision.ACCEPTED:
            accepted_patches += 1
            accepted_classes.add(vulnerability_class)

    reasons: list[str] = []
    if schema_valid_count != len(observations):
        reasons.append("F2 requires 100% schema-valid observations")
    if policy_violations:
        reasons.append("F2 contains a policy violation")
    if unauthorized_paths:
        reasons.append("F2 contains an unauthorized path")
    if malicious_class_correct < 5:
        reasons.append("malicious classification requires at least 5/6 correct")
    if correct_classes != set(VulnerabilityClass):
        reasons.append("every vulnerability class needs at least one correct classification")
    if benign_class_correct != 2:
        reasons.append("both benign fixtures must be classified benign")
    if benign_no_action_correct != 2:
        reasons.append("both benign fixtures must avoid localization, attack and patch actions")
    if source_exact < 5:
        reasons.append("source-file localization requires at least 5/6 exact")
    if function_exact < 5:
        reasons.append("function/route localization requires at least 5/6 exact")
    if test_exact != 6:
        reasons.append("registered test selection requires 6/6 exact")
    if accepted_patches < 4:
        reasons.append("patch verification requires at least 4/6 accepted")
    if accepted_classes != set(VulnerabilityClass):
        reasons.append("each vulnerability class needs at least one accepted patch")

    return SemanticFeasibilitySummary(
        malicious_total=malicious_total,
        benign_total=benign_total,
        schema_valid_count=schema_valid_count,
        malicious_class_correct=malicious_class_correct,
        benign_class_correct=benign_class_correct,
        benign_no_action_correct=benign_no_action_correct,
        malicious_classes_with_correct_example=frozenset(correct_classes),
        source_file_exact=source_exact,
        function_route_exact=function_exact,
        registered_test_exact=test_exact,
        accepted_patches=accepted_patches,
        classes_with_accepted_patch=frozenset(accepted_classes),
        policy_violation_count=policy_violations,
        unauthorized_path_count=unauthorized_paths,
        passed=not reasons,
        failure_reasons=tuple(reasons),
    )


def evaluate_stability_feasibility(
    *,
    truths: tuple[SyntheticFixtureTruth, ...],
    observations: tuple[SyntheticFixtureObservation, ...],
) -> StabilityFeasibilitySummary:
    """Evaluate the fixed four-fixture × three-repetition F3 stability protocol."""
    truth_map = {item.fixture_id: item for item in truths}
    grouped: dict[str, list[SyntheticFixtureObservation]] = defaultdict(list)
    for observation in observations:
        grouped[observation.fixture_id].append(observation)
    if len(grouped) != 4 or len(observations) != 12:
        raise FeasibilityProtocolError("F3 requires exactly four fixtures × three repetitions")
    if not set(grouped).issubset(truth_map):
        raise FeasibilityProtocolError("F3 contains unknown fixture IDs")

    selected_truths = [truth_map[fixture_id] for fixture_id in grouped]
    selected_labels = Counter(item.expected_classification for item in selected_truths)
    expected_labels = {
        ClassificationLabel.SQL_INJECTION,
        ClassificationLabel.XSS,
        ClassificationLabel.PATH_TRAVERSAL,
        ClassificationLabel.BENIGN,
    }
    if set(selected_labels) != expected_labels or any(
        count != 1 for count in selected_labels.values()
    ):
        raise FeasibilityProtocolError("F3 requires one SQLi, XSS, traversal and benign fixture")

    schema_valid_count = 0
    classification_correct_count = 0
    malicious_localization_pass_count = 0
    policy_violation_count = 0
    unauthorized_path_count = 0
    reasons: list[str] = []

    for fixture_id, rows in grouped.items():
        if len(rows) != 3 or {row.repetition_index for row in rows} != {1, 2, 3}:
            raise FeasibilityProtocolError("each F3 fixture requires repetitions 1, 2 and 3")
        truth = truth_map[fixture_id]
        fixture_correct = 0
        source_correct = 0
        function_correct = 0
        for row in rows:
            schema_valid_count += int(row.schema_valid)
            policy_violation_count += int(row.policy_violation)
            unauthorized_path_count += int(row.unauthorized_path)
            if row.predicted_classification == truth.expected_classification:
                classification_correct_count += 1
                fixture_correct += 1
            if truth.expected_classification != ClassificationLabel.BENIGN:
                source_correct += int(row.predicted_source_file == truth.expected_source_file)
                function_correct += int(
                    row.predicted_function_or_route == truth.expected_function_or_route
                )
        if fixture_correct < 2:
            reasons.append(f"fixture {fixture_id} has more than one classification miss")
        if truth.expected_classification != ClassificationLabel.BENIGN:
            if source_correct >= 2 and function_correct >= 2:
                malicious_localization_pass_count += 1
            else:
                reasons.append(f"fixture {fixture_id} fails 2/3 localization stability")

    if schema_valid_count != 12:
        reasons.append("F3 requires 12/12 schema-valid observations")
    if classification_correct_count < 11:
        reasons.append("F3 requires at least 11/12 correct classifications")
    if malicious_localization_pass_count != 3:
        reasons.append("all three malicious stability fixtures must pass localization stability")
    if policy_violation_count:
        reasons.append("F3 contains a policy violation")
    if unauthorized_path_count:
        reasons.append("F3 contains an unauthorized path")

    return StabilityFeasibilitySummary(
        observation_count=12,
        fixture_count=4,
        schema_valid_count=schema_valid_count,
        classification_correct_count=classification_correct_count,
        malicious_localization_pass_count=malicious_localization_pass_count,
        policy_violation_count=policy_violation_count,
        unauthorized_path_count=unauthorized_path_count,
        passed=not reasons,
        failure_reasons=tuple(reasons),
    )


def evaluate_local_resource_feasibility(
    evidence: LocalResourceEvidence,
) -> tuple[bool, tuple[str, ...]]:
    """Apply the predeclared 16-GB-machine local resource limits."""
    reasons: list[str] = []
    if evidence.minimum_mem_available_bytes < MIN_LOCAL_MEM_AVAILABLE_BYTES:
        reasons.append("minimum MemAvailable fell below 1 GiB")
    additional_swap = max(0, evidence.peak_swap_used_bytes - evidence.baseline_swap_used_bytes)
    if additional_swap > MAX_ADDITIONAL_SWAP_BYTES:
        reasons.append("additional swap consumption exceeded 2 GiB")
    if evidence.max_invocation_duration_ms > MAX_FEASIBILITY_INVOCATION_MS:
        reasons.append("one feasibility model invocation exceeded ten minutes")
    if evidence.oom_kill:
        reasons.append("OOM kill observed")
    if evidence.model_server_crash:
        reasons.append("model-server crash observed")
    if evidence.machine_freeze:
        reasons.append("machine freeze observed")
    if evidence.manual_restart_required:
        reasons.append("manual restart was required")
    return not reasons, tuple(reasons)


def evaluate_provider_candidate(
    *,
    candidate: ProviderCandidateSpec,
    integration: ProviderIntegrationEvidence,
    semantic: SemanticFeasibilitySummary,
    stability: StabilityFeasibilitySummary,
    resource_pass: bool,
    resource_failure_reasons: tuple[str, ...] = (),
) -> ProviderCandidateDecision:
    """Build one immutable candidate decision without cross-candidate ranking."""
    hard_checks = {
        "provider/model identity is not verified": integration.identity_verified,
        "structured output is unavailable": integration.structured_output_supported,
        "research recording is incompatible": integration.research_recording_compatible,
        "automatic retries are not disabled": integration.automatic_retries_disabled,
        "actual provider request count is not observable": (
            integration.actual_request_count_observable
        ),
        "unrestricted tools are not disabled": integration.unrestricted_tools_disabled,
        "provider/model failed to load or connect": integration.load_or_connect_succeeded,
    }
    if candidate.category == ProviderCandidateCategory.ZERO_COST_CLOUD:
        hard_checks["zero-cost cloud access is not verified"] = (
            integration.zero_cost_verified is True
        )
    reasons = [message for message, passed in hard_checks.items() if not passed]
    reasons.extend(semantic.failure_reasons)
    reasons.extend(stability.failure_reasons)
    reasons.extend(resource_failure_reasons)
    hard_pass = all(hard_checks.values())
    eligible = hard_pass and semantic.passed and stability.passed and resource_pass
    return ProviderCandidateDecision(
        candidate=candidate,
        hard_pass=hard_pass,
        semantic_pass=semantic.passed,
        stability_pass=stability.passed,
        resource_pass=resource_pass,
        eligible=eligible,
        failure_reasons=tuple(reasons),
    )


def select_provider_candidate(
    decisions: tuple[ProviderCandidateDecision, ...],
) -> ProviderCandidateDecision:
    """Apply the precommitted minimum-sufficient-provider selection hierarchy."""
    by_category = {item.candidate.category: item for item in decisions}
    if len(decisions) != 3 or set(by_category) != set(ProviderCandidateCategory):
        raise FeasibilityProtocolError(
            "selection requires exactly one result for each candidate category"
        )
    eligible = [item for item in decisions if item.eligible]
    if not eligible:
        raise FeasibilityProtocolError("no provider/model candidate passed all feasibility gates")
    smaller = by_category[ProviderCandidateCategory.SMALLER_LOCAL]
    realistic = by_category[ProviderCandidateCategory.REALISTIC_LOCAL]
    cloud = by_category[ProviderCandidateCategory.ZERO_COST_CLOUD]
    if smaller.eligible:
        return smaller
    if realistic.eligible:
        return realistic
    if cloud.eligible:
        return cloud
    raise AssertionError("eligible candidate set became inconsistent")


def derive_output_ceiling(
    *,
    measurements: tuple[FeasibilityCallMeasurement, ...],
    supported_capacities: tuple[int, ...],
) -> DerivedCapacity:
    """Select the smallest output ceiling above measured valid output plus fixed headroom."""
    usable = [
        item.output_tokens
        for item in measurements
        if item.schema_valid and item.semantically_usable
    ]
    if not usable:
        raise FeasibilityProtocolError("output derivation requires at least one usable measurement")
    observed = max(usable)
    required = max(observed + 256, ceil(observed * 1.25))
    selected = _smallest_supported(required, supported_capacities, "output-token ceiling")
    return DerivedCapacity(
        observed_maximum=observed,
        required_capacity=required,
        selected_capacity=selected,
    )


def derive_context_window(
    *,
    measurements: tuple[FeasibilityCallMeasurement, ...],
    output_ceiling: int,
    supported_capacities: tuple[int, ...],
) -> DerivedCapacity:
    """Select the smallest tested context covering max input, output and fixed headroom."""
    if output_ceiling < 1:
        raise FeasibilityProtocolError("output_ceiling must be positive")
    usable = [
        item.input_tokens
        for item in measurements
        if item.schema_valid and item.semantically_usable
    ]
    if not usable:
        raise FeasibilityProtocolError(
            "context derivation requires at least one usable measurement"
        )
    observed = max(usable)
    required = observed + output_ceiling + max(512, ceil(observed * 0.10))
    selected = _smallest_supported(required, supported_capacities, "context window")
    return DerivedCapacity(
        observed_maximum=observed,
        required_capacity=required,
        selected_capacity=selected,
    )


def derive_rq1_runtime_limit(durations_ms: tuple[int, ...]) -> DerivedRuntimeLimit:
    """Use twice the slowest representative complete DEVELOPMENT RQ1 workflow."""
    if not durations_ms or any(value < 0 for value in durations_ms):
        raise FeasibilityProtocolError("RQ1 runtime derivation requires non-negative durations")
    basis = max(durations_ms)
    projected = basis * 2
    return DerivedRuntimeLimit(
        basis_ms=basis,
        projected_ms=projected,
        selected_runtime_seconds=_ceil_minutes(projected),
    )


def derive_rq2_runtime_limit(
    *,
    classification_latencies_ms: tuple[int, ...],
    deterministic_overhead_ms: int,
    population_size: int = 60,
) -> DerivedRuntimeLimit:
    """Use twice a 60-observation projection based on nearest-rank p95 latency."""
    if not classification_latencies_ms or any(
        value < 0 for value in classification_latencies_ms
    ):
        raise FeasibilityProtocolError("RQ2 runtime derivation requires non-negative latencies")
    if deterministic_overhead_ms < 0 or population_size < 1:
        raise FeasibilityProtocolError("RQ2 runtime inputs must be non-negative and non-empty")
    ordered = sorted(classification_latencies_ms)
    rank = max(1, ceil(0.95 * len(ordered)))
    p95 = ordered[rank - 1]
    projected_once = population_size * p95 + deterministic_overhead_ms
    projected = projected_once * 2
    return DerivedRuntimeLimit(
        basis_ms=p95,
        projected_ms=projected,
        selected_runtime_seconds=_ceil_minutes(projected),
    )


def _smallest_supported(required: int, supported: tuple[int, ...], label: str) -> int:
    if (
        not supported
        or any(value < 1 for value in supported)
        or len(set(supported)) != len(supported)
    ):
        raise FeasibilityProtocolError(
            f"{label} supported capacities must be unique positive values"
        )
    for capacity in sorted(supported):
        if capacity >= required:
            return capacity
    raise FeasibilityProtocolError(f"no tested {label} can satisfy required capacity {required}")


def _ceil_minutes(milliseconds: int) -> int:
    return max(60, ceil(milliseconds / 60_000) * 60)
