"""Prospective DEVELOPMENT-only Blue decision gates.

This code uses model predictions and independently attested registered Red
results, never evaluator truth. No model calls or side effects.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from schemas.common import ClassificationLabel, WorkflowState
from schemas.red_team import RedTeamRunResult
from schemas.rq2_dataset import RQ2ClassificationDecision
from services.bound_registered_red_evidence import BoundRegisteredRedEvidence
from services.target_registry import TargetRegistry, TargetRegistryError


class BlueNextAction(str, Enum):
    NO_ACTION = "no_action"
    MANUAL_REVIEW = "manual_review"
    SELECT_REGISTERED_TEST = "select_registered_test"
    SOURCE_ANALYSIS = "source_analysis"
    WITHHOLD_REPAIR = "withhold_repair"


@dataclass(frozen=True, slots=True)
class BlueGateDecision:
    action: BlueNextAction
    reason_code: str

    @property
    def may_prepare_patch(self) -> bool:
        return self.action == BlueNextAction.SOURCE_ANALYSIS


_ATTACKS = frozenset((
    ClassificationLabel.SQL_INJECTION,
    ClassificationLabel.XSS,
    ClassificationLabel.PATH_TRAVERSAL,
))


def route_model_triage(*, decision: RQ2ClassificationDecision) -> BlueGateDecision:
    """Route only on the actual model response, never expected truth.

    This decision cannot correct misclassifications or change scientific scores.
    """
    if decision.classification == ClassificationLabel.BENIGN:
        return BlueGateDecision(BlueNextAction.NO_ACTION, "model_predicted_benign")
    if decision.classification == ClassificationLabel.UNKNOWN:
        return BlueGateDecision(BlueNextAction.MANUAL_REVIEW, "model_uncertain")
    if decision.classification in _ATTACKS:
        return BlueGateDecision(
            BlueNextAction.SELECT_REGISTERED_TEST, "model_suspects_attack"
        )
    return BlueGateDecision(BlueNextAction.MANUAL_REVIEW, "unrecognized_model_label")


def authorize_registered_test(
    *,
    decision: RQ2ClassificationDecision,
    selected_test_id: str,
    target_id: str,
    trusted_endpoint_id: str,
    registry: TargetRegistry,
) -> BlueGateDecision:
    """Validate a model-selected test using the trusted static registry only."""
    if route_model_triage(decision=decision).action != BlueNextAction.SELECT_REGISTERED_TEST:
        return BlueGateDecision(BlueNextAction.WITHHOLD_REPAIR, "non_actionable_triage")
    try:
        target = registry.get_target(target_id)
        endpoint = registry.get_endpoint(target_id, trusted_endpoint_id)
        definition = registry.get_security_test(selected_test_id)
    except (TargetRegistryError, ValueError):
        return BlueGateDecision(BlueNextAction.WITHHOLD_REPAIR, "unregistered_selection")
    if (
        selected_test_id not in target.allowed_test_ids
        or definition.target_id != target_id
        or definition.endpoint_id != trusted_endpoint_id
        or definition.vulnerability_class.value != decision.classification.value
        or definition.method not in endpoint.allowed_methods
    ):
        return BlueGateDecision(BlueNextAction.WITHHOLD_REPAIR, "selection_context_mismatch")
    return BlueGateDecision(BlueNextAction.SELECT_REGISTERED_TEST, "registered_selection_allowed")


def authorize_source_analysis(
    *,
    decision: RQ2ClassificationDecision,
    selected_test_id: str,
    target_id: str,
    trusted_endpoint_id: str,
    trusted_run_id: str,
    red: RedTeamRunResult | None,
    registry: TargetRegistry,
) -> BlueGateDecision:
    """Require a matching independently executed and verified Red result.

    The caller must separately attest that Red output came from its trusted
    executor. A Pydantic object is not cryptographic runtime provenance.
    """
    selection = authorize_registered_test(
        decision=decision,
        selected_test_id=selected_test_id,
        target_id=target_id,
        trusted_endpoint_id=trusted_endpoint_id,
        registry=registry,
    )
    if selection.reason_code != "registered_selection_allowed":
        return BlueGateDecision(BlueNextAction.WITHHOLD_REPAIR, selection.reason_code)
    if red is None:
        return BlueGateDecision(BlueNextAction.WITHHOLD_REPAIR, "no_verified_red_evidence")
    verification = red.verification
    if (
        red.run_id != trusted_run_id
        or red.target_id != target_id
        or red.final_state != WorkflowState.BLUE_MONITORING
        or red.attempt_number != 1
        or red.reconnaissance.target_id != target_id
        or red.attack_plan.target_id != target_id
        or red.attack_plan.test_id != selected_test_id
        or red.attack_plan.endpoint_id != trusted_endpoint_id
        or red.attack_plan.vulnerability_class.value != decision.classification.value
        or red.execution.run_id != trusted_run_id
        or red.execution.target_id != target_id
        or red.execution.test_id != selected_test_id
        or red.execution.attempt_number != 1
        or red.execution.request_count < 1
        or not red.execution.completed
        or red.execution.timed_out
        or red.execution.error_code is not None
        or verification is None
    ):
        return BlueGateDecision(BlueNextAction.WITHHOLD_REPAIR, "unbound_red_evidence")
    if (
        verification.target_id != target_id
        or verification.test_id != selected_test_id
        or not verification.confirmed
        or not verification.evidence_ids
        or not red.execution.evidence
        or not set(verification.evidence_ids).issubset(
            {e.evidence_id for e in red.execution.evidence}
        )
    ):
        return BlueGateDecision(BlueNextAction.WITHHOLD_REPAIR, "unconfirmed_red_evidence")
    return BlueGateDecision(BlueNextAction.SOURCE_ANALYSIS, "confirmed_registered_red")


@dataclass(frozen=True, slots=True)
class ProspectiveRoutingReceipt:
    """Observed callback dispatch counts; not evaluator correctness or final qualification."""
    triage: BlueGateDecision
    final: BlueGateDecision
    selected_test_id: str | None
    test_selection_calls: int
    registered_execution_calls: int


def run_prospective_gate(
    *,
    decision: RQ2ClassificationDecision,
    target_id: str,
    trusted_endpoint_id: str,
    trusted_run_id: str,
    registry: TargetRegistry,
    select_test: Callable[[], str],
    execute_registered: Callable[[str], RedTeamRunResult | None],
) -> ProspectiveRoutingReceipt:
    """Dispatch from Q6 prediction only, then require attested registered Red.

    Callbacks are supplied by trusted orchestration, never by evaluator truth.
    On rejection or callback failure: no retries, no source-analysis authority.
    """
    first = route_model_triage(decision=decision)
    if first.action != BlueNextAction.SELECT_REGISTERED_TEST:
        return ProspectiveRoutingReceipt(first, first, None, 0, 0)
    try:
        test_id = select_test()
    except Exception:  # noqa: BLE001 - fail closed on injected callback failure
        blocked = BlueGateDecision(BlueNextAction.WITHHOLD_REPAIR, "test_selection_failed")
        return ProspectiveRoutingReceipt(first, blocked, None, 1, 0)
    if not isinstance(test_id, str) or not test_id:
        blocked = BlueGateDecision(BlueNextAction.WITHHOLD_REPAIR, "invalid_test_selection")
        return ProspectiveRoutingReceipt(first, blocked, None, 1, 0)
    allowed = authorize_registered_test(
        decision=decision, selected_test_id=test_id, target_id=target_id,
        trusted_endpoint_id=trusted_endpoint_id, registry=registry,
    )
    if allowed.action != BlueNextAction.SELECT_REGISTERED_TEST:
        return ProspectiveRoutingReceipt(first, allowed, test_id, 1, 0)
    try:
        red = execute_registered(test_id)
    except Exception:  # noqa: BLE001 - fail closed on injected callback failure
        blocked = BlueGateDecision(BlueNextAction.WITHHOLD_REPAIR, "registered_execution_failed")
        return ProspectiveRoutingReceipt(first, blocked, test_id, 1, 1)
    final = authorize_source_analysis(
        decision=decision, selected_test_id=test_id, target_id=target_id,
        trusted_endpoint_id=trusted_endpoint_id, trusted_run_id=trusted_run_id,
        red=red, registry=registry,
    )
    return ProspectiveRoutingReceipt(first, final, test_id, 1, 1)


@dataclass(frozen=True, slots=True)
class ArchivedEvidenceRoutingReceipt:
    """Development archive check only: NO live executor or model dispatch."""

    triage: BlueGateDecision
    final: BlueGateDecision
    selected_test_id: str | None
    test_selection_calls: int
    archived_evidence_load_calls: int


def authorize_bound_source_analysis(
    *,
    decision: RQ2ClassificationDecision,
    selected_test_id: str,
    target_id: str,
    trusted_endpoint_id: str,
    trusted_run_id: str,
    evidence: BoundRegisteredRedEvidence | None,
    registry: TargetRegistry,
) -> BlueGateDecision:
    """Use only the verified archived registered observation, never invented agent Red.

    The caller must have called verify_archived_registered_red with separately
    authorized SHA pins. This is a development gate, not live Docker admission.
    """
    selection = authorize_registered_test(
        decision=decision, selected_test_id=selected_test_id,
        target_id=target_id, trusted_endpoint_id=trusted_endpoint_id,
        registry=registry,
    )
    if selection.action != BlueNextAction.SELECT_REGISTERED_TEST:
        return BlueGateDecision(BlueNextAction.WITHHOLD_REPAIR, selection.reason_code)
    if not isinstance(evidence, BoundRegisteredRedEvidence):
        return BlueGateDecision(BlueNextAction.WITHHOLD_REPAIR, "no_bound_red_evidence")
    obs = evidence.observation
    if (
        evidence.run_id != trusted_run_id
        or evidence.target_id != target_id
        or evidence.test_id != selected_test_id
        or evidence.endpoint_id != trusted_endpoint_id
        or evidence.vulnerability_class != decision.classification.value
        or obs.evidence_scope != "reported_controlled_executor"
        or obs.phase != "vulnerable_baseline"
        or obs.registered_test_id != selected_test_id
        or obs.registered_endpoint_id != trusted_endpoint_id
        or obs.execution.run_id != trusted_run_id
        or obs.execution.attempt_number != 1
        or not obs.execution.completed
        or obs.execution.timed_out
        or obs.evaluation_status != "assessed"
        or not obs.test_completed
        or obs.exploit_confirmed is not True
        or not obs.execution.evidence
    ):
        return BlueGateDecision(BlueNextAction.WITHHOLD_REPAIR, "archived_evidence_context_mismatch")
    return BlueGateDecision(BlueNextAction.SOURCE_ANALYSIS, "archived_registered_red_bound")


def run_archived_evidence_gate(
    *,
    decision: RQ2ClassificationDecision,
    target_id: str,
    trusted_endpoint_id: str,
    trusted_run_id: str,
    registry: TargetRegistry,
    select_test: Callable[[], str],
    load_bound_evidence: Callable[[str], BoundRegisteredRedEvidence | None],
) -> ArchivedEvidenceRoutingReceipt:
    """Offline integrated route with NO new Docker dispatch or evaluator-truth input."""
    triage = route_model_triage(decision=decision)
    if triage.action != BlueNextAction.SELECT_REGISTERED_TEST:
        return ArchivedEvidenceRoutingReceipt(triage, triage, None, 0, 0)
    try:
        selected = select_test()
    except Exception:  # noqa: BLE001 - fail closed on injected model-select callback
        blocked = BlueGateDecision(BlueNextAction.WITHHOLD_REPAIR, "test_selection_failed")
        return ArchivedEvidenceRoutingReceipt(triage, blocked, None, 1, 0)
    if not isinstance(selected, str) or not selected:
        blocked = BlueGateDecision(BlueNextAction.WITHHOLD_REPAIR, "invalid_test_selection")
        return ArchivedEvidenceRoutingReceipt(triage, blocked, None, 1, 0)
    allowed = authorize_registered_test(
        decision=decision, selected_test_id=selected, target_id=target_id,
        trusted_endpoint_id=trusted_endpoint_id, registry=registry,
    )
    if allowed.action != BlueNextAction.SELECT_REGISTERED_TEST:
        return ArchivedEvidenceRoutingReceipt(triage, allowed, selected, 1, 0)
    try:
        evidence = load_bound_evidence(selected)
    except Exception:  # noqa: BLE001 - fail closed on archive-verification error
        blocked = BlueGateDecision(BlueNextAction.WITHHOLD_REPAIR, "bound_evidence_load_failed")
        return ArchivedEvidenceRoutingReceipt(triage, blocked, selected, 1, 1)
    final = authorize_bound_source_analysis(
        decision=decision, selected_test_id=selected,
        target_id=target_id, trusted_endpoint_id=trusted_endpoint_id,
        trusted_run_id=trusted_run_id, evidence=evidence, registry=registry,
    )
    return ArchivedEvidenceRoutingReceipt(triage, final, selected, 1, 1)
