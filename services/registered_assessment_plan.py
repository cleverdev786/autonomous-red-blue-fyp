"""Read-only operational handoff: Q8 prediction -> registered test -> Blue gate.

No model call, HTTP request, registered-test dispatch, evidence fabrication, patch,
Docker, DB write, or research admission. This is a *plan* for an independently
authorized operational workflow, not a completed Red-Blue assessment.
"""
from __future__ import annotations

from pathlib import Path

from pydantic import ValidationError

from schemas.rq2_dataset import RQ2ClassificationDecision
from services.model_assignment import ModelAssignmentBlocked, assign_registered_model
from services.model_driven_decision_gate import (
    BlueNextAction,
    authorize_registered_test,
    authorize_source_analysis,
    route_model_triage,
)
from services.q8_c12_development_bridge import validate_pair
from services.target_registry import TargetRegistry, TargetRegistryError

TARGET_ID = "vulnerable-store"
APPROVED_ROUTES = {
    "/sql-injection/login": "scenario-sqli-login",
    "/xss/search": "scenario-xss-search",
    "/path-traversal/read": "scenario-path-traversal-read",
}

# Backend scenario names bind to the *actual* registered test, route and Red
# scenario ID. A model prediction never selects these execution identities.
SCENARIO_IDENTITIES = {
    "sql": ("/sql-injection/login", "sqli-login-001"),
    "xss": ("/xss/search", "xss-search-001"),
    "traversal": ("/path-traversal/read", "path-traversal-read-001"),
}


class AssessmentPlanBlocked(ValueError):
    """A model suggestion cannot be grounded in the trusted local registry."""


def _registry(root: Path) -> TargetRegistry:
    if not root.is_dir() or root.is_symlink():
        raise AssessmentPlanBlocked("untrusted_application_root")
    try:
        return TargetRegistry.from_directories(
            targets_dir=root / "config" / "targets",
            security_tests_dir=root / "config" / "security_tests",
        )
    except (OSError, ValueError, TargetRegistryError) as exc:
        raise AssessmentPlanBlocked("trusted_registry_unavailable") from exc


def registered_catalog(root: Path) -> dict:
    """Actual registered local target and tests; not a discovered external URL."""
    registry = _registry(root)
    target = registry.get_target(TARGET_ID)
    rows = []
    for route, endpoint_id in APPROVED_ROUTES.items():
        endpoint = registry.get_endpoint(TARGET_ID, endpoint_id)
        tests = [x for x in registry.list_security_tests()
                 if x.target_id == TARGET_ID and x.endpoint_id == endpoint_id
                 and x.test_id in target.allowed_test_ids]
        if len(tests) != 1:
            raise AssessmentPlanBlocked("registered_test_ambiguous_or_missing")
        test = tests[0]
        try:
            model_choice = assign_registered_model(
                target_id=TARGET_ID, route=route, endpoint_id=endpoint_id,
                registered_test_id=test.test_id,
                vulnerability_class=test.vulnerability_class.value,
            )
        except ModelAssignmentBlocked as exc:
            raise AssessmentPlanBlocked("trusted_model_scope_not_supported") from exc
        rows.append({
            "route": route,
            "target_id": TARGET_ID,
            "endpoint_id": endpoint_id,
            "registered_test_id": test.test_id,
            "vulnerability_class": test.vulnerability_class.value,
            "method": test.method.value,
            "endpoint_path": endpoint.path,
            "max_requests": min(target.max_requests_per_attempt, test.max_requests),
            "timeout_seconds": min(target.max_attempt_duration_seconds,
                                   test.timeout_seconds),
            "execution_enabled": False,
            "trusted_registry_verified": True,
            "development_model": model_choice,
        })
    return {
        "target_id": TARGET_ID,
        "scope": "approved_local_synthetic_target_only",
        "registered_assessments": rows,
        "remote_targets_discovered": False,
        "real_test_executed": False,
        "final_research_admitted": False,
    }


def plan_from_model_receipt(
    *, root: Path, pair: dict, receipt: dict
) -> dict:
    """Retain raw label while withholding every unverified operational claim."""
    observed = validate_pair(pair)
    catalog = registered_catalog(root)
    if type(receipt) is not dict or type(receipt.get("decision")) is not dict:
        raise AssessmentPlanBlocked("typed_model_receipt_required")
    if receipt.get("origin") not in ("q8_0_cpu_model", "insufficient_evidence_policy"):
        raise AssessmentPlanBlocked("unknown_classifier_origin")
    if receipt.get("registered_test_dispatched") is not False:
        raise AssessmentPlanBlocked("received_receipt_claimed_test_dispatch")
    if receipt.get("ready_for_source_analysis") is not False:
        raise AssessmentPlanBlocked("received_receipt_claimed_source_authority")
    if receipt.get("ready_for_patch_preparation") is not False:
        raise AssessmentPlanBlocked("received_receipt_claimed_patch_authority")
    if receipt.get("final_research_qualified") is not False:
        raise AssessmentPlanBlocked("received_receipt_claimed_research_qualification")

    try:
        decision = RQ2ClassificationDecision.model_validate(receipt["decision"])
    except ValidationError as exc:
        raise AssessmentPlanBlocked("model_classification_not_typed") from exc

    matched = [row for row in catalog["registered_assessments"]
               if row["route"] == observed["route"]]
    if len(matched) != 1:
        raise AssessmentPlanBlocked("route_not_in_authorized_registry")
    chosen = matched[0]
    endpoint = _registry(root).get_endpoint(TARGET_ID, chosen["endpoint_id"])
    for row in observed["observations"]:
        if row["method"] not in {method.value for method in endpoint.allowed_methods}:
            raise AssessmentPlanBlocked("observation_method_not_registered")
        if not set(row["parameters"]).issubset(endpoint.input_fields):
            raise AssessmentPlanBlocked("observation_parameters_not_registered")

    triage = route_model_triage(decision=decision)
    if (triage.action.value != receipt.get("preliminary_blue_action")
            or triage.reason_code != receipt.get("preliminary_reason_code")):
        raise AssessmentPlanBlocked("model_triage_receipt_mismatch")

    selected = None
    selection = "not_applicable"
    evidence_reason = "no_independent_confirmation"
    if triage.action == BlueNextAction.SELECT_REGISTERED_TEST:
        selected = chosen["registered_test_id"]
        selection_gate = authorize_registered_test(
            decision=decision,
            selected_test_id=selected,
            target_id=TARGET_ID,
            trusted_endpoint_id=chosen["endpoint_id"],
            registry=_registry(root),
        )
        selection = selection_gate.reason_code
        # Reuse the existing Blue gate: no executed and attested Red result exists.
        final_gate = authorize_source_analysis(
            decision=decision,
            selected_test_id=selected,
            target_id=TARGET_ID,
            trusted_endpoint_id=chosen["endpoint_id"],
            trusted_run_id="not_executed",
            red=None,
            registry=_registry(root),
        )
        if selection_gate.action == BlueNextAction.SELECT_REGISTERED_TEST:
            operational = "suspected_requires_registered_verification"
            evidence_reason = final_gate.reason_code
        else:
            operational = "withheld_registration_mismatch"
            evidence_reason = selection_gate.reason_code
    elif triage.action == BlueNextAction.NO_ACTION:
        # A model-only benign label is not evidence that the operation is safe.
        operational = "benign_unverified_requires_trusted_safe_evidence"
        evidence_reason = "no_trusted_safe_outcome_attested"
    else:
        operational = "manual_review_required"
        evidence_reason = "insufficient_or_ambiguous_observed_evidence"

    steps = [
        {"stage": "Target registration", "state": "verified",
         "reason": "target_and_endpoint_from_static_registry"},
        {"stage": "Model triage", "state": "observed_not_authoritative",
         "reason": triage.reason_code},
        {"stage": "Registered test selection",
         "state": "eligible_not_dispatched" if selection == "registered_selection_allowed"
                 else "withheld_or_not_applicable", "reason": selection},
        {"stage": "Red verification", "state": "not_executed",
         "reason": "no_attested_registered_red_evidence"},
        {"stage": "Blue source analysis", "state": "withheld",
         "reason": evidence_reason},
        {"stage": "Trusted remediation", "state": "not_authorized",
         "reason": "verified_red_and_grounded_blue_required"},
        {"stage": "Post-remediation verification", "state": "not_executed",
         "reason": "no_authorized_patch_to_verify"},
        {"stage": "Reporting", "state": "development_plan_only",
         "reason": "not_an_executed_or_scientific_run"},
    ]
    return {
        "kind": "registry_bound_development_assessment_plan_v1",
        "target_id": TARGET_ID,
        "endpoint_id": chosen["endpoint_id"],
        "registered_test_id": selected,
        "route": observed["route"],
        "raw_model_output": decision.model_dump(mode="json"),
        "raw_model_origin": receipt["origin"],
        "evidence_policy_result": (
            "trusted_safe_evidence_required"
            if triage.action == BlueNextAction.NO_ACTION
            else "insufficient_evidence_manual_review"
            if triage.action == BlueNextAction.MANUAL_REVIEW
            else "registered_red_verification_required"
            if selection == "registered_selection_allowed"
            else "registration_context_mismatch"
        ),
        "operational_verdict": operational,
        "reason_code": evidence_reason,
        "triage_action": triage.action.value,
        "registered_selection_reason": selection,
        "stages": steps,
        "executed_tests": False,
        "registered_test_execution_authorized": False,
        "verified_vulnerability": False,
        "trusted_safe_outcome": False,
        "source_analysis_authorized": False,
        "patch_preparation_authorized": False,
        "patch_applied": False,
        "post_remediation_verified": False,
        "final_research_qualified": False,
    }
