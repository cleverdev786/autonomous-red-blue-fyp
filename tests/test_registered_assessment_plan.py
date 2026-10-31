"""Registry-bound Q8 assessment handoff, no real execution or evaluator truth."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dashboard.api.console import create_console_app
from services.q8_c12_development_bridge import classification_receipt
from services.registered_assessment_plan import (
    APPROVED_ROUTES,
    AssessmentPlanBlocked,
    plan_from_model_receipt,
    registered_catalog,
)

ROOT = Path(__file__).resolve().parents[1]
TARGET = "vulnerable-store"
ROUTE_TEST = (
    ("/sql-injection/login", "sql_injection", "sqli-login-bypass-001", "POST", "username"),
    ("/xss/search", "xss", "xss-reflection-001", "GET", "q"),
    ("/path-traversal/read", "path_traversal", "path-traversal-private-file-001", "GET", "path"),
)


def pair(route, method, field):
    return {
        "route": route,
        "observations": [
            {"method": method, "parameters": {field: "one"}, "status_code": 200,
             "response_excerpt": "PUBLIC_EXAMPLE"},
            {"method": method, "parameters": {field: "two"}, "status_code": 200,
             "response_excerpt": "SECOND_EXAMPLE"},
        ],
    }


def receipt(paired, label, *, origin="q8_0_cpu_model"):
    return classification_receipt(pair=paired, gateway_reply={
        "role": "classification", "origin": origin, "executed_tests": False,
        "result": {
            "classification": label, "confidence": 0.91,
            "reason": "Model-only synthetic description, not attested execution."
        }
    })


def test_target_catalog_is_loaded_from_actual_registry():
    c = registered_catalog(ROOT)
    assert c["target_id"] == TARGET
    assert len(c["registered_assessments"]) == 3
    assert {row["route"] for row in c["registered_assessments"]} == set(APPROVED_ROUTES)
    assert all(not row["execution_enabled"] for row in c["registered_assessments"])
    assert all(row["max_requests"] <= 5 for row in c["registered_assessments"])


@pytest.mark.parametrize(("route","label","test_id","method","field"), ROUTE_TEST)
def test_vulnerability_prediction_produces_registered_nonexecuting_handoff(
    route, label, test_id, method, field
):
    paired = pair(route, method, field)
    result = plan_from_model_receipt(root=ROOT, pair=paired, receipt=receipt(paired, label))
    assert result["raw_model_output"]["classification"] == label
    assert result["registered_test_id"] == test_id
    assert result["operational_verdict"] == "suspected_requires_registered_verification"
    assert result["registered_selection_reason"] == "registered_selection_allowed"
    assert result["reason_code"] == "no_verified_red_evidence"
    assert result["evidence_policy_result"] == "registered_red_verification_required"
    assert result["registered_test_execution_authorized"] is False
    assert result["stages"][2]["state"] == "eligible_not_dispatched"
    assert result["stages"][3]["state"] == "not_executed"
    assert result["source_analysis_authorized"] is False
    assert result["patch_preparation_authorized"] is False
    assert result["post_remediation_verified"] is False
    assert result["final_research_qualified"] is False


def test_confident_xss_false_positive_kept_verbatim_but_does_not_authorize_patch():
    paired = pair("/xss/search", "GET", "q")
    result = plan_from_model_receipt(root=ROOT, pair=paired, receipt=receipt(paired, "xss"))
    assert result["raw_model_output"]["classification"] == "xss"
    assert result["raw_model_output"]["confidence"] == 0.91
    assert result["verified_vulnerability"] is False
    assert result["operational_verdict"] == "suspected_requires_registered_verification"
    assert result["patch_applied"] is False


@pytest.mark.parametrize(("label","origin","expected"), [
    ("benign","q8_0_cpu_model","benign_unverified_requires_trusted_safe_evidence"),
    ("unknown","q8_0_cpu_model","manual_review_required"),
    ("unknown","insufficient_evidence_policy","manual_review_required"),
])
def test_benign_and_unknown_are_distinct_and_require_evidence(label,origin,expected):
    paired=pair("/xss/search","GET","q")
    result=plan_from_model_receipt(
        root=ROOT,pair=paired,receipt=receipt(paired,label,origin=origin))
    assert result["raw_model_output"]["classification"] == label
    assert result["raw_model_origin"] == origin
    assert result["operational_verdict"] == expected
    assert result["evidence_policy_result"] == (
        "trusted_safe_evidence_required"
        if label == "benign" else "insufficient_evidence_manual_review"
    )
    assert result["registered_test_id"] is None
    assert result["trusted_safe_outcome"] is False
    assert result["verified_vulnerability"] is False


def test_wrong_class_for_registered_route_withheld_without_dispatch():
    paired = pair("/xss/search","GET","q")
    result = plan_from_model_receipt(root=ROOT,pair=paired,receipt=receipt(paired,"sql_injection"))
    assert result["registered_test_id"] == "xss-reflection-001"
    assert result["registered_selection_reason"] == "selection_context_mismatch"
    assert result["operational_verdict"] == "withheld_registration_mismatch"
    assert result["stages"][2]["state"] == "withheld_or_not_applicable"
    assert result["executed_tests"] is False


@pytest.mark.parametrize("corrupt",[
    {"registered_test_dispatched": True},
    {"ready_for_source_analysis": True},
    {"ready_for_patch_preparation": True},
    {"final_research_qualified": True},
    {"origin": "externally_supplied"},
    {"preliminary_blue_action": "source_analysis"},
    {"preliminary_reason_code": "confirmed_registered_red"},
])
def test_forged_authority_or_origin_cannot_cross_gate(corrupt):
    paired=pair("/xss/search","GET","q")
    supplied=receipt(paired,"xss")
    supplied.update(corrupt)
    with pytest.raises(AssessmentPlanBlocked):
        plan_from_model_receipt(root=ROOT,pair=paired,receipt=supplied)


@pytest.mark.parametrize("corrupt",[
    lambda d: d["observations"][0].update({"method":"POST"}),
    lambda d: d["observations"][0]["parameters"].update({"root":"private"}),
    lambda d: d.update({"route":"/not-registered"}),
])
def test_route_method_parameter_are_all_validated_against_registry(corrupt):
    paired=pair("/xss/search","GET","q")
    supplied=receipt(paired,"xss")
    altered=json.loads(json.dumps(paired))
    corrupt(altered)
    with pytest.raises((AssessmentPlanBlocked,ValueError)):
        plan_from_model_receipt(root=ROOT,pair=altered,receipt=supplied)


def test_invalid_or_missing_registry_rejects_plan(tmp_path):
    paired=pair("/xss/search","GET","q")
    with pytest.raises(AssessmentPlanBlocked,match="trusted_registry_unavailable"):
        plan_from_model_receipt(root=tmp_path,pair=paired,receipt=receipt(paired,"xss"))


def test_operator_registry_endpoint_returns_only_registered_local_metadata():
    with TestClient(create_console_app(database_path="/nonexistent/testdb.sqlite")) as client:
        response=client.get("/api/console/assessment/registry")
        assert response.status_code==200
        catalog=response.json()
        assert len(catalog["registered_assessments"])==3
        assert catalog["remote_targets_discovered"] is False
        assert catalog["real_test_executed"] is False


def test_plan_source_has_no_red_test_or_patch_executor_imports():
    import inspect

    import services.registered_assessment_plan as m
    source=inspect.getsource(m)
    for banned in (
        "ControlledExecutor","execute_registered_test(","TrustedRemediationCompiler(",
        "subprocess","httpx","docker compose","patch_service"
    ):
        assert banned not in source
