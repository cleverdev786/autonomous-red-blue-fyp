"""Prospective model selection from registered scope, never evaluator or model labels."""
from pathlib import Path

import pytest

from services.model_assignment import ModelAssignmentBlocked, assign_registered_model
from services.registered_assessment_plan import registered_catalog

ROOT = Path(__file__).resolve().parents[1]


def test_trusted_catalog_withholds_xss_until_qualification_and_preserves_sql_q8():
    catalog = registered_catalog(ROOT)
    assigned = {item["route"]: item["development_model"] for item in catalog["registered_assessments"]}
    xss = assigned["/xss/search"]
    sql = assigned["/sql-injection/login"]
    traversal = assigned["/path-traversal/read"]
    assert xss["filename"] is None
    assert xss["sha256"] is None
    assert xss["model_role"] == "xss_quality_review_pending"
    assert xss["execution_enabled"] is False
    assert sql["filename"] == "c08b-nf4-effective-Q8_0.gguf"
    assert sql["sha256"] == "51b63a132c73a592d954e96b15c1d28176f0cc3e5f05533304e92a6fb40ad304"
    assert sql["model_role"] == "q8_sqli_development"
    assert traversal["model_role"] == "not_assigned"
    assert traversal["filename"] is None
    for item in assigned.values():
        assert item["selection_basis"] == "trusted_registered_scope"
        assert item["inference_executed"] is False
        assert item["final_research_qualified"] is False


@pytest.mark.parametrize(("field", "value"), [
    ("target_id", "outside-target"),
    ("route", "/other-site/search"),
    ("endpoint_id", "scenario-sqli-login"),
    ("registered_test_id", "sqli-login-bypass-001"),
    ("vulnerability_class", "sql_injection"),
])
def test_xss_model_cannot_be_chosen_by_inconsistent_or_external_scope(field, value):
    entry = {
        "target_id": "vulnerable-store", "route": "/xss/search",
        "endpoint_id": "scenario-xss-search",
        "registered_test_id": "xss-reflection-001", "vulnerability_class": "xss",
    }
    entry[field] = value
    with pytest.raises(ModelAssignmentBlocked):
        assign_registered_model(**entry)


def test_scope_assignment_has_no_prediction_or_evaluator_input():
    import inspect
    params = set(inspect.signature(assign_registered_model).parameters)
    assert not params & {
        "classification", "predicted_label", "model_decision",
        "ground_truth", "expected_label", "confidence", "is_attack",
    }
