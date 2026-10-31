"""Prospective specialist choice from trusted *registered* scope only.

This is not an inference adapter, a model correctness label, or execution
authority. It cannot retrospectively change recorded classifications or RQ2.
"""
from __future__ import annotations


class ModelAssignmentBlocked(ValueError):
    """Caller did not supply one of the registered synthetic scope identities."""


# Exact route + endpoint + test + vulnerability identity must agree. A model
# prediction, user-entered URL, or evaluator label is never a routing input.
_SCOPES = {
    ("vulnerable-store", "/sql-injection/login", "scenario-sqli-login",
     "sqli-login-bypass-001", "sql_injection"): (
        "q8_sqli_development",
        "c08b-nf4-effective-Q8_0.gguf",
        "51b63a132c73a592d954e96b15c1d28176f0cc3e5f05533304e92a6fb40ad304",
    ),
    ("vulnerable-store", "/xss/search", "scenario-xss-search",
     "xss-reflection-001", "xss"): (
        "xss_quality_review_pending", None, None,
    ),
    ("vulnerable-store", "/path-traversal/read", "scenario-path-traversal-read",
     "path-traversal-private-file-001", "path_traversal"): (
        "not_assigned", None, None,
    ),
}


def assign_registered_model(
    *, target_id: str, route: str, endpoint_id: str,
    registered_test_id: str, vulnerability_class: str,
) -> dict:
    """Name the specialist for a separately registry-verified local scenario.

    This function never loads a model or uses inferred/evaluator truth.
    """
    key = (target_id, route, endpoint_id, registered_test_id, vulnerability_class)
    try:
        role, filename, digest = _SCOPES[key]
    except (KeyError, TypeError) as exc:
        raise ModelAssignmentBlocked("Unregistered model assignment scope") from exc
    return {
        "model_role": role,
        "filename": filename,
        "sha256": digest,
        "selection_basis": "trusted_registered_scope",
        "execution_enabled": False,
        "inference_executed": False,
        "final_research_qualified": False,
    }
