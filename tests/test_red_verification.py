"""T20 deterministic verification over persisted integrity-bound results."""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from agents.red.attack_verifier import DeterministicAttackVerifier
from orchestrator.policy_engine import StandardRedPolicy
from schemas.red_team import (
    HttpExchangeEvidence,
    RedEndpointCandidate,
)
from schemas.red_team import (
    TestExecutionResult as ExecutionResult,
)
from schemas.red_team_state import (
    AssessmentDTO,
    CoverageDTO,
    FindingState,
    OperationDTO,
    PlanVersionDTO,
    ReceiptDTO,
)
from services.red_assessment_store import RedAssessmentStore
from services.red_evidence_store import EvidenceDenied, RedEvidenceStore
from services.target_registry import TargetRegistry

ROOT = Path(__file__).resolve().parents[1]


def result_for(test_id, statuses, bodies):
    endpoint = {
        "sqli-login-bypass-001": "scenario-sqli-login",
        "xss-reflection-001": "scenario-xss-search",
        "path-traversal-private-file-001": "scenario-path-traversal-read",
    }[test_id]
    steps = {
        "sqli-login-bypass-001": ("control-wrong-password", "injection-bypass"),
        "xss-reflection-001": ("control-normal-search", "unescaped-reflection"),
        "path-traversal-private-file-001": (
            "control-public-file", "traversal-private-file",
        ),
    }[test_id]
    exchanges = tuple(
        HttpExchangeEvidence(
            exchange_id=f"exchange-{index}", request_id=f"request-{index}",
            step_id=step, endpoint_id=endpoint,
            method="POST" if "sqli" in test_id else "GET",
            status_code=status, body_excerpt=body, duration_ms=1,
        )
        for index, (step, status, body) in enumerate(zip(steps, statuses, bodies), 1)
    )
    return ExecutionResult(
        run_id=f"run-{test_id}", target_id="vulnerable-store", test_id=test_id,
        attempt_number=1, request_count=2, completed=True,
        status_code=statuses[-1], exchanges=exchanges, duration_ms=2,
    )


def receipt_for(result, *, scope, source="controlled_http", status="completed"):
    raw = json.dumps(
        result.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    ).encode()
    suffix = f"{source}-{status}"
    exchanges = (
        tuple(
            {
                "step_id": item.step_id,
                "endpoint_id": item.endpoint_id,
                "method": item.method,
                "status_code": item.status_code,
                "body_sha256": hashlib.sha256(item.body_excerpt.encode()).hexdigest(),
                "body_length": len(item.body_excerpt),
            }
            for item in result.exchanges
        )
        if source == "controlled_http" else ()
    )
    return ReceiptDTO(
        scope=scope, receipt_id=f"receipt-{result.test_id}-{suffix}",
        operation_id=f"op-{result.test_id}", plan_version="plan-1",
        test_id=result.test_id, run_id=result.run_id,
        target_revision=scope.target_fingerprint,
        recorded_at=datetime(2026, 10, 28, tzinfo=UTC), source=source,
        observation_status="suspected" if source == "zap" else None,
        status=status, request_count=result.request_count, exchanges=exchanges,
        raw_response_sha256=hashlib.sha256(raw).hexdigest(),
        evidence_id=f"evidence-{result.test_id}-{suffix}",
    )


@pytest.fixture
def verification_env(tmp_path):
    registry = TargetRegistry.from_directories(
        targets_dir=ROOT / "config/targets",
        security_tests_dir=ROOT / "config/security_tests",
    )
    authorization = StandardRedPolicy(
        registry=registry, budget_file=ROOT / "config/red_standard.json",
    ).freeze(
        assessment_id="as-verify", approval_id="approval-verify",
        target_id="vulnerable-store",
    )
    store = RedAssessmentStore(tmp_path / "verify.sqlite3")
    store.create(
        AssessmentDTO(
            scope=authorization.scope, mode="manual", status="running",
            workflow_complete=False, coverage=CoverageDTO(),
        ),
        authorization, request_id="request-verify",
    )
    for metadata in registry.list_security_tests():
        endpoint = registry.get_endpoint(metadata.target_id, metadata.endpoint_id)
        store.add_candidate(
            authorization.scope.assessment_id,
            RedEndpointCandidate(
                candidate_id=f"candidate-{metadata.test_id}", method=metadata.method,
                path=endpoint.path, source="registered",
                observed_at=datetime(2026, 10, 28, tzinfo=UTC),
            ),
        )
    store.add_plan(
        PlanVersionDTO(
            scope=authorization.scope, plan_version="plan-1",
            surface_revision="surface-1", status="approved",
        )
    )
    for metadata in registry.list_security_tests():
        store.add_operation(
            OperationDTO(
                scope=authorization.scope,
                operation_id=f"op-{metadata.test_id}", plan_version="plan-1",
                candidate_id=f"candidate-{metadata.test_id}",
                test_id=metadata.test_id, status="approved",
            )
        )
    journal = RedEvidenceStore(store, tmp_path / "evidence")
    return (
        DeterministicAttackVerifier(registry, journal=journal),
        authorization.scope,
        journal,
        registry,
    )


def persist_receipt(journal, receipt):
    journal.add_receipt_with_evidence(
        receipt,
        data={
            "operation_id": receipt.operation_id,
            "test_id": receipt.test_id,
            "status": receipt.status,
        },
    )
    return receipt


@pytest.mark.parametrize(
    ("test_id", "statuses", "bodies", "severity"),
    [
        ("sqli-login-bypass-001", (401, 200),
         ('{"detail":"invalid"}', '{"authenticated":true}'), "high"),
        ("xss-reflection-001", (200, 200),
         ("Search term: notebook", "<script>fyp_xss_marker()</script>"), "medium"),
        ("path-traversal-private-file-001", (200, 200),
         ("Public scenario guide", "FYP_SCENARIO_SECRET=synthetic-traversal-evidence-only"), "high"),
    ],
)
def test_supported_positive_receipts_confirm_with_provenance(
    verification_env, test_id, statuses, bodies, severity
):
    verifier, scope, journal, _ = verification_env
    result = result_for(test_id, statuses, bodies)
    receipt = persist_receipt(journal, receipt_for(result, scope=scope))
    finding = verifier.verify(receipt, result)
    assert finding.status == FindingState.CONFIRMED
    assert finding.severity == severity
    assert finding.route.startswith("/scenarios/")
    assert finding.provenance == "controlled_http"
    assert finding.reproduction_scope == "registered_local_lab"
    assert finding.evidence_id.startswith("evidence-")


@pytest.mark.parametrize(
    ("test_id", "statuses", "bodies"),
    [
        ("sqli-login-bypass-001", (401, 401), ("invalid", "invalid")),
        ("xss-reflection-001", (200, 200), ("Search term: notebook", "escaped")),
        ("path-traversal-private-file-001", (200, 404),
         ("Public scenario guide", "missing")),
    ],
)
def test_complete_negative_receipts_are_not_confirmed(
    verification_env, test_id, statuses, bodies
):
    verifier, scope, journal, _ = verification_env
    result = result_for(test_id, statuses, bodies)
    receipt = persist_receipt(journal, receipt_for(result, scope=scope))
    assert verifier.verify(receipt, result).status == FindingState.NOT_CONFIRMED


def test_zap_timeout_missing_unpersisted_and_tampered_never_confirm(verification_env):
    verifier, scope, journal, _ = verification_env
    result = result_for(
        "xss-reflection-001", (200, 200),
        ("Search term: notebook", "<script>fyp_xss_marker()</script>"),
    )
    zap = persist_receipt(journal, receipt_for(result, scope=scope, source="zap"))
    timeout = persist_receipt(
        journal, receipt_for(result, scope=scope, status="timeout")
    )
    assert verifier.verify(zap, None).status == FindingState.SUSPECTED
    assert verifier.verify(timeout, result).status == FindingState.INCONCLUSIVE
    assert verifier.verify(None, None) is None
    controlled = receipt_for(result, scope=scope)
    assert verifier.verify(controlled, result).status == FindingState.INCONCLUSIVE
    artifactless = controlled.model_copy(update={
        "receipt_id": "receipt-xss-reflection-artifactless",
        "evidence_id": "evidence-xss-reflection-artifactless",
    })
    journal.add_receipt(artifactless)
    assert verifier.verify(artifactless, result).status == FindingState.INCONCLUSIVE
    controlled = persist_receipt(journal, controlled)
    with pytest.raises(EvidenceDenied, match="integrity"):
        verifier.verify(controlled, result.model_copy(update={"duration_ms": 99}))


def test_zap_no_alert_receipt_is_inconclusive(verification_env):
    verifier, scope, journal, _ = verification_env
    result = result_for(
        "xss-reflection-001", (200, 200),
        ("Search term: notebook", "escaped"),
    )
    receipt = receipt_for(result, scope=scope, source="zap").model_copy(update={
        "receipt_id": "receipt-xss-reflection-zap-no-alert",
        "evidence_id": "evidence-xss-reflection-zap-no-alert",
        "observation_status": "not_observed",
    })
    persist_receipt(journal, receipt)

    assert verifier.verify(receipt, None).status == FindingState.INCONCLUSIVE


def test_unsupported_oracle_is_inconclusive(verification_env):
    _, scope, journal, registry = verification_env
    verifier = DeterministicAttackVerifier(
        registry, supported_oracles=frozenset(), journal=journal
    )
    result = result_for(
        "xss-reflection-001", (200, 200),
        ("Search term: notebook", "<script>fyp_xss_marker()</script>"),
    )
    receipt = persist_receipt(journal, receipt_for(result, scope=scope))
    assert verifier.verify(receipt, result).status == FindingState.INCONCLUSIVE
