"""T06: append-only redacted Red evidence journal; isolated local fixtures."""

import json
import sqlite3
from datetime import datetime, timezone

import pytest

from orchestrator.policy_engine import StandardRedPolicy
from schemas.red_team import RedEndpointCandidate
from schemas.red_team_state import AssessmentDTO, CoverageDTO, OperationDTO, PlanVersionDTO, ReceiptDTO
from services.red_assessment_store import RedAssessmentStore
from services.red_evidence_store import RedEvidenceStore, EvidenceDenied
from services.target_registry import TargetRegistry

from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def journal(tmp_path):
    registry = TargetRegistry.from_directories(
        targets_dir=ROOT / "config/targets", security_tests_dir=ROOT / "config/security_tests",
    )
    auth = StandardRedPolicy(
        registry=registry, budget_file=ROOT / "config/red_standard.json",
    ).freeze(assessment_id="assessment-1", approval_id="approval-1", target_id="vulnerable-store")
    store = RedAssessmentStore(tmp_path / "red.sqlite3")
    store.create(AssessmentDTO(scope=auth.scope, mode="manual", status="created",
                               workflow_complete=False, coverage=CoverageDTO()),
                 auth, request_id="req-1")
    store.add_candidate("assessment-1", RedEndpointCandidate(
        candidate_id="candidate-1", method="GET", path="/scenarios/xss/search",
        source="registered", observed_at=datetime(2026, 10, 27, tzinfo=timezone.utc),
    ))
    store.add_plan(PlanVersionDTO(scope=auth.scope, plan_version="plan-1",
                                  surface_revision="surface-1", status="approved"))
    store.add_operation(OperationDTO(scope=auth.scope, operation_id="op-1",
                                     plan_version="plan-1", candidate_id="candidate-1",
                                     test_id="xss-reflection-001", status="completed"))
    evidence = RedEvidenceStore(store, tmp_path / "artifacts")
    receipt = ReceiptDTO(scope=auth.scope, receipt_id="receipt-1", operation_id="op-1",
                         plan_version="plan-1", source="controlled_http", status="completed")
    evidence.add_receipt(receipt)
    return auth.scope, evidence, store, tmp_path


def test_events_retain_actor_outcome_order_and_restart(journal):
    scope, evidence, store, tmp_path = journal
    at = datetime(2026, 10, 27, tzinfo=timezone.utc)
    evidence.append_event(scope, "event-1", actor="operator", action="assessment_created",
                          outcome="allowed", occurred_at=at, details={"stage": "reconnaissance"})
    evidence.append_event(scope, "event-2", actor="policy", action="operation_blocked",
                          outcome="denied", occurred_at=at, details={"reason_code": "budget_exhausted"})
    reopened = RedEvidenceStore(RedAssessmentStore(store.path), tmp_path / "artifacts")
    events = reopened.list_events(scope)
    assert [item["event_id"] for item in events] == ["event-1", "event-2"]
    assert [(item["actor"], item["outcome"]) for item in events] == [
        ("operator", "allowed"), ("policy", "denied"),
    ]


def test_redacts_sensitive_fields_in_event_and_evidence(journal):
    scope, evidence, _, _ = journal
    evidence.append_event(
        scope, "event-secret", actor="executor", action="receipt_written",
        outcome="allowed", details={
            "request_body": {"password": "never-store-123"},
            "Authorization": "Bearer never-store-456",
            "status": "completed",
            "reason_code": "session-token-789"
        },
    )
    events = evidence.list_events(scope)
    serialized = json.dumps(events)
    assert "never-store-123" not in serialized
    assert "never-store-456" not in serialized
    assert "[REDACTED]" in serialized
    artifact = evidence.write_evidence(
        scope, "evidence-1", receipt_id="receipt-1",
        data={"test_id": "xss-reflection-001",
              "password": "never-store-123",
              "request_body": {"access_token": "never-store-456"},
              "status_code": 200},
    )
    raw = evidence.read_evidence(scope, artifact.evidence_id)
    assert artifact.sha256
    assert artifact.scope.target_fingerprint == scope.target_fingerprint
    assert artifact.operation_id == "op-1"
    assert "never-store-123" not in raw.decode()
    assert "never-store-456" not in raw.decode()
    assert json.loads(raw)["test_id"] == "xss-reflection-001"


def test_hash_integrity_detects_tampering_and_restart(journal):
    scope, evidence, store, tmp_path = journal
    artifact = evidence.write_evidence(
        scope, "evidence-1", receipt_id="receipt-1",
        data={"status_code": 200, "status": "completed"},
    )
    reopened = RedEvidenceStore(RedAssessmentStore(store.path), tmp_path / "artifacts")
    assert reopened.list_evidence(scope) == (artifact,)
    assert reopened.read_evidence(scope, "evidence-1") == evidence.read_evidence(scope, "evidence-1")
    path = tmp_path / "artifacts" / artifact.storage_ref
    path.write_bytes(b"tampered")
    with pytest.raises(EvidenceDenied, match="integrity"):
        reopened.read_evidence(scope, "evidence-1")


def test_cross_scope_read_denied_and_foreign_receipt_rejected(journal):
    scope, evidence, store, tmp_path = journal
    evidence.write_evidence(scope, "ev-1", receipt_id="receipt-1",
                            data={"status": "completed"})
    wrong = scope.model_copy(update={"authorization_fingerprint": "f" * 64})
    with pytest.raises(EvidenceDenied):
        evidence.read_evidence(wrong, "ev-1")
    with pytest.raises(EvidenceDenied):
        evidence.list_events(wrong)
    with pytest.raises(EvidenceDenied):
        evidence.write_evidence(wrong, "ev-2", receipt_id="receipt-1", data={})
    with pytest.raises(EvidenceDenied, match="receipt"):
        evidence.write_evidence(scope, "ev-2", receipt_id="foreign", data={})


def test_path_traversal_and_symlink_escape_denied(journal):
    scope, evidence, _, tmp_path = journal
    with pytest.raises(ValueError):
        evidence.write_evidence(scope, "../escape", receipt_id="receipt-1", data={})
    item = evidence.write_evidence(scope, "ev-1", receipt_id="receipt-1",
                                   data={"status": "completed"})
    with sqlite3.connect(evidence.store.path) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("UPDATE red_evidence SET storage_ref='../outside' WHERE evidence_id='ev-1'")
    stored = tmp_path / "artifacts" / item.storage_ref
    stored.unlink()
    stored.symlink_to(tmp_path / "red.sqlite3")
    with pytest.raises(EvidenceDenied, match="unsafe"):
        evidence.read_evidence(scope, "ev-1")


def test_append_only_db_and_duplicate_keys(journal):
    scope, evidence, _, _ = journal
    evidence.append_event(scope, "ev-1", actor="policy", action="scope_checked",
                          outcome="allowed")
    with pytest.raises(EvidenceDenied, match="duplicate"):
        evidence.append_event(scope, "ev-1", actor="policy", action="scope_checked",
                              outcome="allowed")
    evidence.write_evidence(scope, "artifact-1", receipt_id="receipt-1", data={})
    with pytest.raises(EvidenceDenied, match="duplicate"):
        evidence.write_evidence(scope, "artifact-1", receipt_id="receipt-1", data={})
    with sqlite3.connect(evidence.store.path) as conn:
        for table in ("red_events", "red_evidence"):
            with pytest.raises(sqlite3.DatabaseError):
                conn.execute(f"DELETE FROM {table}")


def test_cancelled_assessment_history_remains_retrievable(journal):
    scope, evidence, store, tmp_path = journal
    evidence.append_event(scope, "cancel-1", actor="operator",
                          action="assessment_cancelled", outcome="cancelled")
    evidence.write_evidence(scope, "ev-1", receipt_id="receipt-1", data={"status": "cancelled"})
    # Simulate the later lifecycle writer transitioning into a terminal state.
    original, _ = store.load("assessment-1")
    cancelled = AssessmentDTO.model_validate({
        **original.assessment.model_dump(), "status": "cancelled",
        "workflow_complete": True,
    })
    with store._connect() as db:
        db.execute(
            "UPDATE red_assessments SET assessment_json=? WHERE assessment_id=?",
            (cancelled.model_dump_json(), "assessment-1"),
        )
    reopened = RedEvidenceStore(RedAssessmentStore(store.path), tmp_path / "artifacts")
    saved, _ = RedAssessmentStore(store.path).load("assessment-1")
    assert saved.assessment.status.value == "cancelled"
    assert reopened.list_events(scope)[0]["outcome"] == "cancelled"
    assert reopened.list_evidence(scope)[0].evidence_id == "ev-1"
    assert reopened.read_evidence(scope, "ev-1")


def test_large_or_unstructured_payload_denied(journal):
    scope, evidence, _, _ = journal
    with pytest.raises(EvidenceDenied, match="size"):
        evidence.write_evidence(scope, "too-large", receipt_id="receipt-1",
                                data={"response_body": "X" * 70000})
    with pytest.raises(EvidenceDenied):
        evidence.write_evidence(scope, "unsupported", receipt_id="receipt-1",
                                data={"nested": object()})
