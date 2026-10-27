"""T04 red-team lifecycle/API DTO contract tests; no Docker or scan."""

from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from schemas.red_team import RedEndpointCandidate, RedScopeReference
from schemas.red_team_state import (
    AssessmentDTO, AssessmentState, CoverageDTO, CoverageGapDTO,
    EvidenceArtifactDTO, FindingDTO, FindingState, OperationDTO,
    PlanVersionDTO, ReceiptDTO, RedAssessmentDetailDTO, StageDTO, StageState, PendingHandoffDTO,
    TimelineEventDTO, GapState, require_finding_transition,
    require_gap_transition, require_assessment_transition, require_stage_transition,
)


@pytest.fixture
def scope():
    return RedScopeReference(
        assessment_id="a-01", target_id="vulnerable-store",
        target_fingerprint="a" * 64, authorization_fingerprint="b" * 64,
    )


@pytest.fixture
def snapshot(scope):
    assessment = AssessmentDTO(
        scope=scope, mode="manual", status="running",
        workflow_complete=False,
        coverage=CoverageDTO(eligible=1, executed=1, completed=1),
    )
    plan = PlanVersionDTO(scope=scope, plan_version="p-01", surface_revision="s-01",
                          status="approved")
    op = OperationDTO(scope=scope, operation_id="op-01", plan_version="p-01",
                      candidate_id="c-01", test_id="xss-reflection-001",
                      status="completed")
    receipt = ReceiptDTO(scope=scope, receipt_id="r-01", operation_id="op-01",
                         plan_version="p-01", source="controlled_http", status="completed")
    finding = FindingDTO(scope=scope, finding_id="f-01", operation_id="op-01",
                         status="confirmed", oracle_id="oracle-xss-01",
                         evidence_receipt_ids=("r-01",))
    event = TimelineEventDTO(scope=scope, event_id="e-01", action="operation_completed",
                             occurred_at=datetime(2026, 10, 27, tzinfo=timezone.utc))
    candidate = RedEndpointCandidate(
        candidate_id="c-01", method="GET", path="/scenarios/xss/search",
        source="registered", observed_at=datetime(2026, 10, 27, tzinfo=timezone.utc),
    )
    return RedAssessmentDetailDTO(
        assessment=assessment, candidates=(candidate,),
        stages=(StageDTO(scope=scope, stage="verification", status="succeeded",
                         plan_version="p-01"),),
        plans=(plan,), operations=(op,), receipts=(receipt,),
        findings=(finding,), events=(event,),
    )


def test_api_payload_roundtrip_preserves_scope_status_and_coverage(snapshot):
    decoded = RedAssessmentDetailDTO.model_validate_json(snapshot.model_dump_json())
    assert decoded == snapshot
    assert decoded.assessment.profile == "standard"
    assert decoded.assessment.workflow_complete is False
    assert decoded.assessment.coverage.coverage_complete is True
    assert decoded.findings[0].status is FindingState.CONFIRMED


def test_all_assessment_state_transitions_are_explicit_and_terminal():
    chain = ["created", "awaiting_authorization", "queued", "running",
             "completed_with_limitations"]
    for source, dest in zip(chain, chain[1:]):
        require_assessment_transition(source, dest)
    for terminal in ("completed", "completed_with_limitations",
                     "failed", "blocked", "cancelled"):
        with pytest.raises(ValueError, match="assessment transition"):
            require_assessment_transition(terminal, "running")
    with pytest.raises(ValueError, match="assessment transition"):
        require_assessment_transition("created", "completed")


def test_stage_rerun_and_stale_transitions_are_explicit():
    for a, b in zip(("not_started", "ready", "queued", "running", "succeeded"),
                    ("ready", "queued", "running", "succeeded", "stale")):
        require_stage_transition(a, b)
    require_stage_transition("stale", "ready")
    with pytest.raises(ValueError, match="stage transition"):
        require_stage_transition("blocked", "succeeded")
    with pytest.raises(ValueError, match="stage transition"):
        require_stage_transition("not_started", "running")


def test_workflow_completion_independent_of_coverage(scope):
    incomplete = CoverageDTO(eligible=3, executed=1, completed=1, skipped=2,
                             observed_candidate_gaps=1)
    row = AssessmentDTO(scope=scope, mode="autonomous", status="completed_with_limitations",
                        workflow_complete=True, coverage=incomplete)
    assert not row.coverage.coverage_complete
    with pytest.raises(ValidationError):
        AssessmentDTO(scope=scope, mode="manual", status="completed",
                      workflow_complete=True, coverage=incomplete)
    with pytest.raises(ValidationError):
        AssessmentDTO(scope=scope, mode="manual", status="running",
                      workflow_complete=True, coverage=CoverageDTO())


@pytest.mark.parametrize("values", [
    {"eligible": 1, "executed": 0, "completed": 1},
    {"eligible": 2, "executed": 1, "blocked": 0, "skipped": 0},
    {"eligible": 1, "executed": 1, "completed": 0, "coverage_complete": True},
    {"eligible": 1, "executed": 1, "completed": 1, "observed_candidate_gaps": 2,
     "coverage_complete": True},
])
def test_inconsistent_coverage_is_rejected(values):
    with pytest.raises(ValidationError):
        CoverageDTO(**values)


def test_reject_foreign_scope_or_orphan_operation(snapshot):
    wrong_scope = snapshot.assessment.scope.model_copy(update={"target_id": "foreign"})
    foreign = snapshot.operations[0].model_copy(update={"scope": wrong_scope})
    with pytest.raises(ValidationError, match="scope"):
        # Pydantic model_copy bypasses validation; revalidation must reject.
        RedAssessmentDetailDTO.model_validate(
            {**snapshot.model_dump(), "operations": [foreign.model_dump()]}
        )
    orphan = snapshot.operations[0].model_copy(update={"plan_version": "unknown"})
    with pytest.raises(ValidationError, match="plan"):
        RedAssessmentDetailDTO.model_validate(
            {**snapshot.model_dump(), "operations": [orphan.model_dump()]}
        )


def test_reject_stale_plan_for_active_operation(snapshot):
    stale = snapshot.plans[0].model_copy(update={"status": "stale"})
    running = snapshot.operations[0].model_copy(update={"status": "running"})
    with pytest.raises(ValidationError, match="stale"):
        RedAssessmentDetailDTO.model_validate({
            **snapshot.model_dump(),
            "plans": [stale.model_dump()],
            "operations": [running.model_dump()],
        })


def test_reject_receipt_with_wrong_operation_or_plan(snapshot):
    bad = snapshot.receipts[0].model_copy(update={"operation_id": "unknown"})
    with pytest.raises(ValidationError, match="receipt"):
        RedAssessmentDetailDTO.model_validate({
            **snapshot.model_dump(), "receipts": [bad.model_dump()],
        })
    bad = snapshot.receipts[0].model_copy(update={"plan_version": "p-02"})
    with pytest.raises(ValidationError, match="receipt"):
        RedAssessmentDetailDTO.model_validate({
            **snapshot.model_dump(), "receipts": [bad.model_dump()],
        })


def test_zap_alert_cannot_confirm_without_controlled_receipt(snapshot):
    alert = snapshot.receipts[0].model_copy(update={"source": "zap"})
    with pytest.raises(ValidationError, match="confirmed"):
        RedAssessmentDetailDTO.model_validate({
            **snapshot.model_dump(), "receipts": [alert.model_dump()],
        })
    with pytest.raises(ValidationError, match="oracle"):
        FindingDTO(scope=snapshot.assessment.scope, finding_id="x",
                   operation_id="op-01", status="confirmed",
                   evidence_receipt_ids=("r-01",))


def test_timeout_and_untested_must_not_be_inferred_negative(scope, snapshot):
    with pytest.raises(ValidationError, match="confirmed"):
        RedAssessmentDetailDTO.model_validate({
            **snapshot.model_dump(),
            "receipts": [snapshot.receipts[0].model_copy(update={"status": "timeout"}).model_dump()],
        })
    gap = CoverageGapDTO(scope=scope, gap_id="gap-01", reason="budget_exhausted",
                         candidate_id="c-02")
    assert gap.reason == "budget_exhausted"
    with pytest.raises(ValidationError):
        FindingDTO(scope=scope, finding_id="not-tested", operation_id="op-01",
                   status="not_tested")


def test_invalid_payload_shape_and_duplicate_ids(snapshot):
    data = snapshot.model_dump()
    data["shell"] = "id"
    with pytest.raises(ValidationError):
        RedAssessmentDetailDTO.model_validate(data)
    with pytest.raises(ValidationError, match="duplicate"):
        RedAssessmentDetailDTO.model_validate({
            **snapshot.model_dump(),
            "receipts": [snapshot.receipts[0].model_dump()] * 2,
        })


def test_evidence_artifact_is_bounded_and_references_receipt(scope, snapshot):
    item = EvidenceArtifactDTO(scope=scope, evidence_id="ev-01", receipt_id="r-01",
                               sha256="c" * 64, content_type="application/json",
                               storage_ref="evidence/ev-01.json")
    payload = {**snapshot.model_dump(), "evidence": [item.model_dump()]}
    assert len(RedAssessmentDetailDTO.model_validate(payload).evidence) == 1
    with pytest.raises(ValidationError):
        EvidenceArtifactDTO(scope=scope, evidence_id="x", receipt_id="r-01",
                            sha256="c" * 64, content_type="text/plain",
                            storage_ref="../private")
    with pytest.raises(ValidationError, match="evidence"):
        RedAssessmentDetailDTO.model_validate({
            **snapshot.model_dump(), "evidence": [item.model_copy(update={"receipt_id": "missing"}).model_dump()],
        })



def test_fastapi_response_model_matches_expected_contract(snapshot):
    app = FastAPI()

    @app.get("/api/red/contract-example", response_model=RedAssessmentDetailDTO)
    def example():
        return snapshot

    with TestClient(app) as client:
        result = client.get("/api/red/contract-example")
    assert result.status_code == 200
    assert RedAssessmentDetailDTO.model_validate(result.json()) == snapshot
    assert set(result.json()) == set(snapshot.model_dump(mode="json"))


def test_handoff_is_only_data_and_requires_confirmed_finding(snapshot):
    handoff = PendingHandoffDTO(
        scope=snapshot.assessment.scope, finding_id="f-01",
    )
    assert handoff.data_only is True
    assert len(RedAssessmentDetailDTO.model_validate({
        **snapshot.model_dump(),
        "pending_handoffs": [handoff.model_dump()],
    }).pending_handoffs) == 1
    with pytest.raises(ValidationError, match="handoff"):
        RedAssessmentDetailDTO.model_validate({
            **snapshot.model_dump(),
            "pending_handoffs": [handoff.model_copy(update={"finding_id": "unknown"}).model_dump()],
        })


def test_scope_fingerprint_must_match_plan_and_receipt(snapshot):
    wrong = snapshot.assessment.scope.model_copy(
        update={"authorization_fingerprint": "c" * 64}
    )
    for field, record in (
        ("plans", snapshot.plans[0]),
        ("receipts", snapshot.receipts[0]),
    ):
        with pytest.raises(ValidationError, match="scope"):
            RedAssessmentDetailDTO.model_validate({
                **snapshot.model_dump(),
                field: [record.model_copy(update={"scope": wrong}).model_dump()],
            })


def test_completed_historical_receipt_survives_stale_plan(snapshot):
    stale_plan = snapshot.plans[0].model_copy(update={"status": "stale"})
    historic = RedAssessmentDetailDTO.model_validate({
        **snapshot.model_dump(),
        "plans": [stale_plan.model_dump()],
    })
    assert historic.receipts[0].receipt_id == "r-01"
    assert historic.plans[0].status == "stale"



def test_finding_verdict_and_gap_transitions():
    require_finding_transition("suspected", "confirmed")
    require_finding_transition("suspected", "not_confirmed")
    require_finding_transition("suspected", "inconclusive")
    require_finding_transition("inconclusive", "suspected")
    with pytest.raises(ValueError, match="finding transition"):
        require_finding_transition("confirmed", "suspected")
    with pytest.raises(ValueError):
        require_finding_transition("suspected", "not_tested")

    require_gap_transition("open", "resolved")
    with pytest.raises(ValueError, match="gap transition"):
        require_gap_transition("resolved", "open")


def test_gap_status_is_explicit_and_not_a_finding(scope):
    gap = CoverageGapDTO(scope=scope, gap_id="g-01", reason="not_tested")
    assert gap.status is GapState.OPEN
    assert CoverageGapDTO.model_validate_json(gap.model_dump_json()) == gap
    with pytest.raises(ValidationError):
        CoverageGapDTO(scope=scope, gap_id="g-01", reason="not_tested",
                       status="confirmed")
