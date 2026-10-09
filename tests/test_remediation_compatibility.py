"""Recovery schema, provenance, safe no-patch RQ1 and legacy compatibility.

No model, compiler, Docker, or live repository access is required.
"""
from __future__ import annotations

from pathlib import Path
import json

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from experiments.rq1_runner import RQ1ExperimentRunner, RQ1RemediationExecutionResult, RQ1RunnerError
from orchestrator.policy_engine import PolicyEngine
from orchestrator.remediation_outcome_flow import RemediationOutcomeFlow, RemediationTerminationBlocked
from schemas.blue_team import BlueTeamAnalysisResult, CodeFinding, MonitoringResult, SourceLineRange, TriageResult
from schemas.common import ClassificationLabel, ResearchQuestion, RunStatus, RunType, VulnerabilityClass, WorkflowState, PolicyReasonCode
from schemas.experiment_results import ArtifactType
from schemas.experiments import BlueTeamMode, ClassificationMode, ExperimentConfiguration, ModelConfiguration
from schemas.logging import AuditExecutionStatus, AuditPolicyDecision
from schemas.patches import PatchGenerationResult, PatchProposal, PreparedFileChange, PreparedPatch, ProposedFileChange
from schemas.remediation import (
    NoActionReason, RemediationAttemptResult, RemediationDecision,
    RemediationDisposition, RepairStrategy,
)
from services.audit_service import AuditService
from services.target_registry import TargetRegistry
from storage.database import create_database_engine, initialize_database, make_session_factory
from storage.models import Base, ExperimentRunRow, PatchAttemptRow, ResultArtifactRow
from storage.repositories import (
    ExperimentWriteRepository, ResearchReadRepository, ResearchStorageError,
    canonical_model_json, canonical_sha256,
)

ROOT = Path(__file__).resolve().parents[1]
HASH = "a" * 64
HASH2 = "b" * 64
HASH3 = "c" * 64
TARGET = "vulnerable-store"


def decision(*, action="repair", cls=VulnerabilityClass.SQL_INJECTION, reason=None):
    if action == "no_action":
        return RemediationDecision(schema_version="1.0", action="no_action", no_action_reason=reason)
    strategies = {
        VulnerabilityClass.SQL_INJECTION: RepairStrategy.SQLALCHEMY_NAMED_BIND,
        VulnerabilityClass.XSS: RepairStrategy.HTML_TEXT_ESCAPE,
        VulnerabilityClass.PATH_TRAVERSAL: RepairStrategy.CANONICAL_PUBLIC_ROOT,
    }
    return RemediationDecision(schema_version="1.0", action="repair", vulnerability_class=cls,
                               strategy=strategies[cls], tainted_symbol="payload.username")


def outcome(run_id, disposition, *, classification=ClassificationLabel.SQL_INJECTION):
    opts = {
        "schema_version": "1.0", "run_id": run_id, "target_id": TARGET,
        "attempt_number": 1, "disposition": disposition, "reason_code": disposition.value,
    }
    if disposition == RemediationDisposition.NO_ACTION:
        pass  # trusted upstream benign bypass, no LLM call
    elif disposition == RemediationDisposition.UNSUPPORTED:
        opts.update(decision=decision(action="no_action", reason=NoActionReason.UNSUPPORTED),
                    model_input_sha256=HASH, raw_response_sha256=HASH2)
    elif disposition == RemediationDisposition.COMPILER_REJECTED:
        opts.update(decision=decision(), model_input_sha256=HASH, raw_response_sha256=HASH2,
                    source_sha256=HASH3, compiler_version="compiler-v1", compiler_sha256=HASH)
    elif disposition == RemediationDisposition.INVALID_OUTPUT:
        opts.update(model_input_sha256=HASH, raw_response_sha256=HASH2)
    elif disposition == RemediationDisposition.PROVIDER_FAILED:
        opts.update(model_input_sha256=HASH)
    elif disposition == RemediationDisposition.POLICY_BLOCKED:
        opts.update(model_input_sha256=HASH, policy_event_id="blocked-prior-event",
                    reason_code=PolicyReasonCode.PROHIBITED_OPERATION.value)
    return RemediationAttemptResult(**opts)


def make_analysis(run_id, *, benign=False):
    classification = ClassificationLabel.BENIGN if benign else ClassificationLabel.SQL_INJECTION
    finding = None if benign else CodeFinding(
        run_id=run_id, file_path="dummy_apps/vulnerable_store/app/scenario_routes.py",
        function_or_route="vulnerable_login", root_cause="unsafe SQL query",
        supporting_lines=(SourceLineRange(start_line=1, end_line=1),), confidence=0.9,
    )
    return BlueTeamAnalysisResult(
        run_id=run_id, target_id=TARGET, classification_mode=ClassificationMode.HYBRID,
        triage=TriageResult(run_id=run_id, is_suspicious=not benign,
                            classification=classification, confidence=0.9, reason="synthetic evidence"),
        code_finding=finding,
        final_state=WorkflowState.TRIAGE if benign else WorkflowState.CODE_ANALYSIS,
    )


@pytest.fixture
def sandbox(tmp_path):
    db = tmp_path / "evidence.sqlite"
    engine = create_database_engine(f"sqlite:///{db}", project_root=tmp_path)
    initialize_database(engine)
    factory = make_session_factory(engine)
    write = ExperimentWriteRepository(factory)
    read = ResearchReadRepository(factory)
    registry = TargetRegistry.from_directories(
        targets_dir=ROOT / "config/targets", security_tests_dir=ROOT / "config/security_tests",
    )
    policy = PolicyEngine(registry=registry, project_root=tmp_path)
    audit = AuditService(project_root=tmp_path)
    flow = RemediationOutcomeFlow(policy_engine=policy, audit_service=audit, write_repository=write)
    yield write, read, factory, policy, audit, flow, engine
    engine.dispose()


def create_run(write, run_id, *, benign=False):
    config = ExperimentConfiguration(
        config_id=f"cfg-{run_id}", run_type=RunType.DEVELOPMENT,
        research_question=ResearchQuestion.RQ1, scenario_ids=("sqli-login-001",),
        blue_team_mode=BlueTeamMode.SINGLE_AGENT,
        model=ModelConfiguration(provider="mock", model_name="fixture"),
    )
    write.create_configuration(config)
    write.create_run(run_id=run_id, config_id=config.config_id, repetition_index=1,
                     baseline_commit="c" * 40, scenario_id="sqli-login-001")
    write.mark_running(run_id)
    monitoring = MonitoringResult(run_id=run_id, summary="Synthetic observation")
    analysis = make_analysis(run_id, benign=benign)
    write.record_monitoring_result(monitoring)
    write.record_blue_result(analysis)
    return monitoring, analysis


def test_plan_json_roundtrip_and_forbidden_fields():
    valid = decision()
    assert RemediationDecision.model_validate_json(valid.model_dump_json()) == valid
    assert valid.strategy == RepairStrategy.SQLALCHEMY_NAMED_BIND
    for invalid in [
        {**valid.model_dump(mode="json"), "target_file": "/etc/passwd"},
        {**valid.model_dump(mode="json"), "strategy": "html_text_escape"},
        {**valid.model_dump(mode="json"), "tainted_symbol": "import os"},
        {**valid.model_dump(mode="json"), "no_action_reason": "benign"},
        {**valid.model_dump(mode="json"), "schema_version": "2.0"},
    ]:
        with pytest.raises(ValidationError):
            RemediationDecision.model_validate(invalid)
    with pytest.raises(ValidationError):
        RemediationDecision.model_validate({"schema_version": "1.0", "action": "no_action"})


def test_provenance_shapes_and_disposition_invariants():
    for d in [RemediationDisposition.NO_ACTION, RemediationDisposition.UNSUPPORTED,
              RemediationDisposition.INVALID_OUTPUT, RemediationDisposition.COMPILER_REJECTED,
              RemediationDisposition.POLICY_BLOCKED, RemediationDisposition.PROVIDER_FAILED]:
        assert outcome(f"run-{d.value}", d).disposition == d

def test_no_patch_schema_guards():
    base = outcome("run-n", RemediationDisposition.NO_ACTION).model_dump(mode="json")
    for edit in [
        {"prepared_diff_sha256": HASH},
        {"legacy_generation_artifact_sha256": HASH},
        {"decision": decision().model_dump(mode="json")},
        {"compiler_sha256": HASH},
    ]:
        with pytest.raises(ValidationError):
            RemediationAttemptResult.model_validate({**base, **edit})
    bad = outcome("run-x", RemediationDisposition.INVALID_OUTPUT).model_dump(mode="json")
    with pytest.raises(ValidationError):
        RemediationAttemptResult.model_validate({**bad, "raw_response_sha256": None})
    prepared = {
        "schema_version": "1.0", "run_id": "run-p", "target_id": TARGET,
        "attempt_number": 1, "disposition": "prepared", "reason_code": "prepared",
        "decision": decision().model_dump(mode="json"),
        "model_input_sha256": HASH, "raw_response_sha256": HASH2,
        "source_sha256": HASH3, "compiler_version": "compiler-v1",
        "compiler_sha256": HASH, "prepared_diff_sha256": HASH2,
        "legacy_generation_artifact_sha256": HASH3,
    }
    assert RemediationAttemptResult.model_validate(prepared).disposition == RemediationDisposition.PREPARED
    with pytest.raises(ValidationError):
        RemediationAttemptResult.model_validate({**prepared, "compiler_version": None})


@pytest.mark.parametrize("disp,benign,status", [
    (RemediationDisposition.NO_ACTION, True, RunStatus.COMPLETED),
    (RemediationDisposition.UNSUPPORTED, False, RunStatus.COMPLETED),
    (RemediationDisposition.COMPILER_REJECTED, False, RunStatus.COMPLETED),
    (RemediationDisposition.INVALID_OUTPUT, False, RunStatus.FAILED),
    (RemediationDisposition.PROVIDER_FAILED, False, RunStatus.FAILED),
    (RemediationDisposition.POLICY_BLOCKED, False, RunStatus.POLICY_BLOCKED),
])
def test_terminal_dispositions_persist_without_patch(sandbox, disp, benign, status):
    write, read, factory, policy, audit, flow, _ = sandbox
    run_id = f"run-{disp.value}"
    _, analysis = create_run(write, run_id, benign=benign)
    result = outcome(run_id, disp)
    if disp == RemediationDisposition.POLICY_BLOCKED:
        prior = audit.record(
            run_id=run_id, component="trusted_policy", actor_type="orchestrator",
            operation="patch_policy_check", target=TARGET,
            policy_decision=AuditPolicyDecision.BLOCKED,
            policy_reason=PolicyReasonCode.PROHIBITED_OPERATION,
            execution_status=AuditExecutionStatus.BLOCKED,
        )
        result = result.model_copy(update={"policy_event_id": prior.event_id})
    artifact_id = flow.finish_without_patch(analysis=analysis, result=result)
    with factory() as session:
        run = session.get(ExperimentRunRow, run_id)
        rows = session.scalars(select(ResultArtifactRow).where(
            ResultArtifactRow.run_id == run_id,
            ResultArtifactRow.artifact_type == ArtifactType.REMEDIATION_ATTEMPT_RESULT.value,
        )).all()
        assert run.status == status.value
        assert run.completed_at is not None
        assert len(rows) == 1 and rows[0].artifact_id == artifact_id
        assert rows[0].schema_version == "1.0"
        assert rows[0].payload_sha256 == canonical_sha256(rows[0].payload_json)
        assert RemediationAttemptResult.model_validate_json(rows[0].payload_json) == result
        assert session.scalars(select(PatchAttemptRow).where(PatchAttemptRow.run_id == run_id)).all() == []
    expected_events = ["authorized", "succeeded"]
    if disp == RemediationDisposition.POLICY_BLOCKED:
        expected_events.insert(0, "blocked")
    assert [event.execution_status.value for event in audit.read_run(run_id=run_id)] == expected_events
    with pytest.raises(ResearchStorageError):
        flow.finish_without_patch(analysis=analysis, result=result)


def test_policy_denies_malicious_no_action_and_mismatched_identity(sandbox):
    write, _, factory, policy, audit, flow, _ = sandbox
    create_run(write, "malicious")
    analysis = make_analysis("malicious")
    no_action = outcome("malicious", RemediationDisposition.NO_ACTION)
    with pytest.raises(RemediationTerminationBlocked):
        flow.finish_without_patch(analysis=analysis, result=no_action)
    bad = outcome("another", RemediationDisposition.UNSUPPORTED)
    with pytest.raises(RemediationTerminationBlocked):
        flow.finish_without_patch(analysis=analysis, result=bad)
    with factory() as session:
        assert session.get(ExperimentRunRow, "malicious").status == RunStatus.RUNNING.value
        assert session.scalars(select(ResultArtifactRow).where(
            ResultArtifactRow.artifact_type == ArtifactType.REMEDIATION_ATTEMPT_RESULT.value,
        )).all() == []
    assert all(event.execution_status.value == "blocked" for event in audit.read_run(run_id="malicious"))


def test_actionable_insufficient_evidence_no_action(sandbox):
    write, _, factory, _, _, flow, _ = sandbox
    _, analysis = create_run(write, "insufficient-evidence")
    r = outcome("insufficient-evidence", RemediationDisposition.NO_ACTION).model_copy(update={
        "decision": decision(action="no_action", reason=NoActionReason.INSUFFICIENT_EVIDENCE),
        "model_input_sha256": HASH, "raw_response_sha256": HASH2,
        "reason_code": "insufficient_evidence",
    })
    # Ensure revalidation (not model_copy's unchecked state) succeeds.
    r = RemediationAttemptResult.model_validate(r.model_dump(mode="json"))
    flow.finish_without_patch(analysis=analysis, result=r)
    with factory() as session:
        assert session.get(ExperimentRunRow, "insufficient-evidence").status == RunStatus.COMPLETED.value
        assert session.scalars(select(PatchAttemptRow)).all() == []


def test_policy_blocked_must_reference_real_blocked_audit_event(sandbox):
    write, _, factory, _, _, flow, _ = sandbox
    _, analysis = create_run(write, "fake-block")
    with pytest.raises(RemediationTerminationBlocked, match="blocked audit"):
        flow.finish_without_patch(
            analysis=analysis,
            result=outcome("fake-block", RemediationDisposition.POLICY_BLOCKED),
        )
    with factory() as session:
        assert session.get(ExperimentRunRow, "fake-block").status == RunStatus.RUNNING.value


def test_policy_blocked_rejects_unrelated_audit_reason(sandbox):
    write, _, factory, _, audit, flow, _ = sandbox
    _, analysis = create_run(write, "wrong-block")
    event = audit.record(
        run_id="wrong-block", component="trusted_policy", actor_type="orchestrator",
        operation="patch_policy_check", target=TARGET,
        policy_decision=AuditPolicyDecision.BLOCKED,
        policy_reason=PolicyReasonCode.INVALID_STATE,
        execution_status=AuditExecutionStatus.BLOCKED,
    )
    result = outcome("wrong-block", RemediationDisposition.POLICY_BLOCKED).model_copy(
        update={"policy_event_id": event.event_id}
    )
    with pytest.raises(RemediationTerminationBlocked):
        flow.finish_without_patch(analysis=analysis, result=result)
    with factory() as session:
        assert session.get(ExperimentRunRow, "wrong-block").status == RunStatus.RUNNING.value


def test_storage_does_not_trust_result_without_recorded_blue_evidence(sandbox):
    write, _, _, policy, _, _, _ = sandbox
    _, analysis = create_run(write, "blue-match")
    forged = make_analysis("blue-match", benign=True)
    result = outcome("blue-match", RemediationDisposition.NO_ACTION)
    with pytest.raises(ResearchStorageError):
        write.finalize_remediation_without_patch(result=result, analysis=forged, policy_engine=policy)
    with pytest.raises(ResearchStorageError):
        write.finalize_remediation_without_patch(result=result, analysis=analysis, policy_engine=policy)


def test_storage_direct_call_cannot_bypass_no_patch_policy(sandbox):
    write, _, factory, policy, _, _, _ = sandbox
    _, analysis = create_run(write, "malicious-direct")
    benign_result = outcome("malicious-direct", RemediationDisposition.NO_ACTION)
    with pytest.raises(ResearchStorageError, match="denied"):
        write.finalize_remediation_without_patch(
            result=benign_result, analysis=analysis, policy_engine=policy,
        )
    with factory() as session:
        assert session.get(ExperimentRunRow, "malicious-direct").status == RunStatus.RUNNING.value


def test_terminal_storage_refuses_existing_patch_attempt(sandbox):
    write, _, factory, _, audit, flow, _ = sandbox
    _, analysis = create_run(write, "pending", benign=True)
    write.begin_patch_attempt(run_id="pending", attempt_number=1)
    with pytest.raises(ResearchStorageError, match="after patch attempt"):
        flow.finish_without_patch(analysis=analysis, result=outcome("pending", RemediationDisposition.NO_ACTION))
    assert audit.read_run(run_id="pending")[-1].execution_status.value == "failed"
    with factory() as session:
        assert session.get(ExperimentRunRow, "pending").status == RunStatus.RUNNING.value


def test_prepared_provenance_links_to_real_legacy_artifact(sandbox):
    write, _, factory, _, _, _, _ = sandbox
    create_run(write, "patch-link")
    patch = PreparedPatch(
        run_id="patch-link", target_id=TARGET, attempt_number=1,
        files=(PreparedFileChange(file_path="dummy_apps/vulnerable_store/app/scenario_routes.py",
                                  original_sha256=HASH, replacement_sha256=HASH2,
                                  replacement_content="fixed"),),
        unified_diff="--- a\n+++ b", diff_sha256=HASH3,
        files_changed=1, inserted_lines=1, deleted_lines=1, total_diff_bytes=11,
    )
    proposal = PatchProposal(
        run_id="patch-link", target_id=TARGET, attempt_number=1,
        changes=(ProposedFileChange(file_path="dummy_apps/vulnerable_store/app/scenario_routes.py",
                                    original_content="bad", replacement_content="good", rationale="fix"),),
        security_rationale="fix", expected_effect="secure",
    )
    old = PatchGenerationResult(
        run_id="patch-link", target_id=TARGET, attempt_number=1,
        proposal=proposal, prepared_patch=patch, final_state=WorkflowState.PATCH_VALIDATING,
    )
    write.record_patch_generation_result(old)
    old_hash = canonical_sha256(canonical_model_json(old))
    r = RemediationAttemptResult(
        schema_version="1.0", run_id="patch-link", target_id=TARGET, attempt_number=1,
        disposition=RemediationDisposition.PREPARED, reason_code="prepared",
        decision=decision(), model_input_sha256=HASH, raw_response_sha256=HASH2,
        source_sha256=HASH3, compiler_version="compiler-v1", compiler_sha256=HASH,
        prepared_diff_sha256=HASH3, legacy_generation_artifact_sha256=old_hash,
    )
    artifact_id = write.record_remediation_attempt_result(r)
    with factory() as session:
        old_row = session.scalar(select(ResultArtifactRow).where(
            ResultArtifactRow.artifact_type == ArtifactType.PATCH_GENERATION_RESULT.value,
        ))
        new_row = session.get(ResultArtifactRow, artifact_id)
        assert old_row.payload_sha256 == old_hash
        assert old_row.payload_json == canonical_model_json(old)
        assert new_row.attempt_number == 1
    with pytest.raises(ResearchStorageError):
        write.record_remediation_attempt_result(r)
    with pytest.raises(ResearchStorageError):
        write.record_remediation_attempt_result(r.model_copy(update={
            "legacy_generation_artifact_sha256": HASH,
        }))


def test_existing_legacy_schema_and_twenty_tables(sandbox):
    assert len(Base.metadata.tables) == 20
    assert "remediation_attempts" not in Base.metadata.tables
    assert "remediation" not in PatchGenerationResult.model_fields
    assert "remediation" not in PatchProposal.model_fields
    assert "remediation" not in PreparedPatch.model_fields
    # Serialize and round-trip an unmodified legacy shape from the existing schema.
    keys = set(PatchGenerationResult.model_fields)
    assert keys == {"run_id", "target_id", "attempt_number", "proposal", "prepared_patch", "final_state"}


def test_rq1_new_terminal_path_does_not_bypass_final_freeze(sandbox):
    write, read, _, policy, audit, _, _ = sandbox
    monitoring, analysis = create_run(write, "final-guard", benign=True)
    runner = RQ1ExperimentRunner(
        target_registry=policy.registry, policy_engine=policy, provider=object(),
        audit_service=audit, project_root=ROOT,
        patch_branch_flow=object(), verification_pipeline=object(),
        read_repository=read, write_repository=write,
    )
    original = runner._stored_configuration("final-guard")
    runner._stored_configuration = lambda _run_id: original.model_copy(
        update={"run_type": RunType.FINAL_EVALUATION}
    )
    with pytest.raises(RQ1RunnerError, match="final RQ1 no-patch"):
        runner.complete_without_patch(
            run_id="final-guard", monitoring=monitoring, analysis=analysis,
            remediation=outcome("final-guard", RemediationDisposition.NO_ACTION),
        )
    assert audit.read_run(run_id="final-guard") == ()


def test_rq1_compatibility_entrypoint_without_model_call(sandbox):
    write, read, factory, policy, audit, _, _ = sandbox
    monitoring, analysis = create_run(write, "rq1-bypass", benign=True)
    runner = RQ1ExperimentRunner(
        target_registry=policy.registry, policy_engine=policy, provider=object(),
        audit_service=audit, project_root=ROOT,
        patch_branch_flow=object(), verification_pipeline=object(),
        read_repository=read, write_repository=write,
    )
    result = runner.complete_without_patch(
        run_id="rq1-bypass", monitoring=monitoring, analysis=analysis,
        remediation=outcome("rq1-bypass", RemediationDisposition.NO_ACTION),
    )
    assert isinstance(result, RQ1RemediationExecutionResult)
    assert result.patch_generation is None and result.patch_branch is None and result.verification is None
    assert result.blue_team_mode == BlueTeamMode.SINGLE_AGENT
    with factory() as session:
        assert session.get(ExperimentRunRow, "rq1-bypass").status == RunStatus.COMPLETED.value
    with pytest.raises(RQ1RunnerError):
        RQ1RemediationExecutionResult(
            run_id=result.run_id, blue_team_mode=result.blue_team_mode,
            monitoring=result.monitoring, analysis=result.analysis,
            remediation=result.remediation, patch_generation=object(),
        )
