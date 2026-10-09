"""R3 atomic storage and DEVELOPMENT RQ1 adapter tests, isolated SQLite only.

No provider, live Red, Git patch application, Docker, or primary-repo writes.
"""
from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import select, func

from experiments.rq1_trusted_development import TrustedRQ1DevelopmentAdapter, TrustedRQ1DevelopmentBlocked
from orchestrator.limits import RunLimitTracker
from orchestrator.policy_engine import PolicyEngine
from schemas.blue_team import (
    BlueTeamAnalysisResult, CodeFinding, MonitoringResult, SourceLineRange, TriageResult,
)
from schemas.common import ClassificationLabel, ResearchQuestion, RunStatus, RunType, VulnerabilityClass, WorkflowState
from schemas.experiment_results import ArtifactType
from schemas.experiments import BlueTeamMode, ClassificationMode, ExperimentConfiguration, ModelConfiguration
from schemas.red_team import (
    AttackPlan, AttackVerification, EvidenceItem, ReconnaissanceResult,
    RedTeamRunResult, TestExecutionResult as RedTestExecutionResult,
)
from schemas.trusted_compilation import TrustedCompilerStoredOutcome
from services.audit_service import AuditService
from services.target_registry import TargetRegistry
from services.trusted_remediation_compiler import TrustedRemediationCompiler, SOURCE, EXPECTED_SOURCE_SHA256
from storage.database import create_database_engine, initialize_database, make_session_factory
from storage.models import Base, ExperimentRunRow, PatchAttemptRow, ResultArtifactRow
from storage.repositories import ExperimentWriteRepository, ResearchReadRepository, ResearchStorageError
from storage.trusted_compilation_repository import TrustedCompilationWriteRepository

REPO=Path(__file__).resolve().parents[1]
CHOICES=[
  (ClassificationLabel.SQL_INJECTION,"vulnerable_login",48,"sqli-login-bypass-001","scenario-sqli-login"),
  (ClassificationLabel.XSS,"vulnerable_search",84,"xss-reflection-001","scenario-xss-search"),
  (ClassificationLabel.PATH_TRAVERSAL,"vulnerable_file_read",104,
   "path-traversal-private-file-001","scenario-path-traversal-read"),
]


@pytest.fixture
def setup(tmp_path):
    source=tmp_path/SOURCE
    source.parent.mkdir(parents=True)
    shutil.copyfile(REPO/SOURCE,source)
    assert hashlib.sha256(source.read_bytes()).hexdigest()==EXPECTED_SOURCE_SHA256
    engine=create_database_engine(f"sqlite:///{tmp_path/'lab.db'}", project_root=tmp_path)
    initialize_database(engine)
    session_factory=make_session_factory(engine)
    registry=TargetRegistry.from_directories(
       targets_dir=REPO/"config/targets",security_tests_dir=REPO/"config/security_tests")
    policy=PolicyEngine(registry=registry,project_root=tmp_path)
    audit=AuditService(project_root=tmp_path)
    compiler=TrustedRemediationCompiler(
        project_root=tmp_path,registry=registry,policy_engine=policy,audit_service=audit)
    writer=TrustedCompilationWriteRepository(session_factory,project_root=tmp_path)
    legacy=ExperimentWriteRepository(session_factory)
    read=ResearchReadRepository(session_factory)
    adapter=TrustedRQ1DevelopmentAdapter(
        read_repository=read,write_repository=writer,
        compiler=compiler,policy_engine=policy,audit_service=audit)
    yield dict(root=tmp_path,source=source,engine=engine,factory=session_factory,
               compiler=compiler,writer=writer,legacy=legacy,reader=read,
               adapter=adapter,audit=audit,policy=policy)
    engine.dispose()


def create_blue(run_id, choice=CHOICES[0], *, mismatch=False, benign=False, wrong_line=False):
    cls,route,line,*_=choice
    if benign:
        cls=ClassificationLabel.BENIGN
    if mismatch:
        route="unsupported_function"
    finding=(None if benign else CodeFinding(
        run_id=run_id,file_path=SOURCE,function_or_route=route,
        root_cause="Synthetic offline localized finding.",
        supporting_lines=(SourceLineRange(start_line=(1 if wrong_line else line),
                                           end_line=(1 if wrong_line else line)),),
        confidence=1.0))
    return BlueTeamAnalysisResult(
        run_id=run_id,target_id="vulnerable-store",
        classification_mode=ClassificationMode.HYBRID,
        triage=TriageResult(run_id=run_id,is_suspicious=not benign,
            classification=cls,confidence=1.0,reason="Synthetic offline observation."),
        code_finding=finding,
        final_state=(WorkflowState.TRIAGE if benign else WorkflowState.CODE_ANALYSIS))


def create_red(run_id, choice=CHOICES[0]):
    cls,route,line,test_id,endpoint_id=choice
    evidence=EvidenceItem(evidence_id=f"test-evidence-{run_id}",
        evidence_type="registered-test",summary="Synthetic offline Red verification fixture.")
    return RedTeamRunResult(
        run_id=run_id,target_id="vulnerable-store",attempt_number=1,
        reconnaissance=ReconnaissanceResult(target_id="vulnerable-store",
            candidate_endpoints=(),rationale="Synthetic offline reconnaissance."),
        attack_plan=AttackPlan(target_id="vulnerable-store",test_id=test_id,
            endpoint_id=endpoint_id,vulnerability_class=VulnerabilityClass(cls.value),
            rationale="Registered local test fixture."),
        execution=RedTestExecutionResult(
            run_id=run_id,target_id="vulnerable-store",test_id=test_id,
            attempt_number=1,request_count=1,completed=True,status_code=200,
            evidence=(evidence,),duration_ms=5),
        verification=AttackVerification(
            target_id="vulnerable-store",test_id=test_id,confirmed=True,
            confidence=1.0,evidence_ids=(evidence.evidence_id,),
            reason="Confirmed synthetic Red fixture."),
        final_state=WorkflowState.BLUE_MONITORING,
    )


def seed(setup, *, run_id="r3-run", mode=BlueTeamMode.SINGLE_AGENT,
         choice=CHOICES[0], mismatch=False, benign=False, wrong_line=False,
         recorded_red=True, recorded_blue=True):
    scenario_by_class={
        ClassificationLabel.SQL_INJECTION:"sqli-login-001",
        ClassificationLabel.XSS:"xss-search-001",
        ClassificationLabel.PATH_TRAVERSAL:"path-traversal-read-001",
    }
    scenario_id=scenario_by_class[choice[0]]
    cfg=ExperimentConfiguration(
        config_id=f"cfg-{run_id}",run_type=RunType.DEVELOPMENT,
        research_question=ResearchQuestion.RQ1,scenario_ids=(scenario_id,),
        blue_team_mode=mode,classification_mode=ClassificationMode.HYBRID,
        model=ModelConfiguration(provider="mock",model_name="synthetic-offline"))
    setup["writer"].create_configuration(cfg)
    setup["writer"].create_run(
        run_id=run_id,config_id=cfg.config_id,repetition_index=1,
        baseline_commit="a"*40,scenario_id=scenario_id)
    setup["writer"].mark_running(run_id)
    monitoring=MonitoringResult(run_id=run_id,summary="Already recorded synthetic monitoring.")
    analysis=create_blue(run_id,choice,mismatch=mismatch,benign=benign,wrong_line=wrong_line)
    red=create_red(run_id,choice)
    setup["writer"].record_monitoring_result(monitoring)
    if recorded_blue:setup["writer"].record_blue_result(analysis)
    if recorded_red:setup["writer"].record_red_result(red)
    return cfg,monitoring,analysis,red


def counts(setup,run_id):
    with setup["factory"]() as session:
        artifacts=list(session.scalars(select(ResultArtifactRow).where(ResultArtifactRow.run_id==run_id)))
        attempts=list(session.scalars(select(PatchAttemptRow).where(PatchAttemptRow.run_id==run_id)))
        run=session.get(ExperimentRunRow,run_id)
        return artifacts,attempts,run.status,run.system_error_code


@pytest.mark.parametrize("choice",CHOICES)
@pytest.mark.parametrize("mode",[BlueTeamMode.SINGLE_AGENT,BlueTeamMode.MULTI_AGENT])
def test_three_prepared_persist_atomically_and_stay_unverified(setup,choice,mode):
    run_id=f"prepared-{choice[0].value}-{mode.value}"
    cfg,monitoring,analysis,red=seed(setup,run_id=run_id,choice=choice,mode=mode)
    before=setup["source"].read_bytes()
    result=setup["adapter"].run_recorded(run_id=run_id,monitoring=monitoring,
        analysis=analysis,red_run=red,attempt_number=1,
        limits=RunLimitTracker(cfg.limits))
    assert result.status=="prepared_unverified"
    assert result.accepted is False
    assert result.compiler_receipt is not None
    assert result.compiler_receipt.status=="prepared"
    assert result.compiler_receipt.accepted is False
    assert result.prepared_diff_sha256
    art,attempts,status,code=counts(setup,run_id)
    assert status==RunStatus.RUNNING.value
    assert len(attempts)==1
    assert len([a for a in art if a.artifact_type==ArtifactType.TRUSTED_COMPILER_OUTCOME.value])==1
    assert len([a for a in art if a.artifact_type==ArtifactType.PATCH_GENERATION_RESULT.value])==1
    gen=next(a for a in art if a.artifact_type==ArtifactType.PATCH_GENERATION_RESULT.value)
    prov=next(a for a in art if a.artifact_type==ArtifactType.TRUSTED_COMPILER_OUTCOME.value)
    payload=TrustedCompilerStoredOutcome.model_validate_json(prov.payload_json)
    assert payload.generation_artifact_sha256==gen.payload_sha256
    assert payload.prepared_diff_sha256==result.prepared_diff_sha256
    assert payload.model_decision_used is False
    assert payload.model_input_sha256 is None and payload.model_response_sha256 is None
    assert prov.schema_version=="r3-deterministic-v1"
    assert gen.schema_version=="1.0"
    assert result.compiler_receipt.generation_artifact_id==gen.artifact_id
    assert result.compiler_receipt.provenance_artifact_id==prov.artifact_id
    assert attempts[0].prepared_patch_artifact_id==gen.artifact_id
    assert setup["source"].read_bytes()==before
    assert all(a.artifact_type not in (
        ArtifactType.PATCH_BRANCH_RESULT.value,ArtifactType.PATCH_VERIFICATION_RESULT.value,
        ArtifactType.REMEDIATION_ATTEMPT_RESULT.value) for a in art)


@pytest.mark.parametrize("choice",CHOICES)
def test_wrong_blue_route_rejected_with_no_patch_and_terminal_denominator(setup,choice):
    run_id="rejected-"+choice[0].value
    cfg,monitoring,analysis,red=seed(setup,run_id=run_id,choice=choice,mismatch=True)
    result=setup["adapter"].run_recorded(run_id=run_id,monitoring=monitoring,
        analysis=analysis,red_run=red,attempt_number=1,
        limits=RunLimitTracker(cfg.limits))
    assert result.status=="rejected"
    assert result.accepted is False
    assert result.prepared_diff_sha256 is None
    artifacts,attempts,status,code=counts(setup,run_id)
    assert not attempts
    assert status==RunStatus.COMPLETED.value and code=="trusted_compiler_rejected"
    assert len([a for a in artifacts if a.artifact_type==ArtifactType.TRUSTED_COMPILER_OUTCOME.value])==1
    assert not [a for a in artifacts if a.artifact_type in (
        ArtifactType.PATCH_GENERATION_RESULT.value,ArtifactType.PATCH_BRANCH_RESULT.value,
        ArtifactType.PATCH_VERIFICATION_RESULT.value)]
    prov=next(a for a in artifacts if a.artifact_type==ArtifactType.TRUSTED_COMPILER_OUTCOME.value)
    parsed=TrustedCompilerStoredOutcome.model_validate_json(prov.payload_json)
    assert parsed.status=="rejected"
    assert parsed.prepared_diff_sha256 is None and parsed.generation_artifact_sha256 is None


def test_benign_uses_legacy_trusted_no_patch_and_not_compiler(setup):
    cfg,monitoring,analysis,red=seed(setup,run_id="benign",benign=True)
    result=setup["adapter"].run_recorded(run_id="benign",monitoring=monitoring,
        analysis=analysis,red_run=red,attempt_number=1,limits=RunLimitTracker(cfg.limits))
    assert result.status=="no_action" and result.compiler_receipt is None
    art,attempts,status,_=counts(setup,"benign")
    assert not attempts and status==RunStatus.COMPLETED.value
    assert not any(a.artifact_type==ArtifactType.TRUSTED_COMPILER_OUTCOME.value for a in art)


def test_duplicate_prepared_attempt_rejected_before_writing_more(setup):
    cfg,monitoring,analysis,red=seed(setup,run_id="dup")
    args=dict(run_id="dup",monitoring=monitoring,analysis=analysis,
        red_run=red,attempt_number=1,limits=RunLimitTracker(cfg.limits))
    setup["adapter"].run_recorded(**args)
    before=counts(setup,"dup")
    with pytest.raises(ResearchStorageError,match="duplicate|already recorded"):
        setup["adapter"].run_recorded(**args)
    after=counts(setup,"dup")
    assert len(before[0])==len(after[0]) and len(before[1])==len(after[1])


def test_duplicate_rejected_attempt_blocked(setup):
    cfg,monitoring,analysis,red=seed(setup,run_id="dup-reject",mismatch=True)
    args=dict(run_id="dup-reject",monitoring=monitoring,analysis=analysis,
        red_run=red,attempt_number=1,limits=RunLimitTracker(cfg.limits))
    setup["adapter"].run_recorded(**args)
    before=counts(setup,"dup-reject")
    with pytest.raises((ResearchStorageError,TrustedRQ1DevelopmentBlocked)):
        setup["adapter"].run_recorded(**args)
    after=counts(setup,"dup-reject")
    assert len(before[0])==len(after[0])


@pytest.mark.parametrize("rejected",[False,True])
def test_transaction_failure_rolls_back_artifacts_and_state(setup,rejected,monkeypatch):
    cfg,monitoring,analysis,red=seed(setup,run_id="rollback-"+str(rejected),mismatch=rejected)
    before=counts(setup,analysis.run_id)
    def fail(session):raise RuntimeError("forced failure after flush")
    monkeypatch.setattr(setup["writer"],"_before_commit",fail)
    with pytest.raises(RuntimeError,match="forced failure"):
        setup["adapter"].run_recorded(run_id=analysis.run_id,monitoring=monitoring,
            analysis=analysis,red_run=red,attempt_number=1,limits=RunLimitTracker(cfg.limits))
    after=counts(setup,analysis.run_id)
    assert len(after[0])==len(before[0]) and len(after[1])==len(before[1])
    assert after[2]==RunStatus.RUNNING.value
    assert after[3] is None


def test_no_written_blue_artifact_denied(setup):
    cfg,monitoring,analysis,red=seed(setup,run_id="missing-blue",recorded_blue=False)
    before=counts(setup,"missing-blue")
    with pytest.raises(TrustedRQ1DevelopmentBlocked,match="missing or changed"):
        setup["adapter"].run_recorded(run_id="missing-blue",monitoring=monitoring,
            analysis=analysis,red_run=red,attempt_number=1,limits=RunLimitTracker(cfg.limits))
    after=counts(setup,"missing-blue")
    assert len(before[0])==len(after[0])


def test_no_written_red_artifact_denied(setup):
    cfg,monitoring,analysis,red=seed(setup,run_id="missing-red",recorded_red=False)
    with pytest.raises(TrustedRQ1DevelopmentBlocked,match="missing or changed"):
        setup["adapter"].run_recorded(run_id="missing-red",monitoring=monitoring,
            analysis=analysis,red_run=red,attempt_number=1,limits=RunLimitTracker(cfg.limits))


def test_final_configuration_denied_before_compiler(setup):
    cfg,monitoring,analysis,red=seed(setup,run_id="fake-final")
    from storage.models import ExperimentConfigurationRow
    with setup["factory"]() as s:
        x=s.get(ExperimentConfigurationRow,cfg.config_id)
        x.run_type=RunType.FINAL_EVALUATION.value
        x.configuration_json=json.dumps({**cfg.model_dump(mode="json"),"run_type":"final_evaluation"})
        s.commit()
    with pytest.raises(TrustedRQ1DevelopmentBlocked,match="FINAL_EVALUATION"):
        setup["adapter"].run_recorded(run_id="fake-final",monitoring=monitoring,
            analysis=analysis,red_run=red,attempt_number=1,limits=RunLimitTracker(cfg.limits))


def test_trusted_model_hash_forgery_rejected_in_schema():
    with pytest.raises(ValidationError):
        TrustedCompilerStoredOutcome.model_validate(dict(
            schema_version="r3-deterministic-v1",run_id="forgery",target_id="vulnerable-store",
            attempt_number=1,status="rejected",reason_code="untrusted",
            blue_analysis_sha256="a"*64,compiler_version="known",compiler_sha256="a"*64,
            model_response_sha256="b"*64))
    with pytest.raises(ValidationError):
        TrustedCompilerStoredOutcome.model_validate(dict(
            schema_version="r3-deterministic-v1",run_id="forgery",target_id="vulnerable-store",
            attempt_number=1,status="prepared",reason_code="prepared",
            blue_analysis_sha256="a"*64,compiler_version="known",compiler_sha256="a"*64))


def test_no_new_sqlalchemy_tables_and_legacy_registry_same(setup):
    assert len(Base.metadata.tables)==20
    assert ArtifactType.TRUSTED_COMPILER_OUTCOME.value=="trusted_compiler_outcome"
    legacy=[x for x in ArtifactType if x!=ArtifactType.TRUSTED_COMPILER_OUTCOME]
    assert len(legacy)==12


def test_red_test_must_match_configured_scenario(setup):
    cfg,monitoring,analysis,red=seed(setup,run_id="cross-scenario")
    mismatch_red=create_red("cross-scenario",CHOICES[1])
    with pytest.raises(TrustedRQ1DevelopmentBlocked,match="configured scenario"):
        setup["adapter"].run_recorded(
            run_id="cross-scenario",monitoring=monitoring,
            analysis=analysis,red_run=mismatch_red,attempt_number=1,
            limits=RunLimitTracker(cfg.limits))
    artifacts,attempts,status,_=counts(setup,"cross-scenario")
    assert not attempts and status==RunStatus.RUNNING.value


def test_forged_replacement_cannot_be_persisted_as_deterministic(setup):
    from dataclasses import replace
    cfg,monitoring,analysis,red=seed(setup,run_id="forged-patch")
    real=setup["compiler"].prepare(
        analysis=analysis,attempt_number=1,
        limits=RunLimitTracker(cfg.limits))
    assert real.generation is not None
    forged_file=real.generation.prepared_patch.files[0].model_copy(
        update={"replacement_content":"def silently_wrong():\n    pass\n"})
    forged_prepared=real.generation.prepared_patch.model_copy(update={"files":(forged_file,)})
    forged_generation=real.generation.model_copy(update={"prepared_patch":forged_prepared})
    forged=replace(real,generation=forged_generation)
    with pytest.raises(ResearchStorageError,match="fixed trusted output"):
        setup["writer"].persist(outcome=forged,analysis=analysis)
    artifacts,attempts,status,_=counts(setup,"forged-patch")
    assert not attempts and status==RunStatus.RUNNING.value
    assert not any(a.artifact_type==ArtifactType.TRUSTED_COMPILER_OUTCOME.value for a in artifacts)


def test_forged_compiler_identity_cannot_be_persisted(setup):
    from dataclasses import replace
    cfg,monitoring,analysis,red=seed(setup,run_id="forged-compiler")
    real=setup["compiler"].prepare(
        analysis=analysis,attempt_number=1,
        limits=RunLimitTracker(cfg.limits))
    forged=replace(real,provenance=real.provenance.model_copy(
        update={"compiler_sha256":"b"*64}))
    with pytest.raises(ResearchStorageError,match="compiler module identity mismatch"):
        setup["writer"].persist(outcome=forged,analysis=analysis)
    artifacts,attempts,status,_=counts(setup,"forged-compiler")
    assert not attempts and status==RunStatus.RUNNING.value


def test_writer_standalone_does_not_trust_missing_recorded_blue(setup):
    cfg,monitoring,analysis,red=seed(
        setup,run_id="unrecorded-blue",recorded_blue=False)
    result=setup["compiler"].prepare(
        analysis=analysis,attempt_number=1,
        limits=RunLimitTracker(cfg.limits))
    with pytest.raises(ResearchStorageError,match="recorded Blue analysis"):
        setup["writer"].persist(outcome=result,analysis=analysis)
    artifacts,attempts,status,_=counts(setup,"unrecorded-blue")
    assert not attempts and status==RunStatus.RUNNING.value
