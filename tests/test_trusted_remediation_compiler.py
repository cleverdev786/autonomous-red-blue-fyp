"""R3 trusted deterministic compiler tests. NO LLM, Docker, Git application, or network."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path

import pytest

from orchestrator.limits import RunLimitTracker
from orchestrator.policy_engine import PolicyEngine
from schemas.blue_team import BlueTeamAnalysisResult, CodeFinding, SourceLineRange, TriageResult
from schemas.common import ClassificationLabel, WorkflowState
from schemas.experiments import ClassificationMode, ExperimentLimits
from services.audit_service import AuditService
from services.target_registry import TargetRegistry
from services.trusted_remediation_compiler import (
    SOURCE, TARGET, EXPECTED_SOURCE_SHA256, TrustedRemediationCompiler,
)

ROOT = Path(__file__).resolve().parents[1]
CLASSES = (
    (ClassificationLabel.SQL_INJECTION, "vulnerable_login", 48),
    (ClassificationLabel.XSS, "vulnerable_search", 84),
    (ClassificationLabel.PATH_TRAVERSAL, "vulnerable_file_read", 104),
)

@pytest.fixture
def lab(tmp_path):
    path=tmp_path/SOURCE
    path.parent.mkdir(parents=True)
    original=(ROOT/SOURCE).read_bytes()
    assert hashlib.sha256(original).hexdigest()==EXPECTED_SOURCE_SHA256
    path.write_bytes(original)
    reg=TargetRegistry.from_directories(
        targets_dir=ROOT/"config/targets",security_tests_dir=ROOT/"config/security_tests")
    policy=PolicyEngine(registry=reg,project_root=tmp_path)
    audit=AuditService(project_root=tmp_path)
    compiler=TrustedRemediationCompiler(project_root=tmp_path,registry=reg,
        policy_engine=policy,audit_service=audit)
    return path,compiler,audit,tmp_path

def blue(cat=ClassificationLabel.SQL_INJECTION, *, name=None, line=None,
         run_id="r3-offline-01", target=TARGET, file=SOURCE,
         suspicious=True, final=WorkflowState.CODE_ANALYSIS, finding=True):
    identity={c:(n,l) for c,n,l in CLASSES}
    fname,lin=identity.get(cat,("unknown",100))
    if name is not None:fname=name
    if line is not None:lin=line
    return BlueTeamAnalysisResult(
       run_id=run_id,target_id=target,classification_mode=ClassificationMode.HYBRID,
       triage=TriageResult(run_id=run_id,is_suspicious=suspicious,
           classification=cat,confidence=0.90,reason="Synthetic bounded Blue fixture."),
       code_finding=CodeFinding(run_id=run_id,file_path=file,function_or_route=fname,
           root_cause="A bounded source finding to validate.",
           supporting_lines=(SourceLineRange(start_line=lin,end_line=lin),),
           confidence=0.90) if finding else None,
       final_state=final,
    )

def run(compiler, analysis, *, tracker=None):
    return compiler.prepare(analysis=analysis,attempt_number=1,
        limits=tracker or RunLimitTracker(ExperimentLimits()))

@pytest.mark.parametrize("category,name,line",CLASSES)
def test_three_positive_source_patterns_build_one_safe_inmemory_patch(
    lab,category,name,line
):
    source,compiler,audit,tmp=lab
    before=source.read_bytes()
    out=run(compiler,blue(category))
    assert out.provenance.status=="prepared",out.provenance.reason_code
    assert out.generation is not None
    assert source.read_bytes()==before
    prepared=out.generation.prepared_patch
    assert prepared.files_changed==1
    assert prepared.files[0].file_path==SOURCE
    assert prepared.files[0].original_sha256==EXPECTED_SOURCE_SHA256
    assert prepared.generated_test_path is None
    assert len(out.generation.proposal.changes) <= 2
    assert all(change.file_path==SOURCE for change in out.generation.proposal.changes)
    assert out.provenance.prepared_diff_sha256==prepared.diff_sha256
    assert out.provenance.proposal_sha256
    assert out.provenance.model_decision_used is False
    assert out.provenance.model_response_sha256 is None
    assert out.provenance.model_input_sha256 is None
    assert out.provenance.source_sha256==EXPECTED_SOURCE_SHA256
    assert out.provenance.compiler_sha256==hashlib.sha256(
      (ROOT/"services/trusted_remediation_compiler.py").read_bytes()).hexdigest()
    assert out.provenance.function_ast_sha256
    result=prepared.files[0].replacement_content
    if category==ClassificationLabel.SQL_INJECTION:
        assert "WHERE username = :username" in result
        assert '"password_hash": password_hash' in result
        assert "f\"WHERE username = '{payload.username}'" not in result
    elif category==ClassificationLabel.XSS:
        assert "from html import escape" in result
        assert "escape(q, quote=False)" in result
    else:
        assert "candidate.relative_to(intended_public_root)" in result
        assert "candidate.relative_to(scenario_root)" not in result
        assert 'detail="Scenario sandbox escape blocked"' in result
    # Provenance can be serialized and hashed without claiming an LLM decision.
    packed=json.dumps(out.provenance.model_dump(mode="json"),sort_keys=True)
    assert "trusted_deterministic_builder" in packed
    assert '"model_decision_used": false' in packed
    assert audit.read_run(run_id="r3-offline-01")

@pytest.mark.parametrize("category,name,line",CLASSES)
def test_current_modified_source_rejected_with_zero_patch(lab,category,name,line):
    path,compiler,audit,tmp=lab
    path.write_bytes(path.read_bytes().replace(b"DELIBERATE VULNERABILITY",b"DELIBERATE MODIFIED"))
    before=path.read_bytes()
    out=run(compiler,blue(category))
    assert out.generation is None
    assert out.provenance.status=="rejected"
    assert out.provenance.reason_code=="source_hash_drift"
    assert out.provenance.prepared_diff_sha256 is None
    assert out.provenance.model_decision_used is False
    assert path.read_bytes()==before

@pytest.mark.parametrize("category,name,line",CLASSES)
def test_mismatched_blue_route_is_denied(lab,category,name,line):
    path,compiler,audit,tmp=lab
    other="vulnerable_file_read" if name!="vulnerable_file_read" else "vulnerable_login"
    out=run(compiler,blue(category,name=other))
    assert out.generation is None
    assert out.provenance.reason_code=="unregistered_blue_class_or_function"

@pytest.mark.parametrize("category,name,line",CLASSES)
def test_missing_supporting_sink_line_denied(lab,category,name,line):
    path,compiler,audit,tmp=lab
    out=run(compiler,blue(category,line=1))
    assert out.generation is None
    assert out.provenance.reason_code=="finding_lines_do_not_cover_sink"

def test_benign_no_finding_is_never_patched(lab):
    path,compiler,audit,tmp=lab
    out=run(compiler,blue(ClassificationLabel.BENIGN,
        suspicious=False,final=WorkflowState.TRIAGE,finding=False))
    assert out.generation is None
    assert out.provenance.reason_code=="non_actionable_blue_state"

def test_wrong_source_path_never_opened(lab):
    path,compiler,audit,tmp=lab
    out=run(compiler,blue(file="dummy_apps/vulnerable_store/app/main.py"))
    assert out.generation is None
    assert out.provenance.reason_code=="source_path_not_supported"

def test_wrong_target_denied(lab):
    path,compiler,audit,tmp=lab
    out=run(compiler,blue(target="other-lab-target"))
    assert out.generation is None
    assert out.provenance.reason_code=="unregistered_target"

def test_wrong_blue_state_denied(lab):
    path,compiler,audit,tmp=lab
    out=run(compiler,blue(final=WorkflowState.TRIAGE))
    assert out.generation is None
    assert out.provenance.reason_code=="non_actionable_blue_state"

def test_source_symlink_rejected(lab):
    path,compiler,audit,tmp=lab
    backup=path.with_suffix(".backup")
    path.rename(backup)
    path.symlink_to(backup)
    out=run(compiler,blue())
    assert out.generation is None
    assert out.provenance.reason_code=="source_not_regular"

def test_compiler_never_uses_llm_provider(lab):
    path,compiler,audit,tmp=lab
    assert not hasattr(compiler,"provider")
    assert not hasattr(compiler,"model")
    assert not hasattr(compiler,"git_service")
    assert not hasattr(compiler,"environment_service")

def test_provenance_rejected_contains_no_fake_model_hashes(lab):
    path,compiler,audit,tmp=lab
    out=run(compiler,blue(name="not_a_registered_route"))
    assert out.generation is None
    assert out.provenance.proposal_sha256 is None
    assert out.provenance.prepared_diff_sha256 is None
    assert out.provenance.model_input_sha256 is None
    assert out.provenance.model_response_sha256 is None

def test_preparation_is_repeatable_without_mutating_input(lab):
    path,compiler,audit,tmp=lab
    orig=path.read_bytes()
    a=run(compiler,blue(run_id="repeat-1"))
    b=run(compiler,blue(run_id="repeat-2"))
    assert a.generation is not None and b.generation is not None
    assert a.generation.prepared_patch.diff_sha256==b.generation.prepared_patch.diff_sha256
    assert path.read_bytes()==orig
