"""R4-A offline-only readiness, registered Red observation and prepared artifact tests.

No live Docker, HTTP, model inference, Git patches, or commits.
"""
from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from schemas.red_team import HttpExchangeEvidence, TestExecutionResult as RegisteredExecutionResult
from schemas.r4a_red_observation import (
    DeterministicRedObservation, DeterministicRedEvidenceError,
    observe_registered_result, REGISTERED,
)
from security_tests.registry import SecurityTestRegistry
from services.r4a_static_preflight import (
    R4AStaticPlan, R4AStaticReadiness, inspect_static_plan,
)
from services.target_registry import TargetRegistry
from services.trusted_remediation_compiler import SOURCE, EXPECTED_SOURCE_SHA256
from storage.models import ResultArtifactRow, PatchAttemptRow
from storage.trusted_prepared_loader import (
    TrustedPreparedReadRepository, TrustedPreparedLoadBlocked,
)
from storage.repositories import canonical_sha256

# Reuse an existing disposable SQLite fixture; all its databases are tmp-local.
from test_r3_trusted_storage_and_rq1_adapter import setup, seed, counts, CHOICES
from orchestrator.limits import RunLimitTracker

REPO=Path(__file__).resolve().parents[1]


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def observed_fixture(scenario, phase, *, compromised=None, missing=False):
    test_id,endpoint,cls=REGISTERED[scenario]
    registry=SecurityTestRegistry.default()
    definition=registry.get(test_id)
    steps=definition.build_steps()
    if compromised is None:
        compromised=(phase=="vulnerable_baseline")
    if scenario=="sqli-login-001":
        codes=(401,200 if compromised else 401)
        excerpts=("Invalid credentials",'{"authenticated":true}' if compromised else "Invalid credentials")
    elif scenario=="xss-search-001":
        codes=(200,200)
        excerpts=("<p>Search term: notebook</p>", "<p><script>fyp_xss_marker()</script></p>" if compromised else "&lt;script&gt;fyp_xss_marker()&lt;/script&gt;")
    else:
        codes=(200,200 if compromised else 403)
        excerpts=("Public scenario guide", "FYP_SCENARIO_SECRET=synthetic-traversal-evidence-only" if compromised else "Scenario sandbox escape blocked")
    exchanges=tuple(
        HttpExchangeEvidence(exchange_id=f"ex-{i}",request_id=f"req-{i}",
            step_id=step.step_id,endpoint_id=endpoint,method=step.method.value,
            status_code=codes[i],body_excerpt=excerpts[i],duration_ms=2)
        for i,step in enumerate(steps))
    evidence=definition.evaluate(exchanges)
    if missing:
        exchanges=exchanges[:1]
        evidence=()
    result=RegisteredExecutionResult(
        run_id="offline-r4a-test",target_id="vulnerable-store",test_id=test_id,
        attempt_number=1,request_count=len(exchanges),completed=not missing,
        timed_out=False,status_code=exchanges[-1].status_code,evidence=evidence,
        exchanges=exchanges,duration_ms=10,
        error_code=("incomplete-test" if missing else
                    ("evidence-not-observed" if not evidence else None)))
    return result


def observe(scenario, phase, *, result=None, scope="offline_fixture", session_sha=None):
    test_id=REGISTERED[scenario][0]
    value=result if result is not None else observed_fixture(scenario,phase)
    raw=value.model_dump_json().encode()
    registry=TargetRegistry.from_directories(
        targets_dir=REPO/"config/targets",security_tests_dir=REPO/"config/security_tests")
    return observe_registered_result(
        raw_result=raw,scenario_id=scenario,phase=phase,
        source_sha256=EXPECTED_SOURCE_SHA256,
        policy_config_sha256=sha(REPO/"config/security_tests"/(test_id+".json")),
        test_implementation_sha256=sha(REPO/{
            "sqli-login-bypass-001":"security_tests/sql_injection/login_bypass.py",
            "xss-reflection-001":"security_tests/xss/reflection.py",
            "path-traversal-private-file-001":"security_tests/path_traversal/private_file.py",
        }[test_id]),
        evidence_scope=scope,docker_session_evidence_sha256=session_sha,
        registry=registry,implementations=SecurityTestRegistry.default())


@pytest.mark.parametrize("scenario",list(REGISTERED))
def test_fixture_registered_baseline_provenance_is_not_agent_red(scenario):
    x=observe(scenario,"vulnerable_baseline")
    assert x.test_completed and x.exploit_confirmed is True
    assert x.evidence_scope=="offline_fixture"
    assert x.agent_red_plan_authored is False and x.agent_model_calls==0
    assert x.research_final_result is False
    assert x.docker_session_evidence_sha256 is None


@pytest.mark.parametrize("scenario",list(REGISTERED))
def test_fixture_patched_replay_provenance_is_not_a_security_success_claim(scenario):
    x=observe(scenario,"patched_replay")
    assert x.test_completed and x.exploit_confirmed is False
    assert x.agent_red_plan_authored is False
    assert x.research_final_result is False
    assert x.execution.evidence==()


def test_incomplete_test_cannot_be_marked_safe():
    x=observe("xss-search-001","patched_replay",
              result=observed_fixture("xss-search-001","patched_replay",missing=True))
    assert x.evaluation_status=="inconclusive"
    assert x.exploit_confirmed is None
    assert not x.test_completed


def test_forged_attack_evidence_denied():
    bad=observed_fixture("sqli-login-001","vulnerable_baseline")
    bad=bad.model_copy(update={"evidence":()})
    with pytest.raises(DeterministicRedEvidenceError,match="deterministic evaluator"):
        observe("sqli-login-001","vulnerable_baseline",result=bad)


def test_forged_no_exploit_denied():
    bad=observed_fixture("xss-search-001","vulnerable_baseline")
    bad=bad.model_copy(update={"exchanges":(
        bad.exchanges[0],
        bad.exchanges[1].model_copy(update={"body_excerpt":"safe"}),
    )})
    with pytest.raises(DeterministicRedEvidenceError,match="deterministic evaluator"):
        observe("xss-search-001","vulnerable_baseline",result=bad)


def test_wrong_steps_denied():
    bad=observed_fixture("path-traversal-read-001","vulnerable_baseline")
    bad=bad.model_copy(update={"exchanges":(
        bad.exchanges[0].model_copy(update={"step_id":"other"}),bad.exchanges[1])})
    with pytest.raises(DeterministicRedEvidenceError,match="step/endpoint/method"):
        observe("path-traversal-read-001","vulnerable_baseline",result=bad)


def test_scope_cannot_be_upgraded_with_live_claim_without_receipt():
    with pytest.raises(ValidationError,match="live reports require"):
        DeterministicRedObservation.model_validate({
            **observe("sqli-login-001","vulnerable_baseline").model_dump(mode="json"),
            "evidence_scope":"reported_controlled_executor"})
    with pytest.raises(ValidationError,match="offline fixtures"):
        DeterministicRedObservation.model_validate({
            **observe("sqli-login-001","vulnerable_baseline").model_dump(mode="json"),
            "docker_session_evidence_sha256":"a"*64})


def test_runtime_receipt_is_claim_not_attestation():
    # The payload may be *reported*, but never declares it authenticated.
    item=observe("sqli-login-001","vulnerable_baseline",
                 scope="reported_controlled_executor",session_sha="b"*64)
    assert item.evidence_scope=="reported_controlled_executor"
    assert item.research_final_result is False


def test_tampered_completion_status_denied():
    bad=observed_fixture("sqli-login-001","vulnerable_baseline")
    bad=bad.model_copy(update={"status_code":401})
    with pytest.raises(DeterministicRedEvidenceError,match="last status"):
        observe("sqli-login-001","vulnerable_baseline",result=bad)


def test_live_attribution_cannot_override_literal_no_agent_fields():
    data=observe("sqli-login-001","vulnerable_baseline").model_dump(mode="json")
    data["agent_red_plan_authored"]=True
    with pytest.raises(ValidationError):
        DeterministicRedObservation.model_validate(data)
    data["agent_red_plan_authored"]=False
    data["research_final_result"]=True
    with pytest.raises(ValidationError):
        DeterministicRedObservation.model_validate(data)


def test_registered_test_policy_hash_denied():
    test_id="sqli-login-bypass-001"
    registry=TargetRegistry.from_directories(
       targets_dir=REPO/"config/targets",security_tests_dir=REPO/"config/security_tests")
    with pytest.raises(DeterministicRedEvidenceError,match="policy hash"):
        observe_registered_result(
            raw_result=observed_fixture("sqli-login-001","vulnerable_baseline").model_dump_json().encode(),
            scenario_id="sqli-login-001",phase="vulnerable_baseline",
            source_sha256=EXPECTED_SOURCE_SHA256,policy_config_sha256="f"*64,
            test_implementation_sha256="0"*64,
            registry=registry,implementations=SecurityTestRegistry.default())


def fresh_loader(setup, *, choice=CHOICES[0], run_id="load-prepared"):
    cfg,monitoring,analysis,red=seed(setup,run_id=run_id,choice=choice)
    outcome=setup["compiler"].prepare(
        analysis=analysis,attempt_number=1,limits=RunLimitTracker(cfg.limits))
    assert outcome.generation is not None
    receipt=setup["writer"].persist(outcome=outcome,analysis=analysis)
    loader=TrustedPreparedReadRepository(
        setup["factory"],project_root=setup["root"])
    return loader,receipt


@pytest.mark.parametrize("choice",CHOICES)
def test_loaded_persisted_generation_hash_matches_both_artifacts_and_source(setup,choice):
    loader,receipt=fresh_loader(setup,choice=choice,run_id="load-"+choice[0].value)
    before=setup["source"].read_bytes()
    item=loader.load(run_id=receipt.run_id,attempt_number=1,
                     expected_baseline_commit="a"*40)
    assert item.accepted is False
    assert item.generation_artifact_id==receipt.generation_artifact_id
    assert item.provenance_artifact_id==receipt.provenance_artifact_id
    assert item.baseline_commit=="a"*40
    assert item.generation.prepared_patch.diff_sha256==item.provenance.prepared_diff_sha256
    assert item.provenance.model_decision_used is False
    assert setup["source"].read_bytes()==before


def test_tampered_generation_row_denied_even_if_hash_recalculated(setup):
    loader,receipt=fresh_loader(setup)
    with setup["factory"]() as s:
        x=s.get(ResultArtifactRow,receipt.generation_artifact_id)
        v=json.loads(x.payload_json)
        v["proposal"]["security_rationale"]="FORGED LLM PLAN"
        x.payload_json=json.dumps(v,sort_keys=True,separators=(",",":"))
        x.payload_sha256=canonical_sha256(x.payload_json)
        s.commit()
    with pytest.raises(TrustedPreparedLoadBlocked):
        loader.load(run_id=receipt.run_id,attempt_number=1)


def test_tampered_compiler_provenance_denied_even_if_rehashed(setup):
    loader,receipt=fresh_loader(setup)
    with setup["factory"]() as s:
        x=s.get(ResultArtifactRow,receipt.provenance_artifact_id)
        v=json.loads(x.payload_json)
        v["compiler_sha256"]="b"*64
        x.payload_json=json.dumps(v,sort_keys=True,separators=(",",":"))
        x.payload_sha256=canonical_sha256(x.payload_json)
        s.commit()
    with pytest.raises(TrustedPreparedLoadBlocked):
        loader.load(run_id=receipt.run_id,attempt_number=1)


def test_tampered_source_after_storage_denied(setup):
    loader,receipt=fresh_loader(setup)
    setup["source"].write_text("A different source text")
    with pytest.raises(TrustedPreparedLoadBlocked):
        loader.load(run_id=receipt.run_id,attempt_number=1)


def test_unverified_loader_denies_already_attached_branch(setup):
    loader,receipt=fresh_loader(setup)
    with setup["factory"]() as s:
        patch=s.scalars(select(PatchAttemptRow).where(
            PatchAttemptRow.run_id==receipt.run_id)).one()
        patch.branch_name="agent-patch-unexpected"
        s.commit()
    with pytest.raises(TrustedPreparedLoadBlocked,match="unverified"):
        loader.load(run_id=receipt.run_id,attempt_number=1)


def test_wrong_expected_baseline_denied(setup):
    loader,receipt=fresh_loader(setup)
    with pytest.raises(TrustedPreparedLoadBlocked,match="baseline SHA"):
        loader.load(run_id=receipt.run_id,attempt_number=1,
                    expected_baseline_commit="f"*40)


def test_rejected_compiler_cannot_load_prepared(setup):
    cfg,monitoring,analysis,red=seed(setup,run_id="rejected-loader",mismatch=True)
    outcome=setup["compiler"].prepare(
        analysis=analysis,attempt_number=1,limits=RunLimitTracker(cfg.limits))
    setup["writer"].persist(outcome=outcome,analysis=analysis)
    loader=TrustedPreparedReadRepository(setup["factory"],project_root=setup["root"])
    with pytest.raises(TrustedPreparedLoadBlocked):
        loader.load(run_id="rejected-loader",attempt_number=1)


@pytest.fixture
def static_environment(tmp_path):
    source=tmp_path/"sandbox"/SOURCE
    source.parent.mkdir(parents=True)
    shutil.copyfile(REPO/SOURCE,source)
    shutil.copyfile(REPO/"compose.yaml",tmp_path/"sandbox/compose.yaml")
    config=tmp_path/"sandbox/config"
    config.mkdir(parents=True)
    shutil.copyfile(REPO/"config/git-policy.json",config/"git-policy.json")
    primary=tmp_path/"primary"
    primary.mkdir()
    return R4AStaticPlan(primary_root=primary,sandbox_root=tmp_path/"sandbox",
                         proposed_checkout_path=tmp_path/"fresh-r4-clone",
                         approved_integration_commit=None)


def test_static_preflight_marks_live_blocked_without_approved_commit(static_environment):
    x=inspect_static_plan(static_environment)
    assert not x.passed_static_checks and not x.ready_for_live
    assert "separately approved immutable integration commit missing" in x.reasons
    assert not x.docker_invoked and not x.git_clone_created
    assert x.docker_ownership_verified is False


def test_static_preflight_never_grants_live_even_with_placeholder_commit(static_environment):
    from dataclasses import replace
    x=inspect_static_plan(replace(static_environment,
          approved_integration_commit="b"*40))
    assert x.passed_static_checks
    assert not x.ready_for_live
    assert "exclusive Docker daemon/resource ownership NOT verified" in x.reasons


def test_static_preflight_rejects_overlapping_and_existing_path(static_environment):
    from dataclasses import replace
    inside=static_environment.primary_root/"evil"
    x=inspect_static_plan(replace(static_environment,
        proposed_checkout_path=inside,approved_integration_commit="a"*40))
    assert not x.passed_static_checks
    assert any("overlaps" in r for r in x.reasons)
    existing=static_environment.sandbox_root
    x2=inspect_static_plan(replace(static_environment,
        proposed_checkout_path=existing,approved_integration_commit="a"*40))
    assert not x2.passed_static_checks
    assert any("already exists" in r for r in x2.reasons)


def test_static_preflight_rejects_modified_compose_without_invocation(static_environment):
    from dataclasses import replace
    p=static_environment.sandbox_root/"compose.yaml"
    p.write_text(p.read_text().replace("internal: true","internal: false"))
    x=inspect_static_plan(replace(static_environment,
        approved_integration_commit="c"*40))
    assert not x.passed_static_checks
    assert not x.docker_invoked
    assert any("internal network changed" in r for r in x.reasons)


def test_static_preflight_rejects_drifted_target_and_git_policy(static_environment):
    from dataclasses import replace
    src=static_environment.sandbox_root/SOURCE
    src.write_bytes(b"broken")
    g=static_environment.sandbox_root/"config/git-policy.json"
    g.write_text('{"baseline_branch":"other"}')
    x=inspect_static_plan(replace(static_environment,
        approved_integration_commit="c"*40))
    assert not x.passed_static_checks
    assert any("source changed" in r for r in x.reasons)
    assert any("Git branch policy changed" in r for r in x.reasons)

def test_compose_comment_cannot_spoof_runtime_isolation(static_environment):
    from dataclasses import replace
    p=static_environment.sandbox_root/"compose.yaml"
    p.write_text(p.read_text().replace(
        "internal: true", "internal: false # internal: true"))
    result=inspect_static_plan(replace(
        static_environment,approved_integration_commit="c"*40))
    assert not result.passed_static_checks
    assert any("internal network changed" in reason for reason in result.reasons)

def test_compose_comment_cannot_spoof_container_name(static_environment):
    from dataclasses import replace
    p=static_environment.sandbox_root/"compose.yaml"
    p.write_text(p.read_text().replace(
        "container_name: fyp-vulnerable-store",
        "container_name: example-store # container_name: fyp-vulnerable-store"))
    result=inspect_static_plan(replace(
        static_environment,approved_integration_commit="c"*40))
    assert not result.passed_static_checks
    assert any("service hardening changed" in reason for reason in result.reasons)


# R4-B1 contract integration: REAL ControlledExecutor code via an inert fake transport.
# These cases do not send a network packet or imply live Docker verification.
from schemas.experiments import ExperimentLimits
from orchestrator.limits import RunLimitTracker
from orchestrator.policy_engine import PolicyEngine
from services.controlled_executor import (
    ControlledExecutor, TransportResponse, TransportTimeoutError,
)


class _R4B1InertTransport:
    def __init__(self, replies, *, timeout_step=None):
        self.replies=tuple(replies)
        self.timeout_step=timeout_step
        self.calls=[]

    def send(self, **kwargs):
        self.calls.append(kwargs)
        index=len(self.calls)
        if self.timeout_step==index:
            raise TransportTimeoutError("offline fake-transport timeout")
        if index > len(self.replies):
            raise AssertionError("registered executor made an unexpected request")
        code,body=self.replies[index-1]
        return TransportResponse(status_code=code,text=body,headers={})


_R4B1_CASES=(
    ("sqli-login-001",
     ((401, "Invalid credentials"),(200, '{"authenticated":true}')),
     ((401, "Invalid credentials"),(401, "Invalid credentials"))),
    ("xss-search-001",
     ((200, "<p>Search term: notebook</p>"),
      (200, '<p><script>fyp_xss_marker()</script></p>')),
     ((200, "<p>Search term: notebook</p>"),
      (200, '<p>&lt;script&gt;fyp_xss_marker()&lt;/script&gt;</p>'))),
    ("path-traversal-read-001",
     ((200, "Public scenario guide"),
      (200, "FYP_SCENARIO_SECRET=synthetic-traversal-evidence-only")),
     ((200, "Public scenario guide"),(403, "Scenario sandbox escape blocked"))),
)


def _r4b1_actual_executor_result(scenario, replies, *, timeout_step=None):
    """Use actual ControlledExecutor + policy + registered-test evaluator.

    Only HTTP send is replaced by an inert in-memory response sequencer.
    """
    test_id=REGISTERED[scenario][0]
    registry=TargetRegistry.from_directories(
        targets_dir=REPO/"config/targets",
        security_tests_dir=REPO/"config/security_tests")
    fake=_R4B1InertTransport(replies,timeout_step=timeout_step)
    executor=ControlledExecutor(
        target_registry=registry,
        test_registry=SecurityTestRegistry.default(),
        policy_engine=PolicyEngine(registry=registry,project_root=REPO),
        limits=RunLimitTracker(ExperimentLimits(
            max_model_calls=1,max_attack_attempts=3,
            max_patch_attempts=1,max_http_requests=10,max_runtime_seconds=60)),
        transport=fake,
    )
    result=executor.execute_registered_test(
        test_id=test_id,attempt_number=1,run_id="r4b1-offline-executor")
    assert len(fake.calls) <= 2, "no retries or unexpected extra requests"
    return result,fake


@pytest.mark.parametrize("scenario,baseline_replies,patched_replies",_R4B1_CASES)
@pytest.mark.parametrize("phase,confirmed",[
    ("vulnerable_baseline",True),("patched_replay",False)])
def test_r4b1_actual_executor_baseline_and_patched_replay_are_assessed(
    scenario,baseline_replies,patched_replies,phase,confirmed
):
    replies=baseline_replies if phase=="vulnerable_baseline" else patched_replies
    real,fake=_r4b1_actual_executor_result(scenario,replies)
    assert real.completed and not real.timed_out
    assert len(real.exchanges)==2 and real.request_count==2
    assert len(fake.calls)==2
    assert real.error_code == (None if confirmed else "evidence-not-observed")
    assert bool(real.evidence)==confirmed
    parsed=observe(scenario,phase,result=real)
    assert parsed.evidence_scope=="offline_fixture"
    assert parsed.evaluation_status=="assessed"
    assert parsed.test_completed is True
    assert parsed.exploit_confirmed is confirmed
    assert parsed.execution.model_dump(mode="json")==real.model_dump(mode="json")
    assert parsed.raw_result_sha256==hashlib.sha256(
        real.model_dump_json().encode()).hexdigest()
    assert parsed.agent_red_plan_authored is False
    assert parsed.research_final_result is False
    assert parsed.agent_model_calls == 0
    # Registered executor was not allowed to invent extra parameters.
    assert all("X-FYP-" not in str(x) for x in fake.calls)


@pytest.mark.parametrize("scenario,baseline_replies,patched_replies",_R4B1_CASES)
def test_r4b1_actual_executor_timeout_is_inconclusive_not_secure(
    scenario,baseline_replies,patched_replies
):
    real,fake=_r4b1_actual_executor_result(
        scenario,baseline_replies,timeout_step=2)
    assert real.completed is False and real.timed_out is True
    assert real.error_code=="request-timeout"
    assert real.request_count==2 and len(real.exchanges)==1
    assert len(fake.calls)==2
    result=observe(scenario,"patched_replay",result=real)
    assert result.evaluation_status=="inconclusive"
    assert result.exploit_confirmed is None
    assert result.test_completed is False


@pytest.mark.parametrize("scenario,baseline_replies,patched_replies",_R4B1_CASES)
def test_r4b1_reject_absent_exploit_without_executor_no_evidence_signal(
    scenario,baseline_replies,patched_replies
):
    real,_=_r4b1_actual_executor_result(scenario,patched_replies)
    assert real.error_code=="evidence-not-observed"
    forged=real.model_copy(update={"error_code":None})
    with pytest.raises(DeterministicRedEvidenceError,match="absent exploit requires"):
        observe(scenario,"patched_replay",result=forged)


@pytest.mark.parametrize("scenario,baseline_replies,patched_replies",_R4B1_CASES)
def test_r4b1_reject_confirmed_exploit_with_false_no_evidence_code(
    scenario,baseline_replies,patched_replies
):
    real,_=_r4b1_actual_executor_result(scenario,baseline_replies)
    assert real.error_code is None
    forged=real.model_copy(update={"error_code":"evidence-not-observed"})
    with pytest.raises(DeterministicRedEvidenceError,match="exploit evidence contradicts"):
        observe(scenario,"vulnerable_baseline",result=forged)


@pytest.mark.parametrize("scenario,baseline_replies,patched_replies",_R4B1_CASES)
def test_r4b1_completed_timeout_and_arbitrary_error_are_rejected(
    scenario,baseline_replies,patched_replies
):
    real,_=_r4b1_actual_executor_result(scenario,patched_replies)
    for updated in (
        real.model_copy(update={"timed_out":True}),
        real.model_copy(update={"error_code":"transport-error"}),
        real.model_copy(update={"error_code":"request-timeout"}),
        real.model_copy(update={"error_code":"redirect-blocked"}),
    ):
        with pytest.raises(DeterministicRedEvidenceError,match="contradictory error or timeout"):
            observe(scenario,"patched_replay",result=updated)


@pytest.mark.parametrize("scenario,baseline_replies,patched_replies",_R4B1_CASES)
def test_r4b1_incomplete_result_cannot_carry_exploit_evidence(
    scenario,baseline_replies,patched_replies
):
    real,_=_r4b1_actual_executor_result(scenario,baseline_replies,timeout_step=2)
    confirmed_evidence=_r4b1_actual_executor_result(scenario,baseline_replies)[0].evidence
    forged=real.model_copy(update={"evidence":confirmed_evidence})
    with pytest.raises(DeterministicRedEvidenceError,match="incomplete test"):
        observe(scenario,"patched_replay",result=forged)


@pytest.mark.parametrize("scenario,baseline_replies,patched_replies",_R4B1_CASES)
def test_r4b1_missing_complete_registered_exchange_rejected(
    scenario,baseline_replies,patched_replies
):
    real,_=_r4b1_actual_executor_result(scenario,patched_replies)
    forged=real.model_copy(update={"exchanges":real.exchanges[:1]})
    with pytest.raises(DeterministicRedEvidenceError,match="completed test lacks"):
        observe(scenario,"patched_replay",result=forged)
