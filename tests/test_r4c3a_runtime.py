"""R4-C3A offline-only admission and mocked runtime identity contract tests."""
from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import shutil

import pytest

from schemas.r4c3a_admission import (
    AdmissionBlocked, R4C3AAdmission, INITIAL_SCENARIO_SHA256,
    read_external_admission,
)
from services.r4c3a_runtime import (
    MockGitState, MockRuntimeState, R4C3ABlocked,
    R4C3AMockedRuntimeCollector, StreamedMockProcess,
)
from services.trusted_remediation_compiler import SOURCE
from services.target_registry import TargetRegistry
from security_tests.registry import SecurityTestRegistry
from test_r4a_prelive_readiness import _R4B1_CASES, _r4b1_actual_executor_result

REPO=Path(__file__).resolve().parents[1]
APPROVED="6ead7a2203bd0c22000a8b5d9af47c40bccbb7a9"
TREE="20ceaf0ff8c976e794687ab76f9d963ed8765775"
PARENT="6b7224f077af0c300d79e6e6a3a98a215fe3ff73"
CASE_IDS=tuple(item[0] for item in _R4B1_CASES)
FILES=(
    "compose.yaml", "config/git-policy.json","config/verification-policy.json",
    "dummy_apps/vulnerable_store/app/scenario_routes.py",
    "config/targets/vulnerable-store.json",
    "config/security_tests/sqli-login-bypass-001.json",
    "config/security_tests/xss-reflection-001.json",
    "config/security_tests/path-traversal-private-file-001.json",
    "security_tests/sql_injection/login_bypass.py",
    "security_tests/xss/reflection.py",
    "security_tests/path_traversal/private_file.py",
)


@pytest.fixture
def env(tmp_path):
    source=tmp_path/"checkout"
    for relative in FILES:
        target=source/relative
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(REPO/relative,target)
    outside=tmp_path/"outside"
    outside.mkdir()
    (outside/"cases").mkdir()
    admission=R4C3AAdmission(
        approved_commit=APPROVED,approved_tree=TREE,approved_parent=PARENT,
        source_hashes={
            x:sha256((source/x).read_bytes()).hexdigest()
            for x in FILES[:4]
        },scenario_ids=CASE_IDS,run_id="r4c3a-offline-test",stage_id="security_replay")
    manifest=outside/"admission.json"
    raw=admission.canonical_bytes()
    manifest.write_bytes(raw)
    digest=sha256(raw).hexdigest()
    checked=read_external_admission(
        source_root=source,manifest_path=manifest,expected_sha256=digest)
    assert checked==admission
    registry=TargetRegistry.from_directories(
        targets_dir=REPO/"config/targets",
        security_tests_dir=REPO/"config/security_tests")
    return source,outside,admission,digest,registry


def setup_case(env,scenario,phase,*,modified_result=None,mutate_git=None,
               mutate_runtime=None,returncode=0,timed_out=False,
               stdout_chunks=None,stderr_chunks=None):
    source,outside,admission,digest,registry=env
    index=CASE_IDS.index(scenario)
    replies=_R4B1_CASES[index][1 if phase=="vulnerable_baseline" else 2]
    real,_=_r4b1_actual_executor_result(scenario,replies)
    real=real.model_copy(update={"run_id":admission.observed_run_id})
    if modified_result is not None:
        real=modified_result(real)
    raw=real.model_dump_json().encode()+b"\r\n"
    if phase=="patched_replay":
        rootfile=source/SOURCE
        rootfile.write_bytes(rootfile.read_bytes()+b"\n# simulated staged patch marker ONLY\n")
    source_digest=sha256((source/SOURCE).read_bytes()).hexdigest()
    staged=("b"*64 if phase=="patched_replay" else None)
    git=MockGitState(
        head=admission.approved_commit,tree=admission.approved_tree,
        branch=("main" if phase=="vulnerable_baseline" else "agent-patch/offline"),
        clean=phase=="vulnerable_baseline",shallow=False,has_remotes=False,
        has_alternates=False,common_directory_is_private=True,
        source_sha256=source_digest,staged_diff_sha256=staged)
    docker=MockRuntimeState(
        context_id="mock-context",daemon_id="mock-daemon",ledger_id="mock-ledger",
        app_container_id="mock-app",executor_container_id="mock-executor",
        image_id="mock-image",deployed_source_sha256=source_digest)
    git_calls=[]
    runtime_calls=[]
    run_calls=[]
    def inspect_git():
        git_calls.append(1)
        return mutate_git(git,len(git_calls)) if mutate_git else git
    def inspect_runtime():
        runtime_calls.append(1)
        return mutate_runtime(docker,len(runtime_calls)) if mutate_runtime else docker
    def runner(args,cwd):
        run_calls.append((args,cwd))
        return StreamedMockProcess(
            returncode=returncode,timed_out=timed_out,
            stdout_chunks=stdout_chunks if stdout_chunks is not None else (raw[:7],raw[7:]),
            stderr_chunks=stderr_chunks if stderr_chunks is not None else (b"offline\r\n",))
    col=R4C3AMockedRuntimeCollector(
        source_root=source,evidence_root=outside/"cases",admission=admission,
        admission_sha256=digest,git_observer=inspect_git,
        runtime_observer=inspect_runtime,expected_mock_owner=docker,
        process_runner=runner,
        registry=registry,implementations=SecurityTestRegistry.default())
    return col,run_calls,git_calls,runtime_calls,source_digest,staged,raw


@pytest.mark.parametrize("scenario",CASE_IDS)
@pytest.mark.parametrize("phase,expected",[
    ("vulnerable_baseline","baseline_exploit_confirmed"),
    ("patched_replay","patched_exploit_not_observed"),
])
def test_r4c3a_real_executor_python_fake_transport_correctly_bound(
    env,scenario,phase,expected,
):
    col,calls,gits,runtimes,source_sha,staged,raw=setup_case(env,scenario,phase)
    case=f"{scenario}-{phase}"
    receipt=col.collect(case_id=case,scenario_id=scenario,phase=phase,
                        staged_diff_sha256=staged)
    assert receipt.outcome==expected
    assert receipt.admitted_commit==APPROVED and receipt.admitted_tree==TREE
    assert receipt.requested_run_id=="r4c3a-offline-test"
    assert receipt.observed_run_id=="r4c3a-offline-test-security_replay"
    assert receipt.model_calls==0 and not receipt.red_agent_plan_authored
    assert not receipt.ready_for_live and receipt.evidence_scope=="offline_mock_only"
    assert receipt.stdout_sha256==sha256(raw).hexdigest()
    assert receipt.stderr_sha256==sha256(b"offline\r\n").hexdigest()
    assert receipt.source_sha256==source_sha
    assert len(calls)==1 and len(gits)==2 and len(runtimes)==2
    assert calls[0][0][-2:]==("--run-id",receipt.observed_run_id)
    path=env[1]/"cases"/case
    assert (path/"dispatch-intent.json").is_file()
    assert (path/"stdout.raw").read_bytes()==raw
    assert (path/"stderr.raw").read_bytes()==b"offline\r\n"
    assert (path/"receipt.json").is_file()
    assert (path/"observation.json").is_file()


def test_r4c3a_external_manifest_roundtrip_and_tampering(env):
    source,outside,admission,digest,_=env
    manifest=outside/"admission.json"
    assert read_external_admission(source_root=source,manifest_path=manifest,
                                   expected_sha256=digest)==admission
    manifest.write_bytes(manifest.read_bytes()+b" ")
    with pytest.raises(AdmissionBlocked,match="hash mismatch"):
        read_external_admission(source_root=source,manifest_path=manifest,
                                expected_sha256=digest)


@pytest.mark.parametrize("changed",["approved_commit","approved_tree","original_sha"])
def test_r4c3a_old_commit_tree_or_source_rejected_by_external_manifest(env,changed):
    source,outside,admission,digest,_=env
    updates={}
    if changed=="approved_commit":updates["approved_commit"]=PARENT
    elif changed=="approved_tree":updates["approved_tree"]="612cbe74627cfef1a736bb0506f038b3513c82db"
    else:
        source.joinpath(SOURCE).write_text("changed original")
        with pytest.raises(AdmissionBlocked,match="source mismatch"):
            read_external_admission(source_root=source,
                                    manifest_path=outside/"admission.json",
                                    expected_sha256=digest)
        return
    tampered=admission.model_copy(update=updates)
    # An independently reviewed SHA is the trust anchor, so the old values
    # cannot be accepted by a caller reusing the frozen original checksum.
    (outside/"admission.json").write_bytes(tampered.canonical_bytes())
    with pytest.raises(AdmissionBlocked,match="hash mismatch"):
        read_external_admission(source_root=source,
                                manifest_path=outside/"admission.json",
                                expected_sha256=digest)


@pytest.mark.parametrize("field,value",[
    ("head",PARENT),("tree","612cbe74627cfef1a736bb0506f038b3513c82db"),
    ("branch","recovery/wrong"),("clean",False),("shallow",True),
    ("has_remotes",True),("has_alternates",True),
    ("common_directory_is_private",False),("source_sha256","0"*64),
])
def test_r4c3a_git_baseline_fails_closed(env,field,value):
    col,calls,*rest=setup_case(
        env,CASE_IDS[0],"vulnerable_baseline",
        mutate_git=lambda x,n:x.model_copy(update={field:value}))
    with pytest.raises(R4C3ABlocked,match="Git baseline"):
        col.collect(case_id="git-fail",scenario_id=CASE_IDS[0],
                    phase="vulnerable_baseline")
    assert calls==[] and not (env[1]/"cases"/"git-fail").exists()


@pytest.mark.parametrize("field,value",[
    ("daemon_id","switched-daemon"),("context_id","other-context"),
    ("ledger_id","other-lease"),("app_container_id","other-app"),
    ("executor_container_id","foreign-executor"),("image_id","other-image"),
    ("deployed_source_sha256","0"*64),
])
def test_r4c3a_runtime_mismatch_before_dispatch_blocks(env,field,value):
    col,calls,*rest=setup_case(
        env,CASE_IDS[0],"vulnerable_baseline",
        mutate_runtime=lambda x,n:x.model_copy(update={field:value}))
    with pytest.raises(R4C3ABlocked,match="runtime/container"):
        col.collect(case_id="identity-fail",scenario_id=CASE_IDS[0],
                    phase="vulnerable_baseline")
    assert calls==[]


@pytest.mark.parametrize("field,value",[
    ("daemon_id","switched-daemon"),("context_id","other-context"),
    ("image_id","other-image"),("executor_container_id","foreign-executor"),
    ("deployed_source_sha256","0"*64),
])
def test_r4c3a_runtime_drift_after_dispatch_not_a_success(env,field,value):
    col,calls,*rest=setup_case(
        env,CASE_IDS[0],"vulnerable_baseline",
        mutate_runtime=lambda x,n:x if n==1 else x.model_copy(update={field:value}))
    receipt=col.collect(case_id="changed-runtime",scenario_id=CASE_IDS[0],
                        phase="vulnerable_baseline")
    assert receipt.outcome=="provenance_failed"
    assert len(calls)==1
    assert (env[1]/"cases"/"changed-runtime"/"stdout.raw").is_file()


@pytest.mark.parametrize("mode,expected",[
    ("wrong_run","provenance_failed"),
    ("wrong_attempt","provenance_failed"),
    ("wrong_test","provenance_failed"),
    ("malformed","provenance_failed"),
    ("nonzero","executor_failed"),
    ("timeout","inconclusive"),
])
def test_r4c3a_wrong_result_or_failure_never_marked_secure(env,mode,expected):
    def update(row):
        if mode=="wrong_run":return row.model_copy(update={"run_id":"not-the-requested-run"})
        if mode=="wrong_attempt":return row.model_copy(update={"attempt_number":2})
        if mode=="wrong_test":return row.model_copy(update={"test_id":"unknown-test"})
        return row
    overrides={}
    if mode in ("wrong_run","wrong_attempt","wrong_test"):
        overrides["modified_result"]=update
    if mode=="malformed":overrides["stdout_chunks"]=(b"{bad-json",)
    if mode=="nonzero":overrides["returncode"]=2
    if mode=="timeout":overrides["timed_out"]=True
    col,calls,*rest=setup_case(env,CASE_IDS[0],"patched_replay",**overrides)
    receipt=col.collect(case_id="bad-result",scenario_id=CASE_IDS[0],
                        phase="patched_replay",staged_diff_sha256="b"*64)
    assert receipt.outcome==expected and len(calls)==1
    assert (env[1]/"cases"/"bad-result"/"receipt.json").is_file()


def test_r4c3a_duplicate_case_never_redispatch(env):
    col,calls,*rest=setup_case(env,CASE_IDS[0],"vulnerable_baseline")
    kw=dict(case_id="once",scenario_id=CASE_IDS[0],phase="vulnerable_baseline")
    col.collect(**kw)
    with pytest.raises(R4C3ABlocked,match="never redispatch"):
        col.collect(**kw)
    assert len(calls)==1


def test_r4c3a_byte_overflow_after_intent_stops_and_records_failure(env):
    col,calls,*rest=setup_case(
        env,CASE_IDS[0],"vulnerable_baseline",
        stdout_chunks=(b"a"*32768,b"b"*32769))
    with pytest.raises(R4C3ABlocked,match="no retry"):
        col.collect(case_id="overflow",scenario_id=CASE_IDS[0],
                    phase="vulnerable_baseline")
    folder=env[1]/"cases"/"overflow"
    assert len(calls)==1
    assert (folder/"dispatch-intent.json").is_file()
    assert (folder/"failure.json").is_file()
    assert not (folder/"receipt.json").exists()


def test_r4c3a_stage_binding_does_not_execute_twice(env):
    col,calls,*rest=setup_case(env,CASE_IDS[1],"vulnerable_baseline")
    result=col.collect(case_id="one-stage",scenario_id=CASE_IDS[1],
                       phase="vulnerable_baseline")
    assert len(calls)==1
    assert result.observed_run_id.endswith("-security_replay")
    assert calls[0][0].count("--run-id")==1


@pytest.mark.parametrize("tampered",["source","test_policy","test_implementation"])
def test_r4c3a_source_and_registered_test_drift_block_before_dispatch(env,tampered):
    source=env[0]
    target={
        "source":SOURCE,
        "test_policy":"config/security_tests/sqli-login-bypass-001.json",
        "test_implementation":"security_tests/sql_injection/login_bypass.py",
    }[tampered]
    (source/target).write_bytes((source/target).read_bytes()+b"\n# test-only drift\n")
    col,calls,*rest=setup_case(env,CASE_IDS[0],"vulnerable_baseline")
    with pytest.raises(R4C3ABlocked):
        col.collect(case_id="tamper",scenario_id=CASE_IDS[0],
                    phase="vulnerable_baseline")
    assert len(calls)==0


def test_r4c3a_mock_contract_cannot_claim_real_execution(env):
    col,calls,*rest=setup_case(env,CASE_IDS[0],"vulnerable_baseline")
    receipt=col.collect(case_id="no-live",scenario_id=CASE_IDS[0],
                        phase="vulnerable_baseline")
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        type(receipt).model_validate({
            **receipt.model_dump(mode="json"),
            "origin":"observed_registered_controlled_executor",
            "evidence_scope":"live"})
    assert not receipt.ready_for_live and not receipt.final_research_result


@pytest.mark.parametrize("field,value",[
    ("head",PARENT),("tree","612cbe74627cfef1a736bb0506f038b3513c82db"),
    ("branch","main"),("staged_diff_sha256","f"*64),
])
def test_r4c3a_mock_git_state_drift_after_dispatch_is_provenance_failure(env,field,value):
    col,calls,*rest=setup_case(
        env,CASE_IDS[0],"patched_replay",
        mutate_git=lambda x,n:x if n==1 else x.model_copy(update={field:value}))
    receipt=col.collect(case_id="git-change",scenario_id=CASE_IDS[0],
                        phase="patched_replay",staged_diff_sha256="b"*64)
    assert receipt.outcome=="provenance_failed"
    assert len(calls)==1
    assert (env[1]/"cases"/"git-change"/"stdout.raw").is_file()


@pytest.mark.parametrize("change",["wrong_step","wrong_evidence"])
def test_r4c3a_registered_exchange_and_evidence_tampering_rejected(env,change):
    def mutate(result):
        if change=="wrong_step":
            return result.model_copy(update={"exchanges":(
                result.exchanges[0].model_copy(update={"step_id":"unauthorized-step"}),
                *result.exchanges[1:])})
        return result.model_copy(update={"evidence":()})
    col,calls,*rest=setup_case(
        env,CASE_IDS[0],"vulnerable_baseline",modified_result=mutate)
    receipt=col.collect(case_id="bad-registered",scenario_id=CASE_IDS[0],
                        phase="vulnerable_baseline")
    assert receipt.outcome=="provenance_failed"
    assert len(calls)==1


def test_r4c3a_multiple_json_objects_denied(env):
    col,calls,*rest=setup_case(
        env,CASE_IDS[0],"patched_replay",
        stdout_chunks=(b'{"a":1}\n{"b":2}\n',))
    receipt=col.collect(case_id="two-json",scenario_id=CASE_IDS[0],
                        phase="patched_replay",staged_diff_sha256="b"*64)
    assert receipt.outcome=="provenance_failed"
    assert len(calls)==1


def test_r4c3a_unexpected_binary_chunk_type_durably_fails(env):
    col,calls,*rest=setup_case(
        env,CASE_IDS[0],"vulnerable_baseline",
        stdout_chunks=(b'good', "not bytes"))
    with pytest.raises(R4C3ABlocked,match="no retry"):
        col.collect(case_id="bad-binary",scenario_id=CASE_IDS[0],
                    phase="vulnerable_baseline")
    assert len(calls)==1
    assert (env[1]/"cases"/"bad-binary"/"failure.json").is_file()
