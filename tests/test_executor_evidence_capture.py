"""R4-C1 offline tests: actual registered evaluator, injected binary process/Git/Docker.

No live subprocess, Docker call, git command, network, clone, or model inference.
"""
from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import shutil

import pytest

from services.executor_evidence_capture import (
    APPROVED_COMMIT, BinaryProcessResult, R4C1CaptureBlocked,
    R4C1CaptureCollector, SOURCE, EXPECTED_SOURCE_SHA256,
)
from services.environment_readiness import (
    APPROVED_TREE, DOCKER_CMDS, GIT_CMDS, ObservedProcess,
    inspect_docker_mock, inspect_git_baseline_mock,
)
from security_tests.registry import SecurityTestRegistry
from services.target_registry import TargetRegistry

# This existing fixture exercises the REAL ControlledExecutor Python logic
# with an inert in-memory HttpTransport seam. No external target is contacted.
from test_security_preflight import _R4B1_CASES, _r4b1_actual_executor_result

REPO = Path(__file__).resolve().parents[1]
HASHED="a"*64
SCENARIOS=[a for a,_,_ in _R4B1_CASES]


@pytest.fixture
def mini_checkout(tmp_path):
    root=tmp_path/"source"
    for source in [SOURCE, "config/targets/vulnerable-store.json",
                   "config/security_tests/sqli-login-bypass-001.json",
                   "config/security_tests/xss-reflection-001.json",
                   "config/security_tests/path-traversal-private-file-001.json",
                   "security_tests/sql_injection/login_bypass.py",
                   "security_tests/xss/reflection.py",
                   "security_tests/path_traversal/private_file.py"]:
        p=root/source
        p.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(REPO/source,p)
    evidence=tmp_path/"evidence"
    evidence.mkdir()
    registry=TargetRegistry.from_directories(
        targets_dir=REPO/"config/targets",
        security_tests_dir=REPO/"config/security_tests")
    return root,evidence,registry


def collector_for(mini_checkout,runner):
    root,evidence,registry=mini_checkout
    return R4C1CaptureCollector(
        source_root=root,evidence_root=evidence,runner=runner,
        registry=registry,implementations=SecurityTestRegistry.default())


def capture_case(mini_checkout, scenario, phase, response=None, **kw):
    root,evidence,registry=mini_checkout
    idx=SCENARIOS.index(scenario)
    baseline,patched=_R4B1_CASES[idx][1:]
    actual,_fake=_r4b1_actual_executor_result(
        scenario,baseline if phase=="vulnerable_baseline" else patched)
    raw=actual.model_dump_json().encode()+b"\n"
    process=response if response is not None else BinaryProcessResult(0,raw,b"mock stderr \r\n")
    calls=[]
    def runner(argv,cwd):
        calls.append((argv,cwd))
        return process
    obj=collector_for(mini_checkout,runner)
    original=root/SOURCE
    if phase=="patched_replay":
        original.write_bytes(original.read_bytes()+b"\n# simulated patch fixture only\n")
    digest=sha256(original.read_bytes()).hexdigest()
    outcome=obj.collect(
        case_id=f"{scenario}-{phase}",run_id="r4b1-offline-executor",
        scenario_id=scenario,phase=phase,attempt_number=1,
        observed_source_sha256=digest,
        prepared_diff_sha256=("b"*64 if phase=="patched_replay" else None),
        daemon_fingerprint_claim_sha256=HASHED,
        container_id_claim="offline-synthetic-container",
        **kw)
    return outcome,root,evidence,calls,raw


@pytest.mark.parametrize("scenario",SCENARIOS)
@pytest.mark.parametrize("phase,expected",[
    ("vulnerable_baseline","baseline_exploit_confirmed"),
    ("patched_replay","patched_exploit_not_observed")])
def test_r4c1_real_executor_binary_output_frozen_with_exact_newline(
    mini_checkout,scenario,phase,expected):
    receipt,root,evidence,calls,raw=capture_case(mini_checkout,scenario,phase)
    assert receipt.outcome==expected
    assert not receipt.red_agent_plan_authored and not receipt.final_research_result
    assert receipt.model_calls==0 and receipt.scope=="offline_only"
    assert receipt.raw_stdout_sha256==sha256(raw).hexdigest()
    assert receipt.raw_stderr_sha256==sha256(b"mock stderr \r\n").hexdigest()
    assert len(calls)==1
    assert calls[0][0][:5]==("docker","compose","exec","-T","controlled-executor")
    directory=evidence/f"{scenario}-{phase}"
    assert (directory/"stdout.raw").read_bytes()==raw
    assert (directory/"stderr.raw").read_bytes()==b"mock stderr \r\n"
    assert (directory/"observation.json").is_file()
    assert (directory/"dispatch-intent.json").is_file()
    assert (directory/"receipt.json").is_file()
    assert (directory/"receipt.json").read_text().find("injected_mock_process_runner")>=0
    assert not (root/".git").exists()


def test_r4c1_duplicate_attempt_never_dispatches_again(mini_checkout):
    root,evidence,registry=mini_checkout
    real,_=_r4b1_actual_executor_result(
        SCENARIOS[0],_R4B1_CASES[0][1])
    count=[]
    def mock(argv,cwd):
        count.append(argv)
        return BinaryProcessResult(0,real.model_dump_json().encode(),b"")
    col=collector_for(mini_checkout,mock)
    kwargs=dict(case_id="once",run_id="r4b1-offline-executor",
        scenario_id=SCENARIOS[0],phase="vulnerable_baseline",attempt_number=1,
        observed_source_sha256=EXPECTED_SOURCE_SHA256,
        daemon_fingerprint_claim_sha256=HASHED,
        container_id_claim="mock-container")
    col.collect(**kwargs)
    with pytest.raises(R4C1CaptureBlocked,match="case already reserved"):
        col.collect(**kwargs)
    assert len(count)==1


@pytest.mark.parametrize("mode,expected",[
    ("nonzero","executor_failed"),("timeout","inconclusive"),
    ("invalid-json","provenance_failed"),("wrong-run","provenance_failed"),
    ("empty","provenance_failed"),
])
def test_r4c1_mocked_subprocess_failures_are_not_success(mini_checkout,mode,expected):
    valid,_=_r4b1_actual_executor_result(
        SCENARIOS[0],_R4B1_CASES[0][1])
    raw=valid.model_dump_json().encode()
    if mode=="nonzero":
        response=BinaryProcessResult(2,raw,b"offline subprocess failed")
    elif mode=="timeout":
        response=BinaryProcessResult(None,raw,b"",True)
    elif mode=="invalid-json":
        response=BinaryProcessResult(0,b"{not json}",b"")
    elif mode=="wrong-run":
        changed=valid.model_copy(update={"run_id":"spoofed"})
        response=BinaryProcessResult(0,changed.model_dump_json().encode(),b"")
    else:
        response=BinaryProcessResult(0,b"",b"")
    result,root,evidence,calls,_=capture_case(mini_checkout,SCENARIOS[0],"vulnerable_baseline",response)
    assert result.outcome==expected
    assert result.model_calls==0
    assert len(calls)==1
    assert (evidence/f"{SCENARIOS[0]}-vulnerable_baseline"/"stdout.raw").read_bytes()==response.stdout


def test_r4c1_source_drift_blocked_before_dispatch(mini_checkout):
    root,evidence,_=mini_checkout
    root.joinpath(SOURCE).write_text("tampered")
    calls=[]
    col=collector_for(mini_checkout,lambda *a: calls.append(a))
    with pytest.raises(R4C1CaptureBlocked,match="source differs"):
        col.collect(case_id="drift",run_id="r4b1-offline-executor",
                    scenario_id=SCENARIOS[0],phase="vulnerable_baseline",
                    attempt_number=1,observed_source_sha256=EXPECTED_SOURCE_SHA256,
                    daemon_fingerprint_claim_sha256=HASHED,
                    container_id_claim="offline-container")
    assert calls==[] and not (evidence/"drift").exists()


def test_r4c1_failed_runner_no_retry_and_durable_intent(mini_checkout):
    def fail(argv,cwd):raise RuntimeError("injected crash")
    root,evidence,_=mini_checkout
    col=collector_for(mini_checkout,fail)
    with pytest.raises(R4C1CaptureBlocked,match="no automatic retry"):
        col.collect(case_id="boom",run_id="r4b1-offline-executor",
                    scenario_id=SCENARIOS[0],phase="vulnerable_baseline",
                    attempt_number=1,observed_source_sha256=EXPECTED_SOURCE_SHA256,
                    daemon_fingerprint_claim_sha256=HASHED,
                    container_id_claim="offline-container")
    assert (evidence/"boom"/"dispatch-intent.json").is_file()
    assert (evidence/"boom"/"process-failure.json").is_file()
    assert not (evidence/"boom"/"receipt.json").exists()
    with pytest.raises(R4C1CaptureBlocked,match="case already reserved"):
        col.collect(case_id="boom",run_id="r4b1-offline-executor",
                    scenario_id=SCENARIOS[0],phase="vulnerable_baseline",
                    attempt_number=1,observed_source_sha256=EXPECTED_SOURCE_SHA256,
                    daemon_fingerprint_claim_sha256=HASHED,
                    container_id_claim="offline-container")


def test_r4c1_unsupported_id_denied(mini_checkout):
    calls=[]
    col=collector_for(mini_checkout,lambda *a:calls.append(a))
    with pytest.raises(R4C1CaptureBlocked,match="unregistered"):
        col.collect(case_id="invalid",run_id="r4b1-offline-executor",
                    scenario_id="unregistered-scenario",phase="vulnerable_baseline",
                    attempt_number=1,observed_source_sha256=EXPECTED_SOURCE_SHA256,
                    daemon_fingerprint_claim_sha256=HASHED,
                    container_id_claim="offline-container")
    assert calls==[]


def docker_runner_mock(overrides=None):
    overrides=overrides or {}
    rows={
        DOCKER_CMDS[0]:"r4-isolated",
        DOCKER_CMDS[1]:json.dumps({"Name":"r4-isolated","Endpoints":{"docker":{"Host":"unix:///mock.sock"}}}),
        DOCKER_CMDS[2]:json.dumps({"ID":"mock-daemon","ServerVersion":"offline"}),
        DOCKER_CMDS[3]:"",
        DOCKER_CMDS[4]:"",
        DOCKER_CMDS[5]:"",
        DOCKER_CMDS[6]:"",
    }
    calls=[]
    def runner(cmd):
        calls.append(cmd)
        output=overrides.get(cmd,rows.get(cmd, "r4-isolated"))
        return output if isinstance(output,ObservedProcess) else ObservedProcess(0,output)
    return runner,calls


def test_r4c1_readonly_docker_mock_checks_no_mutation():
    runner,calls=docker_runner_mock()
    result=inspect_docker_mock(
        runner,context_expected="r4-isolated",
        operator_claims_exclusive_daemon=True,host_port_8000_confirmed_free=True)
    assert result.static_checks_pass
    assert result.ready_for_live is False and result.safe_to_mutate is False
    assert len(calls)==len(DOCKER_CMDS)
    assert all(c in DOCKER_CMDS for c in calls)
    assert all("up" not in c and "down" not in c and "prune" not in c for c in calls)


@pytest.mark.parametrize("conflict_cmd,line",[
    (DOCKER_CMDS[3],json.dumps({"Names":"fyp-controlled-executor"})),
    (DOCKER_CMDS[4],json.dumps({"Name":"fyp-red-blue-lab_security-lab"})),
    (DOCKER_CMDS[5],json.dumps({"Name":"fyp-red-blue-lab_store-runtime"})),
    (DOCKER_CMDS[6],json.dumps({"Repository":"fyp-red-blue-lab","Tag":"local"})),
])
def test_r4c1_docker_conflicts_block(conflict_cmd,line):
    runner,_=docker_runner_mock({conflict_cmd:line})
    report=inspect_docker_mock(
        runner,context_expected="r4-isolated",
        operator_claims_exclusive_daemon=True,host_port_8000_confirmed_free=True)
    assert not report.static_checks_pass
    assert report.ready_for_live is False
    assert any("already exists" in r or "preexisting" in r or "fixed-tag" in r for r in report.reasons)


def test_r4c1_docker_context_drift_blocks():
    calls=[]
    def runner(cmd):
        calls.append(cmd)
        if len(calls)==len(DOCKER_CMDS)-1:return ObservedProcess(0,"different")
        defaults,_=docker_runner_mock()
        return defaults(cmd)
    outcome=inspect_docker_mock(
        runner,context_expected="r4-isolated",
        operator_claims_exclusive_daemon=True,host_port_8000_confirmed_free=True)
    assert not outcome.static_checks_pass
    assert any("context drift" in s for s in outcome.reasons)


def test_r4c1_docker_incomplete_info_blocks():
    runner,_=docker_runner_mock({DOCKER_CMDS[2]:ObservedProcess(1,"", "denied")})
    outcome=inspect_docker_mock(
        runner,context_expected="r4-isolated",
        operator_claims_exclusive_daemon=True,host_port_8000_confirmed_free=True)
    assert not outcome.static_checks_pass
    assert any("discovery incomplete" in s for s in outcome.reasons)


def git_runner_mock(destination:Path,overrides=None):
    overrides=overrides or {}
    defaults=[
        APPROVED_COMMIT,APPROVED_TREE,"main","","false",
        str(destination/".git"),str(destination/".git/objects/info/alternates"),"",
    ]
    responses={("git","-C",str(destination),*cmd):resp for cmd,resp in zip(GIT_CMDS,defaults)}
    seen=[]
    def runner(cmd,cwd):
        seen.append(cmd)
        assert cwd==destination
        response=overrides.get(cmd,responses[cmd])
        return response if isinstance(response,ObservedProcess) else ObservedProcess(0,response)
    return runner,seen


def test_r4c1_mocked_git_clean_main_at_approved_commit(tmp_path):
    root=tmp_path/"candidate"
    runner,seen=git_runner_mock(root)
    result=inspect_git_baseline_mock(
        runner,destination=root,
        protected_paths=(tmp_path/"primary",tmp_path/"integration"))
    assert result.static_checks_pass
    assert not result.ready_for_live and not result.safe_to_mutate
    assert len(seen)==len(GIT_CMDS)
    assert all(x[0]=="git" for x in seen)
    assert not root.exists()  # mock cannot create clone


@pytest.mark.parametrize("index,val",[
    (0,"f"*40),(1,"0"*40),(2,"detached"),(3,"?? untracked-file"),
    (4,"true"),(5,"/home/user/primary/.git"),(7,"origin /home/user/primary (fetch)"),
])
def test_r4c1_git_wrong_baseline_identity_blocked(tmp_path,index,val):
    root=tmp_path/"candidate"
    cmd=("git","-C",str(root),*GIT_CMDS[index])
    runner,_=git_runner_mock(root,{cmd:val})
    result=inspect_git_baseline_mock(
        runner,destination=root,
        protected_paths=(tmp_path/"primary",tmp_path/"integration"))
    assert not result.static_checks_pass
    assert not result.ready_for_live


def test_r4c1_git_nested_protected_destination_blocked(tmp_path):
    primary=tmp_path/"primary"
    dest=primary/"inside"
    runner,_=git_runner_mock(dest)
    result=inspect_git_baseline_mock(
        runner,destination=dest,protected_paths=(primary,))
    assert not result.static_checks_pass
    assert any("protected repository" in x for x in result.reasons)


def test_r4c1_git_shared_alternates_file_blocked(tmp_path):
    root=tmp_path/"candidate"
    alt=root/".git/objects/info/alternates"
    alt.parent.mkdir(parents=True)
    alt.write_text("/tmp/primary/objects")
    runner,_=git_runner_mock(root)
    result=inspect_git_baseline_mock(
        runner,destination=root,protected_paths=(tmp_path/"primary",))
    assert not result.static_checks_pass
    assert any("alternates" in s for s in result.reasons)

def test_r4c1_docker_daemon_switch_detected():
    calls=[]
    default,_=docker_runner_mock()
    def runner(command):
        calls.append(command)
        if len(calls)==len(DOCKER_CMDS):
            return ObservedProcess(0,json.dumps({"ID":"different-daemon"}))
        return default(command)
    result=inspect_docker_mock(
        runner,context_expected="r4-isolated",
        operator_claims_exclusive_daemon=True,host_port_8000_confirmed_free=True)
    assert not result.static_checks_pass
    assert any("daemon identity changed" in x for x in result.reasons)
    assert not result.ready_for_live


def test_r4c1_stream_exceeded_limit_never_discards_intent(mini_checkout):
    root,evidence,reg=mini_checkout
    calls=[]
    def too_large(argv,cwd):
        calls.append(argv)
        return BinaryProcessResult(0,b"A"*65537,b"")
    col=collector_for(mini_checkout,too_large)
    with pytest.raises(R4C1CaptureBlocked,match="exceeds evidence limit"):
        col.collect(
            case_id="huge",run_id="r4b1-offline-executor",
            scenario_id=SCENARIOS[0],phase="vulnerable_baseline",attempt_number=1,
            observed_source_sha256=EXPECTED_SOURCE_SHA256,
            daemon_fingerprint_claim_sha256=HASHED,
            container_id_claim="offline-container",
        )
    assert len(calls)==1
    assert (evidence/"huge"/"dispatch-intent.json").is_file()
    assert "stream-exceeded-limit" in (evidence/"huge"/"process-failure.json").read_text()
    assert not (evidence/"huge"/"receipt.json").exists()

@pytest.mark.parametrize("modified",["policy","implementation"])
def test_r4c1_tampered_registered_file_never_passes_observation(mini_checkout,modified):
    root,evidence,_=mini_checkout
    if modified=="policy":
        p=root/"config/security_tests/sqli-login-bypass-001.json"
    else:
        p=root/"security_tests/sql_injection/login_bypass.py"
    p.write_bytes(p.read_bytes()+b"\n# tampering not allowed\n")
    result,_,_,calls,_=capture_case(
        mini_checkout,SCENARIOS[0],"vulnerable_baseline")
    assert result.outcome=="provenance_failed"
    assert "differs from pinned approved source" in result.reason
    assert len(calls)==1
