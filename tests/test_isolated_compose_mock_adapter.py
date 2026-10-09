"""R4-C4F mock-only isolated Compose overlay/argv provenance regression tests."""
from __future__ import annotations

from hashlib import sha256
import copy
import json
from pathlib import Path
import shutil
import yaml

from pydantic import ValidationError
import pytest

from services.isolated_compose_mock_adapter import (
    APP_CONTAINER, EXECUTOR_CONTAINER, PROJECT, IMAGE, NETWORK, VOLUME,
    BASE_COMPOSE_SHA256, ISOLATED_COMPOSE, ORIGINAL_IMAGE, OPERATIONS,
    REQUIRED_HASHES, MockOptionBAdmission, MockInventory, MockBinaryProcess,
    R4C4FMockComposeAdapter, R4C4FBlocked, verify_isolation_yaml,
    load_mock_option_b_admission,
)

REPO=Path(__file__).resolve().parents[1]
PIN="2a83c9301f2b408cb5c8e0e8b0aecd47f8d93e19"
TREE="c583aa04b8b37b27b95c1476957f6eabb8f67b30"
PARENT="f19f77a5e2400f1a08d001213e479c4879ae2f42"


@pytest.fixture
def fixture(tmp_path):
    root=tmp_path/"source"
    root.mkdir()
    for rel in REQUIRED_HASHES:
        dst=root/rel
        dst.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(REPO/rel,dst)
    evidence=tmp_path/"evidence"
    evidence.mkdir()
    admission=MockOptionBAdmission(
        source_commit=PIN,source_tree=TREE,source_parent=PARENT,
        source_sha256={rel:sha256((root/rel).read_bytes()).hexdigest()
                       for rel in REQUIRED_HASHES},
        run_id="r4c4f-offline-test",
    )
    manifest=evidence/"external-request.json"
    manifest.write_bytes(admission.canonical_bytes())
    digest=sha256(manifest.read_bytes()).hexdigest()
    assert load_mock_option_b_admission(
        source_root=root,manifest=manifest,external_sha256=digest)==admission
    return root,evidence,manifest,digest,admission


def valid_inventory(**updates):
    original={
        "context":"default","daemon_id":"mock-dedicated-daemon",
        "existing_containers":("kind_jepsen","awesome_franklin"),
        "existing_images":(ORIGINAL_IMAGE,"hello-world:latest"),
        "existing_networks":("bridge","host","none"),
        "existing_volumes":(),
        "occupied_host_ports":(),
    }
    original.update(updates)
    return MockInventory(**original)


def fake_normalized():
    """Synthetic, NOT actual Docker Compose normalization."""
    src=yaml.safe_load((REPO/ISOLATED_COMPOSE).read_bytes())
    return {
        "name":src["name"],
        "services":{
            name:{
                "image":row["image"], "container_name":row["container_name"],
                "read_only":row["read_only"],"cap_drop":row["cap_drop"],
                **({"ports":row["ports"]} if "ports" in row else {}),
            }
            for name,row in src["services"].items()
        },
        "networks":{"security-lab":{"name":src["networks"]["security-lab"]["name"]}},
        "volumes":{"store-runtime":{"name":src["volumes"]["store-runtime"]["name"]}},
    }


def configured(fixture, *, inventory=None, inventory_changes=None, result=None):
    root,evidence,manifest,digest,admission=fixture
    expected=inventory if inventory is not None else valid_inventory()
    seen=[]
    observations=[]
    def inspect():
        observations.append(True)
        if inventory_changes:
            return inventory_changes(expected,len(observations))
        return expected
    def runner(argv,cwd):
        seen.append((argv,cwd))
        if callable(result):return result(argv,cwd)
        if result is not None:return result
        if "config" in argv:
            return MockBinaryProcess(
                returncode=0,
                stdout_chunks=(json.dumps(fake_normalized(),sort_keys=True).encode()+b"\r\n",),
                stderr_chunks=(b"offline-mock\r\n",))
        return MockBinaryProcess(
            returncode=0,stdout_chunks=(b"synthetic ",b"ok\r\n"),
            stderr_chunks=(b"mock\r\n",))
    return (
        R4C4FMockComposeAdapter(
            source_root=root,evidence_root=evidence,
            manifest_path=manifest,manifest_sha256=digest,
            expected_inventory=expected,inventory_observer=inspect,
            binary_runner=runner),
        seen,observations)


def test_c4f_overlay_changes_only_expected_isolation_names():
    base=yaml.safe_load((REPO/"compose.yaml").read_bytes())
    over=verify_isolation_yaml(REPO)
    assert over["name"]==PROJECT
    assert over["name"] != base["name"]
    assert over["services"]["vulnerable-store"]["image"]==IMAGE
    assert over["services"]["controlled-executor"]["image"]==IMAGE
    assert over["services"]["vulnerable-store"]["container_name"]==APP_CONTAINER
    assert over["services"]["controlled-executor"]["container_name"]==EXECUTOR_CONTAINER
    assert over["services"]["vulnerable-store"]["ports"]==["127.0.0.1:18080:8000"]
    assert over["services"]["vulnerable-store"]["expose"]==base["services"]["vulnerable-store"]["expose"]
    assert over["networks"]["security-lab"]["name"]==NETWORK
    assert over["volumes"]["store-runtime"]["name"]==VOLUME
    assert over["services"]["vulnerable-store"]["command"]==base["services"]["vulnerable-store"]["command"]
    assert over["services"]["controlled-executor"]["command"]==base["services"]["controlled-executor"]["command"]
    assert over["services"]["controlled-executor"]["depends_on"]==base["services"]["controlled-executor"]["depends_on"]
    assert over["services"]["vulnerable-store"]["environment"]==base["services"]["vulnerable-store"]["environment"]
    assert sha256((REPO/"compose.yaml").read_bytes()).hexdigest()==BASE_COMPOSE_SHA256


def test_c4f_external_manifest_canonical_and_not_live(fixture):
    root,evidence,manifest,digest,admission=fixture
    assert admission.source_commit==PIN and admission.source_tree==TREE
    assert admission.source_parent==PARENT
    assert admission.context=="default"
    assert not admission.authorizes_real_docker
    assert not admission.authorizes_cleanup
    assert not admission.authorizes_final_research
    assert digest==sha256(admission.canonical_bytes()).hexdigest()
    assert load_mock_option_b_admission(
        source_root=root,manifest=manifest,external_sha256=digest)==admission


@pytest.mark.parametrize("change",[
    {"authorizes_real_docker":True},
    {"authorizes_cleanup":True},
    {"authorizes_final_research":True},
    {"image":"fyp-red-blue-lab:local"},
    {"project":"fyp-red-blue-lab"},
    {"app_container":"fyp-vulnerable-store"},
    {"executor_container":"fyp-controlled-executor"},
    {"host_port":8000},
    {"context":"unknown"},
    {"source_commit":PARENT,"source_parent":PARENT},
])
def test_c4f_schema_refuses_scope_expansion(fixture,change):
    original=fixture[-1]
    with pytest.raises(ValidationError):
        MockOptionBAdmission.model_validate({**original.model_dump(),**change})


@pytest.mark.parametrize("tamper",["old-commit","old-tree","whitespace"])
def test_c4f_external_digest_pins_old_commit_or_whitespace(fixture,tamper):
    root,evidence,manifest,digest,admission=fixture
    if tamper=="old-commit":
        raw=admission.model_copy(update={"source_commit":PARENT}).canonical_bytes()
    elif tamper=="old-tree":
        raw=admission.model_copy(update={"source_tree":"395aa349d9299eea24f3c6bfd6d5fcb6dabfa5e3"}).canonical_bytes()
    else:
        raw=admission.canonical_bytes()+b" "
    manifest.write_bytes(raw)
    with pytest.raises(R4C4FBlocked,match="SHA256 mismatch"):
        load_mock_option_b_admission(source_root=root,manifest=manifest,external_sha256=digest)


@pytest.mark.parametrize("file",REQUIRED_HASHES)
def test_c4f_source_hash_mutation_detected(fixture,file):
    root,evidence,manifest,digest,admission=fixture
    target=root/file
    target.write_bytes(target.read_bytes()+b"\n# drift\n")
    with pytest.raises(R4C4FBlocked,match="source/config hash mismatch"):
        load_mock_option_b_admission(source_root=root,manifest=manifest,external_sha256=digest)


@pytest.mark.parametrize("old_term,new_term",[
    ("fyp-r4c4f-vulnerable-store","fyp-vulnerable-store"),
    ("fyp-r4c4f-controlled-executor","fyp-controlled-executor"),
    ("fyp-r4c4f-red-blue-lab:local","fyp-red-blue-lab:local"),
    ("127.0.0.1:18080:8000","127.0.0.1:8000:8000"),
    ("fyp-r4c4f-security-lab","fyp-red-blue-lab_security-lab"),
    ("fyp-r4c4f-store-runtime","fyp-red-blue-lab_store-runtime"),
    ("internal: true","internal: false"),
    ("read_only: true","read_only: false"),
    ("cap_drop:\n    - ALL","cap_drop:\n    - NET_ADMIN"),
])
def test_c4f_yaml_rejects_legacy_collision_or_security_tamper(fixture,old_term,new_term):
    root,*_=fixture
    f=root/ISOLATED_COMPOSE
    raw=f.read_text()
    assert old_term in raw
    f.write_text(raw.replace(old_term,new_term,1))
    with pytest.raises(R4C4FBlocked):
        verify_isolation_yaml(root)


@pytest.mark.parametrize("action",OPERATIONS)
def test_c4f_all_actions_route_explicit_overlay_and_mock_only(fixture,action):
    adapter,calls,observations=configured(fixture)
    kwargs={"test_id":"sqli-login-bypass-001"} if action=="registered_replay" else {}
    argv=adapter.command(action,**kwargs)
    if action.startswith("health_"):
        assert argv[:4]==("docker","--context","default","inspect")
        assert argv[-1] in (APP_CONTAINER,EXECUTOR_CONTAINER)
    else:
        assert argv[:5]==("docker","--context","default","compose","-f")
        assert argv[5]==str(fixture[0]/ISOLATED_COMPOSE)
        assert argv[6:8]==("--project-directory",str(fixture[0]))
        assert str(fixture[0]/"compose.yaml") not in argv
    receipt=adapter.collect_mock(operation=action,case_id="one",**kwargs)
    assert receipt.outcome=="mock_success"
    assert receipt.ready_for_live is False and receipt.real_docker_calls==0
    assert receipt.origin=="injected_mock_runner_no_docker_invocation"
    assert len(calls)==1 and len(observations)==2
    assert calls[0]==(argv,fixture[0])
    assert (fixture[1]/"one"/"stdout.raw").exists()
    assert (fixture[1]/"one"/"stderr.raw").exists()
    assert (fixture[1]/"one"/"receipt.json").exists()


@pytest.mark.parametrize("invalid",[
    "cleanup","down","prune","stop","remove","push","pull","exec","unknown",
])
def test_c4f_cleanup_and_unregistered_docker_verbs_not_dispatchable(fixture,invalid):
    adapter,calls,_=configured(fixture)
    with pytest.raises(R4C4FBlocked,match="allowlist"):
        adapter.collect_mock(operation=invalid,case_id="blocked")
    assert calls==[]


@pytest.mark.parametrize("test_id",[
    "not-a-real-registered-test","docker","xss-reflection-001-extra",
])
def test_c4f_unregistered_test_blocked(fixture,test_id):
    adapter,calls,_=configured(fixture)
    with pytest.raises(R4C4FBlocked):
        adapter.collect_mock(operation="registered_replay",case_id="blocked",test_id=test_id)
    assert calls==[]


def test_c4f_registered_run_id_and_exact_single_dispatch(fixture):
    adapter,calls,_=configured(fixture)
    receipt=adapter.collect_mock(
        operation="registered_replay",case_id="registered-1",
        test_id="path-traversal-private-file-001")
    assert len(calls)==1
    assert receipt.argv.count("--run-id")==1
    assert receipt.argv[-2:]==("--run-id","r4c4f-offline-test-security_replay")
    assert receipt.argv[-6:-2]==("--test-id","path-traversal-private-file-001","--attempt-number","1")
    with pytest.raises(R4C4FBlocked,match="duplicate"):
        adapter.collect_mock(
            operation="registered_replay",case_id="registered-1",
            test_id="path-traversal-private-file-001")
    assert len(calls)==1


@pytest.mark.parametrize("value",[0,2,-1])
def test_c4f_duplicate_attempt_count_rejected(fixture,value):
    adapter,calls,_=configured(fixture)
    with pytest.raises(R4C4FBlocked):
        adapter.collect_mock(operation="registered_replay",case_id="blocked",
                             test_id="sqli-login-bypass-001",attempt_number=value)
    assert calls==[]


@pytest.mark.parametrize("collision",[
    {"existing_containers":(APP_CONTAINER,)},
    {"existing_containers":(EXECUTOR_CONTAINER,)},
    {"existing_images":(ORIGINAL_IMAGE,IMAGE)},
    {"existing_networks":(NETWORK,)},
    {"existing_volumes":(VOLUME,)},
    {"occupied_host_ports":(18080,)},
    {"daemon_id":""},
    {"context":"unexpected-context"},
])
def test_c4f_collisions_refuse_dispatch(fixture,collision):
    adapter,calls,_=configured(fixture,inventory=valid_inventory(**collision))
    with pytest.raises(R4C4FBlocked,match="pre-dispatch"):
        adapter.collect_mock(operation="config",case_id="blocked")
    assert calls==[]


@pytest.mark.parametrize("collision",[
    {"existing_images":(ORIGINAL_IMAGE,IMAGE)},
    {"existing_containers":(EXECUTOR_CONTAINER,)},
    {"existing_networks":(NETWORK,)},
    {"existing_volumes":(VOLUME,)},
    {"occupied_host_ports":(18080,)},
    {"context":"switched-context"},
    {"daemon_id":"changed-daemon"},
])
def test_c4f_post_dispatch_inventory_mismatch_is_not_success(fixture,collision):
    adapter,calls,observations=configured(
        fixture,inventory_changes=lambda valid,n:
            valid if n==1 else valid.model_copy(update=collision))
    receipt=adapter.collect_mock(operation="config",case_id="drifted")
    assert receipt.outcome=="mock_provenance_failure"
    assert len(calls)==1 and len(observations)==2
    assert (fixture[1]/"drifted"/"stdout.raw").exists()


@pytest.mark.parametrize("tamper",[
    "name","image","app_container","executor_container",
    "port","network","volume","read_only","cap_drop",
])
def test_c4f_wrong_normalized_compose_rejected(fixture,tamper):
    obj=fake_normalized()
    if tamper=="name":obj["name"]="fyp-red-blue-lab"
    if tamper=="image":obj["services"]["controlled-executor"]["image"]=ORIGINAL_IMAGE
    if tamper=="app_container":obj["services"]["vulnerable-store"]["container_name"]="fyp-vulnerable-store"
    if tamper=="executor_container":obj["services"]["controlled-executor"]["container_name"]="fyp-controlled-executor"
    if tamper=="port":obj["services"]["vulnerable-store"]["ports"]=["127.0.0.1:8000:8000"]
    if tamper=="network":obj["networks"]["security-lab"]["name"]="legacy-network"
    if tamper=="volume":obj["volumes"]["store-runtime"]["name"]="legacy-volume"
    if tamper=="read_only":obj["services"]["vulnerable-store"]["read_only"]=False
    if tamper=="cap_drop":obj["services"]["controlled-executor"]["cap_drop"]=[]
    stdout=json.dumps(obj).encode()
    adapter,calls,_=configured(
        fixture,result=MockBinaryProcess(returncode=0,stdout_chunks=(stdout,)))
    receipt=adapter.collect_mock(operation="config",case_id="normalize-invalid")
    assert receipt.outcome=="mock_provenance_failure"
    assert len(calls)==1 and receipt.reasons


def test_c4f_malformed_normalized_config_rejected(fixture):
    adapter,calls,_=configured(fixture,result=MockBinaryProcess(
        returncode=0,stdout_chunks=(b"{not-json",)))
    result=adapter.collect_mock(operation="config",case_id="malformed")
    assert result.outcome=="mock_provenance_failure" and len(calls)==1


@pytest.mark.parametrize("reason,result",[
    ("exit_nonzero",MockBinaryProcess(returncode=1,stdout_chunks=(b"fail",))),
    ("timeout",MockBinaryProcess(returncode=0,stdout_chunks=(b"late",),timed_out=True)),
])
def test_c4f_mock_failure_not_success(fixture,reason,result):
    adapter,calls,_=configured(fixture,result=result)
    receipt=adapter.collect_mock(operation="build",case_id="failed")
    assert receipt.outcome=="mock_failure" and len(calls)==1


def test_c4f_byte_preservation_and_digest(fixture):
    stdout=b"a\r\nb\x00c\n"
    stderr=b"error\r\n"
    adapter,calls,_=configured(fixture,result=MockBinaryProcess(
        returncode=0,stdout_chunks=(stdout[:2],stdout[2:]),
        stderr_chunks=(stderr[:3],stderr[3:])))
    result=adapter.collect_mock(operation="build",case_id="binary")
    assert (fixture[1]/"binary"/"stdout.raw").read_bytes()==stdout
    assert (fixture[1]/"binary"/"stderr.raw").read_bytes()==stderr
    assert result.stdout_sha256==sha256(stdout).hexdigest()
    assert result.stderr_sha256==sha256(stderr).hexdigest()


@pytest.mark.parametrize("stream",["stdout","stderr"])
def test_c4f_byte_overflow_durable_failure_no_retry(fixture,stream):
    chunks=(b"x"*32768,b"y"*32769)
    result=MockBinaryProcess(
        returncode=0,
        stdout_chunks=chunks if stream=="stdout" else (b"small",),
        stderr_chunks=chunks if stream=="stderr" else ())
    adapter,calls,_=configured(fixture,result=result)
    with pytest.raises(R4C4FBlocked,match="no retry"):
        adapter.collect_mock(operation="build",case_id="too-big")
    assert len(calls)==1
    assert (fixture[1]/"too-big"/"dispatch-intent.json").is_file()
    assert (fixture[1]/"too-big"/"failure.json").is_file()
    assert not (fixture[1]/"too-big"/"receipt.json").exists()
    with pytest.raises(R4C4FBlocked,match="duplicate"):
        adapter.collect_mock(operation="build",case_id="too-big")
    assert len(calls)==1


def test_c4f_pre_dispatch_source_integrity_blocked(fixture):
    adapter,calls,_=configured(fixture)
    f=fixture[0]/ISOLATED_COMPOSE
    f.write_bytes(f.read_bytes()+b"#tamper")
    with pytest.raises(R4C4FBlocked,match="source/config"):
        adapter.collect_mock(operation="build",case_id="drift")
    assert calls==[]


def test_c4f_post_dispatch_source_drift_not_success(fixture):
    f=fixture[0]/ISOLATED_COMPOSE
    def mutate(argv,cwd):
        f.write_bytes(f.read_bytes()+b"\n# unauthorized")
        return MockBinaryProcess(returncode=0,stdout_chunks=(b"ok\n",))
    adapter,calls,_=configured(fixture,result=mutate)
    receipt=adapter.collect_mock(operation="build",case_id="changed-after")
    assert receipt.outcome=="mock_provenance_failure"
    assert len(calls)==1


def test_c4f_original_runner_bytes_stay_separate_and_unchanged():
    assert (REPO/"services/environment_service.py").is_file()
    assert (REPO/"services/test_runner.py").is_file()
    source=(REPO/"services/test_runner.py").read_text()
    assert '"docker", "compose", "exec"' in source
    assert "infrastructure.executor.run_verification_test" in source
    isolated=(REPO/"services/isolated_compose_mock_adapter.py").read_text()
    assert '--project-directory' in isolated
    assert 'compose.isolated.yaml' in isolated
    assert "subprocess.run(" not in isolated


def test_c4f_schema_cannot_coerce_mock_receipt_to_live(fixture):
    adapter,_,_=configured(fixture)
    receipt=adapter.collect_mock(operation="config",case_id="one")
    with pytest.raises(ValidationError):
        type(receipt).model_validate({
            **receipt.model_dump(mode="json"),
            "origin":"observed_registered_controlled_executor",
            "ready_for_live":True,"real_docker_calls":1,
        })
