"""R4-C4A isolated mock-only readiness admission and negative gate tests."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import shutil

from pydantic import ValidationError
import pytest

from schemas.registered_red_observation import REGISTERED
from schemas.readiness_request import (
    C4AAdmissionBlocked, C4AReadinessRequest, REQUIRED_HASH_PATHS,
    DISPOSABLE_NAMES, load_mock_external_request,
)
from services.readiness_guards import (
    MockFSState, MockProcessOutput, MockDockerOperatorClaim,
    inspect_private_root_mock, inspect_git_main_mock,
    inspect_docker_ownership_mock, C4AGuardBlocked,
)

REPO=Path(__file__).resolve().parents[1]
COMMIT="f19f77a5e2400f1a08d001213e479c4879ae2f42"
PARENT="6ead7a2203bd0c22000a8b5d9af47c40bccbb7a9"
TREE="395aa349d9299eea24f3c6bfd6d5fcb6dabfa5e3"
CTX="r4-private-daemon"
DAEMON="mock-daemon-001"
ENDPOINT="unix:///mock/private/docker.sock"


@pytest.fixture
def request_env(tmp_path):
    source=tmp_path/"source"
    source.mkdir()
    hashes={}
    for rel in REQUIRED_HASH_PATHS:
        path=source/rel
        path.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(REPO/rel,path)
        hashes[rel]=sha256(path.read_bytes()).hexdigest()
    request=C4AReadinessRequest(
        approved_source_commit=COMMIT,approved_parent_commit=PARENT,
        approved_source_tree=TREE,source_hashes=hashes,
        scenario_ids=tuple(REGISTERED),
        intended_daemon_context=CTX,
        operator_approval_reference="offline-operator-claim-not-real-approval",
        run_id="r4c4a-only-mocked")
    outside=tmp_path/"evidence"
    outside.mkdir()
    manifest=outside/"readiness-request.json"
    manifest.write_bytes(request.canonical_bytes())
    digest=sha256(manifest.read_bytes()).hexdigest()
    assert load_mock_external_request(root=source,external_path=manifest,
                                     trusted_sha256=digest)==request
    return source,outside,request,manifest,digest


def private_mock_factory(*, existing_mode_overrides=None, symlinks=(),
                         missing=(), owner_overrides=None, occupied=False):
    home=Path("/home/mockuser")
    run=home/".local/state/r4-run-01"
    existing={Path("/"),Path("/home"),home,home/".local",home/".local/state"}
    modes=existing_mode_overrides or {}
    users=owner_overrides or {}
    observations=[]
    def watcher(path):
        observations.append(path)
        if path==run:
            return MockFSState(exists=occupied,is_directory=occupied,
                               owner_uid=1000,unix_mode=0o700)
        return MockFSState(exists=(path in existing and path not in missing),
                           is_directory=(path in existing),
                           is_symlink=(path in symlinks),
                           owner_uid=users.get(path,0 if path in (Path("/"),Path("/home")) else 1000),
                           unix_mode=modes.get(path,0o755 if path in (Path("/"),Path("/home")) else 0o700))
    return home,run,watcher,observations


def mock_git_factory(request, *, overrides=None, source_override=None,
                     alternates=False, failure=None):
    dest=Path("/home/mockuser/.local/state/r4-run-01/checkouts/01-sqli")
    expected={
      ("rev-parse","HEAD"):COMMIT,
      ("rev-parse","HEAD^{tree}"):TREE,
      ("rev-parse","HEAD^"):PARENT,
      ("symbolic-ref","--quiet","--short","HEAD"):"main",
      ("rev-parse","refs/heads/main"):COMMIT,
      ("status","--porcelain=v1","--untracked-files=all"):"",
      ("rev-parse","--is-shallow-repository"):"false",
      ("remote",):"",
      ("rev-parse","--path-format=absolute","--git-common-dir"):str(dest/".git"),
    }
    expected.update(overrides or {})
    calls=[]
    def runner(command,cwd):
        calls.append(command)
        assert cwd==dest
        assert command[:3]==("git","-C",str(dest))
        token=command[3:]
        if token==failure:
            return MockProcessOutput(1,"","simulated error")
        assert token in expected,(token,command)
        return MockProcessOutput(0,expected[token])
    def hashes(path):
        if path==source_override:return "0"*64
        return request.source_hashes[path]
    return dest,runner,hashes,lambda:alternates,calls


def mock_docker_factory(*, changes=None, fail_index=None, owner=None):
    owner=owner or MockDockerOperatorClaim(
        operator_approved=True,dedicated_exclusive=True,
        exclusive_lease_valid=True,daemon_host_port_8000_free=True,
        approved_context=CTX,approved_daemon_id=DAEMON,
        approved_endpoint=ENDPOINT)
    context={"Name":CTX,"Endpoints":{"docker":{"Host":ENDPOINT}}}
    info={"ID":DAEMON,"Rootless":True}
    rows={
       "ps":[],
       "networks":[{"Name":"bridge"},{"Name":"host"},{"Name":"none"}],
       "volumes":[],
       "images":[],
    }
    values=[
        CTX,json.dumps(context),json.dumps(info),
        "", "\n".join(json.dumps(x) for x in rows["networks"]),
        "", "",json.dumps(info),CTX,
    ]
    if changes:
        changes(values,rows)
        values[4]="\n".join(json.dumps(x) for x in rows["networks"])
    calls=[]
    def runner(command):
        calls.append(command)
        n=len(calls)-1
        if fail_index is not None and n==fail_index:
            return MockProcessOutput(1,"","simulated failure")
        return MockProcessOutput(0,values[n])
    return owner,runner,calls,values,rows


def test_c4a_external_request_has_zero_live_authority(request_env):
    source,outside,req,path,digest=request_env
    assert req.approved_source_commit==COMMIT and req.approved_source_tree==TREE
    assert req.approved_parent_commit==PARENT
    assert req.checkout_names==DISPOSABLE_NAMES
    assert req.scope=="mock_readiness_contract_only"
    assert not req.authorizes_git_clone and not req.authorizes_docker_call
    assert not req.authorizes_patch_application and not req.authorizes_inference
    assert sha256(req.canonical_bytes()).hexdigest()==digest


@pytest.mark.parametrize("tamper",[
    {"authorizes_git_clone":True},
    {"authorizes_docker_call":True},
    {"authorizes_live_execution":True},
    {"authorizes_patch_application":True},
    {"requested_actions":("docker_compose_up",)},
    {"checkout_names":("01-sqli",)},
    {"scenario_ids":("unknown",)},
    {"approved_source_commit":PARENT,"approved_parent_commit":PARENT},
])
def test_c4a_schema_refuses_escalation_or_scope_drift(request_env,tamper):
    _,_,req,_,_=request_env
    with pytest.raises(ValidationError):
        C4AReadinessRequest.model_validate({**req.model_dump(),**tamper})


@pytest.mark.parametrize("tamper",["old-commit","old-tree","append-whitespace"])
def test_c4a_old_commit_tree_and_noncanonical_bytes_denied(request_env,tamper):
    root,_,req,path,digest=request_env
    if tamper=="old-commit":
        other=req.model_copy(update={"approved_source_commit":PARENT}).canonical_bytes()
    elif tamper=="old-tree":
        other=req.model_copy(update={"approved_source_tree":"20ceaf0ff8c976e794687ab76f9d963ed8765775"}).canonical_bytes()
    else:
        other=req.canonical_bytes()+b" "
    path.write_bytes(other)
    with pytest.raises(C4AAdmissionBlocked,match="bytes/hash mismatch"):
        load_mock_external_request(root=root,external_path=path,trusted_sha256=digest)


def test_c4a_different_source_hash_rejected(request_env):
    root,_,_,path,digest=request_env
    target=root/"compose.yaml"
    target.write_bytes(target.read_bytes()+b"\n#changed\n")
    with pytest.raises(C4AAdmissionBlocked,match="source policy drift"):
        load_mock_external_request(root=root,external_path=path,trusted_sha256=digest)


def test_c4a_external_manifest_must_be_outside_source(request_env):
    root,_,req,_,_=request_env
    path=root/"internal.json"
    path.write_bytes(req.canonical_bytes())
    with pytest.raises(C4AAdmissionBlocked,match="cannot be inside source root"):
        load_mock_external_request(root=root,external_path=path,
                                   trusted_sha256=sha256(path.read_bytes()).hexdigest())


def test_c4a_good_private_path_guard_still_mock_only():
    home,run,watcher,calls=private_mock_factory()
    result=inspect_private_root_mock(trusted_home=home,proposed_run_root=run,
                    expected_uid=1000,protected_roots=(home/"fyp-project",),
                    fs_observer=watcher)
    assert result.private_parent_static_checks_pass and not result.ready_for_live
    assert len(calls)==6 and result.checked_existing_paths[-1]==str(run.parent)


@pytest.mark.parametrize("ancestor",[
    Path("/home/mockuser"),Path("/home/mockuser/.local"),
    Path("/home/mockuser/.local/state"),
])
def test_c4a_group_or_world_writable_ancestor_blocked(ancestor):
    home,run,probe,_=private_mock_factory(existing_mode_overrides={ancestor:0o777})
    row=inspect_private_root_mock(trusted_home=home,proposed_run_root=run,
                  expected_uid=1000,protected_roots=(),fs_observer=probe)
    assert not row.private_parent_static_checks_pass
    assert any("writable ancestor" in r for r in row.reasons)


def test_c4a_symlink_ancestor_denied():
    item=Path("/home/mockuser/.local")
    home,run,probe,_=private_mock_factory(symlinks=(item,))
    row=inspect_private_root_mock(trusted_home=home,proposed_run_root=run,
                     expected_uid=1000,protected_roots=(),fs_observer=probe)
    assert not row.private_parent_static_checks_pass
    assert any("symlink" in r for r in row.reasons)


def test_c4a_foreign_owner_denied():
    item=Path("/home/mockuser/.local/state")
    home,run,probe,_=private_mock_factory(owner_overrides={item:2000})
    row=inspect_private_root_mock(trusted_home=home,proposed_run_root=run,
                     expected_uid=1000,protected_roots=(),fs_observer=probe)
    assert not row.private_parent_static_checks_pass
    assert any("foreign owner" in r for r in row.reasons)


@pytest.mark.parametrize("occupied",[True,False])
def test_c4a_existing_or_new_root(occupied):
    home,run,probe,_=private_mock_factory(occupied=occupied)
    row=inspect_private_root_mock(trusted_home=home,proposed_run_root=run,
                     expected_uid=1000,protected_roots=(),fs_observer=probe)
    assert row.private_parent_static_checks_pass is not occupied


def test_c4a_missing_parent_denied():
    item=Path("/home/mockuser/.local/state")
    home,run,probe,_=private_mock_factory(missing=(item,))
    row=inspect_private_root_mock(trusted_home=home,proposed_run_root=run,
                     expected_uid=1000,protected_roots=(),fs_observer=probe)
    assert not row.private_parent_static_checks_pass
    assert any("parent missing" in r for r in row.reasons)


def test_c4a_overlap_protected_repository_denied():
    home,run,probe,_=private_mock_factory()
    row=inspect_private_root_mock(trusted_home=home,proposed_run_root=run,
        expected_uid=1000,protected_roots=(home/".local/state",),fs_observer=probe)
    assert not row.private_parent_static_checks_pass
    assert any("overlaps protected" in r for r in row.reasons)


def test_c4a_relative_or_dotdot_root_refused():
    home,run,probe,_=private_mock_factory()
    with pytest.raises(C4AGuardBlocked):
        inspect_private_root_mock(trusted_home=home,proposed_run_root=Path("relative"),
                      expected_uid=1000,protected_roots=(),fs_observer=probe)
    with pytest.raises(C4AGuardBlocked):
        inspect_private_root_mock(trusted_home=home,
                      proposed_run_root=home/".."/"elsewhere",
                      expected_uid=1000,protected_roots=(),fs_observer=probe)


def test_c4a_clean_git_main_mock_succeeds_but_unattested(request_env):
    _,_,req,_,_=request_env
    path,runner,source,alternates,calls=mock_git_factory(req)
    result=inspect_git_main_mock(checkout=path,checkout_name="01-sqli",
                     admission=req,runner=runner,
                     source_hash_observer=source,
                     alternates_path_exists_observer=alternates)
    assert result.checkout_readonly_checks_pass and not result.ready_for_live
    assert result.observed_head==COMMIT and result.observed_tree==TREE
    assert len(calls)==9 and all(x[0]=="git" for x in calls)


@pytest.mark.parametrize("cmd,value",[
    (("rev-parse","HEAD"),PARENT),
    (("rev-parse","HEAD^{tree}"),"20ceaf0ff8c976e794687ab76f9d963ed8765775"),
    (("rev-parse","HEAD^"),"6b7224f077af0c300d79e6e6a3a98a215fe3ff73"),
    (("symbolic-ref","--quiet","--short","HEAD"),"detached"),
    (("symbolic-ref","--quiet","--short","HEAD"),"agent-patch/random"),
    (("rev-parse","refs/heads/main"),PARENT),
    (("status","--porcelain=v1","--untracked-files=all"),"?? synthetic.log"),
    (("rev-parse","--is-shallow-repository"),"true"),
    (("remote",),"origin"),
    (("rev-parse","--path-format=absolute","--git-common-dir"),"/shared/objects/.git"),
])
def test_c4a_mock_git_rejects_wrong_identity(request_env,cmd,value):
    _,_,req,_,_=request_env
    dest,runner,src,alternate,calls=mock_git_factory(req,overrides={cmd:value})
    result=inspect_git_main_mock(checkout=dest,checkout_name="01-sqli",
        admission=req,runner=runner,source_hash_observer=src,
        alternates_path_exists_observer=alternate)
    assert not result.checkout_readonly_checks_pass and not result.ready_for_live
    assert result.reasons


@pytest.mark.parametrize("issue",["alternates","source","failed-command","name"])
def test_c4a_git_other_negative_paths(request_env,issue):
    _,_,req,_,_=request_env
    path,runner,src,alternate,calls=mock_git_factory(
        req,alternates=issue=="alternates",
        source_override="compose.yaml" if issue=="source" else None,
        failure=("rev-parse","HEAD") if issue=="failed-command" else None)
    if issue=="name":
        with pytest.raises(C4AGuardBlocked):
            inspect_git_main_mock(checkout=path,checkout_name="02-xss",
                admission=req,runner=runner,source_hash_observer=src,
                alternates_path_exists_observer=alternate)
    else:
        output=inspect_git_main_mock(checkout=path,checkout_name="01-sqli",
                admission=req,runner=runner,source_hash_observer=src,
                alternates_path_exists_observer=alternate)
        assert not output.checkout_readonly_checks_pass and output.reasons


def test_c4a_empty_exclusive_docker_mock_is_never_live_approval(request_env):
    req=request_env[2]
    owner,runner,calls,_,_=mock_docker_factory()
    result=inspect_docker_ownership_mock(admission=req,owner=owner,runner=runner)
    assert result.mock_readonly_checks_pass
    assert not result.ready_for_live and not result.safe_to_mutate
    assert len(calls)==9
    assert all(any(word in call for word in ("show","inspect","info","ps","ls")) for call in calls)
    assert all(not any(word in call for word in ("build","up","down","exec","rm","prune","stop")) for call in calls)


@pytest.mark.parametrize("claim",[
    {"operator_approved":False},{"dedicated_exclusive":False},
    {"exclusive_lease_valid":False},{"daemon_host_port_8000_free":False},
    {"approved_context":"other-context"},{"approved_daemon_id":"other-daemon"},
    {"approved_endpoint":"tcp://unknown"},
])
def test_c4a_docker_missing_owner_or_port_or_binding(request_env,claim):
    req=request_env[2]
    owner,runner,_,_,_=mock_docker_factory()
    owner=owner.model_copy(update=claim)
    output=inspect_docker_ownership_mock(admission=req,owner=owner,runner=runner)
    assert not output.mock_readonly_checks_pass
    assert not output.ready_for_live and output.reasons


@pytest.mark.parametrize("change",["first-context","last-context","daemon-change",
                                   "bad-context-inspect","bad-json","error"])
def test_c4a_docker_context_daemon_error_drift_denied(request_env,change):
    req=request_env[2]
    def mutate(values,rows):
        if change=="first-context":values[0]="wrong"
        if change=="last-context":values[-1]="wrong"
        if change=="daemon-change":values[7]=json.dumps({"ID":"wrong-daemon"})
        if change=="bad-context-inspect":values[1]=json.dumps({"Name":"unexpected","Endpoints":{}})
        if change=="bad-json":values[2]="not JSON"
    owner,runner,_,_,_=mock_docker_factory(changes=mutate if change!="error" else None,
                                               fail_index=3 if change=="error" else None)
    output=inspect_docker_ownership_mock(admission=req,owner=owner,runner=runner)
    assert not output.mock_readonly_checks_pass
    assert output.reasons


@pytest.mark.parametrize("resource",["container","volume","network","image"])
def test_c4a_docker_foreign_resource_collision_denied(request_env,resource):
    req=request_env[2]
    def mutate(values,rows):
        if resource=="container":values[3]=json.dumps({"Names":"fyp-vulnerable-store","ID":"foreign"})
        if resource=="volume":values[5]=json.dumps({"Name":"fyp-red-blue-lab_store-runtime"})
        if resource=="network":rows["networks"].append({"Name":"fyp-red-blue-lab_security-lab"})
        if resource=="image":values[6]=json.dumps({"Repository":"fyp-red-blue-lab","Tag":"local"})
    owner,runner,calls,_,_=mock_docker_factory(changes=mutate)
    output=inspect_docker_ownership_mock(admission=req,owner=owner,runner=runner)
    assert not output.mock_readonly_checks_pass and not output.ready_for_live
    assert output.reasons and len(calls)==9


def test_c4a_all_readiness_reports_explicitly_mock_only(request_env):
    req=request_env[2]
    home,run,probe,_=private_mock_factory()
    fs=inspect_private_root_mock(trusted_home=home,proposed_run_root=run,
                expected_uid=1000,protected_roots=(),fs_observer=probe)
    checkout,runner,src,alternate,_=mock_git_factory(req)
    git=inspect_git_main_mock(checkout=checkout,checkout_name="01-sqli",
                        admission=req,runner=runner,source_hash_observer=src,
                        alternates_path_exists_observer=alternate)
    owner,docker_runner,_,_,_=mock_docker_factory()
    docker=inspect_docker_ownership_mock(admission=req,owner=owner,runner=docker_runner)
    assert fs.private_parent_static_checks_pass and git.checkout_readonly_checks_pass
    assert docker.mock_readonly_checks_pass
    assert fs.ready_for_live is git.ready_for_live is docker.ready_for_live is False
    assert req.authorizes_live_execution is False

@pytest.mark.parametrize("ancestor",[Path("/"),Path("/home")])
def test_c4a_system_ancestor_world_writable_denied(ancestor):
    home,run,probe,_=private_mock_factory(existing_mode_overrides={ancestor:0o777})
    result=inspect_private_root_mock(trusted_home=home,proposed_run_root=run,
             expected_uid=1000,protected_roots=(),fs_observer=probe)
    assert not result.private_parent_static_checks_pass
    assert any("writable ancestor" in x for x in result.reasons)


def test_c4a_world_ancestor_symlink_denied():
    home,run,probe,_=private_mock_factory(symlinks=(Path("/home"),))
    result=inspect_private_root_mock(trusted_home=home,proposed_run_root=run,
             expected_uid=1000,protected_roots=(),fs_observer=probe)
    assert not result.private_parent_static_checks_pass
    assert any("symlink" in x for x in result.reasons)


def test_c4a_unrelated_preexisting_image_unowned_denied(request_env):
    req=request_env[2]
    def change(values,rows):
        values[6]=json.dumps({"Repository":"unrelated-foreign","Tag":"test"})
    owner,runner,_,_,_=mock_docker_factory(changes=change)
    result=inspect_docker_ownership_mock(admission=req,owner=owner,runner=runner)
    assert not result.mock_readonly_checks_pass
    assert any("unowned or unexplained" in x for x in result.reasons)
