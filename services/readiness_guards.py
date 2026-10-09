"""R4-C4A *offline-mock-only* filesystem, Git and Docker readiness guards.

Every external observation is provided by a required injected callback.
No subprocess, Git CLI, Docker CLI, network, clone, mutation or attestation.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Callable, Literal

from pydantic import BaseModel, ConfigDict, Field

from schemas.readiness_request import (
    C4AReadinessRequest, DISPOSABLE_NAMES,
)

SCENARIO_SOURCE = "dummy_apps/vulnerable_store/app/scenario_routes.py"
DOCKER_PROJECT = "fyp-red-blue-lab"
BLOCKED_FIXED_NAMES = (
    "fyp-vulnerable-store","fyp-controlled-executor",
    "fyp-red-blue-lab","fyp-red-blue-lab_security-lab",
    "fyp-red-blue-lab_store-runtime","fyp-red-blue-lab:local",
)
SHA256 = r"^[a-f0-9]{64}$"


class C4AGuardBlocked(RuntimeError):
    pass


class MockFSState(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    provenance: Literal["injected_mock_fs"] = "injected_mock_fs"
    exists: bool
    is_directory: bool = False
    is_symlink: bool = False
    owner_uid: int = Field(ge=0)
    unix_mode: int = Field(ge=0, le=0o7777)


class C4APathReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["r4c4a-fs-preflight-v1"] = "r4c4a-fs-preflight-v1"
    evidence_origin: Literal["injected_mock_fs"] = "injected_mock_fs"
    ready_for_live: Literal[False] = False
    private_parent_static_checks_pass: bool
    proposed_run_root: str
    checked_existing_paths: tuple[str, ...]
    reasons: tuple[str, ...]


def _lexical_absolute(path: Path) -> Path:
    text=str(path)
    if (not path.is_absolute() or "\x00" in text or
        any(part in (".","..") for part in text.split("/"))):
        raise C4AGuardBlocked("unsafe noncanonical absolute filesystem path")
    return path


def _contained(root: Path, candidate: Path) -> bool:
    return candidate == root or root in candidate.parents


def inspect_private_root_mock(
    *, trusted_home: Path, proposed_run_root: Path, expected_uid: int,
    protected_roots: tuple[Path, ...],
    fs_observer: Callable[[Path], MockFSState],
) -> C4APathReport:
    """Mock preflight of existing path ancestors. Does NOT create directories."""
    home=_lexical_absolute(trusted_home)
    proposed=_lexical_absolute(proposed_run_root)
    protected=tuple(_lexical_absolute(x) for x in protected_roots)
    reasons=[]
    traversed=[]
    if not _contained(home, proposed) or proposed==home:
        reasons.append("proposed root is not below trusted private home")
    for path in protected:
        if _contained(path,proposed) or _contained(proposed,path):
            reasons.append("proposed root overlaps protected source/evidence location")
    if not reasons:
        chain=[]
        parent=proposed.parent
        while True:
            chain.append(parent)
            if parent==parent.parent:
                break
            parent=parent.parent
        for item in reversed(chain):
            state=fs_observer(item)
            traversed.append(str(item))
            if not isinstance(state,MockFSState):
                reasons.append("mock filesystem observer returned invalid object")
                break
            if not state.exists:
                reasons.append(f"existing parent missing: {item}")
            if state.is_symlink or not state.is_directory:
                reasons.append(f"symlink or nondirectory in parent chain: {item}")
            # Before the trusted home, root-owned system parents are expected.
            # The home and its descendants must be owned by the operator.
            allowed_owners = ((0,expected_uid) if not _contained(home,item)
                              else (expected_uid,))
            if state.owner_uid not in allowed_owners:
                reasons.append(f"foreign owner of parent: {item}")
            if state.unix_mode & 0o022:
                reasons.append(f"group/other writable ancestor: {item}")
        final=fs_observer(proposed)
        if not isinstance(final,MockFSState):
            reasons.append("invalid proposed destination observation")
        elif final.exists or final.is_symlink:
            reasons.append("requested new run root already exists or is symlink")
    return C4APathReport(
        private_parent_static_checks_pass=not reasons,
        proposed_run_root=str(proposed),
        checked_existing_paths=tuple(traversed),
        reasons=tuple(reasons))


@dataclass(frozen=True)
class MockProcessOutput:
    returncode: int
    stdout: str
    stderr: str = ""


class C4AGitGuardReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["r4c4a-mocked-git-main-v1"] = "r4c4a-mocked-git-main-v1"
    evidence_origin: Literal["injected_mock_git_responses"] = "injected_mock_git_responses"
    checkout_readonly_checks_pass: bool
    ready_for_live: Literal[False] = False
    checkout_name: str
    observed_head: str | None = None
    observed_tree: str | None = None
    expected_commit: str
    expected_tree: str
    commands_issued_to_mock: tuple[tuple[str, ...], ...]
    reasons: tuple[str, ...]


def inspect_git_main_mock(
    *, checkout: Path, checkout_name: str, admission: C4AReadinessRequest,
    runner: Callable[[tuple[str, ...], Path], MockProcessOutput],
    source_hash_observer: Callable[[str], str],
    alternates_path_exists_observer: Callable[[], bool],
) -> C4AGitGuardReport:
    """No real Git CLI. An injected command runner supplies ALL results."""
    root=_lexical_absolute(checkout)
    if checkout_name not in DISPOSABLE_NAMES or root.name != checkout_name:
        raise C4AGuardBlocked("Git checkout is not one of the exact three cases")
    def argv(*rest: str) -> tuple[str,...]:
        return ("git","-C",str(root),*rest)
    commands=(
      argv("rev-parse","HEAD"),
      argv("rev-parse","HEAD^{tree}"),
      argv("rev-parse","HEAD^"),
      argv("symbolic-ref","--quiet","--short","HEAD"),
      argv("rev-parse","refs/heads/main"),
      argv("status","--porcelain=v1","--untracked-files=all"),
      argv("rev-parse","--is-shallow-repository"),
      argv("remote"),
      argv("rev-parse","--path-format=absolute","--git-common-dir"),
    )
    reasons=[]
    results=[]
    for command in commands:
        result=runner(command,root)
        if not isinstance(result,MockProcessOutput) or result.returncode!=0:
            reasons.append("mock read-only Git subprocess returned invalid/nonzero status")
            results.append("")
        elif len(result.stdout)>8192 or len(result.stderr)>8192 or result.stderr:
            reasons.append("unbounded/ambiguous Git mock output")
            results.append("")
        else:
            results.append(result.stdout.strip())
    head,tree,parent,branch,main,status,shallow,remotes,common=results
    if head!=admission.approved_source_commit or main!=head:
        reasons.append("Git main HEAD or ref not at frozen approved commit")
    if tree!=admission.approved_source_tree or parent!=admission.approved_parent_commit:
        reasons.append("Git tree or parent differs from externally approved identity")
    if branch!="main" or status!="":
        reasons.append("Git branch not main or working tree dirty/untracked")
    if shallow!="false" or remotes:
        reasons.append("Git source shallow or has a remote")
    if common!=str(root/".git"):
        reasons.append("Git common directory not private within checkout")
    if alternates_path_exists_observer():
        reasons.append("Git object alternates present")
    for name,expected in admission.source_hashes.items():
        if source_hash_observer(name)!=expected:
            reasons.append(f"mock Git checkout source/policy hash mismatch: {name}")
    return C4AGitGuardReport(
        checkout_readonly_checks_pass=not reasons,checkout_name=checkout_name,
        observed_head=head or None, observed_tree=tree or None,
        expected_commit=admission.approved_source_commit,
        expected_tree=admission.approved_source_tree,
        commands_issued_to_mock=commands,reasons=tuple(reasons))


class MockDockerOperatorClaim(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["r4c4a-injected-owner-claim-v1"] = "r4c4a-injected-owner-claim-v1"
    evidence_origin: Literal["operator_claim_mock_not_attestation"] = "operator_claim_mock_not_attestation"
    operator_approved: bool
    dedicated_exclusive: bool
    exclusive_lease_valid: bool
    daemon_host_port_8000_free: bool
    approved_context: str
    approved_daemon_id: str
    approved_endpoint: str


class C4ADockerGuardReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["r4c4a-mocked-docker-readonly-audit-v1"] = "r4c4a-mocked-docker-readonly-audit-v1"
    evidence_origin: Literal["injected_mock_docker_cli_responses"] = "injected_mock_docker_cli_responses"
    mock_readonly_checks_pass: bool
    ready_for_live: Literal[False] = False
    safe_to_mutate: Literal[False] = False
    inspected_context: str
    observed_daemon_id: str | None = None
    commands_issued_to_mock: tuple[tuple[str, ...], ...]
    reasons: tuple[str, ...]


def _parse_json_output(text: str):
    try:
        return json.loads(text)
    except (TypeError,ValueError):
        return None


def _parse_lines(text: str):
    if not text.strip():
        return []
    lines=text.splitlines()
    if len(lines)>512:
        return None
    rows=[_parse_json_output(x) for x in lines]
    if any(not isinstance(x,dict) for x in rows):
        return None
    return rows


def inspect_docker_ownership_mock(
    *, admission: C4AReadinessRequest,
    owner: MockDockerOperatorClaim,
    runner: Callable[[tuple[str, ...]], MockProcessOutput],
) -> C4ADockerGuardReport:
    """Only injected results. Fail closed on ambiguous inventory, never mutate."""
    ctx=admission.intended_daemon_context
    commands=(
        ("docker","context","show"),
        ("docker","context","inspect",ctx,"--format","{{json .}}"),
        ("docker","--context",ctx,"info","--format","{{json .}}"),
        ("docker","--context",ctx,"ps","-a","--no-trunc","--format","{{json .}}"),
        ("docker","--context",ctx,"network","ls","--format","{{json .}}"),
        ("docker","--context",ctx,"volume","ls","--format","{{json .}}"),
        ("docker","--context",ctx,"image","ls","--digests","--format","{{json .}}"),
        ("docker","--context",ctx,"info","--format","{{json .}}"),
        ("docker","context","show"),
    )
    reasons=[]
    if not owner.operator_approved or not owner.dedicated_exclusive or not owner.exclusive_lease_valid:
        reasons.append("independent operator/exclusivity/lease proof absent (mock claim)")
    if not owner.daemon_host_port_8000_free:
        reasons.append("daemon-host port 8000 not proven free")
    if owner.approved_context!=ctx:
        reasons.append("requested Docker context differs from mock owner claim")
    outs=[]
    for command in commands:
        result=runner(command)
        if not isinstance(result,MockProcessOutput) or result.returncode!=0:
            reasons.append("Docker read-only mock command failed")
            outs.append("")
        elif result.stderr or len(result.stdout)>65536:
            reasons.append("Docker mock command produced unexpected stderr or oversized output")
            outs.append("")
        else:
            outs.append(result.stdout.strip())
    first_ctx,raw_context,first_info,ps,nets,vols,images,final_info,last_ctx=outs
    context=_parse_json_output(raw_context)
    info0=_parse_json_output(first_info)
    info1=_parse_json_output(final_info)
    if first_ctx!=ctx or last_ctx!=ctx:
        reasons.append("Docker context changed during mock audit")
    if not isinstance(context,dict) or context.get("Name")!=ctx or (
        context.get("Endpoints",{}).get("docker",{}).get("Host") != owner.approved_endpoint
    ):
        reasons.append("Docker context endpoint identity differs")
    daemon=None
    if not isinstance(info0,dict) or not isinstance(info1,dict):
        reasons.append("Docker daemon information invalid")
    else:
        daemon=info0.get("ID")
        if not daemon or daemon!=info1.get("ID") or daemon!=owner.approved_daemon_id:
            reasons.append("Docker daemon identity changed or is not owned")
    parsed=[_parse_lines(x) for x in (ps,nets,vols,images)]
    if any(rows is None for rows in parsed):
        reasons.append("Docker resource listing unparsable or incomplete")
    else:
        containers,networks,volumes,images_rows=parsed
        # For this initial exclusive-dedicated mock contract, fail closed for
        # ANY leftover container, named volume or custom network. The only
        # allowed network names are built-in Docker networks.
        if containers:
            reasons.append("unowned or unknown Docker container already exists")
        if volumes:
            reasons.append("unowned or unknown Docker volume already exists")
        for item in networks:
            if item.get("Name") not in ("bridge","host","none"):
                reasons.append("unowned custom Docker network already exists")
        for image in images_rows:
            if not isinstance(image,dict):
                reasons.append("Docker image inventory incomplete")
            elif (image.get("Repository") == DOCKER_PROJECT or
                  image.get("Repository") == "fyp-red-blue-lab" or
                  any(v in json.dumps(image,sort_keys=True) for v in BLOCKED_FIXED_NAMES)):
                reasons.append("fixed project image tag or label collision")
            else:
                reasons.append("unowned or unexplained pre-existing Docker image")
    return C4ADockerGuardReport(
        mock_readonly_checks_pass=not reasons,inspected_context=ctx,
        observed_daemon_id=daemon,
        commands_issued_to_mock=commands,reasons=tuple(reasons))
