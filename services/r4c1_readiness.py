"""R4-C1 read-only Docker and Git-baseline audits with required injected runners.

No actual Docker/Git calls are possible without supplying a runner.
Neither audit can grant live authorization or exclusive ownership on its own.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
from typing import Callable, Literal

from pydantic import BaseModel, ConfigDict

from services.r4c1_executor_capture import APPROVED_COMMIT

APPROVED_TREE = "612cbe74627cfef1a736bb0506f038b3513c82db"
EXPECTED_PROJECT = "fyp-red-blue-lab"
EXPECTED_NAMES = frozenset(("fyp-vulnerable-store", "fyp-controlled-executor"))
EXPECTED_IMAGE = "fyp-red-blue-lab:local"
DOCKER_CMDS = (
    ("docker", "context", "show"),
    ("docker", "context", "inspect", "--format", "{{json .}}"),
    ("docker", "info", "--format", "{{json .}}"),
    ("docker", "ps", "-a", "--format", "{{json .}}"),
    ("docker", "network", "ls", "--format", "{{json .}}"),
    ("docker", "volume", "ls", "--format", "{{json .}}"),
    ("docker", "image", "ls", "--format", "{{json .}}"),
    ("docker", "context", "show"),
    ("docker", "info", "--format", "{{json .}}"),
)
GIT_CMDS = (
    ("rev-parse", "HEAD"),
    ("rev-parse", "HEAD^{tree}"),
    ("branch", "--show-current"),
    ("status", "--porcelain=v1", "--untracked-files=all"),
    ("rev-parse", "--is-shallow-repository"),
    ("rev-parse", "--git-common-dir"),
    ("rev-parse", "--git-path", "objects/info/alternates"),
    ("remote", "-v"),
)


@dataclass(frozen=True, slots=True)
class ObservedProcess:
    returncode: int
    stdout: str
    stderr: str = ""


class ReadinessReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["r4c1-readonly-mocked-v1"] = "r4c1-readonly-mocked-v1"
    scope: Literal["mock_injected_no_live_attestation"] = "mock_injected_no_live_attestation"
    kind: Literal["docker_discovery", "git_baseline"]
    static_checks_pass: bool
    ready_for_live: Literal[False] = False
    safe_to_mutate: Literal[False] = False
    reasons: tuple[str, ...]
    audited_commands: tuple[tuple[str, ...], ...]
    fingerprint_sha256: str


def _parse_lines(text: str) -> list[dict]:
    if not text.strip():
        return []
    rows = []
    for line in text.splitlines():
        item = json.loads(line)
        if not isinstance(item, dict):
            raise ValueError("inventory row must be a JSON object")
        rows.append(item)
    return rows


def inspect_docker_mock(
    runner: Callable[[tuple[str, ...]], ObservedProcess],
    *,
    context_expected: str,
    operator_claims_exclusive_daemon: bool,
    host_port_8000_confirmed_free: bool,
) -> ReadinessReport:
    """Docker read-only command intent. Runner MUST be injected from offline mocks."""
    reasons = []
    outputs = []
    commands = []
    for command in DOCKER_CMDS:
        commands.append(command)
        try:
            p = runner(command)
            if not isinstance(p, ObservedProcess) or p.returncode != 0 or p.stderr:
                raise ValueError("Docker discovery command failed")
            if len(p.stdout.encode("utf-8")) > 128 * 1024:
                raise ValueError("Docker inventory too large")
            outputs.append(p.stdout)
        except Exception:
            reasons.append("Docker read-only discovery incomplete")
            break
    if len(outputs) == len(DOCKER_CMDS):
        try:
            before, context, info, containers, networks, volumes, images, after, after_info = outputs
            if not context_expected or before.strip() != context_expected or after.strip() != before.strip():
                reasons.append("Docker context drift or unexpected context")
            parsed_context = json.loads(context)
            parsed_info = json.loads(info)
            parsed_after_info = json.loads(after_info)
            if not isinstance(parsed_context, dict) or not isinstance(parsed_info, dict) or not isinstance(parsed_after_info, dict):
                raise ValueError("invalid Docker context or daemon record")
            if not parsed_info.get("ID") or not parsed_context.get("Name"):
                raise ValueError("missing Docker daemon/context identity")
            if parsed_context["Name"] != context_expected:
                reasons.append("Docker context inspect mismatch")
            if parsed_info["ID"] != parsed_after_info.get("ID"):
                reasons.append("Docker daemon identity changed during discovery")
            for row in _parse_lines(containers):
                if (row.get("Names") in EXPECTED_NAMES
                    or EXPECTED_PROJECT in str(row.get("Labels", row.get("Label", "")))
                    or EXPECTED_PROJECT in row.get("Image", "")):
                    reasons.append("fixed-name or Compose-project container already exists")
            for row in _parse_lines(networks):
                if EXPECTED_PROJECT in row.get("Name", ""):
                    reasons.append("preexisting fixed Compose network")
            for row in _parse_lines(volumes):
                if EXPECTED_PROJECT in row.get("Name", ""):
                    reasons.append("preexisting Compose volume")
            for row in _parse_lines(images):
                if row.get("Repository", "") + ":" + row.get("Tag", "") == EXPECTED_IMAGE:
                    reasons.append("fixed-tag image already exists and ownership is unknown")
        except Exception:
            reasons.append("Docker inventory parsing or attribution failed")
    if not operator_claims_exclusive_daemon:
        reasons.append("exclusive Docker daemon authorization unconfirmed")
    if not host_port_8000_confirmed_free:
        reasons.append("daemon-host loopback port 8000 ownership unconfirmed")
    if not outputs:
        reasons.append("no Docker inventory evidence")
    return ReadinessReport(
        kind="docker_discovery",
        static_checks_pass=not reasons,
        reasons=tuple(reasons + ["read-only mocked audit never establishes live ownership"]),
        audited_commands=tuple(commands),
        fingerprint_sha256=sha256(
            json.dumps(outputs, separators=(",", ":"), sort_keys=True).encode()).hexdigest(),
    )


def inspect_git_baseline_mock(
    runner: Callable[[tuple[str, ...], Path], ObservedProcess],
    *,
    destination: Path,
    protected_paths: tuple[Path, ...],
    expected_commit: str = APPROVED_COMMIT,
    expected_tree: str = APPROVED_TREE,
) -> ReadinessReport:
    """Static verification of mock-discovered disposable main; never performs Git."""
    reasons=[]
    destination=destination.resolve(strict=False)
    for protected in protected_paths:
        guarded=protected.resolve(strict=False)
        if destination==guarded or guarded in destination.parents:
            reasons.append("proposed destination inside protected repository")
    commands=[]
    outputs=[]
    for args in GIT_CMDS:
        argv=("git", "-C", str(destination), *args)
        commands.append(argv)
        try:
            p=runner(argv, destination)
            if not isinstance(p, ObservedProcess) or p.returncode!=0 or p.stderr:
                raise ValueError("mocked read-only Git query failed")
            if len(p.stdout)>16384:
                raise ValueError("Git response too large")
            outputs.append(p.stdout.strip())
        except Exception:
            reasons.append("mock Git baseline inspection incomplete")
            break
    if len(outputs)==len(GIT_CMDS):
        head,tree,branch,status,shallow,common_dir,alternates,remotes=outputs
        if head!=expected_commit or tree!=expected_tree:
            reasons.append("Git commit or approved tree mismatch")
        if branch!="main":
            reasons.append("disposable baseline branch is not main")
        if status:
            reasons.append("disposable baseline has staged/unstaged/untracked files")
        if shallow!="false":
            reasons.append("shallow repository not allowed")
        expected_common=destination/".git"
        if Path(common_dir).resolve(strict=False)!=expected_common:
            reasons.append("shared Git common directory or unexpected Git dir")
        alt_path=Path(alternates)
        if alternates and alt_path.exists():
            reasons.append("shared Git object alternates present")
        if remotes:
            reasons.append("disposable checkout still has a remote")
    return ReadinessReport(
        kind="git_baseline",
        static_checks_pass=not reasons,
        reasons=tuple(reasons + ["mock Git baseline audit cannot create or authorize a clone"]),
        audited_commands=tuple(commands),
        fingerprint_sha256=sha256(
            json.dumps(outputs, separators=(",", ":"), sort_keys=True).encode()).hexdigest(),
    )
