"""R4-A static-only Git/Docker pre-live planning checks.

NO git, Docker, network, filesystem write, or shell execution.
Never asserts runtime container ownership from merely static configuration.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, model_validator

from services.trusted_remediation_compiler import EXPECTED_SOURCE_SHA256, SOURCE

EXPECTED_COMPOSE_PROJECT="fyp-red-blue-lab"
EXPECTED_CONTAINERS=frozenset({"fyp-vulnerable-store","fyp-controlled-executor"})
EXPECTED_PORT="127.0.0.1:8000:8000"
EXPECTED_GIT_BASE="main"
COMMIT=re.compile(r"^[0-9a-f]{40}$")


class R4AStaticReadiness(BaseModel):
    model_config=ConfigDict(frozen=True,extra="forbid")
    schema_version: str = "r4a-static-preflight-v1"
    passed_static_checks: bool
    ready_for_live: bool = False
    reasons: tuple[str,...]
    proposed_checkout_path: str
    approved_integration_commit: str | None
    source_file_sha256: str | None
    compose_sha256: str | None
    git_policy_sha256: str | None
    docker_ownership_verified: bool = False
    git_clone_created: bool = False
    docker_invoked: bool = False

    @model_validator(mode="after")
    def never_assert_live_authorization(self):
        if self.ready_for_live or self.docker_ownership_verified or self.git_clone_created or self.docker_invoked:
            raise ValueError("static preflight cannot assert runtime readiness or side effects")
        return self


@dataclass(frozen=True)
class R4AStaticPlan:
    primary_root: Path
    sandbox_root: Path
    proposed_checkout_path: Path
    approved_integration_commit: str | None = None


def inspect_static_plan(plan: R4AStaticPlan) -> R4AStaticReadiness:
    """Pure read-only checks; logs proposed paths but NEVER allocates them."""
    reasons=[]
    static_failures=[]
    primary=plan.primary_root.resolve(strict=False)
    sandbox=plan.sandbox_root.resolve(strict=False)
    desired=plan.proposed_checkout_path.resolve(strict=False)

    def descendant(path,root):
        return path==root or root in path.parents

    if descendant(desired,primary) or descendant(desired,sandbox):
        static_failures.append("disposable checkout overlaps protected repository")
    if desired.exists() or desired.is_symlink():
        static_failures.append("proposed checkout already exists; no overwrite")
    if not plan.proposed_checkout_path.is_absolute():
        static_failures.append("proposed checkout path is not absolute")
    if not COMMIT.fullmatch(plan.approved_integration_commit or ""):
        static_failures.append("separately approved immutable integration commit missing")
    path=sandbox/SOURCE
    source_sha=None
    if path.is_file() and not path.is_symlink():
        source_sha=hashlib.sha256(path.read_bytes()).hexdigest()
    if source_sha!=EXPECTED_SOURCE_SHA256:
        static_failures.append("sandbox original vulnerable source changed")
    compose=sandbox/"compose.yaml"
    comp_sha=None
    if compose.is_file() and not compose.is_symlink():
        contents=compose.read_text()
        comp_sha=hashlib.sha256(compose.read_bytes()).hexdigest()
        import yaml
        try:
            parsed=yaml.safe_load(contents)
        except yaml.YAMLError:
            parsed=None
        if not isinstance(parsed,dict):
            static_failures.append("invalid structured Compose configuration")
        else:
            services=parsed.get("services",{})
            network=parsed.get("networks",{}).get("security-lab",{})
            if parsed.get("name") != EXPECTED_COMPOSE_PROJECT:
                static_failures.append("Compose project name changed")
            if not isinstance(network,dict) or network.get("internal") is not True:
                static_failures.append("Compose security-lab internal network changed")
            if not isinstance(services,dict) or set(services)!={"vulnerable-store","controlled-executor"}:
                static_failures.append("Compose service allowlist changed")
            else:
                for name,expected_name in (
                    ("vulnerable-store","fyp-vulnerable-store"),
                    ("controlled-executor","fyp-controlled-executor"),
                ):
                    obj=services[name]
                    if not isinstance(obj,dict) or (
                        obj.get("container_name")!=expected_name or
                        obj.get("read_only") is not True or
                        obj.get("privileged") is not False or
                        obj.get("cap_drop")!=["ALL"] or
                        "no-new-privileges:true" not in obj.get("security_opt",[]) or
                        "security-lab" not in obj.get("networks",{})
                    ):
                        static_failures.append("Compose service hardening changed: "+name)
                if services["vulnerable-store"].get("ports")!=["127.0.0.1:8000:8000"]:
                    static_failures.append("Compose vulnerable-store loopback port changed")
                if services["controlled-executor"].get("ports"):
                    static_failures.append("Compose executor exposes unexpected host port")
    else:
        static_failures.append("compose configuration absent or symlink")
    gitpolicy=sandbox/"config/git-policy.json"
    policy_sha=None
    if gitpolicy.is_file() and not gitpolicy.is_symlink():
        import json
        try:
            value=json.loads(gitpolicy.read_bytes())
        except Exception:
            value={}
        policy_sha=hashlib.sha256(gitpolicy.read_bytes()).hexdigest()
        if value!={"baseline_branch":"main","patch_branch_prefix":"agent-patch"}:
            static_failures.append("Git branch policy changed")
    else:
        static_failures.append("Git policy absent or symlink")
    # Never infer process ownership, remote Docker state or commit authorization.
    reasons.extend(static_failures)
    reasons.extend((
        "exclusive Docker daemon/resource ownership NOT verified",
        "approved disposable main baseline NOT created or hash-verified",
        "real executor Red evidence NOT observed",
        "disposable accepted-commit permission NOT granted by this check",
        "live R4 verification still requires explicit user approval",
    ))
    return R4AStaticReadiness(
        passed_static_checks=(len(static_failures)==0),
        reasons=tuple(reasons),
        proposed_checkout_path=str(desired),
        approved_integration_commit=plan.approved_integration_commit,
        source_file_sha256=source_sha,compose_sha256=comp_sha,
        git_policy_sha256=policy_sha,
    )
