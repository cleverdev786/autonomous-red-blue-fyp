"""R4-C4A narrow external readiness request, offline simulation ONLY.

A SHA-256 pins the bytes of this request. It is NOT an operator's approval,
a signature, or permission to create clones / call Docker.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from schemas.r4c3a_admission import INITIAL_SCENARIO_SHA256
from schemas.r4a_red_observation import REGISTERED

REQUIRED_HASH_PATHS = (
    "compose.yaml",
    "config/git-policy.json",
    "config/verification-policy.json",
    "dummy_apps/vulnerable_store/app/scenario_routes.py",
)
DISPOSABLE_NAMES = ("01-sqli", "02-xss", "03-path")
REQUESTED_ACTIONS = (
    "prepare_three_disposable_git_main_checkouts",
    "inspect_exclusive_docker_daemon_read_only",
)
SHA40 = r"^[a-f0-9]{40}$"


class C4AAdmissionBlocked(ValueError):
    pass


class C4AReadinessRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["r4c4a-readiness-request-v1"] = "r4c4a-readiness-request-v1"
    scope: Literal["mock_readiness_contract_only"] = "mock_readiness_contract_only"
    authorizes_live_execution: Literal[False] = False
    authorizes_git_clone: Literal[False] = False
    authorizes_docker_call: Literal[False] = False
    authorizes_patch_application: Literal[False] = False
    authorizes_inference: Literal[False] = False
    requested_actions: tuple[str, ...] = REQUESTED_ACTIONS
    checkout_names: tuple[str, ...] = DISPOSABLE_NAMES
    approved_source_commit: str = Field(pattern=SHA40)
    approved_parent_commit: str = Field(pattern=SHA40)
    approved_source_tree: str = Field(pattern=SHA40)
    source_hashes: dict[str, str]
    scenario_ids: tuple[str, ...]
    intended_daemon_context: str
    operator_approval_reference: str
    run_id: str

    @model_validator(mode="after")
    def check_scope(self):
        if self.requested_actions != REQUESTED_ACTIONS:
            raise ValueError("request action scope changed")
        if self.checkout_names != DISPOSABLE_NAMES:
            raise ValueError("exact three independent checkout names required")
        if set(self.source_hashes) != set(REQUIRED_HASH_PATHS):
            raise ValueError("four exact source and policy digests required")
        if any(len(v) != 64 or any(ch not in "0123456789abcdef" for ch in v)
               for v in self.source_hashes.values()):
            raise ValueError("source SHA-256 invalid")
        if self.source_hashes["dummy_apps/vulnerable_store/app/scenario_routes.py"] != INITIAL_SCENARIO_SHA256:
            raise ValueError("approved original vulnerable source hash differs")
        if self.scenario_ids != tuple(REGISTERED):
            raise ValueError("registered scenario list changed")
        import re
        for name,value in (("run_id",self.run_id),
                           ("context",self.intended_daemon_context),
                           ("operator_approval_reference",self.operator_approval_reference)):
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}",value):
                raise ValueError(f"invalid bounded {name}")
        if self.approved_source_commit == self.approved_parent_commit:
            raise ValueError("approved parent cannot equal approved commit")
        return self

    def canonical_bytes(self) -> bytes:
        return (json.dumps(self.model_dump(mode="json"), sort_keys=True,
                           separators=(",", ":"),ensure_ascii=True) + "\n").encode("ascii")


def load_mock_external_request(
    *, root: Path, external_path: Path, trusted_sha256: str,
    require_hashes_of_source_files: bool = True,
) -> C4AReadinessRequest:
    """Byte-pinned read-only loader. Caller-provided hash is not an authorization."""
    if not isinstance(trusted_sha256,str) or len(trusted_sha256)!=64:
        raise C4AAdmissionBlocked("missing external digest")
    if any(ch not in "0123456789abcdef" for ch in trusted_sha256):
        raise C4AAdmissionBlocked("invalid trusted digest")
    if not root.is_dir() or root.is_symlink():
        raise C4AAdmissionBlocked("invalid source root")
    root=root.resolve(strict=True)
    if not external_path.is_absolute() or external_path.is_symlink() or not external_path.is_file():
        raise C4AAdmissionBlocked("external manifest must be absolute and regular")
    external_path=external_path.absolute()
    if external_path == root or root in external_path.parents:
        raise C4AAdmissionBlocked("admission manifest cannot be inside source root")
    raw=external_path.read_bytes()
    if len(raw)>8192 or sha256(raw).hexdigest()!=trusted_sha256:
        raise C4AAdmissionBlocked("external readiness request bytes/hash mismatch")
    try:
        parsed=C4AReadinessRequest.model_validate_json(raw)
        if parsed.canonical_bytes()!=raw:
            raise ValueError("noncanonical external readiness request")
    except Exception as exc:
        raise C4AAdmissionBlocked("external readiness request invalid") from exc
    if require_hashes_of_source_files:
        for relative,expected in parsed.source_hashes.items():
            path=root/relative
            if not path.is_file() or path.is_symlink() or sha256(path.read_bytes()).hexdigest()!=expected:
                raise C4AAdmissionBlocked(f"source policy drift: {relative}")
    return parsed
