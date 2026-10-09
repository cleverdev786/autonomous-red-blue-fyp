"""Versioned R4-C3A externally pinned admission contract, OFFLINE ONLY.

No Git, Docker, network or live measurement. Approved SHA/tree are DATA in a
frozen external manifest, not self-referential literals in a future code commit.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from schemas.r4a_red_observation import REGISTERED

SHA40 = r"^[0-9a-f]{40}$"
SHA64 = r"^[0-9a-f]{64}$"
INITIAL_SCENARIO_SHA256 = "f8675d5bed857138f49cdf717bd4c696aad7e4e42c5f14cd41b4623b140a6e5d"
REQUIRED_SOURCE_HASHES = (
    "compose.yaml",
    "config/git-policy.json",
    "config/verification-policy.json",
    "dummy_apps/vulnerable_store/app/scenario_routes.py",
)


class AdmissionBlocked(RuntimeError):
    pass


class R4C3AAdmission(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["r4c3a-external-admission-v1"] = "r4c3a-external-admission-v1"
    scope: Literal["offline_mock_validation_only"] = "offline_mock_validation_only"
    research_final_result: Literal[False] = False
    permits_git_clone: Literal[False] = False
    permits_docker_execution: Literal[False] = False
    permits_patch_application: Literal[False] = False
    approved_commit: str = Field(pattern=SHA40)
    approved_tree: str = Field(pattern=SHA40)
    approved_parent: str = Field(pattern=SHA40)
    source_hashes: dict[str, str]
    scenario_ids: tuple[str, ...]
    run_id: str
    stage_id: str

    @model_validator(mode="after")
    def validate_frozen_selection(self):
        if set(self.source_hashes) != set(REQUIRED_SOURCE_HASHES):
            raise ValueError("external admission must pin exact four source-policy files")
        if any(not isinstance(v, str) or len(v) != 64
               or any(c not in "0123456789abcdef" for c in v)
               for v in self.source_hashes.values()):
            raise ValueError("invalid source digest")
        if (self.source_hashes["dummy_apps/vulnerable_store/app/scenario_routes.py"]
                != INITIAL_SCENARIO_SHA256):
            raise ValueError("original vulnerable source identity drift")
        if tuple(self.scenario_ids) != tuple(REGISTERED):
            raise ValueError("frozen scenario registry mismatch")
        if not (1 <= len(self.run_id) <= 64) or not self.run_id.isascii() or not self.run_id.replace("_","").replace("-","").isalnum():
            raise ValueError("invalid bounded run ID")
        if not (1 <= len(self.stage_id) <= 40) or not self.stage_id.isascii() or not self.stage_id.replace("_","").replace("-","").isalnum():
            raise ValueError("invalid stage ID")
        return self

    @property
    def observed_run_id(self) -> str:
        # Existing TestRunner's registered execution identity convention.
        return f"{self.run_id[:70]}-{self.stage_id}"

    def canonical_bytes(self) -> bytes:
        return (json.dumps(self.model_dump(mode="json"), sort_keys=True,
                           separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def read_external_admission(
    *,
    source_root: Path,
    manifest_path: Path,
    expected_sha256: str,
) -> R4C3AAdmission:
    """External byte hash and path are mandatory; no self-issuing trust."""
    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
        raise AdmissionBlocked("expected admission manifest digest missing")
    source_root=source_root.resolve(strict=True)
    path=manifest_path.absolute()
    if path.is_symlink() or not path.is_file() or source_root in path.parents:
        raise AdmissionBlocked("admission must be external, regular and immutable in this gate")
    raw=path.read_bytes()
    if len(raw)>8192 or sha256(raw).hexdigest()!=expected_sha256:
        raise AdmissionBlocked("external admission bytes/hash mismatch")
    try:
        result=R4C3AAdmission.model_validate_json(raw)
        if result.canonical_bytes()!=raw:
            raise ValueError("noncanonical admission serialization")
    except Exception as exc:
        raise AdmissionBlocked("external manifest invalid") from exc
    for relative,expected in result.source_hashes.items():
        source=source_root/relative
        if source.is_symlink() or not source.is_file() or sha256(source.read_bytes()).hexdigest()!=expected:
            raise AdmissionBlocked(f"admission source mismatch: {relative}")
    return result
