"""Portable offline positive/negative checks for pinned isolated Docker build inputs."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from verify_isolated_build_inputs import (
    BuildInputMismatch,
    require_evidence,
    verify_clean_commit,
    verify_source_inputs,
)

PIN = "5a251d0a4911a15e2a5dbebcd673dc59595aa1b106777d988c1fd3788f81fd43"
FILES = (
    ".dockerignore",
    "dummy_apps/vulnerable_store/Dockerfile",
    "requirements/isolated-py313-linux-amd64.lock",
    "pyproject.toml",
)
BASE = "sha256:8fb4cfa1a2616d7b8e0c2175cc6ad68f5729c34ea8488c0b360d2934b7be9024"


@pytest.fixture
def fixture(tmp_path):
    repo = tmp_path / "source"
    repo.mkdir()
    for name in FILES:
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    locked = (repo / FILES[2]).read_text().splitlines()
    pattern = re.compile(r"^([a-z0-9-]+)==([a-zA-Z0-9.+!_-]+) --hash=sha256:([0-9a-f]{64})$")
    packages = [pattern.fullmatch(line) for line in locked if line and not line.startswith("#")]
    assert len(packages) == 33 and all(packages)
    rows = [
        {"name": item[1], "version": item[2], "sha256": item[3]}
        for item in packages
    ]
    pyproject = tomllib.loads((repo / "pyproject.toml").read_text())
    requirements = (
        pyproject["project"]["dependencies"]
        + pyproject["project"]["optional-dependencies"]["verification"]
        + pyproject["build-system"]["requires"]
    )
    return repo, {"linux_amd64_child_sha256": BASE}, {"wheel_files": rows}, {
        "root_requirements": requirements,
    }


def test_verified_source_pins_and_allowlist_are_consistent(fixture):
    root, image, wheels, closure = fixture
    result = verify_source_inputs(root, image, wheels, closure, PIN)
    assert result["verified_wheels"] == 33
    assert result["base_linux_amd64_image_manifest"] == BASE
    assert result["locked_requirements_sha256"]


@pytest.mark.parametrize(("name", "old", "new"), [
    ("dummy_apps/vulnerable_store/Dockerfile", BASE, "sha256:" + "f" * 64),
    ("dummy_apps/vulnerable_store/Dockerfile", "--require-hashes", "--no-deps"),
    ("dummy_apps/vulnerable_store/Dockerfile", "--only-binary=:all:", "--only-binary=:none:"),
    ("dummy_apps/vulnerable_store/Dockerfile", "https://pypi.org/simple", "http://example.invalid/simple"),
    (".dockerignore", "!services/**", "!secrets/**"),
    (".dockerignore", "**/.env.*", "**/unsafe"),
    ("requirements/isolated-py313-linux-amd64.lock", "--hash=sha256:", "--hash=sha512:"),
    ("pyproject.toml", "fastapi>=0.115,<1.0", "fastapi>=0.100,<1.0"),
])
def test_drifted_build_inputs_are_rejected(fixture, name, old, new):
    root, image, wheels, closure = fixture
    path = root / name
    current = path.read_text()
    assert old in current
    path.write_text(current.replace(old, new, 1))
    with pytest.raises(BuildInputMismatch):
        verify_source_inputs(root, image, wheels, closure, PIN)


def test_arbitrary_additional_docker_copy_is_rejected(fixture):
    root, image, wheels, closure = fixture
    file = root / "dummy_apps/vulnerable_store/Dockerfile"
    file.write_text(file.read_text() + "\nCOPY private ./private\n")
    with pytest.raises(BuildInputMismatch, match="COPY"):
        verify_source_inputs(root, image, wheels, closure, PIN)


def test_additional_lock_requirement_is_rejected(fixture):
    root, image, wheels, closure = fixture
    lock = root / FILES[2]
    lock.write_text(lock.read_text() + "evil-package==1.0.0 --hash=sha256:" + "a" * 64 + "\n")
    with pytest.raises(BuildInputMismatch, match="lock"):
        verify_source_inputs(root, image, wheels, closure, PIN)


def test_unapproved_git_identity_blocks_without_git_mutation(fixture, monkeypatch):
    root, _image, _wheels, _closure = fixture

    def answers(_root, *args):
        if args == ("branch", "--show-current"):
            return "main"
        raise AssertionError("guard should stop at wrong branch")

    monkeypatch.setattr("verify_isolated_build_inputs.git_value", answers)
    with pytest.raises(BuildInputMismatch, match="unapproved Git"):
        verify_clean_commit(root, "a" * 40, "b" * 40)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n")


@pytest.fixture
def synthetic_external_evidence(tmp_path):
    """Small synthetic registry/PyPI records, no network and no package install."""
    external = tmp_path / "outside"
    external.mkdir()
    wheels = external / "wheels"
    wheels.mkdir()
    entries = []
    for n in range(33):
        name = f"sample-{n:02d}"
        filename = f"{name}-1.0.0-py3-none-any.whl"
        raw = f"synthetic wheel {n}".encode()
        (wheels / filename).write_bytes(raw)
        entries.append({
            "name": name, "version": "1.0.0", "filename": filename,
            "size": len(raw), "sha256": _sha(raw),
            "pypi_verification": "SHA256, size and filename match",
        })
    child = b'{"schemaVersion":2}'
    (external / "official-python-3.13-slim-linux-amd64-manifest.json").write_bytes(child)
    descriptor = "sha256:" + _sha(child)
    multi = json.dumps({"manifests": [{"platform": {"os": "linux", "architecture": "amd64"},
                                       "digest": descriptor}]}).encode()
    (external / "official-python-3.13-slim-index.json").write_bytes(multi)
    _write_json(external / "official-image-verification.json", {
        "linux_amd64_child_sha256": descriptor,
        "tag_manifest_index_sha256": "sha256:" + _sha(multi),
    })
    _write_json(external / "verified-wheel-manifest.json", {"wheel_files": entries})
    _write_json(external / "verified-dependency-closure.json", {
        "missing_or_unmet_dependencies": [], "selected_wheel_count": 33,
    })
    (external / "pip_download.log").write_text("synthetic provenance test\n")
    (external / "requested_requirements.txt").write_text("sample\n")
    (external / "candidate-fully-hashed-requirements.txt").write_text("synthetic\n")
    names = (
        "official-python-3.13-slim-linux-amd64-manifest.json",
        "official-python-3.13-slim-index.json",
        "official-image-verification.json",
        "verified-wheel-manifest.json",
        "verified-dependency-closure.json",
        "pip_download.log",
        "requested_requirements.txt",
        "candidate-fully-hashed-requirements.txt",
    )
    stamps = {
        name: {"sha256": _sha((external / name).read_bytes()),
               "bytes": (external / name).stat().st_size}
        for name in names
    }
    _write_json(external / "gate5an-evidence-index.json", {
        "external_evidence_files": stamps,
    })
    return external, _sha((external / "gate5an-evidence-index.json").read_bytes())


def test_independently_pinned_external_evidence_verified(synthetic_external_evidence):
    evidence, external_digest = synthetic_external_evidence
    image, manifest, closure = require_evidence(evidence, external_digest)
    assert image["linux_amd64_child_sha256"].startswith("sha256:")
    assert len(manifest["wheel_files"]) == 33
    assert closure["missing_or_unmet_dependencies"] == []


def test_wrong_independent_evidence_digest_rejected(synthetic_external_evidence):
    evidence, _external_digest = synthetic_external_evidence
    with pytest.raises(BuildInputMismatch, match="independent evidence index SHA"):
        require_evidence(evidence, "0" * 64)


def test_tampered_wheel_rejected(synthetic_external_evidence):
    evidence, external_digest = synthetic_external_evidence
    path = next((evidence / "wheels").glob("*.whl"))
    path.write_bytes(path.read_bytes() + b"tamper")
    with pytest.raises(BuildInputMismatch, match="PyPI wheel digest"):
        require_evidence(evidence, external_digest)


def test_symlink_wheelhouse_rejected(synthetic_external_evidence):
    evidence, external_digest = synthetic_external_evidence
    folder = evidence / "wheels"
    relocated = evidence / "moved"
    folder.rename(relocated)
    folder.symlink_to(relocated, target_is_directory=True)
    with pytest.raises(BuildInputMismatch, match="wheelhouse path"):
        require_evidence(evidence, external_digest)
