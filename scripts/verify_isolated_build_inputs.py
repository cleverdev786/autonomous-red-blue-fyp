"""Offline, independently pinned pre-build input verifier for the isolated lab.

No network, package install, Docker call, file write, or container execution.
The CLI additionally requires the authorized clean Git HEAD and tree.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tomllib
from pathlib import Path

COPY_DIRS = (
    "agents", "orchestrator", "schemas", "services", "llm", "dummy_apps",
    "infrastructure", "security_tests", "verification", "config", "requirements",
)
LOCK = "requirements/isolated-py313-linux-amd64.lock"
DOCKERFILE = "dummy_apps/vulnerable_store/Dockerfile"
EXPECTED_PIN_COUNT = 33
DENY_PATTERNS = (
    "**/.env", "**/.env.*", "**/*.pem", "**/*.key", "**/*.p12", "**/*.pfx",
    "**/__pycache__", "**/__pycache__/**", "**/*.pyc", "**/*.db",
    "**/*.sqlite", "**/*.sqlite3", "**/.pytest_cache", "**/.pytest_cache/**",
    "**/.ruff_cache", "**/.ruff_cache/**", "**/*.egg-info",
    "**/*.egg-info/**", "**/scenario_files", "**/scenario_files/**",
    "**/generated_patches", "**/generated_patches/**",
    "**/experiment-results", "**/experiment-results/**", "**/.DS_Store",
    "/models/",
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class BuildInputMismatch(ValueError):
    """An approved source, provenance artifact, or hash no longer matches."""


def fail_if(condition: bool, reason: str) -> None:
    if condition:
        raise BuildInputMismatch(reason)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def safe_file(root: Path, name: str) -> Path:
    fail_if(Path(name).is_absolute() or ".." in Path(name).parts, "unsafe provenance filename")
    file = root / name
    fail_if(file.is_symlink() or not file.is_file(), f"missing or symlink file: {name}")
    return file


def require_evidence(evidence: Path, independently_pinned_index_sha256: str) -> tuple[dict, dict, dict]:
    fail_if(not SHA256.fullmatch(independently_pinned_index_sha256), "independent evidence digest required")
    fail_if(evidence.is_symlink() or not evidence.is_dir(), "external evidence directory invalid")
    raw_index = safe_file(evidence, "gate5an-evidence-index.json").read_bytes()
    fail_if(digest(raw_index) != independently_pinned_index_sha256, "independent evidence index SHA mismatch")
    index = json.loads(raw_index)
    stamps = index["external_evidence_files"]
    fail_if(not isinstance(stamps, dict) or len(stamps) != 8, "incomplete evidence index")
    for name, stamp in stamps.items():
        file = safe_file(evidence, name)
        raw = file.read_bytes()
        fail_if(
            digest(raw) != stamp["sha256"] or len(raw) != stamp["bytes"],
            f"evidence artifact hash drift: {name}",
        )
    image = json.loads(safe_file(evidence, "official-image-verification.json").read_bytes())
    child = safe_file(evidence, "official-python-3.13-slim-linux-amd64-manifest.json").read_bytes()
    multi = safe_file(evidence, "official-python-3.13-slim-index.json").read_bytes()
    fail_if(
        "sha256:" + digest(child) != image["linux_amd64_child_sha256"]
        or "sha256:" + digest(multi) != image["tag_manifest_index_sha256"],
        "base-image registry manifest bytes drift",
    )
    descriptors = [
        m for m in json.loads(multi)["manifests"]
        if m.get("platform", {}).get("os") == "linux"
        and m.get("platform", {}).get("architecture") == "amd64"
    ]
    fail_if(
        len(descriptors) != 1 or descriptors[0]["digest"] != image["linux_amd64_child_sha256"],
        "base-image platform manifest descriptor drift",
    )
    wheel_manifest = json.loads(safe_file(evidence, "verified-wheel-manifest.json").read_bytes())
    closure = json.loads(safe_file(evidence, "verified-dependency-closure.json").read_bytes())
    entries = wheel_manifest["wheel_files"]
    fail_if(
        len(entries) != EXPECTED_PIN_COUNT or len({i["name"] for i in entries}) != len(entries)
        or closure["missing_or_unmet_dependencies"] != []
        or closure["selected_wheel_count"] != EXPECTED_PIN_COUNT,
        "incomplete dependency closure or wheel manifest",
    )
    wheel_dir = evidence / "wheels"
    fail_if(wheel_dir.is_symlink() or not wheel_dir.is_dir(), "wheelhouse path invalid")
    actual = {p.name for p in wheel_dir.iterdir()}
    wanted = {i["filename"] for i in entries}
    fail_if(actual != wanted, "unexpected wheelhouse contents")
    for item in entries:
        wheel = safe_file(evidence / "wheels", item["filename"])
        fail_if(
            wheel.stat().st_size != item["size"]
            or digest(wheel.read_bytes()) != item["sha256"]
            or item["pypi_verification"] != "SHA256, size and filename match",
            "verified PyPI wheel digest drift: " + item["name"],
        )
    return image, wheel_manifest, closure


def expected_lock(manifest: dict, independently_pinned_index_sha256: str) -> bytes:
    entries = sorted(manifest["wheel_files"], key=lambda row: row["name"])
    fail_if(len(entries) != EXPECTED_PIN_COUNT, "wrong package count")
    values = [
        "# Verified CPython 3.13 Linux AMD64 wheel candidate (Gate 5A-N)",
        "# Evidence index SHA-256: " + independently_pinned_index_sha256,
        "# SHA-256 values are exact wheel artifact hashes; no sdist or alternate wheel allowed.",
    ]
    for item in entries:
        fail_if(
            not re.fullmatch(r"[a-z0-9][a-z0-9-]*", item["name"])
            or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.+!_-]*", item["version"])
            or not SHA256.fullmatch(item["sha256"]),
            "invalid wheel lock entry",
        )
        values.append(f'{item["name"]}=={item["version"]} --hash=sha256:{item["sha256"]}')
    return ("\n".join(values) + "\n").encode()


def verify_source_inputs(repo: Path, image: dict, wheels: dict, closure: dict, evidence_sha: str) -> dict:
    fail_if(repo.is_symlink() or not repo.is_dir(), "repository location invalid")
    lock = safe_file(repo, LOCK).read_bytes()
    fail_if(lock != expected_lock(wheels, evidence_sha), "hash-locked dependency file mismatch")

    declared = tomllib.loads(safe_file(repo, "pyproject.toml").read_text())
    roots = (
        declared["project"]["dependencies"]
        + declared["project"]["optional-dependencies"]["verification"]
        + declared["build-system"]["requires"]
    )
    fail_if(roots != closure["root_requirements"], "project requirements drift from resolved closure")

    dockerfile = safe_file(repo, DOCKERFILE).read_text()
    source_lines = dockerfile.splitlines()
    fail_if(
        not source_lines or source_lines[0]
        != "FROM --platform=linux/amd64 python:3.13-slim@" + image["linux_amd64_child_sha256"]
        or sum(line.startswith("FROM ") for line in source_lines) != 1,
        "Docker base image is not independently pinned",
    )
    required = (
        "COPY " + LOCK + " ./requirements/",
        "--require-hashes", "--only-binary=:all:",
        "--index-url https://pypi.org/simple",
        "-r " + LOCK,
        "python -m pip install --no-cache-dir --no-deps --no-build-isolation .",
    )
    fail_if(any(fragment not in dockerfile for fragment in required), "hashed install protocol changed")
    fail_if(dockerfile.count("python -m pip install ") != 2, "unexpected package installation")
    copy_sources: set[str] = set()
    for line in source_lines:
        if not line.startswith("COPY "):
            continue
        parts = line.split()
        fail_if(len(parts) < 3, "unsupported Docker COPY syntax")
        copy_sources.update(parts[1:-1])
    allowed = {"README.md", "pyproject.toml", LOCK, *(folder for folder in COPY_DIRS if folder != "requirements")}
    fail_if(copy_sources != allowed, "unexpected Docker COPY sources")

    ignore_rules = [
        line.strip() for line in safe_file(repo, ".dockerignore").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    prefixes = ["**", "!README.md", "!pyproject.toml"]
    for folder in COPY_DIRS:
        prefixes.extend((f"!{folder}/", f"!{folder}/**"))
    fail_if(
        ignore_rules != prefixes + list(DENY_PATTERNS),
        "Docker build-context allowlist or safety exclusions changed",
    )
    return {
        "base_linux_amd64_image_manifest": image["linux_amd64_child_sha256"],
        "evidence_index_sha256": evidence_sha,
        "verified_wheels": len(wheels["wheel_files"]),
        "dockerfile_sha256": digest(safe_file(repo, DOCKERFILE).read_bytes()),
        "dockerignore_sha256": digest(safe_file(repo, ".dockerignore").read_bytes()),
        "locked_requirements_sha256": digest(lock),
    }


def git_value(repo: Path, *args: str) -> str:
    return subprocess.check_output(("git", "-C", str(repo), *args), text=True).strip()


def verify_clean_commit(repo: Path, expected_head: str, expected_tree: str) -> dict:
    fail_if(
        not re.fullmatch(r"[0-9a-f]{40}", expected_head)
        or not re.fullmatch(r"[0-9a-f]{40}", expected_tree),
        "externally approved Git identity required",
    )
    fail_if(
        git_value(repo, "branch", "--show-current") != "development"
        or git_value(repo, "rev-parse", "HEAD") != expected_head
        or git_value(repo, "rev-parse", "HEAD^{tree}") != expected_tree
        or git_value(repo, "--no-optional-locks", "status", "--porcelain=v1", "--untracked-files=all"),
        "unapproved Git branch, commit, tree or uncommitted changes",
    )
    # Use bytes instead of null-terminated text for full file-path fidelity.
    output = subprocess.check_output(("git", "-C", str(repo), "ls-files", "-z"))
    tracked = [raw.decode("utf-8") for raw in output.split(b"\0") if raw]
    relevant = [
        p for p in tracked
        if p in {"README.md", "pyproject.toml", LOCK, DOCKERFILE, ".dockerignore"}
        or any(p.startswith(folder + "/") for folder in COPY_DIRS)
    ]
    fail_if(LOCK not in relevant or DOCKERFILE not in relevant, "uncommitted build inputs")
    rows = []
    for name in sorted(relevant):
        rows.append(f"{name}\t{digest(safe_file(repo, name).read_bytes())}\n")
    return {
        "source_head": expected_head,
        "source_tree": expected_tree,
        "tracked_build_input_count": len(rows),
        "tracked_build_input_manifest_sha256": digest("".join(rows).encode()),
        "context_requirement": "Build from a disposable clean git-archive of the approved commit.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--evidence-index-sha256", required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-tree", required=True)
    args = parser.parse_args()
    source = args.repo.resolve(strict=True)
    pin = verify_clean_commit(source, args.expected_head, args.expected_tree)
    fail_if(
        args.evidence.resolve(strict=True) == source
        or source in args.evidence.resolve(strict=True).parents,
        "evidence must remain outside the checkout",
    )
    image, wheel_manifest, closure = require_evidence(args.evidence, args.evidence_index_sha256)
    record = verify_source_inputs(source, image, wheel_manifest, closure, args.evidence_index_sha256)
    print(json.dumps({**pin, **record, "status": "OFFLINE_SOURCE_INPUTS_ONLY_NOT_IMAGE_ATTESTATION"}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
