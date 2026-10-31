"""Prepare a hash-inventoried patched Docker build context, without Docker authority.

This creates an external, uniquely named candidate for independent image-build
review. It cannot start/build/stop a container or authorize a security replay.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
from hashlib import sha256
from pathlib import Path

import yaml
from git import Repo

from services.blue_replay import _checked_stage
from services.isolated_compose_mock_adapter import verify_isolation_yaml
from services.trusted_remediation_compiler import SOURCE

ROOT = Path(__file__).resolve().parents[1]
COPIED = (
    ".dockerignore", "README.md", "pyproject.toml", "compose.yaml",
    "requirements/isolated-py313-linux-amd64.lock", "agents", "orchestrator",
    "schemas", "services", "llm", "dummy_apps", "infrastructure",
    "security_tests", "verification", "config", "compose.isolated.yaml",
)
MAX_ARCHIVE_BYTES = 30 * 1024 * 1024


class BlueDockerBlocked(RuntimeError):
    """No safe, proven build context could be prepared."""


def _replay_verified(stage: Path, sha: str, source_sha: str, job: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{64}", sha):
        raise BlueDockerBlocked("External offline-replay digest required")
    path = stage / "replay.json"
    if (path.is_symlink() or not path.is_file() or path.stat().st_size > 8192):
        raise BlueDockerBlocked("Recorded offline replay is missing")
    raw = path.read_bytes()
    if len(raw) > 8192 or sha256(raw).hexdigest() != sha:
        raise BlueDockerBlocked("Offline-replay evidence changed")
    receipt = json.loads(raw)
    if (receipt.get("status") != "passed" or
            receipt.get("job_id") != job or
            receipt.get("test_id") != "sqli-login-bypass-001" or
            receipt.get("replay_mode") != "in_process_registered_test" or
            receipt.get("staged_source_sha256") != source_sha or
            receipt.get("registered_steps_executed") != 2 or
            receipt.get("control_status") != 401 or
            receipt.get("injection_status") != 401 or
            receipt.get("registered_exploit_evidence") != [] or
            not isinstance(receipt.get("checks"), dict) or
            set(receipt["checks"]) != {
                "legitimate_scenario_login", "incorrect_password_rejected",
                "normal_application_login", "normal_application_rejects_invalid_password",
                "health_endpoint",
            } or not all(value is True for value in receipt["checks"].values()) or
            receipt.get("docker_replayed") is not False or
            receipt.get("final_repair_accepted") is not False or
            receipt.get("final_research_qualified") is not False):
        raise BlueDockerBlocked("Offline replay did not establish a safe candidate")


def _copy_committed_tree(repo: Repo, destination: Path) -> None:
    """Copy only frozen Dockerfile inputs from Git objects, never working files."""
    tree = repo.head.commit.tree
    total = 0
    count = 0
    for name in COPIED:
        root = tree / name
        entries = (root,) if root.type == "blob" else root.traverse()
        for entry in entries:
            if entry.type == "tree":
                continue
            if (entry.type != "blob" or entry.mode not in (0o100644, 0o100755) or
                    Path(entry.path).is_absolute() or ".." in Path(entry.path).parts):
                raise BlueDockerBlocked("Committed Docker source contains an unsafe path")
            raw = entry.data_stream.read(MAX_ARCHIVE_BYTES + 1)
            total += len(raw)
            count += 1
            if total > MAX_ARCHIVE_BYTES or count > 5000:
                raise BlueDockerBlocked("Committed Docker context exceeds size bounds")
            path = destination / entry.path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
    if (destination / "models").exists() or (destination / ".git").exists():
        raise BlueDockerBlocked("Unapproved Docker build context path")


def prepare_docker_candidate(
    *, staged: dict, output_parent: Path, source_root: Path,
    replay_sha256: str,
) -> dict:
    """Create a new external candidate with no real Docker operation."""
    try:
        repo_root, patched = _checked_stage(staged, Path(output_parent), Path(source_root))
        stage = repo_root.parent
        _replay_verified(
            stage, replay_sha256, sha256(patched).hexdigest(), staged["job_id"],
        )
        target = stage / "docker-context"
        if target.exists() or target.is_symlink():
            raise BlueDockerBlocked("Docker review candidate already exists")
        source_repo = Repo(ROOT)
        if source_repo.active_branch.name != "development":
            raise BlueDockerBlocked("Committed Docker source must be on development")
        head = source_repo.head.commit.hexsha
        target.mkdir(mode=0o700)
        try:
            _copy_committed_tree(source_repo, target)
            # Use the existing frozen isolation contract; patched source bytes
            # are permitted, but Compose hardening is not silently relaxed.
            verify_isolation_yaml(target)
            source = target / SOURCE
            if source.is_symlink() or not source.is_file():
                raise BlueDockerBlocked("Archived registered source is not regular")
            source.write_bytes(patched)
            name = "fyp-blue-" + staged["job_id"].replace("-", "")[:12]
            document = yaml.safe_load((target / "compose.isolated.yaml").read_text())
            if (type(document) is not dict or
                    set(document.get("services", {})) != {
                        "vulnerable-store", "controlled-executor",
                    } or document.get("name") != "fyp-r4c4f-red-blue-lab" or
                    document.get("networks", {}).get("security-lab", {}).get("internal") is not True):
                raise BlueDockerBlocked("Frozen Docker isolation configuration changed")
            image = name + ":local"
            document["name"] = name
            document["x-lab-image"]["image"] = image
            for service in ("vulnerable-store", "controlled-executor"):
                item = document["services"][service]
                if (item.get("image") != "fyp-r4c4f-red-blue-lab:local" or
                        item.get("ports", []) != [] or
                        item.get("privileged") is not False or
                        item.get("read_only") is not True or
                        item.get("cap_drop") != ["ALL"] or
                        "no-new-privileges:true" not in item.get("security_opt", []) or
                        item.get("build") != {
                            "context": ".", "dockerfile": "dummy_apps/vulnerable_store/Dockerfile",
                        }):
                    raise BlueDockerBlocked("Frozen container safety settings changed")
                item["image"] = image
                item["container_name"] = name + "-" + service
            network = document["networks"]["security-lab"]
            if (network.get("internal") is not True or
                    network.get("attachable") is not False):
                raise BlueDockerBlocked("Patched network may not be externally reachable")
            network["name"] = name + "-network"
            document["volumes"]["store-runtime"]["name"] = name + "-volume"
            compose = target / "compose.blue.yaml"
            compose.write_text(yaml.safe_dump(document, sort_keys=False))
            # Always fail if a source archive contains symlinks, runtime data or secrets.
            for item in target.rglob("*"):
                if item.is_symlink():
                    raise BlueDockerBlocked("Untrusted link found in candidate")
            files = {
                str(item.relative_to(target)): sha256(item.read_bytes()).hexdigest()
                for item in target.rglob("*") if item.is_file()
            }
            receipt = {
                "schema_version": "isolated-docker-candidate-v1",
                "job_id": staged["job_id"],
                "source_commit": head,
                "staged_git_diff_sha256": staged["git_diff_sha256"],
                "in_process_replay_sha256": replay_sha256,
                "patched_source_sha256": sha256(patched).hexdigest(),
                "image": image,
                "compose_path": "compose.blue.yaml",
                "file_sha256": dict(sorted(files.items())),
                "image_built": False,
                "docker_executed": False,
                "independent_admission_granted": False,
                "final_repair_accepted": False,
                "final_research_qualified": False,
            }
            data = (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode()
            artifact = stage / "candidate.json"
            with artifact.open("xb") as handle:
                handle.write(data)
            return {
                **receipt, "build_context": str(target),
                "candidate_sha256": sha256(data).hexdigest(),
            }
        except Exception:
            shutil.rmtree(target)
            raise
    except BlueDockerBlocked:
        raise
    except Exception as exc:
        raise BlueDockerBlocked("Patched Docker candidate preparation refused") from exc


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare an offline patched Docker review candidate, without Docker",
    )
    for field in ("branch-receipt", "output-parent", "source-root"):
        parser.add_argument("--" + field, type=Path, required=True)
    parser.add_argument("--replay-sha256", required=True)
    args = parser.parse_args()
    staged = json.loads(args.branch_receipt.read_text())
    print(json.dumps(prepare_docker_candidate(
        staged=staged, output_parent=args.output_parent,
        source_root=args.source_root, replay_sha256=args.replay_sha256,
    ), indent=2))


if __name__ == "__main__":
    main()
