#!/usr/bin/env python3
"""Read-only, bounded MARS development evidence reconciliation.

Portable reviewer utility. Makes no model, Docker, network, Git write,
patch or research run. Requires the actual authorized laptop artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

BASELINE_SHA = "7bd9b048dff60d1c7a50e43d706de167e1acccbd6296f4bc86120cf12a95f545"
DIAGNOSTIC_SHA = "1066fb310b94e241911e6c675fe25fd6eb550647057f66db43e696918bcd0e8f"
EXPECTED_PROTECTED = {
    "dummy_apps/vulnerable_store/app/scenario_routes.py": "f8675d5bed857138f49cdf717bd4c696aad7e4e42c5f14cd41b4623b140a6e5d",
    "experiments/datasets/rq2-classification-v1/inputs.jsonl": "9a7db4522d96c2a4d27b6f131bd145c6fd38b7614e0ccbbef8ab7dbf4cc5c6f5",
    "experiments/datasets/rq2-classification-v1/ground_truth.jsonl": "376cac8cbf7963aa0630f0a2437f555d56861c945beda2a0ffdb63f47391781f",
    "experiments/datasets/rq2-classification-v1/manifest.json": "8131e0ad2a40a6963fe9f405445352ce8af287f6ab41297f80ebba0735e31345",
}
PAIRED_SCENARIOS = {"xss", "traversal"}


class EvidenceMismatch(RuntimeError):
    """Archive or source did not match its pinned expected bytes or boundaries."""


def ordinary_file(path: Path) -> Path:
    # Reject symlinks in the final path and every existing ancestor.
    if not path.is_absolute():
        raise EvidenceMismatch(f"Expected absolute path: {path}")
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise EvidenceMismatch(f"Symlink in evidence path: {path}")
    if not path.is_file():
        raise EvidenceMismatch(f"Missing regular evidence file: {path}")
    return path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with ordinary_file(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_sha(path: Path, expected: str) -> str:
    if (
        not isinstance(expected, str)
        or len(expected) != 64
        or any(char not in "0123456789abcdef" for char in expected)
    ):
        raise EvidenceMismatch(f"Bad expected digest for {path}")
    observed = sha256(path)
    if observed != expected:
        raise EvidenceMismatch(f"Digest mismatch: {path}")
    return observed


def read_json(path: Path) -> dict:
    data = json.loads(ordinary_file(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise EvidenceMismatch(f"Expected JSON object: {path}")
    return data


def child_file(directory: Path, relative: str) -> Path:
    if (
        not isinstance(relative, str)
        or not relative
        or Path(relative).is_absolute()
        or "\\" in relative
        or any(part in ("", ".", "..") for part in relative.split("/"))
    ):
        raise EvidenceMismatch("Unsafe archive-relative name")
    target = directory / relative
    if directory.resolve() not in target.resolve().parents:
        raise EvidenceMismatch("Evidence would escape archive")
    return target


def verify_indexed_files(directory: Path, pinned: dict) -> int:
    if not isinstance(pinned, dict) or not pinned:
        raise EvidenceMismatch("Missing non-empty file hash inventory")
    for name, expected in pinned.items():
        require_sha(child_file(directory, name), expected)
    return len(pinned)


def verify_original(directory: Path) -> dict:
    require_sha(directory / "outcome.json", BASELINE_SHA)
    index = read_json(directory / "outcome.json")
    if (
        index.get("final_research_qualified") is not False
        or index.get("model_authored_patch") is not False
    ):
        raise EvidenceMismatch("Development outcomes were misrepresented as final/model-authored")
    rows = index.get("scenarios")
    if (
        not isinstance(rows, list)
        or {row.get("scenario") for row in rows} != PAIRED_SCENARIOS
        or len(rows) != 2
    ):
        raise EvidenceMismatch("Expected exactly the two original development cases")
    file_count = verify_indexed_files(directory, index.get("external_file_sha256"))
    model_root = directory.parent / "capability-evidence"
    for row in rows:
        if (
            row.get("real_red_exploit_confirmed") is not True
            or row.get("source_localization_accepted") is not False
            or row.get("trusted_deterministic_patched_docker_passed") is not True
            or row.get("model_authored_patch") is not False
            or row.get("model_intent_status") != "outcome_unknown"
        ):
            raise EvidenceMismatch("Unexpected model/Red/Docker evidence status")
        archive = Path(row["model_archived"])
        if archive.parent != model_root or not archive.name.startswith("probe-"):
            raise EvidenceMismatch("Untrusted external model archive location")
        verify_indexed_files(archive, row["model_files_sha256"])
        outcome = child_file(directory, row["scenario"] + "-patched-docker-receipt.json")
        require_sha(outcome, row["trusted_deterministic_patched_docker_receipt_sha256"])
        replay = read_json(outcome)
        if not (
            replay.get("status") == "passed"
            and replay.get("docker_replayed") is True
            and replay.get("model_authored_patch") is False
            and replay.get("final_research_qualified") is False
            and replay.get("registered_exploit_evidence") == []
            and isinstance(replay.get("functional_checks"), dict)
            and all(v is True for v in replay["functional_checks"].values())
        ):
            raise EvidenceMismatch("Registered patched Docker outcome not supported")
    return {
        "real_red_jobs": len(rows),
        "verified_archived_files": file_count,
        "model_localizations_accepted": 0,
        "trusted_docker_replays_passed": 2,
    }


def verify_diagnostic(directory: Path) -> dict:
    require_sha(directory / "audit.json", DIAGNOSTIC_SHA)
    audit = read_json(directory / "audit.json")
    if (
        audit.get("original_evidence_sha256") != BASELINE_SHA
        or audit.get("prospective") is not False
        or audit.get("model_authority") is not False
        or audit.get("final_research_qualified") is not False
    ):
        raise EvidenceMismatch("Retrospective study provenance is invalid")
    rows = audit.get("results")
    if (
        not isinstance(rows, list)
        or len(rows) != 2
        or {r.get("scenario") for r in rows} != PAIRED_SCENARIOS
    ):
        raise EvidenceMismatch("Missing a retrospective model observation")
    files = 0
    for row in rows:
        if row.get("status") != "rejected" or row.get("old_model_receipt_untouched") is not True:
            raise EvidenceMismatch("Retrospective outcome is not an archived rejection")
        subdirectory = Path(row["directory"])
        if subdirectory != directory / row["scenario"]:
            raise EvidenceMismatch("Unexpected retrospective archive folder")
        files += verify_indexed_files(subdirectory, row["file_sha256"])
        outcome = read_json(subdirectory / "outcome.json")
        if (
            outcome.get("status") != "rejected"
            or outcome.get("qualified") is not False
            or outcome.get("model_repair_authority") is not False
            or outcome.get("raw_selected", {}).get("sink_line") != row["raw_selected_line"]
        ):
            raise EvidenceMismatch("Retroactive promotion or model answer mismatch")
    return {
        "retrospective_cases": len(rows),
        "verified_archived_files": files,
        "localizations_accepted": 0,
    }


def verify_repo(repo: Path) -> dict:
    if repo.is_symlink() or not repo.is_dir():
        raise EvidenceMismatch("Expected a real local repository")
    for filename, expected in EXPECTED_PROTECTED.items():
        require_sha(child_file(repo, filename), expected)

    def git(*arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(repo), *arguments],
            check=True,
            text=True,
            capture_output=True,
            timeout=20,
        )
        return result.stdout.strip()

    branch = git("branch", "--show-current")
    if branch != "development":
        raise EvidenceMismatch(f"Unexpected active branch: {branch}")
    status = git("status", "--porcelain=v1")
    if status:
        raise EvidenceMismatch("Working tree is not clean")
    return {
        "branch": branch,
        "local_head": git("rev-parse", "HEAD"),
        "protected_files_sha256_match": len(EXPECTED_PROTECTED),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--external", type=Path, default=Path.home() / ".local/state/sentinel-fyp")
    args = parser.parse_args()
    try:
        report = {
            "scope": "read_only_historical_development_evidence_verification",
            "no_model_calls": True,
            "no_security_tests_executed": True,
            "repo": verify_repo(args.repo.absolute()),
            "original": verify_original(
                (args.external / "mars-nonsql-live-20261017-v1").absolute()
            ),
            "retrospective": verify_diagnostic(
                (args.external / "mars-source-profile-v2-retrospective-20261017").absolute()
            ),
            "verification": "PASS",
        }
    except (
        EvidenceMismatch,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        subprocess.SubprocessError,
        json.JSONDecodeError,
    ) as exc:
        print(json.dumps({"verification": "FAIL", "reason": str(exc)}, indent=2))
        return 1
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
