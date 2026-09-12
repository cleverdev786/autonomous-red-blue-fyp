"""Build an M18 RQ2 candidate dataset from real controlled runtime captures.

This command performs no HTTP/network/Git/Docker action. The input JSONL must
already contain 60 captured observations produced by the controlled laptop
runtime using the existing registered security tests.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from experiments.rq2_dataset import build_candidate_dataset
from schemas.rq2_dataset import RQ2CapturedObservation
from security_tests.registry import SecurityTestRegistry
from services.target_registry import TargetRegistry


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--captures",
        type=Path,
        required=True,
        help="JSONL of 60 real RQ2CapturedObservation records from controlled runtime.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="New candidate directory; existing frozen files are never overwritten.",
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    project_root = args.project_root.resolve()
    captures = tuple(
        RQ2CapturedObservation.model_validate_json(line)
        for line in args.captures.read_text(encoding="utf-8").splitlines()
        if line.strip()
    )

    target_registry = TargetRegistry.from_directories(
        targets_dir=project_root / "config" / "targets",
        security_tests_dir=project_root / "config" / "security_tests",
    )
    test_registry = SecurityTestRegistry.default()

    manifest = build_candidate_dataset(
        captures,
        output_dir=args.output_dir,
        target_registry=target_registry,
        test_registry=test_registry,
    )

    print(f"dataset_id={manifest.dataset_id}")
    print(f"dataset_version={manifest.dataset_version}")
    print(f"item_count={manifest.item_count}")
    print(f"inputs_sha256={manifest.inputs_sha256}")
    print(f"ground_truth_sha256={manifest.ground_truth_sha256}")
    print(f"unique_event_ids={manifest.duplication_audit.unique_event_ids}")
    print(
        "unique_semantic_input_hashes="
        f"{manifest.duplication_audit.unique_semantic_input_hashes}"
    )
    print("repetition_group_sizes=")
    for key, value in manifest.duplication_audit.repetition_group_sizes.items():
        print(f"  {key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
