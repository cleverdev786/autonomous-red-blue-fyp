"""Run one registered deterministic test inside controlled-executor.

This CLI intentionally accepts only:
- registered test ID
- attempt number

It exposes no URL, hostname, method, header, payload, file, or shell argument.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from orchestrator.limits import RunLimitTracker
from orchestrator.policy_engine import PolicyEngine
from schemas.experiments import ExperimentLimits
from security_tests.registry import SecurityTestRegistry
from services.controlled_executor import ControlledExecutor, HttpxTransport
from services.target_registry import TargetRegistry


PROJECT_ROOT = Path("/workspace")


def build_parser(allowed_test_ids: tuple[str, ...]) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one registered local FYP security test."
    )
    parser.add_argument(
        "--test-id",
        required=True,
        choices=allowed_test_ids,
        help="Registered deterministic security-test ID.",
    )
    parser.add_argument(
        "--attempt-number",
        type=int,
        default=1,
        help="Positive experiment attempt number.",
    )
    return parser


def main() -> None:
    target_registry = TargetRegistry.from_directories(
        targets_dir=PROJECT_ROOT / "config" / "targets",
        security_tests_dir=PROJECT_ROOT / "config" / "security_tests",
    )
    test_registry = SecurityTestRegistry.default()
    test_registry.validate_against_target_registry(target_registry)

    allowed_test_ids = tuple(
        item.test_id
        for item in target_registry.list_security_tests()
    )
    args = build_parser(allowed_test_ids).parse_args()

    policy_engine = PolicyEngine(
        registry=target_registry,
        project_root=PROJECT_ROOT,
    )
    limits = RunLimitTracker(
        ExperimentLimits(
            max_model_calls=1,
            max_attack_attempts=3,
            max_patch_attempts=1,
            max_http_requests=10,
            max_runtime_seconds=120,
        )
    )
    executor = ControlledExecutor(
        target_registry=target_registry,
        test_registry=test_registry,
        policy_engine=policy_engine,
        limits=limits,
        transport=HttpxTransport(),
    )

    result = executor.execute_registered_test(
        test_id=args.test_id,
        attempt_number=args.attempt_number,
    )
    print(result.model_dump_json(indent=2))

    if not result.completed or not result.evidence:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
