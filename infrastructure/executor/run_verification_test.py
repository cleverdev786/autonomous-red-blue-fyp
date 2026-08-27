"""Run one registered deterministic security test for Blue verification.

This entry point is intentionally narrow. It accepts only a registered test ID,
positive attempt number, and opaque run correlation ID. It does not expose URL,
hostname, method, headers, payload, filesystem paths, or shell arguments.

Unlike the Red demonstration CLI, absence of exploit evidence is not a process
failure here. The structured result is emitted for the trusted verification
pipeline to interpret deterministically.
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
    parser = argparse.ArgumentParser(description="Run one registered Blue verification test.")
    parser.add_argument("--test-id", required=True, choices=allowed_test_ids)
    parser.add_argument("--attempt-number", required=True, type=int)
    parser.add_argument("--run-id", required=True)
    return parser


def main() -> None:
    target_registry = TargetRegistry.from_directories(
        targets_dir=PROJECT_ROOT / "config" / "targets",
        security_tests_dir=PROJECT_ROOT / "config" / "security_tests",
    )
    test_registry = SecurityTestRegistry.default()
    test_registry.validate_against_target_registry(target_registry)
    allowed_test_ids = tuple(item.test_id for item in target_registry.list_security_tests())
    args = build_parser(allowed_test_ids).parse_args()

    executor = ControlledExecutor(
        target_registry=target_registry,
        test_registry=test_registry,
        policy_engine=PolicyEngine(registry=target_registry, project_root=PROJECT_ROOT),
        limits=RunLimitTracker(
            ExperimentLimits(
                max_model_calls=1,
                max_attack_attempts=3,
                max_patch_attempts=1,
                max_http_requests=10,
                max_runtime_seconds=120,
            )
        ),
        transport=HttpxTransport(),
    )
    result = executor.execute_registered_test(
        test_id=args.test_id,
        attempt_number=args.attempt_number,
        run_id=args.run_id,
    )
    print(result.model_dump_json())


if __name__ == "__main__":
    main()
