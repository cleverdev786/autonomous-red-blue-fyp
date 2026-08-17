"""Milestone 8 runtime verification for the complete mock-provider Red Team flow.

This module is intentionally a verification entry point. Running the mock
reasoning/orchestration layer inside controlled-executor for this milestone does
not make that container the future production home of orchestration or LLM
providers. MockProvider performs no external communication.

The CLI accepts only:
- a registered test ID used to configure MockProvider's planner fixture;
- a positive attempt number.

The CLI never passes its --test-id directly to ControlledExecutor. Execution is
reached only through MockProvider -> AttackPlanningAgent -> AttackPlan ->
RedTeamFlow deterministic validation -> ControlledExecutor.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from llm.mock_provider import MockProvider
from orchestrator.limits import RunLimitTracker
from orchestrator.policy_engine import PolicyEngine
from orchestrator.red_team_flow import RedTeamFlow
from schemas.common import WorkflowState
from schemas.experiments import ExperimentLimits
from schemas.red_team import RedTeamRunResult
from security_tests.registry import SecurityTestRegistry
from services.controlled_executor import ControlledExecutor, HttpTransport, HttpxTransport
from services.target_registry import TargetRegistry


PROJECT_ROOT = Path("/workspace")


def build_parser(allowed_test_ids: tuple[str, ...]) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the Milestone 8 mock-provider Red Team MVP flow."
    )
    parser.add_argument(
        "--test-id",
        required=True,
        choices=allowed_test_ids,
        help="Registered test fixture that MockProvider should select during planning.",
    )
    parser.add_argument(
        "--attempt-number",
        type=int,
        default=1,
        help="Positive experiment attempt number.",
    )
    return parser


def run_red_team_mvp(
    *,
    project_root: Path,
    target_registry: TargetRegistry,
    planned_test_id: str,
    attempt_number: int,
    transport: HttpTransport,
) -> RedTeamRunResult:
    """Build trusted runtime components and execute one full mock Red Team flow."""
    metadata = target_registry.get_security_test(planned_test_id)
    test_registry = SecurityTestRegistry.default()
    test_registry.validate_against_target_registry(target_registry)

    policy_engine = PolicyEngine(
        registry=target_registry,
        project_root=project_root,
    )
    limits = RunLimitTracker(
        ExperimentLimits(
            max_model_calls=3,
            max_attack_attempts=1,
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
        transport=transport,
    )
    provider = MockProvider(planned_test_id=planned_test_id)
    flow = RedTeamFlow(
        target_registry=target_registry,
        policy_engine=policy_engine,
        limits=limits,
        executor=executor,
        provider=provider,
    )

    result = flow.run(
        target_id=metadata.target_id,
        attempt_number=attempt_number,
    )

    if limits.snapshot().model_calls != 3:
        raise RuntimeError("successful Milestone 8 flow must consume three model calls")

    return result


def main() -> None:
    target_registry = TargetRegistry.from_directories(
        targets_dir=PROJECT_ROOT / "config" / "targets",
        security_tests_dir=PROJECT_ROOT / "config" / "security_tests",
    )
    allowed_test_ids = tuple(
        item.test_id
        for item in target_registry.list_security_tests()
    )
    args = build_parser(allowed_test_ids).parse_args()

    if args.attempt_number < 1:
        raise SystemExit("--attempt-number must be >= 1")

    result = run_red_team_mvp(
        project_root=PROJECT_ROOT,
        target_registry=target_registry,
        planned_test_id=args.test_id,
        attempt_number=args.attempt_number,
        transport=HttpxTransport(),
    )
    print(result.model_dump_json(indent=2))

    if result.final_state != WorkflowState.BLUE_MONITORING:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
