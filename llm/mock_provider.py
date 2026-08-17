"""Deterministic no-network provider used for Milestone 8 verification."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel

from schemas.common import AgentRole
from schemas.red_team import (
    AttackPlan,
    AttackPlanningCatalog,
    AttackVerification,
    ReconnaissanceResult,
    RestrictedReconnaissanceContext,
    TestExecutionResult,
)


class MockProviderError(RuntimeError):
    """Raised when a deterministic mock fixture cannot satisfy a request."""


class MockProvider:
    """Produce deterministic typed Red Team responses without external I/O."""

    def __init__(self, *, planned_test_id: str) -> None:
        self.planned_test_id = planned_test_id
        self._call_roles: list[AgentRole] = []

    @property
    def call_roles(self) -> tuple[AgentRole, ...]:
        """Return provider-call roles in deterministic invocation order."""
        return tuple(self._call_roles)

    def generate_structured(
        self,
        *,
        role: AgentRole,
        input_data: Mapping[str, Any],
        response_model: type[BaseModel],
    ) -> Mapping[str, Any]:
        self._call_roles.append(role)

        if role == AgentRole.RED_RECONNAISSANCE:
            if response_model is not ReconnaissanceResult:
                raise MockProviderError("unexpected reconnaissance response model")
            return self._reconnaissance(input_data)

        if role == AgentRole.RED_ATTACK_PLANNER:
            if response_model is not AttackPlan:
                raise MockProviderError("unexpected attack-planning response model")
            return self._attack_plan(input_data)

        if role == AgentRole.RED_ATTACK_VERIFIER:
            if response_model is not AttackVerification:
                raise MockProviderError("unexpected verification response model")
            return self._attack_verification(input_data)

        raise MockProviderError(f"unsupported mock agent role: {role.value}")

    @staticmethod
    def _reconnaissance(input_data: Mapping[str, Any]) -> Mapping[str, Any]:
        context = RestrictedReconnaissanceContext.model_validate(input_data)
        return {
            "target_id": context.target_id,
            "candidate_endpoints": [
                endpoint.model_dump(mode="json")
                for endpoint in context.endpoints
            ],
            "rationale": (
                "Describe only the approved registered endpoint surface supplied "
                "by the trusted reconnaissance service."
            ),
        }

    def _attack_plan(self, input_data: Mapping[str, Any]) -> Mapping[str, Any]:
        reconnaissance = ReconnaissanceResult.model_validate(
            input_data.get("reconnaissance")
        )
        catalog = AttackPlanningCatalog.model_validate(
            input_data.get("planning_catalog")
        )

        option = next(
            (
                item
                for item in catalog.options
                if item.test_id == self.planned_test_id
            ),
            None,
        )
        if option is None:
            raise MockProviderError(
                f"planned test {self.planned_test_id!r} is not in the restricted catalog"
            )

        if not any(
            endpoint.endpoint_id == option.endpoint_id
            for endpoint in reconnaissance.candidate_endpoints
        ):
            raise MockProviderError(
                "planned test endpoint was not present in reconnaissance output"
            )

        return {
            "target_id": catalog.target_id,
            "test_id": option.test_id,
            "endpoint_id": option.endpoint_id,
            "vulnerability_class": option.vulnerability_class.value,
            "parameter_choices": {},
            "rationale": (
                "Select the configured deterministic registered test from the "
                "restricted planning catalog."
            ),
        }

    @staticmethod
    def _attack_verification(
        input_data: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        plan = AttackPlan.model_validate(input_data.get("attack_plan"))
        execution = TestExecutionResult.model_validate(
            input_data.get("execution_result")
        )

        confirmed = (
            execution.completed
            and not execution.timed_out
            and bool(execution.evidence)
        )
        evidence_ids = (
            [item.evidence_id for item in execution.evidence]
            if confirmed
            else []
        )

        return {
            "target_id": plan.target_id,
            "test_id": plan.test_id,
            "confirmed": confirmed,
            "confidence": 1.0,
            "evidence_ids": evidence_ids,
            "reason": (
                "Structured deterministic executor evidence supports the planned test."
                if confirmed
                else "Deterministic execution did not produce confirmable evidence."
            ),
        }
