"""Milestone 8 typed Red Team workflow around the deterministic executor."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from pydantic import BaseModel

from agents.base import TypedReasoningAgent
from agents.red import AttackPlanningAgent, AttackVerificationAgent, ReconnaissanceAgent
from llm.interface import StructuredGenerationProvider
from orchestrator.limits import RunLimitTracker
from orchestrator.policy_engine import PolicyEngine
from schemas.common import WorkflowState
from schemas.red_team import (
    AttackPlan,
    AttackPlanningCatalog,
    AttackVerification,
    ReconnaissanceResult,
    RedTeamRunResult,
    RestrictedReconnaissanceContext,
    TestExecutionResult,
)
from schemas.verification import PolicyDecision
from services.controlled_executor import ControlledExecutor
from services.reconnaissance_service import ReconnaissanceService
from services.target_registry import TargetRegistry


AgentOutputT = TypeVar("AgentOutputT", bound=BaseModel)


class RedTeamFlowError(RuntimeError):
    """Raised when a Red Team recommendation fails deterministic validation."""


class RedTeamPolicyBlocked(RedTeamFlowError):
    """Raised when deterministic policy denies a Red Team workflow action."""

    def __init__(self, decision: PolicyDecision) -> None:
        super().__init__(decision.message)
        self.decision = decision


class RedTeamFlow:
    """Coordinate one policy-controlled, single-attempt Red Team MVP run."""

    def __init__(
        self,
        *,
        target_registry: TargetRegistry,
        policy_engine: PolicyEngine,
        limits: RunLimitTracker,
        executor: ControlledExecutor,
        provider: StructuredGenerationProvider,
    ) -> None:
        self.target_registry = target_registry
        self.policy_engine = policy_engine
        self.limits = limits
        self.executor = executor
        self.provider = provider
        self.reconnaissance_service = ReconnaissanceService(registry=target_registry)
        self.reconnaissance_agent = ReconnaissanceAgent()
        self.attack_planning_agent = AttackPlanningAgent()
        self.attack_verification_agent = AttackVerificationAgent()

    def run(
        self,
        *,
        target_id: str,
        attempt_number: int = 1,
    ) -> RedTeamRunResult:
        """Run the approved Milestone 8 flow from READY to handoff/rejection."""
        if attempt_number < 1:
            raise ValueError("attempt_number must be >= 1")

        self._require_policy(self.policy_engine.validate_target(target_id))
        state = WorkflowState.READY

        state = self._transition(state, WorkflowState.RECONNAISSANCE)
        reconnaissance_context = (
            self.reconnaissance_service.build_reconnaissance_context(
                target_id=target_id
            )
        )
        reconnaissance = self._invoke_agent(
            agent=self.reconnaissance_agent,
            input_data=self.reconnaissance_agent.prepare_input(
                reconnaissance_context
            ),
        )
        self._validate_reconnaissance(
            context=reconnaissance_context,
            result=reconnaissance,
        )

        state = self._transition(state, WorkflowState.ATTACK_PLANNING)
        planning_catalog = (
            self.reconnaissance_service.build_attack_planning_catalog(
                target_id=target_id
            )
        )
        attack_plan = self._invoke_agent(
            agent=self.attack_planning_agent,
            input_data=self.attack_planning_agent.prepare_input(
                reconnaissance=reconnaissance,
                catalog=planning_catalog,
            ),
        )
        self._validate_attack_plan(
            reconnaissance=reconnaissance,
            catalog=planning_catalog,
            plan=attack_plan,
        )

        state = self._transition(state, WorkflowState.ATTACK_EXECUTING)
        execution = self.executor.execute_registered_test(
            test_id=attack_plan.test_id,
            attempt_number=attempt_number,
        )

        state = self._transition(state, WorkflowState.ATTACK_VERIFYING)
        if not self._execution_matches_plan(
            plan=attack_plan,
            execution=execution,
        ):
            state = self._transition(state, WorkflowState.REJECTED)
            return RedTeamRunResult(
                target_id=target_id,
                attempt_number=attempt_number,
                reconnaissance=reconnaissance,
                attack_plan=attack_plan,
                execution=execution,
                verification=None,
                final_state=state,
            )

        verification = self._invoke_agent(
            agent=self.attack_verification_agent,
            input_data=self.attack_verification_agent.prepare_input(
                plan=attack_plan,
                execution=execution,
            ),
        )

        if self._is_confirmed_verification(
            plan=attack_plan,
            execution=execution,
            verification=verification,
        ):
            state = self._transition(state, WorkflowState.BLUE_MONITORING)
        else:
            state = self._transition(state, WorkflowState.REJECTED)

        return RedTeamRunResult(
            target_id=target_id,
            attempt_number=attempt_number,
            reconnaissance=reconnaissance,
            attack_plan=attack_plan,
            execution=execution,
            verification=verification,
            final_state=state,
        )

    def _invoke_agent(
        self,
        *,
        agent: TypedReasoningAgent[AgentOutputT],
        input_data: Mapping[str, Any],
    ) -> AgentOutputT:
        """Authorize, count, invoke, then Pydantic-validate one model call."""
        self._require_policy(
            self.policy_engine.validate_model_call_budget(self.limits)
        )
        self.limits.consume_model_calls()
        raw_output = self.provider.generate_structured(
            role=agent.role,
            input_data=input_data,
            response_model=agent.output_model,
        )
        return agent.validate_output(raw_output)

    def _transition(
        self,
        current: WorkflowState,
        requested: WorkflowState,
    ) -> WorkflowState:
        self._require_policy(
            self.policy_engine.validate_state_transition(
                current=current,
                requested=requested,
            )
        )
        return requested

    def _validate_reconnaissance(
        self,
        *,
        context: RestrictedReconnaissanceContext,
        result: ReconnaissanceResult,
    ) -> None:
        if result.target_id != context.target_id:
            raise RedTeamFlowError(
                "reconnaissance target does not match the approved context"
            )

        approved = {
            endpoint.endpoint_id: endpoint
            for endpoint in context.endpoints
        }
        seen_endpoint_ids: set[str] = set()

        for observed in result.candidate_endpoints:
            if observed.endpoint_id in seen_endpoint_ids:
                raise RedTeamFlowError(
                    "reconnaissance returned a duplicate endpoint ID"
                )
            seen_endpoint_ids.add(observed.endpoint_id)

            registered = approved.get(observed.endpoint_id)
            if registered is None:
                raise RedTeamFlowError(
                    "reconnaissance introduced an unapproved endpoint"
                )
            if not set(observed.allowed_methods).issubset(
                registered.allowed_methods
            ):
                raise RedTeamFlowError(
                    "reconnaissance introduced an unapproved HTTP method"
                )
            if not set(observed.input_fields).issubset(
                registered.input_fields
            ):
                raise RedTeamFlowError(
                    "reconnaissance introduced an unapproved input field"
                )

    def _validate_attack_plan(
        self,
        *,
        reconnaissance: ReconnaissanceResult,
        catalog: AttackPlanningCatalog,
        plan: AttackPlan,
    ) -> None:
        if plan.target_id != catalog.target_id:
            raise RedTeamFlowError(
                "attack plan target does not match the planning catalog"
            )
        if plan.target_id != reconnaissance.target_id:
            raise RedTeamFlowError(
                "attack plan target does not match reconnaissance"
            )

        option = next(
            (item for item in catalog.options if item.test_id == plan.test_id),
            None,
        )
        if option is None:
            raise RedTeamFlowError(
                "attack plan selected a test outside the restricted catalog"
            )
        if plan.endpoint_id != option.endpoint_id:
            raise RedTeamFlowError(
                "attack plan endpoint does not match registered test metadata"
            )
        if plan.vulnerability_class != option.vulnerability_class:
            raise RedTeamFlowError(
                "attack plan vulnerability class does not match registered metadata"
            )
        if not set(plan.parameter_choices).issubset(
            option.allowed_parameter_names
        ):
            raise RedTeamFlowError(
                "attack plan contains an unregistered parameter name"
            )
        if not any(
            endpoint.endpoint_id == plan.endpoint_id
            for endpoint in reconnaissance.candidate_endpoints
        ):
            raise RedTeamFlowError(
                "attack plan endpoint was not identified by reconnaissance"
            )

        self._require_policy(
            self.policy_engine.validate_security_test(
                target_id=plan.target_id,
                test_id=plan.test_id,
                endpoint_id=plan.endpoint_id,
            )
        )

    @staticmethod
    def _execution_matches_plan(
        *,
        plan: AttackPlan,
        execution: TestExecutionResult,
    ) -> bool:
        return (
            execution.target_id == plan.target_id
            and execution.test_id == plan.test_id
        )

    @staticmethod
    def _is_confirmed_verification(
        *,
        plan: AttackPlan,
        execution: TestExecutionResult,
        verification: AttackVerification,
    ) -> bool:
        if verification.target_id != plan.target_id:
            return False
        if verification.test_id != plan.test_id:
            return False
        if not execution.completed or execution.timed_out:
            return False
        if not execution.evidence:
            return False

        evidence_ids = {item.evidence_id for item in execution.evidence}
        cited_ids = set(verification.evidence_ids)
        if not cited_ids.issubset(evidence_ids):
            return False

        if verification.confirmed and not cited_ids:
            return False

        return verification.confirmed

    @staticmethod
    def _require_policy(decision: PolicyDecision) -> None:
        if not decision.allowed:
            raise RedTeamPolicyBlocked(decision)
