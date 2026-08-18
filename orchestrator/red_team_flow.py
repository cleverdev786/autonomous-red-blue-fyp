"""Typed Red Team workflow around the deterministic controlled executor."""

from __future__ import annotations

from collections.abc import Mapping
import time
from typing import Any, TypeVar

from pydantic import BaseModel

from agents.base import TypedReasoningAgent
from agents.red import AttackPlanningAgent, AttackVerificationAgent, ReconnaissanceAgent
from llm.interface import StructuredGenerationProvider
from orchestrator.limits import RunLimitTracker
from orchestrator.policy_engine import PolicyEngine
from schemas.common import WorkflowState
from schemas.logging import AuditExecutionStatus, AuditPolicyDecision
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
from services.audit_service import AuditService
from services.controlled_executor import ControlledExecutionBlocked, ControlledExecutor
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
    """Coordinate one policy-controlled, single-attempt Red Team run."""

    def __init__(
        self,
        *,
        target_registry: TargetRegistry,
        policy_engine: PolicyEngine,
        limits: RunLimitTracker,
        executor: ControlledExecutor,
        provider: StructuredGenerationProvider,
        audit_service: AuditService,
    ) -> None:
        self.target_registry = target_registry
        self.policy_engine = policy_engine
        self.limits = limits
        self.executor = executor
        self.provider = provider
        self.audit_service = audit_service
        self.reconnaissance_service = ReconnaissanceService(registry=target_registry)
        self.reconnaissance_agent = ReconnaissanceAgent()
        self.attack_planning_agent = AttackPlanningAgent()
        self.attack_verification_agent = AttackVerificationAgent()

    def run(
        self,
        *,
        run_id: str,
        target_id: str,
        attempt_number: int = 1,
    ) -> RedTeamRunResult:
        """Run the approved single-attempt flow from READY to handoff/rejection."""
        if attempt_number < 1:
            raise ValueError("attempt_number must be >= 1")

        self._require_policy(
            run_id=run_id,
            operation="target_authorization",
            target=target_id,
            decision=self.policy_engine.validate_target(target_id),
        )
        state = WorkflowState.READY

        state = self._transition(
            run_id=run_id,
            current=state,
            requested=WorkflowState.RECONNAISSANCE,
        )
        reconnaissance_context = self.reconnaissance_service.build_reconnaissance_context(
            target_id=target_id
        )
        reconnaissance = self._invoke_agent(
            run_id=run_id,
            agent=self.reconnaissance_agent,
            input_data=self.reconnaissance_agent.prepare_input(reconnaissance_context),
        )
        self._validate_reconnaissance(
            context=reconnaissance_context,
            result=reconnaissance,
        )

        state = self._transition(
            run_id=run_id,
            current=state,
            requested=WorkflowState.ATTACK_PLANNING,
        )
        planning_catalog = self.reconnaissance_service.build_attack_planning_catalog(
            target_id=target_id
        )
        attack_plan = self._invoke_agent(
            run_id=run_id,
            agent=self.attack_planning_agent,
            input_data=self.attack_planning_agent.prepare_input(
                reconnaissance=reconnaissance,
                catalog=planning_catalog,
            ),
        )
        self._validate_attack_plan(
            run_id=run_id,
            reconnaissance=reconnaissance,
            catalog=planning_catalog,
            plan=attack_plan,
        )

        state = self._transition(
            run_id=run_id,
            current=state,
            requested=WorkflowState.ATTACK_EXECUTING,
        )
        execution_started = time.monotonic()
        try:
            execution = self.executor.execute_registered_test(
                test_id=attack_plan.test_id,
                attempt_number=attempt_number,
                run_id=run_id,
            )
        except ControlledExecutionBlocked as exc:
            self.audit_service.record(
                run_id=run_id,
                component="red_team_flow",
                actor_type="orchestrator",
                operation="controlled_execution",
                target=attack_plan.test_id,
                policy_decision=AuditPolicyDecision.BLOCKED,
                policy_reason=exc.decision.reason_code,
                execution_status=AuditExecutionStatus.BLOCKED,
                duration_ms=self._elapsed_ms(execution_started),
                error_code="policy-blocked",
            )
            raise

        evidence_reference = ",".join(item.evidence_id for item in execution.evidence) or None
        self.audit_service.record(
            run_id=run_id,
            component="red_team_flow",
            actor_type="orchestrator",
            operation="controlled_execution",
            target=attack_plan.test_id,
            policy_decision=AuditPolicyDecision.NOT_APPLICABLE,
            execution_status=(
                AuditExecutionStatus.SUCCEEDED
                if execution.completed
                else AuditExecutionStatus.FAILED
            ),
            duration_ms=self._elapsed_ms(execution_started),
            evidence_reference=evidence_reference,
            error_code=execution.error_code,
        )

        state = self._transition(
            run_id=run_id,
            current=state,
            requested=WorkflowState.ATTACK_VERIFYING,
        )
        if not self._execution_matches_plan(plan=attack_plan, execution=execution):
            state = self._transition(
                run_id=run_id,
                current=state,
                requested=WorkflowState.REJECTED,
            )
            return RedTeamRunResult(
                run_id=run_id,
                target_id=target_id,
                attempt_number=attempt_number,
                reconnaissance=reconnaissance,
                attack_plan=attack_plan,
                execution=execution,
                verification=None,
                final_state=state,
            )

        verification = self._invoke_agent(
            run_id=run_id,
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
            state = self._transition(
                run_id=run_id,
                current=state,
                requested=WorkflowState.BLUE_MONITORING,
            )
        else:
            state = self._transition(
                run_id=run_id,
                current=state,
                requested=WorkflowState.REJECTED,
            )

        return RedTeamRunResult(
            run_id=run_id,
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
        run_id: str,
        agent: TypedReasoningAgent[AgentOutputT],
        input_data: Mapping[str, Any],
    ) -> AgentOutputT:
        """Authorize, count, invoke, then Pydantic-validate one model call."""
        self._require_policy(
            run_id=run_id,
            operation="model_call_authorization",
            target=agent.role.value,
            decision=self.policy_engine.validate_model_call_budget(self.limits),
        )
        self.limits.consume_model_calls()
        started = time.monotonic()
        try:
            raw_output = self.provider.generate_structured(
                role=agent.role,
                input_data=input_data,
                response_model=agent.output_model,
            )
            result = agent.validate_output(raw_output)
        except Exception:
            self.audit_service.record(
                run_id=run_id,
                component="red_team_flow",
                actor_type="orchestrator",
                operation="model_call",
                target=agent.role.value,
                policy_decision=AuditPolicyDecision.NOT_APPLICABLE,
                execution_status=AuditExecutionStatus.FAILED,
                duration_ms=self._elapsed_ms(started),
                error_code="model-call-failed",
            )
            raise

        self.audit_service.record(
            run_id=run_id,
            component="red_team_flow",
            actor_type="orchestrator",
            operation="model_call",
            target=agent.role.value,
            policy_decision=AuditPolicyDecision.NOT_APPLICABLE,
            execution_status=AuditExecutionStatus.SUCCEEDED,
            duration_ms=self._elapsed_ms(started),
        )
        return result

    def _transition(
        self,
        *,
        run_id: str,
        current: WorkflowState,
        requested: WorkflowState,
    ) -> WorkflowState:
        self._require_policy(
            run_id=run_id,
            operation="workflow_transition",
            target=f"{current.value}->{requested.value}",
            decision=self.policy_engine.validate_state_transition(
                current=current,
                requested=requested,
            ),
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

        approved = {endpoint.endpoint_id: endpoint for endpoint in context.endpoints}
        seen_endpoint_ids: set[str] = set()

        for observed in result.candidate_endpoints:
            if observed.endpoint_id in seen_endpoint_ids:
                raise RedTeamFlowError("reconnaissance returned a duplicate endpoint ID")
            seen_endpoint_ids.add(observed.endpoint_id)

            registered = approved.get(observed.endpoint_id)
            if registered is None:
                raise RedTeamFlowError("reconnaissance introduced an unapproved endpoint")
            if not set(observed.allowed_methods).issubset(registered.allowed_methods):
                raise RedTeamFlowError("reconnaissance introduced an unapproved HTTP method")
            if not set(observed.input_fields).issubset(registered.input_fields):
                raise RedTeamFlowError("reconnaissance introduced an unapproved input field")

    def _validate_attack_plan(
        self,
        *,
        run_id: str,
        reconnaissance: ReconnaissanceResult,
        catalog: AttackPlanningCatalog,
        plan: AttackPlan,
    ) -> None:
        if plan.target_id != catalog.target_id:
            raise RedTeamFlowError("attack plan target does not match the planning catalog")
        if plan.target_id != reconnaissance.target_id:
            raise RedTeamFlowError("attack plan target does not match reconnaissance")

        option = next((item for item in catalog.options if item.test_id == plan.test_id), None)
        if option is None:
            raise RedTeamFlowError("attack plan selected a test outside the restricted catalog")
        if plan.endpoint_id != option.endpoint_id:
            raise RedTeamFlowError("attack plan endpoint does not match registered test metadata")
        if plan.vulnerability_class != option.vulnerability_class:
            raise RedTeamFlowError(
                "attack plan vulnerability class does not match registered metadata"
            )
        if not set(plan.parameter_choices).issubset(option.allowed_parameter_names):
            raise RedTeamFlowError("attack plan contains an unregistered parameter name")
        if not any(
            endpoint.endpoint_id == plan.endpoint_id
            for endpoint in reconnaissance.candidate_endpoints
        ):
            raise RedTeamFlowError("attack plan endpoint was not identified by reconnaissance")

        self._require_policy(
            run_id=run_id,
            operation="registered_test_authorization",
            target=plan.test_id,
            decision=self.policy_engine.validate_security_test(
                target_id=plan.target_id,
                test_id=plan.test_id,
                endpoint_id=plan.endpoint_id,
            ),
        )

    @staticmethod
    def _execution_matches_plan(
        *,
        plan: AttackPlan,
        execution: TestExecutionResult,
    ) -> bool:
        return execution.target_id == plan.target_id and execution.test_id == plan.test_id

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

    def _require_policy(
        self,
        *,
        run_id: str,
        operation: str,
        target: str,
        decision: PolicyDecision,
    ) -> None:
        self.audit_service.record(
            run_id=run_id,
            component="red_team_flow",
            actor_type="orchestrator",
            operation=operation,
            target=target,
            policy_decision=(
                AuditPolicyDecision.ALLOWED
                if decision.allowed
                else AuditPolicyDecision.BLOCKED
            ),
            policy_reason=decision.reason_code,
            execution_status=(
                AuditExecutionStatus.AUTHORIZED
                if decision.allowed
                else AuditExecutionStatus.BLOCKED
            ),
            error_code=None if decision.allowed else "policy-blocked",
        )
        if not decision.allowed:
            raise RedTeamPolicyBlocked(decision)

    @staticmethod
    def _elapsed_ms(started: float) -> int:
        return max(0, int((time.monotonic() - started) * 1000))
