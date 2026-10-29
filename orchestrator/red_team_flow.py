"""Model-free Red v1 stage coordination and the legacy Milestone 8 workflow."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, TypeVar
from uuid import uuid4

from pydantic import BaseModel

from agents.base import TypedReasoningAgent
from agents.red import AttackPlanningAgent, AttackVerificationAgent, ReconnaissanceAgent
from agents.red.contracts import RedWork, RedWorkResult, validate_worker_result
from llm.interface import StructuredGenerationProvider, require_research_recording_for_final_capable
from orchestrator.limits import RunLimitTracker
from orchestrator.policy_engine import PolicyEngine
from schemas.common import WorkflowState
from schemas.logging import AuditExecutionStatus, AuditPolicyDecision
from schemas.red_team import (
    AttackPlan,
    AttackPlanningCatalog,
    AttackVerification,
    ExecutionWork,
    PlanningWork,
    ReconnaissanceResult,
    RedTeamRunResult,
    RedWorkerStatus,
    RestrictedReconnaissanceContext,
    TestExecutionResult,
    VerificationWork,
)
from schemas.red_team_state import (
    AssessmentState,
    FindingState,
    StageDTO,
    StageState,
    StageTransitionEventDTO,
)
from schemas.verification import PolicyDecision
from services.audit_service import AuditService
from services.controlled_executor import ControlledExecutionBlocked, ControlledExecutor
from services.reconnaissance_service import ReconnaissanceService
from services.red_assessment_queue import RedAssessmentQueue
from services.red_evidence_store import RedEvidenceStore
from services.target_registry import TargetRegistry

AgentOutputT = TypeVar("AgentOutputT", bound=BaseModel)


class RedTeamFlowError(RuntimeError):
    """Raised when a Red Team recommendation fails deterministic validation."""


class RedTeamPolicyBlocked(RedTeamFlowError):
    """Raised when deterministic policy denies a Red Team workflow action."""

    def __init__(self, decision: PolicyDecision) -> None:
        super().__init__(decision.message)
        self.decision = decision


class RedStageBlocked(RedTeamFlowError):
    """A persisted assessment state or prerequisite denied stage dispatch."""


class RedStageExecutionError(RedTeamFlowError):
    """A worker raised or returned data outside its typed stage contract."""


_RED_STAGE_ORDER = (
    "reconnaissance",
    "planning",
    "execution",
    "verification",
)


class RedStageCoordinator:
    """Model-free coordinator over durable Red v1 stage contracts.

    Workers own their stage artifacts. This class owns only dependency checks,
    dispatch, and atomic stage-transition/event persistence.
    """

    def __init__(
        self,
        *,
        journal: RedEvidenceStore,
        workers: Mapping[str, Callable[[RedWork], RedWorkResult]],
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        event_id_factory: Callable[[], str] = lambda: f"event-{uuid4().hex}",
    ) -> None:
        if set(workers) != set(_RED_STAGE_ORDER):
            raise ValueError("coordinator requires exactly the four Red stage workers")
        self.journal = journal
        self.workers = dict(workers)
        self.clock = clock
        self.event_id_factory = event_id_factory

    def run_manual(self, task: RedWork) -> RedWorkResult:
        self._require_mode(task, "manual")
        return self._run_stage(task)

    def run_autonomous(self, tasks: Sequence[RedWork]) -> tuple[RedWorkResult, ...]:
        work = tuple(tasks)
        if not work:
            raise ValueError("autonomous dispatch requires at least one stage task")
        if any(task.scope != work[0].scope for task in work):
            raise RedStageBlocked("autonomous tasks must share one authorized scope")
        positions = [_RED_STAGE_ORDER.index(task.stage) for task in work]
        if positions != sorted(set(positions)):
            raise RedStageBlocked("autonomous tasks must follow dependency order")
        self._require_mode(work[0], "autonomous")
        results = []
        for task in work:
            result = self._run_stage(task)
            results.append(result)
            if result.status != RedWorkerStatus.SUCCEEDED:
                break
        return tuple(results)

    def _require_mode(self, task: RedWork, expected: str) -> None:
        snapshot, authorization = self.journal.store.load(task.scope.assessment_id)
        if snapshot.assessment.scope != task.scope or authorization.scope != task.scope:
            raise RedStageBlocked("task scope differs from persisted authorization")
        if snapshot.assessment.mode != expected:
            raise RedStageBlocked(f"assessment is not in {expected} mode")
        if snapshot.assessment.status != AssessmentState.RUNNING:
            raise RedStageBlocked("assessment is not running")

    def _run_stage(self, task: RedWork) -> RedWorkResult:
        snapshot, authorization = self.journal.store.load(task.scope.assessment_id)
        if authorization.scope != task.scope or snapshot.assessment.scope != task.scope:
            raise RedStageBlocked("task scope differs from persisted authorization")
        if snapshot.assessment.status != AssessmentState.RUNNING:
            raise RedStageBlocked("assessment is not running")
        current = next(
            (item for item in snapshot.stages if item.stage == task.stage), None
        )
        state = current.status if current is not None else StageState.NOT_STARTED
        if state == StageState.RUNNING:
            raise RedStageBlocked(
                f"{task.stage} has an interrupted running operation requiring recovery"
            )
        plan_version = self._task_plan_version(task)
        if state not in {StageState.READY, StageState.QUEUED}:
            self._transition(
                task, state, StageState.READY, "before_worker", plan_version,
            )
            state = StageState.READY

        reason = self._prerequisite_denial(task)
        if reason is not None:
            self._transition(
                task, state, StageState.BLOCKED, "before_worker", plan_version,
            )
            raise RedStageBlocked(reason)

        if state == StageState.READY:
            self._transition(
                task, state, StageState.QUEUED, "before_worker", plan_version,
            )
            state = StageState.QUEUED
        self._transition(
            task, state, StageState.RUNNING, "before_worker", plan_version,
        )
        try:
            result = validate_worker_result(task, self.workers[task.stage](task))
        except Exception as exc:
            self._transition(
                task,
                StageState.RUNNING,
                StageState.FAILED,
                "after_worker",
                plan_version,
            )
            raise RedStageExecutionError(f"{task.stage} worker failed") from exc

        final_state = StageState(result.status.value)
        final_plan = self._result_plan_version(task, result)
        if result.status == RedWorkerStatus.SUCCEEDED:
            denial = self._result_denial(task, result)
            if denial is not None:
                self._transition(
                    task,
                    StageState.RUNNING,
                    StageState.FAILED,
                    "after_worker",
                    plan_version,
                )
                raise RedStageExecutionError(denial)
        self._transition(
            task,
            StageState.RUNNING,
            final_state,
            "after_worker",
            final_plan,
        )
        return result

    def _prerequisite_denial(self, task: RedWork) -> str | None:
        snapshot, _ = self.journal.store.load(task.scope.assessment_id)
        stage_states = {item.stage: item.status for item in snapshot.stages}
        position = _RED_STAGE_ORDER.index(task.stage)
        for required in _RED_STAGE_ORDER[:position]:
            if stage_states.get(required) != StageState.SUCCEEDED:
                return f"{task.stage} requires succeeded {required}"

        if isinstance(task, PlanningWork):
            surface = snapshot.surfaces[-1] if snapshot.surfaces else None
            candidates = {item.candidate_id: item for item in snapshot.candidates}
            canonical = (
                tuple(candidates.get(candidate_id) for candidate_id in surface.candidate_ids)
                if surface is not None
                else ()
            )
            if (
                surface is None
                or surface.surface_revision != task.surface_revision
                or any(item is None for item in canonical)
                or tuple(sorted(canonical, key=lambda item: item.candidate_id))
                != tuple(sorted(task.candidates, key=lambda item: item.candidate_id))
            ):
                return "planning requires the persisted reconnaissance surface"
        elif isinstance(task, ExecutionWork):
            operation = next(
                (item for item in snapshot.operations if item.operation_id == task.operation_id),
                None,
            )
            if (
                operation is None
                or operation.plan_version != task.plan_version
                or operation.status != "approved"
            ):
                return "execution requires an approved operation on the active plan"
        elif isinstance(task, VerificationWork):
            operation = next(
                (item for item in snapshot.operations if item.operation_id == task.operation_id),
                None,
            )
            receipts = {
                item.receipt_id: item for item in self.journal.list_receipts(task.scope)
            }
            if (
                operation is None
                or operation.plan_version != task.plan_version
                or any(
                    receipt_id not in receipts
                    or receipts[receipt_id].operation_id != task.operation_id
                    for receipt_id in task.receipt_ids
                )
            ):
                return "verification requires persisted receipts for its operation"
        return None

    def _result_denial(self, task: RedWork, result: RedWorkResult) -> str | None:
        snapshot, _ = self.journal.store.load(task.scope.assessment_id)
        if task.stage == "reconnaissance":
            persisted = {item.candidate_id: item for item in snapshot.candidates}
            if any(persisted.get(item.candidate_id) != item for item in result.candidates):
                return "reconnaissance worker did not persist its candidate output"
            surface = snapshot.surfaces[-1] if snapshot.surfaces else None
            if surface is None or set(surface.candidate_ids) != {
                item.candidate_id for item in result.candidates
            }:
                return "reconnaissance worker did not persist its surface output"
        elif task.stage == "planning":
            plan = next(
                (item for item in snapshot.plans if item.plan_version == result.plan_version),
                None,
            )
            operations = {
                item.operation_id: item for item in snapshot.operations
                if item.plan_version == result.plan_version
            }
            if (
                plan is None
                or plan.status != "approved"
                or plan.surface_revision != task.surface_revision
                or set(operations) != set(result.operation_ids)
            ):
                return "planning worker did not persist its plan output"
            current_gap_ids = {
                item.gap_id
                for item in self.journal.list_coverage_gaps(task.scope)
                if item.surface_revision == task.surface_revision
                and item.status.value == "open"
            }
            if current_gap_ids != set(result.coverage_gap_ids):
                return "planning worker did not persist its coverage-gap output"
        elif task.stage == "execution":
            receipts = {
                item.receipt_id: item for item in self.journal.list_receipts(task.scope)
            }
            artifacts = {
                item.receipt_id: item for item in self.journal.list_evidence(task.scope)
            }
            if any(
                receipt_id not in receipts
                or receipts[receipt_id].operation_id != task.operation_id
                or receipts[receipt_id].plan_version != task.plan_version
                or receipt_id not in artifacts
                for receipt_id in result.receipt_ids
            ):
                return "execution worker did not persist its receipt output"
            try:
                for receipt_id in result.receipt_ids:
                    self.journal.read_evidence(
                        task.scope, receipts[receipt_id].evidence_id,
                    )
            except ValueError:
                return "execution worker persisted unreadable evidence"
        elif task.stage == "verification":
            if result.outcome == "not_tested":
                operation = next(
                    (
                        item for item in snapshot.operations
                        if item.operation_id == task.operation_id
                    ),
                    None,
                )
                gaps = self.journal.list_coverage_gaps(task.scope)
                if operation is None or not any(
                    item.candidate_id == operation.candidate_id
                    and item.test_id == operation.test_id
                    and item.reason == "not_tested"
                    and item.status.value == "open"
                    for item in gaps
                ):
                    return "verification worker did not persist its coverage gap"
            else:
                expected = FindingState(result.outcome)
                if not any(
                    item.operation_id == task.operation_id
                    and item.status == expected
                    and item.oracle_id == task.oracle_id
                    and item.evidence_receipt_ids == result.evidence_receipt_ids
                    for item in self.journal.list_findings(task.scope)
                ):
                    return "verification worker did not persist its finding output"
        return None

    def _transition(
        self,
        task: RedWork,
        previous: StageState,
        status: StageState,
        phase: str,
        plan_version: str | None,
    ) -> None:
        occurred_at = self.clock()
        stage = StageDTO(
            scope=task.scope,
            stage=task.stage,
            status=status,
            plan_version=plan_version,
        )
        event = StageTransitionEventDTO(
            scope=task.scope,
            event_id=self.event_id_factory(),
            stage=task.stage,
            previous_status=previous,
            status=status,
            phase=phase,
            occurred_at=occurred_at,
        )
        self.journal.transition_stage(stage, event)

    @staticmethod
    def _task_plan_version(task: RedWork) -> str | None:
        return task.plan_version if isinstance(task, (ExecutionWork, VerificationWork)) else None

    @staticmethod
    def _result_plan_version(task: RedWork, result: RedWorkResult) -> str | None:
        if isinstance(task, PlanningWork):
            return result.plan_version
        return RedStageCoordinator._task_plan_version(task)


class RedQueuedStageRunner:
    """Claim one durable queue lease and dispatch it through the T22 coordinator."""

    def __init__(
        self,
        *,
        queue: RedAssessmentQueue,
        coordinator: RedStageCoordinator,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if queue.store.path.resolve() != coordinator.journal.store.path.resolve():
            raise ValueError("queue and coordinator must share one assessment database")
        self.queue = queue
        self.coordinator = coordinator
        self.clock = clock

    def run_next(
        self, *, worker_id: str, claimed_at: datetime | None = None
    ) -> RedWorkResult | None:
        job = self.queue.claim_next(
            worker_id=worker_id,
            claimed_at=claimed_at or self.clock(),
        )
        if job is None:
            return None
        assert job.worker_id is not None and job.lease_id is not None
        assessment, _ = self.queue.store.load(job.work.scope.assessment_id)
        try:
            if assessment.assessment.mode == "manual":
                result = self.coordinator.run_manual(job.work)
            else:
                result = self.coordinator.run_autonomous((job.work,))[0]
        except Exception:
            self.queue.finish(
                job_id=job.job_id,
                lease_id=job.lease_id,
                worker_id=job.worker_id,
                status="failed",
                finished_at=self.clock(),
            )
            raise
        self.queue.finish(
            job_id=job.job_id,
            lease_id=job.lease_id,
            worker_id=job.worker_id,
            status=(
                "completed"
                if result.status == RedWorkerStatus.SUCCEEDED
                else "failed"
            ),
            finished_at=self.clock(),
        )
        return result


class RedTeamFlow:
    """Legacy single-attempt workflow retained for historical compatibility.

    Red v1 will use model-free stage contracts in agents.red.contracts.
    """

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
        require_research_recording_for_final_capable(provider)
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
