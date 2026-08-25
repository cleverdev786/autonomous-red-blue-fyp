"""Typed Blue Team triage and bounded source-analysis orchestration."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
import time
from typing import Any, TypeVar

from pydantic import BaseModel

from agents.base import TypedReasoningAgent
from agents.blue import CodeAnalysisAgent, MonitoringAgent, TriageAgent
from llm.interface import StructuredGenerationProvider
from orchestrator.limits import RunLimitTracker
from orchestrator.policy_engine import PolicyEngine
from schemas.blue_team import (
    BlueTeamAnalysisResult,
    CodeFinding,
    MonitoringResult,
    SourceReadResult,
    TriageResult,
)
from schemas.common import ClassificationLabel, WorkflowState
from schemas.experiments import ClassificationMode
from schemas.logging import (
    ApplicationLogEvent,
    AuditExecutionStatus,
    AuditPolicyDecision,
    LogReadResult,
)
from schemas.verification import PolicyDecision
from services.audit_service import AuditService
from services.rule_engine import RuleEngine
from services.source_reader import SourceReader
from services.target_registry import TargetRegistry


AgentOutputT = TypeVar("AgentOutputT", bound=BaseModel)
_VULNERABILITY_LABELS = {
    ClassificationLabel.SQL_INJECTION,
    ClassificationLabel.XSS,
    ClassificationLabel.PATH_TRAVERSAL,
}


class BlueTeamFlowError(RuntimeError):
    """Raised when Blue Team input or model output fails deterministic validation."""


class BlueTeamPolicyBlocked(BlueTeamFlowError):
    """Raised when deterministic policy denies a Blue Team workflow action."""

    def __init__(self, decision: PolicyDecision) -> None:
        super().__init__(decision.message)
        self.decision = decision


class BlueTeamFlow:
    """Coordinate comparable RQ2 triage and bounded source localization."""

    def __init__(
        self,
        *,
        target_registry: TargetRegistry,
        policy_engine: PolicyEngine,
        limits: RunLimitTracker,
        provider: StructuredGenerationProvider,
        audit_service: AuditService,
        project_root: Path,
    ) -> None:
        self.target_registry = target_registry
        self.policy_engine = policy_engine
        self.limits = limits
        self.provider = provider
        self.audit_service = audit_service
        self.rule_engine = RuleEngine()
        self.monitoring_agent = MonitoringAgent()
        self.triage_agent = TriageAgent()
        self.code_analysis_agent = CodeAnalysisAgent()
        self.source_reader = SourceReader(
            registry=target_registry,
            policy_engine=policy_engine,
            audit_service=audit_service,
            project_root=project_root,
        )

    def monitor(self, logs: LogReadResult) -> MonitoringResult:
        """Run the specialized monitoring role outside the RQ2 classifier path."""
        self._validate_logs(logs)
        result = self._invoke_agent(
            run_id=logs.run_id,
            agent=self.monitoring_agent,
            input_data=self.monitoring_agent.prepare_input(logs),
        )
        self._validate_monitoring(logs=logs, result=result)
        return result

    def classify(
        self,
        *,
        logs: LogReadResult,
        mode: ClassificationMode,
    ) -> TriageResult:
        """Return one comparable TriageResult for the selected frozen RQ2 mode."""
        self._validate_logs(logs)

        if mode == ClassificationMode.RULE_ONLY:
            result = self.rule_engine.classify(logs)
        elif mode == ClassificationMode.LLM_ONLY:
            result = self._invoke_agent(
                run_id=logs.run_id,
                agent=self.triage_agent,
                input_data=self.triage_agent.prepare_input(logs=logs),
            )
        elif mode == ClassificationMode.HYBRID:
            rule_result = self.rule_engine.classify(logs)
            result = self._invoke_agent(
                run_id=logs.run_id,
                agent=self.triage_agent,
                input_data=self.triage_agent.prepare_input(
                    logs=logs,
                    rule_result=rule_result,
                ),
            )
        else:  # pragma: no cover - Enum exhaustiveness guard.
            raise BlueTeamFlowError(f"unsupported classification mode: {mode!r}")

        self._validate_triage(logs=logs, result=result)
        return result

    def analyze_code(
        self,
        *,
        logs: LogReadResult,
        triage: TriageResult,
    ) -> CodeFinding | None:
        """Return a grounded code finding only for a supported vulnerability label."""
        self._validate_logs(logs)
        self._validate_triage(logs=logs, result=triage)
        if triage.classification not in _VULNERABILITY_LABELS:
            return None

        supporting_events = self._supporting_events(logs=logs, triage=triage)
        route_names = tuple(sorted({event.route_name for event in supporting_events}))
        source_context = self.source_reader.read_relevant(
            run_id=logs.run_id,
            target_id=logs.target_id,
            route_names=route_names,
        )
        if not source_context.snippets:
            raise BlueTeamFlowError("no approved source snippets matched supporting events")

        finding = self._invoke_agent(
            run_id=logs.run_id,
            agent=self.code_analysis_agent,
            input_data=self.code_analysis_agent.prepare_input(
                triage=triage,
                supporting_events=supporting_events,
                source_context=source_context,
            ),
        )
        self._validate_code_finding(
            logs=logs,
            source_context=source_context,
            finding=finding,
        )
        return finding

    def run(
        self,
        *,
        logs: LogReadResult,
        mode: ClassificationMode,
    ) -> BlueTeamAnalysisResult:
        """Run RQ2 triage and, when actionable, bounded source localization."""
        self._require_policy(
            run_id=logs.run_id,
            operation="target_authorization",
            target=logs.target_id,
            decision=self.policy_engine.validate_target(logs.target_id),
        )
        self._validate_logs(logs)

        state = WorkflowState.BLUE_MONITORING
        state = self._transition(
            run_id=logs.run_id,
            current=state,
            requested=WorkflowState.TRIAGE,
        )
        triage = self.classify(logs=logs, mode=mode)

        finding: CodeFinding | None = None
        if triage.classification in _VULNERABILITY_LABELS:
            state = self._transition(
                run_id=logs.run_id,
                current=state,
                requested=WorkflowState.CODE_ANALYSIS,
            )
            finding = self.analyze_code(logs=logs, triage=triage)

        return BlueTeamAnalysisResult(
            run_id=logs.run_id,
            target_id=logs.target_id,
            classification_mode=mode,
            triage=triage,
            code_finding=finding,
            final_state=state,
        )

    def _invoke_agent(
        self,
        *,
        run_id: str,
        agent: TypedReasoningAgent[AgentOutputT],
        input_data: Mapping[str, Any],
    ) -> AgentOutputT:
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
                component="blue_team_flow",
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
            component="blue_team_flow",
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

    def _validate_logs(self, logs: LogReadResult) -> None:
        self.target_registry.get_target(logs.target_id)
        mismatched = tuple(
            event.event_id for event in logs.events if event.run_id != logs.run_id
        )
        if mismatched:
            raise BlueTeamFlowError(
                "normalized events must all match LogReadResult.run_id"
            )

    @staticmethod
    def _validate_monitoring(
        *,
        logs: LogReadResult,
        result: MonitoringResult,
    ) -> None:
        if result.run_id != logs.run_id:
            raise BlueTeamFlowError("monitoring result run_id does not match logs")
        input_ids = {event.event_id for event in logs.events}
        event_ids = set(result.event_ids)
        suspicious_ids = set(result.suspicious_event_ids)
        if not event_ids.issubset(input_ids):
            raise BlueTeamFlowError("monitoring result introduced an unknown event ID")
        if not suspicious_ids.issubset(event_ids):
            raise BlueTeamFlowError(
                "suspicious monitoring IDs must be included in selected event IDs"
            )

    @staticmethod
    def _validate_triage(*, logs: LogReadResult, result: TriageResult) -> None:
        if result.run_id != logs.run_id:
            raise BlueTeamFlowError("triage result run_id does not match logs")
        input_ids = {event.event_id for event in logs.events}
        supporting_ids = set(result.supporting_event_ids)
        if not supporting_ids.issubset(input_ids):
            raise BlueTeamFlowError("triage result introduced an unknown supporting event ID")

        if result.classification in _VULNERABILITY_LABELS:
            if not result.is_suspicious:
                raise BlueTeamFlowError(
                    "vulnerability classifications must be marked suspicious"
                )
            if not supporting_ids:
                raise BlueTeamFlowError(
                    "vulnerability classifications must cite supporting events"
                )
        elif result.classification == ClassificationLabel.BENIGN and result.is_suspicious:
            raise BlueTeamFlowError("benign classification cannot be marked suspicious")

    @staticmethod
    def _supporting_events(
        *,
        logs: LogReadResult,
        triage: TriageResult,
    ) -> tuple[ApplicationLogEvent, ...]:
        by_id = {event.event_id: event for event in logs.events}
        return tuple(by_id[event_id] for event_id in triage.supporting_event_ids)

    @staticmethod
    def _validate_code_finding(
        *,
        logs: LogReadResult,
        source_context: SourceReadResult,
        finding: CodeFinding,
    ) -> None:
        if finding.run_id != logs.run_id:
            raise BlueTeamFlowError("code finding run_id does not match logs")
        if not finding.supporting_lines:
            raise BlueTeamFlowError("code finding must cite supplied source lines")

        snippets = tuple(
            snippet
            for snippet in source_context.snippets
            if snippet.file_path == finding.file_path
        )
        if not snippets:
            raise BlueTeamFlowError("code finding cited a file not supplied to the agent")

        for line_range in finding.supporting_lines:
            if not any(
                snippet.start_line <= line_range.start_line
                and line_range.end_line <= snippet.end_line
                for snippet in snippets
            ):
                raise BlueTeamFlowError(
                    "code finding cited lines outside supplied source context"
                )

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
            component="blue_team_flow",
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
            raise BlueTeamPolicyBlocked(decision)

    @staticmethod
    def _elapsed_ms(started: float) -> int:
        return max(0, int((time.monotonic() - started) * 1000))
