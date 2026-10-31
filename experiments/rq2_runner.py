"""Truth-isolated executor for the frozen RQ2 classifier dataset."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
import time
from typing import Any

from llm.interface import StructuredGenerationProvider
from llm.research_provider import ResearchRecordingProvider
from orchestrator.limits import RunLimitTracker
from orchestrator.policy_engine import PolicyEngine
from schemas.common import AgentRole, ClassificationLabel, ResearchQuestion, RunType
from schemas.experiments import ClassificationMode, ExperimentConfiguration
from schemas.rq2_dataset import RQ2ClassificationDecision
from schemas.logging import AuditExecutionStatus, AuditPolicyDecision
from services.audit_service import AuditService
from services.rule_engine import RuleEngine
from services.target_registry import TargetRegistry
from experiments.rq2_dataset import (
    RQ2_DATASET_ID,
    load_classifier_dataset,
    materialize_log_read_result,
)
from storage.repositories import ExperimentExecutionReadRepository, ExperimentWriteRepository


class RQ2RunnerError(RuntimeError):
    """Raised when frozen classifier execution violates RQ2 controls."""


@dataclass(frozen=True, slots=True)
class RQ2ExecutionResult:
    run_id: str
    classification_mode: ClassificationMode
    observation_count: int


def validate_rq2_configuration_set(configurations: tuple[ExperimentConfiguration, ...]) -> None:
    """Compatibility export; canonical implementation lives in experiments.freeze."""
    from experiments.freeze import validate_rq2_configuration_set as _validate

    _validate(configurations)


class RQ2ExperimentRunner:
    """Evaluate classifier-visible M18 inputs without loading evaluator truth."""

    def __init__(
        self,
        *,
        target_registry: TargetRegistry,
        policy_engine: PolicyEngine,
        provider: StructuredGenerationProvider | None,
        audit_service: AuditService,
        execution_repository: ExperimentExecutionReadRepository,
        write_repository: ExperimentWriteRepository,
    ) -> None:
        self.target_registry = target_registry
        self.policy_engine = policy_engine
        self.provider = provider
        self.audit_service = audit_service
        self.execution_repository = execution_repository
        self.write_repository = write_repository
        self.rule_engine = RuleEngine()

    def run(
        self,
        *,
        run_id: str,
        dataset_dir: Path,
        target_id: str,
    ) -> RQ2ExecutionResult:
        stored = self.execution_repository.run_context(run_id)
        config = stored.configuration
        if config.research_question != ResearchQuestion.RQ2:
            raise RQ2RunnerError("RQ2ExperimentRunner requires a stored RQ2 configuration")
        if config.dataset_id != RQ2_DATASET_ID or stored.dataset_id != RQ2_DATASET_ID:
            raise RQ2RunnerError("stored RQ2 run/config does not reference rq2-classification")
        self.target_registry.get_target(target_id)

        items = load_classifier_dataset(dataset_dir)
        database_items = self._database_item_map(
            dataset_id=RQ2_DATASET_ID,
            dataset_version="v1",
        )
        if tuple(database_items) != tuple(item.event_id for item in items):
            raise RQ2RunnerError("database classifier item order/identity differs from frozen inputs")
        for item in items:
            db_id, db_hash = database_items[item.event_id]
            if db_hash != item.classifier_input_sha256:
                raise RQ2RunnerError("database classifier item hash differs from frozen input")
            if db_id < 1:
                raise RQ2RunnerError("invalid dataset item database identity")

        limits = RunLimitTracker(config.limits)
        recording_provider: ResearchRecordingProvider | None = None
        if config.classification_mode != ClassificationMode.RULE_ONLY:
            if self.provider is None:
                raise RQ2RunnerError("model-using RQ2 condition requires a provider")
            recording_provider = ResearchRecordingProvider(
                delegate=self.provider,
                run_id=run_id,
                model_configuration=config.model,
                first_sequence_number=self.execution_repository.next_agent_sequence(run_id),
                write_repository=None,
                require_verified_binding=(config.run_type == RunType.FINAL_EVALUATION),
            )

        observation_count = 0
        for index, item in enumerate(items, start=1):
            started = time.monotonic()
            internal_logs = materialize_log_read_result(
                item,
                target_id=target_id,
                run_id=run_id,
                request_id=f"rq2item-{index:03d}",
                timestamp=datetime(2000, 1, 1, tzinfo=UTC),
            )
            rule_result = self.rule_engine.classify(internal_logs)
            try:
                decision = self._classify(
                    config=config,
                    limits=limits,
                    provider=recording_provider,
                    item=item,
                    rule_result=rule_result,
                    run_id=run_id,
                )
            except Exception:
                if recording_provider is not None:
                    self._flush_failed_call(recording_provider, run_id=run_id)
                raise

            duration_ms = max(0, int((time.monotonic() - started) * 1000))
            dataset_item_id = database_items[item.event_id][0]
            observation_id = self.write_repository.record_event_classification(
                run_id=run_id,
                dataset_item_id=dataset_item_id,
                classification_mode=config.classification_mode,
                predicted_label=decision.classification,
                confidence=decision.confidence,
                duration_ms=duration_ms,
            )
            if config.classification_mode != ClassificationMode.RULE_ONLY:
                if recording_provider is None:  # pragma: no cover - guarded above
                    raise RQ2RunnerError("model-using RQ2 condition lacks recorder")
                call = recording_provider.pop_pending_call().model_copy(
                    update={"classification_observation_id": observation_id}
                )
                self.write_repository.record_agent_call(run_id, call)
            observation_count += 1

        return RQ2ExecutionResult(
            run_id=run_id,
            classification_mode=config.classification_mode,
            observation_count=observation_count,
        )

    def _classify(
        self,
        *,
        config: ExperimentConfiguration,
        limits: RunLimitTracker,
        provider: ResearchRecordingProvider | None,
        item,
        rule_result,
        run_id: str,
    ) -> RQ2ClassificationDecision:
        if config.classification_mode == ClassificationMode.RULE_ONLY:
            return RQ2ClassificationDecision(
                classification=rule_result.classification,
                confidence=rule_result.confidence,
                reason=rule_result.reason,
            )

        if provider is None:
            raise RQ2RunnerError("model-using RQ2 condition requires a provider")
        decision = self.policy_engine.validate_model_call_budget(limits)
        self.audit_service.record(
            run_id=run_id,
            component="rq2_runner",
            actor_type="orchestrator",
            operation="model_call_authorization",
            target=AgentRole.BLUE_TRIAGE.value,
            policy_decision=(
                AuditPolicyDecision.ALLOWED if decision.allowed else AuditPolicyDecision.BLOCKED
            ),
            policy_reason=decision.reason_code,
            execution_status=(
                AuditExecutionStatus.AUTHORIZED if decision.allowed else AuditExecutionStatus.BLOCKED
            ),
            error_code=None if decision.allowed else "policy-blocked",
        )
        if not decision.allowed:
            raise RQ2RunnerError("model-call budget denied RQ2 classifier invocation")
        limits.consume_model_calls()
        payload: dict[str, Any] = {
            "event_id": item.event_id,
            "normalized_event": item.normalized_event.model_dump(mode="json"),
            "allowed_labels": [label.value for label in ClassificationLabel],
        }
        if config.classification_mode == ClassificationMode.HYBRID:
            payload["rule_result"] = {
                "classification": rule_result.classification.value,
                "confidence": rule_result.confidence,
                "reason": rule_result.reason,
            }
        started = time.monotonic()
        try:
            raw = provider.generate_structured(
                role=AgentRole.BLUE_TRIAGE,
                input_data=payload,
                response_model=RQ2ClassificationDecision,
            )
            result = RQ2ClassificationDecision.model_validate(raw)
        except Exception:
            self.audit_service.record(
                run_id=run_id,
                component="rq2_runner",
                actor_type="orchestrator",
                operation="model_call",
                target=AgentRole.BLUE_TRIAGE.value,
                policy_decision=AuditPolicyDecision.NOT_APPLICABLE,
                execution_status=AuditExecutionStatus.FAILED,
                duration_ms=max(0, int((time.monotonic() - started) * 1000)),
                error_code="model-call-failed",
            )
            raise
        self.audit_service.record(
            run_id=run_id,
            component="rq2_runner",
            actor_type="orchestrator",
            operation="model_call",
            target=AgentRole.BLUE_TRIAGE.value,
            policy_decision=AuditPolicyDecision.NOT_APPLICABLE,
            execution_status=AuditExecutionStatus.SUCCEEDED,
            duration_ms=max(0, int((time.monotonic() - started) * 1000)),
        )
        return result

    def _database_item_map(
        self,
        *,
        dataset_id: str,
        dataset_version: str,
    ) -> dict[str, tuple[int, str]]:
        rows = self.execution_repository.classifier_dataset_items(
            dataset_id=dataset_id,
            dataset_version=dataset_version,
        )
        return {
            row.event_id: (row.database_id, row.normalized_input_sha256)
            for row in rows
        }

    def _flush_failed_call(self, provider: ResearchRecordingProvider, *, run_id: str) -> None:
        for call in provider.drain_pending_calls():
            self.write_repository.record_agent_call(run_id, call)
