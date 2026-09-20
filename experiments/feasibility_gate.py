"""Role-separated F1-F4 orchestration for M20 DEVELOPMENT feasibility.

Every candidate uses the same four frozen zero-shot prompt assets. F2 and F3
contain 75 predetermined logical role-call slots per candidate. Role outputs are
independent and are aggregated only by trusted deterministic code after calls
complete. No model output is fed into another model prompt.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import json
from typing import Protocol

from pydantic import ValidationError

from experiments.feasibility import (
    evaluate_local_resource_feasibility,
    evaluate_provider_candidate,
    evaluate_semantic_feasibility,
    evaluate_stability_feasibility,
)
from experiments.feasibility_assets import LoadedFeasibilityAssets
from experiments.feasibility_role_calls import (
    PreparedFeasibilityRoleCall,
    build_role_call_slots,
    prepare_role_call,
)
from experiments.synthetic_verification import observation_from_response
from llm.no_retry import ProviderRetryCapability, validate_no_hidden_retry_capability
from schemas.feasibility import (
    FeasibilityCallMeasurement,
    LocalResourceEvidence,
    ProviderCandidateCategory,
    ProviderCandidateDecision,
    ProviderFeasibilityEvidence,
    ProviderIntegrationEvidence,
    SyntheticFixtureInput,
    SyntheticFixtureObservation,
)
from schemas.feasibility_gate import (
    FeasibilityCandidateDescriptor,
    FeasibilityRuntimeKind,
    SyntheticCandidateResponse,
)
from schemas.feasibility_role_calls import (
    FeasibilityCallPhase,
    FeasibilityRoleCallDispatchStatus,
    FeasibilityRoleCallRecord,
    FeasibilityRoleCallResultStatus,
    FeasibilityRoleCallSlot,
    FeasibilityRoleCallTransportResult,
    FeasibilityRoleFailureKind,
    FeasibilityRoleTask,
    FeasibilityRawRoleResponse,
)


class FeasibilityGateExecutionError(RuntimeError):
    """Raised when DEVELOPMENT feasibility execution violates the frozen protocol."""


class FeasibilityCandidateExecutor(Protocol):
    """Provider-neutral adapter for a later explicitly authorized DEVELOPMENT run.

    Post-dispatch provider failures must be returned as FeasibilityRoleCallTransportResult
    with an explicit failure_kind. The adapter must not retry or regenerate.
    """

    def integration_evidence(
        self,
        *,
        candidate: FeasibilityCandidateDescriptor,
    ) -> tuple[ProviderIntegrationEvidence, ProviderRetryCapability]:
        """Return trusted F1 integration/retry evidence without model inference."""

    def execute_role_call(
        self,
        *,
        candidate: FeasibilityCandidateDescriptor,
        fixture: SyntheticFixtureInput,
        call: PreparedFeasibilityRoleCall,
    ) -> FeasibilityRoleCallTransportResult:
        """Dispatch exactly one provider request for one predetermined logical slot."""

    def local_resource_evidence(
        self,
        *,
        candidate: FeasibilityCandidateDescriptor,
    ) -> LocalResourceEvidence | None:
        """Return F4 local resource evidence; cloud candidates return None."""


@dataclass(frozen=True)
class CandidateGateResult:
    """One candidate's complete DEVELOPMENT evidence without selecting a winner."""

    evidence: ProviderFeasibilityEvidence
    decision: ProviderCandidateDecision
    role_calls: tuple[FeasibilityRoleCallRecord, ...]
    observations: tuple[SyntheticFixtureObservation, ...]
    raw_responses: tuple[FeasibilityRawRoleResponse, ...]
    complete_schedule: bool


class FeasibilityGateOrchestrator:
    """Run the fixed F1-F4 plan without changing prompts, slots, or final state."""

    def __init__(self, *, assets: LoadedFeasibilityAssets) -> None:
        self.assets = assets
        self._input_map = {item.fixture_id: item for item in assets.inputs}
        self._truth_map = {item.truth.fixture_id: item for item in assets.truth_records}
        self._candidate_map = {item.spec.candidate_id: item for item in assets.candidates}
        self._prompts_by_task = assets.prompts_by_task
        self._slots = build_role_call_slots(assets.execution_plan)
        self._static_preflight()

    @property
    def predetermined_slots(self) -> tuple[FeasibilityRoleCallSlot, ...]:
        return self._slots

    def run_candidate(
        self,
        *,
        candidate_id: str,
        executor: FeasibilityCandidateExecutor,
        development_execution_authorized: bool,
    ) -> CandidateGateResult:
        """Run exactly the predetermined slots unless a catastrophic failure stops dispatch."""
        if not development_execution_authorized:
            raise FeasibilityGateExecutionError(
                "model execution is disabled until an explicit DEVELOPMENT gate authorizes it"
            )
        candidate = self._candidate(candidate_id)
        integration, retry_capability = executor.integration_evidence(candidate=candidate)
        validate_no_hidden_retry_capability(retry_capability)
        self._require_f1_pass(candidate=candidate, integration=integration, retry=retry_capability)

        records: list[FeasibilityRoleCallRecord] = []
        raw_responses: list[FeasibilityRawRoleResponse] = []
        terminal_failure: FeasibilityRoleFailureKind | None = None
        for slot in self._slots:
            fixture = self._input_map[slot.fixture_id]
            prepared = prepare_role_call(
                slot=slot,
                fixture=fixture,
                prompt=self._prompts_by_task[slot.task],
                generation_settings=self.assets.execution_plan.generation_settings,
            )
            if terminal_failure is not None:
                records.append(
                    self._incomplete_record(
                        candidate=candidate,
                        call=prepared,
                        failure_kind=terminal_failure,
                    )
                )
                continue

            try:
                transport = executor.execute_role_call(
                    candidate=candidate,
                    fixture=fixture,
                    call=prepared,
                )
            except Exception as exc:  # adapter exceptions make request accounting unknowable
                raise FeasibilityGateExecutionError(
                    "feasibility executor raised instead of returning preserved call evidence"
                ) from exc

            record, raw_response, stop = self._record_transport_result(
                candidate=candidate,
                fixture=fixture,
                call=prepared,
                transport=transport,
            )
            records.append(record)
            if raw_response is not None:
                raw_responses.append(raw_response)
            if stop:
                terminal_failure = (
                    record.failure_kind or FeasibilityRoleFailureKind.PROTOCOL_VIOLATION
                )

        role_calls = tuple(records)
        if len(role_calls) != self.assets.execution_plan.logical_call_slots_per_candidate:
            raise FeasibilityGateExecutionError("candidate did not preserve all predetermined slots")

        phase_observations = self._aggregate_observations(role_calls)
        observations = tuple(row for _, row in phase_observations)
        f2_observations = tuple(
            row for phase, row in phase_observations if phase == FeasibilityCallPhase.F2
        )
        f3_observations = tuple(
            row for phase, row in phase_observations if phase == FeasibilityCallPhase.F3
        )
        semantic = evaluate_semantic_feasibility(
            truths=self.assets.truths,
            observations=f2_observations,
        )
        stability = evaluate_stability_feasibility(
            truths=self.assets.truths,
            observations=f3_observations,
        )

        resource_evidence = executor.local_resource_evidence(candidate=candidate)
        resource_reasons: tuple[str, ...]
        if candidate.runtime_kind == FeasibilityRuntimeKind.LOCAL_LLAMA_CPP:
            if resource_evidence is None:
                raise FeasibilityGateExecutionError("local F4 execution requires LocalResourceEvidence")
            resource_pass, resource_reasons = evaluate_local_resource_feasibility(resource_evidence)
        else:
            if resource_evidence is not None:
                raise FeasibilityGateExecutionError(
                    "cloud candidate must not report local machine resource evidence"
                )
            resource_pass, resource_reasons = True, ()

        complete_schedule = terminal_failure is None
        if not complete_schedule:
            resource_pass = False
            resource_reasons = resource_reasons + (
                "candidate execution terminated before all predetermined slots dispatched",
            )

        decision = evaluate_provider_candidate(
            candidate=candidate.spec,
            integration=integration,
            semantic=semantic,
            stability=stability,
            resource_pass=resource_pass,
            resource_failure_reasons=resource_reasons,
        )
        evidence = ProviderFeasibilityEvidence(
            candidate=candidate.spec,
            integration=integration,
            semantic=semantic,
            stability=stability,
            local_resource=resource_evidence,
            measurements=_measurements(role_calls),
        )
        return CandidateGateResult(
            evidence=evidence,
            decision=decision,
            role_calls=role_calls,
            observations=observations,
            raw_responses=tuple(raw_responses),
            complete_schedule=complete_schedule,
        )

    def _static_preflight(self) -> None:
        plan = self.assets.execution_plan
        f2 = [slot for slot in self._slots if slot.phase == FeasibilityCallPhase.F2]
        f3 = [slot for slot in self._slots if slot.phase == FeasibilityCallPhase.F3]
        if len(f2) != 30 or len(f3) != 45 or len(self._slots) != 75:
            raise FeasibilityGateExecutionError("role-call schedule is not exactly 30/45/75")
        if sum(slot.task == FeasibilityRoleTask.PATCH_GENERATION for slot in f2) != 6:
            raise FeasibilityGateExecutionError("F2 must contain exactly six patch-generation slots")
        if sum(slot.task == FeasibilityRoleTask.PATCH_GENERATION for slot in f3) != 9:
            raise FeasibilityGateExecutionError("F3 must contain exactly nine patch-generation slots")
        if plan.provider_selection_deferred is not True or plan.final_evaluation_forbidden is not True:
            raise FeasibilityGateExecutionError("feasibility plan must defer selection and forbid final evaluation")
        for prompt in self.assets.prompts:
            if not prompt.system_prompt.endswith("/no_think"):
                raise FeasibilityGateExecutionError("every feasibility prompt must end with /no_think")

    def _require_f1_pass(
        self,
        *,
        candidate: FeasibilityCandidateDescriptor,
        integration: ProviderIntegrationEvidence,
        retry: ProviderRetryCapability,
    ) -> None:
        checks = {
            "provider/model identity is not verified": integration.identity_verified,
            "structured output is unavailable": integration.structured_output_supported,
            "research recording is incompatible": integration.research_recording_compatible,
            "automatic retries are not disabled": integration.automatic_retries_disabled,
            "actual provider request count is not observable": integration.actual_request_count_observable,
            "unrestricted tools are not disabled": integration.unrestricted_tools_disabled,
            "provider/model failed to load or connect": integration.load_or_connect_succeeded,
            "retry capability cannot observe actual request count": retry.actual_request_count_observable,
        }
        if candidate.spec.category == ProviderCandidateCategory.ZERO_COST_CLOUD:
            checks["zero-cost cloud access is not verified"] = integration.zero_cost_verified is True
        failures = [message for message, passed in checks.items() if not passed]
        if failures:
            raise FeasibilityGateExecutionError("F1 pre-dispatch failed: " + "; ".join(failures))

    def _record_transport_result(
        self,
        *,
        candidate: FeasibilityCandidateDescriptor,
        fixture: SyntheticFixtureInput,
        call: PreparedFeasibilityRoleCall,
        transport: FeasibilityRoleCallTransportResult,
    ) -> tuple[FeasibilityRoleCallRecord, FeasibilityRawRoleResponse | None, bool]:
        raw_sha = (
            hashlib.sha256(transport.raw_response_text.encode("utf-8")).hexdigest()
            if transport.raw_response_text is not None
            else None
        )
        common = self._record_common(candidate=candidate, call=call)
        raw_evidence = (
            FeasibilityRawRoleResponse(
                call_id=common["call_id"],
                sha256=raw_sha,
                raw_response_text=transport.raw_response_text,
            )
            if raw_sha is not None and transport.raw_response_text is not None
            else None
        )

        if transport.actual_request_count != 1:
            return (
                FeasibilityRoleCallRecord(
                    **common,
                    dispatch_status=FeasibilityRoleCallDispatchStatus.DISPATCHED,
                    actual_request_count=transport.actual_request_count,
                    duration_ms=transport.duration_ms,
                    input_tokens=transport.input_tokens,
                    output_tokens=transport.output_tokens,
                    raw_response_sha256=raw_sha,
                    result_status=FeasibilityRoleCallResultStatus.FAILED,
                    failure_kind=FeasibilityRoleFailureKind.HIDDEN_RETRY,
                ),
                raw_evidence,
                True,
            )

        if transport.failure_kind is not None:
            return (
                FeasibilityRoleCallRecord(
                    **common,
                    dispatch_status=FeasibilityRoleCallDispatchStatus.DISPATCHED,
                    actual_request_count=1,
                    duration_ms=transport.duration_ms,
                    input_tokens=transport.input_tokens,
                    output_tokens=transport.output_tokens,
                    raw_response_sha256=raw_sha,
                    result_status=FeasibilityRoleCallResultStatus.FAILED,
                    failure_kind=transport.failure_kind,
                ),
                raw_evidence,
                transport.catastrophic,
            )

        if transport.raw_response_text is None:
            return (
                FeasibilityRoleCallRecord(
                    **common,
                    dispatch_status=FeasibilityRoleCallDispatchStatus.DISPATCHED,
                    actual_request_count=1,
                    duration_ms=transport.duration_ms,
                    input_tokens=transport.input_tokens,
                    output_tokens=transport.output_tokens,
                    result_status=FeasibilityRoleCallResultStatus.FAILED,
                    failure_kind=FeasibilityRoleFailureKind.EMPTY_RESPONSE,
                ),
                raw_evidence,
                False,
            )

        try:
            payload = json.loads(transport.raw_response_text)
            parsed = call.response_model.model_validate(payload)
        except (json.JSONDecodeError, ValidationError, TypeError, ValueError):
            return (
                FeasibilityRoleCallRecord(
                    **common,
                    dispatch_status=FeasibilityRoleCallDispatchStatus.DISPATCHED,
                    actual_request_count=1,
                    duration_ms=transport.duration_ms,
                    input_tokens=transport.input_tokens,
                    output_tokens=transport.output_tokens,
                    raw_response_sha256=raw_sha,
                    result_status=FeasibilityRoleCallResultStatus.FAILED,
                    failure_kind=FeasibilityRoleFailureKind.SCHEMA_INVALID,
                ),
                raw_evidence,
                False,
            )

        if not self._role_response_semantically_bounded(
            task=call.slot.task,
            fixture=fixture,
            parsed=parsed.model_dump(mode="json"),
        ):
            return (
                FeasibilityRoleCallRecord(
                    **common,
                    dispatch_status=FeasibilityRoleCallDispatchStatus.DISPATCHED,
                    actual_request_count=1,
                    duration_ms=transport.duration_ms,
                    input_tokens=transport.input_tokens,
                    output_tokens=transport.output_tokens,
                    raw_response_sha256=raw_sha,
                    result_status=FeasibilityRoleCallResultStatus.FAILED,
                    failure_kind=FeasibilityRoleFailureKind.SEMANTIC_INVALID,
                ),
                raw_evidence,
                False,
            )

        return (
            FeasibilityRoleCallRecord(
                **common,
                dispatch_status=FeasibilityRoleCallDispatchStatus.DISPATCHED,
                actual_request_count=1,
                duration_ms=transport.duration_ms,
                input_tokens=transport.input_tokens,
                output_tokens=transport.output_tokens,
                raw_response_sha256=raw_sha,
                parsed_response=parsed.model_dump(mode="json"),
                result_status=FeasibilityRoleCallResultStatus.COMPLETED,
            ),
            raw_evidence,
            False,
        )

    def _role_response_semantically_bounded(
        self,
        *,
        task: FeasibilityRoleTask,
        fixture: SyntheticFixtureInput,
        parsed: dict[str, object],
    ) -> bool:
        if parsed.get("fixture_id") != fixture.fixture_id:
            return False
        if task == FeasibilityRoleTask.TEST_SELECTION:
            selected = parsed.get("selected_registered_test_id")
            return selected is None or selected in {item.test_id for item in fixture.registered_tests}
        if task == FeasibilityRoleTask.SOURCE_ANALYSIS:
            source = parsed.get("predicted_source_file")
            function = parsed.get("predicted_function_or_route")
            visible = {item.file_path: item.content for item in fixture.source_files}
            if source is not None and source not in visible:
                return False
            if function is None:
                return True
            candidate_sources = [visible[source]] if source is not None else list(visible.values())
            return any(function in _top_level_function_names(text) for text in candidate_sources)
        return True

    def _aggregate_observations(
        self,
        role_calls: tuple[FeasibilityRoleCallRecord, ...],
    ) -> tuple[tuple[FeasibilityCallPhase, SyntheticFixtureObservation], ...]:
        groups: dict[tuple[FeasibilityCallPhase, str, int], list[FeasibilityRoleCallRecord]] = {}
        for record in role_calls:
            groups.setdefault(
                (record.phase, record.fixture_id, record.repetition_index), []
            ).append(record)

        observations: list[tuple[FeasibilityCallPhase, SyntheticFixtureObservation]] = []
        for (phase, fixture_id, repetition_index), rows in groups.items():
            fixture = self._input_map[fixture_id]
            truth = self._truth_map[fixture_id]
            by_task = {row.task: row for row in rows}
            response = SyntheticCandidateResponse(
                fixture_id=fixture_id,
                repetition_index=repetition_index,
                schema_valid=all(
                    row.result_status == FeasibilityRoleCallResultStatus.COMPLETED for row in rows
                ),
                predicted_classification=_parsed_field(
                    by_task.get(FeasibilityRoleTask.CLASSIFICATION), "predicted_classification"
                ),
                predicted_source_file=_parsed_field(
                    by_task.get(FeasibilityRoleTask.SOURCE_ANALYSIS), "predicted_source_file"
                ),
                predicted_function_or_route=_parsed_field(
                    by_task.get(FeasibilityRoleTask.SOURCE_ANALYSIS),
                    "predicted_function_or_route",
                ),
                selected_registered_test_id=_parsed_field(
                    by_task.get(FeasibilityRoleTask.TEST_SELECTION),
                    "selected_registered_test_id",
                ),
                replacement_file_path=_parsed_field(
                    by_task.get(FeasibilityRoleTask.PATCH_GENERATION),
                    "replacement_file_path",
                ),
                replacement_source=_parsed_field(
                    by_task.get(FeasibilityRoleTask.PATCH_GENERATION), "replacement_source"
                ),
                duration_ms=sum(row.duration_ms for row in rows),
                input_tokens=_sum_complete_telemetry(rows, "input_tokens"),
                output_tokens=_sum_complete_telemetry(rows, "output_tokens"),
            )
            observation = observation_from_response(
                fixture=fixture,
                truth_record=truth,
                response=response,
            )
            observations.append((phase, observation))
        observations.sort(
            key=lambda item: (
                0 if item[0] == FeasibilityCallPhase.F2 else 1,
                self._fixture_order(item[1].fixture_id),
                item[1].repetition_index,
            )
        )
        return tuple(observations)

    def _incomplete_record(
        self,
        *,
        candidate: FeasibilityCandidateDescriptor,
        call: PreparedFeasibilityRoleCall,
        failure_kind: FeasibilityRoleFailureKind,
    ) -> FeasibilityRoleCallRecord:
        return FeasibilityRoleCallRecord(
            **self._record_common(candidate=candidate, call=call),
            dispatch_status=FeasibilityRoleCallDispatchStatus.NOT_DISPATCHED,
            actual_request_count=0,
            result_status=FeasibilityRoleCallResultStatus.INCOMPLETE,
            failure_kind=failure_kind,
        )

    def _record_common(
        self,
        *,
        candidate: FeasibilityCandidateDescriptor,
        call: PreparedFeasibilityRoleCall,
    ) -> dict[str, object]:
        slot = call.slot
        return {
            "call_id": _call_id(candidate.spec.candidate_id, slot),
            "candidate_id": candidate.spec.candidate_id,
            "phase": slot.phase,
            "fixture_id": slot.fixture_id,
            "repetition_index": slot.repetition_index,
            "task": slot.task,
            "agent_role": slot.agent_role,
            "prompt_id": call.prompt.prompt_id,
            "prompt_version": call.prompt.version,
            "system_prompt_sha256": call.system_prompt_sha256,
            "canonical_user_payload_sha256": call.canonical_user_payload_sha256,
            "response_schema_id": call.response_schema_id,
            "response_schema_sha256": call.response_schema_sha256,
            "generation_settings_sha256": call.generation_settings_sha256,
            "provider": candidate.spec.provider_identity,
            "model_name": candidate.spec.model_identity,
        }

    def _candidate(self, candidate_id: str) -> FeasibilityCandidateDescriptor:
        try:
            return self._candidate_map[candidate_id]
        except KeyError as exc:
            raise FeasibilityGateExecutionError("unknown feasibility candidate ID") from exc

    def _fixture_order(self, fixture_id: str) -> int:
        order = {item: index for index, item in enumerate(self.assets.execution_plan.f2_fixture_ids)}
        return order[fixture_id]

def _call_id(candidate_id: str, slot: FeasibilityRoleCallSlot) -> str:
    return (
        f"m20-{candidate_id}-{slot.phase.value}-{slot.fixture_id}-"
        f"r{slot.repetition_index}-{slot.task.value}"
    )


def _parsed_field(record: FeasibilityRoleCallRecord | None, field: str):
    if record is None or record.result_status != FeasibilityRoleCallResultStatus.COMPLETED:
        return None
    assert record.parsed_response is not None
    return record.parsed_response.get(field)


def _sum_complete_telemetry(rows: list[FeasibilityRoleCallRecord], field: str) -> int | None:
    values = [getattr(row, field) for row in rows]
    if any(value is None for value in values):
        return None
    return sum(int(value) for value in values if value is not None)


def _top_level_function_names(source: str) -> set[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()
    return {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _measurements(
    role_calls: tuple[FeasibilityRoleCallRecord, ...],
) -> tuple[FeasibilityCallMeasurement, ...]:
    rows: list[FeasibilityCallMeasurement] = []
    for record in role_calls:
        if record.dispatch_status != FeasibilityRoleCallDispatchStatus.DISPATCHED:
            continue
        if record.input_tokens is None or record.output_tokens is None:
            continue
        completed = record.result_status == FeasibilityRoleCallResultStatus.COMPLETED
        rows.append(
            FeasibilityCallMeasurement(
                measurement_id=record.call_id,
                input_tokens=record.input_tokens,
                output_tokens=record.output_tokens,
                duration_ms=record.duration_ms,
                schema_valid=completed,
                semantically_usable=completed,
            )
        )
    return tuple(rows)
