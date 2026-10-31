"""Frozen role-call preparation for M20 DEVELOPMENT feasibility execution."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any

from pydantic import BaseModel

from schemas.feasibility import SyntheticFixtureInput
from schemas.feasibility_gate import FeasibilityGateExecutionPlan
from schemas.feasibility_role_calls import (
    FeasibilityCallPhase,
    FeasibilityClassificationResponse,
    FeasibilityGenerationSettings,
    FeasibilityPatchResponse,
    FeasibilityRoleCallSlot,
    FeasibilityRoleTask,
    FeasibilitySourceAnalysisResponse,
    FeasibilityTestSelectionResponse,
    role_for_task,
)
from schemas.prompts import PromptAsset


_RESPONSE_MODELS: dict[FeasibilityRoleTask, type[BaseModel]] = {
    FeasibilityRoleTask.TEST_SELECTION: FeasibilityTestSelectionResponse,
    FeasibilityRoleTask.CLASSIFICATION: FeasibilityClassificationResponse,
    FeasibilityRoleTask.SOURCE_ANALYSIS: FeasibilitySourceAnalysisResponse,
    FeasibilityRoleTask.PATCH_GENERATION: FeasibilityPatchResponse,
}

_RESPONSE_SCHEMA_IDS: dict[FeasibilityRoleTask, str] = {
    FeasibilityRoleTask.TEST_SELECTION: "m20-dev-test-selection-response-v1",
    FeasibilityRoleTask.CLASSIFICATION: "m20-dev-classification-response-v1",
    FeasibilityRoleTask.SOURCE_ANALYSIS: "m20-dev-source-analysis-response-v1",
    FeasibilityRoleTask.PATCH_GENERATION: "m20-dev-patch-response-v1",
}


@dataclass(frozen=True)
class PreparedFeasibilityRoleCall:
    """Candidate-independent request envelope; only prompt/payload/schema are model-visible."""

    slot: FeasibilityRoleCallSlot
    prompt: PromptAsset
    response_model: type[BaseModel]
    response_schema_id: str
    canonical_user_payload: str
    response_json_schema: dict[str, Any]
    system_prompt_sha256: str
    canonical_user_payload_sha256: str
    response_schema_sha256: str
    generation_settings: FeasibilityGenerationSettings
    generation_settings_sha256: str


def canonical_json_text(value: object) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_model_sha256(value: object) -> str:
    return sha256_text(canonical_json_text(value))


def response_model_for_task(task: FeasibilityRoleTask) -> type[BaseModel]:
    return _RESPONSE_MODELS[task]


def response_schema_id_for_task(task: FeasibilityRoleTask) -> str:
    return _RESPONSE_SCHEMA_IDS[task]


def response_schema_sha256(task: FeasibilityRoleTask) -> str:
    schema = response_model_for_task(task).model_json_schema()
    return sha256_text(canonical_json_text(schema))


def canonical_fixture_payload(fixture: SyntheticFixtureInput) -> str:
    """The only user-message bytes allowed for every feasibility role call."""
    return canonical_json_text({"fixture": fixture.model_dump(mode="json")})


def generation_settings_sha256(settings: FeasibilityGenerationSettings) -> str:
    return canonical_model_sha256(settings)


def build_role_call_slots(plan: FeasibilityGateExecutionPlan) -> tuple[FeasibilityRoleCallSlot, ...]:
    """Build the immutable 30 F2 + 45 F3 schedule without consulting model output."""
    slots: list[FeasibilityRoleCallSlot] = []
    base_tasks = (
        FeasibilityRoleTask.TEST_SELECTION,
        FeasibilityRoleTask.CLASSIFICATION,
        FeasibilityRoleTask.SOURCE_ANALYSIS,
    )
    f2_patch = set(plan.f2_patch_fixture_ids)
    for fixture_id in plan.f2_fixture_ids:
        tasks = base_tasks + ((FeasibilityRoleTask.PATCH_GENERATION,) if fixture_id in f2_patch else ())
        for task in tasks:
            slots.append(
                FeasibilityRoleCallSlot(
                    phase=FeasibilityCallPhase.F2,
                    fixture_id=fixture_id,
                    repetition_index=1,
                    task=task,
                    agent_role=role_for_task(task),
                )
            )

    f3_patch = set(plan.f3_patch_fixture_ids)
    for fixture_id in plan.f3_fixture_ids:
        for repetition_index in (1, 2, 3):
            tasks = base_tasks + (
                (FeasibilityRoleTask.PATCH_GENERATION,) if fixture_id in f3_patch else ()
            )
            for task in tasks:
                slots.append(
                    FeasibilityRoleCallSlot(
                        phase=FeasibilityCallPhase.F3,
                        fixture_id=fixture_id,
                        repetition_index=repetition_index,
                        task=task,
                        agent_role=role_for_task(task),
                    )
                )

    f2_count = sum(slot.phase == FeasibilityCallPhase.F2 for slot in slots)
    f3_count = sum(slot.phase == FeasibilityCallPhase.F3 for slot in slots)
    if f2_count != plan.f2_logical_call_slots or f3_count != plan.f3_logical_call_slots:
        raise ValueError("role-call schedule differs from frozen F2/F3 logical-call counts")
    if len(slots) != plan.logical_call_slots_per_candidate:
        raise ValueError("role-call schedule differs from frozen per-candidate call count")
    return tuple(slots)


def prepare_role_call(
    *,
    slot: FeasibilityRoleCallSlot,
    fixture: SyntheticFixtureInput,
    prompt: PromptAsset,
    generation_settings: FeasibilityGenerationSettings,
) -> PreparedFeasibilityRoleCall:
    """Prepare a request without candidate identity, phase metadata, or prior model outputs."""
    if prompt.role != slot.agent_role:
        raise ValueError("prompt role does not match the predetermined role-call slot")
    payload = canonical_fixture_payload(fixture)
    response_model = response_model_for_task(slot.task)
    schema = response_model.model_json_schema()
    return PreparedFeasibilityRoleCall(
        slot=slot,
        prompt=prompt,
        response_model=response_model,
        response_schema_id=response_schema_id_for_task(slot.task),
        canonical_user_payload=payload,
        response_json_schema=schema,
        system_prompt_sha256=sha256_text(prompt.system_prompt),
        canonical_user_payload_sha256=sha256_text(payload),
        response_schema_sha256=sha256_text(canonical_json_text(schema)),
        generation_settings=generation_settings,
        generation_settings_sha256=generation_settings_sha256(generation_settings),
    )
