"""Tests for the repaired role-separated M20 DEVELOPMENT feasibility orchestration."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from experiments.feasibility_assets import load_feasibility_assets
from experiments.feasibility_gate import FeasibilityGateExecutionError, FeasibilityGateOrchestrator
from experiments.feasibility_role_calls import PreparedFeasibilityRoleCall
from llm.no_retry import ProviderRetryCapability
from schemas.common import ClassificationLabel
from schemas.feasibility import (
    LocalResourceEvidence,
    ProviderCandidateCategory,
    ProviderIntegrationEvidence,
)
from schemas.feasibility_gate import FeasibilityCandidateDescriptor
from schemas.feasibility_role_calls import (
    FeasibilityCallPhase,
    FeasibilityRoleCallResultStatus,
    FeasibilityRoleCallTransportResult,
    FeasibilityRoleFailureKind,
    FeasibilityRoleTask,
)


ASSET_ROOT = Path("experiments/development_assets")


REPLACEMENTS = {
    "dev-sqli-member-lookup-01": (
        'def find_member_by_email(cursor, email):\n'
        '    cursor.execute("SELECT id, email FROM members WHERE email = ?", (email,))\n'
        '    return cursor.fetchone()\n'
    ),
    "dev-sqli-invoice-load-02": (
        'def load_invoice(cursor, invoice_id):\n'
        '    cursor.execute("SELECT owner, total FROM invoices WHERE invoice_id = ?", '
        '(invoice_id,))\n'
        '    return cursor.fetchone()\n'
    ),
    "dev-xss-badge-preview-01": (
        'import html\n\n'
        'def preview_badge(nickname):\n'
        '    safe = html.escape(nickname)\n'
        '    return "<span class=\\\'badge\\\'>" + safe + "</span>"\n'
    ),
    "dev-xss-note-render-02": (
        'import html\n\n'
        'def render_note(note_body):\n'
        '    safe = html.escape(note_body)\n'
        '    return "<article>" + safe + "</article>"\n'
    ),
    "dev-path-export-download-01": (
        'from pathlib import Path\n\n'
        'EXPORT_ROOT = Path("/srv/synthetic/exports")\n\n'
        'def download_export(filename):\n'
        '    root = EXPORT_ROOT.resolve()\n'
        '    candidate = (root / filename).resolve()\n'
        '    candidate.relative_to(root)\n'
        '    return candidate.read_bytes()\n'
    ),
    "dev-path-asset-open-02": (
        'from pathlib import Path\n'
        'from urllib.parse import unquote\n\n'
        'ASSET_ROOT = Path("/srv/synthetic/assets")\n\n'
        'def open_asset(asset):\n'
        '    decoded = unquote(asset)\n'
        '    root = ASSET_ROOT.resolve()\n'
        '    candidate = (root / decoded).resolve()\n'
        '    candidate.relative_to(root)\n'
        '    return candidate.read_bytes()\n'
    ),
}


class _PerfectRoleExecutor:
    """Truth-backed fake used only for deterministic orchestration tests."""

    def __init__(
        self,
        *,
        actual_request_count: int = 1,
        malformed_call_number: int | None = None,
        catastrophic_call_number: int | None = None,
    ) -> None:
        self.actual_request_count = actual_request_count
        self.malformed_call_number = malformed_call_number
        self.catastrophic_call_number = catastrophic_call_number
        self.calls: list[PreparedFeasibilityRoleCall] = []
        assets = load_feasibility_assets(ASSET_ROOT)
        self.truths = {record.truth.fixture_id: record.truth for record in assets.truth_records}

    def integration_evidence(self, *, candidate: FeasibilityCandidateDescriptor):
        cloud = candidate.spec.category == ProviderCandidateCategory.ZERO_COST_CLOUD
        return (
            ProviderIntegrationEvidence(
                identity_verified=True,
                structured_output_supported=True,
                research_recording_compatible=True,
                automatic_retries_disabled=True,
                actual_request_count_observable=True,
                unrestricted_tools_disabled=True,
                load_or_connect_succeeded=True,
                zero_cost_verified=True if cloud else None,
            ),
            ProviderRetryCapability(
                automatic_retries_disabled=True,
                configured_max_retries=0,
                actual_request_count_observable=True,
            ),
        )

    def execute_role_call(self, *, candidate, fixture, call):
        del candidate
        self.calls.append(call)
        call_number = len(self.calls)
        if self.catastrophic_call_number == call_number:
            return FeasibilityRoleCallTransportResult(
                actual_request_count=1,
                duration_ms=25,
                failure_kind=FeasibilityRoleFailureKind.CATASTROPHIC_RUNTIME,
                catastrophic=True,
            )
        if self.malformed_call_number == call_number:
            return FeasibilityRoleCallTransportResult(
                actual_request_count=1,
                raw_response_text="{not-json",
                duration_ms=25,
                input_tokens=100,
                output_tokens=10,
            )
        truth = self.truths[fixture.fixture_id]
        benign = truth.expected_classification == ClassificationLabel.BENIGN
        if call.slot.task == FeasibilityRoleTask.TEST_SELECTION:
            payload = {
                "fixture_id": fixture.fixture_id,
                "selected_registered_test_id": None if benign else truth.expected_registered_test_id,
            }
        elif call.slot.task == FeasibilityRoleTask.CLASSIFICATION:
            payload = {
                "fixture_id": fixture.fixture_id,
                "predicted_classification": truth.expected_classification.value,
            }
        elif call.slot.task == FeasibilityRoleTask.SOURCE_ANALYSIS:
            payload = {
                "fixture_id": fixture.fixture_id,
                "predicted_source_file": None if benign else truth.expected_source_file,
                "predicted_function_or_route": None if benign else truth.expected_function_or_route,
            }
        else:
            payload = {
                "fixture_id": fixture.fixture_id,
                "replacement_file_path": truth.expected_source_file,
                "replacement_source": REPLACEMENTS[fixture.fixture_id],
            }
        return FeasibilityRoleCallTransportResult(
            actual_request_count=self.actual_request_count,
            raw_response_text=json.dumps(payload, sort_keys=True),
            duration_ms=25,
            input_tokens=100,
            output_tokens=20,
        )

    def local_resource_evidence(self, *, candidate: FeasibilityCandidateDescriptor):
        if candidate.spec.category == ProviderCandidateCategory.ZERO_COST_CLOUD:
            return None
        return LocalResourceEvidence(
            baseline_mem_available_bytes=8 * 1024**3,
            minimum_mem_available_bytes=2 * 1024**3,
            baseline_swap_used_bytes=0,
            peak_swap_used_bytes=512 * 1024**2,
            max_invocation_duration_ms=30_000,
            model_server_crash=self.catastrophic_call_number is not None,
        )


def test_predetermined_schedule_is_exactly_30_45_75_with_6_and_9_patch_slots() -> None:
    orchestrator = FeasibilityGateOrchestrator(assets=load_feasibility_assets(ASSET_ROOT))
    f2 = [row for row in orchestrator.predetermined_slots if row.phase == FeasibilityCallPhase.F2]
    f3 = [row for row in orchestrator.predetermined_slots if row.phase == FeasibilityCallPhase.F3]
    assert len(f2) == 30
    assert len(f3) == 45
    assert len(orchestrator.predetermined_slots) == 75
    assert sum(row.task == FeasibilityRoleTask.PATCH_GENERATION for row in f2) == 6
    assert sum(row.task == FeasibilityRoleTask.PATCH_GENERATION for row in f3) == 9
    assert not any(
        row.task == FeasibilityRoleTask.PATCH_GENERATION
        for row in orchestrator.predetermined_slots
        if row.fixture_id.startswith("dev-benign-")
    )


def test_orchestrator_refuses_execution_without_later_development_authorization() -> None:
    assets = load_feasibility_assets(ASSET_ROOT)
    orchestrator = FeasibilityGateOrchestrator(assets=assets)
    executor = _PerfectRoleExecutor()
    with pytest.raises(FeasibilityGateExecutionError, match="explicit DEVELOPMENT gate"):
        orchestrator.run_candidate(
            candidate_id="l2-qwen3-4b-q4-k-m",
            executor=executor,
            development_execution_authorized=False,
        )
    assert executor.calls == []


def test_complete_local_candidate_uses_75_independent_requests_and_20_observations() -> None:
    assets = load_feasibility_assets(ASSET_ROOT)
    executor = _PerfectRoleExecutor()
    result = FeasibilityGateOrchestrator(assets=assets).run_candidate(
        candidate_id="l2-qwen3-4b-q4-k-m",
        executor=executor,
        development_execution_authorized=True,
    )
    assert result.complete_schedule is True
    assert len(executor.calls) == 75
    assert len(result.role_calls) == 75
    assert len(result.raw_responses) == 75
    assert sum(row.actual_request_count for row in result.role_calls) == 75
    assert all(row.result_status == FeasibilityRoleCallResultStatus.COMPLETED for row in result.role_calls)
    assert len(result.observations) == 20
    assert result.evidence.semantic.passed is True
    assert result.evidence.stability.passed is True
    assert result.decision.eligible is True
    assert len(result.evidence.measurements) == 75


def test_role_calls_never_chain_prior_outputs_or_expose_phase_candidate_repetition() -> None:
    assets = load_feasibility_assets(ASSET_ROOT)
    executor = _PerfectRoleExecutor()
    FeasibilityGateOrchestrator(assets=assets).run_candidate(
        candidate_id="l1-qwen3-8b-q4-k-m",
        executor=executor,
        development_execution_authorized=True,
    )
    forbidden = {
        "candidate_id", "provider", "model", "phase", "repetition_index", "call_id",
        "expected_classification", "expected_source_file", "expected_function_or_route",
        "expected_registered_test_id", "replacement_source", "predicted_classification",
    }
    for call in executor.calls:
        payload = json.loads(call.canonical_user_payload)
        assert set(payload) == {"fixture"}
        assert forbidden.isdisjoint(payload["fixture"])
    same_fixture = [
        call for call in executor.calls
        if call.slot.phase == FeasibilityCallPhase.F3
        and call.slot.fixture_id == "dev-sqli-member-lookup-01"
        and call.slot.task == FeasibilityRoleTask.CLASSIFICATION
    ]
    assert len(same_fixture) == 3
    assert len({call.canonical_user_payload_sha256 for call in same_fixture}) == 1
    assert len({call.system_prompt_sha256 for call in same_fixture}) == 1
    assert len({call.response_schema_sha256 for call in same_fixture}) == 1


def test_malformed_role_output_is_preserved_without_retry_and_later_slots_continue() -> None:
    executor = _PerfectRoleExecutor(malformed_call_number=1)
    result = FeasibilityGateOrchestrator(assets=load_feasibility_assets(ASSET_ROOT)).run_candidate(
        candidate_id="l2-qwen3-4b-q4-k-m",
        executor=executor,
        development_execution_authorized=True,
    )
    assert len(executor.calls) == 75
    assert len(result.role_calls) == 75
    assert result.role_calls[0].failure_kind == FeasibilityRoleFailureKind.SCHEMA_INVALID
    assert result.role_calls[0].actual_request_count == 1
    assert len(result.raw_responses) == 75
    assert result.raw_responses[0].sha256 == result.role_calls[0].raw_response_sha256
    assert result.role_calls[1].result_status == FeasibilityRoleCallResultStatus.COMPLETED
    assert result.evidence.semantic.passed is False
    assert result.complete_schedule is True


def test_hidden_retry_is_preserved_then_remaining_slots_become_incomplete() -> None:
    executor = _PerfectRoleExecutor(actual_request_count=2)
    result = FeasibilityGateOrchestrator(assets=load_feasibility_assets(ASSET_ROOT)).run_candidate(
        candidate_id="l1-qwen3-8b-q4-k-m",
        executor=executor,
        development_execution_authorized=True,
    )
    assert len(executor.calls) == 1
    assert len(result.role_calls) == 75
    assert result.role_calls[0].failure_kind == FeasibilityRoleFailureKind.HIDDEN_RETRY
    assert result.role_calls[0].actual_request_count == 2
    assert all(
        row.result_status == FeasibilityRoleCallResultStatus.INCOMPLETE
        for row in result.role_calls[1:]
    )
    assert result.complete_schedule is False
    assert result.decision.eligible is False


def test_catastrophic_failure_keeps_all_remaining_predetermined_slots_incomplete() -> None:
    executor = _PerfectRoleExecutor(catastrophic_call_number=5)
    result = FeasibilityGateOrchestrator(assets=load_feasibility_assets(ASSET_ROOT)).run_candidate(
        candidate_id="l2-qwen3-4b-q4-k-m",
        executor=executor,
        development_execution_authorized=True,
    )
    assert len(executor.calls) == 5
    assert len(result.role_calls) == 75
    assert result.role_calls[4].failure_kind == FeasibilityRoleFailureKind.CATASTROPHIC_RUNTIME
    assert all(
        row.result_status == FeasibilityRoleCallResultStatus.INCOMPLETE
        for row in result.role_calls[5:]
    )
    assert result.complete_schedule is False
    assert result.decision.resource_pass is False


def test_cloud_candidate_uses_same_75_slot_protocol_without_local_resource_evidence() -> None:
    result = FeasibilityGateOrchestrator(assets=load_feasibility_assets(ASSET_ROOT)).run_candidate(
        candidate_id="c1-gemini-3.5-flash-lite",
        executor=_PerfectRoleExecutor(),
        development_execution_authorized=True,
    )
    assert len(result.role_calls) == 75
    assert result.evidence.local_resource is None
    assert result.evidence.integration.zero_cost_verified is True
    assert result.decision.eligible is True


class _UnobservableRequestExecutor(_PerfectRoleExecutor):
    def integration_evidence(self, *, candidate: FeasibilityCandidateDescriptor):
        integration, capability = super().integration_evidence(candidate=candidate)
        return (
            integration.model_copy(update={"actual_request_count_observable": False}),
            capability.model_copy(update={"actual_request_count_observable": False}),
        )


class _AutomaticRetryExecutor(_PerfectRoleExecutor):
    def integration_evidence(self, *, candidate: FeasibilityCandidateDescriptor):
        integration, capability = super().integration_evidence(candidate=candidate)
        return (
            integration.model_copy(update={"automatic_retries_disabled": False}),
            capability.model_copy(
                update={"automatic_retries_disabled": False, "configured_max_retries": 1}
            ),
        )


def test_f1_blocks_before_dispatch_when_request_count_is_unobservable() -> None:
    executor = _UnobservableRequestExecutor()
    with pytest.raises(FeasibilityGateExecutionError, match="actual provider request count"):
        FeasibilityGateOrchestrator(assets=load_feasibility_assets(ASSET_ROOT)).run_candidate(
            candidate_id="l2-qwen3-4b-q4-k-m",
            executor=executor,
            development_execution_authorized=True,
        )
    assert executor.calls == []


def test_f1_blocks_before_dispatch_when_automatic_retries_are_enabled() -> None:
    executor = _AutomaticRetryExecutor()
    with pytest.raises(Exception, match="automatic provider/runtime retries"):
        FeasibilityGateOrchestrator(assets=load_feasibility_assets(ASSET_ROOT)).run_candidate(
            candidate_id="l2-qwen3-4b-q4-k-m",
            executor=executor,
            development_execution_authorized=True,
        )
    assert executor.calls == []
