"""Milestone 12 grounded patch-generation and in-memory patch-policy tests."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from llm.mock_provider import MockProvider
from orchestrator.limits import RunLimitTracker
from orchestrator.patch_generation_flow import (
    PatchGenerationFlow,
    PatchGenerationFlowError,
    PatchGenerationPolicyBlocked,
)
from orchestrator.policy_engine import PolicyEngine
from schemas.blue_team import (
    BlueTeamAnalysisResult,
    CodeFinding,
    SourceLineRange,
    SourceReadResult,
    SourceSnippet,
    TriageResult,
)
from schemas.common import AgentRole, ClassificationLabel, PolicyReasonCode, WorkflowState
from schemas.experiments import ClassificationMode, ExperimentLimits
from schemas.patches import (
    PatchProposal,
    PatchRetryFeedback,
    ProposedFileChange,
    ProposedSecurityTest,
)
from services.audit_service import AuditService
from services.patch_service import PatchGroundingError, PatchService, PatchServiceBlocked
from services.target_registry import TargetRegistry


ROOT = Path(__file__).resolve().parents[1]
TARGET_ID = "vulnerable-store"
SOURCE_FILE = "dummy_apps/vulnerable_store/app/scenario_routes.py"


@pytest.fixture
def registry() -> TargetRegistry:
    return TargetRegistry.from_directories(
        targets_dir=ROOT / "config" / "targets",
        security_tests_dir=ROOT / "config" / "security_tests",
    )


def _analysis(
    label: ClassificationLabel = ClassificationLabel.XSS,
    *,
    run_id: str = "patch-run-001",
) -> BlueTeamAnalysisResult:
    details = {
        ClassificationLabel.SQL_INJECTION: (46, "vulnerable_login"),
        ClassificationLabel.XSS: (80, "vulnerable_search"),
        ClassificationLabel.PATH_TRAVERSAL: (99, "vulnerable_file_read"),
    }
    line, function_name = details[label]
    return BlueTeamAnalysisResult(
        run_id=run_id,
        target_id=TARGET_ID,
        classification_mode=ClassificationMode.HYBRID,
        triage=TriageResult(
            run_id=run_id,
            is_suspicious=True,
            classification=label,
            confidence=1.0,
            supporting_event_ids=("evt-1",),
            reason="Deterministic Milestone 12 fixture.",
        ),
        code_finding=CodeFinding(
            run_id=run_id,
            file_path=SOURCE_FILE,
            function_or_route=function_name,
            root_cause="Deterministic Milestone 12 fixture.",
            supporting_lines=(SourceLineRange(start_line=line, end_line=line),),
            confidence=1.0,
        ),
        final_state=WorkflowState.CODE_ANALYSIS,
    )


def _flow(
    *,
    registry: TargetRegistry,
    tmp_path: Path,
    provider,
    limits: ExperimentLimits | None = None,
    tracker: RunLimitTracker | None = None,
) -> PatchGenerationFlow:
    return PatchGenerationFlow(
        target_registry=registry,
        policy_engine=PolicyEngine(registry=registry, project_root=ROOT),
        limits=tracker or RunLimitTracker(limits or ExperimentLimits()),
        provider=provider,
        audit_service=AuditService(project_root=tmp_path),
        project_root=ROOT,
    )


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class CapturingProvider:
    def __init__(self, delegate: MockProvider) -> None:
        self.delegate = delegate
        self.inputs: dict[AgentRole, Mapping[str, Any]] = {}

    def generate_structured(
        self,
        *,
        role: AgentRole,
        input_data: Mapping[str, Any],
        response_model: type[BaseModel],
    ):
        self.inputs[role] = input_data
        return self.delegate.generate_structured(
            role=role,
            input_data=input_data,
            response_model=response_model,
        )


class CountingProvider:
    def __init__(self) -> None:
        self.calls = 0

    def generate_structured(self, **kwargs):
        self.calls += 1
        return MockProvider().generate_structured(**kwargs)


@pytest.mark.parametrize(
    "label",
    [
        ClassificationLabel.SQL_INJECTION,
        ClassificationLabel.XSS,
        ClassificationLabel.PATH_TRAVERSAL,
    ],
)
def test_mock_flow_prepares_grounded_patch_for_each_supported_class(
    registry: TargetRegistry,
    tmp_path: Path,
    label: ClassificationLabel,
) -> None:
    source_path = ROOT / SOURCE_FILE
    before = _sha(source_path)
    provider = MockProvider()
    result = _flow(registry=registry, tmp_path=tmp_path, provider=provider).run(
        analysis=_analysis(label),
        attempt_number=1,
    )

    assert result.final_state == WorkflowState.PATCH_VALIDATING
    assert result.prepared_patch.files_changed == 1
    assert result.prepared_patch.files[0].file_path == SOURCE_FILE
    assert result.prepared_patch.diff_sha256
    assert result.prepared_patch.unified_diff.startswith(f"--- a/{SOURCE_FILE}")
    assert provider.call_roles == (AgentRole.BLUE_PATCH_GENERATION,)
    assert _sha(source_path) == before


def test_patch_agent_input_is_bounded_and_excludes_ground_truth_and_red_artifacts(
    registry: TargetRegistry,
    tmp_path: Path,
) -> None:
    provider = CapturingProvider(MockProvider())
    _flow(registry=registry, tmp_path=tmp_path, provider=provider).run(
        analysis=_analysis(),
        attempt_number=1,
    )

    patch_input = provider.inputs[AgentRole.BLUE_PATCH_GENERATION]
    assert set(patch_input) == {
        "triage",
        "code_finding",
        "source_context",
        "attempt_number",
        "patch_constraints",
    }
    serialized = repr(patch_input)
    for forbidden in (
        "security_test_id",
        "attack_plan",
        "execution_result",
        "scenario_ground_truth",
        "/scenarios/",
    ):
        assert forbidden not in serialized
    snippets = patch_input["source_context"]["snippets"]
    assert snippets
    assert all(item["file_path"] == SOURCE_FILE for item in snippets)
    assert len(serialized) < 20_000


def test_structured_retry_feedback_is_included_only_when_supplied(
    registry: TargetRegistry,
    tmp_path: Path,
) -> None:
    without = CapturingProvider(MockProvider())
    _flow(registry=registry, tmp_path=tmp_path / "without", provider=without).run(
        analysis=_analysis(run_id="retry-none"),
        attempt_number=1,
    )
    assert "retry_feedback" not in without.inputs[AgentRole.BLUE_PATCH_GENERATION]

    feedback = PatchRetryFeedback(
        failed_stage="regression",
        failing_test_id="generated-001",
        error_summary="Synthetic structured feedback for a future RQ3 comparison.",
        prior_diff_summary="Previous patch changed the localized function only.",
    )
    with_feedback = CapturingProvider(MockProvider())
    _flow(
        registry=registry,
        tmp_path=tmp_path / "with",
        provider=with_feedback,
    ).run(
        analysis=_analysis(run_id="retry-structured"),
        attempt_number=2,
        retry_feedback=feedback,
    )
    assert with_feedback.inputs[AgentRole.BLUE_PATCH_GENERATION][
        "retry_feedback"
    ] == feedback.model_dump(mode="json")


def test_optional_generated_test_path_is_service_derived_and_not_written(
    registry: TargetRegistry,
    tmp_path: Path,
) -> None:
    provider = MockProvider(include_generated_patch_test=True)
    result = _flow(registry=registry, tmp_path=tmp_path, provider=provider).run(
        analysis=_analysis(),
        attempt_number=1,
    )

    expected = (
        "dummy_apps/vulnerable_store/tests/generated/"
        "test_generated_xss_remediation.py"
    )
    assert result.prepared_patch.generated_test_path == expected
    assert result.prepared_patch.files_changed == 2
    assert any(item.file_path == expected and item.is_new_file for item in result.prepared_patch.files)
    assert not (ROOT / expected).exists()


def test_patch_preparation_records_authorization_and_diff_hash_audit(
    registry: TargetRegistry,
    tmp_path: Path,
) -> None:
    result = _flow(
        registry=registry,
        tmp_path=tmp_path,
        provider=MockProvider(),
    ).run(analysis=_analysis(), attempt_number=1)

    events = AuditService(project_root=tmp_path).read_run(run_id=result.run_id)
    operations = [item.operation for item in events]
    for expected in (
        "patch_attempt_authorization",
        "model_call_authorization",
        "model_call",
        "patch_path_validation",
        "patch_size_validation",
        "patch_prepare",
        "workflow_transition",
    ):
        assert expected in operations
    prepare = [item for item in events if item.operation == "patch_prepare"][-1]
    assert prepare.execution_status.value == "succeeded"
    assert prepare.evidence_reference == result.prepared_patch.diff_sha256


def test_patch_attempt_budget_blocks_before_provider_call(
    registry: TargetRegistry,
    tmp_path: Path,
) -> None:
    tracker = RunLimitTracker(ExperimentLimits(max_patch_attempts=1))
    tracker.consume_patch_attempts()
    provider = CountingProvider()
    flow = _flow(
        registry=registry,
        tmp_path=tmp_path,
        provider=provider,
        tracker=tracker,
    )

    with pytest.raises(PatchGenerationPolicyBlocked) as exc_info:
        flow.run(analysis=_analysis(), attempt_number=2)
    assert exc_info.value.decision.reason_code == PolicyReasonCode.ATTEMPT_LIMIT_REACHED
    assert provider.calls == 0


def test_model_call_budget_blocks_before_provider_invocation(
    registry: TargetRegistry,
    tmp_path: Path,
) -> None:
    tracker = RunLimitTracker(ExperimentLimits(max_model_calls=1))
    tracker.consume_model_calls()
    provider = CountingProvider()
    flow = _flow(
        registry=registry,
        tmp_path=tmp_path,
        provider=provider,
        tracker=tracker,
    )

    with pytest.raises(PatchGenerationPolicyBlocked) as exc_info:
        flow.run(analysis=_analysis(), attempt_number=1)
    assert exc_info.value.decision.reason_code == PolicyReasonCode.MODEL_CALL_LIMIT_REACHED
    assert provider.calls == 0


def test_patch_flow_requires_code_analysis_state_and_code_finding(
    registry: TargetRegistry,
    tmp_path: Path,
) -> None:
    analysis = _analysis()
    wrong_state = analysis.model_copy(update={"final_state": WorkflowState.TRIAGE})
    with pytest.raises(PatchGenerationFlowError):
        _flow(registry=registry, tmp_path=tmp_path, provider=MockProvider()).run(
            analysis=wrong_state,
            attempt_number=1,
        )

    missing = analysis.model_copy(update={"code_finding": None})
    with pytest.raises(PatchGenerationFlowError):
        _flow(registry=registry, tmp_path=tmp_path, provider=MockProvider()).run(
            analysis=missing,
            attempt_number=1,
        )


def test_patch_proposal_identity_mismatch_is_rejected(
    registry: TargetRegistry,
    tmp_path: Path,
) -> None:
    class WrongRunProvider:
        def generate_structured(self, **kwargs):
            raw = MockProvider().generate_structured(**kwargs)
            raw = dict(raw)
            raw["run_id"] = "wrong-run"
            return raw

    with pytest.raises(PatchGenerationFlowError, match="run_id"):
        _flow(registry=registry, tmp_path=tmp_path, provider=WrongRunProvider()).run(
            analysis=_analysis(),
            attempt_number=1,
        )


def _service_context() -> tuple[CodeFinding, SourceReadResult]:
    source = (ROOT / SOURCE_FILE).read_text(encoding="utf-8")
    snippet = SourceSnippet(
        file_path=SOURCE_FILE,
        start_line=1,
        end_line=len(source.splitlines()),
        content=source[:6000],
    )
    finding = CodeFinding(
        run_id="service-run",
        file_path=SOURCE_FILE,
        function_or_route="vulnerable_search",
        root_cause="Synthetic service test.",
        supporting_lines=(SourceLineRange(start_line=80, end_line=80),),
        confidence=1.0,
    )
    return finding, SourceReadResult(
        run_id="service-run",
        target_id=TARGET_ID,
        snippets=(snippet,),
    )


def _service(registry: TargetRegistry, tmp_path: Path) -> PatchService:
    return PatchService(
        registry=registry,
        policy_engine=PolicyEngine(registry=registry, project_root=ROOT),
        audit_service=AuditService(project_root=tmp_path),
        project_root=ROOT,
    )


def test_patch_service_rejects_anchor_absent_from_current_source(
    registry: TargetRegistry,
    tmp_path: Path,
) -> None:
    finding, context = _service_context()
    proposal = PatchProposal(
        run_id="service-run",
        target_id=TARGET_ID,
        attempt_number=1,
        changes=(
            ProposedFileChange(
                file_path=SOURCE_FILE,
                original_content="this text does not exist",
                replacement_content="replacement",
                rationale="Invalid grounding fixture.",
            ),
        ),
        security_rationale="Synthetic test.",
        expected_effect="None.",
    )
    with pytest.raises(PatchGroundingError):
        _service(registry, tmp_path).prepare_patch(
            proposal=proposal,
            code_finding=finding,
            source_context=context,
        )
    assert AuditService(project_root=tmp_path).read_run(run_id="service-run")[-1].error_code == (
        "patch-grounding-blocked"
    )


def test_patch_service_rejects_anchor_not_in_supplied_context(
    registry: TargetRegistry,
    tmp_path: Path,
) -> None:
    finding, context = _service_context()
    context = context.model_copy(
        update={
            "snippets": (
                SourceSnippet(
                    file_path=SOURCE_FILE,
                    start_line=1,
                    end_line=1,
                    content='"""Deliberately vulnerable routes for the controlled local FYP scenarios.',
                ),
            )
        }
    )
    proposal = PatchProposal(
        run_id="service-run",
        target_id=TARGET_ID,
        attempt_number=1,
        changes=(
            ProposedFileChange(
                file_path=SOURCE_FILE,
                original_content="from pathlib import Path",
                replacement_content="from html import escape\nfrom pathlib import Path",
                rationale="Grounding test.",
            ),
        ),
        security_rationale="Synthetic test.",
        expected_effect="None.",
    )
    with pytest.raises(PatchGroundingError, match="not supplied"):
        _service(registry, tmp_path).prepare_patch(
            proposal=proposal,
            code_finding=finding,
            source_context=context,
        )


def test_patch_service_rejects_edit_to_file_other_than_code_finding(
    registry: TargetRegistry,
    tmp_path: Path,
) -> None:
    finding, context = _service_context()
    proposal = PatchProposal(
        run_id="service-run",
        target_id=TARGET_ID,
        attempt_number=1,
        changes=(
            ProposedFileChange(
                file_path="dummy_apps/vulnerable_store/app/main.py",
                original_content="from __future__ import annotations",
                replacement_content="from __future__ import annotations\n# changed",
                rationale="Must be rejected.",
            ),
        ),
        security_rationale="Synthetic test.",
        expected_effect="None.",
    )
    with pytest.raises(PatchGroundingError, match="CodeFinding"):
        _service(registry, tmp_path).prepare_patch(
            proposal=proposal,
            code_finding=finding,
            source_context=context,
        )


def test_patch_service_policy_blocks_protected_path(
    registry: TargetRegistry,
    tmp_path: Path,
) -> None:
    protected = "orchestrator/policy_engine.py"
    text = (ROOT / protected).read_text(encoding="utf-8")
    finding = CodeFinding(
        run_id="protected-run",
        file_path=protected,
        function_or_route="validate_patch_path",
        root_cause="Synthetic malicious fixture.",
        supporting_lines=(SourceLineRange(start_line=1, end_line=1),),
        confidence=1.0,
    )
    context = SourceReadResult(
        run_id="protected-run",
        target_id=TARGET_ID,
        snippets=(
            SourceSnippet(
                file_path=protected,
                start_line=1,
                end_line=len(text[:6000].splitlines()),
                content=text[:6000],
            ),
        ),
    )
    proposal = PatchProposal(
        run_id="protected-run",
        target_id=TARGET_ID,
        attempt_number=1,
        changes=(
            ProposedFileChange(
                file_path=protected,
                original_content='"""Fail-closed deterministic authorization for sensitive project actions."""',
                replacement_content='"""Weakened policy."""',
                rationale="Malicious test fixture.",
            ),
        ),
        security_rationale="Synthetic test.",
        expected_effect="Must be blocked.",
    )
    with pytest.raises(PatchServiceBlocked) as exc_info:
        _service(registry, tmp_path).prepare_patch(
            proposal=proposal,
            code_finding=finding,
            source_context=context,
        )
    assert exc_info.value.decision.reason_code == PolicyReasonCode.PATCH_PATH_NOT_ALLOWED


def test_oversized_generated_test_is_blocked_by_configured_patch_limits(
    registry: TargetRegistry,
    tmp_path: Path,
) -> None:
    flow = _flow(
        registry=registry,
        tmp_path=tmp_path,
        provider=MockProvider(include_generated_patch_test=True),
    )
    # Build a valid flow proposal/context first, then inflate only the optional test.
    analysis = _analysis(run_id="oversized-run")
    context = flow._build_patch_context(analysis)  # deterministic internal helper under test
    agent_input = flow.patch_agent.prepare_input(
        triage=analysis.triage,
        code_finding=analysis.code_finding,
        source_context=context,
        attempt_number=1,
        patch_constraints={"allowed_source_file": SOURCE_FILE},
    )
    raw = MockProvider(include_generated_patch_test=True).generate_structured(
        role=AgentRole.BLUE_PATCH_GENERATION,
        input_data=agent_input,
        response_model=PatchProposal,
    )
    raw = dict(raw)
    raw["proposed_security_test"] = dict(raw["proposed_security_test"])
    raw["proposed_security_test"]["proposed_test_content"] = "\n".join(
        f"line_{index} = True" for index in range(130)
    )
    proposal = PatchProposal.model_validate(raw)

    with pytest.raises(PatchServiceBlocked) as exc_info:
        flow.patch_service.prepare_patch(
            proposal=proposal,
            code_finding=analysis.code_finding,
            source_context=context,
        )
    assert exc_info.value.decision.reason_code == PolicyReasonCode.PATCH_TOO_LARGE


def test_patch_schema_rejects_unsafe_generated_test_name() -> None:
    with pytest.raises(ValidationError):
        ProposedSecurityTest(
            test_name="test-bad-name",
            target_file=SOURCE_FILE,
            purpose="Must reject a non-Python-safe generated test name.",
            proposed_test_content="def test_placeholder():\n    assert True\n",
        )


def test_patch_service_rejects_ambiguous_duplicate_anchor(
    registry: TargetRegistry,
    tmp_path: Path,
) -> None:
    finding, context = _service_context()
    proposal = PatchProposal(
        run_id="service-run",
        target_id=TARGET_ID,
        attempt_number=1,
        changes=(
            ProposedFileChange(
                file_path=SOURCE_FILE,
                original_content="        )",
                replacement_content="        )  # changed",
                rationale="Ambiguous anchor fixture.",
            ),
        ),
        security_rationale="Synthetic test.",
        expected_effect="Must be rejected.",
    )
    with pytest.raises(PatchGroundingError, match="exactly once"):
        _service(registry, tmp_path).prepare_patch(
            proposal=proposal,
            code_finding=finding,
            source_context=context,
        )


def test_patch_service_rejects_overlapping_exact_text_edits(
    registry: TargetRegistry,
    tmp_path: Path,
) -> None:
    finding, context = _service_context()
    proposal = PatchProposal(
        run_id="service-run",
        target_id=TARGET_ID,
        attempt_number=1,
        changes=(
            ProposedFileChange(
                file_path=SOURCE_FILE,
                original_content="from pathlib import Path",
                replacement_content="from html import escape\nfrom pathlib import Path",
                rationale="First overlapping edit.",
            ),
            ProposedFileChange(
                file_path=SOURCE_FILE,
                original_content=(
                    "from pathlib import Path\n\n"
                    "from fastapi import APIRouter, Depends, HTTPException, Query"
                ),
                replacement_content=(
                    "from pathlib import Path\n\n"
                    "from fastapi import APIRouter, Depends, HTTPException, Query\n"
                    "# changed"
                ),
                rationale="Second overlapping edit.",
            ),
        ),
        security_rationale="Synthetic test.",
        expected_effect="Must be rejected.",
    )
    with pytest.raises(PatchGroundingError, match="overlap"):
        _service(registry, tmp_path).prepare_patch(
            proposal=proposal,
            code_finding=finding,
            source_context=context,
        )


def test_prepared_diff_hash_is_stable_for_identical_inputs(
    registry: TargetRegistry,
    tmp_path: Path,
) -> None:
    first = _flow(
        registry=registry,
        tmp_path=tmp_path / "first",
        provider=MockProvider(),
    ).run(analysis=_analysis(), attempt_number=1)
    second = _flow(
        registry=registry,
        tmp_path=tmp_path / "second",
        provider=MockProvider(),
    ).run(analysis=_analysis(), attempt_number=1)

    assert first.prepared_patch.unified_diff == second.prepared_patch.unified_diff
    assert first.prepared_patch.diff_sha256 == second.prepared_patch.diff_sha256
