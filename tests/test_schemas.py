"""Milestone 2 schema contract tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from schemas import (
    AttackPlan,
    ClassificationLabel,
    EndpointDefinition,
    ExperienceMode,
    ExperimentConfiguration,
    ExperimentLimits,
    HttpMethod,
    ModelConfiguration,
    PatchDecision,
    PatchProposal,
    PolicyDecision,
    PolicyReasonCode,
    ProposedFileChange,
    ResearchQuestion,
    RunType,
    SecurityTestDefinition,
    SourceLineRange,
    TargetDefinition,
    TriageResult,
    VerificationResult,
    VerificationStageResult,
    VulnerabilityClass,
)


@pytest.fixture
def endpoint() -> EndpointDefinition:
    return EndpointDefinition(
        endpoint_id="search",
        path="/search",
        allowed_methods=(HttpMethod.GET,),
        input_fields=("q",),
    )


@pytest.fixture
def target(endpoint: EndpointDefinition) -> TargetDefinition:
    return TargetDefinition(
        target_id="vulnerable-store",
        container_name="fyp-vulnerable-store",
        hostname="vulnerable-store",
        port=8000,
        endpoints=(endpoint,),
        allowed_test_ids=("xss-search-001",),
        source_root="dummy_apps/vulnerable_store",
        writable_patch_roots=(
            "dummy_apps/vulnerable_store/app",
            "dummy_apps/vulnerable_store/tests/generated",
        ),
        log_sources=("data/logs/vulnerable-store.jsonl",),
        reset_operation_id="reset-vulnerable-store",
    )


def test_target_definition_accepts_registered_local_shape(target: TargetDefinition) -> None:
    assert target.scheme == "http"
    assert target.port == 8000
    assert target.endpoints[0].endpoint_id == "search"


def test_target_rejects_external_url_style_endpoint(endpoint: EndpointDefinition) -> None:
    with pytest.raises(ValidationError):
        EndpointDefinition(
            endpoint_id="bad",
            path="https://example.com/search",
            allowed_methods=(HttpMethod.GET,),
        )


def test_target_rejects_parent_directory_escape(endpoint: EndpointDefinition) -> None:
    with pytest.raises(ValidationError):
        TargetDefinition(
            target_id="bad-target",
            container_name="bad-target",
            hostname="bad-target",
            port=8000,
            endpoints=(endpoint,),
            allowed_test_ids=("test-1",),
            source_root="../outside",
            writable_patch_roots=("dummy_apps/app",),
            log_sources=("data/log.jsonl",),
            reset_operation_id="reset",
        )


def test_registered_security_test_uses_only_approved_vulnerability_enum() -> None:
    test = SecurityTestDefinition(
        test_id="xss-search-001",
        vulnerability_class=VulnerabilityClass.XSS,
        target_id="vulnerable-store",
        endpoint_id="search",
        method=HttpMethod.GET,
        allowed_parameter_names=("q",),
        request_template_id="xss-search-template",
        success_evidence_rule_id="xss-reflection-rule",
        description="Controlled reflected XSS test for the local dummy search endpoint.",
    )
    assert test.vulnerability_class == VulnerabilityClass.XSS

    with pytest.raises(ValidationError):
        SecurityTestDefinition(
            test_id="bad-test",
            vulnerability_class="ssrf",
            target_id="vulnerable-store",
            endpoint_id="search",
            method=HttpMethod.GET,
            request_template_id="bad-template",
            success_evidence_rule_id="bad-rule",
            description="Not an approved vulnerability class.",
        )


def test_attack_plan_cannot_add_unknown_top_level_fields() -> None:
    with pytest.raises(ValidationError):
        AttackPlan(
            target_id="vulnerable-store",
            test_id="xss-search-001",
            endpoint_id="search",
            vulnerability_class=VulnerabilityClass.XSS,
            parameter_choices={"q": "registered-option"},
            rationale="Select the registered local XSS test.",
            arbitrary_url="https://example.com",
        )


def test_triage_rejects_unapproved_classification_label() -> None:
    with pytest.raises(ValidationError):
        TriageResult(
            run_id="run-001",
            is_suspicious=True,
            classification="command_injection",
            confidence=0.9,
            supporting_event_ids=("event-001",),
            reason="Not part of the frozen label set.",
        )

    valid = TriageResult(
        run_id="run-001",
        is_suspicious=False,
        classification=ClassificationLabel.BENIGN,
        confidence=0.8,
        supporting_event_ids=(),
        reason="No approved suspicious indicators were present.",
    )
    assert valid.classification == ClassificationLabel.BENIGN


def test_source_line_range_rejects_reverse_range() -> None:
    with pytest.raises(ValidationError):
        SourceLineRange(start_line=20, end_line=10)


def test_patch_proposal_rejects_obvious_path_escape() -> None:
    with pytest.raises(ValidationError):
        PatchProposal(
            run_id="run-001",
            target_id="vulnerable-store",
            attempt_number=1,
            changes=(
                ProposedFileChange(
                    file_path="../../orchestrator/policy_engine.py",
                    original_content="safe",
                    replacement_content="unsafe",
                    rationale="This must never pass schema validation.",
                ),
            ),
            security_rationale="Unsafe test case.",
            expected_effect="None.",
        )


def test_patch_file_change_requires_a_real_grounded_edit() -> None:
    with pytest.raises(ValidationError):
        ProposedFileChange(
            file_path="dummy_apps/vulnerable_store/app/main.py",
            original_content="unchanged",
            replacement_content="unchanged",
            rationale="No-op edits are not valid patch proposals.",
        )


def test_policy_decision_reason_must_match_allowed_flag() -> None:
    allowed = PolicyDecision(
        allowed=True,
        reason_code=PolicyReasonCode.ALLOWED,
        message="Registered operation is permitted.",
    )
    assert allowed.allowed is True

    with pytest.raises(ValidationError):
        PolicyDecision(
            allowed=False,
            reason_code=PolicyReasonCode.ALLOWED,
            message="Contradictory decision.",
        )


def test_verification_cannot_accept_when_required_stage_fails() -> None:
    stages = (
        VerificationStageResult(
            stage_id="functional",
            required=True,
            passed=True,
            duration_ms=50,
            details="Functional tests passed.",
        ),
        VerificationStageResult(
            stage_id="replay",
            required=True,
            passed=False,
            duration_ms=25,
            details="Original attack still succeeds.",
        ),
    )

    with pytest.raises(ValidationError):
        VerificationResult(
            run_id="run-001",
            patch_attempt_number=1,
            stages=stages,
            decision=PatchDecision.ACCEPTED,
            total_duration_ms=75,
        )

    rejected = VerificationResult(
        run_id="run-001",
        patch_attempt_number=1,
        stages=stages,
        decision=PatchDecision.REJECTED,
        rejection_reason="Original attack replay failed verification.",
        total_duration_ms=75,
    )
    assert rejected.decision == PatchDecision.REJECTED


def test_final_primary_experiment_rejects_exploratory_experience_mode() -> None:
    model = ModelConfiguration(
        provider="mock",
        model_name="deterministic-fixture",
        temperature=0,
        max_output_tokens=500,
    )

    with pytest.raises(ValidationError):
        ExperimentConfiguration(
            config_id="rq1-final-invalid",
            run_type=RunType.FINAL_EVALUATION,
            research_question=ResearchQuestion.RQ1,
            scenario_ids=("scenario-sqli-001",),
            repetitions=3,
            experience_mode=ExperienceMode.ENABLED_EXPLORATORY,
            model=model,
            limits=ExperimentLimits(),
        )


def test_schema_serialization_round_trip(target: TargetDefinition) -> None:
    serialized = target.model_dump_json()
    restored = TargetDefinition.model_validate_json(serialized)
    assert restored == target


def test_git_policy_config_generates_deterministic_patch_branch() -> None:
    from schemas.git import GitPolicyConfig

    config = GitPolicyConfig(
        baseline_branch="main",
        patch_branch_prefix="agent-patch",
    )

    assert config.branch_name(run_id="run-123", attempt_number=2) == (
        "agent-patch/run-123/attempt-2"
    )


def test_git_policy_config_rejects_unsafe_or_overlapping_names() -> None:
    from pydantic import ValidationError
    from schemas.git import GitPolicyConfig

    with pytest.raises(ValidationError):
        GitPolicyConfig(
            baseline_branch="main",
            patch_branch_prefix="../agent-patch",
        )

    with pytest.raises(ValidationError):
        GitPolicyConfig(
            baseline_branch="agent-patch/main",
            patch_branch_prefix="agent-patch",
        )


def test_patch_branch_result_rejects_baseline_branch_as_patch_branch() -> None:
    from pydantic import ValidationError
    from schemas.common import WorkflowState
    from schemas.git import PatchBranchResult

    with pytest.raises(ValidationError):
        PatchBranchResult(
            run_id="git-schema-run",
            target_id="vulnerable-store",
            attempt_number=1,
            baseline_branch="main",
            base_commit="a" * 40,
            branch_name="main",
            prepared_diff_sha256="b" * 64,
            git_diff="diff --git a/a.py b/a.py\n",
            git_diff_sha256="c" * 64,
            changed_paths=("dummy_apps/vulnerable_store/app/a.py",),
            final_state=WorkflowState.PATCH_APPLYING,
        )


def test_repository_git_policy_file_is_valid() -> None:
    from schemas.git import GitPolicyConfig

    config = GitPolicyConfig.model_validate_json(
        (Path(__file__).resolve().parents[1] / "config" / "git-policy.json").read_text(
            encoding="utf-8"
        )
    )

    assert config.baseline_branch == "main"
    assert config.patch_branch_prefix == "agent-patch"


def test_verification_policy_file_is_valid_and_excludes_vulnerability_proof_tests() -> None:
    from schemas.verification import VerificationPolicyConfig

    policy = VerificationPolicyConfig.model_validate_json(
        (Path(__file__).resolve().parents[1] / "config" / "verification-policy.json").read_text(
            encoding="utf-8"
        )
    )
    assert set(policy.security_test_by_vulnerability) == set(VulnerabilityClass)
    joined = "\n".join(policy.required_regression_tests)
    assert "reproducibly_vulnerable" not in joined
    assert "reproducibly_reflects" not in joined
    assert "reaches_synthetic_private_file" not in joined


def test_verification_policy_requires_exact_frozen_vulnerability_mapping() -> None:
    from schemas.verification import VerificationPolicyConfig

    with pytest.raises(ValidationError):
        VerificationPolicyConfig(
            target_id="vulnerable-store",
            fixed_import_module="dummy_apps.vulnerable_store.app.main",
            security_test_by_vulnerability={
                VulnerabilityClass.XSS: "xss-reflection-001",
            },
            required_regression_tests=(
                "dummy_apps/vulnerable_store/tests/test_baseline.py",
            ),
        )


def test_patch_verification_result_cannot_accept_without_commit_and_restored_baseline() -> None:
    from schemas.verification import PatchVerificationResult

    verification = VerificationResult(
        run_id="verify-schema",
        patch_attempt_number=1,
        stages=(
            VerificationStageResult(
                stage_id="regression",
                passed=True,
                duration_ms=1,
                details="passed",
            ),
        ),
        decision=PatchDecision.ACCEPTED,
        total_duration_ms=1,
    )
    with pytest.raises(ValidationError):
        PatchVerificationResult(
            run_id="verify-schema",
            target_id="vulnerable-store",
            attempt_number=1,
            branch_name="agent-patch/verify-schema/attempt-1",
            base_commit="a" * 40,
            git_diff_sha256="b" * 64,
            verification=verification,
            baseline_restored=False,
            final_state="accepted",
        )
