"""Milestone 14 deterministic patch-verification tests without real Docker."""

from __future__ import annotations

import difflib
import hashlib
from pathlib import Path

import pytest

from orchestrator.policy_engine import PolicyEngine
from schemas.common import HttpMethod, PatchDecision, VulnerabilityClass, WorkflowState
from schemas.git import PatchBranchResult
from schemas.patches import PreparedFileChange, PreparedPatch
from schemas.red_team import (
    AttackPlan,
    AttackVerification,
    EvidenceItem,
    ReconnaissanceResult,
    RedTeamRunResult,
    TestExecutionResult as ExecutionResult,
)
from schemas.verification import VerificationPolicyConfig, VerificationStageResult
from services.audit_service import AuditService
from services.environment_service import (
    EnvironmentService,
    EnvironmentServiceError,
    PatchedApplicationError,
    ProcessResult as EnvironmentProcessResult,
)
from services.target_registry import TargetRegistry
from services.test_runner import (
    ProcessResult as RunnerProcessResult,
    TestRunner as VerificationTestRunner,
    TestRunnerError as VerificationTestRunnerError,
)
from verification.decisions import decide_verification
from verification.pipeline import PatchVerificationPipeline
from verification.security import security_stage_result


ROOT = Path(__file__).resolve().parents[1]
TARGET_ID = "vulnerable-store"
SOURCE_FILE = "dummy_apps/vulnerable_store/app/example.py"
GENERATED_FILE = "dummy_apps/vulnerable_store/tests/generated/test_generated_example.py"
BASE_COMMIT = "a" * 40


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _prepared(*, run_id: str = "verify-run", include_generated: bool = False) -> PreparedPatch:
    before = "def value():\n    return 'bad'\n"
    after = "def value():\n    return 'good'\n"
    diff = "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{SOURCE_FILE}",
            tofile=f"b/{SOURCE_FILE}",
        )
    )
    files = [
        PreparedFileChange(
            file_path=SOURCE_FILE,
            original_sha256=_sha(before),
            replacement_sha256=_sha(after),
            replacement_content=after,
        )
    ]
    generated_path = None
    if include_generated:
        generated = "raise RuntimeError('generated tests must never execute')\n"
        files.append(
            PreparedFileChange(
                file_path=GENERATED_FILE,
                original_sha256=_sha(""),
                replacement_sha256=_sha(generated),
                replacement_content=generated,
                is_new_file=True,
            )
        )
        diff += "".join(
            difflib.unified_diff(
                [],
                generated.splitlines(keepends=True),
                fromfile="/dev/null",
                tofile=f"b/{GENERATED_FILE}",
            )
        )
        generated_path = GENERATED_FILE
    inserted = sum(1 for line in diff.splitlines() if line.startswith("+") and not line.startswith("+++"))
    deleted = sum(1 for line in diff.splitlines() if line.startswith("-") and not line.startswith("---"))
    return PreparedPatch(
        run_id=run_id,
        target_id=TARGET_ID,
        attempt_number=1,
        files=tuple(files),
        unified_diff=diff,
        diff_sha256=_sha(diff),
        files_changed=len(files),
        inserted_lines=inserted,
        deleted_lines=deleted,
        total_diff_bytes=len(diff.encode("utf-8")),
        generated_test_path=generated_path,
    )


def _branch(patch: PreparedPatch) -> PatchBranchResult:
    git_diff = "diff --git a/example.py b/example.py\n+bounded\n"
    return PatchBranchResult(
        run_id=patch.run_id,
        target_id=patch.target_id,
        attempt_number=patch.attempt_number,
        baseline_branch="main",
        base_commit=BASE_COMMIT,
        branch_name=f"agent-patch/{patch.run_id}/attempt-1",
        prepared_diff_sha256=patch.diff_sha256,
        git_diff=git_diff,
        git_diff_sha256=_sha(git_diff),
        changed_paths=tuple(item.file_path for item in patch.files),
        final_state=WorkflowState.PATCH_APPLYING,
    )


def _red_run(*, run_id: str = "verify-run", test_id: str = "xss-reflection-001") -> RedTeamRunResult:
    evidence = EvidenceItem(
        evidence_id="exploit-evidence",
        evidence_type="registered-test",
        summary="Original deterministic exploit evidence.",
    )
    return RedTeamRunResult(
        run_id=run_id,
        target_id=TARGET_ID,
        attempt_number=1,
        reconnaissance=ReconnaissanceResult(
            target_id=TARGET_ID,
            candidate_endpoints=(),
            rationale="Trusted runtime fixture.",
        ),
        attack_plan=AttackPlan(
            target_id=TARGET_ID,
            test_id=test_id,
            endpoint_id="scenario-xss-search",
            vulnerability_class=VulnerabilityClass.XSS,
            rationale="Original confirmed registered XSS test.",
        ),
        execution=ExecutionResult(
            run_id=run_id,
            target_id=TARGET_ID,
            test_id=test_id,
            attempt_number=1,
            request_count=1,
            completed=True,
            status_code=200,
            evidence=(evidence,),
            duration_ms=10,
        ),
        verification=AttackVerification(
            target_id=TARGET_ID,
            test_id=test_id,
            confirmed=True,
            confidence=1.0,
            evidence_ids=(evidence.evidence_id,),
            reason="Original attack confirmed.",
        ),
        final_state=WorkflowState.BLUE_MONITORING,
    )


def _policy() -> VerificationPolicyConfig:
    return VerificationPolicyConfig.model_validate_json(
        (ROOT / "config/verification-policy.json").read_text(encoding="utf-8")
    )


def _policy_engine() -> PolicyEngine:
    registry = TargetRegistry.from_directories(
        targets_dir=ROOT / "config/targets",
        security_tests_dir=ROOT / "config/security_tests",
    )
    return PolicyEngine(registry=registry, project_root=ROOT)


class FakeGitService:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.block_verify: Exception | None = None
        self.restore_error: Exception | None = None

    def verify_materialized_patch(self, *, prepared_patch, branch_result) -> str:
        self.calls.append("verify")
        if self.block_verify:
            raise self.block_verify
        return branch_result.git_diff_sha256

    def commit_accepted_patch(self, *, branch_result, decision) -> str:
        self.calls.append("commit")
        assert decision == PatchDecision.ACCEPTED
        return "b" * 40

    def restore_baseline(self, *, prepared_patch, branch_name, base_commit) -> None:
        self.calls.append("restore")
        if self.restore_error:
            raise self.restore_error


class FakeEnvironment:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.error_at: str | None = None
        self.patched_startup_error = False

    def _call(self, name: str) -> None:
        self.calls.append(name)
        if self.error_at == name:
            raise EnvironmentServiceError("trusted environment failure", error_code="docker-unavailable")

    def verify_available(self): self._call("verify_available")
    def build(self): self._call("build")
    def start(self): self._call("start")
    def verify_isolation(self): self._call("verify_isolation")
    def cleanup(self): self._call("cleanup")

    def wait_healthy(self):
        self.calls.append("wait_healthy")
        if self.patched_startup_error:
            raise PatchedApplicationError("patched app unhealthy", error_code="patched-application-unhealthy")
        if self.error_at == "wait_healthy":
            raise EnvironmentServiceError("health infrastructure failure", error_code="verification-health-inspection-failed")


class FakeTestRunner:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.fail_stage: str | None = None
        self.runner_error: str | None = None
        self.syntax_paths: tuple[str, ...] = ()

    def _stage(self, stage_id: str) -> VerificationStageResult:
        self.calls.append(stage_id)
        if self.runner_error == stage_id:
            raise VerificationTestRunnerError("trusted runner failed", error_code=f"verification-{stage_id}-runner-failed")
        return VerificationStageResult(
            stage_id=stage_id,
            required=True,
            passed=self.fail_stage != stage_id,
            duration_ms=1,
            details=f"{stage_id} {'failed' if self.fail_stage == stage_id else 'passed'}",
        )

    def run_syntax_import(self, *, changed_paths):
        self.syntax_paths = changed_paths
        return self._stage("syntax_import")

    def run_functional_checks(self):
        return self._stage("functional")

    def run_registered_security_test(self, *, stage_id, test_id, attempt_number, run_id):
        self.calls.append(stage_id)
        exploit = self.fail_stage == stage_id
        evidence = (
            EvidenceItem(
                evidence_id=f"{stage_id}-evidence",
                evidence_type="registered-test",
                summary="Exploit still observed.",
            ),
        ) if exploit else ()
        return ExecutionResult(
            run_id=f"{run_id[:70]}-{stage_id}",
            target_id=TARGET_ID,
            test_id=test_id,
            attempt_number=attempt_number,
            request_count=1,
            completed=True,
            status_code=200,
            evidence=evidence,
            duration_ms=1,
            error_code=None if exploit else "evidence-not-observed",
        )

    def run_regression_suite(self):
        return self._stage("regression")


def _pipeline(tmp_path: Path, git=None, env=None, runner=None) -> PatchVerificationPipeline:
    return PatchVerificationPipeline(
        policy_engine=_policy_engine(),
        git_service=git or FakeGitService(),
        environment_service=env or FakeEnvironment(),
        test_runner=runner or FakeTestRunner(),
        verification_policy=_policy(),
        audit_service=AuditService(project_root=tmp_path / "audit"),
    )


def test_all_required_stages_pass_accepts_commits_and_restores(tmp_path: Path) -> None:
    patch = _prepared()
    git = FakeGitService()
    env = FakeEnvironment()
    runner = FakeTestRunner()
    result = _pipeline(tmp_path, git, env, runner).run(
        branch_result=_branch(patch), prepared_patch=patch, red_run=_red_run()
    )

    assert result.final_state == WorkflowState.ACCEPTED
    assert result.verification is not None
    assert result.verification.decision == PatchDecision.ACCEPTED
    assert [stage.stage_id for stage in result.verification.stages] == [
        "patch_policy", "path_diff", "syntax_import", "application_startup",
        "functional", "security", "original_replay", "regression",
    ]
    assert result.accepted_commit_sha == "b" * 40
    assert result.baseline_restored is True
    assert git.calls == ["verify", "commit", "restore"]
    assert env.calls[-1] == "cleanup"


def test_syntax_failure_rejects_before_application_start(tmp_path: Path) -> None:
    patch = _prepared()
    env = FakeEnvironment()
    runner = FakeTestRunner()
    runner.fail_stage = "syntax_import"
    result = _pipeline(tmp_path, env=env, runner=runner).run(
        branch_result=_branch(patch), prepared_patch=patch, red_run=_red_run()
    )
    assert result.final_state == WorkflowState.REJECTED
    assert "start" not in env.calls
    assert runner.calls == ["syntax_import"]


@pytest.mark.parametrize("failed_stage", ["functional", "security", "original_replay", "regression"])
def test_behavioral_failure_rejects_but_collects_all_behavioral_stages(
    tmp_path: Path, failed_stage: str
) -> None:
    patch = _prepared()
    runner = FakeTestRunner()
    runner.fail_stage = failed_stage
    git = FakeGitService()
    result = _pipeline(tmp_path, git=git, runner=runner).run(
        branch_result=_branch(patch), prepared_patch=patch, red_run=_red_run()
    )
    assert result.final_state == WorkflowState.REJECTED
    assert result.accepted_commit_sha is None
    assert "commit" not in git.calls
    for stage in ("functional", "security", "original_replay", "regression"):
        assert stage in runner.calls


def test_patched_application_unhealthy_is_rejected_not_infrastructure_failed(tmp_path: Path) -> None:
    patch = _prepared()
    env = FakeEnvironment()
    env.patched_startup_error = True
    result = _pipeline(tmp_path, env=env).run(
        branch_result=_branch(patch), prepared_patch=patch, red_run=_red_run()
    )
    assert result.final_state == WorkflowState.REJECTED
    assert result.verification is not None
    assert result.verification.stages[-1].stage_id == "application_startup"
    assert result.verification.stages[-1].passed is False


def test_trusted_environment_failure_is_failed(tmp_path: Path) -> None:
    patch = _prepared()
    env = FakeEnvironment()
    env.error_at = "verify_available"
    result = _pipeline(tmp_path, env=env).run(
        branch_result=_branch(patch), prepared_patch=patch, red_run=_red_run()
    )
    assert result.final_state == WorkflowState.FAILED
    assert result.verification is None
    assert "docker-unavailable" in (result.failure_reason or "")


def test_identity_mismatch_is_policy_blocked_before_docker(tmp_path: Path) -> None:
    patch = _prepared()
    env = FakeEnvironment()
    wrong_red = _red_run(run_id="different-run")
    result = _pipeline(tmp_path, env=env).run(
        branch_result=_branch(patch), prepared_patch=patch, red_run=wrong_red
    )
    assert result.final_state == WorkflowState.POLICY_BLOCKED
    assert env.calls == []


def test_tampered_prepared_diff_is_policy_blocked_before_git_or_docker(tmp_path: Path) -> None:
    patch = _prepared()
    tampered = patch.model_copy(update={"unified_diff": patch.unified_diff + "# drift\n"})
    git = FakeGitService()
    env = FakeEnvironment()
    result = _pipeline(tmp_path, git=git, env=env).run(
        branch_result=_branch(patch), prepared_patch=tampered, red_run=_red_run()
    )
    assert result.final_state == WorkflowState.POLICY_BLOCKED
    assert "verify" not in git.calls
    assert env.calls == []


def test_generated_test_is_only_sent_to_syntax_stage_and_never_run_as_regression(tmp_path: Path) -> None:
    patch = _prepared(include_generated=True)
    runner = FakeTestRunner()
    result = _pipeline(tmp_path, runner=runner).run(
        branch_result=_branch(patch), prepared_patch=patch, red_run=_red_run()
    )
    assert result.final_state == WorkflowState.ACCEPTED
    assert GENERATED_FILE in runner.syntax_paths
    assert runner.calls.count("regression") == 1


def test_decision_engine_rejects_first_required_failure() -> None:
    result = decide_verification(
        run_id="decision-run",
        attempt_number=1,
        stages=(
            VerificationStageResult(stage_id="functional", passed=False, duration_ms=1, details="broken"),
            VerificationStageResult(stage_id="security", passed=True, duration_ms=1, details="safe"),
        ),
    )
    assert result.decision == PatchDecision.REJECTED
    assert "functional" in (result.rejection_reason or "")


def test_security_interpretation_inverts_red_evidence_semantics() -> None:
    safe = ExecutionResult(
        run_id="security-run", target_id=TARGET_ID, test_id="xss-reflection-001",
        attempt_number=1, request_count=1, completed=True, evidence=(), duration_ms=1,
        error_code="evidence-not-observed",
    )
    unsafe = safe.model_copy(update={
        "evidence": (
            EvidenceItem(evidence_id="still-vulnerable", evidence_type="xss", summary="marker reflected"),
        ),
        "error_code": None,
    })
    assert security_stage_result(stage_id="security", execution=safe).passed is True
    assert security_stage_result(stage_id="security", execution=unsafe).passed is False


def test_environment_service_exposes_only_fixed_lifecycle_commands(tmp_path: Path) -> None:
    commands: list[tuple[str, ...]] = []

    def runner(args, cwd):
        commands.append(tuple(args))
        if args[:3] == ("docker", "inspect", "--format={{.State.Health.Status}}"):
            return EnvironmentProcessResult(0, "healthy\n", "")
        return EnvironmentProcessResult(0, "ok\n", "")

    service = EnvironmentService(repository_root=tmp_path, runner=runner, sleep=lambda _: None)
    service.verify_available()
    service.build()
    service.start()
    service.wait_healthy()
    service.verify_isolation()
    service.cleanup()

    assert ("docker", "compose", "build") in commands
    assert ("docker", "compose", "up", "-d", "--no-build", "vulnerable-store") in commands
    assert ("docker", "compose", "up", "-d", "--no-build", "controlled-executor") in commands
    assert all("--privileged" not in command for command in commands)
    for prohibited in ("run_command", "docker_command", "exec_arbitrary", "shell"):
        assert not hasattr(service, prohibited)


def test_test_runner_uses_no_deps_for_syntax_and_fixed_controlled_executor(tmp_path: Path) -> None:
    commands: list[tuple[str, ...]] = []

    def runner(args, cwd):
        commands.append(tuple(args))
        return RunnerProcessResult(0, '{"passed": true, "details": "ok", "duration_ms": 1}\n', "")

    service = VerificationTestRunner(repository_root=tmp_path, policy=_policy(), runner=runner)
    stage = service.run_syntax_import(changed_paths=(SOURCE_FILE, GENERATED_FILE))
    assert stage.passed is True
    command = commands[0]
    assert command[:7] == ("docker", "compose", "run", "--rm", "--no-deps", "controlled-executor", "python")
    assert "verification.syntax" in command
    for prohibited in ("run_command", "shell", "execute", "exec_in_container"):
        assert not hasattr(service, prohibited)


def test_test_runner_regression_command_is_exact_policy_allowlist(tmp_path: Path) -> None:
    commands: list[tuple[str, ...]] = []

    def runner(args, cwd):
        commands.append(tuple(args))
        return RunnerProcessResult(0, "5 passed\n", "")

    policy = _policy()
    stage = VerificationTestRunner(repository_root=tmp_path, policy=policy, runner=runner).run_regression_suite()
    assert stage.passed is True
    assert commands[0][-len(policy.required_regression_tests):] == policy.required_regression_tests
    assert not any("reproducibly_vulnerable" in item for item in commands[0])
    assert not any("reproducibly_reflects" in item for item in commands[0])


def test_test_runner_rejects_untrusted_registered_test_id(tmp_path: Path) -> None:
    service = VerificationTestRunner(
        repository_root=tmp_path,
        policy=_policy(),
        runner=lambda args, cwd: RunnerProcessResult(0, "{}", ""),
    )
    with pytest.raises(VerificationTestRunnerError, match="outside trusted verification policy"):
        service.run_registered_security_test(
            stage_id="security",
            test_id="not-registered",
            attempt_number=1,
            run_id="verify-run",
        )


def test_generated_python_is_compiled_without_executing_top_level_code(tmp_path: Path, monkeypatch) -> None:
    from verification import syntax as syntax_module

    generated = tmp_path / GENERATED_FILE
    generated.parent.mkdir(parents=True)
    generated.write_text("raise RuntimeError('must not execute')\n", encoding="utf-8")
    imported: list[str] = []
    monkeypatch.setattr(
        syntax_module.importlib,
        "import_module",
        lambda name: imported.append(name) or object(),
    )
    passed, details, _ = syntax_module.check_sources(
        project_root=tmp_path,
        paths=(GENERATED_FILE,),
    )
    assert passed is True
    assert imported == [syntax_module.FIXED_IMPORT_MODULE]
    assert "compiled" in details


def test_verification_registered_test_cli_exposes_no_url_or_payload_arguments() -> None:
    from infrastructure.executor.run_verification_test import build_parser

    parser = build_parser(("xss-reflection-001",))
    destinations = {action.dest for action in parser._actions}
    assert destinations >= {"test_id", "attempt_number", "run_id"}
    assert destinations.isdisjoint({"url", "host", "hostname", "method", "payload", "headers", "file"})


def test_trusted_test_runner_failure_is_failed_not_patch_rejected(tmp_path: Path) -> None:
    patch = _prepared()
    runner = FakeTestRunner()
    runner.runner_error = "functional"
    result = _pipeline(tmp_path, runner=runner).run(
        branch_result=_branch(patch), prepared_patch=patch, red_run=_red_run()
    )
    assert result.final_state == WorkflowState.FAILED
    assert "runner-failed" in (result.failure_reason or "")


def test_cleanup_failure_surfaces_failed_even_after_accepted_verification(tmp_path: Path) -> None:
    patch = _prepared()
    env = FakeEnvironment()
    env.error_at = "cleanup"
    git = FakeGitService()
    result = _pipeline(tmp_path, env=env, git=git).run(
        branch_result=_branch(patch), prepared_patch=patch, red_run=_red_run()
    )
    assert result.verification is not None
    assert result.verification.decision == PatchDecision.ACCEPTED
    assert result.accepted_commit_sha == "b" * 40
    assert result.final_state == WorkflowState.FAILED
    assert "environment cleanup failed" in (result.failure_reason or "")


def test_test_runner_preserves_typed_functional_check_observations(tmp_path: Path) -> None:
    payload = (
        '{"passed": false, "details": "functional verification failed", "duration_ms": 3, '
        '"checks": ['
        '{"check_id": "health", "status": "passed", "duration_ms": 1, "details": "passed"},'
        '{"check_id": "normal_login", "status": "failed", "duration_ms": 2, "details": "failed"},'
        '{"check_id": "normal_search", "status": "not_run", "duration_ms": 0, "details": "not run"}'
        ']}\n'
    )
    service = VerificationTestRunner(
        repository_root=tmp_path,
        policy=_policy(),
        runner=lambda args, cwd: RunnerProcessResult(2, payload, ""),
    )
    stage = service.run_functional_checks()
    assert stage.passed is False
    assert [check.status.value for check in stage.checks] == ["passed", "failed", "not_run"]


def test_security_stage_keeps_structured_execution_as_observational_evidence() -> None:
    execution = ExecutionResult(
        run_id="verify-evidence",
        target_id=TARGET_ID,
        test_id="xss-reflection-001",
        attempt_number=1,
        request_count=1,
        completed=True,
        status_code=200,
        evidence=(),
        duration_ms=7,
    )
    stage = security_stage_result(stage_id="security", execution=execution)
    assert stage.passed is True
    assert stage.test_execution == execution
