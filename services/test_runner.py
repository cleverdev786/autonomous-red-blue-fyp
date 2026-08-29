"""Restricted deterministic verification-command runner.

Live HTTP checks are never performed by this host service. It invokes only fixed
verification entry points inside the isolated controlled-executor container.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import subprocess
import time
from typing import Callable, Sequence

from schemas.red_team import TestExecutionResult
from schemas.verification import (
    VerificationCheckResult,
    VerificationPolicyConfig,
    VerificationStageResult,
)


@dataclass(frozen=True, slots=True)
class ProcessResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class TestRunnerError(RuntimeError):
    def __init__(self, message: str, *, error_code: str = "verification-test-runner-failed") -> None:
        super().__init__(message)
        self.error_code = error_code


Runner = Callable[[Sequence[str], Path], ProcessResult]


def _subprocess_runner(args: Sequence[str], cwd: Path) -> ProcessResult:
    completed = subprocess.run(
        list(args),
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
        shell=False,
    )
    return ProcessResult(completed.returncode, completed.stdout, completed.stderr)


class TestRunner:
    """Expose only named deterministic verification operations."""

    def __init__(
        self,
        *,
        repository_root: Path,
        policy: VerificationPolicyConfig,
        runner: Runner = _subprocess_runner,
    ) -> None:
        self.repository_root = repository_root.resolve(strict=False)
        self.policy = policy
        self._runner = runner

    def run_syntax_import(self, *, changed_paths: tuple[str, ...]) -> VerificationStageResult:
        python_paths = tuple(path for path in changed_paths if path.endswith(".py"))
        if not python_paths:
            return VerificationStageResult(
                stage_id="syntax_import",
                required=True,
                passed=True,
                duration_ms=0,
                details="No changed Python files required syntax/import verification.",
            )
        command = [
            "docker", "compose", "run", "--rm", "--no-deps", "controlled-executor",
            "python", "-m", "verification.syntax",
        ]
        for path in python_paths:
            command.extend(("--path", path))
        return self._json_stage(command, stage_id="syntax_import")

    def run_functional_checks(self) -> VerificationStageResult:
        return self._json_stage(
            (
                "docker", "compose", "exec", "-T", "controlled-executor",
                "python", "-m", "verification.functional",
            ),
            stage_id="functional",
        )

    def run_registered_security_test(
        self,
        *,
        stage_id: str,
        test_id: str,
        attempt_number: int,
        run_id: str,
    ) -> TestExecutionResult:
        if test_id not in self.policy.security_test_by_vulnerability.values():
            raise TestRunnerError(
                "requested security test is outside trusted verification policy",
                error_code="verification-test-not-allowed",
            )
        result = self._runner(
            (
                "docker", "compose", "exec", "-T", "controlled-executor",
                "python", "-m", "infrastructure.executor.run_verification_test",
                "--test-id", test_id,
                "--attempt-number", str(attempt_number),
                "--run-id", f"{run_id[:70]}-{stage_id}",
            ),
            self.repository_root,
        )
        if result.returncode != 0:
            raise TestRunnerError(
                f"registered verification test runner failed: {self._bounded(result.stderr or result.stdout)}",
                error_code="verification-registered-test-runner-failed",
            )
        try:
            return TestExecutionResult.model_validate_json(result.stdout.strip())
        except Exception as exc:
            raise TestRunnerError(
                "registered verification test returned invalid structured output",
                error_code="verification-registered-test-output-invalid",
            ) from exc

    def run_regression_suite(self) -> VerificationStageResult:
        started = time.monotonic()
        command = (
            "docker", "compose", "exec", "-T",
            "-e", "VULNERABLE_STORE_DATABASE_URL=sqlite:////tmp/m14-regression.db",
            "-e", "VULNERABLE_STORE_SEED_FILES_DIR=/tmp/m14-regression-seed",
            "-e", "VULNERABLE_STORE_SCENARIO_FILES_DIR=/tmp/m14-regression-scenarios",
            "controlled-executor",
            "python", "-m", "pytest", "-q", "-p", "no:cacheprovider",
            *self.policy.required_regression_tests,
        )
        result = self._runner(command, self.repository_root)
        duration_ms = max(0, int((time.monotonic() - started) * 1000))
        output = self._bounded((result.stdout + "\n" + result.stderr).strip())
        if result.returncode in {2, 3, 4, 5} or result.returncode < 0:
            raise TestRunnerError(
                f"trusted regression runner failed: {output}",
                error_code="verification-regression-runner-failed",
            )
        return VerificationStageResult(
            stage_id="regression",
            required=True,
            passed=result.returncode == 0,
            duration_ms=duration_ms,
            details=output or ("trusted regression allowlist passed" if result.returncode == 0 else "regression tests failed"),
        )

    def _json_stage(self, command: Sequence[str], *, stage_id: str) -> VerificationStageResult:
        result = self._runner(tuple(command), self.repository_root)
        raw = result.stdout.strip().splitlines()
        payload = raw[-1] if raw else ""
        try:
            data = json.loads(payload)
            passed = bool(data["passed"])
            details = self._bounded(str(data["details"]))
            duration_ms = max(0, int(data["duration_ms"]))
            checks = tuple(VerificationCheckResult.model_validate(item) for item in data.get("checks", ()))
        except Exception as exc:
            raise TestRunnerError(
                f"{stage_id} returned invalid structured output",
                error_code=f"verification-{stage_id}-output-invalid",
            ) from exc
        if result.returncode not in {0, 2}:
            raise TestRunnerError(
                f"{stage_id} trusted runner failed: {self._bounded(result.stderr or result.stdout)}",
                error_code=f"verification-{stage_id}-runner-failed",
            )
        return VerificationStageResult(
            stage_id=stage_id,
            required=True,
            passed=passed,
            duration_ms=duration_ms,
            details=details,
            checks=checks,
        )

    def _bounded(self, value: str) -> str:
        value = value.strip() or "verification command produced no details"
        return value[: self.policy.stage_output_limit_chars]
