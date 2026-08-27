"""Restricted deterministic Docker lifecycle service for patch verification."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import subprocess
import time
from typing import Callable, Sequence


@dataclass(frozen=True, slots=True)
class ProcessResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class EnvironmentServiceError(RuntimeError):
    """Trusted verification infrastructure failed."""

    def __init__(self, message: str, *, error_code: str = "verification-environment-failed") -> None:
        super().__init__(message)
        self.error_code = error_code


class PatchedApplicationError(EnvironmentServiceError):
    """The patched application itself failed startup/health verification."""


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


class EnvironmentService:
    """Expose only fixed Docker Compose lifecycle and isolation operations."""

    def __init__(
        self,
        *,
        repository_root: Path,
        health_timeout_seconds: int = 60,
        runner: Runner = _subprocess_runner,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.repository_root = repository_root.resolve(strict=False)
        self.health_timeout_seconds = health_timeout_seconds
        self._runner = runner
        self._sleep = sleep

    def verify_available(self) -> None:
        self._require_success(
            ("docker", "--version"),
            error_code="docker-unavailable",
            message="Docker CLI is unavailable.",
        )
        self._require_success(
            ("docker", "compose", "version"),
            error_code="docker-compose-unavailable",
            message="Docker Compose is unavailable.",
        )
        self._require_success(
            ("docker", "compose", "config", "-q"),
            error_code="docker-compose-invalid",
            message="Trusted Compose configuration is invalid.",
        )

    def build(self) -> None:
        self._require_success(
            ("docker", "compose", "build"),
            error_code="verification-image-build-failed",
            message="Patched verification image build failed.",
        )

    def start(self) -> None:
        # Start only the patched application first. This keeps application health
        # failures distinguishable from trusted controlled-executor failures.
        self._require_success(
            ("docker", "compose", "up", "-d", "--no-build", "vulnerable-store"),
            error_code="verification-application-start-command-failed",
            message="Patched application container could not be started.",
            patched_application=True,
        )

    def wait_healthy(self) -> None:
        self._wait_for_health(
            "fyp-vulnerable-store",
            patched_application=True,
        )
        self._require_success(
            ("docker", "compose", "up", "-d", "--no-build", "controlled-executor"),
            error_code="verification-executor-start-failed",
            message="Controlled verification executor failed to start.",
        )
        self._wait_for_health(
            "fyp-controlled-executor",
            patched_application=False,
        )

    def verify_isolation(self) -> None:
        self._require_success(
            (
                "docker",
                "compose",
                "exec",
                "-T",
                "controlled-executor",
                "python",
                "-m",
                "infrastructure.executor.isolation_probe",
            ),
            error_code="verification-isolation-failed",
            message="Controlled verification network isolation check failed.",
        )

    def cleanup(self) -> None:
        self._require_success(
            ("docker", "compose", "down", "--volumes", "--remove-orphans"),
            error_code="verification-environment-cleanup-failed",
            message="Verification Docker cleanup failed.",
        )

    def _wait_for_health(self, container_name: str, *, patched_application: bool) -> None:
        deadline = time.monotonic() + self.health_timeout_seconds
        last = "unknown"
        while time.monotonic() < deadline:
            last = self._inspect_health(container_name)
            if last == "healthy":
                return
            if patched_application and last == "unhealthy":
                raise PatchedApplicationError(
                    "patched vulnerable-store container became unhealthy",
                    error_code="patched-application-unhealthy",
                )
            self._sleep(1.0)
        if patched_application:
            raise PatchedApplicationError(
                f"patched vulnerable-store did not become healthy (last={last})",
                error_code="patched-application-health-timeout",
            )
        raise EnvironmentServiceError(
            f"controlled-executor did not become healthy (last={last})",
            error_code="controlled-executor-health-timeout",
        )

    def _inspect_health(self, container_name: str) -> str:
        result = self._runner(
            (
                "docker",
                "inspect",
                "--format={{.State.Health.Status}}",
                container_name,
            ),
            self.repository_root,
        )
        if result.returncode != 0:
            raise EnvironmentServiceError(
                f"failed to inspect trusted verification container {container_name!r}",
                error_code="verification-health-inspection-failed",
            )
        return result.stdout.strip()

    def _require_success(
        self,
        args: Sequence[str],
        *,
        error_code: str,
        message: str,
        patched_application: bool = False,
    ) -> None:
        result = self._runner(tuple(args), self.repository_root)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()[:1000]
            exc_type = PatchedApplicationError if patched_application else EnvironmentServiceError
            raise exc_type(
                f"{message} {detail}".strip(),
                error_code=error_code,
            )
