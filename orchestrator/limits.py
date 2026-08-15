"""Deterministic run-budget enforcement.

The tracker has no knowledge of LLM reasoning. It only tracks measurable
resource counters and time against a frozen ExperimentLimits configuration.
"""

from __future__ import annotations

from dataclasses import dataclass
import time
from collections.abc import Callable

from schemas.experiments import ExperimentLimits


class LimitExceededError(RuntimeError):
    """Raised when code tries to consume a run budget that is exhausted."""


@dataclass(frozen=True, slots=True)
class LimitSnapshot:
    """Read-only current budget state for audit/debugging."""

    model_calls: int
    attack_attempts: int
    patch_attempts: int
    http_requests: int
    elapsed_seconds: float


class RunLimitTracker:
    """Mutable counter object owned by one experiment run."""

    def __init__(
        self,
        limits: ExperimentLimits,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.limits = limits
        self._clock = clock
        self._started_at = clock()
        self._model_calls = 0
        self._attack_attempts = 0
        self._patch_attempts = 0
        self._http_requests = 0

    def elapsed_seconds(self) -> float:
        return max(0.0, self._clock() - self._started_at)

    def snapshot(self) -> LimitSnapshot:
        return LimitSnapshot(
            model_calls=self._model_calls,
            attack_attempts=self._attack_attempts,
            patch_attempts=self._patch_attempts,
            http_requests=self._http_requests,
            elapsed_seconds=self.elapsed_seconds(),
        )

    def runtime_available(self) -> bool:
        return self.elapsed_seconds() < self.limits.max_runtime_seconds

    def can_consume_model_calls(self, amount: int = 1) -> bool:
        self._validate_amount(amount)
        return self._model_calls + amount <= self.limits.max_model_calls

    def can_consume_attack_attempts(self, amount: int = 1) -> bool:
        self._validate_amount(amount)
        return (
            self._attack_attempts + amount
            <= self.limits.max_attack_attempts
        )

    def can_consume_patch_attempts(self, amount: int = 1) -> bool:
        self._validate_amount(amount)
        return (
            self._patch_attempts + amount
            <= self.limits.max_patch_attempts
        )

    def can_consume_http_requests(self, amount: int = 1) -> bool:
        self._validate_amount(amount)
        return (
            self._http_requests + amount
            <= self.limits.max_http_requests
        )

    def consume_model_calls(self, amount: int = 1) -> None:
        if not self.runtime_available():
            raise LimitExceededError("run runtime limit has been reached")
        if not self.can_consume_model_calls(amount):
            raise LimitExceededError("model-call limit would be exceeded")
        self._model_calls += amount

    def consume_attack_attempts(self, amount: int = 1) -> None:
        if not self.runtime_available():
            raise LimitExceededError("run runtime limit has been reached")
        if not self.can_consume_attack_attempts(amount):
            raise LimitExceededError("attack-attempt limit would be exceeded")
        self._attack_attempts += amount

    def consume_patch_attempts(self, amount: int = 1) -> None:
        if not self.runtime_available():
            raise LimitExceededError("run runtime limit has been reached")
        if not self.can_consume_patch_attempts(amount):
            raise LimitExceededError("patch-attempt limit would be exceeded")
        self._patch_attempts += amount

    def consume_http_requests(self, amount: int = 1) -> None:
        if not self.runtime_available():
            raise LimitExceededError("run runtime limit has been reached")
        if not self.can_consume_http_requests(amount):
            raise LimitExceededError("HTTP-request limit would be exceeded")
        self._http_requests += amount

    @staticmethod
    def _validate_amount(amount: int) -> None:
        if amount < 1:
            raise ValueError("budget consumption amount must be >= 1")
