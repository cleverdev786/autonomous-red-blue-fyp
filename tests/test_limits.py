"""Tests for deterministic run-budget accounting."""

from __future__ import annotations

import pytest

from orchestrator.limits import LimitExceededError, RunLimitTracker
from schemas.experiments import ExperimentLimits


class FakeClock:
    def __init__(self) -> None:
        self.value = 100.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def make_tracker(clock: FakeClock | None = None) -> RunLimitTracker:
    return RunLimitTracker(
        ExperimentLimits(
            max_model_calls=2,
            max_attack_attempts=2,
            max_patch_attempts=1,
            max_http_requests=3,
            max_runtime_seconds=10,
        ),
        clock=clock or FakeClock(),
    )


def test_limit_tracker_counts_and_snapshots() -> None:
    tracker = make_tracker()

    tracker.consume_model_calls()
    tracker.consume_attack_attempts()
    tracker.consume_patch_attempts()
    tracker.consume_http_requests(2)

    snapshot = tracker.snapshot()
    assert snapshot.model_calls == 1
    assert snapshot.attack_attempts == 1
    assert snapshot.patch_attempts == 1
    assert snapshot.http_requests == 2


def test_limit_tracker_blocks_request_overflow() -> None:
    tracker = make_tracker()

    tracker.consume_http_requests(3)

    assert tracker.can_consume_http_requests() is False
    with pytest.raises(LimitExceededError):
        tracker.consume_http_requests()


def test_limit_tracker_blocks_patch_attempt_overflow() -> None:
    tracker = make_tracker()

    tracker.consume_patch_attempts()

    with pytest.raises(LimitExceededError):
        tracker.consume_patch_attempts()


def test_limit_tracker_blocks_after_runtime_expiry() -> None:
    clock = FakeClock()
    tracker = make_tracker(clock)

    clock.advance(10)

    assert tracker.runtime_available() is False
    with pytest.raises(LimitExceededError):
        tracker.consume_model_calls()


def test_limit_tracker_rejects_zero_or_negative_consumption() -> None:
    tracker = make_tracker()

    with pytest.raises(ValueError):
        tracker.can_consume_http_requests(0)

    with pytest.raises(ValueError):
        tracker.consume_model_calls(-1)
