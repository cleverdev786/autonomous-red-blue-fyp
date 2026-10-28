"""T18 target-owned clean-state reset gates."""

from __future__ import annotations

import json

import pytest
from test_isolated_compose_executor import configured

from services.isolated_compose_executor import IsolatedExecutionBlocked

pytest_plugins = ("test_isolated_compose_executor",)


def test_committed_execution_evidence_is_required_before_reset(environment) -> None:
    seam, calls, _dispatches, _payload = configured(environment)

    with pytest.raises(IsolatedExecutionBlocked, match="committed execution evidence"):
        seam.reset_registered_target()

    assert not any("dummy_apps.vulnerable_store.app.reset" in call for call in calls)


def test_mutation_reset_restores_baseline_without_broad_docker_action(environment) -> None:
    state = {"baseline": False, "unrelated": "same-container-id"}

    def reset_hook(argv):
        if "dummy_apps.vulnerable_store.app.reset" in argv:
            state["baseline"] = True
            return b"baseline reset complete\n"
        if "dummy_apps.vulnerable_store.app.baseline" in argv:
            return json.dumps({"passed": state["baseline"]}).encode()
        if "verification.functional" in argv:
            return json.dumps({
                "passed": state["baseline"],
                "details": "fixed checks",
                "duration_ms": 3,
                "checks": [],
            }).encode()
        return None

    seam, calls, _dispatches, _payload = configured(
        environment,
        command_hook=reset_hook,
    )
    seam.run_registered()

    receipt = seam.reset_registered_target()

    assert state["baseline"] is True
    assert state["unrelated"] == "same-container-id"
    assert receipt.status == "restored"
    assert receipt.case_id == "gate2-case-1"
    assert receipt.baseline_verified is True
    mutating = [call for call in calls if "dummy_apps.vulnerable_store.app.reset" in call]
    assert len(mutating) == 1
    assert mutating[0][-3:] == (
        "python", "-m", "dummy_apps.vulnerable_store.app.reset",
    )
    assert mutating[0][3:7] == ("container", "exec", "-i", "b" * 64)
    assert not any(any(word in call for word in ("down", "rm", "prune")) for call in calls)


def test_unknown_post_reset_baseline_is_blocked(environment) -> None:
    def reset_hook(argv):
        if "dummy_apps.vulnerable_store.app.reset" in argv:
            return b"baseline reset complete\n"
        if "dummy_apps.vulnerable_store.app.baseline" in argv:
            return json.dumps({"passed": False, "checks": []}).encode()
        return None

    seam, _calls, _dispatches, _payload = configured(
        environment,
        command_hook=reset_hook,
    )
    seam.run_registered()

    with pytest.raises(IsolatedExecutionBlocked, match="baseline verification failed"):
        seam.reset_registered_target()
    saved = json.loads((seam.evidence / "gate2-case-1" / "reset-receipt.json").read_text())
    assert saved["status"] == "inconclusive"
    assert saved["baseline_verified"] is False
    with pytest.raises(IsolatedExecutionBlocked, match="already recorded"):
        seam.reset_registered_target()
