"""Opt-in T35 cancel/restart exercise for the isolated Docker lab."""

from __future__ import annotations

import json
import os
import subprocess
from hashlib import sha256
from pathlib import Path

import pytest

from schemas.red_team import TestExecutionResult as ExecutionResult
from services.red_assessment_queue import RedAssessmentQueue
from services.red_assessment_store import RedAssessmentStore
from services.red_evidence_store import RedEvidenceStore
from tests.test_red_modes import authorize, build_supervisor, resources

ROOT = Path(__file__).resolve().parents[2]
PROJECT = "fyp-r4c4f-red-blue-lab"
COMPOSE = ("docker", "compose", "-f", "compose.isolated.yaml")

pytestmark = pytest.mark.skipif(
    os.getenv("MARS_RUN_T35_OPERATIONAL") != "1",
    reason="requires the explicitly enabled isolated Docker lab",
)


def _run(*argv: str, timeout: int = 45) -> bytes:
    return subprocess.run(
        argv,
        cwd=ROOT,
        check=True,
        capture_output=True,
        timeout=timeout,
    ).stdout


def _json_lines(raw: bytes) -> tuple[dict[str, object], ...]:
    return tuple(json.loads(line) for line in raw.decode().splitlines() if line)


def _all_containers() -> dict[str, tuple[str, str, str]]:
    records = _json_lines(_run(
        "docker", "ps", "-a", "--no-trunc", "--format", "{{json .}}",
    ))
    return {
        str(item["ID"]): (
            str(item.get("Image", "")),
            str(item.get("State", "")),
            str(item.get("Project", "")),
        )
        for item in records
    }


def _project_services() -> dict[str, dict[str, object]]:
    return {
        str(item["Service"]): item
        for item in _json_lines(_run(*COMPOSE, "ps", "--format", "json"))
    }


def _cancel_and_restore(tmp_path: Path) -> dict[str, object]:
    tmp_path.mkdir(parents=True)
    supervisor, journal, tasks = build_supervisor(tmp_path, mode="autonomous")
    scope = tasks[0].scope
    authorize(supervisor, tasks[0], "autonomous")
    jobs = supervisor.enqueue_autonomous(
        tasks,
        command_id="t35-cancel-restart",
        resources=resources(),
        enqueued_at=journal.list_receipts(scope)[0].recorded_at,
    )
    evidence = journal.list_evidence(scope)[0]
    evidence_before = journal.read_evidence(scope, evidence.evidence_id)
    supervisor.cancel(
        scope,
        cancellation_id="t35-cancel-before-dispatch",
        requested_at=journal.list_receipts(scope)[0].recorded_at,
    )

    restored_store = RedAssessmentStore(journal.store.path)
    restored_queue = RedAssessmentQueue(restored_store)
    restored_journal = RedEvidenceStore(restored_store, journal.evidence_root)
    restored_jobs = restored_queue.list_jobs(scope)
    snapshot, _ = restored_store.load(scope.assessment_id)

    assert len(jobs) == len(restored_jobs) == 4
    assert {item.status for item in restored_jobs} == {"cancelled"}
    assert restored_queue.claim_next(
        worker_id="t35-worker-after-restart",
        claimed_at=journal.list_receipts(scope)[0].recorded_at,
    ) is None
    assert restored_journal.read_evidence(scope, evidence.evidence_id) == evidence_before
    assert snapshot.assessment.status.value == "cancelled"
    return {
        "assessment_status": snapshot.assessment.status.value,
        "job_statuses": [item.status for item in restored_jobs],
        "redelivery_count": 0,
        "evidence_sha256": sha256(evidence_before).hexdigest(),
    }


def test_t35_cancel_restart_is_bounded_and_preserves_state(
    tmp_path: Path,
) -> None:
    before_all = _all_containers()
    before_project = _project_services()
    assert set(before_project) == {"controlled-executor", "vulnerable-store"}
    assert {str(item["Health"]) for item in before_project.values()} == {"healthy"}
    unrelated_before = {
        container_id: state
        for container_id, state in before_all.items()
        if state[2] != PROJECT
    }

    raw_result = _run(
        *COMPOSE,
        "exec", "-T", "controlled-executor",
        "python", "-m", "infrastructure.executor.run_registered_test",
        "--test-id", "sqli-login-bypass-001",
        "--attempt-number", "1",
    )
    result = ExecutionResult.model_validate_json(raw_result)
    assert result.completed and not result.timed_out and result.evidence

    _run(*COMPOSE, "restart", "controlled-executor")
    _run(*COMPOSE, "up", "-d", "--no-build", "--wait", timeout=90)

    after_all = _all_containers()
    after_project = _project_services()
    unrelated_after = {
        container_id: state
        for container_id, state in after_all.items()
        if state[2] != PROJECT
    }
    assert unrelated_after == unrelated_before
    assert {
        service: str(item["ID"])
        for service, item in after_project.items()
    } == {
        service: str(item["ID"])
        for service, item in before_project.items()
    }
    assert {str(item["Health"]) for item in after_project.values()} == {"healthy"}

    host_config = json.loads(_run(
        "docker", "container", "inspect", "--format", "{{json .HostConfig}}",
        str(after_project["controlled-executor"]["ID"]),
    ))
    assert host_config["Privileged"] is False
    assert host_config["ReadonlyRootfs"] is True
    assert "ALL" in host_config["CapDrop"]
    assert "no-new-privileges:true" in host_config["SecurityOpt"]

    exported = {
        "schema_version": "mars-red-t35-operational-v1",
        "registered_dispatch": {
            "test_id": result.test_id,
            "run_id": result.run_id,
            "dispatch_count": 1,
            "result_sha256": sha256(raw_result).hexdigest(),
        },
        "docker_restart": {
            "services": sorted(after_project),
            "container_ids_preserved": True,
            "healthy_after_restart": True,
            "unrelated_container_count": len(unrelated_after),
            "unrelated_containers_unchanged": True,
            "privileged": host_config["Privileged"],
            "read_only_rootfs": host_config["ReadonlyRootfs"],
        },
        "queue_restart": _cancel_and_restore(tmp_path / "queue"),
    }
    export_path = Path(os.environ.get(
        "MARS_T35_EXPORT", tmp_path / "mars-red-t35-operational.json",
    ))
    export_path.write_text(json.dumps(exported, indent=2, sort_keys=True) + "\n")
    assert "body_excerpt" not in export_path.read_text()
