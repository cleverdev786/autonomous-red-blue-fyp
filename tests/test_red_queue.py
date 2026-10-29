"""T23 durable, resource-aware Red assessment queue."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event

import pytest
import yaml

from orchestrator.policy_engine import StandardRedPolicy
from orchestrator.red_team_flow import (
    RedQueuedStageRunner,
    RedStageCoordinator,
    RedStageExecutionError,
)
from schemas.red_queue import QueueResourceDTO
from schemas.red_team import ExecutionWork
from schemas.red_team_state import AssessmentDTO, CoverageDTO, StageState
from services.red_assessment_queue import QueueDenied, RedAssessmentQueue
from services.red_assessment_store import RedAssessmentStore
from services.target_registry import TargetRegistry
from tests.test_red_orchestrator_states import build_environment

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 29, 9, tzinfo=UTC)


def build_queue(tmp_path, *, count=2, assessment_status="queued"):
    registry = TargetRegistry.from_directories(
        targets_dir=ROOT / "config/targets",
        security_tests_dir=ROOT / "config/security_tests",
    )
    store = RedAssessmentStore(tmp_path / "queue.sqlite3")
    authorizations = []
    for index in range(1, count + 1):
        authorization = StandardRedPolicy(
            registry=registry, budget_file=ROOT / "config/red_standard.json",
        ).freeze(
            assessment_id=f"as-queue-{index}",
            approval_id=f"approval-queue-{index}",
            target_id="vulnerable-store",
        )
        store.create(
            AssessmentDTO(
                scope=authorization.scope,
                mode="manual",
                status=assessment_status,
                workflow_complete=False,
                coverage=CoverageDTO(),
            ),
            authorization,
            request_id=f"request-queue-{index}",
        )
        authorizations.append(authorization)
    return RedAssessmentQueue(store), tuple(authorizations)


def heavy_resource(kind="docker"):
    return QueueResourceDTO(
        resource_class=kind,
        requests=2,
        runtime_seconds=30,
        cpu_cores=0.5,
        memory_mb=512,
    )


def test_concurrent_claims_serialize_heavy_jobs_on_same_target(tmp_path):
    queue, authorizations = build_queue(tmp_path)
    for index, authorization in enumerate(authorizations, 1):
        queue.enqueue(
            job_id=f"job-{index}",
            work=ExecutionWork(
                scope=authorization.scope,
                plan_version="plan-queue",
                operation_id=f"operation-{index}",
            ),
            resource=heavy_resource(),
            enqueued_at=NOW + timedelta(seconds=index),
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        claimed = tuple(
            pool.map(
                lambda worker: RedAssessmentQueue(queue.store).claim_next(
                    worker_id=worker, claimed_at=NOW + timedelta(minutes=1),
                ),
                ("worker-a", "worker-b"),
            )
        )

    active = tuple(item for item in claimed if item is not None)
    assert len(active) == 1
    assert active[0].job_id == "job-1"
    first_snapshot, _ = queue.store.load("as-queue-1")
    assert first_snapshot.assessment.status == "running"
    queue.finish(
        job_id=active[0].job_id,
        lease_id=active[0].lease_id,
        worker_id=active[0].worker_id,
        status="completed",
        finished_at=NOW + timedelta(minutes=2),
    )
    second = queue.claim_next(
        worker_id="worker-c", claimed_at=NOW + timedelta(minutes=3),
    )
    assert second is not None and second.job_id == "job-2"


def test_queue_and_running_lease_survive_restart_without_redelivery(tmp_path):
    queue, (authorization,) = build_queue(tmp_path, count=1)
    work = ExecutionWork(
        scope=authorization.scope,
        plan_version="plan-restart",
        operation_id="operation-restart",
    )
    queued = queue.enqueue(
        job_id="job-restart",
        work=work,
        resource=heavy_resource("zap"),
        enqueued_at=NOW,
    )
    claimed = queue.claim_next(worker_id="worker-before", claimed_at=NOW)
    assert claimed is not None and claimed.sequence == queued.sequence

    restored = RedAssessmentQueue(RedAssessmentStore(queue.store.path))
    jobs = restored.list_jobs(authorization.scope)
    assert jobs[0].status == "running"
    assert jobs[0].work == work
    assert restored.claim_next(worker_id="worker-after", claimed_at=NOW) is None


def test_zap_resource_request_cannot_exceed_frozen_authorization(tmp_path):
    queue, (authorization,) = build_queue(tmp_path, count=1)
    work = ExecutionWork(
        scope=authorization.scope,
        plan_version="plan-zap",
        operation_id="operation-zap",
    )
    excessive = heavy_resource("zap").model_copy(update={"memory_mb": 513})

    with pytest.raises(QueueDenied, match="resource budget"):
        queue.enqueue(
            job_id="job-over-budget",
            work=work,
            resource=excessive,
            enqueued_at=NOW,
        )
    excessive_requests = heavy_resource("zap").model_copy(update={"requests": 13})
    with pytest.raises(QueueDenied, match="resource budget"):
        queue.enqueue(
            job_id="job-over-request-budget",
            work=work,
            resource=excessive_requests,
            enqueued_at=NOW,
        )
    accepted = queue.enqueue(
        job_id="job-in-budget",
        work=work,
        resource=heavy_resource("zap"),
        enqueued_at=NOW,
    )
    assert accepted.resource.memory_mb == authorization.budget.max_memory_mb
    assert accepted.resource.cpu_cores == authorization.budget.max_cpu_cores


def test_heavy_reservations_cannot_collectively_exhaust_assessment_budget(tmp_path):
    queue, (authorization,) = build_queue(tmp_path, count=1)
    work = ExecutionWork(
        scope=authorization.scope,
        plan_version="plan-budget",
        operation_id="operation-budget",
    )
    first = heavy_resource().model_copy(update={
        "requests": 12, "runtime_seconds": 90,
    })
    queue.enqueue(
        job_id="job-budget-1", work=work, resource=first, enqueued_at=NOW,
    )
    second = first.model_copy(update={"requests": 13})

    with pytest.raises(QueueDenied, match="budget is exhausted"):
        queue.enqueue(
            job_id="job-budget-2",
            work=work,
            resource=second,
            enqueued_at=NOW,
        )


def test_zap_reservations_cannot_collectively_exceed_crawl_budget(tmp_path):
    queue, (authorization,) = build_queue(tmp_path, count=1)
    work = ExecutionWork(
        scope=authorization.scope,
        plan_version="plan-zap-budget",
        operation_id="operation-zap-budget",
    )
    seven_requests = heavy_resource("zap").model_copy(update={"requests": 7})
    queue.enqueue(
        job_id="job-zap-budget-1",
        work=work,
        resource=seven_requests,
        enqueued_at=NOW,
    )

    with pytest.raises(QueueDenied, match="budget is exhausted"):
        queue.enqueue(
            job_id="job-zap-budget-2",
            work=work,
            resource=seven_requests,
            enqueued_at=NOW,
        )


def test_queued_runner_uses_t22_coordinator_and_completes_lease(tmp_path):
    coordinator, journal, tasks, workers = build_environment(tmp_path, mode="manual")
    queue = RedAssessmentQueue(journal.store)
    queue.enqueue(
        job_id="job-coordinator",
        work=tasks[0],
        resource=QueueResourceDTO(resource_class="light"),
        enqueued_at=NOW,
    )
    runner = RedQueuedStageRunner(
        queue=queue,
        coordinator=coordinator,
        clock=lambda: NOW + timedelta(seconds=1),
    )

    result = runner.run_next(worker_id="worker-coordinator", claimed_at=NOW)

    assert result is not None and result.stage == "reconnaissance"
    assert queue.list_jobs(tasks[0].scope)[0].status == "completed"
    snapshot, _ = journal.store.load(tasks[0].scope.assessment_id)
    assert snapshot.stages[0].status == StageState.SUCCEEDED
    assert set(coordinator.workers) == set(workers)


def test_crashed_runner_leaves_one_running_lease_and_never_double_dispatches(tmp_path):
    _, journal, tasks, workers = build_environment(tmp_path, mode="manual")
    calls = []

    def interrupt(task):
        calls.append(task.stage)
        raise KeyboardInterrupt("simulated worker loss")

    coordinator = RedStageCoordinator(
        journal=journal,
        workers={**workers, "reconnaissance": interrupt},
        clock=lambda: NOW,
    )
    queue = RedAssessmentQueue(journal.store)
    queue.enqueue(
        job_id="job-crash",
        work=tasks[0],
        resource=QueueResourceDTO(resource_class="light"),
        enqueued_at=NOW,
    )
    runner = RedQueuedStageRunner(queue=queue, coordinator=coordinator)
    with pytest.raises(KeyboardInterrupt, match="worker loss"):
        runner.run_next(worker_id="worker-crash", claimed_at=NOW)

    restored_queue = RedAssessmentQueue(RedAssessmentStore(journal.store.path))
    assert restored_queue.list_jobs(tasks[0].scope)[0].status == "running"
    assert restored_queue.claim_next(worker_id="worker-new", claimed_at=NOW) is None
    assert calls == ["reconnaissance"]


def test_heavy_runner_holds_lease_during_dispatch_and_records_failure(tmp_path):
    _, journal, tasks, workers = build_environment(tmp_path, mode="manual")
    started = Event()
    release = Event()

    def blocked_execution(task):
        started.set()
        assert release.wait(timeout=5)
        return workers["execution"](task)

    coordinator = RedStageCoordinator(
        journal=journal,
        workers={**workers, "execution": blocked_execution},
        clock=lambda: NOW,
    )
    coordinator.run_manual(tasks[0])
    coordinator.run_manual(tasks[1])
    queue = RedAssessmentQueue(journal.store)
    for index in (1, 2):
        queue.enqueue(
            job_id=f"job-heavy-{index}",
            work=tasks[2],
            resource=heavy_resource().model_copy(update={
                "requests": 2, "runtime_seconds": 10,
            }),
            enqueued_at=NOW,
        )
    runner = RedQueuedStageRunner(
        queue=queue,
        coordinator=coordinator,
        clock=lambda: NOW + timedelta(seconds=1),
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            runner.run_next, worker_id="worker-heavy", claimed_at=NOW,
        )
        assert started.wait(timeout=5)
        assert queue.claim_next(worker_id="worker-second", claimed_at=NOW) is None
        release.set()
        assert future.result(timeout=5).stage == "execution"
    assert queue.list_jobs(tasks[0].scope)[0].status == "completed"

    failed_root = tmp_path / "failed"
    failed_root.mkdir()
    _, failed_journal, failed_tasks, failed_workers = build_environment(
        failed_root, mode="manual",
    )
    failing = RedStageCoordinator(
        journal=failed_journal,
        workers={
            **failed_workers,
            "execution": lambda _task: (_ for _ in ()).throw(RuntimeError("boom")),
        },
        clock=lambda: NOW,
    )
    failing.run_manual(failed_tasks[0])
    failing.run_manual(failed_tasks[1])
    failed_queue = RedAssessmentQueue(failed_journal.store)
    failed_queue.enqueue(
        job_id="job-heavy-failed",
        work=failed_tasks[2],
        resource=heavy_resource(),
        enqueued_at=NOW,
    )
    failed_runner = RedQueuedStageRunner(
        queue=failed_queue,
        coordinator=failing,
        clock=lambda: NOW + timedelta(seconds=1),
    )
    with pytest.raises(RedStageExecutionError, match="execution worker failed"):
        failed_runner.run_next(worker_id="worker-failed", claimed_at=NOW)
    assert failed_queue.list_jobs(failed_tasks[0].scope)[0].status == "failed"


def test_fifo_payload_and_terminal_status_survive_restart(tmp_path):
    queue, authorizations = build_queue(tmp_path)
    first_work = ExecutionWork(
        scope=authorizations[0].scope,
        plan_version="plan-first",
        operation_id="operation-first",
    )
    second_work = ExecutionWork(
        scope=authorizations[1].scope,
        plan_version="plan-second",
        operation_id="operation-second",
    )
    queue.enqueue(
        job_id="job-first", work=first_work,
        resource=heavy_resource(), enqueued_at=NOW,
    )
    queue.enqueue(
        job_id="job-second", work=second_work,
        resource=heavy_resource(), enqueued_at=NOW + timedelta(seconds=1),
    )
    first = queue.claim_next(worker_id="worker-first", claimed_at=NOW)
    queue.finish(
        job_id=first.job_id, lease_id=first.lease_id,
        worker_id=first.worker_id, status="completed",
        finished_at=NOW + timedelta(seconds=1),
    )

    restored = RedAssessmentQueue(RedAssessmentStore(queue.store.path))
    assert restored.list_jobs(authorizations[0].scope)[0].status == "completed"
    second = restored.claim_next(
        worker_id="worker-second", claimed_at=NOW + timedelta(seconds=2),
    )
    assert second.work == second_work
    assert second.resource == heavy_resource()


def test_invalid_queue_chronology_is_denied_without_mutation(tmp_path):
    queue, (authorization,) = build_queue(tmp_path, count=1)
    work = ExecutionWork(
        scope=authorization.scope,
        plan_version="plan-time",
        operation_id="operation-time",
    )
    queue.enqueue(
        job_id="job-time", work=work, resource=heavy_resource(),
        enqueued_at=NOW,
    )
    with pytest.raises(QueueDenied, match="precede enqueue"):
        queue.claim_next(
            worker_id="worker-time", claimed_at=NOW - timedelta(seconds=1),
        )
    assert queue.list_jobs(authorization.scope)[0].status == "queued"
    claimed = queue.claim_next(worker_id="worker-time", claimed_at=NOW)
    with pytest.raises(QueueDenied, match="precede claim"):
        queue.finish(
            job_id=claimed.job_id,
            lease_id=claimed.lease_id,
            worker_id=claimed.worker_id,
            status="completed",
            finished_at=NOW - timedelta(seconds=1),
        )
    assert queue.list_jobs(authorization.scope)[0].status == "running"


def test_claim_rejects_denormalized_row_that_disagrees_with_typed_payload(tmp_path):
    queue, (authorization,) = build_queue(tmp_path, count=1)
    work = ExecutionWork(
        scope=authorization.scope,
        plan_version="plan-tamper",
        operation_id="operation-tamper",
    )
    queue.enqueue(
        job_id="job-tamper", work=work, resource=heavy_resource(),
        enqueued_at=NOW,
    )
    with queue.store._connect() as db:
        db.execute(
            "UPDATE red_queue_jobs SET resource_class='light' WHERE job_id='job-tamper'"
        )

    with pytest.raises(QueueDenied, match="provenance"):
        queue.claim_next(worker_id="worker-tamper", claimed_at=NOW)
    with queue.store._connect() as db:
        status = db.execute(
            "SELECT status FROM red_queue_jobs WHERE job_id='job-tamper'"
        ).fetchone()["status"]
    assert status == "queued"


def test_claim_rejects_tampered_running_lease_before_conflict_decision(tmp_path):
    queue, authorizations = build_queue(tmp_path)
    for index, authorization in enumerate(authorizations, 1):
        queue.enqueue(
            job_id=f"job-running-tamper-{index}",
            work=ExecutionWork(
                scope=authorization.scope,
                plan_version="plan-running-tamper",
                operation_id=f"operation-running-tamper-{index}",
            ),
            resource=heavy_resource(),
            enqueued_at=NOW,
        )
    queue.claim_next(worker_id="worker-running-tamper", claimed_at=NOW)
    with queue.store._connect() as db:
        db.execute(
            """UPDATE red_queue_jobs SET target_id='other-target'
               WHERE job_id='job-running-tamper-1'"""
        )

    with pytest.raises(QueueDenied, match="provenance"):
        queue.claim_next(worker_id="worker-after-tamper", claimed_at=NOW)
    assert queue.list_jobs(authorizations[1].scope)[0].status == "queued"


def test_compose_limits_are_at_or_below_queue_authorization_ceiling():
    base = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
    zap = yaml.safe_load((ROOT / "compose.zap.yaml").read_text(encoding="utf-8"))
    assert base["services"]["controlled-executor"]["cpus"] <= 0.5
    assert base["services"]["controlled-executor"]["mem_limit"] == "128m"
    assert zap["services"]["zap"]["cpus"] <= 0.5
    assert zap["services"]["zap"]["mem_limit"] == "512m"
