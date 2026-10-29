"""T24 prompt cancellation and no-blind-retry recovery tests."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Event

import pytest

from orchestrator.red_team_flow import RedQueuedStageRunner, RedStageCoordinator
from schemas.red_queue import QueueResourceDTO
from schemas.red_team import ExecutionWork, RedPolicyUsage
from schemas.red_team_state import OperationDTO
from services.red_assessment_queue import QueueDenied, RedAssessmentQueue
from services.red_assessment_recovery import RedAssessmentRecovery
from services.red_assessment_store import RedAssessmentStore
from services.red_evidence_store import RedEvidenceStore
from services.zap_adapter import (
    FixedTargetedZapRunner,
    TargetedZapOperation,
    ZapAdapterDenied,
)
from tests.test_red_orchestrator_states import NOW, build_environment
from tests.test_red_real_execution import build_execution_env


def test_cancel_before_start_revokes_queue_and_is_idempotent(tmp_path):
    _, journal, tasks, _ = build_environment(tmp_path, mode="manual")
    queue = RedAssessmentQueue(journal.store)
    queue.enqueue(
        job_id="job-cancel-before",
        work=tasks[0],
        resource=QueueResourceDTO(resource_class="light"),
        enqueued_at=NOW,
    )

    first = queue.request_cancellation(
        tasks[0].scope,
        cancellation_id="cancel-before",
        requested_at=NOW + timedelta(seconds=1),
    )
    second = queue.request_cancellation(
        tasks[0].scope,
        cancellation_id="cancel-before",
        requested_at=NOW + timedelta(seconds=1),
    )

    assert first == second
    assert first[0].status == "cancelled"
    assert queue.claim_next(
        worker_id="worker-after-cancel",
        claimed_at=NOW + timedelta(seconds=2),
    ) is None
    snapshot, _ = journal.store.load(tasks[0].scope.assessment_id)
    assert snapshot.assessment.status == "cancelled"
    assert snapshot.plans[0].plan_version == "plan-t22"
    assert journal.list_receipts(tasks[0].scope)[0].receipt_id == "receipt-t22"
    assert journal.list_events(tasks[0].scope)[-1]["action"] == (
        "assessment-cancellation"
    )
    with pytest.raises(QueueDenied, match="not queueable|cannot accept"):
        queue.enqueue(
            job_id="job-after-cancel",
            work=tasks[0],
            resource=QueueResourceDTO(resource_class="light"),
            enqueued_at=NOW + timedelta(seconds=2),
        )


def test_cancel_during_worker_signals_stop_and_records_cancelled_stage(tmp_path):
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
        clock=lambda: NOW + timedelta(seconds=2),
    )
    coordinator.run_manual(tasks[0])
    coordinator.run_manual(tasks[1])
    queue = RedAssessmentQueue(journal.store)
    queue.enqueue(
        job_id="job-cancel-running",
        work=tasks[2],
        resource=QueueResourceDTO(
            resource_class="docker", requests=2, runtime_seconds=30,
            cpu_cores=0.5, memory_mb=512,
        ),
        enqueued_at=NOW,
    )
    runner = RedQueuedStageRunner(
        queue=queue,
        coordinator=coordinator,
        clock=lambda: NOW + timedelta(seconds=3),
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            runner.run_next,
            worker_id="worker-cancel-running",
            claimed_at=NOW + timedelta(seconds=1),
        )
        assert started.wait(timeout=5)
        jobs = queue.request_cancellation(
            tasks[0].scope,
            cancellation_id="cancel-running",
            requested_at=NOW + timedelta(seconds=2),
        )
        assert jobs[0].status == "running"
        assert jobs[0].cancellation_requested_at is not None
        release.set()
        assert future.result(timeout=5) is None

    job = queue.list_jobs(tasks[0].scope)[0]
    snapshot, _ = journal.store.load(tasks[0].scope.assessment_id)
    assert job.status == "cancelled"
    assert snapshot.assessment.status == "cancelled"
    assert next(stage for stage in snapshot.stages if stage.stage == "execution").status == "cancelled"


def test_controlled_http_stops_after_current_request_when_cancelled(tmp_path):
    dispatcher, request, transport = build_execution_env(tmp_path)
    state = {"cancelled": False}
    original_send = transport.send

    def send_then_cancel(**kwargs):
        response = original_send(**kwargs)
        state["cancelled"] = True
        return response

    transport.send = send_then_cancel
    receipt = dispatcher.execute(
        request=request,
        usage=RedPolicyUsage(),
        attempt_number=1,
        run_id="run-cancelled-http",
        cancellation_requested=lambda: state["cancelled"],
    )

    assert receipt.status == "cancelled"
    assert receipt.error_class == "cancellation-requested"
    assert receipt.request_count == 1
    assert len(transport.calls) == 1
    persisted = dispatcher.admission.journal.list_receipts(request.scope)[0]
    assert persisted.status == "cancelled"


def test_targeted_zap_requests_stop_scan_after_cancellation():
    calls = []
    state = {"cancelled": False}

    def request_json(route, params, timeout):
        calls.append((route, params, timeout))
        if route.endswith("/scan/"):
            state["cancelled"] = True
            return {"scan": "7"}
        return {}

    runner = FixedTargetedZapRunner(
        request_json=request_json,
        gate_status=lambda _timeout: {"forwarded": 0, "limit": 2},
        cancellation_requested=lambda: state["cancelled"],
    )
    operation = TargetedZapOperation(
        test_id="xss-reflection-001",
        scanner_id="40012",
        endpoint_id="scenario-xss-search",
        method="GET",
        url="http://vulnerable-store:8000/scenarios/xss/search?q=notebook",
        scan_policy_name="mars-xss-reflection-001",
        request_limit=2,
        duration_seconds=30,
    )

    with pytest.raises(ZapAdapterDenied, match="targeted_runner_cancelled"):
        runner(operation)

    assert any(route.endswith("/stop/") for route, _params, _timeout in calls)
    assert not any(route.endswith("/alerts/") for route, _params, _timeout in calls)


def test_restart_recovery_marks_unknown_execution_inconclusive_without_retry(tmp_path):
    _, journal, tasks, workers = build_environment(tmp_path, mode="manual")
    coordinator = RedStageCoordinator(
        journal=journal,
        workers={
            **workers,
            "execution": lambda _task: (_ for _ in ()).throw(
                KeyboardInterrupt("process lost")
            ),
        },
        clock=lambda: NOW,
    )
    coordinator.run_manual(tasks[0])
    coordinator.run_manual(tasks[1])
    recovery_operation = OperationDTO(
        scope=tasks[0].scope,
        operation_id="operation-recovery",
        plan_version=tasks[2].plan_version,
        candidate_id="candidate-xss",
        test_id="xss-reflection-001",
        status="approved",
    )
    journal.store.add_operation(recovery_operation)
    recovery_work = ExecutionWork(
        scope=tasks[0].scope,
        plan_version=tasks[2].plan_version,
        operation_id=recovery_operation.operation_id,
    )
    queue = RedAssessmentQueue(journal.store)
    queue.enqueue(
        job_id="job-recovery",
        work=recovery_work,
        resource=QueueResourceDTO(
            resource_class="docker", requests=2, runtime_seconds=30,
            cpu_cores=0.5, memory_mb=512,
        ),
        enqueued_at=NOW,
    )
    runner = RedQueuedStageRunner(queue=queue, coordinator=coordinator)
    try:
        runner.run_next(worker_id="worker-lost", claimed_at=NOW)
    except KeyboardInterrupt:
        pass

    restored_store = RedAssessmentStore(journal.store.path)
    restored_journal = RedEvidenceStore(restored_store, journal.evidence_root)
    restored_queue = RedAssessmentQueue(restored_store)
    recovered = RedAssessmentRecovery(
        queue=restored_queue, journal=restored_journal,
    ).recover(
        recovery_work.scope,
        recovered_at=NOW + timedelta(minutes=1),
    )

    assert recovered[0].status == "failed"
    assert restored_queue.claim_next(
        worker_id="worker-no-retry",
        claimed_at=NOW + timedelta(minutes=2),
    ) is None
    receipts = [
        item for item in restored_journal.list_receipts(recovery_work.scope)
        if item.operation_id == recovery_work.operation_id
    ]
    assert len(receipts) == 1 and receipts[0].status == "failed"
    findings = [
        item for item in restored_journal.list_findings(recovery_work.scope)
        if item.operation_id == recovery_work.operation_id
    ]
    assert len(findings) == 1 and findings[0].status == "inconclusive"
    snapshot, authorization = restored_store.load(
        recovery_work.scope.assessment_id
    )
    assert authorization.budget.max_retries == 0
    assert snapshot.assessment.status == "failed"
    assert snapshot.plans[0].plan_version == "plan-t22"
