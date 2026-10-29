"""T25 authorized Manual and Autonomous dispatch tests."""

from datetime import timedelta

import pytest

from orchestrator.red_team_flow import RedQueuedStageRunner
from schemas.red_queue import QueueResourceDTO
from schemas.red_team import RedEndpointCandidate
from schemas.red_team_state import AssessmentDTO, AssessmentState
from services.red_assessment_queue import RedAssessmentQueue
from services.red_assessment_supervisor import (
    RedAssessmentSupervisor,
    RedDispatchDenied,
)
from tests.test_red_orchestrator_states import NOW, build_environment


def build_supervisor(tmp_path, *, mode):
    coordinator, journal, tasks, _ = build_environment(tmp_path, mode=mode)
    snapshot, _ = journal.store.load(tasks[0].scope.assessment_id)
    awaiting = AssessmentDTO.model_validate(snapshot.assessment.model_copy(update={
        "status": AssessmentState.AWAITING_AUTHORIZATION,
        "workflow_complete": False,
    }))
    with journal.store._connect() as db:
        db.execute(
            """UPDATE red_assessments SET assessment_json=?
               WHERE assessment_id=?""",
            (awaiting.model_dump_json(), tasks[0].scope.assessment_id),
        )
    queue = RedAssessmentQueue(journal.store)
    runner = RedQueuedStageRunner(
        queue=queue,
        coordinator=coordinator,
        clock=lambda: NOW + timedelta(minutes=10),
    )
    return (
        RedAssessmentSupervisor(queue=queue, runner=runner),
        journal,
        tasks,
    )


def resources():
    return (
        QueueResourceDTO(resource_class="light"),
        QueueResourceDTO(resource_class="light"),
        QueueResourceDTO(
            resource_class="docker",
            requests=2,
            runtime_seconds=30,
            cpu_cores=0.5,
            memory_mb=512,
        ),
        QueueResourceDTO(resource_class="light"),
    )


def authorize(supervisor, task, mode):
    return supervisor.authorize(
        task.scope,
        approval_id=f"approval-t22-{mode}",
        command_id=f"authorize-{mode}",
        authorized_at=NOW,
    )


def test_autonomous_requires_one_explicit_authorization_and_completes(tmp_path):
    supervisor, journal, tasks = build_supervisor(tmp_path, mode="autonomous")
    assert supervisor.queue.list_jobs(tasks[0].scope) == ()
    with pytest.raises(RedDispatchDenied, match="authorization required"):
        supervisor.enqueue_autonomous(
            tasks,
            command_id="start-before-authorization",
            resources=resources(),
            enqueued_at=NOW,
        )
    with pytest.raises(RedDispatchDenied, match="authorization required"):
        supervisor.authorize(
            tasks[0].scope,
            approval_id="wrong-approval",
            command_id="authorize-wrong",
            authorized_at=NOW,
        )

    first = authorize(supervisor, tasks[0], "autonomous")
    second = authorize(supervisor, tasks[0], "autonomous")
    assert first == second and first.status == AssessmentState.QUEUED
    jobs = supervisor.enqueue_autonomous(
        tasks,
        command_id="start-autonomous",
        resources=resources(),
        enqueued_at=NOW,
    )
    assert tuple(job.work.stage for job in jobs) == (
        "reconnaissance", "planning", "execution", "verification",
    )
    results = tuple(
        supervisor.run_next(
            worker_id=f"worker-auto-{index}",
            claimed_at=NOW + timedelta(minutes=index),
        )
        for index in range(1, 5)
    )

    assert tuple(result.stage for result in results) == (
        "reconnaissance", "planning", "execution", "verification",
    )
    snapshot, _ = journal.store.load(tasks[0].scope.assessment_id)
    assert snapshot.assessment.status == "completed_with_limitations"
    authorization_events = [
        event for event in journal.list_events(tasks[0].scope)
        if event["action"] == "assessment-authorization"
    ]
    assert len(authorization_events) == 1


def test_autonomous_dispatch_is_atomic_when_a_resource_is_denied(tmp_path):
    supervisor, _, tasks = build_supervisor(tmp_path, mode="autonomous")
    authorize(supervisor, tasks[0], "autonomous")
    denied_resources = list(resources())
    denied_resources[2] = denied_resources[2].model_copy(update={
        "requests": 25,
    })

    with pytest.raises(RedDispatchDenied, match="budget exceeds"):
        supervisor.enqueue_autonomous(
            tasks,
            command_id="start-over-budget",
            resources=denied_resources,
            enqueued_at=NOW,
        )

    assert supervisor.queue.list_jobs(tasks[0].scope) == ()


def test_manual_dispatches_selected_stages_and_allows_independent_rerun(tmp_path):
    supervisor, journal, tasks = build_supervisor(tmp_path, mode="manual")
    authorize(supervisor, tasks[0], "manual")

    supervisor.enqueue_manual(
        tasks[0], command_id="manual-recon-1",
        resource=resources()[0], enqueued_at=NOW,
    )
    assert supervisor.run_next(
        worker_id="worker-manual-1", claimed_at=NOW + timedelta(minutes=1),
    ).stage == "reconnaissance"
    supervisor.enqueue_manual(
        tasks[0], command_id="manual-recon-2",
        resource=resources()[0], enqueued_at=NOW + timedelta(minutes=2),
    )
    assert supervisor.run_next(
        worker_id="worker-manual-2", claimed_at=NOW + timedelta(minutes=2),
    ).stage == "reconnaissance"

    for index, (task, resource) in enumerate(
        zip(tasks[1:], resources()[1:], strict=True), start=3,
    ):
        supervisor.enqueue_manual(
            task,
            command_id=f"manual-{task.stage}",
            resource=resource,
            enqueued_at=NOW + timedelta(minutes=index),
        )
        assert supervisor.run_next(
            worker_id=f"worker-manual-{index}",
            claimed_at=NOW + timedelta(minutes=index),
        ).stage == task.stage

    snapshot, _ = journal.store.load(tasks[0].scope.assessment_id)
    assert snapshot.assessment.status == "completed_with_limitations"
    assert tuple(plan.plan_version for plan in snapshot.plans) == ("plan-t22",)
    recon_events = [
        event for event in journal.list_stage_events(tasks[0].scope)
        if event.stage == "reconnaissance" and event.status.value == "succeeded"
    ]
    assert len(recon_events) == 2


def test_stale_plan_and_midrun_mode_change_are_denied_without_queueing(tmp_path):
    supervisor, journal, tasks = build_supervisor(tmp_path, mode="manual")
    authorize(supervisor, tasks[0], "manual")
    for index, task in enumerate(tasks[:2], 1):
        supervisor.enqueue_manual(
            task,
            command_id=f"prepare-{task.stage}",
            resource=resources()[index - 1],
            enqueued_at=NOW + timedelta(minutes=index),
        )
        supervisor.run_next(
            worker_id=f"worker-prepare-{index}",
            claimed_at=NOW + timedelta(minutes=index),
        )

    extra = RedEndpointCandidate(
        candidate_id="candidate-extra",
        method="GET",
        path="/health",
        source="registered",
        observed_at=NOW + timedelta(minutes=3),
    )
    journal.store.add_candidate(tasks[0].scope.assessment_id, extra)
    journal.store.record_surface(
        tasks[0].scope,
        candidates=(*tasks[1].candidates, extra),
        observed_at=NOW + timedelta(minutes=3),
    )
    before = supervisor.queue.list_jobs(tasks[0].scope)

    with pytest.raises(RedDispatchDenied, match="approved operation|active plan"):
        supervisor.enqueue_manual(
            tasks[2],
            command_id="manual-stale-execution",
            resource=resources()[2],
            enqueued_at=NOW + timedelta(minutes=4),
        )
    with pytest.raises(RedDispatchDenied, match="mode is immutable"):
        supervisor.change_mode(tasks[0].scope, "autonomous")

    assert supervisor.queue.list_jobs(tasks[0].scope) == before
    snapshot, _ = journal.store.load(tasks[0].scope.assessment_id)
    assert snapshot.plans[0].status == "stale"
    assert snapshot.assessment.mode == "manual"


def test_authorized_assessment_retains_cancellation_in_both_modes(tmp_path):
    for mode in ("manual", "autonomous"):
        root = tmp_path / mode
        root.mkdir()
        supervisor, journal, tasks = build_supervisor(root, mode=mode)
        authorize(supervisor, tasks[0], mode)
        if mode == "manual":
            supervisor.enqueue_manual(
                tasks[0], command_id=f"queued-{mode}",
                resource=resources()[0], enqueued_at=NOW,
            )
        else:
            supervisor.enqueue_autonomous(
                tasks, command_id=f"queued-{mode}",
                resources=resources(), enqueued_at=NOW,
            )
        cancelled = supervisor.cancel(
            tasks[0].scope,
            cancellation_id=f"cancel-{mode}",
            requested_at=NOW + timedelta(seconds=1),
        )
        assert all(job.status == "cancelled" for job in cancelled)
        snapshot, _ = journal.store.load(tasks[0].scope.assessment_id)
        assert snapshot.assessment.status == "cancelled"
