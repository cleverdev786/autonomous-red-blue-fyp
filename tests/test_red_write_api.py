"""T27 authenticated Red command API integration tests."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from threading import Barrier

import httpx
import pytest

from dashboard.api.console import create_console_app
from orchestrator.red_team_flow import RedStageExecutionError
from schemas.red_queue import QueueResourceDTO
from schemas.red_team import (
    ExecutionWorkResult,
    PlanningWorkResult,
    VerificationWorkResult,
)
from schemas.red_team_state import AssessmentState, FindingDTO
from services.red_assessment_queue import RedAssessmentQueue
from services.red_assessment_store import RedAssessmentStore
from services.target_registry import TargetRegistry
from tests.test_red_modes import build_supervisor
from tests.test_red_orchestrator_states import NOW

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "http://127.0.0.1:8090"
TOKEN = "test-operator-credential-at-least-32-bytes"


@pytest.fixture
def empty_site(tmp_path, monkeypatch):
    monkeypatch.setenv("MARS_RED_OPERATOR_TOKEN", TOKEN)
    state_db = tmp_path / "red.sqlite3"
    app = create_console_app(
        database_path=tmp_path / "missing-research.db",
        mars_workspace_db=tmp_path / "mars.db",
        red_state_db=state_db,
    )
    return app, state_db


@pytest.fixture
def manual_site(tmp_path, monkeypatch):
    monkeypatch.setenv("MARS_RED_OPERATOR_TOKEN", TOKEN)
    supervisor, journal, tasks = build_supervisor(tmp_path, mode="manual")
    app = create_console_app(
        database_path=tmp_path / "missing-research.db",
        mars_workspace_db=tmp_path / "mars.db",
        red_state_db=journal.store.path,
    )
    return app, supervisor, journal, tasks


@pytest.fixture
def autonomous_site(tmp_path, monkeypatch):
    monkeypatch.setenv("MARS_RED_OPERATOR_TOKEN", TOKEN)
    supervisor, journal, tasks = build_supervisor(tmp_path, mode="autonomous")
    supervisor.registry = TargetRegistry.from_directories(
        targets_dir=ROOT / "config/targets",
        security_tests_dir=ROOT / "config/security_tests",
    )
    app = create_console_app(
        database_path=tmp_path / "missing-research.db",
        mars_workspace_db=tmp_path / "mars.db",
        red_state_db=journal.store.path,
    )
    return app, supervisor, journal, tasks


def _headers(csrf: str | None = None):
    headers = {"Authorization": f"Bearer {TOKEN}", "Origin": ORIGIN}
    if csrf is not None:
        headers["X-Red-CSRF"] = csrf
    return headers


def _request(app, method: str, path: str, body=None, *, headers=None):
    async def request():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            supplied = headers
            if supplied is None:
                challenge = await client.get(
                    "/api/red/operator/csrf",
                    headers=_headers(),
                )
                assert challenge.status_code == 200
                supplied = _headers(challenge.json()["csrf_token"])
            return await client.request(method, path, headers=supplied, json=body)

    return asyncio.run(request())


def test_draft_authorize_start_is_idempotent_and_never_runs_on_create(empty_site):
    app, state_db = empty_site
    draft = {
        "request_id": "create-autonomous-1",
        "target_id": "vulnerable-store",
        "mode": "autonomous",
        "approval_id": "approval-autonomous-1",
    }

    created = _request(app, "POST", "/api/red/assessments", draft)
    repeated = _request(app, "POST", "/api/red/assessments", draft)
    assessment_id = created.json()["assessment_id"]

    assert created.status_code == 201
    assert repeated.status_code == 201
    assert repeated.json() == created.json()
    assert created.json() == {
        "assessment_id": assessment_id,
        "request_id": "create-autonomous-1",
        "status": "awaiting_authorization",
        "job_ids": [],
    }
    summary = _request(app, "GET", "/api/red/summary")
    assert summary.status_code == 200
    assert summary.json()["assessment_count"] == 1
    assert summary.json()["active_assessments"] == 0
    before_authorization = _request(
        app,
        "POST",
        f"/api/red/assessments/{assessment_id}/start",
        {"request_id": "start-before-authorization"},
    )
    assert before_authorization.status_code == 409
    assert _request(
        app,
        "POST",
        f"/api/red/assessments/{assessment_id}/authorize",
        {"request_id": "authorize-autonomous-1", "approval_id": "wrong"},
    ).status_code == 409

    authorized = _request(
        app,
        "POST",
        f"/api/red/assessments/{assessment_id}/authorize",
        {
            "request_id": "authorize-autonomous-1",
            "approval_id": "approval-autonomous-1",
        },
    )
    started = _request(
        app,
        "POST",
        f"/api/red/assessments/{assessment_id}/start",
        {"request_id": "start-autonomous-1"},
    )
    replay = _request(
        app,
        "POST",
        f"/api/red/assessments/{assessment_id}/start",
        {"request_id": "start-autonomous-1"},
    )

    assert authorized.status_code == 202
    assert authorized.json()["status"] == "queued"
    assert started.status_code == replay.status_code == 202
    assert started.json() == replay.json()
    assert len(started.json()["job_ids"]) == 1
    workspace = _request(app, "GET", f"/api/red/assessments/{assessment_id}")
    assert workspace.status_code == 200
    assert workspace.json()["assessment"]["stage_statuses"] == {
        "reconnaissance": "queued",
    }
    assert workspace.json()["stages"][0]["status"] == "queued"
    supervisor_store = RedAssessmentStore(state_db)
    queue = RedAssessmentQueue(supervisor_store)
    jobs = queue.list_jobs(supervisor_store.load(assessment_id)[0].assessment.scope)
    assert len(jobs) == 1 and jobs[0].work.stage == "reconnaissance"
    assert _request(app, "POST", "/api/red/assessments", draft).status_code == 201


def test_unauthorized_draft_can_be_cancelled_idempotently(empty_site):
    app, state_db = empty_site
    created = _request(app, "POST", "/api/red/assessments", {
        "request_id": "create-cancellable-draft",
        "target_id": "vulnerable-store",
        "mode": "manual",
        "approval_id": "approval-cancellable-draft",
    })
    assessment_id = created.json()["assessment_id"]
    path = f"/api/red/assessments/{assessment_id}/cancel"
    command = {"request_id": "cancel-unauthorized-draft"}

    cancelled = _request(app, "POST", path, command)
    replay = _request(app, "POST", path, command)

    assert cancelled.status_code == replay.status_code == 202
    assert cancelled.json() == replay.json() == {
        "assessment_id": assessment_id,
        "request_id": "cancel-unauthorized-draft",
        "status": "cancelled",
        "job_ids": [],
    }
    snapshot, _ = RedAssessmentStore(state_db).load(assessment_id)
    assert snapshot.assessment.status == AssessmentState.CANCELLED


def test_autonomous_start_durably_continues_all_stages(autonomous_site):
    app, supervisor, journal, tasks = autonomous_site
    scope = tasks[0].scope
    assert _request(
        app,
        "POST",
        f"/api/red/assessments/{scope.assessment_id}/authorize",
        {
            "request_id": "authorize-progressive-api",
            "approval_id": "approval-t22-autonomous",
        },
    ).status_code == 202
    assert _request(
        app,
        "POST",
        f"/api/red/assessments/{scope.assessment_id}/start",
        {"request_id": "start-progressive-api"},
    ).status_code == 202

    first_claim = supervisor.queue.list_jobs(scope)[0].enqueued_at + timedelta(minutes=1)
    supervisor.runner.clock = lambda: first_claim + timedelta(minutes=1)
    results = [supervisor.runner.run_next(
        worker_id="worker-progressive-0",
        claimed_at=first_claim,
    )]
    assert len(supervisor.queue.list_jobs(scope)) == 1
    supervisor.runner.clock = lambda: first_claim + timedelta(minutes=2)
    results.append(supervisor.run_next(
        worker_id="worker-progressive-recovery",
        claimed_at=first_claim + timedelta(minutes=2),
    ))

    for index in range(2, 4):
        claimed_at = first_claim + timedelta(minutes=index * 2)
        supervisor.runner.clock = (
            lambda claimed_at=claimed_at: claimed_at + timedelta(minutes=1)
        )
        results.append(supervisor.run_next(
            worker_id=f"worker-progressive-{index}",
            claimed_at=claimed_at,
        ))

    assert tuple(result.stage for result in results) == (
        "reconnaissance", "planning", "execution", "verification",
    )
    assert len(supervisor.queue.list_jobs(scope)) == 4
    snapshot, _ = journal.store.load(scope.assessment_id)
    assert snapshot.assessment.status == AssessmentState.COMPLETED_WITH_LIMITATIONS


def test_autonomous_start_sequences_every_approved_operation(autonomous_site):
    app, supervisor, journal, tasks = autonomous_site
    scope = tasks[0].scope
    snapshot, _ = journal.store.load(scope.assessment_id)
    original = snapshot.operations[0]
    second = original.model_copy(update={"operation_id": "operation-t27-second"})
    journal.store.add_operation(second)
    original_receipt = journal.list_receipts(scope)[0]
    second_receipt = original_receipt.model_copy(update={
        "receipt_id": "receipt-t27-second",
        "operation_id": second.operation_id,
        "run_id": "run-t27-second",
        "evidence_id": "evidence-t27-second",
    })
    journal.add_receipt_with_evidence(
        second_receipt,
        data={
            "operation_id": second.operation_id,
            "test_id": second.test_id,
            "status": "completed",
        },
    )
    journal._record_verified_finding(FindingDTO(
        scope=scope,
        finding_id="finding-t27-second",
        operation_id=second.operation_id,
        status="inconclusive",
        oracle_id="unescaped-reflection-evidence-001",
        evidence_receipt_ids=(second_receipt.receipt_id,),
    ))
    receipts = {
        original.operation_id: original_receipt.receipt_id,
        second.operation_id: second_receipt.receipt_id,
    }
    supervisor.runner.coordinator.workers.update({
        "planning": lambda task: PlanningWorkResult(
            scope=task.scope,
            plan_version=original.plan_version,
            operation_ids=(original.operation_id, second.operation_id),
        ),
        "execution": lambda task: ExecutionWorkResult(
            scope=task.scope,
            plan_version=task.plan_version,
            operation_id=task.operation_id,
            receipt_ids=(receipts[task.operation_id],),
        ),
        "verification": lambda task: VerificationWorkResult(
            scope=task.scope,
            plan_version=task.plan_version,
            operation_id=task.operation_id,
            outcome="inconclusive",
            evidence_receipt_ids=(receipts[task.operation_id],),
        ),
    })
    _request(
        app,
        "POST",
        f"/api/red/assessments/{scope.assessment_id}/authorize",
        {
            "request_id": "authorize-multi-operation",
            "approval_id": "approval-t22-autonomous",
        },
    )
    _request(
        app,
        "POST",
        f"/api/red/assessments/{scope.assessment_id}/start",
        {"request_id": "start-multi-operation"},
    )

    results = []
    for index in range(6):
        claimed_at = NOW + timedelta(days=2, minutes=index * 2)
        supervisor.runner.clock = (
            lambda claimed_at=claimed_at: claimed_at + timedelta(minutes=1)
        )
        results.append(supervisor.run_next(
            worker_id=f"worker-multi-{index}", claimed_at=claimed_at,
        ))

    assert tuple(result.stage for result in results) == (
        "reconnaissance", "planning", "execution", "verification",
        "execution", "verification",
    )
    assert tuple(
        job.work.operation_id
        for job in supervisor.queue.list_jobs(scope)
        if job.work.stage == "execution"
    ) == (original.operation_id, second.operation_id)
    completed, _ = journal.store.load(scope.assessment_id)
    assert completed.assessment.status == AssessmentState.COMPLETED_WITH_LIMITATIONS


def test_progressive_failure_terminalizes_without_retry(autonomous_site):
    app, supervisor, journal, tasks = autonomous_site
    scope = tasks[0].scope
    supervisor.runner.coordinator.workers["reconnaissance"] = (
        lambda _task: (_ for _ in ()).throw(RuntimeError("worker unavailable"))
    )
    _request(
        app,
        "POST",
        f"/api/red/assessments/{scope.assessment_id}/authorize",
        {
            "request_id": "authorize-failed-progressive",
            "approval_id": "approval-t22-autonomous",
        },
    )
    _request(
        app,
        "POST",
        f"/api/red/assessments/{scope.assessment_id}/start",
        {"request_id": "start-failed-progressive"},
    )
    supervisor.runner.clock = lambda: NOW + timedelta(days=3, minutes=1)

    with pytest.raises(RedStageExecutionError, match="worker failed"):
        supervisor.run_next(
            worker_id="worker-failed-progressive",
            claimed_at=NOW + timedelta(days=3),
        )

    failed, _ = journal.store.load(scope.assessment_id)
    assert failed.assessment.status == AssessmentState.FAILED
    assert [job.status for job in supervisor.queue.list_jobs(scope)] == ["failed"]
    assert supervisor.run_next(
        worker_id="worker-no-retry",
        claimed_at=NOW + timedelta(days=3, minutes=1),
    ) is None
    assert len(supervisor.queue.list_jobs(scope)) == 1


def test_progressive_plan_without_approved_operations_finishes_truthfully(
    autonomous_site,
):
    app, supervisor, journal, tasks = autonomous_site
    scope = tasks[0].scope
    snapshot, _ = journal.store.load(scope.assessment_id)
    proposed = snapshot.operations[0].model_copy(update={"status": "proposed"})
    with journal.store._connect() as db:
        db.execute(
            """UPDATE red_operations SET payload=?
               WHERE assessment_id=? AND operation_id=?""",
            (proposed.model_dump_json(), scope.assessment_id, proposed.operation_id),
        )
    _request(
        app,
        "POST",
        f"/api/red/assessments/{scope.assessment_id}/authorize",
        {
            "request_id": "authorize-no-approved-operations",
            "approval_id": "approval-t22-autonomous",
        },
    )
    _request(
        app,
        "POST",
        f"/api/red/assessments/{scope.assessment_id}/start",
        {"request_id": "start-no-approved-operations"},
    )

    for index in range(2):
        claimed_at = NOW + timedelta(days=3, hours=1, minutes=index * 2)
        supervisor.runner.clock = (
            lambda claimed_at=claimed_at: claimed_at + timedelta(minutes=1)
        )
        supervisor.run_next(
            worker_id=f"worker-no-approved-{index}", claimed_at=claimed_at,
        )

    completed, _ = journal.store.load(scope.assessment_id)
    assert completed.assessment.status == AssessmentState.COMPLETED_WITH_LIMITATIONS
    assert tuple(
        job.work.stage for job in supervisor.queue.list_jobs(scope)
    ) == ("reconnaissance", "planning")


def test_progressive_recovery_tolerates_an_active_successor(autonomous_site):
    app, supervisor, _, tasks = autonomous_site
    scope = tasks[0].scope
    _request(
        app,
        "POST",
        f"/api/red/assessments/{scope.assessment_id}/authorize",
        {
            "request_id": "authorize-active-successor",
            "approval_id": "approval-t22-autonomous",
        },
    )
    _request(
        app,
        "POST",
        f"/api/red/assessments/{scope.assessment_id}/start",
        {"request_id": "start-active-successor"},
    )
    supervisor.runner.clock = lambda: NOW + timedelta(days=4, seconds=30)
    supervisor.run_next(
        worker_id="worker-recon-successor",
        claimed_at=NOW + timedelta(days=4),
    )
    active = supervisor.queue.claim_next(
        worker_id="worker-owning-successor",
        claimed_at=NOW + timedelta(days=4, minutes=1),
    )
    assert active is not None and active.work.stage == "planning"

    assert supervisor.run_next(
        worker_id="worker-idle-successor",
        claimed_at=NOW + timedelta(days=4, minutes=2),
    ) is None
    assert len(supervisor.queue.list_jobs(scope)) == 2


def test_progressive_recovery_runs_before_other_queued_work(autonomous_site):
    app, supervisor, _, tasks = autonomous_site
    scope = tasks[0].scope
    _request(
        app,
        "POST",
        f"/api/red/assessments/{scope.assessment_id}/authorize",
        {
            "request_id": "authorize-recovery-order",
            "approval_id": "approval-t22-autonomous",
        },
    )
    _request(
        app,
        "POST",
        f"/api/red/assessments/{scope.assessment_id}/start",
        {"request_id": "start-recovery-order"},
    )
    supervisor.runner.clock = lambda: NOW + timedelta(days=5, seconds=30)
    supervisor.runner.run_next(
        worker_id="worker-crash-window",
        claimed_at=NOW + timedelta(days=5),
    )
    supervisor.queue.enqueue(
        job_id="job-unrelated-before-recovery",
        work=tasks[0],
        resource=QueueResourceDTO(resource_class="light"),
        enqueued_at=NOW + timedelta(days=5, minutes=1),
    )
    supervisor.runner.clock = lambda: NOW + timedelta(days=5, minutes=3)

    supervisor.run_next(
        worker_id="worker-other-queued-work",
        claimed_at=NOW + timedelta(days=5, minutes=2),
    )

    assert any(
        job.work.stage == "planning"
        for job in supervisor.queue.list_jobs(scope)
    )


def test_progressive_finalization_is_idempotent_across_recovery_workers(
    autonomous_site,
):
    app, supervisor, journal, tasks = autonomous_site
    scope = tasks[0].scope
    _request(
        app,
        "POST",
        f"/api/red/assessments/{scope.assessment_id}/authorize",
        {
            "request_id": "authorize-concurrent-finalize",
            "approval_id": "approval-t22-autonomous",
        },
    )
    _request(
        app,
        "POST",
        f"/api/red/assessments/{scope.assessment_id}/start",
        {"request_id": "start-concurrent-finalize"},
    )
    for index in range(4):
        if index:
            supervisor._resume_progressive_autonomous()
        claimed_at = NOW + timedelta(days=6, minutes=index * 2)
        supervisor.runner.clock = (
            lambda claimed_at=claimed_at: claimed_at + timedelta(minutes=1)
        )
        supervisor.runner.run_next(
            worker_id=f"worker-pre-finalize-{index}", claimed_at=claimed_at,
        )
    running, _ = journal.store.load(scope.assessment_id)
    assert running.assessment.status == AssessmentState.RUNNING

    barrier = Barrier(2)

    def recover():
        barrier.wait()
        supervisor._resume_progressive_autonomous()

    with ThreadPoolExecutor(max_workers=2) as pool:
        tuple(pool.map(lambda _index: recover(), range(2)))

    completed, _ = journal.store.load(scope.assessment_id)
    assert completed.assessment.status == AssessmentState.COMPLETED_WITH_LIMITATIONS


def test_manual_stage_run_cancel_and_conflicts_have_no_duplicate_effect(manual_site):
    app, supervisor, journal, tasks = manual_site
    scope = tasks[0].scope

    authorized = _request(
        app,
        "POST",
        f"/api/red/assessments/{scope.assessment_id}/authorize",
        {"request_id": "authorize-manual-api", "approval_id": "approval-t22-manual"},
    )
    run = _request(
        app,
        "POST",
        f"/api/red/assessments/{scope.assessment_id}/stages/reconnaissance/run",
        {"request_id": "run-recon-api"},
    )
    replay = _request(
        app,
        "POST",
        f"/api/red/assessments/{scope.assessment_id}/stages/reconnaissance/run",
        {"request_id": "run-recon-api"},
    )
    active_duplicate = _request(
        app,
        "POST",
        f"/api/red/assessments/{scope.assessment_id}/stages/reconnaissance/run",
        {"request_id": "run-recon-api-other"},
    )
    wrong_mode = _request(
        app,
        "POST",
        f"/api/red/assessments/{scope.assessment_id}/start",
        {"request_id": "autonomous-on-manual"},
    )
    cancelled = _request(
        app,
        "POST",
        f"/api/red/assessments/{scope.assessment_id}/cancel",
        {"request_id": "cancel-manual-api"},
    )
    cancel_replay = _request(
        app,
        "POST",
        f"/api/red/assessments/{scope.assessment_id}/cancel",
        {"request_id": "cancel-manual-api"},
    )

    assert authorized.status_code == 202
    assert run.status_code == replay.status_code == 202
    assert run.json() == replay.json()
    assert active_duplicate.status_code == 409
    assert active_duplicate.json()["error"]["code"] == "active_operation"
    assert wrong_mode.status_code == 409
    assert wrong_mode.json()["error"]["code"] == "locked_mode"
    assert cancelled.status_code == cancel_replay.status_code == 202
    assert cancelled.json() == cancel_replay.json()
    jobs = supervisor.queue.list_jobs(scope)
    assert len(jobs) == 1 and jobs[0].status == "cancelled"
    snapshot, _ = journal.store.load(scope.assessment_id)
    assert snapshot.assessment.status == AssessmentState.CANCELLED


def test_stale_plan_and_active_stage_are_explained_without_side_effect(manual_site):
    app, supervisor, journal, tasks = manual_site
    scope = tasks[0].scope
    _request(
        app,
        "POST",
        f"/api/red/assessments/{scope.assessment_id}/authorize",
        {"request_id": "authorize-stale-api", "approval_id": "approval-t22-manual"},
    )
    candidate = tasks[1].candidates[0]
    extra = candidate.model_copy(update={
        "candidate_id": "candidate-stale-api",
        "path": "/health",
        "observed_at": candidate.observed_at + timedelta(seconds=1),
    })
    journal.store.add_candidate(scope.assessment_id, extra)
    journal.store.record_surface(
        scope,
        candidates=(*tasks[1].candidates, extra),
        observed_at=extra.observed_at,
    )
    before = supervisor.queue.list_jobs(scope)

    response = _request(
        app,
        "POST",
        f"/api/red/assessments/{scope.assessment_id}/stages/execution/run",
        {"request_id": "run-stale-api", "operation_id": "operation-t22"},
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "stale_plan"
    assert supervisor.queue.list_jobs(scope) == before


def test_manual_prerequisite_error_is_reported_as_blocked_operation(manual_site):
    app, supervisor, _, tasks = manual_site
    scope = tasks[0].scope
    _request(
        app,
        "POST",
        f"/api/red/assessments/{scope.assessment_id}/authorize",
        {"request_id": "authorize-blocked-api", "approval_id": "approval-t22-manual"},
    )

    response = _request(
        app,
        "POST",
        f"/api/red/assessments/{scope.assessment_id}/stages/planning/run",
        {"request_id": "run-planning-too-soon"},
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "blocked_operation"
    assert supervisor.queue.list_jobs(scope) == ()


@pytest.mark.parametrize(
    "headers, expected",
    [
        ({"Origin": ORIGIN}, 401),
        ({"Authorization": f"Bearer {TOKEN}", "Origin": ORIGIN}, 403),
        ({"Authorization": f"Bearer {TOKEN}", "Origin": "https://evil.test", "X-Red-CSRF": "x"}, 403),
    ],
)
def test_every_write_requires_operator_auth_origin_and_csrf(empty_site, headers, expected):
    app, state_db = empty_site
    response = _request(
        app,
        "POST",
        "/api/red/assessments",
        {
            "request_id": "denied-create",
            "target_id": "vulnerable-store",
            "mode": "manual",
            "approval_id": "denied-approval",
        },
        headers=headers,
    )

    assert response.status_code == expected
    assert not state_db.exists()


def test_forged_fields_unknown_ids_and_reused_keys_fail_closed(empty_site):
    app, state_db = empty_site
    body = {
        "request_id": "create-manual-1",
        "target_id": "vulnerable-store",
        "mode": "manual",
        "approval_id": "approval-manual-1",
    }
    created = _request(app, "POST", "/api/red/assessments", body)
    reused = _request(
        app,
        "POST",
        "/api/red/assessments",
        {**body, "mode": "autonomous"},
    )
    forged = _request(
        app,
        "POST",
        "/api/red/assessments",
        {**body, "request_id": "forged-command", "url": "http://evil.test"},
    )
    missing = _request(
        app,
        "POST",
        "/api/red/assessments/not-real/cancel",
        {"request_id": "cancel-not-real"},
    )

    assert created.status_code == 201
    assert reused.status_code == 409
    assert reused.json()["error"]["code"] == "idempotency_conflict"
    assert forged.status_code == 422
    assert missing.status_code == 404
    assert state_db.exists()
