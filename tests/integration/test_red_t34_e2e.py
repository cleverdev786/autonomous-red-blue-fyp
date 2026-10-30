"""Opt-in T34 acceptance against the authorized isolated Docker lab."""

from __future__ import annotations

import json
import os
import subprocess
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

import pytest

from agents.red.attack_planner import DeterministicAttackPlanner
from agents.red.attack_verifier import DeterministicAttackVerifier
from orchestrator.policy_engine import StandardRedPolicy
from orchestrator.red_team_flow import RedQueuedStageRunner, RedStageCoordinator
from schemas.red_queue import QueueResourceDTO
from schemas.red_team import (
    ExecutionWork,
    ExecutionWorkResult,
    PlanningWork,
    PlanningWorkResult,
    ReconnaissanceWork,
    ReconnaissanceWorkResult,
    RedEndpointCandidate,
    VerificationWork,
    VerificationWorkResult,
)
from schemas.red_team import (
    TestExecutionResult as ExecutionResult,
)
from schemas.red_team_state import AssessmentDTO, CoverageDTO, FindingState
from security_tests.registry import SecurityTestRegistry
from services.reconnaissance_service import ReconnaissanceService
from services.red_assessment_queue import RedAssessmentQueue
from services.red_assessment_store import RedAssessmentStore
from services.red_assessment_supervisor import RedAssessmentSupervisor
from services.red_evidence_receipts import RedEvidenceRecorder
from services.red_evidence_store import RedEvidenceStore
from services.target_registry import TargetRegistry
from services.zap_adapter import ZapTargetedObservation

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 10, 29, 12, tzinfo=UTC)
TEST_IDS = (
    "path-traversal-private-file-001",
    "sqli-login-bypass-001",
    "xss-reflection-001",
)

pytestmark = pytest.mark.skipif(
    os.getenv("MARS_RUN_T34_E2E") != "1",
    reason="requires the explicitly enabled isolated Docker lab",
)


def _registry() -> TargetRegistry:
    return TargetRegistry.from_directories(
        targets_dir=ROOT / "config/targets",
        security_tests_dir=ROOT / "config/security_tests",
    )


def _run_live_registered(test_id: str) -> ExecutionResult:
    completed = subprocess.run(
        (
            "docker",
            "compose",
            "-f",
            "compose.isolated.yaml",
            "exec",
            "-T",
            "controlled-executor",
            "python",
            "-m",
            "infrastructure.executor.run_registered_test",
            "--test-id",
            test_id,
            "--attempt-number",
            "1",
        ),
        cwd=ROOT,
        check=True,
        capture_output=True,
        timeout=30,
    )
    result = ExecutionResult.model_validate_json(completed.stdout)
    assert result.completed and not result.timed_out
    assert result.test_id == test_id
    assert SecurityTestRegistry.default().get(test_id).evaluate(result.exchanges)
    return result


class AcceptanceWorkflow:
    def __init__(
        self,
        root: Path,
        *,
        mode: str,
        live_results: dict[str, ExecutionResult],
        suspected_xss: bool = False,
    ) -> None:
        root.mkdir(parents=True)
        self.mode = mode
        self.now = NOW
        self.registry = _registry()
        self.authorization = StandardRedPolicy(
            registry=self.registry,
            budget_file=ROOT / "config/red_standard.json",
        ).freeze(
            assessment_id=f"t34-{mode}",
            approval_id=f"approval-t34-{mode}",
            target_id="vulnerable-store",
        )
        self.store = RedAssessmentStore(root / f"{mode}.sqlite3")
        self.store.create(
            AssessmentDTO(
                scope=self.authorization.scope,
                mode=mode,
                status="awaiting_authorization",
                workflow_complete=False,
                coverage=CoverageDTO(),
            ),
            self.authorization,
            request_id=f"create-t34-{mode}",
        )
        self.journal = RedEvidenceStore(self.store, root / f"{mode}-evidence")
        self.recorder = RedEvidenceRecorder(self.journal)
        self.verifier = DeterministicAttackVerifier(
            self.registry,
            journal=self.journal,
        )
        self.live_results = live_results
        self.suspected_xss = suspected_xss
        self.candidates = self._candidates()
        queue = RedAssessmentQueue(self.store)
        coordinator = RedStageCoordinator(
            journal=self.journal,
            workers={
                "reconnaissance": self._reconnaissance,
                "planning": self._planning,
                "execution": self._execution,
                "verification": self._verification,
            },
            clock=self._clock,
        )
        self.supervisor = RedAssessmentSupervisor(
            queue=queue,
            registry=self.registry,
            runner=RedQueuedStageRunner(
                queue=queue,
                coordinator=coordinator,
                clock=self._clock,
            ),
        )
        self.supervisor.authorize(
            self.authorization.scope,
            approval_id=self.authorization.approval_id,
            command_id=f"authorize-t34-{mode}",
            authorized_at=self._clock(),
        )

    def _clock(self) -> datetime:
        self.now += timedelta(seconds=1)
        return self.now

    def _candidates(self) -> tuple[RedEndpointCandidate, ...]:
        target = self.registry.get_target("vulnerable-store")
        registered = []
        for test_id in TEST_IDS:
            test = self.registry.get_security_test(test_id)
            endpoint = next(
                item for item in target.endpoints if item.endpoint_id == test.endpoint_id
            )
            registered.append(
                RedEndpointCandidate(
                    candidate_id=f"candidate-{test.endpoint_id}",
                    method=test.method,
                    path=endpoint.path,
                    parameter_names=endpoint.input_fields,
                    source="registered",
                    observed_at=NOW,
                )
            )
        return (
            *registered,
            RedEndpointCandidate(
                candidate_id="candidate-auth-only",
                method="GET",
                path="/admin/panel",
                source="zap",
                observed_at=NOW,
            ),
            RedEndpointCandidate(
                candidate_id="candidate-missing-template",
                method="GET",
                path="/reports/export",
                source="zap",
                observed_at=NOW,
            ),
        )

    def _reconnaissance(self, task: ReconnaissanceWork) -> ReconnaissanceWorkResult:
        existing, _ = self.store.load(task.scope.assessment_id)
        known = {item.candidate_id for item in existing.candidates}
        for candidate in self.candidates:
            if candidate.candidate_id not in known:
                self.store.add_candidate(task.scope.assessment_id, candidate)
        self.store.record_surface(
            task.scope,
            candidates=self.candidates,
            observed_at=NOW,
        )
        return ReconnaissanceWorkResult(scope=task.scope, candidates=self.candidates)

    def _planning(self, task: PlanningWork) -> PlanningWorkResult:
        catalog = ReconnaissanceService(
            registry=self.registry,
        ).build_attack_planning_catalog(target_id=task.scope.target_id)
        decision = DeterministicAttackPlanner().plan(
            work=task,
            catalog=catalog,
            authorization=self.authorization,
        )
        self.store.add_plan(decision.plan)
        for operation in decision.operations:
            self.store.add_operation(operation.model_copy(update={"status": "approved"}))
        self.journal.record_coverage_gaps(task.scope, decision.coverage_gaps)
        return PlanningWorkResult(
            scope=task.scope,
            plan_version=decision.plan.plan_version,
            operation_ids=tuple(item.operation_id for item in decision.operations),
            coverage_gap_ids=tuple(item.gap_id for item in decision.coverage_gaps),
        )

    def _execution(self, task: ExecutionWork) -> ExecutionWorkResult:
        snapshot, _ = self.store.load(task.scope.assessment_id)
        operation = next(
            item for item in snapshot.operations if item.operation_id == task.operation_id
        )
        if self.suspected_xss and operation.test_id == "xss-reflection-001":
            observation = ZapTargetedObservation(
                scope=task.scope,
                test_id="xss-reflection-001",
                scanner_id="40012",
                endpoint_id="scenario-xss-search",
                status="suspected",
                confirmed=False,
                request_count=1,
                duration_seconds=1,
                alert_count=1,
            )
            suspected = self.recorder.record_zap(
                observation=observation,
                operation_id=operation.operation_id,
                plan_version=operation.plan_version,
                target_revision=task.scope.target_fingerprint,
                recorded_at=self._clock(),
            )
            assert self.verifier.verify(suspected, None).status == FindingState.SUSPECTED
        receipt = self.recorder.record_controlled(
            scope=task.scope,
            operation_id=operation.operation_id,
            plan_version=operation.plan_version,
            target_revision=task.scope.target_fingerprint,
            result=self.live_results[operation.test_id],
            recorded_at=self._clock(),
        )
        return ExecutionWorkResult(
            scope=task.scope,
            plan_version=task.plan_version,
            operation_id=task.operation_id,
            receipt_ids=(receipt.receipt_id,),
        )

    def _verification(self, task: VerificationWork) -> VerificationWorkResult:
        receipts = {item.receipt_id: item for item in self.journal.list_receipts(task.scope)}
        receipt = next(
            receipts[item]
            for item in task.receipt_ids
            if receipts[item].source == "controlled_http"
        )
        finding = self.verifier.verify(receipt, self.live_results[receipt.test_id])
        assert finding is not None
        return VerificationWorkResult(
            scope=task.scope,
            plan_version=task.plan_version,
            operation_id=task.operation_id,
            outcome=finding.status.value,
            evidence_receipt_ids=(receipt.receipt_id,),
        )

    def run_manual(self) -> None:
        scope = self.authorization.scope
        recon = ReconnaissanceWork(scope=scope)
        light = QueueResourceDTO(resource_class="light")
        for index in (1, 2):
            self.supervisor.enqueue_manual(
                recon,
                command_id=f"manual-recon-{index}",
                resource=light,
                enqueued_at=self._clock(),
            )
            assert (
                self.supervisor.run_next(
                    worker_id=f"manual-worker-recon-{index}",
                    claimed_at=self._clock(),
                ).stage
                == "reconnaissance"
            )
        snapshot, _ = self.store.load(scope.assessment_id)
        surface = snapshot.surfaces[-1]
        planning = PlanningWork(
            scope=scope,
            surface_revision=surface.surface_revision,
            candidates=tuple(snapshot.candidates),
            vetted_test_ids=self.registry.get_target(scope.target_id).allowed_test_ids,
        )
        self.supervisor.enqueue_manual(
            planning,
            command_id="manual-plan",
            resource=light,
            enqueued_at=self._clock(),
        )
        self.supervisor.run_next(worker_id="manual-worker-plan", claimed_at=self._clock())
        snapshot, _ = self.store.load(scope.assessment_id)
        for index, operation in enumerate(snapshot.operations, 1):
            execution = ExecutionWork(
                scope=scope,
                plan_version=operation.plan_version,
                operation_id=operation.operation_id,
            )
            test = self.registry.get_security_test(operation.test_id)
            self.supervisor.enqueue_manual(
                execution,
                command_id=f"manual-execute-{index}",
                resource=QueueResourceDTO(
                    resource_class="docker",
                    requests=test.max_requests,
                    runtime_seconds=test.timeout_seconds,
                    cpu_cores=0.5,
                    memory_mb=512,
                ),
                enqueued_at=self._clock(),
            )
            self.supervisor.run_next(
                worker_id=f"manual-worker-execute-{index}",
                claimed_at=self._clock(),
            )
            receipt_ids = tuple(
                item.receipt_id
                for item in self.journal.list_receipts(scope)
                if item.operation_id == operation.operation_id
            )
            verification = VerificationWork(
                scope=scope,
                plan_version=operation.plan_version,
                operation_id=operation.operation_id,
                receipt_ids=receipt_ids,
                oracle_id=test.success_evidence_rule_id,
            )
            self.supervisor.enqueue_manual(
                verification,
                command_id=f"manual-verify-{index}",
                resource=light,
                enqueued_at=self._clock(),
            )
            self.supervisor.run_next(
                worker_id=f"manual-worker-verify-{index}",
                claimed_at=self._clock(),
            )

    def run_autonomous(self) -> None:
        self.supervisor.enqueue_autonomous_start(
            ReconnaissanceWork(scope=self.authorization.scope),
            command_id="autonomous-start",
            resource=QueueResourceDTO(resource_class="light"),
            enqueued_at=self._clock(),
        )
        for index in range(12):
            result = self.supervisor.run_next(
                worker_id=f"autonomous-worker-{index}",
                claimed_at=self._clock(),
            )
            if result is None:
                break
        else:
            raise AssertionError("autonomous queue did not drain")

    def export(self) -> dict[str, object]:
        scope = self.authorization.scope
        snapshot, _ = self.store.load(scope.assessment_id)
        jobs = self.supervisor.queue.list_jobs(scope)
        receipts = self.journal.list_receipts(scope)
        findings = self.journal.list_findings(scope)
        coverage_gaps = self.journal.list_coverage_gaps(scope)
        return {
            "assessment_id": scope.assessment_id,
            "mode": self.mode,
            "status": snapshot.assessment.status.value,
            "target_fingerprint": scope.target_fingerprint,
            "plan_digests": [item.plan_digest for item in snapshot.plans],
            "planned_test_ids": [item.test_id for item in snapshot.operations],
            "coverage": snapshot.assessment.coverage.model_dump(mode="json"),
            "agent_task_count": len(jobs),
            "agent_tasks_by_stage": {
                stage: sum(item.work.stage == stage for item in jobs)
                for stage in ("reconnaissance", "planning", "execution", "verification")
            },
            "queue": [
                {"stage": item.work.stage, "status": item.status}
                for item in jobs
            ],
            "timeline": [
                {"stage": item.stage, "status": item.status.value, "phase": item.phase}
                for item in self.journal.list_stage_events(scope)
            ],
            "receipts": [
                {
                    "receipt_id": item.receipt_id,
                    "test_id": item.test_id,
                    "source": item.source,
                    "target_revision": item.target_revision,
                    "raw_response_sha256": item.raw_response_sha256,
                }
                for item in receipts
            ],
            "findings": [
                {"status": item.status.value, "category": item.category} for item in findings
            ],
            "coverage_gaps": [
                {"reason": item.reason, "candidate_id": item.candidate_id}
                for item in coverage_gaps
            ],
        }


def test_t34_real_docker_manual_autonomous_and_stop_acceptance(tmp_path: Path) -> None:
    live_results = {test_id: _run_live_registered(test_id) for test_id in TEST_IDS}
    manual = AcceptanceWorkflow(
        tmp_path / "manual",
        mode="manual",
        live_results=live_results,
        suspected_xss=True,
    )
    manual.run_manual()
    autonomous = AcceptanceWorkflow(
        tmp_path / "autonomous",
        mode="autonomous",
        live_results=live_results,
    )
    autonomous.run_autonomous()

    stopped = AcceptanceWorkflow(
        tmp_path / "stopped",
        mode="autonomous",
        live_results=live_results,
    )
    stopped.supervisor.enqueue_autonomous_start(
        ReconnaissanceWork(scope=stopped.authorization.scope),
        command_id="autonomous-stop-start",
        resource=QueueResourceDTO(resource_class="light"),
        enqueued_at=stopped._clock(),
    )
    stopped.supervisor.cancel(
        stopped.authorization.scope,
        cancellation_id="autonomous-stop",
        requested_at=stopped._clock(),
    )

    exported = {
        "schema_version": "mars-red-t34-acceptance-v1",
        "docker_evidence": {
            test_id: {
                "run_id": result.run_id,
                "request_count": result.request_count,
                "duration_ms": result.duration_ms,
                "result_sha256": sha256(result.model_dump_json().encode("utf-8")).hexdigest(),
            }
            for test_id, result in live_results.items()
        },
        "docker_tool_invocations": len(live_results),
        "docker_duration_ms": sum(item.duration_ms for item in live_results.values()),
        "workflows": [manual.export(), autonomous.export(), stopped.export()],
    }
    export_path = Path(
        os.environ.get(
            "MARS_T34_EXPORT",
            tmp_path / "mars-red-t34-acceptance.json",
        )
    )
    export_path.write_text(json.dumps(exported, indent=2, sort_keys=True) + "\n")

    loaded = json.loads(export_path.read_text())
    assert set(loaded["docker_evidence"]) == set(TEST_IDS)
    assert all(len(item["result_sha256"]) == 64 for item in loaded["docker_evidence"].values())
    manual_export, autonomous_export, stopped_export = loaded["workflows"]
    assert manual_export["status"] == autonomous_export["status"] == ("completed_with_limitations")
    assert stopped_export["status"] == "cancelled"
    assert len(manual_export["plan_digests"]) == 1
    assert all(len(item) == 64 for item in manual_export["plan_digests"])
    assert manual_export["planned_test_ids"] == autonomous_export["planned_test_ids"]
    assert {item["reason"] for item in manual_export["coverage_gaps"]} == {
        "authentication_required",
        "no_template",
    }
    assert {item["status"] for item in manual_export["findings"]} >= {
        "confirmed",
        "suspected",
    }
    for workflow in (manual_export, autonomous_export):
        controlled = [item for item in workflow["receipts"] if item["source"] == "controlled_http"]
        assert {item["test_id"] for item in controlled} == set(TEST_IDS)
        assert all(
            item["target_revision"] == workflow["target_fingerprint"]
            and len(item["raw_response_sha256"]) == 64
            for item in controlled
        )
        assert all(item["status"] == "completed" for item in workflow["queue"])
        assert {item["stage"] for item in workflow["timeline"]} == {
            "reconnaissance",
            "planning",
            "execution",
            "verification",
        }
    assert "body_excerpt" not in export_path.read_text()
