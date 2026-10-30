"""Single local worker for the registered Red assessment queue."""

from __future__ import annotations

import logging
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from threading import Event, Thread

from agents.red.attack_planner import DeterministicAttackPlanner
from agents.red.attack_verifier import DeterministicAttackVerifier
from orchestrator.red_team_flow import RedQueuedStageRunner, RedStageCoordinator
from schemas.red_team import (
    ExecutionWork,
    ExecutionWorkResult,
    PlanningWork,
    PlanningWorkResult,
    ReconnaissanceWork,
    ReconnaissanceWorkResult,
    RedEndpointCandidate,
    TestExecutionResult,
    VerificationWork,
    VerificationWorkResult,
)
from services.reconnaissance_service import ReconnaissanceService
from services.red_assessment_queue import RedAssessmentQueue
from services.red_assessment_store import RedAssessmentStore
from services.red_assessment_supervisor import RedAssessmentSupervisor
from services.red_evidence_receipts import RedEvidenceRecorder
from services.red_evidence_store import RedEvidenceStore
from services.target_registry import TargetRegistry

LOG = logging.getLogger(__name__)


class RedRuntime:
    """Drain one durable queue with the four deterministic registered workers."""

    def __init__(self, *, root: Path, state_db: Path, registry: TargetRegistry) -> None:
        self.root = root
        self.registry = registry
        self.store = RedAssessmentStore(state_db)
        self.journal = RedEvidenceStore(self.store, state_db.with_name(state_db.name + ".evidence"))
        self.recorder = RedEvidenceRecorder(self.journal)
        self.verifier = DeterministicAttackVerifier(registry, journal=self.journal)
        self.results: dict[str, TestExecutionResult] = {}
        queue = RedAssessmentQueue(self.store)
        coordinator = RedStageCoordinator(
            journal=self.journal,
            workers={
                "reconnaissance": self._reconnaissance,
                "planning": self._planning,
                "execution": self._execution,
                "verification": self._verification,
            },
        )
        self.supervisor = RedAssessmentSupervisor(
            queue=queue,
            registry=registry,
            runner=RedQueuedStageRunner(queue=queue, coordinator=coordinator),
        )
        self.stop_event = Event()
        self.thread = Thread(target=self._run, name="mars-red-worker", daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=5)

    def _run(self) -> None:
        while not self.stop_event.is_set():
            try:
                result = self.supervisor.run_next(
                    worker_id="mars-local-red-worker", claimed_at=datetime.now(UTC)
                )
            except Exception:
                LOG.exception("Registered Red queue job failed")
                continue
            if result is None:
                self.stop_event.wait(0.25)

    def _reconnaissance(self, task: ReconnaissanceWork) -> ReconnaissanceWorkResult:
        target = self.registry.get_target(task.scope.target_id)
        observed_at = datetime.now(UTC)
        candidates = []
        for test_id in target.allowed_test_ids:
            test = self.registry.get_security_test(test_id)
            endpoint = self.registry.get_endpoint(task.scope.target_id, test.endpoint_id)
            candidates.append(
                RedEndpointCandidate(
                    candidate_id=f"candidate-{endpoint.endpoint_id}",
                    method=test.method,
                    path=endpoint.path,
                    parameter_names=endpoint.input_fields,
                    source="registered",
                    observed_at=observed_at,
                )
            )
        snapshot, _ = self.store.load(task.scope.assessment_id)
        known = {item.candidate_id for item in snapshot.candidates}
        for candidate in candidates:
            if candidate.candidate_id not in known:
                self.store.add_candidate(task.scope.assessment_id, candidate)
        self.store.record_surface(task.scope, candidates=tuple(candidates), observed_at=observed_at)
        return ReconnaissanceWorkResult(scope=task.scope, candidates=tuple(candidates))

    def _planning(self, task: PlanningWork) -> PlanningWorkResult:
        _, authorization = self.store.load(task.scope.assessment_id)
        decision = DeterministicAttackPlanner().plan(
            work=task,
            catalog=ReconnaissanceService(registry=self.registry).build_attack_planning_catalog(
                target_id=task.scope.target_id
            ),
            authorization=authorization,
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
        completed = subprocess.run(
            (
                "docker",
                "compose",
                "-f",
                str(self.root / "compose.yaml"),
                "exec",
                "-T",
                "controlled-executor",
                "python",
                "-m",
                "infrastructure.executor.run_registered_test",
                "--test-id",
                operation.test_id,
                "--attempt-number",
                "1",
            ),
            cwd=self.root,
            check=True,
            capture_output=True,
            timeout=45,
        )
        result = TestExecutionResult.model_validate_json(completed.stdout)
        receipt = self.recorder.record_controlled(
            scope=task.scope,
            operation_id=operation.operation_id,
            plan_version=operation.plan_version,
            target_revision=task.scope.target_fingerprint,
            result=result,
            recorded_at=datetime.now(UTC),
        )
        self.results[receipt.receipt_id] = result
        return ExecutionWorkResult(
            scope=task.scope,
            plan_version=task.plan_version,
            operation_id=task.operation_id,
            receipt_ids=(receipt.receipt_id,),
        )

    def _verification(self, task: VerificationWork) -> VerificationWorkResult:
        receipts = {item.receipt_id: item for item in self.journal.list_receipts(task.scope)}
        receipt = next(receipts[item] for item in task.receipt_ids if item in receipts)
        finding = self.verifier.verify(receipt, self.results.get(receipt.receipt_id))
        if finding is None:
            raise RuntimeError("registered execution receipt could not be verified")
        return VerificationWorkResult(
            scope=task.scope,
            plan_version=task.plan_version,
            operation_id=task.operation_id,
            outcome=finding.status.value,
            evidence_receipt_ids=(receipt.receipt_id,),
        )
