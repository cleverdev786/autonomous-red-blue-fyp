"""Red Team advisory interpretation of deterministic execution evidence."""

from __future__ import annotations

from collections.abc import Mapping
from hashlib import sha256
from typing import Any

from agents.base import TypedReasoningAgent
from schemas.common import AgentRole
from schemas.red_team import AttackPlan, AttackVerification, TestExecutionResult
from schemas.red_team_state import FindingDTO, FindingState, ReceiptDTO
from security_tests.registry import SecurityTestImplementationError, SecurityTestRegistry
from services.red_evidence_receipts import RedEvidenceRecorder
from services.red_evidence_store import RedEvidenceStore
from services.target_registry import TargetRegistry, TargetRegistryError


class AttackVerificationAgent(TypedReasoningAgent[AttackVerification]):
    """Interpret bounded executor evidence without creating new evidence."""

    role = AgentRole.RED_ATTACK_VERIFIER
    output_model = AttackVerification

    @staticmethod
    def prepare_input(
        *,
        plan: AttackPlan,
        execution: TestExecutionResult,
    ) -> Mapping[str, Any]:
        return {
            "attack_plan": plan.model_dump(mode="json"),
            "execution_result": execution.model_dump(mode="json"),
        }


_SEVERITY = {
    "sql_injection": "high",
    "xss": "medium",
    "path_traversal": "high",
}

class DeterministicAttackVerifier:
    """Re-evaluate integrity-bound raw results with trusted registered oracles."""

    def __init__(
        self,
        target_registry: TargetRegistry,
        test_registry: SecurityTestRegistry | None = None,
        *,
        supported_oracles: frozenset[str] | None = None,
        journal: RedEvidenceStore | None = None,
    ) -> None:
        self.targets = target_registry
        self.tests = test_registry or SecurityTestRegistry.default()
        self.tests.validate_against_target_registry(target_registry)
        self.supported_oracles = supported_oracles
        self.journal = journal

    def verify(
        self,
        receipt: ReceiptDTO | None,
        result: TestExecutionResult | None,
    ) -> FindingDTO | None:
        if receipt is None:
            return None
        try:
            metadata = self.targets.get_security_test(receipt.test_id)
            endpoint = self.targets.get_endpoint(metadata.target_id, metadata.endpoint_id)
            oracle = metadata.success_evidence_rule_id
            category = metadata.vulnerability_class.value
            route = endpoint.path
        except TargetRegistryError:
            return self._finding(receipt, FindingState.INCONCLUSIVE)

        common = {
            "oracle_id": oracle,
            "severity": _SEVERITY[category],
            "category": category,
            "route": route,
            "evidence_id": receipt.evidence_id,
        }
        if not self._trusted_receipt(receipt):
            return self._finding(receipt, FindingState.INCONCLUSIVE, **common)
        if receipt.source == "zap":
            status = (
                FindingState.SUSPECTED
                if receipt.observation_status == "suspected"
                else FindingState.INCONCLUSIVE
            )
            return self._persist_verified(receipt, self._finding(
                receipt, status,
                provenance="zap", reproduction_scope="targeted_scanner", **common,
            ))
        if receipt.status != "completed" or result is None:
            return self._persist_verified(receipt, self._finding(
                receipt, FindingState.INCONCLUSIVE,
                provenance="controlled_http", reproduction_scope="registered_local_lab", **common,
            ))
        RedEvidenceRecorder.verify_result_integrity(receipt, result)
        if (
            not self._valid_structure(receipt, result)
            or self.supported_oracles is not None
            and oracle not in self.supported_oracles
        ):
            state = FindingState.INCONCLUSIVE
        else:
            try:
                observed = self.tests.get(receipt.test_id).evaluate(result.exchanges)
            except SecurityTestImplementationError:
                state = FindingState.INCONCLUSIVE
            else:
                state = FindingState.CONFIRMED if observed else FindingState.NOT_CONFIRMED
        return self._persist_verified(receipt, self._finding(
            receipt, state, provenance="controlled_http",
            reproduction_scope="registered_local_lab", **common,
        ))

    def _trusted_receipt(self, receipt: ReceiptDTO) -> bool:
        if self.journal is None:
            return False
        try:
            if receipt not in self.journal.list_receipts(receipt.scope):
                return False
            artifacts = {
                item.evidence_id: item
                for item in self.journal.list_evidence(receipt.scope)
            }
            artifact = artifacts.get(receipt.evidence_id)
            if artifact is None or artifact.receipt_id != receipt.receipt_id:
                return False
            self.journal.read_evidence(receipt.scope, receipt.evidence_id)
            snapshot, _ = self.journal.store.load(receipt.scope.assessment_id)
        except (ValueError, OSError):
            return False
        operation = next(
            (item for item in snapshot.operations if item.operation_id == receipt.operation_id),
            None,
        )
        return (
            operation is not None
            and operation.test_id == receipt.test_id
            and operation.plan_version == receipt.plan_version
            and operation.status in {"approved", "running", "completed"}
        )

    def _valid_structure(
        self,
        receipt: ReceiptDTO,
        result: TestExecutionResult | None = None,
    ) -> bool:
        try:
            steps = self.tests.get(receipt.test_id).build_steps()
            metadata = self.targets.get_security_test(receipt.test_id)
        except (SecurityTestImplementationError, TargetRegistryError):
            return False
        if (
            receipt.source != "controlled_http"
            or receipt.request_count != len(receipt.exchanges)
            or receipt.request_count != len(steps)
            or receipt.request_count > metadata.max_requests
        ):
            return False
        for observed, expected in zip(receipt.exchanges, steps, strict=True):
            if (
                observed.step_id != expected.step_id
                or observed.endpoint_id != expected.endpoint_id
                or observed.method != expected.method.value
            ):
                return False
        if result is None:
            return True
        if (
            not result.completed
            or result.timed_out
            or result.run_id != receipt.run_id
            or result.request_count != receipt.request_count
            or len(result.exchanges) != len(receipt.exchanges)
        ):
            return False
        for raw, normalized in zip(result.exchanges, receipt.exchanges, strict=True):
            if (
                raw.step_id != normalized.step_id
                or raw.endpoint_id != normalized.endpoint_id
                or raw.method != normalized.method
                or raw.status_code != normalized.status_code
                or sha256(raw.body_excerpt.encode()).hexdigest()
                != normalized.body_sha256
                or len(raw.body_excerpt) != normalized.body_length
            ):
                return False
        return True

    def _persist_verified(self, receipt: ReceiptDTO, finding: FindingDTO) -> FindingDTO:
        if self.journal is None:
            raise ValueError("verified findings require a durable evidence journal")
        self.journal._record_verified_finding(finding)
        return finding

    @staticmethod
    def _finding(receipt: ReceiptDTO, status: FindingState, **details) -> FindingDTO:
        material = f"{receipt.receipt_id}:{status.value}".encode()
        return FindingDTO(
            scope=receipt.scope,
            finding_id=f"finding-{sha256(material).hexdigest()[:24]}",
            operation_id=receipt.operation_id,
            status=status,
            evidence_receipt_ids=(receipt.receipt_id,),
            **details,
        )
