"""Opt-in T19/T20 replay against the existing isolated Docker lab."""

from __future__ import annotations

import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from agents.red.attack_verifier import DeterministicAttackVerifier
from schemas.red_team import TestExecutionResult as ExecutionResult
from schemas.red_team_state import FindingState
from services.red_evidence_receipts import RedEvidenceRecorder
from services.target_registry import TargetRegistry
from tests.test_red_real_execution import build_execution_env

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(
    os.getenv("MARS_RUN_LIVE_RED_RECEIPT") != "1",
    reason="requires the explicitly enabled isolated Docker lab",
)
def test_real_lab_result_roundtrips_through_receipt_and_independent_oracle(tmp_path):
    command = (
        "docker", "compose", "exec", "-T", "controlled-executor", "python", "-m",
        "infrastructure.executor.run_registered_test", "--test-id",
        "xss-reflection-001", "--attempt-number", "1",
    )
    completed = subprocess.run(
        command, cwd=ROOT, check=True, capture_output=True, timeout=30,
    )
    result = ExecutionResult.model_validate_json(completed.stdout)
    dispatcher, request, _ = build_execution_env(tmp_path)
    receipt = RedEvidenceRecorder(dispatcher.admission.journal).record_controlled(
        scope=request.scope, operation_id=request.operation_id,
        plan_version=request.plan_version,
        target_revision=request.scope.target_fingerprint, result=result,
        recorded_at=datetime.now(UTC),
    )
    registry = TargetRegistry.from_directories(
        targets_dir=ROOT / "config/targets",
        security_tests_dir=ROOT / "config/security_tests",
    )

    verifier = DeterministicAttackVerifier(
        registry, journal=dispatcher.admission.journal
    )
    finding = verifier.verify(receipt, result)

    assert finding.status == FindingState.CONFIRMED
    assert receipt.raw_response_sha256
    assert b"fyp_xss_marker" not in dispatcher.admission.journal.read_evidence(
        request.scope, receipt.evidence_id
    )
