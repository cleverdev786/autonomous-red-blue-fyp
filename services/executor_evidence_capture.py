"""R4-C1 bounded byte-preserving deterministic executor collector, OFFLINE.

All process execution is injected; there is deliberately no default subprocess
runner. Production use, runtime attestation, and Docker use require a new gate.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Callable, Literal

from pydantic import BaseModel, ConfigDict, Field

from schemas.registered_red_observation import REGISTERED, observe_registered_result
from security_tests.registry import SecurityTestRegistry
from services.target_registry import TargetRegistry
from services.trusted_remediation_compiler import EXPECTED_SOURCE_SHA256, SOURCE

APPROVED_COMMIT = "6b7224f077af0c300d79e6e6a3a98a215fe3ff73"
HASH64 = re.compile(r"^[0-9a-f]{64}$")
ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,70}$")
MAX_STREAM_BYTES = 64 * 1024
TIMEOUT_SECONDS = 180

TEST_POLICY = {
    "sqli-login-001": ("security_tests/sql_injection/login_bypass.py", "sqli-login-bypass-001"),
    "xss-search-001": ("security_tests/xss/reflection.py", "xss-reflection-001"),
    "path-traversal-read-001": ("security_tests/path_traversal/private_file.py", "path-traversal-private-file-001"),
}


PINNED_REGISTERED_HASHES = {
    "sqli-login-001": (
        "5dee7a53513c3b213fd7cb6421e1037df491c413218b09bb7c75cdb61fbcd01c",
        "8c462c2439dd72b230d15dfb7778e74c9df87a49b1e026a25a98a7340a66ca35",
    ),
    "xss-search-001": (
        "67cf760c1abc9e3abbf64fe796fa8ae4ab8d08da126d40d9e11247f0649437b2",
        "1aac6df246737f63ec0d4f290f600e71c5b8e3cf64a4714ca49b48b1b453620d",
    ),
    "path-traversal-read-001": (
        "cdd2ea481d189d58f97fd40e0bcc6cfcbd80c94cee6e7cb0d5828a733e18e13c",
        "cff361f0db0c4a0221e31e6b12c39c798630bc5d2a68455a7005d6418b24c3ef",
    ),
}


class R4C1CaptureBlocked(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class BinaryProcessResult:
    returncode: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool = False


class R4C1CaptureReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["r4c1-mocked-binary-executor-v1"] = "r4c1-mocked-binary-executor-v1"
    evidence_origin: Literal["injected_mock_process_runner"] = "injected_mock_process_runner"
    scope: Literal["offline_only"] = "offline_only"
    model_calls: Literal[0] = 0
    red_agent_plan_authored: Literal[False] = False
    final_research_result: Literal[False] = False
    run_id: str
    case_id: str
    scenario_id: str
    test_id: str
    phase: Literal["vulnerable_baseline", "patched_replay"]
    approved_commit: Literal[APPROVED_COMMIT] = APPROVED_COMMIT
    observed_source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    prepared_diff_sha256: str | None
    daemon_fingerprint_claim_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    container_id_claim: str
    argv: tuple[str, ...]
    raw_stdout_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    raw_stderr_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    returncode: int | None
    timed_out: bool
    outcome: Literal[
        "baseline_exploit_confirmed", "baseline_exploit_not_observed",
        "patched_exploit_not_observed", "patched_exploit_still_present",
        "inconclusive", "executor_failed", "provenance_failed",
    ]
    parsed_observation_sha256: str | None = None
    reason: str


class R4C1CaptureCollector:
    """One attempt per case directory. Uses injected, non-shell process runner."""

    def __init__(
        self,
        *,
        source_root: Path,
        evidence_root: Path,
        runner: Callable[[tuple[str, ...], Path], BinaryProcessResult],
        registry: TargetRegistry,
        implementations: SecurityTestRegistry,
    ):
        self.source_root = source_root.resolve(strict=True)
        self.evidence_root = evidence_root.resolve(strict=True)
        if self.source_root in self.evidence_root.parents or self.evidence_root == self.source_root:
            raise R4C1CaptureBlocked("evidence root must be external to source")
        if self.evidence_root.is_symlink():
            raise R4C1CaptureBlocked("evidence root must not be a symlink")
        self.runner = runner
        self.registry = registry
        self.implementations = implementations

    @staticmethod
    def _atomic_new(path: Path, data: bytes):
        with path.open("xb") as stream:
            stream.write(data)
            stream.flush()
            import os
            os.fsync(stream.fileno())

    def collect(
        self,
        *,
        case_id: str, run_id: str, scenario_id: str,
        phase: Literal["vulnerable_baseline", "patched_replay"],
        attempt_number: int,
        observed_source_sha256: str,
        daemon_fingerprint_claim_sha256: str,
        container_id_claim: str,
        prepared_diff_sha256: str | None = None,
    ) -> R4C1CaptureReceipt:
        if not ID.fullmatch(case_id) or not ID.fullmatch(run_id):
            raise R4C1CaptureBlocked("invalid opaque run/case identifier")
        if scenario_id not in REGISTERED or phase not in ("vulnerable_baseline", "patched_replay"):
            raise R4C1CaptureBlocked("unregistered test or phase")
        if attempt_number != 1:
            raise R4C1CaptureBlocked("exactly one registered attempt, no retries")
        if not HASH64.fullmatch(daemon_fingerprint_claim_sha256):
            raise R4C1CaptureBlocked("invalid claimed daemon fingerprint")
        if not ID.fullmatch(container_id_claim):
            raise R4C1CaptureBlocked("invalid claimed container identifier")
        if not HASH64.fullmatch(observed_source_sha256):
            raise R4C1CaptureBlocked("invalid observed source digest")
        if phase == "vulnerable_baseline" and (
            observed_source_sha256 != EXPECTED_SOURCE_SHA256 or prepared_diff_sha256 is not None
        ):
            raise R4C1CaptureBlocked("baseline source or patch claim invalid")
        if phase == "patched_replay" and (
            not isinstance(prepared_diff_sha256, str)
            or not HASH64.fullmatch(prepared_diff_sha256)
            or observed_source_sha256 == EXPECTED_SOURCE_SHA256
        ):
            raise R4C1CaptureBlocked("patched replay requires changed source and real diff digest")
        target = self.source_root / SOURCE
        if not target.is_file() or target.is_symlink() or sha256(target.read_bytes()).hexdigest() != observed_source_sha256:
            raise R4C1CaptureBlocked("phase source differs from declared source bytes")
        test_id = TEST_POLICY[scenario_id][1]
        argv = (
            "docker", "compose", "exec", "-T", "controlled-executor",
            "python", "-m", "infrastructure.executor.run_verification_test",
            "--test-id", test_id, "--attempt-number", "1", "--run-id", run_id,
        )
        location = self.evidence_root / case_id
        try:
            location.mkdir(mode=0o700, exist_ok=False)
        except FileExistsError as exc:
            raise R4C1CaptureBlocked("case already reserved: no redispatch") from exc
        intent = {
            "kind": "offline-injected-mock-intent",
            "run_id": run_id, "case_id": case_id, "scenario_id": scenario_id,
            "phase": phase, "test_id": test_id, "argv": argv,
            "cwd": str(self.source_root), "attempt_number": attempt_number,
            "source_sha256": observed_source_sha256,
            "daemon_fingerprint_claim_sha256": daemon_fingerprint_claim_sha256,
            "container_id_claim": container_id_claim,
            "approved_commit": APPROVED_COMMIT, "no_live_attestation": True,
        }
        self._atomic_new(location / "dispatch-intent.json",
                         (json.dumps(intent, sort_keys=True, indent=2) + "\n").encode())
        process: BinaryProcessResult
        try:
            process = self.runner(argv, self.source_root)
            if not isinstance(process, BinaryProcessResult):
                raise TypeError("injected runner returned unexpected result type")
        except Exception as exc:
            self._atomic_new(location / "process-failure.json",
                             (json.dumps({"status": "executor_failed", "type": type(exc).__name__}) + "\n").encode())
            raise R4C1CaptureBlocked("injected runner failed; no automatic retry") from exc
        if not isinstance(process.stdout, bytes) or not isinstance(process.stderr, bytes):
            self._atomic_new(location / "process-failure.json",
                             json.dumps({"status": "invalid-stream-type"}).encode())
            raise R4C1CaptureBlocked("runner streams must be exact bytes")
        if len(process.stdout) > MAX_STREAM_BYTES or len(process.stderr) > MAX_STREAM_BYTES:
            self._atomic_new(location / "process-failure.json",
                             json.dumps({"status": "stream-exceeded-limit"}).encode())
            raise R4C1CaptureBlocked("raw process stream exceeds evidence limit")
        self._atomic_new(location / "stdout.raw", process.stdout)
        self._atomic_new(location / "stderr.raw", process.stderr)
        observation_sha = None
        reason = "unknown"
        if process.timed_out:
            outcome = "inconclusive"
            reason = "subprocess timeout, regardless of any partial stdout"
        elif process.returncode != 0:
            outcome = "executor_failed"
            reason = "nonzero or missing subprocess exit status"
        else:
            policy_path = self.source_root / "config/security_tests" / (test_id + ".json")
            code_path = self.source_root / TEST_POLICY[scenario_id][0]
            if (policy_path.is_symlink() or code_path.is_symlink()
                    or not policy_path.is_file() or not code_path.is_file()):
                outcome = "provenance_failed"
                reason = "registered policy or test implementation unavailable"
            elif (
                sha256(policy_path.read_bytes()).hexdigest(),
                sha256(code_path.read_bytes()).hexdigest(),
            ) != PINNED_REGISTERED_HASHES[scenario_id]:
                outcome = "provenance_failed"
                reason = "registered test policy or implementation differs from pinned approved source"
            else:
                try:
                    observed = observe_registered_result(
                        raw_result=process.stdout,
                        scenario_id=scenario_id,
                        phase=phase,
                        source_sha256=EXPECTED_SOURCE_SHA256,
                        policy_config_sha256=sha256(policy_path.read_bytes()).hexdigest(),
                        test_implementation_sha256=sha256(code_path.read_bytes()).hexdigest(),
                        evidence_scope="offline_fixture",
                        registry=self.registry, implementations=self.implementations,
                    )
                    # Parser alone cannot bind arbitrary stdout to our dispatch.
                    if (observed.execution.run_id != run_id
                            or observed.execution.attempt_number != attempt_number
                            or observed.execution.test_id != test_id):
                        raise ValueError("registered executor response identity mismatch")
                    raw_observation=(observed.model_dump_json(indent=2) + "\n").encode()
                    self._atomic_new(location / "observation.json", raw_observation)
                    observation_sha=sha256(raw_observation).hexdigest()
                    if not observed.test_completed or observed.exploit_confirmed is None:
                        outcome = "inconclusive"
                        reason = "registered test incomplete"
                    elif phase == "vulnerable_baseline":
                        outcome = ("baseline_exploit_confirmed" if observed.exploit_confirmed
                                   else "baseline_exploit_not_observed")
                        reason = "recomputed registered test evidence"
                    else:
                        outcome = ("patched_exploit_still_present" if observed.exploit_confirmed
                                   else "patched_exploit_not_observed")
                        reason = "recomputed registered test evidence, not patch acceptance"
                except Exception:
                    outcome = "provenance_failed"
                    reason = "untrusted stdout or registered evidence validation failed"
        receipt = R4C1CaptureReceipt(
            run_id=run_id, case_id=case_id, scenario_id=scenario_id, test_id=test_id,
            phase=phase, observed_source_sha256=observed_source_sha256,
            prepared_diff_sha256=prepared_diff_sha256,
            daemon_fingerprint_claim_sha256=daemon_fingerprint_claim_sha256,
            container_id_claim=container_id_claim, argv=argv,
            raw_stdout_sha256=sha256(process.stdout).hexdigest(),
            raw_stderr_sha256=sha256(process.stderr).hexdigest(),
            returncode=process.returncode, timed_out=process.timed_out,
            outcome=outcome, parsed_observation_sha256=observation_sha, reason=reason,
        )
        self._atomic_new(location / "receipt.json",
                         (receipt.model_dump_json(indent=2) + "\n").encode())
        return receipt
