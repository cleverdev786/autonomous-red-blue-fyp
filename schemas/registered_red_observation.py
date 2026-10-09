"""R4-A observational deterministic registered Red-test provenance.

Separate from RedTeamRunResult, which contains an LLM attack plan.
No test execution, network access, Docker, model, or filesystem writes.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from schemas.red_team import TestExecutionResult
from security_tests.registry import SecurityTestRegistry
from services.target_registry import TargetRegistry

SHA256 = r"^[0-9a-f]{64}$"
REGISTERED = {
    "sqli-login-001": ("sqli-login-bypass-001", "scenario-sqli-login", "sql_injection"),
    "xss-search-001": ("xss-reflection-001", "scenario-xss-search", "xss"),
    "path-traversal-read-001": ("path-traversal-private-file-001", "scenario-path-traversal-read", "path_traversal"),
}


class DeterministicRedObservation(BaseModel):
    """Claim-scope limited record, not agent-authored Red evidence or a patch acceptance."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["r4a-deterministic-red-v1"] = "r4a-deterministic-red-v1"
    evidence_origin: Literal["registered_deterministic_test"] = "registered_deterministic_test"
    evidence_scope: Literal["offline_fixture", "reported_controlled_executor"]
    agent_red_plan_authored: Literal[False] = False
    agent_model_calls: Literal[0] = 0
    research_final_result: Literal[False] = False
    target_id: Literal["vulnerable-store"] = "vulnerable-store"
    scenario_id: str
    registered_test_id: str
    registered_endpoint_id: str
    phase: Literal["vulnerable_baseline", "patched_replay"]
    baseline_source_sha256: str = Field(pattern=SHA256)
    policy_config_sha256: str = Field(pattern=SHA256)
    test_implementation_sha256: str = Field(pattern=SHA256)
    raw_result_sha256: str = Field(pattern=SHA256)
    execution: TestExecutionResult
    test_completed: bool
    exploit_confirmed: bool | None
    evaluation_status: Literal["assessed", "inconclusive"]
    docker_session_evidence_sha256: str | None = Field(default=None, pattern=SHA256)

    @model_validator(mode="after")
    def fence(self):
        if self.evidence_scope == "offline_fixture" and self.docker_session_evidence_sha256 is not None:
            raise ValueError("offline fixtures must not claim a real Docker session")
        if self.evidence_scope == "reported_controlled_executor" and self.docker_session_evidence_sha256 is None:
            raise ValueError("live reports require separately obtained Docker session evidence")
        if self.execution.target_id != self.target_id or self.execution.test_id != self.registered_test_id:
            raise ValueError("registered test result identity mismatch")
        if self.evaluation_status == "assessed":
            if not self.test_completed or self.exploit_confirmed is None:
                raise ValueError("assessed result must be complete and non-ambiguous")
        elif self.exploit_confirmed is not None:
            raise ValueError("inconclusive result must not claim exploit truth")
        return self


class DeterministicRedEvidenceError(ValueError):
    pass


def observe_registered_result(
    *,
    raw_result: bytes,
    scenario_id: str,
    phase: Literal["vulnerable_baseline", "patched_replay"],
    source_sha256: str,
    policy_config_sha256: str,
    test_implementation_sha256: str,
    evidence_scope: Literal["offline_fixture", "reported_controlled_executor"] = "offline_fixture",
    docker_session_evidence_sha256: str | None = None,
    registry: TargetRegistry,
    implementations: SecurityTestRegistry,
) -> DeterministicRedObservation:
    """Parse a supplied executor response, never produce/trigger one.

    Reporting controlled-executor source is an attribution of supplied evidence,
    NOT attestation that Docker really ran. R4 live still requires a separate
    authorized observer tying raw bytes to an owned session.
    """
    if scenario_id not in REGISTERED:
        raise DeterministicRedEvidenceError("scenario is not registered for R4")
    test_id, endpoint_id, expected_class = REGISTERED[scenario_id]
    metadata = registry.get_security_test(test_id)
    if (metadata.target_id != "vulnerable-store" or metadata.endpoint_id != endpoint_id
            or metadata.vulnerability_class.value != expected_class):
        raise DeterministicRedEvidenceError("trusted registered-test metadata mismatch")
    implementation = implementations.get(test_id)
    # Verify source and registered policy identities against actual trusted files.
    project_root = Path(__file__).resolve().parents[1]
    policy_path = project_root / "config/security_tests" / (test_id + ".json")
    source_path = {
        "sqli-login-bypass-001": "security_tests/sql_injection/login_bypass.py",
        "xss-reflection-001": "security_tests/xss/reflection.py",
        "path-traversal-private-file-001": "security_tests/path_traversal/private_file.py",
    }[test_id]
    code_path = project_root / source_path
    if policy_path.is_symlink() or code_path.is_symlink():
        raise DeterministicRedEvidenceError("registered test files must not be symlinks")
    if sha256(policy_path.read_bytes()).hexdigest()!=policy_config_sha256:
        raise DeterministicRedEvidenceError("registered policy hash mismatch")
    if sha256(code_path.read_bytes()).hexdigest()!=test_implementation_sha256:
        raise DeterministicRedEvidenceError("registered implementation hash mismatch")
    if source_sha256 != "f8675d5bed857138f49cdf717bd4c696aad7e4e42c5f14cd41b4623b140a6e5d":
        raise DeterministicRedEvidenceError("baseline source hash mismatch")
    steps = implementation.build_steps()
    result = TestExecutionResult.model_validate_json(raw_result)
    if result.test_id != test_id or result.target_id != "vulnerable-store":
        raise DeterministicRedEvidenceError("supplied execution target/test mismatch")
    if not (1 <= result.request_count <= metadata.max_requests) or result.attempt_number < 1:
        raise DeterministicRedEvidenceError("unexpected registered-test request budget")
    if result.completed:
        # ControlledExecutor returns "evidence-not-observed" on a complete,
        # exploit-absent verification replay. This is NOT an executor failure.
        # All other completed error codes are contradictory and fail closed.
        if result.timed_out or result.error_code not in (None, "evidence-not-observed"):
            raise DeterministicRedEvidenceError("completed test has contradictory error or timeout")
        if len(result.exchanges) != len(steps) or result.request_count != len(steps):
            raise DeterministicRedEvidenceError("completed test lacks all registered exchanges")
        if (result.status_code != result.exchanges[-1].status_code or
            len({x.step_id for x in result.exchanges}) != len(steps)):
            raise DeterministicRedEvidenceError("last status or step uniqueness mismatch")
        if any(
            actual.step_id != step.step_id
            or actual.endpoint_id != step.endpoint_id
            or actual.method.lower() != step.method.value.lower()
            for actual, step in zip(result.exchanges, steps)
        ):
            raise DeterministicRedEvidenceError("registered step/endpoint/method mismatch")
        recomputed = implementation.evaluate(result.exchanges)
        if tuple(result.evidence) != tuple(recomputed):
            raise DeterministicRedEvidenceError("evidence does not match deterministic evaluator")
        if recomputed and result.error_code is not None:
            raise DeterministicRedEvidenceError("exploit evidence contradicts no-evidence error")
        if not recomputed and result.error_code != "evidence-not-observed":
            raise DeterministicRedEvidenceError("absent exploit requires registered no-evidence error")
        complete = True
        confirmed = bool(recomputed)
        status = "assessed"
    else:
        if result.evidence:
            raise DeterministicRedEvidenceError("incomplete test must not contain exploit confirmation")
        complete = False
        confirmed = None
        status = "inconclusive"
    return DeterministicRedObservation(
        scenario_id=scenario_id,registered_test_id=test_id,
        registered_endpoint_id=endpoint_id,phase=phase,
        evidence_scope=evidence_scope,
        baseline_source_sha256=source_sha256,
        policy_config_sha256=policy_config_sha256,
        test_implementation_sha256=test_implementation_sha256,
        raw_result_sha256=sha256(raw_result).hexdigest(),
        execution=result,test_completed=complete,exploit_confirmed=confirmed,
        evaluation_status=status,
        docker_session_evidence_sha256=docker_session_evidence_sha256,
    )
