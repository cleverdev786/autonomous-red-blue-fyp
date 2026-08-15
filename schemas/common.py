"""Shared enums and validation primitives for cross-module schemas."""

from __future__ import annotations

from enum import Enum
from typing import Annotated

from pydantic import Field, StringConstraints


Identifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=100,
        pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$",
    ),
]

RelativeProjectPath = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=500,
    ),
]

NonEmptyText = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=4000,
    ),
]

Confidence = Annotated[float, Field(ge=0.0, le=1.0)]


class VulnerabilityClass(str, Enum):
    """Only vulnerability categories approved for the MVP."""

    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"


class ClassificationLabel(str, Enum):
    """Labels allowed in RQ2 classification experiments."""

    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class HttpMethod(str, Enum):
    """HTTP methods the target registry may explicitly allow."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class PolicyReasonCode(str, Enum):
    """Stable reason codes for policy decisions and audit records."""

    ALLOWED = "allowed"
    UNKNOWN_TARGET = "unknown_target"
    HOST_NOT_ALLOWED = "host_not_allowed"
    PORT_NOT_ALLOWED = "port_not_allowed"
    SCHEME_NOT_ALLOWED = "scheme_not_allowed"
    UNKNOWN_ENDPOINT = "unknown_endpoint"
    METHOD_NOT_ALLOWED = "method_not_allowed"
    UNKNOWN_TEST = "unknown_test"
    TEST_TARGET_MISMATCH = "test_target_mismatch"
    TEST_ENDPOINT_MISMATCH = "test_endpoint_mismatch"
    INVALID_STATE = "invalid_state"
    ATTEMPT_LIMIT_REACHED = "attempt_limit_reached"
    REQUEST_LIMIT_REACHED = "request_limit_reached"
    MODEL_CALL_LIMIT_REACHED = "model_call_limit_reached"
    TIME_LIMIT_REACHED = "time_limit_reached"
    SOURCE_PATH_NOT_ALLOWED = "source_path_not_allowed"
    PATCH_PATH_NOT_ALLOWED = "patch_path_not_allowed"
    PROTECTED_PATH = "protected_path"
    SYMLINK_ESCAPE = "symlink_escape"
    PATCH_TOO_LARGE = "patch_too_large"
    PROHIBITED_OPERATION = "prohibited_operation"


class WorkflowState(str, Enum):
    """Explicit workflow states used by the deterministic orchestrator."""

    CREATED = "created"
    ENVIRONMENT_PREPARING = "environment_preparing"
    READY = "ready"
    RECONNAISSANCE = "reconnaissance"
    ATTACK_PLANNING = "attack_planning"
    ATTACK_EXECUTING = "attack_executing"
    ATTACK_VERIFYING = "attack_verifying"
    BLUE_MONITORING = "blue_monitoring"
    TRIAGE = "triage"
    CODE_ANALYSIS = "code_analysis"
    PATCH_GENERATING = "patch_generating"
    PATCH_VALIDATING = "patch_validating"
    PATCH_BRANCH_CREATING = "patch_branch_creating"
    PATCH_APPLYING = "patch_applying"
    PATCH_VERIFYING = "patch_verifying"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    FAILED = "failed"
    POLICY_BLOCKED = "policy_blocked"
    COMPLETED = "completed"


class RunType(str, Enum):
    """Separates development runs from final research evaluation."""

    DEVELOPMENT = "development"
    FINAL_EVALUATION = "final_evaluation"


class ResearchQuestion(str, Enum):
    """Research-question identifiers stored with experiment runs."""

    RQ1 = "rq1"
    RQ2 = "rq2"
    RQ3 = "rq3"


class RunStatus(str, Enum):
    """High-level run lifecycle states used by experiment storage."""

    CREATED = "created"
    RUNNING = "running"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    FAILED = "failed"
    POLICY_BLOCKED = "policy_blocked"
    COMPLETED = "completed"


class PatchDecision(str, Enum):
    """Deterministic patch verification decision."""

    ACCEPTED = "accepted"
    REJECTED = "rejected"


class AgentRole(str, Enum):
    """Named logical agent/verification roles in the approved architecture."""

    RED_RECONNAISSANCE = "red_reconnaissance"
    RED_ATTACK_PLANNER = "red_attack_planner"
    RED_ATTACK_VERIFIER = "red_attack_verifier"
    BLUE_MONITORING = "blue_monitoring"
    BLUE_TRIAGE = "blue_triage"
    BLUE_CODE_ANALYSIS = "blue_code_analysis"
    BLUE_PATCH_GENERATION = "blue_patch_generation"
    BLUE_PATCH_VERIFICATION = "blue_patch_verification"
    BLUE_SINGLE_AGENT = "blue_single_agent"
