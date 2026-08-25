"""Fail-closed deterministic authorization for sensitive project actions."""

from __future__ import annotations

from pathlib import Path

from orchestrator.limits import RunLimitTracker
from schemas.common import (
    HttpMethod,
    PolicyReasonCode,
    WorkflowState,
)
from schemas.verification import PolicyDecision
from services.target_registry import (
    TargetRegistry,
    UnknownSecurityTestError,
    UnknownTargetError,
)


_TERMINAL_STATES = {
    WorkflowState.FAILED,
    WorkflowState.POLICY_BLOCKED,
    WorkflowState.COMPLETED,
}

_ALLOWED_TRANSITIONS: dict[WorkflowState, set[WorkflowState]] = {
    WorkflowState.CREATED: {WorkflowState.ENVIRONMENT_PREPARING},
    WorkflowState.ENVIRONMENT_PREPARING: {WorkflowState.READY},
    WorkflowState.READY: {WorkflowState.RECONNAISSANCE},
    WorkflowState.RECONNAISSANCE: {WorkflowState.ATTACK_PLANNING},
    WorkflowState.ATTACK_PLANNING: {WorkflowState.ATTACK_EXECUTING},
    WorkflowState.ATTACK_EXECUTING: {WorkflowState.ATTACK_VERIFYING},
    WorkflowState.ATTACK_VERIFYING: {
        WorkflowState.ATTACK_PLANNING,
        WorkflowState.BLUE_MONITORING,
        WorkflowState.REJECTED,
    },
    WorkflowState.BLUE_MONITORING: {WorkflowState.TRIAGE},
    WorkflowState.TRIAGE: {WorkflowState.CODE_ANALYSIS},
    WorkflowState.CODE_ANALYSIS: {WorkflowState.PATCH_GENERATING},
    WorkflowState.PATCH_GENERATING: {WorkflowState.PATCH_VALIDATING},
    WorkflowState.PATCH_VALIDATING: {
        WorkflowState.PATCH_BRANCH_CREATING,
        WorkflowState.REJECTED,
    },
    WorkflowState.PATCH_BRANCH_CREATING: {WorkflowState.PATCH_APPLYING},
    WorkflowState.PATCH_APPLYING: {WorkflowState.PATCH_VERIFYING},
    WorkflowState.PATCH_VERIFYING: {
        WorkflowState.ACCEPTED,
        WorkflowState.REJECTED,
    },
    WorkflowState.ACCEPTED: {WorkflowState.COMPLETED},
    WorkflowState.REJECTED: {
        WorkflowState.PATCH_GENERATING,
        WorkflowState.COMPLETED,
    },
}


class PolicyEngine:
    """Authorize only actions explicitly allowed by trusted project policy."""

    def __init__(
        self,
        *,
        registry: TargetRegistry,
        project_root: Path,
    ) -> None:
        self.registry = registry
        self.project_root = project_root.resolve(strict=False)

    @staticmethod
    def _allow(message: str) -> PolicyDecision:
        return PolicyDecision(
            allowed=True,
            reason_code=PolicyReasonCode.ALLOWED,
            message=message,
        )

    @staticmethod
    def _deny(
        reason_code: PolicyReasonCode,
        message: str,
    ) -> PolicyDecision:
        return PolicyDecision(
            allowed=False,
            reason_code=reason_code,
            message=message,
        )

    def validate_target(self, target_id: str) -> PolicyDecision:
        try:
            self.registry.get_target(target_id)
        except UnknownTargetError:
            return self._deny(
                PolicyReasonCode.UNKNOWN_TARGET,
                f"Target {target_id!r} is not registered.",
            )
        return self._allow(f"Target {target_id!r} is registered.")

    def validate_network_destination(
        self,
        *,
        target_id: str,
        scheme: str,
        hostname: str,
        port: int,
    ) -> PolicyDecision:
        try:
            target = self.registry.get_target(target_id)
        except UnknownTargetError:
            return self._deny(
                PolicyReasonCode.UNKNOWN_TARGET,
                f"Target {target_id!r} is not registered.",
            )

        if scheme != target.scheme:
            return self._deny(
                PolicyReasonCode.SCHEME_NOT_ALLOWED,
                f"Scheme {scheme!r} does not match the registered target.",
            )
        if hostname != target.hostname:
            return self._deny(
                PolicyReasonCode.HOST_NOT_ALLOWED,
                f"Hostname {hostname!r} is not the registered target hostname.",
            )
        if port != target.port:
            return self._deny(
                PolicyReasonCode.PORT_NOT_ALLOWED,
                f"Port {port!r} is not the registered target port.",
            )

        return self._allow(
            f"Destination {scheme}://{hostname}:{port} matches registered target "
            f"{target_id!r}."
        )

    def validate_endpoint(
        self,
        *,
        target_id: str,
        endpoint_id: str,
    ) -> PolicyDecision:
        try:
            target = self.registry.get_target(target_id)
        except UnknownTargetError:
            return self._deny(
                PolicyReasonCode.UNKNOWN_TARGET,
                f"Target {target_id!r} is not registered.",
            )

        endpoint = next(
            (
                item
                for item in target.endpoints
                if item.endpoint_id == endpoint_id
            ),
            None,
        )
        if endpoint is None:
            return self._deny(
                PolicyReasonCode.UNKNOWN_ENDPOINT,
                f"Endpoint {endpoint_id!r} is not registered for target "
                f"{target_id!r}.",
            )

        return self._allow(
            f"Endpoint {endpoint_id!r} is registered for target {target_id!r}."
        )

    def validate_http_method(
        self,
        *,
        target_id: str,
        endpoint_id: str,
        method: HttpMethod,
    ) -> PolicyDecision:
        endpoint_decision = self.validate_endpoint(
            target_id=target_id,
            endpoint_id=endpoint_id,
        )
        if not endpoint_decision.allowed:
            return endpoint_decision

        target = self.registry.get_target(target_id)
        endpoint = next(
            item
            for item in target.endpoints
            if item.endpoint_id == endpoint_id
        )

        if method not in endpoint.allowed_methods:
            return self._deny(
                PolicyReasonCode.METHOD_NOT_ALLOWED,
                f"Method {method.value!r} is not permitted for endpoint "
                f"{endpoint_id!r}.",
            )

        return self._allow(
            f"Method {method.value!r} is permitted for endpoint "
            f"{endpoint_id!r}."
        )

    def validate_security_test(
        self,
        *,
        target_id: str,
        test_id: str,
        endpoint_id: str | None = None,
    ) -> PolicyDecision:
        try:
            target = self.registry.get_target(target_id)
        except UnknownTargetError:
            return self._deny(
                PolicyReasonCode.UNKNOWN_TARGET,
                f"Target {target_id!r} is not registered.",
            )

        try:
            security_test = self.registry.get_security_test(test_id)
        except UnknownSecurityTestError:
            return self._deny(
                PolicyReasonCode.UNKNOWN_TEST,
                f"Security test {test_id!r} is not registered.",
            )

        if test_id not in target.allowed_test_ids:
            return self._deny(
                PolicyReasonCode.UNKNOWN_TEST,
                f"Security test {test_id!r} is not allowed for target "
                f"{target_id!r}.",
            )

        if security_test.target_id != target_id:
            return self._deny(
                PolicyReasonCode.TEST_TARGET_MISMATCH,
                f"Security test {test_id!r} belongs to a different target.",
            )

        if endpoint_id is not None and security_test.endpoint_id != endpoint_id:
            return self._deny(
                PolicyReasonCode.TEST_ENDPOINT_MISMATCH,
                f"Security test {test_id!r} is registered for endpoint "
                f"{security_test.endpoint_id!r}, not {endpoint_id!r}.",
            )

        return self._allow(
            f"Security test {test_id!r} is registered for target "
            f"{target_id!r}."
        )

    def validate_source_read(
        self,
        *,
        target_id: str,
        relative_path: str,
    ) -> PolicyDecision:
        try:
            target = self.registry.get_target(target_id)
        except UnknownTargetError:
            return self._deny(
                PolicyReasonCode.UNKNOWN_TARGET,
                f"Target {target_id!r} is not registered.",
            )

        candidate_decision = self._resolve_candidate(
            relative_path=relative_path,
            allowed_roots=(target.source_root,),
            path_reason=PolicyReasonCode.SOURCE_PATH_NOT_ALLOWED,
        )
        if not candidate_decision.allowed:
            return candidate_decision

        protected = self._protected_read_path(relative_path)
        if protected is not None:
            return self._deny(
                PolicyReasonCode.PROTECTED_PATH,
                protected,
            )

        return self._allow(
            f"Source path {relative_path!r} is inside the registered source root."
        )

    def validate_patch_path(
        self,
        *,
        target_id: str,
        relative_path: str,
    ) -> PolicyDecision:
        try:
            target = self.registry.get_target(target_id)
        except UnknownTargetError:
            return self._deny(
                PolicyReasonCode.UNKNOWN_TARGET,
                f"Target {target_id!r} is not registered.",
            )

        candidate_decision = self._resolve_candidate(
            relative_path=relative_path,
            allowed_roots=target.writable_patch_roots,
            path_reason=PolicyReasonCode.PATCH_PATH_NOT_ALLOWED,
        )
        if not candidate_decision.allowed:
            return candidate_decision

        if Path(relative_path).suffix.lower() != ".py":
            return self._deny(
                PolicyReasonCode.PATCH_PATH_NOT_ALLOWED,
                "Generated patches are restricted to Python source/test files in the MVP.",
            )

        protected = self._protected_patch_path(relative_path)
        if protected is not None:
            return self._deny(
                PolicyReasonCode.PROTECTED_PATH,
                protected,
            )

        return self._allow(
            f"Patch path {relative_path!r} is inside an approved writable root."
        )

    def validate_patch_size(
        self,
        *,
        target_id: str,
        files_changed: int,
        inserted_lines: int,
        deleted_lines: int,
        total_diff_bytes: int,
    ) -> PolicyDecision:
        try:
            target = self.registry.get_target(target_id)
        except UnknownTargetError:
            return self._deny(
                PolicyReasonCode.UNKNOWN_TARGET,
                f"Target {target_id!r} is not registered.",
            )

        limits = target.patch_limits
        exceeded: list[str] = []
        if files_changed > limits.max_files_changed:
            exceeded.append(
                f"files_changed={files_changed} > {limits.max_files_changed}"
            )
        if inserted_lines > limits.max_inserted_lines:
            exceeded.append(
                f"inserted_lines={inserted_lines} > {limits.max_inserted_lines}"
            )
        if deleted_lines > limits.max_deleted_lines:
            exceeded.append(
                f"deleted_lines={deleted_lines} > {limits.max_deleted_lines}"
            )
        if total_diff_bytes > limits.max_total_diff_bytes:
            exceeded.append(
                f"total_diff_bytes={total_diff_bytes} > {limits.max_total_diff_bytes}"
            )

        if exceeded:
            return self._deny(
                PolicyReasonCode.PATCH_TOO_LARGE,
                "Generated patch exceeds configured limits: " + "; ".join(exceeded),
            )

        return self._allow("Generated patch is within configured size limits.")

    def _resolve_candidate(
        self,
        *,
        relative_path: str,
        allowed_roots: tuple[str, ...],
        path_reason: PolicyReasonCode,
    ) -> PolicyDecision:
        supplied = Path(relative_path)
        if supplied.is_absolute():
            return self._deny(
                path_reason,
                "Absolute filesystem paths are not allowed.",
            )

        raw_parts = supplied.parts
        if ".." in raw_parts:
            return self._deny(
                path_reason,
                "Parent-directory traversal is not allowed in privileged paths.",
            )

        candidate = (self.project_root / supplied).resolve(strict=False)
        allowed_paths = tuple(
            (self.project_root / root).resolve(strict=False)
            for root in allowed_roots
        )

        inside_allowed_root = any(
            self._is_relative_to(candidate, root)
            for root in allowed_paths
        )
        if not inside_allowed_root:
            return self._deny(
                path_reason,
                f"Path {relative_path!r} is outside approved roots.",
            )

        # If an existing symlink caused resolution outside the textual root,
        # the resolved containment check above already fails closed.
        return self._allow(
            f"Path {relative_path!r} resolves inside an approved root."
        )

    @staticmethod
    def _is_relative_to(candidate: Path, root: Path) -> bool:
        try:
            candidate.relative_to(root)
        except ValueError:
            return False
        return True

    @staticmethod
    def _protected_read_path(relative_path: str) -> str | None:
        normalized = relative_path.replace("\\", "/")
        parts = tuple(part.lower() for part in Path(normalized).parts)
        name = Path(normalized).name.lower()

        if ".git" in parts:
            return "Git metadata is not readable by agents."
        if name == ".env" or name.startswith(".env."):
            return "Environment/secret files are not readable by agents."
        if name.endswith((".pem", ".key", ".p12", ".pfx")):
            return "Key/certificate files are not readable by agents."
        if any(part in {"secrets", "credentials"} for part in parts):
            return "Secret/credential directories are not readable by agents."

        return None

    @staticmethod
    def _protected_patch_path(relative_path: str) -> str | None:
        normalized = relative_path.replace("\\", "/")
        parts = tuple(part.lower() for part in Path(normalized).parts)
        name = Path(normalized).name.lower()

        if ".git" in parts:
            return "Generated patches cannot modify Git metadata."
        if name == ".env" or name.startswith(".env."):
            return "Generated patches cannot modify environment/secret files."
        if name in {"pyproject.toml", "compose.yaml", "dockerfile"}:
            return "Generated patches cannot modify dependency/infrastructure files."
        if "config" in parts:
            return "Generated patches cannot modify trusted registry configuration."
        if "orchestrator" in parts:
            return "Generated patches cannot modify orchestrator safety controls."

        # Mandatory baseline tests are outside configured writable roots. Keep a
        # second explicit guard for defense in depth.
        if "tests" in parts and "generated" not in parts:
            return "Generated patches cannot modify mandatory baseline tests."

        return None

    def validate_state_transition(
        self,
        *,
        current: WorkflowState,
        requested: WorkflowState,
    ) -> PolicyDecision:
        if current in _TERMINAL_STATES:
            return self._deny(
                PolicyReasonCode.INVALID_STATE,
                f"Terminal state {current.value!r} cannot transition.",
            )

        if requested in {WorkflowState.FAILED, WorkflowState.POLICY_BLOCKED}:
            return self._allow(
                f"Safety/error transition {current.value!r} -> "
                f"{requested.value!r} is permitted."
            )

        allowed = _ALLOWED_TRANSITIONS.get(current, set())
        if requested not in allowed:
            return self._deny(
                PolicyReasonCode.INVALID_STATE,
                f"Transition {current.value!r} -> {requested.value!r} "
                "is not permitted.",
            )

        return self._allow(
            f"Transition {current.value!r} -> {requested.value!r} is permitted."
        )

    def validate_runtime_budget(
        self,
        tracker: RunLimitTracker,
    ) -> PolicyDecision:
        if not tracker.runtime_available():
            return self._deny(
                PolicyReasonCode.TIME_LIMIT_REACHED,
                "Experiment runtime budget is exhausted.",
            )
        return self._allow("Experiment runtime budget remains available.")

    def validate_model_call_budget(
        self,
        tracker: RunLimitTracker,
        *,
        amount: int = 1,
    ) -> PolicyDecision:
        if not tracker.runtime_available():
            return self.validate_runtime_budget(tracker)
        if not tracker.can_consume_model_calls(amount):
            return self._deny(
                PolicyReasonCode.MODEL_CALL_LIMIT_REACHED,
                "Model-call budget would be exceeded.",
            )
        return self._allow("Model-call budget is available.")

    def validate_attack_attempt_budget(
        self,
        tracker: RunLimitTracker,
        *,
        amount: int = 1,
    ) -> PolicyDecision:
        if not tracker.runtime_available():
            return self.validate_runtime_budget(tracker)
        if not tracker.can_consume_attack_attempts(amount):
            return self._deny(
                PolicyReasonCode.ATTEMPT_LIMIT_REACHED,
                "Attack-attempt budget would be exceeded.",
            )
        return self._allow("Attack-attempt budget is available.")

    def validate_patch_attempt_budget(
        self,
        tracker: RunLimitTracker,
        *,
        amount: int = 1,
    ) -> PolicyDecision:
        if not tracker.runtime_available():
            return self.validate_runtime_budget(tracker)
        if not tracker.can_consume_patch_attempts(amount):
            return self._deny(
                PolicyReasonCode.ATTEMPT_LIMIT_REACHED,
                "Patch-attempt budget would be exceeded.",
            )
        return self._allow("Patch-attempt budget is available.")

    def validate_http_request_budget(
        self,
        tracker: RunLimitTracker,
        *,
        amount: int = 1,
    ) -> PolicyDecision:
        if not tracker.runtime_available():
            return self.validate_runtime_budget(tracker)
        if not tracker.can_consume_http_requests(amount):
            return self._deny(
                PolicyReasonCode.REQUEST_LIMIT_REACHED,
                "HTTP-request budget would be exceeded.",
            )
        return self._allow("HTTP-request budget is available.")
