"""Fail-closed deterministic authorization for sensitive project actions."""

from __future__ import annotations

from pathlib import Path
from hashlib import sha256
import json

from orchestrator.limits import RunLimitTracker
from schemas.common import (
    HttpMethod,
    VulnerabilityClass,
    PolicyReasonCode,
    WorkflowState,
)
from schemas.red_team import (
    RedPolicyOperation,
    RedPolicyUsage,
    RedScopeReference,
    RedStandardAuthorization,
    RedStandardBudget,
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

    def validate_no_patch_termination(
        self,
        *,
        analysis: "BlueTeamAnalysisResult",
        result: "RemediationAttemptResult",
    ) -> PolicyDecision:
        """Separate, tightly scoped non-patch gate; does not alter normal transitions."""
        from schemas.common import ClassificationLabel
        from schemas.remediation import RemediationDisposition, NoActionReason

        def invalid(message: str) -> PolicyDecision:
            return self._deny(PolicyReasonCode.INVALID_STATE, message)

        if result.run_id != analysis.run_id or result.target_id != analysis.target_id:
            return invalid("run/target identity mismatch")
        if not self.validate_target(analysis.target_id).allowed:
            return self._deny(PolicyReasonCode.UNKNOWN_TARGET, "unregistered target")
        if analysis.triage.run_id != analysis.run_id:
            return invalid("triage run identity mismatch")
        if analysis.code_finding is not None and analysis.code_finding.run_id != analysis.run_id:
            return invalid("code finding run identity mismatch")
        if result.disposition == RemediationDisposition.PREPARED:
            return invalid("prepared patches must use ordinary verification")
        benign = (
            analysis.triage.classification == ClassificationLabel.BENIGN
            and analysis.final_state == WorkflowState.TRIAGE
            and analysis.code_finding is None
        )
        actionable = (
            analysis.triage.classification in {
                ClassificationLabel.SQL_INJECTION,
                ClassificationLabel.XSS,
                ClassificationLabel.PATH_TRAVERSAL,
            }
            and analysis.final_state == WorkflowState.CODE_ANALYSIS
            and analysis.code_finding is not None
            and bool(analysis.code_finding.supporting_lines)
        )
        if result.disposition == RemediationDisposition.NO_ACTION:
            if benign:
                if result.decision is not None and result.decision.no_action_reason != NoActionReason.BENIGN:
                    return invalid("benign decision reason mismatch")
            elif actionable:
                if result.decision is None or result.decision.no_action_reason != NoActionReason.INSUFFICIENT_EVIDENCE:
                    return invalid("malicious no-patch requires explicit insufficient-evidence refusal")
            else:
                return invalid("no-patch requires supported benign or actionable analysis")
        elif result.disposition == RemediationDisposition.UNSUPPORTED:
            if not actionable:
                return invalid("unsupported requires actionable malicious analysis")
        elif result.disposition in {
            RemediationDisposition.COMPILER_REJECTED,
            RemediationDisposition.INVALID_OUTPUT,
            RemediationDisposition.PROVIDER_FAILED,
            RemediationDisposition.POLICY_BLOCKED,
        }:
            if not actionable:
                return invalid("remediation error requires actionable malicious analysis")
        else:
            return invalid("unrecognized terminal remediation disposition")
        if result.decision is not None and result.decision.vulnerability_class is not None:
            if result.decision.vulnerability_class.value != analysis.triage.classification.value:
                return invalid("decision vulnerability class disagrees with triage")
        return self._allow("Bounded remediation termination with no patch is permitted")

    def validate_strategy_selection(
        self,
        *,
        strategy_id: str,
        registered_strategy_ids: tuple[str, ...],
        allowed_strategy_ids: tuple[str, ...],
    ) -> PolicyDecision:
        """Allow only a trusted registered strategy that human policy permits."""
        if strategy_id not in registered_strategy_ids:
            return self._deny(
                PolicyReasonCode.PROHIBITED_OPERATION,
                f"Strategy {strategy_id!r} is not registered.",
            )
        if strategy_id not in allowed_strategy_ids:
            return self._deny(
                PolicyReasonCode.PROHIBITED_OPERATION,
                f"Strategy {strategy_id!r} is not allowed by the current policy.",
            )
        return self._allow(
            f"Strategy {strategy_id!r} is registered and policy-approved."
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


class StandardRedPolicy:
    """T03 immutable policy preflight against the fixed, registered Docker lab.

    Policy decisions alone never authorize dispatch: later tasks bind real
    operator approval and atomic budget consumption to each operation.
    """

    def __init__(self, *, registry: TargetRegistry, budget_file: Path) -> None:
        self.registry = registry
        self.budget = RedStandardBudget.model_validate(
            json.loads(budget_file.read_text(encoding="utf-8"))
        )
        self.base = PolicyEngine(registry=registry, project_root=budget_file.parent)

    def freeze(
        self,
        *,
        assessment_id: str,
        approval_id: str,
        target_id: str,
        allowed_methods: set[str] | frozenset[str] | None = None,
        allowed_classes: set[str] | frozenset[str] | None = None,
    ) -> RedStandardAuthorization:
        if target_id != "vulnerable-store":
            raise ValueError("target not enabled for Red v1")
        target = self.registry.get_target(target_id)
        methods = frozenset(allowed_methods if allowed_methods is not None else ("GET", "POST"))
        classes = frozenset(
            allowed_classes if allowed_classes is not None
            else tuple(v.value for v in VulnerabilityClass)
        )
        allowed_method_values = {"GET", "POST"}
        allowed_class_values = {v.value for v in VulnerabilityClass}
        if not methods or not methods.issubset(allowed_method_values):
            raise ValueError("method not approved for Standard Red assessment")
        if not classes or not classes.issubset(allowed_class_values):
            raise ValueError("class not approved for Standard Red assessment")

        target_fp = sha256(target.model_dump_json().encode("utf-8")).hexdigest()
        body = {
            "assessment_id": assessment_id,
            "approval_id": approval_id,
            "target_id": target_id,
            "target_fingerprint": target_fp,
            "scheme": target.scheme,
            "hostname": target.hostname,
            "port": target.port,
            "budget": self.budget.model_dump(mode="json"),
            "allowed_methods": sorted(methods),
            "allowed_classes": sorted(classes),
        }
        auth_fp = sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return RedStandardAuthorization(
            scope=RedScopeReference(
                assessment_id=assessment_id, target_id=target_id,
                target_fingerprint=target_fp,
                authorization_fingerprint=auth_fp,
            ),
            approval_id=approval_id,
            scheme=target.scheme,
            hostname=target.hostname,
            port=target.port,
            budget=self.budget,
            allowed_methods=methods,
            allowed_classes=classes,
        )

    def check(
        self,
        snapshot: RedStandardAuthorization,
        operation: RedPolicyOperation,
        usage: RedPolicyUsage,
    ) -> PolicyDecision:
        """Fail closed on tampering, unregistered operations and exhausted limits."""
        deny = self.base._deny
        try:
            current = self.freeze(
                assessment_id=snapshot.scope.assessment_id,
                approval_id=snapshot.approval_id,
                target_id=snapshot.scope.target_id,
                allowed_methods={v.value for v in snapshot.allowed_methods},
                allowed_classes={v.value for v in snapshot.allowed_classes},
            )
        except (ValueError, TypeError, KeyError):
            return deny(PolicyReasonCode.PROHIBITED_OPERATION, "Invalid approval snapshot.")
        if current != snapshot or operation.scope != snapshot.scope:
            return deny(PolicyReasonCode.PROHIBITED_OPERATION, "Approval or target fingerprint mismatch.")
        target = self.registry.get_target(snapshot.scope.target_id)
        decision = self.base.validate_network_destination(
            target_id=target.target_id, scheme=operation.scheme,
            hostname=operation.hostname, port=operation.port,
        )
        if not decision.allowed:
            return decision
        if operation.method not in snapshot.allowed_methods:
            return deny(PolicyReasonCode.METHOD_NOT_ALLOWED, "HTTP method outside approval.")
        if operation.retry_number > snapshot.budget.max_retries:
            return deny(PolicyReasonCode.PROHIBITED_OPERATION, "Retries exceed Standard limit.")
        if operation.depth > snapshot.budget.max_depth:
            return deny(PolicyReasonCode.PROHIBITED_OPERATION, "Crawl depth exceeds Standard limit.")
        if usage.elapsed_seconds >= snapshot.budget.max_runtime_seconds:
            return deny(PolicyReasonCode.TIME_LIMIT_REACHED, "Standard runtime exhausted.")
        if usage.active_operations >= snapshot.budget.max_parallel_operations:
            return deny(PolicyReasonCode.PROHIBITED_OPERATION, "Standard concurrency exhausted.")
        if usage.http_requests + operation.requests > snapshot.budget.max_http_requests:
            return deny(PolicyReasonCode.REQUEST_LIMIT_REACHED, "Standard request budget exhausted.")

        endpoint = self.base.validate_http_method(
            target_id=target.target_id, endpoint_id=operation.endpoint_id,
            method=operation.method,
        )
        if not endpoint.allowed:
            return endpoint
        if operation.kind == "crawl":
            if operation.method.value != "GET" or operation.test_id is not None or operation.vulnerability_class is not None:
                return deny(PolicyReasonCode.PROHIBITED_OPERATION, "Crawl is limited to GET without test payloads.")
            if usage.crawl_requests + operation.requests > snapshot.budget.max_crawl_requests:
                return deny(PolicyReasonCode.REQUEST_LIMIT_REACHED, "Standard crawl budget exhausted.")
        elif operation.kind == "test":
            if usage.tests_started >= snapshot.budget.max_tests:
                return deny(PolicyReasonCode.ATTEMPT_LIMIT_REACHED, "Standard test budget exhausted.")
            if operation.vulnerability_class not in snapshot.allowed_classes:
                return deny(PolicyReasonCode.PROHIBITED_OPERATION, "Vulnerability class outside approval.")
            if operation.test_id is None:
                return deny(PolicyReasonCode.UNKNOWN_TEST, "A registered test is required.")
            decision = self.base.validate_security_test(
                target_id=target.target_id, endpoint_id=operation.endpoint_id,
                test_id=operation.test_id,
            )
            if not decision.allowed:
                return decision
            registered = self.registry.get_security_test(operation.test_id)
            if (registered.method != operation.method
                    or registered.vulnerability_class != operation.vulnerability_class):
                return deny(PolicyReasonCode.PROHIBITED_OPERATION, "Test metadata differs from registered policy.")
        else:
            return deny(PolicyReasonCode.PROHIBITED_OPERATION, "Unknown Standard operation.")
        return self.base._allow("Operation is within frozen Standard assessment bounds.")
