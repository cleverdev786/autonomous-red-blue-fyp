"""T07 Red v1 admission: compare untrusted operation refs to trusted persisted data.

This gate never runs a tool, reserves budgets, or follows redirects. The future
execution dispatcher must call it again immediately before each actual operation.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from ipaddress import IPv4Network, ip_address
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from orchestrator.policy_engine import StandardRedPolicy
from schemas.common import HttpMethod, Identifier, PolicyReasonCode
from schemas.red_team import RedPolicyOperation, RedPolicyUsage, RedScopeReference
from schemas.verification import PolicyDecision
from services.red_assessment_store import RedAssessmentStore
from services.red_evidence_store import RedEvidenceStore
from services.target_registry import TargetRegistryError


_PRIVATE_DOCKER_RANGES = tuple(
    IPv4Network(item) for item in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


class AdmissionRequest(BaseModel):
    """Untrusted operation reference and destination, never a tool command."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scope: RedScopeReference
    operation_id: Identifier
    plan_version: Identifier
    tool: Identifier
    method: HttpMethod
    url: str = Field(min_length=1, max_length=500)
    redirect_url: str | None = Field(default=None, max_length=500)


class TrustedRedAdmission:
    """Read-only pre-dispatch admission with append-only policy event records."""

    def __init__(
        self,
        *,
        store: RedAssessmentStore,
        journal: RedEvidenceStore,
        policy: StandardRedPolicy,
        pinned_ips: frozenset[str],
        resolver: Callable[[str], Iterable[str]],
    ) -> None:
        self.store = store
        self.journal = journal
        self.policy = policy
        # Pins must originate in a trusted lab network inventory, not the request.
        self.pinned_ips = pinned_ips
        self.resolver = resolver

    @staticmethod
    def _network_safe(ips: Iterable[str]) -> bool:
        values = tuple(ips)
        if not values:
            return False
        try:
            parsed = tuple(ip_address(value) for value in values)
        except ValueError:
            return False
        return all(
            address.version == 4 and any(address in subnet for subnet in _PRIVATE_DOCKER_RANGES)
            for address in parsed
        )

    def _evaluate(self, request: AdmissionRequest, usage: RedPolicyUsage) -> PolicyDecision:
        deny = self.policy.base._deny

        # Do not trust model_copy or any caller-provided object without revalidation.
        request = AdmissionRequest.model_validate(request.model_dump())
        usage = RedPolicyUsage.model_validate(usage.model_dump())

        snapshot, authorization = self.store.load(request.scope.assessment_id)
        if snapshot.assessment.scope != request.scope or authorization.scope != request.scope:
            return deny(PolicyReasonCode.PROHIBITED_OPERATION, "Scope/fingerprint mismatch.")

        if snapshot.assessment.status.value != "running":
            return deny(PolicyReasonCode.INVALID_STATE, "Assessment is not running.")
        if (not snapshot.plans or snapshot.plans[-1].status != "approved"
                or snapshot.plans[-1].plan_version != request.plan_version):
            return deny(PolicyReasonCode.INVALID_STATE, "Plan is stale or not current.")

        operation = next(
            (item for item in snapshot.operations if item.operation_id == request.operation_id),
            None,
        )
        if (operation is None or operation.status != "approved"
                or operation.plan_version != request.plan_version or operation.scope != request.scope):
            return deny(PolicyReasonCode.PROHIBITED_OPERATION, "Unknown or unapproved operation.")

        if request.tool != "controlled_http":
            return deny(PolicyReasonCode.PROHIBITED_OPERATION, "Unknown or disabled execution tool.")
        if request.redirect_url is not None:
            return deny(PolicyReasonCode.PROHIBITED_OPERATION, "Redirects are forbidden.")
        if operation.test_id is None:
            return deny(PolicyReasonCode.UNKNOWN_TEST, "Registered test required.")
        try:
            security_test = self.policy.registry.get_security_test(operation.test_id)
            endpoint = self.policy.registry.get_endpoint(
                request.scope.target_id, security_test.endpoint_id,
            )
        except TargetRegistryError:
            # Registry errors are deny conditions, not instructions for the tool.
            return deny(PolicyReasonCode.UNKNOWN_TEST, "Unregistered test or endpoint.")
        candidate = next(
            (item for item in snapshot.candidates if item.candidate_id == operation.candidate_id),
            None,
        )
        if (candidate is None or candidate.path != endpoint.path
                or candidate.method != security_test.method
                or not set(candidate.parameter_names).issubset(security_test.allowed_parameter_names)):
            return deny(PolicyReasonCode.PROHIBITED_OPERATION, "Candidate exceeds registered endpoint/method/parameters.")
        if request.method != security_test.method:
            return deny(PolicyReasonCode.METHOD_NOT_ALLOWED, "Method differs from vetted registered test.")

        target = self.policy.registry.get_target(request.scope.target_id)
        # Exact canonical comparison rejects credentials, encoding tricks, alternate
        # hosts/ports, path traversal, query strings and fragments with no DNS request.
        expected_url = f"{target.scheme}://{target.hostname}:{target.port}{endpoint.path}"
        if request.url != expected_url:
            return deny(PolicyReasonCode.HOST_NOT_ALLOWED, "Untrusted or noncanonical destination.")

        operation_scope = RedPolicyOperation(
            scope=authorization.scope, kind="test", scheme=target.scheme,
            hostname=target.hostname, port=target.port, method=security_test.method,
            endpoint_id=security_test.endpoint_id, test_id=security_test.test_id,
            vulnerability_class=security_test.vulnerability_class,
            requests=security_test.max_requests,
        )
        decision = self.policy.check(authorization, operation_scope, usage)
        if not decision.allowed:
            return decision
        try:
            answers = frozenset(self.resolver(target.hostname))
        except Exception:
            return deny(PolicyReasonCode.HOST_NOT_ALLOWED, "Trusted DNS resolution unavailable.")
        if (not self._network_safe(self.pinned_ips)
                or not self._network_safe(answers)
                or answers != self.pinned_ips):
            return deny(PolicyReasonCode.HOST_NOT_ALLOWED, "DNS rebinding or IP scope violation.")
        return self.policy.base._allow("Trusted operation preflight passed; execution not yet authorized.")

    def check(self, request: AdmissionRequest, usage: RedPolicyUsage) -> PolicyDecision:
        """Validate every reference, then write an event before returning allow."""
        try:
            decision = self._evaluate(request, usage)
        except (ValueError, TypeError, AttributeError):
            decision = self.policy.base._deny(
                PolicyReasonCode.PROHIBITED_OPERATION, "Invalid trusted admission inputs."
            )
        try:
            # Log under the stored authorization, not the untrusted scope.
            # A forged fingerprint must still leave an auditable denial.
            _, saved_authorization = self.store.load(request.scope.assessment_id)
            self.journal.append_event(
                saved_authorization.scope, uuid4().hex,
                actor="policy",
                action="operation_admitted" if decision.allowed else "operation_blocked",
                outcome="allowed" if decision.allowed else "denied",
                details={
                    "operation_id": request.operation_id,
                    "reason_code": decision.reason_code.value,
                },
            )
        except Exception:
            return self.policy.base._deny(
                PolicyReasonCode.PROHIBITED_OPERATION, "Admission audit unavailable; refused."
            )
        return decision
