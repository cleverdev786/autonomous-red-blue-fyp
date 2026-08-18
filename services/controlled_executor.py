"""Policy-controlled deterministic local HTTP security-test executor."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import time
from typing import Any, Mapping, Protocol
from urllib.parse import urljoin

import httpx
from pydantic import TypeAdapter

from orchestrator.limits import RunLimitTracker
from orchestrator.policy_engine import PolicyEngine
from schemas.common import Identifier, PolicyReasonCode
from schemas.red_team import HttpExchangeEvidence, TestExecutionResult
from schemas.verification import PolicyDecision
from security_tests.base import RequestStep
from security_tests.registry import SecurityTestRegistry
from services.target_registry import TargetRegistry, TargetRegistryError


_IDENTIFIER_ADAPTER = TypeAdapter(Identifier)


class ControlledExecutionBlocked(RuntimeError):
    """Raised before network activity when deterministic policy denies execution."""

    def __init__(self, decision: PolicyDecision) -> None:
        super().__init__(decision.message)
        self.decision = decision


class TransportTimeoutError(RuntimeError):
    """Raised when a controlled request exceeds its configured timeout."""


class TransportRequestError(RuntimeError):
    """Raised for deterministic transport failures."""


@dataclass(frozen=True, slots=True)
class TransportResponse:
    """Small transport-neutral HTTP response used by executor logic."""

    status_code: int
    text: str
    headers: Mapping[str, str]


class HttpTransport(Protocol):
    """Transport boundary used by production HTTP and in-process unit tests."""

    def send(
        self,
        *,
        method: str,
        url: str,
        query_params: Mapping[str, str],
        json_body: Mapping[str, Any] | None,
        timeout_seconds: int,
        run_id: str,
        request_id: str,
    ) -> TransportResponse:
        """Send one already-authorized request without following redirects."""


class HttpxTransport:
    """Production transport used inside the isolated controlled-executor container."""

    def send(
        self,
        *,
        method: str,
        url: str,
        query_params: Mapping[str, str],
        json_body: Mapping[str, Any] | None,
        timeout_seconds: int,
        run_id: str,
        request_id: str,
    ) -> TransportResponse:
        try:
            with httpx.Client(
                follow_redirects=False,
                timeout=timeout_seconds,
            ) as client:
                response = client.request(
                    method=method,
                    url=url,
                    params=dict(query_params),
                    json=dict(json_body) if json_body is not None else None,
                    headers={
                        "X-FYP-Run-ID": run_id,
                        "X-FYP-Request-ID": request_id,
                    },
                )
        except httpx.TimeoutException as exc:
            raise TransportTimeoutError("controlled request timed out") from exc
        except httpx.RequestError as exc:
            raise TransportRequestError(
                f"controlled request failed: {exc.__class__.__name__}"
            ) from exc

        return TransportResponse(
            status_code=response.status_code,
            text=response.text,
            headers=dict(response.headers),
        )


class ControlledExecutor:
    """Execute fixed registered tests only after deterministic authorization."""

    def __init__(
        self,
        *,
        target_registry: TargetRegistry,
        test_registry: SecurityTestRegistry,
        policy_engine: PolicyEngine,
        limits: RunLimitTracker,
        transport: HttpTransport,
        clock=time.monotonic,
    ) -> None:
        self.target_registry = target_registry
        self.test_registry = test_registry
        self.policy_engine = policy_engine
        self.limits = limits
        self.transport = transport
        self.clock = clock

        self.test_registry.validate_against_target_registry(self.target_registry)

    def execute_registered_test(
        self,
        *,
        test_id: str,
        attempt_number: int,
        run_id: str,
    ) -> TestExecutionResult:
        """Execute one fixed local test sequence with trusted correlation metadata.

        The caller supplies a registered test ID, attempt number, and opaque run
        correlation ID. Destination, endpoint, method, payload, and request IDs
        remain derived by trusted deterministic code.
        """
        if attempt_number < 1:
            raise ValueError("attempt_number must be >= 1")
        run_id = _IDENTIFIER_ADAPTER.validate_python(run_id)

        try:
            metadata = self.target_registry.get_security_test(test_id)
        except TargetRegistryError:
            decision = PolicyDecision(
                allowed=False,
                reason_code=PolicyReasonCode.UNKNOWN_TEST,
                message=f"Security test {test_id!r} is not registered.",
            )
            raise ControlledExecutionBlocked(decision) from None

        test = self.test_registry.get(test_id)
        target = self.target_registry.get_target(metadata.target_id)
        steps = test.build_steps()

        self._require(
            self.policy_engine.validate_security_test(
                target_id=metadata.target_id,
                test_id=test_id,
                endpoint_id=metadata.endpoint_id,
            )
        )
        self._require(
            self.policy_engine.validate_network_destination(
                target_id=metadata.target_id,
                scheme=target.scheme,
                hostname=target.hostname,
                port=target.port,
            )
        )
        self._require(
            self.policy_engine.validate_attack_attempt_budget(self.limits)
        )

        max_step_count = min(
            metadata.max_requests,
            target.max_requests_per_attempt,
        )
        if len(steps) > max_step_count:
            decision = PolicyDecision(
                allowed=False,
                reason_code=PolicyReasonCode.REQUEST_LIMIT_REACHED,
                message=(
                    f"Registered test {test_id!r} contains {len(steps)} steps "
                    f"but policy allows at most {max_step_count}."
                ),
            )
            raise ControlledExecutionBlocked(decision)

        self.limits.consume_attack_attempts()

        started = self.clock()
        exchanges: list[HttpExchangeEvidence] = []
        last_status: int | None = None

        for index, step in enumerate(steps, start=1):
            self._validate_step(metadata=metadata, step=step)
            self._require(
                self.policy_engine.validate_http_request_budget(self.limits)
            )
            self.limits.consume_http_requests()

            endpoint = self.target_registry.get_endpoint(
                metadata.target_id,
                step.endpoint_id,
            )
            base_url = f"{target.scheme}://{target.hostname}:{target.port}"
            url = urljoin(base_url, endpoint.path)
            request_id = self._request_id(
                run_id=run_id,
                attempt_number=attempt_number,
                request_index=index,
            )

            request_started = self.clock()
            try:
                response = self.transport.send(
                    method=step.method.value,
                    url=url,
                    query_params=step.query_params,
                    json_body=step.json_body,
                    timeout_seconds=metadata.timeout_seconds,
                    run_id=run_id,
                    request_id=request_id,
                )
            except TransportTimeoutError:
                return TestExecutionResult(
                    run_id=run_id,
                    target_id=metadata.target_id,
                    test_id=test_id,
                    attempt_number=attempt_number,
                    request_count=len(exchanges) + 1,
                    completed=False,
                    timed_out=True,
                    status_code=last_status,
                    evidence=(),
                    exchanges=tuple(exchanges),
                    duration_ms=self._elapsed_ms(started),
                    error_code="request-timeout",
                )
            except TransportRequestError:
                return TestExecutionResult(
                    run_id=run_id,
                    target_id=metadata.target_id,
                    test_id=test_id,
                    attempt_number=attempt_number,
                    request_count=len(exchanges) + 1,
                    completed=False,
                    timed_out=False,
                    status_code=last_status,
                    evidence=(),
                    exchanges=tuple(exchanges),
                    duration_ms=self._elapsed_ms(started),
                    error_code="transport-error",
                )

            last_status = response.status_code
            redirect_location = response.headers.get("location")
            exchange = HttpExchangeEvidence(
                exchange_id=f"exchange-{index:02d}",
                request_id=request_id,
                step_id=step.step_id,
                endpoint_id=step.endpoint_id,
                method=step.method.value,
                status_code=response.status_code,
                body_excerpt=response.text[:2000],
                redirect_location=redirect_location,
                duration_ms=self._elapsed_ms(request_started),
            )
            exchanges.append(exchange)

            # Current MVP redirect policy: do not follow redirects at all.
            # This is stricter than revalidation and prevents redirect escape.
            if 300 <= response.status_code <= 399:
                return TestExecutionResult(
                    run_id=run_id,
                    target_id=metadata.target_id,
                    test_id=test_id,
                    attempt_number=attempt_number,
                    request_count=len(exchanges),
                    completed=False,
                    timed_out=False,
                    status_code=response.status_code,
                    evidence=(),
                    exchanges=tuple(exchanges),
                    duration_ms=self._elapsed_ms(started),
                    error_code="redirect-blocked",
                )

        evidence = test.evaluate(tuple(exchanges))

        return TestExecutionResult(
            run_id=run_id,
            target_id=metadata.target_id,
            test_id=test_id,
            attempt_number=attempt_number,
            request_count=len(exchanges),
            completed=True,
            timed_out=False,
            status_code=last_status,
            evidence=evidence,
            exchanges=tuple(exchanges),
            duration_ms=self._elapsed_ms(started),
            error_code=None if evidence else "evidence-not-observed",
        )

    @staticmethod
    def _request_id(*, run_id: str, attempt_number: int, request_index: int) -> str:
        """Create a deterministic opaque request ID from trusted run correlation."""
        material = f"{run_id}:{attempt_number}:{request_index}".encode("utf-8")
        return f"req-{sha256(material).hexdigest()[:24]}"

    def _validate_step(self, *, metadata, step: RequestStep) -> None:
        self._require(
            self.policy_engine.validate_endpoint(
                target_id=metadata.target_id,
                endpoint_id=step.endpoint_id,
            )
        )
        self._require(
            self.policy_engine.validate_http_method(
                target_id=metadata.target_id,
                endpoint_id=step.endpoint_id,
                method=step.method,
            )
        )

        if step.endpoint_id != metadata.endpoint_id:
            decision = PolicyDecision(
                allowed=False,
                reason_code=PolicyReasonCode.TEST_ENDPOINT_MISMATCH,
                message=(
                    f"Test step endpoint {step.endpoint_id!r} does not match "
                    f"registered endpoint {metadata.endpoint_id!r}."
                ),
            )
            raise ControlledExecutionBlocked(decision)

        supplied_names = set(step.query_params)
        if step.json_body is not None:
            supplied_names.update(step.json_body)

        allowed_names = set(metadata.allowed_parameter_names)
        if not supplied_names.issubset(allowed_names):
            decision = PolicyDecision(
                allowed=False,
                reason_code=PolicyReasonCode.PROHIBITED_OPERATION,
                message=(
                    "Registered test implementation supplied parameters not "
                    "authorized by test metadata."
                ),
            )
            raise ControlledExecutionBlocked(decision)

    @staticmethod
    def _require(decision: PolicyDecision) -> None:
        if not decision.allowed:
            raise ControlledExecutionBlocked(decision)

    def _elapsed_ms(self, started: float) -> int:
        return max(0, int((self.clock() - started) * 1000))
