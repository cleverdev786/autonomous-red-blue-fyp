"""T10 bounded ZAP observation adapter, deliberately not a generic scanner client.

The trusted caller supplies the transport that reaches ZAP on container-local
loopback. This module never opens sockets, runs a scan, follows redirects or
reserves budgets. Only the two fixed core API operations below are supported.
"""

from __future__ import annotations

import ast
import json
import math
import os
import re
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from orchestrator.policy_engine import StandardRedPolicy
from schemas.common import HttpMethod
from schemas.red_team import (
    RedPolicyOperation,
    RedPolicyUsage,
    RedScopeReference,
    RedStandardAuthorization,
)
from services.target_registry import TargetRegistryError


class ZapAdapterDenied(ValueError):
    """A stable, non-sensitive reason why a ZAP request was refused."""


class ZapBudget(BaseModel):
    """A finite per-request cap. Callers must track actual usage separately."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_urls: int = Field(ge=1, le=12)
    max_depth: int = Field(ge=1, le=2)
    duration_seconds: int = Field(ge=1, le=180)


class TargetedZapOperation(BaseModel):
    """Non-effectful description of one vetted, individually scoped ZAP test."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    test_id: Literal["xss-reflection-001"]
    scanner_id: Literal["40012"]
    endpoint_id: Literal["scenario-xss-search"]
    method: Literal["GET"]
    url: Literal[
        "http://vulnerable-store:8000/scenarios/xss/search?q=notebook"
    ]
    scan_policy_name: Literal["mars-xss-reflection-001"]
    recurse: Literal[False] = False
    in_scope_only: Literal[True] = True
    request_limit: int = Field(ge=1, le=24)
    duration_seconds: int = Field(ge=1, le=180)
    status: Literal["prepared_not_executed"] = "prepared_not_executed"


class ZapAlert(BaseModel):
    """Sanitized alert emitted by the bounded targeted runner."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scanner_id: Literal["40012"]
    url: Literal[
        "http://vulnerable-store:8000/scenarios/xss/search?q=notebook"
    ]
    name: str = Field(min_length=1, max_length=120)


class TargetedZapRunResult(BaseModel):
    """Measured result from a runner that enforces the operation request cap."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_count: int = Field(ge=0, le=24)
    duration_seconds: int = Field(ge=0, le=180)
    alerts: tuple[ZapAlert, ...] = Field(default=(), max_length=8)


class ZapTargetedObservation(BaseModel):
    """Persistable non-confirming classification of one targeted ZAP result."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scope: RedScopeReference
    test_id: Literal["xss-reflection-001"]
    scanner_id: Literal["40012"]
    endpoint_id: Literal["scenario-xss-search"]
    status: Literal["suspected", "not_observed"]
    confirmed: Literal[False] = False
    request_count: int = Field(ge=0, le=24)
    duration_seconds: int = Field(ge=0, le=180)
    alert_count: int = Field(ge=0, le=8)


# Injected transport must be ZAP-only in the same isolated lab namespace.
# It must never accept arbitrary caller-chosen routes or destination hosts.
ZapJSON = Callable[[str, Mapping[str, str], float], object]
TargetedZapRunner = Callable[[TargetedZapOperation], TargetedZapRunResult]
SuspectedStore = Callable[[ZapTargetedObservation], None]
ObservationStore = Callable[[ZapTargetedObservation], None]
GateStatus = Callable[[float], object]
_STATUS = re.compile(r"^HTTP/1\.[01] ([1-5][0-9]{2})\b")


class ZapObservationStore:
    """Append-only durable store for sanitized targeted ZAP observations."""

    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.root.is_symlink() or not self.root.is_dir():
            raise ZapAdapterDenied("suspected_store_unavailable")

    def save(self, observation: ZapTargetedObservation) -> None:
        directory = self.root / observation.scope.assessment_id
        directory.mkdir(mode=0o700, exist_ok=True)
        if directory.is_symlink() or directory.resolve(strict=True).parent != self.root:
            raise ZapAdapterDenied("suspected_store_unavailable")
        path = directory / f"{observation.test_id}.json"
        data = (observation.model_dump_json(indent=2) + "\n").encode()
        try:
            descriptor = os.open(
                path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as exc:
            raise ZapAdapterDenied("suspected_store_unavailable") from exc

    def read(self, scope: RedScopeReference, test_id: str) -> ZapTargetedObservation:
        if test_id != "xss-reflection-001":
            raise ZapAdapterDenied("suspected_store_unavailable")
        path = self.root / scope.assessment_id / f"{test_id}.json"
        if path.is_symlink() or not path.is_file():
            raise ZapAdapterDenied("suspected_store_unavailable")
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(descriptor, "rb") as stream:
                raw = stream.read(16_385)
            if len(raw) > 16_384:
                raise ValueError("oversize")
            result = ZapTargetedObservation.model_validate_json(raw)
        except (OSError, ValueError) as exc:
            raise ZapAdapterDenied("suspected_store_unavailable") from exc
        if result.scope != scope:
            raise ZapAdapterDenied("suspected_store_unavailable")
        return result


class FixedTargetedZapRunner:
    """One-rule active scan whose target is the two-request network gate."""

    def __init__(
        self,
        *,
        request_json: ZapJSON,
        gate_status: GateStatus,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self._request_json = request_json
        self._gate_status = gate_status
        self._monotonic = monotonic
        self._sleep = sleep

    def _call(self, route: str, params: Mapping[str, str], timeout: float) -> dict:
        value = self._request_json(route, params, timeout)
        if type(value) is not dict or "error" in value:
            raise ZapAdapterDenied("targeted_runner_failed")
        return value

    def __call__(self, operation: TargetedZapOperation) -> TargetedZapRunResult:
        if not isinstance(operation, TargetedZapOperation):
            raise ZapAdapterDenied("targeted_runner_failed")
        started = self._monotonic()
        deadline = started + operation.duration_seconds
        scan_id: str | None = None

        def bounded_call(route: str, params: Mapping[str, str]) -> dict:
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                raise ZapAdapterDenied("targeted_runner_failed")
            result = self._call(route, params, min(5.0, remaining))
            if self._monotonic() > deadline:
                raise ZapAdapterDenied("targeted_runner_failed")
            return result

        def bounded_gate_status() -> object:
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                raise ZapAdapterDenied("targeted_runner_failed")
            result = self._gate_status(min(5.0, remaining))
            if self._monotonic() > deadline:
                raise ZapAdapterDenied("targeted_runner_failed")
            return result

        initial = bounded_gate_status()
        if type(initial) is not dict or initial != {
            "forwarded": 0, "limit": operation.request_limit,
        }:
            raise ZapAdapterDenied("targeted_runner_failed")
        try:
            bounded_call("/JSON/core/action/deleteAllAlerts/", {})
            bounded_call("/JSON/ascan/action/disableAllScanners/", {})
            bounded_call(
                "/JSON/ascan/action/enableScanners/",
                {"ids": operation.scanner_id},
            )
            scan = bounded_call(
                "/JSON/ascan/action/scan/",
                {
                    "url": operation.url,
                    "recurse": "false",
                    "inScopeOnly": "true",
                    "method": operation.method,
                },
            )
            scan_id = scan.get("scan")
            if (
                not isinstance(scan_id, str)
                or not scan_id.isdigit()
                or len(scan_id) > 8
            ):
                raise ZapAdapterDenied("targeted_runner_failed")
            while True:
                status = bounded_call(
                    "/JSON/ascan/view/status/", {"scanId": scan_id},
                ).get("status")
                if status == "100":
                    break
                if not isinstance(status, str) or not status.isdigit():
                    raise ZapAdapterDenied("targeted_runner_failed")
                remaining = deadline - self._monotonic()
                if remaining <= 0:
                    raise ZapAdapterDenied("targeted_runner_failed")
                self._sleep(min(0.25, remaining))
            gate = bounded_gate_status()
            if (
                type(gate) is not dict
                or gate.get("limit") != operation.request_limit
                or type(gate.get("forwarded")) is not int
                or not 1 <= gate["forwarded"] <= operation.request_limit
            ):
                raise ZapAdapterDenied("targeted_runner_failed")
            response = bounded_call(
                "/JSON/core/view/alerts/",
                {"baseurl": operation.url, "start": "0", "count": "8"},
            )
        except ZapAdapterDenied:
            if scan_id is not None:
                with suppress(Exception):
                    self._request_json(
                        "/JSON/ascan/action/stop/", {"scanId": scan_id}, 1.0,
                    )
            raise
        raw_alerts = response.get("alerts")
        if not isinstance(raw_alerts, list) or len(raw_alerts) > 8:
            raise ZapAdapterDenied("targeted_runner_failed")
        alerts = []
        for alert in raw_alerts:
            if not isinstance(alert, dict):
                raise ZapAdapterDenied("targeted_runner_failed")
            if str(alert.get("pluginId")) != operation.scanner_id:
                continue
            alerts.append(ZapAlert(
                scanner_id=operation.scanner_id,
                url=alert.get("url"),
                name=alert.get("name"),
            ))
        return TargetedZapRunResult(
            request_count=gate["forwarded"],
            duration_seconds=math.ceil(self._monotonic() - started),
            alerts=tuple(alerts),
        )


class ZapAdapter:
    """Approved passive URL reads and single registered GET seeding only."""

    def __init__(
        self,
        *,
        policy: StandardRedPolicy,
        request_json: ZapJSON,
        run_targeted: TargetedZapRunner | None = None,
        store_suspected: SuspectedStore | None = None,
        store_observation: ObservationStore | None = None,
    ):
        self.policy = policy
        self._request_json = request_json
        self._run_targeted = run_targeted
        self._store_suspected = store_suspected
        self._store_observation = store_observation

    def _authorize(
        self,
        authorization: RedStandardAuthorization,
        target_id: str,
        endpoint_id: str,
        budget: ZapBudget,
        usage: RedPolicyUsage,
        *,
        requests: int,
    ):
        if authorization.scope.target_id != target_id:
            raise ZapAdapterDenied("denied_target")
        try:
            target = self.policy.registry.get_target(target_id)
            endpoint = self.policy.registry.get_endpoint(target_id, endpoint_id)
        except TargetRegistryError as exc:
            raise ZapAdapterDenied("denied_registry") from exc
        if HttpMethod.GET not in endpoint.allowed_methods:
            raise ZapAdapterDenied("denied_method")
        if (budget.max_depth > authorization.budget.max_depth
                or budget.max_urls > authorization.budget.max_crawl_requests
                or usage.elapsed_seconds + budget.duration_seconds > authorization.budget.max_runtime_seconds):
            raise ZapAdapterDenied("budget_denied")
        op = RedPolicyOperation(
            scope=authorization.scope, kind="crawl", scheme=target.scheme,
            hostname=target.hostname, port=target.port, method=HttpMethod.GET,
            endpoint_id=endpoint_id, requests=requests, depth=budget.max_depth,
        )
        decision = self.policy.check(authorization, op, usage)
        if not decision.allowed:
            raise ZapAdapterDenied("budget_denied")
        return target, endpoint

    def _call(self, route: str, params: Mapping[str, str], timeout: int) -> dict:
        # Do not surface raw ZAP HTTP responses, which might contain secrets.
        try:
            result = self._request_json(route, params, timeout)
        except TimeoutError as exc:
            raise ZapAdapterDenied("timeout") from exc
        except (OSError, ValueError) as exc:
            raise ZapAdapterDenied("transport_error") from exc
        if not isinstance(result, dict) or "error" in result:
            raise ZapAdapterDenied("malformed_response")
        try:
            raw = json.dumps(result)
        except (TypeError, ValueError) as exc:
            raise ZapAdapterDenied("malformed_response") from exc
        if len(raw) > 65_536:
            raise ZapAdapterDenied("malformed_response")
        return result

    @staticmethod
    def _safe_path(url: str, expected_origin: str) -> str:
        if (not isinstance(url, str) or len(url) > 512
                or any(ord(char) < 33 or ord(char) > 126 for char in url)
                or "%" in url or "\\" in url):
            raise ZapAdapterDenied("out_of_scope")
        try:
            result = urlsplit(url)
        except ValueError as exc:
            raise ZapAdapterDenied("out_of_scope") from exc
        if (result.scheme != "http"
                or result.netloc != expected_origin.removeprefix("http://")
                or not result.path.startswith("/")
                or "//" in result.path
                or ".." in result.path.split("/")
                or result.fragment
                or len(result.query) > 256):
            raise ZapAdapterDenied("out_of_scope")
        return result.path

    def discover(
        self, authorization: RedStandardAuthorization, *, target_id: str,
        endpoint_id: str, budget: ZapBudget, usage: RedPolicyUsage,
    ) -> tuple[str, ...]:
        """Normalize bounded passive ZAP URL observations, never admit actions."""
        target, _ = self._authorize(
            authorization, target_id, endpoint_id, budget, usage,
            requests=budget.max_urls,
        )
        origin = f"{target.scheme}://{target.hostname}:{target.port}"
        result = self._call(
            "/JSON/core/view/urls/", {"baseurl": origin}, budget.duration_seconds,
        )
        urls = result.get("urls")
        if (not isinstance(urls, list) or len(urls) > budget.max_urls
                or not all(isinstance(url, str) for url in urls)):
            raise ZapAdapterDenied("malformed_response")
        paths = [self._safe_path(url, origin) for url in urls]
        # No query values or response bodies leave this boundary.
        return tuple(dict.fromkeys(paths))

    def seed(
        self, authorization: RedStandardAuthorization, *, target_id: str,
        endpoint_id: str, budget: ZapBudget, usage: RedPolicyUsage,
    ) -> bool:
        """Ask ZAP to fetch one registered GET URL with redirect following off."""
        target, endpoint = self._authorize(
            authorization, target_id, endpoint_id, budget, usage, requests=1,
        )
        url = f"{target.scheme}://{target.hostname}:{target.port}{endpoint.path}"
        self._safe_path(url, f"{target.scheme}://{target.hostname}:{target.port}")
        result = self._call(
            "/JSON/core/action/accessUrl/",
            {"url": url, "followRedirects": "false"},
            budget.duration_seconds,
        )
        response = result.get("accessUrl")
        if isinstance(response, str):
            if len(response) > 65_536:
                raise ZapAdapterDenied("malformed_response")
            if response.startswith("HTTP/1."):
                header = response
            else:
                try:
                    exchanges = ast.literal_eval(response)
                except (SyntaxError, ValueError, MemoryError, RecursionError) as exc:
                    raise ZapAdapterDenied("malformed_response") from exc
                if (not isinstance(exchanges, list) or len(exchanges) != 1
                        or not isinstance(exchanges[0], dict)):
                    raise ZapAdapterDenied("malformed_response")
                header = exchanges[0].get("responseHeader")
        elif isinstance(response, list) and len(response) == 1 and isinstance(response[0], dict):
            # Official ZAP 2.17.0 JSON response: one structured exchange.
            header = response[0].get("responseHeader")
        else:
            raise ZapAdapterDenied("malformed_response")
        if not isinstance(header, str) or len(header) > 2000:
            raise ZapAdapterDenied("malformed_response")
        response = header
        status = _STATUS.match(response)
        if status is None or re.search(r"(?im)^location\s*:", response):
            raise ZapAdapterDenied("malformed_response")
        if status.group(1).startswith("3"):
            raise ZapAdapterDenied("redirect")
        if not status.group(1).startswith("2"):
            raise ZapAdapterDenied("malformed_response")
        return True

    def prepare_targeted_scan(
        self,
        authorization: RedStandardAuthorization,
        *,
        test_id: str,
        budget: ZapBudget,
        usage: RedPolicyUsage,
    ) -> TargetedZapOperation:
        """Prepare one fixed reflected-XSS scan without calling ZAP."""
        if test_id != "xss-reflection-001":
            raise ZapAdapterDenied("targeted_test_denied")
        try:
            metadata = self.policy.registry.get_security_test(test_id)
            target = self.policy.registry.get_target(metadata.target_id)
            endpoint = self.policy.registry.get_endpoint(
                metadata.target_id,
                metadata.endpoint_id,
            )
        except TargetRegistryError as exc:
            raise ZapAdapterDenied("targeted_test_denied") from exc
        if (
            metadata.endpoint_id != "scenario-xss-search"
            or metadata.method != HttpMethod.GET
            or metadata.vulnerability_class.value != "xss"
            or budget.max_depth != 1
            or budget.max_urls > metadata.max_requests
            or usage.elapsed_seconds + budget.duration_seconds
            > authorization.budget.max_runtime_seconds
        ):
            raise ZapAdapterDenied("targeted_test_denied")
        operation = RedPolicyOperation(
            scope=authorization.scope,
            kind="test",
            scheme=target.scheme,
            hostname=target.hostname,
            port=target.port,
            method=metadata.method,
            endpoint_id=metadata.endpoint_id,
            test_id=metadata.test_id,
            vulnerability_class=metadata.vulnerability_class,
            requests=budget.max_urls,
        )
        if not self.policy.check(authorization, operation, usage).allowed:
            raise ZapAdapterDenied("targeted_test_denied")
        return TargetedZapOperation(
            test_id=test_id,
            scanner_id="40012",
            endpoint_id=metadata.endpoint_id,
            method=metadata.method.value,
            url=(
                f"{target.scheme}://{target.hostname}:{target.port}"
                f"{endpoint.path}?q=notebook"
            ),
            scan_policy_name="mars-xss-reflection-001",
            request_limit=budget.max_urls,
            duration_seconds=budget.duration_seconds,
        )

    def run_targeted_scan(
        self,
        authorization: RedStandardAuthorization,
        *,
        test_id: str,
        budget: ZapBudget,
        usage: RedPolicyUsage,
    ) -> ZapTargetedObservation:
        """Run only the immutable operation through a trusted cap-enforcing seam.

        The seam receives no generic ZAP route or caller-selected scan options.
        Its implementation must stop before ``request_limit``; the measured
        result is checked again here before any observation is persisted.
        """
        operation = self.prepare_targeted_scan(
            authorization,
            test_id=test_id,
            budget=budget,
            usage=usage,
        )
        if self._run_targeted is None:
            raise ZapAdapterDenied("targeted_runner_unavailable")
        try:
            result = self._run_targeted(operation)
        except (TimeoutError, OSError, ValueError) as exc:
            raise ZapAdapterDenied("targeted_runner_failed") from exc
        if not isinstance(result, TargetedZapRunResult):
            raise ZapAdapterDenied("targeted_result_denied")
        if (
            result.request_count > operation.request_limit
            or result.duration_seconds > operation.duration_seconds
            or any(
                alert.scanner_id != operation.scanner_id
                or alert.url != operation.url
                for alert in result.alerts
            )
        ):
            raise ZapAdapterDenied("targeted_result_denied")
        observation = ZapTargetedObservation(
            scope=authorization.scope,
            test_id=operation.test_id,
            scanner_id=operation.scanner_id,
            endpoint_id=operation.endpoint_id,
            status="suspected" if result.alerts else "not_observed",
            request_count=result.request_count,
            duration_seconds=result.duration_seconds,
            alert_count=len(result.alerts),
        )
        if self._store_observation is not None:
            try:
                self._store_observation(observation)
            except (OSError, ValueError) as exc:
                raise ZapAdapterDenied("observation_store_failed") from exc
        if result.alerts and self._store_suspected is not None:
            try:
                self._store_suspected(observation)
            except (OSError, ValueError) as exc:
                raise ZapAdapterDenied("suspected_store_failed") from exc
        elif result.alerts and self._store_observation is None:
            raise ZapAdapterDenied("suspected_store_unavailable")
        return observation
