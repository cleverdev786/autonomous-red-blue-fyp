"""T10 bounded ZAP observation adapter, deliberately not a generic scanner client.

The trusted caller supplies the transport that reaches ZAP on container-local
loopback. This module never opens sockets, runs a scan, follows redirects or
reserves budgets. Only the two fixed core API operations below are supported.
"""

from __future__ import annotations

import ast
import json
import re
from collections.abc import Callable, Mapping
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from orchestrator.policy_engine import StandardRedPolicy
from schemas.common import HttpMethod
from schemas.red_team import (
    RedPolicyOperation,
    RedPolicyUsage,
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


# Injected transport must be ZAP-only in the same isolated lab namespace.
# It must never accept arbitrary caller-chosen routes or destination hosts.
ZapJSON = Callable[[str, Mapping[str, str], int], object]
_STATUS = re.compile(r"^HTTP/1\.[01] ([1-5][0-9]{2})\b")


class ZapAdapter:
    """Approved passive URL reads and single registered GET seeding only."""

    def __init__(self, *, policy: StandardRedPolicy, request_json: ZapJSON):
        self.policy = policy
        self._request_json = request_json

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
