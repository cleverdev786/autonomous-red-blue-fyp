"""Fixed normal-behavior checks executed only inside controlled-executor."""

from __future__ import annotations

import json
import time
from collections.abc import Callable

import httpx

from schemas.verification import VerificationCheckResult, VerificationCheckStatus


BASE_URL = "http://vulnerable-store:8000"
CHECK_IDS = (
    "health",
    "normal_login",
    "normal_search",
    "document_listing",
    "document_download",
    "scenario_sqli_normal_login",
    "scenario_xss_normal_display",
    "scenario_path_public_read",
)


def _check(check_id: str, operation: Callable[[], None]) -> VerificationCheckResult:
    started = time.monotonic()
    try:
        operation()
    except Exception as exc:
        return VerificationCheckResult(
            check_id=check_id,
            status=VerificationCheckStatus.FAILED,
            duration_ms=max(0, int((time.monotonic() - started) * 1000)),
            details=f"{type(exc).__name__}: {str(exc)[:900]}",
        )
    return VerificationCheckResult(
        check_id=check_id,
        status=VerificationCheckStatus.PASSED,
        duration_ms=max(0, int((time.monotonic() - started) * 1000)),
        details="fixed normal-behavior check passed",
    )


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def run_functional_checks() -> tuple[bool, str, int, tuple[VerificationCheckResult, ...]]:
    """Run the same checks as M14 and expose per-check outcomes without extra HTTP work."""
    started = time.monotonic()
    results: list[VerificationCheckResult] = []

    with httpx.Client(base_url=BASE_URL, follow_redirects=False, timeout=5.0) as client:
        operations: tuple[tuple[str, Callable[[], None]], ...] = (
            ("health", lambda: _health(client)),
            ("normal_login", lambda: _normal_login(client)),
            ("normal_search", lambda: _normal_search(client)),
            ("document_listing", lambda: _document_listing(client)),
            ("document_download", lambda: _document_download(client)),
            ("scenario_sqli_normal_login", lambda: _scenario_sqli(client)),
            ("scenario_xss_normal_display", lambda: _scenario_xss(client)),
            ("scenario_path_public_read", lambda: _scenario_path(client)),
        )
        for index, (check_id, operation) in enumerate(operations):
            result = _check(check_id, operation)
            results.append(result)
            if result.status == VerificationCheckStatus.FAILED:
                for pending_id, _ in operations[index + 1 :]:
                    results.append(VerificationCheckResult(
                        check_id=pending_id,
                        status=VerificationCheckStatus.NOT_RUN,
                        duration_ms=0,
                        details="not run because an earlier fixed functional check failed",
                    ))
                duration_ms = max(0, int((time.monotonic() - started) * 1000))
                return False, f"functional verification failed: {result.details}", duration_ms, tuple(results)

    return (
        True,
        "fixed normal-behavior HTTP checks passed inside controlled-executor",
        max(0, int((time.monotonic() - started) * 1000)),
        tuple(results),
    )


def _health(client: httpx.Client) -> None:
    response = client.get("/health")
    _require(response.status_code == 200, "health endpoint returned non-200")
    _require(response.json().get("status") == "ok", "health payload is not ok")


def _normal_login(client: httpx.Client) -> None:
    response = client.post("/login", json={"username": "student1", "password": "demo-pass-1"})
    _require(response.status_code == 200, "normal login failed")
    _require(response.json().get("authenticated") is True, "normal login was not authenticated")


def _normal_search(client: httpx.Client) -> None:
    response = client.get("/search", params={"q": "Notebook"})
    _require(response.status_code == 200, "normal search failed")
    _require(any(item.get("name") == "Web Testing Notebook" for item in response.json()), "expected product missing from normal search")


def _document_listing(client: httpx.Client) -> None:
    response = client.get("/documents")
    _require(response.status_code == 200 and len(response.json()) >= 2, "document listing failed")


def _document_download(client: httpx.Client) -> None:
    response = client.get("/files/1")
    _require(response.status_code == 200 and "Welcome" in response.text, "document download failed")


def _scenario_sqli(client: httpx.Client) -> None:
    response = client.post("/scenarios/sql-injection/login", json={"username": "student1", "password": "demo-pass-1"})
    _require(response.status_code == 200, "normal SQLi-scenario login failed")
    _require(response.json().get("authenticated") is True, "normal SQLi-scenario login was not authenticated")


def _scenario_xss(client: httpx.Client) -> None:
    response = client.get("/scenarios/xss/search", params={"q": "notebook"})
    _require(response.status_code == 200, "normal XSS-scenario display failed")
    _require("Search term: notebook" in response.text, "normal XSS-scenario content changed")


def _scenario_path(client: httpx.Client) -> None:
    response = client.get("/scenarios/path-traversal/read", params={"path": "guide.txt"})
    _require(response.status_code == 200, "normal path-scenario read failed")
    _require("Public scenario guide" in response.text, "normal public file content changed")


def main() -> None:
    passed, details, duration_ms, checks = run_functional_checks()
    print(json.dumps({
        "passed": passed,
        "details": details,
        "duration_ms": duration_ms,
        "checks": [item.model_dump(mode="json") for item in checks],
    }))
    raise SystemExit(0 if passed else 2)


if __name__ == "__main__":
    main()
