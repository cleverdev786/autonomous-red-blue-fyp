"""Fixed normal-behavior checks executed only inside controlled-executor."""

from __future__ import annotations

import json
import time

import httpx


BASE_URL = "http://vulnerable-store:8000"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def run_functional_checks() -> tuple[bool, str, int]:
    """Run the same bounded normal-behavior checks for every patch condition."""
    started = time.monotonic()
    try:
        with httpx.Client(base_url=BASE_URL, follow_redirects=False, timeout=5.0) as client:
            health = client.get("/health")
            _require(health.status_code == 200, "health endpoint returned non-200")
            _require(health.json().get("status") == "ok", "health payload is not ok")

            login = client.post(
                "/login",
                json={"username": "student1", "password": "demo-pass-1"},
            )
            _require(login.status_code == 200, "normal login failed")
            _require(login.json().get("authenticated") is True, "normal login was not authenticated")

            search = client.get("/search", params={"q": "Notebook"})
            _require(search.status_code == 200, "normal search failed")
            _require(
                any(item.get("name") == "Web Testing Notebook" for item in search.json()),
                "expected product missing from normal search",
            )

            docs = client.get("/documents")
            _require(docs.status_code == 200 and len(docs.json()) >= 2, "document listing failed")
            download = client.get("/files/1")
            _require(download.status_code == 200 and "Welcome" in download.text, "document download failed")

            normal_sqli = client.post(
                "/scenarios/sql-injection/login",
                json={"username": "student1", "password": "demo-pass-1"},
            )
            _require(normal_sqli.status_code == 200, "normal SQLi-scenario login failed")
            _require(
                normal_sqli.json().get("authenticated") is True,
                "normal SQLi-scenario login was not authenticated",
            )

            normal_xss = client.get("/scenarios/xss/search", params={"q": "notebook"})
            _require(normal_xss.status_code == 200, "normal XSS-scenario display failed")
            _require("Search term: notebook" in normal_xss.text, "normal XSS-scenario content changed")

            normal_path = client.get(
                "/scenarios/path-traversal/read",
                params={"path": "guide.txt"},
            )
            _require(normal_path.status_code == 200, "normal path-scenario read failed")
            _require("Public scenario guide" in normal_path.text, "normal public file content changed")
    except Exception as exc:
        return False, f"functional verification failed: {type(exc).__name__}: {str(exc)[:1000]}", max(
            0, int((time.monotonic() - started) * 1000)
        )
    return True, "fixed normal-behavior HTTP checks passed inside controlled-executor", max(
        0, int((time.monotonic() - started) * 1000)
    )


def main() -> None:
    passed, details, duration_ms = run_functional_checks()
    print(json.dumps({"passed": passed, "details": details, "duration_ms": duration_ms}))
    raise SystemExit(0 if passed else 2)


if __name__ == "__main__":
    main()
