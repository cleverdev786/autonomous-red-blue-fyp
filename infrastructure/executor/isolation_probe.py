"""Runtime isolation probe for the controlled-executor container.

This check is intentionally hard-coded. It is not a generic URL-fetching tool.

Expected behavior:
1. the internal dummy app is reachable;
2. a public internet HTTP destination is not reachable.

Run only inside the controlled-executor container.
"""

from __future__ import annotations

import json
from urllib.error import URLError
from urllib.request import urlopen


INTERNAL_HEALTH_URL = "http://vulnerable-store:8000/health"
PUBLIC_PROBE_URL = "http://example.com/"


def verify_internal_app() -> None:
    with urlopen(INTERNAL_HEALTH_URL, timeout=3) as response:  # noqa: S310 - fixed lab URL
        if response.status != 200:
            raise RuntimeError(f"Internal app returned HTTP {response.status}.")
        payload = json.loads(response.read().decode("utf-8"))
        if payload.get("status") != "ok":
            raise RuntimeError("Internal app health payload is invalid.")


def verify_public_internet_blocked() -> None:
    try:
        with urlopen(PUBLIC_PROBE_URL, timeout=3):  # noqa: S310 - fixed negative probe URL
            pass
    except (OSError, URLError, TimeoutError):
        return

    raise RuntimeError(
        "Public internet was reachable from controlled-executor; isolation FAILED."
    )


def main() -> None:
    verify_internal_app()
    print("PASS: controlled-executor can reach vulnerable-store on the lab network.")

    verify_public_internet_blocked()
    print("PASS: public internet is blocked from controlled-executor.")


if __name__ == "__main__":
    main()
