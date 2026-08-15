"""Health check proving the executor can reach only the lab app path it needs."""

from __future__ import annotations

import json
from urllib.request import urlopen


HEALTH_URL = "http://vulnerable-store:8000/health"


def main() -> None:
    with urlopen(HEALTH_URL, timeout=3) as response:  # noqa: S310 - fixed local lab URL
        if response.status != 200:
            raise SystemExit(f"Unexpected health status: {response.status}")
        payload = json.loads(response.read().decode("utf-8"))

    if payload.get("status") != "ok":
        raise SystemExit("Dummy application health response is not ok.")


if __name__ == "__main__":
    main()
