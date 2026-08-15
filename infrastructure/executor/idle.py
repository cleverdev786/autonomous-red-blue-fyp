"""Idle process for the Milestone 5 controlled-executor container.

The actual deterministic security-test harness is implemented in a later
milestone. This process intentionally exposes no command interface and performs
no attack activity.
"""

from __future__ import annotations

import time


def main() -> None:
    print("Controlled executor container ready; security harness not enabled yet.", flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
