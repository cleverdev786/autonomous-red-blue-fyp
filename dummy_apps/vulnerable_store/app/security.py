"""Tiny deterministic password helpers for synthetic demo users.

These helpers are intentionally simple because the application contains only
fabricated local data. They are not a recommendation for production password
storage.
"""

from __future__ import annotations

import hashlib
import hmac


_DEMO_NAMESPACE = b"fyp-vulnerable-store-baseline"


def hash_demo_password(password: str) -> str:
    """Hash one synthetic password deterministically for seeded fixtures."""
    return hashlib.sha256(_DEMO_NAMESPACE + password.encode("utf-8")).hexdigest()


def verify_demo_password(password: str, expected_hash: str) -> bool:
    """Constant-time comparison for the synthetic seeded password."""
    supplied_hash = hash_demo_password(password)
    return hmac.compare_digest(supplied_hash, expected_hash)
