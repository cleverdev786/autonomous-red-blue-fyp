"""Trusted regression allowlist validation helpers."""

from __future__ import annotations

from schemas.verification import VerificationPolicyConfig


def required_regression_tests(policy: VerificationPolicyConfig) -> tuple[str, ...]:
    """Return the already-schema-validated frozen regression allowlist."""
    return policy.required_regression_tests
