"""Code-defined security-test registry.

The JSON registry authorizes which tests may exist. This module maps those
authorized IDs to deterministic Python implementations.
"""

from __future__ import annotations

from security_tests.base import RegisteredSecurityTest
from security_tests.path_traversal.private_file import PathTraversalPrivateFileTest
from security_tests.sql_injection.login_bypass import SqlInjectionLoginBypassTest
from security_tests.xss.reflection import XssReflectionTest
from services.target_registry import TargetRegistry


class SecurityTestImplementationError(RuntimeError):
    """Raised when trusted test metadata and code implementations disagree."""


class SecurityTestRegistry:
    """Deterministic mapping from registered IDs to fixed implementations."""

    def __init__(self, tests: tuple[RegisteredSecurityTest, ...]) -> None:
        mapping: dict[str, RegisteredSecurityTest] = {}
        for test in tests:
            if test.test_id in mapping:
                raise SecurityTestImplementationError(
                    f"duplicate security-test implementation: {test.test_id}"
                )
            mapping[test.test_id] = test
        self._tests = mapping

    @classmethod
    def default(cls) -> "SecurityTestRegistry":
        return cls(
            (
                SqlInjectionLoginBypassTest(),
                XssReflectionTest(),
                PathTraversalPrivateFileTest(),
            )
        )

    def get(self, test_id: str) -> RegisteredSecurityTest:
        try:
            return self._tests[test_id]
        except KeyError as exc:
            raise SecurityTestImplementationError(
                f"no code implementation for test_id: {test_id}"
            ) from exc

    def validate_against_target_registry(
        self,
        target_registry: TargetRegistry,
    ) -> None:
        metadata_ids = {
            item.test_id
            for item in target_registry.list_security_tests()
        }
        implementation_ids = set(self._tests)

        if metadata_ids != implementation_ids:
            missing_code = sorted(metadata_ids - implementation_ids)
            extra_code = sorted(implementation_ids - metadata_ids)
            raise SecurityTestImplementationError(
                "security-test metadata/code mismatch; "
                f"missing_code={missing_code}, extra_code={extra_code}"
            )
