"""Human-controlled target and security-test registry.

The registry is the source of truth for which local application resources may
be used by later controlled security execution.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from schemas.targets import SecurityTestDefinition, TargetDefinition


class TargetRegistryError(RuntimeError):
    """Base error for invalid or inconsistent trusted registry configuration."""


class UnknownTargetError(TargetRegistryError):
    """Raised when code requests a target that is not registered."""


class UnknownSecurityTestError(TargetRegistryError):
    """Raised when code requests a security test that is not registered."""


class RegistryConfigurationError(TargetRegistryError):
    """Raised when trusted registry files are internally inconsistent."""


class TargetRegistry:
    """Immutable in-memory view of trusted target/test definitions."""

    def __init__(
        self,
        *,
        targets: Iterable[TargetDefinition],
        security_tests: Iterable[SecurityTestDefinition],
    ) -> None:
        target_map: dict[str, TargetDefinition] = {}
        test_map: dict[str, SecurityTestDefinition] = {}

        for target in targets:
            if target.target_id in target_map:
                raise RegistryConfigurationError(
                    f"duplicate target_id: {target.target_id}"
                )
            target_map[target.target_id] = target

        for security_test in security_tests:
            if security_test.test_id in test_map:
                raise RegistryConfigurationError(
                    f"duplicate test_id: {security_test.test_id}"
                )
            test_map[security_test.test_id] = security_test

        self._targets = target_map
        self._security_tests = test_map
        self._validate_cross_references()

    @classmethod
    def from_directories(
        cls,
        *,
        targets_dir: Path,
        security_tests_dir: Path,
    ) -> "TargetRegistry":
        """Load strict JSON definitions from trusted human-controlled folders."""
        target_paths = sorted(targets_dir.glob("*.json"))
        security_test_paths = sorted(security_tests_dir.glob("*.json"))

        if not target_paths:
            raise RegistryConfigurationError(
                f"no target definitions found in {targets_dir}"
            )
        if not security_test_paths:
            raise RegistryConfigurationError(
                f"no security-test definitions found in {security_tests_dir}"
            )

        targets = [
            TargetDefinition.model_validate_json(path.read_text(encoding="utf-8"))
            for path in target_paths
        ]
        security_tests = [
            SecurityTestDefinition.model_validate_json(
                path.read_text(encoding="utf-8")
            )
            for path in security_test_paths
        ]

        return cls(targets=targets, security_tests=security_tests)

    def _validate_cross_references(self) -> None:
        for target in self._targets.values():
            endpoint_map = {
                endpoint.endpoint_id: endpoint
                for endpoint in target.endpoints
            }

            for allowed_test_id in target.allowed_test_ids:
                security_test = self._security_tests.get(allowed_test_id)
                if security_test is None:
                    raise RegistryConfigurationError(
                        f"target {target.target_id!r} references unknown "
                        f"test {allowed_test_id!r}"
                    )
                if security_test.target_id != target.target_id:
                    raise RegistryConfigurationError(
                        f"test {security_test.test_id!r} points to target "
                        f"{security_test.target_id!r}, not {target.target_id!r}"
                    )

                endpoint = endpoint_map.get(security_test.endpoint_id)
                if endpoint is None:
                    raise RegistryConfigurationError(
                        f"test {security_test.test_id!r} references unknown "
                        f"endpoint {security_test.endpoint_id!r}"
                    )
                if security_test.method not in endpoint.allowed_methods:
                    raise RegistryConfigurationError(
                        f"test {security_test.test_id!r} method "
                        f"{security_test.method.value!r} is not allowed by "
                        f"endpoint {endpoint.endpoint_id!r}"
                    )

                endpoint_fields = set(endpoint.input_fields)
                test_fields = set(security_test.allowed_parameter_names)
                if not test_fields.issubset(endpoint_fields):
                    raise RegistryConfigurationError(
                        f"test {security_test.test_id!r} contains parameters "
                        f"not declared by endpoint {endpoint.endpoint_id!r}"
                    )

        for security_test in self._security_tests.values():
            target = self._targets.get(security_test.target_id)
            if target is None:
                raise RegistryConfigurationError(
                    f"test {security_test.test_id!r} references unknown target "
                    f"{security_test.target_id!r}"
                )
            if security_test.test_id not in target.allowed_test_ids:
                raise RegistryConfigurationError(
                    f"test {security_test.test_id!r} is not included in "
                    f"target {target.target_id!r} allowed_test_ids"
                )

    def get_target(self, target_id: str) -> TargetDefinition:
        """Return one registered target or fail closed."""
        try:
            return self._targets[target_id]
        except KeyError as exc:
            raise UnknownTargetError(f"unknown target_id: {target_id}") from exc

    def get_endpoint(self, target_id: str, endpoint_id: str):
        """Return one endpoint registered under a known target."""
        target = self.get_target(target_id)
        for endpoint in target.endpoints:
            if endpoint.endpoint_id == endpoint_id:
                return endpoint
        raise TargetRegistryError(
            f"unknown endpoint_id {endpoint_id!r} for target {target_id!r}"
        )

    def get_security_test(self, test_id: str) -> SecurityTestDefinition:
        """Return one registered security test or fail closed."""
        try:
            return self._security_tests[test_id]
        except KeyError as exc:
            raise UnknownSecurityTestError(f"unknown test_id: {test_id}") from exc

    def list_targets(self) -> tuple[TargetDefinition, ...]:
        """Return registered targets in deterministic ID order."""
        return tuple(self._targets[key] for key in sorted(self._targets))

    def list_security_tests(self) -> tuple[SecurityTestDefinition, ...]:
        """Return registered tests in deterministic ID order."""
        return tuple(
            self._security_tests[key]
            for key in sorted(self._security_tests)
        )
