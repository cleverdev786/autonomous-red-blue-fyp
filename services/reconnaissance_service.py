"""Trusted bounded metadata views for Red Team reconnaissance and planning."""

from __future__ import annotations

from schemas.red_team import (
    AttackPlanningCatalog,
    ReconnaissanceEndpoint,
    RegisteredTestOption,
    RestrictedReconnaissanceContext,
)
from services.target_registry import TargetRegistry


class ReconnaissanceService:
    """Project trusted registry data into narrowly scoped Red Team inputs."""

    def __init__(self, *, registry: TargetRegistry) -> None:
        self.registry = registry

    def build_reconnaissance_context(
        self,
        *,
        target_id: str,
    ) -> RestrictedReconnaissanceContext:
        """Expose approved surface metadata only, with no attack strategy data."""
        target = self.registry.get_target(target_id)
        endpoints = tuple(
            ReconnaissanceEndpoint(
                endpoint_id=endpoint.endpoint_id,
                allowed_methods=endpoint.allowed_methods,
                input_fields=endpoint.input_fields,
            )
            for endpoint in target.endpoints
        )
        return RestrictedReconnaissanceContext(
            target_id=target.target_id,
            endpoints=endpoints,
        )

    def build_attack_planning_catalog(
        self,
        *,
        target_id: str,
    ) -> AttackPlanningCatalog:
        """Expose only metadata needed to select an already-registered test."""
        target = self.registry.get_target(target_id)
        options = tuple(
            self._registered_option(test_id)
            for test_id in sorted(target.allowed_test_ids)
        )
        return AttackPlanningCatalog(
            target_id=target.target_id,
            options=options,
        )

    def _registered_option(self, test_id: str) -> RegisteredTestOption:
        metadata = self.registry.get_security_test(test_id)
        return RegisteredTestOption(
            test_id=metadata.test_id,
            vulnerability_class=metadata.vulnerability_class,
            endpoint_id=metadata.endpoint_id,
            allowed_parameter_names=metadata.allowed_parameter_names,
            safe_description=metadata.description,
        )
