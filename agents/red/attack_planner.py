"""Red Team planning that may select only a registered test option."""

from __future__ import annotations

import json
from collections.abc import Mapping
from hashlib import sha256
from typing import Any

from agents.base import TypedReasoningAgent
from schemas.common import AgentRole
from schemas.red_team import (
    AttackPlan,
    AttackPlanningCatalog,
    PlanningWork,
    ReconnaissanceResult,
    RedStandardAuthorization,
)
from schemas.red_team_state import (
    CoverageGapDTO,
    OperationDTO,
    PlanningDecisionDTO,
    PlanVersionDTO,
)


class AttackPlanningAgent(TypedReasoningAgent[AttackPlan]):
    """Recommend one already-approved registered security-test ID."""

    role = AgentRole.RED_ATTACK_PLANNER
    output_model = AttackPlan

    @staticmethod
    def prepare_input(
        *,
        reconnaissance: ReconnaissanceResult,
        catalog: AttackPlanningCatalog,
    ) -> Mapping[str, Any]:
        return {
            "reconnaissance": reconnaissance.model_dump(mode="json"),
            "planning_catalog": catalog.model_dump(mode="json"),
        }


class DeterministicAttackPlanner:
    """Match candidates to trusted descriptors without a provider or side effect."""

    @staticmethod
    def _digest(value: object) -> str:
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"))
        return sha256(canonical.encode("utf-8")).hexdigest()

    def plan(
        self,
        *,
        work: PlanningWork,
        catalog: AttackPlanningCatalog,
        authorization: RedStandardAuthorization,
    ) -> PlanningDecisionDTO:
        work = PlanningWork.model_validate(work.model_dump())
        catalog = AttackPlanningCatalog.model_validate(catalog.model_dump())
        authorization = RedStandardAuthorization.model_validate(authorization.model_dump())
        if work.scope != authorization.scope or catalog.target_id != work.scope.target_id:
            raise ValueError("planning scope does not match authorization")
        if any(option.target_id != catalog.target_id for option in catalog.options):
            raise ValueError("planning catalog contains a foreign target")
        trusted_ids = tuple(sorted(option.test_id for option in catalog.options))
        if tuple(sorted(work.vetted_test_ids)) != trusted_ids:
            raise ValueError("planning template set differs from trusted catalog")

        candidates = tuple(
            sorted(
                work.candidates,
                key=lambda item: (
                    item.path,
                    item.method.value,
                    item.parameter_names,
                    item.candidate_id,
                ),
            )
        )
        templates = tuple(sorted(catalog.options, key=lambda item: item.test_id))
        digest = self._digest(
            {
                "scope": work.scope.model_dump(mode="json"),
                "surface_revision": work.surface_revision,
                "candidates": [item.model_dump(mode="json") for item in candidates],
                "templates": [item.model_dump(mode="json") for item in templates],
            }
        )
        plan_version = f"plan-{digest[:20]}"
        operations: list[OperationDTO] = []
        gaps: list[CoverageGapDTO] = []
        requests = 0
        runtime_seconds = 0

        for candidate in candidates:
            if candidate.path.startswith(("/admin", "/auth")):
                gaps.append(
                    self._gap(
                        work,
                        candidate.candidate_id,
                        "authentication_required",
                        "Provide an approved authenticated route before testing this candidate.",
                    )
                )
                continue
            path_templates = tuple(item for item in templates if item.path == candidate.path)
            method_templates = tuple(
                item for item in path_templates if item.method == candidate.method
            )
            compatible = tuple(
                item
                for item in method_templates
                if set(candidate.parameter_names).issubset(item.allowed_parameter_names)
            )
            if not path_templates:
                gaps.append(
                    self._gap(
                        work,
                        candidate.candidate_id,
                        "no_template",
                        "Add a vetted template before testing this candidate.",
                    )
                )
                continue
            if not method_templates:
                gaps.append(
                    self._gap(
                        work,
                        candidate.candidate_id,
                        "method_out_of_scope",
                        "Use only the method registered for this endpoint.",
                    )
                )
                continue
            if not compatible:
                gaps.append(
                    self._gap(
                        work,
                        candidate.candidate_id,
                        "no_template",
                        "Register a template compatible with the observed parameters.",
                    )
                )
                continue
            for template in compatible:
                if template.method not in authorization.allowed_methods:
                    gaps.append(
                        self._gap(
                            work,
                            candidate.candidate_id,
                            "method_out_of_scope",
                            "Authorize this registered HTTP method in a new assessment.",
                            test_id=template.test_id,
                        )
                    )
                    continue
                if template.vulnerability_class not in authorization.allowed_classes:
                    gaps.append(
                        self._gap(
                            work,
                            candidate.candidate_id,
                            "unsupported_class",
                            "Authorize this registered vulnerability class in a new assessment.",
                            test_id=template.test_id,
                        )
                    )
                    continue
                cost = template.resource_cost.max_requests
                if (
                    len(operations) >= authorization.budget.max_tests
                    or requests + cost > authorization.budget.max_http_requests
                    or runtime_seconds + template.resource_cost.timeout_seconds
                    > authorization.budget.max_runtime_seconds
                ):
                    gaps.append(
                        self._gap(
                            work,
                            candidate.candidate_id,
                            "budget_exhausted",
                            "Replan under a fresh explicitly approved Standard budget.",
                            test_id=template.test_id,
                        )
                    )
                    continue
                operation_digest = self._digest(
                    {
                        "plan": plan_version,
                        "candidate": candidate.candidate_id,
                        "test": template.test_id,
                    }
                )
                operations.append(
                    OperationDTO(
                        scope=work.scope,
                        operation_id=f"op-{operation_digest[:20]}",
                        plan_version=plan_version,
                        candidate_id=candidate.candidate_id,
                        test_id=template.test_id,
                        status="proposed",
                    )
                )
                requests += cost
                runtime_seconds += template.resource_cost.timeout_seconds

        return PlanningDecisionDTO(
            plan=PlanVersionDTO(
                scope=work.scope,
                plan_version=plan_version,
                surface_revision=work.surface_revision,
                status="approved",
                plan_digest=digest,
            ),
            operations=tuple(operations),
            coverage_gaps=tuple(gaps),
        )

    def _gap(
        self,
        work: PlanningWork,
        candidate_id: str,
        reason: str,
        recommendation: str,
        *,
        test_id: str | None = None,
    ) -> CoverageGapDTO:
        digest = self._digest(
            {
                "surface": work.surface_revision,
                "candidate": candidate_id,
                "test": test_id,
                "reason": reason,
            }
        )
        return CoverageGapDTO(
            scope=work.scope,
            gap_id=f"gap-{digest[:20]}",
            reason=reason,
            surface_revision=work.surface_revision,
            candidate_id=candidate_id,
            test_id=test_id,
            recommendation=recommendation,
        )
