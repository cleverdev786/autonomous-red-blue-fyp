"""Trusted bounded metadata views for Red Team reconnaissance and planning."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256

from pydantic import BaseModel, ConfigDict, Field

from schemas.common import HttpMethod
from schemas.red_team import (
    AttackPlanningCatalog,
    ReconnaissanceEndpoint,
    ReconnaissancePreview,
    ReconnaissancePreviewCandidate,
    ReconnaissancePreviewLimitation,
    RedEndpointCandidate,
    RedPolicyUsage,
    RedScopeReference,
    RedStandardAuthorization,
    RegisteredTestOption,
    RestrictedReconnaissanceContext,
)
from schemas.targets import TargetDefinition
from services.red_assessment_store import RedAssessmentStore, StoreConflict
from services.red_evidence_store import RedEvidenceStore
from services.target_registry import TargetRegistry, TargetRegistryError
from services.zap_adapter import ZapAdapter, ZapBudget


class ReconnaissanceService:
    """Project trusted registry data into narrowly scoped Red Team inputs."""

    def __init__(self, *, registry: TargetRegistry) -> None:
        self.registry = registry

    def map_zap_observations(
        self,
        *,
        target_id: str,
        observations: Iterable[ZapObservation],
        observed_at: datetime,
    ) -> ReconMapping:
        """Only classify passive observations, never authorize an operation."""
        return _map_zap_observations(
            self.registry,
            target_id,
            observations,
            observed_at,
        )

    def collect_registered_zap(
        self,
        *,
        adapter: ZapAdapter,
        authorization: RedStandardAuthorization,
        endpoint_ids: Iterable[str],
        budget: ZapBudget,
        usage: RedPolicyUsage,
        observed_at: datetime,
    ) -> ReconMapping:
        """Bounded registered GET seeding, not a spider or active scan."""
        requested = tuple(endpoint_ids)
        ids = tuple(dict.fromkeys(requested))
        if (
            not requested
            or len(requested) > budget.max_urls
            or len(ids) > authorization.budget.max_crawl_requests
            or usage.http_requests + len(ids) > authorization.budget.max_http_requests
            or usage.crawl_requests + len(ids) > authorization.budget.max_crawl_requests
            or len(ids) * budget.duration_seconds + usage.elapsed_seconds
            > authorization.budget.max_runtime_seconds
        ):
            raise ValueError("reconnaissance budget exceeded")
        if authorization.scope.target_id not in {
            target.target_id for target in self.registry.list_targets()
        }:
            raise ValueError("unregistered target")
        if observed_at.tzinfo is None:
            raise ValueError("timezone-aware timestamp required")
        for endpoint_id in ids:
            try:
                endpoint = self.registry.get_endpoint(authorization.scope.target_id, endpoint_id)
            except TargetRegistryError as exc:
                raise ValueError("unregistered reconnaissance endpoint") from exc
            if (
                HttpMethod.GET not in endpoint.allowed_methods
                or "{" in endpoint.path
                or "}" in endpoint.path
            ):
                raise ValueError("only concrete registered GET endpoints may be seeded")
        observations = []
        for index, endpoint_id in enumerate(ids):
            snapshot = RedPolicyUsage.model_validate(
                {
                    **usage.model_dump(),
                    "http_requests": usage.http_requests + index,
                    "crawl_requests": usage.crawl_requests + index,
                }
            )
            if not adapter.seed(
                authorization,
                target_id=authorization.scope.target_id,
                endpoint_id=endpoint_id,
                budget=budget,
                usage=snapshot,
            ):
                raise ValueError("registered ZAP GET not observed")
            endpoint = self.registry.get_endpoint(authorization.scope.target_id, endpoint_id)
            observations.append(ZapObservation(path=endpoint.path, method="GET"))
        return self.map_zap_observations(
            target_id=authorization.scope.target_id,
            observations=observations,
            observed_at=observed_at,
        )

    def persist_mapping(
        self,
        *,
        mapping: ReconMapping,
        scope: RedScopeReference,
        store: RedAssessmentStore,
        journal: RedEvidenceStore,
    ) -> None:
        """Scope-check and append sanitized recon observations/events for restart."""
        snapshot, authorization = store.load(scope.assessment_id)
        if (
            snapshot.assessment.scope != scope
            or authorization.scope != scope
            or mapping.target_id != scope.target_id
            or snapshot.assessment.status.value != "running"
        ):
            raise StoreConflict("reconnaissance scope or state mismatch")
        existing = {item.candidate_id: item for item in snapshot.candidates}
        for entry in mapping.candidates:
            prior = existing.get(entry.candidate.candidate_id)
            if prior is not None and prior.model_dump(
                exclude={"observed_at"}
            ) != entry.candidate.model_dump(exclude={"observed_at"}):
                raise StoreConflict("conflicting reconnaissance candidate")
        previous = {item["event_id"]: item for item in journal.list_events(scope)}
        for event in mapping.events:
            saved = previous.get(event.event_id)
            if saved is not None and (
                saved["action"] != event.action
                or saved["actor"] != "red_reconnaissance"
                or saved["outcome"] != "observed"
            ):
                raise StoreConflict("conflicting reconnaissance event")
        for event in mapping.events:
            if event.action == "recon_completed":
                for entry in mapping.candidates:
                    if entry.candidate.candidate_id not in existing:
                        try:
                            store.add_candidate(scope.assessment_id, entry.candidate)
                        except StoreConflict:
                            fresh, _ = store.load(scope.assessment_id)
                            if entry.candidate not in fresh.candidates:
                                raise
            if event.event_id not in previous:
                journal.append_event(
                    scope,
                    event.event_id,
                    actor="red_reconnaissance",
                    action=event.action,
                    outcome="observed",
                    details={
                        "stage": "reconnaissance",
                        "status": "completed" if event.action == "recon_completed" else "started",
                    },
                    occurred_at=mapping.observed_at,
                )

    def build_preview(
        self,
        *,
        authorization: RedStandardAuthorization,
        candidates: Iterable[RedEndpointCandidate],
    ) -> ReconnaissancePreview:
        """Reclassify stored candidates against the current trusted registry."""
        scope = authorization.scope
        target = self.registry.get_target(scope.target_id)
        if sha256(target.model_dump_json().encode("utf-8")).hexdigest() != (
            scope.target_fingerprint
        ):
            raise ValueError("registered target fingerprint changed")
        entries: list[ReconnaissancePreviewCandidate] = []
        limitations: dict[tuple[str, str], ReconnaissancePreviewLimitation] = {}
        for candidate in candidates:
            names = tuple(candidate.parameter_names)
            _validate_path(candidate.path, names)
            if candidate.method not in authorization.allowed_methods:
                status, endpoint_id, reason = ("unsupported", None, "method_out_of_scope")
            else:
                status, endpoint_id, reason = _classify_observation(
                    target, candidate.method.value, candidate.path, names
                )
            entries.append(
                ReconnaissancePreviewCandidate(
                    candidate=candidate,
                    policy_status=status,
                    registered_endpoint_id=endpoint_id,
                )
            )
            if reason is not None:
                limitations[(candidate.path, reason)] = ReconnaissancePreviewLimitation(
                    path=candidate.path,
                    reason=reason,
                )
        return ReconnaissancePreview(
            scope=scope,
            candidates=tuple(entries),
            limitations=tuple(limitations[key] for key in sorted(limitations)),
        )

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
            self._registered_option(test_id) for test_id in sorted(target.allowed_test_ids)
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


class ZapObservation(BaseModel):
    """Untrusted passive observation, never an approved endpoint action."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1, max_length=500)
    method: str = Field(default="GET", min_length=1, max_length=12)
    parameter_names: tuple[str, ...] = Field(default=(), max_length=16)


@dataclass(frozen=True)
class ReconCandidateEntry:
    candidate: RedEndpointCandidate
    admission_status: str
    registered_endpoint_id: str | None = None


@dataclass(frozen=True)
class ReconLimitation:
    path: str
    reason: str


@dataclass(frozen=True)
class ReconEvent:
    event_id: str
    action: str


@dataclass(frozen=True)
class ReconMapping:
    target_id: str
    observed_at: datetime
    candidates: tuple[ReconCandidateEntry, ...]
    limitations: tuple[ReconLimitation, ...]
    events: tuple[ReconEvent, ...]


def _recon_id(*values: str) -> str:
    return sha256("\x1f".join(values).encode("utf-8")).hexdigest()[:20]


def _validate_path(path: str, names: tuple[str, ...]) -> None:
    if (
        not path.startswith("/")
        or path.startswith("//")
        or any(token in path for token in ("\\", "%", "?", "#", "//"))
        or ".." in path.split("/")
        or any(ord(c) < 32 or ord(c) > 126 for c in path)
        or any(not name.isidentifier() or name.startswith("_") or len(name) > 64 for name in names)
    ):
        raise ValueError("unsafe passive observation")


def _classify_observation(
    target: TargetDefinition,
    method: str,
    path: str,
    names: tuple[str, ...],
) -> tuple[str, str | None, str | None]:
    if method not in {"GET", "POST"}:
        return "unsupported", None, "method_out_of_scope"
    endpoint = next(
        (
            item
            for item in target.endpoints
            if item.path == path
            and HttpMethod(method) in item.allowed_methods
            and set(names).issubset(item.input_fields)
        ),
        None,
    )
    if endpoint is not None:
        return "candidate_only", endpoint.endpoint_id, None
    reason = "authentication_required" if path.startswith(("/admin", "/auth")) else "no_template"
    return "unsupported", None, reason


def _map_zap_observations(
    registry: TargetRegistry,
    target_id: str,
    observations: Iterable[ZapObservation],
    observed_at: datetime,
) -> ReconMapping:
    target = registry.get_target(target_id)
    if observed_at.tzinfo is None:
        raise ValueError("timezone-aware observation timestamp required")
    values = tuple(observations)
    if len(values) > 12:
        raise ValueError("passive observation cap exceeded")
    candidates: dict[str, ReconCandidateEntry] = {}
    limitations: dict[tuple[str, str], ReconLimitation] = {}
    for raw in values:
        obs = ZapObservation.model_validate(raw.model_dump())
        names = tuple(sorted(set(obs.parameter_names)))
        _validate_path(obs.path, names)
        status, endpoint_id, reason = _classify_observation(target, obs.method, obs.path, names)
        if reason == "method_out_of_scope":
            limitations[(obs.path, "method_out_of_scope")] = ReconLimitation(
                obs.path, "method_out_of_scope"
            )
            continue
        if reason is not None:
            limitations[(obs.path, reason)] = ReconLimitation(obs.path, reason)
        candidate_id = "zap-" + _recon_id(target_id, obs.method, obs.path, ",".join(names))
        candidate = RedEndpointCandidate(
            candidate_id=candidate_id,
            method=obs.method,
            path=obs.path,
            parameter_names=names,
            source="zap",
            observed_at=observed_at,
        )
        candidates[candidate_id] = ReconCandidateEntry(
            candidate=candidate,
            admission_status=status,
            registered_endpoint_id=endpoint_id,
        )
    signature = _recon_id(
        target_id,
        observed_at.isoformat(),
        *(sorted(candidates) + [f"{p}:{r}" for p, r in sorted(limitations)]),
    )
    events = tuple(
        ReconEvent(event_id="recon-" + _recon_id(signature, action), action=action)
        for action in ("recon_started", "recon_completed")
    )
    return ReconMapping(
        target_id=target_id,
        observed_at=observed_at,
        candidates=tuple(sorted(candidates.values(), key=lambda item: item.candidate.candidate_id)),
        limitations=tuple(sorted(limitations.values(), key=lambda item: (item.path, item.reason))),
        events=events,
    )
