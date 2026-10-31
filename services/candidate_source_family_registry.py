"""Non-live, hash-pinned candidate-test registration for source-family qualification.

This is NOT TargetRegistry registration, ControlledExecutor authority, Docker
admission, model evaluation, source-patch admission, or final research approval.
Always require an external manifest/protocol SHA-256 and recheck the sealed
bundle before selecting an OFFLINE review record.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from schemas.rq2_dataset import RQ2ClassificationDecision
from scripts.prepare_source_family_holdout import (
    PROTOCOL,
    RECIPES,
    REPO,
    SourceFamilyBlocked,
    canonical,
    read_strict,
    sha,
    verify,
)
from services.target_registry import TargetRegistry

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_TRUSTED_REGISTRY_ROOT = REPO / "config"
_CLASSES = {
    "spectrometry": "sql_injection",
    "weatherbeacon": "xss",
    "magnetometry": "path_traversal",
}
_TEST_IDS = {
    "spectrometry": "sfh-spectrometry-read-v1",
    "weatherbeacon": "sfh-weatherbeacon-caption-v1",
    "magnetometry": "sfh-magnetometry-record-v1",
}
_SUPPORTED = frozenset(_CLASSES)
_DENIED_ACTION = (
    "Candidate-only evaluation has no live source, patch, container, or executor authority."
)


class CandidateAdmissionDenied(RuntimeError):
    """Incomplete or mismatched candidate registration; no escalation allowed."""


@dataclass(frozen=True, slots=True)
class CandidateTestRegistration:
    """One exact offline test identity, not a live registered security test."""

    test_id: str
    source_family: str
    vulnerability_class: str
    endpoint: str
    method: Literal["GET"]
    input_field: str
    source_sha256: str
    source_excerpt_sha256: str
    allowed_case_ids: tuple[str, ...]
    live_executor_allowed: Literal[False] = False
    patch_application_allowed: Literal[False] = False


@dataclass(frozen=True, slots=True)
class CandidateReviewSelection:
    """Q6 label plus offline test registration, with no executor authority."""

    case_id: str
    selected_test_id: str
    vulnerability_class: str
    model_input_sha256: str
    source_sha256: str
    action: Literal["offline_review_only"] = "offline_review_only"
    may_execute_live: Literal[False] = False
    may_prepare_live_patch: Literal[False] = False


class CandidateRegistrationCatalog:
    """Load immutable offline qualification identities with external SHA pins."""

    def __init__(
        self,
        *,
        bundle_root: Path,
        expected_manifest_sha256: str,
        expected_protocol_sha256: str,
        live_registry: TargetRegistry,
    ) -> None:
        if (
            not _SHA.fullmatch(expected_manifest_sha256)
            or not _SHA.fullmatch(expected_protocol_sha256)
            or not bundle_root.is_absolute()
            or not bundle_root.is_dir()
            or bundle_root.is_symlink()
            or any(parent.is_symlink() for parent in bundle_root.parents)
        ):
            raise CandidateAdmissionDenied("external hashes and off-repo bundle required")
        root = bundle_root.resolve(strict=True)
        live_repo = REPO.resolve(strict=True)
        if root == live_repo or live_repo in root.parents:
            raise CandidateAdmissionDenied("sealed candidate cannot resolve inside live repository")
        self._bundle = bundle_root
        manifest_file = bundle_root / "manifest.json"
        frozen_file = bundle_root / "frozen-protocol.json"
        try:
            if (
                sha(read_strict(manifest_file)) != expected_manifest_sha256
                or sha(read_strict(frozen_file)) != expected_protocol_sha256
            ):
                raise CandidateAdmissionDenied("external frozen hash mismatch")
            manifest = json.loads(read_strict(manifest_file))
            frozen = json.loads(read_strict(frozen_file))
            if (
                frozen != PROTOCOL
                or manifest.get("frozen_protocol_sha256") != expected_protocol_sha256
                or not manifest.get("development_only")
                or manifest.get("model_calls") != 0
                or manifest.get("actual_live_executor_runs") != 0
                or frozen.get("registered_executor_dispatch_authorized") is not False
                or frozen.get("research_final_admission") is not False
            ):
                raise CandidateAdmissionDenied("candidate does not satisfy no-live freeze")
            # This *reexecutes* only the preapproved, pinned original/repair
            # development source via TestClient; never Docker or external URLs.
            counts = verify(bundle_root)
            if counts != {"malicious": 9, "benign": 9, "patched_replay": 9}:
                raise CandidateAdmissionDenied("offline independent replay incomplete")

            live_tests = {t.test_id for t in live_registry.list_security_tests()}
            live_targets = {t.target_id for t in live_registry.list_targets()}
            if live_tests & set(_TEST_IDS.values()):
                raise CandidateAdmissionDenied("candidate IDs already entered live registry")
            if live_targets != {"vulnerable-store"}:
                raise CandidateAdmissionDenied("live target registry has changed")

            routes = frozen["classifier_input_field_names"]
            if routes != ["route", "observations"]:
                raise CandidateAdmissionDenied("classifier input schema drift")
            raw_registry = read_strict(bundle_root / "candidate-registry.json")
            registered = json.loads(raw_registry)
            expected_registry = {
                "schema": "nonlive-source-family-candidate-registry-v1",
                "admitted_to_live_executor": False,
                "family_routes": [
                    {"name": recipe.name, "route": recipe.route,
                     "function": recipe.function}
                    for recipe in RECIPES
                ],
            }
            if raw_registry != canonical(expected_registry) or registered != expected_registry:
                raise CandidateAdmissionDenied("candidate-only registry bytes changed")
            proposed = {r["name"]: r for r in registered["family_routes"]}
            if set(proposed) != _SUPPORTED:
                raise CandidateAdmissionDenied("candidate route coverage mismatch")

            by_case: dict[str, tuple[str, str, str]] = {}
            for record in manifest["cases"]:
                case_id = record["case_id"]
                if case_id in by_case:
                    raise CandidateAdmissionDenied("duplicate candidate case identity")
                family = record["family_slot"]
                if family not in _SUPPORTED:
                    raise CandidateAdmissionDenied("unknown candidate source family")
                by_case[case_id] = (
                    family,
                    record["model_input_sha256"],
                    record["source_sha256"],
                )
            if len(by_case) != 18:
                raise CandidateAdmissionDenied("candidate case cardinality invalid")

            registrations = []
            for recipe in RECIPES:
                family = recipe.name
                proposed_route = proposed[family]
                if proposed_route != {
                    "name": family,
                    "route": recipe.route,
                    "function": recipe.function,
                }:
                    raise CandidateAdmissionDenied("unapproved candidate route mapping")
                cases = tuple(k for k, (f, _, _) in by_case.items() if f == family)
                if len(cases) != 6:
                    raise CandidateAdmissionDenied("candidate case count per family drift")
                sha_source = manifest["sources"][family]
                excerpt_path = bundle_root / "source-excerpts" / (family + ".json")
                registrations.append(CandidateTestRegistration(
                    test_id=_TEST_IDS[family],
                    source_family=family,
                    vulnerability_class=_CLASSES[family],
                    endpoint=recipe.route,
                    method="GET",
                    input_field=recipe.parameter,
                    source_sha256=sha_source,
                    source_excerpt_sha256=sha(read_strict(excerpt_path)),
                    allowed_case_ids=cases,
                ))
            self._registrations = {r.test_id: r for r in registrations}
            self._cases = by_case
            self._manifest_sha = expected_manifest_sha256
            self._protocol_sha = expected_protocol_sha256
            self._registry_sha = sha(raw_registry)
        except (KeyError, ValueError, OSError, TypeError, SourceFamilyBlocked) as exc:
            raise CandidateAdmissionDenied(
                "sealed candidate registration verification failed"
            ) from exc

    @property
    def test_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._registrations))

    @property
    def manifest_sha256(self) -> str:
        return self._manifest_sha

    @property
    def protocol_sha256(self) -> str:
        return self._protocol_sha

    def resolve_offline_review(
        self,
        *,
        case_id: str,
        selected_test_id: str,
        model_decision: RQ2ClassificationDecision,
    ) -> CandidateReviewSelection:
        """Reject wrong test/class/case. Never read evaluator truth for routing."""
        if not isinstance(model_decision, RQ2ClassificationDecision):
            raise CandidateAdmissionDenied("a typed model decision is required")
        row = self._cases.get(case_id)
        registration = self._registrations.get(selected_test_id)
        if row is None or registration is None:
            raise CandidateAdmissionDenied("unrecognized candidate case/test ID")
        family, input_digest, source_digest = row
        if (
            family != registration.source_family
            or model_decision.classification.value != registration.vulnerability_class
            or source_digest != registration.source_sha256
            or case_id not in registration.allowed_case_ids
        ):
            raise CandidateAdmissionDenied("model-selection/candidate-boundary mismatch")
        # Validate sealed identity again at the exact moment of selection.
        try:
            unchanged = (
                sha(read_strict(self._bundle / "manifest.json")) == self._manifest_sha
                and sha(read_strict(self._bundle / "frozen-protocol.json")) == self._protocol_sha
                and sha(read_strict(self._bundle / "candidate-registry.json")) == self._registry_sha
                and sha(read_strict(
                    self._bundle / "model-inputs" / (case_id + ".json")
                )) == input_digest
                and sha(read_strict(
                    self._bundle / "source" / (family + ".py")
                )) == source_digest
                and sha(read_strict(
                    self._bundle / "source-excerpts" / (family + ".json")
                )) == registration.source_excerpt_sha256
            )
        except (OSError, SourceFamilyBlocked) as exc:
            raise CandidateAdmissionDenied("candidate file became invalid") from exc
        if not unchanged:
            raise CandidateAdmissionDenied("candidate altered after registration")
        return CandidateReviewSelection(
            case_id=case_id,
            selected_test_id=selected_test_id,
            vulnerability_class=registration.vulnerability_class,
            model_input_sha256=input_digest,
            source_sha256=source_digest,
        )

    def execute_registered(self, *_args: object, **_kwargs: object) -> None:
        raise CandidateAdmissionDenied(_DENIED_ACTION)

    def authorize_docker(self, *_args: object, **_kwargs: object) -> None:
        raise CandidateAdmissionDenied(_DENIED_ACTION)

    def authorize_research_admission(self, *_args: object, **_kwargs: object) -> None:
        raise CandidateAdmissionDenied(_DENIED_ACTION)
