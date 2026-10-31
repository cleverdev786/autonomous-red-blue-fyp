"""Portable offline candidate registration tests using a temporary sealed bundle."""
from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

import pytest

from schemas.common import ClassificationLabel
from schemas.rq2_dataset import RQ2ClassificationDecision
from scripts.prepare_source_family_holdout import build, sha
from services.candidate_source_family_registry import (
    CandidateAdmissionDenied,
    CandidateRegistrationCatalog,
)
from services.target_registry import TargetRegistry

ROOT = Path(__file__).resolve().parents[1]
CLASSES = {
    "spectrometry": ("sql_injection", "sfh-spectrometry-read-v1"),
    "weatherbeacon": ("xss", "sfh-weatherbeacon-caption-v1"),
    "magnetometry": ("path_traversal", "sfh-magnetometry-record-v1"),
}


@dataclass(frozen=True)
class Assets:
    root: Path
    manifest_sha256: str
    protocol_sha256: str


@pytest.fixture(scope="module")
def assets(tmp_path_factory):
    root = tmp_path_factory.mktemp("offline-candidate-registration") / "sealed"
    build(root)
    return Assets(
        root=root,
        manifest_sha256=sha((root / "manifest.json").read_bytes()),
        protocol_sha256=sha((root / "frozen-protocol.json").read_bytes()),
    )


@pytest.fixture(scope="module")
def registry():
    return TargetRegistry.from_directories(
        targets_dir=ROOT / "config/targets",
        security_tests_dir=ROOT / "config/security_tests",
    )


def decision(label: str) -> RQ2ClassificationDecision:
    return RQ2ClassificationDecision(
        classification=ClassificationLabel(label),
        confidence=0.9,
        reason="Synthetic typed model-only decision, no evaluator scoring fields.",
    )


def load(assets: Assets, registry: TargetRegistry, *, root=None, **overrides):
    params = {
        "bundle_root": root or assets.root,
        "expected_manifest_sha256": assets.manifest_sha256,
        "expected_protocol_sha256": assets.protocol_sha256,
        "live_registry": registry,
    }
    params.update(overrides)
    return CandidateRegistrationCatalog(**params)


def test_external_hashes_required_and_no_live_authority(assets, registry):
    catalog = load(assets, registry)
    assert len(catalog.test_ids) == 3
    assert catalog.manifest_sha256 == assets.manifest_sha256
    assert catalog.protocol_sha256 == assets.protocol_sha256
    assert all(identifier.startswith("sfh-") for identifier in catalog.test_ids)
    for action in (
        catalog.execute_registered,
        catalog.authorize_docker,
        catalog.authorize_research_admission,
    ):
        with pytest.raises(CandidateAdmissionDenied):
            action()


@pytest.mark.parametrize("family", tuple(CLASSES))
def test_review_only_selection_never_grants_patch_or_docker(assets, registry, family):
    catalog = load(assets, registry)
    manifest = json.loads((assets.root / "manifest.json").read_text())
    record = next(c for c in manifest["cases"] if c["family_slot"] == family)
    label, test_id = CLASSES[family]
    result = catalog.resolve_offline_review(
        case_id=record["case_id"],
        selected_test_id=test_id,
        model_decision=decision(label),
    )
    assert result.action == "offline_review_only"
    assert not result.may_execute_live
    assert not result.may_prepare_live_patch


@pytest.mark.parametrize("family", tuple(CLASSES))
def test_mismatched_selected_test_rejected(assets, registry, family):
    catalog = load(assets, registry)
    manifest = json.loads((assets.root / "manifest.json").read_text())
    record = next(c for c in manifest["cases"] if c["family_slot"] == family)
    label, _ = CLASSES[family]
    wrong = next(t for key, (_, t) in CLASSES.items() if key != family)
    with pytest.raises(CandidateAdmissionDenied):
        catalog.resolve_offline_review(
            case_id=record["case_id"],
            selected_test_id=wrong,
            model_decision=decision(label),
        )


@pytest.mark.parametrize("wrong_label", (
    "benign", "unknown", "xss", "path_traversal",
))
def test_nonmatching_classifications_cannot_authorize_registration_review(
    assets, registry, wrong_label,
):
    catalog = load(assets, registry)
    with pytest.raises(CandidateAdmissionDenied):
        catalog.resolve_offline_review(
            case_id="sfh-v1-001",
            selected_test_id="sfh-spectrometry-read-v1",
            model_decision=decision(wrong_label),
        )


@pytest.mark.parametrize("corrupt", (
    "manifest", "protocol", "case", "source", "registry",
))
def test_tampering_candidate_rejected(assets, registry, tmp_path, corrupt):
    root = tmp_path / "candidate"
    shutil.copytree(assets.root, root)
    targets = {
        "manifest": root / "manifest.json",
        "protocol": root / "frozen-protocol.json",
        "case": root / "model-inputs/sfh-v1-001.json",
        "source": root / "source/spectrometry.py",
        "registry": root / "candidate-registry.json",
    }
    path = targets[corrupt]
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(CandidateAdmissionDenied):
        load(assets, registry, root=root)


def test_changed_input_after_catalog_open_rejected(assets, registry, tmp_path):
    root = tmp_path / "candidate"
    shutil.copytree(assets.root, root)
    catalog = load(assets, registry, root=root)
    f = root / "model-inputs/sfh-v1-001.json"
    f.write_bytes(f.read_bytes() + b"\n")
    with pytest.raises(CandidateAdmissionDenied):
        catalog.resolve_offline_review(
            case_id="sfh-v1-001",
            selected_test_id="sfh-spectrometry-read-v1",
            model_decision=decision("sql_injection"),
        )


def test_invalid_external_pin_denied(assets, registry):
    with pytest.raises(CandidateAdmissionDenied):
        load(assets, registry, expected_manifest_sha256="0" * 64)
    with pytest.raises(CandidateAdmissionDenied):
        load(assets, registry, expected_protocol_sha256="0" * 64)


def test_evaluator_truth_cannot_be_used_as_model_decision(assets, registry):
    catalog = load(assets, registry)
    truth = json.loads((assets.root / "evaluator-only/truth.json").read_text())
    assert "expected_classification" in truth["sfh-v1-001"]
    with pytest.raises(CandidateAdmissionDenied):
        catalog.resolve_offline_review(
            case_id="sfh-v1-001",
            selected_test_id="sfh-spectrometry-read-v1",
            model_decision=truth["sfh-v1-001"],
        )


def test_live_registered_test_ids_remain_unmodified(assets, registry):
    live = {x.test_id for x in registry.list_security_tests()}
    new = set(load(assets, registry).test_ids)
    assert not live & new
    assert live == {
        "sqli-login-bypass-001", "xss-reflection-001",
        "path-traversal-private-file-001",
    }


def test_changed_registry_after_catalog_open_rejected(assets, registry, tmp_path):
    root = tmp_path / "candidate"
    shutil.copytree(assets.root, root)
    catalog = load(assets, registry, root=root)
    f = root / "candidate-registry.json"
    f.write_bytes(f.read_bytes() + b"\\n")
    with pytest.raises(CandidateAdmissionDenied):
        catalog.resolve_offline_review(
            case_id="sfh-v1-001",
            selected_test_id="sfh-spectrometry-read-v1",
            model_decision=decision("sql_injection"),
        )


def test_removed_input_after_catalog_open_fails_closed(assets, registry, tmp_path):
    root = tmp_path / "candidate"
    shutil.copytree(assets.root, root)
    catalog = load(assets, registry, root=root)
    (root / "model-inputs/sfh-v1-001.json").unlink()
    with pytest.raises(CandidateAdmissionDenied):
        catalog.resolve_offline_review(
            case_id="sfh-v1-001",
            selected_test_id="sfh-spectrometry-read-v1",
            model_decision=decision("sql_injection"),
        )
