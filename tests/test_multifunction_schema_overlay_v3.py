"""Validate prospective source schema v3 without model calls or Docker."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from pydantic import ValidationError

from schemas.multifunction_source_selection import (
    ALLOWED_FUNCTION_NAMES,
    CandidateMultifunctionSourceSelection,
)
from scripts.prepare_multifunction_schema_overlay_v3 import (
    V2_MANIFEST_SHA256,
    V2_PROTOCOL_SHA256,
    V2_SOURCE_SCHEMA_SHA256,
    V3_SOURCE_SCHEMA_SHA256,
    CompatibilityBlocked,
    freeze_overlay,
    frozen_contract,
    verify_overlay,
)
from scripts.prepare_multifunction_source_holdout_v2 import (
    PROTOCOL as V2_PROTOCOL,
)
from scripts.prepare_multifunction_source_holdout_v2 import (
    RECIPES,
    source_location,
    source_view,
)
from services.compact_source_selection import CompactSourceSelection


@pytest.fixture(scope="module")
def overlay(tmp_path_factory):
    result = tmp_path_factory.mktemp("sfh-v3-schema-fix") / "overlay"
    freeze_overlay(result)
    yield result


def response(function: str, line: int) -> dict:
    return {
        "function_or_route": function,
        "sink_line": line,
        "root_cause": "Untrusted input reaches vulnerable sink without a trusted check.",
        "confidence": 0.9,
    }


def test_v2_schema_rejects_correct_new_family_output():
    for recipe in RECIPES:
        with pytest.raises(ValidationError):
            CompactSourceSelection.model_validate(
                response(recipe.function, source_location(recipe))
            )


@pytest.mark.parametrize("recipe", RECIPES, ids=lambda x: x.name)
def test_v3_accepts_correct_family_function_and_line(recipe):
    prediction = CandidateMultifunctionSourceSelection.model_validate(
        response(recipe.function, source_location(recipe))
    )
    assert prediction.function_or_route == recipe.function
    assert prediction.sink_line == source_location(recipe)


@pytest.mark.parametrize("recipe", RECIPES, ids=lambda x: x.name)
def test_v3_also_permits_both_safe_decoy_functions_without_leaking_answer(recipe):
    functions = source_view(recipe)["candidate_function_names"]
    for function in functions:
        decision = CandidateMultifunctionSourceSelection.model_validate(
            response(function, source_location(recipe))
        )
        assert decision.function_or_route == function


def test_schema_contains_exactly_nine_allowlisted_names():
    expected = set()
    for recipe in RECIPES:
        expected.update(source_view(recipe)["candidate_function_names"])
    assert ALLOWED_FUNCTION_NAMES == expected
    assert len(ALLOWED_FUNCTION_NAMES) == 9
    assert all(not name.startswith("vulnerable_") for name in expected)


@pytest.mark.parametrize("invalid_name", (
    "vulnerable_login", "vulnerable_search", "vulnerable_file_read",
    "../../etc/passwd", "os.system", "some_new_function",
))
def test_v3_refuses_unapproved_function_names(invalid_name):
    with pytest.raises(ValidationError):
        CandidateMultifunctionSourceSelection.model_validate(
            response(invalid_name, 24)
        )


@pytest.mark.parametrize("change", (
    {"sink_line": 0}, {"sink_line": 201},
    {"confidence": 1.1}, {"root_cause": "       "},
    {"patch": "not authorized"}, {"function_or_route": "vulnerable_login"},
))
def test_v3_strictly_rejects_unbounded_or_extra_model_outputs(change):
    fields = response("read_beam", 53)
    fields.update(change)
    with pytest.raises(ValidationError):
        CandidateMultifunctionSourceSelection.model_validate(fields)


def test_v3_manifest_links_original_v2_sources_not_copied(overlay):
    data = json.loads((overlay / "manifest.json").read_text())
    assert len(list(overlay.iterdir())) == 2
    assert len(data["parent_case_ids"]) == 18
    assert data["v2_cases_reused_without_duplication"] == 18
    assert data["parent_v2_manifest_sha256"] == V2_MANIFEST_SHA256
    assert data["parent_v2_protocol_sha256"] == V2_PROTOCOL_SHA256
    assert data["independent_source_tasks"] == 3
    assert not data["independent_human_approval"]
    assert not data["official_m21_admitted"]
    assert data["model_calls"] == data["docker_runs"] == 0


def test_only_source_schema_and_explicit_overlay_metadata_change():
    corrected = frozen_contract()
    original = {key: value for key, value in corrected.items()
                if key in V2_PROTOCOL}
    original["source_schema_sha256"] = V2_PROTOCOL["source_schema_sha256"]
    original["schema"] = V2_PROTOCOL["schema"]
    assert original == V2_PROTOCOL
    assert corrected["source_schema_sha256"] == V3_SOURCE_SCHEMA_SHA256
    assert corrected["source_schema_sha256"] != V2_SOURCE_SCHEMA_SHA256
    assert corrected["generation"] == V2_PROTOCOL["generation"]
    assert corrected["classification_accuracy_min"] == V2_PROTOCOL[
        "classification_accuracy_min"
    ]
    assert corrected["classification_benign_correct_min"] == 8
    assert corrected["function_and_sink_joint_correct_min"] == 8
    assert corrected["research_final_admission"] is False
    assert corrected["registered_executor_dispatch_authorized"] is False


def test_v3_overlay_reverification(overlay):
    assert verify_overlay(overlay) == {
        "source_schema_compatible": True,
        "parent_cases": 18,
        "unique_source_selection_tasks": 3,
        "new_model_calls": 0,
        "external_review_pending": True,
    }


@pytest.mark.parametrize("filename", (
    "manifest.json", "corrected-protocol.json",
))
def test_byte_tampering_invalidates_v3_overlay(overlay, tmp_path, filename):
    clone = tmp_path / "altered"
    shutil.copytree(overlay, clone)
    p = clone / filename
    p.write_bytes(p.read_bytes() + b"\n")
    with pytest.raises((CompatibilityBlocked, ValueError)):
        verify_overlay(clone)


def test_added_unrecognized_file_invalidates_overlay(overlay, tmp_path):
    clone = tmp_path / "altered"
    shutil.copytree(overlay, clone)
    (clone / "extra-model-output.json").write_text("{}\n")
    with pytest.raises(CompatibilityBlocked):
        verify_overlay(clone)


def test_no_reuse_or_repo_live_output_location(overlay, tmp_path):
    from scripts.prepare_multifunction_source_holdout_v2 import REPO, V1
    with pytest.raises(CompatibilityBlocked):
        freeze_overlay(overlay)
    with pytest.raises(CompatibilityBlocked):
        freeze_overlay(V1)
    with pytest.raises(CompatibilityBlocked):
        freeze_overlay(REPO / "MUST_NOT_CREATE")
    with pytest.raises(CompatibilityBlocked):
        freeze_overlay(Path("not-an-absolute-path"))
    assert not (REPO / "MUST_NOT_CREATE").exists()
