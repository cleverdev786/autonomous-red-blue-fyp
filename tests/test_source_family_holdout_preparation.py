"""Candidate source-family freeze and deterministic offline replay tests.

No Q6, Docker, network, official RQ2 mutations, or research admission.
"""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

import pytest

from scripts.prepare_source_family_holdout import (
    FAMILIES,
    PROTOCOL,
    RECIPE_BY_NAME,
    RECIPES,
    REPO,
    SourceFamilyBlocked,
    build,
    canonical,
    patch_preview,
    read_strict,
    run_case,
    sha,
    source_location,
    verify,
)


@pytest.fixture(scope="module")
def frozen_bundle():
    with tempfile.TemporaryDirectory(prefix="sfh-test-freeze-") as temp:
        root = Path(temp) / "new"
        manifest = build(root)
        assert manifest["case_count"] == 18
        yield root


def test_three_source_families_are_distinct_and_replay_deterministically(frozen_bundle):
    stats = verify(frozen_bundle)
    assert stats == {"malicious": 9, "benign": 9, "patched_replay": 9}
    manifest = json.loads(read_strict(frozen_bundle / "manifest.json"))
    assert len(manifest["sources"]) == 3
    assert set(manifest["sources"]) == set(FAMILIES)
    assert manifest["model_calls"] == 0
    assert manifest["actual_live_executor_runs"] == 0
    assert manifest["development_only"] is True
    assert manifest["training"]["old_theme_overlap"] == []
    assert manifest["training"]["distinctive_marker_hits"] == {}
    assert len(manifest["training"]["corpora"]) == 4


def test_model_visible_inputs_have_no_evaluator_truth_and_distinct_hashes(frozen_bundle):
    manifest = json.loads(read_strict(frozen_bundle / "manifest.json"))
    truth = json.loads(read_strict(frozen_bundle / "evaluator-only/truth.json"))
    assert len(truth) == 18
    assert sum(value["expected_exploit"] for value in truth.values()) == 9
    actual = []
    for case in manifest["cases"]:
        path = frozen_bundle / "model-inputs" / (case["case_id"] + ".json")
        raw = read_strict(path)
        model_data = json.loads(raw)
        assert canonical(model_data) == raw
        assert case["model_input_sha256"] == sha(raw)
        assert set(model_data) == {"route", "observations"}
        assert len(model_data["observations"]) == 2
        assert not any(
            field in raw.decode()
            for field in ("ground_truth", "expected_exploit", "sink_line",
                          "expected_classification", "evaluator_only")
        )
        actual.append(case["model_input_sha256"])
    assert len(set(actual)) == 18


def test_frozen_protocol_has_prospective_benign_restraint_and_no_admission(frozen_bundle):
    frozen = json.loads(read_strict(frozen_bundle / "frozen-protocol.json"))
    assert frozen == PROTOCOL
    assert frozen["candidate_only"] is True
    assert frozen["research_final_admission"] is False
    assert frozen["classifier_inputs"] == 18
    assert frozen["classify_benign_min_correct"] == 8
    assert frozen["classify_malicious_min_correct"] == 8
    assert frozen["inference_settings"]["max_attempts_per_role"] == 1
    assert len(frozen["classification_response_schema_sha256"]) == 64
    assert len(frozen["source_response_schema_sha256"]) == 64
    assert "normal or blocked" in frozen["classification_system_prompt_v1"]
    assert "No generated code" in frozen["source_localization_system_prompt_v1"]
    assert frozen["benign_unknown_prediction_scores_as_error"] is True
    registry = json.loads(read_strict(frozen_bundle / "candidate-registry.json"))
    assert registry["admitted_to_live_executor"] is False


@pytest.mark.parametrize("recipe", RECIPES, ids=lambda x: x.name)
def test_only_frozen_source_and_hardcoded_patches_are_supported(
    recipe, frozen_bundle, tmp_path
):
    original = read_strict(
        frozen_bundle / "source" / (recipe.name + ".py")
    )
    fixed = read_strict(
        frozen_bundle / "trusted-preview" / (recipe.name + ".py")
    )
    label = {
        "spectrometry": "sql_injection",
        "weatherbeacon": "xss",
        "magnetometry": "path_traversal",
    }[recipe.name]
    assert fixed == patch_preview(
        name=recipe.name, frozen_source=original,
        proposed_class=label, proposed_function=recipe.function,
        proposed_sink=source_location(recipe),
    )
    with pytest.raises(SourceFamilyBlocked):
        patch_preview(
            name=recipe.name, frozen_source=original + b"\n",
            proposed_class=label, proposed_function=recipe.function,
            proposed_sink=source_location(recipe),
        )
    for malformed in (
        (label, "unregistered_function", source_location(recipe)),
        (label, recipe.function, source_location(recipe) + 1),
        ("benign", recipe.function, source_location(recipe)),
    ):
        with pytest.raises(SourceFamilyBlocked):
            patch_preview(
                name=recipe.name, frozen_source=original,
                proposed_class=malformed[0], proposed_function=malformed[1],
                proposed_sink=malformed[2],
            )
    with pytest.raises(SourceFamilyBlocked, match="untrusted candidate source"):
        run_case(
            recipe, source=original + b"\n# untrusted",
            payload=recipe.control, data_root=tmp_path,
        )


@pytest.mark.parametrize("part", (
    "source", "trusted-preview", "model-inputs", "source-excerpts",
    "evaluator-only", "frozen-protocol",
))
def test_tampering_sealed_inputs_prevents_verify(frozen_bundle, tmp_path, part):
    duplicate = tmp_path / "copy"
    shutil.copytree(frozen_bundle, duplicate)
    first = RECIPES[0]
    targets = {
        "source": duplicate / "source" / (first.name + ".py"),
        "trusted-preview": duplicate / "trusted-preview" / (first.name + ".py"),
        "model-inputs": duplicate / "model-inputs" / "sfh-v1-001.json",
        "source-excerpts": duplicate / "source-excerpts" / (first.name + ".json"),
        "evaluator-only": duplicate / "evaluator-only" / "truth.json",
        "frozen-protocol": duplicate / "frozen-protocol.json",
    }
    path = targets[part]
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(SourceFamilyBlocked):
        verify(duplicate)


def test_missing_or_symlinked_model_visible_source_is_rejected(
    frozen_bundle, tmp_path
):
    duplicate = tmp_path / "bad-link"
    shutil.copytree(frozen_bundle, duplicate)
    path = duplicate / "source" / "spectrometry.py"
    path.unlink()
    path.symlink_to(frozen_bundle / "source" / "spectrometry.py")
    with pytest.raises(SourceFamilyBlocked):
        verify(duplicate)


def test_freeze_is_no_overwrite_and_refuses_live_repo(frozen_bundle, tmp_path):
    with pytest.raises(SourceFamilyBlocked):
        build(frozen_bundle)
    inside_repo = REPO / "NOT_A_REAL_CANDIDATE_ARTIFACT_DIRECTORY"
    with pytest.raises(SourceFamilyBlocked):
        build(inside_repo)
    assert not inside_repo.exists()
    with pytest.raises(SourceFamilyBlocked):
        build(Path("relative/path"))


def test_benign_inputs_and_postrepair_replays_stay_exploit_free(
    frozen_bundle, tmp_path
):
    truth = json.loads(read_strict(frozen_bundle / "evaluator-only/truth.json"))
    benign = {k: v for k, v in truth.items() if not v["expected_exploit"]}
    assert len(benign) == 9
    for case_id, record in benign.items():
        recipe = RECIPE_BY_NAME[record["family"]]
        input_data = json.loads(
            read_strict(frozen_bundle / "model-inputs" / (case_id + ".json"))
        )
        payload = input_data["observations"][1]["parameters"][recipe.parameter]
        fixed = read_strict(
            frozen_bundle / "trusted-preview" / (recipe.name + ".py")
        )
        with tempfile.TemporaryDirectory(prefix="sfh-benign-regress-") as td:
            observation, exploit = run_case(
                recipe, source=fixed, payload=payload,
                data_root=Path(td),
            )
        assert not exploit
        assert observation["route"] == recipe.route
