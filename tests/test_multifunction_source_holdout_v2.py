"""v2 multi-function, blinded source-selection, no-model offline admission tests."""
from __future__ import annotations

import json
import shutil
import stat
import tempfile
from pathlib import Path

import pytest

from scripts.prepare_multifunction_source_holdout_v2 import (
    DECOY_FUNCTIONS,
    EXPECTED_VULNERABLE_ORDINAL,
    PROTOCOL,
    RECIPES,
    REPO,
    V1,
    V1_MANIFEST_SHA,
    V1_PROTOCOL_SHA,
    SourceFamilyBlocked,
    allowed_functions,
    canonical,
    contamination,
    freeze,
    read_strict,
    run_case,
    sha,
    source_location,
    source_view,
    trusted_patch,
    verify,
)


@pytest.fixture(scope="module")
def sealed(tmp_path_factory):
    dest = tmp_path_factory.mktemp("sfh-v2-prep") / "frozen"
    manifest = freeze(dest)
    assert len(manifest["cases"]) == 18
    yield dest


def test_replay_every_family_and_scope(sealed):
    assert verify(sealed) == {
        "malicious": 9, "benign": 9,
        "patched_replay": 9, "safe_decoy_routes": 6,
    }
    manifest = json.loads(read_strict(sealed / "manifest.json"))
    assert manifest["schema"] == "source-family-multi-function-prequalification-v2"
    assert manifest["candidate_functions_per_family"] == 3
    assert manifest["verified_safe_decoys_per_family"] == 2
    assert manifest["model_calls"] == manifest["docker_runs"] == 0
    assert manifest["scientifically_independent_approved"] is False


@pytest.mark.parametrize("recipe", RECIPES, ids=lambda r: r.name)
def test_exactly_three_plausible_routes_with_different_vulnerable_positions(recipe):
    functions = allowed_functions(recipe)
    view = source_view(recipe)
    names = view["candidate_function_names"]
    assert len(functions) == len(names) == 3
    assert len(DECOY_FUNCTIONS[recipe.name]) == 2
    assert set(names) == {recipe.function, *DECOY_FUNCTIONS[recipe.name]}
    assert all(n.decorator_list and n.lineno < n.end_lineno for n in functions)
    assert all(n.name in view["numbered_candidate_functions"] for n in functions)
    assert names.index(recipe.function) + 1 == EXPECTED_VULNERABLE_ORDINAL[recipe.name]
    assert "expected_function" not in view
    assert "expected_sink" not in view
    assert source_location(recipe) > 1


def test_vulnerable_function_positions_cover_first_middle_last():
    assert set(EXPECTED_VULNERABLE_ORDINAL.values()) == {1, 2, 3}
    assert {r.name for r in RECIPES} == set(EXPECTED_VULNERABLE_ORDINAL)


def test_v2_rejects_v1_exact_input_and_source_reuse(sealed):
    inputs = {
        sha(read_strict(f))
        for f in (sealed / "model-inputs").glob("sfh-v2-*.json")
    }
    previous = {
        sha(read_strict(f))
        for f in (V1 / "model-inputs").glob("sfh-v1-*.json")
    }
    assert len(inputs) == len(previous) == 18
    assert not inputs & previous
    before = {
        sha(read_strict(f))
        for f in (V1 / "source").glob("*.py")
    }
    now = {
        sha(read_strict(f))
        for f in (sealed / "source").glob("*.py")
    }
    assert len(now) == 3 and not now & before
    c = contamination()
    assert c["previous_v1_manifest_sha256"] == V1_MANIFEST_SHA
    assert c["previous_v1_protocol_sha256"] == V1_PROTOCOL_SHA
    assert c["distinctive_marker_hits"] == {}


def test_classifier_and_source_views_separate_from_evaluator_truth(sealed):
    m = json.loads(read_strict(sealed / "manifest.json"))
    truth = json.loads(read_strict(sealed / "evaluator-only/truth.json"))
    assert len(truth) == len(m["cases"]) == 18
    for row in m["cases"]:
        case_id = row["case_id"]
        inp = read_strict(sealed / "model-inputs" / (case_id + ".json"))
        obj = json.loads(inp)
        src = read_strict(
            sealed / "source-views" / (row["family_slot"] + ".json")
        )
        assert inp == canonical(obj)
        assert row["model_input_sha256"] == sha(inp)
        assert set(obj) == {"route", "observations"}
        assert set(json.loads(src)) == {
            "route", "source_sha256",
            "numbered_candidate_functions", "candidate_function_names",
        }
        for key in (
            "expected_classification", "expected_exploit", "expected_function",
            "expected_sink_line", "ground_truth",
        ):
            assert key not in obj
            assert key not in json.loads(src)
        assert truth[case_id]["input_sha256"] == sha(inp)
    assert sum(d["expected_exploit"] for d in truth.values()) == 9
    assert sum(not d["expected_exploit"] for d in truth.values()) == 9


def test_protocol_is_prospective_and_scoring_requires_benign_restraint(sealed):
    protocol = json.loads(read_strict(sealed / "frozen-protocol.json"))
    assert protocol == PROTOCOL
    assert protocol["evaluation_cases"] == 18
    assert protocol["classification_benign_correct_min"] == 8
    assert protocol["classification_accuracy_min"] == 16
    assert protocol["function_and_sink_joint_correct_min"] == 8
    assert protocol["source_functions_visible_per_family"] == 3
    assert protocol["unknown_benign_is_not_true_negative"] is True
    assert protocol["no_retries"] is True
    assert protocol["independent_external_review_required"] is True
    assert not protocol["registered_executor_dispatch_authorized"]
    assert not protocol["research_final_admission"]
    assert protocol["generation"]["temperature"] == 0
    assert len(protocol["classification_schema_sha256"]) == 64
    assert len(protocol["source_schema_sha256"]) == 64
    assert "THREE competing route functions" in protocol["source_system_prompt"]


@pytest.mark.parametrize("recipe", RECIPES, ids=lambda r: r.name)
def test_only_known_function_sink_class_and_source_prepare_preview(recipe, sealed):
    input_bytes = read_strict(sealed / "source" / (recipe.name + ".py"))
    preview = read_strict(sealed / "trusted-preview" / (recipe.name + ".py"))
    label = {
        "spectrometry": "sql_injection",
        "weatherbeacon": "xss",
        "magnetometry": "path_traversal",
    }[recipe.name]
    legitimate = trusted_patch(
        recipe=recipe, original=input_bytes,
        proposed_label=label, proposed_function=recipe.function,
        proposed_line=source_location(recipe),
    )
    assert preview == legitimate
    for changes in (
        {"proposed_label": "benign"},
        {"proposed_function": DECOY_FUNCTIONS[recipe.name][0]},
        {"proposed_function": DECOY_FUNCTIONS[recipe.name][1]},
        {"proposed_line": source_location(recipe) + 1},
        {"original": input_bytes + b"\n"},
    ):
        args = {
            "recipe": recipe, "original": input_bytes,
            "proposed_label": label, "proposed_function": recipe.function,
            "proposed_line": source_location(recipe),
        }
        args.update(changes)
        with pytest.raises(SourceFamilyBlocked):
            trusted_patch(**args)


@pytest.mark.parametrize("part", (
    "manifest", "protocol", "truth", "registry", "source",
    "preview", "view", "input",
))
def test_any_byte_tampering_sealed_v2_bundle_is_rejected(sealed, tmp_path, part):
    dest = tmp_path / "tampered"
    shutil.copytree(sealed, dest)
    files = {
        "manifest": dest / "manifest.json",
        "protocol": dest / "frozen-protocol.json",
        "truth": dest / "evaluator-only/truth.json",
        "registry": dest / "candidate-registry.json",
        "source": dest / "source/spectrometry.py",
        "preview": dest / "trusted-preview/spectrometry.py",
        "view": dest / "source-views/spectrometry.json",
        "input": dest / "model-inputs/sfh-v2-001.json",
    }
    p = files[part]
    p.write_bytes(p.read_bytes() + b"\n")
    with pytest.raises((SourceFamilyBlocked, ValueError)):
        verify(dest)


def test_symlinked_source_blocked_and_no_source_execution(sealed, tmp_path):
    dest = tmp_path / "linked"
    shutil.copytree(sealed, dest)
    s = dest / "source/spectrometry.py"
    s.unlink()
    s.symlink_to(sealed / "source/spectrometry.py")
    with pytest.raises(SourceFamilyBlocked):
        verify(dest)
    recipe = RECIPES[0]
    with (
        tempfile.TemporaryDirectory(prefix="sfh-v2-disallowed-") as td,
        pytest.raises(SourceFamilyBlocked),
    ):
        run_case(
            recipe=recipe,
            source=recipe.source.encode() + b"\n# unapproved source",
            payload=recipe.control, data_root=Path(td),
        )


def test_no_overwrite_v1_or_v2_live_repo_and_restricted_truth(sealed):
    with pytest.raises(SourceFamilyBlocked):
        freeze(sealed)
    with pytest.raises(SourceFamilyBlocked):
        freeze(V1)
    with pytest.raises(SourceFamilyBlocked):
        freeze(REPO / "NEVER_CREATE_V2_ARTIFACTS")
    with pytest.raises(SourceFamilyBlocked):
        freeze(Path("not-an-absolute-path"))
    assert sha(read_strict(V1 / "manifest.json")) == V1_MANIFEST_SHA
    assert sha(read_strict(V1 / "frozen-protocol.json")) == V1_PROTOCOL_SHA
    assert stat.S_IMODE(sealed.stat().st_mode) == 0o700
    assert stat.S_IMODE((sealed / "evaluator-only/truth.json").stat().st_mode) == 0o600
