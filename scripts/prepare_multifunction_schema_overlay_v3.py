"""Prospectively seal a v3 source-schema COMPATIBILITY overlay for v2 holdout.

No Q6 calls, no Docker, no inference, no new/recycled model inputs, no
retrospective changes to v1/v2, and no autonomous research admission.
Reviews can use this new schema only after independent human source review.
"""
from __future__ import annotations

import argparse
import json
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

from schemas.multifunction_source_selection import (
    ALLOWED_FUNCTION_NAMES,
    CandidateMultifunctionSourceSelection,
)
from scripts.prepare_multifunction_source_holdout_v2 import (
    PROTOCOL as V2_PROTOCOL,
)
from scripts.prepare_multifunction_source_holdout_v2 import (
    RECIPES,
    REPO,
    _schema_sha,
    canonical,
    read_strict,
    sha,
    source_view,
)
from scripts.prepare_multifunction_source_holdout_v2 import (
    verify as verify_v2,
)
from services.compact_source_selection import CompactSourceSelection

V2_BUNDLE = Path("/home/zain/fyp-provenance/source-family-multifunction-holdout-v2")
V2_MANIFEST_SHA256 = "930e23d38acee20d19a6348ae4841742c51dc822f2fb5f3f6e7f23d0c61a3fac"
V2_PROTOCOL_SHA256 = "f6054313d00c2af79f78ec898a5e6945e084d901941806a705a7970e1bb9ad45"
V3_SOURCE_SCHEMA_SHA256 = _schema_sha(CandidateMultifunctionSourceSelection)
V2_SOURCE_SCHEMA_SHA256 = _schema_sha(CompactSourceSelection)


class CompatibilityBlocked(ValueError):
    """v2 parent, v3 compatibility contract, or external parent pin invalid."""


def frozen_contract() -> dict:
    """Preserve v2 scoring, generation and prompts exactly; only correct schema."""
    if V2_PROTOCOL["source_schema_sha256"] != V2_SOURCE_SCHEMA_SHA256:
        raise CompatibilityBlocked("v2 old source-selection schema hash changed")
    expected_names = frozenset(
        name for recipe in RECIPES
        for name in source_view(recipe)["candidate_function_names"]
    )
    if (
        len(expected_names) != 9
        or expected_names != ALLOWED_FUNCTION_NAMES
        or expected_names & frozenset({
            "vulnerable_login", "vulnerable_search", "vulnerable_file_read"
        })
    ):
        raise CompatibilityBlocked("candidate schema not exactly all nine v2 functions")
    corrected = deepcopy(V2_PROTOCOL)
    corrected["schema"] = "multi-function-source-family-development-protocol-v3"
    corrected["source_schema_sha256"] = V3_SOURCE_SCHEMA_SHA256
    corrected["schema_correction"] = {
        "supersedes_source_schema_sha256": V2_SOURCE_SCHEMA_SHA256,
        "reason": (
            "v2 source schema incorrectly constrained function_or_route to "
            "the three original vulnerable_store functions; none match v2"
        ),
        "new_source_model": "CandidateMultifunctionSourceSelection",
        "allowed_function_names": sorted(expected_names),
        "schema_permits_all_safe_decoys": True,
        "independent_reviewer_approval_still_required": True,
        "effective_independent_source_localization_tasks": 3,
        "positive_variants_per_source_task": 3,
    }
    corrected["model_inputs_location"] = {
        "external_parent": str(V2_BUNDLE),
        "parent_manifest_sha256": V2_MANIFEST_SHA256,
        "parent_protocol_sha256": V2_PROTOCOL_SHA256,
        "case_ids_reused_without_new_exposure": True,
    }
    corrected["new_model_calls_performed_in_preparation"] = 0
    corrected["research_final_admission"] = False
    corrected["registered_executor_dispatch_authorized"] = False
    return corrected


def parent_is_valid() -> dict:
    """Verify every source/case from the pinned v2 archive before linking."""
    if (
        sha(read_strict(V2_BUNDLE / "manifest.json")) != V2_MANIFEST_SHA256
        or sha(read_strict(V2_BUNDLE / "frozen-protocol.json")) != V2_PROTOCOL_SHA256
    ):
        raise CompatibilityBlocked("externally pinned v2 bundle hash changed")
    parsed = json.loads(read_strict(V2_BUNDLE / "manifest.json"))
    if (
        parsed["schema"] != "source-family-multi-function-prequalification-v2"
        or parsed["case_count"] != 18
        or parsed["model_calls"] != 0
        or parsed["docker_runs"] != 0
        or parsed["scientifically_independent_approved"] is not False
    ):
        raise CompatibilityBlocked("v2 archive no longer a frozen development holdout")
    replay = verify_v2(V2_BUNDLE)
    if replay != {
        "malicious": 9, "benign": 9,
        "patched_replay": 9, "safe_decoy_routes": 6,
    }:
        raise CompatibilityBlocked("v2 parent evidence did not independently replay")
    return parsed


def _new_external_root(destination: Path) -> None:
    if (
        not destination.is_absolute()
        or destination.exists()
        or destination.is_symlink()
        or destination == REPO
        or REPO in destination.parents
        or destination == V2_BUNDLE
        or V2_BUNDLE in destination.parents
    ):
        raise CompatibilityBlocked("v3 overlay must use new external non-repository directory")
    if any(parent.is_symlink() for parent in destination.parents):
        raise CompatibilityBlocked("symlinked output ancestry refused")


def _write_new(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(canonical(payload))
    path.chmod(0o600)


def freeze_overlay(destination: Path) -> dict:
    _new_external_root(destination)
    parent = parent_is_valid()
    contract = frozen_contract()
    destination.mkdir(parents=True, mode=0o700, exist_ok=False)
    destination.chmod(0o700)
    _write_new(destination / "corrected-protocol.json", contract)
    manifest = {
        "schema": "source-family-source-schema-compatibility-overlay-v3",
        "frozen_utc": datetime.now(UTC).isoformat(),
        "parent_bundle": str(V2_BUNDLE),
        "parent_v2_manifest_sha256": V2_MANIFEST_SHA256,
        "parent_v2_protocol_sha256": V2_PROTOCOL_SHA256,
        "parent_case_ids": [c["case_id"] for c in parent["cases"]],
        "parent_source_sha256": parent["original_source_sha256"],
        "parent_truth_sha256": parent["evaluator_truth_sha256"],
        "corrected_protocol_sha256": sha(
            read_strict(destination / "corrected-protocol.json")
        ),
        "corrected_source_selection_schema_sha256": V3_SOURCE_SCHEMA_SHA256,
        "model_calls": 0,
        "docker_runs": 0,
        "independent_human_approval": False,
        "official_m21_admitted": False,
        "independent_source_tasks": 3,
        "v2_cases_reused_without_duplication": 18,
        "code_builder_sha256": sha(read_strict(Path(__file__))),
    }
    _write_new(destination / "manifest.json", manifest)
    return manifest


def verify_overlay(destination: Path) -> dict:
    raw_manifest = read_strict(destination / "manifest.json")
    manifest = json.loads(raw_manifest)
    if raw_manifest != canonical(manifest):
        raise CompatibilityBlocked("v3 overlay manifest not canonical")
    contract_bytes = read_strict(destination / "corrected-protocol.json")
    contract = json.loads(contract_bytes)
    parent = parent_is_valid()
    if (
        contract_bytes != canonical(contract)
        or contract != frozen_contract()
        or manifest["schema"] != "source-family-source-schema-compatibility-overlay-v3"
        or manifest["parent_bundle"] != str(V2_BUNDLE)
        or manifest["parent_v2_manifest_sha256"] != V2_MANIFEST_SHA256
        or manifest["parent_v2_protocol_sha256"] != V2_PROTOCOL_SHA256
        or manifest["parent_case_ids"] != [c["case_id"] for c in parent["cases"]]
        or manifest["parent_source_sha256"] != parent["original_source_sha256"]
        or manifest["parent_truth_sha256"] != parent["evaluator_truth_sha256"]
        or manifest["corrected_protocol_sha256"] != sha(contract_bytes)
        or manifest["corrected_source_selection_schema_sha256"] != V3_SOURCE_SCHEMA_SHA256
        or manifest["model_calls"] != 0
        or manifest["docker_runs"] != 0
        or manifest["independent_human_approval"] is not False
        or manifest["official_m21_admitted"] is not False
        or manifest["independent_source_tasks"] != 3
        or manifest["v2_cases_reused_without_duplication"] != 18
        or manifest["code_builder_sha256"] != sha(read_strict(Path(__file__)))
    ):
        raise CompatibilityBlocked("v3 schema overlay identities/permissions drift")
    if sorted(path.name for path in destination.iterdir()) != [
        "corrected-protocol.json", "manifest.json"
    ]:
        raise CompatibilityBlocked("overlay must contain only two immutable JSON files")
    return {
        "source_schema_compatible": True,
        "parent_cases": 18,
        "unique_source_selection_tasks": 3,
        "new_model_calls": 0,
        "external_review_pending": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    if args.verify_only:
        print("V3_COMPATIBILITY_REVIEW_PASS", json.dumps(
            verify_overlay(args.output_root), sort_keys=True
        ))
        return
    created = freeze_overlay(args.output_root)
    print("V3_SCHEMA_CORRECTION_FROZEN", str(args.output_root))
    print("PARENT_CASES",len(created["parent_case_ids"]),
          "INDEPENDENT_SOURCE_TASKS",created["independent_source_tasks"])
    print("V3_VERIFICATION", json.dumps(verify_overlay(args.output_root), sort_keys=True))
    print("NO_MODEL_NO_DOCKER_NO_RESEARCH_ADMISSION")


if __name__ == "__main__":
    main()
